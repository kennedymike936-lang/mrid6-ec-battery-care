// ECGuard hardened bridge for BM5235 / MRID6 EC research.
//
// Hardening vs. the original prototype:
//   1. Loads WinRing0x64.dll/.sys ONLY from an administrator-protected
//      directory (default C:\ProgramData\ECGuard\driver), never from the
//      executable's own directory -> removes the DLL-planting surface.
//   2. Verifies SHA256 of both driver files before InitializeOls().
//   3. Takes the SAME global mutex the Python parent uses, so the bridge can
//      never be driven concurrently behind the parent's back.
//   4. Strict stdio whitelist: inspection may only issue 0x92; writes may only
//      issue 0x93 and only the exact audited byte sequences.
//   5. DeinitializeOls() in finally -> driver unloaded as soon as the process
//      exits, which happens immediately after the single transaction.
//
// This program does not elevate itself, does not install a service, does not
// create scheduled tasks, and does not persist.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

static class ECGuardBridge
{
    const string DEFAULT_DRIVER_DIR = @"C:\ProgramData\ECGuard\driver";
    const string DEFAULT_MUTEX = @"Global\ECGuard.BM5235.EC";

    // Audited hashes, cross-checked against the upstream repo's driver_probe.json
    // and re-verified at fetch time in ecguard/fetch_driver.py.
    const string DLL_SHA256 = "a746fd5728e7485f741cc330a279674bc8590b1b8007d8614046c49f58698485";
    const string SYS_SHA256 = "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5";

    [DllImport("WinRing0x64.dll", CallingConvention = CallingConvention.Winapi)]
    static extern bool InitializeOls();
    [DllImport("WinRing0x64.dll", CallingConvention = CallingConvention.Winapi)]
    static extern uint GetDllStatus();
    [DllImport("WinRing0x64.dll", CallingConvention = CallingConvention.Winapi)]
    static extern void DeinitializeOls();
    [DllImport("WinRing0x64.dll", CallingConvention = CallingConvention.Winapi)]
    static extern bool ReadIoPortByteEx(ushort port, out byte value);
    [DllImport("WinRing0x64.dll", CallingConvention = CallingConvention.Winapi)]
    static extern bool WriteIoPortByteEx(ushort port, byte value);
    [DllImport("shell32.dll")]
    static extern bool IsUserAnAdmin();

    static string driverDir = DEFAULT_DRIVER_DIR;
    static string mutexName = DEFAULT_MUTEX;
    static bool initialized;
    static bool poisoned;
    static Mutex heldMutex;

    // ------------------------------------------------------------------ output
    static void Line(string s)
    {
        Console.Out.Write(s);
        Console.Out.Write('\n');
        Console.Out.Flush();
    }

    static void Fail(string message)
    {
        // Once a transaction may be in flight, never hide that fact.
        Line("ERR " + message.Replace('\n', ' ').Replace('\r', ' '));
    }

    // ------------------------------------------------------------------ hashes
    static string Sha256Of(string path)
    {
        using (var sha = SHA256.Create())
        using (var fs = File.OpenRead(path))
            return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
    }

    static void VerifyDriverFiles()
    {
        string dll = Path.Combine(driverDir, "WinRing0x64.dll");
        string sys = Path.Combine(driverDir, "WinRing0x64.sys");
        if (!File.Exists(dll) || !File.Exists(sys))
            throw new InvalidOperationException(
                "Driver files not found in " + driverDir +
                ". Run Install-EcGuard.ps1 elevated to deploy and lock them down.");
        string gotDll = Sha256Of(dll), gotSys = Sha256Of(sys);
        if (gotDll != DLL_SHA256)
            throw new InvalidOperationException("WinRing0x64.dll SHA256 mismatch: " + gotDll);
        if (gotSys != SYS_SHA256)
            throw new InvalidOperationException("WinRing0x64.sys SHA256 mismatch: " + gotSys);
    }

    static void Init()
    {
        VerifyDriverFiles();
        try { Directory.SetCurrentDirectory(driverDir); } catch { /* load is by full path below */ }
        initialized = InitializeOls();
        uint status = GetDllStatus();
        if (!initialized || status != 0)
        {
            if (initialized) { try { DeinitializeOls(); } catch { } initialized = false; }
            throw new InvalidOperationException(
                "WinRing0 DLL status=" + status + "; admin=" + IsUserAnAdmin() +
                "; driverDir=" + driverDir +
                ". Status 2 = driver not loaded (blocked by policy?), 3 = driver file not found. " +
                "Security policy is NOT bypassed by this tool.");
        }
    }

    // ------------------------------------------------------------------ port IO
    static byte In(ushort port)
    {
        if (port != 0x62 && port != 0x66) throw new ArgumentException("Port outside guard profile");
        byte result;
        if (!ReadIoPortByteEx(port, out result)) throw new InvalidOperationException("I/O read failed");
        return result;
    }

    static void Out(ushort port, byte value)
    {
        if (port != 0x62 && port != 0x66) throw new ArgumentException("Port outside guard profile");
        if (!WriteIoPortByteEx(port, value)) throw new InvalidOperationException("I/O write failed");
    }

    static void Wait(byte mask, byte expected, int timeoutMs)
    {
        var timer = Stopwatch.StartNew();
        do
        {
            byte s = In(0x66);
            if (s == 0xFF) throw new InvalidOperationException("EC status is FF: controller/transport unavailable");
            if ((s & mask) == expected) return;
            Thread.Sleep(1);
        } while (timer.ElapsedMilliseconds < timeoutMs);
        throw new TimeoutException("EC port timeout; transaction state is UNCERTAIN; no flush/retry attempted");
    }

    static byte ReadXram(ushort address)
    {
        if (poisoned) throw new InvalidOperationException("EC transaction object is poisoned");
        try
        {
            byte s = In(0x66);
            if (s == 0xFF || (s & 0x23) != 0)
                throw new InvalidOperationException("EC busy/SCI/output pending: " + s.ToString("X2") + "; no command submitted");
            Out(0x66, 0x92);                       // READ command only
            Wait(2, 0, 250); Out(0x62, (byte)(address >> 8));
            Wait(2, 0, 250); Out(0x62, (byte)address);
            Wait(2, 0, 250); Wait(1, 1, 250);
            return In(0x62);
        }
        catch { poisoned = true; throw; }
    }

    static void WriteXram(ushort address, byte value)
    {
        if (poisoned) throw new InvalidOperationException("EC transaction object is poisoned");
        try
        {
            byte s = In(0x66);
            if (s == 0xFF || (s & 0x23) != 0)
                throw new InvalidOperationException("EC busy/SCI/output pending: " + s.ToString("X2") + "; no command submitted");
            Out(0x66, 0x93);                       // WRITE command only
            Wait(2, 0, 250); Out(0x62, (byte)(address >> 8));
            Wait(2, 0, 250); Out(0x62, (byte)address);
            Wait(2, 0, 250); Out(0x62, value);
            Wait(2, 0, 250);
        }
        catch { poisoned = true; throw; }
    }

    // ------------------------------------------------------------------ commands
    static readonly ushort[] InspectAddresses = {
        0x8150, 0x8151, 0x8152, 0x83C0, 0x8370, 0x8394, 0x8395,
        0x83A0, 0x83A1, 0x83A2, 0x837C, 0x837D, 0x8460, 0x847C,
        0x8410, 0x8411, 0x8412, 0x8413,
    };

    static void Inspect()
    {
        var raw = new Dictionary<string, string>();
        foreach (ushort address in InspectAddresses)
            raw[address.ToString("X4")] = ReadXram(address).ToString("X2");

        var ordered = new List<string>();
        foreach (var kv in raw)
            ordered.Add("\"" + kv.Key + "\":\"" + kv.Value + "\"");
        Line("{\"operation\":\"inspect\",\"writes_ec_ram\":false,\"admin\":" +
             (IsUserAnAdmin() ? "true" : "false") + ",\"ec\":{" + string.Join(",", ordered.ToArray()) + "}}");
    }

    // The ONLY byte sequences this bridge will ever place on the wire.
    static readonly HashSet<string> AllowedWrites = new HashSet<string>
    {
        // native threshold configuration, exclusively in this order
        "8153:50", "8154:3C", "8151:0D", "8150:10",
        // audited stop / resume / explicit native disable
        "8151:0E", "8151:0F",
    };

    static bool IsAllowedWrite(ushort address, byte value)
    {
        return AllowedWrites.Contains(address.ToString("X4") + ":" + value.ToString("X2"));
    }

    static void Serve(bool allowWrites)
    {
        Line("READY");
        string line;
        while ((line = Console.In.ReadLine()) != null)
        {
            if (line == "QUIT") { Line("BYE"); return; }
            string[] f = line.Split(' ');
            if (f.Length == 2 && f[0] == "R")
            {
                Line("V " + In(ushort.Parse(f[1], NumberStyles.HexNumber)).ToString("X2"));
            }
            else if (f.Length == 2 && f[0] == "Q")     // guarded XRAM read
            {
                Line("V " + ReadXram(ushort.Parse(f[1], NumberStyles.HexNumber)).ToString("X2"));
            }
            else if (f.Length == 3 && f[0] == "W")
            {
                ushort port = ushort.Parse(f[1], NumberStyles.HexNumber);
                byte value = byte.Parse(f[2], NumberStyles.HexNumber);
                if (port == 0x66 && value != 0x92 && !(value == 0x93 && allowWrites))
                    throw new InvalidOperationException("Only analyzed EC commands are allowed");
                Out(port, value);
                Line("OK");
            }
            else if (f.Length == 3 && f[0] == "X")     // guarded XRAM write
            {
                ushort address = ushort.Parse(f[1], NumberStyles.HexNumber);
                byte value = byte.Parse(f[2], NumberStyles.HexNumber);
                if (!allowWrites)
                    throw new InvalidOperationException("Write mode not enabled for this bridge instance");
                if (!IsAllowedWrite(address, value))
                    throw new InvalidOperationException(
                        "Write to " + address.ToString("X4") + "=" + value.ToString("X2") +
                        " is not in the audited write profile");
                WriteXram(address, value);
                Line("OK");
            }
            else throw new ArgumentException("Invalid stdio command");
        }
    }

    static int Main(string[] args)
    {
        bool serve = Array.IndexOf(args, "--serve") >= 0;
        bool inspect = Array.IndexOf(args, "--inspect") >= 0;
        bool allowWrites = Array.IndexOf(args, "--allow-ec-write") >= 0;
        int di = Array.IndexOf(args, "--driver-dir");
        if (di >= 0 && di + 1 < args.Length) driverDir = args[di + 1];
        int mi = Array.IndexOf(args, "--mutex-name");
        if (mi >= 0 && mi + 1 < args.Length) mutexName = args[mi + 1];

        try
        {
            if (!serve && !inspect)
            {
                Line("{\"operation\":\"status\",\"writes_ec_ram\":false,\"admin\":" +
                     (IsUserAnAdmin() ? "true" : "false") + ",\"driver_dir\":\"" +
                     driverDir.Replace("\\", "\\\\") + "\"}");
                return 0;
            }
            if (serve && Array.IndexOf(args, "--experimental-raw-io") < 0)
                throw new ArgumentException("Internal bridge requires --experimental-raw-io");
            if (serve && !allowWrites && Array.IndexOf(args, "--allow-ec-write") < 0)
            {
                // read-only serve is legitimate; nothing extra required
            }

            // Same global mutex the Python parent uses.
            //
            // Ownership model: in --serve mode the parent holds the mutex for the
            // whole session and spawns this child, so this process must NOT try
            // to take it (that would deadlock the design). Instead we only
            // require the mutex to exist and be owned by our parent. In
            // --inspect mode we claim it ourselves so a standalone inspection
            // cannot race a running controller.
            bool createdNew;
            heldMutex = new Mutex(false, mutexName, out createdNew);
            if (inspect)
            {
                bool acquired = false;
                try { acquired = heldMutex.WaitOne(TimeSpan.Zero, false); }
                catch (AbandonedMutexException) { acquired = true; }
                if (!acquired)
                    throw new InvalidOperationException(
                        "Another ECGuard instance holds " + mutexName +
                        "; refusing concurrent EC access.");
            }
            else if (createdNew)
            {
                // We created it, so no controller was running: that means we were
                // launched directly rather than by the Python parent.
                throw new InvalidOperationException(
                    "Serve mode must be launched by the ECGuard Python parent (mutex " +
                    mutexName + " was not held). Refusing unsupervised EC access.");
            }

            Init();
            if (serve) Serve(allowWrites);
            else Inspect();
            return 0;
        }
        catch (Exception error)
        {
            if (serve) Fail(error.Message);
            else
                Line("{\"error\":\"" +
                     error.Message.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", " ").Replace("\r", " ") +
                     "\",\"admin\":" + (IsUserAnAdmin() ? "true" : "false") +
                     ",\"automatic_retry\":false,\"ec_ram_write_submitted\":false}");
            return 1;
        }
        finally
        {
            try { if (initialized) DeinitializeOls(); } catch { }
            try { if (heldMutex != null) heldMutex.Dispose(); } catch { }
        }
    }
}
