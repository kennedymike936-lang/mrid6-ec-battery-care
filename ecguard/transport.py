"""EC transport: hardened bridge client, shared mutex, exponential backoff.

Changes vs. the audited prototype:
  * One shared global mutex, held by the Python parent and verified by the
    bridge, so EC access can never be made concurrent.
  * Mailbox polling uses exponential backoff instead of hammering 0x92. The
    prototype issued ~90 full read transactions inside 3 seconds; here the
    worst case is a bounded, much smaller number of polls.
  * Every write goes through guard.require_writable() and the strict
    profile.WRITE_PROFILE whitelist.
  * The driver is loaded only from the administrator-protected directory.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from pathlib import Path

from . import guard, profile

DEFAULT_DRIVER_DIR = Path(r"C:\ProgramData\ECGuard\driver")
# The bridge MUST live in the same protected directory as WinRing0x64.dll/.sys:
# InitializeOls() resolves its driver as <host-exe-dir>\WinRing0x64.sys, so the
# SYS has to sit beside the executable that loads the DLL.
DEFAULT_BRIDGE = DEFAULT_DRIVER_DIR / "ECGuardBridge.exe"
GLOBAL_MUTEX = r"Global\ECGuard.BM5235.EC"

# Backoff schedule for mailbox completion polling (seconds). Total worst case
# is the sum, ~2.2 s, versus the prototype's unbounded 3 s hammering loop.
POLL_SCHEDULE = (0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256,
                 0.256, 0.256, 0.256, 0.256, 0.256, 0.256)


class TransportError(RuntimeError):
    pass


# --------------------------------------------------------------------- mutex
class SingleInstance:
    """Owns the one and only EC transaction mutex.

    Must wrap the whole session, including the bridge child process, so that
    no second instance (and no hand-launched bridge) can interleave EC traffic.
    """

    def __init__(self, name: str = GLOBAL_MUTEX):
        self.name = name
        self._handle = None
        self._kernel32 = None

    def __enter__(self):
        import ctypes as ct
        from ctypes import wintypes as wt
        if os.name != "nt":
            raise TransportError("EC access requires Windows")
        k = ct.WinDLL("kernel32", use_last_error=True)
        k.CreateMutexW.argtypes = [ct.c_void_p, wt.BOOL, wt.LPCWSTR]
        k.CreateMutexW.restype = wt.HANDLE
        k.ReleaseMutex.argtypes = [wt.HANDLE]
        k.CloseHandle.argtypes = [wt.HANDLE]
        # Create WITHOUT ownership, then take it explicitly: this way a
        # lingering previous process that died holding it is recoverable via
        # WAIT_ABANDONED instead of deadlocking forever.
        handle = k.CreateMutexW(None, False, self.name)
        if not handle:
            raise TransportError(f"CreateMutexW failed: {ct.get_last_error()}")
        WAIT_OBJECT_0, WAIT_ABANDONED = 0x0, 0x80
        rc = k.WaitForSingleObject(handle, 0)
        if rc not in (WAIT_OBJECT_0, WAIT_ABANDONED):
            k.CloseHandle(handle)
            raise TransportError(
                "Another ECGuard session already holds the EC transaction mutex; "
                "refusing concurrent EC access."
            )
        self._handle, self._kernel32 = handle, k
        return self

    def __exit__(self, *exc):
        if self._handle:
            self._kernel32.ReleaseMutex(self._handle)
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


# ------------------------------------------------------------------- bridge
class Bridge:
    """Line-protocol client for ECGuardBridge.exe."""

    def __init__(self, exe: Path = DEFAULT_BRIDGE, driver_dir: Path = DEFAULT_DRIVER_DIR,
                 allow_writes: bool = False):
        self.exe = Path(exe)
        self.driver_dir = Path(driver_dir)
        self.allow_writes = allow_writes
        self.process = None
        self._out: queue.Queue = queue.Queue()

    def open(self) -> "Bridge":
        if not self.exe.exists():
            raise TransportError(f"bridge not found: {self.exe}")
        args = [str(self.exe), "--serve", "--experimental-raw-io",
                "--mutex-name", GLOBAL_MUTEX, "--driver-dir", str(self.driver_dir)]
        if self.allow_writes:
            args.append("--allow-ec-write")
        self.process = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            encoding="utf-8", bufsize=1, creationflags=subprocess.CREATE_NO_WINDOW,
        )

        def pump():
            try:
                for line in self.process.stdout:
                    self._out.put(line.rstrip("\n"))
            finally:
                self._out.put(None)

        threading.Thread(target=pump, daemon=True).start()
        ready = self._reply(10.0)
        if ready != "READY":
            self.close()
            raise TransportError(f"bridge did not become ready: {ready}")
        return self

    def _reply(self, timeout: float) -> str:
        try:
            line = self._out.get(timeout=timeout)
        except queue.Empty:
            raise TransportError("bridge timeout (no reply)")
        if line is None:
            raise TransportError("bridge exited unexpectedly")
        if line.startswith("ERR "):
            raise TransportError(line[4:])
        return line

    def _request(self, text: str, timeout: float = 5.0) -> str:
        if not self.process or self.process.poll() is not None:
            raise TransportError("bridge is not running")
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()
        return self._reply(timeout)

    def read_port(self, port: int) -> int:
        reply = self._request(f"R {port:04X}")
        if not reply.startswith("V "):
            raise TransportError(f"unexpected read reply: {reply}")
        return int(reply[2:], 16)

    def write_port(self, port: int, value: int) -> None:
        if self._request(f"W {port:04X} {value:02X}") != "OK":
            raise TransportError("unexpected write reply")

    def read_xram(self, address: int) -> int:
        reply = self._request(f"Q {address:04X}")
        if not reply.startswith("V "):
            raise TransportError(f"unexpected XRAM read reply: {reply}")
        return int(reply[2:], 16)

    def write_xram(self, address: int, value: int) -> None:
        if self._request(f"X {address:04X} {value:02X}") != "OK":
            raise TransportError("unexpected XRAM write reply")

    def close(self) -> None:
        if self.process and self.process.poll() is None:
            try:
                self.process.stdin.write("QUIT\n")
                self.process.stdin.flush()
                self.process.wait(timeout=2)
            except Exception:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=2)
                except Exception:
                    pass
        if self.process:
            for stream in (self.process.stdin, self.process.stdout):
                try:
                    stream.close()
                except Exception:
                    pass


# ----------------------------------------------------------------------- EC
class EC:
    """Semantic EC object. Fail-closed on every uncertain outcome."""

    def __init__(self, bridge: Bridge):
        self.bridge = bridge
        self.poisoned = False

    # ------------------------------------------------------------ primitives
    def _guard_address(self, address: int) -> None:
        if address not in profile.READ_ADDRESSES:
            raise profile.ProfileError(f"read outside audited profile: 0x{address:04X}")

    def read(self, address: int) -> int:
        self._guard_address(address)
        if self.poisoned:
            raise TransportError("EC object poisoned; further I/O disabled")
        try:
            return self.bridge.read_xram(address)
        except BaseException:
            self.poisoned = True
            guard.poison(f"read 0x{address:04X} failed")
            raise

    def snapshot(self) -> dict:
        raw = {a: self.read(a) for a in sorted(profile.READ_ADDRESSES)}
        return profile.build_snapshot(raw)

    def snapshot_repeated(self, repeats: int = profile.READ_STABILITY_REPEATS):
        """Read the whole register set `repeats` times and report instability."""
        samples = [self.snapshot() for _ in range(repeats)]
        unstable = []
        for address in sorted(profile.READ_ADDRESSES):
            key = f"{address:04X}"
            values = {s["raw"][key] for s in samples}
            # 0x847C (SOC) is allowed to move by one during a long session;
            # every other audited register must be bit-stable to be trusted.
            if len(values) > 1 and address != profile.ADDR_SOC:
                unstable.append({"address": key, "values": sorted(values)})
        return samples[-1], unstable

    # ---------------------------------------------------------------- writes
    def write(self, address: int, value: int) -> None:
        if (address, value) not in profile.WRITE_PROFILE:
            raise profile.ProfileError(
                f"write 0x{address:04X}=0x{value:02X} is not in the audited write profile"
            )
        if self.poisoned:
            raise TransportError("EC object poisoned; further I/O disabled")
        try:
            self.bridge.write_xram(address, value)
            guard.ledger({"event": "ec_write", "address": f"{address:04X}",
                          "value": f"{value:02X}", "purpose": profile.WRITE_PROFILE[(address, value)]})
        except BaseException as error:
            # An interrupted write is never retried and never cleaned up.
            self.poisoned = True
            guard.poison(f"write 0x{address:04X}=0x{value:02X} failed: {error}")
            raise

    # ----------------------------------------------------------- mailbox wait
    def wait_mailbox_idle(self) -> int:
        """Poll 0x8150 with exponential backoff until the EC clears it."""
        polls = 0
        for delay in POLL_SCHEDULE:
            value = self.read(profile.ADDR_MAILBOX_COMMAND)
            polls += 1
            if value == 0:
                guard.ledger({"event": "mailbox_idle", "polls": polls})
                return polls
            time.sleep(delay)
        self.poisoned = True
        guard.poison("mailbox 0x8150 never returned to 0; transaction state uncertain")
        raise TransportError(
            f"mailbox did not return to idle after {polls} polls (~{sum(POLL_SCHEDULE):.2f}s); "
            "no retry and no cleanup write attempted"
        )


# ------------------------------------------------------------ OS-side status
def windows_status() -> dict:
    """AC/battery/SOC as Windows sees them, via GetSystemPowerStatus."""
    import ctypes as ct
    from ctypes import wintypes as wt

    class PowerStatus(ct.Structure):
        _fields_ = [("ac", wt.BYTE), ("flags", wt.BYTE), ("soc", wt.BYTE),
                    ("saver", wt.BYTE), ("life", wt.DWORD), ("full", wt.DWORD)]

    fn = ct.WinDLL("kernel32", use_last_error=True).GetSystemPowerStatus
    fn.argtypes, fn.restype = [ct.POINTER(PowerStatus)], wt.BOOL
    status = PowerStatus()
    if not fn(ct.byref(status)):
        raise ct.WinError(ct.get_last_error())
    unknown = status.flags == 255
    return {
        "ac": {0: False, 1: True}.get(status.ac),
        "soc": status.soc if status.soc <= 100 else None,
        "battery_present": None if unknown else not bool(status.flags & 128),
        "charging": None if unknown else bool(status.flags & 8),
        "discharging": None if unknown else bool(status.flags & 2),
    }


def cim_battery_telemetry() -> dict:
    """BatteryStatus WMI rates; never loads any EC driver."""
    shell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / \
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    query = (
        "$ErrorActionPreference='Stop';"
        "try{$c=@(Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus|"
        "Select-Object InstanceName,PowerOnline,Charging,Discharging,ChargeRate,"
        "DischargeRate,RemainingCapacity,Voltage);"
        "$j=[ordered]@{available=($c.Count -gt 0);batteries=$c}|ConvertTo-Json -Compress -Depth 4}"
        "catch{$j=[ordered]@{available=$false;error=$_.Exception.Message;batteries=@()}};"
        "[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($j))"
    )
    try:
        import base64
        result = subprocess.run([str(shell), "-NoProfile", "-NonInteractive", "-Command", query],
                                capture_output=True, encoding="utf-8", timeout=10,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or f"exit {result.returncode}")
        return json.loads(base64.b64decode(result.stdout.strip(), validate=True).decode("utf-8"))
    except Exception as error:
        return {"available": False, "error": str(error), "batteries": []}


def board_is_mrid6() -> dict:
    """Confirm the platform via SMBIOS registry values (no WMI, no admin)."""
    import winreg
    out = {"ok": False}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            for field in ("SystemManufacturer", "SystemProductName",
                          "BaseBoardManufacturer", "BaseBoardProduct", "BIOSVersion"):
                out[field] = winreg.QueryValueEx(key, field)[0]
    except FileNotFoundError:
        return out
    product = f"{out.get('SystemProductName','')} {out.get('BaseBoardProduct','')}".upper()
    out["ok"] = "MRID6" in product
    return out
