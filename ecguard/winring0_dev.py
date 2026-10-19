"""Bypass the broken WinRing0x64.dll and talk to the kernel driver directly.

WHY
---
The user-supplied WinRing0x64.dll cannot initialise on this machine because
OlsDll.cpp::Initialize() resolves the driver as
    <directory-of-the-HOST-EXE>\\WinRing0x64.sys
(GetModuleFileName(NULL, ...) returns the host process image, not the DLL), and
its GetDllVersion() ABI also faults. The kernel driver itself loads fine and
\\\\.\\WinRing0_1_2_0 opens successfully, so we drive it ourselves.

IOCTL PROVENANCE (no guessing)
------------------------------
Source A: GermanAizek/WinRing0  WinRing0Dll/OlsIoctl.h
Source B: QCute/WinRing0       WinRing0Dll/OlsIoctl.h
Both are byte-identical on the values used here:
    #define OLS_TYPE 40000                     (0x9C40)
    IOCTL_OLS_READ_IO_PORT_BYTE  = CTL_CODE(OLS_TYPE, 0x833, METHOD_BUFFERED, FILE_READ_ACCESS)
    IOCTL_OLS_WRITE_IO_PORT_BYTE = CTL_CODE(OLS_TYPE, 0x836, METHOD_BUFFERED, FILE_WRITE_ACCESS)

CTL_CODE(DeviceType, Function, Method, Access) =
    (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
with OLS_TYPE = 40000 = 0x9C40, METHOD_BUFFERED = 0,
and FILE_READ_ACCESS = 1 / FILE_WRITE_ACCESS = 2 (winnt.h):

    IOCTL_OLS_READ_IO_PORT_BYTE
        = (0x9C40 << 16) | (1 << 14) | (0x833 << 2) | 0
        = 0x9C400000 | 0x00004000 | 0x000020CC = 0x9C4060CC
    IOCTL_OLS_WRITE_IO_PORT_BYTE
        = (0x9C40 << 16) | (2 << 14) | (0x836 << 2) | 0
        = 0x9C400000 | 0x00008000 | 0x000020D8 = 0x9C40A0D8

NOTE: the access bits matter. Using FILE_ANY_ACCESS by mistake yields
0x9C4020CC / 0x9C4020D8, which is wrong for these two codes.

Corroboration: the shipped WinRing0x64.dll and WinRing0x64.sys images both
contain the literal
    GET_DRIVER_VERSION 0x9C402000   and   READ_MSR 0x9C402084
(verified by raw byte search), which confirms the OLS_TYPE<<16 encoding and that
this build uses this function-number base. GET_DRIVER_VERSION/READ_MSR carry
FILE_ANY_ACCESS so they are 0x9C40200x; the port IOCTLs carry read/write access
and therefore 0x9C4060xx / 0x9C40A0xx.

STRUCTURES (both headers agree)
-------------------------------
    typedef struct _OLS_WRITE_IO_PORT_INPUT {
        ULONG PortNumber;
        union { ULONG LongData; USHORT ShortData; UCHAR CharData; };
    } OLS_WRITE_IO_PORT_INPUT;

Read path, per OlsApi.cpp::ReadIoPortByteEx:
    input  = WORD port            (sizeof(WORD) == 2)
    output = WORD value           (sizeof(WORD) == 2)

SCOPE LIMITS ENFORCED HERE
--------------------------
Only two operations exist on this object, and only ports 0x62/0x66 are
accepted. Physical memory, MSR, PCI and arbitrary ports are simply not
implemented -- there is no code path that could reach them.
"""
from __future__ import annotations

import ctypes as ct
import os
import time
from ctypes import wintypes as wt

# ---------------------------------------------------------------- IOCTL codes
OLS_TYPE = 40000  # 0x9C40

FILE_ANY_ACCESS = 0x0000
FILE_READ_ACCESS = 0x0001
FILE_WRITE_ACCESS = 0x0002
METHOD_BUFFERED = 0x0000


def ctl_code(function: int, method: int = METHOD_BUFFERED, access: int = FILE_ANY_ACCESS) -> int:
    return (OLS_TYPE << 16) | (access << 14) | (function << 2) | method


IOCTL_OLS_GET_DRIVER_VERSION = ctl_code(0x800)
IOCTL_OLS_GET_REFCOUNT = ctl_code(0x801)
IOCTL_OLS_READ_IO_PORT_BYTE = ctl_code(0x833, access=FILE_READ_ACCESS)
IOCTL_OLS_WRITE_IO_PORT_BYTE = ctl_code(0x836, access=FILE_WRITE_ACCESS)

# The only ports this project may ever touch.
ALLOWED_PORTS = (0x62, 0x66)

DEVICE_PATH = r"\\.\WinRing0_1_2_0"
SERVICE_NAME = "WinRing0_1_2_0"   # must match OLS_DRIVER_ID in the DLL
DRIVER_SYS = r"C:\ProgramData\ECGuard\driver\WinRing0x64.sys"

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ct.c_void_p(-1).value


class WinRing0Error(RuntimeError):
    pass


class PortAccessDenied(WinRing0Error):
    """Raised when a port outside the guarded profile is requested."""


# ------------------------------------------------------------------- service
class KernelService:
    """Temporary demand-start kernel service lifecycle.

    create(demand) -> start -> ... -> stop -> delete, with cleanup guaranteed
    on every exit path. Never Boot/System/Auto start, never persistent.
    """

    def __init__(self, name: str = SERVICE_NAME, sys_path: str = DRIVER_SYS):
        self.name = name
        self.sys_path = sys_path
        self.created = False
        self.started = False

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _sc(args: list[str]) -> tuple[int, str]:
        import subprocess
        proc = subprocess.run(["sc.exe", *args], capture_output=True, timeout=30)
        out = (proc.stdout or b"") + (proc.stderr or b"")
        # sc.exe emits text in the OEM console codepage; never let a decode
        # hiccup abort a service operation.
        return proc.returncode, out.decode("utf-8", errors="replace")

    def query_state(self) -> str | None:
        rc, out = self._sc(["query", self.name])
        if rc != 0:
            return None
        for line in out.splitlines():
            if "STATE" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    tokens = parts[1].split()
                    if len(tokens) >= 2:
                        return tokens[1]
        return "UNKNOWN"

    # -- lifecycle ---------------------------------------------------------
    def create(self) -> None:
        if not os.path.exists(self.sys_path):
            raise WinRing0Error(f"driver not found: {self.sys_path}")
        existing = self.query_state()
        if existing is not None:
            raise WinRing0Error(
                f"service {self.name} already exists (state={existing}); refusing to touch it"
            )
        rc, out = self._sc([
            "create", self.name, "type=", "kernel", "start=", "demand",
            "binPath=", self.sys_path,
        ])
        if rc != 0:
            raise WinRing0Error(f"sc create failed ({rc}): {out.strip()}")
        self.created = True

    def start(self) -> None:
        rc, out = self._sc(["start", self.name])
        if rc != 0:
            raise WinRing0Error(
                f"sc start failed ({rc}): {out.strip()}. If this is a signature or "
                "blocklist refusal, STOP -- security policy is not bypassed here."
            )
        self.started = True
        # Wait for RUNNING
        for _ in range(20):
            if self.query_state() == "RUNNING":
                return
            time.sleep(0.15)
        raise WinRing0Error("driver did not reach RUNNING")

    def cleanup(self) -> dict:
        """Idempotent teardown. Always safe to call."""
        result = {"stopped": False, "deleted": False, "errors": []}
        state = self.query_state()
        if state is None:
            result["already_absent"] = True
            return result
        if state == "RUNNING":
            rc, out = self._sc(["stop", self.name])
            result["stopped"] = rc == 0
            if rc != 0 and "1062" not in out:      # 1062 = not started
                result["errors"].append(f"stop: {out.strip()}")
            for _ in range(20):
                if self.query_state() in (None, "STOPPED"):
                    break
                time.sleep(0.15)
        rc, out = self._sc(["delete", self.name])
        result["deleted"] = rc == 0
        if rc != 0:
            result["errors"].append(f"delete: {out.strip()}")
        result["final_state"] = self.query_state()
        return result


# --------------------------------------------------------------------- device
class WinRing0Device:
    """Minimal, strictly scoped WinRing0 device client."""

    def __init__(self, path: str = DEVICE_PATH):
        self.path = path
        self.handle = None
        self.k32 = None
        self.port_reads = 0
        self.port_writes = 0

    def open(self) -> "WinRing0Device":
        if os.name != "nt":
            raise WinRing0Error("Windows required")
        k = ct.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ct.c_void_p,
                                  wt.DWORD, wt.DWORD, wt.HANDLE]
        k.CreateFileW.restype = wt.HANDLE
        k.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, ct.c_void_p, wt.DWORD,
                                      ct.c_void_p, wt.DWORD, ct.POINTER(wt.DWORD),
                                      ct.c_void_p]
        k.DeviceIoControl.restype = wt.BOOL
        k.CloseHandle.argtypes = [wt.HANDLE]
        self.k32 = k

        handle = k.CreateFileW(self.path, GENERIC_READ | GENERIC_WRITE, 0, None,
                               OPEN_EXISTING, 0, None)
        if handle in (0, INVALID_HANDLE_VALUE):
            raise WinRing0Error(
                f"cannot open {self.path}: Win32 error {ct.get_last_error()}"
            )
        self.handle = handle
        return self

    @property
    def refcount(self) -> int:
        buf = wt.DWORD(0)
        returned = wt.DWORD(0)
        ok = self.k32.DeviceIoControl(self.handle, IOCTL_OLS_GET_REFCOUNT, None, 0,
                                      ct.byref(buf), ct.sizeof(buf),
                                      ct.byref(returned), None)
        return buf.value if ok else -1

    @property
    def driver_version(self) -> int:
        buf = wt.DWORD(0)
        returned = wt.DWORD(0)
        ok = self.k32.DeviceIoControl(self.handle, IOCTL_OLS_GET_DRIVER_VERSION, None, 0,
                                      ct.byref(buf), ct.sizeof(buf),
                                      ct.byref(returned), None)
        return buf.value if ok else -1

    # -- guarded port access ----------------------------------------------
    def _check_port(self, port: int) -> None:
        if port not in ALLOWED_PORTS:
            raise PortAccessDenied(
                f"port 0x{port:02X} is outside the guarded profile "
                f"{[hex(p) for p in ALLOWED_PORTS]}"
            )

    def read_port_byte(self, port: int) -> int:
        self._check_port(port)
        # ReadIoPortByteEx: input = WORD port, output = WORD value
        port_in = wt.WORD(port)
        value_out = wt.WORD(0)
        returned = wt.DWORD(0)
        ok = self.k32.DeviceIoControl(
            self.handle, IOCTL_OLS_READ_IO_PORT_BYTE,
            ct.byref(port_in), ct.sizeof(port_in),
            ct.byref(value_out), ct.sizeof(value_out),
            ct.byref(returned), None,
        )
        if not ok:
            raise WinRing0Error(f"ReadIoPortByte(0x{port:02X}) failed: {ct.get_last_error()}")
        self.port_reads += 1
        return value_out.value & 0xFF

    def write_port_byte(self, port: int, value: int) -> None:
        self._check_port(port)
        if not 0 <= value <= 0xFF:
            raise WinRing0Error("byte value out of range")
        # OLS_WRITE_IO_PORT_INPUT { ULONG PortNumber; union { ULONG; USHORT; UCHAR; } }
        # CharData sits at offset 4 (union starts there), so the struct is 8 bytes
        # and the call passes only up to and including CharData (offsetof + 1 = 5).
        import ctypes
        class WriteInput(ct.Structure):
            _fields_ = [("PortNumber", wt.ULONG), ("Data", ct.c_ubyte * 4)]
        buf = WriteInput()
        buf.PortNumber = port
        buf.Data[0] = value
        length = ct.sizeof(wt.ULONG) + 1  # offsetof(CharData) + sizeof(CharData) == 5
        returned = wt.DWORD(0)
        ok = self.k32.DeviceIoControl(
            self.handle, IOCTL_OLS_WRITE_IO_PORT_BYTE,
            ct.byref(buf), length,
            None, 0,
            ct.byref(returned), None,
        )
        if not ok:
            raise WinRing0Error(
                f"WriteIoPortByte(0x{port:02X},{value:02X}) failed: {ct.get_last_error()}"
            )
        self.port_writes += 1

    def close(self) -> None:
        if self.handle not in (None, 0, INVALID_HANDLE_VALUE):
            try:
                self.k32.CloseHandle(self.handle)
            except Exception:
                pass
            self.handle = None
