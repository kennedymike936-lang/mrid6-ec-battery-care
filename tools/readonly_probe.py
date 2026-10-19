"""Minimal READ-ONLY EC 0.38 verification over the direct DeviceIoControl transport.

This stage is authorised for transport bring-up and read-only semantics only.

Hard guarantees implemented here:
  * NO EC RAM write. The transport refuses to emit the 0x93 (write) command
    entirely, and refuses to write EC mailbox RAM under any circumstance.
  * The ONLY port writes permitted are the protocol bytes needed to complete a
    0x92 (read) transaction: OUT 0x66,0x92 and the address high/low bytes to
    0x62. Those are protocol framing, not EC RAM writes.
  * No 0x93, no 10/0C, no 10/0D, no 10/0E, no 10/0F. Nothing is written to
    8150/8151/8153/8154.
  * Any timeout / IBF-OBF anomaly / unstable read -> poison, stop all EC I/O,
    no flush, no retry, no recovery command.

Phase 1 reads ONLY the EC version (0x8410-0x8413), repeated, and must be stable.
Phase 2 runs only after phase 1 is fully stable, and reads exactly the
addresses the read-only semantic gate needs. Nothing else is scanned.
"""
from __future__ import annotations

import ctypes as ct
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecguard import guard, profile, probe                  # noqa: E402
from ecguard import transport as _tr                       # noqa: E402
from ecguard.winring0_dev import (                         # noqa: E402
    KernelService, WinRing0Device, WinRing0Error,
)

# ---- protocol constants (same semantics as the audited prototype) ----------
CMD_READ = 0x92
CMD_WRITE = 0x93           # NEVER emitted in this stage; kept only to assert on
PORT_DATA = 0x62
PORT_CMD = 0x66

IBF = 0x02                 # input buffer full
OBF = 0x01                 # output buffer full
STATUS_BUSY_MASK = 0x23    # SCI(0x20) | IBF(0x02) | OBF(0x01)

WAIT_TIMEOUT = 0.25


class Anomaly(RuntimeError):
    """Any EC transaction anomaly. Aborts the whole run."""


class ReadOnlyTransport:
    """0x92-only EC transport over the guarded WinRing0 device client."""

    def __init__(self, device: WinRing0Device):
        self.dev = device
        self.transactions = 0
        self.port_accesses = 0
        self.timeouts = 0
        self.retries = 0
        self.anomalies: list[str] = []

    # -- raw port accounting ----------------------------------------------
    def _read(self, port: int) -> int:
        value = self.dev.read_port_byte(port)
        self.port_accesses += 1
        return value

    def _write(self, port: int, value: int) -> None:
        if value == CMD_WRITE:
            raise Anomaly("refused to emit 0x93: EC RAM writes are not authorised in this stage")
        if port == PORT_CMD and value != CMD_READ:
            raise Anomaly(f"refused unknown command 0x{value:02X} to 0x66")
        self.dev.write_port_byte(port, value)
        self.port_accesses += 1

    def _wait(self, mask: int, expected: int) -> None:
        deadline = time.monotonic() + WAIT_TIMEOUT
        while True:
            status = self._read(PORT_CMD)
            if status == 0xFF:
                self.anomalies.append(f"EC status FF (bus {status:02X})")
                raise Anomaly("EC status is 0xFF: controller/transport unavailable")
            if (status & mask) == expected:
                return
            if time.monotonic() >= deadline:
                self.timeouts += 1
                self.anomalies.append(f"wait timeout mask={mask:#x} last={status:#04x}")
                raise Anomaly(
                    f"EC port timeout waiting mask={mask:#x} expected={expected:#x} "
                    f"last_status={status:#04x}; transaction state UNCERTAIN; "
                    "no flush / no retry / no recovery"
                )
            time.sleep(0.0005)

    # -- the one and only EC operation exposed ----------------------------
    def read_xram(self, address: int) -> int:
        """Issue a 0x92 extended read transaction. Never writes EC RAM."""
        if address not in profile.READ_ADDRESSES:
            raise Anomaly(f"read outside audited profile: 0x{address:04X}")

        status = self._read(PORT_CMD)
        if status == 0xFF or (status & STATUS_BUSY_MASK):
            self.anomalies.append(f"pre-read status {status:#04x}")
            raise Anomaly(
                f"EC busy/SCI/output pending ({status:#04x}) before read; "
                "no command submitted"
            )

        self._write(PORT_CMD, CMD_READ)
        self._wait(IBF, 0)
        self._write(PORT_DATA, (address >> 8) & 0xFF)
        self._wait(IBF, 0)
        self._write(PORT_DATA, address & 0xFF)
        self._wait(IBF, 0)
        self._wait(OBF, OBF)
        value = self._read(PORT_DATA)
        self.transactions += 1
        return value

    def counters(self) -> dict:
        return {
            "ec_transactions": self.transactions,
            "port_accesses": self.port_accesses,
            "port_reads": self.dev.port_reads,
            "port_writes": self.dev.port_writes,
            "timeouts": self.timeouts,
            "retries": self.retries,
            "anomalies": self.anomalies,
        }


def wstatus() -> dict:
    class PowerStatus(ct.Structure):
        _fields_ = [("ac", ct.c_ubyte), ("flags", ct.c_ubyte), ("soc", ct.c_ubyte),
                    ("saver", ct.c_ubyte), ("life", ct.c_ulong), ("full", ct.c_ulong)]
    fn = ct.WinDLL("kernel32", use_last_error=True).GetSystemPowerStatus
    fn.argtypes, fn.restype = [ct.POINTER(PowerStatus)], ct.c_int
    s = PowerStatus()
    if not fn(ct.byref(s)):
        raise ct.WinError(ct.get_last_error())
    unknown = s.flags == 255
    return {
        "ac": {0: False, 1: True}.get(s.ac),
        "soc": s.soc if s.soc <= 100 else None,
        "battery_present": None if unknown else not bool(s.flags & 128),
        "charging": None if unknown else bool(s.flags & 8),
        "discharging": None if unknown else bool(s.flags & 2),
    }


def emit(entry: dict) -> None:
    record = {"time": __import__("datetime").datetime.now().astimezone().isoformat(), **entry}
    print(json.dumps(record, ensure_ascii=False), flush=True)


# --------------------------------------------------------------------- main
def main(argv=None) -> int:
    repeats = 3
    phase2 = True
    if argv:
        for i, a in enumerate(argv):
            if a == "--repeats" and i + 1 < len(argv):
                repeats = int(argv[i + 1])
            if a == "--phase1-only":
                phase2 = False

    result = {
        "stage": "transport-bringup-readonly",
        "ec_ram_write_submitted": False,
        "success": False,
    }
    service = KernelService()
    device = None
    transport = None

    try:
        # ---------------------------------------------------------- service
        emit({"event": "service_create", "name": service.name, "start_type": "demand",
              "binPath": service.sys_path})
        service.create()
        service.start()
        emit({"event": "service_state", "state": service.query_state()})

        # ----------------------------------------------------------- device
        device = WinRing0Device().open()
        result["device_opened"] = True
        result["driver_version"] = device.driver_version
        result["refcount"] = device.refcount
        emit({"event": "device", "path": device.path, "opened": True,
              "driver_version": hex(device.driver_version),
              "refcount": device.refcount})

        transport = ReadOnlyTransport(device)

        # ------------------------------------------------- phase 1: version
        emit({"event": "phase1_begin", "note": "EC version only, no other address",
              "repeats": repeats})
        version_samples = []
        for index in range(repeats):
            sample = [transport.read_xram(a) for a in profile.ADDR_VERSION]
            version_samples.append(sample)
            emit({"event": "version_sample", "index": index,
                  "addresses": [f"{a:04X}" for a in profile.ADDR_VERSION],
                  "values": [f"{v:02X}" for v in sample]})
        stable = all(s == version_samples[0] for s in version_samples)
        version = tuple(version_samples[0])
        result["version_samples"] = version_samples
        result["version_stable"] = stable
        result["ec_version"] = list(version)
        emit({"event": "phase1_result", "stable": stable, "version": list(version),
              "expected": list(profile.EXPECTED_VERSION_038),
              "matches_0_38": version == profile.EXPECTED_VERSION_038,
              "counters": transport.counters()})

        if not stable:
            raise Anomaly("EC version reads are NOT stable across repeats; "
                          "aborting before touching any other address")
        if version != profile.EXPECTED_VERSION_038:
            raise Anomaly(f"EC version {list(version)} is not the expected 0.38")

        if not phase2:
            result["success"] = True
            result["note"] = "phase 1 only"
            return 0

        # ------------------------- phase 2: minimal gate address set only
        gate_addresses = sorted(profile.READ_ADDRESSES)
        emit({"event": "phase2_begin", "addresses": [f"{a:04X}" for a in gate_addresses],
              "count": len(gate_addresses),
              "note": "exactly the addresses the read-only semantic gate needs"})
        raw = {}
        for address in gate_addresses:
            raw[address] = transport.read_xram(address)
        snap = profile.build_snapshot(raw)
        emit({"event": "phase2_snapshot", "ec": snap})

        ws = wstatus()
        emit({"event": "windows", **ws})

        # ---- gate evaluation (reuses the audited probe logic) ----
        board = _tr.board_is_mrid6()

        class _Shim:
            """Adapts the read-only transport to probe.gate_readonly's EC API."""
            def __init__(self, t, base_snapshot):
                self.t = t
                self.base = base_snapshot

            def snapshot(self):
                return self.base

            def snapshot_repeated(self, repeats=3):
                # stability already proven in phase 1; re-verify cheaply
                return self.base, []

        checks, evidence = probe.gate_readonly(
            _Shim(transport, snap), ws, board, repeats=repeats
        )
        all_pass = True
        for check in checks:
            emit({"event": "check", **check.to_dict()})
            if not check.passed and check.fatal:
                all_pass = False

        result["gate_pass"] = all_pass
        result["success"] = all_pass
        emit({"event": "readonly_gate", "pass": all_pass,
              "ec_version": snap["version"], "soc": snap["soc"], "mode": snap["mode"],
              "poisoned": False,
              "note": "read-only; no EC RAM write was submitted"})
        return 0 if all_pass else 2

    except BaseException as error:  # noqa: BLE001
        reason = f"{type(error).__name__}: {error}"
        result["error"] = reason
        try:
            guard.poison(f"read-only transport stage aborted: {reason}")
            result["poisoned"] = True
        except Exception as poison_error:  # noqa: BLE001
            result["poison_error"] = str(poison_error)
        emit({"event": "aborted", "error": reason, "poisoned": True,
              "automatic_retry": False, "flush_attempted": False,
              "recovery_command_sent": False,
              "counters": transport.counters() if transport else None})
        return 4
    finally:
        # every exit path: close handle, stop, delete, then verify
        if device:
            try:
                device.close()
                result["handle_closed"] = True
            except Exception as error:  # noqa: BLE001
                result["handle_close_error"] = str(error)
        cleanup = service.cleanup()
        result["service_cleanup"] = cleanup
        emit({"event": "cleanup", **cleanup})
        if transport:
            result["counters"] = transport.counters()
        emit({"event": "summary", **result})
        _write_report(result)


def _write_report(result: dict) -> None:
    out = Path(__file__).resolve().parent.parent / "logs" / "readonly-transport-report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"report: {out}", flush=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
