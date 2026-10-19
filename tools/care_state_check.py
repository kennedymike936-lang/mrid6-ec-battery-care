"""Decisive post-0x0D check: is the machine in the target care state?

Reads the EC state and Windows telemetry a few times a few seconds apart and
prints a clear verdict. Read-only: no writes, no driver left loaded.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecguard import profile, transport  # noqa: E402
from ecguard.winring0_dev import KernelService, WinRing0Device  # noqa: E402
from ecguard.ec_write import EcWriteTransport  # noqa: E402


def cim_first():
    try:
        data = transport.cim_battery_telemetry()
    except Exception as error:  # noqa: BLE001
        return {"error": str(error)}
    bats = (data or {}).get("batteries") or []
    return bats[0] if bats else {}


def main() -> int:
    service = KernelService()
    device = None
    try:
        service.create()
        service.start()
        device = WinRing0Device().open()
        t = EcWriteTransport(device, allow_writes=False)
        for i in range(3):
            raw = {a: t.read_xram(a) for a in sorted(profile.READ_ADDRESSES)}
            s = profile.build_snapshot(raw)
            w = transport.windows_status()
            b = cim_first()
            print(json.dumps({
                "sample": i,
                "ec": {k: s[k] for k in ("version", "soc", "mode", "state",
                                         "native_substate", "native_high", "native_low",
                                         "mailbox_command", "mailbox_result",
                                         "requested_current_zero",
                                         "ac", "battery_present", "charging", "discharging")},
                "windows": w,
                "cim": {k: b.get(k) for k in ("PowerOnline", "Charging", "Discharging",
                                              "ChargeRate", "DischargeRate",
                                              "RemainingCapacity", "Voltage")},
            }, ensure_ascii=False))
            if i < 2:
                time.sleep(10)
        return 0
    finally:
        if device:
            device.close()
        print("cleanup:", json.dumps(service.cleanup()))


if __name__ == "__main__":
    sys.exit(main())
