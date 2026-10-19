"""Investigate a reported SOC drop while in native 60/80 care mode.

Answers: is the battery actually discharging, or is this gauge re-settling /
a reporting difference? Read-only; unloads the driver afterwards.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecguard import profile, transport  # noqa: E402
from ecguard.ec_write import EcWriteTransport  # noqa: E402
from ecguard.winring0_dev import KernelService, WinRing0Device  # noqa: E402

SAMPLES = 6
INTERVAL = 10.0


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

        rows = []
        for i in range(SAMPLES):
            raw = {a: t.read_xram(a) for a in sorted(profile.READ_ADDRESSES)}
            s = profile.build_snapshot(raw)
            w = transport.windows_status()
            b = cim_first()
            row = {
                "i": i,
                "t": __import__("datetime").datetime.now().astimezone().strftime("%H:%M:%S"),
                "ec_soc": s["soc"], "win_soc": w.get("soc"),
                "mode": hex(s["mode"]), "state": hex(s["state"]),
                "substate": s["native_substate"],
                "ac": s["ac"],
                "ec_chg": s["charging"], "ec_dis": s["discharging"],
                "win_chg": w.get("charging"), "win_dis": w.get("discharging"),
                "req_cur_zero": s["requested_current_zero"],
                "cim_chg": b.get("Charging"), "cim_dis": b.get("Discharging"),
                "charge_rate": b.get("ChargeRate"), "discharge_rate": b.get("DischargeRate"),
                "rem_cap": b.get("RemainingCapacity"), "volt": b.get("Voltage"),
                "flags_8460": s["raw"]["8460"],
            }
            rows.append(row)
            print(json.dumps(row, ensure_ascii=False), flush=True)
            if i < SAMPLES - 1:
                time.sleep(INTERVAL)

        print("\n=== ANALYSIS ===")
        any_discharge = any(r["ec_dis"] or r["win_dis"] or r["cim_dis"] for r in rows)
        any_charge = any(r["ec_chg"] or r["win_chg"] or r["cim_chg"] for r in rows)
        print(f"any discharging observed : {any_discharge}")
        print(f"any charging observed    : {any_charge}")
        print(f"EC SOC series            : {[r['ec_soc'] for r in rows]}")
        print(f"Windows SOC series       : {[r['win_soc'] for r in rows]}")
        print(f"RemainingCapacity series : {[r['rem_cap'] for r in rows]}")
        print(f"DischargeRate series     : {[r['discharge_rate'] for r in rows]}")
        print(f"ChargeRate series        : {[r['charge_rate'] for r in rows]}")
        print(f"voltage series           : {[r['volt'] for r in rows]}")
        print(f"substate series          : {[r['substate'] for r in rows]}")
        print(f"8460 series              : {[r['flags_8460'] for r in rows]}")
        return 0
    finally:
        if device:
            device.close()
        print("cleanup:", json.dumps(service.cleanup()))


if __name__ == "__main__":
    sys.exit(main())
