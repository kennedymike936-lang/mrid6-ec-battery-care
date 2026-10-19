"""Final stage: enable EC-native 60/80 battery-care mode via 10/0D.

Authorised writes, in this exact order, and nothing else:
    0x8153 <- 0x50     (High = 80)
    0x8154 <- 0x3C     (Low  = 60)
    0x8151 <- 0x0D     (native threshold subcommand)
    0x8150 <- 0x10     (battery command trigger, MUST be last)

Forbidden this round: 0x0C, unknown opcodes, internal state registers,
automatic re-writes/retries, BIOS/EC/SPI writes.

Verification uses the settled approach (hard immediate criteria + settle
polling), because this EC's state machine is asynchronous.

Target state with AC online and SOC inside the band:
    0x8150 idle, 0x8152 processed, thresholds still 80/60, native mode enabled,
    charging false, discharging false, rates ~0, SOC/capacity stable, AC online.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecguard import guard, profile, probe                     # noqa: E402
from ecguard import transport as _tr                          # noqa: E402
from ecguard.ec_write import (                                # noqa: E402
    PROFILE_0D, Anomaly, EcWriteTransport,
)
from ecguard.winring0_dev import KernelService, WinRing0Device  # noqa: E402

TARGET_HIGH = 80
TARGET_LOW = 60
ADDR_HIGH = 0x8153
ADDR_LOW = 0x8154
ADDR_SUBCMD = 0x8151
ADDR_TRIGGER = 0x8150
SUBCMD_NATIVE = 0x0D
TRIGGER_VALUE = 0x10

POLL_SCHEDULE = (0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256,
                 0.256, 0.256, 0.256, 0.256, 0.256, 0.256)

SETTLE_SECONDS = 60.0
SAMPLE_INTERVAL = 6.0


def emit(entry: dict) -> None:
    record = {"time": __import__("datetime").datetime.now().astimezone().isoformat(), **entry}
    print(json.dumps(record, ensure_ascii=False), flush=True)


def cim_first() -> dict:
    try:
        data = _tr.cim_battery_telemetry()
    except Exception as error:  # noqa: BLE001
        return {"error": str(error)}
    bats = (data or {}).get("batteries") or []
    return bats[0] if bats else {}


def snapshot(t: EcWriteTransport) -> dict:
    raw = {a: t.read_xram(a) for a in sorted(profile.READ_ADDRESSES)}
    return profile.build_snapshot(raw)


class _StaticEC:
    def __init__(self, snapshot):
        self.base = snapshot

    def snapshot(self):
        return self.base

    def snapshot_repeated(self, repeats=1):
        return self.base, []


def main() -> int:
    result: dict = {
        "stage": "native-0D-60-80-enable",
        "authorised_writes": [[f"{ADDR_HIGH:04X}", "50"], [f"{ADDR_LOW:04X}", "3C"],
                              [f"{ADDR_SUBCMD:04X}", "0D"], [f"{ADDR_TRIGGER:04X}", "10"]],
        "ec_ram_writes": [],
        "success": False,
    }
    service = KernelService()
    device = None
    t = None

    try:
        service.create()
        service.start()
        device = WinRing0Device().open()
        emit({"event": "device_opened", "driver_version": hex(device.driver_version),
              "refcount": device.refcount})

        # =============================================== preflight (no writes)
        t = EcWriteTransport(device, allow_writes=False, allowed_pairs=PROFILE_0D)
        guard.require_writable()
        pre = snapshot(t)
        ws = _tr.windows_status()
        board = _tr.board_is_mrid6()
        result["preflight_snapshot"] = pre
        result["preflight_windows"] = ws
        emit({"event": "preflight", "ec": pre, "windows": ws, "board": board})

        ro_checks, _ = probe.gate_readonly(_StaticEC(pre), ws, board, repeats=1)
        for c in ro_checks:
            emit({"event": "check", **c.to_dict()})
        ro_ok = all(c.passed for c in ro_checks if c.fatal)

        stage_ok = True

        def need(name, ok, detail):
            nonlocal stage_ok
            emit({"event": "check", "check": name, "pass": ok, "detail": detail, "fatal": True})
            if not ok:
                stage_ok = False

        soc = pre["soc"]
        need("ec_version_is_0_38", tuple(pre["version"]) == profile.EXPECTED_VERSION_038,
             f"version={pre['version']}")
        need("ac_connected_ec", bool(pre["ac"]), f"EC ac={pre['ac']}")
        need("ac_connected_windows", ws.get("ac") is True, f"Windows ac={ws.get('ac')}")
        need("soc_in_60_79", TARGET_LOW <= soc <= 79, f"EC SOC={soc}%")
        need("soc_windows_in_band",
             ws.get("soc") is not None and TARGET_LOW <= ws["soc"] <= 79,
             f"Windows SOC={ws.get('soc')}%")
        need("soc_ec_windows_consistent",
             ws.get("soc") is not None and abs(soc - ws["soc"]) <= profile.SOC_TOLERANCE,
             f"EC={soc}% Windows={ws.get('soc')}% delta="
             f"{None if ws.get('soc') is None else abs(soc - ws['soc'])}")
        need("ac_ec_windows_consistent", pre["ac"] == ws.get("ac"),
             f"EC={pre['ac']} Windows={ws.get('ac')}")
        need("battery_present", bool(pre["battery_present"]), f"{pre['battery_present']}")
        need("mailbox_idle", pre["mailbox_command"] == 0,
             f"0x8150=0x{pre['mailbox_command']:02X}")
        need("mode_is_normal_0x00", pre["mode"] == profile.NORMAL_MODE,
             f"0x83C0=0x{pre['mode']:02X}")
        need("guard_clean", not guard.load_state().get("poisoned"),
             "not poisoned, no unfinished transaction")
        need("soc_strictly_below_high", soc < TARGET_HIGH,
             f"SOC={soc}% < {TARGET_HIGH}% (avoids the firmware discharge-initialisation branch)")

        if not (ro_ok and stage_ok):
            raise Anomaly("preflight failed; NOTHING was written")

        emit({"event": "preflight_pass", "soc": soc, "note": "all conditions satisfied"})
        result["preflight_pass"] = True

        # =============================================== the 4 writes, once
        t.allow_writes = True
        plan = [[ADDR_HIGH, 0x50], [ADDR_LOW, 0x3C], [ADDR_SUBCMD, SUBCMD_NATIVE],
                [ADDR_TRIGGER, TRIGGER_VALUE]]
        guard.begin_transaction(plan, "native 0x0D thresholds 80/60, single submission")
        emit({"event": "submit_0D", "submissions": 1,
              "order": [[f"{a:04X}", f"{v:02X}"] for a, v in plan]})

        t.write_xram(ADDR_HIGH, 0x50)
        t.write_xram(ADDR_LOW, 0x3C)
        # stage-parameter read-back before arming
        rb_high = t.read_xram(ADDR_HIGH)
        rb_low = t.read_xram(ADDR_LOW)
        emit({"event": "parameter_readback", "high": rb_high, "low": rb_low})
        if rb_high != 0x50 or rb_low != 0x3C:
            raise Anomaly(f"threshold read-back mismatch: {rb_high}/{rb_low}")
        t.write_xram(ADDR_SUBCMD, SUBCMD_NATIVE)
        t.write_xram(ADDR_TRIGGER, TRIGGER_VALUE)
        result["ec_ram_writes"] = [[f"{a:04X}", f"{v:02X}"] for a, v in t.bytes_written]
        emit({"event": "writes_done", "writes": result["ec_ram_writes"]})

        polls = t.wait_mailbox_idle(POLL_SCHEDULE)
        emit({"event": "mailbox_idle_after_0D", "polls": polls})

        # =============================================== hard immediate check
        post = snapshot(t)
        result["post_0D_snapshot"] = post
        emit({"event": "post_0D_snapshot", "ec": post, "cim": cim_first()})

        hard_ok = (post["mailbox_command"] == 0
                   and post["mailbox_result"] == profile.MAILBOX_RESULT_OK
                   and post["mode"] == profile.NATIVE_MODE
                   and post["native_high"] == TARGET_HIGH
                   and post["native_low"] == TARGET_LOW)
        result["hard_criteria_ok"] = hard_ok
        emit({"event": "hard_verification",
              "mailbox_idle": post["mailbox_command"] == 0,
              "mailbox_55": post["mailbox_result"] == profile.MAILBOX_RESULT_OK,
              "mode_is_0x48": post["mode"] == profile.NATIVE_MODE,
              "native_high_80": post["native_high"] == TARGET_HIGH,
              "native_low_60": post["native_low"] == TARGET_LOW,
              "pass": hard_ok,
              "note": "0x8152=0x55 alone is never used as proof"})
        if not hard_ok:
            raise Anomaly("0x0D hard criteria not met; no retry, no cleanup write")

        # =============================================== settle to target state
        rows = []
        settled = False
        deadline = time.monotonic() + SETTLE_SECONDS
        while True:
            s, w, b = snapshot(t), _tr.windows_status(), cim_first()
            row = {
                "ec": s, "windows": w,
                "cim": {k: b.get(k) for k in
                        ("PowerOnline", "Charging", "Discharging", "ChargeRate",
                         "DischargeRate", "RemainingCapacity", "Voltage")},
            }
            rows.append(row)
            emit({"event": "observe_native", **row})
            settled = (s["mode"] == profile.NATIVE_MODE
                       and s["native_substate"] in (profile.NATIVE_SUBSTATE_HOLD,
                                                    profile.NATIVE_SUBSTATE_CHARGE)
                       and s["charging"] is False and s["discharging"] is False
                       and s["requested_current_zero"])
            if settled or time.monotonic() >= deadline:
                break
            time.sleep(SAMPLE_INTERVAL)

        result["observations"] = rows
        result["settled"] = settled
        last = rows[-1] if rows else {"ec": post, "windows": {}, "cim": {}}
        le, lw, lb = last["ec"], last["windows"], last["cim"]

        criteria = {
            "mode_native_0x48": le["mode"] == profile.NATIVE_MODE,
            "substate_hold_or_charge": le["native_substate"] in (2, 3),
            "thresholds_80_60": le["native_high"] == TARGET_HIGH and le["native_low"] == TARGET_LOW,
            "mailbox_idle": le["mailbox_command"] == 0,
            "ac_online_ec": bool(le["ac"]),
            "ac_online_windows": lw.get("ac") is True,
            "charging_false_ec": le["charging"] is False,
            "discharging_false_ec": le["discharging"] is False,
            "charging_false_windows": lw.get("charging") is False,
            "discharging_false_windows": lw.get("discharging") is False,
            "requested_current_zero": le["requested_current_zero"],
            "charge_rate_zero": (lb.get("ChargeRate") in (0, None)),
            "discharge_rate_zero": (lb.get("DischargeRate") in (0, None)),
            "soc_stable": len({r["ec"]["soc"] for r in rows}) <= 2 if rows else False,
            "capacity_stable": len({r["cim"].get("RemainingCapacity") for r in rows}) <= 2 if rows else False,
        }
        result["acceptance_criteria"] = criteria
        # AC must have been online across every sample
        ac_always = all(r["ec"]["ac"] and r["windows"].get("ac") is True for r in rows)
        criteria["ac_online_all_samples"] = ac_always
        all_pass = all(criteria.values())
        result["acceptance_pass"] = all_pass
        result["success"] = all_pass

        emit({"event": "acceptance", "criteria": criteria, "pass": all_pass,
              "settled": settled,
              "soc_series": [r["ec"]["soc"] for r in rows],
              "capacity_series": [r["cim"].get("RemainingCapacity") for r in rows],
              "charge_rate_series": [r["cim"].get("ChargeRate") for r in rows]})

        if all_pass:
            guard.complete_transaction({"phase": "0D_native", "mode": le["mode"],
                                        "native_high": le["native_high"],
                                        "native_low": le["native_low"],
                                        "substate": le["native_substate"]})
            emit({"event": "done", "success": True,
                  "note": "native 60/80 battery-care mode enabled; no 10/0C, no retries"})
            return 0
        raise Anomaly("0x0D accepted but the target care state was not reached")

    except BaseException as error:  # noqa: BLE001
        reason = f"{type(error).__name__}: {error}"
        result["error"] = reason
        try:
            guard.poison(f"0D native enable aborted: {reason}")
            result["poisoned"] = True
        except Exception as poison_error:  # noqa: BLE001
            result["poison_error"] = str(poison_error)
        emit({"event": "aborted", "error": reason, "poisoned": True,
              "automatic_retry": False, "flush_attempted": False,
              "cleanup_write_sent": False,
              "counters": t.counters() if t else None})
        return 4
    finally:
        if device:
            try:
                device.close()
                result["handle_closed"] = True
            except Exception as error:  # noqa: BLE001
                result["handle_close_error"] = str(error)
        cleanup = service.cleanup()
        result["service_cleanup"] = cleanup
        emit({"event": "cleanup", **cleanup})
        if t:
            result["counters"] = t.counters()
        emit({"event": "summary", **result})
        out = Path(__file__).resolve().parent.parent / "logs" / "0d-native-report.json"
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"report: {out}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
