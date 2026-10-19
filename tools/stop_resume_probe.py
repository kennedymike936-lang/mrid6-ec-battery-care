"""Authorised minimal write validation: 10/0E -> verify stop -> 10/0F -> verify restore.

AUTHORISATION (this run)
  0x8151=0x0E, 0x8150=0x10   then verify
  0x8151=0x0F, 0x8150=0x10   then verify
NOT authorised: 0x0D (native 60/80), 0x0C, any other address/opcode.

FAIL-CLOSED CONTRACT
  * Preflight must pass on every point or NOTHING is written.
  * 0x0E is submitted exactly once. 0x0F is submitted exactly once, and ONLY if
    0x0E verified as a successful, healthy stop. If the stop verification is
    inconsistent we do NOT issue a recovery write (that would be exactly the
    blind second write the user forbade) -- we poison and stop.
  * Any timeout / anomaly / inconsistency: poison, no retry, no flush, no
    re-run, unload driver, delete service.
"""
from __future__ import annotations

import ctypes as ct
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecguard import guard, profile, probe                    # noqa: E402
from ecguard import transport as _tr                         # noqa: E402
from ecguard.ec_write import (                               # noqa: E402
    Anomaly, EcWriteTransport, NotAuthorised,
)
from ecguard.winring0_dev import KernelService, WinRing0Device  # noqa: E402

STOP_SUBCOMMAND = 0x0E
RESTORE_SUBCOMMAND = 0x0F
TRIGGER_ADDRESS = 0x8150
SUBCMD_ADDRESS = 0x8151
TRIGGER_VALUE = 0x10

# Exponential backoff for the mailbox-ready poll.
POLL_SCHEDULE = (0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256,
                 0.256, 0.256, 0.256, 0.256, 0.256, 0.256)

OBSERVE_SECONDS = 12.0
OBSERVE_INTERVAL = 4.0
RESTORE_WAIT_SECONDS = 20.0


def emit(entry: dict) -> None:
    record = {"time": __import__("datetime").datetime.now().astimezone().isoformat(), **entry}
    print(json.dumps(record, ensure_ascii=False), flush=True)


def cim() -> dict:
    try:
        return _tr.cim_battery_telemetry()
    except Exception as error:  # noqa: BLE001
        return {"available": False, "error": str(error), "batteries": []}


def first_battery(data: dict) -> dict:
    bats = (data or {}).get("batteries") or []
    return bats[0] if bats else {}


def snap(t: EcWriteTransport) -> dict:
    raw = {a: t.read_xram(a) for a in sorted(profile.READ_ADDRESSES)}
    return profile.build_snapshot(raw)


def main() -> int:
    result: dict = {
        "stage": "authorised-0E-0F-validation",
        "authorised_writes": [[f"{SUBCMD_ADDRESS:04X}", "0E"], [f"{TRIGGER_ADDRESS:04X}", "10"],
                              [f"{SUBCMD_ADDRESS:04X}", "0F"], [f"{TRIGGER_ADDRESS:04X}", "10"]],
        "success_stop": False,
        "success_restore": False,
    }
    service = KernelService()
    device = None
    t = None

    try:
        # ------------------------------------------------ service + device
        service.create()
        service.start()
        emit({"event": "service_running", "state": service.query_state()})
        device = WinRing0Device().open()
        result["driver_version"] = device.driver_version
        emit({"event": "device_opened", "path": device.path,
              "driver_version": hex(device.driver_version), "refcount": device.refcount})

        t = EcWriteTransport(device, allow_writes=True)

        # ------------------------------------------------------ preflight
        guard.require_writable()                      # poison / journal gate
        emit({"event": "preflight_begin", "note": "read-only; no write has occurred yet"})

        pre = snap(t)
        ws = _tr.windows_status()
        board = _tr.board_is_mrid6()
        result["preflight_snapshot"] = pre
        result["preflight_windows"] = ws
        emit({"event": "preflight_snapshot", "ec": pre, "windows": ws, "board": board})

        checks, _ = probe.gate_readonly(
            _StaticEC(pre), ws, board, repeats=1)
        for c in checks:
            emit({"event": "check", **c.to_dict()})
        ro_ok = all(c.passed for c in checks if c.fatal)
        if not ro_ok:
            raise Anomaly("read-only preflight gate failed; nothing written")

        # stage-specific preflight
        stage_checks = probe.gate_enable_0d(pre, ws, guard.load_state())
        # For 0x0E we do NOT need SOC < 80 (that guard exists for 0x0D's
        # discharge branch), but the user requires AC + SOC 60..79 + charging.
        soc = pre["soc"]
        stage_ok = True
        def need(name, ok, detail):
            nonlocal stage_ok
            emit({"event": "check", "check": name, "pass": ok, "detail": detail, "fatal": True})
            if not ok:
                stage_ok = False

        need("ec_version_is_0_38",
             tuple(pre["version"]) == profile.EXPECTED_VERSION_038,
             f"version={pre['version']} expected={list(profile.EXPECTED_VERSION_038)}")
        need("ac_online_ec", bool(pre["ac"]), f"EC ac={pre['ac']}")
        need("ac_online_windows", ws.get("ac") is True, f"Windows ac={ws.get('ac')}")
        need("soc_in_60_79", profile.TARGET_LOW <= soc <= profile.ENABLE_SOC_MAX_EXCLUSIVE - 1,
             f"EC SOC={soc}%")
        need("soc_windows_in_band",
             ws.get("soc") is not None
             and profile.TARGET_LOW <= ws["soc"] <= profile.ENABLE_SOC_MAX_EXCLUSIVE - 1,
             f"Windows SOC={ws.get('soc')}%")
        need("soc_ec_windows_consistent",
             ws.get("soc") is not None and abs(soc - ws["soc"]) <= profile.SOC_TOLERANCE,
             f"EC={soc}% Windows={ws.get('soc')}% delta={None if ws.get('soc') is None else abs(soc-ws['soc'])}")
        need("ac_ec_windows_consistent", pre["ac"] == ws.get("ac"),
             f"EC={pre['ac']} Windows={ws.get('ac')}")
        need("battery_present", bool(pre["battery_present"]) and ws.get("battery_present") is True,
             f"EC={pre['battery_present']} Windows={ws.get('battery_present')}")
        need("mailbox_idle", pre["mailbox_command"] == 0,
             f"0x8150=0x{pre['mailbox_command']:02X}")
        need("mode_no_conflict", pre["mode"] in (profile.NORMAL_MODE,),
             f"0x83C0=0x{pre['mode']:02X} (must be 0x00 normal)")
        need("guard_clean", not guard.load_state().get("poisoned"),
             "guard not poisoned, no unfinished transaction")
        need("initially_charging", bool(pre["charging"]) and ws.get("charging") is True,
             f"EC charging={pre['charging']} Windows charging={ws.get('charging')}")

        if not stage_ok:
            raise Anomaly("stage preflight failed; NOTHING was written")

        emit({"event": "preflight_pass", "soc": soc,
              "note": "all preflight conditions satisfied"})
        result["preflight_pass"] = True

        # =================================================== 10/0E (once)
        guard.begin_transaction([[SUBCMD_ADDRESS, STOP_SUBCOMMAND],
                                 [TRIGGER_ADDRESS, TRIGGER_VALUE]],
                                "10/0E stop charging, single submission")
        emit({"event": "submit_0E", "writes": [[f"{SUBCMD_ADDRESS:04X}", "0E"],
                                               [f"{TRIGGER_ADDRESS:04X}", "10"]],
              "submissions": 1})
        t.write_xram(SUBCMD_ADDRESS, STOP_SUBCOMMAND)
        t.write_xram(TRIGGER_ADDRESS, TRIGGER_VALUE)
        polls = t.wait_mailbox_idle(POLL_SCHEDULE)
        emit({"event": "mailbox_idle_after_0E", "polls": polls})

        post_stop = snap(t)
        emit({"event": "post_0E_snapshot", "ec": post_stop, "cim": cim()})

        # ------------------------------------------------------------------
        # FIX (learned the hard way on the first live run):
        # 0x83C0 and 0x8152 change immediately when the mailbox handler returns,
        # but the EC's periodic scheduler updates 0x8370 and zeroes the
        # requested-current buffer 0x837C/0x837D on a LATER pass, and the
        # charger/SMBus action happens later still. Demanding instant
        # consistency produced a false failure. So:
        #   hard, immediate  : mode == 0x02 and mailbox result == 0x55
        #   settle-polled    : requested-current zero, charging flag cleared
        # ------------------------------------------------------------------
        immediate_ok = (post_stop["mode"] == profile.STOP_MODE
                        and post_stop["mailbox_result"] == profile.MAILBOX_RESULT_OK)
        result["stop_immediate_ok"] = immediate_ok
        emit({"event": "stop_verification_immediate",
              "mode_is_02": post_stop["mode"] == profile.STOP_MODE,
              "mailbox_55": post_stop["mailbox_result"] == profile.MAILBOX_RESULT_OK,
              "requested_current_zero": post_stop["requested_current_zero"],
              "scheduler_state": f"0x{post_stop['state']:02X}",
              "immediate_pass": immediate_ok,
              "note": "0x8152=0x55 alone is NOT treated as success"})

        if not immediate_ok:
            raise Anomaly(
                "0x0E rejected at the mailbox level (mode/result); NOT issuing 0x0F"
            )

        # Poll for the scheduler/charger to settle.
        settled = False
        settle_rows = []
        deadline = time.monotonic() + OBSERVE_SECONDS
        while True:
            s, w, b = snap(t), _tr.windows_status(), cim()
            first = first_battery(b)
            row = {"ec": s, "windows": w,
                   "cim": {k: first.get(k) for k in
                           ("PowerOnline", "Charging", "Discharging", "ChargeRate",
                            "DischargeRate", "RemainingCapacity", "Voltage")}}
            settle_rows.append(row)
            emit({"event": "observe_stop", **row})
            settled = (s["requested_current_zero"]
                       and s["charging"] is False and s["discharging"] is False)
            if settled or time.monotonic() >= deadline:
                break
            time.sleep(OBSERVE_INTERVAL)
        result["stop_observations"] = settle_rows
        result["stop_settled"] = settled

        if not settled:
            raise Anomaly(
                "0x0E was accepted (mode 0x02) but the charger never settled to "
                "not-charging with a zero requested current; NOT issuing 0x0F"
            )

        stop_ok = True
        result["stop_mode_ok"] = True
        emit({"event": "stop_verification", "settled": settled, "pass": True,
              "settle_seconds": OBSERVE_SECONDS})

        # acceptance over the settled window
        def ok_row(row) -> bool:
            s, w, b = row["ec"], row["windows"], row["cim"]
            return (s["ac"] and w.get("ac") is True
                    and s["charging"] is False and s["discharging"] is False
                    and w.get("charging") is False and w.get("discharging") is False
                    and (b.get("ChargeRate") in (0, None)) and (b.get("DischargeRate") in (0, None)))

        stop_accepted = ok_row(settle_rows[-1])
        socs = [r["ec"]["soc"] for r in settle_rows]
        caps = [r["cim"].get("RemainingCapacity") for r in settle_rows]
        result["stop_accepted"] = stop_accepted
        result["success_stop"] = True
        emit({"event": "stop_accepted", "pass": stop_accepted,
              "soc_series": socs, "capacity_series": caps,
              "note": "AC on, charging=false, discharging=false, rates 0"})

        guard.complete_transaction({"phase": "0E_stop", "mode": post_stop["mode"],
                                    "state": post_stop["state"]})

        if not stop_accepted:
            raise Anomaly("0x0E stopped the charger but the acceptance criteria were not met")

        # =================================================== 10/0F (once)
        guard.begin_transaction([[SUBCMD_ADDRESS, RESTORE_SUBCOMMAND],
                                 [TRIGGER_ADDRESS, TRIGGER_VALUE]],
                                "10/0F restore normal policy, single submission")
        emit({"event": "submit_0F", "writes": [[f"{SUBCMD_ADDRESS:04X}", "0F"],
                                               [f"{TRIGGER_ADDRESS:04X}", "10"]],
              "submissions": 1})
        t.write_xram(SUBCMD_ADDRESS, RESTORE_SUBCOMMAND)
        t.write_xram(TRIGGER_ADDRESS, TRIGGER_VALUE)
        polls = t.wait_mailbox_idle(POLL_SCHEDULE)
        emit({"event": "mailbox_idle_after_0F", "polls": polls})

        restore_rows = []
        restored = False
        deadline = time.monotonic() + RESTORE_WAIT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(OBSERVE_INTERVAL)
            s, w, c = snap(t), _tr.windows_status(), cim()
            b = first_battery(c)
            row = {"ec": s, "windows": w,
                   "cim": {k: b.get(k) for k in
                           ("PowerOnline", "Charging", "Discharging", "ChargeRate",
                            "DischargeRate", "RemainingCapacity", "Voltage")}}
            restore_rows.append(row)
            emit({"event": "observe_restore", **row})
            if s["mode"] == profile.NORMAL_MODE and not s["requested_current_zero"]:
                restored = True
                break
        result["restore_observations"] = restore_rows

        last = restore_rows[-1] if restore_rows else {"ec": post_stop, "windows": {}, "cim": {}}
        mode_restored = last["ec"]["mode"] == profile.NORMAL_MODE
        current_restored = not last["ec"]["requested_current_zero"]
        charging_restored = bool(last["ec"]["charging"]) or last["windows"].get("charging") is True
        rate_restored = (last["cim"].get("ChargeRate") or 0) > 0

        result["restore_mode_normal"] = mode_restored
        result["restore_requested_current_nonzero"] = current_restored
        result["restore_charging"] = charging_restored
        result["restore_charge_rate"] = last["cim"].get("ChargeRate")
        result["success_restore"] = bool(mode_restored)
        emit({"event": "restore_verification",
              "mode_0x00": mode_restored,
              "requested_current_nonzero": current_restored,
              "ec_charging": last["ec"]["charging"],
              "windows_charging": last["windows"].get("charging"),
              "charge_rate": last["cim"].get("ChargeRate"),
              "pass": mode_restored})

        guard.complete_transaction({"phase": "0F_restore", "mode": last["ec"]["mode"]})
        result["success"] = bool(stop_accepted and mode_restored)
        emit({"event": "done", "success": result["success"],
              "stop_ok": stop_accepted, "restore_mode_ok": mode_restored,
              "note": "no 10/0D was executed"})
        return 0 if result["success"] else 3

    except BaseException as error:  # noqa: BLE001
        reason = f"{type(error).__name__}: {error}"
        result["error"] = reason
        try:
            guard.poison(f"0E/0F validation aborted: {reason}")
            result["poisoned"] = True
        except Exception as poison_error:  # noqa: BLE001
            result["poison_error"] = str(poison_error)
        emit({"event": "aborted", "error": reason, "poisoned": True,
              "automatic_retry": False, "flush_attempted": False,
              "recovery_write_sent": False,
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
        out = Path(__file__).resolve().parent.parent / "logs" / "0e-0f-validation-report.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"report: {out}", flush=True)


class _StaticEC:
    """Adapter so probe.gate_readonly can be reused on an already-taken snapshot."""

    def __init__(self, snapshot):
        self.base = snapshot

    def snapshot(self):
        return self.base

    def snapshot_repeated(self, repeats=1):
        return self.base, []


if __name__ == "__main__":
    sys.exit(main())
