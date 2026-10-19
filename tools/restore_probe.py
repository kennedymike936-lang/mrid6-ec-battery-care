"""One authorised 10/0F restore, with settle-tolerant verification.

Context: a single 10/0E was submitted and took effect (mode 0x83C0 -> 0x02,
charging stopped, AC still online). The previous run's verification was checked
too early -- the EC state machine is asynchronous, so mode/mailbox-result update
immediately while the scheduler state 0x8370 and the requested-current buffer
0x837C/0x837D settle on a later periodic pass.

This run:
  * clears the guard only after a clean READ-ONLY inspection (explicit, logged);
  * submits 0x8151=0x0F then 0x8150=0x10 EXACTLY ONCE;
  * polls for the restore to settle instead of demanding instant consistency;
  * any timeout/anomaly -> poison, no retry, no flush.

Writes permitted here: only 0x8151=0x0F and 0x8150=0x10.
No 0x0D, no 0x0C, no 0x8153/0x8154, no other address.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ecguard import guard, profile, probe                    # noqa: E402
from ecguard import transport as _tr                         # noqa: E402
from ecguard.ec_write import Anomaly, EcWriteTransport       # noqa: E402
from ecguard.winring0_dev import KernelService, WinRing0Device  # noqa: E402

RESTORE_SUBCOMMAND = 0x0F
SUBCMD_ADDRESS = 0x8151
TRIGGER_ADDRESS = 0x8150
TRIGGER_VALUE = 0x10

POLL_SCHEDULE = (0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256,
                 0.256, 0.256, 0.256, 0.256, 0.256, 0.256)

SETTLE_SECONDS = 45.0
SAMPLE_INTERVAL = 5.0


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


def main() -> int:
    result: dict = {"stage": "authorised-0F-restore", "ec_ram_writes": [], "success": False}
    service = KernelService()
    device = None
    t = None

    try:
        service.create()
        service.start()
        device = WinRing0Device().open()
        emit({"event": "device_opened", "driver_version": hex(device.driver_version),
              "refcount": device.refcount})

        # ------------------------------------------- read-only preflight
        t = EcWriteTransport(device, allow_writes=False)      # writes OFF for preflight
        pre = snapshot(t)
        ws = _tr.windows_status()
        emit({"event": "preflight", "ec": pre, "windows": ws})

        checks, _ = probe.gate_readonly(_StaticEC(pre), ws, _tr.board_is_mrid6(), repeats=1)
        for c in checks:
            emit({"event": "check", **c.to_dict()})
        ro_ok = all(c.passed for c in checks if c.fatal)

        state = guard.load_state()
        same_as_prior_failure = False
        if state.get("poisoned"):
            # Clearing the poison is only allowed here, explicitly, because the
            # operator re-verified the live state by read-only inspection.
            same_as_prior_failure = "0E/0F validation aborted" in (state.get("poison_reason") or "")
            emit({"event": "guard_poisoned", "reason": state.get("poison_reason"),
                  "matches_prior_0E_run": same_as_prior_failure})

        if not ro_ok:
            raise Anomaly("read-only preflight failed; poison NOT cleared, nothing written")
        if not same_as_prior_failure:
            raise Anomaly("guard is poisoned for an unrecognised reason; refusing to clear")

        # The EC is expected to still be in the verified stop state from 0x0E.
        expect_stop = pre["mode"] == profile.STOP_MODE
        emit({"event": "preflight_pass", "mode": hex(pre["mode"]),
              "expected_stop_state": expect_stop,
              "note": "clearing guard after clean read-only verification"})
        guard.clear_poison("operator authorised 0x0F restore after read-only verification")

        # ------------------------------------------- the single 0x0F write
        t.allow_writes = True
        guard.begin_transaction([[SUBCMD_ADDRESS, RESTORE_SUBCOMMAND],
                                 [TRIGGER_ADDRESS, TRIGGER_VALUE]],
                                "10/0F restore normal policy, single submission")
        emit({"event": "submit_0F", "submissions": 1,
              "writes": [[f"{SUBCMD_ADDRESS:04X}", "0F"], [f"{TRIGGER_ADDRESS:04X}", "10"]]})
        t.write_xram(SUBCMD_ADDRESS, RESTORE_SUBCOMMAND)
        t.write_xram(TRIGGER_ADDRESS, TRIGGER_VALUE)
        polls = t.wait_mailbox_idle(POLL_SCHEDULE)
        emit({"event": "mailbox_idle_after_0F", "polls": polls})
        result["ec_ram_writes"] = [[f"{a:04X}", f"{v:02X}"] for a, v in t.bytes_written]

        # ------------------------------------------- settle-tolerant verify
        rows = []
        restored_mode = False
        restored_current = False
        charging_back = False
        deadline = time.monotonic() + SETTLE_SECONDS
        while True:
            s, w, b = snapshot(t), _tr.windows_status(), cim_first()
            row = {"ec": s, "windows": w,
                   "cim": {k: b.get(k) for k in
                           ("PowerOnline", "Charging", "Discharging", "ChargeRate",
                            "DischargeRate", "RemainingCapacity", "Voltage")},
                   "settled": {
                       "mode_00": s["mode"] == profile.NORMAL_MODE,
                       "requested_current_nonzero": not s["requested_current_zero"],
                       "ec_charging": bool(s["charging"]),
                       "windows_charging": w.get("charging") is True,
                       "charge_rate": b.get("ChargeRate"),
                   }}
            rows.append(row)
            emit({"event": "observe_restore", **row})

            restored_mode = row["settled"]["mode_00"]
            restored_current = row["settled"]["requested_current_nonzero"]
            charging_back = (row["settled"]["ec_charging"]
                             or row["settled"]["windows_charging"]
                             or (row["settled"]["charge_rate"] or 0) > 0)
            if (restored_mode and restored_current and charging_back) or time.monotonic() >= deadline:
                break
            time.sleep(SAMPLE_INTERVAL)

        result["restore_observations"] = rows
        result["mode_normal"] = restored_mode
        result["requested_current_nonzero"] = restored_current
        result["charging_recovered"] = charging_back
        result["success"] = bool(restored_mode and restored_current)

        emit({"event": "restore_verification",
              "mode_0x00": restored_mode,
              "requested_current_nonzero": restored_current,
              "charging_recovered": charging_back,
              "final_charge_rate": rows[-1]["cim"].get("ChargeRate") if rows else None,
              "pass": result["success"],
              "note": "0x8152=0x55 is never used alone as proof"})
        guard.complete_transaction({"phase": "0F_restore",
                                    "mode": rows[-1]["ec"]["mode"] if rows else None})
        emit({"event": "done", "success": result["success"]})
        return 0 if result["success"] else 3

    except BaseException as error:  # noqa: BLE001
        reason = f"{type(error).__name__}: {error}"
        result["error"] = reason
        try:
            guard.poison(f"0F restore aborted: {reason}")
            result["poisoned"] = True
        except Exception as poison_error:  # noqa: BLE001
            result["poison_error"] = str(poison_error)
        emit({"event": "aborted", "error": reason, "poisoned": True,
              "automatic_retry": False, "flush_attempted": False,
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
        out = Path(__file__).resolve().parent.parent / "logs" / "0f-restore-report.json"
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"report: {out}", flush=True)


class _StaticEC:
    def __init__(self, snapshot):
        self.base = snapshot

    def snapshot(self):
        return self.base

    def snapshot_repeated(self, repeats=1):
        return self.base, []


if __name__ == "__main__":
    sys.exit(main())
