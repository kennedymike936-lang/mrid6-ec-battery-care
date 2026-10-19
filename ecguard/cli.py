"""ECGuard CLI - MRID6 EC 0.38 native 60/80 battery-care mode.

Subcommands
  guard-status : show poison flag / transaction journal / ledger tail. No EC I/O.
  inspect      : READ-ONLY sweep + precondition gate. Never writes.
  enable       : submit 10/0D (high 80, low 60) EXACTLY ONCE, then verify.
  disable      : submit 10/0F to return to factory policy.
  verify       : read-only post-configuration verification sweep.

Safety contract
  * enable refuses unless every gate passes; it never auto-discharges to reach
    the SOC band and never retries an interrupted transaction.
  * Any timeout/uncertainty poisons the guard file and blocks future writes
    until a human re-verifies with 'inspect' and clears it explicitly.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import guard, profile, probe, transport


def emit(entry: dict) -> None:
    record = {"time": __import__("datetime").datetime.now().astimezone().isoformat(), **entry}
    print(json.dumps(record, ensure_ascii=False), flush=True)


def report(checks: list[probe.Check]) -> bool:
    ok = True
    for check in checks:
        emit({"event": "check", **check.to_dict()})
        if not check.passed and check.fatal:
            ok = False
    return ok


def _open(allow_writes: bool):
    """Hold the global mutex for the whole session, then open the bridge."""
    session = transport.SingleInstance()
    session.__enter__()
    bridge = transport.Bridge(allow_writes=allow_writes)
    try:
        bridge.open()
    except BaseException:
        session.__exit__(None, None, None)
        raise
    return session, bridge


def cmd_guard_status(_args) -> int:
    state = guard.load_state()
    emit({"event": "guard_state", **state})
    for entry in guard.ledger_tail(20):
        emit({"event": "ledger", **entry})
    return 0


def cmd_inspect(args) -> int:
    session, bridge = _open(allow_writes=False)
    try:
        ec = transport.EC(bridge)
        windows = transport.windows_status()
        board = transport.board_is_mrid6()
        emit({"event": "board", **board})
        emit({"event": "windows", **windows})
        emit({"event": "cim_telemetry", **transport.cim_battery_telemetry()})
        checks, evidence = probe.gate_readonly(ec, windows, board, repeats=args.repeats)
        ok = report(checks)
        emit({"event": "readonly_gate", "pass": ok, "poisoned": ec.poisoned,
              "ec_version": evidence["snapshot"]["version"],
              "soc": evidence["snapshot"]["soc"],
              "mode": evidence["snapshot"]["mode"],
              "note": "read-only; no EC address was written"})
        if args.clear_guard_after_inspection and ok and not ec.poisoned:
            guard.clear_poison("read-only inspection passed after explicit operator request")
            emit({"event": "guard_cleared",
                  "reason": "read-only inspection passed; operator asked to clear"})
        return 0 if ok else 2
    finally:
        bridge.close()
        session.__exit__(None, None, None)


def cmd_verify(args) -> int:
    """Read-only verification sweep; used after enable and for acceptance."""
    session, bridge = _open(allow_writes=False)
    try:
        ec = transport.EC(bridge)
        windows = transport.windows_status()
        for index in range(args.samples):
            snap = ec.snapshot()
            telemetry = transport.cim_battery_telemetry()
            emit({"event": "verify_sample", "index": index, "ec": snap,
                  "windows": windows, "cim": telemetry})
            if index + 1 < args.samples:
                time.sleep(args.interval)
        return 0
    finally:
        bridge.close()
        session.__exit__(None, None, None)


def cmd_enable(args) -> int:
    # Guard is checked before we even open a transport.
    state = guard.require_writable()

    session, bridge = _open(allow_writes=True)
    try:
        ec = transport.EC(bridge)
        windows = transport.windows_status()
        board = transport.board_is_mrid6()

        emit({"event": "board", **board})
        emit({"event": "windows", **windows})

        checks, evidence = probe.gate_readonly(ec, windows, board, repeats=args.repeats)
        if not report(checks):
            emit({"event": "abort", "stage": "readonly_gate",
                  "reason": "read-only precondition gate failed; nothing was written"})
            return 2

        snap = evidence["snapshot"]
        emit({"event": "pre_write_snapshot", "ec": snap})

        enable_checks = probe.gate_enable_0d(snap, windows, guard.load_state())
        if not report(enable_checks):
            soc = snap["soc"]
            if soc >= profile.ENABLE_SOC_MAX_EXCLUSIVE:
                emit({"event": "abort", "stage": "soc_gate",
                      "reason": "请先正常使用电脑，把电量降到 60%～79%，然后重新运行。",
                      "soc": soc,
                      "why": "SOC >= 80 would enter the firmware active-discharge "
                             "initialisation branch; this tool will not discharge for you"})
            else:
                emit({"event": "abort", "stage": "enable_gate",
                      "reason": "enable preconditions not met; nothing was written"})
            return 2

        # -------- single submission, journalled before the first byte --------
        # Extracted so the exact production ordering and guards can be exercised
        # offline (see selftest.py) without any EC access.
        return run_native_submission(ec, transport)
    finally:
        bridge.close()
        session.__exit__(None, None, None)


def run_native_submission(ec, transport_module=transport) -> int:
    """Submit native 10/0D (high 80, low 60) EXACTLY ONCE, then verify.

    Order is fixed and must never change: parameters -> subcommand -> trigger.
    On any failure: poison, no retry, no cleanup write, no re-run.

    `ec` may be the real transport.EC or a recording stand-in; this function
    never touches hardware directly, which is what makes the exact production
    ordering testable offline (see selftest.py).
    """
    plan = [
        [profile.ADDR_MAILBOX_HIGH, profile.TARGET_HIGH],
        [profile.ADDR_MAILBOX_LOW, profile.TARGET_LOW],
        [profile.ADDR_MAILBOX_SUBCMD, profile.NATIVE_SUBCOMMAND],
        [profile.ADDR_MAILBOX_COMMAND, 0x10],
    ]
    guard.begin_transaction(plan, "native 0x0D thresholds 80/60, single submission")
    emit({"event": "submitting", "plan": [[f"{a:04X}", f"{v:02X}"] for a, v in plan],
          "submissions": 1})

    written = 0
    try:
        # Guard again immediately before the first write.
        if ec.read(profile.ADDR_MAILBOX_COMMAND) != 0:
            raise transport_module.TransportError("mailbox became busy before submission")
        if ec.read(profile.ADDR_MODE) not in (profile.NORMAL_MODE, profile.STOP_MODE):
            raise transport_module.TransportError("mode changed before submission")

        ec.write(profile.ADDR_MAILBOX_HIGH, profile.TARGET_HIGH); written += 1
        ec.write(profile.ADDR_MAILBOX_LOW, profile.TARGET_LOW); written += 1
        # read-back of the staged parameters before arming
        readback_high = ec.read(profile.ADDR_MAILBOX_HIGH)
        readback_low = ec.read(profile.ADDR_MAILBOX_LOW)
        if readback_high != profile.TARGET_HIGH or readback_low != profile.TARGET_LOW:
            raise transport_module.TransportError(
                f"parameter read-back mismatch: {readback_high}/{readback_low}")
        ec.write(profile.ADDR_MAILBOX_SUBCMD, profile.NATIVE_SUBCOMMAND); written += 1
        ec.write(profile.ADDR_MAILBOX_COMMAND, 0x10); written += 1
        guard.mark_bytes_written(written)

        polls = ec.wait_mailbox_idle()
        emit({"event": "mailbox_idle_after_submit", "polls": polls})

        after = ec.snapshot()
        emit({"event": "post_submit_snapshot", "ec": after})

        result_ok = after["mailbox_result"] == profile.MAILBOX_RESULT_OK
        mode_ok = after["mode"] == profile.NATIVE_MODE
        copies_ok = (after["native_high"] == profile.TARGET_HIGH
                     and after["native_low"] == profile.TARGET_LOW)
        emit({"event": "verification", "submitted_once": True,
              "bytes_written": written,
              "mailbox_result_ok": result_ok,
              "mode_is_native": mode_ok,
              "native_copies_match": copies_ok,
              "note": "0x8152=0x55 alone is NOT treated as success"})
        guard.complete_transaction({"mode": after["mode"], "state": after["state"],
                                    "native_high": after["native_high"],
                                    "native_low": after["native_low"],
                                    "result": after["mailbox_result"]})
        return 0 if (result_ok and mode_ok and copies_ok) else 3
    except BaseException as error:
        # Never retry, never clean up, never re-run.
        ec.poisoned = True
        guard.poison(f"0x0D submission failed after {written} byte(s): {error}",
                     transaction=guard.load_state().get("transaction"))
        emit({"event": "poisoned", "error": str(error), "bytes_written": written,
              "automatic_retry": False, "cleanup_write_attempted": False,
              "note": "EC state is uncertain. Do NOT re-run enable. "
                      "Run 'inspect' to read the live state, then decide."})
        return 4


def cmd_disable(_args) -> int:
    guard.require_writable()
    session, bridge = _open(allow_writes=True)
    try:
        ec = transport.EC(bridge)
        snap = ec.snapshot()
        emit({"event": "before", "ec": snap})
        if snap["mode"] == profile.NORMAL_MODE:
            emit({"event": "complete", "note": "already in normal mode; nothing written"})
            return 0
        guard.begin_transaction([[profile.ADDR_MAILBOX_SUBCMD, 0x0F],
                                 [profile.ADDR_MAILBOX_COMMAND, 0x10]],
                                "explicit restore to factory policy")
        try:
            ec.write(profile.ADDR_MAILBOX_SUBCMD, 0x0F)
            ec.write(profile.ADDR_MAILBOX_COMMAND, 0x10)
            ec.wait_mailbox_idle()
            after = ec.snapshot()
            emit({"event": "after", "ec": after})
            guard.complete_transaction({"mode": after["mode"]})
            return 0
        except BaseException as error:
            ec.poisoned = True
            guard.poison(f"0x0F restore failed: {error}")
            emit({"event": "poisoned", "error": str(error), "automatic_retry": False})
            return 4
    finally:
        bridge.close()
        session.__exit__(None, None, None)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("guard-status").set_defaults(func=cmd_guard_status)

    p = sub.add_parser("inspect", help="read-only sweep and precondition gate")
    p.add_argument("--repeats", type=int, default=profile.READ_STABILITY_REPEATS)
    p.add_argument("--clear-guard-after-inspection", action="store_true")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("verify", help="read-only post-configuration verification")
    p.add_argument("--samples", type=int, default=5)
    p.add_argument("--interval", type=float, default=10.0)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("enable", help="submit native 10/0D thresholds once")
    p.add_argument("--repeats", type=int, default=profile.READ_STABILITY_REPEATS)
    p.set_defaults(func=cmd_enable)

    sub.add_parser("disable").set_defaults(func=cmd_disable)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except transport.TransportError as error:
        emit({"event": "transport_error", "error": str(error), "automatic_retry": False})
        return 5
    except RuntimeError as error:
        emit({"event": "refused", "error": str(error), "automatic_retry": False})
        return 6


if __name__ == "__main__":
    sys.exit(main())
