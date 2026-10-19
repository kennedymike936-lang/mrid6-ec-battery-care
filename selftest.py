"""Hardware-free self-test of the ECGuard safety guarantees.

Runs entirely against a temporary state directory; performs NO EC I/O.
Verifies the properties the user explicitly demanded.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((passed, name, detail))


def main() -> int:
    # NOTE: deliberately NOT tempfile.mkdtemp(). The DSH file sandbox permits
    # writes to the temp store but denies creating files inside temp dirs that
    # were themselves just created, so mkdtemp causes a hang/EPERM. A
    # workspace-local state dir is inside the writable sandbox root.
    tmp = str(Path(__file__).resolve().parent / ".selftest-state")
    Path(tmp).mkdir(parents=True, exist_ok=True)
    os.environ["ECGUARD_STATE_DIR"] = tmp

    from ecguard import guard, profile, probe, transport  # noqa: E402

    # ---------------------------------------------------------- 1. write profile
    forbidden = [(profile.ADDR_MAILBOX_SUBCMD, 0x0C),
                 (0x83C0, 0x02), (0x83A0, 2), (0x837C, 0),
                 (profile.ADDR_MAILBOX_HIGH, 101), (profile.ADDR_MAILBOX_LOW, 0)]
    for address, value in forbidden:
        check(f"write_profile_rejects {address:04X}={value:02X}",
              (address, value) not in profile.WRITE_PROFILE,
              "not present in WRITE_PROFILE")

    check("0x0C_LEARN_absent_everywhere",
          all(v != 0x0C for _, v in profile.WRITE_PROFILE),
          f"profile values = {[f'{v:02X}' for _, v in profile.WRITE_PROFILE]}")

    check("every_write_address_is_a_mailbox_register",
          {a for a, _ in profile.WRITE_PROFILE} <=
          {profile.ADDR_MAILBOX_COMMAND, profile.ADDR_MAILBOX_SUBCMD,
           profile.ADDR_MAILBOX_HIGH, profile.ADDR_MAILBOX_LOW},
          "writes are confined to 0x8150-0x8154")

    # ------------------------------------------------------------- 2. profile
    check("accepts_EC_0.40", profile.version_is_accepted((0x00, 0x28, 0x00, 0x00)), "")
    check("accepts_EC_0.38", profile.version_is_accepted((0x00, 0x26, 0x00, 0x00)), "")
    check("rejects_unknown_EC_version",
          not profile.version_is_accepted((0x00, 0x27, 0x00, 0x00)), "0x27 refused")
    check("read_addresses_cover_required_registers",
          {0x8150, 0x8151, 0x8152, 0x8153, 0x8154, 0x83C0, 0x83A0, 0x83A1,
           0x83A2, 0x8370, 0x837C, 0x837D, 0x8460, 0x847C} <= set(profile.READ_ADDRESSES),
          f"{len(profile.READ_ADDRESSES)} audited read addresses")

    # --------------------------------------------------- 3. guard persistence
    state = guard.load_state()
    check("fresh_guard_not_poisoned", state.get("poisoned") is False, "")

    guard.poison("selftest simulated timeout")
    reloaded = guard.load_state()
    check("poison_persists_across_reload", reloaded.get("poisoned") is True,
          f"reason recorded: {reloaded.get('poison_reason')}")

    blocked = False
    try:
        guard.require_writable()
    except RuntimeError as error:
        blocked = "did not complete cleanly" in str(error)
    check("poisoned_guard_blocks_writes", blocked, "require_writable() raised")

    guard.clear_poison("selftest operator re-verified")
    try:
        guard.require_writable()
        check("cleared_guard_allows_writes", True, "")
    except RuntimeError as error:
        check("cleared_guard_allows_writes", False, str(error))

    # ------------------------------------------------------ 4. crash journal
    guard.begin_transaction([[0x8153, 80]], "selftest in-flight")
    in_flight = guard.load_state()["transaction"]
    check("transaction_journalled_before_write",
          in_flight.get("started_at") and in_flight.get("completed") is False, "")

    interrupted_blocked = False
    try:
        guard.require_writable()
    except RuntimeError as error:
        interrupted_blocked = "in-flight" in str(error)
    check("interrupted_transaction_blocks_next_write", interrupted_blocked,
          "an uncompleted journal entry forbids the next write")

    guard.complete_transaction({"mode": 0x48})
    try:
        guard.require_writable()
        check("completed_transaction_allows_writes", True, "")
    except RuntimeError as error:
        check("completed_transaction_allows_writes", False, str(error))

    ledger = guard.ledger_tail(50)
    check("ledger_records_events", len(ledger) >= 3,
          f"{len(ledger)} ledger entries: {[e.get('event') for e in ledger]}")

    # --------------------------------------------------------- 5. SOC gate
    good = {"soc": 70, "ac": True, "mailbox_command": 0, "mode": 0x00,
            "battery_present": True, "raw": {"8460": "07"}}
    checks = probe.gate_enable_0d(good, {"ac": True}, {"poisoned": False, "transaction": None})
    check("soc_70_enable_gate_passes", all(c.passed for c in checks),
          "; ".join(f"{c.name}={c.passed}" for c in checks))

    for soc in (80, 85, 97, 100):
        snap = dict(good, soc=soc)
        checks = probe.gate_enable_0d(snap, {"ac": True}, {"poisoned": False, "transaction": None})
        failed = [c.name for c in checks if not c.passed]
        check(f"soc_{soc}_enable_gate_refused",
              "soc_strictly_below_high" in failed,
              f"blocking checks: {failed}")

    snap = dict(good, soc=59)
    checks = probe.gate_enable_0d(snap, {"ac": True}, {"poisoned": False, "transaction": None})
    failed = [c.name for c in checks if not c.passed]
    check("soc_59_below_band_refused", "soc_in_target_band" in failed, f"{failed}")

    snap = dict(good, soc=79)
    checks = probe.gate_enable_0d(snap, {"ac": True}, {"poisoned": False, "transaction": None})
    check("soc_79_top_of_band_allowed", all(c.passed for c in checks), "")

    snap = dict(good)
    checks = probe.gate_enable_0d(snap, {"ac": False}, {"poisoned": False, "transaction": None})
    failed = [c.name for c in checks if not c.passed]
    check("ac_disconnected_refused", "windows_ac_connected" in failed, f"{failed}")

    checks = probe.gate_enable_0d(dict(good, mailbox_command=0x10), {"ac": True},
                                 {"poisoned": False, "transaction": None})
    failed = [c.name for c in checks if not c.passed]
    check("busy_mailbox_refused", "mailbox_idle" in failed, f"{failed}")

    checks = probe.gate_enable_0d(dict(good, mode=0x48), {"ac": True},
                                 {"poisoned": False, "transaction": None})
    failed = [c.name for c in checks if not c.passed]
    check("conflicting_mode_refused", "mode_not_conflicting" in failed, f"{failed}")

    checks = probe.gate_enable_0d(good, {"ac": True}, {"poisoned": True, "transaction": None})
    failed = [c.name for c in checks if not c.passed]
    check("poisoned_state_refused_in_gate", "guard_writable" in failed, f"{failed}")

    # ------------------------------------------------- 6. snapshot semantics
    raw = {a: 0 for a in profile.READ_ADDRESSES}
    raw[profile.ADDR_POWER_FLAGS] = 0x07
    raw[profile.ADDR_SOC] = 78
    raw[profile.ADDR_MODE] = profile.NATIVE_MODE
    raw[profile.ADDR_NATIVE_HIGH] = 80
    raw[profile.ADDR_NATIVE_LOW] = 60
    raw[profile.ADDR_MAILBOX_HIGH] = 80
    raw[profile.ADDR_MAILBOX_LOW] = 60
    raw[profile.ADDR_NATIVE_SUBSTATE] = 2
    raw[0x8411] = 0x26
    snap = profile.build_snapshot(raw)
    check("snapshot_decodes_power_flags",
          snap["ac"] and snap["battery_present"] and snap["charging"] and not snap["discharging"],
          f"0x8460=0x07 -> {snap['ac']},{snap['battery_present']},{snap['charging']},{snap['discharging']}")
    check("snapshot_detects_native_mode", snap["native_enabled"] is True, "")
    check("snapshot_reads_version_0.38", snap["version"] == [0x00, 0x26, 0x00, 0x00],
          f"{snap['version']}")

    # ------------------------------------------------- 7. backoff schedule
    polls = len(transport.POLL_SCHEDULE)
    total = sum(transport.POLL_SCHEDULE)
    check("poll_schedule_is_bounded", polls <= 20 and total < 3.0,
          f"{polls} polls, {total:.2f}s worst case (prototype: ~90 full transactions in 3s)")

    # ------------------------------------- 8. enable write path, offline
    # Exercises the REAL production submission function with a recording
    # stand-in, so the exact write order and the failure semantics are proven
    # without touching any hardware.
    from ecguard import cli  # noqa: E402

    class FakeEC:
        """Records every read/write; never touches the EC."""

        def __init__(self, ready_value=0, mode=0x00, final=None, fail_on=None):
            self.writes: list[tuple[int, int]] = []
            self.reads: list[int] = []
            self.poisoned = False
            self._ready = ready_value
            self._mode = mode
            self._final = final or {
                "mode": profile.NATIVE_MODE, "state": profile.NATIVE_STATE,
                "native_high": 80, "native_low": 60,
                "mailbox_result": profile.MAILBOX_RESULT_OK,
            }
            self._fail_on = fail_on

        def read(self, address):
            self.reads.append(address)
            if address == profile.ADDR_MAILBOX_COMMAND:
                return self._ready
            if address == profile.ADDR_MODE:
                return self._mode
            if address == profile.ADDR_MAILBOX_HIGH:
                return 0x50
            if address == profile.ADDR_MAILBOX_LOW:
                return 0x3C
            return 0

        def write(self, address, value):
            if self._fail_on == (address, value):
                raise RuntimeError("simulated transport failure")
            self.writes.append((address, value))

        def wait_mailbox_idle(self):
            return 3

        def snapshot(self):
            return dict(self._final)

    # -- 8a. happy path: exact order, exactly once
    guard.clear_poison("selftest")
    fake = FakeEC()
    rc = cli.run_native_submission(fake)
    expected = [
        (profile.ADDR_MAILBOX_HIGH, 80),
        (profile.ADDR_MAILBOX_LOW, 60),
        (profile.ADDR_MAILBOX_SUBCMD, profile.NATIVE_SUBCOMMAND),
        (profile.ADDR_MAILBOX_COMMAND, 0x10),
    ]
    check("enable_writes_exact_order", fake.writes == expected,
          f"{[(f'{a:04X}', f'{v:02X}') for a, v in fake.writes]}")
    check("enable_returns_success_on_good_verify", rc == 0, f"rc={rc}")
    check("enable_never_poisoned_on_success", fake.poisoned is False, "")

    # -- 8b. order invariant: trigger must be LAST and subcommand before it
    order_ok = (fake.writes[-1] == (profile.ADDR_MAILBOX_COMMAND, 0x10)
                and fake.writes[-2] == (profile.ADDR_MAILBOX_SUBCMD, profile.NATIVE_SUBCOMMAND))
    check("enable_trigger_is_last_write", order_ok, "subcommand then trigger")

    # -- 8c. busy mailbox -> abort BEFORE any write
    guard.clear_poison("selftest")
    fake = FakeEC(ready_value=0x10)
    rc = cli.run_native_submission(fake)
    check("enable_busy_mailbox_aborts_before_write",
          rc == 4 and fake.writes == [] and fake.poisoned is True,
          f"rc={rc} writes={fake.writes} poisoned={fake.poisoned}")

    # -- 8d. conflicting mode -> abort BEFORE any write
    guard.clear_poison("selftest")
    fake = FakeEC(mode=profile.NATIVE_MODE)
    rc = cli.run_native_submission(fake)
    check("enable_conflicting_mode_aborts_before_write",
          rc == 4 and fake.writes == [], f"rc={rc} writes={fake.writes}")

    # -- 8e. mid-sequence failure -> poison, no retry, no cleanup write
    guard.clear_poison("selftest")
    fake = FakeEC(fail_on=(profile.ADDR_MAILBOX_SUBCMD, profile.NATIVE_SUBCOMMAND))
    rc = cli.run_native_submission(fake)
    wrote_after_failure = [w for w in fake.writes
                           if w == (profile.ADDR_MAILBOX_COMMAND, 0x10)]
    check("enable_failure_poisons_and_never_triggers",
          rc == 4 and fake.poisoned is True and wrote_after_failure == [],
          f"rc={rc} poisoned={fake.poisoned} trigger_after_failure={wrote_after_failure}")
    check("enable_failure_is_durable_and_blocks_next_write",
          guard.load_state().get("poisoned") is True,
          "poison persisted to disk")

    # -- 8f. 0x8152=0x55 alone must NOT be treated as success
    guard.clear_poison("selftest")
    bad = {"mode": profile.NORMAL_MODE, "state": 4, "native_high": 0,
           "native_low": 0, "mailbox_result": profile.MAILBOX_RESULT_OK}
    fake = FakeEC(final=bad)
    rc = cli.run_native_submission(fake)
    check("enable_rejects_55_only_success", rc == 3,
          f"0x8152=0x55 but mode stayed 0x00 -> rc={rc} (expected 3)")

    guard.clear_poison("selftest cleanup")

    # --------------------------------- 9. authorised 0x0E/0x0F write framing
    from ecguard.ec_write import (  # noqa: E402
        PROFILE_0D, PROFILE_0E_0F, WRITE_PAIRS, Anomaly, EcWriteTransport,
        NotAuthorised,
    )

    class FakeDevice:
        """Records port traffic; simulates a ready EC (IBF clear, OBF set)."""

        def __init__(self):
            self.port_reads = 0
            self.port_writes = 0
            self.trace: list[tuple[str, int, int | None]] = []
            self.status = 0x00          # IBF clear, OBF clear

        def read_port_byte(self, port):
            self.port_reads += 1
            self.trace.append(("R", port, None))
            if port == 0x66:
                return self.status
            return 0x00

        def write_port_byte(self, port, value):
            self.port_writes += 1
            self.trace.append(("W", port, value))
            if port == 0x66 and value == 0x92:
                self.status = 0x01      # OBF set so Wait(OBF,OBF) returns
            elif port == 0x66 and value == 0x93:
                self.status = 0x00

    # -- 9a. writes refused unless explicitly enabled
    t = EcWriteTransport(FakeDevice(), allow_writes=False)
    refused = False
    try:
        t.write_xram(0x8151, 0x0E)
    except NotAuthorised:
        refused = True
    check("write_refused_when_not_enabled", refused, "allow_writes=False blocks 0x0E")

    # -- 9b. default profile (0E/0F) must refuse the native-threshold writes
    t = EcWriteTransport(FakeDevice(), allow_writes=True)
    for addr, val, label in (
        (0x8151, 0x0D, "native 0x0D subcommand not in default profile"),
        (0x8153, 0x50, "threshold 0x8153 not in default profile"),
        (0x8154, 0x3C, "threshold 0x8154 not in default profile"),
    ):
        blocked = False
        try:
            t.write_xram(addr, val)
        except NotAuthorised:
            blocked = True
        check(f"default_profile_refuses_{addr:04X}={val:02X}", blocked, label)

    # -- 9b2. 0x0C is refused in EVERY profile, permanently
    for profile_name, pairs in (("default", PROFILE_0E_0F), ("native", PROFILE_0D)):
        t = EcWriteTransport(FakeDevice(), allow_writes=True, allowed_pairs=pairs)
        blocked = False
        try:
            t.write_xram(0x8151, 0x0C)
        except NotAuthorised:
            blocked = True
        check(f"0x0C_refused_in_{profile_name}_profile", blocked,
              "LEARN/active-discharge permanently forbidden")

    # -- 9b3. native profile allows exactly its 4 writes and nothing else
    native_allowed = {(0x8153, 0x50), (0x8154, 0x3C), (0x8151, 0x0D), (0x8150, 0x10)}
    check("native_profile_is_exactly_four_writes", set(PROFILE_0D) == native_allowed,
          f"{sorted((f'{a:04X}', f'{v:02X}') for a, v in PROFILE_0D)}")
    t = EcWriteTransport(FakeDevice(), allow_writes=True, allowed_pairs=PROFILE_0D)
    for addr, val, label in (
        (0x8151, 0x0E, "stop subcommand not in native profile"),
        (0x8151, 0x0F, "restore subcommand not in native profile"),
        (0x8153, 0x51, "wrong high threshold (81)"),
        (0x8154, 0x3B, "wrong low threshold (59)"),
        (0x8151, 0x0C, "LEARN"),
        (0x83C0, 0x48, "internal mode register"),
        (0x83A0, 2, "internal substate"),
        (0x83A1, 0x50, "native upper copy"),
        (0x83A2, 0x3C, "native lower copy"),
        (0x837C, 0, "requested-current register"),
    ):
        blocked = False
        try:
            t.write_xram(addr, val)
        except NotAuthorised:
            blocked = True
        check(f"native_refuses_{addr:04X}={val:02X}", blocked, label)

    # -- 9b4. the 4 native writes frame correctly, trigger last
    dev = FakeDevice()
    t = EcWriteTransport(dev, allow_writes=True, allowed_pairs=PROFILE_0D)
    for addr, val in ((0x8153, 0x50), (0x8154, 0x3C), (0x8151, 0x0D), (0x8150, 0x10)):
        t.write_xram(addr, val)
    check("native_four_writes_in_order",
          t.bytes_written == [(0x8153, 0x50), (0x8154, 0x3C), (0x8151, 0x0D), (0x8150, 0x10)],
          f"{[(f'{a:04X}', f'{v:02X}') for a, v in t.bytes_written]}")
    check("native_trigger_is_last", t.bytes_written[-1] == (0x8150, 0x10),
          "0x8150 written last")
    data_writes = [f for f in dev.trace if f[0] == "W" and f[1] == 0x62]
    check("native_writes_only_0x93_command",
          all(f[2] == 0x93 for f in dev.trace if f[0] == "W" and f[1] == 0x66),
          "no other command byte emitted")

    # -- 9b5. unauthorised legacy 0x0D-style internal writes still refused
    t = EcWriteTransport(FakeDevice(), allow_writes=True, allowed_pairs=PROFILE_0D)
    for addr, val, label in (
        (0x83C0, 0x02, "internal mode register 0x83C0"),
        (0x83A0, 2, "internal substate 0x83A0"),
        (0x837C, 0, "requested-current register"),
        (0x8152, 0x55, "mailbox result register"),
        (0x847C, 0, "SOC register"),
    ):
        blocked = False
        try:
            t.write_xram(addr, val)
        except NotAuthorised:
            blocked = True
        check(f"write_refuses_{addr:04X}={val:02X}", blocked, label)

    check("write_profile_has_no_0C",
          all(v != 0x0C for _, v in WRITE_PAIRS), "")

    # -- 9c. authorised pair frames correctly and is accounted for
    dev = FakeDevice()
    t = EcWriteTransport(dev, allow_writes=True)
    t.write_xram(0x8151, 0x0E)
    t.write_xram(0x8150, 0x10)
    frames = [f for f in dev.trace if f[0] == "W"]
    # each write: 0x66<-0x93, 0x62<-hi, 0x62<-lo, 0x62<-value
    check("write_framing_uses_0x93",
          all(f[2] == 0x93 for f in frames if f[1] == 0x66),
          f"commands emitted: {[hex(f[2]) for f in frames if f[1] == 0x66]}")
    check("write_framing_address_hi_lo_value",
          [f[2] for f in frames if f[1] == 0x62][:3] == [0x81, 0x51, 0x0E]
          and [f[2] for f in frames if f[1] == 0x62][3:6] == [0x81, 0x50, 0x10],
          "hi,lo,value ordering verified for both writes")
    check("write_ledger_records_only_authorised_pairs",
          t.bytes_written == [(0x8151, 0x0E), (0x8150, 0x10)],
          f"{[(f'{a:04X}', f'{v:02X}') for a, v in t.bytes_written]}")
    check("write_counters_correct",
          t.ec_ram_writes == 2 and t.write_transactions == 2 and t.timeouts == 0,
          f"ec_ram_writes={t.ec_ram_writes} write_txns={t.write_transactions}")

    # -- 9d. a full 0x0E + verify + 0x0F sequence uses exactly the 4 authorised writes
    dev = FakeDevice()
    t = EcWriteTransport(dev, allow_writes=True)
    t.write_xram(0x8151, 0x0E); t.write_xram(0x8150, 0x10)
    t.write_xram(0x8151, 0x0F); t.write_xram(0x8150, 0x10)
    check("full_0E_0F_sequence_is_four_writes",
          t.bytes_written == [(0x8151, 0x0E), (0x8150, 0x10),
                              (0x8151, 0x0F), (0x8150, 0x10)],
          f"{[(f'{a:04X}', f'{v:02X}') for a, v in t.bytes_written]}")

    # ------------------------------------------------------------ report
    width = max(len(name) for _, name, _ in RESULTS)
    failures = 0
    print("ECGuard self-test (no hardware, no EC I/O)\n" + "=" * 78)
    for passed, name, detail in RESULTS:
        if not passed:
            failures += 1
        print(f"[{'PASS' if passed else 'FAIL'}] {name:<{width}}  {detail}")
    print("=" * 78)
    print(f"{len(RESULTS) - failures}/{len(RESULTS)} checks passed")
    print(f"state dir used: {tmp}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
