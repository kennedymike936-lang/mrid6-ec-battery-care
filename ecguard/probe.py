"""Read-only verification gates.

Two levels:
  * gate_readonly()  - the 8 checks from the brief. Must all pass before the
    machine is considered profile-compatible at all.
  * gate_enable_0d() - the additional conditions that must hold before the
    single 0x0D submission is allowed.
"""
from __future__ import annotations

from . import profile


class Check:
    def __init__(self, name: str, passed: bool, detail: str, fatal: bool = True):
        self.name, self.passed, self.detail, self.fatal = name, passed, detail, fatal

    def to_dict(self) -> dict:
        return {"check": self.name, "pass": self.passed, "detail": self.detail,
                "fatal": self.fatal}

    def __repr__(self) -> str:
        return f"{'PASS' if self.passed else ('FAIL' if self.fatal else 'WARN')}  {self.name}: {self.detail}"


def gate_readonly(ec, windows: dict, board: dict, repeats: int = 3) -> tuple[list[Check], dict]:
    """Run every read-only precondition. Returns (checks, evidence)."""
    checks: list[Check] = []

    snap, unstable = ec.snapshot_repeated(repeats)

    # 1. EC version is an accepted profile entry
    version = tuple(snap["version"])
    if version in profile.VERSION_PROVENANCE:
        checks.append(Check("ec_version_accepted", True,
                            f"{list(version)} - {profile.VERSION_PROVENANCE[version]}"))
    else:
        checks.append(Check("ec_version_accepted", False,
                            f"{list(version)} is not in the accepted profile set "
                            f"{[list(v) for v in profile.VERSION_PROVENANCE]}"))

    # 2. Platform really is MRID6
    checks.append(Check("platform_is_mrid6", bool(board.get("ok")),
                        f"{board.get('SystemManufacturer')} / {board.get('SystemProductName')} / "
                        f"{board.get('BaseBoardProduct')} / BIOS {board.get('BIOSVersion')}"))

    # 3. mailbox idle
    checks.append(Check("mailbox_idle", snap["mailbox_command"] == 0,
                        f"0x8150 = 0x{snap['mailbox_command']:02X}"))

    # 4. mode is a known legal state
    checks.append(Check("mode_known", snap["mode"] in profile.KNOWN_MODES,
                        f"0x83C0 = 0x{snap['mode']:02X} "
                        f"(known: {[hex(m) for m in sorted(profile.KNOWN_MODES)]})"))

    # 5. AC state agrees between EC and Windows
    checks.append(Check("ac_consistent",
                        windows.get("ac") is not None and snap["ac"] == windows["ac"],
                        f"EC={snap['ac']} Windows={windows.get('ac')}"))

    # 6. SOC agrees within tolerance
    soc_delta = None if windows.get("soc") is None else abs(snap["soc"] - windows["soc"])
    checks.append(Check("soc_consistent",
                        soc_delta is not None and soc_delta <= profile.SOC_TOLERANCE,
                        f"EC={snap['soc']}% Windows={windows.get('soc')}% delta={soc_delta}"))

    # 7. battery present, both views
    checks.append(Check("battery_present",
                        bool(snap["battery_present"]) and windows.get("battery_present") is True,
                        f"EC={snap['battery_present']} Windows={windows.get('battery_present')}"))

    # 8. all status registers readable and stable across repeats
    checks.append(Check("registers_stable", not unstable,
                        "all audited registers bit-identical across "
                        f"{repeats} full sweeps" if not unstable else f"unstable: {unstable}"))

    # --- additional semantic invariants (cheap, and catch a wrong register map)
    checks.append(Check("soc_in_range", 0 <= snap["soc"] <= 100,
                        f"SOC byte = {snap['soc']}"))
    checks.append(Check("power_flags_plausible",
                        bool(snap["battery_present"]) or snap["ac"],
                        f"0x8460 = 0x{int(snap['raw']['8460'], 16):02X} "
                        f"(AC={snap['ac']} batt={snap['battery_present']})"))
    checks.append(Check("not_charging_and_discharging",
                        not (snap["charging"] and snap["discharging"]),
                        f"charging={snap['charging']} discharging={snap['discharging']}"))

    # If native mode is already active, the copies must mirror the mailbox.
    if snap["mode"] == profile.NATIVE_MODE:
        checks.append(Check("native_copies_match_mailbox",
                            snap["native_high"] == snap["mailbox_high"]
                            and snap["native_low"] == snap["mailbox_low"],
                            f"mailbox {snap['mailbox_high']}/{snap['mailbox_low']} vs "
                            f"83A1/83A2 {snap['native_high']}/{snap['native_low']}"))
    else:
        checks.append(Check("native_copies_expected_inactive",
                            snap["native_substate"] == 0,
                            f"mode=0x{snap['mode']:02X}, 83A0=0x{snap['native_substate']:02X}"))

    evidence = {
        "snapshot": snap,
        "windows": windows,
        "board": board,
        "unstable_registers": unstable,
        "soc_delta": soc_delta,
        "repeats": repeats,
    }
    return checks, evidence


def gate_enable_0d(snap: dict, windows: dict, guard_state: dict) -> list[Check]:
    """Extra conditions required before submitting 10/0D = 60/80."""
    checks: list[Check] = []

    soc = snap["soc"]
    below = soc < profile.ENABLE_SOC_MAX_EXCLUSIVE
    checks.append(Check("soc_strictly_below_high", below,
                        f"SOC={soc}% must be < {profile.ENABLE_SOC_MAX_EXCLUSIVE}% "
                        f"(guards the 0x0D active-discharge initialisation branch)"))
    checks.append(Check("soc_in_target_band",
                        profile.TARGET_LOW <= soc <= profile.ENABLE_SOC_MAX_EXCLUSIVE - 1,
                        f"SOC={soc}% must be in {profile.TARGET_LOW}..{profile.ENABLE_SOC_MAX_EXCLUSIVE - 1}%"))
    checks.append(Check("ac_connected", bool(snap["ac"]), f"EC reports AC={snap['ac']}"))
    checks.append(Check("windows_ac_connected", windows.get("ac") is True,
                        f"Windows reports AC={windows.get('ac')}"))
    checks.append(Check("mailbox_idle", snap["mailbox_command"] == 0,
                        f"0x8150 = 0x{snap['mailbox_command']:02X}"))
    checks.append(Check("mode_not_conflicting",
                        snap["mode"] in (profile.NORMAL_MODE, profile.STOP_MODE),
                        f"0x83C0 = 0x{snap['mode']:02X}; refusing to overwrite an unknown controller"))
    checks.append(Check("battery_present", bool(snap["battery_present"]),
                        f"battery_present={snap['battery_present']}"))
    txn = guard_state.get("transaction") or {}
    guard_clean = not guard_state.get("poisoned") and not txn.get("started_at")
    checks.append(Check("guard_writable", guard_clean,
                        "guard state clean" if guard_clean
                        else f"guard blocked: poisoned={guard_state.get('poisoned')} "
                             f"txn_started={txn.get('started_at')} "
                             f"reason={guard_state.get('poison_reason')}"))
    return checks
