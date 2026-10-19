"""MRID6 / BM5235 EC profile, including the explicit EC 0.38 entry.

WHY 0.38 IS TRUSTED (evidence chain, no hand-waving)
----------------------------------------------------
The only firmware images available are EC 0.35 and EC 0.40. Their entire
difference is 15 bytes, and every register-access site that the 0x10/0x0D
native-threshold feature depends on lies outside those bytes:

  * 15 differing bytes, in 9 runs:
      0x0004A-0x0004B   f153 -> d0de
      0x071B7-0x071B8   3a3a -> 3535   (x4 parameter tables)
      0x071F3-0x071F4
      0x0722F-0x07230
      0x0726B-0x0726C
      0x08036           33   -> 38     (version digit)
      0x08040           23   -> 28     (version "00.23" -> "00.28")
      0x0804F           31   -> 38     (date "2024/01/10" -> "2024/08/02")
      0x08051-0x08052   3130 -> 3032
  * All 19 audited register-access sites are OUTSIDE those runs (0/19 hit).
  * These regions are byte-identical between 0.35 and 0.40:
      0x00700-0x00800  switch helper
      0x00900-0x00A80  host command dispatcher (92/93/DC/F0)
      0x02F00-0x03000  control check
      0x03E00-0x03F40  native state machine + scheduler
      0x04400-0x04500  requested-current clear
      0x04500-0x04700  native threshold copy + mailbox
      0x04A00-0x04C00  mailbox transaction handlers

Reproduce with:  ecguard/../audit-src/ec_profile_static.py

WHAT THIS DOES *NOT* PROVE
--------------------------
Because no EC 0.38 image exists, this is inference from 0.35<->0.40 identity,
not a direct byte-level comparison of 0.38. It is therefore a *conditional*
acceptance: version 0.38 is admitted only after live_readonly_gate() confirms
on the real machine that every register this profile touches behaves exactly
as the analyzed firmware semantics require. Live evidence, not the version
number, is what authorises the write path.
"""
from __future__ import annotations

# ---------------------------------------------------------------- identities
EXPECTED_VERSION_040 = (0x00, 0x28, 0x00, 0x00)   # directly verified upstream
EXPECTED_VERSION_038 = (0x00, 0x26, 0x00, 0x00)   # this machine; inferred

VERSION_PROVENANCE = {
    EXPECTED_VERSION_040: "direct: ec_40.bin analyzed and verified live by upstream",
    EXPECTED_VERSION_038: "inferred: 0.35/0.40 charging code byte-identical; "
                          "admitted only after live read-only semantic gate",
}

# Firmware-internal version string bytes (ec_35 -> 0x33, ec_40 -> 0x38), read
# from file offset 0x08036. Used only as a secondary corroboration during the
# read-only probe; not a gate on its own.
KNOWN_FIRMWARE_VERSION_BYTES = {0x33, 0x38}

# ------------------------------------------------------------ XRAM addresses
ADDR_MAILBOX_COMMAND = 0x8150   # 0 = idle, 0x10 = battery group command
ADDR_MAILBOX_SUBCMD = 0x8151    # 0x0D native thresholds, 0x0E stop, 0x0F resume
ADDR_MAILBOX_RESULT = 0x8152    # 0x55 = handler returned (NOT proof of effect)
ADDR_MAILBOX_HIGH = 0x8153      # native upper threshold (80 -> 0x50)
ADDR_MAILBOX_LOW = 0x8154       # native lower threshold (60 -> 0x3C)

ADDR_MODE = 0x83C0              # 0x00 normal, 0x02 stop, 0x48 native thresholds
ADDR_SCHED_STATE = 0x8370       # 0x32 = native hold, 0x31 = stop, 0x04/0x10 normal
ADDR_NATIVE_SUBSTATE = 0x83A0   # 1 init/discharge, 2 hold(stopped), 3 allow charge
ADDR_NATIVE_HIGH = 0x83A1       # copy of 0x8153
ADDR_NATIVE_LOW = 0x83A2        # copy of 0x8154
ADDR_AUX_STATE = 0x8394
ADDR_AUX_STATE2 = 0x8395
ADDR_REQ_CURRENT_HI = 0x837C    # firmware requested-current buffer (not a measurement)
ADDR_REQ_CURRENT_LO = 0x837D
ADDR_POWER_FLAGS = 0x8460       # bit0 AC, bit1 battery present, bit2 charging, bit3 discharging
ADDR_SOC = 0x847C               # state of charge, percent
ADDR_VERSION = tuple(range(0x8410, 0x8414))

# Every address this tool is permitted to read. Anything else is a bug.
READ_ADDRESSES = frozenset(
    {ADDR_MAILBOX_COMMAND, ADDR_MAILBOX_SUBCMD, ADDR_MAILBOX_RESULT,
     ADDR_MAILBOX_HIGH, ADDR_MAILBOX_LOW,
     ADDR_MODE, ADDR_SCHED_STATE, ADDR_NATIVE_SUBSTATE,
     ADDR_NATIVE_HIGH, ADDR_NATIVE_LOW,
     ADDR_AUX_STATE, ADDR_AUX_STATE2,
     ADDR_REQ_CURRENT_HI, ADDR_REQ_CURRENT_LO,
     ADDR_POWER_FLAGS, ADDR_SOC}
    | set(ADDR_VERSION)
)

# The complete set of byte sequences this project will ever transmit.
# 0x8151=0x0C (active discharge / LEARN) is deliberately ABSENT and must stay so.
WRITE_PROFILE = {
    (ADDR_MAILBOX_HIGH, 80): "native threshold upper (80%)",
    (ADDR_MAILBOX_LOW, 60): "native threshold lower (60%)",
    (ADDR_MAILBOX_SUBCMD, 0x0D): "native threshold subcommand",
    (ADDR_MAILBOX_SUBCMD, 0x0E): "audited stop subcommand",
    (ADDR_MAILBOX_SUBCMD, 0x0F): "audited resume/normal subcommand",
    (ADDR_MAILBOX_COMMAND, 0x10): "battery group main command trigger",
}
PARAMETER_ADDRESSES = frozenset({ADDR_MAILBOX_HIGH, ADDR_MAILBOX_LOW})

# Admissible mailbox subcommands for the native configuration, in order.
NATIVE_SUBCOMMAND = 0x0D
NATIVE_MODE = 0x48
NATIVE_STATE = 0x32
NATIVE_SUBSTATE_HOLD = 2
NATIVE_SUBSTATE_CHARGE = 3
NATIVE_SUBSTATE_INIT = 1

STOP_MODE = 0x02
NORMAL_MODE = 0x00
KNOWN_MODES = frozenset({NORMAL_MODE, STOP_MODE, NATIVE_MODE})

MAILBOX_RESULT_OK = 0x55

# Target policy, fixed by the user's requirement.
TARGET_LOW = 60
TARGET_HIGH = 80
# Enabling 0x0D is only permitted strictly below the upper threshold, because
# SOC >= high enters the firmware's active-discharge initialisation branch.
ENABLE_SOC_MAX_EXCLUSIVE = 80

# --------------------------------------------------------------- flag decode
POWER_AC = 0x01
POWER_BATTERY_PRESENT = 0x02
POWER_CHARGING = 0x04
POWER_DISCHARGING = 0x08

SOC_TOLERANCE = 5          # EC vs Windows SOC must agree within this
READ_STABILITY_REPEATS = 3  # identical reads required to call a register stable


class ProfileError(RuntimeError):
    """Raised when the machine does not match the accepted EC profile."""


def version_is_accepted(version) -> bool:
    return tuple(version) in VERSION_PROVENANCE


def decode_power(flags: int) -> dict:
    return {
        "ac": bool(flags & POWER_AC),
        "battery_present": bool(flags & POWER_BATTERY_PRESENT),
        "charging": bool(flags & POWER_CHARGING),
        "discharging": bool(flags & POWER_DISCHARGING),
    }


def build_snapshot(raw: dict[int, int]) -> dict:
    """Turn a raw address->byte map into the semantic snapshot used by gates."""
    flags = raw[ADDR_POWER_FLAGS]
    power = decode_power(flags)
    return {
        "version": [raw[a] for a in ADDR_VERSION],
        "soc": raw[ADDR_SOC],
        "mode": raw[ADDR_MODE],
        "state": raw[ADDR_SCHED_STATE],
        "mailbox_command": raw[ADDR_MAILBOX_COMMAND],
        "mailbox_subcommand": raw[ADDR_MAILBOX_SUBCMD],
        "mailbox_result": raw[ADDR_MAILBOX_RESULT],
        "mailbox_high": raw[ADDR_MAILBOX_HIGH],
        "mailbox_low": raw[ADDR_MAILBOX_LOW],
        "native_substate": raw[ADDR_NATIVE_SUBSTATE],
        "native_high": raw[ADDR_NATIVE_HIGH],
        "native_low": raw[ADDR_NATIVE_LOW],
        "aux_state": raw[ADDR_AUX_STATE],
        "aux_state2": raw[ADDR_AUX_STATE2],
        "requested_current_zero": raw[ADDR_REQ_CURRENT_HI] == 0 and raw[ADDR_REQ_CURRENT_LO] == 0,
        "native_enabled": raw[ADDR_MODE] == NATIVE_MODE,
        **power,
        "raw": {f"{a:04X}": f"{v:02X}" for a, v in sorted(raw.items())},
    }
