"""Minimal write-framing transport for the authorised 10/0E and 10/0F only.

AUTHORISED SCOPE (this stage)
-----------------------------
  * 0x8151 = 0x0E   then   0x8150 = 0x10      (stop charging)
  * 0x8151 = 0x0F   then   0x8150 = 0x10      (restore normal policy)

EXPLICITLY NOT IMPLEMENTED HERE
-------------------------------
  * 0x0D native thresholds -- this stage is not authorised for it, so the
    subcommand is refused outright even if asked for.
  * 0x0C (LEARN / active discharge) -- refused.
  * 0x8153 / 0x8154 (threshold parameters) -- refused, not in this stage's profile.
  * Any address outside 0x8150/0x8151 -- refused.
  * Any other subcommand -- refused.

Frame (same semantics as the audited prototype):
  READ  (0x92): OUT 0x66,0x92 -> hi -> lo -> wait OBF -> IN 0x62   (has result byte)
  WRITE (0x93): OUT 0x66,0x93 -> hi -> lo -> data -> wait IBF clear (NO result byte)
"""
from __future__ import annotations

import time

CMD_READ = 0x92
CMD_WRITE = 0x93
PORT_DATA = 0x62
PORT_CMD = 0x66

IBF = 0x02
OBF = 0x01
STATUS_BUSY_MASK = 0x23

WAIT_TIMEOUT = 0.25

# The complete set of (address, value) pairs this module will ever place on the wire.
#
# Stage 1 (0E/0F validation) used only the first three.
# Stage 2 (native threshold enable, explicitly authorised) adds the 0x0D group,
# submitted in the order: parameters -> subcommand -> trigger.
WRITE_PAIRS = {
    # -- native threshold configuration (0x0D) --
    (0x8153, 0x50): "native upper threshold = 80",
    (0x8154, 0x3C): "native lower threshold = 60",
    (0x8151, 0x0D): "native threshold subcommand",
    # -- stop / resume --
    (0x8151, 0x0E): "stop-charging subcommand",
    (0x8151, 0x0F): "restore-normal subcommand",
    # -- shared trigger, always written LAST --
    (0x8150, 0x10): "battery group main command trigger",
}

# Permanently refused, regardless of authorisation.
REFUSED_SUBCOMMANDS = {
    0x0C: "LEARN/active-discharge is permanently forbidden",
}

# Selects which subsets a given stage may use.
PROFILE_0E_0F = frozenset({(0x8151, 0x0E), (0x8151, 0x0F), (0x8150, 0x10)})
PROFILE_0D = frozenset({(0x8153, 0x50), (0x8154, 0x3C), (0x8151, 0x0D), (0x8150, 0x10)})


class Anomaly(RuntimeError):
    """Any EC transaction anomaly. Aborts everything."""


class NotAuthorised(RuntimeError):
    """A write outside this stage's authorisation was attempted."""


class EcWriteTransport:
    """EC transport exposing only the authorised read + 0x0E/0x0F writes."""

    def __init__(self, device, allow_writes: bool = False,
                 allowed_pairs: frozenset | None = None):
        self.dev = device
        self.allow_writes = allow_writes
        # Which subset of the audited write profile this run may use.
        # Defaults to the conservative 0E/0F set; the native stage must opt in.
        self.allowed_pairs = allowed_pairs if allowed_pairs is not None else PROFILE_0E_0F
        self.transactions = 0
        self.read_transactions = 0
        self.write_transactions = 0
        self.port_accesses = 0
        self.ec_ram_writes = 0
        self.bytes_written: list[tuple[int, int]] = []
        self.timeouts = 0
        self.retries = 0
        self.anomalies: list[str] = []

    # ---- raw port framing -------------------------------------------------
    def _read(self, port: int) -> int:
        value = self.dev.read_port_byte(port)
        self.port_accesses += 1
        return value

    def _write(self, port: int, value: int) -> None:
        self.dev.write_port_byte(port, value)
        self.port_accesses += 1

    def _wait(self, mask: int, expected: int) -> None:
        deadline = time.monotonic() + WAIT_TIMEOUT
        while True:
            status = self._read(PORT_CMD)
            if status == 0xFF:
                self.anomalies.append("status FF")
                raise Anomaly("EC status 0xFF: transport unavailable")
            if (status & mask) == expected:
                return
            if time.monotonic() >= deadline:
                self.timeouts += 1
                self.anomalies.append(f"timeout mask={mask:#x} last={status:#04x}")
                raise Anomaly(
                    f"EC timeout waiting mask={mask:#x} last={status:#04x}; "
                    "state UNCERTAIN; no flush / no retry / no recovery"
                )
            time.sleep(0.0005)

    def _precheck(self, what: str) -> None:
        status = self._read(PORT_CMD)
        if status == 0xFF or (status & STATUS_BUSY_MASK):
            self.anomalies.append(f"pre-{what} status {status:#04x}")
            raise Anomaly(f"EC busy/SCI/output pending ({status:#04x}) before {what}")

    # ---- authorised operations -------------------------------------------
    def read_xram(self, address: int) -> int:
        self._precheck("read")
        self._write(PORT_CMD, CMD_READ)
        self._wait(IBF, 0)
        self._write(PORT_DATA, (address >> 8) & 0xFF)
        self._wait(IBF, 0)
        self._write(PORT_DATA, address & 0xFF)
        self._wait(IBF, 0)
        self._wait(OBF, OBF)
        value = self._read(PORT_DATA)
        self.transactions += 1
        self.read_transactions += 1
        return value

    def write_xram(self, address: int, value: int) -> None:
        """The ONLY write path. Refuses everything outside this stage's profile."""
        if not self.allow_writes:
            raise NotAuthorised("EC RAM writes are not enabled for this run")
        if address == 0x8151 and value in REFUSED_SUBCOMMANDS:
            raise NotAuthorised(
                f"0x8151=0x{value:02X} refused: {REFUSED_SUBCOMMANDS[value]}"
            )
        if (address, value) not in self.allowed_pairs:
            if (address, value) in WRITE_PAIRS:
                raise NotAuthorised(
                    f"0x{address:04X}=0x{value:02X} is a valid audited write but is "
                    f"NOT authorised for this run's profile"
                )
            raise NotAuthorised(
                f"write 0x{address:04X}=0x{value:02X} is outside the authorised profile"
            )

        self._precheck(f"write 0x{address:04X}")
        self._write(PORT_CMD, CMD_WRITE)
        self._wait(IBF, 0)
        self._write(PORT_DATA, (address >> 8) & 0xFF)
        self._wait(IBF, 0)
        self._write(PORT_DATA, address & 0xFF)
        self._wait(IBF, 0)
        self._write(PORT_DATA, value & 0xFF)
        self._wait(IBF, 0)          # 0x93 has no result byte
        self.transactions += 1
        self.write_transactions += 1
        self.ec_ram_writes += 1
        self.bytes_written.append((address, value))

    def wait_mailbox_idle(self, schedule) -> int:
        """Poll 0x8150 with exponential backoff until the EC clears it."""
        polls = 0
        for delay in schedule:
            if self.read_xram(0x8150) == 0:
                return polls
            polls += 1
            time.sleep(delay)
        self.timeouts += 1
        raise Anomaly(
            f"mailbox 0x8150 did not return to 0 after {polls} polls; "
            "no retry and no cleanup write attempted"
        )

    def counters(self) -> dict:
        return {
            "ec_transactions": self.transactions,
            "read_transactions": self.read_transactions,
            "write_transactions": self.write_transactions,
            "ec_ram_writes": self.ec_ram_writes,
            "port_accesses": self.port_accesses,
            "port_reads": self.dev.port_reads,
            "port_writes": self.dev.port_writes,
            "bytes_written": [[f"{a:04X}", f"{v:02X}"] for a, v in self.bytes_written],
            "timeouts": self.timeouts,
            "retries": self.retries,
            "anomalies": self.anomalies,
        }
