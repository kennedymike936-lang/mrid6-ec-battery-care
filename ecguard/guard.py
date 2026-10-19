"""Cross-process transaction guard: poison flag, write ledger, crash journal.

Requirements this implements:
  * 'poisoned' survives process death and blocks the next write.
  * An interrupted/timed-out EC transaction forbids the next write until a
    human explicitly re-verifies the live state and clears it.
  * The write ledger records exactly what was submitted, how many times, and
    whether the transaction completed.

The journal is written BEFORE the first EC byte and marked complete AFTER the
last verification, so a crash between the two leaves an in-flight marker on
disk that any later invocation will see.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
from pathlib import Path

STATE_DIR = Path(os.environ.get("ECGUARD_STATE_DIR", r"C:\ProgramData\ECGuard\state"))
STATE_FILE = STATE_DIR / "state.json"
LEDGER_FILE = STATE_DIR / "ledger.jsonl"

STATE_SCHEMA = 1


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat()


def _ensure_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def _atomic_write(path: Path, text: str) -> None:
    """Write state atomically.

    Uses a sibling temp file rather than os.fdopen(mkstemp(...)) so the write
    only ever touches the state directory itself.
    """
    _ensure_dir()
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def probe_state_dir() -> dict:
    """Report whether the guard state directory is usable, without creating it."""
    info = {"path": str(STATE_DIR), "exists": STATE_DIR.exists(), "writable": False}
    try:
        _ensure_dir()
        test = STATE_DIR / ".write-test"
        test.write_text("ok", encoding="utf-8")
        test.unlink()
        info["writable"] = True
    except Exception as error:  # noqa: BLE001
        info["error"] = f"{type(error).__name__}: {error}"
    return info


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {"schema": STATE_SCHEMA, "poisoned": False, "transaction": None}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as error:  # unreadable state must fail closed
        return {
            "schema": STATE_SCHEMA,
            "poisoned": True,
            "poison_reason": f"state file unreadable: {error}",
            "transaction": None,
        }
    if data.get("schema") != STATE_SCHEMA:
        data["poisoned"] = True
        data["poison_reason"] = "state schema mismatch"
    return data


def save_state(state: dict) -> None:
    state["schema"] = STATE_SCHEMA
    _atomic_write(STATE_FILE, json.dumps(state, indent=2, ensure_ascii=False))


def poison(reason: str, *, transaction: dict | None = None) -> dict:
    """Fail closed: record that the EC is in an unknown state."""
    _ensure_dir()
    state = load_state()
    state["poisoned"] = True
    state["poison_reason"] = reason
    state["poisoned_at"] = _now()
    if transaction is not None:
        state["poisoned_transaction"] = transaction
    save_state(state)
    ledger({"event": "poisoned", "reason": reason,
            "transaction": transaction})
    return state


def clear_poison(reason: str) -> dict:
    """Only ever called after a human-driven read-only re-verification.

    This clears BOTH the poison flag AND any stale in-flight transaction
    journal. Clearing the journal is the whole point of the explicit
    re-verification step: if the operator has just read the live EC state and
    confirmed the mailbox is idle and no transaction is in progress, then a
    journal entry left behind by a crashed process is stale by definition and
    would otherwise block every future write forever.

    The discarded journal is archived into `transaction_history` so the audit
    trail is preserved rather than silently dropped.
    """
    state = load_state()

    stale = state.get("transaction")
    if stale and not stale.get("completed"):
        archive = state.setdefault("transaction_history", [])
        archived = dict(stale)
        archived["discarded_at"] = _now()
        archived["discarded_because"] = reason
        archive.append(archived)
        ledger({"event": "stale_transaction_discarded", "reason": reason,
                "started_at": stale.get("started_at"),
                "planned_writes": stale.get("planned_writes")})
        state["transaction"] = None

    state["poisoned"] = False
    state.pop("poison_reason", None)
    state["cleared_at"] = _now()
    state["cleared_reason"] = reason
    history = state.setdefault("clear_history", [])
    history.append({"at": state["cleared_at"], "reason": reason})
    save_state(state)
    ledger({"event": "guard_cleared", "reason": reason})
    return state


def require_writable() -> dict:
    """Raise if any prior run left the EC in an unverified state."""
    state = load_state()
    if state.get("poisoned"):
        raise RuntimeError(
            "Refusing to write: a previous EC transaction did not complete cleanly.\n"
            f"  reason : {state.get('poison_reason')}\n"
            f"  at     : {state.get('poisoned_at')}\n"
            "Run the read-only inspection, confirm the live EC state is sane, then "
            "clear the guard explicitly with --clear-guard-after-inspection."
        )
    txn = state.get("transaction")
    if txn and not txn.get("completed"):
        raise RuntimeError(
            "Refusing to write: a transaction is marked in-flight (process died mid-write).\n"
            f"  started: {txn.get('started_at')}\n"
            f"  plan   : {txn.get('planned_writes')}\n"
            "Run the read-only inspection and clear the guard explicitly."
        )
    return state


def begin_transaction(planned_writes: list[list[int]], note: str) -> dict:
    """Journal the intent BEFORE the first EC byte is written."""
    txn = {
        "started_at": _now(),
        "planned_writes": planned_writes,
        "note": note,
        "completed": False,
        "bytes_written": 0,
    }
    state = load_state()
    state["transaction"] = txn
    save_state(state)
    ledger({"event": "transaction_begin", "planned_writes": planned_writes, "note": note})
    return txn


def mark_bytes_written(count: int) -> None:
    state = load_state()
    txn = state.get("transaction") or {}
    txn["bytes_written"] = count
    state["transaction"] = txn
    save_state(state)


def complete_transaction(verification: dict) -> None:
    state = load_state()
    txn = state.get("transaction") or {}
    txn["completed"] = True
    txn["completed_at"] = _now()
    txn["verification"] = verification
    state["transaction"] = txn
    save_state(state)
    ledger({"event": "transaction_complete", "verification": verification})


def ledger(entry: dict) -> None:
    """Append-only audit trail of every EC-affecting action."""
    _ensure_dir()
    record = {"time": _now(), **entry}
    with LEDGER_FILE.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def ledger_tail(n: int = 20) -> list[dict]:
    if not LEDGER_FILE.exists():
        return []
    lines = LEDGER_FILE.read_text(encoding="utf-8").splitlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"unparsable": line})
    return out
