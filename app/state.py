# SPDX-FileCopyrightText: 2026 Stephan Baenisch
# SPDX-License-Identifier: Apache-2.0
"""Audit log and pending-change store.

Audit: append-only JSONL at $WIREHAND_DATA/audit.jsonl. Never contains credentials.
Pending changes: in-memory, TTL-bound, plus an on-disk snapshot so rollback
survives a container restart."""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

DATA_DIR = Path(os.environ.get("WIREHAND_DATA", "/app/data"))
AUDIT_FILE = DATA_DIR / "audit.jsonl"
SNAP_DIR = DATA_DIR / "snapshots"
CHANGE_TTL = int(os.environ.get("WIREHAND_CHANGE_TTL", "600"))

_audit_lock = threading.Lock()


def audit(event: str, device: str = "", **fields) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, "device": device, **fields}
    with _audit_lock, AUDIT_FILE.open("a") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def read_audit(device: str = "", n: int = 20) -> list[dict]:
    if not AUDIT_FILE.exists():
        return []
    rows = []
    for line in AUDIT_FILE.read_text().splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not device or rec.get("device") == device:
            rows.append(rec)
    return rows[-n:]


@dataclass
class PendingChange:
    code: str
    device: str
    lines: list[str]
    snapshot_path: str
    mode: str = "config"          # config = config-view change | exec = user-view maintenance
    created: float = field(default_factory=time.time)
    diff: str = ""

    @property
    def expired(self) -> bool:
        return time.time() - self.created > CHANGE_TTL


class ChangeStore:
    def __init__(self):
        self._pending: dict[str, PendingChange] = {}
        self._lock = threading.Lock()

    def save_snapshot(self, device: str, content: str) -> Path:
        d = SNAP_DIR / device
        d.mkdir(parents=True, exist_ok=True)
        p = d / (time.strftime("%Y%m%d-%H%M%S") + ".txt")
        p.write_text(content)
        # keep last 20 snapshots per device
        for old in sorted(d.glob("*.txt"))[:-20]:
            old.unlink(missing_ok=True)
        return p

    def latest_snapshot(self, device: str) -> Path | None:
        d = SNAP_DIR / device
        snaps = sorted(d.glob("*.txt")) if d.exists() else []
        return snaps[-1] if snaps else None

    def create(self, device: str, lines: list[str], snapshot_path: Path, diff: str, mode: str = "config") -> PendingChange:
        code = secrets.token_hex(3).upper()  # 6 hex chars: easy to read back in chat
        pc = PendingChange(code=code, device=device, lines=lines, snapshot_path=str(snapshot_path), diff=diff, mode=mode)
        with self._lock:
            self._purge()
            self._pending[code] = pc
        return pc

    def peek(self, code: str) -> PendingChange:
        """Look up a staged change WITHOUT consuming it - confirm_change has to
        check the human approval first, and a wrong code must not throw the
        staged change away."""
        with self._lock:
            self._purge()
            pc = self._pending.get(code.strip().upper())
        if pc is None:
            raise KeyError(f"no pending change with code '{code}' (expired after {CHANGE_TTL}s, or already applied)")
        return pc

    def pop(self, code: str) -> PendingChange:
        with self._lock:
            self._purge()
            pc = self._pending.pop(code.strip().upper(), None)
        if pc is None:
            raise KeyError(f"no pending change with code '{code}' (expired after {CHANGE_TTL}s, or already applied)")
        return pc

    def restore(self, pc: PendingChange) -> None:
        """Put a popped change back, unchanged (same code, same expiry) - for a
        confirm_change that ended before anything was sent to the device."""
        with self._lock:
            self._pending.setdefault(pc.code, pc)

    def _purge(self):
        for k in [k for k, v in self._pending.items() if v.expired]:
            del self._pending[k]

    def list(self) -> list[dict]:
        with self._lock:
            self._purge()
            return [{**asdict(p), "age_s": int(time.time() - p.created)} for p in self._pending.values()]
