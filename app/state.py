# SPDX-FileCopyrightText: 2026 Stephan Baenisch
# SPDX-License-Identifier: Apache-2.0
"""Audit log, pending-change store and configuration snapshots.

Audit: append-only JSONL at $WIREHAND_DATA/audit.jsonl. Never contains credentials.
Pending changes: in-memory, TTL-bound, plus an on-disk snapshot so rollback
survives a container restart.
Snapshots: $WIREHAND_DATA/snapshots/<device>/<YYYYmmdd-HHMMSS>.txt, the
configuration BEFORE a staged change. What became of that change is not stored
next to the file; snapshot_index() derives it from the audit log."""
from __future__ import annotations

import json
import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

DATA_DIR = Path(os.environ.get("WIREHAND_DATA", "/app/data"))
AUDIT_FILE = DATA_DIR / "audit.jsonl"
SNAP_DIR = DATA_DIR / "snapshots"
CHANGE_TTL = int(os.environ.get("WIREHAND_CHANGE_TTL", "600"))

SNAP_NAME = re.compile(r"^\d{8}-\d{6}$")
SNAP_TIME_FORMAT = "%Y%m%d-%H%M%S"
# What propose_change wrote on platforms without a snapshot command before 0.6.3,
# e.g. "(no config snapshot on this platform; ...)" or "(linux: no config snapshot; ...)".
PLACEHOLDER_MARK = "no config snapshot"

# Snapshot retention per device; 0 switches a rule off. See prune().
SNAPSHOT_KEEP = int(os.environ.get("WIREHAND_SNAPSHOT_KEEP", "20"))
SNAPSHOT_MAX_AGE_DAYS = float(os.environ.get("WIREHAND_SNAPSHOT_MAX_AGE_DAYS", "90"))
SNAPSHOT_UNAPPLIED_DAYS = float(os.environ.get("WIREHAND_SNAPSHOT_UNAPPLIED_DAYS", "7"))

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


def _audit_rows(device: str) -> list[dict]:
    """Every audit entry of one device, oldest first. Broken lines are skipped
    like in read_audit()."""
    if not AUDIT_FILE.exists():
        return []
    rows = []
    for line in AUDIT_FILE.read_text().splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and rec.get("device") == device:
            rows.append(rec)
    return rows


@dataclass
class SnapshotInfo:
    """A snapshot and the change it was taken for. The snapshot is the
    configuration BEFORE that change."""
    name: str
    trigger: str | None = None     # propose_change | rollback_staged | None (no audit entry)
    code: str | None = None
    mode: str | None = None        # config | exec | rollback
    reason: str = ""
    status: str = "no audit entry"
    staged_ts: str | None = None
    applied_ts: str | None = None
    applied_seq: int = field(default=-1, repr=False)   # audit line of confirm_change: orders applies

    @property
    def applied(self) -> bool:
        return self.status.startswith("applied")

    @property
    def protected(self) -> bool:
        """Never removed by the cleanup: the change may still be applied, or may
        have been applied without wirehand knowing."""
        return self.status.startswith("pending") or self.status == "outcome unknown"

    @property
    def unapplied(self) -> bool:
        return self.status in ("expired", "denied", "incomplete", "failed", "no audit entry")


def _code(value) -> str:
    return str(value or "").strip().upper()


def snapshot_index(device: str, pending: dict[str, float] | None = None) -> dict[str, SnapshotInfo]:
    """Snapshot name -> what became of the change it was taken for.

    Reads the WHOLE audit log once (read_audit(n) would lose old snapshots).
    `pending` maps the codes still staged to their seconds left (ChangeStore.remaining()).
    Files on disk that no staging event names are included as 'no audit entry'.

    The status is the strongest outcome of the change's code, because a wrong
    approval (confirm_denied) does not discard the staged change:
      applied > outcome unknown > pending > incomplete / failed > denied > expired
    """
    pending = pending or {}
    staged: dict[str, dict] = {}            # snapshot name -> staging event
    events: dict[str, list[tuple[int, dict]]] = {}
    for seq, rec in enumerate(_audit_rows(device)):
        ev = rec.get("event")
        if ev in ("propose_change", "rollback_staged"):
            if rec.get("snapshot"):
                # Match on the file name, not the path: robust against a moved WIREHAND_DATA.
                staged[Path(str(rec["snapshot"])).stem] = rec
        elif rec.get("code"):
            events.setdefault(_code(rec["code"]), []).append((seq, rec))

    index: dict[str, SnapshotInfo] = {}
    for name, rec in staged.items():
        code = _code(rec.get("code")) or None
        ev = rec["event"]
        mode = "rollback" if ev == "rollback_staged" else (rec.get("mode") or "config")
        info = SnapshotInfo(name=name, trigger=ev, code=code, mode=mode, reason=rec.get("reason") or "",
                            staged_ts=rec.get("ts"))
        seen = events.get(code or "", [])
        names = {r.get("event") for _, r in seen}
        applied = [(seq, r) for seq, r in seen if r.get("event") == "confirm_change"]
        if applied:
            info.applied_seq, last = applied[-1]
            info.applied_ts = last.get("ts")
            info.status = "applied (rollback)" if mode == "rollback" else "applied"
        elif names & {"confirm_unknown", "confirm_timeout"}:
            info.status = "outcome unknown"
        elif code in pending:
            info.status = f"pending ({max(1, math.ceil(pending[code] / 60))} min left)"
        elif "confirm_incomplete" in names:
            info.status = "incomplete"
        elif names & {"confirm_change_error", "auth_failed"}:
            info.status = "failed"          # nothing reached the device
        elif "confirm_denied" in names:
            info.status = "denied"
        else:
            info.status = "expired"
        index[name] = info

    d = SNAP_DIR / device
    if d.is_dir():
        for p in d.glob("*.txt"):
            if SNAP_NAME.match(p.stem) and p.stem not in index:
                index[p.stem] = SnapshotInfo(name=p.stem)
    return index


def snapshot_path(device: str, name: str) -> Path:
    return SNAP_DIR / device / f"{name}.txt"


def is_placeholder(path: Path) -> bool:
    """A pre-0.6.3 marker file from a platform without a snapshot command."""
    try:
        with path.open() as fh:
            head = fh.read(80)
    except (OSError, UnicodeDecodeError):
        return False
    return head.startswith("(") and PLACEHOLDER_MARK in head


def last_applied(device: str, config_only: bool = True,
                 index: dict[str, SnapshotInfo] | None = None) -> SnapshotInfo | None:
    """The most recently applied change whose snapshot still exists. With
    config_only, exec-mode changes are skipped: they do not change the
    configuration. Placeholders are no rollback base either."""
    index = snapshot_index(device) if index is None else index
    best = None
    for info in index.values():
        if not info.applied or (config_only and info.mode == "exec"):
            continue
        p = snapshot_path(device, info.name)
        if not p.is_file() or is_placeholder(p):
            continue
        if best is None or info.applied_seq > best.applied_seq:
            best = info
    return best


def last_applied_snapshot(device: str, config_only: bool = True) -> Path | None:
    """The snapshot of the last applied change: the configuration from before it."""
    info = last_applied(device, config_only)
    return snapshot_path(device, info.name) if info else None


def retention_summary() -> str:
    """The active retention rules, e.g. 'max 20, 90 days, unapplied 7 days'."""
    return ", ".join([
        f"max {SNAPSHOT_KEEP}" if SNAPSHOT_KEEP else "no count limit",
        f"{SNAPSHOT_MAX_AGE_DAYS:g} days" if SNAPSHOT_MAX_AGE_DAYS else "no age limit",
        f"unapplied {SNAPSHOT_UNAPPLIED_DAYS:g} days" if SNAPSHOT_UNAPPLIED_DAYS else "unapplied: no age limit",
    ])


def snapshot_time(path: Path) -> float:
    """When a snapshot was taken, from its name (container local time, like the
    time.strftime that made it); the file's mtime only if the name does not parse."""
    try:
        return time.mktime(time.strptime(path.stem, SNAP_TIME_FORMAT))
    except (ValueError, OverflowError):
        return path.stat().st_mtime


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
        self._files = threading.RLock()     # snapshot files: saving and cleanup must not interleave

    def save_snapshot(self, device: str, content: str) -> Path:
        with self._files:
            d = SNAP_DIR / device
            d.mkdir(parents=True, exist_ok=True)
            p = d / (time.strftime(SNAP_TIME_FORMAT) + ".txt")
            p.write_text(content)
            self.prune(device)
            return p

    def list_snapshots(self, device: str) -> list[Path]:
        """Snapshot files of one device, newest first."""
        d = SNAP_DIR / device
        if not d.is_dir():
            return []
        return sorted((p for p in d.glob("*.txt") if SNAP_NAME.match(p.stem)), key=lambda p: p.stem, reverse=True)

    def latest_snapshot(self, device: str) -> Path | None:
        snaps = self.list_snapshots(device)
        return snaps[0] if snaps else None

    def get_snapshot(self, device: str, name: str) -> Path | None:
        """`name` is a snapshot name (YYYYmmdd-HHMMSS) or 'latest'. ValueError for
        anything else; None if there is no such snapshot."""
        name = name.strip()
        if name == "latest":
            return self.latest_snapshot(device)
        if not SNAP_NAME.match(name):
            raise ValueError(f"invalid snapshot name '{name}'")
        d = (SNAP_DIR / device).resolve()
        p = (d / f"{name}.txt").resolve()
        if p.parent != d or d.parent != SNAP_DIR.resolve():
            raise ValueError(f"invalid snapshot name '{name}'")
        return p if p.is_file() else None

    def prune(self, device: str | None = None) -> list[tuple[str, str, str]]:
        """Apply the retention rules to one device's snapshots, or to every
        device's. Returns (device, name, reason) for each file removed.

        Never removed: the rollback base (snapshot of the last applied config
        change), and snapshots whose change is pending or has an unknown outcome.
        Of the rest, in this order:
          1. unapplied_age  not applied and older than SNAPSHOT_UNAPPLIED_DAYS
          2. max_age        older than SNAPSHOT_MAX_AGE_DAYS
          3. max_count      more than SNAPSHOT_KEEP: oldest first; protected
                            snapshots count, but are skipped
        """
        with self._files:
            if device is not None:
                devices = [device]
            else:
                devices = sorted(p.name for p in SNAP_DIR.iterdir() if p.is_dir()) if SNAP_DIR.is_dir() else []
            removed = []
            for dev in devices:
                removed += self._prune_device(dev)
            return removed

    def _prune_device(self, device: str) -> list[tuple[str, str, str]]:
        files = self.list_snapshots(device)          # newest first
        if not files:
            self._remove_empty_dir(device)
            return []
        index = self.index(device)
        base = last_applied(device, index=index)
        keep = {n for n, i in index.items() if i.protected} | ({base.name} if base else set())
        now = time.time()
        doomed: dict[str, str] = {}
        for p in files:
            if p.stem in keep:
                continue
            info = index.get(p.stem) or SnapshotInfo(name=p.stem)
            age_days = (now - snapshot_time(p)) / 86400
            if SNAPSHOT_UNAPPLIED_DAYS and info.unapplied and age_days > SNAPSHOT_UNAPPLIED_DAYS:
                doomed[p.stem] = "unapplied_age"
            elif SNAPSHOT_MAX_AGE_DAYS and age_days > SNAPSHOT_MAX_AGE_DAYS:
                doomed[p.stem] = "max_age"
        if SNAPSHOT_KEEP:
            left = [p for p in files if p.stem not in doomed]
            count = len(left)
            for p in reversed(left):                 # oldest first
                if count <= SNAPSHOT_KEEP:
                    break
                if p.stem not in keep:
                    doomed[p.stem] = "max_count"
                    count -= 1
        removed = []
        for p in files:
            reason = doomed.get(p.stem)
            if reason is None:
                continue
            p.unlink(missing_ok=True)
            audit("snapshot_pruned", device, snapshot=str(p), reason=reason)
            removed.append((device, p.stem, reason))
        self._remove_empty_dir(device)
        return removed

    @staticmethod
    def _remove_empty_dir(device: str) -> None:
        try:
            (SNAP_DIR / device).rmdir()      # only succeeds when empty
        except OSError:
            pass

    def remaining(self) -> dict[str, float]:
        """Staged change ID -> seconds until it expires."""
        with self._lock:
            self._purge()
            return {k: CHANGE_TTL - (time.time() - v.created) for k, v in self._pending.items()}

    def index(self, device: str) -> dict[str, SnapshotInfo]:
        return snapshot_index(device, self.remaining())

    def create(self, device: str, lines: list[str], snapshot_path: Path | None, diff: str, mode: str = "config") -> PendingChange:
        code = secrets.token_hex(3).upper()  # 6 hex chars: easy to read back in chat
        pc = PendingChange(code=code, device=device, lines=lines, snapshot_path=str(snapshot_path or ""), diff=diff, mode=mode)
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
            raise KeyError(f"no pending change with change ID '{code}' (expired after {CHANGE_TTL}s, or already applied)")
        return pc

    def pop(self, code: str) -> PendingChange:
        with self._lock:
            self._purge()
            pc = self._pending.pop(code.strip().upper(), None)
        if pc is None:
            raise KeyError(f"no pending change with change ID '{code}' (expired after {CHANGE_TTL}s, or already applied)")
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
