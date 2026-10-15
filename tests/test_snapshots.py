# SPDX-FileCopyrightText: 2026 Stephan Baenisch
# SPDX-License-Identifier: Apache-2.0
"""Snapshots: what became of the change each one was taken for (from the audit
log), the read tools, the cleanup, and the rollback base on platforms without a
native rollback.

DATA_DIR, SNAP_DIR and AUDIT_FILE are module constants of app.state; every test
points them at its own tmp_path and writes a synthetic audit.jsonl."""
import json
import os
import sys
import tempfile
import time

import pytest

os.environ["WIREHAND_API_KEY"] = "k"
os.environ["WIREHAND_DATA"] = tempfile.mkdtemp()
_inv = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
_inv.write("""devices:
  r1: {host: 1.1.1.1, device_type: cisco_xr, username: u, password: p, access: rw}
  ios1: {host: 1.1.1.2, device_type: cisco_ios, username: u, password: p, access: rw}
  srv1: {host: 1.1.1.3, device_type: linux, username: u, password: p, access: rw}
  ro1: {host: 1.1.1.4, device_type: cisco_ios, username: u, password: p, access: ro}
""")
_inv.close()
os.environ["WIREHAND_INVENTORY"] = _inv.name
os.environ["WIREHAND_CONFIRM_MODE"] = "off"
for _m in list(sys.modules):
    if _m.startswith("app"):
        del sys.modules[_m]

from fastapi.testclient import TestClient  # noqa: E402

from app import main, state  # noqa: E402
from app.state import PendingChange, SnapshotInfo  # noqa: E402

H = {"Authorization": "Bearer k"}
client = TestClient(main.app)

RUNNING = ("hostname r1\ninterface Loopback0\n ipv4 address 1.1.1.1/32\n"
           "interface GigabitEthernet0/0/0/0\n description uplink\n cost 10\nrouter ospf 1\n")


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "DATA_DIR", tmp_path)
    monkeypatch.setattr(state, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(state, "AUDIT_FILE", tmp_path / "audit.jsonl")
    monkeypatch.setattr(main, "changes", state.ChangeStore())
    return tmp_path


def snap(name, device="r1", text=RUNNING):
    p = state.SNAP_DIR / device / f"{name}.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def log(*recs):
    state.AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with state.AUDIT_FILE.open("a") as fh:
        for r in recs:
            fh.write(json.dumps({"ts": "2026-10-15T12:00:00+0200", "device": "r1", **r}) + "\n")


def staged(name, code, device="r1", event="propose_change", **kw):
    # Another WIREHAND_DATA than today's: the index must match on the file name only.
    log({"event": event, "device": device, "code": code,
         "snapshot": f"/old/data/snapshots/{device}/{name}.txt", **kw})


def ev(event, code, device="r1", **kw):
    log({"event": event, "device": device, "code": code, **kw})


def ago(days, seconds=0):
    """A snapshot name from `days` ago, in container local time like save_snapshot."""
    return time.strftime(state.SNAP_TIME_FORMAT, time.localtime(time.time() - days * 86400 - seconds))


# --------------------------------------------------------------- index ---

@pytest.mark.parametrize("events, want", [
    ([("confirm_change", {})], "applied"),
    ([("confirm_denied", {}), ("confirm_change", {})], "applied"),     # a wrong TOTP does not discard
    ([("confirm_unknown", {})], "outcome unknown"),
    ([("confirm_timeout", {})], "outcome unknown"),
    ([("confirm_incomplete", {})], "incomplete"),
    ([("confirm_change_error", {})], "failed"),
    ([("confirm_denied", {})], "denied"),
    ([], "expired"),
])
def test_status_from_the_audit_log(data, events, want):
    snap("20261015-201502")
    staged("20261015-201502", "65C02D", reason="OSPF cost", mode="config")
    for e, kw in events:
        ev(e, "65C02D", **kw)
    info = state.snapshot_index("r1")["20261015-201502"]
    assert info.status == want, info
    assert (info.trigger, info.code, info.mode, info.reason) == ("propose_change", "65C02D", "config", "OSPF cost")
    assert info.staged_ts == "2026-10-15T12:00:00+0200"
    assert (info.applied_ts is not None) == (want == "applied")


def test_status_applied_rollback(data):
    staged("20261014-110847", "9F3E21", event="rollback_staged")
    ev("confirm_change", "9F3E21", mode="rollback")
    info = state.snapshot_index("r1")["20261014-110847"]
    assert (info.status, info.mode, info.trigger) == ("applied (rollback)", "rollback", "rollback_staged")


def test_status_pending_needs_the_code_still_staged(data):
    staged("20261015-201502", "A1B2C3")
    ev("confirm_denied", "A1B2C3")
    main.changes._pending["A1B2C3"] = PendingChange("A1B2C3", "r1", ["x"], "", created=time.time() - 30)
    assert main.changes.index("r1")["20261015-201502"].status == "pending (10 min left)"
    main.changes._pending["A1B2C3"].created = time.time() - state.CHANGE_TTL - 1
    assert main.changes.index("r1")["20261015-201502"].status == "denied"


def test_status_no_audit_entry(data):
    snap("20261014-110120")
    info = state.snapshot_index("r1")["20261014-110120"]
    assert info == SnapshotInfo(name="20261014-110120") and info.status == "no audit entry"


def test_index_reads_the_whole_log(data):
    """read_audit(n) only sees the last n entries: an old snapshot must not lose its change."""
    staged("20260101-080000", "0LD0LD")
    ev("confirm_change", "0LD0LD")
    for i in range(300):
        log({"event": "run_read", "commands": [f"show {i}"]})
    with state.AUDIT_FILE.open("a") as fh:
        fh.write("{broken json\n")
    assert state.snapshot_index("r1")["20260101-080000"].status == "applied"


def test_index_is_per_device_and_normalizes_codes(data):
    staged("20261015-201502", "abc123")
    ev("confirm_change", " abc123 ")                  # older entries logged the code as typed
    staged("20261015-201503", "DDDDDD", device="other")
    ev("confirm_change", "DDDDDD", device="other")
    idx = state.snapshot_index("r1")
    assert set(idx) == {"20261015-201502"} and idx["20261015-201502"].status == "applied"
    assert idx["20261015-201502"].code == "ABC123"


def test_index_skips_staging_without_a_snapshot(data):
    log({"event": "propose_change", "code": "AAAAAA", "snapshot": ""})
    assert state.snapshot_index("r1") == {}


def test_last_applied_snapshot(data):
    for name, code, mode in [("20261015-100000", "AAAAAA", "config"),
                             ("20261015-110000", "BBBBBB", "config"),
                             ("20261015-120000", "CCCCCC", "exec"),
                             ("20261015-130000", "DDDDDD", "config")]:
        snap(name)
        staged(name, code, mode=mode)
    ev("confirm_change", "BBBBBB")
    ev("confirm_change", "AAAAAA")      # applied after B: A is the last applied change
    ev("confirm_change", "CCCCCC")      # exec changes no configuration
    # DDDDDD is newest, but never applied
    assert state.last_applied_snapshot("r1") == state.snapshot_path("r1", "20261015-100000")
    assert state.last_applied_snapshot("r1", config_only=False) == state.snapshot_path("r1", "20261015-120000")
    state.snapshot_path("r1", "20261015-100000").unlink()     # the file must still exist
    assert state.last_applied_snapshot("r1").stem == "20261015-110000"


def test_last_applied_skips_placeholders(data):
    snap("20261015-100000", text="(no config snapshot on this platform; per-file backups ...)")
    staged("20261015-100000", "AAAAAA")
    ev("confirm_change", "AAAAAA")
    assert state.last_applied_snapshot("r1") is None


# ---------------------------------------------------------- ChangeStore ---

def test_list_and_get_snapshot(data):
    store = state.ChangeStore()
    assert store.list_snapshots("r1") == [] and store.get_snapshot("r1", "latest") is None
    for n in ("20261014-110120", "20261015-201502", "20261015-193011"):
        snap(n)
    (state.SNAP_DIR / "r1" / "notes.txt").write_text("not a snapshot")
    assert [p.stem for p in store.list_snapshots("r1")] == ["20261015-201502", "20261015-193011", "20261014-110120"]
    assert store.get_snapshot("r1", "latest").stem == "20261015-201502"
    assert store.get_snapshot("r1", "20261014-110120").read_text() == RUNNING
    assert store.get_snapshot("r1", "20200101-000000") is None
    for bad in ("../x", "2026", "20261015-201502.txt", "x/../y", "", "notes"):
        with pytest.raises(ValueError):
            store.get_snapshot("r1", bad)


def test_snapshot_time_from_the_name(data):
    p = snap("20261015-201502")
    assert state.snapshot_time(p) == time.mktime(time.strptime("20261015-201502", "%Y%m%d-%H%M%S"))
    odd = state.SNAP_DIR / "r1" / "20261399-999999.txt"      # matches the format, not a date
    odd.write_text("x")
    os.utime(odd, (1_000_000, 1_000_000))
    assert state.snapshot_time(odd) == 1_000_000
