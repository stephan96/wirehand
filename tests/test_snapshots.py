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
import threading
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


# --------------------------------------------------------------- prune ---

@pytest.fixture
def retention(monkeypatch):
    def set_(keep=20, max_age=90, unapplied=7):
        monkeypatch.setattr(state, "SNAPSHOT_KEEP", keep)
        monkeypatch.setattr(state, "SNAPSHOT_MAX_AGE_DAYS", max_age)
        monkeypatch.setattr(state, "SNAPSHOT_UNAPPLIED_DAYS", unapplied)
    set_()
    return set_


def applied(name, code, device="r1"):
    snap(name, device)
    staged(name, code, device)
    ev("confirm_change", code, device)


def left(device="r1"):
    return {p.stem for p in main.changes.list_snapshots(device)}


def pruned_events():
    return [json.loads(l) for l in state.AUDIT_FILE.read_text().splitlines()
            if json.loads(l)["event"] == "snapshot_pruned"]


def test_prune_unapplied_age(data, retention):
    old_expired, old_orphan, old_applied, young_expired = ago(8), ago(8, 1), ago(8, 2), ago(6)
    for n, code in ((old_expired, "AAAAAA"), (young_expired, "BBBBBB")):
        snap(n)
        staged(n, code)
    snap(old_orphan)
    applied(old_applied, "CCCCCC")
    applied(ago(1), "DDDDDD")                     # the rollback base is someone else
    removed = main.changes.prune("r1")
    assert sorted(removed) == sorted([("r1", old_expired, "unapplied_age"), ("r1", old_orphan, "unapplied_age")])
    assert {old_applied, young_expired} <= left()
    ev_ = pruned_events()
    assert {(e["device"], os.path.basename(e["snapshot"]), e["reason"]) for e in ev_} == {
        ("r1", f"{old_expired}.txt", "unapplied_age"), ("r1", f"{old_orphan}.txt", "unapplied_age")}


def test_prune_max_age_keeps_the_rollback_base(data, retention):
    base, older, young = ago(100), ago(120), ago(30)
    applied(older, "AAAAAA")
    applied(base, "BBBBBB")                       # last applied change, older than MAX_AGE_DAYS
    snap(young)
    staged(young, "CCCCCC")                       # expired, but young
    retention(unapplied=0)
    assert main.changes.prune("r1") == [("r1", older, "max_age")]
    assert left() == {base, young}


def test_prune_max_count_oldest_first_skipping_protected(data, retention):
    names = [ago(1, i) for i in range(6)]         # names[0] newest
    for i, n in enumerate(names):
        snap(n)
        staged(n, f"C0000{i}")
    ev("confirm_change", "C00005")                # the oldest one is the rollback base
    retention(keep=3)
    removed = main.changes.prune("r1")
    # the protected base counts towards the limit, but the next-oldest go instead of it
    assert sorted(removed) == sorted(("r1", n, "max_count") for n in names[2:5])
    assert left() == {names[0], names[1], names[5]}
    retention(keep=1)                             # never below the protected ones
    assert main.changes.prune("r1") == [("r1", names[0], "max_count"), ("r1", names[1], "max_count")]
    assert left() == {names[5]}


def test_prune_never_removes_pending_or_unknown(data, retention):
    pend, unknown, timeout = ago(200), ago(200, 1), ago(200, 2)
    for n, code in ((pend, "AAAAAA"), (unknown, "BBBBBB"), (timeout, "CCCCCC")):
        snap(n)
        staged(n, code)
    main.changes._pending["AAAAAA"] = PendingChange("AAAAAA", "r1", ["x"], "")
    ev("confirm_unknown", "BBBBBB")
    ev("confirm_timeout", "CCCCCC")
    retention(keep=1, max_age=1, unapplied=1)
    assert main.changes.prune("r1") == []
    assert left() == {pend, unknown, timeout}


@pytest.mark.parametrize("off, want", [
    ({"unapplied": 0, "max_age": 0, "keep": 0}, []),
    ({"unapplied": 0, "keep": 0}, ["max_age"]),
    ({"max_age": 0, "keep": 0}, ["unapplied_age"]),
    ({"unapplied": 0, "max_age": 0}, ["max_count"]),
])
def test_prune_zero_switches_a_rule_off(data, retention, off, want):
    old = ago(100)
    snap(old)
    staged(old, "AAAAAA")                         # expired, 100 days old
    applied(ago(0, 60), "BBBBBB")                 # rollback base
    retention(**{"keep": 1, "max_age": 90, "unapplied": 7, **off})
    assert [r for _, _, r in main.changes.prune("r1")] == want


def test_prune_count_only(data, retention):
    for i in range(3):
        snap(ago(0, 10 + i))
    retention(keep=1, max_age=0, unapplied=0)
    assert [r for _, _, r in main.changes.prune("r1")] == ["max_count", "max_count"]


def test_prune_all_devices_and_empty_dirs(data, retention):
    snap(ago(10), device="gone")
    snap(ago(10), device="r1")
    applied(ago(0, 5), "AAAAAA")
    (state.SNAP_DIR / "empty").mkdir(parents=True)
    removed = main.changes.prune()
    assert {(d, r) for d, _, r in removed} == {("gone", "unapplied_age"), ("r1", "unapplied_age")}
    assert not (state.SNAP_DIR / "gone").exists() and not (state.SNAP_DIR / "empty").exists()
    assert (state.SNAP_DIR / "r1").is_dir()


def test_save_snapshot_prunes_that_device(data, retention):
    for i in range(3):
        snap(ago(0, 10 + i))
    snap(ago(0, 10), device="other")
    snap(ago(0, 11), device="other")
    retention(keep=2)
    p = main.changes.save_snapshot("r1", RUNNING)
    assert p.stem in left() and len(left()) == 2
    assert len(left("other")) == 2                # other devices untouched


def test_startup_prunes_and_logs_retention(data, retention, caplog):
    snap(ago(10))
    retention(keep=0, max_age=0)
    caplog.set_level("INFO", logger="wirehand")
    with TestClient(main.app):
        assert left() == set()
    msgs = [r.getMessage() for r in caplog.records]
    assert any("snapshot retention: no count limit, no age limit, unapplied 7 days" in m for m in msgs), msgs
    assert any("grow without limit" in m for m in msgs), msgs
    assert not any(t.name == "wirehand-prune" for t in threading.enumerate()), "stopped at shutdown"


# --------------------------------------------------------------- tools ---

def get(path, **params):
    return client.get(path, params=params, headers=H)


def test_list_snapshots_table(data):
    snap("20261014-110120")
    for name, code, kw in [("20261014-110847", "9F3E21", {"event": "rollback_staged"}),
                           ("20261015-193011", "A1B2C3", {"reason": "test loopback"}),
                           ("20261015-201502", "65C02D", {"reason": "OSPF cost on Gi0/0/0/1"})]:
        snap(name)
        staged(name, code, **kw)
    ev("confirm_change", "9F3E21", mode="rollback")
    ev("confirm_change", "65C02D")
    r = get("/list_snapshots", device="r1")
    assert r.status_code == 200, r.text
    lines = r.text.splitlines()
    assert lines[0] == ("Snapshots for r1 (4, newest first). Each snapshot is the configuration "
                        "BEFORE the change.")
    assert lines[2].split() == ["NAME", "SIZE", "TRIGGER", "CHANGE", "STATUS", "REASON"]
    rows = [l.split(None, 5) for l in lines[3:7]]
    assert [r_[0] for r_ in rows] == ["20261015-201502", "20261015-193011", "20261014-110847", "20261014-110120"]
    assert rows[0][2:] == ["propose_change", "65C02D", "applied", "OSPF cost on Gi0/0/0/1"]
    assert rows[1][2:] == ["propose_change", "A1B2C3", "expired", "test loopback"]
    assert lines[5].split()[2:] == ["rollback_staged", "9F3E21", "applied", "(rollback)", "-"]
    assert lines[6].split()[2:] == ["-", "-", "no", "audit", "entry", "-"]
    head = lines[2]
    for row in lines[3:7]:                         # fixed columns, like list_devices
        for col in ("SIZE", "TRIGGER", "CHANGE", "STATUS", "REASON"):
            assert row[head.index(col) - 1] == " " and row[head.index(col)] != " ", (col, row)
    assert "Rollback base (last applied change): 20261015-201502" in r.text
    assert "get_snapshot(device='r1', name='20261015-201502')" in r.text
    assert "Retention - kept: max 20, 90 days, unapplied 7 days." in r.text
    assert "list_snapshots" in state.AUDIT_FILE.read_text()


def test_list_snapshots_marks_placeholders(data):
    snap("20261001-100000", device="srv1", text="(no config snapshot on this platform; per-file backups ...)")
    staged("20261001-100000", "AAAAAA", device="srv1", reason="nginx")
    r = get("/list_snapshots", device="srv1")
    assert "[placeholder] nginx" in r.text and "an empty marker from before 0.6.3" in r.text, r.text
    assert "Rollback base (last applied change): none" in r.text


@pytest.mark.parametrize("device, why", [
    ("srv1", "has no configuration to snapshot"),
    ("ro1", "read-only (access=ro)"),
    ("r1", "no change has been staged on it yet"),
])
def test_list_snapshots_empty(data, device, why):
    r = get("/list_snapshots", device=device)
    assert r.status_code == 200 and r.text.startswith(f"No snapshots for {device}: ") and why in r.text, r.text


def test_snapshot_tools_unknown_device(data):
    assert get("/list_snapshots", device="nope").status_code == 404
    assert get("/get_snapshot", device="nope", name="latest").status_code == 404
    assert get("/list_snapshots", device="r1").status_code == 200
    assert client.get("/list_snapshots", params={"device": "r1"}).status_code == 401


def test_get_snapshot(data):
    snap("20261014-110120", text="old config\n")
    snap("20261015-201502")
    staged("20261015-201502", "65C02D", reason="OSPF cost")
    r = get("/get_snapshot", device="r1", name="latest")
    assert r.status_code == 200, r.text
    assert r.text.startswith("=== r1 : snapshot 20261015-201502 ===\n"
                             "Status: expired | Change ID: 65C02D | Trigger: propose_change | Reason: OSPF cost\n"
                             "This is the configuration BEFORE change 65C02D"), r.text
    assert r.text.endswith("\n\n" + RUNNING), r.text           # content unchanged
    r = get("/get_snapshot", device="r1", name="20261014-110120")
    assert "No audit entry names this snapshot" in r.text and r.text.endswith("\nold config\n"), r.text
    log_ = [json.loads(l) for l in state.AUDIT_FILE.read_text().splitlines()]
    assert {"event": "get_snapshot", "snapshot": "20261014-110120", "filter": ""}.items() <= log_[-1].items()


@pytest.mark.parametrize("bad", ["../x", "2026", "20261015-201502.txt", "x/../y", "../../audit"])
def test_get_snapshot_bad_name_is_400(data, bad):
    snap("20261015-201502")
    r = get("/get_snapshot", device="r1", name=bad)
    assert r.status_code == 400 and "YYYYmmdd-HHMMSS" in r.text, r.text


def test_get_snapshot_missing_is_404(data):
    r = get("/get_snapshot", device="r1", name="latest")
    assert r.status_code == 404 and "list_snapshots(device='r1')" in r.text, r.text
    snap("20261015-201502")
    r = get("/get_snapshot", device="r1", name="20261015-201503")
    assert r.status_code == 404 and "list_snapshots" in r.text, r.text


class TextPool:
    def run(self, dev, cmds, **kw):
        return [(c, RUNNING) for c in cmds]

    def close_all(self):
        pass


@pytest.mark.parametrize("flt, ctx", [("", 0), ("cost|loopback", 0), ("description", 2), ("nomatch", 1), ("([", 0)])
def test_get_snapshot_filter_matches_run_read(data, monkeypatch, flt, ctx):
    monkeypatch.setattr(main, "pool", TextPool())
    snap("20261015-201502")
    read = get("/run_read", device="r1", commands="show running-config", filter=flt, context=ctx).text
    got = get("/get_snapshot", device="r1", name="latest", filter=flt, context=ctx).text
    assert read.split("===\n", 1)[1] == got.split("\n\n", 1)[1], (read, got)


def test_get_snapshot_truncates_with_filter_hint(data, monkeypatch):
    monkeypatch.setattr(main, "MAX_OUT", 300)
    snap("20261015-201502", text="x" * 1000)
    r = get("/get_snapshot", device="r1", name="latest")
    assert "output truncated at 300 chars - use filter=" in r.text, r.text


def test_openapi_has_the_snapshot_tools():
    paths = client.get("/openapi.json").json()["paths"]
    for tool in ("list_snapshots", "get_snapshot"):
        op = paths[f"/{tool}"]["get"]
        assert op["operationId"] == tool
        assert f"{tool}(device='r1'" in op["description"]
    params = {p["name"] for p in paths["/get_snapshot"]["get"]["parameters"]}
    assert {"device", "name", "filter", "context"} <= params, params


# -------------------------------------------- rollback without native ---

def test_rollback_without_native_uses_the_last_applied_snapshot(data):
    snap("20261015-100000", device="ios1", text="hostname before-A\n")
    staged("20261015-100000", "AAAAAA", device="ios1", reason="OSPF cost")
    ev("confirm_change", "AAAAAA", device="ios1", ts="2026-10-15T10:01:00+0200")
    snap("20261015-110000", device="ios1", text="hostname before-B\n")
    staged("20261015-110000", "BBBBBB", device="ios1")          # proposed, never applied
    r = client.post("/rollback_change", params={"device": "ios1"}, headers=H)
    assert r.status_code == 200, r.text
    assert "Snapshot 20261015-100000 is the configuration BEFORE change AAAAAA" in r.text, r.text
    assert "reason: OSPF cost" in r.text and "Nothing was changed" in r.text
    assert "never applied" in r.text and "20261015-110000" in r.text
    assert r.text.endswith("hostname before-A\n") and "before-B" not in r.text
    last = json.loads(state.AUDIT_FILE.read_text().splitlines()[-1])
    assert last["event"] == "rollback_snapshot" and last["code"] == "AAAAAA"
    assert last["snapshot"].endswith("ios1/20261015-100000.txt")


def test_rollback_without_native_and_nothing_applied(data):
    snap("20261015-110000", device="ios1")
    staged("20261015-110000", "BBBBBB", device="ios1")
    r = client.post("/rollback_change", params={"device": "ios1"}, headers=H)
    assert r.status_code == 200 and "no applied change on ios1 has a saved snapshot" in r.text, r.text
    assert "list_snapshots(device='ios1')" in r.text and RUNNING not in r.text
