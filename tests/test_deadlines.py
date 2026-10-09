# SPDX-FileCopyrightText: 2026 Stephan Baenisch
# SPDX-License-Identifier: Apache-2.0
"""A tool call that goes wrong half-way must end, and must say honestly what
happened: a change command is never sent twice, and an error after it was sent
is never reported as APPLIED / EXECUTED / ROLLED BACK."""
import os
import sys
import tempfile

import pytest

pytest.importorskip("netmiko")

os.environ["WIREHAND_API_KEY"] = "k"
os.environ["WIREHAND_DATA"] = tempfile.mkdtemp()
_inv = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
_inv.write("""devices:
  r1: {host: 1.1.1.1, device_type: cisco_xr, username: u, password: p, access: rw}
""")
_inv.close()
os.environ["WIREHAND_INVENTORY"] = _inv.name
os.environ["WIREHAND_CONFIRM_MODE"] = "off"
for _m in list(sys.modules):
    if _m.startswith("app"):
        del sys.modules[_m]

from fastapi.testclient import TestClient  # noqa: E402

from app import main, transport  # noqa: E402
from app.inventory import Device  # noqa: E402
from app.transport import OutcomeUnknown, Pool  # noqa: E402

H = {"Authorization": "Bearer k"}
client = TestClient(main.app)


# ------------------------------------------------------------ transport ---

class FakeConn:
    """A Netmiko connection stand-in. `fail` = how many send_command calls raise."""
    def __init__(self, fail=0):
        self.fail, self.sent = fail, []

    def is_alive(self):
        return True

    def send_command(self, cmd, **kw):
        self.sent.append(cmd)
        if self.fail:
            self.fail -= 1
            raise OSError("Socket is closed")
        return f"ok {cmd}"

    def send_config_set(self, lines, **kw):
        raise OSError("Socket is closed")

    def disconnect(self):
        pass


def _dev():
    return Device(name="r1", host="1.1.1.1", device_type="cisco_xr", username="u", password="p")


@pytest.fixture
def pool(monkeypatch):
    """A Pool whose session for r1 already holds `first`; reconnects get `fresh`."""
    p = Pool()
    p.first, p.fresh, p.connects = FakeConn(), FakeConn(), 0

    def connect(**kw):
        p.connects += 1
        return p.fresh
    monkeypatch.setattr(transport, "ConnectHandler", connect)
    p._get(_dev()).conn = p.first
    return p


def test_read_path_reconnects_and_retries_once(pool):
    pool.first.fail = 1
    res = pool.run(_dev(), ["show clock"])
    assert res == [("show clock", "ok show clock")]
    assert pool.first.sent == ["show clock"] and pool.fresh.sent == ["show clock"]
    assert pool.connects == 1


def test_change_path_never_resends_a_command(pool):
    pool.first.fail = 1
    with pytest.raises(OutcomeUnknown, match="clear bgp"):
        pool.run(_dev(), ["clear bgp *", "show clock"], prompts="yes", idempotent=False)
    assert pool.first.sent == ["clear bgp *"], "the failed command must not be sent again"
    assert pool.connects == 0 and pool.fresh.sent == []


def test_config_error_after_sending_is_outcome_unknown(pool):
    with pytest.raises(OutcomeUnknown):
        pool.configure(_dev(), ["interface Loopback1"], commit=True)


# ------------------------------------------------------------------ API ---

class RecordingPool:
    """Records how confirm_change calls the pool; can fail on the change path."""
    def __init__(self, fail_change=False):
        self.fail_change, self.calls = fail_change, []

    def run(self, dev, cmds, timeout=60, prompts="no", idempotent=True, **kw):
        self.calls.append(("run", tuple(cmds), idempotent))
        if self.fail_change and not idempotent:
            raise OutcomeUnknown(dev.name, f"'{cmds[0]}'", OSError("Socket is closed"))
        return [(c, f"out of {c}") for c in cmds]

    def configure(self, dev, lines, commit, **kw):
        self.calls.append(("configure", tuple(lines), False))
        if self.fail_change:
            raise OutcomeUnknown(dev.name, "the configuration change", OSError("Socket is closed"))
        return "Commit complete"

    def reset(self, dev):
        pass

    def close_all(self):
        pass


def _staged(path, **kw):
    r = client.post(path, headers=H, **kw)
    assert r.status_code == 200 and "STAGED" in r.text, r.text
    return r.text.split("code: ")[1][:6]


def _audit_events():
    return client.get("/get_audit_log", params={"n": 200}, headers=H).text


def test_confirm_change_runs_rollback_without_retry():
    main.pool = RecordingPool()
    code = _staged("/rollback_change", params={"device": "r1"})
    r = client.post("/confirm_change", params={"code": code}, headers=H)
    assert r.status_code == 200 and "ROLLED BACK" in r.text, r.text
    assert main.pool.calls[-1] == ("run", ("rollback configuration last 1",), False)


@pytest.mark.parametrize("staging", [
    ("/rollback_change", {"params": {"device": "r1"}}),
    ("/propose_change", {"json": {"device": "r1", "config": "clear counters", "mode": "exec"}}),
    ("/propose_change", {"json": {"device": "r1", "config": "interface Loopback1"}}),
])
def test_error_during_confirm_is_never_reported_as_success(staging):
    main.pool = RecordingPool(fail_change=True)
    path, kw = staging
    code = _staged(path, **kw)
    r = client.post("/confirm_change", params={"code": code}, headers=H)
    assert r.status_code == 502, (r.status_code, r.text)
    assert "OUTCOME UNKNOWN" in r.text and "Do NOT retry" in r.text, r.text
    for word in ("APPLIED", "EXECUTED", "ROLLED BACK"):
        assert word not in r.text, r.text
    assert "confirm_unknown" in _audit_events()


# ----------------------------------------------------------- lock wait ---

import time  # noqa: E402

from app.transport import DeviceBusy  # noqa: E402


@pytest.fixture
def held(pool, monkeypatch):
    """The real pool, with r1's session lock held by 'another call'."""
    monkeypatch.setattr(transport, "LOCK_WAIT", 0.3)
    s = pool._get(_dev())
    s.lock.acquire()
    yield pool
    s.lock.release()


def test_busy_session_gives_up_after_lock_wait(held):
    t0 = time.monotonic()
    with pytest.raises(DeviceBusy, match="Nothing was sent"):
        held.run(_dev(), ["show clock"])
    assert 0.25 < time.monotonic() - t0 < 2
    with pytest.raises(DeviceBusy):
        held.configure(_dev(), ["interface Loopback1"], commit=True)
    assert held.first.sent == []


def test_busy_device_is_409_and_nothing_sent(held):
    main.pool = held
    t0 = time.monotonic()
    r = client.get("/get_facts", params={"device": "r1"}, headers=H)
    assert r.status_code == 409 and "Nothing was sent" in r.text, (r.status_code, r.text)
    assert time.monotonic() - t0 < 2
    assert client.get("/run_read", params={"device": "r1", "commands": "show clock"},
                      headers=H).status_code == 409
    r = client.post("/propose_change", json={"device": "r1", "config": "interface Loopback1"}, headers=H)
    assert r.status_code == 409 and "STAGED" not in r.text, r.text
    assert held.first.sent == []


def test_busy_confirm_keeps_the_change_staged(held):
    main.pool = held
    s = held._get(_dev())
    s.lock.release()
    code = _staged("/rollback_change", params={"device": "r1"})
    s.lock.acquire()
    r = client.post("/confirm_change", params={"code": code}, headers=H)
    assert r.status_code == 409 and "NOT APPLIED" in r.text and code in r.text, r.text
    assert "rollback configuration last 1" not in held.first.sent
    s.lock.release()
    r = client.post("/confirm_change", params={"code": code}, headers=H)   # retry later works
    assert r.status_code == 200 and "ROLLED BACK" in r.text, r.text
    s.lock.acquire()


# ------------------------------------------------------------ deadlines ---

from types import SimpleNamespace  # noqa: E402

from app.transport import Budget, DeadlineExceeded  # noqa: E402

DEADLINE = 1.0     # stands in for the 60s default, so the suite stays fast


class HungConn(FakeConn):
    """Hangs on any command containing `hang_on` and ignores read_timeout, like
    a device that stopped answering in the middle of a step that has no timeout
    of its own (save_config). Only abort() taking the channel away ends it."""
    def __init__(self, hang_on):
        super().__init__()
        self.hang_on = hang_on
        self.channel = SimpleNamespace(remote_conn=object())
        self.remote_conn_pre = SimpleNamespace(close=lambda: None)

    def _hang(self):
        end = time.monotonic() + 30
        while time.monotonic() < end:
            if self.channel.remote_conn is None:
                raise OSError("Attempt to read, but there is no active channel.")
            time.sleep(0.01)

    def send_command(self, cmd, **kw):
        self.sent.append(cmd)
        if self.hang_on in cmd:
            self._hang()
        return f"ok {cmd}"

    def send_config_set(self, lines, **kw):
        self.sent.extend(lines)
        return ""

    def commit(self, read_timeout=120.0):
        self.sent.append("commit")
        if self.hang_on == "commit":
            self._hang()
        return "committed"

    def exit_config_mode(self):
        pass


@pytest.fixture
def hung(pool, monkeypatch):
    monkeypatch.setattr(transport, "MIN_STEP", 0.05)
    for name in ("DEADLINE_READ", "DEADLINE_PROPOSE", "DEADLINE_CONFIRM"):
        monkeypatch.setattr(main, name, DEADLINE)
    main.pool = pool

    def hang_on(word):
        pool._get(_dev()).conn = conn = HungConn(word)
        return conn
    pool.hang_on = hang_on
    return pool


def _lock_freed(pool, within=2.0):
    """The hung worker must end and release the device's lock after the abort."""
    s = pool._get(_dev())
    if not s.lock.acquire(timeout=within):
        return False
    s.lock.release()
    return True


@pytest.mark.parametrize("hang_on, staging", [
    ("rollback", ("/rollback_change", {"params": {"device": "r1"}})),
    ("commit", ("/propose_change", {"json": {"device": "r1", "config": "interface Loopback1"}})),
])
def test_hung_confirm_is_504_outcome_unknown(hung, hang_on, staging):
    hung.hang_on("nothing yet")
    path, kw = staging
    code = _staged(path, **kw)
    hung.hang_on(hang_on)
    t0 = time.monotonic()
    r = client.post("/confirm_change", params={"code": code}, headers=H)
    took = time.monotonic() - t0
    assert r.status_code == 504, (r.status_code, r.text)
    assert DEADLINE * 0.9 < took < DEADLINE + 1.5, took
    assert "OUTCOME UNKNOWN on r1" in r.text and "Do NOT retry" in r.text and "run_read" in r.text
    assert "used up" in r.text, "the text must say the staged change is consumed"
    for word in ("APPLIED", "EXECUTED", "ROLLED BACK"):
        assert word not in r.text, r.text
    assert _lock_freed(hung)
    log = _audit_events()
    assert "confirm_timeout" in log and code in log
    assert client.post("/confirm_change", params={"code": code}, headers=H).status_code == 404


def test_hung_read_is_504_nothing_changed(hung):
    hung.hang_on("show")
    for path, params in [("/get_facts", {"device": "r1"}),
                         ("/run_read", {"device": "r1", "commands": "show clock"})]:
        t0 = time.monotonic()
        r = client.get(path, params=params, headers=H)
        assert r.status_code == 504 and "Nothing was changed" in r.text, (path, r.status_code, r.text)
        assert time.monotonic() - t0 < DEADLINE + 1.5
        assert _lock_freed(hung)
        hung.hang_on("show")        # the abort took the channel away; hang again
    assert "read_timeout" in _audit_events()


def test_hung_snapshot_stages_nothing(hung):
    hung.hang_on("running")
    before = len(main.changes.list())
    for path, kw in [("/propose_change", {"json": {"device": "r1", "config": "interface Loopback1"}}),
                     ("/rollback_change", {"params": {"device": "r1"}})]:
        r = client.post(path, headers=H, **kw)
        assert r.status_code == 504 and "Nothing was staged" in r.text and "code:" not in r.text, r.text
        assert _lock_freed(hung)
        hung.hang_on("running")
    assert len(main.changes.list()) == before
    assert "propose_timeout" in _audit_events()


def test_a_session_freed_by_abort_is_reused_after_reconnect(hung):
    hung.hang_on("show")
    assert client.get("/get_facts", params={"device": "r1"}, headers=H).status_code == 504
    assert _lock_freed(hung)
    r = client.get("/get_facts", params={"device": "r1"}, headers=H)   # reconnects (fresh FakeConn)
    assert r.status_code == 200 and "ok show" in r.text, r.text


class TimeoutRecorder(FakeConn):
    def __init__(self):
        super().__init__()
        self.timeouts = []

    def send_command(self, cmd, read_timeout=None, **kw):
        self.timeouts.append(read_timeout)
        return super().send_command(cmd)


def test_steps_get_only_the_time_left(pool):
    pool.first = conn = TimeoutRecorder()
    pool._get(_dev()).conn = conn
    pool.run(_dev(), ["show clock"], timeout=45, budget=Budget(5))
    assert conn.timeouts[0] <= 5
    pool.run(_dev(), ["show clock"], timeout=3, budget=Budget(60))
    assert conn.timeouts[1] == 3


def test_no_step_starts_after_the_deadline(pool):
    b = Budget(10)
    b.until = time.monotonic() - 1
    with pytest.raises(DeadlineExceeded):
        pool.run(_dev(), ["show clock"], budget=b)
    assert pool.first.sent == []


def test_commit_gets_an_explicit_read_timeout():
    seen = {}

    class XR:
        def commit(self, confirm=False, read_timeout=120.0):
            seen["xr"] = read_timeout
            return ""

    class Plain:            # e.g. a driver whose commit() takes no timeout at all
        def commit(self):
            seen["plain"] = True
            return ""
    Pool._commit(XR(), 12.5)
    Pool._commit(Plain(), 12.5)
    assert seen == {"xr": 12.5, "plain": True}


def test_default_step_limits_are_below_the_deadlines():
    for step, value, deadline, dname in main._step_limits():
        assert value < deadline, (step, value, dname, deadline)
