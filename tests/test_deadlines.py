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
