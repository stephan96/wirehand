import json, os, tempfile
from pathlib import Path
from app import clab
from app.inventory import Inventory

ANS = """all:
  children:
    cisco_xrd:
      vars: {ansible_user: clab, ansible_password: clab@123}
      hosts:
        clab-xrd-test-xrd1: {ansible_host: 172.20.20.2}
        clab-xrd-test-xrd2: {ansible_host: 172.20.20.3}
    fortinet_fortigate:
      hosts:
        clab-xrd-test-fgt1: {ansible_host: 172.20.20.9}
    unknown_kind:
      hosts:
        clab-xrd-test-x: {ansible_host: 172.20.20.99}
"""
TOPO = {"nodes": {"r11": {"kind": "huawei_vrp", "mgmt-ipv4-address": "172.20.20.11"}}}


def make(root: Path):
    (root / "xrd-test" / "clab-xrd-test").mkdir(parents=True)
    (root / "xrd-test" / "clab-xrd-test" / "ansible-inventory.yml").write_text(ANS)
    (root / "hui" / "clab-hui").mkdir(parents=True)
    (root / "hui" / "clab-hui" / "topology-data.json").write_text(json.dumps(TOPO))
    (root / "old" / "clab-old").mkdir(parents=True)  # deployed-dir without files -> ignored


def test_discover():
    root = Path(tempfile.mkdtemp()); make(root)
    devs = {d["name"]: d for d in clab.discover(root, {"credentials": {"fortinet_fortigate": {"username": "admin", "password": "x"}}})}
    assert set(devs) == {"xrd-test-xrd1", "xrd-test-xrd2", "xrd-test-fgt1", "hui-r11"}
    assert devs["xrd-test-xrd1"]["device_type"] == "cisco_xr" and devs["xrd-test-xrd1"]["password"] == "clab@123"
    assert devs["xrd-test-fgt1"]["device_type"] == "fortinet" and devs["xrd-test-fgt1"]["password"] == "x"
    assert devs["hui-r11"]["device_type"] == "huawei_vrpv8" and devs["hui-r11"]["access"] == "rw"


def test_merge_manual_wins_and_rescan():
    root = Path(tempfile.mkdtemp()); make(root)
    inv_file = root / "inventory.yaml"
    inv_file.write_text("""devices:
  xrd-test-xrd2: {host: 10.9.9.9, device_type: cisco_xr, username: me, password: pw, access: ro}
containerlab:
  default_access: ro
  credentials:
    fortinet_fortigate: {username: admin, password: env:FGTP}
""")
    os.environ["FGTP"] = "secret"
    inv = Inventory(inv_file, str(root))
    d = inv.get("xrd-test-xrd2")
    assert d.host == "10.9.9.9" and d.source == "inventory.yaml"
    assert inv.get("xrd-test-xrd1").access == "ro" and inv.get("xrd-test-xrd1").source == "containerlab:xrd-test"
    assert inv.get("xrd-test-fgt1").password == "secret"
    # lab destroyed -> disappears on rescan
    import shutil; shutil.rmtree(root / "xrd-test" / "clab-xrd-test")
    inv._last_scan = 0
    assert "xrd-test-xrd1" not in [x.name for x in inv.all()]
    assert "hui-r11" in [x.name for x in inv.all()]


def test_missing_inventory_file_ok():
    root = Path(tempfile.mkdtemp()); make(root)
    inv = Inventory(root / "nope.yaml", str(root))
    assert len(inv.all()) == 4


def test_manual_edit_triggers_rescan(tmp_path):
    make(tmp_path)
    inv_file = tmp_path / "inventory.yaml"
    inv_file.write_text("devices: {}\ncontainerlab: {default_access: rw}\n")
    inv = Inventory(inv_file, str(tmp_path))
    assert "ubuntu2" not in [d.name for d in inv.all()]
    inv_file.write_text("""devices:
  ubuntu2: {host: 127.0.0.1, device_type: linux, username: u, password: p, access: ro}
""")
    import os as _os
    _os.utime(inv_file, (0, 9999999999))   # ensure mtime differs even on fast fs
    inv._last_scan = 0
    assert "ubuntu2" in [d.name for d in inv.all()]


def test_no_clab_dir_still_rescans_manual(tmp_path):
    inv_file = tmp_path / "inventory.yaml"
    inv_file.write_text("devices: {}\n")
    inv = Inventory(inv_file, "")
    inv_file.write_text("devices:\n  s1: {host: 1.1.1.1, device_type: linux, username: u, password: p}\n")
    import os as _os
    _os.utime(inv_file, (0, 9999999999))
    inv._last_scan = 0
    assert [d.name for d in inv.all()] == ["s1"]


def test_retry_once_after_dead_session(monkeypatch, tmp_path):
    from app import transport
    from app.inventory import Device
    calls = {"n": 0}
    class FakeConn:
        def __init__(self, fail_first): self.fail_first = fail_first
        def is_alive(self): return True
        def send_command(self, cmd, **kw):
            calls["n"] += 1
            if self.fail_first and calls["n"] == 1:
                raise OSError("Socket is closed")
            return f"ok {cmd}"
        def disconnect(self): pass
        def disable_paging(self): pass
    conns = [FakeConn(True), FakeConn(False)]
    monkeypatch.setattr(transport, "ConnectHandler", lambda **kw: conns.pop(0))
    dev = Device(name="d", host="h", device_type="fortinet", username="u", password="p")
    pool = transport.Pool()
    res = pool.run(dev, ["get system status"])
    assert res == [("get system status", "ok get system status")]
    assert calls["n"] == 2


def test_reachability_check():
    import socket, threading
    from app.transport import check_devices
    from app.inventory import Device
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    up = Device(name="up", host="127.0.0.1", device_type="linux", username="u", password="p", port=port)
    down = Device(name="down", host="127.0.0.1", device_type="linux", username="u", password="p", port=1)
    state = check_devices([up, down])
    srv.close()
    assert state == {"up": True, "down": False}


def test_corrected_password_retires_pooled_session(monkeypatch):
    """An auth failure must not block the device: once the inventory hands out a
    corrected password, the next call opens a NEW session with it."""
    from app import transport
    from app.inventory import Device
    from netmiko import NetmikoAuthenticationException
    opened = []
    class FakeConn:
        def __init__(self, pw): self.pw = pw
        def is_alive(self): return True
        def send_command(self, cmd, **kw): return f"ok {cmd}"
        def disconnect(self): pass
        def find_prompt(self): return "#"
    def connect(**kw):
        opened.append(kw["password"])
        if kw["password"] == "wrong":
            raise NetmikoAuthenticationException("Authentication failure")
        return FakeConn(kw["password"])
    monkeypatch.setattr(transport, "ConnectHandler", connect)
    pool = transport.Pool()

    bad = Device(name="d", host="h", device_type="linux", username="u", password="wrong")
    try:
        pool.run(bad, ["uptime"])
        assert False, "expected AuthError"
    except transport.AuthError as exc:
        assert "NOT permanent" in str(exc)          # message invites a retry after the fix
        assert "FINAL" not in str(exc)

    # same (still wrong) credentials -> a fresh attempt is made, not a cached refusal
    try:
        pool.run(bad, ["uptime"])
        assert False, "expected AuthError"
    except transport.AuthError:
        pass
    assert opened == ["wrong", "wrong"]

    # inventory reload with the corrected password -> session is retired, call succeeds
    good = Device(name="d", host="h", device_type="linux", username="u", password="right")
    assert pool.run(good, ["uptime"]) == [("uptime", "ok uptime")]
    assert opened == ["wrong", "wrong", "right"]


def test_unchanged_device_keeps_pooled_session(monkeypatch):
    """A clab rescan hands out equal-but-new Device objects every 30s; that must
    not throw away the pooled connection."""
    from app import transport
    from app.inventory import Device
    opened = []
    class FakeConn:
        def is_alive(self): return True
        def send_command(self, cmd, **kw): return f"ok {cmd}"
        def disconnect(self): pass
        def find_prompt(self): return "#"
    monkeypatch.setattr(transport, "ConnectHandler", lambda **kw: (opened.append(1), FakeConn())[1])
    pool = transport.Pool()
    kw = dict(name="d", host="h", device_type="linux", username="u", password="p")
    pool.run(Device(**kw), ["uptime"])
    pool.run(Device(**kw), ["uptime"])          # equal, but a different object
    assert len(opened) == 1


def test_clab_confirm_defaults_and_per_kind_override(tmp_path):
    """`default_confirm` reaches discovered nodes, and a per-kind `confirm: off`
    is not swallowed by YAML 1.1 turning it into False."""
    make(tmp_path)
    inv_file = tmp_path / "inventory.yaml"
    inv_file.write_text("""devices: {}
containerlab:
  default_confirm: totp
  kinds:
    cisco_xrd: {confirm: off}
    huawei_vrp: {access: ro}
  credentials:
    fortinet_fortigate: {username: admin, password: x}
""")
    inv = Inventory(inv_file, str(tmp_path))
    assert inv.get("xrd-test-xrd1").confirm == "off"      # per-kind wins over the default
    assert inv.get("xrd-test-fgt1").confirm == "totp"     # falls back to default_confirm
    assert inv.get("hui-r11").confirm == "totp"           # ... also on the topology-json path
    assert inv.get("hui-r11").access == "ro"              # per-kind access still applies


def test_bad_inventory_keys_name_the_device(tmp_path):
    """A typo or a missing key must fail the load with a message that says WHICH
    device is wrong - a bare TypeError from Device(**spec) does not."""
    inv_file = tmp_path / "inventory.yaml"

    def err(body: str) -> str:
        inv_file.write_text(body)
        try:
            Inventory(inv_file, "")
        except RuntimeError as exc:
            return str(exc)
        raise AssertionError("expected RuntimeError")

    msg = err("devices:\n  core-sw1: {host: 1.1.1.1, device_type: linux, username: u, passwrod: p}\n")
    assert "core-sw1" in msg and "passwrod" in msg and "password" in msg   # names the typo and the real key
    assert "device_type" in err("devices:\n  core-sw1: {host: 1.1.1.1, username: u}\n")
    assert "username" in err("devices:\n  core-sw1: {host: 1.1.1.1, device_type: linux}\n")

    # every key the README documents is accepted
    inv_file.write_text("""devices:
  core-sw1:
    host: 1.1.1.1
    device_type: cisco_ios
    username: u
    password: p
    secret: s
    port: 2222
    timeout: 60
    access: rw
    confirm: off
    description: d
    tags: [a]
""")
    d = Inventory(inv_file, "").get("core-sw1")
    assert (d.port, d.timeout, d.secret, d.confirm) == (2222, 60, "s", "off")
    assert d.netmiko_kwargs()["password"] == "p" and "key_file" not in d.netmiko_kwargs()
