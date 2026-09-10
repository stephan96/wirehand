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
