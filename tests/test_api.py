"""End-to-end API test with a fake SSH pool (no real devices)."""
import os, sys, tempfile
os.environ["WIREHAND_API_KEY"] = "k"
os.environ["WIREHAND_DATA"] = tempfile.mkdtemp()
inv = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
inv.write("""devices:
  r1: {host: 1.1.1.1, device_type: cisco_xr, username: u, password: p, access: rw}
  s1: {host: 1.1.1.2, device_type: linux, username: u, password: p, access: ro}
""")
inv.close()
os.environ["WIREHAND_INVENTORY"] = inv.name
os.environ["LAB"] = "x"
for m in list(sys.modules):
    if m.startswith("app"):
        del sys.modules[m]

from fastapi.testclient import TestClient
from app import main

RUNNING = "interface Loopback0\n ipv4 address 1.1.1.1/32\ninterface GigabitEthernet0/0/0/0\n description uplink\n"

class FakePool:
    def __init__(self): self.configured = []
    def run(self, dev, cmds, timeout=60):
        return [(c, RUNNING if "running" in c else f"out of {c} on {dev.name}") for c in cmds]
    def configure(self, dev, lines, commit):
        self.configured.append((dev.name, lines, commit)); return "Commit complete"
    def close_all(self): pass

main.pool = FakePool()
H = {"Authorization": "Bearer k"}
c = TestClient(main.app)

assert c.get("/list_devices").status_code == 401
assert "r1" in c.get("/list_devices", headers=H).text
assert "out of show version" in c.get("/get_facts", params={"device": "r1"}, headers=H).text
r = c.get("/run_read", params={"device": "r1,s1", "commands": "show running-config", "filter": "loopback", "context": 1}, headers=H)
assert "Loopback0" in r.text and "uplink" not in r.text and "=== s1" in r.text, r.text
assert c.get("/run_read", params={"device": "s1", "commands": "sudo reboot"}, headers=H).status_code == 403
assert c.get("/run_read", params={"device": "nope", "commands": "uptime"}, headers=H).status_code == 404

p = c.post("/propose_change", json={"device": "r1", "config": "interface Loopback10\n description test"}, headers=H)
assert p.status_code == 200 and "STAGED" in p.text, p.text
code = p.text.split("code: ")[1][:6]
assert c.post("/propose_change", json={"device": "s1", "config": "echo hi"}, headers=H).status_code == 403
assert c.post("/confirm_change", params={"code": "ZZZZZZ"}, headers=H).status_code == 404
a = c.post("/confirm_change", params={"code": code}, headers=H)
assert a.status_code == 200 and "APPLIED" in a.text and main.pool.configured[0][1] == ["interface Loopback10", " description test"], a.text
assert c.post("/confirm_change", params={"code": code}, headers=H).status_code == 404  # single use
assert "rollback configuration last 1" in c.post("/rollback_change", params={"device": "r1"}, headers=H).text
log = c.get("/get_audit_log", headers=H).text
assert "propose_change" in log and "confirm_change" in log
ops = [op["operationId"] for p_ in c.get("/openapi.json").json()["paths"].values() for op in p_.values()]
print("tools:", ops)
print("OK")
pre = c.options("/openapi.json", headers={"Origin": "http://llm-srv1:3000", "Access-Control-Request-Method": "GET"})
assert pre.status_code == 200 and pre.headers.get("access-control-allow-origin"), pre.status_code
print("CORS OK")
pre = c.options("/get_facts", params={"device": "r1"}, headers={"Origin": "http://x", "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization,content-type,x-requested-with,accept"})
assert pre.status_code == 200, pre.text
print("CORS wide OK")
p = c.post("/propose_change", json={"device": "r1", "config": "reset ospf process 1", "mode": "exec"}, headers=H)
assert p.status_code == 200 and "user/exec view" in p.text, p.text
code2 = p.text.split("code: ")[1][:6]
a = c.post("/confirm_change", params={"code": code2}, headers=H)
assert "EXECUTED" in a.text and "reset ospf process 1" in a.text and len(main.pool.configured) == 1, a.text
assert c.post("/propose_change", json={"device": "r1", "config": "x", "mode": "wrong"}, headers=H).status_code == 400
print("EXEC MODE OK")
# fortinet: blocks with config/end allowed, missing end auto-appended, honest preview
import yaml as _yaml
inv2 = open(os.environ["WIREHAND_INVENTORY"]).read()
open(os.environ["WIREHAND_INVENTORY"], "w").write(inv2 + "  fgt: {host: 1.1.1.3, device_type: fortinet, username: u, password: p, access: rw}\n")
c.get("/list_devices", params={"refresh": "true"}, headers=H)
p = c.post("/propose_change", json={"device": "fgt", "config": "config system global\nset lldp-reception enable"}, headers=H)
assert p.status_code == 200 and "+ end" in p.text and "lldp-reception" in p.text, p.text
code3 = p.text.split("code: ")[1][:6]
a = c.post("/confirm_change", params={"code": code3}, headers=H)
assert a.status_code == 200 and main.pool.configured[-1][1][-1] == "end", a.text
# ios still rejects end
p = c.post("/propose_change", json={"device": "r1", "config": "interface Lo1\nend"}, headers=H)
assert p.status_code == 400, p.text
print("FORTINET BLOCKS OK")
# auth failure: 401 (not 502), terminal wording, never retried, audited
from app.transport import AuthError
class AuthFailPool(FakePool):
    def __init__(self): FakePool.__init__(self); self.attempts = 0
    def run(self, dev, cmds, timeout=60):
        if dev.name == "s1":
            self.attempts += 1
            raise AuthError("AUTHENTICATION FAILED for 's1' (linux, user 'u'). This is FINAL: do not retry this device.")
        return FakePool.run(self, dev, cmds, timeout)
afp = AuthFailPool(); main.pool = afp
r = c.get("/get_facts", params={"device": "s1"}, headers=H)
assert r.status_code == 401 and "FINAL" in r.text, (r.status_code, r.text)
r = c.get("/run_read", params={"device": "s1,r1", "commands": "uptime"}, headers=H)
assert "AUTHENTICATION FAILED" in r.text and "=== r1" in r.text, r.text   # other devices still processed
assert afp.attempts == 2, afp.attempts                                    # one per call, never retried
assert "auth_failed" in c.get("/get_audit_log", headers=H).text
main.pool = FakePool()
print("AUTH STOP OK")
# health check: duplicate mgmt IPs across labs -> 'up?' + warning
import app.main as _m
_m.inventory.reload()
orig_check = _m.check_devices
_m.check_devices = lambda devs: {d.name: True for d in devs}
inv3 = open(os.environ["WIREHAND_INVENTORY"]).read()
open(os.environ["WIREHAND_INVENTORY"], "w").write(
    inv3 + "  labA-x: {host: 172.20.20.2, device_type: linux, username: u, password: p}\n"
           "  labB-x: {host: 172.20.20.2, device_type: linux, username: u, password: p}\n")
r = c.get("/list_devices", params={"refresh": "true", "check": "true"}, headers=H).text
assert "up?" in r and "WARNING" in r and "172.20.20.2 -> labA-x, labB-x" in r, r
assert r.count("up?   ") == 2 and "ipv4-subnet" in r, r
_m.check_devices = orig_check
print("SHARED IP WARNING OK")
