"""config/platforms/: the shipped files, and the loader that guards them."""
import pytest

from app import platforms
from app.platforms import PlatformError, load_platforms, pending_prompt


def test_shipped_platform_directory_loads():
    """The files the project ships must always be valid - this is what `--lint` checks."""
    reg = load_platforms()
    assert set(reg.platforms) == {
        "linux", "cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos", "huawei", "huawei_vrpv8",
        "fortinet", "arista_eos", "juniper_junos"}
    assert {dt for dt, p in reg.platforms.items() if p.rollback_last} == {"cisco_xr", "huawei_vrpv8", "juniper_junos"}
    assert {dt for dt, p in reg.platforms.items() if p.shell} == {"linux"}
    assert {dt for dt, p in reg.platforms.items() if p.enable} == {"cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos"}
    assert {dt for dt, p in reg.platforms.items() if not p.commits} == {"linux", "fortinet"}
    assert all(p.refuse for p in reg.platforms.values() if not p.shell)
    assert platforms._main(["--lint"]) == 0


def test_extends_inherits_and_containerlab_does_not():
    reg = load_platforms()
    ios, xe = reg.platforms["cisco_ios"], reg.platforms["cisco_xe"]
    assert xe.name == "Cisco IOS-XE" and xe.facts == ios.facts and xe.finish == ios.finish
    assert xe.sources == ("cisco_ios.yaml", "cisco_xe.yaml")
    assert "cisco_iol" in ios.kinds and "cisco_iol" not in xe.kinds and "cisco_c8000v" in xe.kinds
    assert reg.kinds["cisco_iol"] == "cisco_ios" and reg.kinds["cisco_c8000v"] == "cisco_xe"


def test_containerlab_kinds_and_default_credentials():
    reg = load_platforms()
    assert reg.kinds["huawei_vrp"] == "huawei_vrpv8" and reg.kinds["sonic-vs"] == "linux"
    assert reg.platforms["cisco_xr"].kinds == {"cisco_xrd": ("clab", "clab@123"),
                                               "cisco_xrv9k": ("clab", "clab@123"), "cisco_xrv": None}


def test_platform_prompts_come_before_the_common_ones():
    xr = platforms.get("cisco_xr")
    assert [p.proceed for p in xr.prompts][:2] == ["Y", "yes"]       # common.yaml's, in order
    assert pending_prompt("Commit? [yes,no] (yes)", "juniper_junos")[1] == "yes"
    assert pending_prompt("Commit? [yes,no] (yes)", "no_such_type")[1] == "yes"   # falls back to common



# --- refuse_in_config: what a config change must not contain ----------------
CISCO_REFUSED = ["end", "conf t", "config t", "configure terminal", "commit", "comm", "wr", "write mem",
                 "reload", "relo", "reboot", "do write", "do reload", "  END  "]
CISCO_ALLOWED = ["interface Gi0/0", " description uplink", "config-register 0x2102", "wrr-queue bandwidth 1 2",
                 "controller T1 0/0/0", "comment", "end-policy", "endif", "router bgp 65000",
                 " no shutdown", "domain-name lab", "delay 10"]
GUARDS = {
    "cisco_ios": (CISCO_REFUSED, CISCO_ALLOWED),
    "cisco_xe": (CISCO_REFUSED, CISCO_ALLOWED),
    "cisco_nxos": (CISCO_REFUSED + ["copy run start", "delete bootflash:x"], CISCO_ALLOWED),
    "arista_eos": (CISCO_REFUSED + ["copy run start", "delete flash:x"], CISCO_ALLOWED),
    "cisco_xr": (CISCO_REFUSED + ["abort", "commit replace"], CISCO_ALLOWED + ["control-plane", "commit-x"]),
    "huawei": (["return", "ret", "run display version", "save", "sa", "reboot", "commit"],
               ["sysname r1", "interface GE1/0/0", " ip address 10.0.0.1 24", "quit", "undo shutdown", "retry 3"]),
    "huawei_vrpv8": (["return", "run reset ospf process 1", "commit", "save"],
                     ["sysname r1", "quit", "ospf 1", " area 0"]),
    "juniper_junos": (["commit", "commit and-quit", "rollback 1", "load override x", "run request system reboot",
                       "top run show version", "up 2 commit", "exit", "quit configuration-mode"],
                      ["set interfaces ge-0/0/0 description x", "delete protocols ospf", "top", "up 2",
                       "set system commit synchronize"]),
    "fortinet": (["execute reboot", "exe factoryreset", "diagnose sys kill 11 1", "diag sys kill", "sudo x",
                  "fnsysctl ls", "reboot"],
                 ["config system global", "set hostname fgt", "end", "edit 1", "next", "show", "get system status"]),
}


@pytest.mark.parametrize("dt", sorted(GUARDS))
def test_config_change_guards(dt):
    p = platforms.get(dt)
    refused, allowed = GUARDS[dt]
    for line in refused:
        assert p.refused_lines([line]) == [line], (dt, line)
    for line in allowed:
        assert p.refused_lines([line]) == [], (dt, line)


def test_every_config_set_platform_has_guard_tests():
    assert set(GUARDS) == {dt for dt in platforms.known() if not platforms.get(dt).shell}


# --- loader: a minimal tree, then one defect at a time ----------------------
COMMON = """
version: 1
comment_prefixes: ['#']
prompts:
  - {pattern: '\\[y/n\\]', proceed: 'Y', abort: 'N'}
"""

CFG = """
version: 1
name: Test
facts: [show version]
snapshot: show running-config
session: {enable: true, prep: []}
change:
  apply: config_set
  finish: commit
  rollback_last: [rollback configuration last 1]
  refuse_in_config: {reason: refused, patterns: ['^end(\\s|$)']}
containerlab:
  kinds:
    cisco_xrd: {username: u, password: p}
"""

SHELL = """
version: 1
name: Shell
facts: [uptime]
snapshot: null
change: {apply: shell, finish: none, rollback_last: null}
"""


def _tree(tmp_path, **files):
    files = {"common": COMMON, "cisco_xr": CFG, "linux": SHELL, **files}
    for name, text in files.items():
        if text is not None:
            (tmp_path / f"{name}.yaml").write_text(text)
    return tmp_path


def test_minimal_tree(tmp_path):
    reg = load_platforms(_tree(tmp_path))
    xr = reg.platforms["cisco_xr"]
    assert xr.comment_prefixes == ("#",) and xr.commits and xr.enable
    assert xr.refused_lines(["interface Lo0", " END", "end-policy"]) == [" END"]
    assert reg.kinds == {"cisco_xrd": "cisco_xr"}
    assert not reg.platforms["linux"].commits


@pytest.mark.parametrize("files, message", [
    ({"common": None}, "common.yaml is missing"),
    ({"cisco_xr": CFG.replace("version: 1", "version: 2")}, "'version: 1' is required"),
    ({"cisco_xr": CFG + "colour: red\n"}, "unknown key(s) colour"),
    ({"cisco_xr": CFG.replace("facts: [show version]", "facts: []")}, "facts: must not be empty"),
    ({"cisco_xr": CFG.replace("snapshot: show running-config\n", "")}, "'snapshot' is required"),
    ({"cisco_xr": CFG.replace("finish: commit", "finish: maybe")}, "change.finish must be one of"),
    ({"cisco_xr": CFG.replace("apply: config_set", "apply: telnet")}, "change.apply must be one of"),
    ({"cisco_xr": CFG.replace("  refuse_in_config: {reason: refused, patterns: ['^end(\\s|$)']}\n", "")},
     "refuse_in_config is required"),
    ({"cisco_xr": CFG.replace("'^end(\\s|$)'", "'^end(\\s'")}, "invalid regular expression"),
    ({"cisco_xr": CFG.replace("finish: commit", "finish: none")}, "no commits to roll back"),
    ({"linux": SHELL.replace("finish: none", "finish: save")}, "set change.finish: none"),
    ({"cisco_xr": CFG.replace("{username: u, password: p}", "{username: u}")}, "both 'username' and 'password'"),
    ({"cisco_ios": SHELL + "containerlab: {kinds: {cisco_xrd: {}}}\n"}, "already mapped by"),
    ({"cisco_ios": "version: 1\nname: X\nextends: nope\n"}, "extends 'nope'"),
    ({"cisco_ios": "version: 1\nname: X\nextends: cisco_xe\n",
      "cisco_xe": "version: 1\nname: Y\nextends: cisco_xr\n"}, "only one level"),
    ({"common": COMMON.replace("proceed: 'Y'", "proceed: yes").replace("abort: 'N'", "abort: no")},
     "must be a non-empty string - quote it"),
    ({"cisco_xr": None, "cisco_foo": CFG}, "not a Netmiko device_type"),
])
def test_malformed_files_are_refused_with_a_precise_message(tmp_path, files, message):
    if message.startswith("not a Netmiko") and platforms._netmiko_types() is None:
        pytest.skip("netmiko not installed")
    with pytest.raises(PlatformError) as exc:
        load_platforms(_tree(tmp_path, **files))
    assert message in str(exc.value), str(exc.value)


def test_yml_suffix_is_refused_not_skipped(tmp_path):
    _tree(tmp_path)
    (tmp_path / "arista_eos.yml").write_text(CFG)
    with pytest.raises(PlatformError, match="must end in .yaml"):
        load_platforms(tmp_path)


# --- transport.configure follows change.apply / change.finish -----------------
@pytest.mark.parametrize("device_type, calls", [
    ("cisco_xr", ["config_set", "commit", "exit_config_mode"]),
    ("huawei_vrpv8", ["config_set", "commit", "exit_config_mode"]),
    ("juniper_junos", ["config_set", "commit", "exit_config_mode"]),
    ("cisco_ios", ["config_set", "exit_config_mode", "save_config"]),
    ("huawei", ["config_set", "exit_config_mode", "save_config"]),
    ("fortinet", ["config_set"]),
    ("linux", ["send_command"]),
])
def test_configure_follows_the_platform_file(monkeypatch, device_type, calls):
    transport = pytest.importorskip("app.transport")
    from app.inventory import Device

    class FakeConn:
        def __init__(self): self.calls = []
        def is_alive(self): return True
        def find_prompt(self): return "#"
        def send_command(self, cmd, **kw): self.calls.append("send_command"); return "ok"
        def send_config_set(self, lines, **kw): self.calls.append("config_set"); return "ok"
        def commit(self): self.calls.append("commit"); return "committed"
        def save_config(self): self.calls.append("save_config"); return "saved"
        def exit_config_mode(self): self.calls.append("exit_config_mode")
        def disconnect(self): pass
    conn = FakeConn()
    monkeypatch.setattr(transport, "ConnectHandler", lambda **kw: conn)
    dev = Device(name="d", host="h", device_type=device_type, username="u", password="p")
    pool = transport.Pool()
    pool.configure(dev, ["line one"], commit=dev.platform.commits)
    session_prep = len(dev.platform.prep)          # mmi-mode on Huawei goes through send_command
    assert conn.calls[session_prep:] == calls, conn.calls
