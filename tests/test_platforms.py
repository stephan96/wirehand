# SPDX-FileCopyrightText: 2026 Stephan Baenisch
# SPDX-License-Identifier: Apache-2.0
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
CISCO_REFUSED = ["conf t", "config t", "configure terminal", "commit", "comm", "wr", "write mem",
                 "reload", "relo", "reboot", "do write", "do reload", "  DO WR  "]
CISCO_ALLOWED = ["end", "exit", "interface Gi0/0", " description uplink", "config-register 0x2102", "wrr-queue bandwidth 1 2",
                 "controller T1 0/0/0", "comment", "end-policy", "endif", "router bgp 65000",
                 " no shutdown", "domain-name lab", "delay 10"]
GUARDS = {
    "cisco_ios": (CISCO_REFUSED, CISCO_ALLOWED),
    "cisco_xe": (CISCO_REFUSED, CISCO_ALLOWED),
    "cisco_nxos": (CISCO_REFUSED + ["copy run start", "delete bootflash:x"], CISCO_ALLOWED),
    "arista_eos": (CISCO_REFUSED + ["copy run start", "delete flash:x"], CISCO_ALLOWED),
    "cisco_xr": (CISCO_REFUSED + ["abort", "commit replace"], CISCO_ALLOWED + ["control-plane", "commit-x"]),
    "huawei": (["run display version", "save", "sa", "reboot", "commit"],
               ["sysname r1", "interface GE1/0/0", " ip address 10.0.0.1 24", "quit", "return", "undo shutdown", "retry 3"]),
    "huawei_vrpv8": (["run reset ospf process 1", "commit", "save"],
                     ["sysname r1", "quit", "return", "ospf 1", " area 0"]),
    "juniper_junos": (["commit", "commit and-quit", "rollback 1", "load override x", "run request system reboot",
                       "top run show version", "up 2 commit"],
                      ["set interfaces ge-0/0/0 description x", "delete protocols ospf", "top", "up 2", "exit", "quit",
                       "edit interfaces ge-0/0/0",
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


@pytest.mark.parametrize("dt, lines, kept", [
    ("cisco_xr", ["interface Lo1", " exit", "end"], ["interface Lo1"]),
    ("cisco_xr", ["interface Lo1", "end", "interface Lo2"], ["interface Lo1", "end", "interface Lo2"]),
    ("cisco_ios", ["interface Lo1", "end-policy"], ["interface Lo1", "end-policy"]),
    ("huawei_vrpv8", ["interface LoopBack1", "quit", "return"], ["interface LoopBack1"]),
    ("huawei", ["sysname r1", "return"], ["sysname r1"]),
    ("juniper_junos", ["set system host-name r1", "top", "exit configuration-mode"], ["set system host-name r1"]),
    ("fortinet", ["config system global", "set hostname f", "end"], ["config system global", "set hostname f", "end"]),
])
def test_trailing_mode_exits_are_dropped(dt, lines, kept):
    got, dropped = platforms.get(dt).split_trailing(lines)
    assert got == kept and got + dropped == lines


@pytest.mark.parametrize("dt, lines, misplaced", [
    ("cisco_xr", ["interface Lo1", "end", "interface Lo2"], ["end"]),
    ("cisco_xr", ["interface Lo1", " exit", "interface Lo2"], []),          # exit only moves up
    ("cisco_ios", ["interface Lo1", "end-policy", "endif"], []),
    ("huawei_vrpv8", ["interface LoopBack1", "return", "sysname r1"], ["return"]),
    ("huawei_vrpv8", ["interface LoopBack1", "quit", "sysname r1"], []),
    ("juniper_junos", ["set a", "exit", "set b"], []),
    ("fortinet", ["config system global", "end", "config system dns", "end"], []),
])
def test_mode_exits_only_as_the_last_line(dt, lines, misplaced):
    p = platforms.get(dt)
    kept, _ = p.split_trailing(lines + ["end" if dt != "huawei_vrpv8" else "return"])
    assert p.misplaced_lines(kept) == misplaced


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
    ({"linux": SHELL.replace("rollback_last: null}", "rollback_last: null, drop_trailing: ['^end$']}")},
     "only apply to change.apply: config_set"),
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
        def config_mode(self): pass
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


# --- change.config_errors: a rejected line stops the change --------------------
REJECT = "interface Ethernet3/0/1\n                               ^\nError[1]: Unrecognized command found at '^' position.\n[*vrp3-Ethernet3/0/0]"


@pytest.mark.parametrize("dt", ["huawei", "huawei_vrpv8"])
def test_huawei_recognises_rejected_lines(dt):
    p = platforms.get(dt)
    assert p.config_error(REJECT) == "Error[1]: Unrecognized command found at '^' position."
    assert p.config_error("Error: Wrong parameter found at '^' position.")
    assert p.config_error("[*vrp3-LoopBack1]description Error: not a device error") is None
    assert p.config_error("Warning: The slave board is not in position.") is None
    assert "quit" in p.error_hint


def test_only_vrp8_discards():
    assert platforms.get("huawei_vrpv8").discard == ("clear configuration candidate",)
    assert platforms.get("huawei").discard == () and platforms.get("huawei").dirty_prompt is None


CE = "  config_errors: {patterns: ['^Error:'], discard: [abort], dirty_prompt: '^\\[\\*'}\n"


def test_config_errors_load(tmp_path):
    xr = load_platforms(_tree(tmp_path, cisco_xr=CFG.replace("containerlab:", CE + "containerlab:"))).platforms["cisco_xr"]
    assert xr.discard == ("abort",) and xr.dirty_prompt.search("[*r1]") and xr.config_error("Error: x")


@pytest.mark.parametrize("files, message", [
    ({"cisco_xr": CFG.replace("finish: commit", "finish: save").replace("  rollback_last: [rollback configuration last 1]\n", "  rollback_last: null\n").replace("containerlab:", CE + "containerlab:")},
     "need change.finish: commit"),
    ({"cisco_xr": CFG.replace("containerlab:", "  config_errors: {patterns: []}\ncontainerlab:")}, "patterns must be a non-empty list"),
    ({"cisco_xr": CFG.replace("containerlab:", "  config_errors: {patterns: ['^E'], dirty_prompt: 'x'}\ncontainerlab:")},
     "list the discard commands"),
    ({"cisco_xr": CFG.replace("containerlab:", "  config_errors: {patterns: ['^E'], colour: red}\ncontainerlab:")}, "unknown key(s) colour"),
    ({"linux": SHELL.replace("rollback_last: null}", "rollback_last: null, config_errors: {patterns: ['^E']}}")},
     "only applies to change.apply: config_set"),
])
def test_config_errors_are_validated(tmp_path, files, message):
    with pytest.raises(PlatformError) as exc:
        load_platforms(_tree(tmp_path, **files))
    assert message in str(exc.value), str(exc.value)


class RejectingConn:
    """Answers every config line with a prompt, the `bad` one with Huawei's error."""
    def __init__(self, bad: str, prompt_after_discard: str = "[~vrp3]"):
        self.bad, self.after = bad, prompt_after_discard
        self.calls, self.sent = [], []
    def is_alive(self): return True
    def find_prompt(self): return self.after
    def config_mode(self): pass
    def send_command(self, cmd, **kw): return ""
    def send_config_set(self, lines, **kw):
        self.calls.append("config_set"); self.sent += lines
        return REJECT if lines == [self.bad] else f"{lines[0]}\n[*vrp3-x]"
    def commit(self, **kw): self.calls.append("commit"); return "committed"
    def save_config(self): self.calls.append("save_config"); return "saved"
    def exit_config_mode(self): self.calls.append("exit_config_mode")
    def disconnect(self): pass


LINES = ["interface Ethernet3/0/0", " ip address 1.1.1.1 255.255.255.0",
         "interface Ethernet3/0/1", " ip address 1.1.1.2 255.255.255.0"]


def _configure(monkeypatch, device_type, conn, lines=LINES):
    transport = pytest.importorskip("app.transport")
    from app.inventory import Device
    monkeypatch.setattr(transport, "ConnectHandler", lambda **kw: conn)
    dev = Device(name="vrp3", host="h", device_type=device_type, username="u", password="p")
    with pytest.raises(transport.ConfigRejected) as exc:
        transport.Pool().configure(dev, lines, commit=dev.platform.commits)
    return exc.value


@pytest.mark.parametrize("after, state", [("[~vrp3]", "discarded"), ("[*vrp3]", "unverified")])
def test_vrp8_rejected_line_is_not_committed_but_discarded(monkeypatch, after, state):
    conn = RejectingConn("interface Ethernet3/0/1", after)
    exc = _configure(monkeypatch, "huawei_vrpv8", conn)
    assert exc.state == state and exc.index == 2 and exc.line == "interface Ethernet3/0/1"
    # the line after the rejected one must NOT reach the device (it would land on Ethernet3/0/0)
    assert conn.sent == LINES[:3] + ["clear configuration candidate"], conn.sent
    assert "commit" not in conn.calls and "Error[1]" in exc.output


@pytest.mark.parametrize("bad, state, index", [("interface Ethernet3/0/1", "partial", 2),
                                               ("interface Ethernet3/0/0", "nothing", 0)])
def test_vrp5_rejected_line_is_not_saved(monkeypatch, bad, state, index):
    conn = RejectingConn(bad)
    exc = _configure(monkeypatch, "huawei", conn)
    assert exc.state == state and exc.index == index
    assert conn.sent == LINES[:index + 1] and "save_config" not in conn.calls


def test_accepted_lines_go_one_at_a_time_and_commit(monkeypatch):
    transport = pytest.importorskip("app.transport")
    from app.inventory import Device
    conn = RejectingConn("never sent")
    monkeypatch.setattr(transport, "ConnectHandler", lambda **kw: conn)
    dev = Device(name="vrp3", host="h", device_type="huawei_vrpv8", username="u", password="p")
    transport.Pool().configure(dev, LINES, commit=True)
    assert conn.sent == LINES and conn.calls == ["config_set"] * 4 + ["commit", "exit_config_mode"]


# --- change.close_views: insert the 'quit' that mmi-mode needs -----------------
def _cv(lines, dt="huawei_vrpv8"):
    out, added = platforms.get(dt).close_views(lines)
    return [("+ " if i in added else "  ") + ln for i, ln in enumerate(out)]


@pytest.mark.parametrize("dt", ["huawei", "huawei_vrpv8"])
def test_flat_change_is_left_to_the_device(dt):
    """Without indentation wirehand cannot know where a view ends ('isis ipv6
    enable 1' is an interface line, 'isis 1' opens a view): nothing is inserted,
    the apply step leaves a view where the device rejects a line."""
    lines = ["interface LoopBack1", "ipv6 enable", "isis ipv6 enable 1",
             "interface Ethernet3/0/1", "isis cost 100", "isis 1", "is-level level-2"]
    assert _cv(lines, dt) == ["  " + ln for ln in lines]


AAA = ["aaa", " local-user ansible level 3",
       " authentication-scheme default_admin", "  authentication-mode local hwtacacs",
       " authorization-scheme default_admin", "  authorization-mode local hwtacacs",
       "stelnet server enable"]


def test_indented_change_closes_every_view_it_leaves():
    """Issue #47, second example, without the quit lines the model forgot."""
    assert _cv(AAA) == [
        "  aaa", "   local-user ansible level 3",
        "   authentication-scheme default_admin", "    authentication-mode local hwtacacs",
        "+ quit", "   authorization-scheme default_admin", "    authorization-mode local hwtacacs",
        "+ quit", "+ quit", "  stelnet server enable"]


def test_quit_lines_already_there_are_kept_and_counted():
    with_quits = AAA[:4] + [" quit"] + AAA[4:6] + [" quit", " quit"] + AAA[6:]
    assert _cv(with_quits) == ["  " + ln for ln in with_quits]
    # one of the two missing: only the other one is added
    one = AAA[:4] + [" quit"] + AAA[4:6] + [" quit"] + AAA[6:]
    assert _cv(one).count("+ quit") == 1


def test_indented_top_level_lines_close_the_view():
    """Display-config layout, also for a line that is no known opener."""
    assert _cv(["interface LoopBack1", " description a", "ip route-static 0.0.0.0 0 10.0.0.1"]) == [
        "  interface LoopBack1", "   description a", "+ quit", "  ip route-static 0.0.0.0 0 10.0.0.1"]
    # a whole change indented by one space is the same change
    assert _cv([" interface LoopBack1", "  description a", " interface LoopBack2"]).count("+ quit") == 1


@pytest.mark.parametrize("lines", [
    ["vlan batch 10 20", "vlan batch 30"],                         # no view
    ["undo interface LoopBack1", "undo interface LoopBack2"],      # no view
    ["interface LoopBack1", "quit", "interface LoopBack2"],        # already left
    ["sysname r1", "lldp enable"],
    ["interface LoopBack1", " description a"],                    # nothing after the view
])
def test_nothing_added_where_nothing_is_missing(lines):
    assert _cv(lines) == ["  " + ln for ln in lines]


def test_other_platforms_are_untouched():
    lines = ["interface Gi0/0", " description a", "interface Gi0/1"]
    assert platforms.get("cisco_ios").close_views(lines) == (lines, {})


CV = ("  drop_trailing: ['^quit$']\n  config_errors: {patterns: ['^Error:']}\n"
      "  close_views: {command: quit, retry_on: [Unrecognized], view_prompt: '^\\[[~*]?(.+)\\]$'}\n")


def test_close_views_load(tmp_path):
    xr = load_platforms(_tree(tmp_path, cisco_xr=CFG.replace("containerlab:", CV + "containerlab:"))).platforms["cisco_xr"]
    assert xr.close_cmd == "quit" and xr.close_views(["interface a", " x", "interface b"])[1] == {2: "interface a"}
    assert xr.retry_in_parent("Error: Unrecognized command") and not xr.retry_in_parent("Error: Wrong parameter")
    assert xr.view_of("[*r1-GigabitEthernet0/0]") == "r1-GigabitEthernet0/0" and xr.view_of("<r1>") is None


@pytest.mark.parametrize("dt", ["huawei", "huawei_vrpv8"])
def test_huawei_views(dt):
    p = platforms.get(dt)
    assert p.retry_in_parent(REJECT)
    assert not p.retry_in_parent("Error: Wrong parameter found at '^' position.")
    assert p.view_of("[~wirehand-lab-vrp3]") == "wirehand-lab-vrp3"
    assert p.view_of("[*wirehand-lab-vrp3-LoopBack1]") == "wirehand-lab-vrp3-LoopBack1"
    assert p.view_of("[vrp3-aaa-authen-default]") == "vrp3-aaa-authen-default"


@pytest.mark.parametrize("files, message", [
    ({"cisco_xr": CFG.replace("containerlab:", CV.replace("  drop_trailing: ['^quit$']\n", "") + "containerlab:")},
     "must also match change.drop_trailing"),
    ({"cisco_xr": CFG.replace("containerlab:", CV.replace("command: quit", "command: 'quit now'") + "containerlab:")},
     "must be one word"),
    ({"linux": SHELL.replace("rollback_last: null}", "rollback_last: null, close_views: {command: quit}}")},
     "only applies to change.apply: config_set"),
    ({"cisco_xr": CFG.replace("containerlab:", CV.replace("  config_errors: {patterns: ['^Error:']}\n", "") + "containerlab:")},
     "needs change.config_errors"),
    ({"cisco_xr": CFG.replace("containerlab:", CV.replace("retry_on: [Unrecognized], ", "") + "containerlab:")},
     "retry_on must be a non-empty list"),
    ({"cisco_xr": CFG.replace("containerlab:", CV.replace("(.+)", ".+") + "containerlab:")},
     "group 1 is the view"),
    ({"cisco_xr": CFG.replace("containerlab:", CV.replace("retry_on", "openers") + "containerlab:")},
     "unknown key(s) openers"),
])
def test_close_views_is_validated(tmp_path, files, message):
    with pytest.raises(PlatformError) as exc:
        load_platforms(_tree(tmp_path, **files))
    assert message in str(exc.value), str(exc.value)


# --- change.close_views.retry_on: the device decides where a line belongs ----
class ViewConn:
    """A VRP8 in mmi-mode, reduced to views: an opener opens a view from
    system-view; in a sub-view, a line belonging to another view is rejected
    as unknown instead of falling back to the parent view."""
    OPENERS = ("interface ", "isis 1", "aaa")
    SYSTEM_ONLY = ("ip route-static", "sysname")
    UNKNOWN = "Error[1]: Unrecognized command found at '^' position.\n"

    def __init__(self):
        self.view, self.sent, self.calls, self.dirty = [], [], [], False
    def is_alive(self): return True
    def config_mode(self): self.calls.append("config_mode")
    def find_prompt(self): return "[" + "~*"[self.dirty] + "-".join(["vrp3"] + self.view) + "]"
    def send_command(self, cmd, **kw): return ""
    def commit(self, **kw): self.calls.append("commit"); return "committed"
    def exit_config_mode(self): self.calls.append("exit_config_mode")
    def disconnect(self): pass
    def send_config_set(self, lines, **kw):
        (ln,) = lines
        self.sent.append(ln)
        echo = f"{self.find_prompt()}{ln}\n"
        if ln == "quit":
            self.view.pop()
        elif ln == "clear configuration candidate":
            self.view, self.dirty = [], False
            return echo + self.find_prompt()
        elif ln.startswith("bogus"):
            return echo + self.UNKNOWN + self.find_prompt()
        elif ln.startswith(self.OPENERS + self.SYSTEM_ONLY):
            if self.view:
                return echo + self.UNKNOWN + self.find_prompt()
            if ln.startswith(self.OPENERS):
                self.view.append(ln.split()[-1] if ln.startswith("interface") else ln.replace(" ", "-"))
        elif not self.view:
            return echo + self.UNKNOWN + self.find_prompt()
        self.dirty = True
        return echo + self.find_prompt()


ISIS = ["interface LoopBack1", "ipv6 enable", "isis ipv6 enable 1",
        "interface Ethernet3/0/1", "isis ipv6 enable 1", "isis circuit-type p2p", "isis cost 100",
        "isis 1", "is-level level-2", "ip route-static 0.0.0.0 0 10.0.0.1"]


def _apply(monkeypatch, lines, conn):
    transport = pytest.importorskip("app.transport")
    from app.inventory import Device
    monkeypatch.setattr(transport, "ConnectHandler", lambda **kw: conn)
    dev = Device(name="vrp3", host="h", device_type="huawei_vrpv8", username="u", password="p")
    return transport.Pool().configure(dev, lines, commit=True)


def test_flat_change_leaves_a_view_only_where_the_device_rejects_a_line(monkeypatch):
    """The change from the bug report: the interface isis lines stay in their
    interface; 'interface Ethernet3/0/1' and 'isis 1' each leave one view,
    'ip route-static' leaves the isis view."""
    conn = ViewConn()
    out = _apply(monkeypatch, ISIS, conn)
    assert conn.sent == [
        "interface LoopBack1", "ipv6 enable", "isis ipv6 enable 1",
        "interface Ethernet3/0/1", "quit", "interface Ethernet3/0/1",
        "isis ipv6 enable 1", "isis circuit-type p2p", "isis cost 100",
        "isis 1", "quit", "isis 1", "is-level level-2",
        "ip route-static 0.0.0.0 0 10.0.0.1", "quit", "ip route-static 0.0.0.0 0 10.0.0.1"]
    assert conn.calls == ["config_mode", "commit", "exit_config_mode"]
    assert out.startswith("3 'quit' line(s) sent"), out
    assert "line 4 'interface Ethernet3/0/1': rejected in 'vrp3-LoopBack1', accepted after 1 'quit'" in out


def test_nested_views_are_left_one_by_one(monkeypatch):
    conn = ViewConn()
    out = _apply(monkeypatch, ["aaa", "interface LoopBack9", "description x", "sysname r9"], conn)
    assert conn.sent == ["aaa", "interface LoopBack9", "quit", "interface LoopBack9", "description x",
                         "sysname r9", "quit", "sysname r9"]
    assert out.startswith("2 'quit' line(s) sent"), out


def test_two_views_left_for_one_line(monkeypatch):
    class Nested(ViewConn):
        def send_config_set(self, lines, **kw):
            if lines == ["authentication-scheme a"] and self.view == ["aaa"]:
                self.sent += lines
                self.view.append("authen-a")
                return self.find_prompt()
            return super().send_config_set(lines, **kw)
    conn = Nested()
    out = _apply(monkeypatch, ["aaa", "authentication-scheme a", "authentication-mode local", "sysname r9"], conn)
    # tried in every view on the way out, as VRP does outside mmi-mode
    assert conn.sent[-5:] == ["sysname r9", "quit", "sysname r9", "quit", "sysname r9"]
    assert "rejected in 'vrp3-aaa-authen-a' and 'vrp3-aaa', accepted after 2 'quit'" in out


def test_indented_change_needs_no_fallback(monkeypatch):
    conn = ViewConn()
    out = _apply(monkeypatch, ["interface LoopBack1", " ipv6 enable", "quit", "isis 1", " is-level level-2"], conn)
    assert conn.sent.count("quit") == 1 and "line(s) sent" not in out


def test_line_unknown_in_system_view_too_is_rejected_and_discarded(monkeypatch):
    """Never 'quit' out of system-view: the line is rejected, nothing committed."""
    transport = pytest.importorskip("app.transport")
    conn = ViewConn()
    with pytest.raises(transport.ConfigRejected) as exc:
        _apply(monkeypatch, ["interface LoopBack1", "description x", "bogus line"], conn)
    assert conn.sent == ["interface LoopBack1", "description x", "bogus line", "quit", "bogus line",
                         "clear configuration candidate"]
    assert exc.value.index == 2 and exc.value.state == "discarded"
    assert "also after leaving 'vrp3-LoopBack1' with 'quit'" in exc.value.error
    assert "commit" not in conn.calls


def test_other_errors_do_not_leave_the_view(monkeypatch):
    transport = pytest.importorskip("app.transport")

    class Wrong(ViewConn):
        def send_config_set(self, lines, **kw):
            if lines == ["ip address 1.1.1.1"]:
                self.sent += lines
                return "Error: Incomplete command found at '^' position.\n" + self.find_prompt()
            return super().send_config_set(lines, **kw)
    conn = Wrong()
    with pytest.raises(transport.ConfigRejected):
        _apply(monkeypatch, ["interface LoopBack1", "ip address 1.1.1.1"], conn)
    assert "quit" not in conn.sent
