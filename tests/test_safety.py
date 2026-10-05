import time

import pytest

from app import safety
from app.inventory import PLATFORMS
from app.safety import check_read_command, filter_lines, split_commands, truncate

NETWORK = sorted(set(PLATFORMS) - {"linux"})


def test_allows_show_and_linux_reads():
    for dt, c in [("cisco_xr", "show running-config"), ("huawei_vrpv8", "display current-configuration"),
                  ("fortinet", "get system status")]:
        assert check_read_command(c, dt).allowed, (dt, c)
    for c in ["cat /etc/hosts", "journalctl -u nginx -n 50 --no-pager", "ip -brief address",
              "systemctl status nginx", "iptables -L -n", "sysctl net.ipv4.ip_forward",
              "ping -c 3 10.0.0.1", "grep -i error /var/log/syslog"]:
        assert check_read_command(c, "linux").allowed, c


def test_blocks_writes():
    for dt, cmds in {
        "cisco_xr": ["configure terminal", "conf t", "commit", "reload", "write memory", "copy run start",
                     "no shutdown"],
        "huawei_vrpv8": ["undo interface", "save", "reboot"],
        "fortinet": ["execute reboot"],
        "linux": ["rm -rf /tmp/x", "systemctl restart nginx", "sudo cat /etc/shadow", "apt install vim",
                  "cat /etc/hosts > /tmp/x", "cat x | sh", "ip link set eth0 down", "sed -i s/a/b/ f",
                  "passwd", "reboot"],
    }.items():
        for c in cmds:
            assert not check_read_command(c, dt).allowed, (dt, c)


@pytest.mark.parametrize("dt", sorted(PLATFORMS))
def test_common_refusals_hold_for_every_device_type(dt):
    """common.yaml applies everywhere - no device file can lose these."""
    for c in ["show version; reload", "show run > disk0:x", "show run && reload", "show run | sh",
              "show $(id)", "show `id`", "bash -c id", "python3", "ssh 10.0.0.1", "telnet 10.0.0.1",
              "show run | file x", "show run | redirect ftp://h/x", "show configuration | save x"]:
        assert not check_read_command(c, dt).allowed, (dt, c)


@pytest.mark.parametrize("dt", NETWORK)
def test_network_write_verbs_are_refused_on_every_vendor(dt):
    for c in ["configure terminal", "conf t", "commit", "reload", "write memory", "copy run start",
              "delete flash:x", "clear counters", "debug all", "save"]:
        assert not check_read_command(c, dt).allowed, (dt, c)


def test_negation_verb_is_per_vendor():
    for dt in ["cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos", "arista_eos"]:
        assert not check_read_command("no shutdown", dt).allowed, dt
    for dt in ["huawei", "huawei_vrpv8"]:
        assert not check_read_command("undo shutdown", dt).allowed, dt


def test_linux_is_allow_list_only():
    """Deny by default on shell-like devices: a blocklist can only name the
    write commands somebody thought of - 'touch', 'cp', 'ln -s', 'wget' all
    used to pass on the read path."""
    for c in ["touch /tmp/x", "cp /etc/passwd /tmp/x", "mkdir /tmp/x", "ln -s /etc/shadow /tmp/x",
              "wget -O /tmp/x http://h/", "curl http://h", "tar -cf /tmp/a.tar /etc",
              "install -m777 /bin/sh /tmp/s", "docker exec -it c sh", "clab destroy -t x.yml",
              # vendor read verbs are not Linux reads
              "show running-config", "display version", "get system status"]:
        assert not check_read_command(c, "linux").allowed, c
    for c in ["cat /etc/hosts", "ls -la /tmp", "ip -brief address", "ip link show up", "df -h",
              "journalctl -u nginx -n 50 --no-pager", "systemctl status nginx", "docker ps",
              "containerlab inspect --all", "sysctl net.ipv4.ip_forward", "find /etc -name *.conf"]:
        assert check_read_command(c, "linux").allowed, c


def test_allow_listed_verb_with_a_writing_argument():
    """The allow-list matches the verb; these write via the ARGUMENT."""
    for c in ["find /tmp -name x -delete", "find /tmp -maxdepth 0 -exec touch /tmp/x +",
              "awk 'BEGIN{system(\"touch /tmp/x\")}'", "ethtool -s eth0 speed 100",
              "journalctl --vacuum-time=1s", "dmesg -C", "mount /dev/sda1 /mnt",
              "date -s 12:00", "hostname newname", "ss -K dst 1.1.1.1", "env FOO=1 touch /tmp/x"]:
        assert not check_read_command(c, "linux").allowed, c
    # ... while the read forms of the same verbs stay allowed
    for c in ["ethtool -S eth0", "ethtool eth0", "dmesg", "mount", "date", "hostname -f", "env"]:
        assert check_read_command(c, "linux").allowed, c


def test_network_cli_keeps_working_but_cannot_escape():
    for dt, c in [("cisco_xr", "show running-config"), ("cisco_xr", "sh ip int brief"),
                  ("cisco_xr", "admin show platform"), ("cisco_xr", "show run | include interface"),
                  ("cisco_xr", "ping 8.8.8.8 count 5"), ("huawei_vrpv8", "display current-configuration"),
                  ("fortinet", "get system status"), ("fortinet", "execute ping 8.8.8.8")]:
        assert check_read_command(c, dt).allowed, (dt, c)
    for dt, c in [("cisco_xr", "run bash"), ("cisco_nxos", "run bash"), ("cisco_xe", "guestshell run bash"),
                  ("cisco_ios", "event manager run x"), ("juniper_junos", "start shell"),
                  ("juniper_junos", "request shell"), ("huawei", "system-view"),
                  ("huawei_vrpv8", "system-view"), ("fortinet", "fnsysctl ls /"),
                  ("fortinet", "execute factoryreset"), ("cisco_xr", "show run | utility sh"),
                  ("cisco_xe", "show run | append disk0:/x")]:
        assert not check_read_command(c, dt).allowed, (dt, c)


def test_pipeline_stages_split_like_the_shell():
    from app.safety import pipeline_stages
    assert pipeline_stages("ps aux | grep sshd | head -5") == ["ps aux", "grep sshd", "head -5"]
    assert pipeline_stages("grep -E 'a|b' f") == ["grep -E 'a|b' f"]
    assert pipeline_stages('grep "a|b" f | wc -l') == ['grep "a|b" f', "wc -l"]
    assert pipeline_stages("grep a\\|b f") == ["grep a\\|b f"]
    # unbalanced quote: split everywhere, never fewer checks
    assert pipeline_stages("grep \"a|crontab -") == ['grep "a', "crontab -"]


def test_every_pipeline_stage_is_checked_on_linux():
    for c in ["cat /tmp/x | crontab -", "ls | awk 'BEGIN{system(\"touch /tmp/x\")}'",
              "cat /etc/hosts | dd of=/tmp/x", "ps aux | grep x | at now", "grep \"a|crontab -",
              "ls | | wc -l", "cat /etc/hosts | find / -delete"]:
        assert not check_read_command(c, "linux").allowed, c
    for c in ["ps aux | grep sshd | head -5", "grep -E 'a|b' /etc/hosts", "grep a\\|b /etc/hosts",
              "journalctl -n 50 --no-pager | grep -i error | tail -n 5", "sort /etc/passwd | uniq -c"]:
        assert check_read_command(c, "linux").allowed, c
    v = check_read_command("cat /tmp/x | crontab -", "linux")
    assert v.stage == "crontab -" and "'crontab' is not on the read allow-list" in v.reason


@pytest.mark.parametrize("dt", sorted(PLATFORMS))
def test_redirection_and_background_in_any_spelling(dt):
    for c in ["ls 2>/tmp/x", "cat x>/tmp/y", "show run >disk0:x", "ls & touch /tmp/x",
              "cat <(touch /tmp/x)", "show run >> x"]:
        assert not check_read_command(c, dt).allowed, (dt, c)


def test_linux_verbs_with_a_writing_argument():
    for c in ["sysctl -p", "sysctl --system", "sysctl kernel.panic=1", "sysctl -w a.b=1",
              "ip -s netns exec n touch /tmp/x", "ip -batch /tmp/f", "ip -b /tmp/f", "ip vrf exec x id",
              "ip -force -b /tmp/f", "sort -o /tmp/x /etc/hosts", "sort --output=/tmp/x f",
              "sort --compress-program=sh f", "uniq /etc/hosts /tmp/x", "uniq -f 2 a /tmp/x",
              "date 010112002025", "date -u 0101120025", "date --set=12:00", "dmesg -n 1", "dmesg -D",
              "dmesg -Tc", "dmesg --console-off", "journalctl --rotate", "journalctl --flush",
              "journalctl --cursor-file=/tmp/c", "hostname -F /tmp/x", "hostname -b x",
              "ethtool -t eth0", "ethtool --reset eth0", "ethtool --set-eee eth0 eee off",
              "ethtool -X eth0 equal 2", "arp -d 10.0.0.1", "arp -s 10.0.0.1 aa:bb:cc:dd:ee:ff",
              "arp -f /tmp/ethers", "bridge fdb add aa:bb:cc:dd:ee:ff dev eth0",
              "bridge link set dev eth0 cost 4", "iptables -L -Z", "iptables -F", "iptables -nL -Z",
              "iptables -S --flush", "rpm -q --setperms bash", "less -o /tmp/x /etc/hosts",
              "file -C -m /tmp/magic", "clab graph -t x.yml", "containerlab graph --dot"]:
        assert not check_read_command(c, "linux").allowed, c
    for c in ["sysctl -a", "sysctl -n net.ipv4.ip_forward", "ip -s link", "ip -s -s link show eth0",
              "ip -brief addr", "ip route get 1.1.1.1", "ip ro", "date +%s", "date -d 2025-01-01",
              "date -u", "dmesg -T", "dmesg -H --level=err", "journalctl -u ssh -n 20 --no-pager",
              "uniq -c /etc/hosts", "uniq -f 2 /etc/hosts", "sort -n /etc/hosts", "sort -rk2 f",
              "hostname -f", "ethtool -S eth0", "ethtool -i eth0", "ethtool -a eth0", "arp -an",
              "bridge fdb show", "iptables -L -n -v", "iptables -S", "iptables -L INPUT --line-numbers",
              "less /etc/hosts", "file /bin/ls", "rpm -qa", "containerlab inspect --all"]:
        assert check_read_command(c, "linux").allowed, c


@pytest.mark.parametrize("dt,cmds", [
    ("cisco_ios", ["config t", "confi t", "configure terminal", "conf t", "connect 10.0.0.1", "wr",
                   "wri mem", "relo", "reload in 5", "cop run start", "del flash:x", "cle counters",
                   "clock set 10:00:00 1 jan 2025", "u all", "term mon"]),
    ("cisco_xe", ["config t", "relo"]),
    ("cisco_nxos", ["config t", "relo"]),
    ("arista_eos", ["config", "relo"]),
    ("cisco_xr", ["config", "admin reload location all", "admin", "admin config"]),
    ("huawei", ["sys", "sy", "system-view", "sa", "save", "startup saved-configuration x.cfg",
                "reset saved-configuration", "un sh", "undo info-center enable", "reb", "clock datetime 10:00:00 2025-01-01"]),
    ("huawei_vrpv8", ["sys", "system-view immediately", "res saved-configuration"]),
    ("juniper_junos", ["request system zeroize", "req sys reboot", "request system software add x.tgz",
                       "restart routing", "rest chassis-control", "set date 202501011200", "configure",
                       "con", "edit", "file delete /var/tmp/x", "file copy a b", "op x", "start shell",
                       "request routing-engine login other", "show configuration | request message all"]),
    ("fortinet", ["config system admin", "conf sys global", "exe reboot", "exec reboot", "execu factoryreset",
                  "execute date 2020-01-01", "execute time 10:00:00", "diag sys kill 11 1",
                  "diagnose sys session clear", "diag test application ipsmonitor 99",
                  "diagnose vpn tunnel down x", "sudo global execute reboot"]),
])
def test_vendor_write_verbs_in_every_spelling(dt, cmds):
    for c in cmds:
        assert not check_read_command(c, dt).allowed, (dt, c)


@pytest.mark.parametrize("dt,cmds", [
    ("cisco_ios", ["show running-config | include hostname", "sh ip int br | i up", "show run | sec bgp",
                   "show clock", "show run | no-more"]),
    ("cisco_xr", ["admin show platform", "show run | i hostname", "show configuration commit list"]),
    ("huawei", ["display version", "dis cur | include sysname",
                "display current-configuration | include undo", "display clock"]),
    ("juniper_junos", ["request support information", "set cli screen-length 0", "file list /var/tmp",
                       "file show /var/log/messages", "show route | match 1.1.1.1 | count",
                       "show configuration | display set", "show system rollback compare 0 1"]),
    ("fortinet", ["execute date", "execute time", "exe ping 1.1.1.1", "execute traceroute 1.1.1.1",
                  "diag sys top 1", "diagnose sys session list", "diagnose debug crashlog read",
                  "get system status | grep Version", "show full-configuration"]),
])
def test_vendor_reads_keep_working(dt, cmds):
    for c in cmds:
        assert check_read_command(c, dt).allowed, (dt, c)


def test_network_default_deny_keeps_pipe_modifiers(tmp_path):
    """Switching a vendor to 'default: deny' must not break '| include' -
    every stage is checked, so the pipe modifiers are on the allow-list."""
    import shutil
    root = tmp_path / "safety"
    shutil.copytree(safety.RULES_PATH, root, ignore=shutil.ignore_patterns("local"))
    for dt in NETWORK:
        f = root / f"{dt}.yaml"
        f.write_text(f.read_text().replace("default: allow", "default: deny"))
    saved = (safety._rules, safety.RULES_PATH)
    try:
        safety._rules, safety.RULES_PATH = None, root
        for dt, c in [("cisco_xr", "show run | include hostname"), ("huawei", "display cur | i sysname"),
                      ("juniper_junos", "show route | match x | count"), ("fortinet", "get system status | grep V")]:
            assert check_read_command(c, dt).allowed, (dt, c)
        assert not check_read_command("show run | frobnicate", "cisco_xr").allowed
        assert not check_read_command("frobnicate", "cisco_xr").allowed
    finally:
        safety._rules, safety.RULES_PATH = saved


def test_unknown_device_type_is_refused():
    assert not check_read_command("show version", "").allowed
    assert "no read-path safety rules" in check_read_command("show version", "cisco_foo").reason


def test_verdict_names_the_deciding_rule():
    v = check_read_command("system-view", "huawei")
    assert v.section == "hard_refusals" and v.rule.source == "huawei.yaml"
    v = check_read_command("show run | file x", "cisco_xr")
    assert v.rule.source == "common.yaml"
    v = check_read_command("cat /etc/hosts", "linux")
    assert v.allowed and v.section == "allowlist" and v.rule.group == "files-and-text"
    assert check_read_command("frobnicate", "linux").section == "default"


def test_split_commands():
    assert split_commands("show ver; show ip int brief\n# c\nshow run") == ["show ver", "show ip int brief", "show run"]


def test_filter_and_truncate():
    txt = "\n".join(f"line {i}" for i in range(100))
    out = filter_lines(txt, r"line 5\d", context=1)
    assert "line 49" in out and "line 60" in out and "line 70" not in out
    assert "matched 0" in filter_lines(txt, "nope")
    assert "truncated" in truncate("x" * 200, 100)


# --- rule directory loading -------------------------------------------------
COMMON = """
version: 1
hard_refusals:
  - pattern: '^danger\\b'
    reason: refused
blocklist: []
allowlist: []
"""

DEVICE = """
version: 1
default: allow
hard_refusals: []
blocklist:
  - group: g
    patterns: ['^write(\\s|$)']
allowlist:
  - group: g
    patterns: ['^show\\s']
"""

LINUX = DEVICE.replace("default: allow", "default: deny")


def _tree(tmp_path, **override):
    """A complete minimal rule directory; override={'name': text} replaces or
    adds one file (a 'local/x' name lands in local/), text=None removes it."""
    files = {"common": COMMON, "linux": LINUX, **{dt: DEVICE for dt in NETWORK}, **override}
    for name, text in files.items():
        if text is None:
            continue
        p = tmp_path / f"{name}.yaml"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def test_shipped_rule_directory_loads():
    """The files the project ships must always be valid - this is what `--lint` checks."""
    rs = safety.load_rules()
    assert set(rs.policies) == set(PLATFORMS)
    assert {dt for dt, p in rs.policies.items() if p.default == "deny"} == {"linux"}
    assert all(p.hard and p.block and p.allow for p in rs.policies.values())
    assert safety._main(["--lint"]) == 0


def test_minimal_tree_drives_the_verdicts(tmp_path):
    rs = safety.load_rules(_tree(tmp_path))
    xr = rs.policies["cisco_xr"]
    assert xr.sources == ("common.yaml", "cisco_xr.yaml")
    assert len(xr.hard) == 1 and len(xr.block) == 1 and len(xr.allow) == 1


@pytest.mark.parametrize("override,expected", [
    ({"common": ""}, "expected a mapping"),
    ({"cisco_xr": "version: 1\n{"}, "not valid YAML"),
    # YAML 1.1 turns a bare no/off/yes into a boolean - a reason must still be text
    ({"common": COMMON.replace("    reason: refused", "    reason: no")}, "'reason' is required"),
    ({"common": COMMON + "default: deny\n"}, "unknown top-level key(s) default"),
    ({"linux": LINUX + "allow_list: []\n"}, "unknown top-level key(s) allow_list"),
    ({"common": COMMON.replace("blocklist: []\n", "")}, "section 'blocklist' is missing"),
    ({"common": COMMON.replace("  - pattern: '^danger\\b'\n    reason: refused\n", "").replace(
        "hard_refusals:\n", "hard_refusals: []\n")}, "'hard_refusals' is empty"),
    ({"cisco_xr": DEVICE.replace("default: allow\n", "")}, "'default' must be 'allow' or 'deny'"),
    ({"cisco_xr": DEVICE.replace("default: allow", "default: off")}, "'default' must be 'allow' or 'deny'"),
    ({"cisco_xr": DEVICE.replace("  - group: g\n    patterns: ['^write(\\s|$)']", "[]").replace(
        "blocklist:\n[]", "blocklist: []")}, "empty blocklist would let every write verb through"),
    ({"linux": LINUX.replace("  - group: g\n    patterns: ['^show\\s']", "[]").replace(
        "allowlist:\n[]", "allowlist: []")}, "empty allowlist would refuse every command"),
    ({"cisco_xr": DEVICE.replace("'^show\\s'", "'^show(\\s'")}, "invalid regular expression"),
    ({"common": COMMON.replace("    reason: refused", "    note: x")}, "'reason' is required"),
    ({"cisco_xr": DEVICE.replace("['^write(\\s|$)']", "[]")}, "'patterns' must be a non-empty list"),
    ({"cisco_xr": DEVICE.replace("    patterns: ['^show\\s']", "    pattern: '^show\\s'")},
     "unknown key(s) pattern"),
    # coverage: one file per supported device_type, no strays
    ({"huawei": None}, "no rule file for huawei.yaml"),
    ({"common": None}, "no rule file for common.yaml"),
    ({"cisco-xr": DEVICE}, "'cisco-xr' is not a supported device_type"),
    # local files only add
    ({"local/linux": "default: allow\n"}, "'default' cannot be set in a local file"),
    ({"local/cisco-xr": "blocklist: []\n"}, "'cisco-xr' is not a supported device_type"),
    ({"local/linux": "allowlist:\n  - group: g\n    patterns: ['^(ls(\\s|$)']\n"}, "invalid regular expression"),
])
def test_malformed_trees_are_refused_with_a_precise_message(tmp_path, override, expected):
    """Fail closed: every one of these raises instead of loading a partial ruleset."""
    with pytest.raises(safety.RuleError) as exc:
        safety.load_rules(_tree(tmp_path, **override))
    assert expected in str(exc.value)


def test_yml_extension_is_refused_not_ignored(tmp_path):
    _tree(tmp_path)
    (tmp_path / "local").mkdir()
    (tmp_path / "local" / "linux.yml").write_text("allowlist: []\n")
    with pytest.raises(safety.RuleError, match="must end in .yaml"):
        safety.load_rules(tmp_path)


def test_missing_directory_is_refused(tmp_path):
    with pytest.raises(safety.RuleError, match="not found"):
        safety.load_rules(tmp_path / "nope")
    assert safety._main(["--lint", str(tmp_path / "nope")]) == 1


def test_local_files_add_to_common_and_to_their_device_type(tmp_path):
    root = _tree(tmp_path, **{
        "local/common": "hard_refusals:\n  - pattern: '^sitebad\\b'\n    reason: site policy\n",
        "local/linux": "allowlist:\n  - group: site\n    patterns: ['^(jq)(\\s|$)']\n",
        "local/cisco_xr": "",     # an empty local file is allowed and adds nothing
    })
    rs = safety.load_rules(root)
    assert rs.policies["linux"].sources == ("common.yaml", "linux.yaml", "local/common.yaml", "local/linux.yaml")
    assert rs.policies["huawei"].sources == ("common.yaml", "huawei.yaml", "local/common.yaml")
    assert any(r.rx.search("jq .") for r in rs.policies["linux"].allow)
    assert not any(r.rx.search("jq .") for r in rs.policies["cisco_xr"].allow)
    assert all(any(r.rx.search("sitebad") for r in p.hard) for p in rs.policies.values())
    assert rs.policies["linux"].default == "deny"      # local files cannot change it


def test_edit_is_picked_up_and_a_broken_edit_keeps_the_old_rules(tmp_path, caplog):
    """mtime rescan, same contract as the inventory: a bad edit never widens
    the read path - the previously loaded rules keep serving."""
    root = _tree(tmp_path)
    saved = (safety._rules, safety._last_check, safety.RESCAN_SECONDS, safety.RULES_PATH)
    try:
        safety.RESCAN_SECONDS = 0
        safety._rules, safety._last_check = None, 0.0
        safety.RULES_PATH = root
        assert not safety.check_read_command("danger now", "cisco_xr").allowed
        assert safety.check_read_command("ls", "linux").allowed is False   # not allow-listed here

        # a new local file takes effect without a restart
        (root / "local").mkdir()
        (root / "local" / "linux.yaml").write_text("allowlist:\n  - group: g\n    patterns: ['^ls(\\s|$)']\n")
        time.sleep(0.01)
        assert safety.check_read_command("ls", "linux").allowed

        # a broken edit of any file does not
        (root / "cisco_xr.yaml").write_text("version: 1\nhard_refusals: [")
        time.sleep(0.01)
        with caplog.at_level("ERROR"):
            assert safety.check_read_command("ls", "linux").allowed
            assert not safety.check_read_command("write mem", "cisco_xr").allowed
        assert "keeping the previous ones" in caplog.text
    finally:
        safety._rules, safety._last_check, safety.RESCAN_SECONDS, safety.RULES_PATH = saved


def test_explain_names_file_and_rule(capsys):
    assert safety._main(["--explain", "huawei", "system-view"]) == 1
    out = capsys.readouterr().out
    assert "REFUSED by hard_refusals in huawei.yaml" in out and "reason:" in out
    assert safety._main(["--explain", "linux", "cat", "/etc/hosts"]) == 0
    assert "ALLOWED by allowlist group 'files-and-text' in linux.yaml" in capsys.readouterr().out
    assert safety._main(["--explain", "cisco_xr", "frobnicate"]) == 0
    assert "default of cisco_xr.yaml (allow)" in capsys.readouterr().out
    assert safety._main(["--explain", "nope", "show x"]) == 2
    assert safety._main([]) == 2
