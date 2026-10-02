from app.safety import check_read_command, filter_lines, split_commands, truncate


def test_allows_show_and_linux_reads():
    for c in ["show running-config", "display current-configuration", "get system status",
              "cat /etc/hosts", "journalctl -u nginx -n 50 --no-pager", "ip -brief address",
              "systemctl status nginx", "iptables -L -n", "sysctl net.ipv4.ip_forward",
              "ping -c 3 10.0.0.1", "grep -i error /var/log/syslog"]:
        assert check_read_command(c).allowed, c


def test_blocks_writes():
    for c in ["configure terminal", "conf t", "commit", "reload", "write memory", "copy run start",
              "no shutdown", "undo interface", "rm -rf /tmp/x", "systemctl restart nginx",
              "sudo cat /etc/shadow", "apt install vim", "cat /etc/hosts > /tmp/x",
              "cat x | sh", "ip link set eth0 down", "sed -i s/a/b/ f", "execute reboot", "passwd"]:
        assert not check_read_command(c).allowed, c


def test_linux_is_allow_list_only():
    """Deny by default on shell-like devices: a blocklist can only name the
    write commands somebody thought of - 'touch', 'cp', 'ln -s', 'wget' all
    used to pass on the read path."""
    for c in ["touch /tmp/x", "cp /etc/passwd /tmp/x", "mkdir /tmp/x", "ln -s /etc/shadow /tmp/x",
              "wget -O /tmp/x http://h/", "curl http://h", "tar -cf /tmp/a.tar /etc",
              "install -m777 /bin/sh /tmp/s", "docker exec -it c sh", "clab destroy -t x.yml"]:
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
    for c in ["show running-config", "sh ip int brief", "display current-configuration",
              "get system status", "ping 8.8.8.8 count 5", "admin show platform",
              "execute ping 8.8.8.8", "show run | include interface"]:
        assert check_read_command(c, "xr").allowed, c
    for c in ["run bash", "start shell", "request shell", "system-view", "guestshell run bash",
              "fnsysctl ls /", "bash -c id", "execute factoryreset",
              "show run | utility sh", "show run | file /tmp/x", "show configuration | save /tmp/x",
              "show run | redirect ftp://h/x", "show run | append disk0:/x"]:
        assert not check_read_command(c, "xr").allowed, c


def test_split_commands():
    assert split_commands("show ver; show ip int brief\n# c\nshow run") == ["show ver", "show ip int brief", "show run"]


def test_filter_and_truncate():
    txt = "\n".join(f"line {i}" for i in range(100))
    out = filter_lines(txt, r"line 5\d", context=1)
    assert "line 49" in out and "line 60" in out and "line 70" not in out
    assert "matched 0" in filter_lines(txt, "nope")
    assert "truncated" in truncate("x" * 200, 100)


# --- rule file loading ------------------------------------------------------
import time

import pytest

from app import safety

MINIMAL = """
version: 1
shell_families: [linux]
hard_refusals:
  - pattern: '^danger\\b'
    reason: refused
blocklist:
  - group: g
    patterns: ['^write(\\s|$)']
allowlist:
  - group: g
    patterns: ['^show\\s']
"""


def _write(tmp_path, text, name="safety.yaml"):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_shipped_rule_file_loads():
    """The file the project ships must always be valid - this is what `--lint` checks."""
    rs = safety.load_rules()
    assert rs.shell_families == frozenset({"linux"})
    assert rs.hard and rs.block and rs.allow
    assert safety._main(["--lint"]) == 0


def test_minimal_file_drives_the_verdicts(tmp_path):
    rs = safety.load_rules(_write(tmp_path, MINIMAL))
    assert len(rs.hard) == 1 and len(rs.block) == 1 and len(rs.allow) == 1


@pytest.mark.parametrize("text,expected", [
    ("", "expected a mapping"),
    ("version: 1\n{", "not valid YAML"),
    # YAML 1.1 turns a bare no/off/yes into a boolean - a reason must still be text
    (MINIMAL.replace("    reason: refused", "    reason: no"), "'reason' is required"),
    (MINIMAL + "allow_list: []\n", "unknown top-level key(s) allow_list"),
    (MINIMAL.replace("shell_families: [linux]", ""), "'shell_families' must be a list"),
    (MINIMAL.replace("  - group: g\n    patterns: ['^show\\s']", ""), "section 'allowlist' is missing or empty"),
    (MINIMAL.replace("'^show\\s'", "'^show(\\s'"), "invalid regular expression"),
    (MINIMAL.replace("    reason: refused", "    note: x"), "'reason' is required"),
    (MINIMAL.replace("  - group: g\n    patterns: ['^write(\\s|$)']", "  - group: g\n    patterns: []"),
     "'patterns' must be a non-empty list"),
    (MINIMAL.replace("    patterns: ['^show\\s']", "    pattern: '^show\\s'"), "unknown key(s) pattern"),
])
def test_malformed_files_are_refused_with_a_precise_message(tmp_path, text, expected):
    """Fail closed: every one of these raises instead of loading a partial ruleset."""
    with pytest.raises(safety.RuleError) as exc:
        safety.load_rules(_write(tmp_path, text))
    assert expected in str(exc.value)


def test_missing_file_is_refused(tmp_path):
    with pytest.raises(safety.RuleError, match="not found"):
        safety.load_rules(tmp_path / "nope.yaml")
    assert safety._main(["--lint", str(tmp_path / "nope.yaml")]) == 1


def test_edit_is_picked_up_and_a_broken_edit_keeps_the_old_rules(tmp_path, caplog):
    """mtime rescan, same contract as the inventory: a bad edit never widens
    the read path - the previously loaded rules keep serving."""
    path = _write(tmp_path, MINIMAL)
    saved = (safety._rules, safety._last_check, safety.RESCAN_SECONDS)
    try:
        safety.RESCAN_SECONDS = 0
        safety._rules, safety._last_check = None, 0.0
        safety.RULES_PATH = path
        assert not safety.check_read_command("danger now").allowed
        assert safety.check_read_command("ls", "linux").allowed is False   # not allow-listed here

        # a real edit takes effect without a restart
        path.write_text(MINIMAL.replace("'^show\\s'", "'^ls(\\s|$)'"))
        time.sleep(0.01)
        assert safety.check_read_command("ls", "linux").allowed

        # a broken edit does not
        path.write_text("version: 1\nhard_refusals: [")
        time.sleep(0.01)
        with caplog.at_level("ERROR"):
            assert safety.check_read_command("ls", "linux").allowed
        assert "keeping the previous ones" in caplog.text
    finally:
        safety.RULES_PATH = safety.Path(safety.os.environ.get("WIREHAND_SAFETY_RULES")
                                        or safety.Path(safety.__file__).resolve().parent.parent
                                        / "config" / "safety.yaml")
        safety._rules, safety._last_check, safety.RESCAN_SECONDS = saved
