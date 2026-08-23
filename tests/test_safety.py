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


def test_split_commands():
    assert split_commands("show ver; show ip int brief\n# c\nshow run") == ["show ver", "show ip int brief", "show run"]


def test_filter_and_truncate():
    txt = "\n".join(f"line {i}" for i in range(100))
    out = filter_lines(txt, r"line 5\d", context=1)
    assert "line 49" in out and "line 60" in out and "line 70" not in out
    assert "matched 0" in filter_lines(txt, "nope")
    assert "truncated" in truncate("x" * 200, 100)
