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
