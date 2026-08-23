"""Per-platform command bundles. One place to extend when a new device family
shows up. Keys are the `family` property of inventory.Device."""

FACTS: dict[str, list[str]] = {
    "linux": [
        "hostname", "uptime", "uname -a", "cat /etc/os-release",
        "ip -brief address", "ip route", "ss -tulpn", "df -h", "free -m",
        "systemctl list-units --type=service --state=failed --no-pager",
        "journalctl -p warning -n 30 --no-pager",
    ],
    "ios": [
        "show version", "show ip interface brief", "show ip route summary",
        "show cdp neighbors", "show logging | tail 30",
    ],
    "xr": [
        "show version", "show ipv4 interface brief", "show route summary",
        "show bgp summary", "show lldp neighbors", "show logging last 30",
    ],
    "nxos": ["show version", "show interface brief", "show ip route summary", "show cdp neighbors"],
    "vrp": ["display version", "display ip interface brief", "display ip routing-table statistics", "display lldp neighbor brief"],
    "vrpv8": ["display version", "display ip interface brief", "display ip routing-table statistics", "display bgp peer", "display lldp neighbor brief", "display logbuffer size 30"],
    "fortinet": ["get system status", "get system interface physical", "get router info routing-table all", "get system performance status"],
    "eos": ["show version", "show ip interface brief", "show ip route summary", "show lldp neighbors"],
    "junos": ["show version", "show interfaces terse", "show route summary", "show lldp neighbors"],
}

# Command whose output we snapshot before a change (None = linux, handled per file list)
SNAPSHOT: dict[str, str | None] = {
    "linux": None,
    "ios": "show running-config",
    "xr": "show running-config",
    "nxos": "show running-config",
    "vrp": "display current-configuration",
    "vrpv8": "display current-configuration",
    "fortinet": "show full-configuration",
    "eos": "show running-config",
    "junos": "show configuration",
}

# Native rollback of the most recent commit, where the platform has one.
ROLLBACK_LAST: dict[str, list[str] | None] = {
    "xr": ["rollback configuration last 1"],
    "vrpv8": ["rollback configuration last 1"],
    "junos": ["configure", "rollback 1", "commit and-quit"],
    "ios": None, "nxos": None, "vrp": None, "fortinet": None, "eos": None, "linux": None,
}

# Does the change need an explicit commit/save step?
COMMITS: dict[str, bool] = {
    "xr": True, "vrpv8": True, "junos": True,
    "ios": True, "eos": True, "nxos": True, "vrp": True,  # save_config
    "fortinet": False, "linux": False,
}
