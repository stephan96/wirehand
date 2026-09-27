"""Per-platform command bundles. One place to extend when a new device family
shows up. Keys are the `family` property of inventory.Device."""
import re

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


# Commands sent once when a session opens. Huawei VRP asks for confirmation on
# maintenance commands ("Continue? [Y/N]:"); mmi-mode is the vendor's own switch
# for exactly this case - it tells the CLI a machine is typing, and the questions
# stop. Best effort: if the image does not know the command, nothing breaks.
SESSION_PREP: dict[str, list[str]] = {
    "vrp": ["mmi-mode enable"],
    "vrpv8": ["mmi-mode enable"],
}

# Devices that ask before they act. Netmiko's send_command returns as soon as the
# output looks like a prompt - the ']' in '[Y/N]' is enough - so the command has
# NOT run yet and the session sits at the question until somebody answers it.
# (question pattern, answer to go ahead, answer to back out)
_TAIL = r"\s*(?:\[[^\]\n]{1,8}\]|\([^)\n]{1,8}\))?\s*[:?]?\s*$"
CONFIRM_PROMPTS: list[tuple[str, str, str]] = [
    (r"\[y/n\]" + _TAIL, "Y", "N"),            # Huawei VRP, FortiGate
    (r"\[yes/no\]" + _TAIL, "yes", "no"),
    (r"\(y/n\)" + _TAIL, "y", "n"),
    (r"\[yes,no\]" + _TAIL, "yes", "no"),      # Junos
    (r"\[confirm\]" + _TAIL, "y", "n"),        # Cisco IOS: 'clear counters [confirm]'
    (r"\bcontinue\?" + _TAIL, "y", "n"),
    (r"\bare you sure\?" + _TAIL, "y", "n"),
    (r"\bproceed\??" + _TAIL, "y", "n"),
]
CONFIRM_PROMPTS_RX = [(re.compile(p, re.IGNORECASE), yes, no) for p, yes, no in CONFIRM_PROMPTS]


def pending_prompt(text: str) -> tuple[str, str, str] | None:
    """(question, answer-to-proceed, answer-to-abort) if `text` ENDS in a device
    question that is still waiting for an answer, else None.

    Only the tail is examined: a running-config may contain '[Y/N]' in some
    description, but only a question at the very end means the session is
    sitting at a prompt."""
    tail = (text or "")[-200:]
    for rx, yes, no in CONFIRM_PROMPTS_RX:
        m = rx.search(tail)
        if m:
            return m.group(0).strip(), yes, no
    return None
