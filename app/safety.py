"""Safety primitives: write-blocklist, output filtering, truncation.

Deliberately dependency-free so it can be unit-tested without Netmiko.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# --- Output budget --------------------------------------------------------
# ~4 chars/token. 80k chars ~= 20k tokens: fits comfortably inside a 32k
# num_ctx together with system prompt, tool schemas and history.
DEFAULT_MAX_OUTPUT_CHARS = 80_000
TRUNCATION_MARKER = "\n[... output truncated at {limit} chars - use filter='<regex>' to narrow ...]"


def truncate(text: str, limit: int = DEFAULT_MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + TRUNCATION_MARKER.format(limit=limit)


def filter_lines(text: str, pattern: str, context: int = 0) -> str:
    """Keep lines matching `pattern` (case-insensitive regex) plus `context`
    lines around each hit. Returns a note when nothing matches so the model
    does not mistake empty output for 'command produced nothing'."""
    if not pattern:
        return text
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return f"[filter error: invalid regex '{pattern}': {exc}]\n" + text
    lines = text.splitlines()
    keep: set[int] = set()
    for i, line in enumerate(lines):
        if rx.search(line):
            keep.update(range(max(0, i - context), min(len(lines), i + context + 1)))
    if not keep:
        return f"[filter '{pattern}' matched 0 of {len(lines)} lines]"
    out, last = [], -2
    for i in sorted(keep):
        if i != last + 1 and out:
            out.append("...")
        out.append(lines[i])
        last = i
    return f"[filter '{pattern}': {len(keep)} of {len(lines)} lines]\n" + "\n".join(out)


# --- Write blocklist (applies to the READ path, always) --------------------
# Matched against each command, case-insensitive, after whitespace collapse.
# Anything here is refused on run_read regardless of the device's access level.
_GLOBAL = [
    r"^(conf|configure)(\s|$)",
    r"^(commit|rollback|reload|reboot|shutdown|halt|poweroff|init\s+[06])",
    r"^(write|wr)(\s|$)",
    r"^copy\s",
    r"^(delete|erase|format)\s",
    r"^(no|undo)\s",
    r"^(clear|reset)\s",
    r"^(debug|undebug|terminal\s+monitor)",
    r"^(rm|mv|dd|mkfs|fdisk|parted|shred|truncate)(\s|$)",
    r"^(chmod|chown|chgrp)\s",
    r"^(systemctl|service)\s+(start|stop|restart|reload|enable|disable|mask)",
    r"^(apt|apt-get|dnf|yum|pip|pip3|snap)\s+(install|remove|purge|upgrade|autoremove)",
    r"^(useradd|userdel|usermod|passwd|groupadd|groupdel|visudo)",
    r"^(iptables|nft|ufw|firewall-cmd)\s+(?!-L|-S|list|status|show)",
    r"^(ip|ifconfig)\s+.*\b(add|del|set|flush|up|down)\b",
    r"^(kill|killall|pkill)\s",
    r"^(crontab\s+-[er]|tee\s|sed\s+-i|\S+\s*>\s*\S)",
    r"^(sudo|su|doas)\s+",   # no privilege escalation on the read path
    r"(\|\s*(sh|bash|python\d?|perl|xargs)\b)",
    r"^(execute|exec)\s+(reboot|shutdown|factoryreset|restore|backup|formatlogdisk)",
    r"^(save|startup)",
]
_BLOCK = [re.compile(p, re.IGNORECASE) for p in _GLOBAL]

# Commands that are always acceptable even if they look suspicious.
_ALLOW = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^show\s", r"^display\s", r"^get\s", r"^diagnose\s+(?!sys\s+kill)",
        r"^(cat|less|head|tail|grep|egrep|zgrep|find|ls|stat|wc|sort|uniq|cut|awk|df|du|free|uptime|w|who|id|hostname|uname|lsb_release|date|env|ps|top\s+-bn1|ss|netstat|ip\s+(-\S+\s+)*(addr|a|link|l|route|r|neigh|n|-s)|dig|nslookup|host|ping\s+-c\s*\d+|traceroute|mtr\s+-r|journalctl|dmesg|lsblk|lscpu|lspci|lsusb|lsmod|mount|nproc|getent|ethtool\s+-\S|iptables\s+-[LS]|nft\s+list|ufw\s+status|systemctl\s+(status|list-units|list-timers|is-active|is-enabled|show|cat)|docker\s+(ps|images|logs|inspect|stats\s+--no-stream)|sysctl\s+(?!-w))(\s|$)",
    )
]


@dataclass
class Verdict:
    allowed: bool
    reason: str = ""


def check_read_command(cmd: str) -> Verdict:
    c = " ".join(cmd.strip().split())
    if not c:
        return Verdict(False, "empty command")
    # Hard refusals first - these win even for otherwise allow-listed verbs.
    if re.search(r"(\s>\s*\S|\s>>|;|&&|\|\|)", c):
        return Verdict(False, "shell redirection/chaining not allowed on read path")
    if re.search(r"\|\s*(sh|bash|zsh|python\d?|perl|xargs|sudo|tee)\b", c, re.IGNORECASE):
        return Verdict(False, "piping into an interpreter/tee is not allowed on read path")
    if re.match(r"(ip|ifconfig)\s+.*\b(add|del|set|flush|replace|change)\b", c, re.IGNORECASE):
        return Verdict(False, "mutating ip/ifconfig subcommand - use propose_change")
    if any(rx.search(c) for rx in _ALLOW):
        return Verdict(True)
    for rx in _BLOCK:
        if rx.search(c):
            return Verdict(False, f"'{c.split()[0]}' is a write/privileged or disruptive command - use propose_change (mode='exec' for reset/clear maintenance commands)")
    return Verdict(True)


def split_commands(block: str) -> list[str]:
    """Newline- or semicolon-separated commands -> list. Strips comments."""
    out = []
    for raw in re.split(r"[\n;]+", block or ""):
        line = raw.strip()
        if line and not line.startswith(("#", "!")):
            out.append(line)
    return out
