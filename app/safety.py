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
    r"^(touch|cp|ln|mkdir|rmdir|install|tar|unzip|gzip|gunzip|bzip2|xz|setfacl|patch)(\s|$)",
    r"^(systemctl|service)\s+(start|stop|restart|reload|enable|disable|mask)",
    r"^(apt|apt-get|dnf|yum|pip|pip3|snap|apk)\s+(install|remove|purge|upgrade|autoremove|add|del|fix)",
    r"^(useradd|userdel|usermod|passwd|groupadd|groupdel|visudo)",
    r"^(iptables|nft|ufw|firewall-cmd)\s+(?!-L|-S|list|status|show)",
    # '... show up' / '... show down' are reads; only a mutating subcommand is a write.
    r"^(ip|ifconfig)\s+(?!.*\bshow\b).*\b(add|del|set|flush|up|down)\b",
    r"^(kill|killall|pkill)\s",
    r"^(crontab\s+-[er]|tee\s|sed\s+-i|\S+\s*>\s*\S)",
    r"^(sudo|su|doas)\s+",   # no privilege escalation on the read path
    r"(\|\s*(sh|bash|python\d?|perl|xargs)\b)",
    r"^(execute|exec)\s+(reboot|shutdown|factoryreset|restore|backup|formatlogdisk)",
    r"^(save|startup)",
    r"^(docker|podman|kubectl)\s+(run|exec|rm|rmi|kill|stop|start|restart|create|build|pull|push|cp|login|update|prune|compose\s+(up|down|restart))",
    r"^(clab|containerlab)\s+(deploy|destroy|redeploy|exec|save|tools|generate)",
]
_BLOCK = [re.compile(p, re.IGNORECASE) for p in _GLOBAL]

# --- Hard refusals: these win over the allow-list ---------------------------
# The allow-list matches the VERB, so an allow-listed verb carrying the wrong
# ARGUMENT used to slip through and write: `find ... -delete`, `awk
# 'BEGIN{system("...")}'`, `ethtool -s`, `journalctl --vacuum`. Argument-level
# checks therefore run first, for every platform family.
_HARD = [
    (r"(\s>\s*\S|\s>>|;|&&|\|\|)", "shell redirection/chaining not allowed on read path"),
    (r"\|\s*(sh|bash|zsh|python\d?|perl|xargs|sudo|tee)\b",
     "piping into an interpreter/tee is not allowed on read path"),
    (r"[`]|\$\(", "command substitution is not allowed on read path"),
    # Vendor pipe modifiers that write or shell out: IOS-XR '| file', '| utility',
    # IOS '| append|redirect|tee', Junos '| save'. '| include|exclude|begin|count'
    # and friends stay allowed.
    (r"\|\s*(file|utility|append|redirect|save|tee)\b",
     "pipe modifier writes to a file or runs a shell utility - use propose_change"),
    (r"^(ip|ifconfig)\s+(?!.*\bshow\b).*\b(add|del|set|flush|replace|change)\b",
     "mutating ip/ifconfig subcommand - use propose_change"),
    # Interpreters take their program as an argument, so no verb check can make
    # them safe. Bare 'sh' is deliberately absent: on Cisco/Huawei it is the
    # usual abbreviation of 'show'. On Linux it is refused by the allow-list.
    (r"^(bash|zsh|ash|dash|ksh|csh|tcsh|busybox|python[\d.]*|perl|ruby|node|nodejs"
     r"|lua[\d.]*|tclsh|expect|php|awk|gawk|mawk|nawk)\b",
     "shell/interpreter invocation can run arbitrary code - use propose_change"),
    (r"^(xargs|nohup|timeout|watch|nice|ionice|setsid|stdbuf|script|chroot|unshare|nsenter)\b",
     "command wrapper can hide a write command - use propose_change"),
    (r"^env\s+\S", "'env' with arguments can hide a write command - use propose_change"),
    (r"^(ssh|scp|sftp|rsync|socat|nc|ncat|netcat|telnet|curl|wget|ftp|tftp)\b",
     "network/file-transfer client is not allowed on read path"),
    (r"^find\b.*\s-(delete|exec|execdir|ok|okdir|fls|fprintf?|fprint0)\b",
     "'find' with an action that writes or executes - use propose_change"),
    (r"^journalctl\b.*--vacuum", "'journalctl --vacuum' deletes logs - use propose_change"),
    (r"^dmesg\b.*(\s-[Cc]\b|--clear|--read-clear)",
     "'dmesg -C' clears the kernel ring buffer - use propose_change"),
    (r"^(mount|umount)\s+(?!-l\b)\S", "(un)mounting changes the system - use propose_change"),
    (r"^date\s+(-s|--set)", "'date -s' sets the system clock - use propose_change"),
    (r"^hostname\s+(?!-)\S", "'hostname <name>' sets the hostname - use propose_change"),
    # Vendor escapes out of the read-only exec view.
    (r"^(run|shell|system-view|guestshell|fnsysctl|event\s+manager)\b|^(start|request)\s+shell\b",
     "vendor shell escape / config view - use propose_change"),
    (r"^(execute|exec)\s+(?!ping6?\b|traceroute\b|tracert\b|dns\b|date\b|time\b)",
     "FortiGate 'execute' command - use propose_change(mode='exec')"),
]
_HARD_RX = [(re.compile(p, re.IGNORECASE), why) for p, why in _HARD]

# Case-SENSITIVE checks: the allow-list is case-insensitive, so it cannot tell
# 'ethtool -S' (statistics) from 'ethtool -s' (set!), or 'ss -k' from 'ss -K'.
_HARD_CASE = [
    (r"^ethtool\s+(-s|-A|-C|-G|-K|-L|-N|-U|-W|-E|-f|-r|--change|--flash|--set)\b",
     "'ethtool' with a setting flag - use propose_change"),
    (r"^ss\b.*\s-K\b", "'ss -K' closes live sockets - use propose_change"),
]
_HARD_CASE_RX = [(re.compile(p), why) for p, why in _HARD_CASE]

# Commands that are always acceptable even if they look suspicious.
_ALLOW = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^show\s", r"^display\s", r"^get\s", r"^diagnose\s+(?!sys\s+kill)",
        r"^(cat|less|head|tail|grep|egrep|zgrep|find|ls|stat|wc|sort|uniq|cut|df|du|free|uptime|w|who|id|hostname|uname|lsb_release|date|env|ps|top\s+-bn1|ss|netstat|ip\s+(-\S+\s+)*(addr\w*|a|link|l|route|r|neigh\w*|n|rule|-s)|dig|nslookup|host|ping\s+-c\s*\d+|traceroute|mtr\s+-r|journalctl|dmesg|lsblk|lscpu|lspci|lsusb|lsmod|lsof|arp|bridge\s+(link|fdb|vlan)|mount|nproc|getent|vmstat|iostat|mpstat|md5sum|sha\d+sum|readlink|realpath|file|ethtool|iptables\s+-[LS]|nft\s+list|ufw\s+status|systemctl\s+(status|list-units|list-timers|is-active|is-enabled|show|cat)|dpkg\s+-[lLs]|rpm\s+-q\S*|apk\s+(info|list|version)|pip\d?\s+(list|show|freeze)|snap\s+list|docker\s+(ps|images|logs|inspect|version|stats\s+--no-stream|compose\s+ps)|(clab|containerlab)\s+(inspect|version|graph)|sysctl\s+(?!-w)\S*)(\s|$)",
    )
]

# Families whose CLI is a general-purpose shell. There, anything that is not on
# the allow-list is refused (deny by default): a Linux host has thousands of
# binaries, and a blocklist only ever names the ones somebody thought of -
# 'touch', 'cp', 'ln -s', 'wget' and every future one used to pass. Network
# CLIs keep blocklist + default-allow: their exec view cannot start arbitrary
# programs, and vendor read verbs are far too varied to enumerate.
SHELL_FAMILIES = frozenset({"linux"})


@dataclass
class Verdict:
    allowed: bool
    reason: str = ""


def check_read_command(cmd: str, family: str = "") -> Verdict:
    """Is `cmd` safe to run on the read path of a `family` device?

    `family` is inventory.Device.family; an empty value keeps the permissive
    network-CLI semantics.
    """
    c = " ".join(cmd.strip().split())
    if not c:
        return Verdict(False, "empty command")
    # 1. Hard refusals - argument-level, they win even for allow-listed verbs.
    for rx, why in _HARD_RX:
        if rx.search(c):
            return Verdict(False, why)
    for rx, why in _HARD_CASE_RX:
        if rx.search(c):
            return Verdict(False, why)
    # 2. Blocklist - a known write verb, refused with a precise reason.
    for rx in _BLOCK:
        if rx.search(c):
            return Verdict(False, f"'{c.split()[0]}' is a write/privileged or disruptive command - use propose_change (mode='exec' for reset/clear maintenance commands)")
    # 3. Allow-list - known-good read verbs.
    if any(rx.search(c) for rx in _ALLOW):
        return Verdict(True)
    # 4. Anything else: refused on shell-like devices, allowed on network CLIs.
    if family in SHELL_FAMILIES:
        return Verdict(False, f"'{c.split()[0]}' is not on the read allow-list for {family} devices - "
                              "run_read only runs known read-only commands there; use propose_change for the rest")
    return Verdict(True)


def split_commands(block: str) -> list[str]:
    """Newline- or semicolon-separated commands -> list. Strips comments."""
    out = []
    for raw in re.split(r"[\n;]+", block or ""):
        line = raw.strip()
        if line and not line.startswith(("#", "!")):
            out.append(line)
    return out
