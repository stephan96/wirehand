"""Safety primitives: write-blocklist, output filtering, truncation.

The rule lists themselves live in config/safety.yaml so an admin can read and
edit them without touching Python; this module only loads, validates and
applies them. See the header of that file for the format and the evaluation
order.

Fail-closed by design: a missing or malformed rule file raises RuntimeError on
the first load, which aborts startup. A later edit that does not parse is
logged and ignored - the rules already in memory keep serving.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

log = logging.getLogger("wirehand.safety")

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


# --- Rule file ------------------------------------------------------------
# Default resolves to /app/config/safety.yaml in the container (the read-only
# bind mount) and to ./config/safety.yaml in a source checkout, so tests and a
# local run need no environment at all.
RULES_PATH = Path(os.environ.get("WIREHAND_SAFETY_RULES")
                  or Path(__file__).resolve().parent.parent / "config" / "safety.yaml")
# Seconds between mtime checks, mirroring WIREHAND_CLAB_RESCAN for the inventory.
RESCAN_SECONDS = int(os.environ.get("WIREHAND_SAFETY_RESCAN", "30"))

SECTIONS = ("hard_refusals", "blocklist", "allowlist")
_TOP_KEYS = {"version", "shell_families", *SECTIONS}
# Used when a blocklist group names no reason of its own.
DEFAULT_BLOCK_REASON = ("'{verb}' is a write/privileged or disruptive command - use propose_change "
                        "(mode='exec' for reset/clear maintenance commands)")


@dataclass(frozen=True)
class Rule:
    rx: re.Pattern[str]
    reason: str      # handed to the model verbatim; "" means "use the section default"
    group: str       # for --lint output and log messages


@dataclass(frozen=True)
class RuleSet:
    hard: tuple[Rule, ...]
    block: tuple[Rule, ...]
    allow: tuple[Rule, ...]
    shell_families: frozenset[str]
    path: Path
    sig: tuple = ()

    def summary(self) -> str:
        return (f"{len(self.hard)} hard refusals, {len(self.block)} blocklist, "
                f"{len(self.allow)} allow-list entries, "
                f"deny-by-default families: {', '.join(sorted(self.shell_families)) or 'none'}")


class RuleError(RuntimeError):
    """Malformed rule file. The message always names file and location."""


def _sig(path: Path) -> tuple:
    """Cheap change detector, same idea as clab.signature for the inventory."""
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return ()


def _compile(pattern, where: str, case_sensitive: bool) -> re.Pattern[str]:
    if not isinstance(pattern, str) or not pattern.strip():
        raise RuleError(f"{where}: 'pattern' must be a non-empty string, not {pattern!r}")
    try:
        return re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
    except re.error as exc:
        raise RuleError(f"{where}: invalid regular expression {pattern!r}: {exc}") from None


def _entry_keys(entry, allowed: set[str], where: str) -> None:
    if not isinstance(entry, dict):
        raise RuleError(f"{where}: expected a mapping with {', '.join(sorted(allowed))}, "
                        f"not {type(entry).__name__}")
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise RuleError(f"{where}: unknown key(s) {', '.join(unknown)}. "
                        f"Known keys: {', '.join(sorted(allowed))}")


def _load_hard(entries, file: str) -> tuple[Rule, ...]:
    """hard_refusals: one pattern per entry, each with its own reason."""
    rules = []
    for i, entry in enumerate(entries):
        where = f"{file}: hard_refusals[{i}]"
        _entry_keys(entry, {"pattern", "reason", "note", "case_sensitive"}, where)
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise RuleError(f"{where}: 'reason' is required and is shown to the model - "
                            "say what the command would do and what to use instead")
        rules.append(Rule(_compile(entry.get("pattern"), where, bool(entry.get("case_sensitive"))),
                          reason.strip(), "hard_refusals"))
    return tuple(rules)


def _load_groups(entries, section: str, file: str) -> tuple[Rule, ...]:
    """blocklist / allowlist: named groups of patterns sharing one reason."""
    rules = []
    for i, entry in enumerate(entries):
        where = f"{file}: {section}[{i}]"
        _entry_keys(entry, {"group", "patterns", "reason", "note", "case_sensitive"}, where)
        group = entry.get("group")
        if not isinstance(group, str) or not group.strip():
            raise RuleError(f"{where}: 'group' must be a non-empty name")
        where = f"{file}: {section} group '{group}'"
        patterns = entry.get("patterns")
        if not isinstance(patterns, list) or not patterns:
            raise RuleError(f"{where}: 'patterns' must be a non-empty list")
        reason = (entry.get("reason") or "").strip()
        case_sensitive = bool(entry.get("case_sensitive"))
        for j, pattern in enumerate(patterns):
            rules.append(Rule(_compile(pattern, f"{where}, patterns[{j}]", case_sensitive),
                              reason, group.strip()))
    return tuple(rules)


def load_rules(path: Path | None = None) -> RuleSet:
    """Read and validate the rule file. Raises RuleError on any problem."""
    path = Path(path) if path else RULES_PATH
    file = str(path)
    sig = _sig(path)
    if not path.is_file():
        raise RuleError(f"{file}: safety rule file not found. run_read refuses every command "
                        "without it; in Docker it comes from the ./config bind mount "
                        "(see docker-compose.yml) or from WIREHAND_SAFETY_RULES")
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise RuleError(f"{file}: not valid YAML: {exc}") from None
    except OSError as exc:
        raise RuleError(f"{file}: cannot be read: {exc}") from None
    if not isinstance(raw, dict):
        raise RuleError(f"{file}: expected a mapping at the top level with the keys "
                        f"{', '.join(sorted(_TOP_KEYS))}")
    unknown = sorted(set(raw) - _TOP_KEYS)
    if unknown:
        raise RuleError(f"{file}: unknown top-level key(s) {', '.join(unknown)}. "
                        f"Known keys: {', '.join(sorted(_TOP_KEYS))}")
    for section in SECTIONS:
        # Empty sections are refused rather than defaulted: a truncated file must
        # not read as 'no write commands are blocked'.
        if not isinstance(raw.get(section), list) or not raw.get(section):
            raise RuleError(f"{file}: section '{section}' is missing or empty - "
                            "it must be a non-empty list")
    families = raw.get("shell_families")
    if not isinstance(families, list) or any(not isinstance(f, str) for f in families):
        raise RuleError(f"{file}: 'shell_families' must be a list of family names "
                        "(use an empty list to switch deny-by-default off everywhere)")
    return RuleSet(
        hard=_load_hard(raw["hard_refusals"], file),
        block=_load_groups(raw["blocklist"], "blocklist", file),
        allow=_load_groups(raw["allowlist"], "allowlist", file),
        shell_families=frozenset(f.strip().lower() for f in families),
        path=path,
        sig=sig,
    )


_lock = threading.Lock()
_rules: RuleSet | None = None
_last_check = 0.0


def rules() -> RuleSet:
    """The rules in force. First call loads them (and propagates a RuleError so
    startup fails loudly); later calls re-read the file when it changed on
    disk, keeping the previous rules if the new content is broken."""
    global _rules, _last_check
    with _lock:
        if _rules is None:
            _rules = load_rules()
            _last_check = time.time()
            log.info("loaded safety rules from %s: %s", _rules.path, _rules.summary())
        elif time.time() - _last_check >= RESCAN_SECONDS:
            _last_check = time.time()
            if _sig(_rules.path) != _rules.sig:
                try:
                    _rules = load_rules(_rules.path)
                    log.info("reloaded safety rules from %s: %s", _rules.path, _rules.summary())
                except RuleError as exc:
                    log.error("safety rules NOT reloaded, keeping the previous ones: %s", exc)
        return _rules


def reload() -> RuleSet:
    """Force a re-read now (used by the refresh path and by tests)."""
    global _rules, _last_check
    with _lock:
        _rules = load_rules(_rules.path if _rules else None)
        _last_check = time.time()
        log.info("reloaded safety rules from %s: %s", _rules.path, _rules.summary())
        return _rules


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
    rs = rules()
    # 1. Hard refusals - argument-level, they win even for allow-listed verbs.
    for rule in rs.hard:
        if rule.rx.search(c):
            return Verdict(False, rule.reason)
    # 2. Blocklist - a known write verb, refused with a precise reason.
    for rule in rs.block:
        if rule.rx.search(c):
            return Verdict(False, rule.reason or DEFAULT_BLOCK_REASON.format(verb=c.split()[0]))
    # 3. Allow-list - known-good read verbs.
    if any(rule.rx.search(c) for rule in rs.allow):
        return Verdict(True)
    # 4. Anything else: refused on shell-like devices, allowed on network CLIs.
    if family in rs.shell_families:
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


def _main(argv: list[str]) -> int:
    """`python -m app.safety --lint [path]` - validate a rule file before it
    goes live. Exits non-zero with a precise message if it would be refused."""
    args = [a for a in argv if a not in ("--lint", "-l")]
    if len(argv) == len(args) or len(args) > 1:
        print("usage: python -m app.safety --lint [path/to/safety.yaml]")
        return 2
    path = Path(args[0]) if args else RULES_PATH
    try:
        rs = load_rules(path)
    except RuleError as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"OK: {rs.path}\n     {rs.summary()}")
    for section, rule_list in (("blocklist", rs.block), ("allowlist", rs.allow)):
        groups: dict[str, int] = {}
        for rule in rule_list:
            groups[rule.group] = groups.get(rule.group, 0) + 1
        print(f"     {section}: " + ", ".join(f"{g} ({n})" for g, n in groups.items()))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv[1:]))
