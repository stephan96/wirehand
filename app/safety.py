"""Safety primitives: write-blocklist, output filtering, truncation.

The rule lists themselves live in config/safety/ - common.yaml plus one file
per device_type - so an admin can read and edit them without touching Python;
this module only loads, validates and applies them. See the header of
common.yaml for the layout, the format and the evaluation order.

Fail-closed by design: a missing or malformed rule file, or a supported
device_type without one, raises RuntimeError on the first load, which aborts
startup. A later edit that does not parse is logged and ignored - the rules
already in memory keep serving.
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

from .inventory import PLATFORMS

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


# --- Rule directory -------------------------------------------------------
# Default resolves to /app/config/safety in the container (the read-only bind
# mount) and to ./config/safety in a source checkout, so tests and a local run
# need no environment at all.
RULES_PATH = Path(os.environ.get("WIREHAND_SAFETY_RULES")
                  or Path(__file__).resolve().parent.parent / "config" / "safety")
# Seconds between mtime checks, mirroring WIREHAND_CLAB_RESCAN for the inventory.
RESCAN_SECONDS = int(os.environ.get("WIREHAND_SAFETY_RESCAN", "30"))

COMMON = "common"          # common.yaml - applies to every device type
LOCAL_DIR = "local"        # local/<common|device_type>.yaml - git-ignored site additions
SECTIONS = ("hard_refusals", "blocklist", "allowlist")
DEFAULTS = ("allow", "deny")
# Top-level keys per kind of file. A local file has no 'default': it may only add.
_KEYS = {
    "common": {"version", *SECTIONS},
    "device": {"version", "default", *SECTIONS},
    "local": {"version", *SECTIONS},
}
# Used when a blocklist group names no reason of its own.
DEFAULT_BLOCK_REASON = ("'{verb}' is a write/privileged or disruptive command - use propose_change "
                        "(mode='exec' for reset/clear maintenance commands)")


@dataclass(frozen=True)
class Rule:
    rx: re.Pattern[str]
    reason: str      # handed to the model verbatim; "" means "use the section default"
    group: str       # for --lint/--explain output and log messages
    source: str      # file the entry came from, relative to the rule directory


@dataclass(frozen=True)
class Policy:
    """Everything that applies to one device_type, merged from all its files."""
    device_type: str
    default: str                 # "allow" | "deny"
    hard: tuple[Rule, ...]
    block: tuple[Rule, ...]
    allow: tuple[Rule, ...]
    sources: tuple[str, ...]


@dataclass(frozen=True)
class RuleSet:
    policies: dict[str, Policy]
    path: Path
    files: tuple[str, ...]
    sig: tuple = ()

    def summary(self) -> str:
        deny = sorted(t for t, p in self.policies.items() if p.default == "deny")
        local = sum(1 for f in self.files if f.startswith(LOCAL_DIR + "/"))
        return (f"{len(self.policies)} device types from {len(self.files)} files "
                f"({local} local), deny-by-default: {', '.join(deny) or 'none'}")


class RuleError(RuntimeError):
    """Malformed rule file. The message always names file and location."""


def _sig(root: Path) -> tuple:
    """Cheap change detector over every rule file, so an edit, a new local file
    or a removed one all count as a change."""
    out = []
    for d in (root, root / LOCAL_DIR):
        try:
            entries = sorted(d.iterdir())
        except OSError:
            out.append((str(d), None))
            continue
        for p in entries:
            if p.suffix in (".yaml", ".yml"):
                try:
                    st = p.stat()
                    out.append((str(p), st.st_mtime_ns, st.st_size))
                except OSError:
                    out.append((str(p), None))
    return tuple(out)


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


def _load_hard(entries, file: str, source: str) -> tuple[Rule, ...]:
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
                          reason.strip(), "hard_refusals", source))
    return tuple(rules)


def _load_groups(entries, section: str, file: str, source: str) -> tuple[Rule, ...]:
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
                              reason, group.strip(), source))
    return tuple(rules)


@dataclass(frozen=True)
class _File:
    default: str | None
    hard: tuple[Rule, ...]
    block: tuple[Rule, ...]
    allow: tuple[Rule, ...]


def _load_file(path: Path, kind: str, source: str) -> _File:
    """Read and validate one rule file. `kind` is common | device | local."""
    file = str(path)
    allowed = _KEYS[kind]
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise RuleError(f"{file}: not valid YAML: {exc}") from None
    except OSError as exc:
        raise RuleError(f"{file}: cannot be read: {exc}") from None
    if raw is None and kind == "local":
        raw = {}          # an emptied local file adds nothing - that is fine
    if not isinstance(raw, dict):
        raise RuleError(f"{file}: expected a mapping at the top level with the keys "
                        f"{', '.join(sorted(allowed))}")
    if kind == "local" and "default" in raw:
        raise RuleError(f"{file}: 'default' cannot be set in a local file - local files only "
                        f"add entries; 'default' belongs to the shipped {path.stem}.yaml")
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise RuleError(f"{file}: unknown top-level key(s) {', '.join(unknown)}. "
                        f"Known keys: {', '.join(sorted(allowed))}")
    for section in SECTIONS:
        # Shipped files must name every section: a truncated file must not read as
        # 'nothing is blocked here'. '[]' says "empty on purpose".
        if section not in raw and kind == "local":
            continue
        if not isinstance(raw.get(section), list):
            raise RuleError(f"{file}: section '{section}' is missing - it must be a list "
                            "(write '[]' for one that is empty on purpose)")
    default = None
    if kind == "device":
        default = raw.get("default")
        if default not in DEFAULTS:
            raise RuleError(f"{file}: 'default' must be 'allow' or 'deny', not {default!r} - it "
                            "decides commands that match no entry (deny = allow-list only)")
    return _File(
        default=default,
        hard=_load_hard(raw.get("hard_refusals") or [], file, source),
        block=_load_groups(raw.get("blocklist") or [], "blocklist", file, source),
        allow=_load_groups(raw.get("allowlist") or [], "allowlist", file, source),
    )


def _rule_files(d: Path) -> dict[str, Path]:
    """name -> path for every *.yaml directly in `d`. A *.yml is refused rather
    than skipped: a rule file that is silently not applied is the worst outcome."""
    out = {}
    for p in sorted(d.iterdir()):
        if not p.is_file():
            continue
        if p.suffix == ".yml":
            raise RuleError(f"{p}: rule files must end in .yaml - rename it to {p.stem}.yaml")
        if p.suffix == ".yaml":
            out[p.stem] = p
    return out


def load_rules(path: Path | None = None) -> RuleSet:
    """Read and validate the rule directory. Raises RuleError on any problem."""
    root = Path(path) if path else RULES_PATH
    sig = _sig(root)
    if not root.is_dir():
        raise RuleError(f"{root}: safety rule directory not found. run_read refuses every command "
                        "without it; in Docker it comes from the ./config bind mount "
                        "(see docker-compose.yml) or from WIREHAND_SAFETY_RULES")
    known = sorted(PLATFORMS)
    shipped = _rule_files(root)
    unknown = sorted(set(shipped) - {COMMON, *known})
    if unknown:
        raise RuleError(f"{shipped[unknown[0]]}: '{unknown[0]}' is not a supported device_type. "
                        f"Rule files are named common.yaml or <device_type>.yaml, with "
                        f"device_type one of: {', '.join(known)}")
    missing = [n for n in [COMMON, *known] if n not in shipped]
    if missing:
        raise RuleError(f"{root}: no rule file for {', '.join(m + '.yaml' for m in missing)} - every "
                        "supported device_type needs its own file, or its devices would have no "
                        "read-path policy")
    local: dict[str, Path] = {}
    if (root / LOCAL_DIR).is_dir():
        local = _rule_files(root / LOCAL_DIR)
        bad = sorted(set(local) - {COMMON, *known})
        if bad:
            raise RuleError(f"{local[bad[0]]}: '{bad[0]}' is not a supported device_type - a local "
                            f"file must be named common.yaml or one of: {', '.join(known)}")

    common = _load_file(shipped[COMMON], "common", f"{COMMON}.yaml")
    if not common.hard:
        raise RuleError(f"{shipped[COMMON]}: 'hard_refusals' is empty - the shared refusals "
                        "(redirection, chaining, interpreters) must never be missing")
    local_files = {n: _load_file(p, "local", f"{LOCAL_DIR}/{n}.yaml") for n, p in local.items()}
    empty = _File(None, (), (), ())
    policies = {}
    for dt in known:
        own = _load_file(shipped[dt], "device", f"{dt}.yaml")
        # A default-allow file without a blocklist, or a default-deny one without an
        # allow-list, is almost certainly truncated - refuse rather than guess.
        if own.default == "allow" and not own.block:
            raise RuleError(f"{shipped[dt]}: 'default: allow' with an empty blocklist would let "
                            "every write verb through - list the platform's write verbs")
        if own.default == "deny" and not own.allow:
            raise RuleError(f"{shipped[dt]}: 'default: deny' with an empty allowlist would refuse "
                            "every command - list the platform's read verbs")
        parts = [(f"{COMMON}.yaml", common), (f"{dt}.yaml", own)]
        for n in (COMMON, dt):
            if n in local_files:
                parts.append((f"{LOCAL_DIR}/{n}.yaml", local_files[n]))
        policies[dt] = Policy(
            device_type=dt,
            default=own.default,
            hard=tuple(r for _, f in parts for r in f.hard),
            block=tuple(r for _, f in parts for r in f.block),
            allow=tuple(r for _, f in parts for r in f.allow),
            sources=tuple(s for s, _ in parts),
        )
    files = [f"{n}.yaml" for n in shipped] + [f"{LOCAL_DIR}/{n}.yaml" for n in local]
    return RuleSet(policies=policies, path=root, files=tuple(files), sig=sig)


_lock = threading.Lock()
_rules: RuleSet | None = None
_last_check = 0.0


def rules() -> RuleSet:
    """The rules in force. First call loads them (and propagates a RuleError so
    startup fails loudly); later calls re-read the directory when a file in it
    changed, keeping the previous rules if the new content is broken."""
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
    section: str = ""           # hard_refusals | blocklist | allowlist | default
    rule: Rule | None = None    # the entry that decided; None for the default


def check_read_command(cmd: str, device_type: str) -> Verdict:
    """Is `cmd` safe to run on the read path of a `device_type` device?

    `device_type` is inventory.Device.device_type. One without a policy is
    refused - the inventory only admits supported types, so this is a bug guard.
    """
    c = " ".join(cmd.strip().split())
    if not c:
        return Verdict(False, "empty command")
    policy = rules().policies.get(device_type)
    if policy is None:
        return Verdict(False, f"no read-path safety rules for device type '{device_type}'")
    # 1. Hard refusals - argument-level, they win even for allow-listed verbs.
    for rule in policy.hard:
        if rule.rx.search(c):
            return Verdict(False, rule.reason, "hard_refusals", rule)
    # 2. Blocklist - a known write verb, refused with a precise reason.
    for rule in policy.block:
        if rule.rx.search(c):
            return Verdict(False, rule.reason or DEFAULT_BLOCK_REASON.format(verb=c.split()[0]),
                           "blocklist", rule)
    # 3. Allow-list - known-good read verbs.
    for rule in policy.allow:
        if rule.rx.search(c):
            return Verdict(True, "", "allowlist", rule)
    # 4. Anything else: the device file's default.
    if policy.default == "deny":
        return Verdict(False, f"'{c.split()[0]}' is not on the read allow-list for {device_type} devices - "
                              "run_read only runs known read-only commands there; use propose_change for the rest",
                       "default")
    return Verdict(True, "", "default")


def split_commands(block: str) -> list[str]:
    """Newline- or semicolon-separated commands -> list. Strips comments."""
    out = []
    for raw in re.split(r"[\n;]+", block or ""):
        line = raw.strip()
        if line and not line.startswith(("#", "!")):
            out.append(line)
    return out


USAGE = """usage: python -m app.safety --lint [path/to/config/safety]
       python -m app.safety --explain <device_type> '<command>'"""


def _lint(path: Path) -> int:
    try:
        rs = load_rules(path)
    except RuleError as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"OK: {rs.path}\n    {rs.summary()}\n")
    print(f"    {'device_type':<15} {'default':<8} {'hard':>5} {'block':>6} {'allow':>6}  files")
    for dt, p in sorted(rs.policies.items()):
        print(f"    {dt:<15} {p.default:<8} {len(p.hard):>5} {len(p.block):>6} {len(p.allow):>6}  "
              + " + ".join(p.sources))
    return 0


def _explain(device_type: str, command: str) -> int:
    """Show which file and entry decide `command` - the answer to 'why was this refused?'."""
    try:
        rs = rules()
    except RuleError as exc:
        print(f"INVALID: {exc}")
        return 2
    if device_type not in rs.policies:
        print(f"unknown device_type '{device_type}' - one of: {', '.join(sorted(rs.policies))}")
        return 2
    v = check_read_command(command, device_type)
    print(f"{device_type}: {command!r}\n  {'ALLOWED' if v.allowed else 'REFUSED'}", end="")
    if v.rule:
        where = v.section if v.section == "hard_refusals" else f"{v.section} group '{v.rule.group}'"
        print(f" by {where} in {v.rule.source}\n  pattern: '{v.rule.rx.pattern}'")
    else:
        print(f" by the default of {device_type}.yaml ({rs.policies[device_type].default})"
              if v.section == "default" else "")
    if v.reason:
        print(f"  reason:  {v.reason}")
    return 0 if v.allowed else 1


def _main(argv: list[str]) -> int:
    """`--lint` validates a rule directory before it goes live and exits non-zero
    with a precise message if it would be refused. `--explain` names the rule
    that decides a command (exit 0 allowed, 1 refused)."""
    if argv[:1] in (["--lint"], ["-l"]) and len(argv) <= 2:
        return _lint(Path(argv[1]) if len(argv) == 2 else RULES_PATH)
    if argv[:1] == ["--explain"] and len(argv) >= 3:
        return _explain(argv[1], " ".join(argv[2:]))
    print(USAGE)
    return 2


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv[1:]))
