# SPDX-FileCopyrightText: 2026 Stephan Baenisch
# SPDX-License-Identifier: Apache-2.0
"""Per-platform behaviour: what wirehand runs on each device_type and how it
applies changes there.

The data lives in config/platforms/ - common.yaml plus one file per supported
device_type - so a platform can be tuned, or a new one added, without touching
Python; this module only loads, validates and serves it. See the header of
common.yaml for the format. What stays in code is the closed set of behaviours
a file chooses from (change.apply, change.finish, change.balance_end) and the
handling of device questions.

Loaded once, on first use, and fail-closed: a missing or malformed file, or a
file name that is no Netmiko device_type, raises PlatformError, which aborts
startup. Unlike the safety rules these files are not re-read at runtime - they
decide how pooled sessions are opened and how changes are committed, so an edit
takes effect with a restart.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger("wirehand.platforms")

# Default resolves to /app/config/platforms in the container (the read-only bind
# mount) and to ./config/platforms in a source checkout, so tests and a local run
# need no environment at all.
PLATFORMS_PATH = Path(os.environ.get("WIREHAND_PLATFORMS")
                      or Path(__file__).resolve().parent.parent / "config" / "platforms")

COMMON = "common"
APPLY = ("config_set", "shell")
FINISH = ("commit", "save", "none")
_KEYS = {
    "common": {"version", "comment_prefixes", "prompts"},
    "device": {"version", "name", "extends", "facts", "snapshot", "session", "change",
               "comment_prefixes", "prompts", "containerlab"},
    "session": {"enable", "prep"},
    "change": {"apply", "finish", "rollback_last", "balance_end", "refuse_in_config", "drop_trailing",
               "last_line_only"},
    "refuse_in_config": {"reason", "patterns"},
    "containerlab": {"kinds"},
    "prompt": {"pattern", "proceed", "abort", "note"},
    "creds": {"username", "password"},
}
# Appended to every prompt pattern: an optional default in brackets ('[Y]',
# '(yes)') and a trailing ':' or '?', at the very end of the output.
PROMPT_TAIL = r"\s*(?:\[[^\]\n]{1,8}\]|\([^)\n]{1,8}\))?\s*[:?]?\s*$"


class PlatformError(RuntimeError):
    """Malformed platform file. The message always names file and location."""


@dataclass(frozen=True)
class Prompt:
    rx: re.Pattern[str]
    proceed: str      # sent when a human approved the operation
    abort: str        # sent everywhere else


@dataclass(frozen=True)
class Platform:
    """Everything wirehand needs to know about one device_type."""
    device_type: str
    name: str
    facts: tuple[str, ...]
    snapshot: str | None
    enable: bool
    prep: tuple[str, ...]
    apply: str                          # config_set | shell
    finish: str                         # commit | save | none
    rollback_last: tuple[str, ...] | None
    balance_end: bool
    refuse: tuple[re.Pattern[str], ...]
    refuse_reason: str
    drop_trailing: tuple[re.Pattern[str], ...]
    last_line_only: tuple[re.Pattern[str], ...]
    comment_prefixes: tuple[str, ...]
    prompts: tuple[Prompt, ...]         # own first, then common.yaml's
    kinds: dict[str, tuple[str, str] | None] = field(default_factory=dict)
    sources: tuple[str, ...] = ()

    @property
    def shell(self) -> bool:
        return self.apply == "shell"

    @property
    def commits(self) -> bool:
        """Does a config change end with a commit/save step?"""
        return self.apply == "config_set" and self.finish != "none"

    def refused_lines(self, lines: list[str]) -> list[str]:
        """Lines of a config-mode change that refuse_in_config forbids."""
        return [ln for ln in lines if any(rx.search(ln.strip()) for rx in self.refuse)]

    def split_trailing(self, lines: list[str]) -> tuple[list[str], list[str]]:
        """(kept, dropped): trailing lines matching change.drop_trailing or
        change.last_line_only come off the end of a config-mode change - the tool
        leaves config mode itself."""
        drop = self.drop_trailing + self.last_line_only
        end = len(lines)
        while end and any(rx.search(lines[end - 1].strip()) for rx in drop):
            end -= 1
        return lines[:end], lines[end:]

    def misplaced_lines(self, lines: list[str]) -> list[str]:
        """Lines matching change.last_line_only that are NOT at the end (call it
        on what split_trailing kept)."""
        return [ln for ln in lines if any(rx.search(ln.strip()) for rx in self.last_line_only)]


@dataclass(frozen=True)
class Registry:
    platforms: dict[str, Platform]
    path: Path
    prompts: tuple[Prompt, ...]         # common.yaml's
    kinds: dict[str, str]               # containerlab kind -> device_type

    def summary(self) -> str:
        native = sorted(dt for dt, p in self.platforms.items() if p.rollback_last)
        return (f"{len(self.platforms)} device types, {len(self.kinds)} containerlab kinds, "
                f"native rollback: {', '.join(native) or 'none'}")


def _netmiko_types() -> set[str] | None:
    try:
        from netmiko.ssh_dispatcher import CLASS_MAPPER
    except ImportError:      # tests without netmiko: the name check is skipped
        return None
    return set(CLASS_MAPPER)


def _read(path: Path) -> dict:
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise PlatformError(f"{path}: not valid YAML: {exc}") from None
    except OSError as exc:
        raise PlatformError(f"{path}: cannot be read: {exc}") from None
    if not isinstance(raw, dict):
        raise PlatformError(f"{path}: expected a mapping at the top level")
    return raw


def _keys(value, kind: str, where: str) -> dict:
    allowed = _KEYS[kind]
    if not isinstance(value, dict):
        raise PlatformError(f"{where}: expected a mapping with {', '.join(sorted(allowed))}, "
                            f"not {type(value).__name__}")
    unknown = sorted(str(k) for k in set(value) - allowed)
    if unknown:
        raise PlatformError(f"{where}: unknown key(s) {', '.join(unknown)}. "
                            f"Known keys: {', '.join(sorted(allowed))}")
    return value


def _str_list(value, where: str, empty_ok: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise PlatformError(f"{where}: must be a list of non-empty strings")
    if not value and not empty_ok:
        raise PlatformError(f"{where}: must not be empty")
    return tuple(v.strip() for v in value)


def _compile(pattern, where: str, suffix: str = "") -> re.Pattern[str]:
    if not isinstance(pattern, str) or not pattern.strip():
        raise PlatformError(f"{where}: must be a non-empty string, not {pattern!r}")
    try:
        return re.compile(pattern + suffix, re.IGNORECASE)
    except re.error as exc:
        raise PlatformError(f"{where}: invalid regular expression {pattern!r}: {exc}") from None


def _pattern_list(value, where: str) -> tuple[re.Pattern[str], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise PlatformError(f"{where}: must be a list of patterns")
    return tuple(_compile(p, f"{where}[{i}]") for i, p in enumerate(value))


def _prompts(value, where: str) -> tuple[Prompt, ...]:
    if not isinstance(value, list):
        raise PlatformError(f"{where}: must be a list")
    out = []
    for i, entry in enumerate(value):
        w = f"{where}[{i}]"
        _keys(entry, "prompt", w)
        for key in ("proceed", "abort"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise PlatformError(f"{w}: '{key}' must be a non-empty string - quote it, "
                                    f"YAML reads a bare Y/N/yes/no as a boolean")
        out.append(Prompt(_compile(entry.get("pattern"), f"{w}.pattern", PROMPT_TAIL),
                          entry["proceed"], entry["abort"]))
    return tuple(out)


def _merge(parent: dict, child: dict) -> dict:
    """extends: 'session' and 'change' merge key by key, the rest is replaced;
    'containerlab' is never inherited - a kind maps to exactly one device_type."""
    out = {k: v for k, v in parent.items() if k not in ("containerlab", "extends", "name")}
    for key, value in child.items():
        if key in ("session", "change") and isinstance(out.get(key), dict) and isinstance(value, dict):
            out[key] = {**out[key], **value}
        else:
            out[key] = value
    return out


def _platform(dt: str, raw: dict, file: str, sources: tuple[str, ...],
              common_prefixes: tuple[str, ...], common_prompts: tuple[Prompt, ...]) -> Platform:
    def need(key: str, where: str = file, src: dict = raw):
        if key not in src:
            raise PlatformError(f"{where}: '{key}' is required")
        return src[key]

    name = need("name")
    if not isinstance(name, str) or not name.strip():
        raise PlatformError(f"{file}: 'name' must be a non-empty string")
    facts = _str_list(need("facts"), f"{file}: facts", empty_ok=False)
    snapshot = need("snapshot")
    if snapshot is not None and (not isinstance(snapshot, str) or not snapshot.strip()):
        raise PlatformError(f"{file}: 'snapshot' must be a command or null")

    session = _keys(raw.get("session") or {}, "session", f"{file}: session")
    enable = session.get("enable", False)
    if not isinstance(enable, bool):
        raise PlatformError(f"{file}: session.enable must be true or false")
    prep = _str_list(session.get("prep") or [], f"{file}: session.prep")

    change = _keys(need("change"), "change", f"{file}: change")
    apply = need("apply", f"{file}: change", change)
    if apply not in APPLY:
        raise PlatformError(f"{file}: change.apply must be one of {', '.join(APPLY)}, not {apply!r}")
    finish = need("finish", f"{file}: change", change)
    if finish not in FINISH:
        raise PlatformError(f"{file}: change.finish must be one of {', '.join(FINISH)}, not {finish!r}")
    rollback = need("rollback_last", f"{file}: change", change)
    if rollback is not None:
        rollback = _str_list(rollback, f"{file}: change.rollback_last", empty_ok=False)
    balance_end = change.get("balance_end", False)
    if not isinstance(balance_end, bool):
        raise PlatformError(f"{file}: change.balance_end must be true or false")

    refuse, reason = (), ""
    if apply == "shell":
        if finish != "none":
            raise PlatformError(f"{file}: change.apply 'shell' has no commit step - set change.finish: none")
        if balance_end or {"refuse_in_config", "drop_trailing", "last_line_only"} & set(change):
            raise PlatformError(f"{file}: change.balance_end, change.refuse_in_config, change.drop_trailing "
                                "and change.last_line_only only apply to change.apply: config_set")
    else:
        # The guard is what keeps 'end' + 'reload' from running in exec mode in the
        # middle of a config change - a config_set platform without one is a
        # truncated file, not a choice.
        if "refuse_in_config" not in change:
            raise PlatformError(f"{file}: change.refuse_in_config is required with change.apply: "
                                "config_set - list the lines that leave config mode or commit")
        r = _keys(change["refuse_in_config"], "refuse_in_config", f"{file}: change.refuse_in_config")
        reason = r.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise PlatformError(f"{file}: change.refuse_in_config.reason is required - it is shown to the model")
        pats = r.get("patterns")
        if not isinstance(pats, list) or not pats:
            raise PlatformError(f"{file}: change.refuse_in_config.patterns must be a non-empty list")
        refuse = tuple(_compile(p, f"{file}: change.refuse_in_config.patterns[{i}]")
                       for i, p in enumerate(pats))
        reason = reason.strip()
    drop, last = (_pattern_list(change.get(key), f"{file}: change.{key}")
                  for key in ("drop_trailing", "last_line_only"))
    if rollback and finish == "none":
        raise PlatformError(f"{file}: change.rollback_last undoes a commit, but change.finish is "
                            "'none' - this platform has no commits to roll back")

    prefixes = common_prefixes
    if "comment_prefixes" in raw:
        prefixes = _str_list(raw["comment_prefixes"], f"{file}: comment_prefixes")
    prompts = _prompts(raw.get("prompts") or [], f"{file}: prompts") + common_prompts

    return Platform(
        device_type=dt, name=name.strip(), facts=facts,
        snapshot=snapshot.strip() if snapshot else None,
        enable=enable, prep=prep, apply=apply, finish=finish, rollback_last=rollback,
        balance_end=balance_end, refuse=refuse, refuse_reason=reason, drop_trailing=drop, last_line_only=last,
        comment_prefixes=prefixes, prompts=prompts, sources=sources,
    )


def _kinds(raw: dict, file: str) -> dict[str, tuple[str, str] | None]:
    cl = _keys(raw.get("containerlab") or {}, "containerlab", f"{file}: containerlab")
    kinds = cl.get("kinds") or {}
    if not isinstance(kinds, dict):
        raise PlatformError(f"{file}: containerlab.kinds must be a mapping kind -> credentials")
    out = {}
    for kind, creds in kinds.items():
        where = f"{file}: containerlab.kinds.{kind}"
        creds = _keys(creds or {}, "creds", where)
        if not creds:
            out[str(kind)] = None
            continue
        user, pw = creds.get("username"), creds.get("password")
        if not isinstance(user, str) or not user or not isinstance(pw, str):
            raise PlatformError(f"{where}: give both 'username' and 'password' as strings, or neither")
        out[str(kind)] = (user, pw)
    return out


def load_platforms(path: Path | None = None) -> Registry:
    """Read and validate the platform directory. Raises PlatformError on any problem."""
    root = Path(path) if path else PLATFORMS_PATH
    if not root.is_dir():
        raise PlatformError(f"{root}: platform directory not found. In Docker it comes from the "
                            "./config bind mount (see docker-compose.yml) or from WIREHAND_PLATFORMS")
    files: dict[str, Path] = {}
    for p in sorted(root.iterdir()):
        if p.is_file() and p.suffix == ".yml":
            raise PlatformError(f"{p}: platform files must end in .yaml - rename it to {p.stem}.yaml")
        if p.is_file() and p.suffix == ".yaml":
            files[p.stem] = p
    if COMMON not in files:
        raise PlatformError(f"{root}: common.yaml is missing")
    raw = {n: _read(p) for n, p in files.items()}
    for n, r in raw.items():
        _keys(r, "common" if n == COMMON else "device", str(files[n]))
        if r.get("version") != 1:
            raise PlatformError(f"{files[n]}: 'version: 1' is required")

    netmiko = _netmiko_types()
    common = raw.pop(COMMON)
    common_prefixes = _str_list(common.get("comment_prefixes") or [], f"{files[COMMON]}: comment_prefixes")
    common_prompts = _prompts(common.get("prompts") or [], f"{files[COMMON]}: prompts")
    if not raw:
        raise PlatformError(f"{root}: no platform files - every supported device_type needs one")

    platforms: dict[str, Platform] = {}
    kind_owner: dict[str, str] = {}
    for dt, r in raw.items():
        file = str(files[dt])
        if netmiko is not None and dt not in netmiko:
            raise PlatformError(f"{file}: '{dt}' is not a Netmiko device_type - the file name "
                                "must be the driver name, e.g. cisco_ios or huawei_vrpv8")
        sources = (f"{dt}.yaml",)
        spec = r
        parent = r.get("extends")
        if parent is not None:
            if parent not in raw:
                raise PlatformError(f"{file}: extends '{parent}', which has no file here")
            if raw[parent].get("extends") is not None:
                raise PlatformError(f"{file}: extends '{parent}', which extends another file itself - "
                                    "only one level is supported")
            spec = _merge(raw[parent], r)
            sources = (f"{parent}.yaml", f"{dt}.yaml")
        p = _platform(dt, spec, file, sources, common_prefixes, common_prompts)
        kinds = _kinds(r, file)
        for kind in kinds:
            if kind in kind_owner:
                raise PlatformError(f"{file}: containerlab kind '{kind}' is already mapped by "
                                    f"{kind_owner[kind]}.yaml - a kind maps to one device_type")
            kind_owner[kind] = dt
        platforms[dt] = Platform(**{**p.__dict__, "kinds": kinds})
    return Registry(platforms=platforms, path=root, prompts=common_prompts, kinds=kind_owner)


_lock = threading.Lock()
_registry: Registry | None = None


def registry() -> Registry:
    """The platforms in force, loaded on first use (a PlatformError propagates,
    so startup fails loudly)."""
    global _registry
    with _lock:
        if _registry is None:
            _registry = load_platforms()
            log.info("loaded platforms from %s: %s", _registry.path, _registry.summary())
        return _registry


def known() -> list[str]:
    """The supported device_types."""
    return sorted(registry().platforms)


def get(device_type: str) -> Platform:
    try:
        return registry().platforms[device_type]
    except KeyError:
        raise KeyError(f"unsupported device_type '{device_type}' - one of: {', '.join(known())}") from None


def pending_prompt(text: str, device_type: str | None = None) -> tuple[str, str, str] | None:
    """(question, answer-to-proceed, answer-to-abort) if `text` ENDS in a device
    question that is still waiting for an answer, else None.

    Checks the prompts of `device_type` (its own, then common.yaml's), or only
    common.yaml's when no or an unknown type is given. Only the tail is examined:
    a running-config may contain '[Y/N]' in some description, but only a question
    at the very end means the session is sitting at a prompt."""
    reg = registry()
    p = reg.platforms.get(device_type) if device_type else None
    tail = (text or "")[-200:]
    for pr in (p.prompts if p else reg.prompts):
        m = pr.rx.search(tail)
        if m:
            return m.group(0).strip(), pr.proceed, pr.abort
    return None


USAGE = "usage: python -m app.platforms --lint [path/to/config/platforms]"


def _lint(path: Path) -> int:
    try:
        reg = load_platforms(path)
    except PlatformError as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"OK: {reg.path}\n    {reg.summary()}\n")
    print(f"    {'device_type':<15} {'apply':<11} {'finish':<7} {'rollback':<9} {'enable':<7} "
          f"{'facts':>5} {'guards':>6}  containerlab kinds")
    for dt, p in sorted(reg.platforms.items()):
        print(f"    {dt:<15} {p.apply:<11} {p.finish:<7} {'native' if p.rollback_last else '-':<9} "
              f"{'yes' if p.enable else '-':<7} {len(p.facts):>5} {len(p.refuse):>6}  "
              + (", ".join(sorted(p.kinds)) or "-"))
    return 0


def _main(argv: list[str]) -> int:
    """`--lint` validates a platform directory before it goes live and exits
    non-zero with a precise message if it would be refused."""
    if argv[:1] in (["--lint"], ["-l"]) and len(argv) <= 2:
        return _lint(Path(argv[1]) if len(argv) == 2 else PLATFORMS_PATH)
    print(USAGE)
    return 2


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv[1:]))
