"""Inventory = manual devices (config/inventory.yaml) + auto-discovered
containerlab nodes (WIREHAND_CLAB_DIR). Manual entries override discovered ones
with the same name. Credentials may be given as `env:VARNAME`. The model only
ever sees the device name, platform and access level."""
from __future__ import annotations

import os
import threading
import time
from dataclasses import MISSING, dataclass, field, fields
from pathlib import Path

import yaml

from . import clab

INVENTORY_PATH = Path(os.environ.get("WIREHAND_INVENTORY", "/app/config/inventory.yaml"))
CLAB_DIR = os.environ.get("WIREHAND_CLAB_DIR", "")
RESCAN_SECONDS = int(os.environ.get("WIREHAND_CLAB_RESCAN", "30"))

# Netmiko device_type -> platform family used for facts bundles / commit logic
PLATFORMS = {
    "linux": "linux",
    "cisco_ios": "ios",
    "cisco_xe": "ios",
    "cisco_xr": "xr",
    "cisco_nxos": "nxos",
    "huawei": "vrp",
    "huawei_vrpv8": "vrpv8",
    "fortinet": "fortinet",
    "arista_eos": "eos",
    "juniper_junos": "junos",
}


@dataclass
class Device:
    name: str
    host: str
    device_type: str
    username: str
    password: str | None = None
    key_file: str | None = None
    secret: str | None = None
    port: int = 22
    access: str = "ro"  # ro | rw
    # None = use WIREHAND_CONFIRM_MODE; "totp" = confirm_change needs a one-time
    # code from a human; "off" = the model may confirm its own proposal.
    confirm: str | None = None
    description: str = ""
    tags: list[str] = field(default_factory=list)
    timeout: int = 30
    source: str = "inventory.yaml"

    @property
    def family(self) -> str:
        return PLATFORMS.get(self.device_type, self.device_type)

    @property
    def writable(self) -> bool:
        return self.access == "rw"

    def public(self) -> dict:
        return {
            "name": self.name,
            "platform": self.device_type,
            "access": self.access,
            "confirm": self.confirm,
            "description": self.description,
            "tags": self.tags,
            "source": self.source,
        }

    def netmiko_kwargs(self) -> dict:
        kw = {
            "device_type": self.device_type,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "conn_timeout": 15,
            "banner_timeout": 30,
            "fast_cli": False,
            # TCP keepalives so firewalls/devices (FortiGate admintimeout!) do not
            # silently half-close the session while it sits in the pool.
            "keepalive": 30,
        }
        import os as _os
        if _os.environ.get("WIREHAND_SESSION_LOG") == "1":
            _d = _os.environ.get("WIREHAND_DATA", "/app/data")
            kw["session_log"] = f"{_d}/session-{self.name}.log"
            kw["session_log_file_mode"] = "append"
        if self.key_file:
            kw["use_keys"] = True
            kw["key_file"] = self.key_file
        if self.password:
            kw["password"] = self.password
        if self.secret:
            kw["secret"] = self.secret
        return kw


# Derived from Device so the two can never drift apart. 'name' is supplied by the
# loader, 'source' by whoever produced the spec - neither is written by hand.
DEVICE_KEYS = {f.name for f in fields(Device)}
REQUIRED_KEYS = {
    f.name for f in fields(Device)
    if f.default is MISSING and f.default_factory is MISSING
} - {"name"}
WRITABLE_KEYS = DEVICE_KEYS - {"name", "source"}


def _resolve(value):
    if isinstance(value, str) and value.startswith("env:"):
        var = value[4:]
        resolved = os.environ.get(var)
        if resolved is None:
            raise RuntimeError(f"inventory references env var '{var}' which is not set")
        return resolved
    return value


class Inventory:
    def __init__(self, path: Path = INVENTORY_PATH, clab_dir: str = CLAB_DIR):
        self.path = path
        self.clab_dir = clab_dir
        self._devices: dict[str, Device] = {}
        self._lock = threading.Lock()
        self._last_scan = 0.0
        self._sig: tuple = ()
        self.reload()

    # -- loading ------------------------------------------------------------
    def _read_manual(self) -> tuple[dict, dict]:
        """Returns (devices-dict, containerlab-config-dict)."""
        if not self.path.exists():
            return {}, {}
        raw = yaml.safe_load(self.path.read_text()) or {}
        return raw.get("devices") or {}, raw.get("containerlab") or {}

    def reload(self) -> None:
        manual_raw, clab_cfg = self._read_manual()
        # resolve env: refs inside containerlab credential overrides
        for kind, c in (clab_cfg.get("credentials") or {}).items():
            for key in ("username", "password"):
                if key in c:
                    c[key] = _resolve(c[key])
        specs: dict[str, dict] = {}
        if self.clab_dir:
            for spec in clab.discover(self.clab_dir, clab_cfg):
                specs[spec["name"]] = spec
        for name, spec in manual_raw.items():   # manual wins
            specs[name] = {**spec, "source": "inventory.yaml"}

        devices: dict[str, Device] = {}
        for name, spec in specs.items():
            spec = dict(spec)
            # Checked here rather than left to Device(**spec): a bare TypeError names
            # the key but not the device, which does not help with twenty of them.
            unknown = sorted(set(spec) - DEVICE_KEYS)
            if unknown:
                raise RuntimeError(
                    f"device '{name}': unknown key(s) {', '.join(unknown)}. "
                    f"Known keys: {', '.join(sorted(WRITABLE_KEYS))}")
            missing = sorted(REQUIRED_KEYS - set(spec))
            if missing:
                raise RuntimeError(f"device '{name}': missing required key(s) {', '.join(missing)}")
            if spec.get("device_type") not in PLATFORMS:
                raise RuntimeError(f"device '{name}': unsupported device_type '{spec.get('device_type')}'")
            if spec.get("access", "ro") not in ("ro", "rw"):
                raise RuntimeError(f"device '{name}': access must be 'ro' or 'rw'")
            if "confirm" in spec and spec["confirm"] is not None:
                # YAML 1.1 turns a bare off/no/false into a boolean, and 'confirm: off'
                # is exactly how people write it - so accept that spelling too.
                conf = spec["confirm"]
                conf = ("off" if conf is False else "totp") if isinstance(conf, bool) else str(conf).strip().lower()
                if conf not in ("totp", "off"):
                    raise RuntimeError(f"device '{name}': confirm must be 'totp' or 'off', not {spec['confirm']!r}")
                spec["confirm"] = conf
            for key in ("password", "secret", "username"):
                if key in spec:
                    spec[key] = _resolve(spec[key])
            spec.pop("name", None)
            devices[name] = Device(name=name, **spec)
        with self._lock:
            self._devices = devices
            self._sig = clab.signature(self.clab_dir, [self.path])
            self._last_scan = time.time()

    def _maybe_rescan(self) -> None:
        """Pick up deployed/destroyed labs without a restart (mtime-based)."""
        if time.time() - self._last_scan < RESCAN_SECONDS:
            return
        if clab.signature(self.clab_dir, [self.path]) != self._sig:
            try:
                self.reload()
            except Exception as exc:  # keep serving the previous inventory
                import logging
                logging.getLogger("wirehand.inventory").error("rescan failed: %s", exc)
                self._last_scan = time.time()
        else:
            self._last_scan = time.time()

    # -- access --------------------------------------------------------------
    def get(self, name: str) -> Device:
        self._maybe_rescan()
        try:
            return self._devices[name]
        except KeyError:
            known = ", ".join(sorted(self._devices)) or "(none)"
            raise KeyError(f"unknown device '{name}'. Known devices: {known}") from None

    def all(self) -> list[Device]:
        self._maybe_rescan()
        return sorted(self._devices.values(), key=lambda d: d.name)
