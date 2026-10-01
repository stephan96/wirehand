"""Containerlab discovery.

Scans WIREHAND_CLAB_DIR for deployed labs. containerlab writes a
`clab-<lab>/ansible-inventory.yml` next to every deployed topology which holds
node kind (as group), management IP (ansible_host) and, per kind, the default
credentials (ansible_user / ansible_password). That file only exists while the
lab is deployed, so discovery naturally tracks what is actually reachable.

`topology-data.json` is used as a fallback for IPs/kinds when a lab's ansible
inventory is missing, combined with credentials from the `containerlab:`
section of inventory.yaml.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import yaml

log = logging.getLogger("wirehand.clab")

CLAB_DIR = os.environ.get("WIREHAND_CLAB_DIR", "")

# containerlab kind -> Netmiko device_type. Override/extend via inventory.yaml
# `containerlab.kinds`. Kinds not listed (and not overridden) are skipped.
KIND_MAP: dict[str, str] = {
    "cisco_xrd": "cisco_xr",
    "cisco_xrv9k": "cisco_xr",
    "cisco_xrv": "cisco_xr",
    "cisco_iol": "cisco_ios",
    "cisco_csr1000v": "cisco_xe",
    "cisco_c8000v": "cisco_xe",
    "cisco_cat9kv": "cisco_xe",
    "cisco_n9kv": "cisco_nxos",
    "huawei_vrp": "huawei_vrpv8",
    "fortinet_fortigate": "fortinet",
    "arista_ceos": "arista_eos",
    "arista_veos": "arista_eos",
    "juniper_vjunosrouter": "juniper_junos",
    "juniper_vjunosswitch": "juniper_junos",
    "juniper_vmx": "juniper_junos",
    "juniper_vsrx": "juniper_junos",
    "linux": "linux",
    "sonic-vs": "linux",
    "generic_vm": "linux",
}

# Well-known default credentials per kind, used only when the generated
# inventory carries none. Override in inventory.yaml `containerlab.credentials`.
DEFAULT_CREDS: dict[str, tuple[str, str]] = {
    "cisco_xrd": ("clab", "clab@123"),
    "cisco_xrv9k": ("clab", "clab@123"),
    "cisco_iol": ("admin", "admin"),
    "huawei_vrp": ("admin", "admin"),
    "fortinet_fortigate": ("admin", "admin"),
    "arista_ceos": ("admin", "admin"),
    "linux": ("clab", "clab@123"),
}


def _short_name(lab: str, host: str) -> str:
    """'clab-xrd-test-xrd1' in lab 'xrd-test' -> 'xrd-test-xrd1'."""
    prefix = f"clab-{lab}-"
    return host[len(prefix):] if host.startswith(prefix) else host.removeprefix("clab-")


def _setting(kinds_cfg: dict, kind: str, cfg: dict, key: str, default=None):
    """`kinds.<kind>.<key>` beats `default_<key>` beats the built-in default.

    Tests for presence, not truthiness: `confirm: off` is a legitimate value that
    YAML 1.1 hands us as False, and a falsy override must still win.
    """
    per_kind = kinds_cfg.get(kind) or {}
    if per_kind.get(key) is not None:
        return per_kind[key]
    value = cfg.get(f"default_{key}")
    return default if value is None else value


def _parse_ansible(path: Path, lab: str, cfg: dict) -> list[dict]:
    data = yaml.safe_load(path.read_text()) or {}
    out = []
    kinds_cfg = cfg.get("kinds", {})
    creds_cfg = cfg.get("credentials", {})
    for kind, group in (data.get("all", {}).get("children") or {}).items():
        dev_type = (kinds_cfg.get(kind) or {}).get("device_type") or KIND_MAP.get(kind)
        if not dev_type:
            log.info("lab %s: kind '%s' not mapped, skipping", lab, kind)
            continue
        gvars = group.get("vars") or {}
        user = gvars.get("ansible_user")
        pw = gvars.get("ansible_password")
        if kind in creds_cfg:   # explicit override beats generated values
            user = creds_cfg[kind].get("username", user)
            pw = creds_cfg[kind].get("password", pw)
        if not user or pw is None:
            du, dp = DEFAULT_CREDS.get(kind, (None, None))
            user, pw = user or du, pw if pw is not None else dp
        if not user:
            log.warning("lab %s: no credentials for kind '%s', skipping", lab, kind)
            continue
        for host, hv in (group.get("hosts") or {}).items():
            ip = (hv or {}).get("ansible_host")
            if not ip:
                continue
            out.append({
                "name": f"{lab}-{_short_name(lab, host)}" if not cfg.get("long_names") else host,
                "host": ip,
                "device_type": dev_type,
                "username": user,
                "password": pw,
                "access": _setting(kinds_cfg, kind, cfg, "access", "rw"),
                "confirm": _setting(kinds_cfg, kind, cfg, "confirm"),
                "description": f"containerlab {lab} / {kind}",
                "tags": ["clab", lab, kind],
                "source": f"containerlab:{lab}",
            })
    return out


def _parse_topology_json(path: Path, lab: str, cfg: dict) -> list[dict]:
    data = json.loads(path.read_text())
    out = []
    kinds_cfg = cfg.get("kinds", {})
    creds_cfg = cfg.get("credentials", {})
    for node, nv in (data.get("nodes") or {}).items():
        kind = nv.get("kind", "")
        dev_type = (kinds_cfg.get(kind) or {}).get("device_type") or KIND_MAP.get(kind)
        ip = nv.get("mgmt-ipv4-address")
        if not dev_type or not ip:
            continue
        c = creds_cfg.get(kind) or {}
        du, dp = DEFAULT_CREDS.get(kind, (None, None))
        user, pw = c.get("username", du), c.get("password", dp)
        if not user:
            continue
        out.append({
            "name": f"{lab}-{node}", "host": ip, "device_type": dev_type,
            "username": user, "password": pw,
            "access": _setting(kinds_cfg, kind, cfg, "access", "rw"),
            "confirm": _setting(kinds_cfg, kind, cfg, "confirm"),
            "description": f"containerlab {lab} / {kind}", "tags": ["clab", lab, kind],
            "source": f"containerlab:{lab}",
        })
    return out


def discover(clab_dir: str | Path, cfg: dict | None = None) -> list[dict]:
    """Return device specs for every deployed lab below clab_dir."""
    cfg = cfg or {}
    root = Path(clab_dir)
    if not root.is_dir():
        log.warning("containerlab dir %s not found", root)
        return []
    devices: list[dict] = []
    # clab-<lab>/ appears anywhere below root (labs live in their own folders)
    for labdir in sorted(root.glob("**/clab-*/")):
        if not labdir.is_dir():
            continue
        lab = labdir.name.removeprefix("clab-")
        ans, topo = labdir / "ansible-inventory.yml", labdir / "topology-data.json"
        try:
            if ans.exists():
                found = _parse_ansible(ans, lab, cfg)
            elif topo.exists():
                found = _parse_topology_json(topo, lab, cfg)
            else:
                continue
        except Exception as exc:  # one broken lab must not hide the others
            log.error("lab %s: failed to parse: %s", lab, exc)
            continue
        log.info("lab %s: %d device(s)", lab, len(found))
        devices.extend(found)
    return devices


def signature(clab_dir: str | Path, extra_files: list[Path] | None = None) -> tuple:
    """Cheap change detector: lab inventories + extra files (e.g. inventory.yaml)."""
    sig = []
    root = Path(clab_dir) if clab_dir else None
    if root and root.is_dir():
        for labdir in root.glob("**/clab-*/"):
            f = labdir / "ansible-inventory.yml"
            if f.exists():
                sig.append((str(f), f.stat().st_mtime))
    for f in extra_files or []:
        if f.exists():
            sig.append((str(f), f.stat().st_mtime))
    return tuple(sorted(sig))
