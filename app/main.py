"""wirehand: SSH-backed device analysis & change tool for LLM front-ends.

"A hand on the wires" - the LLM works the devices through wirehand, wirehand keeps the glove on.

Exposed as an OpenAPI tool server. Register http://host.docker.internal:8110
in Open WebUI (Admin -> Settings -> External Tools) and in Onyx (Actions ->
OpenAPI schema). Auth: `Authorization: Bearer <WIREHAND_API_KEY>`.

Design rules (see README):
  * few tools, flat string arguments, plain-text responses
  * read path is always safe: blocklist + no privilege escalation
  * writes are two-stage (propose_change -> human approval -> confirm_change)
  * output capped (~20k tokens) with server-side regex filter
"""
from __future__ import annotations

import difflib
import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import platforms
from .inventory import Inventory
from .safety import DEFAULT_MAX_OUTPUT_CHARS, check_read_command, filter_lines, split_commands, truncate
from .state import ChangeStore, audit, read_audit
from .transport import Pool

logging.basicConfig(level=os.environ.get("WIREHAND_LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("wirehand")

API_KEY = os.environ.get("WIREHAND_API_KEY", "")
MAX_OUT = int(os.environ.get("WIREHAND_MAX_OUTPUT_CHARS", DEFAULT_MAX_OUTPUT_CHARS))

inventory = Inventory()
pool = Pool()
changes = ChangeStore()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not API_KEY:
        log.warning("WIREHAND_API_KEY is empty - API is unauthenticated!")
    log.info("loaded %d devices (inventory.yaml=%s, containerlab=%s)", len(inventory.all()), inventory.path, inventory.clab_dir or "off")
    yield
    pool.close_all()


app = FastAPI(
    title="wirehand",
    version="0.3.0",
    description=(
        "Tools to inspect and configure Linux servers and network devices "
        "(Cisco IOS/IOS-XR, Huawei VRP, FortiGate, ...) over SSH. Device names come "
        "from list_devices. Read tools are safe to call freely. Configuration changes "
        "require propose_change followed by human approval and confirm_change."
    ),
    lifespan=lifespan,
)

# Browsers (Open WebUI / Onyx front-end) fetch /openapi.json directly and send a
# CORS preflight first -> without this every OPTIONS request returns 405.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("WIREHAND_CORS_ORIGINS", "*").split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],   # Open WebUI sends extra headers in the preflight; auth is enforced separately
)


def auth(authorization: Annotated[str | None, Header()] = None):
    if not API_KEY:
        return
    if authorization != f"Bearer {API_KEY}":
        raise HTTPException(401, "invalid or missing bearer token")


def _device(name: str):
    try:
        return inventory.get(name.strip())
    except KeyError as exc:
        raise HTTPException(404, str(exc))


def _fmt(device: str, results: list[tuple[str, str]], flt: str = "", context: int = 0) -> str:
    blocks = []
    for cmd, out in results:
        body = filter_lines(out, flt, context) if flt else out
        blocks.append(f"=== {device} : {cmd} ===\n{body.rstrip()}\n")
    return truncate("\n".join(blocks), MAX_OUT)


# ---------------------------------------------------------------- tools ---

@app.get("/list_devices", operation_id="list_devices", response_class=PlainTextResponse,
         summary="List all devices you may work with",
         description=(
             "Returns device names, platform and access level (ro = read only, rw = changes allowed). "
             "Call this first if you do not know the exact device name. "
             "Example: list_devices()"
         ), dependencies=[Depends(auth)])
def list_devices(refresh: bool = Query(False, description="Re-read inventory.yaml and rescan containerlab labs now")) -> str:
    if refresh:
        inventory.reload()
    rows = [f"{d.name:<24} {d.device_type:<14} {d.access:<3} {d.host:<15} {d.description}" for d in inventory.all()]
    return "NAME                     PLATFORM       ACC MGMT-IP         DESCRIPTION\n" + "\n".join(rows)


@app.get("/get_facts", operation_id="get_facts", response_class=PlainTextResponse,
         summary="One-call health/overview bundle for a device",
         description=(
             "Runs a fixed set of overview commands (version, interfaces, routing summary, "
             "neighbors, recent log) and returns them together. Use this as the FIRST step of "
             "any analysis instead of running the commands one by one. "
             "Example: get_facts(device='r1')"
         ), dependencies=[Depends(auth)])
def get_facts(device: str = Query(..., description="Device name from list_devices")) -> str:
    dev = _device(device)
    cmds = platforms.FACTS.get(dev.family, ["show version"])
    try:
        res = pool.run(dev, cmds)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))
    audit("get_facts", dev.name)
    return _fmt(dev.name, res)


@app.get("/run_read", operation_id="run_read", response_class=PlainTextResponse,
         summary="Run read-only show/display/get/cat/grep commands on one or more devices",
         description=(
             "Executes commands in exec mode and returns the raw output. Safe to call repeatedly. "
             "Write commands (configure, commit, rm, systemctl restart, sudo, ...) are refused here - "
             "use propose_change for those. "
             "Put several commands on separate lines or separate them with ';'. "
             "Several devices: comma-separated names. "
             "For long outputs (show running-config, large logs) ALWAYS set filter to a regex so "
             "only matching lines are returned; use context to include surrounding lines. "
             "Examples: "
             "run_read(device='r1', commands='show bgp summary') | "
             "run_read(device='r1', commands='show running-config', filter='interface Gig|description', context=2) | "
             "run_read(device='srv1,srv2', commands='df -h; free -m') | "
             "run_read(device='srv1', commands='journalctl -u nginx -n 200 --no-pager', filter='error|fail')"
         ), dependencies=[Depends(auth)])
def run_read(
    device: str = Query(..., description="Device name, or several names separated by commas"),
    commands: str = Query(..., description="One command per line, or ';'-separated"),
    filter: str = Query("", description="Optional case-insensitive regex; only matching lines are returned"),
    context: int = Query(0, ge=0, le=20, description="Lines of context around each filter match"),
) -> str:
    cmds = split_commands(commands)
    if not cmds:
        raise HTTPException(400, "no commands given")
    refused = [(c, v.reason) for c in cmds if not (v := check_read_command(c)).allowed]
    if refused:
        msg = "; ".join(f"'{c}': {r}" for c, r in refused)
        raise HTTPException(403, f"refused on read path: {msg}")
    out = []
    for name in [n.strip() for n in device.split(",") if n.strip()]:
        dev = _device(name)
        try:
            res = pool.run(dev, cmds)
        except RuntimeError as exc:
            out.append(f"=== {dev.name} ===\n[connection error: {exc}]\n")
            audit("run_read_error", dev.name, commands=cmds, error=str(exc))
            continue
        audit("run_read", dev.name, commands=cmds, filter=filter)
        out.append(_fmt(dev.name, res, filter, context))
    return truncate("\n".join(out), MAX_OUT)


class ProposeIn(BaseModel):
    device: str = Field(..., description="Device name (must have access=rw)")
    config: str = Field(..., description=(
        "Configuration lines, one per line, exactly as typed on the device. "
        "Network devices: config-mode lines (no 'configure terminal', no 'commit' - the tool adds them). "
        "Linux: shell commands run sequentially; prefix with 'sudo' if root is required."))
    reason: str = Field("", description="Short human-readable purpose, goes into the audit log")
    mode: str = Field("config", description=(
        "config (default): configuration lines applied in config/system view and committed/saved. "
        "exec: operational maintenance commands run in user/exec view WITHOUT entering config mode - "
        "use this for reset/clear/process-restart commands (e.g. Huawei 'reset ospf process 1', "
        "Cisco 'clear bgp ipv4 unicast *'). Both modes require user approval via confirm_change."))


@app.post("/propose_change", operation_id="propose_change", response_class=PlainTextResponse,
          summary="Stage a configuration change (does NOT apply it)",
          description=(
              "Step 1 of 2 for any change. Takes a snapshot of the current configuration, shows a "
              "diff/preview and returns a 6-character confirmation code. NOTHING is applied yet. "
              "Show the code and the preview to the user and ask for explicit approval. Only after "
              "the user approves, call confirm_change with that code. Codes expire after 10 minutes. "
              "Examples: propose_change(device='r1', config='interface Loopback10\\n description test\\n ipv4 address 10.0.0.10/32', reason='add test loopback') | "
              "maintenance: propose_change(device='ne1', config='reset ospf process 1', mode='exec', reason='restart OSPF after area change')"
          ), dependencies=[Depends(auth)])
def propose_change(body: ProposeIn) -> str:
    dev = _device(body.device)
    if not dev.writable:
        raise HTTPException(403, f"device '{dev.name}' is read-only (access=ro)")
    lines = [ln.rstrip() for ln in body.config.splitlines() if ln.strip() and not ln.strip().startswith(("#", "!"))]
    if not lines:
        raise HTTPException(400, "config is empty")
    if body.mode not in ("config", "exec"):
        raise HTTPException(400, "mode must be 'config' or 'exec'")
    if body.mode == "config":
        forbidden = [ln for ln in lines if ln.strip().lower().split()[0] in ("commit", "end", "configure", "conf", "write", "reload", "reboot")]
        if forbidden and dev.family != "linux":
            raise HTTPException(400, f"do not include {forbidden} - the tool handles mode changes and commit")

    snap_cmd = platforms.SNAPSHOT.get(dev.family)
    try:
        snapshot = pool.run(dev, [snap_cmd])[0][1] if snap_cmd else "(linux: no config snapshot; per-file backups are your responsibility - include them in the change, e.g. 'sudo cp /etc/x /etc/x.bak')"
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))
    snap_path = changes.save_snapshot(dev.name, snapshot)

    # Preview: for config platforms a unified diff of "what will be added"; for linux/exec the command list.
    if body.mode == "exec":
        preview = "Maintenance commands (user/exec view):\n" + "\n".join(f"  > {ln}" for ln in lines)
    elif dev.family == "linux":
        preview = "Commands to run:\n" + "\n".join(f"  $ {ln}" for ln in lines)
    else:
        existing = snapshot.splitlines()
        added = [ln for ln in lines if ln.strip() not in {e.strip() for e in existing}]
        preview = "\n".join(difflib.unified_diff([], added, fromfile="running-config", tofile="proposed (additions)", lineterm="")) or "(all lines already present in running-config)"
    pc = changes.create(dev.name, lines, snap_path, preview, mode=body.mode)
    audit("propose_change", dev.name, code=pc.code, lines=lines, reason=body.reason, mode=body.mode, snapshot=str(snap_path))
    return (
        f"STAGED, NOT APPLIED. Confirmation code: {pc.code}  (device {dev.name}, expires in 10 min)\n"
        f"Snapshot saved: {snap_path.name}\n\n{preview}\n\n"
        "Ask the user to approve. Then call confirm_change(code='" + pc.code + "')."
    )


@app.post("/confirm_change", operation_id="confirm_change", response_class=PlainTextResponse,
          summary="Apply a previously proposed change after the user approved it",
          description=(
              "Step 2 of 2. Applies the staged change identified by the code from propose_change, "
              "commits/saves it and returns the device output. Only call this after the user has "
              "explicitly approved the exact code in the chat. "
              "Example: confirm_change(code='A1B2C3')"
          ), dependencies=[Depends(auth)])
def confirm_change(code: str = Query(..., min_length=6, max_length=6, description="6-character code from propose_change")) -> str:
    try:
        pc = changes.pop(code)
    except KeyError as exc:
        raise HTTPException(404, str(exc))
    dev = _device(pc.device)
    if not dev.writable:
        raise HTTPException(403, f"device '{dev.name}' is read-only (access=ro)")
    try:
        if pc.mode == "exec":
            out = "\n".join(f"> {c}\n{o}" for c, o in pool.run(dev, pc.lines, timeout=120))
        else:
            out = pool.configure(dev, pc.lines, commit=platforms.COMMITS.get(dev.family, False))
    except Exception as exc:
        audit("confirm_change_error", dev.name, code=code, error=str(exc))
        raise HTTPException(502, f"change failed on {dev.name}: {type(exc).__name__}: {exc}. Snapshot {pc.snapshot_path} is available for rollback.")
    audit("confirm_change", dev.name, code=code, lines=pc.lines, mode=pc.mode)
    if pc.mode == "exec":
        return truncate(f"EXECUTED on {dev.name} (code {code}, exec mode - nothing was committed).\n\n{out}", MAX_OUT)
    rb = "native rollback available via rollback_change" if platforms.ROLLBACK_LAST.get(dev.family) else "no native rollback on this platform - rollback_change returns the snapshot for manual restore"
    return truncate(f"APPLIED on {dev.name} (code {code}). {rb}.\n\n{out}", MAX_OUT)


@app.post("/rollback_change", operation_id="rollback_change", response_class=PlainTextResponse,
          summary="Undo the last applied change on a device",
          description=(
              "On IOS-XR / Huawei VRPv8 / Junos this performs a native rollback of the last commit. "
              "On other platforms it cannot undo automatically and instead returns the pre-change "
              "snapshot so you can propose a corrective change. Always confirm with the user before calling. "
              "Example: rollback_change(device='r1')"
          ), dependencies=[Depends(auth)])
def rollback_change(device: str = Query(..., description="Device name")) -> str:
    dev = _device(device)
    if not dev.writable:
        raise HTTPException(403, f"device '{dev.name}' is read-only (access=ro)")
    cmds = platforms.ROLLBACK_LAST.get(dev.family)
    snap = changes.latest_snapshot(dev.name)
    if cmds:
        try:
            res = pool.run(dev, cmds, timeout=120)
        except RuntimeError as exc:
            raise HTTPException(502, str(exc))
        audit("rollback", dev.name, native=True)
        return _fmt(dev.name, res)
    audit("rollback", dev.name, native=False, snapshot=str(snap))
    if not snap:
        return f"No native rollback on {dev.device_type} and no snapshot found for {dev.name}."
    return truncate(
        f"No native rollback on {dev.device_type}. Pre-change snapshot {snap.name} follows; "
        f"derive a corrective propose_change from it.\n\n{snap.read_text()}", MAX_OUT)


@app.get("/get_audit_log", operation_id="get_audit_log", response_class=PlainTextResponse,
         summary="Show recent tool activity (who ran what, what was changed)",
         description="Returns the last n audit entries, optionally for one device. Example: get_audit_log(device='r1', n=20)",
         dependencies=[Depends(auth)])
def get_audit_log(device: str = Query("", description="Optional device name"), n: int = Query(20, ge=1, le=200)) -> str:
    rows = read_audit(device, n)
    if not rows:
        return "(audit log empty)"
    lines = []
    for r in rows:
        extra = {k: v for k, v in r.items() if k not in ("ts", "event", "device")}
        lines.append(f"{r['ts']}  {r['event']:<20} {r['device']:<14} {extra if extra else ''}")
    return truncate("\n".join(lines), MAX_OUT)


# ------------------------------------------------------------ operational --

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok", "devices": len(inventory.all()), "pending_changes": len(changes.list())}


@app.get("/pending", include_in_schema=False, dependencies=[Depends(auth)])
def pending():
    return changes.list()
