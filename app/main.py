# SPDX-FileCopyrightText: 2026 Stephan Baenisch
# SPDX-License-Identifier: Apache-2.0
"""wirehand: SSH-backed device analysis & change tool for LLM front-ends.

"A hand on the wires" - the LLM works the devices through wirehand, wirehand keeps the glove on.

Exposed as an OpenAPI tool server. Register http://host.docker.internal:8110
in Open WebUI (Admin -> Settings -> External Tools) and in Onyx (Actions ->
OpenAPI schema). Auth: `Authorization: Bearer <WIREHAND_API_KEY>`.

Design rules (see README):
  * few tools, flat string arguments, plain-text responses
  * read path is always safe: hard refusals + blocklist, allow-list only on
    shell-like (Linux) devices, no privilege escalation
  * every write is two-stage (propose_change / rollback_change -> human
    approval -> confirm_change), and the approval is a one-time code the model
    cannot produce itself (app/approval.py) unless confirmation is switched off
  * output capped (~20k tokens) with server-side regex filter
"""
from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import Future, TimeoutError as FutureTimeout
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import platforms, safety
from .approval import Approver, ConfigError
from .inventory import Inventory
from .safety import DEFAULT_MAX_OUTPUT_CHARS, check_read_command, filter_lines, split_commands, truncate
from .state import ChangeStore, audit, read_audit
from .platforms import pending_prompt
from . import transport
from .transport import (AuthError, Budget, DeadlineExceeded, DeviceBusy, OutcomeUnknown, Pool,
                        check_devices)

logging.basicConfig(level=os.environ.get("WIREHAND_LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("wirehand")

API_KEY = os.environ.get("WIREHAND_API_KEY", "")
MAX_OUT = int(os.environ.get("WIREHAND_MAX_OUTPUT_CHARS", DEFAULT_MAX_OUTPUT_CHARS))
# Overall time limit per tool call, in seconds. The front-end's own tool timeout
# must be longer, or it gives up first and never sees the 504.
DEADLINE_READ = float(os.environ.get("WIREHAND_DEADLINE_READ", "60"))        # run_read, get_facts
DEADLINE_PROPOSE = float(os.environ.get("WIREHAND_DEADLINE_PROPOSE", "60"))  # propose_change, rollback_change
DEADLINE_CONFIRM = float(os.environ.get("WIREHAND_DEADLINE_CONFIRM", "60"))  # confirm_change

inventory = Inventory()
pool = Pool()
changes = ChangeStore()
approver = Approver()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not API_KEY:
        log.warning("WIREHAND_API_KEY is empty - API is unauthenticated!")
    if approver.mode_invalid:
        log.warning("WIREHAND_CONFIRM_MODE is not 'totp' or 'off' - falling back to 'totp'")
    if approver.mode == "totp" and not approver.configured:
        log.warning("confirm_change will REFUSE every change: %s", approver.setup_hint())
    elif approver.mode == "off":
        log.warning("WIREHAND_CONFIRM_MODE=off - the model can apply its own proposals without a human")
    else:
        log.info("changes require a one-time approval code (WIREHAND_CONFIRM_MODE=totp)")
    plats = platforms.registry()   # raises PlatformError -> startup fails, which is the point
    log.info("platforms: %s (%s)", plats.summary(), plats.path)
    rules = safety.rules()   # raises RuleError -> startup fails, which is the point
    log.info("read-path safety rules: %s (%s)", rules.summary(), rules.path)
    for step, value, deadline, dname in _step_limits():
        if value >= deadline:
            log.warning("%s=%gs is not below %s=%gs: that step never ends on its own timeout, the "
                        "deadline cuts it off (504) instead", step, value, dname, deadline)
    log.info("loaded %d devices (inventory.yaml=%s, containerlab=%s)", len(inventory.all()), inventory.path, inventory.clab_dir or "off")
    yield
    pool.close_all()


# Also the start of the description: Open WebUI shows that on mouse-over in the
# chat's tool selection, so users see which version they are talking to.
VERSION = "0.6.2"

app = FastAPI(
    title="wirehand",
    version=VERSION,
    license_info={"name": "Apache-2.0", "identifier": "Apache-2.0"},
    description=(
        f"wirehand {VERSION} - Tools to inspect and configure Linux servers and network devices "
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


def _step_limits():
    """(step name, step seconds, deadline seconds, deadline name): every step
    limit should be below the deadline it runs under."""
    t = transport
    return [
        ("WIREHAND_CMD_TIMEOUT", t.CMD_TIMEOUT, DEADLINE_READ, "WIREHAND_DEADLINE_READ"),
        ("WIREHAND_CMD_TIMEOUT", t.CMD_TIMEOUT, DEADLINE_PROPOSE, "WIREHAND_DEADLINE_PROPOSE"),
        ("WIREHAND_CHANGE_CMD_TIMEOUT", t.CHANGE_CMD_TIMEOUT, DEADLINE_CONFIRM, "WIREHAND_DEADLINE_CONFIRM"),
    ] + [("WIREHAND_LOCK_WAIT", t.LOCK_WAIT, d, n) for d, n in (
        (DEADLINE_READ, "WIREHAND_DEADLINE_READ"), (DEADLINE_PROPOSE, "WIREHAND_DEADLINE_PROPOSE"),
        (DEADLINE_CONFIRM, "WIREHAND_DEADLINE_CONFIRM"))]


class ToolTimeout(Exception):
    """The device work of a tool call did not finish within its deadline."""
    def __init__(self, budget: Budget):
        super().__init__(f"deadline of {budget.seconds:g}s reached")
        self.seconds, self.elapsed, self.device = budget.seconds, budget.elapsed(), budget.device


def _within(seconds: float, work):
    """Run work(budget) in a worker thread and wait at most `seconds` for it.

    On timeout the connection the worker is using is force-closed (Pool.abort),
    so the worker fails, frees the device's lock and ends; the caller gets
    ToolTimeout. Exceptions from the worker are re-raised here unchanged."""
    budget = Budget(seconds)
    fut: Future = Future()

    def runner():
        try:
            fut.set_result(work(budget))
        except BaseException as exc:
            fut.set_exception(exc)
    threading.Thread(target=runner, daemon=True, name="wirehand-call").start()
    try:
        return fut.result(timeout=seconds)
    except (FutureTimeout, DeadlineExceeded):
        pool.abort(budget)
        raise ToolTimeout(budget) from None


def _read_timeout(t: ToolTimeout, dev, tool: str, **fields) -> HTTPException:
    name = t.device or dev.name
    audit("read_timeout", name, tool=tool, seconds=round(t.elapsed, 1), **fields)
    return HTTPException(504, (
        f"TIMED OUT on {name} after {t.elapsed:.1f}s (deadline {t.seconds:g}s). Nothing was "
        f"changed - this tool only reads. The connection was closed; the next call reconnects. "
        f"Check the device with list_devices(check=true), or use a narrower command or a filter, "
        f"before retrying."))


def _propose_timeout(t: ToolTimeout, dev, tool: str) -> HTTPException:
    audit("propose_timeout", dev.name, tool=tool, seconds=round(t.elapsed, 1))
    return HTTPException(504, (
        f"TIMED OUT on {dev.name} after {t.elapsed:.1f}s (deadline {t.seconds:g}s) while taking the "
        f"configuration snapshot. Nothing was staged and nothing was applied - there is no "
        f"change ID. Check the device with list_devices(check=true), then call {tool} again."))


def _busy(dev, exc: DeviceBusy, **fields) -> HTTPException:
    audit("device_busy", dev.name, **fields)
    return HTTPException(409, str(exc))


def _next_step(dev, code: str) -> str:
    """What the model must do to get the staged change applied. In totp mode it
    cannot do it alone, and the text says so in the imperative the small models
    actually follow - the old 'Ask the user to approve. Then call confirm_change'
    was read by some as 'call confirm_change now'. In off mode nothing enforces a
    human step, so the text does not pretend one exists."""
    if not approver.requires_approval(dev.confirm):
        return (f"Show the preview above to the user. If the user agrees in the chat, apply it "
                f"with confirm_change(code='{code}'). No authenticator code is needed for this device.")
    return (
        f"STOP HERE. This device needs approval by a human: the user must read the current "
        f"6-digit code from their authenticator app and send it to you. You cannot generate, "
        f"guess or remember that number, and a code you used before will not work again. "
        f"If it is not in the user's NEXT message, ask for it and wait - do not call any tool. "
        f"Once the user gives you the number, call confirm_change with change ID {code}: "
        f"confirm_change(code='{code}', approval='<the 6 digits from the user>')."
    )


def _confirm_label(dev) -> str:
    """The effective approval mode for list_devices: '-' for read-only devices,
    otherwise 'totp' or 'off' after the device > containerlab > global resolution.
    A totp device with a missing/broken secret still says 'totp' (fail-closed)."""
    if not dev.writable:
        return "-"
    return "totp" if approver.requires_approval(dev.confirm) else "off"


# ---------------------------------------------------------------- tools ---

@app.get("/list_devices", operation_id="list_devices", response_class=PlainTextResponse,
         summary="List all devices you may work with",
         description=(
             "Returns device names, platform and access level (ro = read only, rw = changes allowed). "
             "CONFIRM says what applying a change needs: totp = the user must give you a 6-digit "
             "authenticator code for confirm_change; off = no authenticator code needed; confirm_change "
             "only needs the change ID; "
             "- = read-only device. "
             "Call this first if you do not know the exact device name. "
             "With check=true, also tests which devices are currently reachable from the wirehand "
             "host (TCP connect to the SSH port; verifies network path, not credentials) and adds "
             "a STATE column: up / DOWN / 'up?' (ambiguous - several devices share that management "
             "IP; read and relay the WARNING at the end of the output in that case). "
             "Examples: list_devices() | list_devices(check=true) - 'which devices are up right now?'"
         ), dependencies=[Depends(auth)])
def list_devices(
    refresh: bool = Query(False, description="Re-read inventory.yaml and safety.yaml and rescan containerlab labs now"),
    check: bool = Query(False, description="Also check reachability (SSH port) of every device"),
) -> str:
    if refresh:
        inventory.reload()
        safety.reload()
    devs = inventory.all()
    # containerlab names are <lab>-<node> and easily exceed 24 characters; a fixed
    # width would shift every column of those rows.
    w = max([24] + [len(d.name) for d in devs])
    if not check:
        rows = [f"{d.name:<{w}} {d.device_type:<14} {d.access:<3} {_confirm_label(d):<7} {d.host:<15} {d.description}"
                for d in devs]
        return f"{'NAME':<{w}} PLATFORM       ACC CONFIRM MGMT-IP         DESCRIPTION\n" + "\n".join(rows)
    state = check_devices(devs)
    # Several containerlab labs share the default management subnet (172.20.20.0/24),
    # so the same IP can appear in more than one lab's inventory. A TCP probe cannot
    # tell WHICH lab answered -> mark those entries instead of claiming certainty.
    by_host: dict[str, list[str]] = {}
    for d in devs:
        by_host.setdefault(d.host, []).append(d.name)
    shared = {h: names for h, names in by_host.items() if len(names) > 1}

    rows = []
    for d in devs:
        if not state.get(d.name):
            st = "DOWN"
        elif d.host in shared:
            st = "up?"
        else:
            st = "up"
        rows.append(f"{d.name:<{w}} {d.device_type:<14} {d.access:<3} {_confirm_label(d):<7} {st:<5} {d.host:<15} {d.description}")
    up = sum(1 for v in state.values() if v)
    audit("check_devices", "", up=up, total=len(devs), shared_ips=len(shared))

    out = (f"{'NAME':<{w}} PLATFORM       ACC CONFIRM STATE MGMT-IP         DESCRIPTION\n"
           + "\n".join(rows)
           + f"\n\n{up}/{len(devs)} devices answered on the SSH port "
             "(checked from the wirehand host; this tests the network path, not the credentials).")
    # Only an IP that answered is ambiguous: if it did not, every device behind it
    # is down and 'DOWN' is the truth, whichever lab the name belongs to.
    ambiguous = {h: n for h, n in shared.items() if any(state.get(x) for x in n)}
    if ambiguous:
        groups = "; ".join(f"{h} -> {', '.join(sorted(n))}" for h, n in sorted(ambiguous.items()))
        out += (
            "\n\nWARNING - ambiguous results, marked 'up?':\n"
            f"These devices share a management IP: {groups}\n"
            "containerlab gives every lab the same default management subnet "
            "(172.20.20.0/24), so nodes of different labs can end up with identical IPs. "
            "A reachable IP may therefore belong to a DIFFERENT lab than the name suggests, "
            "and a node shown as 'up?' may in fact be down. Tell the user: give each lab its "
            "own subnet in its .clab.yml, e.g.\n"
            "  mgmt:\n"
            "    network: clab-<labname>\n"
            "    ipv4-subnet: 172.20.30.0/24\n"
            "and remove stale lab folders of labs that are no longer deployed "
            "(destroy with --cleanup)."
        )
    return out


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
    cmds = list(dev.platform.facts)
    try:
        res = _within(DEADLINE_READ, lambda b: pool.run(dev, cmds, budget=b))
    except ToolTimeout as t:
        raise _read_timeout(t, dev, "get_facts")
    except AuthError as exc:
        audit("auth_failed", dev.name)
        raise HTTPException(401, str(exc))
    except DeviceBusy as exc:
        raise _busy(dev, exc, tool="get_facts")
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))
    audit("get_facts", dev.name)
    return _fmt(dev.name, res)


@app.get("/run_read", operation_id="run_read", response_class=PlainTextResponse,
         summary="Run read-only show/display/get/cat/grep commands on one or more devices",
         description=(
             "Executes commands in exec mode and returns the raw output. Safe to call repeatedly. "
             "Write commands (configure, commit, rm, systemctl restart, sudo, ...) are refused here - "
             "use propose_change for those. On Linux devices only known read-only commands run at all "
             "(cat, grep, ls, ip, ss, systemctl status, journalctl, docker ps, ...); anything else is "
             "refused even if it looks harmless, so do not try to work around it - use propose_change. "
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
    names = [n.strip() for n in device.split(",") if n.strip()]
    if not names:
        raise HTTPException(400, "no device given")
    # Resolve every device BEFORE running anything: an unknown name in a list
    # must not leave the earlier devices already executed. What counts as a safe
    # read depends on the platform - a Linux shell needs the strict allow-list,
    # a vendor exec view does not - so check each command per target device type.
    devs = [_device(n) for n in names]
    refused = [(d.name, c, v.reason) for d in devs for c in cmds
               if not (v := check_read_command(c, d.device_type)).allowed]
    if refused:
        msg = "; ".join(f"{d}: '{c}': {r}" for d, c, r in refused)
        raise HTTPException(403, f"refused on read path: {msg}")

    def work(budget):
        out = []
        for dev in devs:
            try:
                res = pool.run(dev, cmds, budget=budget)
            except DeadlineExceeded:
                raise
            except AuthError as exc:
                audit("auth_failed", dev.name, commands=cmds)
                out.append(f"=== {dev.name} ===\n[{exc}]\n")
                continue
            except DeviceBusy as exc:
                if len(devs) == 1:
                    raise _busy(dev, exc, tool="run_read")
                audit("device_busy", dev.name, tool="run_read")
                out.append(f"=== {dev.name} ===\n[{exc}]\n")
                continue
            except RuntimeError as exc:
                out.append(f"=== {dev.name} ===\n[connection error - device unreachable or not "
                           f"responding: {exc}. Verify with list_devices(check=true) before retrying.]\n")
                audit("run_read_error", dev.name, commands=cmds, error=str(exc))
                continue
            audit("run_read", dev.name, commands=cmds, filter=filter)
            out.append(_fmt(dev.name, res, filter, context))
        return out

    try:
        out = _within(DEADLINE_READ, work)
    except ToolTimeout as t:
        raise _read_timeout(t, devs[0], "run_read", commands=cmds)
    return truncate("\n".join(out), MAX_OUT)


class ProposeIn(BaseModel):
    device: str = Field(..., description="Device name (must have access=rw)")
    config: str = Field(..., description=(
        "Configuration lines, ONE PER LINE, exactly as typed on the device. "
        "Cisco/Huawei/Arista/Junos: config-mode lines only (no 'configure terminal', no 'commit' - "
        "the tool adds them). "
        "FortiGate: full section blocks INCLUDING 'config ...', 'next' and 'end' lines, e.g. "
        "'config system global\\nset lldp-reception enable\\nset lldp-transmission enable\\nend' "
        "(missing 'end' lines are appended automatically). "
        "Linux: shell commands run sequentially; prefix with 'sudo' if root is required."))
    reason: str = Field("", description="Short human-readable purpose, goes into the audit log")
    mode: str = Field("config", description=(
        "config (default): configuration lines applied in config/system view and committed/saved. "
        "exec: operational maintenance commands run in user/exec view WITHOUT entering config mode - "
        "use this for reset/clear/process-restart commands (e.g. Huawei 'reset ospf process 1', "
        "Cisco 'clear bgp ipv4 unicast *'). Both modes are only staged here and applied via confirm_change."))


@app.post("/propose_change", operation_id="propose_change", response_class=PlainTextResponse,
          summary="Stage a configuration change (does NOT apply it)",
          description=(
              "Step 1 of 2 for any change. Takes a snapshot of the current configuration, shows a "
              "diff/preview and returns a 6-character change ID. NOTHING is applied yet. "
              "Show the preview to the user, then apply it with confirm_change and that change ID. "
              "Whether the user must additionally give a 6-digit authenticator code depends on the "
              "device's CONFIRM mode (see list_devices); the response says which. "
              "Change IDs are single-use and expire after 10 minutes. "
              "Examples: propose_change(device='r1', config='interface Loopback10\\n description test\\n ipv4 address 10.0.0.10/32', reason='add test loopback') | "
              "maintenance: propose_change(device='ne1', config='reset ospf process 1', mode='exec', reason='restart OSPF after area change')"
          ), dependencies=[Depends(auth)])
def propose_change(body: ProposeIn) -> str:
    dev = _device(body.device)
    if not dev.writable:
        raise HTTPException(403, f"device '{dev.name}' is read-only (access=ro)")
    plat = dev.platform
    lines = [ln.rstrip() for ln in body.config.splitlines() if ln.strip() and not ln.strip().startswith(plat.comment_prefixes)]
    if not lines:
        raise HTTPException(400, "config is empty")
    if body.mode not in ("config", "exec"):
        raise HTTPException(400, "mode must be 'config' or 'exec'")
    dropped: list[str] = []
    if body.mode == "config":
        refused = plat.refused_lines(lines)      # change.refuse_in_config
        if refused:
            raise HTTPException(400, f"do not include {refused} - {plat.refuse_reason}")
        # A closing 'end'/'return' is what models habitually add; on platforms that
        # commit, leaving config mode with uncommitted changes makes the device ask
        # a question the commit step then stumbles over. The tool leaves config
        # mode itself, so the line is dropped - and the preview says so.
        lines, dropped = plat.split_trailing(lines)
        if not lines:
            raise HTTPException(400, f"config is empty once {dropped} is dropped - the tool leaves config mode itself")
        # In the middle of a change the same line leaves config mode with the change
        # uncommitted; the device then asks whether to commit and the session hangs.
        misplaced = plat.misplaced_lines(lines)
        if misplaced:
            raise HTTPException(400, (
                f"{misplaced} is only allowed as the last line - in the middle of a change it leaves "
                f"config mode with the change uncommitted. Remove it (the tool leaves config mode "
                f"itself), or split the change into separate propose_change calls"))
        if plat.balance_end:
            # FortiOS applies a section only at 'end' - balance missing ends automatically.
            opens = sum(1 for ln in lines if ln.strip().lower().startswith("config "))
            ends = sum(1 for ln in lines if ln.strip().lower() == "end")
            if opens > ends:
                lines = lines + ["end"] * (opens - ends)

    snap_cmd = plat.snapshot
    try:
        snapshot = (_within(DEADLINE_PROPOSE, lambda b: pool.run(dev, [snap_cmd], budget=b))[0][1] if snap_cmd
                    else "(no config snapshot on this platform; per-file backups are your responsibility - include them in the change, e.g. 'sudo cp /etc/x /etc/x.bak')")
    except ToolTimeout as t:
        raise _propose_timeout(t, dev, "propose_change")
    except AuthError as exc:
        audit("auth_failed", dev.name)
        raise HTTPException(401, str(exc))
    except DeviceBusy as exc:
        raise _busy(dev, exc, tool="snapshot")
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))
    snap_path = changes.save_snapshot(dev.name, snapshot)

    # Preview: ALWAYS the exact lines that will be sent. (An earlier version diffed
    # against the snapshot line-set; on hierarchical configs the same 'set ...' line can
    # exist under a different section, which made the preview claim changes were
    # already present. Honest beats clever here.)
    if body.mode == "exec":
        preview = "Maintenance commands (user/exec view):\n" + "\n".join(f"  > {ln}" for ln in lines)
    elif plat.shell:
        preview = "Commands to run:\n" + "\n".join(f"  $ {ln}" for ln in lines)
    else:
        preview = "Configuration lines to send:\n" + "\n".join(f"  + {ln}" for ln in lines)
        if dropped:
            preview += (f"\n(dropped from the end: {', '.join(repr(d) for d in dropped)} - "
                        f"the tool leaves config mode itself)")
    pc = changes.create(dev.name, lines, snap_path, preview, mode=body.mode)
    audit("propose_change", dev.name, code=pc.code, lines=lines, reason=body.reason, mode=body.mode, snapshot=str(snap_path))
    return (
        f"STAGED, NOT APPLIED. Change ID: {pc.code}  (device {dev.name}, expires in 10 min)\n"
        f"Snapshot saved: {snap_path.name}\n\n{preview}\n\n"
        + _next_step(dev, pc.code)
    )


@app.post("/confirm_change", operation_id="confirm_change", response_class=PlainTextResponse,
          summary="Apply a previously staged change",
          description=(
              "Step 2 of 2. Applies the staged change identified by the change ID from propose_change "
              "or rollback_change, commits/saves it and returns the device output. Most devices "
              "additionally require `approval`: the current 6-digit one-time code from the USER's "
              "authenticator app, which only the user can read. Never call this tool with an "
              "approval you made up, remembered from an earlier change, or derived yourself - it "
              "will be refused and the attempt is logged. If the user has not sent you a fresh "
              "6-digit code, ask for it instead of calling this tool. "
              "Example: confirm_change(code='A1B2C3', approval='481502')"
          ), dependencies=[Depends(auth)])
def confirm_change(
    code: str = Query(..., min_length=6, max_length=6, description="6-character change ID from propose_change / rollback_change"),
    approval: str = Query("", description=(
        "The current 6-digit code from the USER's authenticator app, exactly as the user sent it. "
        "It changes every 30 seconds and each code works only once. You cannot compute or recall "
        "it - if the user did not just give it to you, do not call this tool.")),
) -> str:
    # peek, not pop: a wrong approval must not throw the staged change away.
    try:
        pc = changes.peek(code)
    except KeyError as exc:
        raise HTTPException(404, str(exc))
    dev = _device(pc.device)
    if not dev.writable:
        raise HTTPException(403, f"device '{dev.name}' is read-only (access=ro)")
    if approver.requires_approval(dev.confirm):
        try:
            verdict = approver.verify(approval)
        except ConfigError as exc:
            audit("confirm_denied", dev.name, code=pc.code, reason="approval not configured")
            raise HTTPException(503, str(exc))
        if not verdict.ok:
            audit("confirm_denied", dev.name, code=pc.code, reason=verdict.reason, approval_given=bool(approval.strip()))
            raise HTTPException(403, (
                f"NOT APPLIED - {verdict.reason}. The change is still staged as {pc.code} until it "
                f"expires. Ask the user for the current 6-digit code from their authenticator app "
                f"and call confirm_change again with it. Do not retry with a number you invented."))
    try:
        pc = changes.pop(code)   # consume only once the approval holds
    except KeyError as exc:
        raise HTTPException(404, str(exc))
    def work(budget):
        if pc.mode in ("exec", "rollback"):
            # prompts="yes": a human approved this operation, so a device that asks
            # "Continue? [Y/N]" gets its answer instead of stalling the session.
            # idempotent=False: never re-send a change command after an error.
            res = pool.run(dev, pc.lines, timeout=transport.CHANGE_CMD_TIMEOUT, prompts="yes",
                           idempotent=False, budget=budget)
            return "\n".join(f"> {c}\n{o}" for c, o in res)
        return pool.configure(dev, pc.lines, commit=dev.platform.commits, budget=budget)

    try:
        out = _within(DEADLINE_CONFIRM, work)
    except ToolTimeout as t:
        # No automatic rollback: wirehand cannot tell what the device did, and
        # undoing a change that never landed is a change of its own.
        audit("confirm_timeout", dev.name, code=pc.code, mode=pc.mode, seconds=round(t.elapsed, 1))
        raise HTTPException(504, (
            f"OUTCOME UNKNOWN on {dev.name} after {t.elapsed:.1f}s (deadline {t.seconds:g}s). The "
            f"change may or may not have been applied. Do NOT retry: the change ID {code} is used up and "
            f"the staged change is gone. Verify the current state with run_read and report it to the "
            f"user. The configuration from before this change was saved as {pc.snapshot_path}."))
    except AuthError as exc:
        audit("auth_failed", dev.name, code=pc.code)
        raise HTTPException(401, str(exc))
    except DeviceBusy as exc:
        # Nothing was sent: the change is staged again under the same change ID.
        changes.restore(pc)
        again = ("Ask the user for a NEW 6-digit code from their authenticator app - the one just "
                 "used does not work twice - and call confirm_change again with it."
                 if approver.requires_approval(dev.confirm) else "Call confirm_change again.")
        audit("device_busy", dev.name, tool="confirm_change", code=pc.code)
        raise HTTPException(409, (
            f"{exc} NOT APPLIED. The change is still staged as {pc.code} until it expires. {again}"))
    except OutcomeUnknown as exc:
        # Something went wrong after the change reached the device: it may or may
        # not have been applied. Saying "APPLIED" or "failed" would both be guesses.
        audit("confirm_unknown", dev.name, code=pc.code, mode=pc.mode, error=str(exc))
        raise HTTPException(502, (
            f"NOT CONFIRMED - OUTCOME UNKNOWN on {dev.name}: {exc}. The change may or may not have "
            f"been applied. Do NOT retry confirm_change; the change ID {code} is used up. Verify the "
            f"current state with run_read and report it to the user. The configuration from before "
            f"this change was saved as {pc.snapshot_path}."))
    except Exception as exc:
        audit("confirm_change_error", dev.name, code=pc.code, error=str(exc))
        raise HTTPException(502, f"change failed on {dev.name}: {type(exc).__name__}: {exc}. Snapshot {pc.snapshot_path} is available for rollback.")
    # Never report success while the device is still asking a question: the
    # command has not run then, and saying "ROLLED BACK" when nothing was rolled
    # back is worse than failing.
    stuck = pending_prompt(out, dev.device_type)
    if stuck:
        pool.reset(dev)          # the session is sitting at that question
        audit("confirm_incomplete", dev.name, code=pc.code, mode=pc.mode, question=stuck[0])
        raise HTTPException(502, (
            f"NOT COMPLETED on {dev.name}: the device asked '{stuck[0]}' and is still waiting, "
            f"so the operation did NOT run. Nothing was applied by this call. Report this to the "
            f"user - it needs a fix on the wirehand host (the prompt is unknown to the "
            f"'prompts' in config/platforms/), not another attempt.\n\n{truncate(out, 4000)}"))
    audit("confirm_change", dev.name, code=pc.code, lines=pc.lines, mode=pc.mode,
          approval=approver.mode_for(dev.confirm))
    if pc.mode == "rollback":
        return truncate(f"ROLLED BACK on {dev.name} (change ID {code}). The device is back to the state "
                        f"before its last commit; the configuration from before this rollback was "
                        f"saved as {pc.snapshot_path}.\n\n{out}", MAX_OUT)
    if pc.mode == "exec":
        return truncate(f"EXECUTED on {dev.name} (change ID {code}, exec mode - nothing was committed).\n\n{out}", MAX_OUT)
    rb = "native rollback available via rollback_change" if dev.platform.rollback_last else "no native rollback on this platform - rollback_change returns the snapshot for manual restore"
    return truncate(f"APPLIED on {dev.name} (change ID {code}). {rb}.\n\n{out}", MAX_OUT)


@app.post("/rollback_change", operation_id="rollback_change", response_class=PlainTextResponse,
          summary="Stage an undo of the last applied change (does NOT apply it)",
          description=(
              "Step 1 of 2, exactly like propose_change: on IOS-XR / Huawei VRPv8 / Junos this STAGES "
              "a native rollback of the last commit and returns a 6-character change ID - "
              "nothing is undone yet. Show the preview to the user, then apply it with confirm_change "
              "and that change ID. Whether the user must additionally give a 6-digit authenticator "
              "code depends on the device's CONFIRM mode (see list_devices). On platforms without a native rollback it "
              "changes nothing and returns the pre-change snapshot instead, so you can derive a "
              "corrective propose_change from it. "
              "Example: rollback_change(device='r1')"
          ), dependencies=[Depends(auth)])
def rollback_change(device: str = Query(..., description="Device name")) -> str:
    dev = _device(device)
    if not dev.writable:
        raise HTTPException(403, f"device '{dev.name}' is read-only (access=ro)")
    cmds = list(dev.platform.rollback_last or [])
    if not cmds:
        # No native rollback: returning the snapshot changes nothing on the device.
        snap = changes.latest_snapshot(dev.name)
        audit("rollback_snapshot", dev.name, snapshot=str(snap))
        if not snap:
            return f"No native rollback on {dev.device_type} and no snapshot found for {dev.name}."
        return truncate(
            f"No native rollback on {dev.device_type}. Pre-change snapshot {snap.name} follows; "
            f"derive a corrective propose_change from it.\n\n{snap.read_text()}", MAX_OUT)

    # A native rollback overwrites the running configuration - that is a write, so
    # it goes through the same two-stage gate (and the device's confirm mode) as any
    # other change instead of applying on a single call.
    snap_cmd = dev.platform.snapshot
    try:
        snapshot = (_within(DEADLINE_PROPOSE, lambda b: pool.run(dev, [snap_cmd], budget=b))[0][1] if snap_cmd
                    else "(no config snapshot for this platform)")
    except ToolTimeout as t:
        raise _propose_timeout(t, dev, "rollback_change")
    except AuthError as exc:
        audit("auth_failed", dev.name)
        raise HTTPException(401, str(exc))
    except DeviceBusy as exc:
        raise _busy(dev, exc, tool="snapshot")
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))
    snap_path = changes.save_snapshot(dev.name, snapshot)
    preview = "Rollback commands (user/exec view):\n" + "\n".join(f"  > {c}" for c in cmds)
    pc = changes.create(dev.name, cmds, snap_path, preview, mode="rollback")
    audit("rollback_staged", dev.name, code=pc.code, lines=cmds, snapshot=str(snap_path))
    return (
        f"STAGED, NOT APPLIED. Change ID: {pc.code}  (device {dev.name}, expires in 10 min)\n"
        f"This undoes the last commit on {dev.name}. The configuration as it is RIGHT NOW was saved "
        f"as {snap_path.name} first.\n\n{preview}\n\n"
        + _next_step(dev, pc.code)
    )


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
    return {"status": "ok", "devices": len(inventory.all()), "pending_changes": len(changes.list()),
            "confirm_mode": approver.mode, "approval_ready": approver.configured}


@app.get("/pending", include_in_schema=False, dependencies=[Depends(auth)])
def pending():
    return changes.list()
