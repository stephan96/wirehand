# wirehand

*A hand on the wires - with a glove on.*

**Version:** 0.3.6

## Summary

wirehand lets an LLM front-end (Open WebUI, Onyx) work on real network devices and Linux
servers over SSH: run show commands, analyze the output, and - with explicit human
approval - apply configuration changes.

It is a small FastAPI service that presents a handful of well-described tools via
OpenAPI; any front-end that speaks "OpenAPI tool server" can use it. Devices come from
containerlab auto-discovery and/or a manual inventory file, credentials stay on the
server, and every change is staged, human-approved, snapshotted and audited.

## How it works

```
Browser (Open WebUI chat)                    wirehand container            Devices
        |                                            |                           |
        |--- tool call: run_read(device, cmds) ----->|                           |
        |                                            |--- SSH (Netmiko) -------->|
        |                                            |<-- command output --------|
        |<-- plain text output ----------------------|                           |
```

### The tools, in the order a session uses them

| Tool | Type | What it does |
|---|---|---|
| `list_devices(refresh, check)` | read | Device names, platform, access level, mgmt IP. `refresh=true` forces a rescan; `check=true` adds a STATE column (up / DOWN / `up?`) by TCP-probing each SSH port from the wirehand host. |
| `get_facts(device)` | read | One-call overview bundle (version, interfaces, routing summary, neighbors, recent log) - the intended first step of an analysis. |
| `run_read(device, commands, filter, context)` | read | Arbitrary read-only commands. `device` accepts several names comma-separated. `filter` is a server-side case-insensitive regex; only matching lines (plus `context` surrounding lines) are returned - essential for running-configs and logs. |
| `propose_change(device, config, reason, mode)` | stage | Takes a snapshot, builds a preview, returns a 6-char code. **Applies nothing.** `mode='config'` (default) = configuration lines; `mode='exec'` = operational maintenance commands (reset, clear, process restarts) that must run in user/exec view - e.g. Huawei `reset ospf process 1`. |
| `confirm_change(code)` | write | Applies the staged change: config mode + commit/save for `config`, plain exec for `exec`. Requires `access: rw` on the device. |
| `rollback_change(device)` | write | IOS-XR / VRPv8 / Junos: native rollback of the last commit. Other platforms: returns the pre-change snapshot so a corrective change can be proposed. |
| `get_audit_log(device, n)` | read | The last `n` audit entries, optionally filtered by device. |

Output of every tool is plain text (small local models handle text much better than
JSON) and capped at ~20k tokens (`WIREHAND_MAX_OUTPUT_CHARS`); truncation is marked in the
output together with the hint to use `filter`.

## Key properties

- **Credentials never reach the LLM.** The model only knows device *names*. Hostnames,
  IPs, users and passwords live server-side (inventory file + environment variables).
- **Reading is always safe.** `run_read` refuses write/privileged commands (configure,
  commit, rm, sudo, redirection, pipes into interpreters) no matter what the model asks.
- **Writing is two-stage and human-gated.** `propose_change` only *stages* a change and
  returns a confirmation code. Nothing touches the device until a human approves the code
  in the chat and the model calls `confirm_change` with it. Codes are single-use and
  expire after 10 minutes.
- **Everything is logged.** Every tool call lands in an append-only audit log; every
  proposed change first saves a configuration snapshot (see "Audit log & snapshots").

## Installation

Requirements: Docker + Compose on the machine that can reach your devices - for
containerlab that is the clab host itself.

```bash
tar xzf wirehand-<version>.tar.gz -C ~/docker    # creates/overwrites ~/docker/wirehand
cd ~/docker/wirehand

cp .env.example .env
cp config/inventory.yaml.example config/inventory.yaml
$EDITOR .env                    # see "Configuration" below
$EDITOR config/inventory.yaml
chmod 600 .env config/inventory.yaml

UID=$(id -u) GID=$(id -g) docker compose build
docker compose up -d

# smoke test (replace the key):
curl -H "Authorization: Bearer $(grep WIREHAND_API_KEY .env | cut -d= -f2)" \
     http://localhost:8110/list_devices
docker logs wirehand | grep "device(s)"          # one line per discovered lab
```

**Why `UID=$(id -u) GID=$(id -g)`:** bind mounts keep host ownership. A file with mode
600 is only readable by its *owner*, so the user inside the container must have the same
uid as you on the host. The build args bake your uid/gid into the image. If you skip
this on a system where your uid is not 1000, the container dies with
`PermissionError: ... inventory.yaml`.

**Why `network_mode: host`:** Docker isolates bridge networks from each other, so a
normally-bridged container cannot reach the containerlab management bridge
(172.20.20.0/24). Host networking sidesteps that; it also means port 8110 is bound
directly on the host and the local machine is reachable from inside the container as
`127.0.0.1`.

## Updating to a new version

```bash
tar xzf wirehand-<version>.tar.gz -C ~/docker    # safe: .env and config/inventory.yaml are NOT in the archive (only *.example files)
cd ~/docker/wirehand
UID=$(id -u) GID=$(id -g) docker compose up -d --build
curl -s http://localhost:8110/openapi.json | grep -o '"version": *"[^"]*"'
```

Do **not** unpack the tarball *inside* `~/docker/wirehand` - the archive contains the
`wirehand/` folder as prefix and you would end up with a nested copy while building
the old code. Unpack in the parent (`~/docker`).

Open WebUI caches the tool description: after an update, toggle the tool-server entry
off/on (or re-add it) so the model sees the new tool descriptions.

## Configuration

### `.env` (next to docker-compose.yml, chmod 600)

```bash
WIREHAND_API_KEY=change-me-long-random-string
WIREHAND_CLAB_DIR=/home/stephan/containerlabs   # host path with your labs
UBUNTU2_USER=netops                           # credentials referenced from inventory.yaml
UBUNTU2_PASS=...
```

Dotenv rules that bite in practice: no spaces around `=`, no `export`, and everything
after `#` counts as a comment - a password containing `#` gets silently cut. Avoid
`$ # " ' \ `` ` `` in values (the same file is used by Compose for interpolation). If the
container reports `env var 'X' which is not set` although you set it, check with
`docker compose config | grep X` what actually arrives, and remember that `.env` changes
need `docker compose up -d` (a plain `restart` does not reread it).

### `config/inventory.yaml`

```yaml
devices:                       # manual devices; {} if you only use containerlab
  ubuntu2:
    host: 127.0.0.1            # the clab host itself, via host networking
    device_type: linux
    username: env:UBUNTU2_USER # env:VAR -> resolved from the container environment
    password: env:UBUNTU2_PASS
    access: ro                 # ro (default) | rw; start ro, lift deliberately
    description: containerlab host
    tags: [host, linux]

containerlab:
  default_access: rw           # labs are disposable; set ro for the cautious default
  long_names: false            # true -> full names like clab-xrd-test-xrd1
  kinds:                       # per-kind overrides of driver or access
    huawei_vrp: { device_type: huawei_vrpv8 }   # NE40E/CE = VRP8; 'huawei' for VRP5 images
  credentials:                 # for kinds whose generated inventory has no password
    fortinet_fortigate: { username: admin, password: env:FGT_PASS }
```

`device_type` is the Netmiko driver: `linux`, `cisco_ios`, `cisco_xe`, `cisco_xr`,
`cisco_nxos`, `huawei`, `huawei_vrpv8`, `fortinet`, `arista_eos`, `juniper_junos`.

Missing `env:` variables fail the whole inventory load at startup - deliberately
(fail-fast beats a device with half-empty credentials). Remove dead references.

### Access levels and Linux accounts

`access: ro` allows `get_facts`/`run_read` only; `rw` additionally allows
propose/confirm/rollback (config **and** exec mode). Recommended path: everything `ro`,
lift devices to `rw` one at a time, first write test on a disposable lab node.

For Linux devices, the SSH account is what the LLM gets: the read path can `cat`
anything that account can read. Use a dedicated low-privilege user rather than your
personal account, and grant targeted passwordless sudo only for commands you expect in
changes. The read path never escalates (`sudo` is refused there).

## Connecting the front-ends

### Open WebUI

Admin -> Settings -> **External Tools** -> add: URL `http://<clab-host>:8110`, Auth
Bearer, key = `WIREHAND_API_KEY`. Note that Open WebUI's *browser* talks to the tool
server directly: the URL must be reachable from your workstation, and CORS is handled by
the tool (`WIREHAND_CORS_ORIGINS`, default `*`). The known Save-button issue on LAN-HTTP
applies (workaround: SSH tunnel to localhost:3000).

Per chat: enable the tool and use **Native** function calling. Recommended: a dedicated
"wirehand" model preset (num_ctx 32k, `ENABLE_KB_EXEC` off for that model) with this
system prompt:

> You operate network devices and Linux servers only through the wirehand tools. Use
> device names exactly as shown by list_devices. Start broad analyses with get_facts;
> for specific questions call run_read directly, and for long outputs always pass a
> filter regex. Never claim a command ran unless you called a tool; base all findings
> on tool output only. Changes: call propose_change, show the user the preview and the
> code, then stop and wait for explicit approval; only then call confirm_change with
> that exact code. Maintenance commands (reset, clear, process restarts) go through
> propose_change with mode='exec', never run_read. If unsure about platform CLI syntax,
> verify it via web search before proposing a change.

### Onyx

Admin -> **Actions** -> Add -> OpenAPI schema: fetch `http://<clab-host>:8110/openapi.json`,
auth header `Authorization: Bearer <key>`, attach the action to an Agent. If Onyx runs in
Docker on another host, its `api_server` and `background` containers need
`extra_hosts: ["host.docker.internal:host-gateway"]` to resolve host-mapped services.

## Where devices come from

Two sources, merged at runtime; both can be used at the same time:

1. **containerlab auto-discovery.** Point `WIREHAND_CLAB_DIR` at the folder that holds your
   containerlab topologies (e.g. `/home/stephan/containerlabs`). For every *deployed* lab,
   containerlab generates a `clab-<lab>/ansible-inventory.yml` with node kind, management
   IP and default credentials - wirehand scans these recursively. Nodes appear under
   the name `<lab>-<node>` (e.g. `xrd-test-xrd1`) and disappear automatically when the lab
   is destroyed, because destroying a lab removes the generated folder.
2. **Manual entries** in `config/inventory.yaml` under `devices:` - for anything that is
   not a lab node (the containerlab host itself, physical routers, servers). A manual
   entry with the same name as a discovered node overrides it, which is also the way to
   pin different credentials or a different access level for a single lab node.

Both sources are re-checked every 30 s (`WIREHAND_CLAB_RESCAN`) using file modification
times, so deploying/destroying a lab or editing `inventory.yaml` shows up without a
restart. To force an immediate reload, ask the model to call `list_devices` with
`refresh=true`. Only `.env` changes require a container recreate (`docker compose up -d`),
because environment variables are fixed when a container starts - that is a Docker
property, not a tool limitation.

The file `config/inventory.yaml` is **never written by the tool** - it is your file, and
it is mounted read-only into the container.

## containerlab kind mapping (built in)

| clab kind | Netmiko driver | default creds |
|---|---|---|
| cisco_xrd, cisco_xrv9k | cisco_xr | clab / clab@123 |
| cisco_iol | cisco_ios | admin / admin |
| cisco_csr1000v, c8000v, cat9kv | cisco_xe | - |
| cisco_n9kv | cisco_nxos | - |
| huawei_vrp | huawei_vrpv8 | admin / admin |
| fortinet_fortigate | fortinet | admin / admin |
| arista_ceos / veos | arista_eos | admin / admin |
| juniper_vjunos*, vmx, vsrx | juniper_junos | - |
| linux, sonic-vs, generic_vm | linux | clab / clab@123 |

Precedence: `containerlab.credentials` in inventory.yaml > generated
`ansible_user`/`ansible_password` > the built-in defaults above. Unmapped kinds are
skipped with a log line (`docker logs wirehand`).

## Reachability check and overlapping lab subnets

`list_devices(check=true)` opens a TCP connection to each device's SSH port (2 s timeout,
`WIREHAND_CHECK_TIMEOUT`, all devices in parallel). It verifies the network path and a
listening sshd - **not** credentials: a device can show `up` and still fail the login.

containerlab puts every lab on the same default management subnet (`172.20.20.0/24`)
unless told otherwise, so two labs can legitimately contain the same management IP - and
stale `clab-*` folders from labs destroyed without `--cleanup` keep such entries alive in
discovery. A TCP probe cannot tell which lab answered. wirehand therefore marks every
device whose management IP is shared with another device as `up?` and appends a warning
naming the colliding entries.

To get unambiguous results, give each lab its own subnet in its `.clab.yml`:

```yaml
mgmt:
  network: clab-<labname>
  ipv4-subnet: 172.20.30.0/24      # one distinct /24 per lab
```

and destroy unused labs with `--cleanup` so their generated folders disappear.

## Platform behavior for changes

| Family | Change path | Rollback |
|---|---|---|
| cisco_xr, huawei_vrpv8, junos | config-set + commit | native (`rollback configuration last 1`) |
| cisco_ios/xe/nxos, arista_eos, huawei (VRP5) | config-set + save | snapshot only -> corrective change |
| fortinet | config-set (persists immediately) | snapshot only |
| linux | commands run sequentially as the login user | none - include backups in the change (`sudo cp x x.bak`) |

`mode='exec'` runs in user/exec view on all platforms, commits nothing, and states that
in its response.

## Audit log & snapshots

Everything lives in the named volume `wirehand_data` (`/app/data` inside the container):

```
/app/data/audit.jsonl                    # append-only audit trail
/app/data/snapshots/<device>/<ts>.txt    # pre-change config snapshots (last 20 per device)
```

**From the chat:** ask "what was changed on xrd-test-xrd1 today?" - the model calls
`get_audit_log`.

**From the shell:**

```bash
# follow the audit log live
docker exec wirehand tail -f /app/data/audit.jsonl

# pretty-print the last 20 entries (jq on the host)
docker exec wirehand tail -20 /app/data/audit.jsonl | jq .

# all changes on one device
docker exec wirehand cat /app/data/audit.jsonl \
  | jq 'select(.device=="xrd-test-xrd1" and (.event|startswith("confirm")))'

# list and read snapshots
docker exec wirehand ls -l /app/data/snapshots/xrd-test-xrd1/
docker exec wirehand cat /app/data/snapshots/xrd-test-xrd1/20260823-141502.txt

# copy everything out (backup)
docker cp wirehand:/app/data ./wirehand-data-backup
```

Each audit entry holds timestamp, event (`run_read`, `propose_change`, `confirm_change`,
`rollback`, ...), device, the commands/lines involved and, for changes, the confirmation
code and snapshot path - never credentials. The file is plain JSONL: one JSON object per
line, greppable and jq-able.

**Operational endpoints** (curl, not exposed as LLM tools): `GET /health` (no auth;
status, device count, pending changes) and `GET /pending` (Bearer auth; currently staged
changes with age).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `PermissionError ... inventory.yaml` at startup | container uid != owner of the 600-file | rebuild with `UID=$(id -u) GID=$(id -g)`; once: `docker volume rm wirehand_wirehand_data` |
| `env var 'X' which is not set` | dotenv syntax (spaces, `#` in value) or `.env` edited without recreate | fix syntax; `docker compose up -d` (not `restart`) |
| Browser: "Failed to fetch", log: `OPTIONS ... 400/405` | CORS preflight rejected | check `WIREHAND_CORS_ORIGINS`; tool URL must be reachable from the *browser* |
| Open WebUI shows an old version | cached OpenAPI spec | toggle the tool-server entry off/on or re-add it |
| Model runs `reset`/`clear` into a 403 | maintenance command on the read path | that is by design - `propose_change(mode='exec')` is the way |
| Device missing from `list_devices` | lab not deployed (no `clab-*` dir), unmapped kind, or stale scan | deploy the lab; check `docker logs`; `list_devices(refresh=true)` |
| Ubuntu2/local host unreachable | sshd not listening on the address used | with host networking use `host: 127.0.0.1` |
| Change fails with prompt/timeout errors | wrong Netmiko driver for the platform | check `kinds:` mapping (VRP5 vs VRP8 is the classic) |
| `AUTHENTICATION FAILED` (HTTP 401) | stored credentials rejected by the device | fix them server-side: `config/inventory.yaml` (manual device) or `containerlab.credentials` for that kind, then `docker compose up -d`. The tool never retries auth failures - they are terminal by design. |

## Tests

```bash
pip install -r requirements.txt pytest httpx
python -m pytest tests/                  # safety blocklist + containerlab discovery
PYTHONPATH=. python tests/test_api.py    # full propose/confirm/rollback flow against a fake pool
```

`tests/toolcall_suite.md` is a 16-prompt regression set for judging how reliably a
given LLM drives these tools - run it after every model or prompt change.

## Design rules (why it looks the way it does)

Some of wirehand's choices may look unusual or even old-fashioned. They are deliberate.
This section explains them without assuming background in AI or operations tooling.

### Who is actually using the tools

wirehand is not operated by a person clicking buttons. It is operated by a *language
model* (an LLM - the AI behind a chat interface like Open WebUI). When you ask in the chat
"is OSPF up on router r1?", the model decides on its own which wirehand *tool* to call
(a tool is simply a function the model is allowed to use, such as `run_read`), fills in
the arguments, reads the result, and writes you an answer.

The expected model is often a **small model running locally** - on your own hardware,
so no device data leaves your network. Small models are useful but make mistakes large
cloud models rarely make. Each rule below exists because one of these mistakes was
observed in practice.

### The rules, and the problem each one solves

**1. Few tools, each with a clear job.**
With twenty similar-sounding tools, a small model regularly picks the wrong one. wirehand
has seven, and their names say what they do (`list_devices`, `run_read`,
`propose_change`, ...). Fewer choices mean fewer wrong choices.

**2. Simple arguments - mostly plain text.**
Tools take a few simple values: a device name, a block of commands as text, a yes/no
flag. There are no nested structures (lists inside objects inside lists). Small models
often drop or garble fields in complex structures, and a missing field means a failed
call. Example: `commands` is one string with one command per line, not a list of
command objects.

**3. Answers are plain text, not JSON.**
JSON is a structured data format that programs love and small models struggle with -
they misread nesting or lose track of which value belongs where. Device output is text
anyway (`show ip route` prints text), so wirehand passes it on as text, the same way a
human would see it in a terminal.

**4. Worked examples inside every tool description.**
The model learns how to use a tool only from its description. A sentence like "config
lines to apply" leaves room for guessing; a concrete example such as
`propose_change(device='r1', config='interface Loopback10 ...', reason='add test loopback')`
does not. Models copy patterns very reliably, so the descriptions show the pattern.

**5. An output limit with a visible "truncated" note.**
A model can only keep a limited amount of text in view at once (its *context window*,
a kind of short-term memory). A full router configuration can be larger than that. If
the text simply got cut off silently, the model would reason about half a config
without knowing it - or forget your original question. wirehand therefore caps each
answer (about 80,000 characters, `WIREHAND_MAX_OUTPUT_CHARS`) and, when it cuts, says
so explicitly and suggests using `filter` to fetch only the relevant lines.

**6. The model cannot pretend.**
A known weakness of LLMs is *hallucination*: confidently inventing an answer, including
fake command output that looks real. wirehand cannot fully prevent that, but it makes it
detectable: every real command goes through a tool call and lands in the audit log, and
the recommended system prompt tells the model to base findings on tool output only. If
the chat claims something ran and the audit log has no entry, it did not run.

**7. Safety is enforced by the server, not by trusting the model.**
Instructions to a model are requests, not guarantees. So the rules that really matter
are enforced in wirehand's own code, where the model cannot talk its way around them:
the model never sees passwords, reading refuses anything that could change a device,
and changes need a code that a human must approve. See "Key properties".

**8. Exactly one server process.**
Web services are often run as several parallel copies (*workers*) for speed. wirehand
deliberately runs a single one. The confirmation codes of changes waiting for approval,
and the open SSH connections to devices, are kept in that process's memory. With two
copies, a change could be proposed in one and confirmed in the other, which would not
know the code - approval would fail at random. For a tool used by a few people through
a chat, one process is fast enough.

### The short version

Every rule trades a little elegance for reliability: keep the model's choices few, its
inputs simple, its outputs readable and bounded - and never rely on the model for
anything that must not go wrong.
