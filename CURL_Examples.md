# Testing wirehand with curl (no LLM involved)

Every tool is a plain HTTP endpoint. These calls are exactly what the model sends, so
they are the fastest way to tell "the tool is broken" from "the model used it wrong".

## Setup

```bash
cd ~/docker/wirehand
export WH=http://localhost:8110                       # from another host: http://<clab-host>:8110
export KEY=$(grep WIREHAND_API_KEY .env | cut -d= -f2)
export AUTH="Authorization: Bearer $KEY"
```

`-s` silences the progress meter, `-i` shows response headers (useful for status codes),
`--get --data-urlencode` handles spaces and regex characters in query parameters so you
do not have to escape them by hand.

## 0. health - is the service alive? (no auth)

```bash
curl -s $WH/health
# {"status":"ok","devices":7,"pending_changes":0}
```

## 1. list_devices - which devices exist?

```bash
curl -s -H "$AUTH" $WH/list_devices

# force a re-read of inventory.yaml + containerlab rescan
curl -s -H "$AUTH" "$WH/list_devices?refresh=true"

# with reachability probe (STATE column: up / DOWN / up?)
curl -s -H "$AUTH" "$WH/list_devices?check=true"
```

## 2. get_facts - one-call overview of a device

```bash
curl -s -H "$AUTH" --get --data-urlencode "device=xrd-test-xrd1" $WH/get_facts
```

## 3. run_read - read-only commands

```bash
# single command
curl -s -H "$AUTH" --get \
  --data-urlencode "device=xrd-test-xrd1" \
  --data-urlencode "commands=show lldp neighbors" \
  $WH/run_read

# several commands (newline or ';' separated)
curl -s -H "$AUTH" --get \
  --data-urlencode "device=ubuntu2" \
  --data-urlencode "commands=df -h; free -m; uptime" \
  $WH/run_read

# several devices at once
curl -s -H "$AUTH" --get \
  --data-urlencode "device=xrd-test-xrd1,xrd-test-xrd2" \
  --data-urlencode "commands=show version" \
  $WH/run_read

# long output + server-side regex filter with context lines
curl -s -H "$AUTH" --get \
  --data-urlencode "device=xrd-test-xrd1" \
  --data-urlencode "commands=show running-config" \
  --data-urlencode "filter=interface|description" \
  --data-urlencode "context=2" \
  $WH/run_read

# expected refusal (write command on the read path) -> HTTP 403
curl -s -i -H "$AUTH" --get \
  --data-urlencode "device=ubuntu2" \
  --data-urlencode "commands=systemctl restart nginx" \
  $WH/run_read | head -1

# Linux devices are allow-list only: these are all HTTP 403, even though no
# blocklist entry names them
for c in "touch /tmp/x" "cp /etc/passwd /tmp/x" "find /tmp -name x -delete" \
         "awk 'BEGIN{system(\"id\")}'" "wget http://example.com" "ethtool -s eth0 speed 100"; do
  printf '%-40s -> ' "$c"
  curl -s -o /dev/null -w '%{http_code}\n' -H "$AUTH" --get \
    --data-urlencode "device=ubuntu2" --data-urlencode "commands=$c" $WH/run_read
done

# network CLIs keep working (vendor read verbs are not enumerable) ...
curl -s -H "$AUTH" --get --data-urlencode "device=xrd-test-xrd1" \
  --data-urlencode "commands=ping 8.8.8.8 count 5" $WH/run_read

# ... but cannot escape the read-only exec view -> 403
curl -s -i -H "$AUTH" --get --data-urlencode "device=xrd-test-xrd1" \
  --data-urlencode "commands=show running-config | file /tmp/x" $WH/run_read | head -1
```

## 4. propose_change - stage a change (applies nothing)

POST with a JSON body. `\n` inside the JSON string separates the configuration lines.

```bash
# Cisco IOS-XR: config lines only, no 'configure'/'commit'
curl -s -H "$AUTH" -H "Content-Type: application/json" -X POST $WH/propose_change -d '{
  "device": "xrd-test-xrd1",
  "config": "interface Loopback10\n description wirehand test\n ipv4 address 10.99.0.10/32",
  "reason": "curl smoke test"
}'

# FortiGate: complete section blocks including config/end
curl -s -H "$AUTH" -H "Content-Type: application/json" -X POST $WH/propose_change -d '{
  "device": "fg-rr11-1",
  "config": "config system global\nset lldp-reception enable\nset lldp-transmission enable\nend",
  "reason": "enable LLDP"
}'

# Huawei maintenance command (user/exec view) -> mode=exec
curl -s -H "$AUTH" -H "Content-Type: application/json" -X POST $WH/propose_change -d '{
  "device": "hui-r11",
  "config": "reset ospf process 1",
  "mode": "exec",
  "reason": "restart OSPF"
}'

# Linux
curl -s -H "$AUTH" -H "Content-Type: application/json" -X POST $WH/propose_change -d '{
  "device": "ubuntu2",
  "config": "sudo cp /etc/motd /etc/motd.bak\necho test | sudo tee -a /etc/motd",
  "reason": "motd test"
}'
```

The response ends with the 6-character code, e.g.
`STAGED, NOT APPLIED. Confirmation code: 7F80AE`.

## 5. confirm_change - apply the staged change

```bash
curl -s -H "$AUTH" -X POST "$WH/confirm_change?code=7F80AE"
```

Propose and confirm in one go (grabs the code automatically - convenient for smoke tests,
never do this in production, it bypasses the human approval the code exists for):

```bash
CODE=$(curl -s -H "$AUTH" -H "Content-Type: application/json" -X POST $WH/propose_change \
  -d '{"device":"xrd-test-xrd1","config":"interface Loopback10\n description test","reason":"smoke"}' \
  | sed -n 's/.*Confirmation code: \([A-F0-9]\{6\}\).*/\1/p')
echo "code=$CODE"
curl -s -H "$AUTH" -X POST "$WH/confirm_change?code=$CODE"
```

Error cases worth testing once:

```bash
# unknown/expired code -> 404
curl -s -i -H "$AUTH" -X POST "$WH/confirm_change?code=ZZZZZZ" | head -1

# read-only device -> 403
curl -s -i -H "$AUTH" -H "Content-Type: application/json" -X POST $WH/propose_change \
  -d '{"device":"<a ro device>","config":"interface Loopback11"}' | head -1
```

## 6. rollback_change - stage an undo of the last change

Like propose_change, this applies nothing: on IOS-XR / VRPv8 / Junos it stages the native
rollback and returns a code, which confirm_change then applies.

```bash
curl -s -H "$AUTH" -X POST "$WH/rollback_change?device=xrd-test-xrd1"
# STAGED, NOT APPLIED. Confirmation code: 3C19B4 ...

curl -s -H "$AUTH" -X POST "$WH/confirm_change?code=3C19B4"
# ROLLED BACK on xrd-test-xrd1 (code 3C19B4). ...
```

Platforms without a native rollback (IOS/NX-OS/EOS/VRP5/FortiGate/Linux) touch nothing and
return the pre-change snapshot for a manual corrective change - no code involved.

## 7. get_audit_log - what happened

```bash
curl -s -H "$AUTH" $WH/get_audit_log

curl -s -H "$AUTH" --get \
  --data-urlencode "device=xrd-test-xrd1" \
  --data-urlencode "n=50" \
  $WH/get_audit_log
```

## 8. pending - currently staged changes (operational, not an LLM tool)

```bash
curl -s -H "$AUTH" $WH/pending | jq .
```

## Auth and spec

```bash
# missing/wrong key -> 401
curl -s -i $WH/list_devices | head -1

# the OpenAPI spec the front-ends consume; also shows the running version
curl -s $WH/openapi.json | jq '.info.version, [.paths | keys[]]'
```

## A 30-second smoke test after every update

```bash
curl -s $WH/health &&
curl -s $WH/openapi.json | grep -o '"version": *"[^"]*"' &&
curl -s -H "$AUTH" "$WH/list_devices?check=true" &&
curl -s -H "$AUTH" --get --data-urlencode "device=<a reachable device>" $WH/get_facts | head -5
```

If these four succeed, wirehand itself is healthy - anything that still fails in the chat
is a front-end, model, or prompt problem.

