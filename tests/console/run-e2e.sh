#!/usr/bin/env bash
# Console end-to-end: riskguard (shadow) -> instant mock New API, mock Qwen3Guard. Drives mixed
# traffic, then checks login, summary counts, security headers, restart persistence and that no
# key/token/prompt text reaches the console API or its state file. KEEP=1 leaves it running on
# 127.0.0.1:14101/console/ for a visual check (token printed to stderr).
set -euo pipefail
cd "$(dirname "$0")/../.."
w=$(mktemp -d); PASS=0; FAIL=0
ok()  { echo "PASS $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL $*"; FAIL=$((FAIL+1)); }
cleanup() { kill ${gpid:-} ${upid:-} ${lpid:-} 2>/dev/null || true; rm -rf "$w"; }
[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT

cat > "$w/up.py" <<'PY'
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = 1 << 16
    def _ok(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n: self.rfile.read(n)
        b = b'{"ok":true}'
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    do_GET = do_POST = _ok
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", 14400), H).serve_forever()
PY
python3 "$w/up.py" & upid=$!
python3 tests/mock/mock_llama.py 18092 & lpid=$!
go build -o "$w/riskguard" ./cmd/riskguard
head -c 48 /dev/urandom > "$w/hmac.key"; echo test-guard-key > "$w/guard.key"
TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))'); printf '%s\n' "$TOKEN" > "$w/console.token"
sed -e "s#127.0.0.1:4100#127.0.0.1:14100#; s#127.0.0.1:4101#127.0.0.1:14101#; s#http://127.0.0.1:4000#http://127.0.0.1:14400#" \
    -e "s#/var/lib/riskguard/spool#$w/spool#; s#http://127.0.0.1:8088#http://127.0.0.1:18092#; s#/etc/riskguard/guard.key#$w/guard.key#" \
    -e "s#/etc/riskguard/policy-v1.yaml#$PWD/config/policy-v1.yaml#; s#/etc/riskguard/hmac.key#$w/hmac.key#" \
    -e "s#/etc/riskguard/console.token#$w/console.token#; s#/var/lib/riskguard/console-stats.json#$w/console-stats.json#" \
    config/example.yaml > "$w/config.yaml"
start() { "$w/riskguard" -config "$w/config.yaml" > "$w/audit.log" 2> "$w/stderr.log" & gpid=$!
  for i in $(seq 1 30); do curl -sf -m 1 http://127.0.0.1:14101/__risk/healthz >/dev/null && return; sleep 0.2; done; bad "guard did not start"; }
start

APIKEY=sk-$(python3 -c 'import secrets;print(secrets.token_hex(20))')
chat() { curl -s -o /dev/null -H "Authorization: Bearer $APIKEY" -H 'Content-Type: application/json' http://127.0.0.1:14100/v1/chat/completions \
  -d "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"$1\"}]}"; }
for i in $(seq 1 40); do chat "secretprompt-$i please refactor this function"; done
for i in 1 2 3; do chat "secretprompt-dup summarise the log"; done           # 1 classification, 2 cache hits
for i in $(seq 1 4); do chat "secretprompt-b$i BLOCKME"; done
for i in $(seq 1 3); do chat "secretprompt-m$i MAYBE"; done
curl -s -o /dev/null -H "Authorization: Bearer $APIKEY" http://127.0.0.1:14100/v1/embeddings -d '{"model":"e","input":"secretprompt-emb"}'
curl -s -o /dev/null -H "Authorization: Bearer $APIKEY" http://127.0.0.1:14100/v1/images/generations -d '{"prompt":"secretprompt-img"}'
curl -s -o /dev/null -H "Authorization: Bearer $APIKEY" -H 'Content-Type: application/json' http://127.0.0.1:14100/v1/chat/completions -d 'not json'
for i in 1 2 3; do curl -s -o /dev/null http://127.0.0.1:14100/api/status; done
sleep 1

C=http://127.0.0.1:14101/console
code=$(curl -s -o /dev/null -w '%{http_code}' $C/api/summary); [ "$code" = 401 ] && ok "summary without session -> 401" || bad "no session $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST $C/api/login -d '{"token":"nope"}'); [ "$code" = 401 ] && ok "wrong token -> 401" || bad "wrong token $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$w/jar" -X POST $C/api/login -d "{\"token\":\"$TOKEN\"}"); [ "$code" = 200 ] && ok "login -> 200" || bad "login $code"
grep -q 'HttpOnly' "$w/jar" && ok "session cookie HttpOnly" || bad "cookie not HttpOnly"
curl -s -b "$w/jar" "$C/api/summary?range=1h" > "$w/sum.json"
curl -s -b "$w/jar" "$C/api/events" > "$w/ev.json"
python3 - "$w/sum.json" "$w/ev.json" <<'PY' && ok "summary counts match driven traffic" || bad "summary counts"
import json, sys
s = json.load(open(sys.argv[1])); t = s["stats"]["totals"]; ev = json.load(open(sys.argv[2]))["events"]
exp = dict(req=56, guarded=53, new_turns=48, cache_hits=2, would_block=9)  # 7 review + images gap + non-JSON
got = {k: t.get(k, 0) for k in exp}
d = t["decisions"]
assert got == exp, (got, exp)
assert d == {"allow": 44, "review": 7, "unsupported": 2}, d   # unparseable/no-input forward vs reject per policy
assert t["labels"] == {"Safe": 43, "Unsafe": 4, "Controversial": 3}, t["labels"]
assert t["categories"]["Violent"] == 4 and s["mode"] == "shadow" and len(ev) == 53, (t, len(ev))
PY
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stats"]["totals"])' "$w/sum.json" >&2
hdr=$(curl -sI $C/); echo "$hdr" | grep -qi "content-security-policy: default-src 'none'" && echo "$hdr" | grep -qi 'x-frame-options: DENY' \
  && ok "static security headers" || bad "static headers"
kill "$gpid"; wait "$gpid" 2>/dev/null || true
[ "$(stat -c %a "$w/console-stats.json")" = 600 ] && ok "state file 0600" || bad "state file mode"
if grep -qE "secretprompt|$APIKEY|$TOKEN" "$w/console-stats.json" "$w/sum.json" "$w/ev.json"; then bad "prompt/key/token leaked"; else ok "no prompt/key/token in API or state"; fi
start
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$w/jar" $C/api/summary); [ "$code" = 401 ] && ok "sessions do not survive restart" || bad "session after restart $code"
curl -s -c "$w/jar" -o /dev/null -X POST $C/api/login -d "{\"token\":\"$TOKEN\"}"
n=$(curl -s -b "$w/jar" "$C/api/summary?range=1h" | python3 -c 'import json,sys;print(json.load(sys.stdin)["stats"]["totals"]["req"])')
[ "$n" = 56 ] && ok "stats persisted across restart" || bad "stats after restart $n"
echo "SUMMARY pass=$PASS fail=$FAIL"
if [ "${KEEP:-0}" = 1 ]; then echo "console: http://127.0.0.1:14101/console/  token: $TOKEN  workdir: $w  pids: $gpid $upid $lpid" >&2; fi
[ "$FAIL" = 0 ]
