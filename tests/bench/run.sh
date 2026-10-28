#!/usr/bin/env bash
# C08: Guard overhead vs direct with an instant upstream and an instant mock classifier, so the
# numbers isolate spool + extraction + proxying. Real classifier latency comes from W05.
set -euo pipefail
cd "$(dirname "$0")/../.."
w=$(mktemp -d)
cleanup() { kill "${up:-}" "${ll:-}" "${g:-}" 2>/dev/null || true; rm -rf "$w"; }
trap cleanup EXIT
cat > "$w/fast.py" <<'PY'
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = 1 << 16
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        b = b'{"id":"c","choices":[{"message":{"role":"assistant","content":"ok"}}]}'
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", 14000), H).serve_forever()
PY
python3 "$w/fast.py" & up=$!
python3 tests/mock/mock_llama.py 18091 & ll=$!
go build -o "$w/rg" ./cmd/riskguard && go build -o "$w/bench" ./tests/bench
head -c 48 /dev/urandom > "$w/hmac.key"; echo test-guard-key > "$w/guard.key"
sed 's/^version: .*/version: "policy-v1-bench"/' config/policy-v1.yaml > "$w/p.yaml"
run() { # mode concurrency
  sed -e "s#127.0.0.1:4100#127.0.0.1:14100#; s#127.0.0.1:4101#127.0.0.1:14101#; s#http://127.0.0.1:4000#http://127.0.0.1:14000#; s#^mode: .*#mode: \"$1\"#" \
      -e "s#/var/lib/riskguard/spool#$w/spool#; s#http://127.0.0.1:8088#http://127.0.0.1:18091#; s#/etc/riskguard/guard.key#$w/guard.key#; s#/etc/riskguard/policy-v1.yaml#$w/p.yaml#; s#/etc/riskguard/hmac.key#$w/hmac.key#" \
      -e "s#_per_minute: 120#_per_minute: 100000#g" -e '/^console:/,$d' config/example.yaml > "$w/c.yaml"
  "$w/rg" -config "$w/c.yaml" > /dev/null 2>&1 & g=$!; sleep 1
  ( peak=0; while kill -0 $g 2>/dev/null; do r=$(awk '/VmRSS/{print $2}' /proc/$g/status 2>/dev/null || echo 0); [ "${r:-0}" -gt "$peak" ] && peak=$r && echo "$peak" > "$w/peak"; sleep 0.1; done ) &
  echo "== mode=$1 concurrency=$2 body=200KB"
  "$w/bench" -direct http://127.0.0.1:14000 -guard http://127.0.0.1:14100 -n 2000 -c "$2" -body-kb 200
  echo "guard peak RSS $(cat "$w/peak") KiB; spool files left $(ls "$w/spool" | wc -l)"
  kill $g; wait $g 2>/dev/null || true; g=
}
run shadow 16
run enforce 2
run enforce 16
