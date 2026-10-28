#!/usr/bin/env bash
# Docker e2e: builds deployments/docker (Dockerfile + compose.yaml) and runs it as the non-root
# image user against a mock classifier (host) and a hit-counting mock upstream. Proves the
# container keeps the systemd unit's guarantees: loopback-only listeners, enforce decisions,
# denied requests never forwarded, block-reply switch persisting across restarts, graceful stop.
set -euo pipefail
cd "$(dirname "$0")/../.."
w=$(mktemp -d); PASS=0; FAIL=0
P=rgt-docker; G=127.0.0.1:14200; A=127.0.0.1:14201
ok()  { echo "PASS $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL $*"; FAIL=$((FAIL+1)); }
dc() { RG_ETC="$w/etc" RG_STATE="$w/state" docker compose -p "$P" -f deployments/docker/compose.yaml "$@"; }
cleanup() {
  dc down -t 40 >/dev/null 2>&1 || true
  [ -n "${lpid:-}" ] && kill "$lpid" 2>/dev/null
  docker rm -f rgt-docker-up >/dev/null 2>&1; rm -rf "$w"
}
trap cleanup EXIT
for p in 14200 14201 14482 18089; do
  if ss -ltn | grep -q ":$p "; then echo "port $p in use"; exit 1; fi
done

docker run -d --name rgt-docker-up -p 127.0.0.1:14482:8080 -v "$PWD/tests/mock/mock_openai.py:/m.py:ro" \
  python:3.12-alpine python3 /m.py >/dev/null
python3 tests/mock/mock_llama.py 18089 & lpid=$!

mkdir -p "$w/etc" "$w/state"
head -c 48 /dev/urandom > "$w/etc/hmac.key"; echo test-guard-key > "$w/etc/guard.key"
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'); echo "$TOKEN" > "$w/etc/console.token"
sed -e 's#127.0.0.1:4100#'$G'#; s#127.0.0.1:4101#'$A'#; s#http://127.0.0.1:4000#http://127.0.0.1:14482#' \
    -e 's#^mode: .*#mode: "enforce"#; s#http://127.0.0.1:8088#http://127.0.0.1:18089#' config/example.yaml > "$w/etc/config.yaml"
{ sed 's/^version: .*/version: "policy-v1-docker-e2e"/; s/^  "Violent": review .*/  "Violent": deny/' config/policy-v1.yaml
  printf '  block_replies:\n    - "⠀⣀⣤ docker-e2e"\n'; } > "$w/etc/policy-v1.yaml"
chmod 0600 "$w"/etc/*; chown -R 65532:65532 "$w/etc" "$w/state"; chmod 0700 "$w/state"

dc up -d --build --quiet-pull >/dev/null 2>&1 || { bad "compose up"; dc logs; exit 1; }
for i in $(seq 1 30); do curl -sf -m 1 "http://$A/__risk/readyz" >/dev/null && break; sleep 0.5; done
curl -s "http://$A/__risk/readyz" | grep -q '"mode":"enforce"' && ok "container ready in enforce" || bad "readyz: $(dc logs --tail 5)"
cid=$(dc ps -q riskguard)
[ "$(docker inspect -f '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.NetworkMode}}' "$cid")" = "65532:65532 true [ALL] host" ] \
  && ok "non-root, read-only rootfs, no capabilities, host network" || bad "hardening: $(docker inspect -f '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}' "$cid")"
ss -ltn | grep -E ':1420[01] ' | grep -vq '127.0.0.1' && bad "listener not loopback-only" || ok "listeners bound to 127.0.0.1 only"

hits() { curl -s http://127.0.0.1:14482/hits | python3 -c 'import json,sys;print(json.load(sys.stdin)["hits"])'; }
chat() { curl -s -m 30 -o "$w/out" -w '%{http_code}' -H 'Authorization: Bearer sk-test' -H 'Content-Type: application/json' \
  "http://$G/v1/chat/completions" -d "{\"model\":\"ok\",\"messages\":[{\"role\":\"user\",\"content\":\"$1\"}]}"; }
h0=$(hits)
c=$(chat "write a unit test"); [ "$c" = 200 ] && [ "$(hits)" = $((h0+1)) ] && ok "allow -> 200 via upstream" || bad "allow $c"
c=$(chat "please BLOCKME"); [ "$c" = 403 ] && [ "$(hits)" = $((h0+1)) ] && ok "deny -> 403, not forwarded" || bad "deny $c"
c=$(chat "MAYBE"); [ "$c" = 422 ] && ok "review -> 422 while block reply is off" || bad "review $c"

O="Origin: http://$A"; J='Content-Type: application/json'
curl -s -c "$w/jar" -H "$O" -H "$J" "http://$A/console/api/login" -d "{\"token\":\"$TOKEN\"}" >/dev/null
c=$(curl -s -o /dev/null -w '%{http_code}' -b "$w/jar" -H "$O" -H "$J" "http://$A/console/api/block-reply" -d '{"enabled":true}')
[ "$c" = 200 ] && ok "console switch enabled" || bad "console switch $c"
c=$(chat "BLOCKME reply"); [ "$c" = 200 ] && grep -q 'docker-e2e' "$w/out" && [ "$(hits)" = $((h0+1)) ] \
  && ok "deny -> 200 block reply, not forwarded" || bad "block reply $c $(cat "$w/out")"

dc restart -t 40 >/dev/null 2>&1
for i in $(seq 1 30); do curl -sf -m 1 "http://$A/__risk/readyz" >/dev/null && break; sleep 0.5; done
c=$(chat "BLOCKME after restart"); [ "$c" = 200 ] && grep -q 'docker-e2e' "$w/out" && ok "switch persisted in state volume across restart" || bad "after restart $c"

start=$(date +%s); dc stop -t 40 >/dev/null 2>&1; took=$(( $(date +%s) - start ))
code=$(docker inspect -f '{{.State.ExitCode}}' "$cid")
[ "$code" = 0 ] && [ "$took" -lt 35 ] && ok "graceful stop: exit 0 in ${took}s" || bad "stop exit=$code took=${took}s"
dc logs --no-log-prefix > "$w/logs" 2>&1
n=$(grep -c '"trace_id"' "$w/logs" || true)
if grep -qE "sk-test|BLOCKME|unit test|$TOKEN" "$w/logs"; then bad "container logs leak key or prompt text"; else ok "container logs: $n audit events, no key/prompt text"; fi
echo "SUMMARY pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
