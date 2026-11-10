#!/usr/bin/env bash
# Start the mTLS server and assert: valid client -> 200, no cert -> rejected, attacker -> rejected.
set -uo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-9443}"
URL="https://localhost:${PORT}/"
SERVER_CMD="${SERVER_CMD:-python3 server.py}"
FAIL=0

$SERVER_CMD > server.log 2>&1 &
SERVER_PID=$!
cleanup() { pkill -P "$SERVER_PID" 2>/dev/null; kill "$SERVER_PID" 2>/dev/null; }
trap cleanup EXIT

for _ in $(seq 1 30); do
  if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then break; fi
  sleep 1
done
if ! (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
  echo "❌ Server did not start on port $PORT"; cat server.log; exit 1
fi
echo "Server is listening on $PORT"

pass() { echo "✅ PASS: $1"; }
fail() { echo "❌ FAIL: $1"; FAIL=1; }

code=$(curl -s -o /dev/null -w "%{http_code}" --cacert ca.crt --cert client.crt --key client.key "$URL")
[ "$code" = "200" ] && pass "valid client -> HTTP 200" || fail "valid client expected 200, got $code"

code=$(curl -s -o /dev/null -w "%{http_code}" --cacert ca.crt "$URL"); rc=$?
[ "$rc" -ne 0 ] && [ "$code" = "000" ] && pass "no client cert -> rejected in handshake (curl exit $rc)" \
  || fail "no client cert was not rejected (HTTP $code, curl exit $rc)"

code=$(curl -s -o /dev/null -w "%{http_code}" --cacert ca.crt --cert fake.crt --key fake.key "$URL"); rc=$?
[ "$rc" -ne 0 ] && [ "$code" = "000" ] && pass "attacker cert -> rejected in handshake (curl exit $rc)" \
  || fail "attacker cert was not rejected (HTTP $code, curl exit $rc)"

if [ -f client.py ]; then
  out=$(python3 client.py 2>&1); echo "$out"
  echo "$out" | grep -q "Status Code: 200" && pass "client.py -> 200" || fail "client.py did not get 200"
fi
if [ -f attacker_client.py ]; then
  out=$(python3 attacker_client.py 2>&1); echo "$out"
  if echo "$out" | grep -qi "refused"; then fail "attacker_client.py: server unreachable (invalid test)"
  elif echo "$out" | grep -q "Status Code: 200"; then fail "attacker_client.py got through!"
  else pass "attacker_client.py rejected"; fi
fi

echo "--- server log (tail) ---"; tail -20 server.log
exit $FAIL
