#!/usr/bin/env bash
# Start the lab, prove each security control works (and fails closed), then stop it.
set -uo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
C="$LAB/certs"
RUN="$LAB/run"

"$LAB/scripts/start_lab.sh" || exit 1
trap '"$LAB/scripts/stop_lab.sh" >/dev/null' EXIT
set -a; . "$RUN/secrets.env"; set +a

EDGE="https://localhost:8443"
ORDERS="https://localhost:9101"
PAYMENTS="https://localhost:9102"
PSP="https://localhost:9103"
FAILS=0

pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAILS=$((FAILS + 1)); }

# req <curl args...>  ->  sets CODE and BODY
req() {
  local out
  out=$(curl -s -o - -w $'\n%{http_code}' --max-time 10 "$@")
  CODE="${out##*$'\n'}"
  BODY="${out%$'\n'*}"
}
expect() { # name expected_code [body_substring]
  if [ "$CODE" = "$2" ] && { [ -z "${3:-}" ] || grep -q -- "$3" <<<"$BODY"; }; then
    pass "$1  →  $CODE"
  else
    fail "$1  →  expected $2${3:+ containing '$3'}, got $CODE: $BODY"
  fi
}
# Rejected by mTLS: handshake aborted (000) or nginx's 400 "SSL certificate" page.
# Either way the request never reaches the application.
expect_tls_reject() { # name
  if [ "$CODE" = "000" ] || { [ "$CODE" = "400" ] && grep -qi "ssl certificate" <<<"$BODY"; }; then
    pass "$1  →  rejected by mTLS ($CODE)"
  else
    fail "$1  →  NOT rejected by mTLS, got $CODE: $BODY"
  fi
}

JSON=(-H "Content-Type: application/json")
CA=(--cacert "$C/internal-ca.crt")
PSP_CA=(--cacert "$C/psp-ca.crt")
as() { echo --cert "$C/$1.crt" --key "$C/$1.key"; }

echo
echo "1. Customer → edge (public TLS)"
req "${CA[@]}" "${JSON[@]}" -d '{"item":"sneakers","amount_cents":8999,"payment_token":"tok_visa"}' "$EDGE/api/checkout"
expect "Checkout with tokenized card" 200 '"succeeded"'
req "${CA[@]}" "${JSON[@]}" -d '{"item":"sneakers","amount_cents":8999,"payment_token":"tok_declined"}' "$EDGE/api/checkout"
expect "Checkout with declined card" 402
req "${CA[@]}" "${JSON[@]}" -d '{"item":"sneakers","amount_cents":8999,"payment_token":"tok_visa","card":"4242 4242 4242 4242"}' "$EDGE/api/checkout"
expect "Checkout containing a raw card number" 400 "Tokenize"
req "$EDGE/api/checkout" -X POST --cacert "$C/psp-ca.crt"
[ "$CODE" = "000" ] && pass "Client that doesn't trust the edge cert can't connect" \
                    || fail "Untrusted edge cert accepted (got $CODE)"

echo
echo "2. Service-to-service mTLS (internal CA)"
req "${CA[@]}" "$ORDERS/api/health"
expect_tls_reject "Orders sidecar, no client cert"
req "${CA[@]}" $(as attacker) "${JSON[@]}" -d '{}' "$PAYMENTS/charge"
expect_tls_reject "Payments, self-signed attacker cert claiming CN=orders"
req "${CA[@]}" $(as merchant-payments) "$ORDERS/api/health"
expect_tls_reject "Orders, cert from the wrong CA (PSP CA)"

echo
echo "3. Authorization: valid cert, wrong identity"
req "${CA[@]}" $(as edge) "$ORDERS/api/health"
expect "edge → orders (allowed)" 200
req "${CA[@]}" $(as catalog) "${JSON[@]}" -d '{"order_id":"x","amount_cents":1,"payment_token":"tok_visa"}' "$PAYMENTS/charge"
expect "catalog → payments /charge (not allowed)" 403
req "${CA[@]}" $(as edge) "${JSON[@]}" -d '{"order_id":"x","amount_cents":1,"payment_token":"tok_visa"}' "$PAYMENTS/charge"
expect "edge → payments /charge (not allowed, edge may only deliver webhooks)" 403
req "${CA[@]}" $(as catalog) "$ORDERS/api/health"
expect "catalog → orders (not allowed)" 403

echo
echo "4. Payments → payment provider (separate trust domain + API key)"
req "${PSP_CA[@]}" $(as orders) "${JSON[@]}" -d '{"amount_cents":1,"payment_token":"tok_visa"}' "$PSP/v1/charges"
expect_tls_reject "PSP, our internal cert (not issued by the PSP)"
req "${PSP_CA[@]}" $(as merchant-payments) "${JSON[@]}" -d '{"amount_cents":1,"payment_token":"tok_visa"}' "$PSP/v1/charges"
expect "PSP, merchant cert without API key" 401
req "${PSP_CA[@]}" $(as merchant-payments) "${JSON[@]}" -H "Authorization: Bearer $PSP_API_KEY" \
  -d '{"amount_cents":1,"payment_token":"tok_visa"}' "$PSP/v1/charges"
expect "PSP, merchant cert + API key" 200 '"succeeded"'

echo
echo "5. Webhooks from the provider (HMAC-signed)"
sign() { # timestamp body
  printf '%s.%s' "$1" "$2" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" -r | cut -d' ' -f1
}
now=$(date +%s)
event='{"id":"evt_1001","type":"charge.succeeded","data":{"amount_cents":8999}}'
sig="t=$now,v1=$(sign "$now" "$event")"
req "${CA[@]}" "${JSON[@]}" -H "X-Signature: $sig" --data-binary "$event" "$EDGE/webhooks/payment"
expect "Valid signed webhook" 200 '"evt_1001"'
req "${CA[@]}" "${JSON[@]}" -H "X-Signature: $sig" --data-binary "$event" "$EDGE/webhooks/payment"
expect "Same webhook replayed" 409
tampered='{"id":"evt_1002","type":"charge.succeeded","data":{"amount_cents":1}}'
req "${CA[@]}" "${JSON[@]}" -H "X-Signature: $sig" --data-binary "$tampered" "$EDGE/webhooks/payment"
expect "Tampered body, original signature" 401 "invalid signature"
old=$((now - 600))
stale='{"id":"evt_1003","type":"charge.succeeded"}'
req "${CA[@]}" "${JSON[@]}" -H "X-Signature: t=$old,v1=$(sign "$old" "$stale")" --data-binary "$stale" "$EDGE/webhooks/payment"
expect "Correctly signed but 10 minutes old" 401 "stale"
req "${CA[@]}" "${JSON[@]}" --data-binary "$stale" "$EDGE/webhooks/payment"
expect "Unsigned webhook" 401

echo
if [ "$FAILS" -eq 0 ]; then
  echo "All checks passed."
else
  echo "$FAILS check(s) failed. Recent logs:"
  tail -n 15 "$RUN"/error.log "$RUN"/*.log 2>/dev/null
fi
exit "$FAILS"
