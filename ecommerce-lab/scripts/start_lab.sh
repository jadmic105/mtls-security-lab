#!/usr/bin/env bash
# Start the e-commerce mTLS lab: three FastAPI services + nginx (edge, sidecars, mock PSP).
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$LAB/run"
CERTS="$LAB/certs"
mkdir -p "$RUN/tmp"

[ -f "$CERTS/internal-ca.crt" ] || "$LAB/scripts/gen_certs.sh"

# Secrets: generated once per environment. In production these come from a secrets manager.
if [ ! -f "$RUN/secrets.env" ]; then
  ( umask 077
    echo "PSP_API_KEY=sk_test_$(openssl rand -hex 24)"
    echo "WEBHOOK_SECRET=whsec_$(openssl rand -hex 32)"
  ) > "$RUN/secrets.env"
fi
set -a
. "$RUN/secrets.env"
set +a
export CERTS_DIR="$CERTS"

NGINX="$(command -v nginx || echo /usr/sbin/nginx)"
if [ ! -x "$NGINX" ]; then
  echo "nginx not found. Install it with: sudo apt install -y nginx"; exit 1
fi

sed -e "s#__RUN__#$RUN#g" -e "s#__CERTS__#$CERTS#g" \
  "$LAB/nginx/nginx.conf.template" > "$RUN/nginx.conf"
"$NGINX" -t -q -p "$RUN" -e "$RUN/error.log" -c "$RUN/nginx.conf"

start_app() { # dir port
  python3 -m uvicorn app:app --app-dir "$LAB/services/$1" \
    --host 127.0.0.1 --port "$2" > "$RUN/$1.log" 2>&1 &
  echo $! > "$RUN/$1.pid"
}
start_app orders 8001
start_app payments 8002
start_app psp_gateway 8003

"$NGINX" -p "$RUN" -e "$RUN/error.log" -c "$RUN/nginx.conf"

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for port in 8001 8002 8003 8443 9101 9102 9103; do
  for _ in $(seq 1 30); do port_open "$port" && break; sleep 0.5; done
  if ! port_open "$port"; then
    echo "Port $port did not open. Logs:"; tail -n 20 "$RUN"/*.log; exit 1
  fi
done

cat <<EOF
Lab is running.
  Customer edge (HTTPS):  https://localhost:8443/api/checkout
  Orders sidecar (mTLS):  https://localhost:9101
  Payments sidecar (mTLS): https://localhost:9102
  Mock PSP (mTLS):        https://localhost:9103
Logs: $RUN/*.log    Stop: $LAB/scripts/stop_lab.sh
EOF
