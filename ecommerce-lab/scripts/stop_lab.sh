#!/usr/bin/env bash
# Stop everything started by start_lab.sh.
LAB="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$LAB/run"
for f in "$RUN"/nginx.pid "$RUN"/orders.pid "$RUN"/payments.pid "$RUN"/psp_gateway.pid; do
  [ -f "$f" ] || continue
  kill "$(cat "$f")" 2>/dev/null
  rm -f "$f"
done
echo "Lab stopped."
