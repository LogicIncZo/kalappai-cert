#!/usr/bin/env bash
# kalappai-cert — interactive demo.
#
# Spawns the service on a known port with a throwaway database, seeds a
# deterministic set of practice certificates, prints each verify URL with a
# scannable QR, and holds open so you can click through the pages.
#
# Nothing here touches the deployment: the database is a temp directory and the
# issuer key is generated fresh, so nothing printed here can be mistaken for a
# real issued credential.
#
# Usage:
#   bash demo/run.sh                 seed and hold open (Ctrl-C to stop)
#   bash demo/run.sh --check         assert the whole demo path works, exit
#
# Screenshots (optional, needs agent-browser):
#   bash demo/run.sh --shots <dir>   capture the landing, gate and receipt pages

set -uo pipefail

cd "$(dirname "$0")/.."

PORT="${KALAPPAI_DEMO_PORT:-8642}"
SHOTS=""
CHECK=0

while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1; shift ;;
    --shots) SHOTS="${2:-demo/shots}"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "unknown flag: $1"; exit 2 ;;
  esac
done

if [ "$CHECK" -eq 1 ]; then
  exec bun demo/seed.ts --check
fi

# Hold the service open in the background so the seeded URLs keep resolving
# while the demo is being shown, then seed against it.
bun demo/seed.ts --port "$PORT" &
SEED_PID=$!

cleanup() {
  kill "$SEED_PID" >/dev/null 2>&1 || true
  wait "$SEED_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 6

BASE="http://127.0.0.1:${PORT}"
echo ""
echo "Pages on ${BASE}:"
echo "  ${BASE}/              health"
echo "  ${BASE}/cognizance    the cognizance gate — type the values, get a receipt"
echo "  ${BASE}/cognizance/limits   what a receipt does and does not assert"

if [ -n "$SHOTS" ]; then
  if ! command -v agent-browser >/dev/null 2>&1; then
    echo "agent-browser not found — skipping screenshots"
  else
    mkdir -p "$SHOTS"
    for page in "" "cognizance" "cognizance/limits"; do
      name="${page:-index}"
      agent-browser open "${BASE}/${page}" >/dev/null 2>&1
      sleep 2
      agent-browser screenshot "${SHOTS}/${name//\//-}.png" --full >/dev/null 2>&1 &&
        echo "  captured ${SHOTS}/${name//\//-}.png"
    done
  fi
fi

wait "$SEED_PID"
