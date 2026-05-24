#!/usr/bin/env bash
# scripts/dev-down.sh — stop dev servers started by dev-up.sh.
#
# By default keeps the Oracle + Redis containers running (they hold the DB
# state you want to inspect after a session). Pass --infra to also `docker
# compose down` them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOGS_DIR="$ROOT_DIR/logs"
SERVER_DIR="$ROOT_DIR/server"

STOP_INFRA=0
for arg in "$@"; do
  case "$arg" in
    --infra) STOP_INFRA=1 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $arg (try --help)" >&2; exit 2 ;;
  esac
done

stop_port() {
  local name=$1 port=$2
  local pids
  pids=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    kill $pids 2>/dev/null || true
    sleep 1
    pids=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
    [[ -n "$pids" ]] && kill -9 $pids 2>/dev/null || true
    echo "  stopped $name (port $port)"
  else
    echo "  $name not running (port $port)"
  fi
}

echo "▸ Stopping dev servers"
stop_port "Admin Vite"     "${ADMIN_PORT:-5173}"
stop_port "RP demo"        "${RP_DEMO_PORT:-8090}"
stop_port "Passkey server" "${SERVER_PORT:-8080}"
rm -f "$LOGS_DIR"/*.pid 2>/dev/null || true

if (( STOP_INFRA )); then
  echo "▸ Stopping infra (Oracle + Redis)"
  ( cd "$SERVER_DIR" && docker compose down )
else
  echo "  (infra containers kept — pass --infra to stop them too)"
fi
