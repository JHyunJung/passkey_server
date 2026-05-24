#!/usr/bin/env bash
# scripts/dev-up.sh — one-shot local dev environment bringup.
#
# Resets the Oracle schema, restarts the Passkey server (Flyway re-migrates),
# auto-issues a dev tenant + API key, then boots the RP demo and Admin Vite
# console. Idempotent: re-running wipes state and starts fresh.
#
# Usage:
#   scripts/dev-up.sh            # interactive (asks before DROP)
#   scripts/dev-up.sh -y         # auto-confirm
#   scripts/dev-up.sh --no-rp    # skip RP demo (only server + admin)
#   scripts/dev-up.sh --no-admin # skip admin console
#
# Output:
#   logs/passkey-server.log, logs/rp-demo.log, logs/admin.log
#   .env.dev                     # generated tenant/api key (gitignored)

set -euo pipefail

# ─── paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_DIR="$ROOT_DIR/server"
SDK_JAVA_DIR="$ROOT_DIR/sdk-java"
ADMIN_DIR="$ROOT_DIR/admin"
LOGS_DIR="$ROOT_DIR/logs"
ENV_FILE="$ROOT_DIR/.env.dev"
CLEAN_SQL="$SERVER_DIR/docker/oracle-init/_clean_passkey.sql"

# ─── config (override via env) ────────────────────────────────────────────────
ORACLE_CONTAINER="${ORACLE_CONTAINER:-passkey-oracle}"
REDIS_CONTAINER="${REDIS_CONTAINER:-passkey-redis}"
ORACLE_USER_MIGRATOR="${ORACLE_USER_MIGRATOR:-APP_MIGRATOR}"
ORACLE_PASS_MIGRATOR="${ORACLE_PASS_MIGRATOR:-change_me_migrator}"
ORACLE_USER_RUNTIME="${ORACLE_USER_RUNTIME:-APP_RUNTIME}"
ORACLE_PASS_RUNTIME="${ORACLE_PASS_RUNTIME:-change_me_local}"
ORACLE_USER_ADMIN="${ORACLE_USER_ADMIN:-APP_ADMIN}"
ORACLE_PASS_ADMIN="${ORACLE_PASS_ADMIN:-change_me_admin}"
ORACLE_DSN="${ORACLE_DSN:-//localhost:1521/FREEPDB1}"
ADMIN_EMAIL="${ADMIN_EMAIL:-dev@local.test}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-devpassword!}"
TENANT_NAME="${TENANT_NAME:-RP Demo Tenant}"
TENANT_SLUG="${TENANT_SLUG:-rp-demo}"
API_KEY_NAME="${API_KEY_NAME:-rp-demo-local}"
SERVER_PORT="${SERVER_PORT:-8080}"
RP_DEMO_PORT="${RP_DEMO_PORT:-8090}"
ADMIN_PORT="${ADMIN_PORT:-5173}"
# WebAuthn config defaults for the seeded tenant. rpId=localhost makes the
# browser accept passkeys from any localhost port; origin pin still scopes it
# to the RP demo. Override via env if you point dev-up at a different RP.
WEBAUTHN_RP_ID="${WEBAUTHN_RP_ID:-localhost}"
WEBAUTHN_RP_NAME="${WEBAUTHN_RP_NAME:-RP Demo}"
WEBAUTHN_ORIGIN="${WEBAUTHN_ORIGIN:-http://localhost:${RP_DEMO_PORT}}"
SERVER_ORIGIN="http://localhost:${SERVER_PORT}"
ADMIN_ORIGIN="http://localhost:${ADMIN_PORT}"

# ─── flags ────────────────────────────────────────────────────────────────────
AUTO_YES=0
SKIP_RP=0
SKIP_ADMIN=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes) AUTO_YES=1 ;;
    --no-rp) SKIP_RP=1 ;;
    --no-admin) SKIP_ADMIN=1 ;;
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown arg: $arg (try --help)" >&2; exit 2 ;;
  esac
done

# ─── ui helpers ───────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
else
  C_RESET=''; C_DIM=''; C_BOLD=''; C_GREEN=''; C_RED=''; C_YELLOW=''; C_CYAN=''
fi
step() { echo "${C_CYAN}${C_BOLD}▸ $*${C_RESET}"; }
ok()   { echo "  ${C_GREEN}✓${C_RESET} $*"; }
warn() { echo "  ${C_YELLOW}!${C_RESET} $*"; }
die()  { echo "${C_RED}✗${C_RESET} $*" >&2; exit 1; }

# ─── preflight ────────────────────────────────────────────────────────────────
step "Preflight"
for cmd in docker curl python3 lsof; do
  command -v "$cmd" >/dev/null 2>&1 || die "$cmd not found in PATH"
done
[[ -x "$SERVER_DIR/gradlew" ]] || die "$SERVER_DIR/gradlew missing"
[[ -x "$SDK_JAVA_DIR/gradlew" ]] || die "$SDK_JAVA_DIR/gradlew missing"
[[ -f "$CLEAN_SQL" ]] || die "clean SQL not found: $CLEAN_SQL"
ok "tools present"

if (( ! AUTO_YES )); then
  echo
  echo "${C_YELLOW}This will DROP every Passkey table/user in container '${ORACLE_CONTAINER}' and restart all dev services.${C_RESET}"
  read -r -p "Continue? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || die "aborted"
fi

# ─── 1. infra ─────────────────────────────────────────────────────────────────
step "1/8 Infra containers"
if ! docker ps --format '{{.Names}}' | grep -qx "$ORACLE_CONTAINER"; then
  warn "$ORACLE_CONTAINER not running — starting via docker compose"
  ( cd "$SERVER_DIR" && docker compose up -d )
fi
if ! docker ps --format '{{.Names}}' | grep -qx "$REDIS_CONTAINER"; then
  warn "$REDIS_CONTAINER not running — starting via docker compose"
  ( cd "$SERVER_DIR" && docker compose up -d )
fi
# wait for oracle health (sqlplus echo trick mirrors compose healthcheck)
echo -n "  waiting for Oracle"
for _ in {1..60}; do
  if docker exec "$ORACLE_CONTAINER" sh -lc \
       "echo 'select 1 from dual;' | sqlplus -L -S system/change_me_local@$ORACLE_DSN 2>/dev/null | grep -q 1"; then
    echo; ok "Oracle healthy"; break
  fi
  echo -n "."; sleep 2
done
docker exec "$ORACLE_CONTAINER" sh -lc \
  "echo 'select 1 from dual;' | sqlplus -L -S system/change_me_local@$ORACLE_DSN 2>/dev/null | grep -q 1" \
  || die "Oracle did not become healthy"

# ─── 2. kill prior dev servers ────────────────────────────────────────────────
step "2/8 Stop prior dev servers"
mkdir -p "$LOGS_DIR"
if compgen -G "$LOGS_DIR/*.log" > /dev/null; then
  ARCHIVE="$LOGS_DIR/archive/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$ARCHIVE"
  mv "$LOGS_DIR"/*.log "$ARCHIVE"/ 2>/dev/null || true
  ok "archived previous logs → ${ARCHIVE#$ROOT_DIR/}"
fi
for port in "$SERVER_PORT" "$RP_DEMO_PORT" "$ADMIN_PORT"; do
  pids=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    kill $pids 2>/dev/null || true
    sleep 1
    pids2=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
    [[ -n "$pids2" ]] && kill -9 $pids2 2>/dev/null || true
    ok "freed port $port"
  fi
done

# ─── 3. drop schema ───────────────────────────────────────────────────────────
step "3/8 Reset DB schema (_clean_passkey.sql)"
docker cp "$CLEAN_SQL" "$ORACLE_CONTAINER":/tmp/clean.sql >/dev/null
docker exec "$ORACLE_CONTAINER" sqlplus -L -S \
  "$ORACLE_USER_MIGRATOR/$ORACLE_PASS_MIGRATOR@$ORACLE_DSN" @/tmp/clean.sql \
  | tail -5
ok "schema dropped — Flyway will replay on next boot"

# ─── 4. boot Passkey server ───────────────────────────────────────────────────
step "4/8 Boot Passkey server (port $SERVER_PORT)"
SERVER_LOG="$LOGS_DIR/passkey-server.log"
(
  cd "$SERVER_DIR"
  nohup ./gradlew bootRun \
      --args='--spring.profiles.active=local --passkey.admin.enabled=true' \
      > "$SERVER_LOG" 2>&1 &
  echo $! > "$LOGS_DIR/passkey-server.pid"
) >/dev/null 2>&1 &
disown || true

echo -n "  waiting for $SERVER_ORIGIN/actuator/health"
for _ in {1..150}; do
  if curl -sf "$SERVER_ORIGIN/actuator/health" >/dev/null 2>&1; then
    echo; ok "Passkey server UP"; break
  fi
  echo -n "."; sleep 2
done
curl -sf "$SERVER_ORIGIN/actuator/health" >/dev/null \
  || die "Passkey server failed (see $SERVER_LOG)"

# APP_RUNTIME password drift workaround: Flyway baseline placeholders should
# match application-local.yml, but on re-runs Oracle occasionally keeps stale
# password hashes if a previous boot stamped them. Re-assert here.
docker exec "$ORACLE_CONTAINER" sh -lc \
  "sqlplus -L -S system/change_me_local@$ORACLE_DSN <<SQL >/dev/null 2>&1
ALTER USER $ORACLE_USER_RUNTIME IDENTIFIED BY $ORACLE_PASS_RUNTIME;
ALTER USER $ORACLE_USER_ADMIN IDENTIFIED BY $ORACLE_PASS_ADMIN;
EXIT
SQL" || warn "failed to re-assert runtime/admin passwords (may be fine if first boot)"

# ─── 5. seed tenant + api key ─────────────────────────────────────────────────
step "5/8 Seed dev tenant + API key"
COOKIE_JAR="$(mktemp -t passkey-cookies.XXXXXX)"
trap 'rm -f "$COOKIE_JAR"' EXIT

# trigger CSRF token cookie (any admin endpoint sets it, even on 401)
curl -s -c "$COOKIE_JAR" -o /dev/null -H "Origin: $ADMIN_ORIGIN" \
  "$SERVER_ORIGIN/api/v1/admin/me"
CSRF=$(awk '$6=="XSRF-TOKEN" {print $7}' "$COOKIE_JAR" | tail -1)
[[ -n "$CSRF" ]] || die "could not bootstrap CSRF token"

login_resp=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "X-XSRF-TOKEN: $CSRF" -H 'Content-Type: application/json' -H "Origin: $ADMIN_ORIGIN" \
  -X POST "$SERVER_ORIGIN/api/v1/admin/auth/login" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")
echo "$login_resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("success") else 1)' \
  || die "admin login failed: $login_resp"
ok "logged in as $ADMIN_EMAIL"

# Login rotates the CSRF token (Spring's session-fixation defence). Re-read it
# from the cookie jar before the next mutating call.
CSRF=$(awk '$6=="XSRF-TOKEN" {print $7}' "$COOKIE_JAR" | tail -1)
[[ -n "$CSRF" ]] || die "CSRF token missing after login"

tenant_resp=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "X-XSRF-TOKEN: $CSRF" -H 'Content-Type: application/json' -H "Origin: $ADMIN_ORIGIN" \
  -X POST "$SERVER_ORIGIN/api/v1/admin/tenants" \
  -d "{\"name\":\"$TENANT_NAME\",\"slug\":\"$TENANT_SLUG\"}")
TENANT_ID=$(echo "$tenant_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["id"])') \
  || die "tenant create failed: $tenant_resp"
ok "tenant created: $TENANT_SLUG ($TENANT_ID)"

CSRF=$(awk '$6=="XSRF-TOKEN" {print $7}' "$COOKIE_JAR" | tail -1)
apikey_resp=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "X-XSRF-TOKEN: $CSRF" -H 'Content-Type: application/json' -H "Origin: $ADMIN_ORIGIN" \
  -X POST "$SERVER_ORIGIN/api/v1/admin/tenants/$TENANT_ID/api-keys" \
  -d "{\"name\":\"$API_KEY_NAME\"}")
API_KEY=$(echo "$apikey_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["plaintext"])') \
  || die "api key issue failed: $apikey_resp"
API_KEY_PREFIX=$(echo "$apikey_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["prefix"])')
ok "API key issued: prefix=$API_KEY_PREFIX (full value in .env.dev)"

# WebAuthn config: required for /passkey/* ceremonies — without it the server
# returns P001 'WebAuthn configuration is missing' on first register attempt.
CSRF=$(awk '$6=="XSRF-TOKEN" {print $7}' "$COOKIE_JAR" | tail -1)
webauthn_resp=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "X-XSRF-TOKEN: $CSRF" -H 'Content-Type: application/json' -H "Origin: $ADMIN_ORIGIN" \
  -X PUT "$SERVER_ORIGIN/api/v1/admin/tenants/$TENANT_ID/webauthn-config" \
  -d "{
    \"rpId\":\"$WEBAUTHN_RP_ID\",
    \"rpName\":\"$WEBAUTHN_RP_NAME\",
    \"origins\":[\"$WEBAUTHN_ORIGIN\"],
    \"timeoutMs\":60000,
    \"userVerification\":\"PREFERRED\",
    \"attestationConveyance\":\"NONE\",
    \"residentKey\":\"PREFERRED\",
    \"credProtect\":\"NONE\"
  }")
echo "$webauthn_resp" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("success") else 1)' \
  || die "webauthn-config upsert failed: $webauthn_resp"
ok "WebAuthn config set: rpId=$WEBAUTHN_RP_ID origin=$WEBAUTHN_ORIGIN"

cat > "$ENV_FILE" <<EOF
# Generated by scripts/dev-up.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Do not commit — already in .gitignore via .env.* pattern.
PASSKEY_TENANT_ID=$TENANT_ID
PASSKEY_API_KEY=$API_KEY
PASSKEY_BASE_URL=$SERVER_ORIGIN
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_PASSWORD=$ADMIN_PASSWORD
EOF
ok "wrote $(basename "$ENV_FILE")"

# ─── 6. boot RP demo ──────────────────────────────────────────────────────────
if (( ! SKIP_RP )); then
  step "6/8 Boot RP demo (port $RP_DEMO_PORT)"
  RP_LOG="$LOGS_DIR/rp-demo.log"
  (
    cd "$SDK_JAVA_DIR"
    PASSKEY_TENANT_ID="$TENANT_ID" PASSKEY_API_KEY="$API_KEY" \
      nohup ./gradlew :examples:passkey-rp-demo:bootRun \
        > "$RP_LOG" 2>&1 &
    echo $! > "$LOGS_DIR/rp-demo.pid"
  ) >/dev/null 2>&1 &
  disown || true

  echo -n "  waiting for http://localhost:$RP_DEMO_PORT"
  for _ in {1..90}; do
    if curl -sI "http://localhost:$RP_DEMO_PORT" 2>&1 | grep -q '^HTTP'; then
      echo; ok "RP demo UP"; break
    fi
    echo -n "."; sleep 2
  done
  curl -sI "http://localhost:$RP_DEMO_PORT" 2>&1 | grep -q '^HTTP' \
    || die "RP demo failed (see $RP_LOG)"
else
  step "6/8 RP demo — skipped (--no-rp)"
fi

# ─── 7. boot Admin Vite ───────────────────────────────────────────────────────
if (( ! SKIP_ADMIN )); then
  step "7/8 Boot Admin console (port $ADMIN_PORT)"
  ADMIN_LOG="$LOGS_DIR/admin.log"
  if [[ ! -d "$ADMIN_DIR/node_modules" ]]; then
    warn "node_modules missing — running npm install (one-time)"
    ( cd "$ADMIN_DIR" && npm install )
  fi
  (
    cd "$ADMIN_DIR"
    nohup npm run dev > "$ADMIN_LOG" 2>&1 &
    echo $! > "$LOGS_DIR/admin.pid"
  ) >/dev/null 2>&1 &
  disown || true

  echo -n "  waiting for $ADMIN_ORIGIN"
  for _ in {1..30}; do
    if curl -sI "$ADMIN_ORIGIN" 2>&1 | grep -q '^HTTP'; then
      echo; ok "Admin console UP"; break
    fi
    echo -n "."; sleep 1
  done
  curl -sI "$ADMIN_ORIGIN" 2>&1 | grep -q '^HTTP' \
    || die "Admin console failed (see $ADMIN_LOG)"
else
  step "7/8 Admin console — skipped (--no-admin)"
fi

# ─── 8. summary ───────────────────────────────────────────────────────────────
step "8/8 Ready"
cat <<EOF

${C_BOLD}Dev environment is up.${C_RESET}

  ${C_BOLD}Admin console${C_RESET}    $ADMIN_ORIGIN
      login: ${C_CYAN}$ADMIN_EMAIL${C_RESET} / ${C_CYAN}$ADMIN_PASSWORD${C_RESET}
  ${C_BOLD}Passkey server${C_RESET}   $SERVER_ORIGIN
      swagger: $SERVER_ORIGIN/swagger-ui/index.html
  ${C_BOLD}RP demo${C_RESET}          http://localhost:$RP_DEMO_PORT
      tenant: $TENANT_SLUG ($TENANT_ID)
      api key prefix: $API_KEY_PREFIX  (full value in .env.dev)
      webauthn: rpId=$WEBAUTHN_RP_ID origin=$WEBAUTHN_ORIGIN

  Logs:    tail -f logs/*.log
  Stop:    scripts/dev-down.sh

EOF
