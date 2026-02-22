#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${DEMO_STATE_DIR:-/tmp/clownpeanuts-demo}"
CONFIG_PATH="${DEMO_CONFIG_PATH:-${ROOT_DIR}/config/local-theater-demo.yml}"

API_HOST="${DEMO_API_HOST:-127.0.0.1}"
API_PORT="${DEMO_API_PORT:-8109}"
DASH_HOST="${DEMO_DASH_HOST:-127.0.0.1}"
DASH_PORT="${DEMO_DASH_PORT:-3001}"
SSH_PORT="${DEMO_SSH_PORT:-3222}"
HTTP_PORT="${DEMO_HTTP_PORT:-28080}"

API_PID_FILE="${STATE_DIR}/api.pid"
DASH_PID_FILE="${STATE_DIR}/dashboard.pid"
API_LOG_FILE="${STATE_DIR}/api.log"
DASH_LOG_FILE="${STATE_DIR}/dashboard.log"
SESSION_ID_FILE="${STATE_DIR}/session-id.txt"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

mkdir -p "${STATE_DIR}" "${ROOT_DIR}/config"
require_cmd curl
require_cmd npm

if [[ ! -x "${ROOT_DIR}/.venv/bin/clownpeanuts" ]]; then
  echo "missing ${ROOT_DIR}/.venv/bin/clownpeanuts (create venv and install deps first)" >&2
  exit 1
fi

if [[ ! -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  echo "missing ${ROOT_DIR}/.venv/bin/python (create venv first)" >&2
  exit 1
fi

"${ROOT_DIR}/scripts/dev-down-demo.sh" --quiet || true

"${ROOT_DIR}/.venv/bin/python" - "${ROOT_DIR}/clownpeanuts/config/defaults.yml" "${CONFIG_PATH}" "${SSH_PORT}" "${HTTP_PORT}" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

import yaml

defaults_path = Path(sys.argv[1])
config_path = Path(sys.argv[2])
ssh_port = int(sys.argv[3])
http_port = int(sys.argv[4])

data = yaml.safe_load(defaults_path.read_text(encoding="utf-8"))

data["network"]["segmentation_mode"] = "none"
data["network"]["require_segmentation"] = False
data["network"]["enforce_runtime"] = False
data["session"]["backend"] = "memory"
data["event_bus"]["backend"] = "memory"
data["narrative"]["enabled"] = True
data["bandit"]["enabled"] = True
data["theater"]["enabled"] = True
data["theater"]["rollout_mode"] = "apply-enabled"

for service in data.get("services", []):
    name = str(service.get("name", ""))
    if name == "ssh":
        service["ports"] = [ssh_port]
    if name == "http-admin":
        service["ports"] = [http_port]
    if name in {"redis-db", "mysql-db", "postgres-db"}:
        service["enabled"] = False

config_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY

echo "starting demo api on ${API_HOST}:${API_PORT}"
nohup "${ROOT_DIR}/.venv/bin/clownpeanuts" \
  api \
  --config "${CONFIG_PATH}" \
  --host "${API_HOST}" \
  --port "${API_PORT}" \
  --start-services \
  >"${API_LOG_FILE}" 2>&1 &
echo $! > "${API_PID_FILE}"

api_ready=0
for _ in {1..80}; do
  if curl -fsS "http://${API_HOST}:${API_PORT}/health" >/dev/null 2>&1; then
    api_ready=1
    break
  fi
  sleep 0.25
done
if [[ "${api_ready}" -ne 1 ]]; then
  echo "api failed to start; tailing ${API_LOG_FILE}" >&2
  tail -n 80 "${API_LOG_FILE}" >&2 || true
  exit 1
fi

echo "starting demo dashboard on ${DASH_HOST}:${DASH_PORT}"
(
  cd "${ROOT_DIR}/dashboard"
  NEXT_PUBLIC_CLOWNPEANUTS_API="http://${API_HOST}:${API_PORT}" \
  NEXT_PUBLIC_CLOWNPEANUTS_WS="ws://${API_HOST}:${API_PORT}/ws/events" \
  NEXT_PUBLIC_CLOWNPEANUTS_WS_THEATER="ws://${API_HOST}:${API_PORT}/ws/theater/live" \
  nohup npm run dev -- --hostname "${DASH_HOST}" --port "${DASH_PORT}" >"${DASH_LOG_FILE}" 2>&1 &
  echo $! > "${DASH_PID_FILE}"
)

dash_ready=0
for _ in {1..120}; do
  if curl -fsS "http://${DASH_HOST}:${DASH_PORT}" >/dev/null 2>&1; then
    dash_ready=1
    break
  fi
  sleep 0.25
done
if [[ "${dash_ready}" -ne 1 ]]; then
  echo "dashboard failed to start; tailing ${DASH_LOG_FILE}" >&2
  tail -n 80 "${DASH_LOG_FILE}" >&2 || true
  exit 1
fi

# Seed a small amount of activity so theater/replay have immediate data.
curl -fsS "http://127.0.0.1:${HTTP_PORT}/admin" >/dev/null 2>&1 || true
curl -fsS "http://127.0.0.1:${HTTP_PORT}/api/internal/orders" >/dev/null 2>&1 || true
curl -fsS "http://127.0.0.1:${HTTP_PORT}/api/internal/search?q=invoice&page=2&page_size=9" >/dev/null 2>&1 || true
curl -fsS -X POST "http://127.0.0.1:${HTTP_PORT}/admin" -d "username=admin&password=letmein" >/dev/null 2>&1 || true

session_payload="$(curl -fsS "http://${API_HOST}:${API_PORT}/sessions?limit=1&events_per_session=20" || true)"
session_id="$(
  SESSION_PAYLOAD="${session_payload}" "${ROOT_DIR}/.venv/bin/python" - <<'PY'
from __future__ import annotations

import json
import os
import sys

raw = os.environ.get("SESSION_PAYLOAD", "").strip()
if not raw:
    print("")
    raise SystemExit(0)

try:
    payload = json.loads(raw)
except Exception:
    print("")
    raise SystemExit(0)

sessions = payload.get("sessions", [])
if isinstance(sessions, list) and sessions:
    first = sessions[0]
    if isinstance(first, dict):
        print(str(first.get("session_id", "")))
        raise SystemExit(0)
print("")
PY
)"
printf "%s" "${session_id}" > "${SESSION_ID_FILE}"

echo ""
echo "demo stack is ready"
echo "api:          http://${API_HOST}:${API_PORT}"
echo "dashboard:    http://${DASH_HOST}:${DASH_PORT}"
echo "theater:      http://${DASH_HOST}:${DASH_PORT}/theater"
if [[ -n "${session_id}" ]]; then
  echo "replay:       http://${DASH_HOST}:${DASH_PORT}/theater/replay/${session_id}"
fi
echo ""
echo "ssh emulator: 127.0.0.1:${SSH_PORT}"
echo "http emu:     http://127.0.0.1:${HTTP_PORT}"
echo ""
echo "config:       ${CONFIG_PATH}"
echo "api log:      ${API_LOG_FILE}"
echo "dashboard log:${DASH_LOG_FILE}"
echo ""
echo "stop with:    ${ROOT_DIR}/scripts/dev-down-demo.sh"
