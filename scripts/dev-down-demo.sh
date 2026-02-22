#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${DEMO_STATE_DIR:-/tmp/clownpeanuts-demo}"

API_PID_FILE="${STATE_DIR}/api.pid"
DASH_PID_FILE="${STATE_DIR}/dashboard.pid"
SESSION_ID_FILE="${STATE_DIR}/session-id.txt"

QUIET=0
if [[ "${1:-}" == "--quiet" ]]; then
  QUIET=1
fi

say() {
  if [[ "${QUIET}" -eq 0 ]]; then
    echo "$@"
  fi
}

stop_from_pidfile() {
  local pid_file="$1"
  local label="$2"
  if [[ ! -f "${pid_file}" ]]; then
    return 0
  fi
  local pid
  pid="$(cat "${pid_file}" 2>/dev/null || true)"
  rm -f "${pid_file}"
  if [[ -z "${pid}" ]]; then
    return 0
  fi
  if ! kill -0 "${pid}" >/dev/null 2>&1; then
    return 0
  fi

  say "stopping ${label} (pid ${pid})"
  kill "${pid}" >/dev/null 2>&1 || true
  for _ in {1..30}; do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  kill -9 "${pid}" >/dev/null 2>&1 || true
}

stop_from_pidfile "${API_PID_FILE}" "demo api"
stop_from_pidfile "${DASH_PID_FILE}" "demo dashboard"
rm -f "${SESSION_ID_FILE}"

say "demo stack stopped"
say "to start again: ${ROOT_DIR}/scripts/dev-up-demo.sh"
