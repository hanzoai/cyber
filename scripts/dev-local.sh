#!/usr/bin/env bash
# Start the control plane wired to the local Hanzo native engine on the DGX.
# No Docker: run directly from the venv. Pass OPENCYBER_ENGINE_URL to override.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENGINE="${OPENCYBER_ENGINE_URL:-http://10.0.0.19:1234/v1}"
PORT="${OPENCYBER_CONTROL_PORT:-8787}"
DB="${OPENCYBER_STATE_DB:-/tmp/opencyber-control.db}"
LOG="${OPENCYBER_LOG:-/tmp/opencyber-control.log}"

# A global OpenAI key must not be sent to the local engine.
env -u OPENAI_API_KEY -u DEAD_OPENAI_API_KEY -u ZAI_OPENAI_API_KEY \
  OPENCYBER_WORKSPACE="${OPENCYBER_WORKSPACE:-/workspace}" \
  OPENCYBER_STATE_DB="$DB" \
  OPENCYBER_ENFORCE_SCOPE=1 \
  OPENCYBER_OFFLINE=1 \
  OPENCYBER_CONTROL_ALLOW_REMOTE=1 \
  HANZO_LLM_URL="$ENGINE" \
  nohup "$ROOT/.venv/bin/opencyber-control" --host 0.0.0.0 --port "$PORT" \
  > "$LOG" 2>&1 &

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PORT}/v1/health" >/dev/null 2>&1; then
    echo "OpenCyber Control: http://127.0.0.1:${PORT}/"
    echo "Log: $LOG"
    exit 0
  fi
  sleep 1
done
echo "control plane failed to start; see $LOG" >&2
exit 1
