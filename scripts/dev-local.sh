#!/usr/bin/env bash
# Start the native Go Hanzo Cyber control plane wired to a local private LLM
# (Ollama, MLX, llama.cpp, LM Studio, or LAN hanzo-engine) or Hanzo Cloud AI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${HANZO_CYBER_PORT:-8787}"
DATA_DIR="${HANZO_CYBER_DATA_DIR:-$HOME/.hanzo/cyber}"
LOG="${HANZO_CYBER_LOG:-/tmp/hanzo-cyber.log}"

if [ ! -x "$ROOT/bin/cyber" ]; then
  echo "Building native cyber + cyber-probe + @hanzo/gui..."
  (cd "$ROOT" && make build)
fi

ARGS=(serve --addr "0.0.0.0:${PORT}" --data-dir "$DATA_DIR")
if [ -d "$ROOT/web/dist" ]; then
  ARGS+=(--web-dir "$ROOT/web/dist")
fi

# Pass HANZO_LLM_URL (e.g. http://127.0.0.1:11434/v1 or http://10.0.0.19:1234/v1)
# for local private AI, or HANZO_API_KEY for Hanzo Cloud AI (https://api.hanzo.ai/v1).
nohup "$ROOT/bin/cyber" "${ARGS[@]}" > "$LOG" 2>&1 &

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PORT}/v1/cyber/health" >/dev/null 2>&1; then
    echo "Hanzo Cyber Console: http://127.0.0.1:${PORT}/"
    echo "Health:              http://127.0.0.1:${PORT}/v1/cyber/health"
    echo "OpenAPI 3.1:         http://127.0.0.1:${PORT}/.well-known/openapi.json"
    echo "Log:                 $LOG"
    exit 0
  fi
  sleep 1
done
echo "Hanzo Cyber failed to start; see $LOG" >&2
exit 1
