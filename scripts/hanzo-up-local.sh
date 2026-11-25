#!/usr/bin/env bash
# Run the native Go Hanzo Cyber control plane inside local `hanzo up` (no Docker needed).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KUBECONFIG_FILE="${HOME}/.kube/hanzo.yaml"
HOST_IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo 127.0.0.1)"
PORT="${HANZO_CYBER_PORT:-8787}"
LOCAL_PORT="${HANZO_CYBER_LOCAL_PORT:-8788}"

if [ ! -x "$ROOT/bin/cyber" ]; then
  (cd "$ROOT" && make build)
fi

echo ">> hanzo up (local k3s)"
(hanzo up --no-ui > "${TMPDIR:-/tmp}/hanzo-up.log" 2>&1 &) || true

for _ in $(seq 1 90); do
  if kubectl --kubeconfig "$KUBECONFIG_FILE" get ns hanzo >/dev/null 2>&1; then break; fi
  kubectl --kubeconfig "$KUBECONFIG_FILE" create namespace hanzo >/dev/null 2>&1 || true
  sleep 2
done
kubectl --kubeconfig "$KUBECONFIG_FILE" get nodes

echo ">> start native Go cyber control plane on 0.0.0.0:${PORT}"
if ! curl -fsS "http://127.0.0.1:${PORT}/v1/cyber/health" >/dev/null 2>&1; then
  "$ROOT/bin/cyber" serve --addr "0.0.0.0:${PORT}" --web-dir "$ROOT/web/dist" \
    > "${TMPDIR:-/tmp}/hanzo-cyber.log" 2>&1 &
fi
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PORT}/v1/cyber/health" >/dev/null 2>&1; then break; fi
  sleep 1
done

echo ">> apply local Service and TCP proxy (host ${HOST_IP})"
sed "s/__HOST_IP__/${HOST_IP}/" "$ROOT/deploy/hanzo-up/local.yaml" \
  | kubectl --kubeconfig "$KUBECONFIG_FILE" apply -f -
kubectl --kubeconfig "$KUBECONFIG_FILE" -n cyber rollout status pod/cyber-control-proxy --timeout=180s || true

echo ">> forward ${LOCAL_PORT} -> cluster service"
kubectl --kubeconfig "$KUBECONFIG_FILE" -n cyber port-forward svc/cyber-control "${LOCAL_PORT}:8787" \
  > "${TMPDIR:-/tmp}/hanzo-cyber-portforward.log" 2>&1 &

for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${LOCAL_PORT}/v1/cyber/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${LOCAL_PORT}/v1/cyber/health"
echo ""
echo "Hanzo Cyber Console: http://127.0.0.1:${LOCAL_PORT}/"
