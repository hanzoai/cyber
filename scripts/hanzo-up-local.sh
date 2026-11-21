#!/usr/bin/env bash
# Fully local OpenCyber control plane on `hanzo up`.
# No Docker and no image build: a tiny in-cluster proxy forwards the Service to
# the host-run control plane. Production uses workload/*.yaml instead.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KUBECONFIG_FILE="${HOME}/.kube/hanzo.yaml"
HOST_IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo 127.0.0.1)"
PORT="${OPENCYBER_CONTROL_PORT:-8787}"
LOCAL_PORT="${OPENCYBER_LOCAL_PORT:-8788}"

echo ">> hanzo up (local k3s)"
(hanzo up --no-ui > "${TMPDIR:-/tmp}/hanzo-up.log" 2>&1 &) || true

echo ">> wait for API and pre-create the namespace the cloud bootstrap expects"
for _ in $(seq 1 90); do
  if kubectl --kubeconfig "$KUBECONFIG_FILE" get ns hanzo >/dev/null 2>&1; then break; fi
  kubectl --kubeconfig "$KUBECONFIG_FILE" create namespace hanzo >/dev/null 2>&1 || true
  sleep 2
done
kubectl --kubeconfig "$KUBECONFIG_FILE" get nodes

echo ">> start control plane on 0.0.0.0:${PORT}"
if ! curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
  OPENCYBER_WORKSPACE="${OPENCYBER_WORKSPACE:-/workspace}" \
  OPENCYBER_CONTROL_ALLOW_REMOTE=1 \
    "$ROOT/.venv/bin/opencyber-control" --host 0.0.0.0 --port "$PORT" \
    > "${TMPDIR:-/tmp}/opencyber-control.log" 2>&1 &
fi
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then break; fi
  sleep 1
done

echo ">> apply local Service and TCP proxy (host ${HOST_IP})"
sed "s/__HOST_IP__/${HOST_IP}/" "$ROOT/deploy/hanzo-up/local.yaml" \
  | kubectl --kubeconfig "$KUBECONFIG_FILE" apply -f -
kubectl --kubeconfig "$KUBECONFIG_FILE" -n cyber rollout status pod/cyber-control-proxy --timeout=180s || true

echo ">> forward ${LOCAL_PORT} -> cluster service"
kubectl --kubeconfig "$KUBECONFIG_FILE" -n cyber port-forward svc/cyber-control "${LOCAL_PORT}:8787" \
  > "${TMPDIR:-/tmp}/opencyber-portforward.log" 2>&1 &

for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${LOCAL_PORT}/api/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${LOCAL_PORT}/api/health"

echo "OpenCyber Control: http://127.0.0.1:${LOCAL_PORT}/"
echo "Logs:              ${TMPDIR:-/tmp}/opencyber-control.log"
