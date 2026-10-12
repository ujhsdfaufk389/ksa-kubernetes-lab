#!/usr/bin/env bash
# Create (or recreate) the ksa-lab kind cluster with audit logging enabled.
# Portable: rewrites the absolute hostPaths in kind-config.yaml to THIS checkout.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="ksa-lab"
CFG="${REPO_ROOT}/cluster/kind-config.yaml"
RENDERED="$(mktemp)"

mkdir -p "${REPO_ROOT}/cluster/audit/logs"

# Rewrite the two host mount paths to the current repo location.
sed \
  -e "s|hostPath: .*cluster/audit/audit-policy.yaml|hostPath: ${REPO_ROOT}/cluster/audit/audit-policy.yaml|" \
  -e "s|hostPath: .*cluster/audit/logs|hostPath: ${REPO_ROOT}/cluster/audit/logs|" \
  "${CFG}" > "${RENDERED}"

if kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
  echo "[*] Deleting existing cluster '${CLUSTER_NAME}'..."
  kind delete cluster --name "${CLUSTER_NAME}"
fi

echo "[*] Creating cluster '${CLUSTER_NAME}' (1 control-plane + 2 workers, audit on)..."
kind create cluster --name "${CLUSTER_NAME}" --config "${RENDERED}"
rm -f "${RENDERED}"

echo "[*] Cluster info:"
kubectl cluster-info --context "kind-${CLUSTER_NAME}"
echo "[*] Nodes:"
kubectl get nodes -o wide
echo "[*] Audit log will appear at: ${REPO_ROOT}/cluster/audit/logs/audit.log"
