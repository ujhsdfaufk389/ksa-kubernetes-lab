#!/usr/bin/env bash
# ============================================================================
# SAFE, CONTROLLED attack simulation — LOCAL kind lab ONLY.
# Uses `kubectl --as=` (impersonation by your cluster-admin kubeconfig) to make
# API calls AS the vulnerable ServiceAccounts. No tokens are extracted, nothing
# outside the lab is touched. Each call lands in the audit log so the detector's
# correlation engine can promote the matching path REACHABLE -> OBSERVED.
# ============================================================================
set -uo pipefail
CTX="${KSA_CONTEXT:-kind-ksa-lab}"
K="kubectl --context ${CTX}"

echo "[*] Simulating in context: ${CTX}"

# --- Scenario 1: web-sa (dev) creates a pod in production running as admin-sa ---
echo "[1] dev/web-sa  --create pod as admin-sa-->  production"
$K --as=system:serviceaccount:dev:web-sa -n production apply -f - >/dev/null 2>&1 <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: exfil-x9
  namespace: production
spec:
  serviceAccountName: admin-sa
  containers:
    - name: c
      image: busybox:1.36
      command: ["sh","-c","sleep 3600"]
YAML
echo "    -> create pods (serviceAccountName=admin-sa) issued"

# --- Scenario 4: backup-sa mints a token for admin-sa ---
echo "[4] production/backup-sa  --mint token-->  admin-sa"
$K --as=system:serviceaccount:production:backup-sa -n production create token admin-sa >/dev/null 2>&1 \
  && echo "    -> serviceaccounts/token for admin-sa issued" \
  || echo "    -> (token request issued; output suppressed)"

echo
echo "[*] Done. Re-scan to see paths flip to OBSERVED:"
echo "      ksa-detector scan --context ${CTX}"
echo "      # or click Re-scan in the dashboard"
