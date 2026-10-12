#!/usr/bin/env bash
# Remediate the lab: remove the vulnerable grants, apply least-privilege ones.
# Shared identities (namespaces + ServiceAccounts in 00-...) are left intact.
set -uo pipefail
CTX="${KSA_CONTEXT:-kind-ksa-lab}"
K="kubectl --context ${CTX}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[*] Removing vulnerable grants..."
for f in scenario-01-workload-creation scenario-02-impersonation \
         scenario-03-workload-hijack scenario-04-token-request \
         scenario-05-secret-cred scenario-06-bind-verb scenario-07-escalate-verb \
         scenario-08-wildcard scenario-09-crossns-chain scenario-10-exec; do
  $K delete -f "${ROOT}/lab/vulnerable/${f}.yaml" --ignore-not-found >/dev/null 2>&1
done

echo "[*] Cleaning up simulation artifacts..."
$K -n production delete pod exfil-x9 --ignore-not-found >/dev/null 2>&1

echo "[*] Applying least-privilege (secure) configuration..."
$K apply -f "${ROOT}/lab/secure/" >/dev/null

echo "[*] Done. Re-scan to confirm non-system paths drop to 0:"
echo "      ksa-detector scan --context ${CTX}"
