#!/usr/bin/env bash
# Reset the lab to the intentionally-vulnerable state (undo apply-secure.sh).
set -uo pipefail
CTX="${KSA_CONTEXT:-kind-ksa-lab}"
K="kubectl --context ${CTX}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[*] Removing secure grants..."
$K delete -f "${ROOT}/lab/secure/" --ignore-not-found >/dev/null 2>&1

echo "[*] Applying vulnerable configuration (namespaces, SAs, all scenarios)..."
$K apply -f "${ROOT}/lab/vulnerable/" >/dev/null

echo "[*] Done. Re-scan to see the escalation paths return:"
echo "      ksa-detector scan --context ${CTX}"
