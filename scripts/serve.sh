#!/usr/bin/env bash
# Start the live dashboard + API. Open the printed URL in your browser.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
source .venv/bin/activate
export KSA_CONTEXT="${KSA_CONTEXT:-kind-ksa-lab}"
PORT="${PORT:-8181}"
# --reload is opt-in: its file watcher opens many inotify handles and dies with
# "Too many open files" on crowded hosts. Default off for a reliable run.
# Enable with: RELOAD=1 bash scripts/serve.sh
RELOAD_FLAG=""
[ "${RELOAD:-0}" = "1" ] && RELOAD_FLAG="--reload"
echo "[*] KSA dashboard on http://127.0.0.1:${PORT}  (context: ${KSA_CONTEXT})"
exec uvicorn ksa.api.app:app --host 127.0.0.1 --port "${PORT}" ${RELOAD_FLAG}
