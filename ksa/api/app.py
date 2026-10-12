"""FastAPI backend for the live dashboard (Part 11).

Serves the analysis result as JSON and hosts the dashboard. Collection stays
read-only. The scan is cached after first run; POST /api/rescan refreshes it.

Run:
    uvicorn ksa.api.app:app --reload
    # then open http://127.0.0.1:8000
Config via env:
    KSA_CONTEXT    kube context (default: kind-ksa-lab)
    KSA_DIRECTORY  analyze a manifest dir instead of a live cluster
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ksa.analyzer import Analyzer

_REPO = Path(__file__).resolve().parents[2]
_DASHBOARD_DIR = _REPO / "dashboard"
_DASHBOARD = _DASHBOARD_DIR / "index.html"
_HISTORY_DIR = _REPO / "reports" / "history"

app = FastAPI(title="KSA Detector API", version="0.6.0")
_cache: dict | None = None


def _collect():
    """Collect a snapshot (live or offline); returns (snapshot, cluster, audit_path)."""
    context = os.environ.get("KSA_CONTEXT", "kind-ksa-lab")
    directory = os.environ.get("KSA_DIRECTORY")
    audit_path = os.environ.get("KSA_AUDIT_LOG", str(_REPO / "cluster" / "audit" / "logs" / "audit.log"))
    if directory:
        from ksa.collector.directory_collector import DirectoryCollector
        return DirectoryCollector(directory).collect(), f"dir:{directory}", None
    from ksa.collector.kubernetes_collector import KubernetesCollector
    return KubernetesCollector(context=context).collect(), context, audit_path


def _run_scan() -> dict:
    snap, cluster, audit_path = _collect()
    result = Analyzer(snap).scan_result(cluster=cluster, audit_path=audit_path)
    # persist a slim snapshot so drift / attack-path diff can compare scans
    try:
        from ksa.drift import write_snapshot
        write_snapshot(result, _HISTORY_DIR)
    except Exception as exc:  # noqa: BLE001 - snapshotting must never break a scan
        import logging
        logging.getLogger(__name__).warning("snapshot write failed: %s", exc)
    return result


@app.get("/api/scan")
def get_scan() -> JSONResponse:
    """Return the cached scan (runs it on first request)."""
    global _cache
    if _cache is None:
        try:
            _cache = _run_scan()
        except Exception as exc:  # noqa: BLE001 - surface any cluster/collection error
            raise HTTPException(status_code=500, detail=f"scan failed: {exc}") from exc
    return JSONResponse(_cache)


@app.post("/api/rescan")
def rescan() -> JSONResponse:
    global _cache, _adv_cache
    _adv_cache = None
    try:
        _cache = _run_scan()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"scan failed: {exc}") from exc
    return JSONResponse(_cache)


@app.get("/api/diff")
def get_diff() -> JSONResponse:
    """Attack-path drift between the two most recent scan snapshots."""
    from ksa.drift import diff, load_latest_two
    prev, curr = load_latest_two(_HISTORY_DIR)
    return JSONResponse(diff(prev, curr))


_adv_cache: dict | None = None


@app.get("/api/advanced")
def get_advanced() -> JSONResponse:
    """Research-grade analytics: blast radius, toxic identities, choke points +
    minimum-change remediation, toxic combos, invariants, cloud federation,
    least-privilege. Cached; POST /api/rescan clears it."""
    global _adv_cache
    if _adv_cache is None:
        try:
            snap, _cluster, audit_path = _collect()
            events = None
            if audit_path:
                from ksa.collector.audit_collector import AuditCollector
                events = AuditCollector(audit_path).collect(limit=2000)
            _adv_cache = Analyzer(snap).advanced_analysis(audit_events=events)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"advanced analysis failed: {exc}") from exc
    return JSONResponse(_adv_cache)


@app.get("/api/temporal")
def get_temporal() -> JSONResponse:
    """Temporal attack graph: per-path timeline across all scan snapshots."""
    from ksa.analysis.temporal import became_exploitable, timeline
    t = timeline(_HISTORY_DIR)
    t["became_exploitable"] = became_exploitable(_HISTORY_DIR)
    return JSONResponse(t)


@app.post("/api/whatif")
def post_whatif(payload: dict) -> JSONResponse:
    """Predictive pre-deploy analysis. Body: {"manifest": "<yaml text>"}."""
    import tempfile
    from ksa.analysis.whatif import simulate
    manifest = (payload or {}).get("manifest", "")
    if not manifest.strip():
        raise HTTPException(status_code=400, detail="provide 'manifest' YAML text")
    try:
        snap, _cluster, _ = _collect()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "candidate.yaml").write_text(manifest)
            return JSONResponse(simulate(snap, d))
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"what-if failed: {exc}") from exc


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "cached": _cache is not None,
        "safe_mode": os.environ.get("KSA_SAFE_MODE", "0").lower() in ("1", "true", "yes", "on"),
    }


@app.get("/")
def dashboard() -> FileResponse:
    if not _DASHBOARD.exists():
        raise HTTPException(status_code=404, detail="dashboard/index.html not found")
    return FileResponse(_DASHBOARD)


# Serve vendored assets (cytoscape, etc.) so the dashboard has zero CDN deps and
# works fully offline. Mounted last so it never shadows the API routes above.
_VENDOR_DIR = _DASHBOARD_DIR / "vendor"
if _VENDOR_DIR.exists():
    app.mount("/vendor", StaticFiles(directory=str(_VENDOR_DIR)), name="vendor")
