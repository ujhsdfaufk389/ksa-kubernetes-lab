"""What-if / predictive pre-deployment analysis (Wave 2, features 21/23/32).

Overlay a candidate change (one or more YAML manifests — a new Role, RoleBinding,
Deployment, …) onto the current cluster snapshot *without touching the cluster*,
re-run the escalation engine on the shadow state, and report exactly which attack
paths the change would create or remove. This is the engine behind a GitOps/CI
"security check" and a pre-apply admission gate.
"""
from __future__ import annotations

from pathlib import Path

from ksa.analyzer import Analyzer
from ksa.drift import diff
from ksa.models import ClusterSnapshot


def _merge(base: ClusterSnapshot, overlay: ClusterSnapshot) -> ClusterSnapshot:
    """Overlay objects replace base objects with the same id; others are added."""
    def combine(base_list, overlay_list):
        by_id = {o.id: o for o in base_list}
        for o in overlay_list:
            by_id[o.id] = o  # replace or add
        return list(by_id.values())

    return ClusterSnapshot(
        namespaces=combine(base.namespaces, overlay.namespaces),
        service_accounts=combine(base.service_accounts, overlay.service_accounts),
        roles=combine(base.roles, overlay.roles),
        bindings=combine(base.bindings, overlay.bindings),
        workloads=combine(base.workloads, overlay.workloads),
        secrets=combine(base.secrets, overlay.secrets),
    )


def _slim(result: dict, when: str) -> dict:
    return {"scanned_at": when, "findings": result.get("findings", [])}


def simulate(base: ClusterSnapshot, candidate: str | Path | ClusterSnapshot) -> dict:
    """Return the attack-path diff a candidate change would cause.

    `candidate` is a path to a manifest file/dir, or an already-built snapshot
    containing just the proposed objects.
    """
    if isinstance(candidate, ClusterSnapshot):
        overlay = candidate
    else:
        from ksa.collector.directory_collector import DirectoryCollector
        overlay = DirectoryCollector(candidate).collect()

    merged = _merge(base, overlay)
    before = Analyzer(base).scan_result(cluster="current")
    after = Analyzer(merged).scan_result(cluster="proposed")
    d = diff(_slim(before, "current"), _slim(after, "proposed"))

    b_crit = before["summary"]["severity"]["critical"]
    a_crit = after["summary"]["severity"]["critical"]
    verdict = "DENY" if d["counts"]["new_critical"] else ("WARN" if d["counts"]["new"] else "ALLOW")
    return {
        "verdict": verdict,
        "paths_before": before["summary"]["escalation_paths"],
        "paths_after": after["summary"]["escalation_paths"],
        "critical_before": b_crit,
        "critical_after": a_crit,
        "new_paths": d["new_paths"],
        "removed_paths": d["removed_paths"],
        "counts": d["counts"],
    }
