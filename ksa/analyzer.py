"""Analysis pipeline: ClusterSnapshot -> scored, explainable Findings + exports.

Ties together the graph builder, path engine, permission resolver and risk
scorer, and serializes results into the shapes the CLI, reports and dashboard
consume (findings.json, graph.json in Cytoscape format, summary).
"""
from __future__ import annotations

import datetime as _dt
import logging
import os

from ksa.graph.graph_builder import GraphBuilder
from ksa.graph.graph_queries import DEFAULT_SINKS, EscalationPath, PathFinder
from ksa.graph.relationships import EdgeType
from ksa.models import ClusterSnapshot
from ksa.permissions import PermissionResolver
from ksa.risk.scoring import (
    EDGE_WEIGHT,
    TECHNIQUES,
    Confidence,
    Finding,
    explain_path,
    primary_primitive,
    score_path,
    severity_for,
)

log = logging.getLogger(__name__)

_SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease", "local-path-storage"}


def _is_system_source(sa_id: str) -> bool:
    # sa_id looks like 'sa:<ns>/<name>'
    ns = sa_id.split(":", 1)[1].split("/", 1)[0] if ":" in sa_id else ""
    return ns in _SYSTEM_NS


def _edge_cls(edge_type: str) -> str:
    w = EDGE_WEIGHT.get(edge_type, 60)
    return "crit" if w >= 90 else "high" if w >= 80 else "med"


class Analyzer:
    def __init__(self, snapshot: ClusterSnapshot, max_hops: int = 8) -> None:
        self.snap = snapshot
        self.max_hops = max_hops
        self._graph = GraphBuilder(snapshot).build()
        self._effective = PermissionResolver(snapshot).resolve_all()
        self._finder = PathFinder(self._graph, max_hops=max_hops)

    # ---- findings -------------------------------------------------------
    def findings(self) -> list[Finding]:
        results: list[Finding] = []
        for src in self._finder.sources():
            eff = self._effective.get(src)
            # an identity that is ALREADY cluster-admin is not *escalating*
            if eff and eff.is_cluster_admin():
                continue
            best = self._best_path(src)
            if best is None:
                continue
            results.append(self._to_finding(src, best))
        # rank: highest risk, then non-system before system, then shortest
        results.sort(key=lambda f: (-f.risk_score, f.system_expected, f.path.length))
        for i, f in enumerate(results, 1):
            f.id = f"KSA-PE-{i:03d}"
        return results

    def _best_path(self, src: str) -> EscalationPath | None:
        paths = self._finder.find_from(src, sinks=DEFAULT_SINKS, max_paths=6)
        # keep only paths that include at least one real movement edge
        movement = {
            EdgeType.CREATE_POD_AS.value, EdgeType.WORKLOAD_HIJACK.value,
            EdgeType.REQUEST_TOKEN.value, EdgeType.IMPERSONATE.value,
            EdgeType.EXEC_INTO.value, EdgeType.READ_SECRET_CRED.value,
            EdgeType.CAN_BIND.value, EdgeType.CAN_ESCALATE.value,
            EdgeType.NODE_ACCESS.value, EdgeType.PRIVILEGED_WORKLOAD.value,
            EdgeType.CSR_ESCALATE.value,
        }
        candidates = [
            p for p in paths if any(h.edge_type in movement for h in p.hops)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda p: (score_path(p), -p.length))

    def _to_finding(self, src: str, path: EscalationPath) -> Finding:
        prim = primary_primitive(path)
        tech = TECHNIQUES.get(prim, TECHNIQUES[EdgeType.CREATE_POD_AS.value])
        score = score_path(path)
        # aggregate evidence across hops
        bindings, roles = set(), set()
        for h in path.hops:
            ev = h.evidence or {}
            bindings.update(ev.get("bindings", []))
            roles.update(ev.get("roles", []))
        return Finding(
            id="KSA-PE-000",
            title=tech.title,
            source=src,
            target=path.target,
            severity=severity_for(score),
            risk_score=score,
            confidence=Confidence.REACHABLE,  # graph-confirmed; audit may promote
            primitive=prim,
            path=path,
            mitre=tech.mitre,
            remediation=tech.remediation,
            evidence={"bindings": sorted(bindings), "roles": sorted(roles)},
            system_expected=_is_system_source(src),
            explanation=explain_path(path),
        )

    # ---- advanced analytics (Wave 2, opt-in) ----------------------------
    @property
    def action_graph(self):
        return self._finder.action_graph

    def advanced_analysis(self, policy=None, audit_events=None,
                          crown_jewels=None) -> dict:
        """Research-grade analytics layered on the escalation graph: blast radius,
        toxic identities, choke points + minimum-change remediation, toxic
        permission combos, security invariants, cloud federation, least-privilege.
        All read-only and computed from the already-built graph."""
        from ksa.analysis import (
            blast_radius, centrality, chokepoints, counterfactual, fragility,
            invariants, leastpriv, token_lineage, toxic,
        )
        from ksa.cloud import identity as cloud_identity
        from ksa import policy as policy_mod

        pol = policy or policy_mod.load()
        jewels = crown_jewels if crown_jewels is not None else pol.crown_jewels
        action = self.action_graph
        findings = self.findings()

        # counterfactual "preventable by one change?" for the top escalating sources
        top_sources = [f.source for f in findings
                       if f.severity in ("critical", "high") and not f.system_expected][:12]
        seen, cf = set(), []
        for s in top_sources:
            if s in seen:
                continue
            seen.add(s)
            cf.append(counterfactual.analyze(s, action))

        out = {
            "blast_radius": [b.to_dict() for b in
                             blast_radius.rank_all(self.snap, self._effective, action, jewels)],
            "toxic_identities": [r.to_dict() for r in centrality.rank_identities(action)],
            "choke_points": [c.to_dict() for c in chokepoints.choke_points(findings)[:15]],
            "min_fix": chokepoints.minimum_fix(findings, {"critical", "high"}),
            "toxic_combinations": [t.to_dict() for t in toxic.detect(self._effective)],
            "invariants": invariants.check(action, pol),
            "cloud_identities": [c.to_dict() for c in cloud_identity.detect(self.snap)],
            "cloud_escalations": cloud_identity.escalations(self.snap, action),
            "fragility": fragility.compute(self.snap, self._effective, action),
            "counterfactual": cf,
            "token_lineage": token_lineage.lineage(self.snap, self._graph)[:20],
        }
        if audit_events is not None:
            out["least_privilege"] = leastpriv.rank_waste(self._effective, audit_events)
        return out

    # ---- exports --------------------------------------------------------
    def scan_result(self, cluster: str = "", audit_path: str | None = None,
                    safe_mode: bool | None = None) -> dict:
        findings = self.findings()
        if safe_mode is None:
            safe_mode = os.environ.get("KSA_SAFE_MODE", "0").lower() in ("1", "true", "yes", "on")
        # runtime correlation: promote matching findings to OBSERVED
        audit = {"events": [], "matches": {}, "observed_count": 0}
        if audit_path:
            from ksa.collector.audit_collector import AuditCollector
            from ksa.correlation import AuditCorrelator
            events = AuditCollector(audit_path).collect(limit=1000)
            if events:
                audit = AuditCorrelator(findings, events).correlate()
                audit["events"] = audit["events"][-60:]  # trim for payload
        audit["log_path"] = audit_path or ""

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev_counts[f.severity] += 1
        non_system = [f for f in findings if not f.system_expected]
        return {
            "cluster": cluster,
            "scanned_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "summary": {
                **self.snap.summary(),
                "graph_nodes": self._graph.number_of_nodes(),
                "graph_edges": self._graph.number_of_edges(),
                "escalation_paths": len(findings),
                "non_system_paths": len(non_system),
                "observed": audit["observed_count"],
                "severity": sev_counts,
            },
            "safety": {
                "safe_mode": safe_mode,
                "read_only": True,            # collector only issues GET/LIST/WATCH
                "mutations": "disabled",      # never creates/patches/deletes
                "secrets": "metadata-only",   # Secret .data is never collected
                "attack_simulation": "disabled" if safe_mode else "lab-only",
            },
            "findings": [f.to_dict() for f in findings],
            "graph": self.export_cytoscape(findings),
            "audit": audit,
        }

    def export_cytoscape(self, findings: list[Finding]) -> dict:
        """Compact escalation subgraph (nodes+action edges on any finding path)."""
        node_ids: set[str] = set()
        edges: list[dict] = []
        seen_edge: set[tuple[str, str, str]] = set()
        for f in findings:
            node_ids.add(f.source)
            for h in f.path.hops:
                node_ids.add(h.src)
                node_ids.add(h.dst)
                key = (h.src, h.dst, h.edge_type)
                if key in seen_edge:
                    continue
                seen_edge.add(key)
                edges.append({"data": {
                    "id": f"e_{len(edges)}", "source": h.src, "target": h.dst,
                    "label": h.edge_type, "cls": _edge_cls(h.edge_type),
                }})
        nodes = [{"data": self._node_data(n)} for n in sorted(node_ids)]
        return {"nodes": nodes, "edges": edges}

    def _node_data(self, nid: str) -> dict:
        attrs = self._graph.nodes.get(nid, {})
        ntype = attrs.get("type", "ServiceAccount")
        label = attrs.get("label", nid)
        # short two-line label ns/name -> "name\nns"
        short = label
        if "/" in label and ntype == "ServiceAccount":
            ns, name = label.split("/", 1)
            short = f"{name}\n{ns}"
        data = {"id": nid, "label": short, "type": ntype}
        if ntype == "ServiceAccount":
            data["automount"] = attrs.get("automount", True)
            data["namespace"] = attrs.get("namespace", "")
            data["permissions"] = self._perm_summary(nid)
            data["bindings"] = sorted(self._effective[nid].via_bindings) if nid in self._effective else []
        return data

    def _perm_summary(self, sa_id: str, limit: int = 8) -> list[dict]:
        eff = self._effective.get(sa_id)
        if not eff:
            return []
        out, seen = [], set()
        danger_verbs = {"create", "bind", "escalate", "impersonate", "patch", "update", "*"}
        danger_res = {"secrets", "pods", "serviceaccounts/token", "*"}
        for p in eff.permissions:
            key = (p.verb, p.resource)
            if key in seen:
                continue
            seen.add(key)
            danger = p.verb in danger_verbs and p.resource in danger_res
            out.append({"text": f"{p.verb} {p.resource}", "danger": danger})
            if len(out) >= limit:
                break
        out.sort(key=lambda x: (not x["danger"]))
        return out
