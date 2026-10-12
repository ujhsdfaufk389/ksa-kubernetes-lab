"""Static <-> runtime correlation engine (Part 14).

Matches audit events against the entry primitive of each escalation Finding.
A match promotes the finding's confidence REACHABLE -> OBSERVED and attaches the
audit evidence. This is the project's core differentiator over static-only tools:
a theoretical path becomes an observed attempt.
"""
from __future__ import annotations

import logging

from ksa.collector.audit_collector import AuditEvent
from ksa.graph.relationships import EdgeType
from ksa.risk.scoring import Confidence, Finding

log = logging.getLogger(__name__)

_WORKLOAD_RES = {"pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs"}
_RBAC_RES = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}


def _parts(sa_id: str) -> tuple[str, str]:
    """sa:ns/name -> (ns, name)."""
    body = sa_id.split(":", 1)[1]
    ns, name = body.split("/", 1)
    return ns, name


def _username(sa_id: str) -> str:
    ns, name = _parts(sa_id)
    return f"system:serviceaccount:{ns}:{name}"


class AuditCorrelator:
    def __init__(self, findings: list[Finding], events: list[AuditEvent]) -> None:
        self.findings = findings
        self.events = events

    def correlate(self) -> dict:
        """Promote matching findings to OBSERVED; return an audit summary."""
        matched: dict[str, str] = {}          # finding id -> event ts
        correlated_ts: set[str] = set()
        for f in self.findings:
            ev = self._match(f)
            if ev is not None:
                f.confidence = Confidence.OBSERVED
                f.audit_evidence = {
                    "ts": ev.ts, "verb": ev.verb, "resource": ev.resource,
                    "subresource": ev.subresource, "namespace": ev.namespace,
                    "detail": ev.detail(), "real_user": ev.real_user,
                    "impersonated": ev.impersonated, "source_ips": ev.source_ips,
                }
                matched[f.id] = ev.ts
                correlated_ts.add(ev.ts)
                log.info("Finding %s promoted to OBSERVED (audit %s)", f.id, ev.ts)
        return {
            "events": [self._event_dict(e, correlated_ts, matched) for e in self.events],
            "matches": matched,
            "observed_count": len(matched),
        }

    # ---- per-primitive matchers ----------------------------------------
    def _match(self, f: Finding):
        hop0 = f.path.hops[0] if f.path.hops else None
        if hop0 is None:
            return None
        prim = f.primitive
        if prim in (EdgeType.CREATE_POD_AS.value, EdgeType.WORKLOAD_HIJACK.value):
            return self._match_workload(f, hop0)
        if prim == EdgeType.REQUEST_TOKEN.value:
            return self._match_token(f, hop0)
        if prim == EdgeType.IMPERSONATE.value:
            return self._match_impersonate(f, hop0)
        if prim == EdgeType.READ_SECRET_CRED.value:
            return self._match_secret(f, hop0)
        if prim in (EdgeType.CAN_ESCALATE.value, EdgeType.CAN_BIND.value):
            return self._match_rbac(f)
        return None

    def _match_workload(self, f: Finding, hop0):
        tns, tname = _parts(hop0.dst)
        for e in self.events:
            if (e.actor_sa == f.source and e.verb in {"create", "patch", "update"}
                    and e.resource in _WORKLOAD_RES and e.namespace == tns
                    and e.sa_in_request == tname):
                return e
        return None

    def _match_token(self, f: Finding, hop0):
        tns, tname = _parts(hop0.dst)
        for e in self.events:
            if (e.actor_sa == f.source and e.verb == "create"
                    and e.resource == "serviceaccounts" and e.subresource == "token"
                    and e.name == tname and e.namespace == tns):
                return e
        return None

    def _match_impersonate(self, f: Finding, hop0):
        src_user = _username(f.source)
        target_user = _username(hop0.dst) if hop0.dst.startswith("sa:") else None
        for e in self.events:
            if e.real_user != src_user or not e.impersonated:
                continue
            if e.impersonated == target_user or "system:masters" in (e.impersonated or ""):
                return e
        return None

    def _match_secret(self, f: Finding, hop0):
        for e in self.events:
            if (e.actor_sa == f.source and e.verb in {"get", "list", "watch"}
                    and e.resource == "secrets" and e.namespace == hop0.namespace):
                return e
        return None

    def _match_rbac(self, f: Finding):
        for e in self.events:
            if (e.actor_sa == f.source and e.verb in {"create", "update", "patch"}
                    and e.resource in _RBAC_RES):
                return e
        return None

    # ---- serialization --------------------------------------------------
    @staticmethod
    def _event_dict(e: AuditEvent, correlated_ts, matches) -> dict:
        fid = next((k for k, v in matches.items() if v == e.ts), None)
        return {
            "ts": e.ts,
            "actor": (e.actor_sa or e.real_user).replace("sa:", ""),
            "verb": e.verb,
            "resource": e.resource + (f"/{e.subresource}" if e.subresource else ""),
            "namespace": e.namespace or "—",
            "detail": e.detail(),
            "impersonated": e.impersonated,
            "correlated": fid,   # finding id if this event confirmed a path
        }
