"""Kubernetes audit-log collection (Part 15).

Parses the API-server audit log (JSON lines) into typed AuditEvent objects that
the correlation engine matches against graph paths. Only escalation-relevant
events are kept; Secret *values* never appear in the audit stream (our policy
logs secret access at Metadata level only).

The 'effective actor' of an event is the impersonated identity when present
(so `kubectl --as=system:serviceaccount:...` — our safe attack simulation — is
attributed to the ServiceAccount it acted as), otherwise the authenticated user.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

log = logging.getLogger(__name__)

_SA_PREFIX = "system:serviceaccount:"

# resources whose events matter for escalation correlation
_INTERESTING = {
    "pods", "deployments", "daemonsets", "statefulsets", "replicasets",
    "jobs", "cronjobs", "serviceaccounts", "secrets",
    "roles", "clusterroles", "rolebindings", "clusterrolebindings",
}


def _sa_id(username: Optional[str]) -> Optional[str]:
    """system:serviceaccount:<ns>:<name> -> sa:<ns>/<name> (else None)."""
    if username and username.startswith(_SA_PREFIX):
        rest = username[len(_SA_PREFIX):]
        if ":" in rest:
            ns, name = rest.split(":", 1)
            return f"sa:{ns}/{name}"
    return None


def _sa_in_request(req: dict) -> Optional[str]:
    """Extract spec.serviceAccountName from a pod/workload requestObject."""
    if not isinstance(req, dict):
        return None
    spec = req.get("spec", {}) or {}
    # controllers nest the pod under spec.template.spec / jobTemplate...
    for path in (spec, spec.get("template", {}).get("spec", {}) if isinstance(spec.get("template"), dict) else {}):
        if isinstance(path, dict):
            sa = path.get("serviceAccountName") or path.get("serviceAccount")
            if sa:
                return sa
    return None


@dataclass
class AuditEvent:
    ts: str
    verb: str
    resource: str
    subresource: Optional[str]
    namespace: Optional[str]
    name: Optional[str]
    api_group: str
    real_user: str                       # authenticated principal
    impersonated: Optional[str]          # identity acted-as, if any
    actor_sa: Optional[str]              # effective actor as sa:ns/name (or None)
    sa_in_request: Optional[str]         # serviceAccountName chosen in the request
    code: Optional[int]
    source_ips: list[str] = field(default_factory=list)

    @property
    def effective_user(self) -> str:
        return self.impersonated or self.real_user

    def detail(self) -> str:
        if self.sa_in_request:
            return f"serviceAccountName={self.sa_in_request}"
        if self.subresource:
            return f"{self.resource}/{self.subresource} {self.name or ''}".strip()
        return self.name or "—"


class AuditCollector:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def collect(self, limit: Optional[int] = None) -> list[AuditEvent]:
        if not self.path.exists():
            log.warning("Audit log not found: %s", self.path)
            return []
        events = list(self._iter())
        if limit:
            events = events[-limit:]
        log.info("Parsed %d escalation-relevant audit events from %s", len(events), self.path)
        return events

    def _iter(self) -> Iterator[AuditEvent]:
        with self.path.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("kind") != "Event":
                    continue
                obj = e.get("objectRef", {}) or {}
                resource = obj.get("resource")
                if resource not in _INTERESTING:
                    continue
                user = (e.get("user", {}) or {}).get("username", "")
                imp_obj = e.get("impersonatedUser") or {}
                impersonated = imp_obj.get("username")
                # impersonated groups (e.g. system:masters) matter for IMPERSONATE
                imp_groups = imp_obj.get("groups") or []
                if not impersonated and imp_groups:
                    impersonated = ",".join(imp_groups)
                actor_sa = _sa_id(impersonated) or _sa_id(user)
                yield AuditEvent(
                    ts=e.get("requestReceivedTimestamp") or e.get("stageTimestamp", ""),
                    verb=e.get("verb", ""),
                    resource=resource,
                    subresource=obj.get("subresource"),
                    namespace=obj.get("namespace"),
                    name=obj.get("name"),
                    api_group=obj.get("apiGroup", "") or "",
                    real_user=user,
                    impersonated=(imp_obj.get("username")),
                    actor_sa=actor_sa,
                    sa_in_request=_sa_in_request(e.get("requestObject", {})),
                    code=(e.get("responseStatus", {}) or {}).get("code"),
                    source_ips=list(e.get("sourceIPs", []) or []),
                )
