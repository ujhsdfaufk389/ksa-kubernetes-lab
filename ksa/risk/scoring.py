"""Risk scoring, confidence model, and technique metadata (Parts 13, 25, 35).

Risk score (0-100) answers "how bad is this path", confidence answers "how sure
are we it is real". They are separate dimensions on purpose: a 2-hop path to
cluster-admin is CRITICAL by impact even before we see it exercised, and an audit
match (Phase 10) later raises its *confidence* from REACHABLE to OBSERVED without
changing the impact.

Scoring methodology (thesis-defensible):
    score = impact(sink) * length_factor
        impact         = 100 (cluster-admin) | 90 (node-access)
        length_factor  = max(0.65, 1 - 0.05*(hops-1))   # shorter = easier to exploit
    then a small bonus if the chain uses a direct grant primitive
    (escalate / bind / impersonate), clamped to [0, 100].
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from ksa.graph.graph_queries import EscalationPath
from ksa.graph.relationships import SINK_CLUSTER_ADMIN, EdgeType


class Confidence(IntEnum):
    POSSIBLE = 1     # RBAC would allow the chain
    LIKELY = 2       # all prerequisites (target SA, workloads) exist
    REACHABLE = 3    # graph confirms concrete connectivity of existing objects
    OBSERVED = 4     # audit telemetry shows a hop was exercised
    CONFIRMED = 5    # controlled local validation reproduced it

    @property
    def label(self) -> str:
        return self.name


# base "danger" weight per escalation primitive (used for bonus + ranking)
EDGE_WEIGHT: dict[str, int] = {
    EdgeType.IS_CLUSTER_ADMIN.value: 100,
    EdgeType.CAN_ESCALATE.value: 95,
    EdgeType.CSR_ESCALATE.value: 95,
    EdgeType.CAN_BIND.value: 90,
    EdgeType.IMPERSONATE.value: 90,
    EdgeType.NODE_ACCESS.value: 90,
    EdgeType.PRIVILEGED_WORKLOAD.value: 88,
    EdgeType.CREATE_POD_AS.value: 85,
    EdgeType.REQUEST_TOKEN.value: 85,
    EdgeType.WORKLOAD_HIJACK.value: 80,
    EdgeType.EXEC_INTO.value: 75,
    EdgeType.READ_SECRET_CRED.value: 70,
}

# primitives that are a *direct* grant of privilege (small score bonus)
_DIRECT_GRANT = {EdgeType.CAN_ESCALATE.value, EdgeType.CAN_BIND.value, EdgeType.IMPERSONATE.value}

# exploitability ("ease") per primitive: how trivially an attacker can actually
# perform this step. 1.0 = a single API call with no preconditions; lower means
# it needs a restart, an existing token, etc. The weakest step gates the chain.
EDGE_EASE: dict[str, float] = {
    EdgeType.IS_CLUSTER_ADMIN.value: 1.0,
    EdgeType.CAN_ESCALATE.value: 1.0,
    EdgeType.CSR_ESCALATE.value: 0.92,
    EdgeType.CAN_BIND.value: 1.0,
    EdgeType.IMPERSONATE.value: 1.0,
    EdgeType.NODE_ACCESS.value: 0.98,
    EdgeType.PRIVILEGED_WORKLOAD.value: 0.9,
    EdgeType.CREATE_POD_AS.value: 0.95,
    EdgeType.REQUEST_TOKEN.value: 0.90,
    EdgeType.EXEC_INTO.value: 0.88,
    EdgeType.WORKLOAD_HIJACK.value: 0.85,
    EdgeType.READ_SECRET_CRED.value: 0.80,
}


class Severity(str):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def severity_for(score: int) -> str:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 1:
        return Severity.LOW
    return Severity.INFO


# --- technique registry: primitive -> explainability metadata ---------------
# MITRE IDs verified against the ATT&CK for Containers matrix; re-verify at
# https://attack.mitre.org/matrices/enterprise/containers/ before publication.
@dataclass(frozen=True)
class Technique:
    title: str
    mitre: tuple[str, ...]
    remediation: tuple[str, ...]


TECHNIQUES: dict[str, Technique] = {
    EdgeType.CREATE_POD_AS.value: Technique(
        "ServiceAccount can escalate via workload creation",
        ("T1610 Deploy Container", "T1078 Valid Accounts"),
        ("Remove the source SA from workload-creation bindings in the target namespace",
         "Pin allowed serviceAccountNames with an admission policy (Kyverno/OPA Gatekeeper)",
         "Isolate privileged SAs into namespaces where the source cannot create pods"),
    ),
    EdgeType.WORKLOAD_HIJACK.value: Technique(
        "ServiceAccount can hijack an existing workload's identity",
        ("T1610 Deploy Container", "T1078 Valid Accounts"),
        ("Restrict patch/update on controllers across namespaces",
         "Pin serviceAccountName with an admission policy",
         "Separate deploy RBAC per environment"),
    ),
    EdgeType.REQUEST_TOKEN.value: Technique(
        "ServiceAccount can mint a token for a higher-privileged SA",
        ("T1528 Steal Application Access Token", "T1550.001 Application Access Token"),
        ("Scope serviceaccounts/token to specific resourceNames",
         "Remove token-request permission from the source SA",
         "Use short-lived, audience-bound projected tokens"),
    ),
    EdgeType.IMPERSONATE.value: Technique(
        "ServiceAccount can impersonate a privileged identity",
        ("T1078 Valid Accounts", "T1548 Abuse Elevation Control Mechanism"),
        ("Remove the impersonate verb from the source SA",
         "Constrain impersonation to specific resourceNames",
         "Prefer scoped read-only roles over impersonation"),
    ),
    EdgeType.EXEC_INTO.value: Technique(
        "ServiceAccount can exec into a higher-privileged pod",
        ("T1609 Container Administration Command", "T1078 Valid Accounts"),
        ("Restrict pods/exec, pods/attach to break-glass identities only",
         "Audit and alert on exec into privileged workloads"),
    ),
    EdgeType.READ_SECRET_CRED.value: Technique(
        "ServiceAccount can read a secret holding another SA's token",
        ("T1552.007 Unsecured Credentials: Container API",),
        ("Scope secret reads with resourceNames",
         "Move credentials to an external secret store",
         "Disable legacy ServiceAccount token secrets"),
    ),
    EdgeType.CAN_BIND.value: Technique(
        "ServiceAccount can self-grant any role via the bind verb",
        ("T1098 Account Manipulation", "T1078 Valid Accounts"),
        ("Remove the bind verb unless strictly required",
         "If needed, restrict bind to specific roleRefs via resourceNames"),
    ),
    EdgeType.CAN_ESCALATE.value: Technique(
        "ServiceAccount can add arbitrary rules via the escalate verb",
        ("T1098 Account Manipulation", "T1548 Abuse Elevation Control Mechanism"),
        ("Remove the escalate verb from the source SA",
         "Reserve escalate for trusted controllers only"),
    ),
    EdgeType.NODE_ACCESS.value: Technique(
        "ServiceAccount can reach node-level access",
        ("T1611 Escape to Host",),
        ("Remove nodes/proxy and privileged-pod permissions",
         "Enforce the 'restricted' Pod Security Admission level"),
    ),
    EdgeType.PRIVILEGED_WORKLOAD.value: Technique(
        "ServiceAccount can create a privileged/host pod and escape to the node",
        ("T1611 Escape to Host", "T1610 Deploy Container"),
        ("Enforce the 'restricted' Pod Security Admission level on the namespace",
         "Block privileged, hostPath, hostPID and hostNetwork pods via an admission policy",
         "Remove pod-creation rights from the source SA where not required"),
    ),
    EdgeType.CSR_ESCALATE.value: Technique(
        "ServiceAccount can issue itself a client certificate for any identity",
        ("T1098 Account Manipulation", "T1649 Steal or Forge Authentication Certificates"),
        ("Remove create on certificatesigningrequests and/or update on "
         "certificatesigningrequests/approval from the source SA",
         "Restrict CSR signer approval to a trusted controller only"),
    ),
    EdgeType.IS_CLUSTER_ADMIN.value: Technique(
        "Identity is bound to cluster-admin",
        ("T1078 Valid Accounts",),
        ("Confirm this SA requires cluster-admin; prefer least-privilege roles",),
    ),
}


@dataclass
class Finding:
    """A scored, explainable escalation finding built from one path."""

    id: str
    title: str
    source: str
    target: str
    severity: str
    risk_score: int
    confidence: Confidence
    primitive: str
    path: EscalationPath
    mitre: tuple[str, ...]
    remediation: tuple[str, ...]
    evidence: dict = field(default_factory=dict)
    system_expected: bool = False
    audit_evidence: Optional[dict] = None  # set by the correlator when OBSERVED
    explanation: str = ""  # human-readable "why this is dangerous"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "source": self.source,
            "target": self.target,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": self.confidence.label,
            "primitive": self.primitive,
            "mitre": list(self.mitre),
            "remediation": list(self.remediation),
            "evidence": self.evidence,
            "system_expected": self.system_expected,
            "audit_evidence": self.audit_evidence,
            "explanation": self.explanation or explain_path(self.path),
            "path": self.path.to_dict(),
        }


def _short(nid: str) -> str:
    return nid.split(":", 1)[1] if ":" in nid else nid


def explain_path(path: EscalationPath) -> str:
    """Plain-language 'why is this dangerous' narrative built from the path hops,
    so an analyst never sees only an opaque score (Part 29: explainability)."""
    steps: list[str] = []
    n = 1
    for h in path.hops:
        if h.edge_type == EdgeType.IS_CLUSTER_ADMIN.value:
            steps.append(f"{_short(h.src)} is already bound to a cluster-admin role.")
            continue
        action = h.action or h.edge_type
        steps.append(f"{n}. {_short(h.src)} can {action}, reaching {_short(h.dst)}.")
        n += 1
    goal = ("full cluster-admin control" if path.target == SINK_CLUSTER_ADMIN
            else "node-level access, exposing every pod's token")
    steps.append(f"Net effect: {_short(path.source)} can ultimately obtain {goal}.")
    return " ".join(steps)


def primary_primitive(path: EscalationPath) -> str:
    """The entry technique: first movement edge that isn't just 'already admin'."""
    for hop in path.hops:
        if hop.edge_type != EdgeType.IS_CLUSTER_ADMIN.value:
            return hop.edge_type
    return EdgeType.IS_CLUSTER_ADMIN.value


def score_path(path: EscalationPath) -> int:
    """Blend impact, path-length decay, and the exploitability of the weakest hop.

        score = impact * length_factor * ease(weakest action edge)  (+3 direct grant)
    """
    impact = 100 if path.target == SINK_CLUSTER_ADMIN else 90
    hops = max(1, path.length)
    length_factor = max(0.65, 1 - 0.05 * (hops - 1))
    # the hardest (least easy) step gates the whole chain
    eases = [EDGE_EASE.get(h.edge_type, 0.9) for h in path.hops
             if h.edge_type != EdgeType.IS_CLUSTER_ADMIN.value] or [1.0]
    ease = min(eases)
    score = impact * length_factor * ease
    if any(h.edge_type in _DIRECT_GRANT for h in path.hops):
        score += 3
    return max(0, min(100, round(score)))
