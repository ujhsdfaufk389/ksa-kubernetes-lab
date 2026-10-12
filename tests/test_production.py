"""Tests for the production-hardening features (Wave 1):
aggregated ClusterRoles, new escalation primitives (CSR, privileged workload),
explainability, safe-mode/secret-safe guarantees, and attack-path drift.
"""
from __future__ import annotations

from ksa.analyzer import Analyzer
from ksa.drift import diff
from ksa.graph.relationships import EdgeType
from ksa.models import (
    ClusterSnapshot,
    Namespace,
    PolicyRule,
    Role,
    RoleBinding,
    RoleRef,
    ServiceAccount,
    Subject,
    SubjectKind,
)
from ksa.permissions import PermissionResolver


def _sa(ns, name):
    return ServiceAccount(name=name, namespace=ns)


def _crb(name, role, sa):
    return RoleBinding(
        name=name, namespace=None, role_ref=RoleRef(kind="ClusterRole", name=role),
        subjects=[Subject(kind=SubjectKind.SERVICE_ACCOUNT, name=sa.name, namespace=sa.namespace)],
    )


# ---- aggregated ClusterRole resolution --------------------------------------
def test_aggregated_clusterrole_inherits_matching_rules():
    contributor = Role(
        name="contributor", namespace=None,
        labels={"rbac.authorization.k8s.io/aggregate-to-ops": "true"},
        rules=[PolicyRule(verbs=["get"], api_groups=[""], resources=["secrets"])],
    )
    ops = Role(  # aggregated: no own rules, selects the label above
        name="ops", namespace=None,
        aggregation_selectors=[{"rbac.authorization.k8s.io/aggregate-to-ops": "true"}],
    )
    sa = _sa("dev", "ops-sa")
    snap = ClusterSnapshot(
        namespaces=[Namespace(name="dev")], service_accounts=[sa],
        roles=[contributor, ops], bindings=[_crb("ops-b", "ops", sa)],
    )
    eff = PermissionResolver(snap).resolve_all()[sa.id]
    assert eff.can("get", "secrets", "dev"), "aggregated role should inherit contributor's rule"


# ---- new primitive: CSR create + approve -> cluster-admin --------------------
def test_csr_create_and_approve_is_escalation():
    role = Role(
        name="csr-admin", namespace=None,
        rules=[
            PolicyRule(verbs=["create"], api_groups=["certificates.k8s.io"],
                       resources=["certificatesigningrequests"]),
            PolicyRule(verbs=["update"], api_groups=["certificates.k8s.io"],
                       resources=["certificatesigningrequests/approval"]),
        ],
    )
    sa = _sa("dev", "csr-sa")
    snap = ClusterSnapshot(
        namespaces=[Namespace(name="dev")], service_accounts=[sa],
        roles=[role], bindings=[_crb("csr-b", "csr-admin", sa)],
    )
    findings = Analyzer(snap).findings()
    prims = {f.primitive for f in findings}
    assert EdgeType.CSR_ESCALATE.value in prims


def test_csr_create_without_approve_is_not_escalation():
    role = Role(
        name="csr-only", namespace=None,
        rules=[PolicyRule(verbs=["create"], api_groups=["certificates.k8s.io"],
                          resources=["certificatesigningrequests"])],
    )
    sa = _sa("dev", "csr-sa")
    snap = ClusterSnapshot(
        namespaces=[Namespace(name="dev")], service_accounts=[sa],
        roles=[role], bindings=[_crb("csr-b", "csr-only", sa)],
    )
    prims = {f.primitive for f in Analyzer(snap).findings()}
    assert EdgeType.CSR_ESCALATE.value not in prims


# ---- new primitive: privileged workload only where PSA permits it ------------
def test_privileged_workload_fires_only_when_psa_privileged():
    role = Role(name="pod-maker", namespace=None,
                rules=[PolicyRule(verbs=["create"], api_groups=[""], resources=["pods"])])
    sa = _sa("lab", "maker")

    def build(enforce):
        snap = ClusterSnapshot(
            namespaces=[Namespace(name="lab", pod_security_enforce=enforce)],
            service_accounts=[sa], roles=[role], bindings=[_crb("b", "pod-maker", sa)],
        )
        return {f.primitive for f in Analyzer(snap).findings()}

    assert EdgeType.PRIVILEGED_WORKLOAD.value in build("privileged")
    assert EdgeType.PRIVILEGED_WORKLOAD.value not in build("restricted")
    assert EdgeType.PRIVILEGED_WORKLOAD.value not in build(None)


# ---- explainability ----------------------------------------------------------
def test_findings_have_explanation(findings):
    assert findings, "fixture should produce findings"
    f = findings[0]
    assert f.explanation and f.source.split(":", 1)[1] in f.explanation
    assert "obtain" in f.explanation


# ---- safe-mode + secret-safe guarantees -------------------------------------
def test_scan_result_safety_block(snapshot):
    res = Analyzer(snapshot).scan_result(cluster="test", safe_mode=True)
    safety = res["safety"]
    assert safety["safe_mode"] is True
    assert safety["read_only"] is True
    assert safety["secrets"] == "metadata-only"
    assert safety["attack_simulation"] == "disabled"


def test_secret_model_never_holds_values():
    from ksa.models import Secret
    assert not hasattr(Secret(name="x", namespace="dev"), "data")


# ---- drift / attack-path diff -----------------------------------------------
def test_diff_detects_new_and_removed_paths():
    prev = {"scanned_at": "t0", "findings": [
        {"source": "sa:dev/a", "target": "sink:cluster-admin", "primitive": "CAN_BIND",
         "severity": "critical", "confidence": "REACHABLE"},
    ]}
    curr = {"scanned_at": "t1", "findings": [
        {"source": "sa:dev/b", "target": "sink:cluster-admin", "primitive": "CREATE_POD_AS",
         "severity": "critical", "confidence": "REACHABLE"},
    ]}
    d = diff(prev, curr)
    assert d["counts"]["new"] == 1 and d["counts"]["removed"] == 1
    assert d["new_paths"][0]["source"] == "sa:dev/b"
    assert d["removed_paths"][0]["source"] == "sa:dev/a"
