"""Tests for Wave 2 research-grade analytics: blast radius, centrality,
choke-point/min-fix, invariants, what-if, cloud federation, least-privilege,
temporal timeline.
"""
from __future__ import annotations

from ksa.analysis import blast_radius, centrality, chokepoints, invariants, temporal
from ksa.analysis.leastpriv import analyze as lp_analyze
from ksa.analysis.whatif import simulate
from ksa.analyzer import Analyzer
from ksa.cloud import identity as cloud_identity
from ksa.graph.relationships import SINK_CLUSTER_ADMIN
from ksa.models import (
    ClusterSnapshot, Namespace, PolicyRule, Role, RoleBinding, RoleRef,
    ServiceAccount, Subject, SubjectKind,
)
from ksa.permissions import PermissionResolver
from ksa.policy import Invariant, Policy


def _base(priv_is_admin: bool) -> ClusterSnapshot:
    """x/web can create pods in x; x/priv optionally bound to cluster-admin."""
    cadmin = Role(name="cluster-admin", namespace=None,
                  rules=[PolicyRule(verbs=["*"], api_groups=["*"], resources=["*"])])
    podmaker = Role(name="pod-maker", namespace="x",
                    rules=[PolicyRule(verbs=["create"], api_groups=[""], resources=["pods"])])
    web, priv = ServiceAccount(name="web", namespace="x"), ServiceAccount(name="priv", namespace="x")
    bindings = [RoleBinding(name="web-b", namespace="x", role_ref=RoleRef(kind="Role", name="pod-maker"),
                            subjects=[Subject(kind=SubjectKind.SERVICE_ACCOUNT, name="web", namespace="x")])]
    if priv_is_admin:
        bindings.append(RoleBinding(name="priv-admin", namespace=None,
                                    role_ref=RoleRef(kind="ClusterRole", name="cluster-admin"),
                                    subjects=[Subject(kind=SubjectKind.SERVICE_ACCOUNT, name="priv", namespace="x")]))
    return ClusterSnapshot(namespaces=[Namespace(name="x")], service_accounts=[web, priv],
                           roles=[cadmin, podmaker], bindings=bindings)


def _candidate_make_priv_admin() -> ClusterSnapshot:
    return ClusterSnapshot(bindings=[RoleBinding(
        name="priv-admin", namespace=None, role_ref=RoleRef(kind="ClusterRole", name="cluster-admin"),
        subjects=[Subject(kind=SubjectKind.SERVICE_ACCOUNT, name="priv", namespace="x")])])


def test_blast_radius_admin_reach_is_maximal():
    snap = _base(priv_is_admin=True)
    an = Analyzer(snap)
    br = blast_radius.compute("sa:x/web", snap, an._effective, an.action_graph)
    assert br.reaches_cluster_admin and br.score == 100
    assert "sa:x/priv" in br.reachable_identities


def test_centrality_flags_admin_reachers():
    snap = _base(priv_is_admin=True)
    ranks = centrality.rank_identities(Analyzer(snap).action_graph)
    web = next(r for r in ranks if r.identity == "sa:x/web")
    assert web.reaches_admin and web.privilege_distance == 2  # web -> priv -> sink


def test_chokepoint_min_fix_breaks_all():
    snap = _base(priv_is_admin=True)
    findings = Analyzer(snap).findings()
    mf = chokepoints.minimum_fix(findings)
    assert mf["targeted_paths"] >= 1 and mf["paths_after"] == 0 and mf["fix_count"] >= 1


def test_invariant_violation_detected():
    snap = _base(priv_is_admin=True)
    pol = Policy(invariants=[Invariant(id="no-x-admin", description="no x SA to admin",
                                       forbid_reach=SINK_CLUSTER_ADMIN, source_namespace="x")])
    res = invariants.check(Analyzer(snap).action_graph, pol)
    assert res["failed"] == 1
    assert "sa:x/web" in res["results"][0]["violations"]


def test_whatif_denies_change_that_creates_critical_path():
    base = _base(priv_is_admin=False)
    assert Analyzer(base).findings() == []  # no escalation yet
    r = simulate(base, _candidate_make_priv_admin())
    assert r["verdict"] == "DENY"
    assert r["counts"]["new_critical"] >= 1
    assert any(f["source"] == "sa:x/web" for f in r["new_paths"])


def test_cloud_federation_detected_and_pivotable():
    snap = _base(priv_is_admin=False)
    # annotate priv with an AWS IRSA role; web can take over priv via create-pod-as
    priv = next(s for s in snap.service_accounts if s.name == "priv")
    priv.annotations = {"eks.amazonaws.com/role-arn": "arn:aws:iam::111:role/admin"}
    ids = cloud_identity.detect(snap)
    assert ids and ids[0].provider == "aws"
    esc = cloud_identity.escalations(snap, Analyzer(snap).action_graph)
    assert any(e["source"] == "sa:x/web" and e["pivots_to"] == "sa:x/priv" for e in esc)


def test_least_privilege_waste():
    snap = _base(priv_is_admin=False)
    eff = PermissionResolver(snap).resolve_all()["sa:x/web"]

    class _Ev:  # minimal audit event stand-in
        def __init__(self, verb, resource):
            self.actor_sa, self.verb, self.resource, self.subresource = "sa:x/web", verb, resource, None

    lp = lp_analyze("sa:x/web", eff, [_Ev("create", "pods")])
    assert ("create", "pods") in lp.used
    assert lp.waste_ratio == 0.0  # granted create pods, used create pods
    lp2 = lp_analyze("sa:x/web", eff, [])  # never used
    assert lp2.dormant and lp2.waste_ratio == 1.0


def test_fragility_colocated_privileged_sa():
    from ksa.analysis import fragility
    # ns y: 'boss' is cluster-admin, 'peon' has no permissions (cannot reach admin)
    cadmin = Role(name="cluster-admin", namespace=None,
                  rules=[PolicyRule(verbs=["*"], api_groups=["*"], resources=["*"])])
    boss, peon = ServiceAccount(name="boss", namespace="y"), ServiceAccount(name="peon", namespace="y")
    snap = ClusterSnapshot(
        namespaces=[Namespace(name="y")], service_accounts=[boss, peon], roles=[cadmin],
        bindings=[RoleBinding(name="boss-admin", namespace=None,
                              role_ref=RoleRef(kind="ClusterRole", name="cluster-admin"),
                              subjects=[Subject(kind=SubjectKind.SERVICE_ACCOUNT, name="boss", namespace="y")])],
    )
    an = Analyzer(snap)
    fr = fragility.compute(snap, an._effective, an.action_graph)
    assert fr["security_margin"] == 1          # boss is one step from sink
    assert fr["exposed_identities"] == 1       # peon co-located with privileged boss
    assert fr["fragility_score"] == 100
    assert fr["fragile_namespaces"][0]["namespace"] == "y"


def test_counterfactual_single_change_prevention():
    from ksa.analysis import counterfactual
    snap = _base(priv_is_admin=True)
    r = counterfactual.analyze("sa:x/web", Analyzer(snap).action_graph)
    assert r["reaches_sink"] and r["preventable_by_one_change"]
    assert any(f["remove_primitive"] == "CREATE_POD_AS" and f["from"] == "sa:x/web"
               for f in r["single_change_fixes"])


def test_token_lineage_obtainable_by():
    from ksa.analysis import token_lineage
    snap = _base(priv_is_admin=True)
    an = Analyzer(snap)
    tl = {t["sa"]: t for t in token_lineage.lineage(snap, an._graph)}
    priv = tl["sa:x/priv"]
    assert any(o["identity"] == "sa:x/web" for o in priv["obtainable_by"])


def test_temporal_timeline(tmp_path):
    from ksa.drift import write_snapshot
    write_snapshot({"scanned_at": "2026-10-01T10:00:00",
                    "findings": [{"source": "sa:x/a", "target": "sink:cluster-admin", "primitive": "CAN_BIND",
                                  "severity": "critical", "confidence": "REACHABLE"}]}, tmp_path)
    write_snapshot({"scanned_at": "2026-10-01T11:00:00",
                    "findings": [{"source": "sa:x/a", "target": "sink:cluster-admin", "primitive": "CAN_BIND",
                                  "severity": "critical", "confidence": "REACHABLE"},
                                 {"source": "sa:x/b", "target": "sink:cluster-admin", "primitive": "CREATE_POD_AS",
                                  "severity": "critical", "confidence": "REACHABLE"}]}, tmp_path)
    t = temporal.timeline(tmp_path)
    assert t["count"] == 2 and len(t["paths"]) == 2
    new = temporal.became_exploitable(tmp_path)
    assert len(new) == 1 and new[0]["source"] == "sa:x/b"
