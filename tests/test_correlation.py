"""Audit correlation: matching events promote findings to OBSERVED."""
from ksa.collector.audit_collector import AuditEvent
from ksa.correlation import AuditCorrelator
from ksa.graph.graph_queries import EscalationPath, Hop
from ksa.graph.relationships import SINK_CLUSTER_ADMIN, EdgeType
from ksa.risk.scoring import Confidence, Finding


def _finding(primitive, source, target_dst):
    hop = Hop(src=source, dst=target_dst, edge_type=primitive, action="", namespace="production")
    hop2 = Hop(src=target_dst, dst=SINK_CLUSTER_ADMIN, edge_type=EdgeType.IS_CLUSTER_ADMIN.value, action="")
    path = EscalationPath(source=source, target=SINK_CLUSTER_ADMIN, hops=[hop, hop2])
    return Finding(id="KSA-PE-001", title="t", source=source, target=SINK_CLUSTER_ADMIN,
                   severity="critical", risk_score=90, confidence=Confidence.REACHABLE,
                   primitive=primitive, path=path, mitre=(), remediation=())


def _pod_event(actor="sa:dev/web-sa", sa_in_request="admin-sa", ns="production"):
    return AuditEvent(ts="2026-09-30T10:00:00Z", verb="create", resource="pods",
                      subresource=None, namespace=ns, name="x", api_group="",
                      real_user="kubernetes-admin", impersonated="system:serviceaccount:dev:web-sa",
                      actor_sa=actor, sa_in_request=sa_in_request, code=201)


def test_matching_event_promotes_to_observed():
    f = _finding(EdgeType.CREATE_POD_AS.value, "sa:dev/web-sa", "sa:production/admin-sa")
    summary = AuditCorrelator([f], [_pod_event()]).correlate()
    assert f.confidence == Confidence.OBSERVED
    assert f.audit_evidence is not None
    assert summary["observed_count"] == 1


def test_wrong_sa_does_not_match():
    f = _finding(EdgeType.CREATE_POD_AS.value, "sa:dev/web-sa", "sa:production/admin-sa")
    # pod created as a DIFFERENT SA -> no match
    AuditCorrelator([f], [_pod_event(sa_in_request="other-sa")]).correlate()
    assert f.confidence == Confidence.REACHABLE


def test_wrong_actor_does_not_match():
    f = _finding(EdgeType.CREATE_POD_AS.value, "sa:dev/web-sa", "sa:production/admin-sa")
    AuditCorrelator([f], [_pod_event(actor="sa:dev/someone-else")]).correlate()
    assert f.confidence == Confidence.REACHABLE


def test_token_request_correlation():
    f = _finding(EdgeType.REQUEST_TOKEN.value, "sa:production/backup-sa", "sa:production/admin-sa")
    ev = AuditEvent(ts="t", verb="create", resource="serviceaccounts", subresource="token",
                    namespace="production", name="admin-sa", api_group="",
                    real_user="ka", impersonated="system:serviceaccount:production:backup-sa",
                    actor_sa="sa:production/backup-sa", sa_in_request=None, code=201)
    AuditCorrelator([f], [ev]).correlate()
    assert f.confidence == Confidence.OBSERVED
