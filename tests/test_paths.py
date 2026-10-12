"""Path engine + finding generation: true positives and no false positives."""
from ksa.graph.relationships import EdgeType


def _by_source(findings):
    return {f.source: f for f in findings}


def test_web_sa_finding_detected(findings):
    f = _by_source(findings).get("sa:dev/web-sa")
    assert f is not None
    assert f.primitive == EdgeType.CREATE_POD_AS.value
    assert f.severity == "critical"
    assert f.target == "sink:cluster-admin"


def test_wildcard_sa_detected(findings):
    assert "sa:production/wild-sa" in _by_source(findings)


def test_guest_sa_no_finding(findings):
    # benign read-only SA must not produce an escalation finding
    assert "sa:dev/guest-sa" not in _by_source(findings)


def test_admin_sa_not_a_source(findings):
    # an identity that is ALREADY cluster-admin is not "escalating"
    assert "sa:production/admin-sa" not in _by_source(findings)


def test_path_is_explainable(findings):
    f = _by_source(findings)["sa:dev/web-sa"]
    assert f.path.length >= 2
    assert all(h.edge_type for h in f.path.hops)
    assert f.mitre  # has MITRE mapping
    assert f.remediation  # has remediation


def test_shortest_path_selected(findings):
    # web-sa -> admin-sa -> sink is 2 hops; ensure we didn't pick a longer route
    f = _by_source(findings)["sa:dev/web-sa"]
    assert f.path.length == 2
