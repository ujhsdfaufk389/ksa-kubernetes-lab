"""Risk scoring + severity thresholds."""
from ksa.graph.graph_queries import EscalationPath, Hop
from ksa.graph.relationships import SINK_CLUSTER_ADMIN, SINK_NODE_ACCESS, EdgeType
from ksa.risk.scoring import score_path, severity_for


def _path(edge_types, target=SINK_CLUSTER_ADMIN):
    hops = []
    prev = "sa:dev/src"
    for i, et in enumerate(edge_types):
        dst = target if i == len(edge_types) - 1 else f"sa:ns/n{i}"
        hops.append(Hop(src=prev, dst=dst, edge_type=et, action=""))
        prev = dst
    return EscalationPath(source="sa:dev/src", target=target, hops=hops)


def test_severity_thresholds():
    assert severity_for(95) == "critical"
    assert severity_for(90) == "critical"
    assert severity_for(75) == "high"
    assert severity_for(50) == "medium"
    assert severity_for(10) == "low"
    assert severity_for(0) == "info"


def test_shorter_path_scores_higher():
    short = _path([EdgeType.CREATE_POD_AS.value, EdgeType.IS_CLUSTER_ADMIN.value])
    longer = _path([EdgeType.CREATE_POD_AS.value, EdgeType.CREATE_POD_AS.value,
                    EdgeType.CREATE_POD_AS.value, EdgeType.IS_CLUSTER_ADMIN.value])
    assert score_path(short) > score_path(longer)


def test_weaker_primitive_scores_lower():
    # read-secret (ease .80) should score below create-pod (ease .95) at same length
    strong = _path([EdgeType.CREATE_POD_AS.value, EdgeType.IS_CLUSTER_ADMIN.value])
    weak = _path([EdgeType.READ_SECRET_CRED.value, EdgeType.IS_CLUSTER_ADMIN.value])
    assert score_path(strong) > score_path(weak)


def test_impersonate_is_critical():
    p = _path([EdgeType.IMPERSONATE.value])
    assert score_path(p) >= 90


def test_node_access_impact_lower_than_cluster_admin():
    ca = _path([EdgeType.CREATE_POD_AS.value, EdgeType.IS_CLUSTER_ADMIN.value], SINK_CLUSTER_ADMIN)
    na = _path([EdgeType.CREATE_POD_AS.value], SINK_NODE_ACCESS)
    assert score_path(ca) >= score_path(na)


def test_score_bounded():
    p = _path([EdgeType.CAN_ESCALATE.value])
    assert 0 <= score_path(p) <= 100
