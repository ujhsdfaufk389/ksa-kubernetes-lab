"""Graph construction: nodes, structural + escalation edges."""
from ksa.graph.relationships import SINK_CLUSTER_ADMIN, EdgeType


def _edge_types(graph, src, dst):
    data = graph.get_edge_data(src, dst) or {}
    return {d["type"] for d in data.values()}


def test_sink_node_exists(graph):
    assert SINK_CLUSTER_ADMIN in graph
    assert graph.nodes[SINK_CLUSTER_ADMIN]["type"] == "Sink"


def test_service_account_nodes(graph):
    assert "sa:dev/web-sa" in graph
    assert graph.nodes["sa:dev/web-sa"]["type"] == "ServiceAccount"


def test_create_pod_as_edge(graph):
    # web-sa can create pods in production -> edge to admin-sa there
    assert EdgeType.CREATE_POD_AS.value in _edge_types(graph, "sa:dev/web-sa", "sa:production/admin-sa")


def test_admin_reaches_sink(graph):
    assert EdgeType.IS_CLUSTER_ADMIN.value in _edge_types(graph, "sa:production/admin-sa", SINK_CLUSTER_ADMIN)


def test_guest_has_no_escalation_edge(graph):
    # guest-sa is read-only; it should have no outgoing escalation action edges
    out = list(graph.out_edges("sa:dev/guest-sa", data=True))
    action_like = [e for e in out if e[2]["type"] != EdgeType.BOUND_TO.value]
    assert action_like == []
