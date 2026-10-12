"""Path engine (Part 12): find and explain multi-hop escalation paths.

Only *escalation-action* edges are traversed as attacker steps; structural edges
(BOUND_TO / GRANTS / RUNS_AS / LOCATED_IN) describe how RBAC is wired and are not
themselves attacker moves, so we search over an action-only view of the graph.

Each returned EscalationPath lists its hops (with the action + evidence) so the
finding is explainable end to end.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import islice

import networkx as nx

from ksa.graph.relationships import (
    SINK_CLUSTER_ADMIN,
    SINK_NODE_ACCESS,
    EdgeType,
)

# Edges that represent a real attacker step (one hop each).
ACTION_EDGES = {
    EdgeType.CREATE_POD_AS.value,
    EdgeType.WORKLOAD_HIJACK.value,
    EdgeType.REQUEST_TOKEN.value,
    EdgeType.IMPERSONATE.value,
    EdgeType.EXEC_INTO.value,
    EdgeType.READ_SECRET_CRED.value,
    EdgeType.CAN_BIND.value,
    EdgeType.CAN_ESCALATE.value,
    EdgeType.IS_CLUSTER_ADMIN.value,
    EdgeType.NODE_ACCESS.value,
    EdgeType.PRIVILEGED_WORKLOAD.value,
    EdgeType.CSR_ESCALATE.value,
}

DEFAULT_SINKS = (SINK_CLUSTER_ADMIN, SINK_NODE_ACCESS)


@dataclass
class Hop:
    src: str
    dst: str
    edge_type: str
    action: str
    namespace: str | None = None
    evidence: dict = field(default_factory=dict)

    def render(self) -> str:
        loc = f" @{self.namespace}" if self.namespace else ""
        return f"--[{self.edge_type}{loc}]--> {self.dst}"


@dataclass
class EscalationPath:
    source: str
    target: str
    hops: list[Hop]

    @property
    def length(self) -> int:
        return len(self.hops)

    def render(self) -> str:
        lines = [self.source]
        for h in self.hops:
            lines.append(f"   {h.render()}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "length": self.length,
            "hops": [
                {
                    "from": h.src,
                    "to": h.dst,
                    "type": h.edge_type,
                    "action": h.action,
                    "namespace": h.namespace,
                    "evidence": h.evidence,
                }
                for h in self.hops
            ],
        }


class PathFinder:
    def __init__(self, graph: nx.MultiDiGraph, max_hops: int = 8) -> None:
        self.g = graph
        self.max_hops = max_hops
        # action-only DiGraph view (collapse multi-edges; keep one attrs dict)
        self._action = nx.DiGraph()
        for u, v, k, data in graph.edges(keys=True, data=True):
            if data.get("type") in ACTION_EDGES and not self._action.has_edge(u, v):
                self._action.add_edge(u, v, **data)

    @property
    def action_graph(self) -> nx.DiGraph:
        """The attacker-move-only view (one edge per src->dst), for reachability
        analytics (blast radius, centrality, choke points)."""
        return self._action

    def sources(self) -> list[str]:
        """ServiceAccount nodes that could be an attacker's starting identity."""
        return [
            n for n, d in self.g.nodes(data=True) if d.get("type") == "ServiceAccount"
        ]

    def find_from(
        self, source: str, sinks: tuple[str, ...] = DEFAULT_SINKS, max_paths: int = 5
    ) -> list[EscalationPath]:
        """Find escalation paths from one source SA to any sink."""
        if source not in self._action:
            return []
        results: list[EscalationPath] = []
        for sink in sinks:
            if sink not in self._action or not nx.has_path(self._action, source, sink):
                continue
            # shortest_simple_paths yields SHORTEST-first (Yen's algorithm), so the
            # most direct escalation routes are found even with a small max_paths.
            for node_path in islice(
                nx.shortest_simple_paths(self._action, source, sink), max_paths
            ):
                if len(node_path) - 1 > self.max_hops:
                    break  # remaining paths are only longer
                results.append(self._to_escalation_path(source, sink, node_path))
        # shortest / most direct first
        results.sort(key=lambda p: p.length)
        return results

    def find_all(
        self, sinks: tuple[str, ...] = DEFAULT_SINKS, max_paths_per_source: int = 3
    ) -> dict[str, list[EscalationPath]]:
        out: dict[str, list[EscalationPath]] = {}
        for src in self.sources():
            paths = self.find_from(src, sinks, max_paths=max_paths_per_source)
            if paths:
                out[src] = paths
        return out

    def _to_escalation_path(self, source: str, target: str, node_path: list[str]) -> EscalationPath:
        hops: list[Hop] = []
        for u, v in zip(node_path, node_path[1:]):
            data = self._action.get_edge_data(u, v) or {}
            hops.append(
                Hop(
                    src=u,
                    dst=v,
                    edge_type=data.get("type", "?"),
                    action=data.get("action", ""),
                    namespace=data.get("namespace"),
                    evidence=data.get("evidence", {}),
                )
            )
        return EscalationPath(source=source, target=target, hops=hops)
