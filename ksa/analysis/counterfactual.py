"""Counterfactual incident analysis (Wave 3, feature 10).

Answers "was this preventable by a single RBAC change?" and "which change?".

For a source identity that reaches a sink, we remove — one at a time — each
removable unit (source, primitive) that lies on its paths, then re-check whether
the source can STILL reach any sink. A unit whose removal fully contains the source
is a single-change prevention; if none does, containment needs multiple changes.
"""
from __future__ import annotations

import networkx as nx

from ksa.graph.relationships import SINK_CLUSTER_ADMIN, SINK_NODE_ACCESS, EdgeType

_SINKS = (SINK_CLUSTER_ADMIN, SINK_NODE_ACCESS)
_IGNORE = {EdgeType.IS_CLUSTER_ADMIN.value}


def _reaches_any_sink(g: nx.DiGraph, src: str) -> bool:
    return any(s in g and src in g and nx.has_path(g, src, s) for s in _SINKS)


def _units_on_paths(action: nx.DiGraph, src: str) -> set[tuple[str, str]]:
    """(node, primitive) units reachable from src that lie on a route to a sink."""
    units: set[tuple[str, str]] = set()
    reachable = nx.descendants(action, src) | {src}
    for u, v, data in action.edges(data=True):
        if u in reachable and data.get("type") not in _IGNORE:
            # only keep edges that can still lead to a sink
            if any(s in action and nx.has_path(action, v, s) for s in _SINKS) or v in _SINKS:
                units.add((u, data.get("type")))
    return units


def analyze(source: str, action: nx.DiGraph) -> dict:
    if not _reaches_any_sink(action, source):
        return {"source": source, "reaches_sink": False, "single_change_fixes": [],
                "preventable_by_one_change": False, "candidates_tested": 0}

    fixes = []
    for (node, prim) in sorted(_units_on_paths(action, source)):
        g = action.copy()
        g.remove_edges_from([(u, v) for u, v, d in action.edges(data=True)
                             if u == node and d.get("type") == prim])
        if not _reaches_any_sink(g, source):
            fixes.append({"remove_primitive": prim, "from": node})
    return {
        "source": source,
        "reaches_sink": True,
        "preventable_by_one_change": bool(fixes),
        "single_change_fixes": fixes,
        "candidates_tested": len(_units_on_paths(action, source)),
    }
