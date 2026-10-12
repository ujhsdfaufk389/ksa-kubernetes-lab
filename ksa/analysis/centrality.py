"""Identity centrality & "toxic identity" ranking (Wave 2, features 7/8).

Graph-theoretic view of *which identities matter most* to an attacker, even if
they are not themselves cluster-admin:

    * privilege distance  - hops from the SA to the nearest sink (shorter = worse)
    * betweenness         - how often the SA sits on others' escalation paths
    * reach-in            - how many other SAs can pivot *into* this SA
    * reaches-admin       - does it have any path to cluster-admin

These combine into a toxicity score so remediation can target the few identities
that dominate the graph.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from ksa.graph.relationships import SINK_CLUSTER_ADMIN, SINK_NODE_ACCESS

_SINKS = (SINK_CLUSTER_ADMIN, SINK_NODE_ACCESS)


@dataclass
class IdentityRank:
    identity: str
    toxicity: int
    privilege_distance: int | None  # None = cannot reach any sink
    reaches_admin: bool
    betweenness: float
    reach_in: int   # how many other SAs can reach this one
    reach_out: int  # how many other SAs this one can reach

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["betweenness"] = round(self.betweenness, 4)
        return d


def _distance_to_sink(action: nx.DiGraph, src: str) -> int | None:
    best: int | None = None
    for sink in _SINKS:
        if sink in action and src in action and nx.has_path(action, src, sink):
            d = nx.shortest_path_length(action, src, sink)
            best = d if best is None else min(best, d)
    return best


def rank_identities(action: nx.DiGraph, limit: int = 20) -> list[IdentityRank]:
    sa_nodes = [n for n in action.nodes if n.startswith("sa:")]
    bet = nx.betweenness_centrality(action) if action.number_of_nodes() else {}

    ranks: list[IdentityRank] = []
    for sa in sa_nodes:
        dist = _distance_to_sink(action, sa)
        reaches_admin = (SINK_CLUSTER_ADMIN in action
                         and nx.has_path(action, sa, SINK_CLUSTER_ADMIN))
        reach_out = sum(1 for n in nx.descendants(action, sa) if n.startswith("sa:"))
        reach_in = sum(1 for n in nx.ancestors(action, sa) if n.startswith("sa:"))
        b = bet.get(sa, 0.0)

        # toxicity: admin-reachable + short distance + central + widely reachable
        score = 0.0
        if reaches_admin:
            score += 45
        if dist is not None:
            score += max(0, 25 - (dist - 1) * 7)      # distance 1 => +25
        score += min(20, b * 120)                      # betweenness
        score += min(10, reach_in * 2)                 # pivot magnet
        ranks.append(IdentityRank(
            identity=sa, toxicity=min(100, round(score)),
            privilege_distance=dist, reaches_admin=reaches_admin,
            betweenness=b, reach_in=reach_in, reach_out=reach_out,
        ))
    ranks.sort(key=lambda r: (-r.toxicity, r.privilege_distance if r.privilege_distance is not None else 99))
    return ranks[:limit]
