"""Blast-radius calculator (Wave 2, feature 5/41).

"If this ServiceAccount is compromised, how far can the attacker reach?"

We take the set of identities the SA can *become* (reachable over attacker-move
edges), then union everything those identities can touch — namespaces, secrets,
workloads, other SAs, and any crown-jewel / sink — into a single exposure score.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from ksa.graph.relationships import SINK_CLUSTER_ADMIN, SINK_NODE_ACCESS
from ksa.models import ClusterSnapshot
from ksa.permissions import SAEffective


@dataclass
class BlastRadius:
    source: str
    reaches_cluster_admin: bool
    reachable_identities: list[str]
    reachable_namespaces: list[str]
    reachable_secrets: int
    reachable_workloads: int
    crown_jewels_hit: list[str]
    admin_paths: int
    score: int

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _reachable_sas(action: nx.DiGraph, source: str) -> set[str]:
    if source not in action:
        return {source}
    out = {source}
    for n in nx.descendants(action, source):
        if n.startswith("sa:"):
            out.add(n)
    return out


def compute(
    source: str,
    snapshot: ClusterSnapshot,
    effective: dict[str, SAEffective],
    action: nx.DiGraph,
    crown_jewels: set[str] | None = None,
    admin_path_count: int = 0,
) -> BlastRadius:
    crown_jewels = crown_jewels or set()
    identities = _reachable_sas(action, source)
    reached = nx.descendants(action, source) if source in action else set()
    admin = SINK_CLUSTER_ADMIN in reached
    node_access = SINK_NODE_ACCESS in reached

    effs = [effective[i] for i in identities if i in effective]

    # resources any compromised identity can reach
    ns_hit: set[str] = {i.split(":", 1)[1].split("/", 1)[0] for i in identities if ":" in i}
    secrets_hit = 0
    for s in snapshot.secrets:
        if any(e.can("get", "secrets", s.namespace) or e.can("list", "secrets", s.namespace)
               for e in effs):
            secrets_hit += 1
            ns_hit.add(s.namespace)
    workloads_hit = 0
    for w in snapshot.workloads:
        res = w.kind.value.lower() + "s"
        if any(e.can("create", res, w.namespace) or e.can("patch", res, w.namespace)
               or e.can("update", res, w.namespace) for e in effs):
            workloads_hit += 1
            ns_hit.add(w.namespace)

    jewels = sorted(j for j in crown_jewels if j in reached or j in identities)
    if admin:
        jewels = sorted(set(jewels) | {SINK_CLUSTER_ADMIN})

    # score: an admin-reachable SA is maximal; otherwise weight the spread
    if admin:
        score = 100
    else:
        score = min(95, round(
            (node_access * 35)
            + min(25, len(identities) * 5)
            + min(20, secrets_hit * 2)
            + min(10, workloads_hit)
            + min(10, len(ns_hit) * 3)
            + (10 if jewels else 0)
        ))
    return BlastRadius(
        source=source,
        reaches_cluster_admin=admin,
        reachable_identities=sorted(identities - {source}),
        reachable_namespaces=sorted(ns_hit),
        reachable_secrets=secrets_hit,
        reachable_workloads=workloads_hit,
        crown_jewels_hit=jewels,
        admin_paths=admin_path_count,
        score=score,
    )


def rank_all(
    snapshot: ClusterSnapshot,
    effective: dict[str, SAEffective],
    action: nx.DiGraph,
    crown_jewels: set[str] | None = None,
    limit: int = 20,
) -> list[BlastRadius]:
    out = [compute(sa.id, snapshot, effective, action, crown_jewels)
           for sa in snapshot.service_accounts]
    out.sort(key=lambda b: -b.score)
    return out[:limit]
