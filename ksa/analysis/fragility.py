"""Privilege Fragility & Security Margin (Wave 3, features 57/58/59).

Most scanners only tell you the paths that exist *now*. Fragility asks the harder
question: how close is the cluster to disaster?

    * Security margin — the shortest privilege distance among identities that already
      reach a sink (margin 1 = a single step from cluster-admin).
    * Fragile namespaces — namespaces where a privileged (admin-reaching) SA is
      co-located with ordinary SAs, so a SINGLE realistic grant (create pods / token
      / exec) to an ordinary SA would instantly open a new admin path.

This surfaces latent risk a point-in-time path list cannot.
"""
from __future__ import annotations

import networkx as nx

from ksa.graph.relationships import SINK_CLUSTER_ADMIN, SINK_NODE_ACCESS
from ksa.models import ClusterSnapshot

_SINKS = (SINK_CLUSTER_ADMIN, SINK_NODE_ACCESS)
# realistic single grants that would let an ordinary SA take over a co-located SA
_LATERAL = ("create pods", "create serviceaccounts/token", "create pods/exec", "get secrets")


def _reaches_sink(action: nx.DiGraph, sa: str) -> bool:
    return any(s in action and sa in action and nx.has_path(action, sa, s) for s in _SINKS)


def _privilege_distance(action: nx.DiGraph, sa: str) -> int | None:
    best = None
    for s in _SINKS:
        if s in action and sa in action and nx.has_path(action, sa, s):
            d = nx.shortest_path_length(action, sa, s)
            best = d if best is None else min(best, d)
    return best


def compute(snapshot: ClusterSnapshot, effective, action: nx.DiGraph) -> dict:
    sa_ids = [sa.id for sa in snapshot.service_accounts]
    privileged = {s for s in sa_ids if _reaches_sink(action, s)
                  or (s in effective and effective[s].is_cluster_admin())}

    # security margin: shortest distance to a sink among those that reach one
    dists = [d for d in (_privilege_distance(action, s) for s in privileged) if d is not None]
    margin = min(dists) if dists else None

    # fragile namespaces: a privileged SA co-located with ordinary SAs
    by_ns: dict[str, list[str]] = {}
    for sa in snapshot.service_accounts:
        by_ns.setdefault(sa.namespace, []).append(sa.id)

    fragile = []
    exposed_total = 0
    for ns, members in sorted(by_ns.items()):
        priv_here = [m for m in members if m in privileged]
        ordinary = [m for m in members if m not in privileged]
        if priv_here and ordinary:
            exposed_total += len(ordinary)
            fragile.append({
                "namespace": ns,
                "privileged_targets": sorted(priv_here),
                "exposed_sas": sorted(ordinary),
                "one_grant_flips": len(ordinary),
                "example_grants": list(_LATERAL),
            })

    ordinary_total = len([s for s in sa_ids if s not in privileged]) or 1
    # fragility: how much of the non-privileged population is one grant from admin,
    # amplified when the security margin is already tiny.
    base = (exposed_total / ordinary_total) * 100
    if margin == 1:
        base = min(100, base + 25)
    score = min(100, round(base))
    return {
        "fragility_score": score,
        "security_margin": margin,          # None = nothing reaches a sink
        "privileged_identities": len(privileged),
        "exposed_identities": exposed_total,
        "fragile_namespaces": fragile,
    }
