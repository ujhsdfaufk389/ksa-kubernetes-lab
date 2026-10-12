"""Token lineage graph (Wave 3, feature 2).

The genealogy of a ServiceAccount's credential, from static cluster state:

    ServiceAccount
      ├─ token secrets that hold its credential   (theft surface)
      ├─ workloads that run as it (mount its token) (where the token lives)
      └─ identities that can MINT or READ its token (who can assume it)

The runtime leg (process → token file → API call) needs node eBPF telemetry and is
intentionally out of scope here; this is the static credential-exposure view.
"""
from __future__ import annotations

import networkx as nx

from ksa.graph.relationships import EdgeType
from ksa.models import ClusterSnapshot

# edges by which another identity obtains THIS SA's token
_OBTAIN = {EdgeType.REQUEST_TOKEN.value, EdgeType.READ_SECRET_CRED.value,
           EdgeType.CREATE_POD_AS.value, EdgeType.WORKLOAD_HIJACK.value,
           EdgeType.EXEC_INTO.value}


def lineage(snapshot: ClusterSnapshot, graph: nx.MultiDiGraph) -> list[dict]:
    secrets_by_sa: dict[str, list[str]] = {}
    for s in snapshot.secrets:
        if s.service_account_name:
            secrets_by_sa.setdefault(f"sa:{s.namespace}/{s.service_account_name}", []).append(s.id)
    workloads_by_sa: dict[str, list[str]] = {}
    for w in snapshot.workloads:
        workloads_by_sa.setdefault(f"sa:{w.namespace}/{w.service_account_name}", []).append(w.id)

    out = []
    for sa in snapshot.service_accounts:
        obtainers = []
        for u, v, data in graph.in_edges(sa.id, data=True):
            if data.get("type") in _OBTAIN and u.startswith("sa:") and u != sa.id:
                obtainers.append({"identity": u, "via": data.get("type")})
        out.append({
            "sa": sa.id,
            "automount": sa.automount_token,
            "token_secrets": sorted(secrets_by_sa.get(sa.id, [])),
            "workloads": sorted(workloads_by_sa.get(sa.id, [])),
            "obtainable_by": sorted(obtainers, key=lambda o: o["identity"]),
            "theft_surface": len(secrets_by_sa.get(sa.id, [])) + len(obtainers),
        })
    out.sort(key=lambda l: -l["theft_surface"])
    return out
