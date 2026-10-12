"""Kubernetes -> Cloud IAM federation (Wave 2, features 2/11).

Workload-identity annotations tie a Kubernetes ServiceAccount to a cloud IAM
identity (AWS IRSA, GCP Workload Identity, Azure Workload Identity). That means a
Kubernetes privilege-escalation path that lets an attacker *become* such an SA
also hands them the SA's cloud role — a Kubernetes-to-cloud escalation.

This module reads those annotations (no cloud API calls, fully offline) and, given
the escalation action-graph, reports which identities can reach a cloud-bound SA.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from ksa.models import ClusterSnapshot

# annotation/label keys that bind a K8s SA to a cloud identity
_AWS = "eks.amazonaws.com/role-arn"
_GCP = "iam.gke.io/gcp-service-account"
_AZURE = "azure.workload.identity/client-id"


@dataclass
class CloudIdentity:
    sa: str            # sa:ns/name
    provider: str      # aws | gcp | azure
    cloud_ref: str     # role ARN / GCP SA email / Azure client id

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def detect(snapshot: ClusterSnapshot) -> list[CloudIdentity]:
    out: list[CloudIdentity] = []
    for sa in snapshot.service_accounts:
        a = sa.annotations or {}
        if _AWS in a:
            out.append(CloudIdentity(sa.id, "aws", a[_AWS]))
        if _GCP in a:
            out.append(CloudIdentity(sa.id, "gcp", a[_GCP]))
        if _AZURE in a:
            out.append(CloudIdentity(sa.id, "azure", a[_AZURE]))
    return out


def escalations(snapshot: ClusterSnapshot, action: nx.DiGraph) -> list[dict]:
    """Identities that can pivot (via a K8s escalation path) into a cloud-bound SA,
    thereby inheriting its cloud IAM role."""
    cloud = {c.sa: c for c in detect(snapshot)}
    results: list[dict] = []
    for target_sa, ci in cloud.items():
        if target_sa not in action:
            continue
        reachers = [n for n in nx.ancestors(action, target_sa) if n.startswith("sa:")]
        for src in sorted(reachers):
            results.append({
                "source": src,
                "pivots_to": target_sa,
                "provider": ci.provider,
                "cloud_ref": ci.cloud_ref,
                "why": (f"{src.split(':',1)[1]} can take over {target_sa.split(':',1)[1]}, "
                        f"which is federated to {ci.provider.upper()} identity {ci.cloud_ref} — "
                        f"a Kubernetes-to-cloud privilege escalation."),
            })
    return results


def graph_nodes(snapshot: ClusterSnapshot) -> list[dict]:
    """Cytoscape-style nodes+edges to overlay cloud identities on the graph."""
    nodes, edges = [], []
    for c in detect(snapshot):
        cid = f"cloud:{c.provider}:{c.cloud_ref}"
        nodes.append({"data": {"id": cid, "label": c.cloud_ref, "type": "CloudIdentity",
                               "provider": c.provider}})
        edges.append({"data": {"id": f"wi_{len(edges)}", "source": c.sa, "target": cid,
                               "label": "WORKLOAD_IDENTITY", "cls": "crit"}})
    return {"nodes": nodes, "edges": edges}
