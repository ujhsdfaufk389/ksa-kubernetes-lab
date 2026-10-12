"""Graph builder (Part 6 / Part G).

Turns a ClusterSnapshot + resolved effective permissions into a typed directed
graph (NetworkX MultiDiGraph) whose nodes are identities/objects and whose edges
are either *structural* (how RBAC is wired) or *escalation actions* (one attacker
step each). Privilege-escalation detection then reduces to reachability from a
source ServiceAccount to a synthetic SINK node.

Every escalation edge carries `evidence` (the bindings/roles that authorize it)
so findings are explainable, not opaque.
"""
from __future__ import annotations

import logging

import networkx as nx

from ksa.graph.relationships import (
    SINK_CLUSTER_ADMIN,
    SINK_NODE_ACCESS,
    WORKLOAD_CREATE_RESOURCES,
    EdgeType,
    NodeType,
)
from ksa.models import ClusterSnapshot, ServiceAccount
from ksa.permissions import WILDCARD, PermissionResolver, SAEffective

log = logging.getLogger(__name__)

_HIJACK_RESOURCES = {"deployments", "daemonsets", "statefulsets", "replicasets"}


class GraphBuilder:
    def __init__(self, snapshot: ClusterSnapshot) -> None:
        self.snap = snapshot
        self.g = nx.MultiDiGraph()
        self._effective: dict[str, SAEffective] = {}
        # namespace -> [ServiceAccount]
        self._sa_by_ns: dict[str, list[ServiceAccount]] = {}
        for sa in snapshot.service_accounts:
            self._sa_by_ns.setdefault(sa.namespace, []).append(sa)
        self._all_ns = sorted({sa.namespace for sa in snapshot.service_accounts}
                              | {n.name for n in snapshot.namespaces})
        # namespace -> Pod Security Admission enforce level (None if unset)
        self._psa: dict[str, str | None] = {n.name: n.pod_security_enforce
                                            for n in snapshot.namespaces}
        # dedupe escalation edges: (src, dst, type) -> already added
        self._seen: set[tuple[str, str, str]] = set()

    def build(self) -> nx.MultiDiGraph:
        self._effective = PermissionResolver(self.snap).resolve_all()
        self._add_sink_nodes()
        self._add_structural()
        for sa in self.snap.service_accounts:
            self._add_escalation_edges(sa)
        log.info(
            "Graph built: %d nodes, %d edges", self.g.number_of_nodes(), self.g.number_of_edges()
        )
        return self.g

    # ---- nodes ----------------------------------------------------------
    def _add_sink_nodes(self) -> None:
        self.g.add_node(SINK_CLUSTER_ADMIN, type=NodeType.SINK.value, label="cluster-admin")
        self.g.add_node(SINK_NODE_ACCESS, type=NodeType.SINK.value, label="node-access")
        # owning a node => every pod's token => cluster-admin
        self.g.add_edge(
            SINK_NODE_ACCESS, SINK_CLUSTER_ADMIN, key=EdgeType.NODE_ACCESS.value,
            type=EdgeType.NODE_ACCESS.value, action="node compromise yields all pod tokens",
        )

    def _add_structural(self) -> None:
        for sa in self.snap.service_accounts:
            self.g.add_node(
                sa.id, type=NodeType.SERVICE_ACCOUNT.value, label=f"{sa.namespace}/{sa.name}",
                namespace=sa.namespace, automount=sa.automount_token,
                cluster_admin=self._effective[sa.id].is_cluster_admin(),
            )
        for role in self.snap.roles:
            ntype = NodeType.CLUSTER_ROLE if role.is_cluster_role else NodeType.ROLE
            self.g.add_node(role.id, type=ntype.value, label=role.name, namespace=role.namespace)
        for b in self.snap.bindings:
            ntype = NodeType.CLUSTER_ROLE_BINDING if b.is_cluster_binding else NodeType.ROLE_BINDING
            self.g.add_node(b.id, type=ntype.value, label=b.name, namespace=b.namespace)
            # subject -> binding -> role
            role_id = b.role_ref.target_id(b.namespace)
            for subj in b.subjects:
                if subj.id in self.g or subj.kind.value == "ServiceAccount":
                    self.g.add_edge(subj.id, b.id, key=EdgeType.BOUND_TO.value,
                                    type=EdgeType.BOUND_TO.value)
            self.g.add_edge(b.id, role_id, key=EdgeType.GRANTS.value, type=EdgeType.GRANTS.value)
        for w in self.snap.workloads:
            self.g.add_node(w.id, type=NodeType.WORKLOAD.value, label=f"{w.namespace}/{w.name}",
                            kind=w.kind.value, namespace=w.namespace, privileged=w.is_privileged)
            sa_id = f"sa:{w.namespace}/{w.service_account_name}"
            self.g.add_edge(w.id, sa_id, key=EdgeType.RUNS_AS.value, type=EdgeType.RUNS_AS.value)
        for s in self.snap.secrets:
            self.g.add_node(s.id, type=NodeType.SECRET.value, label=f"{s.namespace}/{s.name}",
                            namespace=s.namespace, secret_type=s.type)

    # ---- escalation edges ----------------------------------------------
    def _namespaces_for(self, eff: SAEffective, verb: str, resource: str,
                        api_group: str = WILDCARD) -> list[str]:
        """Namespaces in which `eff` can (verb, resource). '*' expands to all."""
        scoped: set[str] = set()
        for p in eff.permissions:
            if p.namespace == WILDCARD:
                if p.covers(verb, resource, namespace="*", api_group=api_group) or \
                   self._covers_ignore_ns(p, verb, resource, api_group):
                    return list(self._all_ns)
            elif self._covers_ignore_ns(p, verb, resource, api_group):
                scoped.add(p.namespace)
        return sorted(scoped)

    @staticmethod
    def _covers_ignore_ns(p, verb: str, resource: str, api_group: str) -> bool:
        if p.verb != WILDCARD and p.verb != verb:
            return False
        if p.resource != WILDCARD and p.resource != resource:
            return False
        if api_group != WILDCARD and p.api_group != WILDCARD and p.api_group != api_group:
            return False
        return True

    def _edge(self, src: str, dst: str, etype: EdgeType, **attrs) -> None:
        key = (src, dst, etype.value)
        if key in self._seen:
            return
        self._seen.add(key)
        self.g.add_edge(src, dst, key=etype.value, type=etype.value, **attrs)

    def _add_escalation_edges(self, sa: ServiceAccount) -> None:
        eff = self._effective[sa.id]
        ev = {"bindings": sorted(eff.via_bindings), "roles": sorted(eff.via_roles)}

        # 0) already cluster-admin / node access sinks
        if eff.is_cluster_admin():
            self._edge(sa.id, SINK_CLUSTER_ADMIN, EdgeType.IS_CLUSTER_ADMIN,
                       action="bound to cluster-admin equivalent", evidence=ev)
            # an already-admin SA is at the sink; its other outgoing escalation
            # edges can never create a shorter path for anyone -> skip (big perf win)
            return
        if eff.can("get", "nodes/proxy", "*") or eff.can("create", "nodes/proxy", "*"):
            self._edge(sa.id, SINK_NODE_ACCESS, EdgeType.NODE_ACCESS,
                       action="nodes/proxy access", evidence=ev)

        # 1) workload creation -> run as any SA in that namespace
        for res in WORKLOAD_CREATE_RESOURCES:
            for ns in self._namespaces_for(eff, "create", res):
                for target in self._sa_by_ns.get(ns, []):
                    if target.id != sa.id:
                        self._edge(sa.id, target.id, EdgeType.CREATE_POD_AS,
                                   action=f"create {res} running as target SA", namespace=ns,
                                   evidence=ev)

        # 2) hijack existing workload's SA (patch/update controller pod template)
        for res in _HIJACK_RESOURCES:
            for verb in ("patch", "update"):
                for ns in self._namespaces_for(eff, verb, res):
                    for target in self._sa_by_ns.get(ns, []):
                        if target.id != sa.id:
                            self._edge(sa.id, target.id, EdgeType.WORKLOAD_HIJACK,
                                       action=f"{verb} {res} to swap serviceAccountName",
                                       namespace=ns, evidence=ev)

        # 3) token request
        for ns in self._namespaces_for(eff, "create", "serviceaccounts/token"):
            for target in self._sa_by_ns.get(ns, []):
                if target.id != sa.id:
                    self._edge(sa.id, target.id, EdgeType.REQUEST_TOKEN,
                               action="mint token via serviceaccounts/token", namespace=ns,
                               evidence=ev)

        # 4) impersonation
        for ns in self._namespaces_for(eff, "impersonate", "serviceaccounts"):
            for target in self._sa_by_ns.get(ns, []):
                if target.id != sa.id:
                    self._edge(sa.id, target.id, EdgeType.IMPERSONATE,
                               action="impersonate serviceaccount", namespace=ns, evidence=ev)
        if eff.can("impersonate", "groups", "*"):
            self._edge(sa.id, SINK_CLUSTER_ADMIN, EdgeType.IMPERSONATE,
                       action="impersonate privileged group (e.g. system:masters)", evidence=ev)

        # 5) exec into pods -> inherit those pods' SAs
        exec_ns = set(self._namespaces_for(eff, "create", "pods/exec")) | \
                  set(self._namespaces_for(eff, "get", "pods/exec"))
        if exec_ns:
            for w in self.snap.workloads:
                if w.namespace in exec_ns:
                    target_id = f"sa:{w.namespace}/{w.service_account_name}"
                    if target_id != sa.id and target_id in self.g:
                        self._edge(sa.id, target_id, EdgeType.EXEC_INTO,
                                   action=f"exec into {w.id}", namespace=w.namespace, evidence=ev)

        # 6) read a secret that holds another SA's token
        read_ns = set(self._namespaces_for(eff, "get", "secrets")) | \
                  set(self._namespaces_for(eff, "list", "secrets"))
        if read_ns:
            for s in self.snap.secrets:
                if s.namespace in read_ns and s.service_account_name:
                    target_id = f"sa:{s.namespace}/{s.service_account_name}"
                    if target_id != sa.id and target_id in self.g:
                        self._edge(sa.id, target_id, EdgeType.READ_SECRET_CRED,
                                   action=f"read token secret {s.id}", namespace=s.namespace,
                                   evidence=ev)

        # 6b) create a privileged / host pod where Pod Security Admission permits
        # it (enforce=privileged) -> escape to the node -> every pod's token.
        for ns in self._namespaces_for(eff, "create", "pods"):
            if self._psa.get(ns) == "privileged":
                self._edge(sa.id, SINK_NODE_ACCESS, EdgeType.PRIVILEGED_WORKLOAD,
                           action="create privileged/host pod (PSA=privileged) and escape to node",
                           namespace=ns, evidence=ev)

        # 6c) create AND approve a CertificateSigningRequest -> mint a client cert
        # for any user/group (e.g. system:masters) -> cluster-admin.
        if eff.can("create", "certificatesigningrequests", "*") and \
           eff.can("update", "certificatesigningrequests/approval", "*"):
            self._edge(sa.id, SINK_CLUSTER_ADMIN, EdgeType.CSR_ESCALATE,
                       action="create + approve a CSR to issue an admin client certificate",
                       evidence=ev)

        # 7) bind / escalate verbs -> self-grant any role
        for res in ("roles", "clusterroles"):
            if eff.can("bind", res, "*"):
                self._edge(sa.id, SINK_CLUSTER_ADMIN, EdgeType.CAN_BIND,
                           action=f"bind verb on {res} allows self-granting any role", evidence=ev)
            if eff.can("escalate", res, "*"):
                self._edge(sa.id, SINK_CLUSTER_ADMIN, EdgeType.CAN_ESCALATE,
                           action=f"escalate verb on {res} allows adding arbitrary rules",
                           evidence=ev)
