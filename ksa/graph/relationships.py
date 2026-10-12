"""Vocabulary of the escalation graph: node types, edge types, sinks.

Kept in one place so the builder, path engine, detectors, and the dashboard
all agree on the exact strings used as graph attributes.
"""
from __future__ import annotations

from enum import Enum


class NodeType(str, Enum):
    SERVICE_ACCOUNT = "ServiceAccount"
    USER = "User"
    GROUP = "Group"
    ROLE = "Role"
    CLUSTER_ROLE = "ClusterRole"
    ROLE_BINDING = "RoleBinding"
    CLUSTER_ROLE_BINDING = "ClusterRoleBinding"
    WORKLOAD = "Workload"
    SECRET = "Secret"
    NAMESPACE = "Namespace"
    SINK = "Sink"  # synthetic target (cluster-admin, node-access, ...)


class EdgeType(str, Enum):
    # --- structural (how RBAC is wired) ---
    BOUND_TO = "BOUND_TO"          # subject  -> binding
    GRANTS = "GRANTS"              # binding  -> role
    RUNS_AS = "RUNS_AS"            # workload -> service account
    LOCATED_IN = "LOCATED_IN"      # object   -> namespace

    # --- escalation actions (attacker steps, each = one hop) ---
    CREATE_POD_AS = "CREATE_POD_AS"      # SA -> SA (create workload w/ target SA)
    WORKLOAD_HIJACK = "WORKLOAD_HIJACK"  # SA -> SA (patch existing workload's SA)
    REQUEST_TOKEN = "REQUEST_TOKEN"      # SA -> SA (serviceaccounts/token)
    IMPERSONATE = "IMPERSONATE"          # SA -> SA / User / Group
    EXEC_INTO = "EXEC_INTO"              # SA -> SA (exec into a pod running as target)
    READ_SECRET_CRED = "READ_SECRET_CRED"  # SA -> SA (read a secret holding target's token)
    CAN_BIND = "CAN_BIND"                # SA -> Sink (bind verb -> grant self any role)
    CAN_ESCALATE = "CAN_ESCALATE"        # SA -> Sink (escalate verb)
    IS_CLUSTER_ADMIN = "IS_CLUSTER_ADMIN"  # SA -> Sink (already cluster-admin)
    NODE_ACCESS = "NODE_ACCESS"          # SA -> Sink (privileged pod / nodes/proxy)
    PRIVILEGED_WORKLOAD = "PRIVILEGED_WORKLOAD"  # SA -> Sink (create privileged/host pod -> host escape)
    CSR_ESCALATE = "CSR_ESCALATE"        # SA -> Sink (create+approve CSR -> mint admin client cert)


# Synthetic sink node ids (targets that mean "full escalation").
SINK_CLUSTER_ADMIN = "sink:cluster-admin"
SINK_NODE_ACCESS = "sink:node-access"

# Verbs/resources that create a workload able to carry a serviceAccountName.
WORKLOAD_CREATE_RESOURCES = {
    "pods",
    "deployments",
    "daemonsets",
    "statefulsets",
    "replicasets",
    "jobs",
    "cronjobs",
}
