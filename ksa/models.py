"""Normalized, typed representation of the Kubernetes objects we analyze.

Both the live collector (client-python) and the offline directory loader produce
these same models, so everything downstream (parsers, graph builder, detectors)
is decoupled from *how* the data was obtained.

We deliberately keep only the fields relevant to privilege-escalation analysis.
Secret *values* are never stored here (see collector docstring).
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class SubjectKind(str, Enum):
    """RBAC subject kinds (who a binding grants a role to)."""

    SERVICE_ACCOUNT = "ServiceAccount"
    USER = "User"
    GROUP = "Group"


class WorkloadKind(str, Enum):
    """Workload controller kinds that can carry a serviceAccountName."""

    POD = "Pod"
    DEPLOYMENT = "Deployment"
    STATEFULSET = "StatefulSet"
    DAEMONSET = "DaemonSet"
    REPLICASET = "ReplicaSet"
    JOB = "Job"
    CRONJOB = "CronJob"


class Subject(BaseModel):
    """A binding subject: a ServiceAccount, User, or Group."""

    kind: SubjectKind
    name: str
    # namespace only meaningful for ServiceAccount subjects
    namespace: Optional[str] = None

    @property
    def id(self) -> str:
        """Stable graph node id, e.g. 'sa:dev/web-sa' or 'group:system:masters'."""
        if self.kind == SubjectKind.SERVICE_ACCOUNT:
            return f"sa:{self.namespace}/{self.name}"
        if self.kind == SubjectKind.USER:
            return f"user:{self.name}"
        return f"group:{self.name}"


class PolicyRule(BaseModel):
    """A single RBAC rule (a row in a Role/ClusterRole)."""

    verbs: list[str] = Field(default_factory=list)
    api_groups: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    resource_names: list[str] = Field(default_factory=list)
    non_resource_urls: list[str] = Field(default_factory=list)


class Role(BaseModel):
    """A Role (namespaced) or ClusterRole (cluster-scoped)."""

    name: str
    namespace: Optional[str] = None  # None => ClusterRole
    rules: list[PolicyRule] = Field(default_factory=list)
    # ClusterRole labels + aggregationRule, used to resolve aggregated ClusterRoles
    # (a ClusterRole with an aggregationRule inherits the rules of every ClusterRole
    # whose labels match one of these selectors). matchLabels only (v2).
    labels: dict[str, str] = Field(default_factory=dict)
    aggregation_selectors: list[dict[str, str]] = Field(default_factory=list)

    @property
    def is_aggregated(self) -> bool:
        return bool(self.aggregation_selectors)

    @property
    def is_cluster_role(self) -> bool:
        return self.namespace is None

    @property
    def id(self) -> str:
        if self.is_cluster_role:
            return f"clusterrole:{self.name}"
        return f"role:{self.namespace}/{self.name}"


class RoleRef(BaseModel):
    """Which role a binding points at."""

    kind: str  # "Role" | "ClusterRole"
    name: str

    def target_id(self, binding_namespace: Optional[str]) -> str:
        """Resolve to a Role/ClusterRole node id.

        A RoleBinding may reference a ClusterRole (then it applies namespaced),
        so we need the binding's namespace to build a namespaced Role id.
        """
        if self.kind == "ClusterRole":
            return f"clusterrole:{self.name}"
        return f"role:{binding_namespace}/{self.name}"


class RoleBinding(BaseModel):
    """A RoleBinding (namespaced) or ClusterRoleBinding (cluster-scoped)."""

    name: str
    namespace: Optional[str] = None  # None => ClusterRoleBinding
    role_ref: RoleRef
    subjects: list[Subject] = Field(default_factory=list)

    @property
    def is_cluster_binding(self) -> bool:
        return self.namespace is None

    @property
    def id(self) -> str:
        if self.is_cluster_binding:
            return f"crb:{self.name}"
        return f"rb:{self.namespace}/{self.name}"


class ServiceAccount(BaseModel):
    """A ServiceAccount identity."""

    name: str
    namespace: str
    automount_token: bool = True  # spec.automountServiceAccountToken (default true)
    # names of Secrets referenced by the SA (pre-1.24 static tokens, image pulls)
    secret_names: list[str] = Field(default_factory=list)
    # SA annotations — used to detect cloud workload-identity federation
    # (eks.amazonaws.com/role-arn, iam.gke.io/gcp-service-account, Azure WI).
    annotations: dict[str, str] = Field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"sa:{self.namespace}/{self.name}"


class Container(BaseModel):
    """Security-relevant container fields inside a workload pod spec."""

    name: str
    image: str
    privileged: bool = False
    allow_privilege_escalation: Optional[bool] = None
    run_as_user: Optional[int] = None
    added_capabilities: list[str] = Field(default_factory=list)


class Workload(BaseModel):
    """A workload that runs under a ServiceAccount (the RUNS_AS edge source).

    For Pods we read spec directly; for controllers we read the pod template.
    """

    kind: WorkloadKind
    name: str
    namespace: str
    service_account_name: str = "default"
    automount_token: Optional[bool] = None  # pod-spec override of SA default
    host_network: bool = False
    host_pid: bool = False
    host_path_volumes: list[str] = Field(default_factory=list)
    containers: list[Container] = Field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.kind.value.lower()}:{self.namespace}/{self.name}"

    @property
    def is_privileged(self) -> bool:
        return any(c.privileged for c in self.containers)


class Secret(BaseModel):
    """Secret METADATA only — values are never collected by default."""

    name: str
    namespace: str
    type: str = "Opaque"
    # if this secret is a SA token, which SA it belongs to (annotation)
    service_account_name: Optional[str] = None

    @property
    def id(self) -> str:
        return f"secret:{self.namespace}/{self.name}"


class Namespace(BaseModel):
    name: str
    # Pod Security Admission level, from label pod-security.kubernetes.io/enforce
    pod_security_enforce: Optional[str] = None

    @property
    def id(self) -> str:
        return f"ns:{self.name}"


class ClusterSnapshot(BaseModel):
    """Everything we collected in one scan — the input to the graph builder."""

    namespaces: list[Namespace] = Field(default_factory=list)
    service_accounts: list[ServiceAccount] = Field(default_factory=list)
    roles: list[Role] = Field(default_factory=list)  # Roles + ClusterRoles
    bindings: list[RoleBinding] = Field(default_factory=list)  # RB + CRB
    workloads: list[Workload] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)

    def summary(self) -> dict[str, int]:
        cluster_roles = sum(1 for r in self.roles if r.is_cluster_role)
        return {
            "namespaces": len(self.namespaces),
            "service_accounts": len(self.service_accounts),
            "roles": len(self.roles) - cluster_roles,
            "cluster_roles": cluster_roles,
            "bindings": len(self.bindings),
            "workloads": len(self.workloads),
            "secrets": len(self.secrets),
        }
