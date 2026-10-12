"""Synthetic cluster generator for performance benchmarking (Part 31)."""
from __future__ import annotations

import random

from ksa.models import (
    ClusterSnapshot,
    Namespace,
    PolicyRule,
    Role,
    RoleBinding,
    RoleRef,
    ServiceAccount,
    Subject,
    SubjectKind,
)

_ADMIN_NS = "prod"


def generate_snapshot(n_sas: int, escalation_ratio: float = 0.08, seed: int = 7) -> ClusterSnapshot:
    """Build a snapshot with ~n_sas ServiceAccounts and a realistic RBAC graph.

    A fraction (escalation_ratio) of SAs are granted create-pods in the admin
    namespace, producing genuine escalation paths for the path engine to find.
    """
    rng = random.Random(seed)
    n_app_ns = max(2, n_sas // 40)
    namespaces = [Namespace(name=f"app{i}") for i in range(n_app_ns)] + [Namespace(name=_ADMIN_NS)]

    roles = [
        Role(name="cluster-admin", namespace=None,
             rules=[PolicyRule(verbs=["*"], api_groups=["*"], resources=["*"])]),
        Role(name="podmaker", namespace=None,
             rules=[PolicyRule(verbs=["create"], api_groups=[""], resources=["pods"])]),
        Role(name="viewer", namespace=None,
             rules=[PolicyRule(verbs=["get", "list"], api_groups=[""], resources=["pods", "configmaps"])]),
    ]
    sas = [ServiceAccount(name="admin-sa", namespace=_ADMIN_NS)]
    bindings = [
        RoleBinding(name="admin-binding", namespace=None,
                    role_ref=RoleRef(kind="ClusterRole", name="cluster-admin"),
                    subjects=[Subject(kind=SubjectKind.SERVICE_ACCOUNT, name="admin-sa", namespace=_ADMIN_NS)]),
    ]

    for i in range(n_sas):
        ns = f"app{rng.randrange(n_app_ns)}"
        sa = ServiceAccount(name=f"sa-{i}", namespace=ns)
        sas.append(sa)
        subj = Subject(kind=SubjectKind.SERVICE_ACCOUNT, name=sa.name, namespace=ns)
        if rng.random() < escalation_ratio:
            # cross-namespace create-pods into the admin namespace -> escalation path
            bindings.append(RoleBinding(
                name=f"esc-{i}", namespace=_ADMIN_NS,
                role_ref=RoleRef(kind="ClusterRole", name="podmaker"), subjects=[subj]))
        else:
            # benign viewer grant in own namespace
            bindings.append(RoleBinding(
                name=f"view-{i}", namespace=ns,
                role_ref=RoleRef(kind="ClusterRole", name="viewer"), subjects=[subj]))

    return ClusterSnapshot(namespaces=namespaces, service_accounts=sas, roles=roles, bindings=bindings)
