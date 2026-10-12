"""Effective-permission resolution (Part 11).

Given a ClusterSnapshot, compute what every ServiceAccount can *actually* do by
combining all Roles and ClusterRoles reachable through its bindings, including
the implicit RBAC group memberships every SA has:

  * system:serviceaccounts                (all SAs)
  * system:serviceaccounts:<namespace>    (SAs in that namespace)
  * system:authenticated                  (any authenticated principal)

Handles:
  * RoleBinding -> Role            (namespaced)
  * RoleBinding -> ClusterRole     (ClusterRole applied within one namespace)
  * ClusterRoleBinding -> ClusterRole  (cluster-wide)
  * wildcards in verbs / resources / apiGroups (`*`)

Namespace scope of a granted permission:
  * "*"  => cluster-wide (from a ClusterRoleBinding)
  * "ns" => only within that namespace (from a RoleBinding)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ksa.models import (
    ClusterSnapshot,
    PolicyRule,
    Role,
    RoleBinding,
    ServiceAccount,
    Subject,
    SubjectKind,
)

WILDCARD = "*"


@dataclass(frozen=True)
class Permission:
    """One resolved capability, already scoped to a namespace ('*' = cluster)."""

    namespace: str  # '*' for cluster-wide
    verb: str
    api_group: str
    resource: str
    resource_names: tuple[str, ...] = ()

    def covers(
        self, verb: str, resource: str, namespace: str, api_group: str = WILDCARD
    ) -> bool:
        """Does this permission authorize (verb, resource) in `namespace`?"""
        if self.namespace != WILDCARD and self.namespace != namespace:
            return False
        if self.verb != WILDCARD and self.verb != verb:
            return False
        if self.resource != WILDCARD and self.resource != resource:
            return False
        if (
            api_group != WILDCARD
            and self.api_group != WILDCARD
            and self.api_group != api_group
        ):
            return False
        return True


@dataclass
class SAEffective:
    """All resolved permissions for a single ServiceAccount."""

    sa: ServiceAccount
    permissions: list[Permission] = field(default_factory=list)
    # bindings/roles that produced these perms — kept for finding EVIDENCE
    via_bindings: set[str] = field(default_factory=set)
    via_roles: set[str] = field(default_factory=set)

    def can(
        self, verb: str, resource: str, namespace: str, api_group: str = WILDCARD
    ) -> bool:
        return any(p.covers(verb, resource, namespace, api_group) for p in self.permissions)

    def is_cluster_admin(self) -> bool:
        """True if the SA holds cluster-wide '*' on '*' resources."""
        return any(
            p.namespace == WILDCARD
            and p.verb == WILDCARD
            and p.resource == WILDCARD
            and (p.api_group in (WILDCARD, ""))
            for p in self.permissions
        )


class PermissionResolver:
    """Builds SAEffective for every ServiceAccount in a snapshot."""

    def __init__(self, snapshot: ClusterSnapshot) -> None:
        self.snap = snapshot
        self._roles: dict[str, Role] = {r.id: r for r in snapshot.roles}
        # effective rules per role, with aggregated ClusterRoles expanded to
        # include the rules of every ClusterRole whose labels they select.
        self._rules_for: dict[str, list[PolicyRule]] = self._expand_aggregation()
        # index bindings by subject so resolve() is O(bindings-for-this-SA),
        # not O(all bindings) — avoids O(n^2) on large clusters.
        self._by_sa: dict[str, list[RoleBinding]] = {}
        self._by_group: dict[str, list[RoleBinding]] = {}
        for b in snapshot.bindings:
            for subj in b.subjects:
                if subj.kind == SubjectKind.SERVICE_ACCOUNT:
                    self._by_sa.setdefault(subj.id, []).append(b)
                elif subj.kind == SubjectKind.GROUP:
                    self._by_group.setdefault(subj.name, []).append(b)

    def _expand_aggregation(self) -> dict[str, list[PolicyRule]]:
        """Resolve aggregationRule: a ClusterRole with selectors inherits the rules
        of every (other) ClusterRole whose labels match one of its matchLabels
        selectors. Without this, aggregated roles like the built-in `admin`/`edit`
        look empty and the graph produces false negatives."""
        cluster_roles = [r for r in self.snap.roles if r.is_cluster_role]
        out: dict[str, list[PolicyRule]] = {r.id: list(r.rules) for r in self.snap.roles}
        for agg in cluster_roles:
            if not agg.is_aggregated:
                continue
            merged = list(agg.rules)
            for cand in cluster_roles:
                if cand.id == agg.id or not cand.labels:
                    continue
                if any(self._labels_match(sel, cand.labels) for sel in agg.aggregation_selectors):
                    merged.extend(cand.rules)
            out[agg.id] = merged
        return out

    @staticmethod
    def _labels_match(selector: dict[str, str], labels: dict[str, str]) -> bool:
        """matchLabels semantics: every k=v in selector must be present in labels."""
        return bool(selector) and all(labels.get(k) == v for k, v in selector.items())

    def resolve_all(self) -> dict[str, SAEffective]:
        return {sa.id: self.resolve(sa) for sa in self.snap.service_accounts}

    def _applicable_bindings(self, sa: ServiceAccount) -> list[RoleBinding]:
        out = list(self._by_sa.get(sa.id, []))
        for grp in ("system:authenticated", "system:serviceaccounts",
                    f"system:serviceaccounts:{sa.namespace}"):
            out.extend(self._by_group.get(grp, []))
        return out

    def resolve(self, sa: ServiceAccount) -> SAEffective:
        eff = SAEffective(sa=sa)
        for binding in self._applicable_bindings(sa):
            role = self._roles.get(binding.role_ref.target_id(binding.namespace))
            if role is None:
                continue  # dangling roleRef
            eff.via_bindings.add(binding.id)
            eff.via_roles.add(role.id)
            scope = WILDCARD if binding.is_cluster_binding else (binding.namespace or WILDCARD)
            self._add_rules(eff, self._rules_for.get(role.id, role.rules), scope)
        return eff

    # ---- helpers --------------------------------------------------------
    def _binding_applies(self, binding: RoleBinding, sa: ServiceAccount) -> bool:
        """Does this binding grant to `sa` (directly or via an implicit group)?"""
        for subj in binding.subjects:
            if self._subject_matches(subj, sa):
                return True
        return False

    @staticmethod
    def _subject_matches(subj: Subject, sa: ServiceAccount) -> bool:
        if subj.kind == SubjectKind.SERVICE_ACCOUNT:
            return subj.name == sa.name and subj.namespace == sa.namespace
        if subj.kind == SubjectKind.GROUP:
            return subj.name in {
                "system:authenticated",
                "system:serviceaccounts",
                f"system:serviceaccounts:{sa.namespace}",
            }
        return False  # User subjects never match an SA

    @staticmethod
    def _add_rules(eff: SAEffective, rules: list[PolicyRule], scope: str) -> None:
        for rule in rules:
            groups = rule.api_groups or [""]
            resources = rule.resources or []
            for verb in rule.verbs:
                for grp in groups:
                    for res in resources:
                        eff.permissions.append(
                            Permission(
                                namespace=scope,
                                verb=verb,
                                api_group=grp,
                                resource=res,
                                resource_names=tuple(rule.resource_names),
                            )
                        )
