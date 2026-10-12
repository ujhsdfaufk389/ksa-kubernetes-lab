"""Toxic permission-combination engine (Wave 2, feature 5/composite analysis).

Some permissions are harmless alone but dangerous together — e.g. `create pods`
is normal and `get secrets` is normal, but an identity with *both* in one
namespace can mount any secret into a pod and exfiltrate it. This engine encodes
those composite patterns and reports them per identity, scoped to the namespace(s)
where all required verbs actually co-occur.
"""
from __future__ import annotations

from dataclasses import dataclass

from ksa.permissions import WILDCARD, SAEffective


@dataclass(frozen=True)
class ToxicRule:
    name: str
    requires: tuple[tuple[str, str], ...]  # (verb, resource) pairs
    severity: str
    why: str
    mitre: tuple[str, ...]


TOXIC_RULES: tuple[ToxicRule, ...] = (
    ToxicRule("secret-exfil-via-workload",
              (("create", "pods"), ("get", "secrets")),
              "high",
              "Can create a pod and mount/read any secret in the namespace to exfiltrate credentials.",
              ("T1552.007", "T1610")),
    ToxicRule("sa-enumerate-and-assume",
              (("list", "serviceaccounts"), ("create", "pods")),
              "high",
              "Can enumerate ServiceAccounts then launch a pod running as a more privileged one.",
              ("T1087", "T1078")),
    ToxicRule("full-impersonation",
              (("impersonate", "users"), ("impersonate", "groups")),
              "critical",
              "Can impersonate both users and groups — e.g. assume system:masters for cluster-admin.",
              ("T1078", "T1548")),
    ToxicRule("role-crafting",
              (("create", "roles"), ("create", "rolebindings")),
              "high",
              "Can author a Role and bind it — lateral self-grant of any permission the SA already holds.",
              ("T1098",)),
    ToxicRule("exec-sweep",
              (("list", "pods"), ("create", "pods/exec")),
              "high",
              "Can list pods and exec into any of them, inheriting each pod's ServiceAccount token.",
              ("T1609", "T1078")),
    ToxicRule("config-injection",
              (("patch", "configmaps"), ("patch", "deployments")),
              "medium",
              "Can alter configmaps and patch deployments to inject malicious configuration/commands.",
              ("T1610",)),
)


def _scope(eff: SAEffective, verb: str, resource: str) -> tuple[set[str], bool]:
    """Namespaces where eff can (verb, resource); bool = has a cluster-wide grant."""
    nss: set[str] = set()
    universal = False
    for p in eff.permissions:
        if p.verb not in (WILDCARD, verb):
            continue
        if p.resource not in (WILDCARD, resource):
            continue
        if p.namespace == WILDCARD:
            universal = True
        else:
            nss.add(p.namespace)
    return nss, universal


def _common_namespaces(eff: SAEffective, rule: ToxicRule) -> list[str] | None:
    """Namespaces (or ['*']) where EVERY required verb is satisfied; None if not."""
    concrete: set[str] | None = None
    all_universal = True
    for verb, res in rule.requires:
        nss, universal = _scope(eff, verb, res)
        if not nss and not universal:
            return None  # a requirement is missing entirely
        if not universal:
            all_universal = False
            concrete = nss if concrete is None else (concrete & nss)
    if all_universal:
        return ["*"]
    if concrete:
        return sorted(concrete)
    return None


@dataclass
class ToxicFinding:
    source: str
    rule: str
    severity: str
    namespaces: list[str]
    why: str
    mitre: list[str]
    permissions: list[str]

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def detect(effective: dict[str, SAEffective]) -> list[ToxicFinding]:
    out: list[ToxicFinding] = []
    for sa_id, eff in effective.items():
        if eff.is_cluster_admin():
            continue  # already maximal; combos add nothing
        for rule in TOXIC_RULES:
            ns = _common_namespaces(eff, rule)
            if ns is None:
                continue
            out.append(ToxicFinding(
                source=sa_id, rule=rule.name, severity=rule.severity,
                namespaces=ns, why=rule.why, mitre=list(rule.mitre),
                permissions=[f"{v} {r}" for v, r in rule.requires],
            ))
    sev = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    out.sort(key=lambda t: -sev.get(t.severity, 0))
    return out
