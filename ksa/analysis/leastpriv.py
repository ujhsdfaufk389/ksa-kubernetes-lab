"""Usage-based least-privilege generator (Wave 2, features 23/24/25).

Compare what a ServiceAccount is *granted* (effective RBAC) against what it has
*actually used* (from the audit stream) to surface over-provisioning, dormant
privilege, and a recommended minimal Role containing only the verbs/resources the
SA really exercised.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ksa.permissions import WILDCARD, SAEffective


def _used_by(events, sa_id: str) -> set[tuple[str, str]]:
    used = set()
    for e in events:
        if getattr(e, "actor_sa", None) != sa_id:
            continue
        res = e.resource + (f"/{e.subresource}" if getattr(e, "subresource", None) else "")
        used.add((e.verb, res))
    return used


def _granted(eff: SAEffective) -> set[tuple[str, str]]:
    return {(p.verb, p.resource) for p in eff.permissions}


@dataclass
class LeastPriv:
    sa: str
    granted: list[tuple[str, str]]
    used: list[tuple[str, str]]
    unused: list[tuple[str, str]]
    has_wildcard: bool
    waste_ratio: float
    dormant: bool
    recommended_role_yaml: str = field(default="")

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        for k in ("granted", "used", "unused"):
            d[k] = [f"{v} {r}" for v, r in getattr(self, k)]
        return d


def _role_yaml(sa_id: str, used: set[tuple[str, str]]) -> str:
    ns, name = sa_id.split(":", 1)[1].split("/", 1)
    by_res: dict[str, set[str]] = {}
    for verb, res in sorted(used):
        by_res.setdefault(res, set()).add(verb)
    lines = ["apiVersion: rbac.authorization.k8s.io/v1", "kind: Role",
             f"metadata:\n  name: {name}-least-privilege\n  namespace: {ns}", "rules:"]
    if not by_res:
        lines.append("  []  # no observed usage — candidate for removal")
    for res, verbs in sorted(by_res.items()):
        vlist = ", ".join(f'"{v}"' for v in sorted(verbs))
        lines.append(f'  - apiGroups: [""]\n    resources: ["{res}"]\n    verbs: [{vlist}]')
    return "\n".join(lines)


def analyze(sa_id: str, eff: SAEffective, events) -> LeastPriv:
    granted = _granted(eff)
    has_wild = any(v == WILDCARD or r == WILDCARD for v, r in granted)
    used = _used_by(events, sa_id)
    concrete = {g for g in granted if g[0] != WILDCARD and g[1] != WILDCARD}
    unused = concrete - used
    waste = (len(unused) / len(concrete)) if concrete else 0.0
    dormant = bool(granted) and not used
    return LeastPriv(
        sa=sa_id, granted=sorted(granted), used=sorted(used), unused=sorted(unused),
        has_wildcard=has_wild, waste_ratio=round(waste, 3), dormant=dormant,
        recommended_role_yaml=_role_yaml(sa_id, used),
    )


def rank_waste(effective: dict[str, SAEffective], events, limit: int = 20) -> list[dict]:
    out = [analyze(sa, eff, events) for sa, eff in effective.items()]
    out.sort(key=lambda l: (-l.waste_ratio, -len(l.unused)))
    return [l.to_dict() for l in out[:limit]]
