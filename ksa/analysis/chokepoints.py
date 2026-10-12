"""Choke-point analysis & minimum-change remediation optimizer (Wave 2, feat 6/33).

A removable unit is "the capability behind <primitive> on <source SA>" — removing
it deletes every escalation edge of that kind from that identity. Choke-point
analysis ranks units by how many escalation paths each one sits on; the optimizer
then runs a greedy set-cover to find a small set of units whose removal breaks
*all* targeted paths. This turns a wall of findings into a short, prioritized fix
list.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ksa.graph.relationships import EdgeType
from ksa.risk.scoring import Finding

_IGNORE = {EdgeType.IS_CLUSTER_ADMIN.value}


def _units_of(f: Finding) -> set[tuple[str, str]]:
    """The removable units (source, primitive) that would each break this path."""
    return {(h.src, h.edge_type) for h in f.path.hops if h.edge_type not in _IGNORE}


@dataclass
class ChokePoint:
    source: str
    primitive: str
    breaks: int            # how many targeted paths include this unit
    roles: list[str] = field(default_factory=list)
    bindings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _evidence_for(unit, findings):
    roles, bindings = set(), set()
    for f in findings:
        for h in f.path.hops:
            if (h.src, h.edge_type) == unit:
                ev = h.evidence or {}
                roles.update(ev.get("roles", []))
                bindings.update(ev.get("bindings", []))
    return sorted(roles), sorted(bindings)


def choke_points(findings: list[Finding]) -> list[ChokePoint]:
    """Rank removable units by how many escalation paths they sit on."""
    count: dict[tuple[str, str], int] = {}
    for f in findings:
        for u in _units_of(f):
            count[u] = count.get(u, 0) + 1
    out = []
    for unit, n in count.items():
        roles, bindings = _evidence_for(unit, findings)
        out.append(ChokePoint(source=unit[0], primitive=unit[1], breaks=n,
                              roles=roles, bindings=bindings))
    out.sort(key=lambda c: -c.breaks)
    return out


def minimum_fix(findings: list[Finding], only_severities: set[str] | None = None) -> dict:
    """Greedy set-cover: the smallest set of unit removals that breaks every
    targeted path. Returns the ordered fix list and before/after path counts."""
    targets = [f for f in findings
               if (only_severities is None or f.severity in only_severities)]
    remaining = {f.id: _units_of(f) for f in targets if _units_of(f)}
    total = len(remaining)

    fixes: list[ChokePoint] = []
    while remaining:
        # choose the unit that covers the most still-unbroken paths
        tally: dict[tuple[str, str], int] = {}
        for units in remaining.values():
            for u in units:
                tally[u] = tally.get(u, 0) + 1
        if not tally:
            break
        best = max(tally.items(), key=lambda kv: kv[1])[0]
        roles, bindings = _evidence_for(best, targets)
        fixes.append(ChokePoint(source=best[0], primitive=best[1], breaks=tally[best],
                                roles=roles, bindings=bindings))
        remaining = {fid: units for fid, units in remaining.items() if best not in units}

    return {
        "targeted_paths": total,
        "fixes": [c.to_dict() for c in fixes],
        "fix_count": len(fixes),
        "paths_after": len(remaining),  # 0 when fully covered
    }
