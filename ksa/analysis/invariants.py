"""Continuous security invariants (Wave 2, features 34/35).

The admin declares assertions such as "no ServiceAccount in dev may reach
cluster-admin". After every scan the engine re-verifies each assertion against the
escalation graph and reports PASS / FAIL with the exact violating paths — turning
privilege-escalation detection into a continuous compliance gate (CI-friendly).
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from ksa.policy import Invariant, Policy


@dataclass
class InvariantResult:
    id: str
    description: str
    forbid_reach: str
    passed: bool
    violations: list[str]  # source identities that violate it

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _check_one(inv: Invariant, action: nx.DiGraph) -> InvariantResult:
    target = inv.forbid_reach
    violations: list[str] = []
    if target in action:
        for n in action.nodes:
            if not n.startswith("sa:") or not inv.matches_source(n):
                continue
            if n != target and nx.has_path(action, n, target):
                violations.append(n)
    violations.sort()
    return InvariantResult(
        id=inv.id, description=inv.description, forbid_reach=target,
        passed=not violations, violations=violations,
    )


def check(action: nx.DiGraph, policy: Policy) -> dict:
    results = [_check_one(inv, action) for inv in policy.invariants]
    failed = [r for r in results if not r.passed]
    return {
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": len(failed),
        "results": [r.to_dict() for r in results],
    }
