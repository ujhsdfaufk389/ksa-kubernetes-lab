"""Policy model (Wave 2): crown jewels, namespace asset tiers, and the security
invariants the engine continuously verifies.

Loaded from ksa/config/config.yaml (the `policy:` block) or an explicit path,
with safe built-in defaults so the detector works with no config at all.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_DEFAULT_CONFIG = Path(__file__).resolve().parent / "config" / "config.yaml"
_SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease", "local-path-storage"}


@dataclass(frozen=True)
class Invariant:
    id: str
    description: str
    forbid_reach: str                      # a target node id, e.g. sink:cluster-admin
    source_namespace: str | None = None    # restrict source identities to this ns
    source_regex: str | None = None        # ...or whose id matches this regex
    exclude_system: bool = False           # ignore system-namespace sources

    def matches_source(self, sa_id: str) -> bool:
        ns = sa_id.split(":", 1)[1].split("/", 1)[0] if ":" in sa_id else ""
        if self.exclude_system and ns in _SYSTEM_NS:
            return False
        if self.source_namespace and ns != self.source_namespace:
            return False
        if self.source_regex and not re.search(self.source_regex, sa_id):
            return False
        return True


@dataclass
class Policy:
    crown_jewels: set[str] = field(default_factory=lambda: {"sink:cluster-admin", "sink:node-access"})
    asset_tiers: dict[str, int] = field(default_factory=dict)
    invariants: list[Invariant] = field(default_factory=list)

    def tier(self, namespace: str) -> int:
        return self.asset_tiers.get(namespace, 3)


def load(path: str | Path | None = None) -> Policy:
    cfg_path = Path(path) if path else _DEFAULT_CONFIG
    try:
        raw = yaml.safe_load(cfg_path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return Policy()
    pol = raw.get("policy", {}) or {}
    invs = []
    for i in pol.get("invariants", []) or []:
        if not i.get("id") or not i.get("forbid_reach"):
            continue
        invs.append(Invariant(
            id=i["id"],
            description=i.get("description", ""),
            forbid_reach=i["forbid_reach"],
            source_namespace=i.get("source_namespace"),
            source_regex=i.get("source_regex"),
            exclude_system=bool(i.get("exclude_system", False)),
        ))
    return Policy(
        crown_jewels=set(pol.get("crown_jewels", []) or []) or Policy().crown_jewels,
        asset_tiers=dict(pol.get("asset_tiers", {}) or {}),
        invariants=invs,
    )
