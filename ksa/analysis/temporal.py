"""Temporal attack graph & incident time-machine (Wave 2, features 1/52/53).

Across the ordered history of scan snapshots we reconstruct, for every escalation
path, *when it first became exploitable* and when it disappeared. This powers:

    * "privilege path became exploitable at <t>" alerts,
    * a dashboard time-slider that shows the graph as it was at any past moment,
    * forensic replay of how an attack surface evolved.
"""
from __future__ import annotations

from pathlib import Path

from ksa.drift import load_all


def _key(f: dict) -> str:
    return f"{f.get('source')}|{f.get('target')}|{f.get('primitive')}"


def timeline(history_dir: str | Path) -> dict:
    """Per-path appearance/disappearance timeline across all snapshots."""
    snaps = load_all(history_dir)
    stamps = [s.get("scanned_at") for s in snaps]
    first: dict[str, str] = {}
    last: dict[str, str] = {}
    label: dict[str, dict] = {}
    for s in snaps:
        ts = s.get("scanned_at")
        for f in s.get("findings", []):
            k = _key(f)
            first.setdefault(k, ts)
            last[k] = ts
            label[k] = {"source": f.get("source"), "target": f.get("target"),
                        "primitive": f.get("primitive"), "severity": f.get("severity")}
    present_now = {_key(f) for f in (snaps[-1].get("findings", []) if snaps else [])}
    paths = []
    for k, meta in label.items():
        paths.append({**meta, "first_seen": first[k], "last_seen": last[k],
                      "present_now": k in present_now})
    # newest-appearing first — those are the fresh exposures
    paths.sort(key=lambda p: (p["first_seen"] or ""), reverse=True)
    return {"snapshots": stamps, "count": len(stamps), "paths": paths}


def became_exploitable(history_dir: str | Path) -> list[dict]:
    """Paths that are NEW in the most recent snapshot vs. the one before, with the
    exact timestamp they became exploitable."""
    snaps = load_all(history_dir)
    if len(snaps) < 2:
        return []
    prev = {_key(f) for f in snaps[-2].get("findings", [])}
    out = []
    for f in snaps[-1].get("findings", []):
        if _key(f) not in prev:
            out.append({**f, "became_exploitable_at": snaps[-1].get("scanned_at")})
    return out


def at(history_dir: str | Path, when: str) -> dict | None:
    """Time-machine: the snapshot in effect at timestamp `when` (nearest <= when)."""
    snaps = load_all(history_dir)
    chosen = None
    for s in snaps:
        ts = s.get("scanned_at") or ""
        if ts <= when:
            chosen = s
        else:
            break
    return chosen
