"""RBAC / attack-path drift detection (Parts 20-21).

Each scan can be snapshotted to a small JSON file under a history directory. The
diff between two snapshots answers the questions a security team actually asks:

    * Which escalation paths are NEW since the last scan? (a dangerous change)
    * Which paths were REMOVED? (a remediation landed)
    * Which paths changed severity?

Only the minimal, non-sensitive fields of each finding are stored, so history is
cheap and never contains secret material.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

_FIELDS = ("id", "source", "target", "primitive", "severity", "risk_score", "confidence")


def _slim(result: dict) -> dict:
    """Keep only what drift needs from a full scan_result."""
    findings = [
        {k: f.get(k) for k in _FIELDS} for f in result.get("findings", [])
    ]
    return {
        "scanned_at": result.get("scanned_at"),
        "cluster": result.get("cluster", ""),
        "summary": result.get("summary", {}),
        "findings": findings,
    }


def write_snapshot(result: dict, history_dir: str | Path) -> Path:
    """Persist a slim snapshot of a scan; returns the file path."""
    d = Path(history_dir)
    d.mkdir(parents=True, exist_ok=True)
    ts = (result.get("scanned_at") or _dt.datetime.now(_dt.timezone.utc).isoformat()
          ).replace(":", "-").replace("+00-00", "Z")
    path = d / f"snapshot-{ts}.json"
    path.write_text(json.dumps(_slim(result), indent=2))
    return path


def _list_snapshots(history_dir: str | Path) -> list[Path]:
    d = Path(history_dir)
    if not d.exists():
        return []
    return sorted(d.glob("snapshot-*.json"))


def load_all(history_dir: str | Path) -> list[dict]:
    """All snapshots, oldest first (by scanned_at, then filename)."""
    snaps = []
    for p in _list_snapshots(history_dir):
        try:
            snaps.append(json.loads(p.read_text()))
        except (OSError, json.JSONDecodeError):
            continue
    snaps.sort(key=lambda s: (s.get("scanned_at") or "", ))
    return snaps


def load_latest_two(history_dir: str | Path) -> tuple[dict | None, dict | None]:
    """Return (previous, latest) snapshots, or (None, latest)/(None, None)."""
    snaps = _list_snapshots(history_dir)
    if not snaps:
        return None, None
    latest = json.loads(snaps[-1].read_text())
    prev = json.loads(snaps[-2].read_text()) if len(snaps) >= 2 else None
    return prev, latest


def _key(f: dict) -> tuple:
    """Identity of an escalation path, independent of its generated finding id."""
    return (f.get("source"), f.get("target"), f.get("primitive"))


def diff(prev: dict | None, curr: dict | None) -> dict:
    """Compute the attack-path diff between two snapshots."""
    curr = curr or {"findings": []}
    prev_f = {_key(f): f for f in (prev or {}).get("findings", [])}
    curr_f = {_key(f): f for f in curr.get("findings", [])}

    new = [curr_f[k] for k in curr_f.keys() - prev_f.keys()]
    removed = [prev_f[k] for k in prev_f.keys() - curr_f.keys()]
    changed = []
    for k in curr_f.keys() & prev_f.keys():
        a, b = prev_f[k], curr_f[k]
        if a.get("severity") != b.get("severity") or a.get("confidence") != b.get("confidence"):
            changed.append({"path": k, "from": a, "to": b})

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    new.sort(key=lambda f: -sev_rank.get(f.get("severity"), 0))
    return {
        "previous_at": (prev or {}).get("scanned_at"),
        "current_at": curr.get("scanned_at"),
        "new_paths": new,
        "removed_paths": removed,
        "changed_paths": changed,
        "counts": {
            "new": len(new),
            "removed": len(removed),
            "changed": len(changed),
            "new_critical": sum(1 for f in new if f.get("severity") == "critical"),
        },
    }
