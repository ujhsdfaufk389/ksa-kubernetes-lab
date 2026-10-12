"""Evaluation harness (Part 32).

Compares the graph-based detector against a naive per-permission baseline on a
labeled dataset, computing Precision / Recall / Accuracy / F1. Demonstrates that
relationship/graph analysis reduces false positives versus flagging any subject
that merely *holds* a dangerous verb.
"""
from __future__ import annotations

from dataclasses import dataclass

from ksa.analyzer import Analyzer
from ksa.models import ClusterSnapshot
from ksa.permissions import WILDCARD, PermissionResolver

# (verb, resource) pairs a naive scanner treats as "dangerous" on their own.
_NAIVE_DANGEROUS = [
    ("create", "pods"), ("create", "deployments"), ("create", "daemonsets"),
    ("create", "statefulsets"), ("create", "jobs"), ("create", "cronjobs"),
    ("patch", "deployments"), ("update", "deployments"),
    ("get", "secrets"), ("list", "secrets"),
    ("create", "serviceaccounts/token"),
    ("impersonate", "serviceaccounts"), ("impersonate", "users"), ("impersonate", "groups"),
    ("bind", "roles"), ("bind", "clusterroles"),
    ("escalate", "roles"), ("escalate", "clusterroles"),
    ("create", "pods/exec"),
]


def naive_baseline(snapshot: ClusterSnapshot) -> set[str]:
    """Flag any SA holding a dangerous verb (ignores whether a path exists)."""
    flagged: set[str] = set()
    for sa_id, eff in PermissionResolver(snapshot).resolve_all().items():
        if eff.is_cluster_admin():
            continue  # already-admin excluded from scope
        for p in eff.permissions:
            for dv, dr in _NAIVE_DANGEROUS:
                if p.verb in (dv, WILDCARD) and p.resource in (dr, WILDCARD):
                    flagged.add(sa_id)
                    break
            else:
                continue
            break
    return flagged


def detector_positives(snapshot: ClusterSnapshot) -> set[str]:
    """SAs the graph detector reports as escalation sources (non-system)."""
    findings = Analyzer(snapshot).findings()
    return {f.source for f in findings if not f.system_expected}


@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 3), "recall": round(self.recall, 3),
            "accuracy": round(self.accuracy, 3), "f1": round(self.f1, 3),
        }


def score(predicted: set[str], positives: set[str], negatives: set[str]) -> Metrics:
    scope = positives | negatives
    predicted = predicted & scope  # ignore excluded/out-of-scope SAs
    tp = len(predicted & positives)
    fp = len(predicted & negatives)
    fn = len(positives - predicted)
    tn = len(negatives - predicted)
    return Metrics(tp=tp, fp=fp, fn=fn, tn=tn)
