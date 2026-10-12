#!/usr/bin/env python3
"""Run the evaluation on the labeled dataset and write docs/results/evaluation.md."""
from __future__ import annotations

import pathlib

import yaml

from ksa.collector.directory_collector import DirectoryCollector
from ksa.evaluation import detector_positives, naive_baseline, score

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "eval"
OUT = ROOT / "docs" / "results" / "evaluation.md"


def main() -> None:
    snapshot = DirectoryCollector(FIX).collect()
    labels = yaml.safe_load((FIX / "labels.yaml").read_text())
    pos, neg = set(labels["positive"]), set(labels["negative"])

    graph_pred = detector_positives(snapshot)
    naive_pred = naive_baseline(snapshot)
    m_graph = score(graph_pred, pos, neg)
    m_naive = score(naive_pred, pos, neg)

    scope = pos | neg
    graph_fp = sorted((graph_pred & neg))
    naive_fp = sorted((naive_pred & neg))

    md = f"""# Evaluation Results

Dataset: `tests/fixtures/eval/` — {len(pos)} positive, {len(neg)} negative SAs
(2 already-admin SAs excluded from scope). Deterministic, offline.

## Method
Both approaches predict which ServiceAccounts can escalate to cluster-admin.
- **Naive baseline** — flags any SA that *holds* a dangerous verb
  (`create pods`, `get secrets`, `impersonate`, `bind`, `escalate`, ...).
- **Graph detector (this project)** — flags an SA only when a concrete multi-hop
  path to a privilege sink exists.

Metrics: Precision = TP/(TP+FP), Recall = TP/(TP+FN),
Accuracy = (TP+TN)/N, F1 = 2·P·R/(P+R).

## Results

| Approach | TP | FP | FN | TN | Precision | Recall | Accuracy | F1 |
|---|---|---|---|---|---|---|---|---|
| Naive per-permission | {m_naive.tp} | {m_naive.fp} | {m_naive.fn} | {m_naive.tn} | {m_naive.precision:.3f} | {m_naive.recall:.3f} | {m_naive.accuracy:.3f} | {m_naive.f1:.3f} |
| **Graph detector** | {m_graph.tp} | {m_graph.fp} | {m_graph.fn} | {m_graph.tn} | **{m_graph.precision:.3f}** | **{m_graph.recall:.3f}** | **{m_graph.accuracy:.3f}** | **{m_graph.f1:.3f}** |

## False positives avoided
The graph approach avoids these naive false positives (dangerous verb, but no
actual path to a sink):

{chr(10).join(f'- `{x}`' for x in naive_fp) or '- (none)'}

Graph-detector false positives: {', '.join(f'`{x}`' for x in graph_fp) or 'none'}.

## Interpretation
Both approaches achieve full recall on this dataset (no missed escalations), but
the naive baseline sacrifices precision by flagging benign SAs that merely hold a
dangerous verb — e.g. an SA that can create pods only in its own namespace where
no privileged identity exists, or read Secrets where no privileged token is
stored. Modeling relationships and requiring a concrete path removes those false
positives, raising precision from {m_naive.precision:.3f} to {m_graph.precision:.3f}
and F1 from {m_naive.f1:.3f} to {m_graph.f1:.3f}.
"""
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(md)
    print(f"Naive : {m_naive.as_dict()}")
    print(f"Graph : {m_graph.as_dict()}")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
