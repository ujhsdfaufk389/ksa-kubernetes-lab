# Evaluation Results

Dataset: `tests/fixtures/eval/` — 5 positive, 6 negative SAs
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
| Naive per-permission | 5 | 2 | 0 | 4 | 0.714 | 1.000 | 0.818 | 0.833 |
| **Graph detector** | 5 | 0 | 0 | 6 | **1.000** | **1.000** | **1.000** | **1.000** |

## False positives avoided
The graph approach avoids these naive false positives (dangerous verb, but no
actual path to a sink):

- `sa:dev/reader-sa`
- `sa:sandbox/sandbox-sa`

Graph-detector false positives: none.

## Interpretation
Both approaches achieve full recall on this dataset (no missed escalations), but
the naive baseline sacrifices precision by flagging benign SAs that merely hold a
dangerous verb — e.g. an SA that can create pods only in its own namespace where
no privileged identity exists, or read Secrets where no privileged token is
stored. Modeling relationships and requiring a concrete path removes those false
positives, raising precision from 0.714 to 1.000
and F1 from 0.833 to 1.000.
