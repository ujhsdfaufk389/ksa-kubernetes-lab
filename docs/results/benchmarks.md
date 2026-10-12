# Performance Benchmarks

Synthetic clusters (`ksa/synth.py`), ~8% of ServiceAccounts given a genuine
escalation path. Measured on the development laptop (i7-13700H, 32 GB).
Times in milliseconds, memory = peak `tracemalloc` (MB).

| ServiceAccounts | Graph nodes | Graph edges | Findings | Build (ms) | Paths (ms) | Full scan (ms) | Peak mem (MB) |
|---|---|---|---|---|---|---|---|
| 100 | 207 | 214 | 11 | 15.2 | 2.0 | 19.9 | 0.7 |
| 500 | 1007 | 1056 | 53 | 72.3 | 2.5 | 98.1 | 3.2 |
| 1000 | 2007 | 2097 | 94 | 147.1 | 4.3 | 196.4 | 6.3 |
| 5000 | 10007 | 10401 | 398 | 776.5 | 19.7 | 1015.8 | 30.6 |

## Notes
- Graph build and path discovery scale comfortably to 5,000 ServiceAccounts in
  well under a second of core compute — the NetworkX in-process model is more than
  adequate for real clusters, which rarely exceed a few thousand identities.
- "Full scan" includes effective-permission resolution, graph build, path finding,
  scoring and serialization (no live API latency, which dominates in practice).
- Path discovery uses `shortest_simple_paths`; capping `max_paths_per_source`
  keeps worst-case enumeration bounded on dense graphs.
