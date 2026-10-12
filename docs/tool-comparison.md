# Comparison with Existing Tools (Part 33)

| Tool | Purpose | SA analysis | RBAC graph | Multi-hop paths | Runtime correlation | Risk score | Visualization |
|---|---|---|---|---|---|---|---|
| `kubectl auth can-i` | single permission check | – | – | – | – | – | – |
| `rakkess` / `kubectl-who-can` | who has verb X | partial | – | – | – | – | – |
| Kubescape | posture / compliance | – | – | – | – | severity | limited |
| kube-bench | CIS benchmark | – | – | – | – | pass/fail | – |
| kube-hunter | pen-test recon | – | – | – | – | – | – |
| Popeye | resource hygiene | – | – | – | – | scores | – |
| Trivy | image / IaC / CVE | – | – | – | – | CVSS | – |
| **KubeHound** (Datadog) | attack-path graph | ✅ | ✅ | ✅ | ✗ (static) | ✅ | ✅ (Gremlin) |
| **KSA Detector** (this) | SA escalation + evidence | ✅ | ✅ | ✅ | **✅ audit** | ✅ contextual | ✅ (Cytoscape) |

## Honest positioning
KubeHound already performs static Kubernetes attack-path analysis at production
scale and is more mature. This project is **not** claiming to be the first graph
of Kubernetes attack paths.

## Defensible novelty of this work
1. **Static + runtime correlation.** A path is `REACHABLE` from configuration and
   promoted to `OBSERVED` when Kubernetes audit telemetry shows a matching hop was
   exercised. This static↔runtime bridge is the least-crowded contribution.
2. **Explainable, evidence-carrying paths.** Every hop names the exact bindings and
   roles that authorize it, plus a MITRE mapping and remediation.
3. **Context-aware, exploitability-weighted risk score** (impact × path-decay ×
   ease) with a five-level confidence lifecycle (POSSIBLE→CONFIRMED).
4. **A reproducible teaching lab** (10 vulnerable scenarios + secure fixes + safe
   attack simulation) and a labeled evaluation dataset with measured
   precision/recall/F1 against a naive baseline.

## Evidence
- Evaluation: `docs/results/evaluation.md` (F1 0.833 naive → 1.000 graph).
- Performance: `docs/results/benchmarks.md` (5,000 SAs full scan ~1 s).
