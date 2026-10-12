# KSA Kubernetes Lab

Complete source for the KSA privilege-escalation detector, Kubernetes lab scenarios, and browser dashboard.

## Download and run the offline demo

```sh
git clone https://github.com/ujhsdfaufk389/ksa-kubernetes-lab.git
cd ksa-kubernetes-lab
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -e .
KSA_DIRECTORY=tests/fixtures/eval bash scripts/serve.sh
```

Use Python 3.10+ (the original environment uses Python 3.13). Open **http://127.0.0.1:8181**. The offline demo requires no Kubernetes credentials. For a live authorized cluster, omit `KSA_DIRECTORY` and set `KSA_CONTEXT` to your kubeconfig context. The lab creation scripts below are optional and change only the cluster you configure; vulnerable manifests are intended for an isolated lab.

Original runtime source and dependency pins are preserved. The dependency audit has known Jinja2, pytest and Starlette findings; see [publication validation](docs/PUBLICATION.md) before deploying beyond localhost. Real audit logs, generated scan reports, credentials and virtual environments are excluded. Original historical notes follow; the current server script defaults to port **8181**, despite older references to 8088 below.

Code is available under the [MIT license](LICENSE). Vendored Cytoscape retains its embedded MIT notice; Inter, Fira Code and Bangers use the SIL Open Font License, copied into [docs/licenses](docs/licenses). The dashboard stylesheet also requests Google Fonts.

---

# KSA Detector — Kubernetes Service-Account Privilege-Escalation Detector

> Final Year Project — *Detection of Privilege Escalation Through Kubernetes Service Account Relationships*

Models a Kubernetes cluster's identities (ServiceAccounts), RBAC, workloads, secrets
and tokens as a **typed directed graph**, then finds **multi-hop privilege-escalation
paths** that per-permission tools like `kubectl auth can-i` cannot see — and correlates
them against **Kubernetes audit logs** to promote a theoretical path (`POSSIBLE`) to an
observed one (`OBSERVED`).

```
dev/web-sa ─create pods─▶ prod/admin-sa ─bound to─▶ cluster-admin
Risk 96/100 · CRITICAL · REACHABLE  ──(audit match)──▶ OBSERVED
```

## Why not just `kubectl auth can-i`?
That answers *one* permission for *one* subject. Real escalation is a **chain**:
`web-sa` can only "create pods" (harmless alone) → a pod can *run as* `admin-sa` →
`admin-sa` is `cluster-admin`. Only relationship/graph analysis reveals this.

## Architecture (high level)
```
K8s API + audit log
   → Collector → Parsers → Effective-Permission Resolver
   → Graph Builder (NetworkX) → Detectors + Path Engine + Risk Engine
   → Audit Correlator → FastAPI → React/Cytoscape dashboard + reports
```

## Status — all phases complete
| Phase | Component | State |
|---|---|---|
| 1 | Research foundation | ✅ `docs/thesis.md` |
| 2 | kind lab + audit logging + repo scaffold | ✅ |
| 3 | Collector (live read-only + offline YAML) | ✅ |
| 4–8 | Parsers → Effective perms → Graph → Path engine | ✅ |
| 9 | Vulnerable lab (10 scenarios, all primitives) | ✅ `lab/vulnerable/` |
| 10 | Audit correlation (REACHABLE→OBSERVED) + safe attack sim | ✅ |
| 11 | Live dashboard (FastAPI + Cytoscape, data-driven) | ✅ |
| 12 | Secure lab + before/after (11 non-system paths → 0) | ✅ `lab/secure/` |
| 13 | Risk + confidence scoring, MITRE registry | ✅ |
| 28/29 | CLI (`scan/paths/report`) + JSON/HTML/CSV reports | ✅ |
| 30 | Tests (34 passing, pytest) | ✅ `tests/` |
| 31 | Performance benchmarks (5k SAs ~1s) | ✅ `docs/results/benchmarks.md` |
| 32 | Evaluation (naive F1 0.833 → graph F1 1.000) | ✅ `docs/results/evaluation.md` |
| 33–35 | Tool comparison · threat model · MITRE mapping | ✅ `docs/` |
| 36 | Thesis (15 chapters) + demo + slides | ✅ `docs/` |

## Documentation
| Doc | Purpose |
|---|---|
| [`docs/thesis.md`](docs/thesis.md) | Full 15-chapter FYP thesis |
| [`docs/demo-script.md`](docs/demo-script.md) | 5-minute live demo (copy-paste) |
| [`docs/presentation-outline.md`](docs/presentation-outline.md) | 15-slide defense outline |
| [`docs/threat-model.md`](docs/threat-model.md) | STRIDE threat model |
| [`docs/mitre-mapping.md`](docs/mitre-mapping.md) | Primitive → ATT&CK mapping |
| [`docs/tool-comparison.md`](docs/tool-comparison.md) | vs kubectl/rakkess/KubeHound + novelty |
| [`docs/mitigations.md`](docs/mitigations.md) | Remediation + admission-policy guidance |
| [`docs/results/evaluation.md`](docs/results/evaluation.md) | Precision/Recall/F1 |
| [`docs/results/benchmarks.md`](docs/results/benchmarks.md) | Scaling to 5,000 SAs |

## Quick start (local lab only)
```bash
# 1) create the 3-node kind cluster with audit logging
bash scripts/create-cluster.sh

# 2) python env  (NOTE: use python3.13 — `python3` may be a conda 3.9 env)
python3.13 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt && pip install -e .

# 3) apply a lab scenario, then scan
kubectl apply -f lab/vulnerable/
ksa-detector scan --context kind-ksa-lab       # writes reports/security-report.json + graph.json
ksa-detector paths -s dev/web-sa --context kind-ksa-lab   # explain one SA's paths
ksa-detector report                            # -> reports/security-report.html

# 4) live dashboard (FastAPI + Cytoscape). Port 8088 (8000 is often taken locally)
bash scripts/serve.sh                           # then open http://127.0.0.1:8088
```

## Ethics & safety
All exploitation stays inside the **intentionally vulnerable local kind lab**.
Against any real/authorized cluster the tool runs in **passive observer mode**:
read-only, no RBAC changes, no token minting, no secret values dumped.

## Layout
```
ksa/            core library (collector, parser, graph, detectors, risk, api)
cluster/        kind config + audit policy
lab/            vulnerable/ and secure/ manifests
dashboard/      React + Cytoscape.js UI
tests/          pytest
docs/           thesis + design docs
scripts/        cluster + helper scripts
```
