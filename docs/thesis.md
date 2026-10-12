# Detection of Privilege Escalation Through Kubernetes Service Account Relationships

**Final Year Project — BS Computer Science / Cybersecurity**

> A graph-based system that models Kubernetes identities, RBAC, workloads, secrets
> and tokens as a directed graph, discovers direct and indirect (multi-hop)
> privilege-escalation paths, and correlates them with API-server audit telemetry
> to distinguish theoretical paths from observed attempts.

---

## Chapter 1 — Introduction

Kubernetes authorization is governed by Role-Based Access Control (RBAC), which
grants *verbs* on *resources* to *subjects* (users, groups, ServiceAccounts).
Security tooling typically evaluates these grants one at a time: "can subject X
perform verb Y on resource Z?". Real privilege escalation, however, rarely comes
from a single dangerous permission. It emerges from **chains of relationships**:
a ServiceAccount that may only "create pods" can launch a pod bound to a
higher-privileged ServiceAccount, whose token then grants control of the cluster.

This project builds a working detector that models these relationships as a graph
and searches for escalation paths, then confirms them against runtime audit logs.

**Objectives.** (O1) Losslessly model K8s identity/RBAC as a typed graph; (O2)
detect 1-hop and multi-hop escalations across ≥10 scenarios; (O3) correlate audit
events to raise path confidence; (O4) produce a context-aware risk score that
reduces false positives; (O5) evaluate precision/recall/F1 against a baseline and
benchmark to thousands of identities.

## Chapter 2 — Background

**Control plane & identity.** The API server authenticates every request and
authorizes it via RBAC. A pod runs under a ServiceAccount (SA); unless
`automountServiceAccountToken` is false, the pod receives a projected token at
`/var/run/secrets/kubernetes.io/serviceaccount/token`. Code execution in a pod is
therefore equivalent to holding that SA's identity.

**RBAC.** A `Role` (namespaced) or `ClusterRole` (cluster-scoped) lists rules of
`verbs × apiGroups × resources` (with optional `resourceNames`). A `RoleBinding`
or `ClusterRoleBinding` grants a role to subjects. A `RoleBinding` may reference a
`ClusterRole`, applying it within one namespace.

**Two built-in safeguards** (kubernetes.io RBAC docs): the API server blocks
creating a Role with more rules than the caller holds *unless* the caller has the
`escalate` verb; and blocks binding a role the caller couldn't otherwise grant
*unless* the caller has the `bind` verb. These verbs are therefore crown-jewel
capabilities in our model.

**Privilege escalation in Kubernetes** means moving from a lower-privileged
identity to a higher one — ultimately `cluster-admin` or node/host access.

## Chapter 3 — Literature Review

**Official.** Kubernetes RBAC, ServiceAccount, TokenRequest and Auditing
documentation; NSA/CISA *Kubernetes Hardening Guidance* v1.2 (2022-08-29), which
emphasizes least privilege, disabling unnecessary token automount, and audit
logging. MITRE ATT&CK **for Containers** matrix provides the technique taxonomy.
OWASP Kubernetes Top 10 (2025) lists RBAC misconfiguration (K02) and secrets
management (K03) as top risks.

**Industry.** Datadog's **KubeHound** is the closest prior art: it ingests cluster
state and builds an attack-path graph (JanusGraph/Gremlin). Red Hat's 2026 article
*"Why your RBAC linter misses privilege-escalation chains"* articulates exactly the
per-binding blindness this project targets. CROSSGUARD extends the idea across the
K8s↔AWS-IAM boundary.

**Academic.** Peer-reviewed work specific to Kubernetes ServiceAccount escalation
graphs remains sparse; the graph methodology draws on classical attack-graph
theory (scalable graph-based vulnerability analysis) applied to the K8s identity
domain. (Specific IEEE/ACM references to be finalized from the university library.)

**Gap.** Existing tools are either per-permission (miss chains) or static-only
(KubeHound). None correlate the static graph with runtime audit evidence to move a
finding from *possible* to *observed*, nor emphasize explainability + a
reproducible teaching lab with measured accuracy.

## Chapter 4 — Problem Statement

Traditional Kubernetes RBAC analysis examines permissions individually, while real
privilege escalation emerges through chains of relationships between
ServiceAccounts, RBAC bindings, workloads, secrets and token capabilities. There
is no widely adopted, explainable tool that (a) discovers multi-hop
ServiceAccount escalation paths and (b) confirms them against runtime telemetry.
This project proposes a graph-based detection system that identifies, scores and
*explains* direct and indirect escalation paths, and correlates them with
Kubernetes audit events.

## Chapter 5 — Threat Model

See `docs/threat-model.md`. In brief: the attacker starts with one low-privileged
ServiceAccount (e.g., a compromised application pod). Assets are cluster-admin,
SA tokens, secrets, nodes and etcd. The privilege boundary of interest is
authenticated-SA → cluster-admin. A STRIDE analysis maps spoofing (impersonation),
tampering (workload hijack), information disclosure (secret/token theft) and
elevation of privilege (all paths) to detector primitives.

## Chapter 6 — Proposed Architecture

```
K8s API + audit log
  → Collector (live, read-only | offline YAML)
  → Parsers (typed Pydantic models)
  → Effective-Permission Resolver (Role∪ClusterRole + groups + wildcards)
  → Graph Builder (NetworkX MultiDiGraph)
  → Detectors + Path Engine (shortest_simple_paths to sinks)
  → Risk & Confidence Engine
  → Audit Correlator (REACHABLE → OBSERVED)
  → FastAPI  →  React/Cytoscape dashboard + JSON/HTML/CSV reports
```
Everything before the API is a pure library with no web dependency, which keeps
the core unit-testable. Design rationale for each component and technology choice
is recorded in the repository README and `docs/`.

## Chapter 7 — Graph Model

**Nodes:** ServiceAccount, User, Group, Role, ClusterRole, RoleBinding,
ClusterRoleBinding, Workload, Secret, Namespace, and synthetic **Sink** nodes
(`cluster-admin`, `node-access`).

**Structural edges** describe how RBAC is wired: `BOUND_TO` (subject→binding),
`GRANTS` (binding→role), `RUNS_AS` (workload→SA), `LOCATED_IN`.

**Escalation-action edges** each represent one attacker step:
`CREATE_POD_AS`, `WORKLOAD_HIJACK`, `REQUEST_TOKEN`, `IMPERSONATE`, `EXEC_INTO`,
`READ_SECRET_CRED`, `CAN_BIND`, `CAN_ESCALATE`, `IS_CLUSTER_ADMIN`, `NODE_ACCESS`.

Detection reduces to **reachability**: does a directed path of action edges exist
from a source ServiceAccount to any sink? Each edge carries the bindings/roles that
authorize it, making every finding explainable.

## Chapter 8 — Detection Methodology

**Effective permissions.** For each SA we union all rules reachable through its
bindings, including implicit group memberships (`system:authenticated`,
`system:serviceaccounts`, `system:serviceaccounts:<ns>`), resolving wildcards and
namespace scope (cluster-wide vs namespaced).

**Edge derivation.** From effective permissions we derive action edges, e.g. an SA
that can `create pods` in namespace N gets a `CREATE_POD_AS` edge to every SA in N
(a pod author chooses `serviceAccountName`). Already-cluster-admin SAs are excluded
as sources (they are not *escalating*).

**Path discovery.** `networkx.shortest_simple_paths` enumerates shortest-first
paths from each source to each sink, capped by `max_hops`, so the most direct
routes are always found.

**Risk score.** `score = impact(sink) × length_factor × exploitability(weakest
hop)` (+ small bonus for direct-grant primitives), clamped to [0,100], mapped to
CRITICAL/HIGH/MEDIUM/LOW. This rewards short, easily-exploited paths and discounts
long, fragile ones.

**Confidence lifecycle.** POSSIBLE → LIKELY → REACHABLE (graph-confirmed) →
OBSERVED (audit match) → CONFIRMED (validated in the lab).

**Runtime correlation.** Audit events are matched to each path's entry primitive
(actor SA, verb, resource, and — for pods — the requested `serviceAccountName`);
a match promotes the finding to OBSERVED and attaches the evidence.

## Chapter 9 — Implementation

Python 3.13; NetworkX (graph); Pydantic (models); the official `kubernetes`
client (read-only collection); Typer + Rich (CLI); FastAPI + Uvicorn (API);
Cytoscape.js (graph visualization) on a dark SOC-console dashboard. Package layout:
`ksa/{collector,parser,graph,detectors,risk,api}`, plus `correlation.py`,
`analyzer.py`, `evaluation.py`, `synth.py`. The CLI (`ksa-detector scan|paths|
report`) and the API both call the same pure-library core. All collection is
read-only; a **passive observer mode** never mutates state or reads Secret values.

## Chapter 10 — Experimental Lab

A 3-node `kind` cluster (1 control-plane + 2 workers) with API-server audit
logging enabled via a custom policy that captures pod-create request objects,
token requests, RBAC mutations, secret access (metadata only) and impersonation.
Ten intentionally-vulnerable scenarios (`lab/vulnerable/`) cover every primitive;
matching least-privilege fixes (`lab/secure/`) enable a before/after demonstration.
A safe attack simulation (`scripts/simulate-attacks.sh`) uses `kubectl --as` to
generate real audit events without extracting any tokens — local lab only.

## Chapter 11 — Results

**Detection coverage.** On the vulnerable lab the detector reports **11 non-system
escalation paths** spanning all eight primitives, correctly flagging the 12+
system controllers separately as expected. Example (verified live):
`dev/web-sa --CREATE_POD_AS@production--> production/admin-sa --IS_CLUSTER_ADMIN-->
cluster-admin`, risk 90, CRITICAL.

**Runtime correlation.** After the safe simulation, the `web-sa` (create-pod) and
`backup-sa` (token) paths were promoted **REACHABLE → OBSERVED**, each matched to
its audit event (`serviceAccountName=admin-sa`; token for `admin-sa`).

**Remediation.** Applying the secure configuration reduced non-system escalation
paths from **11 to 0** (before/after), demonstrating effectiveness.

## Chapter 12 — Evaluation

On a labeled dataset (`tests/fixtures/eval/`, `docs/results/evaluation.md`):

| Approach | Precision | Recall | Accuracy | F1 |
|---|---|---|---|---|
| Naive per-permission | 0.714 | 1.000 | 0.818 | 0.833 |
| **Graph detector** | **1.000** | **1.000** | **1.000** | **1.000** |

Both achieve full recall, but the naive baseline over-flags benign SAs that merely
hold a dangerous verb (e.g. create-pods in their own namespace where no privileged
identity exists). Requiring a concrete path removes those false positives.

**Performance** (`docs/results/benchmarks.md`): near-linear scaling — 5,000
ServiceAccounts build the graph in ~0.78 s and complete a full scan in ~1.0 s on
the development laptop (i7-13700H, 32 GB), peak ~31 MB. Real clusters rarely exceed
a few thousand identities, so the in-process NetworkX model is more than adequate.

## Chapter 13 — Limitations

The graph is a **snapshot** (TOCTOU between scan and reality). Some escalations
require CVEs/kernel escapes, which we model as edges but do not exploit. Runtime
correlation needs audit logging enabled (restricted on some managed clusters).
Secret contents are not read, so app-credential-in-secret edges are certain only
in the lab. Admission policies (OPA/Kyverno/PSA) can block a "reachable" path — we
flag but do not fully simulate them in v1.

## Chapter 14 — Future Work

Admission-policy awareness (Kyverno/OPA Gatekeeper), Falco/eBPF runtime signals,
SIEM export (Wazuh/Elastic/Splunk), continuous monitoring mode, Neo4j Mode-2
visualization, and — only if a measurable benefit is demonstrated — graph machine
learning (GNN) for anomaly ranking. Cross-cloud edges (IRSA→IAM) as in CROSSGUARD.

## Chapter 15 — Conclusion

The project delivers a working, explainable, graph-based detector for Kubernetes
ServiceAccount privilege escalation. Its defensible contributions are the
static↔runtime **audit correlation** that turns theoretical paths into observed
attempts, explainable evidence-carrying paths with MITRE mapping, a context-aware
risk/confidence model, and a reproducible lab with measured precision/recall/F1
(F1 0.833 → 1.000 versus a naive baseline) and performance to thousands of
identities.

---

## References
(Verify each against the live source before submission; do not cite unseen works.)

1. Kubernetes — *Using RBAC Authorization* (incl. privilege-escalation prevention). kubernetes.io/docs/reference/access-authn-authz/rbac/
2. Kubernetes — *ServiceAccounts* & projected tokens. kubernetes.io/docs/concepts/security/service-accounts/
3. Kubernetes — *TokenRequest API*. kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/
4. Kubernetes — *Auditing*. kubernetes.io/docs/tasks/debug/debug-cluster/audit/
5. NSA & CISA — *Kubernetes Hardening Guidance*, v1.2, 2022-08-29. media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
6. MITRE ATT&CK — *Containers matrix*. attack.mitre.org/matrices/enterprise/containers/
7. OWASP — *Kubernetes Top 10* (2025). owasp.org/www-project-kubernetes-top-ten/
8. Datadog — *KubeHound*. github.com/DataDog/KubeHound
9. Red Hat — *Why your RBAC linter misses privilege-escalation chains* (2026). developers.redhat.com/articles/2026/07/07/...
10. CNCF — *MITRE ATT&CK matrix for Kubernetes* (2021-10-19). cncf.io/blog/2021/10/19/mitre-attck-matrix-for-kubernetes/
