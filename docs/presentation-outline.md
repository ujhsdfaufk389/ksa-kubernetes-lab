# Presentation Outline (Deliverable 19)

~15 slides for the FYP defense.

1. **Title** — Detection of Privilege Escalation Through Kubernetes Service Account Relationships.
2. **The problem** — RBAC is analyzed per-permission; real escalation is a *chain*. `web-sa` "create pods" looks harmless → becomes cluster-admin.
3. **Why existing tools miss it** — `kubectl auth can-i`, rakkess, Kubescape are per-object; a chain spans deployment→SA→binding→role→secret→SA. (Red Hat 2026, Datadog KubeHound.)
4. **Research question** — Can SA/RBAC/workload/token relationships be modeled as a graph to detect and *explain* multi-hop escalation, and can audit telemetry raise confidence?
5. **Background** — K8s identity model: pods, ServiceAccounts, projected tokens, RBAC (Role/ClusterRole/Bindings), the `bind`/`escalate` safeguards.
6. **Threat model** — assets, attacker (compromised pod = one low-priv SA), trust boundaries, STRIDE.
7. **Approach: the graph** — node/edge taxonomy; escalation reduces to reachability from an SA to a sink. Show the canonical path diagram.
8. **Escalation primitives** — the 10 primitives (create-pod-as, impersonate, token, bind, escalate, secret-cred, exec, hijack, wildcard, node) → MITRE ATT&CK.
9. **Architecture** — collector → parser → effective-perms → graph → detectors → path engine → risk → audit correlation → API → dashboard.
10. **Risk + confidence model** — impact × path-decay × exploitability; POSSIBLE→REACHABLE→OBSERVED→CONFIRMED.
11. **The differentiator** — static↔runtime correlation. Live: simulate → path flips to OBSERVED with audit evidence.
12. **Demo** — vulnerable lab → scan (CRITICAL findings) → dashboard graph → remediate → 0 paths. (See `docs/demo-script.md`.)
13. **Evaluation** — labeled dataset; naive F1 0.833 → graph F1 1.000 (0 false positives, full recall). Performance: 5,000 SAs in ~1 s.
14. **Limitations & future work** — snapshot TOCTOU; needs audit enabled; admission-policy simulation; OPA/Kyverno/Falco/eBPF/SIEM; GNN only if measurable benefit.
15. **Contributions & conclusion** — explainable multi-hop SA escalation detection with runtime correlation, a reproducible lab, and measured results.

**Backup slides:** graph model detail, effective-permission resolution (wildcards, group membership), audit policy, full MITRE table.
