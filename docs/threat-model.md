# Threat Model (Part 34)

## Scope
A multi-tenant Kubernetes cluster where workloads run under ServiceAccounts and
access is governed by RBAC. The detector analyzes this configuration; it does not
defend the workloads at runtime.

## Assets
| Asset | Why it matters |
|---|---|
| `cluster-admin` (and equivalents) | Full control of the cluster and all workloads |
| ServiceAccount tokens | Bearer credentials that *are* an identity to the API server |
| Secrets | App credentials, and (legacy) SA tokens |
| etcd / control plane | Ground truth of all cluster state |
| Nodes | Host all pods' tokens and workloads |

## Actors / attackers
| Actor | Starting capability |
|---|---|
| Compromised app pod | Code execution as a low-privileged SA (stolen via app RCE/SSRF) |
| Malicious/negligent developer | Ability to deploy workloads in one namespace |
| Supply-chain foothold | A container image running in the cluster |
| Insider | A scoped ServiceAccount/kubeconfig |

## Entry points
- A pod's mounted SA token (`/var/run/secrets/...`).
- The Kubernetes API server (authenticated as an SA).
- `kubectl`/CI credentials scoped to a namespace.

## Trust boundaries
1. Container ↔ node (escape).
2. Namespace ↔ namespace (RBAC scoping).
3. ServiceAccount ↔ ServiceAccount (identity reuse via pods/tokens/impersonation).
4. Authenticated user ↔ cluster-admin (privilege boundary — the one this project measures).

## Assumptions
- The attacker has, or can obtain, one low-privileged ServiceAccount identity.
- RBAC is the primary authorization mechanism (no external policy engine assumed,
  though the tool notes when PSA/OPA/Kyverno would block a path).
- Audit logging is available for the correlation feature (optional).

## STRIDE (identity/RBAC focus)
| Threat | Example in scope | Detector coverage |
|---|---|---|
| **S**poofing | Impersonate verb; using another SA's token | `IMPERSONATE`, token/secret primitives |
| **T**ampering | Patch a deployment to change its SA | `WORKLOAD_HIJACK` |
| **R**epudiation | Actions taken as an impersonated identity | Audit correlation records real vs impersonated user |
| **I**nformation disclosure | Reading Secrets holding tokens | `READ_SECRET_CRED` |
| **E**levation of privilege | Any path to cluster-admin | Entire path engine (primary focus) |
| **D**enial of service | Out of scope (not a privilege concern) | — |

## Out of scope
Kernel/CVE container escapes (modeled as `NODE_ACCESS` edges but not exploited),
network attacks, DoS, and application-layer vulnerabilities.
