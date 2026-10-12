# Mitigation Guide

How each detected primitive is remediated, and why RBAC alone is sometimes not
enough. The `lab/secure/` manifests implement the RBAC-level fixes; the admission
policies below close the remaining gaps.

## Per-primitive remediation

| Primitive | RBAC fix | Defence-in-depth |
|---|---|---|
| `CREATE_POD_AS` | Remove cross-namespace pod-create; scope to the SA's own namespace | Admission policy pinning `serviceAccountName` (below) |
| `WORKLOAD_HIJACK` | Scope `patch/update` on controllers to one environment | Same admission policy; separate deploy RBAC per env |
| `REQUEST_TOKEN` | Remove `serviceaccounts/token`; if needed, restrict with `resourceNames` | Short-lived, audience-bound projected tokens |
| `IMPERSONATE` | Remove the `impersonate` verb; use scoped read-only roles | Restrict impersonation to named `resourceNames` |
| `READ_SECRET_CRED` | Scope `get/list secrets` with `resourceNames` | External secret store; disable legacy SA token secrets |
| `CAN_BIND` / `CAN_ESCALATE` | Remove `bind`/`escalate`; reserve for trusted controllers | Alert on any use in audit |
| `NODE_ACCESS` | Remove `nodes/proxy`, privileged pods, `hostPath` | Enforce `restricted` Pod Security Admission |

## Why RBAC can't pin `serviceAccountName`

Kubernetes RBAC authorizes *verbs on resources*; it cannot say "you may create a
pod, but only with `serviceAccountName: X`". So a subject with `create pods` in a
namespace can launch a pod as **any** SA in that namespace. Closing this needs an
admission policy.

### Kyverno example — allow only a workload's own SA
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-serviceaccount
spec:
  validationFailureAction: Enforce
  rules:
    - name: pin-sa
      match:
        any:
          - resources:
              kinds: ["Pod"]
              namespaces: ["production"]
      validate:
        message: "Pods in production may only use the 'workload-sa' ServiceAccount."
        pattern:
          spec:
            serviceAccountName: "workload-sa"
```

### Also recommended (NSA/CISA Kubernetes Hardening Guidance v1.2)
- `automountServiceAccountToken: false` on SAs and pods that don't call the API.
- Enforce Pod Security Admission `restricted` on application namespaces.
- Enable and centrally collect audit logs (this project consumes them for
  runtime correlation).

References: kubernetes.io RBAC docs (privilege-escalation prevention), NSA/CISA
Kubernetes Hardening Guidance v1.2 (2022-08-29).
