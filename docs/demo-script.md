# Demo Script (Deliverable 18)

A ~5-minute live demonstration: build → detect → confirm at runtime → remediate →
verify clean. Copy-paste friendly.

## 0. One-time setup
```bash
bash scripts/create-cluster.sh          # 3-node kind cluster, audit logging on
python3.13 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt && pip install -e .
```

## 1. Deploy the vulnerable lab
```bash
kubectl apply -f lab/vulnerable/
```
> 10 intentional RBAC mistakes across dev / staging / production / security.

## 2. Detect (static)
```bash
ksa-detector scan --context kind-ksa-lab
```
> Reports ~11 non-system escalation paths. Highlight the money finding:
> `dev/web-sa --CREATE_POD_AS--> production/admin-sa --IS_CLUSTER_ADMIN--> cluster-admin`
> and note `kubectl auth can-i` would only see "web-sa can create pods".

```bash
ksa-detector paths -s dev/web-sa --context kind-ksa-lab   # full explained chain
```

## 3. Open the dashboard
```bash
bash scripts/serve.sh                    # http://127.0.0.1:8088
```
> Walk: Overview (risk ranking, severity) → Escalation Paths (hops + evidence +
> MITRE + remediation) → Relationship Graph (click nodes) → Audit Correlation.

## 4. Confirm at runtime (safe simulation)
```bash
bash scripts/simulate-attacks.sh         # kubectl --as, LOCAL LAB ONLY
```
> Click **Re-scan** in the dashboard. `web-sa` and `backup-sa` flip
> **REACHABLE → OBSERVED** — the audit log confirms the paths were exercised.

## 5. Remediate
```bash
bash scripts/apply-secure.sh
ksa-detector scan --context kind-ksa-lab
```
> Non-system escalation paths drop from ~11 to **0**. Show `docs/mitigations.md`
> for why RBAC alone can't pin `serviceAccountName` (Kyverno policy).

## 6. Evidence (for the report)
```bash
python scripts/evaluate.py               # precision/recall/F1 vs naive baseline
python scripts/benchmark.py              # scaling to 5,000 SAs
```

## Reset
```bash
bash scripts/apply-vulnerable.sh         # back to the vulnerable state
```
