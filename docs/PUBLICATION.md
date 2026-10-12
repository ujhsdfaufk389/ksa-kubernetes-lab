# Public source snapshot — 2026-10-12

Source: `/home/syco/Desktop/Priviliage/`. All 102 imported files other than README and .gitignore are byte-for-byte preserved, including backend, dashboard, cluster configuration, vulnerable/secure labs, tests, docs and fonts. The SHA-256 import manifest records original bytes. README and ignore rules have publication additions; license and audit files are new.

Excluded runtime data: real Kubernetes audit logs, generated reports and history, virtual environments, caches, credentials and installed egg metadata. Recreate results from the included fixtures or an authorized cluster. This publication does not alter the original desktop folder or its running server.

## Verification

- 53 pytest tests passed in the staged copy using the existing Python 3.13 environment; a fresh dependency installation was not tested.
- Verified imports resolve to the staged copy; health, offline fixture scan, advanced analysis and dashboard file checks passed.
- Common credential-pattern scan found no matches; this is not an exhaustive security review.
- Direct pinned dependency audit ran before commit: 8 findings in Jinja2 and pytest. The full tested-environment audit from the same publication session has 22 findings in Jinja2, pytest and Starlette. Raw counts include duplicate advisory IDs. Reports: `dependency-audit.json` and `dependency-audit-environment.json`. The audit is not clean. Original pins are retained to preserve the requested project; update dependencies before broader deployment.
- No real Kubernetes cluster operations were executed. Historical evaluation claims in the original README were not rerun.

## Portability

Run `scripts/create-cluster.sh` to regenerate the absolute host paths in `cluster/kind-config.yaml` when creating the optional local kind lab. Do not directly reuse its original workstation paths. The server script uses localhost port 8181. The offline fixture demo requires no real cluster and generates its own ignored reports directory. Existing dashboard scan data is not included.
