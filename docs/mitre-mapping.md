# MITRE ATT&CK Mapping (Part 35)

Each detection primitive is mapped to techniques in the ATT&CK **for Containers**
matrix (and adjacent Enterprise techniques). Verify every ID against the current
matrix before publication: https://attack.mitre.org/matrices/enterprise/containers/

| Primitive (edge) | Technique | ID | Why relevant | Detector rule |
|---|---|---|---|---|
| `CREATE_POD_AS` | Deploy Container | T1610 | Attacker launches a pod bound to a higher-privileged SA | SA with `create pods` in a namespace hosting a privileged SA |
| `CREATE_POD_AS` / any SA reuse | Valid Accounts | T1078 | Acquiring/abusing an existing SA identity | Path terminates at an SA bound to cluster-admin |
| `WORKLOAD_HIJACK` | Deploy Container | T1610 | Editing a controller's pod template to swap the SA | SA with `patch/update` on controllers cross-namespace |
| `REQUEST_TOKEN` | Steal Application Access Token | T1528 | Minting a token for a privileged SA via TokenRequest | SA with `create serviceaccounts/token` |
| `REQUEST_TOKEN` (use) | Use Alt Auth Material: App Access Token | T1550.001 | Using the minted token to authenticate | Correlated audit `create serviceaccounts/token` |
| `IMPERSONATE` | Valid Accounts | T1078 | Acting as another identity via the impersonate verb | SA with `impersonate` on serviceaccounts/groups |
| `IMPERSONATE` (priv group) | Abuse Elevation Control Mechanism | T1548 | Impersonating `system:masters` | `impersonate groups` unrestricted |
| `EXEC_INTO` | Container Administration Command | T1609 | Exec into a privileged running container | SA with `pods/exec` where a privileged pod runs |
| `READ_SECRET_CRED` | Unsecured Credentials: Container API | T1552.007 | Reading a Secret holding an SA token | SA with `get/list secrets` where a token Secret exists |
| `CAN_BIND` | Account Manipulation | T1098 | Self-granting a role via the bind verb | SA with `bind` on roles/clusterroles |
| `CAN_ESCALATE` | Account Manipulation / Abuse Elevation | T1098 / T1548 | Adding rules beyond own via escalate verb | SA with `escalate` on roles/clusterroles |
| `NODE_ACCESS` | Escape to Host | T1611 | Reaching the node from a container/API | `nodes/proxy`, privileged pod, hostPath |

## Tactics covered
- **Privilege Escalation (TA0004)** — the primary tactic of every path.
- **Credential Access (TA0006)** — token minting, secret reading.
- **Persistence (TA0003)** — bind/escalate creating durable grants.
- **Lateral Movement / Execution** — workload creation, exec.

## Runtime correlation
When an audit event matches a path's entry primitive, the finding is promoted to
`OBSERVED` — turning a mapped *technique* into observed *activity*, the basis for
detection engineering (e.g., feeding a SIEM/Wazuh rule).
