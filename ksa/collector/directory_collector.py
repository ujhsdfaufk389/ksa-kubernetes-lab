"""Offline collection: build a ClusterSnapshot from a directory of YAML manifests.

Enables `ksa-detector scan --directory ./lab/vulnerable` with no cluster, and is
the basis for deterministic pytest fixtures (Phase 30). Understands multi-document
YAML files and the same object kinds as the live collector.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

import yaml

from ksa.models import (
    ClusterSnapshot,
    Container,
    Namespace,
    PolicyRule,
    Role,
    RoleBinding,
    RoleRef,
    Secret,
    ServiceAccount,
    Subject,
    SubjectKind,
    Workload,
    WorkloadKind,
)

log = logging.getLogger(__name__)

_SA_TOKEN_ANNOTATION = "kubernetes.io/service-account.name"
_PSA_ENFORCE_LABEL = "pod-security.kubernetes.io/enforce"

_WORKLOAD_KINDS = {
    "Pod": WorkloadKind.POD,
    "Deployment": WorkloadKind.DEPLOYMENT,
    "StatefulSet": WorkloadKind.STATEFULSET,
    "DaemonSet": WorkloadKind.DAEMONSET,
    "ReplicaSet": WorkloadKind.REPLICASET,
    "Job": WorkloadKind.JOB,
    "CronJob": WorkloadKind.CRONJOB,
}


class DirectoryCollector:
    """Loads YAML manifests from a directory tree into a ClusterSnapshot."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def collect(self) -> ClusterSnapshot:
        snap = ClusterSnapshot()
        for doc in self._iter_docs():
            self._dispatch(doc, snap)
        log.info("Loaded snapshot from %s: %s", self.path, snap.summary())
        return snap

    # ---- file iteration -------------------------------------------------
    def _iter_docs(self) -> Iterable[dict[str, Any]]:
        if self.path.is_file():
            files = [self.path] if self.path.suffix.lower() in (".yaml", ".yml") else []
        else:
            files = sorted(
                [p for p in self.path.rglob("*") if p.suffix.lower() in (".yaml", ".yml")]
            )
        if not files:
            log.warning("No YAML files under %s", self.path)
        for f in files:
            try:
                for doc in yaml.safe_load_all(f.read_text()):
                    if isinstance(doc, dict) and doc.get("kind"):
                        yield doc
            except yaml.YAMLError as exc:
                log.error("Failed to parse %s: %s", f, exc)

    # ---- dispatch -------------------------------------------------------
    def _dispatch(self, doc: dict[str, Any], snap: ClusterSnapshot) -> None:
        kind = doc.get("kind")
        meta = doc.get("metadata", {}) or {}
        name = meta.get("name")
        ns = meta.get("namespace")
        if not name:
            return

        if kind == "Namespace":
            labels = meta.get("labels", {}) or {}
            snap.namespaces.append(
                Namespace(name=name, pod_security_enforce=labels.get(_PSA_ENFORCE_LABEL))
            )
        elif kind == "ServiceAccount":
            amt = doc.get("automountServiceAccountToken")
            snap.service_accounts.append(
                ServiceAccount(
                    name=name,
                    namespace=ns or "default",
                    automount_token=True if amt is None else bool(amt),
                    secret_names=[s.get("name") for s in doc.get("secrets", []) if s.get("name")],
                    annotations=dict(meta.get("annotations", {}) or {}),
                )
            )
        elif kind == "Role":
            snap.roles.append(Role(name=name, namespace=ns or "default", rules=self._rules(doc)))
        elif kind == "ClusterRole":
            agg = (doc.get("aggregationRule", {}) or {}).get("clusterRoleSelectors", []) or []
            selectors = [dict(s.get("matchLabels", {}) or {}) for s in agg if s.get("matchLabels")]
            snap.roles.append(Role(
                name=name, namespace=None, rules=self._rules(doc),
                labels=dict((meta.get("labels", {}) or {})),
                aggregation_selectors=selectors,
            ))
        elif kind == "RoleBinding":
            snap.bindings.append(self._binding(doc, name, ns or "default"))
        elif kind == "ClusterRoleBinding":
            snap.bindings.append(self._binding(doc, name, None))
        elif kind == "Secret":
            ann = meta.get("annotations", {}) or {}
            snap.secrets.append(
                Secret(
                    name=name,
                    namespace=ns or "default",
                    type=doc.get("type", "Opaque"),
                    service_account_name=ann.get(_SA_TOKEN_ANNOTATION),
                )
            )
        elif kind in _WORKLOAD_KINDS:
            snap.workloads.append(self._workload(doc, _WORKLOAD_KINDS[kind], name, ns or "default"))

    # ---- builders -------------------------------------------------------
    @staticmethod
    def _rules(doc: dict[str, Any]) -> list[PolicyRule]:
        out = []
        for r in doc.get("rules", []) or []:
            out.append(
                PolicyRule(
                    verbs=list(r.get("verbs", []) or []),
                    api_groups=list(r.get("apiGroups", []) or []),
                    resources=list(r.get("resources", []) or []),
                    resource_names=list(r.get("resourceNames", []) or []),
                    non_resource_urls=list(r.get("nonResourceURLs", []) or []),
                )
            )
        return out

    @staticmethod
    def _binding(doc: dict[str, Any], name: str, ns: str | None) -> RoleBinding:
        rr = doc.get("roleRef", {}) or {}
        subjects = []
        for s in doc.get("subjects", []) or []:
            try:
                kind = SubjectKind(s.get("kind"))
            except ValueError:
                continue
            subjects.append(
                Subject(kind=kind, name=s.get("name"), namespace=s.get("namespace"))
            )
        return RoleBinding(
            name=name,
            namespace=ns,
            role_ref=RoleRef(kind=rr.get("kind", "Role"), name=rr.get("name", "")),
            subjects=subjects,
        )

    @staticmethod
    def _pod_spec(doc: dict[str, Any], kind: WorkloadKind) -> dict[str, Any]:
        spec = doc.get("spec", {}) or {}
        if kind == WorkloadKind.POD:
            return spec
        if kind == WorkloadKind.CRONJOB:
            return (
                spec.get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        # Deployment/StatefulSet/DaemonSet/Job/ReplicaSet
        return spec.get("template", {}).get("spec", {})

    def _workload(
        self, doc: dict[str, Any], kind: WorkloadKind, name: str, ns: str
    ) -> Workload:
        pod = self._pod_spec(doc, kind)
        containers = []
        for c in pod.get("containers", []) or []:
            sc = c.get("securityContext", {}) or {}
            caps = ((sc.get("capabilities") or {}).get("add")) or []
            containers.append(
                Container(
                    name=c.get("name", ""),
                    image=c.get("image", ""),
                    privileged=bool(sc.get("privileged", False)),
                    allow_privilege_escalation=sc.get("allowPrivilegeEscalation"),
                    run_as_user=sc.get("runAsUser"),
                    added_capabilities=list(caps),
                )
            )
        host_paths = [
            v.get("name")
            for v in (pod.get("volumes", []) or [])
            if "hostPath" in v and v.get("name")
        ]
        return Workload(
            kind=kind,
            name=name,
            namespace=ns,
            service_account_name=(pod.get("serviceAccountName") or pod.get("serviceAccount") or "default"),
            automount_token=pod.get("automountServiceAccountToken"),
            host_network=bool(pod.get("hostNetwork", False)),
            host_pid=bool(pod.get("hostPID", False)),
            host_path_volumes=host_paths,
            containers=containers,
        )
