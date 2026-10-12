"""Live, READ-ONLY collection of cluster objects via the official client-python.

Safety (Part 27 — passive observer mode):
  * only GET/LIST calls are ever issued;
  * Secret *values* are NEVER read — we list Secret metadata only;
  * nothing is created, patched, or deleted.

Produces a `ClusterSnapshot` consumed by the graph builder.
"""
from __future__ import annotations

import logging
from typing import Optional

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

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


class KubernetesCollector:
    """Collects a ClusterSnapshot from a live cluster (read-only)."""

    def __init__(
        self,
        kubeconfig: Optional[str] = None,
        context: Optional[str] = None,
        namespaces: Optional[list[str]] = None,
    ) -> None:
        """Load kube config and build API clients.

        Args:
            kubeconfig: path to kubeconfig (None -> default resolution / in-cluster).
            context: kube context name (e.g. 'kind-ksa-lab').
            namespaces: restrict namespaced collection; None/[] means all.
        """
        try:
            config.load_kube_config(config_file=kubeconfig, context=context)
            log.info("Loaded kubeconfig (context=%s)", context or "default")
        except config.ConfigException:
            config.load_incluster_config()
            log.info("Loaded in-cluster config")

        self._core = client.CoreV1Api()
        self._rbac = client.RbacAuthorizationV1Api()
        self._apps = client.AppsV1Api()
        self._batch = client.BatchV1Api()
        self._namespaces_filter = set(namespaces or [])

    # ---- public API -----------------------------------------------------
    def collect(self) -> ClusterSnapshot:
        """Collect everything into a single snapshot."""
        snap = ClusterSnapshot(
            namespaces=self._collect_namespaces(),
            service_accounts=self._collect_service_accounts(),
            roles=self._collect_roles() + self._collect_cluster_roles(),
            bindings=self._collect_role_bindings() + self._collect_cluster_role_bindings(),
            workloads=self._collect_workloads(),
            secrets=self._collect_secrets(),
        )
        log.info("Collected snapshot: %s", snap.summary())
        return snap

    # ---- helpers --------------------------------------------------------
    def _keep_ns(self, ns: Optional[str]) -> bool:
        return not self._namespaces_filter or ns in self._namespaces_filter

    @staticmethod
    def _rules(raw_rules) -> list[PolicyRule]:
        out: list[PolicyRule] = []
        for r in raw_rules or []:
            out.append(
                PolicyRule(
                    verbs=list(r.verbs or []),
                    api_groups=list(r.api_groups or []),
                    resources=list(r.resources or []),
                    resource_names=list(r.resource_names or []),
                    non_resource_urls=list(r.non_resource_ur_ls or []),
                )
            )
        return out

    @staticmethod
    def _subjects(raw_subjects) -> list[Subject]:
        out: list[Subject] = []
        for s in raw_subjects or []:
            try:
                kind = SubjectKind(s.kind)
            except ValueError:
                log.warning("Unknown subject kind %r, skipping", s.kind)
                continue
            out.append(Subject(kind=kind, name=s.name, namespace=getattr(s, "namespace", None)))
        return out

    # ---- collectors -----------------------------------------------------
    def _collect_namespaces(self) -> list[Namespace]:
        items = self._core.list_namespace().items
        out = []
        for ns in items:
            name = ns.metadata.name
            if not self._keep_ns(name):
                continue
            labels = ns.metadata.labels or {}
            out.append(Namespace(name=name, pod_security_enforce=labels.get(_PSA_ENFORCE_LABEL)))
        return out

    def _collect_service_accounts(self) -> list[ServiceAccount]:
        items = self._core.list_service_account_for_all_namespaces().items
        out = []
        for sa in items:
            if not self._keep_ns(sa.metadata.namespace):
                continue
            automount = sa.automount_service_account_token
            out.append(
                ServiceAccount(
                    name=sa.metadata.name,
                    namespace=sa.metadata.namespace,
                    automount_token=True if automount is None else bool(automount),
                    secret_names=[s.name for s in (sa.secrets or []) if s.name],
                    annotations=dict(sa.metadata.annotations or {}),
                )
            )
        return out

    def _collect_roles(self) -> list[Role]:
        items = self._rbac.list_role_for_all_namespaces().items
        return [
            Role(name=r.metadata.name, namespace=r.metadata.namespace, rules=self._rules(r.rules))
            for r in items
            if self._keep_ns(r.metadata.namespace)
        ]

    @staticmethod
    def _aggregation_selectors(raw) -> list[dict]:
        """Extract matchLabels selectors from a ClusterRole's aggregationRule."""
        agg = getattr(raw, "aggregation_rule", None)
        if not agg or not getattr(agg, "cluster_role_selectors", None):
            return []
        out = []
        for sel in agg.cluster_role_selectors:
            ml = getattr(sel, "match_labels", None) or {}
            if ml:
                out.append(dict(ml))
        return out

    def _collect_cluster_roles(self) -> list[Role]:
        items = self._rbac.list_cluster_role().items
        return [
            Role(
                name=r.metadata.name,
                namespace=None,
                rules=self._rules(r.rules),
                labels=dict(r.metadata.labels or {}),
                aggregation_selectors=self._aggregation_selectors(r),
            )
            for r in items
        ]

    def _collect_role_bindings(self) -> list[RoleBinding]:
        items = self._rbac.list_role_binding_for_all_namespaces().items
        out = []
        for b in items:
            if not self._keep_ns(b.metadata.namespace):
                continue
            out.append(
                RoleBinding(
                    name=b.metadata.name,
                    namespace=b.metadata.namespace,
                    role_ref=RoleRef(kind=b.role_ref.kind, name=b.role_ref.name),
                    subjects=self._subjects(b.subjects),
                )
            )
        return out

    def _collect_cluster_role_bindings(self) -> list[RoleBinding]:
        items = self._rbac.list_cluster_role_binding().items
        return [
            RoleBinding(
                name=b.metadata.name,
                namespace=None,
                role_ref=RoleRef(kind=b.role_ref.kind, name=b.role_ref.name),
                subjects=self._subjects(b.subjects),
            )
            for b in items
        ]

    def _collect_secrets(self) -> list[Secret]:
        """Secret METADATA only (never .data)."""
        items = self._core.list_secret_for_all_namespaces().items
        out = []
        for s in items:
            if not self._keep_ns(s.metadata.namespace):
                continue
            ann = s.metadata.annotations or {}
            out.append(
                Secret(
                    name=s.metadata.name,
                    namespace=s.metadata.namespace,
                    type=s.type or "Opaque",
                    service_account_name=ann.get(_SA_TOKEN_ANNOTATION),
                )
            )
        return out

    def _collect_workloads(self) -> list[Workload]:
        out: list[Workload] = []
        out += self._pods()
        out += self._from_template(
            self._apps.list_deployment_for_all_namespaces().items, WorkloadKind.DEPLOYMENT
        )
        out += self._from_template(
            self._apps.list_stateful_set_for_all_namespaces().items, WorkloadKind.STATEFULSET
        )
        out += self._from_template(
            self._apps.list_daemon_set_for_all_namespaces().items, WorkloadKind.DAEMONSET
        )
        out += self._from_template(
            self._batch.list_job_for_all_namespaces().items, WorkloadKind.JOB
        )
        out += self._cronjobs()
        return out

    def _pods(self) -> list[Workload]:
        items = self._core.list_pod_for_all_namespaces().items
        return [
            self._workload_from_spec(WorkloadKind.POD, p.metadata, p.spec)
            for p in items
            if self._keep_ns(p.metadata.namespace)
        ]

    def _from_template(self, items, kind: WorkloadKind) -> list[Workload]:
        out = []
        for w in items:
            if not self._keep_ns(w.metadata.namespace):
                continue
            tmpl = w.spec.template
            out.append(self._workload_from_spec(kind, w.metadata, tmpl.spec))
        return out

    def _cronjobs(self) -> list[Workload]:
        items = self._batch.list_cron_job_for_all_namespaces().items
        out = []
        for w in items:
            if not self._keep_ns(w.metadata.namespace):
                continue
            pod_spec = w.spec.job_template.spec.template.spec
            out.append(self._workload_from_spec(WorkloadKind.CRONJOB, w.metadata, pod_spec))
        return out

    @staticmethod
    def _workload_from_spec(kind: WorkloadKind, meta, pod_spec) -> Workload:
        containers = []
        for c in (pod_spec.containers or []):
            sc = c.security_context
            caps = []
            if sc and sc.capabilities and sc.capabilities.add:
                caps = list(sc.capabilities.add)
            containers.append(
                Container(
                    name=c.name,
                    image=c.image or "",
                    privileged=bool(sc.privileged) if sc and sc.privileged else False,
                    allow_privilege_escalation=(sc.allow_privilege_escalation if sc else None),
                    run_as_user=(sc.run_as_user if sc else None),
                    added_capabilities=caps,
                )
            )
        host_paths = [
            v.name for v in (pod_spec.volumes or []) if getattr(v, "host_path", None) is not None
        ]
        return Workload(
            kind=kind,
            name=meta.name,
            namespace=meta.namespace,
            service_account_name=(pod_spec.service_account_name or "default"),
            automount_token=pod_spec.automount_service_account_token,
            host_network=bool(pod_spec.host_network) if pod_spec.host_network else False,
            host_pid=bool(pod_spec.host_pid) if pod_spec.host_pid else False,
            host_path_volumes=host_paths,
            containers=containers,
        )
