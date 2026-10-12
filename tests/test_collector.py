"""Directory collector parses the fixture correctly."""


def test_snapshot_counts(snapshot):
    s = snapshot.summary()
    assert s["namespaces"] == 2
    assert s["service_accounts"] == 4          # web, guest, admin, wild
    assert s["cluster_roles"] == 1             # cluster-admin
    assert s["roles"] == 3                     # pod-creator, viewer, everything
    assert s["bindings"] == 4                  # 1 CRB + 3 RB


def test_serviceaccount_ids(snapshot):
    ids = {sa.id for sa in snapshot.service_accounts}
    assert "sa:dev/web-sa" in ids
    assert "sa:production/admin-sa" in ids


def test_binding_roleref_resolution(snapshot):
    crb = next(b for b in snapshot.bindings if b.name == "admin-binding")
    assert crb.is_cluster_binding
    assert crb.role_ref.target_id(None) == "clusterrole:cluster-admin"
