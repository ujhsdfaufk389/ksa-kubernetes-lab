"""Effective-permission resolution: combination, wildcards, namespace scoping."""


def test_web_sa_can_create_pods_in_production(effective):
    web = effective["sa:dev/web-sa"]
    assert web.can("create", "pods", "production")


def test_web_sa_cannot_create_pods_in_dev(effective):
    # the grant is namespaced to production only
    web = effective["sa:dev/web-sa"]
    assert not web.can("create", "pods", "dev")


def test_guest_is_read_only(effective):
    guest = effective["sa:dev/guest-sa"]
    assert guest.can("get", "pods", "dev")
    assert not guest.can("create", "pods", "dev")


def test_admin_is_cluster_admin(effective):
    assert effective["sa:production/admin-sa"].is_cluster_admin()


def test_web_sa_not_cluster_admin(effective):
    assert not effective["sa:dev/web-sa"].is_cluster_admin()


def test_wildcard_covers_any_verb_resource(effective):
    wild = effective["sa:production/wild-sa"]
    assert wild.can("create", "pods", "production")
    assert wild.can("delete", "secrets", "production")
    # but wildcard is namespaced -> not effective outside its namespace
    assert not wild.can("create", "pods", "dev")


def test_implicit_group_membership_not_admin(effective):
    # every SA is in system:authenticated etc. but that must not grant admin
    for sa_id, eff in effective.items():
        if sa_id != "sa:production/admin-sa":
            assert not eff.is_cluster_admin(), f"{sa_id} wrongly cluster-admin"
