use std::time::Duration;

use lore_auth_adapters::{
    authz::RebacAuthorizationPolicy,
    sqlite::{CreateDeviceAuthorizationParams, Store},
};
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AddUserInput, AddUserWithIdentityInput, ExternalIdentity, IssuedToken,
        LoginResolutionRequest, LoginStateInput, LoginTrustPolicy, Resource, ResourceID,
        SigningKeyMeta, UserListFilter,
    },
    ports::{
        AccountDirectory, AccountQuery, AdminAuditLog, AuthorizationPolicy,
        DeviceAuthorizationStore, GrantAdmin, GrantQuery, GroupAdmin, GroupQuery, IssuedTokenLog,
        ResourceQuery, ResourceStore, ServiceAccountAdmin, ServiceAccountDirectory,
        SigningKeyAdmin, StateStore,
    },
};
use rusqlite::params;

mod support;

use support::{TestStore, migrated_store, raw_connection};

fn install_admin_audit_failure_trigger(fixture: &TestStore) {
    raw_connection(&fixture.path)
        .execute_batch(
            r#"
            CREATE TRIGGER fail_admin_audit
            BEFORE INSERT ON admin_audit
            BEGIN
              SELECT RAISE(FAIL, 'audit offline');
            END;
            "#,
        )
        .expect("install audit failure trigger");
}

fn assert_core_ports<T>()
where
    T: AccountDirectory
        + ResourceStore
        + DeviceAuthorizationStore
        + StateStore
        + IssuedTokenLog
        + AdminAuditLog
        + GroupAdmin
        + GroupQuery
        + GrantAdmin
        + GrantQuery
        + SigningKeyAdmin
        + Send
        + Sync,
{
}

#[test]
fn sqlite_store_implements_requested_core_ports() {
    assert_core_ports::<Store>();
}

#[tokio::test]
async fn repository_management_rolls_back_on_audit_failure() {
    use lore_auth_core::ports::{MaintenanceAdmin, RepositoryAdmin};
    let fixture = migrated_store().await;
    let store = &fixture.store;
    store
        .upsert(Resource {
            name: "test-repo".into(),
            lore_repository_id: "test-id".into(),
            ..Resource::default()
        })
        .await
        .unwrap();
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".into(),
            display_name: "Alice".into(),
        })
        .await
        .unwrap();
    store
        .add_grant("user", &user.id, "test-repo", "reader")
        .await
        .unwrap();
    let audited = store.audited("admin");
    let id = "urc-test-id";
    MaintenanceAdmin::set(&audited, true, 15).await.unwrap();
    install_admin_audit_failure_trigger(&fixture);
    assert!(matches!(
        RepositoryAdmin::set_enabled(&audited, id, false).await,
        Err(CoreError::AdminAuditFailed(_))
    ));
    assert_eq!(store.get_by_resource_id(id).await.unwrap().status, "active");
    assert!(matches!(
        RepositoryAdmin::remove_grant(&audited, id, "user", &user.id, "reader").await,
        Err(CoreError::AdminAuditFailed(_))
    ));
    assert_eq!(store.list_grants("test-repo").await.unwrap().len(), 1);
    raw_connection(&fixture.path)
        .execute_batch("DROP TRIGGER fail_admin_audit")
        .unwrap();
    RepositoryAdmin::set_enabled(&audited, id, false)
        .await
        .unwrap();
    install_admin_audit_failure_trigger(&fixture);
    assert!(matches!(
        RepositoryAdmin::set_enabled(&audited, id, true).await,
        Err(CoreError::AdminAuditFailed(_))
    ));
    assert!(matches!(
        RepositoryAdmin::delete_disabled(&audited, id).await,
        Err(CoreError::AdminAuditFailed(_))
    ));
    assert_eq!(
        RepositoryAdmin::get(&audited, id).await.unwrap().status,
        "disabled"
    );
    assert_eq!(
        RepositoryAdmin::list_grants(&audited, id)
            .await
            .unwrap()
            .len(),
        1
    );
    raw_connection(&fixture.path)
        .execute_batch("DROP TRIGGER fail_admin_audit")
        .unwrap();
    RepositoryAdmin::delete_disabled(&audited, id)
        .await
        .unwrap();
    assert!(matches!(
        RepositoryAdmin::get(&audited, id).await,
        Err(CoreError::NotFound)
    ));
    assert!(store.list_grants("").await.unwrap().is_empty());
}

#[tokio::test]
async fn maintenance_stops_issuance_and_scopes_bulk_grant_removal() {
    use lore_auth_core::ports::{MaintenanceAdmin, RepositoryAdmin};
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let audited = store.audited("admin");
    let user = store
        .add_user(AddUserInput {
            email: "maintenance@example.com".into(),
            display_name: "Maintenance".into(),
        })
        .await
        .unwrap();
    for (name, id) in [("first", "first-id"), ("second", "second-id")] {
        store
            .upsert(Resource {
                name: name.into(),
                lore_repository_id: id.into(),
                ..Resource::default()
            })
            .await
            .unwrap();
        store
            .add_grant("user", &user.id, name, "reader")
            .await
            .unwrap();
    }
    let id = "urc-first-id";
    assert!(matches!(
        RepositoryAdmin::set_enabled(&audited, id, false).await,
        Err(CoreError::InvalidArgument(_))
    ));
    let first = IssuedToken {
        jti: "before-maintenance".into(),
        kind: "authz".into(),
        ..IssuedToken::default()
    };
    IssuedTokenLog::record(store, first).await.unwrap();
    let settings = MaintenanceAdmin::set(&audited, true, 15).await.unwrap();
    assert!(settings.enabled);
    assert!(settings.enabled_at > 0);
    assert!(matches!(
        IssuedTokenLog::record(
            store,
            IssuedToken {
                jti: "during-maintenance".into(),
                ..IssuedToken::default()
            }
        )
        .await,
        Err(CoreError::MaintenanceMode)
    ));
    assert!(matches!(
        RepositoryAdmin::clear_grants(&audited, id).await,
        Err(CoreError::InvalidArgument(_))
    ));
    RepositoryAdmin::set_enabled(&audited, id, false)
        .await
        .unwrap();
    install_admin_audit_failure_trigger(&fixture);
    assert!(matches!(
        RepositoryAdmin::clear_grants(&audited, id).await,
        Err(CoreError::AdminAuditFailed(_))
    ));
    assert_eq!(
        RepositoryAdmin::list_grants(&audited, id)
            .await
            .unwrap()
            .len(),
        1
    );
    raw_connection(&fixture.path)
        .execute_batch("DROP TRIGGER fail_admin_audit")
        .unwrap();
    assert_eq!(
        RepositoryAdmin::clear_grants(&audited, id).await.unwrap(),
        1
    );
    assert!(
        RepositoryAdmin::list_grants(&audited, id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.list_grants("second").await.unwrap().len(), 1);
    let updated = MaintenanceAdmin::set(&audited, true, 30).await.unwrap();
    assert_eq!(updated.enabled_at, settings.enabled_at);
    assert_eq!(updated.wait_minutes, 30);
    RepositoryAdmin::set_enabled(&audited, id, true)
        .await
        .unwrap();
    MaintenanceAdmin::set(&audited, false, 30).await.unwrap();
    IssuedTokenLog::record(
        store,
        IssuedToken {
            jti: "after-maintenance".into(),
            ..IssuedToken::default()
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn repository_admin_hides_legacy_deleted_registrations() {
    use lore_auth_core::ports::RepositoryAdmin;
    let fixture = migrated_store().await;
    for (name, id) in [
        ("active", "active-id"),
        ("disabled", "disabled-id"),
        ("deleted", "deleted-id"),
    ] {
        fixture
            .store
            .upsert(Resource {
                name: name.into(),
                lore_repository_id: id.into(),
                ..Resource::default()
            })
            .await
            .unwrap();
    }
    let conn = raw_connection(&fixture.path);
    conn.execute(
        "UPDATE repositories SET status = 'disabled' WHERE name = 'disabled'",
        [],
    )
    .unwrap();
    conn.execute(
        "UPDATE repositories SET status = 'deleted' WHERE name = 'deleted'",
        [],
    )
    .unwrap();
    let audited = fixture.store.audited("admin");
    let rows = RepositoryAdmin::list_all(&audited).await.unwrap();
    assert_eq!(
        rows.iter()
            .map(|repo| repo.name.as_str())
            .collect::<Vec<_>>(),
        vec!["active", "disabled"]
    );
    assert!(matches!(
        RepositoryAdmin::get(&audited, "urc-deleted-id").await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn audited_group_cidr_changes_roll_back_on_audit_failure() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let group = store.add_group("network", "").await.unwrap();
    store
        .add_group_allowed_cidr(&group.id, "192.0.2.0/24")
        .await
        .unwrap();
    let audited = store.audited("admin");
    install_admin_audit_failure_trigger(&fixture);
    assert!(matches!(
        audited
            .add_group_allowed_cidr(&group.id, "198.51.100.0/24")
            .await,
        Err(CoreError::AdminAuditFailed(_))
    ));
    assert!(matches!(
        audited
            .remove_group_allowed_cidr(&group.id, "192.0.2.0/24")
            .await,
        Err(CoreError::AdminAuditFailed(_))
    ));
    assert_eq!(
        store.list_group_allowed_cidrs(&group.id).await.unwrap(),
        ["192.0.2.0/24"]
    );
    assert!(store.list_admin_audit().await.unwrap().is_empty());
}

#[tokio::test]
async fn migration_removes_existing_group_nests_once_and_audits_atomically() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let parent = store.add_group("parent", "").await.unwrap();
    let child = store.add_group("child", "").await.unwrap();
    let user = store
        .add_user(AddUserInput {
            email: "member@example.com".into(),
            display_name: "Member".into(),
        })
        .await
        .unwrap();
    store.add_group_member(&child.name, &user.id).await.unwrap();
    store.add_group_group(&parent.id, &child.id).await.unwrap();
    store
        .add_group_allowed_cidr(&parent.id, "192.0.2.0/24")
        .await
        .unwrap();
    let resource_id = ResourceID::for_repository_id("migration-repo").unwrap();
    store
        .upsert(Resource {
            name: "migration-repo".into(),
            lore_repository_id: "migration-repo".into(),
            remote_url: "lore://example".into(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .unwrap();
    store
        .add_grant("group", &parent.id, "migration-repo", "reader")
        .await
        .unwrap();
    assert_eq!(
        store.list_user_allowed_cidrs(&user.id).await.unwrap(),
        vec!["192.0.2.0/24"]
    );
    assert_eq!(
        store
            .grants_for_user_on_repository(&user.id, &resource_id)
            .await
            .unwrap()
            .len(),
        1
    );
    let connection = raw_connection(&fixture.path);
    connection
        .execute(
            "DELETE FROM schema_migrations WHERE version = ?1",
            params!["phase7_remove_existing_group_nests_20261030"],
        )
        .unwrap();
    install_admin_audit_failure_trigger(&fixture);
    assert!(store.migrate().await.is_err());
    assert_eq!(store.list_group_groups(&parent.id).await.unwrap().len(), 1);
    assert!(store.list_admin_audit().await.unwrap().is_empty());
    assert_eq!(
        store.list_user_allowed_cidrs(&user.id).await.unwrap(),
        vec!["192.0.2.0/24"]
    );
    assert_eq!(
        store
            .grants_for_user_on_repository(&user.id, &resource_id)
            .await
            .unwrap()
            .len(),
        1
    );
    connection
        .execute_batch("DROP TRIGGER fail_admin_audit")
        .unwrap();

    store.migrate().await.unwrap();
    assert!(
        store
            .list_group_groups(&parent.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.list_group_members(&child.id).await.unwrap()[0].id,
        user.id
    );
    assert!(
        store
            .list_user_allowed_cidrs(&user.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .grants_for_user_on_repository(&user.id, &resource_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.list_group_allowed_cidrs(&parent.id).await.unwrap(),
        vec!["192.0.2.0/24"]
    );
    let audit = store.list_admin_audit().await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].actor, "migration");
    assert_eq!(audit[0].action, "group.nest.remove");
    assert_eq!(audit[0].object_id, parent.id);
    assert_eq!(audit[0].detail, format!("member_group={}", child.id));
    store.validate_schema().await.unwrap();

    store.add_group_group(&parent.id, &child.id).await.unwrap();
    store.migrate().await.unwrap();
    assert_eq!(store.list_group_groups(&parent.id).await.unwrap().len(), 1);
    assert_eq!(store.list_admin_audit().await.unwrap().len(), 1);
}

#[tokio::test]
async fn audited_sqlite_service_account_creation_is_atomic_and_does_not_log_secret() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let group = store.add_group("ci", "").await.unwrap();
    let input = |client_id: &str| lore_auth_core::model::CreateServiceAccountInput {
        client_id: client_id.into(),
        display_name: "CI Account".into(),
    };
    let audited = store.audited("admin@example.com");
    assert!(
        audited
            .create_service_account_in_group(input("missing"), "missing")
            .await
            .is_err()
    );
    assert!(
        audited
            .create_service_account_in_group(input("bad id"), &group.id)
            .await
            .is_err()
    );
    raw_connection(&fixture.path)
        .execute_batch(
            "CREATE TRIGGER fail_second_account_audit BEFORE INSERT ON admin_audit
         WHEN NEW.action = 'group.member.add'
         BEGIN SELECT RAISE(FAIL, 'audit offline'); END;",
        )
        .unwrap();
    assert!(
        audited
            .create_service_account_in_group(input("ci-runner"), &group.id)
            .await
            .is_err()
    );
    let conn = raw_connection(&fixture.path);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM service_accounts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    assert!(store.list_admin_audit().await.unwrap().is_empty());
    conn.execute_batch("DROP TRIGGER fail_second_account_audit")
        .unwrap();
    let created = audited
        .create_service_account_in_group(input("ci-runner"), &group.id)
        .await
        .unwrap();
    let auth = store
        .authenticate_service_account("ci-runner", &created.client_secret)
        .await
        .unwrap();
    assert_eq!(auth.id, created.account.user.id);
    assert!(store.is_service_account(&auth.id).await.unwrap());
    assert!(
        !store
            .is_service_account("not-a-service-account")
            .await
            .unwrap()
    );
    assert_eq!(
        store.list_group_members(&group.id).await.unwrap()[0].id,
        auth.id
    );
    let entries = store.list_admin_audit().await.unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .all(|entry| entry.actor == "admin@example.com"
                && !entry.detail.contains(&created.client_secret))
    );
    assert!(
        audited
            .create_service_account_in_group(input("ci-runner"), &group.id)
            .await
            .is_err()
    );
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn audited_sqlite_grant_write_records_admin_audit() {
    let fixture = migrated_store().await;
    let store = fixture.store.clone();
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    let grants = store.audited("authctl:test-user");

    let grant = grants
        .add_grant("user", &user.id, "game-assets", "writer")
        .await
        .expect("audited grant add");

    let entries = store.list_admin_audit().await.expect("list admin audit");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].actor, "authctl:test-user");
    assert_eq!(entries[0].action, "grant.add");
    assert_eq!(entries[0].object_type, "grant");
    assert_eq!(entries[0].object_id, grant.id);
    assert!(entries[0].detail.contains("repo=game-assets"));
}

#[tokio::test]
async fn audited_sqlite_bulk_user_grants_are_atomic_and_preserve_existing_roles() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "bulk@example.com".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    for name in ["one", "two", "existing"] {
        store
            .upsert(Resource {
                name: name.into(),
                lore_repository_id: name.into(),
                remote_url: "lore://example".into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    store
        .add_grant("user", &user.id, "existing", "writer")
        .await
        .unwrap();
    let audited = store.audited("admin");
    let ids = |names: &[&str]| {
        names
            .iter()
            .map(|name| format!("urc-{name}"))
            .collect::<Vec<_>>()
    };
    for (selected, role) in [
        (ids(&["one", "missing"]), "reader"),
        (ids(&["one", "one"]), "reader"),
        (ids(&["one", "existing"]), "reader"),
        (ids(&["one", "two"]), "invalid"),
        (vec![], "reader"),
    ] {
        assert!(
            audited
                .add_user_grants(&user.id, &selected, role)
                .await
                .is_err()
        );
        assert!(store.list_grants("one").await.unwrap().is_empty());
        assert!(store.list_admin_audit().await.unwrap().is_empty());
    }
    assert_eq!(
        store.list_grants("existing").await.unwrap()[0].role,
        "writer"
    );
    let grants = audited
        .add_user_grants(&user.id, &ids(&["one", "two"]), "admin")
        .await
        .unwrap();
    assert_eq!(grants.len(), 2);
    assert_eq!(store.list_grants("one").await.unwrap()[0].role, "admin");
    let entries = store.list_admin_audit().await.unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .all(|entry| entry.actor == "admin" && entry.action == "grant.add")
    );
}

#[tokio::test]
async fn audited_sqlite_bulk_user_grants_roll_back_on_audit_failure() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "bulk@example.com".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    for name in ["one", "two"] {
        store
            .upsert(Resource {
                name: name.into(),
                lore_repository_id: name.into(),
                remote_url: "lore://example".into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    raw_connection(&fixture.path)
        .execute_batch(
            "CREATE TRIGGER fail_second_admin_audit BEFORE INSERT ON admin_audit
             WHEN (SELECT COUNT(*) FROM admin_audit) > 0
             BEGIN SELECT RAISE(FAIL, 'audit offline'); END;",
        )
        .unwrap();
    assert!(
        store
            .audited("admin")
            .add_user_grants(&user.id, &["urc-one".into(), "urc-two".into()], "writer")
            .await
            .is_err()
    );
    assert!(store.list_grants("one").await.unwrap().is_empty());
    assert!(store.list_grants("two").await.unwrap().is_empty());
    assert!(store.list_admin_audit().await.unwrap().is_empty());
}

#[tokio::test]
async fn audited_sqlite_set_repository_roles_is_atomic_and_preserves_unchanged_multiple_roles() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "roles@example.com".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    for name in ["one", "two"] {
        store
            .upsert(Resource {
                name: name.into(),
                lore_repository_id: name.into(),
                remote_url: "lore://example".into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    store
        .add_grant("user", &user.id, "one", "reader")
        .await
        .unwrap();
    store
        .add_grant("user", &user.id, "one", "writer")
        .await
        .unwrap();
    let mut changes = vec![
        lore_auth_core::model::DirectRepositoryRoles {
            resource_id: "urc-one".into(),
            expected_roles: vec!["reader".into(), "writer".into()],
            desired_roles: vec!["reader".into(), "writer".into()],
        },
        lore_auth_core::model::DirectRepositoryRoles {
            resource_id: "urc-two".into(),
            expected_roles: vec![],
            desired_roles: vec!["admin".into()],
        },
    ];
    let audited = store.audited("admin");
    audited
        .set_user_repository_roles(&user.id, &changes)
        .await
        .unwrap();
    assert_eq!(store.list_grants("one").await.unwrap().len(), 2);
    assert_eq!(store.list_admin_audit().await.unwrap().len(), 1);
    changes[0].desired_roles = vec!["admin".into()];
    changes[1].expected_roles = vec!["reader".into()];
    assert!(
        audited
            .set_user_repository_roles(&user.id, &changes)
            .await
            .is_err()
    );
    assert_eq!(store.list_grants("one").await.unwrap().len(), 2);
    changes[1].expected_roles = vec!["admin".into()];
    raw_connection(&fixture.path).execute_batch("CREATE TRIGGER fail_role_audit BEFORE INSERT ON admin_audit WHEN NEW.action = 'grant.add' BEGIN SELECT RAISE(FAIL, 'audit offline'); END;").unwrap();
    assert!(
        audited
            .set_user_repository_roles(&user.id, &changes)
            .await
            .is_err()
    );
    assert_eq!(store.list_grants("one").await.unwrap().len(), 2);
    assert_eq!(store.list_admin_audit().await.unwrap().len(), 1);
    raw_connection(&fixture.path)
        .execute_batch("DROP TRIGGER fail_role_audit")
        .unwrap();
    audited
        .set_user_repository_roles(&user.id, &changes)
        .await
        .unwrap();
    let roles = store.list_grants("one").await.unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].role, "admin");
    assert_eq!(store.list_admin_audit().await.unwrap().len(), 4);
}

#[tokio::test]
async fn audited_sqlite_change_user_grants_checks_stale_roles_and_rolls_back_audit_failure() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "change@example.com".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    for name in ["old", "new"] {
        store
            .upsert(Resource {
                name: name.into(),
                lore_repository_id: name.into(),
                remote_url: "lore://example".into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    store
        .add_grant("user", &user.id, "old", "reader")
        .await
        .unwrap();
    store
        .add_grant("user", &user.id, "old", "writer")
        .await
        .unwrap();
    let removal = |role: &str| lore_auth_core::model::DirectRepositoryGrant {
        resource_id: "urc-old".into(),
        role: role.into(),
    };
    let audited = store.audited("admin");
    let additions = ["urc-new".to_owned()];
    assert!(
        audited
            .change_user_grants(&user.id, &additions, &[removal("reader")], "writer")
            .await
            .is_err()
    );
    assert!(
        audited
            .change_user_grants(
                &user.id,
                &["urc-old".into(), "urc-new".into()],
                &[removal("reader")],
                "writer"
            )
            .await
            .is_err()
    );
    assert_eq!(store.list_grants("old").await.unwrap().len(), 2);
    assert!(store.list_grants("new").await.unwrap().is_empty());
    raw_connection(&fixture.path)
        .execute_batch(
            "CREATE TRIGGER fail_removal_audit BEFORE INSERT ON admin_audit
         WHEN NEW.action = 'grant.remove'
         BEGIN SELECT RAISE(FAIL, 'audit offline'); END;",
        )
        .unwrap();
    assert!(
        audited
            .change_user_grants(
                &user.id,
                &additions,
                &[removal("reader"), removal("writer")],
                "writer"
            )
            .await
            .is_err()
    );
    assert_eq!(store.list_grants("old").await.unwrap().len(), 2);
    assert!(store.list_grants("new").await.unwrap().is_empty());
    assert!(store.list_admin_audit().await.unwrap().is_empty());
    raw_connection(&fixture.path)
        .execute_batch("DROP TRIGGER fail_removal_audit")
        .unwrap();
    audited
        .change_user_grants(
            &user.id,
            &additions,
            &[removal("reader"), removal("writer")],
            "writer",
        )
        .await
        .unwrap();
    assert!(store.list_grants("old").await.unwrap().is_empty());
    assert_eq!(store.list_grants("new").await.unwrap()[0].role, "writer");
    let entries = store.list_admin_audit().await.unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.action == "grant.remove")
            .count(),
        2
    );
}

#[tokio::test]
async fn audited_display_name_update_rolls_back_if_audit_fails() {
    let fixture = migrated_store().await;
    let user = fixture
        .store
        .add_user(AddUserInput {
            email: "name@example.com".to_owned(),
            display_name: "Original".to_owned(),
        })
        .await
        .unwrap();
    install_admin_audit_failure_trigger(&fixture);
    let result = fixture
        .store
        .audited("test")
        .update_user_display_name(&user.id, "Changed")
        .await;
    assert!(matches!(result, Err(CoreError::AdminAuditFailed(_))));
    assert_eq!(
        fixture
            .store
            .user_by_id(&user.id)
            .await
            .unwrap()
            .display_name,
        "Original"
    );
}

#[tokio::test]
async fn audited_entra_identity_update_rolls_back_if_audit_fails() {
    let fixture = migrated_store().await;
    let (user, identity) = fixture
        .store
        .add_user_with_identity(AddUserWithIdentityInput {
            email: "entra@example.com".to_owned(),
            display_name: "User".to_owned(),
            provider_id: "entra".to_owned(),
            issuer: "https://example.com".to_owned(),
            subject: "tenant:old".to_owned(),
            subject_strategy: "entra_oid_tid".to_owned(),
        })
        .await
        .unwrap();
    install_admin_audit_failure_trigger(&fixture);
    let result = fixture
        .store
        .audited("test")
        .update_entra_identity(lore_auth_core::model::UpdateEntraIdentityInput {
            user_id: user.id.clone(),
            identity_id: identity.id,
            provider_id: "entra".to_owned(),
            issuer: "https://example.com".to_owned(),
            expected_subject: "tenant:old".to_owned(),
            subject: "tenant:new".to_owned(),
        })
        .await;
    assert!(matches!(result, Err(CoreError::AdminAuditFailed(_))));
    assert_eq!(
        fixture
            .store
            .external_identities_for_user(&user.id)
            .await
            .unwrap()[0]
            .subject,
        "tenant:old"
    );
}

#[tokio::test]
async fn audited_sqlite_rolls_back_mutation_when_admin_audit_insert_fails() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    install_admin_audit_failure_trigger(&fixture);

    let err = store
        .audited("authctl:test-user")
        .add_grant("user", &user.id, "game-assets", "writer")
        .await
        .expect_err("audited grant must fail closed");

    assert!(matches!(err, CoreError::AdminAuditFailed(_)));
    assert!(
        err.to_string()
            .contains("operation rolled back because audit logging failed"),
        "{err}"
    );
    assert!(
        store
            .list_grants("game-assets")
            .await
            .expect("list grants")
            .is_empty(),
        "grant mutation must roll back with audit failure"
    );
}

#[tokio::test]
async fn audited_sqlite_rolls_back_user_disable_when_admin_audit_insert_fails() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    install_admin_audit_failure_trigger(&fixture);

    let err = store
        .audited("admin@example.com")
        .disable_user(&user.id)
        .await
        .expect_err("audit failure should fail user disable");

    assert!(matches!(err, CoreError::AdminAuditFailed(_)));
    let after = store.user_by_id(&user.id).await.expect("user remains");
    assert_eq!(after.status, "active");
}

#[tokio::test]
async fn sqlite_grants_use_repository_name_not_lore_repository_id() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let resource_id = ResourceID::for_repository_id("repo-id").expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    store
        .add_grant("user", &user.id, "game-assets", "writer")
        .await
        .expect("add grant by name");

    let by_name = store
        .list_grants("game-assets")
        .await
        .expect("list grants by repository name");
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0].role, "writer");

    assert!(matches!(
        store.list_grants("repo-id").await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        store.list_grants(&resource_id).await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        store.add_grant("user", &user.id, "repo-id", "reader").await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        store
            .remove_grant("user", &user.id, "repo-id", "writer")
            .await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn sqlite_resource_delete_hard_deletes_related_records_and_reuses_name() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let old_repository_id = "old-repository-id";
    let old_resource_id =
        ResourceID::for_repository_id(old_repository_id).expect("old resource id");
    store
        .upsert(Resource {
            name: "Watch".to_owned(),
            lore_repository_id: old_repository_id.to_owned(),
            resource_id: old_resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("create old resource");
    store
        .add_grant("user", &user.id, "Watch", "writer")
        .await
        .expect("grant old resource");
    let conn = raw_connection(&fixture.path);
    let repository_id: String = conn
        .query_row(
            "SELECT id FROM repositories WHERE lore_repository_id = ?1",
            params![old_repository_id],
            |row| row.get(0),
        )
        .expect("repository id");
    conn.execute(
        "INSERT INTO device_authorizations (
           id, device_code_hash, user_code_hash, requested_remote_url,
           requested_repository_id, status, created_at, expires_at
         ) VALUES ('device-1', 'device-code', 'user-code', 'lore://example', ?1, 'pending', 1, 2)",
        params![repository_id],
    )
    .expect("add device authorization");
    conn.execute(
        "INSERT INTO issued_tokens (
           jti, token_kind, repository_id, lore_resource_id, role, kid,
           audience_json, issued_at, expires_at
         ) VALUES ('token-1', 'authz', ?1, ?2, 'writer', 'test-key', '[]', 1, 2)",
        params![repository_id, old_resource_id],
    )
    .expect("add issued token");
    store
        .delete(&old_resource_id)
        .await
        .expect("delete old resource");
    for table in ["repositories", "grants", "issued_tokens"] {
        let count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {table} WHERE {} = ?1",
                    if table == "repositories" {
                        "lore_repository_id"
                    } else {
                        "repository_id"
                    }
                ),
                params![if table == "repositories" {
                    old_repository_id
                } else {
                    &repository_id
                }],
                |row| row.get(0),
            )
            .expect("count related records");
        assert_eq!(count, 0, "{table} should be deleted");
    }
    let device_authorizations: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM device_authorizations WHERE requested_repository_id = ?1",
            params![repository_id],
            |row| row.get(0),
        )
        .expect("count device authorizations");
    assert_eq!(
        device_authorizations, 0,
        "device authorizations should be deleted"
    );

    let new_repository_id = "new-repository-id";
    let new_resource_id =
        ResourceID::for_repository_id(new_repository_id).expect("new resource id");
    store
        .upsert(Resource {
            name: "Watch".to_owned(),
            lore_repository_id: new_repository_id.to_owned(),
            resource_id: new_resource_id,
            ..Resource::default()
        })
        .await
        .expect("recreate resource with the deleted name");

    let active = store.get_by_name("Watch").await.expect("active resource");
    assert_eq!(active.lore_repository_id, new_repository_id);
    assert!(
        store
            .list_grants("Watch")
            .await
            .expect("list new resource grants")
            .is_empty(),
        "grants for the deleted resource must not carry over"
    );
}

#[tokio::test]
async fn audited_sqlite_rolls_back_repository_add_when_admin_audit_insert_fails() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    install_admin_audit_failure_trigger(&fixture);

    let err = store
        .audited("admin@example.com")
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect_err("audit failure should fail repo add");

    assert!(matches!(err, CoreError::AdminAuditFailed(_)));
    assert!(matches!(
        store.get_by_name("game-assets").await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn sqlite_rejects_invalid_admin_write_inputs() {
    let fixture = migrated_store().await;
    let store = &fixture.store;

    assert!(matches!(
        store
            .add_user(AddUserInput {
                email: "alice example.com".to_owned(),
                ..AddUserInput::default()
            })
            .await,
        Err(CoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        store
            .add_invitation(AddInvitationInput {
                provider_id: "google".to_owned(),
                issuer: "https://accounts.google.com".to_owned(),
                email: "alice".to_owned(),
                ..AddInvitationInput::default()
            })
            .await,
        Err(CoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        store
            .upsert(Resource {
                name: "bad".to_owned(),
                remote_url: "lore://example".to_owned(),
                lore_repository_id: "bad/repo".to_owned(),
                ..Resource::default()
            })
            .await,
        Err(CoreError::InvalidArgument(_))
    ));
    store
        .upsert(Resource {
            name: "ok".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: " repo-id_123 ".to_owned(),
            ..Resource::default()
        })
        .await
        .expect("trimmed repository id is accepted");
    let repo = store.get_by_name("ok").await.expect("repo exists");
    assert_eq!(repo.lore_repository_id, "repo-id_123");
    assert_eq!(repo.resource_id, "urc-repo-id_123");
}

#[tokio::test]
async fn unknown_grant_role_is_rejected() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");

    let err = store
        .add_grant("user", "user-1", "game-assets", "typo-role")
        .await
        .expect_err("unknown role");
    assert!(matches!(err, CoreError::InvalidArgument(_)));
}

#[tokio::test]
async fn login_state_is_one_time_and_carries_private_state() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let (state, _) = store
        .create_login_state(
            LoginStateInput {
                provider_id: "keycloak-prod".to_owned(),
                nonce: "oidc-nonce".to_owned(),
                login_url_nonce: "login-url-nonce".to_owned(),
                return_path: "/tokens".to_owned(),
                ..LoginStateInput::default()
            },
            Duration::from_secs(60),
        )
        .await
        .expect("create login state");
    store
        .set_login_state_private_state(&state, b"pkce-verifier".to_vec())
        .await
        .expect("set private state");

    let got = store
        .consume_login_state(&state)
        .await
        .expect("consume login state");
    assert_eq!(got.provider_id, "keycloak-prod");
    assert_eq!(got.nonce, "oidc-nonce");
    assert_eq!(got.login_url_nonce, "login-url-nonce");
    assert_eq!(got.private_state, b"pkce-verifier");
    assert!(matches!(
        store.consume_login_state(&state).await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn auth_session_and_csrf_tokens_are_one_time_and_expire() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");

    let (code, session) = store
        .create_auth_session("client-state", Duration::from_secs(60))
        .await
        .expect("create auth session");
    let by_code = store
        .get_auth_session_by_code(&code)
        .await
        .expect("get auth session");
    assert_eq!(by_code.id, session.id);
    assert!(store.match_client_state(&by_code, "client-state"));
    store
        .complete_auth_session(&session.id, &user.id)
        .await
        .expect("complete auth session");
    store
        .consume_auth_session(&session.id)
        .await
        .expect("consume auth session");
    assert!(matches!(
        store.consume_auth_session(&session.id).await,
        Err(CoreError::AuthSessionNotFound)
    ));

    let (_expired_code, expired_session) = store
        .create_auth_session("client-state", Duration::ZERO)
        .await
        .expect("create expired auth session");
    assert!(matches!(
        store
            .complete_auth_session(&expired_session.id, &user.id)
            .await,
        Err(CoreError::AuthSessionNotFound)
    ));

    let browser = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("create browser session");
    let csrf = store
        .create_csrf_token(&browser.id, Duration::from_secs(60))
        .await
        .expect("create csrf");
    store
        .consume_csrf_token(&browser.id, &csrf)
        .await
        .expect("consume csrf");
    assert!(matches!(
        store.consume_csrf_token(&browser.id, &csrf).await,
        Err(CoreError::NotFound)
    ));
    let expired_csrf = store
        .create_csrf_token(&browser.id, Duration::ZERO)
        .await
        .expect("create expired csrf");
    assert!(matches!(
        store.consume_csrf_token(&browser.id, &expired_csrf).await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn browser_session_returns_not_found_after_user_is_disabled() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "disabled@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let browser = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("create browser session");

    store
        .disable_user(&user.id)
        .await
        .expect("disable user after browser session");

    assert!(matches!(
        store.user_by_browser_session(&browser.id).await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn sqlite_admin_read_ports_list_users_and_group_edges() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let alice = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            display_name: "Alice Artist".to_owned(),
        })
        .await
        .expect("add alice");
    let bob = store
        .add_user(AddUserInput {
            email: "bob@example.com".to_owned(),
            display_name: "Bob".to_owned(),
        })
        .await
        .expect("add bob");
    let deleted = store
        .add_user(AddUserInput {
            email: "deleted@example.com".to_owned(),
            display_name: "Deleted Artist".to_owned(),
        })
        .await
        .expect("add deleted");
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store.add_group("riggers", "").await.expect("add riggers");
    store
        .add_group_member("artists", &alice.id)
        .await
        .expect("add alice to artists");
    store
        .add_group_member("artists", &bob.id)
        .await
        .expect("add bob to artists");
    store
        .add_group_member("artists", &deleted.id)
        .await
        .expect("add deleted to artists");
    store
        .disable_user(&deleted.id)
        .await
        .expect("mark deleted fixture inactive");
    raw_connection(&fixture.path)
        .execute(
            "UPDATE users SET status = 'deleted' WHERE id = ?1",
            rusqlite::params![deleted.id],
        )
        .expect("delete user fixture");
    store
        .add_group_group(&artists.id, &riggers.id)
        .await
        .expect("nest riggers under artists");

    let users = store
        .list_users(UserListFilter {
            query: "ART".to_owned(),
            limit: 1,
        })
        .await
        .expect("list users");
    assert_eq!(
        users
            .iter()
            .map(|user| user.email.as_str())
            .collect::<Vec<_>>(),
        ["alice@example.com"]
    );
    assert_eq!(users[0].last_login_at, 0);
    assert_eq!(
        store.user_by_id(&bob.id).await.expect("user by id").email,
        "bob@example.com"
    );

    let members = store
        .list_group_members("artists")
        .await
        .expect("list group members");
    assert_eq!(
        members
            .iter()
            .map(|user| user.email.as_str())
            .collect::<Vec<_>>(),
        ["alice@example.com", "bob@example.com"]
    );

    let nested = store
        .list_group_groups("artists")
        .await
        .expect("list nested groups");
    assert_eq!(
        nested
            .iter()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>(),
        ["riggers"]
    );
}

#[tokio::test]
async fn group_and_grant_crud_updates_authorization() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let group = store
        .add_group("artists", "Art team")
        .await
        .expect("add group");
    store.add_group("qa", "").await.expect("add qa group");
    assert_eq!(
        store
            .list_groups()
            .await
            .expect("list groups")
            .iter()
            .map(|group| group.name.as_str())
            .collect::<Vec<_>>(),
        vec!["artists", "qa"]
    );
    store
        .add_group_member("artists", "alice@example.com")
        .await
        .expect("add member");
    let resource_id = ResourceID::for_repository_id("repo-id").expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    let grant = store
        .add_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("add grant");
    assert_eq!(grant.role, "writer");
    let policy = RebacAuthorizationPolicy::from_store(store).expect("rebac policy");
    assert!(
        policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("group grant works")
    );
    assert_eq!(
        store
            .list_grants("game-assets")
            .await
            .expect("list grants")
            .len(),
        1
    );
    store
        .remove_group_member("artists", "alice@example.com")
        .await
        .expect("remove member");
    assert!(
        !policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("group grant removed by membership")
    );
    store
        .remove_grant("group", &group.id, "game-assets", "writer")
        .await
        .expect("remove grant");
    assert_eq!(
        store
            .list_grants("game-assets")
            .await
            .expect("list grants after remove"),
        Vec::new()
    );
}

#[tokio::test]
async fn sqlite_grant_query_lists_direct_and_nested_group_evidence() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store.add_group("riggers", "").await.expect("add riggers");
    store
        .add_group_member("riggers", &user.id)
        .await
        .expect("add user to child group");
    store
        .add_group_group(&artists.id, &riggers.id)
        .await
        .expect("nest riggers under artists");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    store
        .add_grant("user", &user.id, "game-assets", "writer")
        .await
        .expect("add direct grant");
    store
        .add_grant("group", &artists.id, "game-assets", "reader")
        .await
        .expect("add group grant");

    let resource_id = ResourceID::for_repository_id("repo-id").expect("resource id");
    let evidence = store
        .grants_for_user_on_repository(&user.id, &resource_id)
        .await
        .expect("list grant evidence");

    assert_eq!(evidence.len(), 2);
    assert!(
        evidence.iter().any(|grant| grant.subject_type == "user"
            && grant.role == "writer"
            && grant.path.contains("alice@example.com")),
        "{evidence:?}"
    );
    assert!(
        evidence.iter().any(|grant| grant.subject_type == "group"
            && grant.role == "reader"
            && grant.subject_name == "artists"
            && grant.path.contains("riggers")
            && grant.path.contains("artists")),
        "{evidence:?}"
    );
    assert!(matches!(
        store
            .grants_for_user_on_repository(&user.id, "urc-missing")
            .await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn sqlite_grant_evidence_uses_exact_resolved_resource_id() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    store
        .upsert(Resource {
            name: "shared".to_owned(),
            remote_url: "lore://repo-a".to_owned(),
            lore_repository_id: "repo-a".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-a").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo a");
    store
        .upsert(Resource {
            name: "repo-b".to_owned(),
            remote_url: "lore://repo-b".to_owned(),
            lore_repository_id: "shared".to_owned(),
            resource_id: ResourceID::for_repository_id("shared").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo b");
    store
        .add_grant("user", &user.id, "shared", "reader")
        .await
        .expect("add repo a grant by name");
    store
        .add_grant("user", &user.id, "repo-b", "writer")
        .await
        .expect("add repo b grant by name");

    let evidence = store
        .grants_for_user_on_repository(&user.id, "urc-repo-a")
        .await
        .expect("list repo a evidence");

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].role, "reader");
}

#[tokio::test]
async fn sqlite_grant_evidence_bounds_diamond_group_paths_to_groups() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let leaf = store.add_group("leaf", "").await.expect("add leaf");
    let left = store.add_group("left", "").await.expect("add left");
    let right = store.add_group("right", "").await.expect("add right");
    let root = store.add_group("root", "").await.expect("add root");
    store
        .add_group_member(&leaf.name, &user.id)
        .await
        .expect("add user to leaf");
    store
        .add_group_group(&left.id, &leaf.id)
        .await
        .expect("left contains leaf");
    store
        .add_group_group(&right.id, &leaf.id)
        .await
        .expect("right contains leaf");
    store
        .add_group_group(&root.id, &left.id)
        .await
        .expect("root contains left");
    store
        .add_group_group(&root.id, &right.id)
        .await
        .expect("root contains right");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    for group in [&leaf, &left, &right, &root] {
        store
            .add_grant("group", &group.id, "game-assets", "reader")
            .await
            .expect("add group grant");
    }

    let evidence = store
        .grants_for_user_on_repository(&user.id, "urc-repo-id")
        .await
        .expect("list diamond evidence");

    assert_eq!(evidence.len(), 4, "{evidence:?}");
}

#[tokio::test]
async fn sqlite_grant_resolves_group_name_to_internal_id_before_authorization() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    store
        .add_group("artists", "Art team")
        .await
        .expect("add group");
    store
        .add_group_member("artists", &user.id)
        .await
        .expect("add group member");
    let resource_id = ResourceID::for_repository_id("repo-id").expect("resource id");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: resource_id.clone(),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");

    let grant = store
        .audited("admin@example.com")
        .add_grant("group", "artists", "game-assets", "writer")
        .await
        .expect("add group grant by name");

    assert_ne!(grant.subject_id, "artists");
    let policy = RebacAuthorizationPolicy::from_store(store).expect("rebac policy");
    assert!(
        policy
            .can_access(&user.id, &resource_id, "write")
            .await
            .expect("group name grant is effective")
    );
}

#[tokio::test]
async fn sqlite_grant_rejects_unknown_subject_type_and_missing_subject() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");

    assert!(matches!(
        store
            .add_grant("team", "artists", "game-assets", "writer")
            .await,
        Err(CoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        store
            .add_grant("group", "missing", "game-assets", "writer")
            .await,
        Err(CoreError::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn group_group_crud_rejects_self_cycles_and_missing_groups() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store
        .add_group("riggers", "Rigging team")
        .await
        .expect("add riggers");
    store
        .add_group("animators", "")
        .await
        .expect("add animators");

    store
        .add_group_group("artists", "riggers")
        .await
        .expect("nest riggers under artists");
    store
        .remove_group_group(&artists.id, &riggers.id)
        .await
        .expect("remove nested group by ids");
    assert!(matches!(
        store.remove_group_group("artists", "riggers").await,
        Err(CoreError::NotFound)
    ));

    assert!(matches!(
        store.add_group_group("artists", "artists").await,
        Err(CoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        store.add_group_group("missing", "riggers").await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        store.add_group_group("artists", "missing").await,
        Err(CoreError::NotFound)
    ));

    store
        .add_group_group("artists", "riggers")
        .await
        .expect("artists contains riggers");
    store
        .add_group_group("riggers", "animators")
        .await
        .expect("riggers contains animators");
    assert!(matches!(
        store.add_group_group("animators", "artists").await,
        Err(CoreError::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn resolve_login_binds_verified_invitation_then_resolves_existing_identity() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let (reserved, invitation) = store
        .add_invitation(AddInvitationInput {
            provider_id: "keycloak-prod".to_owned(),
            issuer: "https://sso.example.com/realms/prod".to_owned(),
            email: "Alice@Example.com".to_owned(),
            display_name: "Alice".to_owned(),
            binding_policy: "verified_email_invitation".to_owned(),
            expires_at: 0,
        })
        .await
        .expect("add invitation");
    assert_eq!(reserved.status, "pending");

    let (principal, binding) = store
        .resolve_login(LoginResolutionRequest {
            identity: ExternalIdentity {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject:with:colon".to_owned(),
                subject_strategy: "oidc_sub".to_owned(),
                email: "alice@example.com".to_owned(),
                email_verified: true,
                display_name: "Alice Example".to_owned(),
                ..ExternalIdentity::default()
            },
            policy: LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                allowed_email_domains: vec!["example.com".to_owned()],
            },
        })
        .await
        .expect("resolve invitation");
    assert_eq!(principal.user_id, reserved.id);
    assert_eq!(principal.token_subject, format!("user:{}", reserved.id));
    assert_eq!(principal.token_idp, "keycloak-prod");
    assert_eq!(binding.status, "bound_invitation");
    assert_eq!(binding.invitation_id, invitation.id);
    assert!(!binding.external_identity_id.is_empty());

    let (existing, existing_binding) = store
        .resolve_login(LoginResolutionRequest {
            identity: ExternalIdentity {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject:with:colon".to_owned(),
                ..ExternalIdentity::default()
            },
            policy: LoginTrustPolicy {
                email_binding: "disabled".to_owned(),
                allowed_email_domains: vec!["other.example".to_owned()],
            },
        })
        .await
        .expect("resolve existing identity");
    assert_eq!(existing.user_id, reserved.id);
    assert_eq!(existing_binding.status, "existing");
    assert_eq!(
        existing_binding.external_identity_id,
        binding.external_identity_id
    );
}

#[tokio::test]
async fn add_user_with_identity_binds_subject_atomically() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let audited = store.audited("admin@example.com".to_owned());
    let input = AddUserWithIdentityInput {
        email: "Alice@Example.com".to_owned(),
        display_name: "Alice".to_owned(),
        provider_id: "entra".to_owned(),
        issuer: "https://login.microsoftonline.com/tenant-1/v2.0".to_owned(),
        subject: "tenant-1:object-1".to_owned(),
        subject_strategy: "entra_oid_tid".to_owned(),
    };
    let (user, identity) = audited
        .add_user_with_identity(input.clone())
        .await
        .expect("add user with identity");
    assert_eq!(user.status, "active");
    assert_eq!(identity.user_id, user.id);
    assert_eq!(identity.subject, "tenant-1:object-1");

    let (principal, binding) = store
        .resolve_login(LoginResolutionRequest {
            identity: ExternalIdentity {
                provider_id: input.provider_id.clone(),
                issuer: input.issuer.clone(),
                subject: input.subject.clone(),
                ..ExternalIdentity::default()
            },
            policy: LoginTrustPolicy {
                email_binding: "disabled".to_owned(),
                allowed_email_domains: Vec::new(),
            },
        })
        .await
        .expect("resolve bound identity");
    assert_eq!(principal.user_id, user.id);
    assert_eq!(binding.status, "existing");

    let actions: Vec<String> = store
        .list_admin_audit()
        .await
        .expect("audit entries")
        .into_iter()
        .map(|entry| entry.action)
        .collect();
    assert!(actions.contains(&"user.add".to_owned()));
    assert!(actions.contains(&"user.bind_identity".to_owned()));

    let duplicate = audited
        .add_user_with_identity(AddUserWithIdentityInput {
            email: "other@example.com".to_owned(),
            ..input
        })
        .await;
    assert!(matches!(duplicate, Err(CoreError::InvalidArgument(_))));
    let users = store
        .list_users(UserListFilter {
            query: "other@example.com".to_owned(),
            limit: 10,
        })
        .await
        .expect("list users");
    assert!(users.is_empty(), "failed bind must not leave a user behind");
}

#[tokio::test]
async fn resolve_login_rejects_unverified_mismatched_or_untrusted_invitation() {
    for (name, identity, policy) in [
        (
            "unverified email",
            ExternalIdentity {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject-1".to_owned(),
                email: "alice@example.com".to_owned(),
                email_verified: false,
                ..ExternalIdentity::default()
            },
            LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                ..LoginTrustPolicy::default()
            },
        ),
        (
            "provider mismatch",
            ExternalIdentity {
                provider_id: "google".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject-1".to_owned(),
                email: "alice@example.com".to_owned(),
                email_verified: true,
                ..ExternalIdentity::default()
            },
            LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                ..LoginTrustPolicy::default()
            },
        ),
        (
            "domain rejected",
            ExternalIdentity {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                subject: "subject-1".to_owned(),
                email: "alice@example.com".to_owned(),
                email_verified: true,
                ..ExternalIdentity::default()
            },
            LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                allowed_email_domains: vec!["contractor.example".to_owned()],
            },
        ),
    ] {
        let fixture = migrated_store().await;
        let store = &fixture.store;
        store
            .add_invitation(AddInvitationInput {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://sso.example.com/realms/prod".to_owned(),
                email: "Alice@Example.com".to_owned(),
                display_name: "Alice".to_owned(),
                binding_policy: "verified_email_invitation".to_owned(),
                expires_at: 0,
            })
            .await
            .expect("add invitation");
        assert!(
            matches!(
                store
                    .resolve_login(LoginResolutionRequest { identity, policy })
                    .await,
                Err(CoreError::NotFound)
            ),
            "{name}"
        );
    }
}

#[tokio::test]
async fn issued_authn_token_lookup_rejects_expired_and_revoked_tokens() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let now = Store::unix_now();
    IssuedTokenLog::record(
        store,
        IssuedToken {
            jti: "active-jti".to_owned(),
            kind: "authn".to_owned(),
            user_id: user.id.clone(),
            kid: "kid".to_owned(),
            issued_at: now,
            expires_at: now + 60,
            audience: vec!["auth.example.com".to_owned()],
            ..IssuedToken::default()
        },
    )
    .await
    .expect("record active token");
    IssuedTokenLog::record(
        store,
        IssuedToken {
            jti: "expired-jti".to_owned(),
            kind: "authn".to_owned(),
            user_id: user.id.clone(),
            kid: "kid".to_owned(),
            issued_at: now - 120,
            expires_at: now - 60,
            audience: vec!["auth.example.com".to_owned()],
            ..IssuedToken::default()
        },
    )
    .await
    .expect("record expired token");
    IssuedTokenLog::record(
        store,
        IssuedToken {
            jti: "revoked-jti".to_owned(),
            kind: "authn".to_owned(),
            user_id: user.id.clone(),
            kid: "kid".to_owned(),
            issued_at: now,
            expires_at: now + 60,
            audience: vec!["auth.example.com".to_owned()],
            ..IssuedToken::default()
        },
    )
    .await
    .expect("record revoked token");
    store
        .revoke_issued_token("revoked-jti")
        .await
        .expect("revoke token");

    assert_eq!(
        store
            .principal_by_authn_token_jti("active-jti")
            .await
            .expect("active token")
            .user_id,
        user.id
    );
    assert!(matches!(
        store.principal_by_authn_token_jti("expired-jti").await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        store.principal_by_authn_token_jti("revoked-jti").await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn device_authorization_storage_tracks_approval_consumption_and_expiry() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    let user = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            ..AddUserInput::default()
        })
        .await
        .expect("add user");
    let resource = store
        .upsert_and_get(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert repo");
    let device = store
        .create_device_authorization(CreateDeviceAuthorizationParams {
            device_code_hash: "device-hash".to_owned(),
            user_code_hash: "user-hash".to_owned(),
            requested_remote_url: "lore://requested".to_owned(),
            requested_repository_id: resource.id.clone(),
            ttl_seconds: 600,
        })
        .await
        .expect("create device authorization");
    assert_eq!(
        store
            .device_by_user_code_hash("user-hash")
            .await
            .expect("by user code")
            .id,
        device.id
    );
    store
        .approve_device_authorization(&device.id, &user.id)
        .await
        .expect("approve device");
    assert!(matches!(
        store
            .approve_device_authorization(&device.id, &user.id)
            .await,
        Err(CoreError::NotFound)
    ));
    store
        .consume_device_authorization(&device.id)
        .await
        .expect("consume device");
    assert!(matches!(
        store.consume_device_authorization(&device.id).await,
        Err(CoreError::NotFound)
    ));

    let expired = store
        .create_device_authorization(CreateDeviceAuthorizationParams {
            device_code_hash: "expired-device-hash".to_owned(),
            user_code_hash: "expired-user-hash".to_owned(),
            requested_remote_url: "lore://requested".to_owned(),
            requested_repository_id: resource.id,
            ttl_seconds: 0,
        })
        .await
        .expect("create expired device authorization");
    assert!(matches!(
        store
            .approve_device_authorization(&expired.id, &user.id)
            .await,
        Err(CoreError::NotFound)
    ));
    store
        .expire_device_authorization(&expired.id)
        .await
        .expect("expire pending device authorization");
}

#[tokio::test]
async fn signing_key_metadata_is_listed_without_generating_private_keys_in_sqlite() {
    let fixture = migrated_store().await;
    let store = &fixture.store;
    assert!(matches!(
        store.generate_active_key("kid", "RS256", 2048).await,
        Err(CoreError::Unsupported)
    ));
    store
        .add_signing_key_meta(SigningKeyMeta {
            kid: "kid-1".to_owned(),
            alg: "RS256".to_owned(),
            public_jwk_json: r#"{"kty":"RSA","kid":"kid-1"}"#.to_owned(),
            private_key_path: "/tmp/kid-1.pem".to_owned(),
            status: "active".to_owned(),
        })
        .await
        .expect("add signing key");
    assert_eq!(
        store
            .list_keys()
            .await
            .expect("list signing keys")
            .into_iter()
            .map(|key| key.kid)
            .collect::<Vec<_>>(),
        vec!["kid-1"]
    );
}
