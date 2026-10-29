use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use lore_auth_adapters::{
    device::UuidDeviceCodeGenerator,
    memory::Store,
    rs256::{self, Signer, SigningKey},
};
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AuthnTokenInput, AuthzTokenInput, ExternalIdentity, LoginTrustPolicy,
        Permission, Resource, ResourceID, ResourcePermission, SignedToken, TokenPrincipal, User,
        VerifiedAuthn, VerifiedToken, VerifyOptions,
    },
    ports::{
        AccountDirectory, AuthorizationPolicy, BeginAuthRequest, BeginAuthResult,
        CompleteAuthRequest, DeviceCodeGenerator, GrantAdmin, GroupAdmin, IdentityProvider,
        IdentityProviderDescriptor, IdentityProviderRegistry, StateStore, TokenSigner,
    },
    service::{
        device::{DeviceConfig, DeviceService},
        login::{LoginConfig, LoginService},
        permission::PermissionService,
        resource::ResourceService,
        token::{TokenConfig, TokenService},
    },
};

fn token_service(store: &Arc<Store>) -> Arc<TokenService> {
    Arc::new(TokenService::new(
        TokenConfig {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned(), "lore.example.com".to_owned()],
            auth_service_audience: "auth.example.com".to_owned(),
            authn_ttl: Duration::from_secs(3_600),
            authz_ttl: Duration::from_secs(900),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        Some(store.clone()),
    ))
}

struct RecordingSigner {
    store: Arc<Store>,
    resources: Mutex<Vec<ResourcePermission>>,
}

#[async_trait]
impl TokenSigner for RecordingSigner {
    async fn sign_authn(&self, input: AuthnTokenInput) -> Result<SignedToken, CoreError> {
        self.store.sign_authn(input).await
    }

    async fn sign_authz(&self, input: AuthzTokenInput) -> Result<SignedToken, CoreError> {
        *self.resources.lock().expect("resources lock") = input.resources.clone();
        self.store.sign_authz(input).await
    }

    async fn verify(&self, compact: &str, opts: VerifyOptions) -> Result<VerifiedToken, CoreError> {
        self.store.verify(compact, opts).await
    }

    async fn jwks(&self) -> Result<Vec<u8>, CoreError> {
        self.store.jwks().await
    }
}

struct AdminCheckFails;

#[async_trait]
impl AuthorizationPolicy for AdminCheckFails {
    async fn can_access(
        &self,
        _user: &str,
        _resource: &str,
        action: &str,
    ) -> Result<bool, CoreError> {
        if action == "admin" {
            Err(CoreError::Unsupported)
        } else {
            Ok(true)
        }
    }

    async fn list_accessible(
        &self,
        _user: &str,
        _filter: lore_auth_core::model::ResourceFilter,
    ) -> Result<Vec<ResourcePermission>, CoreError> {
        Err(CoreError::Unsupported)
    }
}

#[tokio::test]
async fn admin_permissions_are_checked_per_resource_and_errors_fail_closed() {
    let store = Arc::new(Store::new());
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    for (id, name) in [("urc-admin", "admin"), ("urc-writer", "writer")] {
        store.add_test_resource(Resource {
            id: id.to_owned(),
            name: name.to_owned(),
            remote_url: "lore://example".to_owned(),
            resource_id: id.to_owned(),
            status: "active".to_owned(),
            ..Resource::default()
        });
        store.grant_role(&user.id, id, name);
    }
    let signer = Arc::new(RecordingSigner {
        store: store.clone(),
        resources: Mutex::new(Vec::new()),
    });
    let config = TokenConfig {
        issuer: "https://auth.example.com".to_owned(),
        audience: vec!["lore-service".to_owned()],
        auth_service_audience: "auth.example.com".to_owned(),
        authn_ttl: Duration::from_secs(3600),
        authz_ttl: Duration::from_secs(900),
    };
    let authn = VerifiedAuthn {
        principal: TokenPrincipal {
            user_id: user.id.clone(),
            token_subject: user.bridge_subject(),
            token_idp: "bridge".to_owned(),
            ..TokenPrincipal::default()
        },
        subject: user.bridge_subject(),
        user: user.clone(),
    };
    let service = Arc::new(TokenService::new(
        config.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        signer.clone(),
        None,
    ));
    service
        .exchange_authz(
            authn.clone(),
            &["urc-admin".to_owned(), "urc-writer".to_owned()],
            None,
        )
        .await
        .expect("multi-resource token");
    assert_eq!(
        *signer.resources.lock().expect("resources lock"),
        vec![
            ResourcePermission {
                resource_id: "urc-admin".to_owned(),
                permission: vec![Permission::Read, Permission::Write, Permission::Admin],
            },
            ResourcePermission {
                resource_id: "urc-writer".to_owned(),
                permission: vec![Permission::Read, Permission::Write],
            },
        ]
    );

    let device = DeviceService::new(
        DeviceConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            auth_url: "ucs-auth://auth.example.com".to_owned(),
            device_code_ttl: Duration::from_secs(600),
            poll_interval: Duration::from_secs(3),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        service.clone(),
        Arc::new(fixed_codes("admin-device", "ADMIN-001")),
    );
    let started = device
        .start("lore://example", "admin")
        .await
        .expect("start");
    device
        .approve(&user.id, &started.user_code)
        .await
        .expect("approve");
    assert_eq!(
        device
            .token(&started.device_code)
            .await
            .expect("token")
            .status,
        "ok"
    );
    assert_eq!(
        *signer.resources.lock().expect("resources lock"),
        vec![ResourcePermission {
            resource_id: "urc-admin".to_owned(),
            permission: vec![Permission::Read, Permission::Write, Permission::Admin],
        }]
    );

    store.add_group("admins", "").await.expect("group");
    store
        .add_group_member("admins", &user.id)
        .await
        .expect("member");
    store
        .add_grant("group", "admins", "writer", "admin")
        .await
        .expect("group grant");
    service
        .exchange_authz(authn.clone(), &["urc-writer".to_owned()], None)
        .await
        .expect("group admin token");
    assert_eq!(
        signer.resources.lock().expect("resources lock")[0].permission,
        vec![Permission::Read, Permission::Write, Permission::Admin]
    );

    let failing = Arc::new(AdminCheckFails);
    let service = TokenService::new(
        config,
        store.clone(),
        store.clone(),
        failing.clone(),
        signer,
        None,
    );
    assert!(matches!(
        service
            .exchange_authz(authn, &["urc-admin".to_owned()], None)
            .await,
        Err(CoreError::Unsupported)
    ));
    let permissions = PermissionService::new(store, failing);
    assert!(matches!(
        permissions.check(&user.id, &["urc-admin".to_owned()]).await,
        Err(CoreError::Unsupported)
    ));
}

#[tokio::test]
async fn signed_multi_resource_token_has_repository_scoped_admin_claim() {
    let store = Arc::new(Store::new());
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    for (resource_id, role) in [("urc-admin", "admin"), ("urc-writer", "writer")] {
        store.add_test_resource(Resource {
            id: resource_id.to_owned(),
            name: resource_id.to_owned(),
            resource_id: resource_id.to_owned(),
            status: "active".to_owned(),
            ..Resource::default()
        });
        store.grant_role(&user.id, resource_id, role);
    }
    let signer = Arc::new(Signer::new(
        SigningKey::generate("test", 2048).expect("key"),
    ));
    let service = TokenService::new(
        TokenConfig {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned()],
            auth_service_audience: "auth.example.com".to_owned(),
            authn_ttl: Duration::from_secs(3600),
            authz_ttl: Duration::from_secs(900),
        },
        store.clone(),
        store.clone(),
        store,
        signer.clone(),
        None,
    );
    let token = service
        .exchange_authz(
            VerifiedAuthn {
                principal: TokenPrincipal {
                    user_id: user.id.clone(),
                    token_subject: user.bridge_subject(),
                    token_idp: "bridge".to_owned(),
                    ..TokenPrincipal::default()
                },
                subject: user.bridge_subject(),
                user,
            },
            &["urc-admin".to_owned(), "urc-writer".to_owned()],
            None,
        )
        .await
        .expect("signed token");
    signer
        .verify(
            &token.token,
            VerifyOptions {
                issuer: "https://auth.example.com".to_owned(),
                audience: "lore-service".to_owned(),
            },
        )
        .await
        .expect("verify signed token");
    let claims = rs256::decode_insecure(&token.token)
        .expect("decode verified token")
        .claims;
    assert_eq!(
        claims["resources"],
        serde_json::json!([
            {"resource_id": "urc-admin", "permission": ["read", "write", "admin"]},
            {"resource_id": "urc-writer", "permission": ["read", "write"]}
        ])
    );
}

#[tokio::test]
async fn token_service_mints_authn_with_auth_service_audience_and_verifies_by_jti() {
    let store = Arc::new(Store::new());
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    let service = token_service(&store);

    let (signed, minted_user) = service
        .mint_authn(&user.id, None)
        .await
        .expect("mint authn");
    assert_eq!(minted_user.id, user.id);
    assert!(signed.audience.iter().any(|aud| aud == "lore.example.com"));
    assert!(signed.audience.iter().any(|aud| aud == "auth.example.com"));

    let verified = service
        .verify_authn(&format!("Bearer {}", signed.token))
        .await
        .expect("verify authn");
    assert_eq!(verified.user.id, user.id);
    assert_eq!(verified.principal.token_idp, "bridge");
}

#[tokio::test]
async fn token_service_scopes_admin_to_the_authorized_repository() {
    let store = Arc::new(Store::new());
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    let resource_id = ResourceID::for_repository_id("repo-1").expect("resource id");
    store.add_test_resource(Resource {
        id: "resource-1".to_owned(),
        name: "game-assets".to_owned(),
        remote_url: "lore://example".to_owned(),
        lore_repository_id: "repo-1".to_owned(),
        resource_id: resource_id.clone(),
        status: "active".to_owned(),
    });
    let service = token_service(&store);
    let authn = VerifiedAuthn {
        subject: "user:user-1".to_owned(),
        principal: TokenPrincipal {
            user_id: user.id.clone(),
            token_subject: "user:user-1".to_owned(),
            token_idp: "bridge".to_owned(),
            display_name: "Alice".to_owned(),
            preferred_username: "alice@example.com".to_owned(),
            groups: Vec::new(),
        },
        user,
    };

    store.grant_role("user-1", &resource_id, "reader");
    let err = service
        .exchange_authz(authn.clone(), std::slice::from_ref(&resource_id), None)
        .await
        .expect_err("reader must not receive authz token");
    assert!(matches!(err, CoreError::PermissionDenied));

    store.grant_role("user-1", &resource_id, "writer");
    let signed = service
        .exchange_authz(authn.clone(), std::slice::from_ref(&resource_id), None)
        .await
        .expect("writer token");
    assert_eq!(
        signed.permissions,
        vec![Permission::Read, Permission::Write]
    );

    store.grant_role("user-1", &resource_id, "admin");
    let signed = service
        .exchange_authz(authn.clone(), std::slice::from_ref(&resource_id), None)
        .await
        .expect("admin token");
    assert_eq!(signed.lore_resource_id, "urc-repo-1");
    assert_eq!(
        signed.permissions,
        vec![Permission::Read, Permission::Write, Permission::Admin]
    );

    let manual = service
        .manual_mint_authz("user-1", "game-assets", "writer", None)
        .await
        .expect("manual writer token remains restricted");
    assert_eq!(
        manual.permissions,
        vec![Permission::Read, Permission::Write]
    );
    let device = service
        .device_mint_authz("user-1", "game-assets")
        .await
        .expect("device token includes admin");
    assert_eq!(device.permissions, signed.permissions);

    let other = "urc-repo-2";
    store.add_test_resource(Resource {
        id: "resource-2".to_owned(),
        name: "other-assets".to_owned(),
        lore_repository_id: "repo-2".to_owned(),
        resource_id: other.to_owned(),
        status: "active".to_owned(),
        ..Resource::default()
    });
    store.grant_role("user-1", other, "writer");
    let signed = service
        .exchange_authz(authn, &[other.to_owned()], None)
        .await
        .expect("writer on a different repository");
    assert_eq!(
        signed.permissions,
        vec![Permission::Read, Permission::Write]
    );
}

#[tokio::test]
async fn login_service_uses_requested_provider_and_rejects_provider_or_issuer_mismatch() {
    let store = Arc::new(Store::new());
    let login = login_service(
        &store,
        registry([
            provider(
                "google",
                "https://accounts.google.com",
                "https://google.example/auth",
                ExternalIdentity::default(),
                LoginTrustPolicy::default(),
            ),
            provider(
                "keycloak-prod",
                "https://sso.example.com/realms/prod",
                "https://sso.example.com/auth",
                ExternalIdentity::default(),
                LoginTrustPolicy::default(),
            ),
        ]),
    );

    let started = login
        .begin_auth(
            "keycloak-prod",
            BeginAuthRequest {
                state: "state-1".to_owned(),
                nonce: "nonce-1".to_owned(),
                ..BeginAuthRequest::default()
            },
        )
        .await
        .expect("begin requested provider");
    assert_eq!(
        started.redirect_url,
        "https://sso.example.com/auth?state=state-1&nonce=nonce-1"
    );

    let provider_mismatch = login_service(
        &store,
        registry([provider(
            "google",
            "https://accounts.google.com",
            "https://google.example/auth",
            ExternalIdentity {
                provider_id: "keycloak-prod".to_owned(),
                issuer: "https://accounts.google.com".to_owned(),
                subject: "subject-1".to_owned(),
                ..ExternalIdentity::default()
            },
            LoginTrustPolicy::default(),
        )]),
    );
    assert!(matches!(
        provider_mismatch
            .complete_auth("google", CompleteAuthRequest::default(), "")
            .await,
        Err(CoreError::Unauthenticated)
    ));

    let issuer_mismatch = login_service(
        &store,
        registry([provider(
            "google",
            "https://accounts.google.com",
            "https://google.example/auth",
            ExternalIdentity {
                provider_id: "google".to_owned(),
                issuer: "https://evil.example.com".to_owned(),
                subject: "subject-1".to_owned(),
                ..ExternalIdentity::default()
            },
            LoginTrustPolicy::default(),
        )]),
    );
    assert!(matches!(
        issuer_mismatch
            .complete_auth("google", CompleteAuthRequest::default(), "")
            .await,
        Err(CoreError::Unauthenticated)
    ));
}

#[tokio::test]
async fn login_service_binds_verified_email_invitation_and_rejects_session_state_errors() {
    let store = Arc::new(Store::new());
    let (pending_user, _invitation) = store
        .add_invitation(AddInvitationInput {
            provider_id: "google".to_owned(),
            issuer: "https://accounts.google.com".to_owned(),
            email: "alice@example.com".to_owned(),
            display_name: "Alice".to_owned(),
            binding_policy: "verified_email_invitation".to_owned(),
            expires_at: 0,
        })
        .await
        .expect("add invitation");
    let login = login_service(
        &store,
        registry([provider(
            "google",
            "https://accounts.google.com",
            "https://google.example/auth",
            ExternalIdentity {
                issuer: "https://accounts.google.com".to_owned(),
                subject: "google-sub".to_owned(),
                email: "Alice@Example.com".to_owned(),
                email_verified: true,
                display_name: "Alice".to_owned(),
                ..ExternalIdentity::default()
            },
            LoginTrustPolicy {
                email_binding: "verified_email_invitation".to_owned(),
                allowed_email_domains: vec!["example.com".to_owned()],
            },
        )]),
    );

    let callback = login
        .complete_oauth_callback("code", "")
        .await
        .expect("complete callback");
    assert!(!callback.unknown_user);
    assert_eq!(callback.user.id, pending_user.id);
    assert_eq!(callback.browser_session.user_id, pending_user.id);

    let auth_session = login
        .start_auth_session("client-state")
        .await
        .expect("start auth session");
    let err = login
        .get_auth_session(&auth_session.session_code, "wrong-client-state", None)
        .await
        .expect_err("client state mismatch");
    assert!(matches!(err, CoreError::InvalidArgument(_)));
}

#[tokio::test]
async fn login_service_enforces_all_applicable_group_cidrs_with_or_semantics() {
    let store = Arc::new(Store::new());
    let user = store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    store
        .add_group("company-a", "")
        .await
        .expect("add first group");
    store
        .add_group("company-b", "")
        .await
        .expect("add second group");
    store
        .add_group_member("company-a", &user.id)
        .await
        .expect("add first membership");
    store
        .add_group_member("company-b", &user.id)
        .await
        .expect("add second membership");
    store
        .add_group_allowed_cidr("company-a", "192.0.2.25/24")
        .await
        .expect("add first CIDR");
    store
        .add_group_allowed_cidr("company-b", "198.51.100.0/24")
        .await
        .expect("add second CIDR");
    let login = login_service(&store, registry([]));

    for ip in ["192.0.2.99", "198.51.100.99"] {
        let auth_session = login
            .start_auth_session("client-state")
            .await
            .expect("start auth session");
        let session = store
            .get_auth_session_by_code(&auth_session.session_code)
            .await
            .expect("get auth session");
        store
            .complete_auth_session(&session.id, &user.id)
            .await
            .expect("complete auth session");
        let result = login
            .get_auth_session(
                &auth_session.session_code,
                "client-state",
                Some(ip.parse::<IpAddr>().expect("parse IP")),
            )
            .await
            .expect("allowed IP mints a token");
        assert!(result.ready);
    }

    let auth_session = login
        .start_auth_session("client-state")
        .await
        .expect("start auth session");
    let session = store
        .get_auth_session_by_code(&auth_session.session_code)
        .await
        .expect("get auth session");
    store
        .complete_auth_session(&session.id, &user.id)
        .await
        .expect("complete auth session");
    assert_eq!(
        login
            .get_auth_session(
                &auth_session.session_code,
                "client-state",
                Some("203.0.113.99".parse().expect("parse IP")),
            )
            .await,
        Err(CoreError::PermissionDenied)
    );
}

#[tokio::test]
async fn permission_and_resource_services_wrap_resource_store_and_authz_policy() {
    let store = Arc::new(Store::new());
    let resources = ResourceService::new(store.clone());
    let permissions = PermissionService::new(store.clone(), store.clone());
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    resources
        .create_resource("urc-repo-1", "game-assets")
        .await
        .expect("create resource");
    store.grant_role(&user.id, "urc-repo-1", "writer");

    let checked = permissions
        .check(
            &user.id,
            &["urc-repo-1".to_owned(), "urc-missing".to_owned()],
        )
        .await
        .expect("check permissions");
    assert_eq!(checked[0].resource_id, "urc-repo-1");
    assert!(checked[0].allowed);
    assert_eq!(
        checked[0].permission,
        vec![Permission::Read, Permission::Write]
    );
    assert_eq!(checked[1].resource_id, "urc-missing");
    assert!(!checked[1].allowed);

    store.grant_role(&user.id, "urc-repo-1", "admin");
    let checked = permissions
        .check(&user.id, &["urc-repo-1".to_owned()])
        .await
        .expect("check admin permission");
    assert!(checked[0].allowed);
    assert_eq!(
        checked[0].permission,
        vec![Permission::Read, Permission::Write, Permission::Admin]
    );

    store.grant_role(&user.id, "urc-repo-1", "reader");
    let checked = permissions
        .check(&user.id, &["urc-repo-1".to_owned()])
        .await
        .expect("check reader permission");
    assert!(!checked[0].allowed);
    assert!(checked[0].permission.is_empty());
}

#[tokio::test]
async fn device_service_runs_start_preview_approve_token_and_consumes_authorization() {
    let store = Arc::new(Store::new());
    let user = store.add_test_user(User {
        id: "user-1".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    store.add_test_resource(Resource {
        id: "resource-1".to_owned(),
        name: "game-assets".to_owned(),
        remote_url: "lore://example".to_owned(),
        lore_repository_id: "repo-1".to_owned(),
        resource_id: "urc-repo-1".to_owned(),
        status: "active".to_owned(),
    });
    store.grant_role(&user.id, "urc-repo-1", "writer");

    let service = device_service(&store, fixed_codes("device-code", "ABCD-EFGH"));
    let start = service
        .start("lore://requested.example/repo", "game-assets")
        .await
        .expect("start device flow");
    assert_eq!(start.device_code, "device-code");
    assert_eq!(start.user_code, "ABCD-EFGH");
    assert_eq!(start.verification_uri, "https://auth.example.com/device");

    let pending = service.token(&start.device_code).await.expect("pending");
    assert_eq!(pending.status, "authorization_pending");

    let preview = service.preview(&start.user_code).await.expect("preview");
    assert_eq!(preview.repository.name, "game-assets");
    assert_eq!(preview.repository.remote_url, "lore://example");
    assert_eq!(
        preview.requested_remote_url,
        "lore://requested.example/repo"
    );

    let approved = service
        .approve(&user.id, &start.user_code)
        .await
        .expect("approve device flow");
    assert_eq!(approved.name, "game-assets");

    let token = service.token(&start.device_code).await.expect("token");
    assert_eq!(token.status, "ok");
    assert_eq!(token.token_type, "lore");
    assert!(!token.access_token.is_empty());
    assert_eq!(token.remote_url, "lore://example");
    assert!(token.expires_in > 0 && token.expires_in <= 900);

    let consumed = service
        .token(&start.device_code)
        .await
        .expect("consumed status");
    assert_eq!(consumed.status, "consumed");
}

#[tokio::test]
async fn device_service_classifies_invalid_code_and_denied_approval() {
    let store = Arc::new(Store::new());
    let alice = store.add_test_user(User {
        id: "alice".to_owned(),
        email: "alice@example.com".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    let bob = store.add_test_user(User {
        id: "bob".to_owned(),
        email: "bob@example.com".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    store.add_test_resource(Resource {
        id: "resource-1".to_owned(),
        name: "game-assets".to_owned(),
        remote_url: "lore://example".to_owned(),
        lore_repository_id: "repo-1".to_owned(),
        resource_id: "urc-repo-1".to_owned(),
        status: "active".to_owned(),
    });
    store.grant_role(&alice.id, "urc-repo-1", "writer");

    let service = device_service(&store, fixed_codes("device-code", "ABCD-EFGH"));
    assert!(matches!(
        service.approve(&alice.id, "NOPE-NOPE").await,
        Err(CoreError::DeviceInvalidCode)
    ));
    assert!(matches!(
        service.token("missing-device-code").await,
        Err(CoreError::DeviceInvalidCode)
    ));

    let start = service
        .start("lore://requested.example/repo", "game-assets")
        .await
        .expect("start device flow");
    assert!(matches!(
        service.approve(&bob.id, &start.user_code).await,
        Err(CoreError::PermissionDenied)
    ));
}

#[test]
fn uuid_device_code_generator_formats_user_code_for_manual_entry() {
    let generator = UuidDeviceCodeGenerator;
    let device_code = generator.device_code().expect("device code");
    let user_code = generator.user_code().expect("user code");

    assert_eq!(device_code.len(), 64);
    assert_eq!(user_code.len(), 9);
    assert_eq!(&user_code[4..5], "-");
    assert!(
        user_code
            .chars()
            .all(|ch| ch == '-' || ch.is_ascii_uppercase() || ch.is_ascii_digit())
    );
}

fn login_service(store: &Arc<Store>, registry: TestRegistry) -> LoginService {
    LoginService::new(
        LoginConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            session_ttl: Duration::from_secs(3_600),
            auth_session_ttl: Duration::from_secs(600),
        },
        Arc::new(registry),
        store.clone(),
        store.clone(),
        store.clone(),
        token_service(store),
    )
}

fn device_service(store: &Arc<Store>, codes: FixedCodes) -> DeviceService {
    DeviceService::new(
        DeviceConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            auth_url: "ucs-auth://auth.example.com".to_owned(),
            device_code_ttl: Duration::from_secs(600),
            poll_interval: Duration::from_secs(3),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        token_service(store),
        Arc::new(codes),
    )
}

fn provider(
    id: &str,
    issuer: &str,
    auth_url: &str,
    identity: ExternalIdentity,
    trust_policy: LoginTrustPolicy,
) -> TestProvider {
    TestProvider {
        descriptor: IdentityProviderDescriptor {
            id: id.to_owned(),
            provider_type: "oidc".to_owned(),
            display_name: id.to_owned(),
            issuer: issuer.to_owned(),
            trust_policy,
        },
        auth_url: auth_url.to_owned(),
        identity,
    }
}

fn registry(providers: impl IntoIterator<Item = TestProvider>) -> TestRegistry {
    let mut out = HashMap::<String, Arc<dyn IdentityProvider>>::new();
    for provider in providers {
        out.insert(provider.descriptor.id.clone(), Arc::new(provider));
    }
    TestRegistry {
        default_id: "google".to_owned(),
        providers: out,
    }
}

struct TestRegistry {
    default_id: String,
    providers: HashMap<String, Arc<dyn IdentityProvider>>,
}

impl IdentityProviderRegistry for TestRegistry {
    fn get(&self, id: &str) -> Option<Arc<dyn IdentityProvider>> {
        self.providers.get(id).cloned()
    }

    fn default_id(&self) -> &str {
        &self.default_id
    }

    fn list(&self) -> Vec<IdentityProviderDescriptor> {
        self.providers
            .values()
            .map(|provider| provider.descriptor())
            .collect()
    }
}

#[derive(Clone)]
struct TestProvider {
    descriptor: IdentityProviderDescriptor,
    auth_url: String,
    identity: ExternalIdentity,
}

#[async_trait]
impl IdentityProvider for TestProvider {
    fn descriptor(&self) -> IdentityProviderDescriptor {
        self.descriptor.clone()
    }

    async fn begin_auth(&self, req: BeginAuthRequest) -> Result<BeginAuthResult, CoreError> {
        Ok(BeginAuthResult {
            redirect_url: format!("{}?state={}&nonce={}", self.auth_url, req.state, req.nonce),
            private_state: Vec::new(),
        })
    }

    async fn complete_auth(
        &self,
        _req: CompleteAuthRequest,
    ) -> Result<ExternalIdentity, CoreError> {
        Ok(self.identity.clone())
    }
}

fn fixed_codes(device: &str, user: &str) -> FixedCodes {
    FixedCodes {
        device: device.to_owned(),
        user: user.to_owned(),
    }
}

struct FixedCodes {
    device: String,
    user: String,
}

impl DeviceCodeGenerator for FixedCodes {
    fn device_code(&self) -> Result<String, CoreError> {
        Ok(self.device.clone())
    }

    fn user_code(&self) -> Result<String, CoreError> {
        Ok(self.user.clone())
    }
}
