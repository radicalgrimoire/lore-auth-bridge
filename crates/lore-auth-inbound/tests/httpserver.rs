use std::{collections::BTreeMap, fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::connect_info::ConnectInfo,
    http::{Request, StatusCode, header},
};
use lore_auth_adapters::{authz, idpregistry, memory, sqlite};
use lore_auth_core::{
    CoreError,
    model::{self, AddUserInput, ExternalIdentity, Resource, ResourceID, User},
    ports::{
        AccountDirectory, AccountQuery, AdminAuditLog, AuthorizationPolicy, BeginAuthRequest,
        BeginAuthResult, CompleteAuthRequest, GrantAdmin, GrantQuery, GroupAdmin, GroupQuery,
        IdentityProvider, IdentityProviderDescriptor, ResourceQuery, ResourceStore,
        ServiceAccountDirectory, StateStore,
    },
    service::{
        device::{DeviceConfig, DeviceIdentityStores, DeviceService},
        login::{LoginConfig, LoginService},
        permission::PermissionService,
        token::{TokenConfig, TokenService},
    },
};
use lore_auth_inbound::{
    admin::{AdminConfig, AdminEntraProvider},
    httpserver::{HttpConfig, SESSION_COOKIE_NAME, Services, build_router},
    repository_client::{CreateError, RepositoryCreator},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

struct TestRepositoryCreator {
    resources: Arc<dyn ResourceStore>,
}

struct FailingAdminAudit;

#[async_trait]
impl AdminAuditLog for FailingAdminAudit {
    async fn record(&self, _entry: model::AdminAuditEntry) -> Result<(), CoreError> {
        Err(CoreError::AdminAuditFailed("test failure".into()))
    }
}

#[async_trait]
impl RepositoryCreator for TestRepositoryCreator {
    async fn create(
        &self,
        name: &str,
        _token: &str,
        id: Uuid,
        _branch_id: Uuid,
    ) -> Result<(), CreateError> {
        match name {
            "rpc-rejected" => {
                return Err(CreateError::Rejected("Lore rejected the request".into()));
            }
            "rpc-uncertain" => return Err(CreateError::Uncertain("Lore returned Internal".into())),
            "rpc-unsynchronized" => return Ok(()),
            _ => {}
        }
        self.resources
            .upsert(Resource {
                name: name.to_owned(),
                resource_id: ResourceID::for_repository_id(&id.simple().to_string()).unwrap(),
                ..Resource::default()
            })
            .await
            .map_err(|err| CreateError::Uncertain(err.to_string()))
    }
}

#[tokio::test]
async fn jwks_and_html_responses_carry_security_headers() {
    let (app, store, _) = new_test_app(fake_idp());
    let user = add_alice(&store);
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let jwks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("jwks response");
    assert_eq!(jwks.status(), StatusCode::OK);
    assert_eq!(
        jwks.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_security_headers(jwks.headers());

    let tokens = app
        .oneshot(
            Request::builder()
                .uri("/tokens")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("tokens response");
    assert_eq!(tokens.status(), StatusCode::OK);
    assert_security_headers(tokens.headers());
}

#[tokio::test]
async fn auth_callback_sets_hardened_session_cookie() {
    let (app, store, _) = new_test_app(fake_idp_with_identity(ExternalIdentity {
        provider_id: "google".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        subject: "alice-sub".to_owned(),
        email: "alice@example.com".to_owned(),
        ..ExternalIdentity::default()
    }));
    let user = add_alice(&store);
    store.add_test_external_identity(ExternalIdentity {
        user_id: user.id,
        provider_id: "google".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        subject: "alice-sub".to_owned(),
        email: "alice@example.com".to_owned(),
        status: "active".to_owned(),
        ..ExternalIdentity::default()
    });
    let (state, _) = store
        .create_login_state(
            model::LoginStateInput {
                provider_id: "google".to_owned(),
                nonce: "nonce".to_owned(),
                ..model::LoginStateInput::default()
            },
            Duration::from_secs(60),
        )
        .await
        .expect("login state creates");

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/auth/google/callback?state={state}&code=static"))
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("callback response");

    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("session cookie")
        .to_str()
        .unwrap();
    assert!(cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=")));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Secure"));
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");
}

#[tokio::test]
async fn logout_requires_same_origin_and_single_use_csrf() {
    let (app, store, _) = new_test_app(fake_idp());
    let user = add_alice(&store);
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/logout")
                .header(header::ORIGIN, "https://auth.example.com")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("missing csrf response");
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);

    let csrf = store
        .create_csrf_token(&session.id, Duration::from_secs(60))
        .await
        .expect("csrf creates");
    let bad_origin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/logout")
                .header(header::ORIGIN, "https://evil.example.com")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("bad origin response");
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

    let good = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/logout")
                .header(header::ORIGIN, "https://auth.example.com")
                .header("x-csrf-token", &csrf)
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("logout response");
    assert_eq!(good.status(), StatusCode::NO_CONTENT);

    let me = app
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header(
                    header::COOKIE,
                    format!("{SESSION_COOKIE_NAME}={}", session.id),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("me response");
    assert_eq!(me.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn device_json_endpoints_preserve_contract_and_reject_bad_bodies() {
    let (app, store, _) = new_test_app(fake_idp());
    store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        remote_url: "lore://stored.example/repo".to_owned(),
        lore_repository_id: "0194b726b34e72b0b45550b88a967076".to_owned(),
        ..Resource::default()
    });

    let unknown = app
        .clone()
        .oneshot(json_request(
            "/api/device/start",
            r#"{"remote_url":"lore://example","repository":"game-assets","extra":true}"#,
        ))
        .await
        .expect("unknown field response");
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

    let start = app
        .clone()
        .oneshot(json_request(
            "/api/device/start",
            r#"{"remote_url":"lore://requested.example/repo","repository":"game-assets"}"#,
        ))
        .await
        .expect("start response");
    assert_eq!(start.status(), StatusCode::OK);
    let body: DeviceStart = decode_json(start).await;
    assert!(!body.device_code.is_empty());
    assert!(!body.user_code.is_empty());
    assert_eq!(body.verification_uri, "https://auth.example.com/device");
    assert_eq!(body.expires_in, 600);
    assert_eq!(body.interval, 3);

    let token = app
        .oneshot(json_request(
            "/api/device/token",
            &format!(r#"{{"device_code":"{}"}}"#, body.device_code),
        ))
        .await
        .expect("token response");
    assert_eq!(token.status(), StatusCode::OK);
    let body: DeviceToken = decode_json(token).await;
    assert_eq!(body.status, "authorization_pending");
    assert_eq!(body.token_type, "");
    assert_eq!(body.access_token, "");
}

#[tokio::test]
async fn browser_and_device_token_issuance_check_the_requesting_client_ip() {
    let (app, store, _) = new_test_app(fake_idp());
    let user = add_alice(&store);
    let resource = store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        lore_repository_id: "0194b726b34e72b0b45550b88a967076".to_owned(),
        ..Resource::default()
    });
    store.grant(&user.id, &resource.resource_id);
    for (group, cidr) in [("office", "192.0.2.0/24"), ("vpn", "2001:db8::/32")] {
        store.add_group(group, "").await.unwrap();
        store.add_group_member(group, &user.id).await.unwrap();
        store.add_group_allowed_cidr(group, cidr).await.unwrap();
    }
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .unwrap();
    let cookie = format!("{SESSION_COOKIE_NAME}={}", session.id);

    for (peer, forwarded, expected) in [
        (
            "127.0.0.1:1234",
            Some("198.51.100.1"),
            StatusCode::FORBIDDEN,
        ),
        ("127.0.0.1:1234", Some("not-an-ip"), StatusCode::FORBIDDEN),
        ("127.0.0.1:1234", None, StatusCode::FORBIDDEN),
        (
            "198.51.100.1:1234",
            Some("192.0.2.5"),
            StatusCode::FORBIDDEN,
        ),
        ("127.0.0.1:1234", Some("192.0.2.5"), StatusCode::OK),
        ("127.0.0.1:1234", Some("2001:db8::5"), StatusCode::OK),
    ] {
        let csrf = store
            .create_csrf_token(&session.id, Duration::from_secs(60))
            .await
            .unwrap();
        let mut req = post_form_request(
            "/tokens/mint",
            Some(cookie.clone()),
            &format!("csrf_token={csrf}&repository=game-assets"),
        );
        req.headers_mut()
            .insert(header::ORIGIN, "https://auth.example.com".parse().unwrap());
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        if let Some(ip) = forwarded {
            req.headers_mut()
                .insert("x-lore-client-ip", ip.parse().unwrap());
        }
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            expected,
            "peer={peer} forwarded={forwarded:?}"
        );
    }

    let start = app
        .clone()
        .oneshot(json_request(
            "/api/device/start",
            r#"{"remote_url":"lore://example","repository":"game-assets"}"#,
        ))
        .await
        .unwrap();
    let start: DeviceStart = decode_json(start).await;
    let csrf = store
        .create_csrf_token(&session.id, Duration::from_secs(60))
        .await
        .unwrap();
    let mut approve = post_form_request(
        "/device/approve",
        Some(cookie),
        &format!("csrf_token={csrf}&user_code={}", start.user_code),
    );
    approve
        .headers_mut()
        .insert(header::ORIGIN, "https://auth.example.com".parse().unwrap());
    approve.extensions_mut().insert(ConnectInfo(
        "198.51.100.1:1234".parse::<SocketAddr>().unwrap(),
    ));
    assert_eq!(
        app.clone().oneshot(approve).await.unwrap().status(),
        StatusCode::OK
    );

    for (forwarded, expected) in [
        (None, StatusCode::FORBIDDEN),
        (Some("198.51.100.1"), StatusCode::FORBIDDEN),
        (Some("192.0.2.5"), StatusCode::OK),
    ] {
        let mut req = json_request(
            "/api/device/token",
            &format!(r#"{{"device_code":"{}"}}"#, start.device_code),
        );
        req.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
        if let Some(ip) = forwarded {
            req.headers_mut()
                .insert("x-lore-client-ip", ip.parse().unwrap());
        }
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), expected, "forwarded={forwarded:?}");
        if expected == StatusCode::OK {
            let token: DeviceToken = decode_json(response).await;
            assert_eq!(token.status, "ok");
            assert!(!token.access_token.is_empty());
        }
    }

    store
        .remove_group_allowed_cidr("office", "192.0.2.0/24")
        .await
        .unwrap();
    store
        .remove_group_allowed_cidr("vpn", "2001:db8::/32")
        .await
        .unwrap();
    let csrf = store
        .create_csrf_token(&session.id, Duration::from_secs(60))
        .await
        .unwrap();
    let mut req = post_form_request(
        "/tokens/mint",
        Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
        &format!("csrf_token={csrf}&repository=game-assets"),
    );
    req.headers_mut()
        .insert(header::ORIGIN, "https://auth.example.com".parse().unwrap());
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn login_session_start_binds_existing_nonce_to_provider_state() {
    let (app, store, _) = new_test_app(fake_idp());
    let (_, auth_session) = store
        .create_auth_session("client-state", Duration::from_secs(60))
        .await
        .expect("auth session creates");

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/google/start?login_nonce={}",
                    auth_session.login_url_nonce
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("auth start response");
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let redirect = url::Url::parse(location).expect("fake idp redirect is absolute");
    let state = redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("state query");
    let nonce = redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "nonce").then(|| value.into_owned()))
        .expect("nonce query");
    assert_ne!(state, nonce);

    let login_state = store
        .consume_login_state(&state)
        .await
        .expect("login state persists");
    assert_eq!(login_state.provider_id, "google");
    assert_eq!(login_state.login_url_nonce, auth_session.login_url_nonce);
}

#[tokio::test]
async fn admin_routes_are_not_mounted_when_admin_emails_are_empty() {
    let (app, _store, _) = new_test_app(fake_idp());

    let response = app
        .oneshot(peer_request("/admin", None, [127, 0, 0, 1]))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_entry_redirects_unauthenticated_users_to_login() {
    let (app, _store, _) = new_test_app_with_admin(fake_idp(), admin_config());

    let response = app
        .oneshot(peer_request("/admin", None, [127, 0, 0, 1]))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/login?return_to=admin"
    );
}

#[tokio::test]
async fn admin_entry_login_returns_to_admin_after_authentication() {
    let identity = ExternalIdentity {
        provider_id: "google".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        subject: "admin-sub".to_owned(),
        email: ADMIN_EMAIL.to_owned(),
        ..ExternalIdentity::default()
    };
    let (app, store, _) =
        new_test_app_with_admin(fake_idp_with_identity(identity.clone()), admin_config());
    let admin = store.add_test_user(User {
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    store.add_test_external_identity(ExternalIdentity {
        user_id: admin.id,
        status: "active".to_owned(),
        ..identity
    });
    let entry = app
        .clone()
        .oneshot(peer_request("/admin", None, [127, 0, 0, 1]))
        .await
        .unwrap();
    let login_path = entry
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(login_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let start_path = login
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(start_path, "/auth/google/start?return_to=admin");
    let start = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(start_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let provider_url = url::Url::parse(
        start
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let state = provider_url
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let callback = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/google/callback?state={state}&code=static"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(callback.headers().get(header::LOCATION).unwrap(), "/admin");
    let cookie = callback
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let dashboard = app
        .oneshot(peer_request("/admin", Some(cookie), [127, 0, 0, 1]))
        .await
        .unwrap();
    assert_eq!(dashboard.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_rejects_arbitrary_return_destinations() {
    let (app, store, _) = new_test_app(fake_idp());
    let start = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/google/start?return_to=https%3A%2F%2Fevil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let url = url::Url::parse(
        start
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let login_state = store.consume_login_state(&state).await.unwrap();
    assert!(login_state.return_path.is_empty());
}

#[tokio::test]
async fn admin_login_does_not_authorize_non_admin_users() {
    let identity = ExternalIdentity {
        provider_id: "google".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        subject: "alice-sub".to_owned(),
        email: "alice@example.com".to_owned(),
        ..ExternalIdentity::default()
    };
    let (app, store, _) =
        new_test_app_with_admin(fake_idp_with_identity(identity.clone()), admin_config());
    let user = add_alice(&store);
    store.add_test_external_identity(ExternalIdentity {
        user_id: user.id,
        status: "active".to_owned(),
        ..identity
    });
    let (state, _) = store
        .create_login_state(
            model::LoginStateInput {
                provider_id: "google".to_owned(),
                return_path: "/admin".to_owned(),
                ..model::LoginStateInput::default()
            },
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let callback = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/google/callback?state={state}&code=static"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.headers().get(header::LOCATION).unwrap(), "/admin");
    let cookie = callback
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let dashboard = app
        .oneshot(peer_request("/admin", Some(cookie), [127, 0, 0, 1]))
        .await
        .unwrap();
    assert_eq!(dashboard.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_route_hides_from_non_admin_browser_sessions() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let user = add_alice(&store);
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let response = app
        .oneshot(peer_request(
            "/admin",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [127, 0, 0, 1],
        ))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_route_requires_login_for_disabled_admin_browser_sessions() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let user = store.add_test_user(User {
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");
    store.disable_test_user(&user.id);

    let response = app
        .oneshot(peer_request(
            "/admin",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [127, 0, 0, 1],
        ))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn admin_route_hides_from_disallowed_peers_before_session_check() {
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        admin_config_with(|admin| {
            admin.allowed_peer_cidrs = vec!["127.0.0.1/32".parse().expect("cidr")];
        }),
    );
    let user = store.add_test_user(User {
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let response = app
        .oneshot(peer_request(
            "/admin",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [192, 0, 2, 10],
        ))
        .await
        .expect("admin response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_route_renders_english_dashboard_even_with_old_language_settings() {
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        admin_config_with(|admin| {
            admin.allowed_peer_cidrs = vec!["127.0.0.1/32".parse().expect("cidr")];
        }),
    );
    let user = store.add_test_user(User {
        email: "Admin@Example.com".to_owned(),
        display_name: "Admin <Root> & Co".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let mut request = peer_request(
        "/admin?lang=ja",
        Some(format!(
            "{SESSION_COOKIE_NAME}={}; admin_lang=ja",
            session.id
        )),
        [127, 0, 0, 1],
    );
    request
        .headers_mut()
        .insert("x-forwarded-proto", "https".parse().unwrap());
    let response = app.oneshot(request).await.expect("admin response");

    assert_eq!(response.status(), StatusCode::OK);
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("admin CSP header")
        .to_str()
        .expect("admin CSP header string");
    assert!(
        csp.contains("connect-src 'self'"),
        "admin CSP {csp:?} missing connect-src 'self'"
    );
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let body = response_text(response).await;
    assert!(body.contains("Admin Dashboard"), "{body}");
    let (navigation, _) = body.split_once("</nav>").unwrap();
    assert!(
        navigation.contains(
            "<a href=\"/admin\" aria-current=\"page\"><strong>Lore Auth Admin</strong></a>"
        )
    );
    assert_eq!(navigation.matches("<a ").count(), 5);
    for path in [
        "/admin/repositories",
        "/admin/users",
        "/admin/groups",
        "/admin/server-settings",
    ] {
        assert!(navigation.contains(&format!("href=\"{path}\"")));
    }
    assert!(body.contains("<html lang=\"en\">"), "{body}");
    assert!(!body.contains("/admin?lang="), "{body}");
    assert!(
        body.contains(r#"<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>"#),
        "{body}"
    );
    assert!(body.contains("Admin@Example.com"), "{body}");
    assert!(body.contains("Admin &#60;Root&#62; &#38; Co"), "{body}");
    assert!(!body.contains("&amp;#60;Root&amp;#62;"), "{body}");
}

#[tokio::test]
async fn admin_static_assets_share_admin_guard_and_content_types() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let user = store.add_test_user(User {
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&user.id, Duration::from_secs(60))
        .await
        .expect("session creates");

    let unauthenticated = app
        .clone()
        .oneshot(peer_request(
            "/admin/static/htmx.min.js",
            None,
            [127, 0, 0, 1],
        ))
        .await
        .expect("static response");
    assert_eq!(unauthenticated.status(), StatusCode::NOT_FOUND);

    let htmx = app
        .clone()
        .oneshot(peer_request(
            "/admin/static/htmx.min.js",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [127, 0, 0, 1],
        ))
        .await
        .expect("htmx response");
    assert_eq!(htmx.status(), StatusCode::OK);
    assert_eq!(
        htmx.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/javascript; charset=utf-8"
    );

    let pico = app
        .oneshot(peer_request(
            "/admin/static/pico.min.css",
            Some(format!("{SESSION_COOKIE_NAME}={}", session.id)),
            [127, 0, 0, 1],
        ))
        .await
        .expect("pico response");
    assert_eq!(pico.status(), StatusCode::OK);
    assert_eq!(
        pico.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/css; charset=utf-8"
    );
}

#[tokio::test]
async fn admin_read_pages_share_guard_and_render_for_admin() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    let user = store.add_test_user(User {
        id: "user-alice".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });
    store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        lore_repository_id: "game-assets".to_owned(),
        resource_id: ResourceID::for_repository_id("game-assets").expect("resource id"),
        status: "active".to_owned(),
        ..Resource::default()
    });
    store.add_group("artists", "").await.expect("add group");

    for path in [
        "/admin/repositories",
        "/admin/users",
        "/admin/groups",
        "/admin/server-settings/simulator",
        &format!("/admin/users/{}/access", user.id),
    ] {
        let unauthenticated = app
            .clone()
            .oneshot(peer_request(path, None, [127, 0, 0, 1]))
            .await
            .expect("unauthenticated admin page response");
        assert_eq!(unauthenticated.status(), StatusCode::NOT_FOUND, "{path}");

        let admin = app
            .clone()
            .oneshot(peer_request(
                path,
                Some(admin_cookie.clone()),
                [127, 0, 0, 1],
            ))
            .await
            .expect("admin page response");
        assert_eq!(admin.status(), StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn admin_simulator_posts_real_policy_result_and_grant_evidence() {
    let fixture = new_sqlite_admin_app().await;
    let store = fixture.store.clone();
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store.add_group("riggers", "").await.expect("add riggers");
    store
        .add_group_member("riggers", &fixture.user_id)
        .await
        .expect("add user to child group");
    store
        .add_group_group(&artists.id, &riggers.id)
        .await
        .expect("nest riggers under artists");
    store
        .add_grant("group", &artists.id, "game-assets", "reader")
        .await
        .expect("add group grant");

    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/server-settings/simulator",
    )
    .await;
    let allow = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=game-assets&action=read"),
        ))
        .await
        .expect("simulator allow response");
    assert_eq!(allow.status(), StatusCode::OK);
    let body = response_text(allow).await;
    assert!(body.contains("Allow"), "{body}");
    assert!(body.contains("alice@example.com"), "{body}");
    assert!(body.contains("urc-repo-id"), "{body}");
    assert!(body.contains("writer"), "{body}");
    assert!(body.contains("reader"), "{body}");
    assert!(body.contains("riggers"), "{body}");
    assert!(body.contains("artists"), "{body}");

    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/server-settings/simulator",
    )
    .await;
    let deny = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=game-assets&action=admin"),
        ))
        .await
        .expect("simulator deny response");
    assert_eq!(deny.status(), StatusCode::OK);
    let body = response_text(deny).await;
    assert!(body.contains("Deny"), "{body}");

    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/server-settings/simulator",
    )
    .await;
    let missing = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=missing&action=read"),
        ))
        .await
        .expect("simulator missing response");
    assert_eq!(missing.status(), StatusCode::OK);
    let body = response_text(missing).await;
    assert!(body.contains("NotFound"), "{body}");
    assert!(body.contains("not found or inactive"), "{body}");
    assert!(
        store
            .list_admin_audit()
            .await
            .expect("list admin audit")
            .is_empty(),
        "simulator must not write admin_audit"
    );

    let (_unused_app, invalid_store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let invalid_cookie = admin_session_cookie(&invalid_store).await;
    let invalid_user = invalid_store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });
    invalid_store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        lore_repository_id: "repo-id".to_owned(),
        resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
        status: "active".to_owned(),
        ..Resource::default()
    });
    let invalid_app = admin_app_with_custom_ports(
        invalid_store.clone(),
        invalid_store.clone(),
        Arc::new(PermissionService::new(
            invalid_store.clone(),
            Arc::new(FailingInvalidRoleAuthz),
        )),
    );
    let csrf = admin_csrf(
        invalid_app.clone(),
        &invalid_cookie,
        "/admin/server-settings/simulator",
    )
    .await;
    let invalid = invalid_app
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(invalid_cookie),
            &format!(
                "csrf_token={csrf}&user={}&resource=game-assets&action=read",
                invalid_user.id
            ),
        ))
        .await
        .expect("simulator invalid role response");
    assert_eq!(invalid.status(), StatusCode::OK);
    let body = response_text(invalid).await;
    assert!(body.contains("InvalidArgument"), "{body}");
    assert!(body.contains("typo-role"), "{body}");
}

#[tokio::test]
async fn admin_simulator_explains_implicit_global_admin_access() {
    let fixture = new_sqlite_admin_app_with_global_admin(true).await;
    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/server-settings/simulator",
    )
    .await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user=admin@example.com&resource=game-assets&action=admin"),
        ))
        .await
        .expect("simulator response");
    let body = response_text(response).await;
    assert!(body.contains("Allow"), "{body}");
    assert!(
        body.contains("Server administrator (global repository admin enabled)"),
        "{body}"
    );

    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/server-settings/simulator",
    )
    .await;
    let response = fixture
        .app
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!(
                "csrf_token={csrf}&user=admin@example.com&resource=game-assets&action=obliterate"
            ),
        ))
        .await
        .expect("simulator response");
    let body = response_text(response).await;
    assert!(body.contains("Deny"), "{body}");
    assert!(
        !body.contains("Server administrator (global repository admin enabled)"),
        "{body}"
    );
}

#[tokio::test]
async fn admin_simulator_evidence_includes_nested_groups() {
    let fixture = new_sqlite_admin_app().await;
    add_nested_only_fixture(&fixture).await;
    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/server-settings/simulator",
    )
    .await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=nested-only&action=read"),
        ))
        .await
        .expect("simulator response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("Allow"), "{body}");
    assert!(body.contains("reader"), "{body}");
    assert!(body.contains("artists"), "{body}");
    assert!(body.contains("riggers"), "{body}");
}

#[tokio::test]
async fn admin_simulator_uses_resolved_resource_for_evidence_when_names_collide() {
    let fixture = new_sqlite_admin_app().await;
    let store = fixture.store.clone();
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
        .add_grant("user", &fixture.user_id, "shared", "reader")
        .await
        .expect("add repo a reader");
    store
        .add_grant("user", &fixture.user_id, "repo-b", "writer")
        .await
        .expect("add repo b writer");

    let csrf = admin_csrf(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/server-settings/simulator",
    )
    .await;
    let response = fixture
        .app
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(fixture.admin_cookie),
            &format!("csrf_token={csrf}&user=alice@example.com&resource=shared&action=write"),
        ))
        .await
        .expect("simulator collision response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("Deny"), "{body}");
    assert!(body.contains("urc-repo-a"), "{body}");
    assert!(body.contains("reader"), "{body}");
    assert!(!body.contains("writer"), "{body}");
}

#[tokio::test]
async fn admin_simulator_uses_english_for_missing_user_error() {
    let fixture = new_sqlite_admin_app().await;
    let cookie = format!("{}; admin_lang=ja", fixture.admin_cookie);
    let csrf = admin_csrf(
        fixture.app.clone(),
        &cookie,
        "/admin/server-settings/simulator",
    )
    .await;
    let response = fixture
        .app
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(cookie),
            &format!("csrf_token={csrf}&user=missing@example.com&resource=game-assets&action=read"),
        ))
        .await
        .expect("simulator missing user response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("Error"), "{body}");
    assert!(body.contains("User not found"), "{body}");
    assert!(body.contains("NotFound"), "{body}");
}

#[tokio::test]
async fn admin_repositories_search_renders_hits_and_empty_results() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    let alice = store.add_test_user(User {
        id: "user-alice".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });
    store.add_test_resource(Resource {
        name: "game-assets".to_owned(),
        lore_repository_id: "game-assets".to_owned(),
        resource_id: ResourceID::for_repository_id("game-assets").expect("resource id"),
        status: "active".to_owned(),
        ..Resource::default()
    });
    store.add_test_resource(Resource {
        name: "tools".to_owned(),
        lore_repository_id: "tools".to_owned(),
        resource_id: ResourceID::for_repository_id("tools").expect("resource id"),
        status: "active".to_owned(),
        ..Resource::default()
    });
    store
        .add_grant("user", &alice.id, "game-assets", "writer")
        .await
        .expect("add grant");

    let hit = app
        .clone()
        .oneshot(peer_request(
            "/admin/repositories?q=game",
            Some(admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .expect("repositories response");
    assert_eq!(hit.status(), StatusCode::OK);
    let body = response_text(hit).await;
    assert!(body.contains("Repositories"), "{body}");
    assert!(body.contains("game-assets"), "{body}");
    assert!(body.contains("urc-game-assets"), "{body}");
    assert!(
        body.contains("/admin/repositories/urc-game-assets/access"),
        "{body}"
    );
    assert!(!body.contains("<th scope=\"col\">Actions</th>"), "{body}");
    assert!(!body.contains("/urc-game-assets/disable"), "{body}");
    assert!(!body.contains("user:user-alice"), "{body}");
    assert!(!body.contains("writer"), "{body}");
    assert!(!body.contains(">tools<"), "{body}");

    let empty = app
        .oneshot(peer_request(
            "/admin/repositories?q=missing",
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("repositories empty response");
    let body = response_text(empty).await;
    assert!(body.contains("No repositories found"), "{body}");
}

#[tokio::test]
async fn repository_access_grants_and_lifecycle_are_audited_and_scoped() {
    let fixture = new_sqlite_admin_app().await;
    let app = fixture.app.clone();
    let cookie = fixture.admin_cookie.clone();
    let id = "urc-repo-id";
    let path = format!("/admin/repositories/{id}/access");
    let group = fixture.store.add_group("artists", "").await.unwrap();
    let bob = fixture
        .store
        .add_user(AddUserInput {
            email: "bob@example.com".into(),
            display_name: "Bob".into(),
        })
        .await
        .unwrap();

    let page = app
        .clone()
        .oneshot(peer_request(&path, Some(cookie.clone()), [127, 0, 0, 1]))
        .await
        .unwrap();
    let body = response_text(page).await;
    assert!(body.contains("alice@example.com"));
    assert!(body.contains("writer"));
    assert!(body.find("Search users and groups").unwrap() < body.find("Add grant").unwrap());
    assert!(body.find("Add grant").unwrap() < body.find("<h2>Grants</h2>").unwrap());

    post_admin_form(
        app.clone(),
        &cookie,
        &path,
        &format!("/admin/repositories/{id}/grants/add"),
        "subject_type=group&subject_id=artists&role=reader",
    )
    .await;
    let page = app
        .clone()
        .oneshot(peer_request(
            &format!("{path}?q=artists"),
            Some(cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let body = response_text(page).await;
    assert!(body.contains("artists"));
    assert!(body.contains(&group.id));
    assert!(!body.contains("alice@example.com"));

    post_admin_form(
        app.clone(),
        &cookie,
        &path,
        &format!("/admin/repositories/{id}/grants/add"),
        "subject_type=user&subject_id=bob%40example.com&role=admin",
    )
    .await;
    assert!(
        fixture
            .store
            .list_grants("game-assets")
            .await
            .unwrap()
            .iter()
            .any(|grant| grant.subject_id == bob.id && grant.role == "admin")
    );
    post_admin_form(
        app.clone(),
        &cookie,
        &path,
        &format!("/admin/repositories/{id}/grants/remove"),
        &format!("subject_type=user&subject_id={}&role=admin", bob.id),
    )
    .await;
    post_admin_form(
        app.clone(),
        &cookie,
        &path,
        &format!("/admin/repositories/{id}/grants/remove"),
        &format!("subject_type=group&subject_id={}&role=reader", group.id),
    )
    .await;
    post_admin_form(
        app.clone(),
        &cookie,
        &path,
        &format!("/admin/repositories/{id}/grants/add"),
        "subject_type=group&subject_id=artists&role=reader",
    )
    .await;

    let csrf = admin_csrf(app.clone(), &cookie, &path).await;
    let response = app
        .clone()
        .oneshot(post_form_request(
            &format!("/admin/repositories/{id}/delete"),
            Some(cookie.clone()),
            &format!("csrf_token={csrf}&confirm=yes"),
        ))
        .await
        .unwrap();
    assert!(
        response_text(response)
            .await
            .contains("Repository deletion is not available yet")
    );
    assert!(fixture.store.get_by_resource_id(id).await.is_ok());

    let csrf = admin_csrf(app.clone(), &cookie, &path).await;
    let response = app
        .clone()
        .oneshot(post_form_request(
            &format!("/admin/repositories/{id}/disable"),
            Some(cookie.clone()),
            &format!("csrf_token={csrf}"),
        ))
        .await
        .unwrap();
    assert!(
        response_text(response)
            .await
            .contains("maintenance mode is required")
    );
    assert!(fixture.store.get_by_resource_id(id).await.is_ok());

    post_admin_form(
        app.clone(),
        &cookie,
        "/admin/server-settings",
        "/admin/server-settings/maintenance",
        "enabled=on&wait_minutes=15",
    )
    .await;
    post_admin_form(
        app.clone(),
        &cookie,
        &path,
        &format!("/admin/repositories/{id}/disable"),
        "",
    )
    .await;
    assert!(fixture.store.get_by_resource_id(id).await.is_err());
    let policy = authz::configured_policy(
        fixture.store.as_ref(),
        &lore_auth_adapters::config::AdminConfig::default(),
    )
    .unwrap();
    assert!(matches!(
        policy.can_access(&fixture.user_id, id, "read").await,
        Ok(false) | Err(CoreError::NotFound)
    ));
    let page = app
        .clone()
        .oneshot(peer_request(&path, Some(cookie.clone()), [127, 0, 0, 1]))
        .await
        .unwrap();
    let body = response_text(page).await;
    assert!(body.contains("disabled"));
    assert!(body.contains("alice@example.com"));
    assert!(body.contains("artists"));
    assert!(body.contains("name=\"confirm\""));
    assert!(!body.contains("/grants/add"));

    let csrf = admin_csrf(app.clone(), &cookie, &path).await;
    let response = app
        .clone()
        .oneshot(post_form_request(
            &format!("/admin/repositories/{id}/grants/clear"),
            Some(cookie.clone()),
            &format!("csrf_token={csrf}"),
        ))
        .await
        .unwrap();
    assert!(
        response_text(response)
            .await
            .contains("confirm grant removal first")
    );
    assert_eq!(
        lore_auth_core::ports::RepositoryAdmin::list_grants(&fixture.store.audited("admin"), id)
            .await
            .unwrap()
            .len(),
        2
    );

    fixture
        .store
        .upsert(Resource {
            resource_id: id.into(),
            name: "game-assets".into(),
            ..Resource::default()
        })
        .await
        .unwrap();
    assert!(
        fixture.store.get_by_resource_id(id).await.is_err(),
        "ReBAC synchronization must not re-enable a disabled registration"
    );
    let csrf = admin_csrf(app.clone(), &cookie, &path).await;
    let response = app
        .clone()
        .oneshot(post_form_request(
            &format!("/admin/repositories/{id}/delete"),
            Some(cookie.clone()),
            &format!("csrf_token={csrf}"),
        ))
        .await
        .unwrap();
    assert!(
        response_text(response)
            .await
            .contains("confirm deletion first")
    );

    post_admin_form(
        app.clone(),
        &cookie,
        &path,
        &format!("/admin/repositories/{id}/enable"),
        "",
    )
    .await;
    assert!(
        policy
            .can_access(&fixture.user_id, id, "read")
            .await
            .unwrap()
    );
    assert_eq!(
        fixture
            .store
            .list_grants("game-assets")
            .await
            .unwrap()
            .len(),
        2
    );
    post_admin_form(
        app.clone(),
        &cookie,
        &path,
        &format!("/admin/repositories/{id}/disable"),
        "",
    )
    .await;
    post_admin_form(
        app.clone(),
        &cookie,
        &path,
        &format!("/admin/repositories/{id}/grants/clear"),
        "confirm=yes",
    )
    .await;
    assert!(fixture.store.get_by_resource_id(id).await.is_err());
    let page = app
        .oneshot(peer_request(&path, Some(cookie), [127, 0, 0, 1]))
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(
        response_text(page)
            .await
            .contains("Repository deletion is not available yet")
    );
    let audit = fixture.store.list_admin_audit().await.unwrap();
    let counts = audit_action_counts(&audit);
    assert_eq!(counts.get("grant.add"), Some(&3));
    assert_eq!(counts.get("grant.remove"), Some(&2));
    assert_eq!(counts.get("repository.disable"), Some(&2));
    assert_eq!(counts.get("repository.enable"), Some(&1));
    assert_eq!(counts.get("repository.grants.clear"), Some(&1));
    assert_eq!(counts.get("repository.delete"), None);
}

#[tokio::test]
async fn repository_access_rejects_non_admin_and_invalid_csrf() {
    let fixture = new_sqlite_admin_app().await;
    let path = "/admin/repositories/urc-repo-id/access";
    let unauth = fixture
        .app
        .clone()
        .oneshot(peer_request(path, None, [127, 0, 0, 1]))
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::NOT_FOUND);
    let session = fixture
        .store
        .create_browser_session(&fixture.user_id, Duration::from_secs(60))
        .await
        .unwrap();
    let user_cookie = format!("{SESSION_COOKIE_NAME}={}", session.id);
    let non_admin = fixture
        .app
        .clone()
        .oneshot(peer_request(
            path,
            Some(user_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(non_admin.status(), StatusCode::NOT_FOUND);
    let non_admin_post = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/repositories/urc-repo-id/delete",
            Some(user_cookie),
            "csrf_token=invalid&confirm=yes",
        ))
        .await
        .unwrap();
    assert_eq!(non_admin_post.status(), StatusCode::NOT_FOUND);
    for action in ["disable", "enable", "delete", "grants/add", "grants/remove"] {
        let response = fixture
            .app
            .clone()
            .oneshot(post_form_request(
                &format!("/admin/repositories/urc-repo-id/{action}"),
                Some(fixture.admin_cookie.clone()),
                "csrf_token=invalid&confirm=yes",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{action}");
    }
    assert!(
        fixture
            .store
            .get_by_resource_id("urc-repo-id")
            .await
            .is_ok()
    );
    assert!(fixture.store.list_admin_audit().await.unwrap().is_empty());
}

#[tokio::test]
async fn repository_and_direct_grant_lists_are_not_truncated() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let cookie = admin_session_cookie(&store).await;
    for i in 0..105 {
        let id = format!("repo-{i:03}");
        store.add_test_resource(Resource {
            name: format!("project-{i:03}"),
            resource_id: format!("urc-{id}"),
            lore_repository_id: id,
            ..Resource::default()
        });
        let user = store.add_test_user(User {
            email: format!("user-{i:03}@example.com"),
            display_name: format!("User {i:03}"),
            ..User::default()
        });
        store
            .add_grant("user", &user.id, "project-000", "reader")
            .await
            .unwrap();
    }
    let list = app
        .clone()
        .oneshot(peer_request(
            "/admin/repositories",
            Some(cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let body = response_text(list).await;
    assert!(body.contains("project-104"));
    let access = app
        .oneshot(peer_request(
            "/admin/repositories/urc-repo-000/access",
            Some(cookie),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let body = String::from_utf8(
        to_bytes(access.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("user-104@example.com"));
    assert_eq!(body.matches("value=\"reader\"").count(), 105 + 1);
}

#[tokio::test]
async fn admin_users_search_uses_english_and_renders_hits_and_empty_results() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    store.add_test_user(User {
        id: "user/a?b".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "<Root> & Co Artist".to_owned(),
        last_login_at: 42,
        ..User::default()
    });
    store.add_test_user(User {
        email: "bob@example.com".to_owned(),
        display_name: "Bob Builder".to_owned(),
        ..User::default()
    });

    let hit = app
        .clone()
        .oneshot(peer_request(
            "/admin/users?q=artist&lang=ja",
            Some(format!("{admin_cookie}; admin_lang=ja")),
            [127, 0, 0, 1],
        ))
        .await
        .expect("users response");
    assert_eq!(hit.status(), StatusCode::OK);
    let body = response_text(hit).await;
    assert!(body.contains("Users"), "{body}");
    assert!(body.contains("<html lang=\"en\">"), "{body}");
    assert!(body.contains("alice@example.com"), "{body}");
    assert!(body.contains("&#60;Root&#62; &#38; Co Artist"), "{body}");
    assert!(!body.contains("<Root> & Co Artist"), "{body}");
    assert!(body.contains("/admin/users/user%2Fa%3Fb/access"), "{body}");
    assert!(body.contains("1970-01-01 00:00:42"), "{body}");
    assert!(!body.contains("bob@example.com"), "{body}");

    let empty = app
        .oneshot(peer_request(
            "/admin/users?q=nobody",
            Some(format!("{admin_cookie}; admin_lang=ja")),
            [127, 0, 0, 1],
        ))
        .await
        .expect("users empty response");
    let body = response_text(empty).await;
    assert!(body.contains("No users found"), "{body}");
}

#[tokio::test]
async fn admin_boosted_navigation_returns_full_page_not_results_fragment() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });

    let mut request = peer_request("/admin/users", Some(admin_cookie), [127, 0, 0, 1]);
    request
        .headers_mut()
        .insert("hx-request", "true".parse().unwrap());
    request
        .headers_mut()
        .insert("hx-boosted", "true".parse().unwrap());
    let response = app.oneshot(request).await.expect("boosted users response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("<!doctype html>"), "{body}");
    assert!(body.contains("hx-target=\"#users-results\""), "{body}");
    assert!(body.contains("alice@example.com"), "{body}");
}

#[tokio::test]
async fn admin_groups_render_direct_members_and_nested_groups() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    let alice = store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store.add_group("riggers", "").await.expect("add riggers");
    store
        .add_group_member("artists", &alice.id)
        .await
        .expect("add group member");
    store
        .add_group_group(&artists.id, &riggers.id)
        .await
        .expect("add nested group");

    let response = app
        .clone()
        .oneshot(peer_request(
            "/admin/groups",
            Some(admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .expect("groups response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("artists"), "{body}");
    assert!(body.contains(&artists.id), "{body}");
    assert!(!body.contains("alice@example.com"), "{body}");
    assert!(body.contains("riggers"), "{body}");
    assert!(!body.contains("/admin/groups/nests/add"));
    assert!(!body.contains("/members/add"));
    let response = app
        .oneshot(peer_request(
            &format!("/admin/groups/{}/access", artists.id),
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("alice@example.com"), "{body}");
    assert!(body.contains("riggers"), "{body}");
    assert!(body.contains(&format!("/admin/groups/{}/members/add", artists.id)));
    assert!(body.contains(&format!("/admin/groups/{}/nests/remove", artists.id)));
}

#[tokio::test]
async fn admin_group_lists_and_member_search_are_complete() {
    let fixture = new_sqlite_admin_app().await;
    let group = fixture.store.add_group("team <alpha>", "").await.unwrap();
    for index in 0..105 {
        fixture
            .store
            .add_group(&format!("other-{index:03}"), "")
            .await
            .unwrap();
    }
    for index in 0..25 {
        let user = fixture
            .store
            .add_user(AddUserInput {
                email: format!("member-{index:03}@example.com"),
                display_name: format!("Member {index:03}"),
            })
            .await
            .unwrap();
        fixture
            .store
            .add_group_member(&group.name, &user.id)
            .await
            .unwrap();
    }
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            "/admin/groups",
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response_text(response).await;
    assert!(html.contains("team &#60;alpha&#62;"));
    assert!(html.contains(&group.id));
    for index in 0..105 {
        assert!(html.contains(&format!("other-{index:03}")));
    }
    assert!(html.contains(&format!("/admin/groups/{}/access", group.id)));
    assert!(!html.contains("/members/add"));

    let path = format!("/admin/groups/{}/access", group.id);
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let html = response_text(response).await;
    for index in 0..25 {
        assert!(html.contains(&format!("member-{index:03}@example.com")));
    }
    assert!(html.find("name=\"q\"").unwrap() < html.find("/members/add").unwrap());
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &format!("{path}?q=member-024"),
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let html = response_text(response).await;
    assert!(html.contains("member-024@example.com"));
    assert!(!html.contains("member-000@example.com"));
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &format!("{path}?q=does-not-exist"),
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert!(
        response_text(response)
            .await
            .contains("No matching members")
    );
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            "/admin/groups/missing/access",
            Some(fixture.admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_group_access_manages_only_selected_group_members() {
    let fixture = new_sqlite_admin_app().await;
    let selected = fixture.store.add_group("selected", "").await.unwrap();
    let other = fixture.store.add_group(&selected.id, "").await.unwrap();
    let account = fixture
        .store
        .create_service_account(model::CreateServiceAccountInput {
            client_id: "group-test".into(),
            display_name: "Runner".into(),
        })
        .await
        .unwrap()
        .account;
    let path = format!("/admin/groups/{}/access", selected.id);
    let add = format!("/admin/groups/{}/members/add", selected.id);
    let remove = format!("/admin/groups/{}/members/remove", selected.id);

    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &add,
            None,
            "csrf_token=invalid&user=alice@example.com",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &add,
            Some(fixture.admin_cookie.clone()),
            "csrf_token=invalid&user=alice@example.com",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    post_admin_form(
        fixture.app.clone(),
        &fixture.admin_cookie,
        &path,
        &add,
        "user=alice%40example.com",
    )
    .await;
    post_admin_form(
        fixture.app.clone(),
        &fixture.admin_cookie,
        &path,
        &add,
        &format!("user={}", account.user.id),
    )
    .await;
    let members = fixture
        .store
        .list_group_members(&selected.id)
        .await
        .unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.iter().any(|user| user.id == account.user.id));
    assert!(
        fixture
            .store
            .list_group_members(&other.id)
            .await
            .unwrap()
            .is_empty()
    );
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &format!("{path}?q=Runner"),
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let html = response_text(response).await;
    assert!(html.contains("Runner"));
    assert!(html.contains(&account.user.id));
    assert!(!html.contains("alice@example.com"));
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &format!("{path}?q={}", account.user.id),
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert!(response_text(response).await.contains("Runner"));
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/groups/missing/members/add",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&user={}", account.user.id),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    post_admin_form(
        fixture.app.clone(),
        &fixture.admin_cookie,
        &path,
        &remove,
        &format!("user={}", account.user.id),
    )
    .await;
    let members = fixture
        .store
        .list_group_members(&selected.id)
        .await
        .unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].id, fixture.user_id);
    assert_eq!(
        audit_action_counts(&fixture.store.list_admin_audit().await.unwrap()),
        BTreeMap::from([("group.member.add", 2), ("group.member.remove", 1)])
    );
}

#[tokio::test]
async fn admin_group_access_manages_allowed_source_ips() {
    let fixture = new_sqlite_admin_app().await;
    let selected = fixture.store.add_group("ip-team", "").await.unwrap();
    let other = fixture.store.add_group(&selected.id, "").await.unwrap();
    fixture
        .store
        .add_group_member(&selected.name, &fixture.user_id)
        .await
        .unwrap();
    let page = format!("/admin/groups/{}/access", selected.id);
    let add = format!("/admin/groups/{}/cidrs/add", selected.id);
    let remove = format!("/admin/groups/{}/cidrs/remove", selected.id);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(&add, None, "cidr=192.0.2.0%2F24"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &add,
            Some(fixture.admin_cookie.clone()),
            "csrf_token=invalid&cidr=192.0.2.0%2F24",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &page).await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &add,
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&cidr=192.0.2.0%2F99"),
        ))
        .await
        .unwrap();
    assert!(response_text(response).await.contains("CIDR is invalid"));
    assert!(
        fixture
            .store
            .list_group_allowed_cidrs(&selected.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(fixture.store.list_admin_audit().await.unwrap().is_empty());

    for cidr in ["192.0.2.25%2F24", "198.51.100.7", "2001%3Adb8%3A%3A1"] {
        post_admin_form(
            fixture.app.clone(),
            &fixture.admin_cookie,
            &page,
            &add,
            &format!("cidr={cidr}"),
        )
        .await;
    }
    let cidrs = fixture
        .store
        .list_group_allowed_cidrs(&selected.id)
        .await
        .unwrap();
    assert_eq!(
        cidrs,
        ["192.0.2.0/24", "198.51.100.7/32", "2001:db8::1/128"]
    );
    assert_eq!(
        fixture
            .store
            .list_user_allowed_cidrs(&fixture.user_id)
            .await
            .unwrap(),
        cidrs
    );
    assert!(
        fixture
            .store
            .list_group_allowed_cidrs(&other.id)
            .await
            .unwrap()
            .is_empty()
    );
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &page,
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let html = response_text(response).await;
    for cidr in &cidrs {
        assert!(html.contains(cidr));
    }
    assert!(html.contains(&remove));
    post_admin_form(
        fixture.app.clone(),
        &fixture.admin_cookie,
        &page,
        &remove,
        "cidr=192.0.2.0%2F24",
    )
    .await;
    assert_eq!(
        fixture
            .store
            .list_group_allowed_cidrs(&selected.id)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(
        !fixture
            .store
            .list_user_allowed_cidrs(&fixture.user_id)
            .await
            .unwrap()
            .contains(&"192.0.2.0/24".to_owned())
    );
    let entries = fixture.store.list_admin_audit().await.unwrap();
    assert_eq!(
        audit_action_counts(&entries),
        BTreeMap::from([
            ("group.network_cidr.add", 3),
            ("group.network_cidr.remove", 1)
        ])
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry.actor == ADMIN_EMAIL && entry.object_id == selected.id)
    );
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &page).await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/groups/missing/cidrs/add",
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&cidr=192.0.2.1"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_group_nest_add_route_is_unavailable() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let cookie = admin_session_cookie(&store).await;
    let parent = store.add_group("parent", "").await.unwrap();
    let child = store.add_group("child", "").await.unwrap();
    let csrf = admin_csrf(app.clone(), &cookie, "/admin/groups").await;
    let response = app
        .oneshot(post_form_request(
            "/admin/groups/nests/add",
            Some(cookie),
            &format!("csrf_token={csrf}&parent_group=parent&member_group=child"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        store
            .list_group_groups(&parent.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_ne!(parent.id, child.id);
    assert!(store.admin_audit_entries().is_empty());
}

#[tokio::test]
async fn admin_simulator_is_accessible_from_server_settings() {
    let fixture = new_sqlite_admin_app().await;
    let settings = fixture
        .app
        .clone()
        .oneshot(peer_request(
            "/admin/server-settings",
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(settings.status(), StatusCode::OK);
    let html = response_text(settings).await;
    let (navigation, content) = html.split_once("</nav>").unwrap();
    assert!(navigation.contains("<a href=\"/admin\"><strong>Lore Auth Admin</strong></a>"));
    assert_eq!(navigation.matches("<a ").count(), 5);
    assert!(!navigation.contains("href=\"/admin/server-settings/simulator\""));
    assert!(content.contains("href=\"/admin/server-settings/simulator\""));

    let simulator = fixture
        .app
        .clone()
        .oneshot(peer_request(
            "/admin/server-settings/simulator",
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(simulator.status(), StatusCode::OK);
    let html = response_text(simulator).await;
    assert!(html.contains("href=\"/admin/server-settings\" aria-current=\"true\""));
    assert!(html.contains("<p><a href=\"/admin/server-settings\">Server settings</a></p>"));
    assert!(html.contains("action=\"/admin/server-settings/simulator\""));

    let dashboard = fixture
        .app
        .clone()
        .oneshot(peer_request(
            "/admin",
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let html = response_text(dashboard).await;
    assert!(html.contains("href=\"/admin/server-settings\""));
    assert!(!html.contains("href=\"/admin/simulator\""));
    assert!(!html.contains("href=\"/admin/server-settings/simulator\""));

    let old_get = fixture
        .app
        .clone()
        .oneshot(peer_request(
            "/admin/simulator",
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(old_get.status(), StatusCode::NOT_FOUND);
    let old_post = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/simulator",
            Some(fixture.admin_cookie),
            "csrf_token=unused",
        ))
        .await
        .unwrap();
    assert_eq!(old_post.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_server_settings_creates_service_account_in_selected_group() {
    let fixture = new_sqlite_admin_app().await;
    let group = fixture.store.add_group("ci <team>", "").await.unwrap();
    let path = "/admin/server-settings";
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            path,
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response_text(response).await;
    assert!(html.contains("ci &#60;team&#62;"));
    assert!(html.contains("hx-boost=\"false\""));
    assert!(html.contains("allowed network CIDRs"));
    let csrf = extract_csrf(&html);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/server-settings/service-accounts",
            Some(fixture.admin_cookie.clone()),
            &format!(
                "csrf_token={csrf}&client_id=ci-runner&display_name=CI+Runner&group_id={}",
                group.id
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store, private"
    );
    let html = response_text(response).await;
    assert!(html.contains("hx-history=\"false\""));
    assert!(html.contains("cannot be shown again"));
    let secret = html
        .split_once("<code>")
        .unwrap()
        .1
        .split_once("</code>")
        .unwrap()
        .0;
    assert!(!secret.is_empty());
    let user = fixture
        .store
        .authenticate_service_account("ci-runner", secret)
        .await
        .unwrap();
    assert_eq!(user.display_name, "CI Runner");
    assert_eq!(
        fixture.store.list_group_members(&group.id).await.unwrap()[0].id,
        user.id
    );
    assert!(html.contains(&format!("/admin/users/{}/access", user.id)));
    let audit = fixture.store.list_admin_audit().await.unwrap();
    assert_eq!(
        audit_action_counts(&audit),
        BTreeMap::from([("group.member.add", 1), ("service_account.add", 1)])
    );
    assert!(
        audit
            .iter()
            .all(|entry| entry.actor == ADMIN_EMAIL && !entry.detail.contains(secret))
    );
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            path,
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let settings = response_text(response).await;
    assert!(!settings.contains(secret));
    let csrf = extract_csrf(&settings);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            "/admin/server-settings/service-accounts",
            Some(fixture.admin_cookie.clone()),
            &format!(
                "csrf_token={csrf}&client_id=unnamed&display_name=&group_id={}",
                group.id
            ),
        ))
        .await
        .unwrap();
    let html = response_text(response).await;
    let secret = html
        .split_once("<code>")
        .unwrap()
        .1
        .split_once("</code>")
        .unwrap()
        .0;
    let user = fixture
        .store
        .authenticate_service_account("unnamed", secret)
        .await
        .unwrap();
    assert_eq!(user.display_name, "unnamed");
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &format!("/admin/users/{}/access", user.id),
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert!(response_text(response).await.contains("unnamed (active)"));
}

#[tokio::test]
async fn admin_server_settings_requires_admin_csrf_and_valid_group() {
    let fixture = new_sqlite_admin_app().await;
    let path = "/admin/server-settings/service-accounts";
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(path, None, "%"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            path,
            Some(fixture.admin_cookie.clone()),
            "csrf_token=wrong&client_id=ci&group_id=missing",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            "/admin/server-settings",
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert!(
        response_text(response)
            .await
            .contains("Create a group before adding a service account.")
    );
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, "/admin/groups").await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            path,
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&client_id=ci&group_id=missing"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response).await.contains("Error"));
    assert!(
        fixture
            .store
            .authenticate_service_account("ci", "anything")
            .await
            .is_err()
    );
    assert!(fixture.store.list_admin_audit().await.unwrap().is_empty());
}

#[tokio::test]
async fn maintenance_settings_require_admin_and_csrf() {
    use lore_auth_core::ports::MaintenanceAdmin;
    let fixture = new_sqlite_admin_app().await;
    let path = "/admin/server-settings/maintenance";
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(path, None, "enabled=on&wait_minutes=20"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            path,
            Some(fixture.admin_cookie.clone()),
            "csrf_token=bad&enabled=on&wait_minutes=20",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let audited = fixture.store.audited("admin");
    assert!(!MaintenanceAdmin::get(&audited).await.unwrap().enabled);
    post_admin_form(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/server-settings",
        path,
        "enabled=on&wait_minutes=20",
    )
    .await;
    let settings = MaintenanceAdmin::get(&audited).await.unwrap();
    assert!(settings.enabled);
    assert_eq!(settings.wait_minutes, 20);
    let response = fixture
        .app
        .oneshot(peer_request(
            "/admin/server-settings",
            Some(fixture.admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response).await.contains("value=\"20\""));
}

#[tokio::test]
async fn admin_user_access_renders_rebac_accessible_permissions() {
    let fixture = new_sqlite_admin_app().await;

    let response = fixture
        .app
        .oneshot(peer_request(
            &format!("/admin/users/{}/access", fixture.user_id),
            Some(fixture.admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("user access response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("User Access"), "{body}");
    assert!(body.contains("alice@example.com"), "{body}");
    assert!(body.contains("urc-repo-id"), "{body}");
    assert!(body.contains("read"), "{body}");
    assert!(body.contains("write"), "{body}");
}

#[tokio::test]
async fn admin_user_access_bulk_repository_selection_is_complete() {
    let fixture = new_sqlite_admin_app().await;
    add_nested_only_fixture(&fixture).await;
    for index in 0..105 {
        let name = format!("repo-{index:03}");
        fixture
            .store
            .upsert(Resource {
                name: name.clone(),
                lore_repository_id: name,
                remote_url: "lore://example".into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    fixture
        .store
        .upsert(Resource {
            name: "disabled-repo".into(),
            lore_repository_id: "disabled-repo".into(),
            remote_url: "lore://example".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    fixture.store.delete("urc-disabled-repo").await.unwrap();
    fixture
        .store
        .upsert(Resource {
            name: "Special <&>".into(),
            lore_repository_id: "special".into(),
            remote_url: "lore://example".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let path = format!("/admin/users/{}/access", fixture.user_id);
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let html = response_text(response).await;
    for index in 0..105 {
        assert!(html.contains(&format!("name=\"role:urc-repo-{index:03}\"")));
    }
    assert!(!html.contains("disabled-repo"));
    assert!(html.contains("Special &#60;&#38;&#62;"));
    assert!(html.contains("name=\"role:urc-repo-id\""));
    assert!(html.contains("name=\"role:urc-nested-only\""));
    assert!(html.contains("Effective permissions"));
    for selection in [
        "snapshot=urc-repo-000%3A&role%3Aurc-repo-000=writer&snapshot=urc-repo-104%3A&role%3Aurc-repo-104=writer",
        "snapshot=urc-repo-001%3A&role%3Aurc-repo-001=reader",
        "snapshot=urc-repo-002%3A&role%3Aurc-repo-002=admin",
    ] {
        let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
        let response = fixture
            .app
            .clone()
            .oneshot(post_form_request(
                &path,
                Some(fixture.admin_cookie.clone()),
                &format!("csrf_token={csrf}&{selection}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = response_text(response).await;
        assert!(html.contains("Saved"), "{html}");
    }
    for (name, role) in [
        ("repo-000", "writer"),
        ("repo-104", "writer"),
        ("repo-001", "reader"),
        ("repo-002", "admin"),
        ("game-assets", "writer"),
    ] {
        assert_eq!(fixture.store.list_grants(name).await.unwrap()[0].role, role);
    }
    let group_grants = fixture.store.list_grants("nested-only").await.unwrap();
    assert_eq!(group_grants.len(), 1);
    assert_eq!(group_grants[0].subject_type, "group");
    let entries = fixture.store.list_admin_audit().await.unwrap();
    assert_eq!(entries.len(), 4);
    assert!(
        entries
            .iter()
            .all(|entry| entry.actor == ADMIN_EMAIL && entry.action == "grant.add")
    );

    for (fields, status) in [
        (
            "snapshot=urc-repo-003%3A&role%3Aurc-repo-003=reader&snapshot=urc-missing%3A&role%3Aurc-missing=reader",
            StatusCode::OK,
        ),
        (
            "snapshot=urc-repo-003%3A&role%3Aurc-repo-003=reader&role%3Aurc-repo-003=reader",
            StatusCode::BAD_REQUEST,
        ),
        (
            "snapshot=urc-repo-003%3A&role%3Aurc-repo-003=reader&snapshot=urc-repo-id%3A&role%3Aurc-repo-id=reader",
            StatusCode::OK,
        ),
        (
            "snapshot=urc-repo-003%3A&role%3Aurc-repo-003=invalid",
            StatusCode::BAD_REQUEST,
        ),
        ("snapshot=urc-repo-003%3A", StatusCode::BAD_REQUEST),
    ] {
        let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
        let response = fixture
            .app
            .clone()
            .oneshot(post_form_request(
                &path,
                Some(fixture.admin_cookie.clone()),
                &format!("csrf_token={csrf}&{fields}"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        if status == StatusCode::OK {
            assert!(response_text(response).await.contains("Error"));
        }
        assert!(
            fixture
                .store
                .list_grants("repo-003")
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(fixture.store.list_admin_audit().await.unwrap().len(), 4);
    assert_eq!(
        fixture.store.list_grants("game-assets").await.unwrap()[0].role,
        "writer"
    );
}

#[tokio::test]
async fn admin_user_role_editor_changes_multiple_roles_and_preserves_legacy_roles() {
    let fixture = new_sqlite_admin_app().await;
    add_nested_only_fixture(&fixture).await;
    fixture
        .store
        .add_grant("user", &fixture.user_id, "game-assets", "reader")
        .await
        .unwrap();
    fixture
        .store
        .upsert(Resource {
            name: "new-repo".into(),
            lore_repository_id: "new-repo".into(),
            remote_url: "lore://example".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let path = format!("/admin/users/{}/access", fixture.user_id);
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    let html = response_text(response).await;
    assert!(html.contains("Keep existing roles: reader, writer"));
    let csrf = extract_csrf(&html);
    let response = fixture.app.clone().oneshot(post_form_request(
        &path, Some(fixture.admin_cookie.clone()),
        &format!("csrf_token={csrf}&snapshot=urc-repo-id%3Areader%2Cwriter&role%3Aurc-repo-id=keep&snapshot=urc-nested-only%3A&role%3Aurc-nested-only=admin&snapshot=urc-new-repo%3A&role%3Aurc-new-repo=reader")
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response).await.contains("Saved"));
    assert_eq!(
        fixture
            .store
            .list_grants("game-assets")
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        fixture.store.list_grants("new-repo").await.unwrap()[0].role,
        "reader"
    );
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
    let response = fixture.app.clone().oneshot(post_form_request(
        &path, Some(fixture.admin_cookie.clone()),
        &format!("csrf_token={csrf}&snapshot=urc-repo-id%3Areader%2Cwriter&role%3Aurc-repo-id=admin&snapshot=urc-nested-only%3Aadmin&role%3Aurc-nested-only=none&snapshot=urc-new-repo%3Areader&role%3Aurc-new-repo=writer")
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response).await.contains("Saved"));
    let direct = fixture.store.list_grants("game-assets").await.unwrap();
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].role, "admin");
    let group = fixture.store.list_grants("nested-only").await.unwrap();
    assert_eq!(group.len(), 1);
    assert_eq!(group[0].subject_type, "group");
    assert_eq!(
        fixture.store.list_grants("new-repo").await.unwrap()[0].role,
        "writer"
    );
    assert_eq!(
        audit_action_counts(&fixture.store.list_admin_audit().await.unwrap()),
        BTreeMap::from([("grant.add", 4), ("grant.remove", 4)])
    );
}

#[tokio::test]
async fn admin_user_role_editor_saves_a_form_larger_than_64_kib() {
    let fixture = new_sqlite_admin_app().await;
    let mut fields = String::new();
    for index in 0..500 {
        let name = format!("repo-{index:04}-{}", "x".repeat(75));
        fixture
            .store
            .upsert(Resource {
                name: name.clone(),
                lore_repository_id: name.clone(),
                remote_url: "lore://example".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        fields.push_str(&format!("&snapshot=urc-{name}%3A&role%3Aurc-{name}=none"));
    }
    assert!(fields.len() > 64 * 1024);
    let path = format!("/admin/users/{}/access", fixture.user_id);
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    for index in 0..500 {
        assert!(html.contains(&format!(
            "name=\"role:urc-repo-{index:04}-{}\"",
            "x".repeat(75)
        )));
    }
    let csrf = extract_csrf(&html);
    fields.push_str("&snapshot=urc-repo-id%3Awriter&role%3Aurc-repo-id=reader");
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}{fields}"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fixture.store.list_grants("game-assets").await.unwrap()[0].role,
        "reader"
    );
}

#[tokio::test]
async fn admin_user_direct_grants_can_be_removed_without_changing_group_access() {
    let fixture = new_sqlite_admin_app().await;
    add_nested_only_fixture(&fixture).await;
    let bob = fixture
        .store
        .add_user(AddUserInput {
            email: "bob@example.com".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    fixture
        .store
        .add_group_member("riggers", &bob.id)
        .await
        .unwrap();
    fixture
        .store
        .add_grant("user", &fixture.user_id, "nested-only", "reader")
        .await
        .unwrap();
    fixture
        .store
        .add_grant("user", &fixture.user_id, "nested-only", "admin")
        .await
        .unwrap();
    fixture
        .store
        .upsert(Resource {
            name: "new-repo".into(),
            lore_repository_id: "new-repo".into(),
            remote_url: "lore://example".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let path = format!("/admin/users/{}/access", fixture.user_id);
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
    let response = fixture.app.clone().oneshot(post_form_request(
        &path, Some(fixture.admin_cookie.clone()),
        &format!("csrf_token={csrf}&snapshot=urc-repo-id%3Awriter&role%3Aurc-repo-id=writer&snapshot=urc-nested-only%3Aadmin%2Creader&role%3Aurc-nested-only=none&snapshot=urc-new-repo%3A&role%3Aurc-new-repo=writer")
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response_text(response).await;
    assert!(html.contains("Saved"));
    assert!(html.contains("name=\"role:urc-nested-only\""));
    assert!(html.contains("Effective permissions"));
    let grants = fixture.store.list_grants("nested-only").await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].subject_type, "group");
    for user in [&fixture.user_id, &bob.id] {
        let evidence = fixture
            .store
            .grants_for_user_on_repository(user, "urc-nested-only")
            .await
            .unwrap();
        assert!(evidence.iter().any(|entry| entry.subject_type == "group"));
    }
    assert_eq!(
        fixture.store.list_grants("game-assets").await.unwrap()[0].role,
        "writer"
    );
    assert_eq!(
        fixture.store.list_grants("new-repo").await.unwrap()[0].role,
        "writer"
    );
    let entries = fixture.store.list_admin_audit().await.unwrap();
    assert_eq!(
        audit_action_counts(&entries),
        BTreeMap::from([("grant.add", 1), ("grant.remove", 2)])
    );

    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
    let response = fixture.app.clone().oneshot(post_form_request(
        &path, Some(fixture.admin_cookie.clone()),
        &format!("csrf_token={csrf}&snapshot=urc-repo-id%3Awriter&role%3Aurc-repo-id=none&snapshot=urc-new-repo%3Awriter&role%3Aurc-new-repo=writer")
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response).await.contains("Saved"));
    assert!(
        fixture
            .store
            .list_grants("game-assets")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn admin_user_direct_grants_reject_stale_snapshot_before_any_changes() {
    let fixture = new_sqlite_admin_app().await;
    fixture
        .store
        .upsert(Resource {
            name: "new-repo".into(),
            lore_repository_id: "new-repo".into(),
            remote_url: "lore://example".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let path = format!("/admin/users/{}/access", fixture.user_id);
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
    fixture
        .store
        .add_grant("user", &fixture.user_id, "game-assets", "reader")
        .await
        .unwrap();
    let response = fixture.app.clone().oneshot(post_form_request(
        &path, Some(fixture.admin_cookie.clone()),
        &format!("csrf_token={csrf}&snapshot=urc-repo-id%3Awriter&role%3Aurc-repo-id=writer&snapshot=urc-new-repo%3A&role%3Aurc-new-repo=reader")
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response_text(response)
            .await
            .contains("direct grants changed")
    );
    assert_eq!(
        fixture
            .store
            .list_grants("game-assets")
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(
        fixture
            .store
            .list_grants("new-repo")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(fixture.store.list_admin_audit().await.unwrap().is_empty());
}

#[tokio::test]
async fn admin_user_direct_grant_page_distinguishes_global_admin_access() {
    let fixture = new_sqlite_admin_app_with_global_admin(true).await;
    let session_id = fixture.admin_cookie.split_once('=').unwrap().1;
    let admin = fixture
        .store
        .user_by_browser_session(session_id)
        .await
        .unwrap();
    let path = format!("/admin/users/{}/access", admin.id);
    let response = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response_text(response).await;
    assert!(html.contains("name=\"role:urc-repo-id\""));
    assert!(html.contains("value=\"none\" selected"));
    assert!(html.contains("Effective permissions: read, write, admin"));
}

#[tokio::test]
async fn admin_user_repository_post_requires_admin_and_csrf() {
    let fixture = new_sqlite_admin_app().await;
    let path = format!("/admin/users/{}/access", fixture.user_id);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(&path, None, "%"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            "csrf_token=wrong&role=reader&repository=urc-repo-id",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            "role=reader&repository=urc-repo-id",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&csrf_token={csrf}&role=reader&repository=urc-repo-id"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.store.list_admin_audit().await.unwrap().is_empty());
}

#[tokio::test]
async fn admin_user_access_returns_404_for_missing_user() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;

    let response = app
        .oneshot(peer_request(
            "/admin/users/missing/access",
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("missing user access response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_users_returns_500_when_list_users_fails() {
    let store = Arc::new(memory::Store::new());
    let admin_cookie = admin_session_cookie(&store).await;
    let permissions = Arc::new(PermissionService::new(store.clone(), store.clone()));
    let app = admin_app_with_custom_ports(
        store.clone(),
        Arc::new(FailingAccounts {
            inner: store,
            fail_list_users: true,
        }),
        permissions,
    );

    let response = app
        .oneshot(peer_request(
            "/admin/users",
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("users response");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn admin_user_access_returns_500_when_list_accessible_fails() {
    let store = Arc::new(memory::Store::new());
    let admin_cookie = admin_session_cookie(&store).await;
    let user = store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });
    let permissions = Arc::new(PermissionService::new(
        store.clone(),
        Arc::new(FailingAuthz),
    ));
    let app = admin_app_with_custom_ports(store.clone(), store.clone(), permissions);

    let response = app
        .oneshot(peer_request(
            &format!("/admin/users/{}/access", user.id),
            Some(admin_cookie),
            [127, 0, 0, 1],
        ))
        .await
        .expect("user access response");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn admin_post_routes_hide_unauthenticated_requests_and_require_csrf() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;

    let unauthenticated = app
        .clone()
        .oneshot(post_form_request(
            "/admin/groups",
            None,
            "name=artists&description=Art",
        ))
        .await
        .expect("unauthenticated group add response");
    assert_eq!(unauthenticated.status(), StatusCode::NOT_FOUND);

    let unauthenticated_empty = app
        .clone()
        .oneshot(post_form_request("/admin/groups", None, ""))
        .await
        .expect("unauthenticated empty group add response");
    assert_eq!(unauthenticated_empty.status(), StatusCode::NOT_FOUND);

    let missing = app
        .clone()
        .oneshot(post_form_request(
            "/admin/groups",
            Some(admin_cookie.clone()),
            "name=artists&description=Art",
        ))
        .await
        .expect("missing csrf response");
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);

    let invalid = app
        .clone()
        .oneshot(post_form_request(
            "/admin/groups",
            Some(admin_cookie.clone()),
            "csrf_token=wrong&name=artists&description=Art",
        ))
        .await
        .expect("invalid csrf response");
    assert_eq!(invalid.status(), StatusCode::FORBIDDEN);

    let user_add_missing = app
        .clone()
        .oneshot(post_form_request(
            "/admin/users",
            Some(admin_cookie.clone()),
            "email=alice@example.com&display_name=Alice",
        ))
        .await
        .expect("user add missing csrf response");
    assert_eq!(user_add_missing.status(), StatusCode::FORBIDDEN);

    let repo_add_invalid = app
        .clone()
        .oneshot(post_form_request(
            "/admin/repositories",
            Some(admin_cookie.clone()),
            "csrf_token=wrong&name=game-assets",
        ))
        .await
        .expect("repo add invalid csrf response");
    assert_eq!(repo_add_invalid.status(), StatusCode::FORBIDDEN);

    let simulator_missing = app
        .clone()
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            Some(admin_cookie.clone()),
            "user=alice@example.com&resource=game-assets&action=read",
        ))
        .await
        .expect("simulator missing csrf response");
    assert_eq!(simulator_missing.status(), StatusCode::FORBIDDEN);

    let simulator_unauthenticated = app
        .clone()
        .oneshot(post_form_request(
            "/admin/server-settings/simulator",
            None,
            "%not-form-urlencoded",
        ))
        .await
        .expect("simulator unauthenticated response");
    assert_eq!(simulator_unauthenticated.status(), StatusCode::NOT_FOUND);

    let csrf = admin_csrf(app.clone(), &admin_cookie, "/admin/groups").await;
    let valid = app
        .oneshot(post_form_request(
            "/admin/groups",
            Some(admin_cookie),
            &format!("csrf_token={csrf}&name=artists&description=Art"),
        ))
        .await
        .expect("valid csrf response");
    assert_eq!(valid.status(), StatusCode::OK);
    let entries = store.admin_audit_entries();
    let actions = audit_action_counts(&entries);
    assert_eq!(actions.get("group.add"), Some(&1));
}

#[tokio::test]
async fn admin_post_guard_hides_malformed_and_large_unauthenticated_bodies() {
    let (app, _store, _) = new_test_app_with_admin(fake_idp(), admin_config());

    let malformed = app
        .clone()
        .oneshot(post_form_request("/admin/groups", None, "%"))
        .await
        .expect("malformed unauthenticated response");
    assert_eq!(malformed.status(), StatusCode::NOT_FOUND);

    let large = format!("csrf_token={}", "x".repeat(3 * 1024 * 1024));
    let response = app
        .oneshot(post_form_request("/admin/groups", None, &large))
        .await
        .expect("large unauthenticated response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_user_disable_refuses_self_and_preserves_last_admin() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin = store.add_test_user(User {
        id: "admin-user".to_owned(),
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&admin.id, Duration::from_secs(60))
        .await
        .expect("session creates");
    let admin_cookie = format!("{SESSION_COOKIE_NAME}={}", session.id);
    let csrf = admin_csrf(app.clone(), &admin_cookie, "/admin/users").await;

    let response = app
        .oneshot(post_form_request(
            &format!("/admin/users/{}/disable", admin.id),
            Some(admin_cookie),
            &format!("csrf_token={csrf}"),
        ))
        .await
        .expect("self disable response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("Error"), "{body}");
    let admin_after = store.user_by_id(&admin.id).await.expect("admin remains");
    assert_eq!(admin_after.status, "active");
    assert!(store.admin_audit_entries().is_empty());
}

#[tokio::test]
async fn admin_user_add_entra_creates_user_and_binds_object_id() {
    let tenant = "11111111-2222-4333-8444-555555555555";
    let object_id = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE";
    let issuer = format!("https://login.microsoftonline.com/{tenant}/v2.0");
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        admin_config_with(|admin| {
            admin.entra_providers = vec![AdminEntraProvider {
                id: "entra".to_owned(),
                display_name: "Entra ID".to_owned(),
                issuer: issuer.clone(),
                tenant_id: tenant.to_owned(),
            }];
        }),
    );
    let admin_cookie = admin_session_cookie(&store).await;

    let page = app
        .clone()
        .oneshot(peer_request(
            "/admin/users",
            Some(admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .expect("users page");
    let page = response_text(page).await;
    assert!(page.contains("action=\"/admin/users/entra\""), "{page}");
    assert!(!page.contains("/admin/users/invite"), "{page}");

    let response = app
        .clone()
        .oneshot(post_form_request(
            "/admin/users/invite",
            Some(admin_cookie.clone()),
            "email=invited%40example.com",
        ))
        .await
        .expect("removed invite route response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let csrf = admin_csrf(app.clone(), &admin_cookie, "/admin/users").await;
    let response = app
        .clone()
        .oneshot(post_form_request(
            "/admin/users/entra",
            Some(admin_cookie.clone()),
            &format!(
                "csrf_token={csrf}&provider_id=entra&email=alice%40example.com&display_name=Alice&object_id={object_id}"
            ),
        ))
        .await
        .expect("entra add response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("alice@example.com"), "{body}");

    let (principal, binding) = store
        .resolve_login(model::LoginResolutionRequest {
            identity: ExternalIdentity {
                provider_id: "entra".to_owned(),
                issuer: issuer.clone(),
                subject: format!("{tenant}:{}", object_id.to_ascii_lowercase()),
                ..ExternalIdentity::default()
            },
            policy: model::LoginTrustPolicy::default(),
        })
        .await
        .expect("bound identity resolves");
    assert_eq!(binding.status, "existing");
    let user = store.user_by_id(&principal.user_id).await.expect("user");
    assert_eq!(user.display_name, "Alice");
    assert_eq!(user.status, "active");
    let entries = store.admin_audit_entries();
    let actions = audit_action_counts(&entries);
    assert_eq!(actions.get("user.add"), Some(&1));
    assert_eq!(actions.get("user.bind_identity"), Some(&1));

    let csrf = admin_csrf(app.clone(), &admin_cookie, "/admin/users").await;
    let response = app
        .oneshot(post_form_request(
            "/admin/users/entra",
            Some(admin_cookie),
            &format!(
                "csrf_token={csrf}&provider_id=entra&email=bad%40example.com&object_id=not-a-guid"
            ),
        ))
        .await
        .expect("invalid entra add response");
    let body = response_text(response).await;
    assert!(
        body.contains("object_id must be an Entra ID Object ID"),
        "{body}"
    );
    assert!(!body.contains("bad@example.com"), "{body}");
}

#[tokio::test]
async fn admin_user_access_edits_display_name_and_shows_bound_entra_identity() {
    let fixture = new_sqlite_admin_app().await;
    let tenant = "11111111-2222-4333-8444-555555555555";
    let object = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let (user, _) = fixture
        .store
        .audited("test")
        .add_user_with_identity(model::AddUserWithIdentityInput {
            email: "new@example.com".to_owned(),
            display_name: "Old name".to_owned(),
            provider_id: "entra".to_owned(),
            issuer: "https://example.com".to_owned(),
            subject: format!("{tenant}:{object}"),
            subject_strategy: "entra_oid_tid".to_owned(),
        })
        .await
        .expect("add bound user");
    fixture
        .store
        .audited("test")
        .bind_external_identity(ExternalIdentity {
            email: user.email.clone(),
            provider_id: "entra-secondary".to_owned(),
            issuer: "https://secondary.example.com".to_owned(),
            subject: "another-tenant:another-object".to_owned(),
            subject_strategy: "entra_oid_tid".to_owned(),
            ..ExternalIdentity::default()
        })
        .await
        .expect("add second identity");
    let path = format!("/admin/users/{}/access", user.id);
    let post_path = format!("/admin/users/{}/display-name", user.id);
    let page = fixture
        .app
        .clone()
        .oneshot(peer_request(
            &path,
            Some(fixture.admin_cookie.clone()),
            [127, 0, 0, 1],
        ))
        .await
        .expect("page");
    let page = response_text(page).await;
    assert!(
        page.contains(tenant) && page.contains(object) && page.contains("Old name"),
        "{page}"
    );
    assert!(
        page.contains("another-tenant") && page.contains("another-object"),
        "{page}"
    );

    let unauthorized = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &post_path,
            None,
            "display_name=Unauthorized",
        ))
        .await
        .expect("unauthorized");
    assert_eq!(unauthorized.status(), StatusCode::NOT_FOUND);
    let no_csrf = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &post_path,
            Some(fixture.admin_cookie.clone()),
            "display_name=Invalid",
        ))
        .await
        .expect("csrf");
    assert!(!no_csrf.status().is_success());
    assert_eq!(
        fixture
            .store
            .user_by_id(&user.id)
            .await
            .unwrap()
            .display_name,
        "Old name"
    );

    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &post_path,
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&display_name=New+name"),
        ))
        .await
        .expect("update");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_text(response).await.contains("New name"));
    assert_eq!(
        fixture
            .store
            .user_by_id(&user.id)
            .await
            .unwrap()
            .display_name,
        "New name"
    );
    let entries = fixture.store.list_admin_audit().await.unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.action == "user.update_display_name"
                && entry.object_id == user.id
                && entry.actor.contains(ADMIN_EMAIL))
    );

    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &path).await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &post_path,
            Some(fixture.admin_cookie.clone()),
            &format!("csrf_token={csrf}&display_name=+++"),
        ))
        .await
        .expect("empty name");
    assert!(
        response_text(response)
            .await
            .contains("display name is required")
    );
    assert_eq!(
        fixture
            .store
            .user_by_id(&user.id)
            .await
            .unwrap()
            .display_name,
        "New name"
    );

    let (principal, binding) = fixture
        .store
        .resolve_login(model::LoginResolutionRequest {
            identity: ExternalIdentity {
                provider_id: "entra".to_owned(),
                issuer: "https://example.com".to_owned(),
                subject: format!("{tenant}:{object}"),
                ..ExternalIdentity::default()
            },
            policy: model::LoginTrustPolicy::default(),
        })
        .await
        .expect("login still resolves");
    assert_eq!(principal.user_id, user.id);
    assert_eq!(binding.status, "existing");
}

#[tokio::test]
async fn admin_updates_entra_identity_with_validation_and_audit() {
    let tenant = "11111111-2222-4333-8444-555555555555";
    let old = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let new = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let duplicate = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    let issuer = "https://example.com";
    let fixture = new_sqlite_admin_app_with_config(
        false,
        vec![AdminEntraProvider {
            id: "entra".to_owned(),
            display_name: "Entra".to_owned(),
            issuer: issuer.to_owned(),
            tenant_id: tenant.to_owned(),
        }],
    )
    .await;
    let create = |email: &str, object: &str| model::AddUserWithIdentityInput {
        email: email.to_owned(),
        display_name: email.to_owned(),
        provider_id: "entra".to_owned(),
        issuer: issuer.to_owned(),
        subject: format!("{tenant}:{object}"),
        subject_strategy: "entra_oid_tid".to_owned(),
    };
    let (user, identity) = fixture
        .store
        .audited("test")
        .add_user_with_identity(create("one@example.com", old))
        .await
        .unwrap();
    fixture
        .store
        .audited("test")
        .add_user_with_identity(create("two@example.com", duplicate))
        .await
        .unwrap();
    let page_path = format!("/admin/users/{}/access", user.id);
    let post_path = format!("/admin/users/{}/identities/{}", user.id, identity.id);
    let form = |csrf: &str, expected: &str, tid: &str, oid: &str| {
        format!("csrf_token={csrf}&expected_subject={expected}&tenant_id={tid}&object_id={oid}")
    };
    let old_subject = format!("{tenant}:{old}");
    let no_csrf = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &post_path,
            Some(fixture.admin_cookie.clone()),
            &form("", &old_subject, tenant, new),
        ))
        .await
        .unwrap();
    assert!(!no_csrf.status().is_success());
    let wrong_user_path = format!(
        "/admin/users/{}/identities/{}",
        fixture.user_id, identity.id
    );
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &page_path).await;
    let wrong_user = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &wrong_user_path,
            Some(fixture.admin_cookie.clone()),
            &form(&csrf, &old_subject, tenant, new),
        ))
        .await
        .unwrap();
    assert_eq!(wrong_user.status(), StatusCode::NOT_FOUND);
    for (tid, oid, message) in [
        ("bad", new, "tenant_id must be"),
        (
            "dddddddd-dddd-dddd-dddd-dddddddddddd",
            new,
            "tenant_id must match",
        ),
        (tenant, "invalid", "object_id must be"),
        (tenant, duplicate, "external identity is already bound"),
    ] {
        let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &page_path).await;
        let response = fixture
            .app
            .clone()
            .oneshot(post_form_request(
                &post_path,
                Some(fixture.admin_cookie.clone()),
                &form(&csrf, &old_subject, tid, oid),
            ))
            .await
            .unwrap();
        let text = response_text(response).await;
        assert!(text.contains(message), "{text}");
        assert_eq!(
            fixture
                .store
                .external_identities_for_user(&user.id)
                .await
                .unwrap()[0]
                .subject,
            old_subject
        );
    }
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &page_path).await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &post_path,
            Some(fixture.admin_cookie.clone()),
            &form(&csrf, &old_subject, tenant, &new.to_ascii_uppercase()),
        ))
        .await
        .unwrap();
    let text = response_text(response).await;
    assert!(text.contains(new), "{text}");
    let entries = fixture.store.list_admin_audit().await.unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.action == "user.update_identity"
                && entry.object_id == user.id
                && entry.detail.contains(&old_subject)
                && entry.detail.contains(new))
    );
    let login = |oid: &str| model::LoginResolutionRequest {
        identity: ExternalIdentity {
            provider_id: "entra".to_owned(),
            issuer: issuer.to_owned(),
            subject: format!("{tenant}:{oid}"),
            ..ExternalIdentity::default()
        },
        policy: model::LoginTrustPolicy::default(),
    };
    assert!(matches!(
        fixture.store.resolve_login(login(old)).await,
        Err(CoreError::NotFound)
    ));
    assert_eq!(
        fixture
            .store
            .resolve_login(login(new))
            .await
            .unwrap()
            .0
            .user_id,
        user.id
    );
    let csrf = admin_csrf(fixture.app.clone(), &fixture.admin_cookie, &page_path).await;
    let response = fixture
        .app
        .clone()
        .oneshot(post_form_request(
            &post_path,
            Some(fixture.admin_cookie.clone()),
            &form(&csrf, &old_subject, tenant, old),
        ))
        .await
        .unwrap();
    assert!(response_text(response).await.contains("identity changed"));
    assert_eq!(
        fixture
            .store
            .resolve_login(login(new))
            .await
            .unwrap()
            .0
            .user_id,
        user.id
    );
}

#[tokio::test]
async fn admin_user_disable_allows_admin_when_another_active_admin_remains() {
    let (app, store, _) = new_test_app_with_admin(
        fake_idp(),
        AdminConfig {
            admin_emails: vec![
                "admin@example.com".to_owned(),
                "other-admin@example.com".to_owned(),
            ],
            ..AdminConfig::default()
        },
    );
    let admin = store.add_test_user(User {
        id: "admin-user".to_owned(),
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let other = store.add_test_user(User {
        id: "other-admin-user".to_owned(),
        email: "other-admin@example.com".to_owned(),
        display_name: "Other Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&admin.id, Duration::from_secs(60))
        .await
        .expect("session creates");
    let admin_cookie = format!("{SESSION_COOKIE_NAME}={}", session.id);

    post_admin_form(
        app,
        &admin_cookie,
        "/admin/users",
        &format!("/admin/users/{}/disable", other.id),
        "",
    )
    .await;

    let other_after = store
        .user_by_id(&other.id)
        .await
        .expect("other admin remains");
    assert_eq!(other_after.status, "disabled");
    let entries = store.admin_audit_entries();
    assert_eq!(audit_action_counts(&entries).get("user.disable"), Some(&1));
}

#[tokio::test]
async fn admin_repository_creation_validates_fields_and_synchronizes_real_ids() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let cookie = admin_session_cookie(&store).await;
    for (fields, expected) in [
        ("name=project&organization=studio", "studio/project"),
        ("name=standalone&organization=", "standalone"),
    ] {
        let csrf = admin_csrf(app.clone(), &cookie, "/admin/repositories").await;
        let response = app
            .clone()
            .oneshot(post_form_request(
                "/admin/repositories",
                Some(cookie.clone()),
                &format!("csrf_token={csrf}&{fields}"),
            ))
            .await
            .unwrap();
        let body = response_text(response).await;
        assert!(body.contains("Saved"));
        let resource = store.get_by_name(expected).await.unwrap();
        assert_eq!(resource.lore_repository_id.len(), 32);
        assert_eq!(
            resource.resource_id,
            format!("urc-{}", resource.lore_repository_id)
        );
    }
    let before = store.admin_audit_entries().len();
    for fields in [
        "name=",
        "name=+++",
        "name=bad%2Fname",
        "name=valid&organization=bad%2Forganization",
        "name=.hidden",
        "name=valid&organization=.hidden",
    ] {
        let csrf = admin_csrf(app.clone(), &cookie, "/admin/repositories").await;
        let response = app
            .clone()
            .oneshot(post_form_request(
                "/admin/repositories",
                Some(cookie.clone()),
                &format!("csrf_token={csrf}&{fields}"),
            ))
            .await
            .unwrap();
        let body = response_text(response).await;
        assert!(body.contains("Name is required"));
    }
    assert_eq!(store.admin_audit_entries().len(), before);
}

#[tokio::test]
async fn admin_repository_creation_reports_partial_results_without_false_success() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let cookie = admin_session_cookie(&store).await;
    for (name, expected) in [
        ("rpc-rejected", "Lore rejected the request"),
        ("rpc-uncertain", "Creation may have partially completed"),
        (
            "rpc-unsynchronized",
            "authorization record could not be verified",
        ),
    ] {
        let csrf = admin_csrf(app.clone(), &cookie, "/admin/repositories").await;
        let response = app
            .clone()
            .oneshot(post_form_request(
                "/admin/repositories",
                Some(cookie.clone()),
                &format!("csrf_token={csrf}&name={name}"),
            ))
            .await
            .unwrap();
        let body = response_text(response).await;
        assert!(body.contains(expected), "{body}");
        assert!(!body.contains(">Saved<"));
        if name != "rpc-rejected" {
            assert!(body.contains("Repository ID:"));
        }
        assert!(store.get_by_name(name).await.is_err());
    }
    assert!(store.admin_audit_entries().is_empty());
}

#[tokio::test]
async fn admin_repository_creation_audits_the_synchronized_sqlite_record() {
    let fixture = new_sqlite_admin_app().await;
    post_admin_form(
        fixture.app.clone(),
        &fixture.admin_cookie,
        "/admin/repositories",
        "/admin/repositories",
        "organization=studio&name=project",
    )
    .await;
    let resource = fixture.store.get_by_name("studio/project").await.unwrap();
    assert_eq!(resource.lore_repository_id.len(), 32);
    assert_eq!(resource.remote_url, "");
    let audit = fixture.store.list_admin_audit().await.unwrap();
    assert_eq!(audit_action_counts(&audit).get("repository.add"), Some(&1));
    assert_eq!(audit[0].actor, ADMIN_EMAIL);
}

#[tokio::test]
async fn admin_repository_creation_reports_audit_failure_after_lore_creation() {
    let (app, store, _) = new_test_app_with_admin_audit(
        fake_idp(),
        admin_config(),
        Some(Arc::new(FailingAdminAudit)),
    );
    let cookie = admin_session_cookie(&store).await;
    let csrf = admin_csrf(app.clone(), &cookie, "/admin/repositories").await;
    let response = app
        .oneshot(post_form_request(
            "/admin/repositories",
            Some(cookie),
            &format!("csrf_token={csrf}&name=project"),
        ))
        .await
        .unwrap();
    let body = response_text(response).await;
    assert!(
        body.contains("Lore created the repository, but the admin audit could not be recorded")
    );
    assert!(body.contains("Repository ID:"));
    assert!(store.get_by_name("project").await.is_ok());
    assert!(store.admin_audit_entries().is_empty());
}

#[tokio::test]
async fn admin_post_writes_record_admin_audit_with_admin_actor() {
    let (app, store, _) = new_test_app_with_admin(fake_idp(), admin_config());
    let admin_cookie = admin_session_cookie(&store).await;
    let alice = store.add_test_user(User {
        id: "user-alice".to_owned(),
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    });

    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/repositories",
        "/admin/repositories",
        "name=game-assets",
    )
    .await;
    let resource_id = store.get_by_name("game-assets").await.unwrap().resource_id;
    let repo_access = format!("/admin/repositories/{resource_id}/access");
    post_admin_form(
        app.clone(),
        &admin_cookie,
        &repo_access,
        &format!("/admin/repositories/{resource_id}/grants/add"),
        &format!("subject_type=user&subject_id={}&role=writer", alice.id),
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        &repo_access,
        &format!("/admin/repositories/{resource_id}/grants/remove"),
        &format!("subject_type=user&subject_id={}&role=writer", alice.id),
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/users",
        "/admin/users",
        "email=bob@example.com&display_name=Bob",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/groups",
        "/admin/groups",
        "name=artists&description=Art",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/groups",
        "/admin/groups",
        "name=riggers&description=Rig",
    )
    .await;
    let artists_id = store
        .list_groups()
        .await
        .unwrap()
        .into_iter()
        .find(|group| group.name == "artists")
        .unwrap()
        .id;
    let access_path = format!("/admin/groups/{artists_id}/access");
    post_admin_form(
        app.clone(),
        &admin_cookie,
        &access_path,
        &format!("/admin/groups/{artists_id}/members/add"),
        &format!("user={}", alice.id),
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        &access_path,
        &format!("/admin/groups/{artists_id}/members/remove"),
        &format!("user={}", alice.id),
    )
    .await;
    store.add_group_group("artists", "riggers").await.unwrap();
    post_admin_form(
        app.clone(),
        &admin_cookie,
        &access_path,
        &format!("/admin/groups/{artists_id}/nests/remove"),
        "member_group=riggers",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/users",
        &format!("/admin/users/{}/disable", alice.id),
        "",
    )
    .await;
    post_admin_form(
        app.clone(),
        &admin_cookie,
        "/admin/server-settings",
        "/admin/server-settings/maintenance",
        "enabled=on&wait_minutes=15",
    )
    .await;
    post_admin_form(
        app,
        &admin_cookie,
        &repo_access,
        &format!("/admin/repositories/{resource_id}/disable"),
        "",
    )
    .await;

    let entries = store.admin_audit_entries();
    assert!(
        entries
            .iter()
            .all(|entry| entry.actor == "admin@example.com"),
        "{entries:?}"
    );
    assert_eq!(
        audit_action_counts(&entries),
        BTreeMap::from([
            ("grant.add", 1),
            ("grant.remove", 1),
            ("group.add", 2),
            ("group.member.add", 1),
            ("group.member.remove", 1),
            ("group.nest.remove", 1),
            ("maintenance.update", 1),
            ("repository.add", 1),
            ("repository.disable", 1),
            ("user.add", 1),
            ("user.disable", 1),
        ])
    );
}

#[test]
fn admin_static_asset_hashes_match_notice() {
    assert_eq!(
        sha256_hex(include_bytes!("../src/admin/static/htmx.min.js")),
        "e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447"
    );
    assert_eq!(
        sha256_hex(include_bytes!("../src/admin/static/pico.min.css")),
        "dd5fd5591afd81ee21dcc117ad85c014dc3f1f19dc2d7b7d101ea0acc29274c2"
    );
    let notice = include_str!("../src/admin/static/NOTICE.md");
    assert!(notice.contains("e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447"));
    assert!(notice.contains("dd5fd5591afd81ee21dcc117ad85c014dc3f1f19dc2d7b7d101ea0acc29274c2"));
}

#[tokio::test]
async fn admin_i18n_dictionaries_and_template_keys_match() {
    lore_auth_inbound::admin::assert_i18n_integrity();
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

const ADMIN_EMAIL: &str = "admin@example.com";

fn admin_config() -> AdminConfig {
    admin_config_with(|_| {})
}

fn admin_config_with(configure: impl FnOnce(&mut AdminConfig)) -> AdminConfig {
    let mut admin = AdminConfig {
        admin_emails: vec![ADMIN_EMAIL.to_owned()],
        ..AdminConfig::default()
    };
    configure(&mut admin);
    admin
}

async fn admin_session_cookie(store: &memory::Store) -> String {
    let admin = store.add_test_user(User {
        email: ADMIN_EMAIL.to_owned(),
        display_name: "Admin".to_owned(),
        ..User::default()
    });
    let session = store
        .create_browser_session(&admin.id, Duration::from_secs(60))
        .await
        .expect("admin session creates");
    format!("{SESSION_COOKIE_NAME}={}", session.id)
}

struct SqliteAdminApp {
    app: Router,
    store: Arc<sqlite::Store>,
    admin_cookie: String,
    user_id: String,
    _dir: TestDir,
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lore-auth-inbound-{}",
            uuid::Uuid::new_v4().as_simple()
        ));
        fs::create_dir_all(&path).expect("create test dir");
        Self { path }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

async fn new_sqlite_admin_app() -> SqliteAdminApp {
    new_sqlite_admin_app_with_global_admin(false).await
}

async fn new_sqlite_admin_app_with_global_admin(global_repository_admin: bool) -> SqliteAdminApp {
    new_sqlite_admin_app_with_config(global_repository_admin, Vec::new()).await
}

async fn new_sqlite_admin_app_with_config(
    global_repository_admin: bool,
    entra_providers: Vec<AdminEntraProvider>,
) -> SqliteAdminApp {
    let dir = TestDir::new();
    let path = dir.path.join("auth.sqlite3");
    let store = Arc::new(sqlite::Store::open(&path).await.expect("open sqlite"));
    store.migrate().await.expect("migrate sqlite");
    let admin = store
        .add_user(AddUserInput {
            email: ADMIN_EMAIL.to_owned(),
            display_name: "Admin".to_owned(),
        })
        .await
        .expect("add admin");
    let admin_session = store
        .create_browser_session(&admin.id, Duration::from_secs(60))
        .await
        .expect("create admin session");
    let alice = store
        .add_user(AddUserInput {
            email: "alice@example.com".to_owned(),
            display_name: "Alice".to_owned(),
        })
        .await
        .expect("add alice");
    store
        .upsert(Resource {
            name: "game-assets".to_owned(),
            remote_url: "lore://example".to_owned(),
            lore_repository_id: "repo-id".to_owned(),
            resource_id: ResourceID::for_repository_id("repo-id").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert resource");
    store
        .add_grant("user", &alice.id, "game-assets", "writer")
        .await
        .expect("add grant");

    let resource_store: Arc<dyn ResourceStore> = store.clone();
    let authz_policy = authz::configured_policy(
        store.as_ref(),
        &lore_auth_adapters::config::AdminConfig {
            admin_emails: vec![ADMIN_EMAIL.to_owned()],
            global_repository_admin,
        },
    )
    .expect("configured authz");
    let signer_store = Arc::new(memory::Store::new());
    let tokens = Arc::new(TokenService::new(
        TokenConfig {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned(), "lore.example.com".to_owned()],
            auth_service_audience: "auth.example.com".to_owned(),
            authn_ttl: Duration::from_secs(60 * 60),
            authz_ttl: Duration::from_secs(15 * 60),
        },
        store.clone(),
        resource_store.clone(),
        authz_policy.clone(),
        signer_store.clone(),
        Some(signer_store.clone()),
    ));
    let resources: Arc<dyn ResourceQuery> = store.clone();
    let permissions = Arc::new(PermissionService::new(resource_store, authz_policy));

    let app = build_router(
        HttpConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            lore_auth_url: "ucs-auth://auth.example.com".to_owned(),
            default_remote_url: "lore://lore.example.com:41337".to_owned(),
            session_ttl: Duration::from_secs(60 * 60),
            admin: admin_config_with(|admin| {
                admin.global_repository_admin = global_repository_admin;
                admin.entra_providers = entra_providers;
            }),
        },
        Services {
            login: None,
            tokens,
            resources,
            permissions,
            accounts: store.clone(),
            admin_writes: Arc::new(sqlite::AuditedStoreFactory::new((*store).clone())),
            admin_audit: store.clone(),
            groups: store.clone(),
            grants: store.clone(),
            state: store.clone(),
            jwks: signer_store,
            device: None,
            repository_creator: Arc::new(TestRepositoryCreator {
                resources: store.clone(),
            }),
        },
    );

    SqliteAdminApp {
        app,
        store,
        admin_cookie: format!("{SESSION_COOKIE_NAME}={}", admin_session.id),
        user_id: alice.id,
        _dir: dir,
    }
}

async fn add_nested_only_fixture(fixture: &SqliteAdminApp) {
    let store = fixture.store.clone();
    let artists = store
        .add_group("artists", "Art team")
        .await
        .expect("add artists");
    let riggers = store.add_group("riggers", "").await.expect("add riggers");
    store
        .add_group_member("riggers", &fixture.user_id)
        .await
        .expect("add user to riggers");
    store
        .add_group_group(&artists.id, &riggers.id)
        .await
        .expect("nest riggers under artists");
    store
        .upsert(Resource {
            name: "nested-only".to_owned(),
            remote_url: "lore://nested".to_owned(),
            lore_repository_id: "nested-only".to_owned(),
            resource_id: ResourceID::for_repository_id("nested-only").expect("resource id"),
            ..Resource::default()
        })
        .await
        .expect("upsert nested repo");
    store
        .add_grant("group", &artists.id, "nested-only", "reader")
        .await
        .expect("add nested-only group grant");
}

fn admin_app_with_custom_ports(
    store: Arc<memory::Store>,
    accounts: Arc<dyn AccountQuery>,
    permissions: Arc<PermissionService>,
) -> Router {
    let tokens = Arc::new(TokenService::new(
        TokenConfig {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned(), "lore.example.com".to_owned()],
            auth_service_audience: "auth.example.com".to_owned(),
            authn_ttl: Duration::from_secs(60 * 60),
            authz_ttl: Duration::from_secs(15 * 60),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        Some(store.clone()),
    ));
    let resources: Arc<dyn ResourceQuery> = store.clone();
    build_router(
        HttpConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            lore_auth_url: "ucs-auth://auth.example.com".to_owned(),
            default_remote_url: "lore://lore.example.com:41337".to_owned(),
            session_ttl: Duration::from_secs(60 * 60),
            admin: admin_config(),
        },
        Services {
            login: None,
            tokens,
            resources,
            permissions,
            accounts,
            admin_writes: Arc::new(memory::AuditedStoreFactory::new((*store).clone())),
            admin_audit: store.clone(),
            groups: store.clone(),
            grants: store.clone(),
            state: store.clone(),
            jwks: store.clone(),
            device: None,
            repository_creator: Arc::new(TestRepositoryCreator {
                resources: store.clone(),
            }),
        },
    )
}

#[derive(Clone)]
struct FailingAccounts {
    inner: Arc<memory::Store>,
    fail_list_users: bool,
}

#[async_trait]
impl AccountDirectory for FailingAccounts {
    async fn update_entra_identity(
        &self,
        input: model::UpdateEntraIdentityInput,
    ) -> Result<(), CoreError> {
        self.inner.update_entra_identity(input).await
    }

    async fn update_user_display_name(
        &self,
        user_id: &str,
        display_name: &str,
    ) -> Result<(), CoreError> {
        self.inner
            .update_user_display_name(user_id, display_name)
            .await
    }

    async fn resolve_login(
        &self,
        req: model::LoginResolutionRequest,
    ) -> Result<(model::TokenPrincipal, model::LoginBindingResult), CoreError> {
        self.inner.resolve_login(req).await
    }

    async fn principal_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<model::TokenPrincipal, CoreError> {
        self.inner.principal_by_user_id(user_id).await
    }

    async fn principal_by_authn_token_jti(
        &self,
        jti: &str,
    ) -> Result<model::TokenPrincipal, CoreError> {
        self.inner.principal_by_authn_token_jti(jti).await
    }

    async fn principal_by_authz_token_jti(
        &self,
        jti: &str,
        resource_id: &str,
    ) -> Result<model::TokenPrincipal, CoreError> {
        self.inner
            .principal_by_authz_token_jti(jti, resource_id)
            .await
    }

    async fn add_user(&self, input: model::AddUserInput) -> Result<model::User, CoreError> {
        self.inner.add_user(input).await
    }

    async fn add_invitation(
        &self,
        input: model::AddInvitationInput,
    ) -> Result<(model::User, model::IdentityInvitation), CoreError> {
        self.inner.add_invitation(input).await
    }

    async fn disable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        self.inner.disable_user(user_id_or_email).await
    }

    async fn enable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        self.inner.enable_user(user_id_or_email).await
    }
}

#[async_trait]
impl AccountQuery for FailingAccounts {
    async fn external_identities_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<ExternalIdentity>, CoreError> {
        self.inner.external_identities_for_user(user_id).await
    }

    async fn user_by_id(&self, user_id: &str) -> Result<model::User, CoreError> {
        self.inner.user_by_id(user_id).await
    }

    async fn list_users(
        &self,
        filter: model::UserListFilter,
    ) -> Result<Vec<model::User>, CoreError> {
        if self.fail_list_users {
            Err(CoreError::Unsupported)
        } else {
            self.inner.list_users(filter).await
        }
    }
}

struct FailingAuthz;

#[async_trait]
impl AuthorizationPolicy for FailingAuthz {
    async fn can_access(
        &self,
        _user_id: &str,
        _resource_id: &str,
        _action: &str,
    ) -> Result<bool, CoreError> {
        Ok(false)
    }

    async fn list_accessible(
        &self,
        _user_id: &str,
        _filter: model::ResourceFilter,
    ) -> Result<Vec<model::ResourcePermission>, CoreError> {
        Err(CoreError::Unsupported)
    }
}

struct FailingInvalidRoleAuthz;

#[async_trait]
impl AuthorizationPolicy for FailingInvalidRoleAuthz {
    async fn can_access(
        &self,
        _user_id: &str,
        _resource_id: &str,
        _action: &str,
    ) -> Result<bool, CoreError> {
        Err(CoreError::InvalidArgument(
            "unknown grant role \"typo-role\"".to_owned(),
        ))
    }

    async fn list_accessible(
        &self,
        _user_id: &str,
        _filter: model::ResourceFilter,
    ) -> Result<Vec<model::ResourcePermission>, CoreError> {
        Ok(Vec::new())
    }
}

fn new_test_app(provider: FakeIdp) -> (Router, Arc<memory::Store>, Arc<TokenService>) {
    new_test_app_with_admin(provider, AdminConfig::default())
}

fn new_test_app_with_admin(
    provider: FakeIdp,
    admin: AdminConfig,
) -> (Router, Arc<memory::Store>, Arc<TokenService>) {
    new_test_app_with_admin_audit(provider, admin, None)
}

fn new_test_app_with_admin_audit(
    provider: FakeIdp,
    admin: AdminConfig,
    audit: Option<Arc<dyn AdminAuditLog>>,
) -> (Router, Arc<memory::Store>, Arc<TokenService>) {
    let store = Arc::new(memory::Store::new());
    let mut registry = idpregistry::Registry::new("google");
    registry
        .register(Arc::new(provider))
        .expect("provider registers");
    let tokens = Arc::new(TokenService::new(
        TokenConfig {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned(), "lore.example.com".to_owned()],
            auth_service_audience: "auth.example.com".to_owned(),
            authn_ttl: Duration::from_secs(60 * 60),
            authz_ttl: Duration::from_secs(15 * 60),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        Some(store.clone()),
    ));
    let login = Arc::new(LoginService::new(
        LoginConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            session_ttl: Duration::from_secs(60 * 60),
            auth_session_ttl: Duration::from_secs(60 * 60),
        },
        Arc::new(registry),
        store.clone(),
        store.clone(),
        store.clone(),
        tokens.clone(),
    ));
    let resources: Arc<dyn ResourceQuery> = store.clone();
    let permissions = Arc::new(PermissionService::new(store.clone(), store.clone()));
    let device = Arc::new(DeviceService::new(
        DeviceConfig {
            public_base_url: "https://auth.example.com".to_owned(),
            auth_url: "https://auth.example.com".to_owned(),
            device_code_ttl: Duration::from_secs(600),
            poll_interval: Duration::from_secs(3),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        DeviceIdentityStores {
            accounts: store.clone(),
            groups: store.clone(),
        },
        tokens.clone(),
        Arc::new(lore_auth_adapters::device::UuidDeviceCodeGenerator),
    ));

    (
        build_router(
            HttpConfig {
                public_base_url: "https://auth.example.com".to_owned(),
                lore_auth_url: "ucs-auth://auth.example.com".to_owned(),
                default_remote_url: "lore://lore.example.com:41337".to_owned(),
                session_ttl: Duration::from_secs(60 * 60),
                admin,
            },
            Services {
                login: Some(login),
                tokens: tokens.clone(),
                resources,
                permissions,
                accounts: store.clone(),
                admin_writes: Arc::new(memory::AuditedStoreFactory::new((*store).clone())),
                admin_audit: audit.unwrap_or_else(|| store.clone()),
                groups: store.clone(),
                grants: store.clone(),
                state: store.clone(),
                jwks: store.clone(),
                device: Some(device),
                repository_creator: Arc::new(TestRepositoryCreator {
                    resources: store.clone(),
                }),
            },
        ),
        store,
        tokens,
    )
}

fn add_alice(store: &memory::Store) -> User {
    store.add_test_user(User {
        email: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
        ..User::default()
    })
}

fn fake_idp() -> FakeIdp {
    fake_idp_with_identity(ExternalIdentity {
        provider_id: "google".to_owned(),
        issuer: "https://accounts.google.com".to_owned(),
        subject: "sub".to_owned(),
        email: "alice@example.com".to_owned(),
        ..ExternalIdentity::default()
    })
}

fn fake_idp_with_identity(identity: ExternalIdentity) -> FakeIdp {
    FakeIdp { identity }
}

#[derive(Clone)]
struct FakeIdp {
    identity: ExternalIdentity,
}

#[async_trait]
impl IdentityProvider for FakeIdp {
    fn descriptor(&self) -> IdentityProviderDescriptor {
        IdentityProviderDescriptor {
            id: "google".to_owned(),
            provider_type: "oidc".to_owned(),
            display_name: "Google".to_owned(),
            issuer: "https://accounts.google.com".to_owned(),
            ..IdentityProviderDescriptor::default()
        }
    }

    async fn begin_auth(&self, req: BeginAuthRequest) -> Result<BeginAuthResult, CoreError> {
        let mut redirect = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
        redirect.query_pairs_mut().append_pair("state", &req.state);
        if !req.nonce.is_empty() {
            redirect.query_pairs_mut().append_pair("nonce", &req.nonce);
        }
        Ok(BeginAuthResult {
            redirect_url: redirect.to_string(),
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

fn json_request(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn peer_request(path: &str, cookie: Option<String>, ip: [u8; 4]) -> Request<Body> {
    let mut builder = Request::builder().uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ip, 43_210))));
    request
}

fn post_form_request(path: &str, cookie: Option<String>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let mut request = builder.body(Body::from(body.to_owned())).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43_210))));
    request
}

async fn admin_csrf(app: Router, cookie: &str, path: &str) -> String {
    let response = app
        .oneshot(peer_request(path, Some(cookie.to_owned()), [127, 0, 0, 1]))
        .await
        .expect("admin csrf page response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    extract_csrf(&body)
}

async fn post_admin_form(
    app: Router,
    cookie: &str,
    csrf_path: &str,
    post_path: &str,
    fields: &str,
) {
    let csrf = admin_csrf(app.clone(), cookie, csrf_path).await;
    let separator = if fields.is_empty() { "" } else { "&" };
    let body = format!("csrf_token={csrf}{separator}{fields}");
    let response = app
        .oneshot(post_form_request(post_path, Some(cookie.to_owned()), &body))
        .await
        .expect("admin post response");
    assert_eq!(response.status(), StatusCode::OK, "{post_path}");
}

fn extract_csrf(body: &str) -> String {
    let marker = "name=\"csrf_token\" value=\"";
    let tail = body
        .split_once(marker)
        .unwrap_or_else(|| panic!("csrf input missing from body: {body}"))
        .1;
    tail.split_once('"')
        .unwrap_or_else(|| panic!("csrf value missing from body: {body}"))
        .0
        .to_owned()
}

fn audit_action_counts(entries: &[model::AdminAuditEntry]) -> BTreeMap<&str, usize> {
    let mut out = BTreeMap::new();
    for entry in entries {
        *out.entry(entry.action.as_str()).or_insert(0) += 1;
    }
    out
}

async fn decode_json<T: for<'de> Deserialize<'de>>(response: axum::response::Response) -> T {
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body bytes");
    serde_json::from_slice(&body).expect("json body")
}

async fn response_text(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body bytes");
    String::from_utf8(body.to_vec()).expect("utf8 body")
}

fn assert_security_headers(headers: &axum::http::HeaderMap) {
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff",
        "missing nosniff header"
    );
    assert_eq!(
        headers.get("referrer-policy").unwrap(),
        "no-referrer",
        "missing referrer policy"
    );
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    for want in [
        "default-src 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "script-src 'none'",
    ] {
        assert!(csp.contains(want), "CSP {csp:?} missing {want:?}");
    }
}

#[derive(Deserialize)]
struct DeviceStart {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: i64,
    interval: i64,
}

#[derive(Deserialize)]
struct DeviceToken {
    status: String,
    token_type: String,
    access_token: String,
}
