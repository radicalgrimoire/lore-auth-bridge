use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use lore_auth_adapters::oidc::{Config, Provider};
use lore_auth_core::{
    CoreError,
    ports::{BeginAuthRequest, CompleteAuthRequest, IdentityProvider},
};
use openidconnect::{IssuerUrl, core::CoreProviderMetadata, reqwest};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::{Url, form_urlencoded};

const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2SynhS44Z4HKx
fKoYYwhJ4eyP1Ov4DG2TbkR0CNP5yFd2HCpBT0978mdZNxTHYG18ikWDNByubh17
Bu4BaUQJu78tFOYS9f0JSTXHRby4nZFInRsLp6X7uP8G1/0cGR0Cbh2Lcs4ApLFa
IrCiuEII0DXNYTdE+Q66lBJOLFPiiatdbtGB8AIw5UKl58Q2EQQaBowZ24EYihji
2VbfjOETW1dCEl2Dv5LQzrw/e7EDj93V0OF0SNscCVtxVwWYVV32RI94CdXx3IYO
wdjD04c4K6qItHwbODCIRvpMkzpNLoSiYJub1+bh1I00a+4o6SvM/pAJLgkyybl0
S52QsoLxAgMBAAECggEAJX0mLvrIjbpKpAUY/vxo0Tbo3TiC0aeOplX0Nm+1VkZU
9El9CCLdHAahKegJuinywjy2aHHgXx/uqKUnb7tb/mtxuL32Rdp4T/9SE7ncApSG
8wm6LOasnCyyp8/l8fAZNu153np88oVsIrcFH+WoUOMu2V6fjOvyUz0N2a1EkA75
+ATV+crgAl59Ro2BL2uFFJgLsjOKpl4SGKaoDnigggl5YkmXTd2Xm/JyvD2t3i2+
Y4LWjoDOPzPsuxYqVwcnEW7PpzGhsSoGzlzvRiKjLp1LiDZy2J2nZCtRrL5iqjB8
ZvK4/s5o+1mzrS2v/2wDaroUmzlPld2IHhC2SLMa5QKBgQDxw6ilSa02FYGR3PL+
2ic1NOYh28NNMrviApSPwA9J86aiCnTeR5LcMIhjMdWqQKjqUxmsoDTRoAPXZIyD
QUpqtVyD+n5lj+pG5DXGwrMuf7iMRhob9XkKgBeRTieafiIkmrwQ6k6RUFdZE4JC
byfIAIU6JAFtaG0O79lOjyNpJQKBgQDBBwwOuB+pYrVKvMtjLKH3lB5QvPF4s46G
+uwdBuO32Q1jjRlydlUToXmfygQtzod+hlp+ehrjpJl7gJio+uzrH1OsnStjHAdq
mnsFNxYEZALXHfL/OSUCi2cxy5ho4+MOXEnP3YY0R9l8nOtgfymjYKJRntcNcHgp
HfiO54xm3QKBgQCLqDzpjk/yqCW6/umX8qkngTFXab2+AIqsGlV7XLT4QTmG7Ydp
R+s8KwT+WDFXMhbhlbOFFt6sIUVWzYyl3beBQNb6nl8ZiDMLVJUEBkC/oaQX0/8N
G5YaTLhQhdc21ZofjwsIsnFEXCa5HB3pBpDyZeqQFXCFpQcq076yNNl9yQKBgAOR
GMTw3AzqOQVfhbaYbYnAn+rIAwJC9yBBZLmIlg6goSG0ysKVsy7Arhmoxvj9tv08
iFGL+hE4ymlA0BFXSadylb47zUBwlSaAIkPPZ8W+/1pwQDw9FxT79HU0GOXfSCPM
ysRfiIpQxZEK6UKINwHA2F7/u2ORL3c7CYvCdZK1AoGBAIzLGN7sR9iQjMHwgSXW
aQUNoFLzaaX7MvzxYrkzRurWhCq6ybe2xJxETwPC8ahX3b7fY6bVd1eZE6j8eNjF
VINmMDDWaxuWWlw98pTZP7b60NMDesH3BWKnTmSkAD4MD0W47ZtZizqgqQg8HdIH
giKbTjMaDDfCdCS1TnGvZU+b
-----END PRIVATE KEY-----"#;

const TEST_RSA_N: &str = "tksp4UuOGeBysXyqGGMISeHsj9Tr-Axtk25EdAjT-chXdhwqQU9Pe_JnWTcUx2BtfIpFgzQcrm4dewbuAWlECbu_LRTmEvX9CUk1x0W8uJ2RSJ0bC6el-7j_Btf9HBkdAm4di3LOAKSxWiKworhCCNA1zWE3RPkOupQSTixT4omrXW7RgfACMOVCpefENhEEGgaMGduBGIoY4tlW34zhE1tXQhJdg7-S0M68P3uxA4_d1dDhdEjbHAlbcVcFmFVd9kSPeAnV8dyGDsHYw9OHOCuqiLR8GzgwiEb6TJM6TS6EomCbm9fm4dSNNGvuKOkrzP6QCS4JMsm5dEudkLKC8Q";

#[tokio::test]
async fn begin_auth_uses_discovered_authorization_endpoint() {
    let issuer = TestIssuer::new();
    let provider = Provider::discover(Config {
        provider_id: "keycloak-prod".to_owned(),
        display_name: "Company SSO".to_owned(),
        issuer: issuer.url.clone(),
        client_id: "client-id".to_owned(),
        client_secret: "client-secret".to_owned(),
        redirect_url: "https://auth.example.com/auth/keycloak-prod/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        ..Config::default()
    })
    .await
    .expect("provider");

    let result = provider
        .begin_auth(BeginAuthRequest {
            state: "state-123".to_owned(),
            nonce: "nonce-123".to_owned(),
            login_hint: "alice@example.com".to_owned(),
            ..BeginAuthRequest::default()
        })
        .await
        .expect("begin auth");

    let redirect = Url::parse(&result.redirect_url).expect("redirect url");
    assert_eq!(
        format!(
            "{}://{}{}{}",
            redirect.scheme(),
            redirect.host_str().unwrap(),
            redirect
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default(),
            redirect.path()
        ),
        format!("{}/authorize", issuer.url)
    );
    let values = redirect.query_pairs().collect::<BTreeMap<_, _>>();
    assert_eq!(values.get("client_id").unwrap(), "client-id");
    assert_eq!(
        values.get("redirect_uri").unwrap(),
        "https://auth.example.com/auth/keycloak-prod/callback"
    );
    assert_eq!(values.get("response_type").unwrap(), "code");
    assert_eq!(values.get("response_mode").unwrap(), "query");
    assert_eq!(values.get("scope").unwrap(), "openid email");
    assert_eq!(values.get("state").unwrap(), "state-123");
    assert_eq!(values.get("nonce").unwrap(), "nonce-123");
    assert_eq!(values.get("login_hint").unwrap(), "alice@example.com");
}

#[tokio::test]
async fn descriptor_includes_login_trust_policy() {
    let issuer = TestIssuer::new();
    let provider = Provider::discover(Config {
        provider_id: "keycloak-prod".to_owned(),
        issuer: issuer.url,
        client_id: "client-id".to_owned(),
        client_secret: "client-secret".to_owned(),
        redirect_url: "https://auth.example.com/auth/keycloak-prod/callback".to_owned(),
        email_binding: "verified_email_invitation".to_owned(),
        allowed_email_domains: vec![
            "Example.com".to_owned(),
            "example.com".to_owned(),
            "contractor.example".to_owned(),
        ],
        ..Config::default()
    })
    .await
    .expect("provider");

    let descriptor = provider.descriptor();
    assert_eq!(
        descriptor.trust_policy.email_binding,
        "verified_email_invitation"
    );
    assert_eq!(
        descriptor.trust_policy.allowed_email_domains,
        ["example.com", "contractor.example"]
    );
}

#[tokio::test]
async fn complete_auth_verifies_id_token_and_maps_claims() {
    let issuer = TestIssuer::new();
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url.clone(),
        "aud": "client-id",
        "sub": "subject:with:colon",
        "exp": now() + 3600,
        "iat": now() - 60,
        "nonce": "nonce-123",
        "mail": "alice@example.com",
        "mail_verified": true,
        "display_name": "Alice Example",
        "avatar": "https://example.com/alice.png",
        "hosted_domain": "example.com",
        "ignored_groups": ["developers"],
    })));
    let provider = Provider::discover(Config {
        provider_id: "keycloak-prod".to_owned(),
        profile: "keycloak".to_owned(),
        display_name: "Company SSO".to_owned(),
        issuer: issuer.url.clone(),
        client_id: "client-id".to_owned(),
        client_secret: "client-secret".to_owned(),
        redirect_url: "https://auth.example.com/auth/keycloak-prod/callback".to_owned(),
        scopes: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
        claim_mapping: BTreeMap::from([
            ("email".to_owned(), "mail".to_owned()),
            ("email_verified".to_owned(), "mail_verified".to_owned()),
            ("name".to_owned(), "display_name".to_owned()),
            ("picture".to_owned(), "avatar".to_owned()),
            ("hosted_domain".to_owned(), "hosted_domain".to_owned()),
        ]),
        allowed_email_domains: vec!["example.com".to_owned()],
        ..Config::default()
    })
    .await
    .expect("provider");

    let identity = provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            nonce: "nonce-123".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("complete auth");

    assert_eq!(identity.provider_id, "keycloak-prod");
    assert_eq!(identity.issuer, issuer.url);
    assert_eq!(identity.subject, "subject:with:colon");
    assert_eq!(identity.email, "alice@example.com");
    assert!(identity.email_verified);
    assert_eq!(identity.display_name, "Alice Example");
    assert_eq!(identity.picture_url, "https://example.com/alice.png");
    assert_eq!(identity.hosted_domain, "example.com");
}

#[tokio::test]
async fn complete_auth_refreshes_unknown_signing_key_without_reexchanging_code() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    issuer.set_signing_key("rotated-key");
    issuer.set_id_token(sign_id_token_with_kid(
        json!({
            "iss": issuer.url,
            "aud": "client-id",
            "sub": "subject-1",
            "nonce": "nonce-123",
        }),
        "rotated-key",
    ));

    let identity = provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            nonce: "nonce-123".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("rotated signing key should be discovered");
    assert_eq!(identity.subject, "subject-1");
    let state = issuer.state.lock().expect("issuer state");
    assert_eq!(state.jwks_requests, 2);
    assert_eq!(state.token_requests, 1);
}

#[tokio::test]
async fn unknown_signing_keys_are_rate_limited_and_still_require_valid_claims() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "missing-key",
    ));
    for _ in 0..3 {
        assert!(matches!(
            provider
                .complete_auth(CompleteAuthRequest {
                    code: "auth-code".to_owned(),
                    ..CompleteAuthRequest::default()
                })
                .await,
            Err(CoreError::Unauthenticated)
        ));
    }
    assert_eq!(issuer.jwks_requests(), 2);

    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url, "aud": "client-id", "sub": "subject-1", "nonce": "incorrect",
    })));
    assert!(matches!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                nonce: "expected".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await,
        Err(CoreError::Unauthenticated)
    ));
    assert_eq!(issuer.jwks_requests(), 2);
}

#[tokio::test]
async fn failed_key_refresh_keeps_valid_keys_until_the_cache_expires() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    issuer.fail_jwks();
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "missing-key",
    ));
    for _ in 0..2 {
        assert!(matches!(
            provider
                .complete_auth(CompleteAuthRequest {
                    code: "auth-code".to_owned(),
                    ..CompleteAuthRequest::default()
                })
                .await,
            Err(CoreError::Unauthenticated)
        ));
    }
    assert_eq!(issuer.jwks_requests(), 2);
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url, "aud": "client-id", "sub": "subject-1",
    })));
    assert!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await
            .is_ok()
    );
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(24 * 60 * 60 + 1)).await;
    tokio::time::resume();
    assert!(matches!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await,
        Err(CoreError::Unauthenticated)
    ));
}

#[tokio::test]
async fn rotated_key_does_not_bypass_nonce_validation() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    issuer.set_signing_key("rotated-key");
    issuer.set_id_token(sign_id_token_with_kid(
        json!({
            "iss": issuer.url, "aud": "client-id", "sub": "subject-1", "nonce": "incorrect",
        }),
        "rotated-key",
    ));
    assert!(matches!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                nonce: "expected".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await,
        Err(CoreError::Unauthenticated)
    ));
    assert_eq!(issuer.jwks_requests(), 2);
}

#[tokio::test]
async fn oversized_jwks_is_rejected_without_replacing_cached_keys() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    issuer.set_signing_key("rotated-key");
    issuer.set_jwks_padding(1024 * 1024 + 1);
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "rotated-key",
    ));
    assert!(matches!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await,
        Err(CoreError::Unauthenticated)
    ));
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url, "aud": "client-id", "sub": "subject-1",
    })));
    assert!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn oversized_jwks_without_content_length_is_rejected() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    issuer.set_signing_key("rotated-key");
    issuer.set_jwks_padding(1024 * 1024 + 1);
    issuer.omit_jwks_content_length();
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "rotated-key",
    ));
    assert!(matches!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await,
        Err(CoreError::Unauthenticated)
    ));
}

#[tokio::test]
async fn concurrent_unknown_keys_share_one_refresh() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    issuer.set_signing_key("rotated-key");
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "rotated-key",
    ));
    let request = CompleteAuthRequest {
        code: "auth-code".to_owned(),
        ..CompleteAuthRequest::default()
    };
    let (a, b, c) = tokio::join!(
        provider.complete_auth(request.clone()),
        provider.complete_auth(request.clone()),
        provider.complete_auth(request)
    );
    assert!(a.is_ok() && b.is_ok() && c.is_ok());
    assert_eq!(issuer.jwks_requests(), 2);
}

#[tokio::test]
async fn cancelled_login_does_not_cancel_shared_key_refresh() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    issuer.set_signing_key("rotated-key");
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "rotated-key",
    ));
    let gate = issuer.block_jwks();
    let first_provider = provider.clone();
    let first = tokio::spawn(async move {
        first_provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while issuer.jwks_requests() < 2 {
        assert!(Instant::now() < deadline, "key refresh did not start");
        tokio::task::yield_now().await;
    }
    first.abort();
    assert!(
        first
            .await
            .expect_err("login should be cancelled")
            .is_cancelled()
    );
    *gate.0.lock().expect("jwks gate") = true;
    gate.1.notify_one();
    assert!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await
            .is_ok()
    );
    assert_eq!(issuer.jwks_requests(), 2);
}

#[test]
fn provider_from_metadata_works_without_a_runtime_and_starts_refresh_when_used() {
    let issuer = TestIssuer::new();
    let client = reqwest::Client::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let metadata = runtime
        .block_on(CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer.url.clone()).expect("issuer URL"),
            &client,
        ))
        .expect("metadata");
    drop(runtime);
    let provider = Provider::from_metadata(
        Config {
            provider_id: "keycloak-prod".to_owned(),
            issuer: issuer.url.clone(),
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".to_owned(),
            redirect_url: "https://auth.example.com/auth/keycloak-prod/callback".to_owned(),
            ..Config::default()
        },
        metadata,
        client,
    )
    .expect("construction without a runtime");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        provider
            .begin_auth(BeginAuthRequest::default())
            .await
            .expect("begin auth");
        tokio::time::pause();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60 * 60 + 1)).await;
        tokio::time::resume();
        let deadline = Instant::now() + Duration::from_secs(5);
        while issuer.jwks_requests() < 2 {
            assert!(Instant::now() < deadline, "periodic refresh did not run");
            tokio::task::yield_now().await;
        }
    });
    drop(runtime);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("replacement runtime");
    runtime.block_on(async {
        provider
            .begin_auth(BeginAuthRequest::default())
            .await
            .expect("begin auth after runtime shutdown");
        tokio::time::pause();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2 * 60 * 60 + 2)).await;
        tokio::time::resume();
        let deadline = Instant::now() + Duration::from_secs(5);
        while issuer.jwks_requests() < 3 {
            assert!(Instant::now() < deadline, "refresh task did not restart");
            tokio::task::yield_now().await;
        }
    });
}

#[tokio::test]
async fn signing_keys_refresh_periodically_and_removed_keys_are_rejected() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    tokio::time::pause();
    tokio::task::yield_now().await;
    issuer.set_signing_key("rotated-key");
    tokio::time::advance(Duration::from_secs(60 * 60 + 1)).await;
    tokio::time::resume();
    let deadline = Instant::now() + Duration::from_secs(5);
    while issuer.jwks_requests() < 2 {
        assert!(Instant::now() < deadline, "periodic refresh did not run");
        tokio::task::yield_now().await;
    }
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "rotated-key",
    ));
    assert!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await
            .is_ok()
    );
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url, "aud": "client-id", "sub": "subject-1",
    })));
    assert!(matches!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await,
        Err(CoreError::Unauthenticated)
    ));
    assert_eq!(issuer.jwks_requests(), 2);
}

#[tokio::test]
async fn scheduled_refresh_waits_for_on_demand_cooldown() {
    let issuer = TestIssuer::new();
    let provider = default_provider(&issuer, Config::default()).await;
    tokio::time::pause();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(59 * 60)).await;
    tokio::time::resume();
    issuer.set_signing_key("rotated-key");
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "rotated-key",
    ));
    provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("on-demand refresh");
    assert_eq!(issuer.jwks_requests(), 2);
    issuer.set_signing_key("replacement-key");

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60 + 1)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5 * 60 + 1)).await;
    tokio::time::resume();
    let deadline = Instant::now() + Duration::from_secs(5);
    while issuer.jwks_requests() < 3 {
        assert!(
            Instant::now() < deadline,
            "deferred periodic refresh did not run"
        );
        tokio::task::yield_now().await;
    }
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "replacement-key",
    ));
    provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("replacement key after periodic refresh");
    issuer.set_id_token(sign_id_token_with_kid(
        json!({"iss": issuer.url, "aud": "client-id", "sub": "subject-1"}),
        "rotated-key",
    ));
    assert!(matches!(
        provider
            .complete_auth(CompleteAuthRequest {
                code: "auth-code".to_owned(),
                ..CompleteAuthRequest::default()
            })
            .await,
        Err(CoreError::Unauthenticated)
    ));
}

#[tokio::test]
async fn complete_auth_does_not_apply_allowed_email_domains_before_login_resolution() {
    let issuer = TestIssuer::new();
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url.clone(),
        "aud": "client-id",
        "sub": "subject-1",
        "exp": now() + 3600,
        "iat": now() - 60,
        "nonce": "nonce-123",
        "email": "alice@other.example",
        "email_verified": false,
    })));
    let provider = default_provider(
        &issuer,
        Config {
            allowed_email_domains: vec!["example.com".to_owned()],
            ..Config::default()
        },
    )
    .await;

    let identity = provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            nonce: "nonce-123".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("allowed email domains are enforced by login resolution");

    assert_eq!(identity.email, "alice@other.example");
    assert!(!identity.email_verified);
}

#[tokio::test]
async fn google_profile_accepts_allowed_hosted_domain_claim() {
    let issuer = TestIssuer::new();
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url.clone(),
        "aud": "client-id",
        "sub": "google-subject",
        "exp": now() + 3600,
        "iat": now() - 60,
        "email": "alice@personal.example",
        "email_verified": true,
        "hd": "example.com",
    })));
    let provider = Provider::discover(Config {
        provider_id: "google".to_owned(),
        profile: "google".to_owned(),
        issuer: issuer.url.clone(),
        client_id: "client-id".to_owned(),
        client_secret: "client-secret".to_owned(),
        redirect_url: "https://auth.example.com/auth/google/callback".to_owned(),
        scopes: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
        allowed_hosted_domains: vec!["example.com".to_owned()],
        personal_accounts: "deny".to_owned(),
        ..Config::default()
    })
    .await
    .expect("provider");

    let identity = provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("complete auth");

    assert_eq!(identity.provider_id, "google");
    assert_eq!(identity.subject, "google-subject");
    assert_eq!(identity.hosted_domain, "example.com");
}

#[tokio::test]
async fn google_profile_does_not_use_email_domain_for_workspace_restriction() {
    let issuer = TestIssuer::new();
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url.clone(),
        "aud": "client-id",
        "sub": "google-subject",
        "exp": now() + 3600,
        "iat": now() - 60,
        "email": "alice@example.com",
        "email_verified": true,
    })));
    let provider = Provider::discover(Config {
        provider_id: "google".to_owned(),
        profile: "google".to_owned(),
        issuer: issuer.url,
        client_id: "client-id".to_owned(),
        client_secret: "client-secret".to_owned(),
        redirect_url: "https://auth.example.com/auth/google/callback".to_owned(),
        scopes: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
        allowed_hosted_domains: vec!["example.com".to_owned()],
        personal_accounts: "deny".to_owned(),
        ..Config::default()
    })
    .await
    .expect("provider");

    let err = provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect_err("missing hd should be rejected");
    assert!(matches!(err, CoreError::PermissionDenied));
}

#[tokio::test]
async fn discover_rejects_unknown_google_personal_accounts_policy() {
    let issuer = TestIssuer::new();

    let err = Provider::discover(Config {
        provider_id: "google".to_owned(),
        profile: "google".to_owned(),
        issuer: issuer.url,
        client_id: "client-id".to_owned(),
        client_secret: "client-secret".to_owned(),
        redirect_url: "https://auth.example.com/auth/google/callback".to_owned(),
        personal_accounts: "denny".to_owned(),
        ..Config::default()
    })
    .await
    .expect_err("unknown personal account policy should fail");
    assert!(
        err.to_string().contains("personal_accounts"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn entra_subject_strategy_uses_tenant_and_object_id() {
    let issuer = TestIssuer::new();
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url.clone(),
        "aud": "client-id",
        "sub": "pairwise-subject",
        "tid": "tenant-1",
        "oid": "object-1",
        "exp": now() + 3600,
        "iat": now() - 60,
        "email": "alice@example.com",
    })));
    let provider = Provider::discover(Config {
        provider_id: "entra".to_owned(),
        profile: "entra".to_owned(),
        issuer: issuer.url,
        client_id: "client-id".to_owned(),
        client_secret: "client-secret".to_owned(),
        redirect_url: "https://auth.example.com/auth/entra/callback".to_owned(),
        subject_strategy: "entra_oid_tid".to_owned(),
        required_tenant_id: "tenant-1".to_owned(),
        ..Config::default()
    })
    .await
    .expect("provider");

    let identity = provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("complete auth");
    assert_eq!(identity.subject, "tenant-1:object-1");
    assert_eq!(identity.subject_strategy, "entra_oid_tid");
}

#[tokio::test]
async fn complete_auth_rejects_nonce_mismatch() {
    let issuer = TestIssuer::new();
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url.clone(),
        "aud": "client-id",
        "sub": "subject-1",
        "exp": now() + 3600,
        "iat": now() - 60,
        "nonce": "actual-nonce",
    })));
    let provider = default_provider(&issuer, Config::default()).await;

    let err = provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            nonce: "expected-nonce".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect_err("nonce mismatch should fail");
    assert!(matches!(err, CoreError::Unauthenticated));
}

#[tokio::test]
async fn begin_auth_with_required_pkce_stores_verifier_and_sends_challenge() {
    let issuer = TestIssuer::new();
    let provider = default_provider(
        &issuer,
        Config {
            pkce: "required".to_owned(),
            ..Config::default()
        },
    )
    .await;

    let result = provider
        .begin_auth(BeginAuthRequest {
            state: "state-123".to_owned(),
            ..BeginAuthRequest::default()
        })
        .await
        .expect("begin auth");
    let private_state: Value =
        serde_json::from_slice(&result.private_state).expect("private state json");
    let verifier = private_state
        .get("code_verifier")
        .and_then(Value::as_str)
        .expect("code verifier");

    let redirect = Url::parse(&result.redirect_url).expect("redirect url");
    let values = redirect.query_pairs().collect::<BTreeMap<_, _>>();
    assert_eq!(values.get("code_challenge_method").unwrap(), "S256");
    assert_eq!(
        values.get("code_challenge").unwrap(),
        &code_challenge_s256(verifier)
    );
}

#[tokio::test]
async fn complete_auth_with_required_pkce_requires_private_verifier() {
    let issuer = TestIssuer::new();
    let provider = default_provider(
        &issuer,
        Config {
            pkce: "required".to_owned(),
            ..Config::default()
        },
    )
    .await;

    let err = provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect_err("missing verifier should fail");
    assert!(
        err.to_string().contains("code_verifier missing"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn complete_auth_with_required_pkce_sends_code_verifier() {
    let issuer = TestIssuer::new();
    issuer.expect_code_verifier("test-pkce-verifier");
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url.clone(),
        "aud": "client-id",
        "sub": "subject-1",
        "exp": now() + 3600,
        "iat": now() - 60,
        "email": "alice@example.com",
        "email_verified": true,
    })));
    let provider = default_provider(
        &issuer,
        Config {
            pkce: "required".to_owned(),
            ..Config::default()
        },
    )
    .await;

    provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            private_state: br#"{"code_verifier":"test-pkce-verifier"}"#.to_vec(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("complete auth");
}

#[tokio::test]
async fn bool_claim_accepts_string_booleans() {
    let issuer = TestIssuer::new();
    issuer.set_id_token(sign_id_token(json!({
        "iss": issuer.url.clone(),
        "aud": "client-id",
        "sub": "subject-1",
        "exp": now() + 3600,
        "iat": now() - 60,
        "email": "alice@example.com",
        "mail_verified": "true",
    })));
    let provider = default_provider(
        &issuer,
        Config {
            claim_mapping: BTreeMap::from([(
                "email_verified".to_owned(),
                "mail_verified".to_owned(),
            )]),
            ..Config::default()
        },
    )
    .await;

    let identity = provider
        .complete_auth(CompleteAuthRequest {
            code: "auth-code".to_owned(),
            ..CompleteAuthRequest::default()
        })
        .await
        .expect("complete auth");
    assert!(identity.email_verified);
}

async fn default_provider(issuer: &TestIssuer, override_config: Config) -> Provider {
    Provider::discover(Config {
        provider_id: "keycloak-prod".to_owned(),
        issuer: issuer.url.clone(),
        client_id: "client-id".to_owned(),
        client_secret: "client-secret".to_owned(),
        redirect_url: "https://auth.example.com/auth/keycloak-prod/callback".to_owned(),
        scopes: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
        ..override_config
    })
    .await
    .expect("provider")
}

fn sign_id_token(claims: Value) -> String {
    sign_id_token_with_kid(claims, "test-key")
}

fn sign_id_token_with_kid(mut claims: Value, kid: &str) -> String {
    if let Value::Object(ref mut map) = claims {
        map.entry("exp").or_insert_with(|| json!(now() + 3600));
        map.entry("iat").or_insert_with(|| json!(now() - 60));
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(&header, &claims, &test_encoding_key()).expect("sign id token")
}

fn test_encoding_key() -> EncodingKey {
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use rsa::pkcs8::DecodePrivateKey as _;
    let private =
        rsa::RsaPrivateKey::from_pkcs8_pem(TEST_RSA_PRIVATE_KEY).expect("test rsa key pem");
    let der = private.to_pkcs1_der().expect("test rsa key der");
    EncodingKey::from_rsa_der(der.as_bytes())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn code_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[derive(Clone)]
struct IssuerState {
    id_token: String,
    expected_code_verifier: Option<String>,
    signing_key: String,
    jwks_requests: usize,
    token_requests: usize,
    jwks_fails: bool,
    jwks_padding: usize,
    jwks_without_content_length: bool,
    jwks_gate: Option<Arc<(Mutex<bool>, Condvar)>>,
}

impl Default for IssuerState {
    fn default() -> Self {
        Self {
            id_token: String::new(),
            expected_code_verifier: None,
            signing_key: "test-key".to_owned(),
            jwks_requests: 0,
            token_requests: 0,
            jwks_fails: false,
            jwks_padding: 0,
            jwks_without_content_length: false,
            jwks_gate: None,
        }
    }
}

struct TestIssuer {
    url: String,
    state: Arc<Mutex<IssuerState>>,
}

impl TestIssuer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test issuer");
        let addr = listener.local_addr().expect("issuer addr");
        let state = Arc::new(Mutex::new(IssuerState::default()));
        let thread_state = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                handle_stream(stream, Arc::clone(&thread_state));
            }
        });
        Self {
            url: format!("http://{addr}"),
            state,
        }
    }

    fn set_id_token(&self, id_token: String) {
        self.state.lock().expect("issuer state").id_token = id_token;
    }

    fn set_signing_key(&self, kid: &str) {
        self.state.lock().expect("issuer state").signing_key = kid.to_owned();
    }

    fn jwks_requests(&self) -> usize {
        self.state.lock().expect("issuer state").jwks_requests
    }

    fn fail_jwks(&self) {
        self.state.lock().expect("issuer state").jwks_fails = true;
    }

    fn set_jwks_padding(&self, bytes: usize) {
        self.state.lock().expect("issuer state").jwks_padding = bytes;
    }

    fn omit_jwks_content_length(&self) {
        self.state
            .lock()
            .expect("issuer state")
            .jwks_without_content_length = true;
    }

    fn block_jwks(&self) -> Arc<(Mutex<bool>, Condvar)> {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        self.state.lock().expect("issuer state").jwks_gate = Some(gate.clone());
        gate
    }

    fn expect_code_verifier(&self, verifier: &str) {
        self.state
            .lock()
            .expect("issuer state")
            .expected_code_verifier = Some(verifier.to_owned());
    }
}

fn handle_stream(mut stream: TcpStream, state: Arc<Mutex<IssuerState>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.trim().is_empty() {
        return;
    }
    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }

    let path = target.split('?').next().unwrap_or("/");
    let response = match path {
        "/.well-known/openid-configuration" => json_response(json!({
            "issuer": issuer_base_from_request(&stream),
            "authorization_endpoint": format!("{}/authorize", issuer_base_from_request(&stream)),
            "token_endpoint": format!("{}/token", issuer_base_from_request(&stream)),
            "jwks_uri": format!("{}/jwks", issuer_base_from_request(&stream)),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })),
        "/jwks" => {
            let mut state = state.lock().expect("issuer state");
            state.jwks_requests += 1;
            let gate = state.jwks_gate.clone();
            let response = if state.jwks_fails {
                empty_response(503, "Service Unavailable")
            } else {
                let mut body = serde_json::to_string(&json!({
                    "keys": [{
                        "kty": "RSA",
                        "use": "sig",
                        "kid": state.signing_key,
                        "alg": "RS256",
                        "n": TEST_RSA_N,
                        "e": "AQAB"
                    }]
                }))
                .expect("jwks JSON");
                body.push_str(&" ".repeat(state.jwks_padding));
                let content_length = if state.jwks_without_content_length {
                    String::new()
                } else {
                    format!("Content-Length: {}\r\n", body.len())
                };
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{content_length}Connection: close\r\n\r\n{body}"
                )
            };
            drop(state);
            if let Some(gate) = gate {
                let mut released = gate.0.lock().expect("jwks gate");
                while !*released {
                    released = gate.1.wait(released).expect("jwks gate");
                }
            }
            response
        }
        "/token" => token_response(&body, &state),
        "/authorize" => empty_response(204, "No Content"),
        _ => empty_response(404, "Not Found"),
    };
    let _ = stream.write_all(response.as_bytes());
}

fn issuer_base_from_request(stream: &TcpStream) -> String {
    format!("http://{}", stream.local_addr().expect("local addr"))
}

fn token_response(body: &[u8], state: &Arc<Mutex<IssuerState>>) -> String {
    let form = form_urlencoded::parse(body)
        .into_owned()
        .collect::<BTreeMap<String, String>>();
    let mut state = state.lock().expect("issuer state");
    state.token_requests += 1;
    if let Some(expected) = &state.expected_code_verifier
        && form.get("code_verifier") != Some(expected)
    {
        return text_response(400, "Bad Request", "unexpected code_verifier");
    }
    if state.id_token.is_empty() {
        return text_response(500, "Internal Server Error", "test id token not configured");
    }
    json_response(json!({
        "access_token": "access-token",
        "token_type": "Bearer",
        "id_token": state.id_token,
    }))
}

fn json_response(value: Value) -> String {
    let body = serde_json::to_string(&value).expect("json response");
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn text_response(status: u16, reason: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn empty_response(status: u16, reason: &str) -> String {
    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}
