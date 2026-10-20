use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

use http::{Request, Response};
use lore_auth_adapters::memory;
use lore_auth_core::{
    model::User,
    service::{resource::ResourceService, token::{TokenConfig, TokenService}},
};
use lore_auth_inbound::grpcrebac::{
    RebacPeerAllowlistLayer, RebacServer, default_allowed_peer_cidrs, parse_allowed_peer_cidrs,
};
use lore_auth_proto::ucs::auth::{
    CreateResourceRequest, DeleteResourceRequest, rebac_api_server::RebacApi,
};
use tonic::{Code, Request as GrpcRequest};
use tower::{Layer, Service, ServiceExt, service_fn};

#[tokio::test]
async fn create_and_delete_resource_are_idempotent_like_go() {
    let store = Arc::new(memory::Store::new());
    let (server, _) = test_server(store.clone());
    let rid = "urc-0194b726b34e72b0b45550b88a967076";

    let create_err = server
        .create_resource(GrpcRequest::new(CreateResourceRequest {
            resource_id: rid.to_owned(),
            resource_name: "game-assets".to_owned(),
        }))
        .await
        .expect_err("create requires a global admin");
    assert_eq!(create_err.code(), Code::Unauthenticated);

    let delete_err = server
        .delete_resource(GrpcRequest::new(DeleteResourceRequest {
            resource_id: rid.to_owned(),
        }))
        .await
        .expect_err("delete requires authorization");
    assert_eq!(delete_err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn create_and_delete_resource_require_resource_id() {
    let store = Arc::new(memory::Store::new());
    let (server, _) = test_server(store);

    let create_err = server
        .create_resource(GrpcRequest::new(CreateResourceRequest {
            resource_id: String::new(),
            resource_name: "game-assets".to_owned(),
        }))
        .await
        .expect_err("resource_id is required");
    assert_eq!(create_err.code(), Code::InvalidArgument);

    let delete_err = server
        .delete_resource(GrpcRequest::new(DeleteResourceRequest {
            resource_id: String::new(),
        }))
        .await
        .expect_err("resource_id is required");
    assert_eq!(delete_err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn delete_resource_requires_global_admin_email() {
    let store = Arc::new(memory::Store::new());
    let (server, tokens) = test_server(store.clone());
    let resource_id = "urc-0194b726b34e72b0b45550b88a967076";
    store.add_test_resource(lore_auth_core::model::Resource {
        name: "game-assets".to_owned(),
        resource_id: resource_id.to_owned(),
        lore_repository_id: "0194b726b34e72b0b45550b88a967076".to_owned(),
        status: "active".to_owned(),
        ..Default::default()
    });
    let user = store.add_test_user(User {
        id: "admin-user".to_owned(),
        email: "admin@example.com".to_owned(),
        display_name: "Admin".to_owned(),
        status: "active".to_owned(),
        ..User::default()
    });
    store.grant_role(&user.id, resource_id, "writer");
    let (authn_token, _) = tokens.mint_authn(&user.id, None).await.expect("mint authn");
    let authn = tokens
        .verify_authn(&authn_token.token)
        .await
        .expect("verify authn");
    let writer = tokens
        .exchange_authz(authn.clone(), &[resource_id.to_owned()], None)
        .await
        .expect("mint writer authz");
    server
        .delete_resource(auth_request(
            DeleteResourceRequest {
                resource_id: resource_id.to_owned(),
            },
            &writer.token,
        ))
        .await
        .expect("global admin may delete");
}

#[test]
fn peer_allowlist_parses_cidr_hosts_and_defaults() {
    let defaults = default_allowed_peer_cidrs();
    assert!(
        defaults
            .iter()
            .any(|prefix| prefix.to_string() == "127.0.0.1/32")
    );
    assert!(
        defaults
            .iter()
            .any(|prefix| prefix.to_string() == "::1/128")
    );

    let parsed = parse_allowed_peer_cidrs(&[" 10.0.0.0/24 ", "192.0.2.10", "::1"])
        .expect("valid allowlist parses");
    assert!(
        parsed
            .iter()
            .any(|prefix| prefix.to_string() == "10.0.0.0/24")
    );
    assert!(
        parsed
            .iter()
            .any(|prefix| prefix.to_string() == "192.0.2.10/32")
    );
    assert!(parsed.iter().any(|prefix| prefix.to_string() == "::1/128"));

    let err = parse_allowed_peer_cidrs(&[" "]).expect_err("empty CIDR is rejected");
    assert!(err.to_string().contains("entry 0"));
}

#[tokio::test]
async fn peer_allowlist_rejects_rebac_method_from_disallowed_peer() {
    let prefixes = parse_allowed_peer_cidrs(&["10.0.0.0/24"]).expect("allowlist parses");
    let mut service = RebacPeerAllowlistLayer::new(prefixes).layer(service_fn(|_req| async {
        Ok::<_, Infallible>(Response::new(tonic::body::empty_body()))
    }));

    let response = service
        .ready()
        .await
        .expect("service ready")
        .call(http_request(
            "/ucs.auth.RebacApi/CreateResource",
            "203.0.113.9:443",
        ))
        .await
        .expect("rejection is encoded as a gRPC response");
    let status = tonic::Status::from_header_map(response.headers())
        .expect("rejected response carries gRPC status");

    assert_eq!(status.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn peer_allowlist_allows_rebac_method_from_allowed_peer() {
    let prefixes = parse_allowed_peer_cidrs(&["10.0.0.0/24"]).expect("allowlist parses");
    let mut service = RebacPeerAllowlistLayer::new(prefixes).layer(service_fn(|_req| async {
        Ok::<_, Infallible>(Response::new(tonic::body::empty_body()))
    }));

    service
        .ready()
        .await
        .expect("service ready")
        .call(http_request(
            "/ucs.auth.RebacApi/DeleteResource",
            "10.0.0.42:443",
        ))
        .await
        .expect("allowed peer reaches handler");
}

#[tokio::test]
async fn peer_allowlist_does_not_apply_to_other_services() {
    let prefixes = parse_allowed_peer_cidrs(&["10.0.0.0/24"]).expect("allowlist parses");
    let mut service = RebacPeerAllowlistLayer::new(prefixes).layer(service_fn(|_req| async {
        Ok::<_, Infallible>(Response::new(tonic::body::empty_body()))
    }));

    service
        .ready()
        .await
        .expect("service ready")
        .call(http_request(
            "/epic_urc.UrcAuthApi/StartAuthSession",
            "203.0.113.9:443",
        ))
        .await
        .expect("non-ReBAC method bypasses allowlist");
}

fn http_request(path: &str, remote_addr: &str) -> Request<()> {
    let mut request = Request::builder()
        .uri(path)
        .body(())
        .expect("request builds");
    request
        .extensions_mut()
        .insert(tonic::transport::server::TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(
                remote_addr
                    .parse::<SocketAddr>()
                    .expect("socket addr parses"),
            ),
        });
    request
}

fn test_server(store: Arc<memory::Store>) -> (RebacServer, Arc<TokenService>) {
    let resources = Arc::new(ResourceService::new(store.clone()));
    let tokens = Arc::new(TokenService::new(
        TokenConfig {
            issuer: "https://auth.example.com".to_owned(),
            audience: vec!["lore-service".to_owned()],
            auth_service_audience: "auth.example.com".to_owned(),
            authn_ttl: Duration::from_secs(3600),
            authz_ttl: Duration::from_secs(900),
        },
        store.clone(),
        store.clone(),
        store.clone(),
        store.clone(),
        Some(store.clone()),
    ));
    (RebacServer::new(
        resources,
        tokens.clone(),
        vec!["admin@example.com".to_owned()],
    ), tokens)
}

fn auth_request<T>(message: T, token: &str) -> GrpcRequest<T> {
    let mut request = GrpcRequest::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().expect("header"));
    request
}
