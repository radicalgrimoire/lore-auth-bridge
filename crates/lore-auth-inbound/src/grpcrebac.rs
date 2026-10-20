//! `ucs.auth.RebacApi` tonic server wiring and ReBAC peer allowlist middleware.

use std::{
    collections::HashSet,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::{Request as HttpRequest, Response as HttpResponse};
use ipnet::IpNet;
use lore_auth_core::{
    CoreError,
    service::{resource::ResourceService, token::TokenService},
};
use lore_auth_proto::ucs::auth::{
    CreateResourceRequest, CreateResourceResponse, DeleteResourceRequest, DeleteResourceResponse,
    rebac_api_server::{RebacApi, RebacApiServer},
};
use tonic::{Request, Response, Status, body::BoxBody};
use tower::{Layer, Service};

use crate::peer::peer_ip_from_request;

const REBAC_SERVICE_METHOD_PREFIX: &str = "/ucs.auth.RebacApi/";

#[derive(Clone)]
pub struct RebacServer {
    resources: Arc<ResourceService>,
    tokens: Arc<TokenService>,
    admin_emails: HashSet<String>,
}

impl RebacServer {
    #[must_use]
    pub fn new(
        resources: Arc<ResourceService>,
        tokens: Arc<TokenService>,
        admin_emails: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            resources,
            tokens,
            admin_emails: admin_emails.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn into_service(self) -> RebacApiServer<Self> {
        RebacApiServer::new(self)
    }
}

#[tonic::async_trait]
impl RebacApi for RebacServer {
    async fn create_resource(
        &self,
        request: Request<CreateResourceRequest>,
    ) -> Result<Response<CreateResourceResponse>, Status> {
        let resource_id = request.get_ref().resource_id.clone();
        if resource_id.is_empty() {
            return Err(Status::invalid_argument("resource_id is required"));
        }
        self.verify_admin_authn(&request).await?;
        let req = request.into_inner();
        self.resources
            .create_resource(&req.resource_id, &req.resource_name)
            .await
            .map_err(|_| Status::internal("failed to create resource"))?;
        Ok(Response::new(CreateResourceResponse {}))
    }

    async fn delete_resource(
        &self,
        request: Request<DeleteResourceRequest>,
    ) -> Result<Response<DeleteResourceResponse>, Status> {
        let resource_id = request.get_ref().resource_id.clone();
        if resource_id.is_empty() {
            return Err(Status::invalid_argument("resource_id is required"));
        }
        let bearer = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("authorization header required"))?;
        let authn = self
            .tokens
            .verify_authz(bearer, &resource_id)
            .await
            .map_err(|_| Status::unauthenticated("invalid authorization token"))?;
        self.require_admin(&authn.user.email)?;
        match self.resources.delete_resource(&resource_id).await {
            Ok(()) | Err(CoreError::NotFound) => Ok(Response::new(DeleteResourceResponse {})),
            Err(_) => Err(Status::internal("failed to delete resource")),
        }
    }
}

impl RebacServer {
    async fn verify_admin_authn<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let bearer = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("authorization header required"))?;
        let authn = self
            .tokens
            .verify_authn(bearer)
            .await
            .map_err(|_| Status::unauthenticated("invalid authentication token"))?;
        self.require_admin(&authn.user.email)
    }

    fn require_admin(&self, email: &str) -> Result<(), Status> {
        if self.admin_emails.contains(&email.to_ascii_lowercase()) {
            Ok(())
        } else {
            Err(Status::permission_denied("global admin permission is required"))
        }
    }
}

#[must_use]
pub fn default_allowed_peer_cidrs() -> Vec<IpNet> {
    parse_allowed_peer_cidrs(&["127.0.0.1/32", "::1/128"])
        .expect("default ReBAC peer CIDRs must parse")
}

pub fn parse_allowed_peer_cidrs(values: &[&str]) -> Result<Vec<IpNet>, String> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            parse_allowed_peer_cidr(value).map_err(|err| format!("entry {index}: {err}"))
        })
        .collect()
}

#[derive(Clone)]
pub struct RebacPeerAllowlistLayer {
    prefixes: Arc<Vec<IpNet>>,
}

impl RebacPeerAllowlistLayer {
    #[must_use]
    pub fn new(prefixes: Vec<IpNet>) -> Self {
        Self {
            prefixes: Arc::new(prefixes),
        }
    }
}

impl<S> Layer<S> for RebacPeerAllowlistLayer {
    type Service = RebacPeerAllowlistService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RebacPeerAllowlistService {
            inner,
            prefixes: self.prefixes.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RebacPeerAllowlistService<S> {
    inner: S,
    prefixes: Arc<Vec<IpNet>>,
}

impl<S, B> Service<HttpRequest<B>> for RebacPeerAllowlistService<S>
where
    S: Service<HttpRequest<B>, Response = HttpResponse<BoxBody>> + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = HttpResponse<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: HttpRequest<B>) -> Self::Future {
        if request
            .uri()
            .path()
            .starts_with(REBAC_SERVICE_METHOD_PREFIX)
            && !peer_allowed(peer_ip_from_request(&request), &self.prefixes)
        {
            return Box::pin(async {
                Ok(Status::permission_denied("rebac caller is not allowed").into_http())
            });
        }
        let future = self.inner.call(request);
        Box::pin(future)
    }
}

fn parse_allowed_peer_cidr(value: &str) -> Result<IpNet, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("CIDR must not be empty".to_owned());
    }
    if value.contains('/') {
        return value.parse::<IpNet>().map_err(|err| err.to_string());
    }
    let addr = value.parse::<IpAddr>().map_err(|err| err.to_string())?;
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    IpNet::new(addr, bits).map_err(|err| err.to_string())
}

fn peer_allowed(addr: Option<IpAddr>, prefixes: &[IpNet]) -> bool {
    let Some(addr) = addr else {
        return false;
    };
    prefixes.iter().any(|prefix| prefix.contains(&addr))
}
