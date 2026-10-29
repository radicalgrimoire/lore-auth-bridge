//! `epic_urc.UrcAuthApi` tonic server wiring.

use std::{net::IpAddr, sync::Arc};

use ipnet::IpNet;
use lore_auth_core::{
    model::{Permission, User, VerifiedAuthn},
    ports::{GroupQuery, ServiceAccountDirectory},
    service::{login::LoginService, permission::PermissionService, token::TokenService},
};
use lore_auth_proto::epic_urc::{
    CheckUserPermissionRequest, CheckUserPermissionResponse, ExchangeApiKeyForUserTokenRequest,
    ExchangeApiKeyForUserTokenResponse, ExchangeExternalTokenForUserTokenRequest,
    ExchangeExternalTokenForUserTokenResponse, ExchangeUserTokenForMultiresourceTokenRequest,
    ExchangeUserTokenForMultiresourceTokenResponse, GetAuthSessionRequest, GetAuthSessionResponse,
    GetProviderUserIdRequest, GetProviderUserIdResponse, GetUserIdRequest, GetUserIdResponse,
    GetUserInfoRequest, GetUserInfoResponse, HealthCheckRequest, HealthCheckResponse,
    LookupUserPermissionsRequest, LookupUserPermissionsResponse, RefreshAuthSessionRequest,
    RefreshAuthSessionResponse, ResourcePermission, StartAuthSessionRequest,
    StartAuthSessionResponse, UserInfo, UserToken, VerifyUserRequest, VerifyUserResponse,
    target_user,
    urc_auth_api_server::{UrcAuthApi, UrcAuthApiServer},
};
use tonic::{Request, Response, Status};

use crate::{
    peer::client_ip_from_grpc_request,
    status::{auth_session_status, resource_token_exchange_status},
};

#[derive(Clone)]
pub struct Services {
    pub login: Arc<LoginService>,
    pub tokens: Arc<TokenService>,
    pub permissions: Arc<PermissionService>,
    pub service_accounts: Arc<dyn ServiceAccountDirectory>,
    pub groups: Arc<dyn GroupQuery>,
}

#[derive(Clone)]
pub struct UrcAuthServer {
    login: Arc<LoginService>,
    tokens: Arc<TokenService>,
    permissions: Arc<PermissionService>,
    service_accounts: Arc<dyn ServiceAccountDirectory>,
    groups: Arc<dyn GroupQuery>,
}

impl UrcAuthServer {
    #[must_use]
    pub fn new(services: Services) -> Self {
        Self {
            login: services.login,
            tokens: services.tokens,
            permissions: services.permissions,
            service_accounts: services.service_accounts,
            groups: services.groups,
        }
    }

    #[must_use]
    pub fn into_service(self) -> UrcAuthApiServer<Self> {
        UrcAuthApiServer::new(self)
    }

    async fn authn_from_request<T>(&self, request: &Request<T>) -> Result<VerifiedAuthn, Status> {
        let bearer = bearer_from_request(request)
            .ok_or_else(|| Status::unauthenticated("authorization header required"))?;
        self.tokens
            .verify_authn(&bearer)
            .await
            .map_err(|_| Status::unauthenticated("invalid authn token"))
    }

    async fn authz_from_request<T>(
        &self,
        request: &Request<T>,
        resource_id: &str,
    ) -> Result<VerifiedAuthn, Status> {
        let bearer = bearer_from_request(request)
            .ok_or_else(|| Status::unauthenticated("authorization header required"))?;
        self.tokens
            .verify_authz(&bearer, resource_id)
            .await
            .map_err(|_| Status::unauthenticated("invalid authorization token"))
    }

    async fn resolve_subject_user(
        &self,
        request: &Request<CheckUserPermissionRequest>,
    ) -> Result<User, Status> {
        if let Some(target_user) = request.get_ref().target_user.as_ref()
            && let Some(target_user::User::UserToken(token)) = target_user.user.as_ref()
            && !token.is_empty()
        {
            return self
                .tokens
                .verify_authn(token)
                .await
                .map(|authn| authn.user)
                .map_err(|_| Status::invalid_argument("invalid target_user token"));
        }

        self.authn_from_request(request)
            .await
            .map(|authn| authn.user)
    }

    async fn authenticate_service_account(
        &self,
        client_id: &str,
        client_secret: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<User, Status> {
        let user = self
            .service_accounts
            .authenticate_service_account(client_id, client_secret)
            .await
            .map_err(|_| Status::unauthenticated("invalid service account credentials"))?;
        let Some(client_ip) = client_ip else {
            return Err(Status::unauthenticated("client address unavailable"));
        };
        let cidrs = self
            .groups
            .list_user_allowed_cidrs(&user.id)
            .await
            .map_err(|_| Status::unauthenticated("service account network is not allowed"))?;
        if cidrs.is_empty()
            || !cidrs
                .iter()
                .filter_map(|cidr| cidr.parse::<IpNet>().ok())
                .any(|cidr| cidr.contains(&client_ip))
        {
            return Err(Status::unauthenticated(
                "service account network is not allowed",
            ));
        }
        Ok(user)
    }
}

#[tonic::async_trait]
impl UrcAuthApi for UrcAuthServer {
    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: "ok".to_owned(),
        }))
    }

    async fn start_auth_session(
        &self,
        request: Request<StartAuthSessionRequest>,
    ) -> Result<Response<StartAuthSessionResponse>, Status> {
        let req = request.into_inner();
        let result = self
            .login
            .start_auth_session(&req.client_state)
            .await
            .map_err(|_| Status::internal("failed to start auth session"))?;
        Ok(Response::new(StartAuthSessionResponse {
            session_code: result.session_code,
            login_url: result.login_url,
        }))
    }

    async fn get_auth_session(
        &self,
        request: Request<GetAuthSessionRequest>,
    ) -> Result<Response<GetAuthSessionResponse>, Status> {
        let client_ip = client_ip_from_grpc_request(&request);
        let req = request.into_inner();
        let result = self
            .login
            .get_auth_session(&req.session_code, &req.client_state, client_ip)
            .await
            .map_err(auth_session_status)?;
        if !result.ready {
            return Ok(Response::new(GetAuthSessionResponse { user_token: None }));
        }
        Ok(Response::new(GetAuthSessionResponse {
            user_token: Some(user_token(result.token, result.user)),
        }))
    }

    async fn refresh_auth_session(
        &self,
        _request: Request<RefreshAuthSessionRequest>,
    ) -> Result<Response<RefreshAuthSessionResponse>, Status> {
        Err(Status::unimplemented(
            "method RefreshAuthSession not implemented",
        ))
    }

    async fn verify_user(
        &self,
        _request: Request<VerifyUserRequest>,
    ) -> Result<Response<VerifyUserResponse>, Status> {
        Err(Status::unimplemented("method VerifyUser not implemented"))
    }

    async fn exchange_external_token_for_user_token(
        &self,
        request: Request<ExchangeExternalTokenForUserTokenRequest>,
    ) -> Result<Response<ExchangeExternalTokenForUserTokenResponse>, Status> {
        let client_ip = client_ip_from_grpc_request(&request);
        let req = request.into_inner();
        if req.token_type != "service-account" {
            return Err(Status::unimplemented("unsupported external token type"));
        }
        let Some((client_id, client_secret)) = req.external_token.split_once(':') else {
            return Err(Status::unauthenticated(
                "invalid service account credentials",
            ));
        };
        if client_id.is_empty() || client_secret.is_empty() || client_secret.contains(':') {
            return Err(Status::unauthenticated(
                "invalid service account credentials",
            ));
        }
        let user = self
            .authenticate_service_account(client_id, client_secret, client_ip)
            .await?;
        let (token, _) = self
            .tokens
            .mint_authn(&user.id, None)
            .await
            .map_err(|_| Status::unauthenticated("service account is not available"))?;
        Ok(Response::new(ExchangeExternalTokenForUserTokenResponse {
            user_token: Some(user_token(token, user)),
        }))
    }

    async fn exchange_api_key_for_user_token(
        &self,
        _request: Request<ExchangeApiKeyForUserTokenRequest>,
    ) -> Result<Response<ExchangeApiKeyForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "method ExchangeAPIKeyForUserToken not implemented",
        ))
    }

    async fn exchange_user_token_for_multiresource_token(
        &self,
        request: Request<ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Result<Response<ExchangeUserTokenForMultiresourceTokenResponse>, Status> {
        let authn = self.authn_from_request(&request).await?;
        let req = request.into_inner();
        if req.resource_id.is_empty() {
            return Err(Status::invalid_argument("resource_id is required"));
        }
        let token = self
            .tokens
            .exchange_authz(authn.clone(), &req.resource_id, None)
            .await
            .map_err(resource_token_exchange_status)?;
        Ok(Response::new(
            ExchangeUserTokenForMultiresourceTokenResponse {
                token: Some(user_token(token, authn.user)),
            },
        ))
    }

    async fn check_user_permission(
        &self,
        request: Request<CheckUserPermissionRequest>,
    ) -> Result<Response<CheckUserPermissionResponse>, Status> {
        let user = self.resolve_subject_user(&request).await?;
        let resource_ids = request.get_ref().resource_id.clone();
        let checked = self
            .permissions
            .check(&user.id, &resource_ids)
            .await
            .map_err(|_| Status::internal("acl evaluation failed"))?;
        let mut response = CheckUserPermissionResponse {
            allowed_resource_permission: Vec::new(),
            denied_resource_permission: Vec::new(),
        };
        for item in checked {
            if item.allowed {
                response
                    .allowed_resource_permission
                    .push(ResourcePermission {
                        resource_id: item.resource_id,
                        permission: permissions_to_strings(&item.permission),
                    });
            } else {
                response
                    .denied_resource_permission
                    .push(ResourcePermission {
                        resource_id: item.resource_id,
                        permission: Vec::new(),
                    });
            }
        }
        Ok(Response::new(response))
    }

    async fn lookup_user_permissions(
        &self,
        request: Request<LookupUserPermissionsRequest>,
    ) -> Result<Response<LookupUserPermissionsResponse>, Status> {
        let authn = self.authn_from_request(&request).await?;
        let req = request.into_inner();
        let permissions = self
            .permissions
            .lookup(
                &authn.user.id,
                lore_auth_core::model::ResourceFilter {
                    prefix: req.resource_filter,
                },
            )
            .await
            .map_err(|_| Status::internal("lookup failed"))?;
        Ok(Response::new(LookupUserPermissionsResponse {
            resource_permission: permissions
                .into_iter()
                .map(|permission| ResourcePermission {
                    resource_id: permission.resource_id,
                    permission: permissions_to_strings(&permission.permission),
                })
                .collect(),
            next_page_token: None,
        }))
    }

    async fn get_user_info(
        &self,
        request: Request<GetUserInfoRequest>,
    ) -> Result<Response<GetUserInfoResponse>, Status> {
        let resource_id = request.get_ref().resource_id.clone();
        if resource_id.is_empty() {
            return Err(Status::invalid_argument("resource_id is required"));
        }
        self.authz_from_request(&request, &resource_id).await?;
        let req = request.into_inner();
        let mut user_info = Vec::with_capacity(req.user_id.len());
        for requested_id in req.user_id {
            let user_id = requested_id.strip_prefix("user:").unwrap_or(&requested_id);
            match self.tokens.user_by_id(user_id).await {
                Ok(user) => user_info.push(UserInfo {
                    user_id: requested_id,
                    display_name: user.display(),
                }),
                Err(lore_auth_core::CoreError::NotFound) => {}
                Err(_) => return Err(Status::internal("failed to resolve user info")),
            }
        }
        Ok(Response::new(GetUserInfoResponse { user_info }))
    }

    async fn get_user_id(
        &self,
        _request: Request<GetUserIdRequest>,
    ) -> Result<Response<GetUserIdResponse>, Status> {
        Err(Status::unimplemented("method GetUserId not implemented"))
    }

    async fn get_provider_user_id(
        &self,
        _request: Request<GetProviderUserIdRequest>,
    ) -> Result<Response<GetProviderUserIdResponse>, Status> {
        Err(Status::unimplemented(
            "method GetProviderUserId not implemented",
        ))
    }
}

fn bearer_from_request<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn user_token(token: lore_auth_core::model::SignedToken, user: User) -> UserToken {
    UserToken {
        user_token: token.token,
        expires_at: token.expires_at,
        user_id: user.bridge_subject(),
        user_name: user.display(),
    }
}

fn permissions_to_strings(permissions: &[Permission]) -> Vec<String> {
    permissions
        .iter()
        .map(|permission| permission.as_str().to_owned())
        .collect()
}
