//! Admin route guard, peer allowlist, and admin CSRF validation.
//! Unauthenticated admin entry requests can start login; other unauthorized routes stay hidden.

use std::net::SocketAddr;

use axum::{
    extract::{Request, State, connect_info::ConnectInfo},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use lore_auth_core::{CoreError, model};

use crate::httpserver::{self, AppState};

use super::{ADMIN_CSRF_TTL, not_found, text_response};

pub(crate) async fn guard_middleware(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    request: Request,
    next: Next,
) -> Response {
    let is_admin_entry =
        request.method() == Method::GET && matches!(request.uri().path(), "/admin" | "/admin/");
    match check_admin(&state, request.headers(), peer).await {
        Ok(_) => {}
        Err(AdminGuardError::LoginRequired) if is_admin_entry => {
            return (
                StatusCode::FOUND,
                [(header::LOCATION, "/login?return_to=admin")],
            )
                .into_response();
        }
        Err(AdminGuardError::LoginRequired) => return not_found(),
        Err(AdminGuardError::Response(response)) => return response,
    }
    next.run(request).await
}

pub(super) async fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Result<httpserver::BrowserSession, Response> {
    check_admin(state, headers, peer)
        .await
        .map_err(|err| match err {
            AdminGuardError::LoginRequired => not_found(),
            AdminGuardError::Response(response) => response,
        })
}

enum AdminGuardError {
    LoginRequired,
    Response(Response),
}

async fn check_admin(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Result<httpserver::BrowserSession, AdminGuardError> {
    let cfg = &state.cfg.admin;
    if !cfg.enabled() {
        return Err(AdminGuardError::Response(not_found()));
    }
    if !cfg.allowed_peer_cidrs.is_empty() {
        let Some(ConnectInfo(addr)) = peer else {
            return Err(AdminGuardError::Response(not_found()));
        };
        if !cfg
            .allowed_peer_cidrs
            .iter()
            .any(|cidr| cidr.contains(&addr.ip()))
        {
            return Err(AdminGuardError::Response(not_found()));
        }
    }
    let session =
        match httpserver::current_browser_session(state.services.state.as_ref(), headers).await {
            Ok(Some(session)) => session,
            Ok(None) => return Err(AdminGuardError::LoginRequired),
            Err(CoreError::PermissionDenied | CoreError::Unauthenticated) => {
                return Err(AdminGuardError::Response(not_found()));
            }
            Err(_) => {
                return Err(AdminGuardError::Response(text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session unavailable",
                )));
            }
        };
    if session.user.status != "active" {
        return Err(AdminGuardError::Response(not_found()));
    }
    let email = model::normalize_email(&session.user.email);
    if email.is_empty()
        || !cfg
            .admin_emails
            .iter()
            .any(|admin| model::normalize_email(admin) == email)
    {
        return Err(AdminGuardError::Response(not_found()));
    }
    Ok(session)
}

pub(super) async fn create_admin_csrf(
    state: &AppState,
    session: &httpserver::BrowserSession,
) -> Result<String, Response> {
    state
        .services
        .state
        .create_csrf_token(&session.session_id, ADMIN_CSRF_TTL)
        .await
        .map_err(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "csrf unavailable"))
}

pub(super) async fn require_admin_csrf(
    state: &AppState,
    session: &httpserver::BrowserSession,
    csrf_token: &str,
) -> Result<(), Response> {
    if csrf_token.trim().is_empty()
        || state
            .services
            .state
            .consume_csrf_token(&session.session_id, csrf_token)
            .await
            .is_err()
    {
        return Err(text_response(StatusCode::FORBIDDEN, "invalid csrf token"));
    }
    Ok(())
}

pub(super) fn admin_actor(session: &httpserver::BrowserSession) -> String {
    if !session.user.email.trim().is_empty() {
        session.user.email.clone()
    } else {
        session.user.id.clone()
    }
}
