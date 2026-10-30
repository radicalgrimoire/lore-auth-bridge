//! Admin dashboard route handler.
//! Renders the dashboard shell.

use std::net::SocketAddr;

use axum::{
    extract::{State, connect_info::ConnectInfo},
    http::HeaderMap,
    response::Response,
};

use crate::httpserver::AppState;

use super::guard::require_admin;
use super::render_template;
use super::templates::DashboardTemplate;

pub(super) async fn handle_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let user_display = session.user.display();
    render_template(DashboardTemplate {
        active: "dashboard",
        user_email: &session.user.email,
        user_display: &user_display,
        flash: "",
    })
}
