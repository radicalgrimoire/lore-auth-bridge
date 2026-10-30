use std::net::SocketAddr;

use axum::{
    extract::{Form, State, connect_info::ConnectInfo},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use lore_auth_core::model::CreateServiceAccountInput;

use crate::httpserver::{self, AppState};

use super::{
    encode_path_segment,
    forms::{MaintenanceForm, ServiceAccountAddForm},
    guard::{admin_actor, create_admin_csrf, require_admin, require_admin_csrf},
    i18n::translate,
    render_template,
    templates::{ServerSettingsTemplate, ServiceAccountCreatedTemplate},
    text_response,
};

pub(super) async fn handle_server_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    render_settings(&state, &session, "").await
}

pub(super) async fn handle_maintenance_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<MaintenanceForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let enabled = match form.enabled.as_str() {
        "on" => true,
        "" => false,
        _ => return text_response(StatusCode::BAD_REQUEST, "invalid maintenance state"),
    };
    let result = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session))
        .maintenance
        .set(enabled, form.wait_minutes)
        .await;
    let flash = match result {
        Ok(_) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_settings(&state, &session, &flash).await
}

pub(super) async fn handle_service_account_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<ServiceAccountAddForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let display_name = if form.display_name.trim().is_empty() {
        form.client_id.trim().to_owned()
    } else {
        form.display_name
    };
    let created = match state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session))
        .service_accounts
        .create_service_account_in_group(
            CreateServiceAccountInput {
                client_id: form.client_id,
                display_name,
            },
            &form.group_id,
        )
        .await
    {
        Ok(created) => created,
        Err(err) => {
            return render_settings(
                &state,
                &session,
                &format!("{}: {err}", translate("admin.flash.error")),
            )
            .await;
        }
    };
    let user_path = encode_path_segment(&created.account.user.id);
    let mut response = render_template(ServiceAccountCreatedTemplate {
        active: "server-settings",
        client_id: &created.account.client_id,
        user_id: &created.account.user.id,
        user_path: &user_path,
        secret: &created.client_secret,
        flash: "",
    });
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn render_settings(
    state: &AppState,
    session: &httpserver::BrowserSession,
    flash: &str,
) -> Response {
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let mut groups = match state.services.groups.list_groups().await {
        Ok(groups) => groups,
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "groups unavailable"),
    };
    groups.sort_by(|left, right| left.name.cmp(&right.name));
    let maintenance = match state
        .services
        .admin_writes
        .for_actor(&admin_actor(session))
        .maintenance
        .get()
        .await
    {
        Ok(settings) => settings,
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "maintenance settings unavailable",
            );
        }
    };
    render_template(ServerSettingsTemplate {
        active: "server-settings",
        groups,
        maintenance_started_at: super::format_unix(maintenance.enabled_at),
        maintenance,
        csrf_token: &csrf_token,
        flash,
    })
}
