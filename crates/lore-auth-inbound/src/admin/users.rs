//! User admin route handlers and user-facing view rows.
//! Includes user access rendering and last-active-admin protection.

use std::{collections::HashMap, net::SocketAddr};

use axum::{
    extract::{Form, FromRequest, Path, Query, Request, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use lore_auth_core::{CoreError, model};

use crate::httpserver::{self, AppState};

use super::forms::{
    CsrfForm, EntraIdentityUpdateForm, SearchQuery, UserAddEntraForm, UserAddForm,
    UserDisplayNameForm,
};
use super::guard::{admin_actor, create_admin_csrf, require_admin, require_admin_csrf};
use super::i18n::translate;
use super::templates::{UserAccessTemplate, UsersTableTemplate, UsersTemplate};
use super::{
    ADMIN_LIST_LIMIT, encode_path_segment, format_unix, is_hx_target, normalized_query, not_found,
    render_template, text_response,
};

pub(super) async fn handle_users(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let csrf_token = match create_admin_csrf(&state, &session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let search = normalized_query(query.q.as_deref());
    let rows = match user_rows(&state, &search).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    if is_hx_target(&headers, "users-results") {
        return render_template(UsersTableTemplate {
            rows: &rows,
            limit: ADMIN_LIST_LIMIT,
            csrf_token: &csrf_token,
            current_user_id: &session.user.id,
        });
    }
    render_template(UsersTemplate {
        active: "users",
        query: &search,
        rows: &rows,
        limit: ADMIN_LIST_LIMIT,
        csrf_token: &csrf_token,
        flash: "",
        current_user_id: &session.user.id,
        entra_providers: &state.cfg.admin.entra_providers,
    })
}

pub(super) async fn handle_user_access(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    render_user_access(&state, &session, &id, "").await
}

pub(super) async fn handle_user_add_repositories(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Form(fields) = match Form::<Vec<(String, String)>>::from_request(request, &state).await {
        Ok(form) => form,
        Err(err) => return err.into_response(),
    };
    let tokens: Vec<_> = fields
        .iter()
        .filter(|(key, _)| key == "csrf_token")
        .collect();
    if tokens.len() > 1 {
        return text_response(
            StatusCode::BAD_REQUEST,
            "exactly one CSRF token is required",
        );
    }
    let token = tokens.first().map_or("", |(_, value)| value.as_str());
    if let Err(response) = require_admin_csrf(&state, &session, token).await {
        return response;
    }
    let mut snapshots = HashMap::new();
    let mut selected = HashMap::new();
    for (key, value) in fields {
        match key.as_str() {
            "csrf_token" => {}
            "snapshot" => {
                let Some((resource_id, roles)) = value.split_once(':') else {
                    return text_response(StatusCode::BAD_REQUEST, "invalid original grant");
                };
                let roles: Vec<String> = if roles.is_empty() {
                    Vec::new()
                } else {
                    roles.split(',').map(str::to_owned).collect()
                };
                if !resource_id.starts_with("urc-")
                    || snapshots.insert(resource_id.to_owned(), roles).is_some()
                {
                    return text_response(StatusCode::BAD_REQUEST, "invalid or duplicate snapshot");
                }
            }
            _ if key.starts_with("role:") => {
                let resource_id = &key[5..];
                if !resource_id.starts_with("urc-")
                    || selected.insert(resource_id.to_owned(), value).is_some()
                {
                    return text_response(
                        StatusCode::BAD_REQUEST,
                        "invalid or duplicate repository",
                    );
                }
            }
            _ => return text_response(StatusCode::BAD_REQUEST, "invalid repository selection"),
        }
    }
    if snapshots.len() != selected.len() || selected.is_empty() {
        return text_response(StatusCode::BAD_REQUEST, "incomplete repository selection");
    }
    let mut repositories = Vec::new();
    for (resource_id, expected_roles) in snapshots {
        let Some(role) = selected.remove(&resource_id) else {
            return text_response(StatusCode::BAD_REQUEST, "incomplete repository selection");
        };
        let desired_roles = match role.as_str() {
            "none" => Vec::new(),
            "keep" if expected_roles.len() > 1 => expected_roles.clone(),
            role if model::is_known_role(role) => vec![role.to_owned()],
            _ => return text_response(StatusCode::BAD_REQUEST, "invalid role"),
        };
        repositories.push(model::DirectRepositoryRoles {
            resource_id,
            expected_roles,
            desired_roles,
        });
    }
    let result = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session))
        .grants
        .set_user_repository_roles(&id, &repositories)
        .await;
    let flash = match result {
        Ok(_) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_user_access(&state, &session, &id, &flash).await
}

pub(super) async fn handle_user_update_display_name(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<UserDisplayNameForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let result = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session))
        .accounts
        .update_user_display_name(&id, &form.display_name)
        .await;
    let flash = match result {
        Ok(()) => translate("admin.flash.saved"),
        Err(CoreError::NotFound) => return not_found(),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_user_access(&state, &session, &id, &flash).await
}

async fn render_user_access(
    state: &AppState,
    session: &httpserver::BrowserSession,
    id: &str,
    flash: &str,
) -> Response {
    let user = match state.services.accounts.user_by_id(id).await {
        Ok(user) => user,
        Err(CoreError::NotFound) => return not_found(),
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "users unavailable"),
    };
    let identities = match state
        .services
        .accounts
        .external_identities_for_user(&user.id)
        .await
    {
        Ok(identities) => identities
            .into_iter()
            .filter(|identity| identity.subject_strategy == ENTRA_SUBJECT_STRATEGY)
            .map(|identity| {
                let (tenant_id, object_id) = identity.subject.split_once(':').unwrap_or(("", ""));
                EntraIdentityRow {
                    id_path: encode_path_segment(&identity.id),
                    provider_id: identity.provider_id.clone(),
                    status: identity.status.clone(),
                    subject: identity.subject.clone(),
                    tenant_id: tenant_id.to_owned(),
                    object_id: object_id.to_owned(),
                }
            })
            .collect(),
        Err(_) => {
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "identities unavailable");
        }
    };
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let access = match state
        .services
        .permissions
        .lookup(
            &user.id,
            model::ResourceFilter {
                prefix: "urc-".to_owned(),
            },
        )
        .await
    {
        Ok(access) => access,
        Err(_) => {
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "access unavailable");
        }
    };
    let accessible: HashMap<_, _> = access
        .iter()
        .map(|item| {
            (
                item.resource_id.as_str(),
                item.permission
                    .iter()
                    .map(|permission| permission.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        })
        .collect();
    let grants = match state.services.grants.list_grants("").await {
        Ok(grants) => grants,
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "grants unavailable"),
    };
    let mut direct_roles: HashMap<String, Vec<String>> = HashMap::new();
    for grant in grants
        .into_iter()
        .filter(|grant| grant.subject_type == "user" && grant.subject_id == user.id)
    {
        direct_roles
            .entry(grant.repository_id)
            .or_default()
            .push(grant.role);
    }
    let mut repositories: Vec<_> = match state.services.resources.list().await {
        Ok(resources) => resources
            .into_iter()
            .filter(|resource| resource.status == "active")
            .map(|resource| {
                let mut roles = direct_roles.remove(&resource.id).unwrap_or_default();
                roles.sort();
                UserRepositoryRow {
                    effective: accessible
                        .get(resource.resource_id.as_str())
                        .cloned()
                        .unwrap_or_else(|| "None".to_owned()),
                    name: resource.name,
                    resource_id: resource.resource_id,
                    roles,
                }
            })
            .collect(),
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "repositories unavailable",
            );
        }
    };
    repositories.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.resource_id.cmp(&right.resource_id))
    });
    render_template(UserAccessTemplate {
        active: "users",
        user: UserRow::from(user),
        identities,
        repositories,
        csrf_token: &csrf_token,
        flash,
    })
}

pub(super) struct UserRepositoryRow {
    pub(super) name: String,
    pub(super) resource_id: String,
    pub(super) effective: String,
    pub(super) roles: Vec<String>,
}

pub(super) struct EntraIdentityRow {
    pub(super) id_path: String,
    pub(super) provider_id: String,
    pub(super) status: String,
    pub(super) subject: String,
    pub(super) tenant_id: String,
    pub(super) object_id: String,
}

pub(super) async fn handle_user_update_entra_identity(
    State(state): State<AppState>,
    Path((id, identity_id)): Path<(String, String)>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<EntraIdentityUpdateForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let result = update_entra_identity(&state, &session, &id, &identity_id, form).await;
    let flash = match result {
        Ok(()) => translate("admin.flash.saved"),
        Err(CoreError::NotFound) => return not_found(),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_user_access(&state, &session, &id, &flash).await
}

async fn update_entra_identity(
    state: &AppState,
    session: &httpserver::BrowserSession,
    user_id: &str,
    identity_id: &str,
    form: EntraIdentityUpdateForm,
) -> Result<(), CoreError> {
    let identity = state
        .services
        .accounts
        .external_identities_for_user(user_id)
        .await?
        .into_iter()
        .find(|identity| {
            identity.id == identity_id && identity.subject_strategy == ENTRA_SUBJECT_STRATEGY
        })
        .ok_or(CoreError::NotFound)?;
    let provider = state
        .cfg
        .admin
        .entra_providers
        .iter()
        .find(|provider| provider.id == identity.provider_id && provider.issuer == identity.issuer)
        .ok_or_else(|| {
            CoreError::InvalidArgument(
                "identity provider and issuer must match a configured Entra provider".to_owned(),
            )
        })?;
    let tenant_id = form.tenant_id.trim();
    if !is_guid(tenant_id) {
        return Err(CoreError::InvalidArgument(
            "tenant_id must be an Entra ID tenant ID (GUID)".to_owned(),
        ));
    }
    if !tenant_id.eq_ignore_ascii_case(provider.tenant_id.trim()) {
        return Err(CoreError::InvalidArgument(
            "tenant_id must match the configured provider tenant".to_owned(),
        ));
    }
    let object_id = entra_object_id(&form.object_id, &provider.tenant_id)?;
    state
        .services
        .admin_writes
        .for_actor(&admin_actor(session))
        .accounts
        .update_entra_identity(model::UpdateEntraIdentityInput {
            user_id: user_id.to_owned(),
            identity_id: identity_id.to_owned(),
            provider_id: provider.id.clone(),
            issuer: provider.issuer.clone(),
            expected_subject: form.expected_subject,
            subject: format!("{}:{object_id}", provider.tenant_id),
        })
        .await
}

pub(super) async fn handle_user_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<UserAddForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let flash = match writes
        .accounts
        .add_user(model::AddUserInput {
            email: form.email,
            display_name: form.display_name,
        })
        .await
    {
        Ok(_) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_users_page(&state, &session, "", &flash).await
}

pub(super) async fn handle_user_add_entra(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<UserAddEntraForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let flash = match add_entra_user(&state, &session, form).await {
        Ok(()) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_users_page(&state, &session, "", &flash).await
}

async fn add_entra_user(
    state: &AppState,
    session: &httpserver::BrowserSession,
    form: UserAddEntraForm,
) -> Result<(), CoreError> {
    let providers = &state.cfg.admin.entra_providers;
    let provider_id = form.provider_id.trim();
    let provider = if provider_id.is_empty() && providers.len() == 1 {
        &providers[0]
    } else {
        providers
            .iter()
            .find(|provider| provider.id == provider_id)
            .ok_or_else(|| {
                CoreError::InvalidArgument(
                    "provider_id must reference a configured Entra ID provider".to_owned(),
                )
            })?
    };
    let object_id = entra_object_id(&form.object_id, &provider.tenant_id)?;
    let email = form.email.trim().to_owned();
    let display_name = match form.display_name.trim() {
        "" => email.clone(),
        name => name.to_owned(),
    };
    state
        .services
        .admin_writes
        .for_actor(&admin_actor(session))
        .accounts
        .add_user_with_identity(model::AddUserWithIdentityInput {
            email,
            display_name,
            provider_id: provider.id.clone(),
            issuer: provider.issuer.clone(),
            subject: format!("{}:{object_id}", provider.tenant_id),
            subject_strategy: ENTRA_SUBJECT_STRATEGY.to_owned(),
        })
        .await
        .map(|_| ())
}

const ENTRA_SUBJECT_STRATEGY: &str = "entra_oid_tid";

/// Accepts a bare Object ID or the full `tenant_id:object_id` subject.
fn entra_object_id(value: &str, tenant_id: &str) -> Result<String, CoreError> {
    let value = value.trim();
    let object_id = match value.split_once(':') {
        Some((tid, oid)) if tid.trim().eq_ignore_ascii_case(tenant_id) => oid.trim(),
        Some(_) => {
            return Err(CoreError::InvalidArgument(
                "object_id tenant does not match the provider tenant".to_owned(),
            ));
        }
        None => value,
    };
    if !is_guid(object_id) {
        return Err(CoreError::InvalidArgument(
            "object_id must be an Entra ID Object ID (GUID)".to_owned(),
        ));
    }
    Ok(object_id.to_ascii_lowercase())
}

fn is_guid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, len)| {
            group.len() == len && group.chars().all(|ch| ch.is_ascii_hexdigit())
        })
}

pub(super) async fn handle_user_disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let target = match state.services.accounts.user_by_id(&id).await {
        Ok(user) => user,
        Err(err) => {
            let flash = format!("{}: {err}", translate("admin.flash.error"));
            return render_users_page(&state, &session, "", &flash).await;
        }
    };
    if let Err(err) = validate_admin_disable_target(&state, &session, &target).await {
        let flash = format!("{}: {err}", translate("admin.flash.error"));
        return render_users_page(&state, &session, "", &flash).await;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let flash = match writes.accounts.disable_user(&id).await {
        Ok(()) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_users_page(&state, &session, "", &flash).await
}

pub(super) struct UserRow {
    pub(super) id: String,
    pub(super) id_path: String,
    pub(super) email: String,
    pub(super) display_name: String,
    pub(super) status: String,
    pub(super) last_login: String,
}

impl From<model::User> for UserRow {
    fn from(user: model::User) -> Self {
        let id_path = encode_path_segment(&user.id);
        Self {
            id: user.id,
            id_path,
            email: user.email,
            display_name: user.display_name,
            status: user.status,
            last_login: format_unix(user.last_login_at),
        }
    }
}

async fn render_users_page(
    state: &AppState,
    session: &httpserver::BrowserSession,
    query: &str,
    flash: &str,
) -> Response {
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let rows = match user_rows(state, query).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    render_template(UsersTemplate {
        active: "users",
        query,
        rows: &rows,
        limit: ADMIN_LIST_LIMIT,
        csrf_token: &csrf_token,
        flash,
        current_user_id: &session.user.id,
        entra_providers: &state.cfg.admin.entra_providers,
    })
}

async fn validate_admin_disable_target(
    state: &AppState,
    session: &httpserver::BrowserSession,
    target: &model::User,
) -> Result<(), CoreError> {
    if target.id == session.user.id {
        return Err(CoreError::InvalidArgument(
            "cannot disable the current admin session user".to_owned(),
        ));
    }
    let target_email = model::normalize_email(&target.email);
    let is_configured_admin = state
        .cfg
        .admin
        .admin_emails
        .iter()
        .any(|email| model::normalize_email(email) == target_email);
    if !is_configured_admin {
        return Ok(());
    }
    let users = state
        .services
        .accounts
        .list_users(model::UserListFilter {
            query: String::new(),
            limit: usize::MAX,
        })
        .await?;
    let active_admins_remaining =
        users.into_iter().any(|user| {
            user.id != target.id
                && user.status == "active"
                && state.cfg.admin.admin_emails.iter().any(|email| {
                    model::normalize_email(email) == model::normalize_email(&user.email)
                })
        });
    if active_admins_remaining {
        Ok(())
    } else {
        Err(CoreError::InvalidArgument(
            "cannot disable the last active admin user".to_owned(),
        ))
    }
}

async fn user_rows(state: &AppState, query: &str) -> Result<Vec<UserRow>, Response> {
    let users = state
        .services
        .accounts
        .list_users(model::UserListFilter {
            query: query.to_owned(),
            limit: ADMIN_LIST_LIMIT,
        })
        .await
        .map_err(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "users unavailable"))?;
    Ok(users.into_iter().map(UserRow::from).collect())
}
