//! Repository and grant admin route handlers.
//! Builds repository rows with their direct grants for admin templates.

use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Form, Path, Query, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use lore_auth_core::{CoreError, model};
use uuid::Uuid;

use crate::httpserver::{self, AppState};
use crate::repository_client::CreateError;

use super::forms::{GrantForm, RepositoryActionForm, RepositoryAddForm, SearchQuery};
use super::guard::{admin_actor, create_admin_csrf, require_admin, require_admin_csrf};
use super::i18n::translate;
use super::templates::{RepositoriesTableTemplate, RepositoriesTemplate, RepositoryAccessTemplate};
use super::{
    encode_path_segment, is_hx_target, matches_search, normalized_query, not_found,
    render_template, text_response,
};

pub(super) async fn handle_repositories(
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
    let rows = match repository_rows(&state, &session, &search).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    if is_hx_target(&headers, "repositories-results") {
        return render_template(RepositoriesTableTemplate { rows: &rows });
    }
    render_template(RepositoriesTemplate {
        active: "repositories",
        query: &search,
        rows: &rows,
        csrf_token: &csrf_token,
        flash: "",
    })
}

pub(super) async fn handle_repository_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<RepositoryAddForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let flash = match create_repository(&state, &session, &form).await {
        Ok(()) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_repositories_page(&state, &session, "", &flash).await
}

async fn create_repository(
    state: &AppState,
    session: &httpserver::BrowserSession,
    form: &RepositoryAddForm,
) -> Result<(), String> {
    let organization = form.organization.trim();
    let name = form.name.trim();
    if !valid_repository_segment(name)
        || (!organization.is_empty() && !valid_repository_segment(organization))
    {
        return Err("Name is required. Organization and name must each contain only ASCII letters, numbers, '-', '_' or '.', and must not start with '.'".into());
    }
    let name = if organization.is_empty() {
        name.to_owned()
    } else {
        format!("{organization}/{name}")
    };
    if name.len() > 1000 {
        return Err("Repository name exceeds 1000 bytes".into());
    }
    let id = Uuid::new_v4();
    let branch_id = Uuid::new_v4();
    let repository_id = id.simple().to_string();
    let resource_id = model::ResourceID::for_repository_id(&repository_id)
        .ok_or_else(|| "Could not prepare repository ID".to_owned())?;
    let (token, _) = state
        .services
        .tokens
        .mint_authn(&session.user.id, None)
        .await
        .map_err(|_| "Could not issue Lore authentication token".to_owned())?;
    match state
        .services
        .repository_creator
        .create(&name, &token.token, id, branch_id)
        .await
    {
        Ok(()) => {}
        Err(CreateError::Rejected(message)) => return Err(message),
        Err(CreateError::Uncertain(message)) => {
            return Err(format!(
                "{message}. Creation may have partially completed; check Lore and authorization records before retrying. Repository ID: {repository_id}"
            ));
        }
    }
    let resource = state.services.resources.get_by_resource_id(&resource_id).await
        .map_err(|_| format!(
            "Lore created the repository, but its authorization record could not be verified. Repository ID: {repository_id}"
        ))?;
    if resource.name != name {
        return Err(format!(
            "Lore created the repository, but the authorization record has a different name. Repository ID: {repository_id}"
        ));
    }
    let created_at = SystemTime::now().duration_since(UNIX_EPOCH)
        .ok().and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .ok_or_else(|| format!("Lore created the repository, but the audit timestamp is unavailable. Repository ID: {repository_id}"))?;
    state.services.admin_audit.record(model::AdminAuditEntry {
        id: Uuid::new_v4().to_string(),
        actor: admin_actor(session),
        action: "repository.add".into(),
        object_type: "repository".into(),
        object_id: resource_id,
        detail: format!("name={name} lore_repository_id={repository_id}"),
        created_at,
    }).await
        .map_err(|_| format!(
            "Lore created the repository, but the admin audit could not be recorded. Repository ID: {repository_id}"
        ))?;
    Ok(())
}

fn valid_repository_segment(segment: &str) -> bool {
    !segment.is_empty()
        && !segment.starts_with('.')
        && segment
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

pub(super) async fn handle_repository_access(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    render_repository_access(
        &state,
        &session,
        &id,
        &normalized_query(query.q.as_deref()),
        "",
    )
    .await
}

pub(super) async fn handle_repository_disable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<RepositoryActionForm>,
) -> Response {
    change_repository_status(state, id, headers, peer, form, "disable").await
}

pub(super) async fn handle_repository_enable(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<RepositoryActionForm>,
) -> Response {
    change_repository_status(state, id, headers, peer, form, "enable").await
}

pub(super) async fn handle_repository_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<RepositoryActionForm>,
) -> Response {
    change_repository_status(state, id, headers, peer, form, "delete").await
}

pub(super) async fn handle_repository_clear_grants(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<RepositoryActionForm>,
) -> Response {
    change_repository_status(state, id, headers, peer, form, "clear-grants").await
}

async fn change_repository_status(
    state: AppState,
    id: String,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    form: RepositoryActionForm,
    action: &str,
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
    let result = match action {
        "disable" => writes.repository_admin.set_enabled(&id, false).await,
        "enable" => writes.repository_admin.set_enabled(&id, true).await,
        "clear-grants" if form.confirm == "yes" => {
            writes.repository_admin.clear_grants(&id).await.map(|_| ())
        }
        "clear-grants" => Err(CoreError::InvalidArgument(
            "confirm grant removal first".into(),
        )),
        "delete" if form.confirm == "yes" => Err(CoreError::Unsupported),
        "delete" => Err(CoreError::InvalidArgument("confirm deletion first".into())),
        _ => unreachable!("repository action is selected by the route"),
    };
    let flash = match result {
        Ok(()) if action == "delete" => {
            return render_repositories_page(&state, &session, "", &translate("admin.flash.saved"))
                .await;
        }
        Ok(()) => translate("admin.flash.saved"),
        Err(CoreError::NotFound) => return not_found(),
        Err(CoreError::Unsupported) if action == "delete" => {
            translate("admin.repositories.delete_unavailable")
        }
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_repository_access(&state, &session, &id, "", &flash).await
}

pub(super) async fn handle_grant_add(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GrantForm>,
) -> Response {
    mutate_grant(state, id, headers, peer, form, true).await
}

pub(super) async fn handle_grant_remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GrantForm>,
) -> Response {
    mutate_grant(state, id, headers, peer, form, false).await
}

async fn mutate_grant(
    state: AppState,
    id: String,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    form: GrantForm,
    add: bool,
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
    let result = if add {
        writes
            .repository_admin
            .add_grant(&id, &form.subject_type, form.subject_id.trim(), &form.role)
            .await
    } else {
        writes
            .repository_admin
            .remove_grant(&id, &form.subject_type, &form.subject_id, &form.role)
            .await
    };
    let flash = match result {
        Ok(()) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_repository_access(&state, &session, &id, "", &flash).await
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RepositoryRow {
    pub(super) name: String,
    pub(super) lore_repository_id: String,
    pub(super) resource_id: String,
    pub(super) resource_id_path: String,
    pub(super) status: String,
}

impl From<model::Resource> for RepositoryRow {
    fn from(resource: model::Resource) -> Self {
        Self {
            name: resource.name,
            lore_repository_id: resource.lore_repository_id,
            resource_id_path: encode_path_segment(&resource.resource_id),
            resource_id: resource.resource_id,
            status: resource.status,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GrantRow {
    pub(super) subject: String,
    pub(super) subject_type: String,
    pub(super) subject_id: String,
    pub(super) role: String,
}

async fn render_repository_access(
    state: &AppState,
    session: &httpserver::BrowserSession,
    id: &str,
    query: &str,
    flash: &str,
) -> Response {
    let writes = state.services.admin_writes.for_actor(&admin_actor(session));
    let repository = match writes.repository_admin.get(id).await {
        Ok(resource) => RepositoryRow::from(resource),
        Err(CoreError::NotFound) => return not_found(),
        Err(_) => {
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "repository unavailable");
        }
    };
    let grants = match writes.repository_admin.list_grants(id).await {
        Ok(grants) => grants,
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "grants unavailable"),
    };
    let has_grants = !grants.is_empty();
    let maintenance = match writes.maintenance.get().await {
        Ok(settings) => settings,
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "maintenance settings unavailable",
            );
        }
    };
    let groups = match state.services.groups.list_groups().await {
        Ok(groups) => groups,
        Err(_) => return text_response(StatusCode::INTERNAL_SERVER_ERROR, "groups unavailable"),
    };
    let mut rows = Vec::new();
    for grant in grants {
        let subject = match grant.subject_type.as_str() {
            "user" => match state.services.accounts.user_by_id(&grant.subject_id).await {
                Ok(user) => format!("{} ({})", user.display_name, user.email),
                Err(CoreError::NotFound) => "Unknown user".to_owned(),
                Err(_) => {
                    return text_response(StatusCode::INTERNAL_SERVER_ERROR, "users unavailable");
                }
            },
            "group" => groups
                .iter()
                .find(|group| group.id == grant.subject_id)
                .map_or_else(|| "Unknown group".to_owned(), |group| group.name.clone()),
            _ => format!("Unknown subject type ({})", grant.subject_type),
        };
        if matches_search(
            query,
            [
                &subject,
                &grant.subject_id,
                &grant.subject_type,
                &grant.role,
            ],
        ) {
            rows.push(GrantRow {
                subject,
                subject_type: grant.subject_type,
                subject_id: grant.subject_id,
                role: grant.role,
            });
        }
    }
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    render_template(RepositoryAccessTemplate {
        active: "repositories",
        repository,
        has_grants,
        maintenance_enabled: maintenance.enabled,
        grants: rows,
        query,
        csrf_token: &csrf_token,
        flash,
    })
}

async fn render_repositories_page(
    state: &AppState,
    session: &httpserver::BrowserSession,
    query: &str,
    flash: &str,
) -> Response {
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let rows = match repository_rows(state, session, query).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };
    render_template(RepositoriesTemplate {
        active: "repositories",
        query,
        rows: &rows,
        csrf_token: &csrf_token,
        flash,
    })
}

async fn repository_rows(
    state: &AppState,
    session: &httpserver::BrowserSession,
    query: &str,
) -> Result<Vec<RepositoryRow>, Response> {
    let resources = state
        .services
        .admin_writes
        .for_actor(&admin_actor(session))
        .repository_admin
        .list_all()
        .await
        .map_err(|_| {
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "repositories unavailable",
            )
        })?;
    Ok(resources
        .into_iter()
        .filter(|resource| {
            matches_search(
                query,
                [
                    &resource.name,
                    &resource.resource_id,
                    &resource.lore_repository_id,
                ],
            )
        })
        .map(RepositoryRow::from)
        .collect())
}
