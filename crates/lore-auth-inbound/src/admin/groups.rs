//! Group administration and direct membership management.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{Form, Path, Query, State, connect_info::ConnectInfo},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use lore_auth_core::model::Group;

use crate::httpserver::{self, AppState};

use super::forms::{
    GroupAddForm, GroupMemberForm, GroupNestForm, GroupNetworkCidrForm, SearchQuery,
};
use super::guard::{admin_actor, create_admin_csrf, require_admin, require_admin_csrf};
use super::i18n::translate;
use super::templates::{GroupAccessTemplate, GroupsTemplate};
use super::users::UserRow;
use super::{
    encode_path_segment, matches_search, normalized_query, not_found, render_template,
    text_response,
};

pub(super) async fn handle_groups(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    render_groups_page(&state, &session, &normalized_query(query.q.as_deref()), "").await
}

pub(super) async fn handle_group_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupAddForm>,
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
    let flash = match writes.groups.add_group(&form.name, &form.description).await {
        Ok(_) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_groups_page(&state, &session, "", &flash).await
}

pub(super) async fn handle_group_access(
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
    render_group_access(
        &state,
        &session,
        &id,
        &normalized_query(query.q.as_deref()),
        "",
    )
    .await
}

pub(super) async fn handle_group_member_add(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupMemberForm>,
) -> Response {
    mutate_group_member(state, id, headers, peer, form, true).await
}

pub(super) async fn handle_group_member_remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupMemberForm>,
) -> Response {
    mutate_group_member(state, id, headers, peer, form, false).await
}

async fn mutate_group_member(
    state: AppState,
    id: String,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    form: GroupMemberForm,
    add: bool,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    let group = match group_by_id(&state, &id).await {
        Ok(group) => group,
        Err(response) => return response,
    };
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let result = if add {
        writes
            .groups
            .add_group_member(&group.name, &form.user)
            .await
    } else {
        writes
            .groups
            .remove_group_member(&group.name, &form.user)
            .await
    };
    let flash = match result {
        Ok(()) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_group_access(&state, &session, &id, "", &flash).await
}

pub(super) async fn handle_group_nest_remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupNestForm>,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    if let Err(response) = group_by_id(&state, &id).await {
        return response;
    }
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let result = writes
        .groups
        .remove_group_group(&id, &form.member_group)
        .await;
    let flash = match result {
        Ok(()) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_group_access(&state, &session, &id, "", &flash).await
}

pub(super) async fn handle_group_cidr_add(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupNetworkCidrForm>,
) -> Response {
    mutate_group_cidr(state, id, headers, peer, form, true).await
}

pub(super) async fn handle_group_cidr_remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<GroupNetworkCidrForm>,
) -> Response {
    mutate_group_cidr(state, id, headers, peer, form, false).await
}

async fn mutate_group_cidr(
    state: AppState,
    id: String,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    form: GroupNetworkCidrForm,
    add: bool,
) -> Response {
    let session = match require_admin(&state, &headers, peer).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_admin_csrf(&state, &session, &form.csrf_token).await {
        return response;
    }
    if let Err(response) = group_by_id(&state, &id).await {
        return response;
    }
    let cidr = match form.cidr.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => format!("{ip}/32"),
        Ok(IpAddr::V6(ip)) => format!("{ip}/128"),
        Err(_) => form.cidr,
    };
    let writes = state
        .services
        .admin_writes
        .for_actor(&admin_actor(&session));
    let result = if add {
        writes.groups.add_group_allowed_cidr(&id, &cidr).await
    } else {
        writes.groups.remove_group_allowed_cidr(&id, &cidr).await
    };
    let flash = match result {
        Ok(()) => translate("admin.flash.saved"),
        Err(err) => format!("{}: {err}", translate("admin.flash.error")),
    };
    render_group_access(&state, &session, &id, "", &flash).await
}

pub(super) struct GroupRow {
    pub(super) id: String,
    pub(super) id_path: String,
    pub(super) name: String,
}

impl From<Group> for GroupRow {
    fn from(group: Group) -> Self {
        Self {
            id_path: encode_path_segment(&group.id),
            id: group.id,
            name: group.name,
        }
    }
}

async fn list_groups(state: &AppState) -> Result<Vec<Group>, Response> {
    state
        .services
        .groups
        .list_groups()
        .await
        .map_err(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "groups unavailable"))
}

async fn group_by_id(state: &AppState, id: &str) -> Result<Group, Response> {
    list_groups(state)
        .await?
        .into_iter()
        .find(|group| group.id == id)
        .ok_or_else(not_found)
}

async fn render_groups_page(
    state: &AppState,
    session: &httpserver::BrowserSession,
    query: &str,
    flash: &str,
) -> Response {
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let mut groups = match list_groups(state).await {
        Ok(groups) => groups,
        Err(response) => return response,
    };
    groups.retain(|group| matches_search(query, [&group.id, &group.name, &group.description]));
    groups.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    render_template(GroupsTemplate {
        active: "groups",
        query,
        rows: groups.into_iter().map(GroupRow::from).collect(),
        csrf_token: &csrf_token,
        flash,
    })
}

async fn render_group_access(
    state: &AppState,
    session: &httpserver::BrowserSession,
    id: &str,
    query: &str,
    flash: &str,
) -> Response {
    let group = match group_by_id(state, id).await {
        Ok(group) => group,
        Err(response) => return response,
    };
    let csrf_token = match create_admin_csrf(state, session).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let members = match state.services.groups.list_group_members(&group.id).await {
        Ok(members) => members,
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "group members unavailable",
            );
        }
    };
    let nested = match state.services.groups.list_group_groups(&group.id).await {
        Ok(groups) => groups,
        Err(_) => {
            return text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "nested groups unavailable",
            );
        }
    };
    let allowed_cidrs = match state
        .services
        .groups
        .list_group_allowed_cidrs(&group.id)
        .await
    {
        Ok(cidrs) => cidrs,
        Err(_) => {
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "group CIDRs unavailable");
        }
    };
    let members = members
        .into_iter()
        .filter(|user| matches_search(query, [&user.id, &user.email, &user.display_name]))
        .map(UserRow::from)
        .collect();
    render_template(GroupAccessTemplate {
        active: "groups",
        group: GroupRow::from(group),
        query,
        members,
        nested_groups: nested.into_iter().map(GroupRow::from).collect(),
        allowed_cidrs,
        csrf_token: &csrf_token,
        flash,
    })
}
