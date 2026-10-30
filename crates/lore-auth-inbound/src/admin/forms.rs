//! Form and query payloads accepted by admin routes.
//! These structs intentionally mirror the existing HTML field names.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct SearchQuery {
    pub(super) q: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct MaintenanceForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) enabled: String,
    pub(super) wait_minutes: u32,
}

#[derive(Deserialize)]
pub(super) struct ServiceAccountAddForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) client_id: String,
    #[serde(default)]
    pub(super) display_name: String,
    #[serde(default)]
    pub(super) group_id: String,
}

#[derive(Deserialize)]
pub(super) struct RepositoryAddForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) name: String,
    #[serde(default)]
    pub(super) organization: String,
}

#[derive(Deserialize)]
pub(super) struct CsrfForm {
    #[serde(default)]
    pub(super) csrf_token: String,
}

#[derive(Deserialize)]
pub(super) struct GrantForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) subject_type: String,
    #[serde(default)]
    pub(super) subject_id: String,
    #[serde(default)]
    pub(super) role: String,
}

#[derive(Deserialize)]
pub(super) struct RepositoryActionForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) confirm: String,
}

#[derive(Deserialize)]
pub(super) struct UserAddForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) email: String,
    #[serde(default)]
    pub(super) display_name: String,
}

#[derive(Deserialize)]
pub(super) struct UserDisplayNameForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) display_name: String,
}

#[derive(Deserialize)]
pub(super) struct EntraIdentityUpdateForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) expected_subject: String,
    #[serde(default)]
    pub(super) tenant_id: String,
    #[serde(default)]
    pub(super) object_id: String,
}

#[derive(Deserialize)]
pub(super) struct UserAddEntraForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) provider_id: String,
    #[serde(default)]
    pub(super) email: String,
    #[serde(default)]
    pub(super) display_name: String,
    #[serde(default)]
    pub(super) object_id: String,
}

#[derive(Deserialize)]
pub(super) struct GroupAddForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) name: String,
    #[serde(default)]
    pub(super) description: String,
}

#[derive(Deserialize)]
pub(super) struct GroupMemberForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) user: String,
}

#[derive(Deserialize)]
pub(super) struct GroupNetworkCidrForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) cidr: String,
}

#[derive(Deserialize)]
pub(super) struct GroupNestForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) member_group: String,
}

#[derive(Deserialize)]
pub(super) struct SimulatorForm {
    #[serde(default)]
    pub(super) csrf_token: String,
    #[serde(default)]
    pub(super) user: String,
    #[serde(default)]
    pub(super) resource: String,
    #[serde(default)]
    pub(super) action: String,
}
