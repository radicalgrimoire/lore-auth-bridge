//! Askama template bindings for the admin UI.
//! Template files remain under the crate-level templates directory.

use askama::Template;

use super::groups::GroupRow;
use super::i18n::translate;
use super::repositories::{GrantRow, RepositoryRow};
use super::simulator::SimulatorResultView;
use super::users::UserRow;

#[derive(Template)]
#[template(path = "admin/server_settings.html")]
pub(super) struct ServerSettingsTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) groups: Vec<lore_auth_core::model::Group>,
    pub(super) maintenance: lore_auth_core::model::MaintenanceSettings,
    pub(super) maintenance_started_at: String,
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
}

impl ServerSettingsTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/service_account_created.html")]
pub(super) struct ServiceAccountCreatedTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) client_id: &'a str,
    pub(super) user_id: &'a str,
    pub(super) user_path: &'a str,
    pub(super) secret: &'a str,
    pub(super) flash: &'a str,
}

impl ServiceAccountCreatedTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/dashboard.html")]
pub(super) struct DashboardTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) user_email: &'a str,
    pub(super) user_display: &'a str,
    pub(super) flash: &'a str,
}

impl DashboardTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/repositories.html")]
pub(super) struct RepositoriesTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) query: &'a str,
    pub(super) rows: &'a [RepositoryRow],
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
}

impl RepositoriesTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/repositories_table.html")]
pub(super) struct RepositoriesTableTemplate<'a> {
    pub(super) rows: &'a [RepositoryRow],
}

impl RepositoriesTableTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/repository_access.html")]
pub(super) struct RepositoryAccessTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) repository: RepositoryRow,
    pub(super) has_grants: bool,
    pub(super) maintenance_enabled: bool,
    pub(super) grants: Vec<GrantRow>,
    pub(super) query: &'a str,
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
}

impl RepositoryAccessTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}
#[derive(Template)]
#[template(path = "admin/users.html")]
pub(super) struct UsersTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) query: &'a str,
    pub(super) rows: &'a [UserRow],
    pub(super) limit: usize,
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
    pub(super) current_user_id: &'a str,
    pub(super) entra_providers: &'a [super::AdminEntraProvider],
}

impl UsersTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/users_table.html")]
pub(super) struct UsersTableTemplate<'a> {
    pub(super) rows: &'a [UserRow],
    pub(super) limit: usize,
    pub(super) csrf_token: &'a str,
    pub(super) current_user_id: &'a str,
}

impl UsersTableTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/user_access.html")]
pub(super) struct UserAccessTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) user: UserRow,
    pub(super) identities: Vec<super::users::EntraIdentityRow>,
    pub(super) repositories: Vec<super::users::UserRepositoryRow>,
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
}

impl UserAccessTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/groups.html")]
pub(super) struct GroupsTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) query: &'a str,
    pub(super) rows: Vec<GroupRow>,
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
}

impl GroupsTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/group_access.html")]
pub(super) struct GroupAccessTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) group: GroupRow,
    pub(super) query: &'a str,
    pub(super) members: Vec<UserRow>,
    pub(super) nested_groups: Vec<GroupRow>,
    pub(super) allowed_cidrs: Vec<String>,
    pub(super) csrf_token: &'a str,
    pub(super) flash: &'a str,
}

impl GroupAccessTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}

#[derive(Template)]
#[template(path = "admin/simulator.html")]
pub(super) struct SimulatorTemplate<'a> {
    pub(super) active: &'a str,
    pub(super) csrf_token: &'a str,
    pub(super) input_user: &'a str,
    pub(super) input_resource: &'a str,
    pub(super) input_action: &'a str,
    pub(super) result: SimulatorResultView,
    pub(super) flash: &'a str,
}

impl SimulatorTemplate<'_> {
    fn t(&self, key: &str) -> String {
        translate(key)
    }
}
