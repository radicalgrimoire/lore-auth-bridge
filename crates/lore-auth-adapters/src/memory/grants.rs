//! Grant administration, grant listing, authorization checks, and grant evidence queries.
//! Grant admin/query repository arguments resolve repository names only.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{self, Grant, GrantEvidence, ResourceFilter, ResourcePermission},
    ports::{AuthorizationPolicy, GrantAdmin, GrantQuery},
};

use super::{
    State, Store, grant_subject_keys_for_user, group_paths_for_user, repository_pk_for_resource_id,
    resolve_exact_resource_id, resolve_grant_subject_id, resolve_resource_id_for_repo,
};

#[async_trait]
impl AuthorizationPolicy for Store {
    async fn can_access(
        &self,
        user_id: &str,
        resource_id: &str,
        action: &str,
    ) -> Result<bool, CoreError> {
        let state = self.lock();
        if !state
            .resources
            .get(resource_id)
            .is_some_and(|resource| resource.status == "active")
        {
            return Ok(false);
        }
        Ok(grant_subject_keys_for_user(&state, user_id)
            .into_iter()
            .filter_map(|subject| state.grants.get(&subject))
            .filter_map(|resources| resources.get(resource_id))
            .any(|role| lore_auth_core::model::role_allows(role, action)))
    }

    async fn list_accessible(
        &self,
        user_id: &str,
        filter: ResourceFilter,
    ) -> Result<Vec<ResourcePermission>, CoreError> {
        let state = self.lock();
        let mut resources = HashMap::<String, HashSet<lore_auth_core::model::Permission>>::new();
        for subject in grant_subject_keys_for_user(&state, user_id) {
            for (resource_id, role) in state.grants.get(&subject).into_iter().flatten() {
                if !state
                    .resources
                    .get(resource_id)
                    .is_some_and(|resource| resource.status == "active")
                {
                    continue;
                }
                if !filter.prefix.is_empty() && !resource_id.starts_with(&filter.prefix) {
                    continue;
                }
                let permission = lore_auth_core::model::role_permissions(role)
                    .ok_or(CoreError::InvalidArgument(format!("unknown role {role:?}")))?;
                resources
                    .entry(resource_id.clone())
                    .or_default()
                    .extend(permission);
            }
        }
        let mut out = resources
            .into_iter()
            .map(|(resource_id, permissions)| {
                let mut permission = permissions.into_iter().collect::<Vec<_>>();
                permission.sort_by_key(|permission| permission.as_str());
                ResourcePermission {
                    resource_id,
                    permission,
                }
            })
            .collect::<Vec<_>>();
        out.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        Ok(out)
    }
}

#[async_trait]
impl GrantAdmin for Store {
    async fn set_user_repository_roles(
        &self,
        user_id: &str,
        repositories: &[model::DirectRepositoryRoles],
    ) -> Result<(), CoreError> {
        set_user_repository_roles_locked(&mut self.lock(), user_id, repositories)?;
        Ok(())
    }

    async fn change_user_grants(
        &self,
        user_id: &str,
        selected: &[String],
        original: &[model::DirectRepositoryGrant],
        role: &str,
    ) -> Result<(), CoreError> {
        change_user_grants_locked(&mut self.lock(), user_id, selected, original, role)?;
        Ok(())
    }

    async fn add_user_grants(
        &self,
        user_id: &str,
        resource_ids: &[String],
        role: &str,
    ) -> Result<Vec<Grant>, CoreError> {
        add_user_grants_locked(&mut self.lock(), user_id, resource_ids, role)
    }

    async fn add_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        role: &str,
    ) -> Result<Grant, CoreError> {
        if !lore_auth_core::model::is_known_role(role) {
            return Err(CoreError::InvalidArgument(format!(
                "unknown grant role {role:?}"
            )));
        }
        let mut state = self.lock();
        let subject_id = resolve_grant_subject_id(&state, subject_type, subject_id)?;
        let resource_id = resolve_resource_id_for_repo(&state, repo)?;
        state
            .grants
            .entry((subject_type.to_owned(), subject_id.clone()))
            .or_default()
            .insert(resource_id, role.to_owned());
        Ok(Grant {
            id: uuid::Uuid::new_v4().to_string(),
            subject_type: subject_type.to_owned(),
            subject_id,
            repository_id: repo.to_owned(),
            role: role.to_owned(),
        })
    }

    async fn remove_grant(
        &self,
        subject_type: &str,
        subject_id: &str,
        repo: &str,
        _role: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.lock();
        let subject_id = resolve_grant_subject_id(&state, subject_type, subject_id)?;
        let resource_id = resolve_resource_id_for_repo(&state, repo)?;
        if let Some(resources) = state.grants.get_mut(&(subject_type.to_owned(), subject_id)) {
            resources.remove(&resource_id);
        }
        Ok(())
    }
}

pub(super) fn set_user_repository_roles_locked(
    state: &mut State,
    user_id: &str,
    repositories: &[model::DirectRepositoryRoles],
) -> Result<(Vec<Grant>, Vec<(model::DirectRepositoryGrant, String)>), CoreError> {
    model::validate_direct_repository_roles(repositories)?;
    if !state
        .users
        .get(user_id)
        .is_some_and(|user| user.status != "deleted")
    {
        return Err(CoreError::NotFound);
    }
    let subject = ("user".to_owned(), user_id.to_owned());
    let mut changes = Vec::new();
    for repository in repositories {
        let resource = state
            .resources
            .get(&repository.resource_id)
            .filter(|resource| resource.status == "active")
            .ok_or(CoreError::NotFound)?;
        let current: Vec<_> = state
            .grants
            .get(&subject)
            .and_then(|grants| grants.get(&repository.resource_id))
            .cloned()
            .into_iter()
            .collect();
        let mut expected = repository.expected_roles.clone();
        expected.sort();
        if current != expected {
            return Err(CoreError::InvalidArgument(
                "direct grants changed; reload the page and try again".to_owned(),
            ));
        }
        if repository.desired_roles.len() > 1 {
            return Err(CoreError::InvalidArgument(
                "multiple direct roles are unsupported by the memory store".to_owned(),
            ));
        }
        changes.push((repository, resource.name.clone()));
    }
    let mut added = Vec::new();
    let mut removed = Vec::new();
    for (repository, name) in changes {
        if repository.expected_roles == repository.desired_roles {
            continue;
        }
        if let Some(role) = repository.expected_roles.first() {
            removed.push((
                model::DirectRepositoryGrant {
                    resource_id: repository.resource_id.clone(),
                    role: role.clone(),
                },
                name.clone(),
            ));
        }
        let grants = state.grants.entry(subject.clone()).or_default();
        if let Some(role) = repository.desired_roles.first() {
            grants.insert(repository.resource_id.clone(), role.clone());
            added.push(Grant {
                id: uuid::Uuid::new_v4().to_string(),
                subject_type: "user".to_owned(),
                subject_id: user_id.to_owned(),
                repository_id: name,
                role: role.clone(),
            });
        } else {
            grants.remove(&repository.resource_id);
        }
    }
    Ok((added, removed))
}

pub(super) fn change_user_grants_locked(
    state: &mut State,
    user_id: &str,
    selected: &[String],
    original: &[model::DirectRepositoryGrant],
    role: &str,
) -> Result<(Vec<Grant>, Vec<(model::DirectRepositoryGrant, String)>), CoreError> {
    if !state
        .users
        .get(user_id)
        .is_some_and(|user| user.status != "deleted")
    {
        return Err(CoreError::NotFound);
    }
    let subject = ("user".to_owned(), user_id.to_owned());
    let mut selected_ids = HashSet::new();
    for id in selected {
        if !id.starts_with("urc-") || !selected_ids.insert(id.as_str()) {
            return Err(CoreError::InvalidArgument(
                "invalid or duplicate repository".to_owned(),
            ));
        }
    }
    let mut seen = HashSet::new();
    let mut removed = Vec::new();
    for grant in original {
        if !grant.resource_id.starts_with("urc-")
            || !model::is_known_role(&grant.role)
            || !seen.insert(grant.resource_id.as_str())
        {
            return Err(CoreError::InvalidArgument(
                "invalid or duplicate direct grant".to_owned(),
            ));
        }
        let resource = state
            .resources
            .get(&grant.resource_id)
            .filter(|resource| resource.status == "active")
            .ok_or(CoreError::NotFound)?;
        if state
            .grants
            .get(&subject)
            .and_then(|grants| grants.get(&grant.resource_id))
            != Some(&grant.role)
        {
            return Err(CoreError::InvalidArgument(
                "direct grants changed; reload the page and try again".to_owned(),
            ));
        }
        if !selected_ids.contains(grant.resource_id.as_str()) {
            removed.push((grant.clone(), resource.name.clone()));
        }
    }
    let add: Vec<_> = selected
        .iter()
        .filter(|id| !seen.contains(id.as_str()))
        .cloned()
        .collect();
    let added = if add.is_empty() {
        Vec::new()
    } else {
        add_user_grants_locked(state, user_id, &add, role)?
    };
    if let Some(grants) = state.grants.get_mut(&subject) {
        for (grant, _) in &removed {
            grants.remove(&grant.resource_id);
        }
    }
    Ok((added, removed))
}

pub(super) fn add_user_grants_locked(
    state: &mut State,
    user_id: &str,
    resource_ids: &[String],
    role: &str,
) -> Result<Vec<Grant>, CoreError> {
    if resource_ids.is_empty() || !lore_auth_core::model::is_known_role(role) {
        return Err(CoreError::InvalidArgument(
            "select repositories and a valid role".to_owned(),
        ));
    }
    if !state
        .users
        .get(user_id)
        .is_some_and(|user| user.status != "deleted")
    {
        return Err(CoreError::NotFound);
    }
    let subject = ("user".to_owned(), user_id.to_owned());
    let mut seen = HashSet::new();
    let mut grants = Vec::new();
    for resource_id in resource_ids {
        if !resource_id.starts_with("urc-") || !seen.insert(resource_id) {
            return Err(CoreError::InvalidArgument(
                "invalid or duplicate repository".to_owned(),
            ));
        }
        let resource = state
            .resources
            .get(resource_id)
            .filter(|resource| resource.status == "active")
            .ok_or(CoreError::NotFound)?;
        if state
            .grants
            .get(&subject)
            .is_some_and(|existing| existing.contains_key(resource_id))
        {
            return Err(CoreError::InvalidArgument(
                "user already has a direct grant for a selected repository".to_owned(),
            ));
        }
        grants.push(Grant {
            id: uuid::Uuid::new_v4().to_string(),
            subject_type: "user".to_owned(),
            subject_id: user_id.to_owned(),
            repository_id: resource.name.clone(),
            role: role.to_owned(),
        });
    }
    let existing = state.grants.entry(subject).or_default();
    for resource_id in resource_ids {
        existing.insert(resource_id.clone(), role.to_owned());
    }
    Ok(grants)
}

#[async_trait]
impl GrantQuery for Store {
    async fn list_grants(&self, repo: &str) -> Result<Vec<Grant>, CoreError> {
        let state = self.lock();
        let resource_filter = if repo.trim().is_empty() {
            None
        } else {
            Some(resolve_resource_id_for_repo(&state, repo)?)
        };
        let mut out = Vec::new();
        for ((subject_type, subject_id), resources) in &state.grants {
            for (resource_id, role) in resources {
                if resource_filter
                    .as_ref()
                    .is_some_and(|filter| filter != resource_id)
                {
                    continue;
                }
                let repository_id = repository_pk_for_resource_id(&state, resource_id)
                    .unwrap_or_else(|| {
                        lore_auth_core::model::ResourceID::repository_id_from_resource_id(
                            resource_id,
                        )
                    });
                out.push(Grant {
                    id: String::new(),
                    subject_type: subject_type.clone(),
                    subject_id: subject_id.clone(),
                    repository_id,
                    role: role.clone(),
                });
            }
        }
        out.sort_by(|left, right| {
            (
                left.repository_id.as_str(),
                left.subject_type.as_str(),
                left.subject_id.as_str(),
                left.role.as_str(),
            )
                .cmp(&(
                    right.repository_id.as_str(),
                    right.subject_type.as_str(),
                    right.subject_id.as_str(),
                    right.role.as_str(),
                ))
        });
        Ok(out)
    }

    async fn grants_for_user_on_repository(
        &self,
        user_id: &str,
        resource_id: &str,
    ) -> Result<Vec<GrantEvidence>, CoreError> {
        let state = self.lock();
        let resource_id = resolve_exact_resource_id(&state, resource_id)?;
        let user = state
            .users
            .get(user_id)
            .filter(|user| user.status != "deleted")
            .ok_or(CoreError::NotFound)?;
        let user_label = if user.email.trim().is_empty() {
            user.id.clone()
        } else {
            user.email.clone()
        };
        let mut out = Vec::new();
        if let Some(resources) = state.grants.get(&("user".to_owned(), user_id.to_owned()))
            && let Some(role) = resources.get(&resource_id)
        {
            out.push(GrantEvidence {
                subject_type: "user".to_owned(),
                subject_id: user_id.to_owned(),
                subject_name: user_label.clone(),
                role: role.clone(),
                path: format!("user:{user_label} -> grant"),
            });
        }
        for (group_id, group_path) in group_paths_for_user(&state, user_id) {
            if let Some(resources) = state.grants.get(&("group".to_owned(), group_id.clone()))
                && let Some(role) = resources.get(&resource_id)
            {
                let subject_name = state
                    .groups
                    .values()
                    .find(|group| group.id == group_id)
                    .map(|group| group.name.clone())
                    .unwrap_or_else(|| group_id.clone());
                out.push(GrantEvidence {
                    subject_type: "group".to_owned(),
                    subject_id: group_id,
                    subject_name,
                    role: role.clone(),
                    path: format!("user:{user_label} -> {group_path} -> grant"),
                });
            }
        }
        out.sort_by(|left, right| {
            (
                left.path.as_str(),
                left.subject_type.as_str(),
                left.subject_id.as_str(),
                left.role.as_str(),
            )
                .cmp(&(
                    right.path.as_str(),
                    right.subject_type.as_str(),
                    right.subject_id.as_str(),
                    right.role.as_str(),
                ))
        });
        Ok(out)
    }
}
