use std::sync::Arc;

use crate::{
    CoreError,
    model::{self, Permission},
    ports::{AuthorizationPolicy, ResourceStore},
};

pub struct PermissionService {
    resources: Arc<dyn ResourceStore>,
    authz: Arc<dyn AuthorizationPolicy>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckedPermission {
    pub resource_id: String,
    pub allowed: bool,
    pub permission: Vec<Permission>,
}

pub(super) async fn writer_permissions(
    authz: &dyn AuthorizationPolicy,
    user_id: &str,
    resource_id: &str,
) -> Result<Vec<Permission>, CoreError> {
    let mut permissions = vec![Permission::Read, Permission::Write];
    if authz.can_access(user_id, resource_id, "admin").await? {
        permissions.push(Permission::Admin);
    }
    Ok(permissions)
}

impl PermissionService {
    #[must_use]
    pub fn new(resources: Arc<dyn ResourceStore>, authz: Arc<dyn AuthorizationPolicy>) -> Self {
        Self { resources, authz }
    }

    pub async fn check(
        &self,
        user_id: &str,
        resource_ids: &[String],
    ) -> Result<Vec<CheckedPermission>, CoreError> {
        let mut out = Vec::with_capacity(resource_ids.len());
        for resource_id in resource_ids {
            let Ok(resource) = self.resources.get_by_resource_id(resource_id).await else {
                out.push(CheckedPermission {
                    resource_id: resource_id.clone(),
                    ..CheckedPermission::default()
                });
                continue;
            };
            let allowed = self
                .authz
                .can_access(user_id, &resource.resource_id, "write")
                .await?;
            let permission = if allowed {
                writer_permissions(self.authz.as_ref(), user_id, &resource.resource_id).await?
            } else {
                Vec::new()
            };
            out.push(CheckedPermission {
                resource_id: resource.resource_id,
                allowed,
                permission,
            });
        }
        Ok(out)
    }

    pub async fn lookup(
        &self,
        user_id: &str,
        filter: model::ResourceFilter,
    ) -> Result<Vec<model::ResourcePermission>, CoreError> {
        self.authz.list_accessible(user_id, filter).await
    }

    pub async fn can_access(
        &self,
        user_id: &str,
        resource_id: &str,
        action: &str,
    ) -> Result<bool, CoreError> {
        self.authz.can_access(user_id, resource_id, action).await
    }
}
