//! Resource store and read-side repository lookup behavior for the memory adapter.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::Resource,
    ports::{ResourceQuery, ResourceStore},
};

use super::{Store, normalize_resource_for_upsert};

#[async_trait]
impl ResourceStore for Store {
    async fn upsert(&self, resource: Resource) -> Result<(), CoreError> {
        let mut resource = normalize_resource_for_upsert(resource)?;
        let mut state = self.lock();
        if let Some(existing) = state.resources.get(&resource.resource_id) {
            if resource.id.is_empty() {
                resource.id = existing.id.clone();
            }
            if existing.status == "disabled" {
                resource.status = "disabled".to_owned();
            }
        }
        if resource.id.is_empty() {
            resource.id = uuid::Uuid::new_v4().to_string();
        }
        if resource.status.is_empty() {
            resource.status = "active".to_owned();
        }
        state
            .resources
            .insert(resource.resource_id.clone(), resource);
        Ok(())
    }

    async fn delete(&self, resource_id: &str) -> Result<(), CoreError> {
        self.lock()
            .resources
            .remove(resource_id)
            .map(|_| ())
            .ok_or(CoreError::NotFound)
    }
}

#[async_trait]
impl ResourceQuery for Store {
    async fn get_by_id(&self, id: &str) -> Result<Resource, CoreError> {
        self.lock()
            .resources
            .values()
            .find(|resource| resource.id == id && resource.status == "active")
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn get_by_resource_id(&self, resource_id: &str) -> Result<Resource, CoreError> {
        self.lock()
            .resources
            .get(resource_id)
            .filter(|resource| resource.status == "active")
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn get_by_name(&self, name: &str) -> Result<Resource, CoreError> {
        self.lock()
            .resources
            .values()
            .find(|resource| resource.name == name && resource.status == "active")
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn list(&self) -> Result<Vec<Resource>, CoreError> {
        let mut out = self
            .lock()
            .resources
            .values()
            .filter(|resource| resource.status == "active")
            .cloned()
            .collect::<Vec<_>>();
        out.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        Ok(out)
    }
}
