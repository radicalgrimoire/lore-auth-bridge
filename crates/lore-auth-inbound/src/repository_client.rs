//! Client for creating repositories on the configured Lore server.

use std::{net::IpAddr, time::Duration};

use lore_auth_proto::lore::repository::v1::{
    RepositoryCreateRequest, repository_service_client::RepositoryServiceClient,
};
use tonic::{
    Code, Request,
    transport::{Channel, ClientTlsConfig, Endpoint},
};
use url::Url;
use uuid::Uuid;

#[derive(Debug)]
pub enum CreateError {
    Rejected(String),
    Uncertain(String),
}

#[tonic::async_trait]
pub trait RepositoryCreator: Send + Sync {
    async fn create(
        &self,
        name: &str,
        token: &str,
        id: Uuid,
        branch_id: Uuid,
    ) -> Result<(), CreateError>;
}

pub struct LoreRepositoryCreator {
    endpoint: String,
}

impl LoreRepositoryCreator {
    #[must_use]
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    fn endpoint(&self) -> Result<Endpoint, CreateError> {
        let url = Url::parse(&self.endpoint).map_err(|_| {
            CreateError::Rejected("Repository creation endpoint is not configured".into())
        })?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(CreateError::Rejected(
                "Invalid repository creation endpoint".into(),
            ));
        }
        let secure = match url.scheme() {
            "https" => true,
            "http"
                if url
                    .host_str()
                    .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
                    .is_some_and(|ip| ip.is_loopback()) =>
            {
                false
            }
            _ => {
                return Err(CreateError::Rejected(
                    "Repository creation requires HTTPS or an HTTP loopback address".into(),
                ));
            }
        };
        let mut endpoint = Channel::from_shared(url.to_string())
            .map_err(|_| CreateError::Rejected("Invalid repository creation endpoint".into()))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30));
        if secure {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .map_err(|_| CreateError::Rejected("Could not configure Lore TLS".into()))?;
        }
        Ok(endpoint)
    }
}

#[tonic::async_trait]
impl RepositoryCreator for LoreRepositoryCreator {
    async fn create(
        &self,
        name: &str,
        token: &str,
        id: Uuid,
        branch_id: Uuid,
    ) -> Result<(), CreateError> {
        let channel =
            self.endpoint()?.connect().await.map_err(|_| {
                CreateError::Rejected("Could not connect to the Lore server".into())
            })?;
        let mut client = RepositoryServiceClient::new(channel);
        let mut request = Request::new(RepositoryCreateRequest {
            id: id.as_bytes().to_vec(),
            name: name.to_owned(),
            description: String::new(),
            default_branch_id: branch_id.as_bytes().to_vec(),
            default_branch_name: "main".into(),
            creator: None,
        });
        let authorization = format!("Bearer {token}")
            .parse()
            .map_err(|_| CreateError::Rejected("Invalid authentication token".into()))?;
        request
            .metadata_mut()
            .insert("authorization", authorization);
        let response = client
            .repository_create(request)
            .await
            .map_err(|status| match status.code() {
                Code::InvalidArgument
                | Code::AlreadyExists
                | Code::Unauthenticated
                | Code::PermissionDenied
                | Code::Unimplemented => {
                    CreateError::Rejected(format!("Lore rejected the request ({})", status.code()))
                }

                _ => CreateError::Uncertain(format!("Lore returned {}", status.code())),
            })?
            .into_inner();
        match response.repository {
            Some(repo) if repo.id == id.as_bytes() && repo.name == name => Ok(()),
            _ => Err(CreateError::Uncertain(
                "Lore returned an unexpected repository".into(),
            )),
        }
    }
}

#[cfg(test)]
#[path = "repository_client_tests.rs"]
mod tests;
