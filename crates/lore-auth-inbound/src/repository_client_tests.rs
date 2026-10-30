use super::*;
use lore_auth_proto::lore::repository::v1::{
    Repository, RepositoryCreateResponse,
    repository_service_server::{RepositoryService, RepositoryServiceServer},
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Response, Status, transport::Server};

struct TestService;

#[tonic::async_trait]
impl RepositoryService for TestService {
    async fn repository_create(
        &self,
        request: Request<RepositoryCreateRequest>,
    ) -> Result<Response<RepositoryCreateResponse>, Status> {
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer test-token"
        );
        let request = request.into_inner();
        assert_eq!(request.id.len(), 16);
        assert_eq!(request.default_branch_id.len(), 16);
        assert_ne!(request.id, request.default_branch_id);
        assert_eq!(request.default_branch_name, "main");
        assert!(request.creator.is_none());
        match request.name.as_str() {
            "existing" => return Err(Status::already_exists("duplicate")),
            "uncertain" => return Err(Status::internal("failed after write")),
            "badresponse" => {
                return Ok(Response::new(RepositoryCreateResponse { repository: None }));
            }
            _ => {}
        }
        Ok(Response::new(RepositoryCreateResponse {
            repository: Some(Repository {
                id: request.id,
                name: request.name,
            }),
        }))
    }
}

#[tokio::test]
async fn create_sends_the_expected_request_and_reports_outcomes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(RepositoryServiceServer::new(TestService))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let client = LoreRepositoryCreator::new(format!("http://{addr}"));
    let id = Uuid::new_v4();
    let branch = Uuid::new_v4();
    assert!(
        client
            .create("org/project", "test-token", id, branch)
            .await
            .is_ok()
    );
    assert!(matches!(
        client.create("existing", "test-token", id, branch).await,
        Err(CreateError::Rejected(_))
    ));
    for name in ["uncertain", "badresponse"] {
        assert!(matches!(
            client.create(name, "test-token", id, branch).await,
            Err(CreateError::Uncertain(_))
        ));
    }
    server.abort();
}

#[test]
fn endpoint_rejects_insecure_remote_or_embedded_credentials() {
    for endpoint in [
        "",
        "http://192.0.2.1:41337",
        "http://localhost:41337",
        "http://user:password@127.0.0.1:41337",
        "https://example.com/path",
    ] {
        assert!(matches!(
            LoreRepositoryCreator::new(endpoint.into()).endpoint(),
            Err(CreateError::Rejected(_))
        ));
    }
    assert!(
        LoreRepositoryCreator::new("http://127.0.0.1:41337".into())
            .endpoint()
            .is_ok()
    );
    assert!(
        LoreRepositoryCreator::new("https://example.com:41337".into())
            .endpoint()
            .is_ok()
    );
}
