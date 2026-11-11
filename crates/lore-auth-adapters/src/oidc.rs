//! OIDC identity provider adapter implementations.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{Arc, LazyLock, Weak},
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lore_auth_core::{
    CoreError,
    model::{ExternalIdentity, LoginTrustPolicy},
    ports::{
        BeginAuthRequest, BeginAuthResult, CompleteAuthRequest, IdentityProvider,
        IdentityProviderDescriptor,
    },
};
use openidconnect::{
    AsyncHttpClient, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpRequest,
    HttpResponse, IssuerUrl, JsonWebKey, JsonWebKeyId, JsonWebKeySetUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreIdTokenVerifier, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm, CoreProviderMetadata,
    },
    reqwest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::{
    sync::{Mutex, OwnedMutexGuard, RwLock},
    task::JoinHandle,
    time::Instant,
};
use tracing::warn;

use crate::config::IdentityProviderConfig;

static DEFAULT_SCOPES: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        "openid".to_owned(),
        "email".to_owned(),
        "profile".to_owned(),
    ]
});

const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
const KEY_REFRESH_COOLDOWN: Duration = Duration::from_secs(5 * 60);
const KEY_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const KEY_REFRESH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_METADATA_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
enum MetadataHttpError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("metadata response exceeds the size limit")]
    TooLarge,
}

struct BoundedMetadataClient(reqwest::Client);

impl<'c> AsyncHttpClient<'c> for BoundedMetadataClient {
    type Error = MetadataHttpError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(bounded_metadata_request(&self.0, request))
    }
}

async fn bounded_metadata_request(
    client: &reqwest::Client,
    request: HttpRequest,
) -> Result<HttpResponse, MetadataHttpError> {
    let mut response = client.execute(request.try_into()?).await?;
    if response
        .content_length()
        .is_some_and(|len| len > MAX_METADATA_BYTES as u64)
    {
        return Err(MetadataHttpError::TooLarge);
    }
    let status = response.status();
    let version = response.version();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_METADATA_BYTES - body.len() {
            return Err(MetadataHttpError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let mut result = HttpResponse::new(body);
    *result.status_mut() = status;
    *result.version_mut() = version;
    *result.headers_mut() = headers;
    Ok(result)
}

struct KeySnapshot {
    keys: CoreJsonWebKeySet,
    verifier: CoreIdTokenVerifier<'static>,
    fetched_at: Instant,
}

impl std::fmt::Debug for KeySnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeySnapshot")
            .field("key_count", &self.keys.keys().len())
            .field("fetched_at", &self.fetched_at)
            .finish()
    }
}

#[derive(Debug)]
struct VerifierParameters {
    client_id: ClientId,
    client_secret: ClientSecret,
    issuer: IssuerUrl,
    allowed_algorithms: Vec<CoreJwsSigningAlgorithm>,
}

impl VerifierParameters {
    fn snapshot(&self, keys: CoreJsonWebKeySet) -> Arc<KeySnapshot> {
        let verifier = CoreIdTokenVerifier::new_confidential_client(
            self.client_id.clone(),
            self.client_secret.clone(),
            self.issuer.clone(),
            keys.clone(),
        )
        .set_allowed_algs(self.allowed_algorithms.clone());
        Arc::new(KeySnapshot {
            keys,
            verifier,
            fetched_at: Instant::now(),
        })
    }
}

#[derive(Debug)]
struct KeyCache {
    provider_id: String,
    jwks_url: JsonWebKeySetUrl,
    http_client: reqwest::Client,
    verifier_parameters: VerifierParameters,
    snapshot: RwLock<Arc<KeySnapshot>>,
    last_attempt: Arc<Mutex<Option<Instant>>>,
    refresh_task: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for KeyCache {
    fn drop(&mut self) {
        if let Some(task) = self.refresh_task.get_mut().take() {
            task.abort();
        }
    }
}

impl KeyCache {
    fn new(
        provider_id: String,
        metadata: &CoreProviderMetadata,
        http_client: reqwest::Client,
        client_id: &str,
        client_secret: &str,
    ) -> Arc<Self> {
        let verifier_parameters = VerifierParameters {
            client_id: ClientId::new(client_id.to_owned()),
            client_secret: ClientSecret::new(client_secret.to_owned()),
            issuer: metadata.issuer().clone(),
            allowed_algorithms: metadata.id_token_signing_alg_values_supported().clone(),
        };
        let snapshot = verifier_parameters.snapshot(metadata.jwks().clone());
        Arc::new(Self {
            provider_id,
            jwks_url: metadata.jwks_uri().clone(),
            http_client,
            verifier_parameters,
            snapshot: RwLock::new(snapshot),
            last_attempt: Arc::new(Mutex::new(None)),
            refresh_task: Mutex::new(None),
        })
    }

    async fn ensure_running(self: &Arc<Self>) {
        let mut task = self.refresh_task.lock().await;
        if task.as_ref().is_none_or(JoinHandle::is_finished) {
            *task = Some(tokio::spawn(Self::refresh_periodically(Arc::downgrade(
                self,
            ))));
        }
    }

    async fn refresh_periodically(cache: Weak<Self>) {
        let mut interval =
            tokio::time::interval_at(Instant::now() + KEY_REFRESH_INTERVAL, KEY_REFRESH_INTERVAL);
        loop {
            interval.tick().await;
            loop {
                let Some(cache) = cache.upgrade() else {
                    return;
                };
                let retry_after = cache.refresh(None).await;
                drop(cache);
                let Some(delay) = retry_after else {
                    break;
                };
                tokio::time::sleep(delay).await;
            }
        }
    }

    async fn refresh(self: &Arc<Self>, missing_key: Option<&JsonWebKeyId>) -> Option<Duration> {
        let last_attempt = self.last_attempt.clone().lock_owned().await;
        if let Some(key_id) = missing_key
            && self
                .snapshot
                .read()
                .await
                .keys
                .keys()
                .iter()
                .any(|key| key.key_id() == Some(key_id))
        {
            return None;
        }
        let now = Instant::now();
        if let Some(last) = *last_attempt {
            let elapsed = now.duration_since(last);
            if elapsed < KEY_REFRESH_COOLDOWN {
                return Some(KEY_REFRESH_COOLDOWN - elapsed);
            }
        }
        let task = tokio::spawn(Self::perform_refresh(self.clone(), last_attempt, now));
        if let Err(err) = task.await {
            warn!(provider_id = %self.provider_id, error = %err, "OIDC signing key refresh task failed");
        }
        None
    }

    async fn perform_refresh(
        self: Arc<Self>,
        mut last_attempt: OwnedMutexGuard<Option<Instant>>,
        started_at: Instant,
    ) {
        let client = BoundedMetadataClient(self.http_client.clone());
        match tokio::time::timeout(
            KEY_REFRESH_TIMEOUT,
            CoreJsonWebKeySet::fetch_async(&self.jwks_url, &client),
        )
        .await
        {
            Ok(Ok(keys)) => {
                *self.snapshot.write().await = self.verifier_parameters.snapshot(keys);
            }
            Ok(Err(err)) => {
                warn!(provider_id = %self.provider_id, error = %err, "OIDC signing key refresh failed");
            }
            Err(_) => {
                warn!(provider_id = %self.provider_id, "OIDC signing key refresh timed out");
            }
        }
        *last_attempt = Some(started_at);
    }

    async fn keys_for_token(
        self: &Arc<Self>,
        kid: Option<&str>,
    ) -> Result<Arc<KeySnapshot>, CoreError> {
        let key_id = kid.map(|kid| JsonWebKeyId::new(kid.to_owned()));
        let snapshot = self.snapshot.read().await;
        let expired = snapshot.fetched_at.elapsed() >= KEY_CACHE_TTL;
        let missing = key_id.as_ref().is_some_and(|key_id| {
            !snapshot
                .keys
                .keys()
                .iter()
                .any(|key| key.key_id() == Some(key_id))
        });
        drop(snapshot);
        if expired {
            let _ = self.refresh(None).await;
        } else if missing {
            let _ = self.refresh(key_id.as_ref()).await;
        }
        let snapshot = self.snapshot.read().await;
        if snapshot.fetched_at.elapsed() >= KEY_CACHE_TTL {
            warn!(provider_id = %self.provider_id, "OIDC signing key cache expired");
            return Err(CoreError::Unauthenticated);
        }
        Ok(snapshot.clone())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub provider_id: String,
    pub profile: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub claim_mapping: BTreeMap<String, String>,
    pub subject_strategy: String,
    pub required_tenant_id: String,
    pub email_binding: String,
    pub pkce: String,
    pub allowed_email_domains: Vec<String>,
    pub allowed_hosted_domains: Vec<String>,
    pub personal_accounts: String,
}

impl Config {
    #[must_use]
    pub fn from_provider_config(
        provider_id: impl Into<String>,
        provider: &IdentityProviderConfig,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            profile: provider.profile.clone(),
            display_name: provider.display_name.clone(),
            issuer: provider.issuer.clone(),
            client_id: provider.client_id.clone(),
            client_secret: client_secret.into(),
            redirect_url: provider.redirect_url.clone(),
            scopes: provider.scopes.clone(),
            claim_mapping: provider.claims.clone(),
            subject_strategy: provider.subject.strategy.clone(),
            required_tenant_id: provider.subject.required_tid.clone(),
            email_binding: provider.trust.email_binding.clone(),
            pkce: provider.pkce.clone(),
            allowed_email_domains: provider.trust.allowed_email_domains.clone(),
            allowed_hosted_domains: provider.trust.hosted_domain.allowed.clone(),
            personal_accounts: provider.trust.personal_accounts.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Provider {
    id: String,
    profile: String,
    display_name: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    scopes: Vec<String>,
    provider_metadata: CoreProviderMetadata,
    key_cache: Arc<KeyCache>,
    http_client: reqwest::Client,
    claim_mapping: BTreeMap<String, String>,
    subject_strategy: String,
    required_tenant_id: String,
    email_binding: String,
    pkce: String,
    allowed_email_domains: Vec<String>,
    allowed_hosted_domains: BTreeSet<String>,
    personal_accounts: String,
}

impl Provider {
    pub async fn discover(config: Config) -> Result<Self, CoreError> {
        let config = normalized_config(config)?;
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| CoreError::InvalidArgument(format!("oidc: build http client: {err}")))?;
        let issuer_url = IssuerUrl::new(config.issuer.clone()).map_err(|err| {
            CoreError::InvalidArgument(format!("oidc: issuer is not a valid URL: {err}"))
        })?;
        let metadata_client = BoundedMetadataClient(http_client.clone());
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &metadata_client)
            .await
            .map_err(|err| {
                CoreError::InvalidArgument(format!(
                    "oidc: discover provider {:?}: {err}",
                    config.issuer
                ))
            })?;
        let provider = Self::from_metadata(config, provider_metadata, http_client)?;
        provider.key_cache.ensure_running().await;
        Ok(provider)
    }

    /// Creates a provider whose signing-key refresh task starts when it is used.
    pub fn from_metadata(
        config: Config,
        provider_metadata: CoreProviderMetadata,
        http_client: reqwest::Client,
    ) -> Result<Self, CoreError> {
        let config = normalized_config(config)?;
        // Keep the issuer exactly as advertised; Url printing would append a
        // trailing slash to bare-origin issuers and diverge from the Go form.
        let issuer = provider_metadata.issuer().as_str().to_owned();
        let key_cache = KeyCache::new(
            config.provider_id.clone(),
            &provider_metadata,
            http_client.clone(),
            &config.client_id,
            &config.client_secret,
        );
        Ok(Self {
            id: config.provider_id.clone(),
            profile: config.profile,
            display_name: display_name_or_default(&config.display_name, &config.provider_id),
            issuer,
            client_id: config.client_id,
            client_secret: config.client_secret,
            redirect_url: config.redirect_url,
            scopes: if config.scopes.is_empty() {
                DEFAULT_SCOPES.clone()
            } else {
                config.scopes
            },
            provider_metadata,
            key_cache,
            http_client,
            claim_mapping: copy_claim_mapping(config.claim_mapping),
            subject_strategy: default_string(&config.subject_strategy, "oidc_sub"),
            required_tenant_id: config.required_tenant_id.trim().to_owned(),
            email_binding: default_string(&config.email_binding, "disabled"),
            pkce: config.pkce.trim().to_owned(),
            allowed_email_domains: normalize_domain_list(config.allowed_email_domains),
            allowed_hosted_domains: normalize_domain_list(config.allowed_hosted_domains)
                .into_iter()
                .collect(),
            personal_accounts: config.personal_accounts.trim().to_owned(),
        })
    }

    fn redirect_url(&self) -> Result<RedirectUrl, CoreError> {
        RedirectUrl::new(self.redirect_url.clone()).map_err(|err| {
            CoreError::InvalidArgument(format!("oidc: redirect URL is invalid: {err}"))
        })
    }

    fn claim<'a>(&'a self, canonical: &'a str, fallback: &'a str) -> &'a str {
        self.claim_mapping
            .get(canonical)
            .map(String::as_str)
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(fallback)
    }

    fn subject(
        &self,
        claims: &Map<String, Value>,
        oidc_subject: &str,
    ) -> Result<String, CoreError> {
        match self.subject_strategy.as_str() {
            "" | "oidc_sub" => Ok(oidc_subject.to_owned()),
            "entra_oid_tid" => {
                let tid = string_claim(claims, "tid");
                if !self.required_tenant_id.is_empty() && tid != self.required_tenant_id {
                    return Err(CoreError::PermissionDenied);
                }
                let oid = string_claim(claims, "oid");
                if tid.is_empty() || oid.is_empty() {
                    return Err(CoreError::InvalidArgument(
                        "oidc: entra_oid_tid requires tid and oid claims".to_owned(),
                    ));
                }
                Ok(format!("{tid}:{oid}"))
            }
            strategy => Err(CoreError::InvalidArgument(format!(
                "oidc: unsupported subject strategy {strategy:?}"
            ))),
        }
    }

    fn validate_trust(&self, identity: &ExternalIdentity) -> Result<(), CoreError> {
        if self.profile == "google" {
            self.validate_hosted_domain(identity)?;
        }
        Ok(())
    }

    fn validate_hosted_domain(&self, identity: &ExternalIdentity) -> Result<(), CoreError> {
        let hosted_domain = identity.hosted_domain.trim().to_lowercase();
        if !self.allowed_hosted_domains.is_empty() {
            if !self.allowed_hosted_domains.contains(&hosted_domain) {
                return Err(CoreError::PermissionDenied);
            }
            return Ok(());
        }
        if hosted_domain.is_empty() && self.personal_accounts == "deny" {
            return Err(CoreError::PermissionDenied);
        }
        Ok(())
    }

    fn token_exchange_verifier(
        &self,
        raw_private_state: &[u8],
    ) -> Result<Option<PkceCodeVerifier>, CoreError> {
        if raw_private_state.is_empty() {
            if self.pkce == "required" {
                return Err(CoreError::InvalidArgument(
                    "oidc: pkce code_verifier missing".to_owned(),
                ));
            }
            return Ok(None);
        }
        let private_state: PrivateState =
            serde_json::from_slice(raw_private_state).map_err(|err| {
                CoreError::InvalidArgument(format!("oidc: decode private state: {err}"))
            })?;
        let verifier = private_state.code_verifier.unwrap_or_default();
        if verifier.is_empty() {
            if self.pkce == "required" {
                return Err(CoreError::InvalidArgument(
                    "oidc: pkce code_verifier missing".to_owned(),
                ));
            }
            return Ok(None);
        }
        Ok(Some(PkceCodeVerifier::new(verifier)))
    }
}

#[async_trait]
impl IdentityProvider for Provider {
    fn descriptor(&self) -> IdentityProviderDescriptor {
        IdentityProviderDescriptor {
            id: self.id.clone(),
            provider_type: "oidc".to_owned(),
            display_name: self.display_name.clone(),
            issuer: self.issuer.clone(),
            trust_policy: LoginTrustPolicy {
                email_binding: self.email_binding.clone(),
                allowed_email_domains: self.allowed_email_domains.clone(),
            },
        }
    }

    async fn begin_auth(&self, req: BeginAuthRequest) -> Result<BeginAuthResult, CoreError> {
        self.key_cache.ensure_running().await;
        let client = CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(self.redirect_url()?);
        let state = req.state.clone();
        let nonce = req.nonce.clone();
        let mut auth_request = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            || CsrfToken::new(state),
            || Nonce::new(nonce),
        );
        for scope in &self.scopes {
            // openidconnect always requests the "openid" scope itself; adding
            // it again would send a duplicated scope value on the wire.
            if scope != "openid" {
                auth_request = auth_request.add_scope(Scope::new(scope.clone()));
            }
        }
        if !req.login_hint.is_empty() {
            auth_request = auth_request.add_extra_param("login_hint", req.login_hint);
        }
        auth_request = auth_request.add_extra_param("response_mode", "query");

        let mut private_state = PrivateState::default();
        if self.pkce == "required" {
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            private_state.code_verifier = Some(verifier.secret().clone());
            auth_request = auth_request.set_pkce_challenge(challenge);
        }

        let (mut redirect_url, _, _) = auth_request.url();
        if req.nonce.is_empty() {
            remove_query_param(&mut redirect_url, "nonce");
        }
        let raw_private_state = if private_state.code_verifier.is_some() {
            serde_json::to_vec(&private_state).map_err(|err| {
                CoreError::InvalidArgument(format!("oidc: encode private state: {err}"))
            })?
        } else {
            Vec::new()
        };
        Ok(BeginAuthResult {
            redirect_url: redirect_url.to_string(),
            private_state: raw_private_state,
        })
    }

    async fn complete_auth(&self, req: CompleteAuthRequest) -> Result<ExternalIdentity, CoreError> {
        self.key_cache.ensure_running().await;
        let client = CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(self.redirect_url()?);
        let mut token_request = client
            .exchange_code(AuthorizationCode::new(req.code.clone()))
            .map_err(|err| CoreError::InvalidArgument(format!("oidc: exchange code: {err}")))?;
        if let Some(verifier) = self.token_exchange_verifier(&req.private_state)? {
            token_request = token_request.set_pkce_verifier(verifier);
        }
        let token_response = token_request
            .request_async(&self.http_client)
            .await
            .map_err(|err| {
                warn!(provider_id = %self.id, error = %err, "OIDC token exchange failed");
                CoreError::Unauthenticated
            })?;
        let id_token = token_response.id_token().ok_or_else(|| {
            warn!(provider_id = %self.id, "OIDC token response did not include an ID token");
            CoreError::Unauthenticated
        })?;
        let raw_id_token = id_token.to_string();
        let token_kid = jwt_key_id(&raw_id_token);
        let snapshot = self.key_cache.keys_for_token(token_kid.as_deref()).await?;
        let verification_key_ids = snapshot
            .keys
            .keys()
            .iter()
            .filter_map(|key| key.key_id())
            .collect::<Vec<_>>();
        let expected_nonce = req.nonce.clone();
        let verified_claims = id_token
            .claims(&snapshot.verifier, |actual_nonce: Option<&Nonce>| {
                if expected_nonce.is_empty() {
                    return Ok(());
                }
                match actual_nonce {
                    Some(actual) if actual.secret() == &expected_nonce => Ok(()),
                    _ => Err("oidc: id token nonce mismatch".to_owned()),
                }
            })
            .map_err(|err| {
                warn!(
                    provider_id = %self.id,
                    token_kid = ?token_kid,
                    verification_key_ids = ?verification_key_ids,
                    error = %err,
                    "OIDC ID token validation failed"
                );
                CoreError::Unauthenticated
            })?;
        let raw_claims = jwt_claims(&raw_id_token)?;
        let subject = self.subject(&raw_claims, verified_claims.subject().as_str())?;
        let identity = ExternalIdentity {
            provider_id: self.id.clone(),
            issuer: verified_claims.issuer().as_str().to_owned(),
            subject,
            subject_strategy: self.subject_strategy.clone(),
            email: string_claim(&raw_claims, self.claim("email", "email")),
            email_verified: bool_claim(&raw_claims, self.claim("email_verified", "email_verified")),
            display_name: string_claim(&raw_claims, self.claim("name", "name")),
            picture_url: string_claim(&raw_claims, self.claim("picture", "picture")),
            hosted_domain: string_claim(&raw_claims, self.claim("hosted_domain", "hd")),
            ..ExternalIdentity::default()
        };
        self.validate_trust(&identity)?;
        Ok(identity)
    }
}

fn jwt_key_id(compact_jwt: &str) -> Option<String> {
    let encoded_header = compact_jwt.split('.').next()?;
    let header = URL_SAFE_NO_PAD.decode(encoded_header).ok()?;
    serde_json::from_slice::<Value>(&header)
        .ok()?
        .get("kid")?
        .as_str()
        .map(ToOwned::to_owned)
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PrivateState {
    #[serde(skip_serializing_if = "Option::is_none")]
    code_verifier: Option<String>,
}

fn normalized_config(mut config: Config) -> Result<Config, CoreError> {
    config.provider_id = config.provider_id.trim().to_owned();
    if config.provider_id.is_empty() {
        return Err(CoreError::InvalidArgument(
            "oidc: provider id is required".to_owned(),
        ));
    }
    config.issuer = config.issuer.trim().to_owned();
    if config.issuer.is_empty() {
        return Err(CoreError::InvalidArgument(
            "oidc: issuer is required".to_owned(),
        ));
    }
    config.client_id = config.client_id.trim().to_owned();
    if config.client_id.is_empty() {
        return Err(CoreError::InvalidArgument(
            "oidc: client id is required".to_owned(),
        ));
    }
    config.profile = config.profile.trim().to_owned();
    config.personal_accounts = config.personal_accounts.trim().to_owned();
    match config.personal_accounts.as_str() {
        "" | "allow" | "deny" => {}
        _ => {
            return Err(CoreError::InvalidArgument(format!(
                "oidc: personal_accounts {:?} is unknown",
                config.personal_accounts
            )));
        }
    }
    if !config.personal_accounts.is_empty() && config.profile != "google" {
        return Err(CoreError::InvalidArgument(
            "oidc: personal_accounts is only valid for google profile".to_owned(),
        ));
    }
    Ok(config)
}

fn copy_claim_mapping(mapping: BTreeMap<String, String>) -> BTreeMap<String, String> {
    mapping
        .into_iter()
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn normalize_domain_list(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        let value = value.trim().to_lowercase();
        if value.is_empty() || !seen.insert(value.clone()) {
            continue;
        }
        out.push(value);
    }
    out
}

fn string_claim(claims: &Map<String, Value>, name: &str) -> String {
    claims
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn bool_claim(claims: &Map<String, Value>, name: &str) -> bool {
    match claims.get(name) {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => value.trim().eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn display_name_or_default(display_name: &str, provider_id: &str) -> String {
    let display_name = display_name.trim();
    if display_name.is_empty() {
        provider_id.to_owned()
    } else {
        display_name.to_owned()
    }
}

fn default_string(value: &str, fallback: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    }
}

fn jwt_claims(raw_id_token: &str) -> Result<Map<String, Value>, CoreError> {
    let payload = raw_id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| CoreError::InvalidArgument("oidc: malformed id token".to_owned()))?;
    let raw = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|err| CoreError::InvalidArgument(format!("oidc: decode id token: {err}")))?;
    let value: Value = serde_json::from_slice(&raw).map_err(|err| {
        CoreError::InvalidArgument(format!("oidc: decode id token claims: {err}"))
    })?;
    value.as_object().cloned().ok_or_else(|| {
        CoreError::InvalidArgument("oidc: id token claims must be object".to_owned())
    })
}

fn remove_query_param(url: &mut openidconnect::url::Url, key: &str) {
    let pairs = url
        .query_pairs()
        .filter(|(name, _)| name != key)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in pairs {
            query.append_pair(&name, &value);
        }
    }
}
