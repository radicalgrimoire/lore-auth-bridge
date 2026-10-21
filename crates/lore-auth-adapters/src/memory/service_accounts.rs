use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{CreateServiceAccountInput, CreatedServiceAccount, ServiceAccount, User},
    ports::ServiceAccountDirectory,
};

use super::{ServiceAccountCredential, Store, hash_secret, random_secret};

#[async_trait]
impl ServiceAccountDirectory for Store {
    async fn create_service_account(
        &self,
        input: CreateServiceAccountInput,
    ) -> Result<CreatedServiceAccount, CoreError> {
        let client_id = validated_client_id(&input.client_id)?;
        let client_secret = random_secret();
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            display_name: input.display_name.trim().to_owned(),
            status: "active".to_owned(),
            ..User::default()
        };
        let mut state = self.lock();
        if state
            .service_accounts
            .values()
            .any(|account| account.client_id == client_id)
        {
            return Err(CoreError::InvalidArgument(
                "service account client_id already exists".to_owned(),
            ));
        }
        state.users.insert(user.id.clone(), user.clone());
        state.service_accounts.insert(
            user.id.clone(),
            ServiceAccountCredential {
                client_id: client_id.clone(),
                secret_hash: hash_secret(&client_secret),
            },
        );
        Ok(CreatedServiceAccount {
            account: ServiceAccount { user, client_id },
            client_secret,
        })
    }

    async fn authenticate_service_account(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<User, CoreError> {
        let client_id = validated_client_id(client_id)?;
        let state = self.lock();
        let (user_id, account) = state
            .service_accounts
            .iter()
            .find(|(_, account)| account.client_id == client_id)
            .ok_or(CoreError::Unauthenticated)?;
        if !constant_time_eq(
            account.secret_hash.as_bytes(),
            hash_secret(client_secret).as_bytes(),
        ) {
            return Err(CoreError::Unauthenticated);
        }
        state
            .users
            .get(user_id)
            .filter(|user| user.status == "active")
            .cloned()
            .ok_or(CoreError::Unauthenticated)
    }

    async fn rotate_service_account_secret(
        &self,
        client_id: &str,
    ) -> Result<CreatedServiceAccount, CoreError> {
        let client_id = validated_client_id(client_id)?;
        let client_secret = random_secret();
        let mut state = self.lock();
        let user_id = state
            .service_accounts
            .iter()
            .find_map(|(user_id, account)| {
                (account.client_id == client_id).then(|| user_id.clone())
            })
            .ok_or(CoreError::NotFound)?;
        let user = state
            .users
            .get(&user_id)
            .filter(|user| user.status == "active")
            .cloned()
            .ok_or(CoreError::NotFound)?;
        let account = state
            .service_accounts
            .get_mut(&user_id)
            .ok_or(CoreError::NotFound)?;
        account.secret_hash = hash_secret(&client_secret);
        Ok(CreatedServiceAccount {
            account: ServiceAccount { user, client_id },
            client_secret,
        })
    }
}

fn validated_client_id(value: &str) -> Result<String, CoreError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CoreError::InvalidArgument(
            "client_id must be 1-128 ASCII letters, digits, '.', '-', or '_'".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    let mut mismatch = expected.len() ^ actual.len();
    let max_len = expected.len().max(actual.len());
    for index in 0..max_len {
        mismatch |= usize::from(
            expected.get(index).copied().unwrap_or_default()
                ^ actual.get(index).copied().unwrap_or_default(),
        );
    }
    mismatch == 0
}
