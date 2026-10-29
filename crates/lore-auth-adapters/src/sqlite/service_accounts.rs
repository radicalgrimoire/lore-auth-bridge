use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{CreateServiceAccountInput, CreatedServiceAccount, ServiceAccount, User},
    ports::ServiceAccountDirectory,
};
use tokio_rusqlite::{
    params,
    rusqlite::{self, OptionalExtension},
};

use super::{
    CoreResult, Store, core_from_driver, core_from_sql, hash_secret, new_id, none_if_empty,
    random_secret, unix_now, user_from_row,
};

#[async_trait]
impl ServiceAccountDirectory for Store {
    async fn create_service_account(
        &self,
        input: CreateServiceAccountInput,
    ) -> CoreResult<CreatedServiceAccount> {
        self.conn
            .call(move |conn| create_service_account_conn(conn, input))
            .await
            .map_err(core_from_driver)
    }

    async fn authenticate_service_account(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> CoreResult<User> {
        let client_id = client_id.to_owned();
        let client_secret = client_secret.to_owned();
        self.conn
            .call(move |conn| authenticate_service_account_conn(conn, &client_id, &client_secret))
            .await
            .map_err(core_from_driver)
    }

    async fn rotate_service_account_secret(
        &self,
        client_id: &str,
    ) -> CoreResult<CreatedServiceAccount> {
        let client_id = client_id.to_owned();
        self.conn
            .call(move |conn| rotate_service_account_secret_conn(conn, &client_id))
            .await
            .map_err(core_from_driver)
    }
}

pub(super) fn create_service_account_conn(
    conn: &rusqlite::Connection,
    input: CreateServiceAccountInput,
) -> CoreResult<CreatedServiceAccount> {
    let client_id = validated_client_id(&input.client_id)?;
    let client_secret = random_secret();
    let now = unix_now();
    let user = User {
        id: new_id(),
        display_name: input.display_name.trim().to_owned(),
        status: "active".to_owned(),
        ..User::default()
    };
    conn.execute(
        "INSERT INTO users (id, display_name, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            user.id,
            none_if_empty(&user.display_name),
            user.status,
            now,
            now
        ],
    )
    .map_err(core_from_sql)?;
    conn.execute(
        "INSERT INTO service_accounts (user_id, client_id, secret_hash, created_at, rotated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user.id, client_id, hash_secret(&client_secret), now, now],
    )
    .map_err(core_from_sql)?;
    Ok(CreatedServiceAccount {
        account: ServiceAccount { user, client_id },
        client_secret,
    })
}

pub(super) fn authenticate_service_account_conn(
    conn: &rusqlite::Connection,
    client_id: &str,
    client_secret: &str,
) -> CoreResult<User> {
    let client_id = validated_client_id(client_id)?;
    if client_secret.trim().is_empty() {
        return Err(CoreError::Unauthenticated);
    }
    let (user, expected_hash) = conn
        .query_row(
            "SELECT u.id, u.primary_email, u.display_name, u.status, COALESCE(u.last_login_at, 0),
                    sa.secret_hash
             FROM service_accounts sa
             JOIN users u ON u.id = sa.user_id
             WHERE sa.client_id = ?1 AND u.status = 'active'",
            params![client_id],
            |row| Ok((user_from_row(row)?, row.get::<_, String>(5)?)),
        )
        .optional()
        .map_err(core_from_sql)?
        .ok_or(CoreError::Unauthenticated)?;
    if !constant_time_eq(
        expected_hash.as_bytes(),
        hash_secret(client_secret).as_bytes(),
    ) {
        return Err(CoreError::Unauthenticated);
    }
    Ok(user)
}

pub(super) fn rotate_service_account_secret_conn(
    conn: &rusqlite::Connection,
    client_id: &str,
) -> CoreResult<CreatedServiceAccount> {
    let client_id = validated_client_id(client_id)?;
    let client_secret = random_secret();
    let user = conn
        .query_row(
            "SELECT u.id, u.primary_email, u.display_name, u.status, COALESCE(u.last_login_at, 0)
             FROM service_accounts sa JOIN users u ON u.id = sa.user_id
             WHERE sa.client_id = ?1 AND u.status = 'active'",
            params![client_id],
            user_from_row,
        )
        .optional()
        .map_err(core_from_sql)?
        .ok_or(CoreError::NotFound)?;
    let changed = conn
        .execute(
            "UPDATE service_accounts SET secret_hash = ?1, rotated_at = ?2 WHERE client_id = ?3",
            params![hash_secret(&client_secret), unix_now(), client_id],
        )
        .map_err(core_from_sql)?;
    if changed != 1 {
        return Err(CoreError::NotFound);
    }
    Ok(CreatedServiceAccount {
        account: ServiceAccount { user, client_id },
        client_secret,
    })
}

fn validated_client_id(value: &str) -> CoreResult<String> {
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
