use std::path::Path;

use anyhow::Result;
use lore_auth_core::{model::CreateServiceAccountInput, ports::ServiceAccountDirectory};

use crate::{ServiceAccountCommand, core_error, open_env};

pub(crate) async fn run(
    config_path: &Path,
    db: Option<&Path>,
    command: ServiceAccountCommand,
) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let created = match command {
        ServiceAccountCommand::Add(args) => env
            .store
            .create_service_account(CreateServiceAccountInput {
                client_id: args.client_id,
                display_name: args.name,
            })
            .await
            .map_err(core_error)?,
        ServiceAccountCommand::Rotate(args) => env
            .store
            .rotate_service_account_secret(&args.client_id)
            .await
            .map_err(core_error)?,
    };
    println!(
        "{}\t{}\t{}",
        created.account.user.id, created.account.client_id, created.client_secret
    );
    Ok(())
}
