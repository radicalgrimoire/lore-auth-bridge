use std::path::Path;

use anyhow::{Result, anyhow, bail};
use lore_auth_core::{
    model::CreateServiceAccountInput,
    ports::{GroupQuery, ServiceAccountAdmin, ServiceAccountDirectory},
};

use crate::{ServiceAccountCommand, authctl_actor, core_error, open_env};

pub(crate) async fn run(
    config_path: &Path,
    db: Option<&Path>,
    command: ServiceAccountCommand,
) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let created = match command {
        ServiceAccountCommand::Add(args) => {
            let group = args.group.trim();
            if group.is_empty() {
                bail!("group must not be empty");
            }
            let groups = env.store.list_groups().await.map_err(core_error)?;
            let group_id = groups
                .iter()
                .find(|entry| entry.id == group)
                .or_else(|| groups.iter().find(|entry| entry.name == group))
                .map(|entry| entry.id.as_str())
                .ok_or_else(|| anyhow!("group not found: {group}"))?;
            env.store
                .audited(authctl_actor())
                .create_service_account_in_group(
                    CreateServiceAccountInput {
                        client_id: args.client_id,
                        display_name: args.name,
                    },
                    group_id,
                )
                .await
                .map_err(core_error)?
        }
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
