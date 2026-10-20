//! User account and invitation command implementations.

use std::path::Path;

use anyhow::Result;
use lore_auth_core::{
    model::{AddInvitationInput, AddUserInput, ExternalIdentity, UserListFilter},
    ports::{AccountDirectory, AccountQuery},
};

use crate::{UserCommand, authctl_actor, core_error, open_env, resolve_user_idp, value};

pub(crate) async fn run(config_path: &Path, db: Option<&Path>, command: UserCommand) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let audited = env.store.audited(authctl_actor());
    match command {
        UserCommand::Invite(args) => {
            let (provider_id, issuer) =
                resolve_user_idp(&env.cfg, args.idp.as_deref(), &args.provider, &args.issuer)?;
            let (user, _) = audited
                .add_invitation(AddInvitationInput {
                    provider_id,
                    issuer,
                    email: args.email,
                    display_name: args.name,
                    binding_policy: "verified_email_invitation".to_owned(),
                    expires_at: 0,
                })
                .await
                .map_err(core_error)?;
            println!("{}\t{}\t{}", user.id, value(&user.email), user.status);
        }
        UserCommand::Add(args) => {
            let user = audited
                .add_user(AddUserInput {
                    email: args.email,
                    display_name: args.name,
                })
                .await
                .map_err(core_error)?;
            println!("{}\t{}\t{}", user.id, value(&user.email), user.status);
        }
        UserCommand::BindIdentity(args) => {
            let (provider_id, issuer) = resolve_user_idp(&env.cfg, Some(&args.idp), "", "")?;
            let provider = env
                .cfg
                .identity_providers
                .providers
                .get(&provider_id)
                .expect("configured provider");
            let identity = audited
                .bind_external_identity(ExternalIdentity {
                    provider_id,
                    issuer,
                    subject: args.subject,
                    subject_strategy: provider.subject.strategy.clone(),
                    email: args.email.clone(),
                    status: "active".to_owned(),
                    ..ExternalIdentity::default()
                })
                .await
                .map_err(core_error)?;
            println!(
                "{}\t{}\t{}",
                identity.user_id, identity.subject, identity.status
            );
        }
        UserCommand::List => {
            for user in env
                .store
                .list_users(UserListFilter {
                    query: String::new(),
                    limit: usize::MAX,
                })
                .await
                .map_err(core_error)?
            {
                let subject = if user.status == "pending" {
                    String::new()
                } else {
                    user.bridge_subject()
                };
                println!(
                    "{}\t{}\t{}\t{}",
                    user.id,
                    value(&user.email),
                    subject,
                    user.status
                );
            }
        }
        UserCommand::Disable(args) => {
            audited.disable_user(&args.user).await.map_err(core_error)?;
            println!("disabled");
        }
        UserCommand::Enable(args) => {
            audited.enable_user(&args.user).await.map_err(core_error)?;
            println!("enabled");
        }
    }
    Ok(())
}
