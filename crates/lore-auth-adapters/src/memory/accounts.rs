//! Account directory and account query behavior for the memory adapter.
//! Handles login resolution, invitation binding, and user list/search reads.

use async_trait::async_trait;
use lore_auth_core::{
    CoreError,
    model::{
        AddInvitationInput, AddUserInput, AddUserWithIdentityInput, ExternalIdentity,
        IdentityInvitation, LoginBindingResult, LoginResolutionRequest, TokenPrincipal,
        UpdateEntraIdentityInput, User, UserListFilter,
    },
    ports::{AccountDirectory, AccountQuery},
};

use super::{
    State, Store, active_user, allows_verified_email_invitation_binding, effective_limit,
    email_domain_allowed, external_identity_key, now_unix, principal_from_user, resolve_user_id,
    validated_account_email,
};

pub(super) fn update_user_display_name_locked(
    state: &mut State,
    user_id: &str,
    display_name: &str,
) -> Result<(), CoreError> {
    let display_name = display_name.trim();
    if display_name.is_empty() {
        return Err(CoreError::InvalidArgument(
            "display name is required".to_owned(),
        ));
    }
    let user = state
        .users
        .get_mut(user_id)
        .filter(|user| user.status != "deleted")
        .ok_or(CoreError::NotFound)?;
    user.display_name = display_name.to_owned();
    Ok(())
}

pub(super) fn update_entra_identity_locked(
    state: &mut State,
    input: &UpdateEntraIdentityInput,
) -> Result<(), CoreError> {
    if input.subject.trim().is_empty() {
        return Err(CoreError::InvalidArgument("subject is required".to_owned()));
    }
    state
        .users
        .get(&input.user_id)
        .filter(|user| user.status != "deleted")
        .ok_or(CoreError::NotFound)?;
    let (old_key, mut identity) = state
        .identities
        .iter()
        .find(|(_, identity)| identity.id == input.identity_id && identity.user_id == input.user_id)
        .map(|(key, identity)| (key.clone(), identity.clone()))
        .ok_or(CoreError::NotFound)?;
    if identity.subject_strategy != "entra_oid_tid"
        || identity.provider_id != input.provider_id
        || identity.issuer != input.issuer
        || identity.subject != input.expected_subject
    {
        return Err(CoreError::InvalidArgument(
            "identity changed or provider does not match; reload the page".to_owned(),
        ));
    }
    identity.subject = input.subject.clone();
    let new_key = external_identity_key(&identity);
    if new_key != old_key && state.identities.contains_key(&new_key) {
        return Err(CoreError::InvalidArgument(
            "external identity is already bound to another user or is inactive".to_owned(),
        ));
    }
    state.identities.remove(&old_key);
    state.identities.insert(new_key, identity);
    Ok(())
}

pub(super) fn add_user_with_identity_locked(
    state: &mut State,
    input: AddUserWithIdentityInput,
) -> Result<(User, ExternalIdentity), CoreError> {
    let email = validated_account_email(&input.email)?;
    let identity = ExternalIdentity {
        provider_id: input.provider_id.trim().to_owned(),
        issuer: input.issuer.trim().to_owned(),
        subject: input.subject.trim().to_owned(),
        subject_strategy: input.subject_strategy.trim().to_owned(),
        ..ExternalIdentity::default()
    };
    if identity.provider_id.is_empty()
        || identity.issuer.is_empty()
        || identity.subject.is_empty()
        || identity.subject_strategy.is_empty()
    {
        return Err(CoreError::InvalidArgument(
            "provider_id, issuer, subject, and subject_strategy are required".to_owned(),
        ));
    }
    let key = external_identity_key(&identity);
    if state.identities.contains_key(&key) {
        return Err(CoreError::InvalidArgument(
            "external identity is already bound to another user or is inactive".to_owned(),
        ));
    }
    let user = User {
        id: uuid::Uuid::new_v4().to_string(),
        email: email.clone(),
        display_name: input.display_name,
        status: "active".to_owned(),
        last_login_at: 0,
    };
    let identity = ExternalIdentity {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user.id.clone(),
        email,
        status: "active".to_owned(),
        ..identity
    };
    state.users.insert(user.id.clone(), user.clone());
    state.identities.insert(key, identity.clone());
    Ok((user, identity))
}

#[async_trait]
impl AccountDirectory for Store {
    async fn update_entra_identity(
        &self,
        input: UpdateEntraIdentityInput,
    ) -> Result<(), CoreError> {
        update_entra_identity_locked(&mut self.lock(), &input)
    }

    async fn update_user_display_name(
        &self,
        user_id: &str,
        display_name: &str,
    ) -> Result<(), CoreError> {
        update_user_display_name_locked(&mut self.lock(), user_id, display_name)
    }

    async fn resolve_login(
        &self,
        req: LoginResolutionRequest,
    ) -> Result<(TokenPrincipal, LoginBindingResult), CoreError> {
        let identity = req.identity;
        let key = external_identity_key(&identity);
        let mut state = self.lock();
        if state.service_accounts.contains_key(&identity.user_id) {
            return Err(CoreError::PermissionDenied);
        }
        if let Some(existing) = state
            .identities
            .get(&key)
            .filter(|existing| existing.status == "active")
            .cloned()
        {
            let user = active_user(&state, &existing.user_id)?;
            return Ok((
                principal_from_user(
                    user,
                    &identity.provider_id,
                    state
                        .group_members
                        .get(&existing.user_id)
                        .cloned()
                        .unwrap_or_default(),
                ),
                LoginBindingResult {
                    status: "existing".to_owned(),
                    external_identity_id: existing.id,
                    invitation_id: String::new(),
                },
            ));
        }

        if identity.email_verified
            && !identity.email.trim().is_empty()
            && allows_verified_email_invitation_binding(&req.policy)
            && email_domain_allowed(&identity.email, &req.policy.allowed_email_domains)
        {
            let now = now_unix();
            let invitation_id = state
                .invitations
                .iter()
                .find(|(_, invitation)| {
                    invitation.provider_id == identity.provider_id
                        && invitation.issuer == identity.issuer
                        && invitation.status == "pending"
                        && (invitation.expires_at == 0 || invitation.expires_at > now)
                        && invitation.binding_policy.trim() == "verified_email_invitation"
                        && invitation
                            .email
                            .trim()
                            .eq_ignore_ascii_case(identity.email.trim())
                })
                .map(|(id, _)| id.clone());
            if let Some(invitation_id) = invitation_id {
                let invitation = state
                    .invitations
                    .get(&invitation_id)
                    .cloned()
                    .ok_or(CoreError::NotFound)?;
                let mut external = identity.clone();
                external.id = uuid::Uuid::new_v4().to_string();
                external.user_id = invitation.user_id.clone();
                if external.subject_strategy.is_empty() {
                    external.subject_strategy = "oidc_sub".to_owned();
                }
                external.status = "active".to_owned();
                let external_identity_id = external.id.clone();
                state.identities.insert(key, external);

                let user = state
                    .users
                    .get_mut(&invitation.user_id)
                    .ok_or(CoreError::NotFound)?;
                user.email = identity.email.clone();
                user.display_name = identity.display_name.clone();
                user.status = "active".to_owned();
                if let Some(invitation) = state.invitations.get_mut(&invitation_id) {
                    invitation.status = "accepted".to_owned();
                    invitation.accepted_identity_id = external_identity_id.clone();
                }

                let user = active_user(&state, &invitation.user_id)?;
                return Ok((
                    principal_from_user(
                        user,
                        &identity.provider_id,
                        state
                            .group_members
                            .get(&invitation.user_id)
                            .cloned()
                            .unwrap_or_default(),
                    ),
                    LoginBindingResult {
                        status: "bound_invitation".to_owned(),
                        external_identity_id,
                        invitation_id,
                    },
                ));
            }
        }

        Err(CoreError::NotFound)
    }

    async fn principal_by_user_id(&self, user_id: &str) -> Result<TokenPrincipal, CoreError> {
        let state = self.lock();
        let user = active_user(&state, user_id)?;
        Ok(principal_from_user(
            user,
            "bridge",
            state
                .group_members
                .get(user_id)
                .cloned()
                .unwrap_or_default(),
        ))
    }

    async fn principal_by_authn_token_jti(&self, jti: &str) -> Result<TokenPrincipal, CoreError> {
        let state = self.lock();
        let issued = state
            .issued_tokens
            .get(jti)
            .filter(|token| {
                token.kind == "authn" && token.expires_at > now_unix() && !token.user_id.is_empty()
            })
            .ok_or(CoreError::NotFound)?;
        let user = state
            .users
            .get(&issued.user_id)
            .filter(|user| user.status == "active")
            .ok_or(CoreError::NotFound)?;
        Ok(principal_from_user(
            user,
            "bridge",
            state
                .group_members
                .get(&issued.user_id)
                .cloned()
                .unwrap_or_default(),
        ))
    }

    async fn principal_by_authz_token_jti(
        &self,
        jti: &str,
        resource_id: &str,
    ) -> Result<TokenPrincipal, CoreError> {
        let state = self.lock();
        let issued = state
            .issued_tokens
            .get(jti)
            .filter(|token| {
                token.kind == "authz"
                    && token.lore_resource_id == resource_id
                    && token.expires_at > now_unix()
                    && !token.user_id.is_empty()
            })
            .ok_or(CoreError::NotFound)?;
        let user = state
            .users
            .get(&issued.user_id)
            .filter(|user| user.status == "active")
            .ok_or(CoreError::NotFound)?;
        Ok(principal_from_user(
            user,
            "bridge",
            state
                .group_members
                .get(&user.id)
                .cloned()
                .unwrap_or_default(),
        ))
    }

    async fn add_user(&self, input: AddUserInput) -> Result<User, CoreError> {
        let email = validated_account_email(&input.email)?;
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email,
            display_name: input.display_name,
            status: "active".to_owned(),
            last_login_at: 0,
        };
        self.lock().users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn add_user_with_identity(
        &self,
        input: AddUserWithIdentityInput,
    ) -> Result<(User, ExternalIdentity), CoreError> {
        add_user_with_identity_locked(&mut self.lock(), input)
    }

    async fn add_invitation(
        &self,
        input: AddInvitationInput,
    ) -> Result<(User, IdentityInvitation), CoreError> {
        if input.provider_id.trim().is_empty() || input.issuer.trim().is_empty() {
            return Err(CoreError::InvalidArgument(
                "provider_id, issuer, and email are required".to_owned(),
            ));
        }
        let email = validated_account_email(&input.email)?;

        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.clone(),
            display_name: input.display_name,
            status: "pending".to_owned(),
            last_login_at: 0,
        };
        let invitation = IdentityInvitation {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            provider_id: input.provider_id,
            issuer: input.issuer,
            email,
            binding_policy: if input.binding_policy.trim().is_empty() {
                "verified_email_invitation".to_owned()
            } else {
                input.binding_policy
            },
            status: "pending".to_owned(),
            expires_at: input.expires_at,
            ..IdentityInvitation::default()
        };
        let mut state = self.lock();
        state.users.insert(user.id.clone(), user.clone());
        state
            .invitations
            .insert(invitation.id.clone(), invitation.clone());
        Ok((user, invitation))
    }

    async fn disable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let user_id = resolve_user_id(&state, user_id_or_email)?.to_owned();
        let user = state.users.get_mut(&user_id).ok_or(CoreError::NotFound)?;
        user.status = "disabled".to_owned();
        Ok(())
    }

    async fn enable_user(&self, user_id_or_email: &str) -> Result<(), CoreError> {
        let mut state = self.lock();
        let user_id = resolve_user_id(&state, user_id_or_email)?.to_owned();
        let user = state.users.get_mut(&user_id).ok_or(CoreError::NotFound)?;
        if user.status != "deleted" {
            user.status = "active".to_owned();
            Ok(())
        } else {
            Err(CoreError::NotFound)
        }
    }
}

#[async_trait]
impl AccountQuery for Store {
    async fn external_identities_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<ExternalIdentity>, CoreError> {
        let state = self.lock();
        let mut identities: Vec<_> = state
            .identities
            .values()
            .filter(|identity| identity.user_id == user_id)
            .cloned()
            .collect();
        identities.sort_by(|a, b| {
            (&a.provider_id, &a.issuer, &a.subject).cmp(&(&b.provider_id, &b.issuer, &b.subject))
        });
        Ok(identities)
    }

    async fn user_by_id(&self, user_id: &str) -> Result<User, CoreError> {
        self.lock()
            .users
            .get(user_id)
            .filter(|user| user.status != "deleted")
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn list_users(&self, filter: UserListFilter) -> Result<Vec<User>, CoreError> {
        let query = filter.query.trim().to_ascii_lowercase();
        let limit = effective_limit(filter.limit);
        let mut out = self
            .lock()
            .users
            .values()
            .filter(|user| user.status != "deleted")
            .filter(|user| {
                query.is_empty()
                    || lore_auth_core::model::normalize_email(&user.email).contains(&query)
                    || user.display_name.to_ascii_lowercase().contains(&query)
            })
            .cloned()
            .collect::<Vec<_>>();
        out.sort_by(|left, right| {
            let left_key = (
                lore_auth_core::model::normalize_email(&left.email),
                &left.id,
            );
            let right_key = (
                lore_auth_core::model::normalize_email(&right.email),
                &right.id,
            );
            left_key.cmp(&right_key)
        });
        out.truncate(limit);
        Ok(out)
    }
}
