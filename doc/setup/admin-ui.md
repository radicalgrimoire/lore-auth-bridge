# Admin Web UI

[日本語](admin-ui.ja.md)

The admin Web UI is served by the same HTTP process as login, JWKS, device flow, and health checks.

The admin Web UI is available in English only.

It is mounted under `/admin` only when `admin.admin_emails` contains at least one address.

If `admin.admin_emails` is omitted or empty, `/admin` is not mounted and returns 404.

## Enable The UI

Add the admin section to `lore-auth.yaml`.

```yaml
admin:
  admin_emails:
    - "admin@example.com"
```

The listed addresses are normalized before comparison.

An operator can open `/admin` directly. If not signed in, they are redirected to OIDC login and returned to `/admin` afterward. The signed-in active user's email must still match `admin.admin_emails`.

An unauthenticated GET to `/admin` redirects to login, so it reveals that the admin UI is enabled. Non-admin users, disallowed peers, and unauthenticated requests to other admin routes still receive 404.

## Network Controls

`/admin` shares the public HTTP listener.

In production, put the bridge behind a reverse proxy such as NGINX or Caddy and restrict `/admin` at that edge.

Use CDN or WAF controls such as Cloudflare when the deployment needs source restrictions or stronger rate limiting at the public boundary.

The bridge also supports a second layer of peer filtering.

```yaml
security:
  admin_allowed_peer_cidrs:
    - "127.0.0.1/32"
```

This check uses the TCP peer address seen directly by the bridge.

Behind a reverse proxy, allow the proxy address and enforce the public admin allowlist at the proxy.

The bridge does not trust `X-Forwarded-For` for this check.

In a minimal deployment without a reverse proxy, the only admin protections are OIDC login, `admin.admin_emails`, and the optional `security.admin_allowed_peer_cidrs` setting.

## Features

The UI can browse and search repositories, users, groups, grants, and user access.

It can add and disable users, create repositories, disable authorization records, manage grants, and manage groups.

To enable repository creation, configure `lore.repository_create_url` with the Lore server's gRPC endpoint, for example `http://127.0.0.1:41337` when the services run on the same host. Plain HTTP is permitted only for loopback IP addresses; other endpoints require HTTPS with a certificate trusted by the host. An empty setting disables creation. The Lore server must support `lore.repository.v1.RepositoryService` and synchronize resources to this bridge through ReBAC.

The Repositories form creates a repository with a `main` branch on Lore. Name is required; optional Organization prefixes it as `Organization/Name`. Each segment uses ASCII letters, digits, `-`, `_`, and `.`, and cannot start with a dot. The creation request uses the signed-in administrator's identity. The bridge verifies the synchronized authorization record and records an admin audit entry after creation. Lore creation, synchronization, and auditing cannot share one transaction: if the UI reports an uncertain or partial result, check the repository and authorization record using the displayed repository ID before retrying.

Server settings can enable maintenance mode and set a deletion wait in minutes (default 15). Maintenance state persists across restarts and blocks new token issuance through the server and authctl, but does not revoke already issued tokens. The wait setting is not enforced yet. Administrators must account for custom token lifetimes and Lore's expiry tolerance.

Repository View access lists and searches direct user and group grants and allows adding or removing them. Access inherited through groups and server administrator privileges is not listed as a direct grant. Disabling requires maintenance mode and preserves grants. Once disabled, the confirmed bulk grant removal removes all direct grants for that repository; enabling does not restore removed grants. Repository deletion from this UI is unavailable until Lore deletion and recovery are implemented; it does not delete the Lore repository or its authorization record. Each implemented management action and its audit entry are atomic. CLI and ReBAC deletion retain their existing behavior.

When an Entra ID provider with `subject.strategy: entra_oid_tid` is configured, the Users page shows an "Add Entra ID user" form. Entering the email, display name, and Entra ID Object ID is equivalent to running `lore-authctl user add` and `user bind-identity --idp entra` in a single transaction, so the user can sign in immediately. The subject is stored as `<required_tid>:<object ID>`. The display name defaults to the email.

Adding a user directly is an advanced operation that creates an account without login binding.

Server settings can create a service account with a Client ID, optional display name (defaults to the Client ID), and an existing group. Creation, group membership, and both audit entries are atomic. The generated Client Secret is shown only in the creation response; save it in a secure credential store. If lost, rotate it with `lore-authctl service-account rotate`. The form does not configure repository grants or network CIDRs. Configure allowed CIDRs on the group's View access page or with `lore-authctl`; service-account authentication is denied unless the client IP matches an applicable CIDR.

On a user's View access page, administrators can change the display name and view bound Entra ID tenant and object IDs. The IDs come from stored bindings, not a live Entra ID lookup.

The Groups page lists groups by name and internal ID. Open View access to search direct members by name, email or user ID, add a member by email or user ID, and remove direct members. The group and member lists are not truncated. The Actions column in the group list is reserved for future operations.

View access also lists, adds, and removes the group's allowed source IP networks. Enter an IPv4 or IPv6 address, or a CIDR network; single addresses become `/32` or `/128`. Networks are normalized to their network address. Applicable CIDRs across all of a user's groups are combined: a normal user with no applicable CIDRs has no IP restriction at login, while service-account authentication requires at least one matching CIDR. Changes do not revoke issued tokens.

The IDs can also be corrected there. The tenant ID must match the provider's configured `required_tid`. Changes affect future sign-ins and do not revoke existing sessions or issued tokens.

The View access page lists all active repositories with their name, resource ID, and a direct user role selector. Choose None, Reader, Writer, or Admin for each repository and save once. Effective permissions, including group and server-admin access, are displayed separately and are not changed by this form. If a repository already has multiple direct roles, "Keep existing roles" preserves them unless another option is selected. Changes and audit records are committed together; stale grant snapshots cause the save to fail. Previously issued tokens are not revoked by these changes. The form has an 8 MiB request-size limit.

Neither the Groups page nor `lore-authctl` can create nested groups. The one-time `phase7_remove_existing_group_nests_20261030` migration removes all existing group-to-group memberships and records each removal in the admin audit. It runs when the server or `lore-authctl` opens the database. Back up the database and review inherited repository access and service-account CIDRs before upgrading; existing tokens are not revoked. Any remaining nested groups can be displayed and removed in the UI or with the CLI.

The check simulator is available under Server settings at `/admin/server-settings/simulator`. It runs the configured authorization policy for a user, repository, and action.

The simulator also shows grant evidence, including nested group paths, as helper information.

When `admin.global_repository_admin` is enabled, applicable implicit access is labeled as server administrator evidence; it is not a stored grant. See [Configuration](configuration.md#admin).

The policy result is authoritative.

Admin mutations are recorded in `admin_audit`.

For direct SQLite inspection:

```bash
sqlite3 /var/lib/lore-auth/auth.sqlite3 \
  "SELECT created_at, actor, action, object_type, object_id, detail FROM admin_audit ORDER BY created_at DESC LIMIT 20;"
```

## Recovery

For admin re-enable and IdP-outage procedures, see [Operations](operations.md#recovery).
