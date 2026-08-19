#!/usr/bin/env bash
# Register a pre-verified Entra user with lore-auth-bridge.
set -euo pipefail

AUTHCTL="${AUTHCTL:-/home/mgs/lore-auth/bin/lore-authctl}"
CONFIG="${CONFIG:-/home/mgs/lore-auth/lore-auth.yaml}"
TENANT_ID="${TENANT_ID:-ec5c9760-1e1d-4de3-a9ff-c2fcf61d617f}"
EMAIL=""
NAME=""
OBJECT_ID=""
REPOSITORY=""
ROLE="writer"

usage() {
  cat <<EOF
Usage: $(basename "$0") --email EMAIL --object-id OBJECT_ID [options]

Register an existing Microsoft Entra ID user and optionally grant repository access.

Options:
  --email EMAIL          User principal email address (required)
  --name NAME            Display name (default: email address)
  --object-id ID         Entra user Object ID (required)
  --repo REPOSITORY      Repository name to grant access to, for example gamestudio/sandbox
  --role ROLE            Repository role: reader, writer, or admin (default: writer)
  --tenant-id ID         Entra tenant ID (default: $TENANT_ID)
  --config PATH          lore-auth.yaml path (default: $CONFIG)
  --authctl PATH         lore-authctl binary path (default: $AUTHCTL)
  -h, --help             Show this help
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email) EMAIL="${2:?missing value for --email}"; shift 2 ;;
    --name) NAME="${2:?missing value for --name}"; shift 2 ;;
    --object-id) OBJECT_ID="${2:?missing value for --object-id}"; shift 2 ;;
    --repo) REPOSITORY="${2:?missing value for --repo}"; shift 2 ;;
    --role) ROLE="${2:?missing value for --role}"; shift 2 ;;
    --tenant-id) TENANT_ID="${2:?missing value for --tenant-id}"; shift 2 ;;
    --config) CONFIG="${2:?missing value for --config}"; shift 2 ;;
    --authctl) AUTHCTL="${2:?missing value for --authctl}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$EMAIL" ]] || die "--email is required"
[[ -n "$OBJECT_ID" ]] || die "--object-id is required"
[[ "$ROLE" =~ ^(reader|writer|admin)$ ]] || die "--role must be reader, writer, or admin"
[[ -x "$AUTHCTL" ]] || die "lore-authctl is not executable: $AUTHCTL"
[[ -r "$CONFIG" ]] || die "config is not readable: $CONFIG"

NAME="${NAME:-$EMAIL}"
EMAIL_LOWER="$(printf '%s' "$EMAIL" | tr '[:upper:]' '[:lower:]')"
SUBJECT="$TENANT_ID:$OBJECT_ID"

user_id="$($AUTHCTL --config "$CONFIG" user list | awk -F '\t' -v email="$EMAIL_LOWER" '
  tolower($2) == email { print $1; exit }
')"
if [[ -z "$user_id" ]]; then
  $AUTHCTL --config "$CONFIG" user add --email "$EMAIL" --name "$NAME"
  user_id="$($AUTHCTL --config "$CONFIG" user list | awk -F '\t' -v email="$EMAIL_LOWER" '
    tolower($2) == email { print $1; exit }
  ')"
fi
[[ -n "$user_id" ]] || die "could not resolve created user: $EMAIL"

$AUTHCTL --config "$CONFIG" user bind-identity \
  --idp entra \
  --email "$EMAIL" \
  --subject "$SUBJECT"

if [[ -n "$REPOSITORY" ]]; then
  grant_exists="$($AUTHCTL --config "$CONFIG" grant list "$REPOSITORY" | awk -F '\t' -v user_id="$user_id" -v role="$ROLE" '
    $2 == "user:" user_id && $4 == role { print "yes"; exit }
  ')"
  if [[ -z "$grant_exists" ]]; then
    $AUTHCTL --config "$CONFIG" grant add "user:$EMAIL" "$REPOSITORY" "$ROLE"
  fi
fi

printf 'Entra user ready: %s (%s)\n' "$EMAIL" "$SUBJECT"
if [[ -n "$REPOSITORY" ]]; then
  printf 'Repository grant: %s %s\n' "$REPOSITORY" "$ROLE"
fi