#!/usr/bin/env bash
# Build a self-contained local Lore + lore-auth-bridge stack on Ubuntu/WSL.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BRIDGE_SOURCE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LORE_SOURCE_DIR="$(cd -- "$BRIDGE_SOURCE_DIR/../lore" 2>/dev/null && pwd || printf '%s' "$BRIDGE_SOURCE_DIR/../lore")"

# Change this default, or pass --install-dir, to choose where the local stack lives.
INSTALL_DIR="${INSTALL_DIR:-$HOME/lore-local}"
HOSTNAME="localhost"
SIGNING_KEY_KID="lore-local-01"
SEED_USER_EMAIL=""
INVITE_USER_EMAIL=""
ENTRA_TENANT_ID=""
ENTRA_CLIENT_ID=""
ENTRA_CLIENT_SECRET_FILE=""
ENTRA_ALLOWED_EMAIL_DOMAIN=""
RENEW_CERT=0
SKIP_APT=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Build the current Lore and lore-auth-bridge source trees for a local Ubuntu/WSL stack.

Options:
  --install-dir DIR         Local stack directory (default: $INSTALL_DIR)
  --bridge-source-dir DIR  lore-auth-bridge source directory (default: $BRIDGE_SOURCE_DIR)
  --lore-source-dir DIR    Lore source directory (default: $LORE_SOURCE_DIR)
  --hostname HOST           Host used in local URLs and certificate SAN (default: $HOSTNAME)
  --signing-key-kid KID    JWT signing key ID (default: $SIGNING_KEY_KID)
  --seed-user EMAIL        Create a no-IdP local user when it does not exist
  --invite-user EMAIL      Invite an Entra ID user when it does not exist
  --entra-tenant-id ID     Enable Microsoft Entra ID for this tenant
  --entra-client-id ID     Entra application (client) ID
  --entra-client-secret-file PATH
                            File containing the Entra client secret
  --entra-allowed-email-domain DOMAIN
                            Restrict invitation email binding to this domain
  --renew-cert             Replace the existing self-signed gRPC certificate
  --skip-apt               Do not install Ubuntu build prerequisites
  -h, --help               Show this help

The installer writes only beneath --install-dir. It does not install or start
systemd units, nginx, or an external identity provider. Start the two services
with bin/start-bridge.sh and bin/start-loreserver.sh after installation.

When the source trees are on /mnt/<drive>, they are mirrored into the Linux
filesystem below --install-dir before building. This avoids WSL file-operation
limitations in Cargo build scripts.

For a local Entra ID test, register this exact redirect URI in the Entra app:
  http://localhost:8080/auth/entra/callback
EOF
}

validate_idp_options() {
  local configured=0
  for value in "$ENTRA_TENANT_ID" "$ENTRA_CLIENT_ID" "$ENTRA_CLIENT_SECRET_FILE"; do
    [[ -n "$value" ]] && configured=1
  done

  if [[ "$configured" -eq 0 ]]; then
    [[ -z "$INVITE_USER_EMAIL" ]] || die "--invite-user requires the Entra ID options"
    return
  fi

  [[ -n "$ENTRA_TENANT_ID" ]] || die "--entra-tenant-id is required when Entra ID is enabled"
  [[ -n "$ENTRA_CLIENT_ID" ]] || die "--entra-client-id is required when Entra ID is enabled"
  [[ -n "$ENTRA_CLIENT_SECRET_FILE" ]] || die "--entra-client-secret-file is required when Entra ID is enabled"
  [[ -r "$ENTRA_CLIENT_SECRET_FILE" ]] || die "Entra client secret file is not readable: $ENTRA_CLIENT_SECRET_FILE"
  [[ -z "$SEED_USER_EMAIL" ]] || die "--seed-user is only for no-IdP testing; use --invite-user with Entra ID"
}

log() {
  printf '[lore-local] %s\n' "$*"
}

die() {
  printf '[lore-local] ERROR: %s\n' "$*" >&2
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --install-dir)
        INSTALL_DIR="${2:?missing value for --install-dir}"; shift 2 ;;
      --bridge-source-dir)
        BRIDGE_SOURCE_DIR="${2:?missing value for --bridge-source-dir}"; shift 2 ;;
      --lore-source-dir)
        LORE_SOURCE_DIR="${2:?missing value for --lore-source-dir}"; shift 2 ;;
      --hostname)
        HOSTNAME="${2:?missing value for --hostname}"; shift 2 ;;
      --signing-key-kid)
        SIGNING_KEY_KID="${2:?missing value for --signing-key-kid}"; shift 2 ;;
      --seed-user)
        SEED_USER_EMAIL="${2:?missing value for --seed-user}"; shift 2 ;;
      --invite-user)
        INVITE_USER_EMAIL="${2:?missing value for --invite-user}"; shift 2 ;;
      --entra-tenant-id)
        ENTRA_TENANT_ID="${2:?missing value for --entra-tenant-id}"; shift 2 ;;
      --entra-client-id)
        ENTRA_CLIENT_ID="${2:?missing value for --entra-client-id}"; shift 2 ;;
      --entra-client-secret-file)
        ENTRA_CLIENT_SECRET_FILE="${2:?missing value for --entra-client-secret-file}"; shift 2 ;;
      --entra-allowed-email-domain)
        ENTRA_ALLOWED_EMAIL_DOMAIN="${2:?missing value for --entra-allowed-email-domain}"; shift 2 ;;
      --renew-cert)
        RENEW_CERT=1; shift ;;
      --skip-apt)
        SKIP_APT=1; shift ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        die "unknown option: $1" ;;
    esac
  done
}

ensure_sources() {
  [[ -f "$BRIDGE_SOURCE_DIR/Cargo.toml" ]] || die "bridge source not found: $BRIDGE_SOURCE_DIR"
  [[ -f "$LORE_SOURCE_DIR/Cargo.toml" ]] || die "Lore source not found: $LORE_SOURCE_DIR"
}

install_packages() {
  if [[ "$SKIP_APT" -eq 1 ]]; then
    log "Skipping Ubuntu package installation"
    return
  fi

  command -v sudo >/dev/null 2>&1 || die "sudo is required; use --skip-apt when prerequisites are already installed"
  log "Installing Ubuntu build prerequisites"
  sudo apt-get update
  sudo apt-get install -y build-essential ca-certificates cmake curl git libssl-dev openssl pkg-config rsync
}

ensure_rust() {
  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    log "Using existing Rust toolchain: $(rustc --version)"
    return
  fi

  log "Installing Rust with rustup for $(id -un)"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  export PATH="$HOME/.cargo/bin:$PATH"
  command -v cargo >/dev/null 2>&1 || die "cargo was not installed by rustup"
}

prepare_build_workspace() {
  BUILD_DIR="$INSTALL_DIR/.build"
  BUILD_BRIDGE_DIR="$BUILD_DIR/lore-auth-bridge"
  BUILD_LORE_DIR="$BUILD_DIR/lore"
  mkdir -p "$BUILD_BRIDGE_DIR" "$BUILD_LORE_DIR"

  command -v rsync >/dev/null 2>&1 || die "rsync is required to prepare the Linux build workspace"
  log "Mirroring bridge source into Linux build workspace"
  rsync -a --delete --exclude .git --exclude target "$BRIDGE_SOURCE_DIR/" "$BUILD_BRIDGE_DIR/"
  log "Mirroring Lore source into Linux build workspace"
  rsync -a --delete --exclude .git --exclude target "$LORE_SOURCE_DIR/" "$BUILD_LORE_DIR/"
}

build_binaries() {
  log "Building lore-auth-bridge from $BUILD_BRIDGE_DIR"
  (
    cd "$BUILD_BRIDGE_DIR"
    cargo build --release -p lore-auth-server -p lore-authctl
  )

  log "Building Lore from $BUILD_LORE_DIR"
  (
    cd "$BUILD_LORE_DIR"
    cargo build --release -p lore-client --bin lore -p lore-server --bin loreserver
  )
}

prepare_layout() {
  BIN_DIR="$INSTALL_DIR/bin"
  CONFIG_DIR="$INSTALL_DIR/config"
  LORE_CONFIG_DIR="$INSTALL_DIR/lore-config"
  DATA_DIR="$INSTALL_DIR/data"
  KEYS_DIR="$INSTALL_DIR/keys"
  CERT_DIR="$INSTALL_DIR/certs"
  HOME_DIR="$INSTALL_DIR/home"
  LOG_DIR="$INSTALL_DIR/log"
  BRIDGE_CONFIG="$CONFIG_DIR/lore-auth.yaml"
  LORE_CONFIG="$LORE_CONFIG_DIR/local.toml"
  CERT_FILE="$CERT_DIR/grpc.crt"
  KEY_FILE="$CERT_DIR/grpc.key"
  ENTRA_SECRET_TARGET="$CONFIG_DIR/entra-client-secret"

  mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$LORE_CONFIG_DIR" "$DATA_DIR" "$KEYS_DIR" "$CERT_DIR" "$HOME_DIR" "$LOG_DIR"
  install -m 0755 "$BUILD_BRIDGE_DIR/target/release/lore-auth-server" "$BIN_DIR/lore-auth-server"
  install -m 0755 "$BUILD_BRIDGE_DIR/target/release/lore-authctl" "$BIN_DIR/lore-authctl"
  install -m 0755 "$BUILD_LORE_DIR/target/release/lore" "$BIN_DIR/lore"
  install -m 0755 "$BUILD_LORE_DIR/target/release/loreserver" "$BIN_DIR/loreserver"
}

prepare_entra_secret() {
  if [[ -z "$ENTRA_TENANT_ID" ]]; then
    return
  fi

  install -m 0600 "$ENTRA_CLIENT_SECRET_FILE" "$ENTRA_SECRET_TARGET"
}

certificate_san() {
  if [[ "$HOSTNAME" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    printf 'DNS:localhost,IP:127.0.0.1,IP:%s' "$HOSTNAME"
  else
    printf 'DNS:localhost,IP:127.0.0.1,DNS:%s' "$HOSTNAME"
  fi
}

create_certificate() {
  if [[ -f "$CERT_FILE" && -f "$KEY_FILE" && "$RENEW_CERT" -eq 0 ]]; then
    log "Reusing self-signed gRPC certificate: $CERT_FILE"
    return
  fi

  log "Generating self-signed gRPC certificate for $HOSTNAME"
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
    -subj "/CN=$HOSTNAME" \
    -addext "subjectAltName=$(certificate_san)" \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" >/dev/null 2>&1
  chmod 0600 "$KEY_FILE"
  chmod 0644 "$CERT_FILE"
}

write_bridge_config() {
  local database_path="$DATA_DIR/lore-auth.sqlite3"
  local auth_url="https://$HOSTNAME:8081"
  local public_base_url="http://$HOSTNAME:8080"
  local remote_url="lore://$HOSTNAME:41337"

  cat > "$BRIDGE_CONFIG" <<EOF
server:
  listen: "127.0.0.1:8080"
  grpc_listen: "127.0.0.1:8081"
  grpc_tls_cert_file: "$CERT_FILE"
  grpc_tls_key_file: "$KEY_FILE"
  public_base_url: "$public_base_url"

EOF

  if [[ -n "$ENTRA_TENANT_ID" ]]; then
    cat >> "$BRIDGE_CONFIG" <<EOF
identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/$ENTRA_TENANT_ID/v2.0"
      client_id: "$ENTRA_CLIENT_ID"
      client_secret_file: "$ENTRA_SECRET_TARGET"
      redirect_url: "$public_base_url/auth/entra/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "$ENTRA_TENANT_ID"
      trust:
        email_binding: verified_email_invitation
EOF
    if [[ -n "$ENTRA_ALLOWED_EMAIL_DOMAIN" ]]; then
      printf '        allowed_email_domains:\n          - "%s"\n' "$ENTRA_ALLOWED_EMAIL_DOMAIN" >> "$BRIDGE_CONFIG"
    else
      printf '        allowed_email_domains: []\n' >> "$BRIDGE_CONFIG"
    fi
    printf '\n' >> "$BRIDGE_CONFIG"
  fi

  cat >> "$BRIDGE_CONFIG" <<EOF

database:
  path: "$database_path"

authz:
  backend: rebac

jwt:
  issuer: "$public_base_url"
  audience:
    - "lore-service"
    - "$HOSTNAME"
  ttl_seconds: 3600
  signing_key_dir: "$KEYS_DIR"
  active_kid: "$SIGNING_KEY_KID"

lore:
  default_remote_url: "$remote_url"
  auth_url: "$auth_url"

security:
  device_code_ttl_seconds: 600
  device_poll_interval_seconds: 3
  session_ttl_seconds: 3600
  rebac_allowed_peer_cidrs:
    - "127.0.0.1/32"
    - "::1/128"
EOF
  chmod 0600 "$BRIDGE_CONFIG"
}

write_lore_config() {
  cat > "$LORE_CONFIG" <<EOF
[environment.endpoint]
auth_url = "https://$HOSTNAME:8081"

[server.auth]
jwt_issuer = "http://$HOSTNAME:8080"
jwt_audience = ["lore-service", "$HOSTNAME"]

[server.auth.jwk]
endpoint = "http://$HOSTNAME:8080/.well-known/jwks.json"

[immutable_store.local]
path = "$DATA_DIR/lore-store"

[mutable_store.local]
path = "$DATA_DIR/lore-store"
EOF
}

initialize_bridge() {
  "$BIN_DIR/lore-authctl" --config "$BRIDGE_CONFIG" init-db

  if "$BIN_DIR/lore-authctl" --config "$BRIDGE_CONFIG" signing-key list | cut -f1 | grep -Fxq "$SIGNING_KEY_KID"; then
    log "Signing key already exists: $SIGNING_KEY_KID"
  else
    "$BIN_DIR/lore-authctl" --config "$BRIDGE_CONFIG" signing-key generate --kid "$SIGNING_KEY_KID"
  fi

  if [[ -n "$SEED_USER_EMAIL" ]]; then
    if "$BIN_DIR/lore-authctl" --config "$BRIDGE_CONFIG" user list | cut -f2 | grep -Fxq "$SEED_USER_EMAIL"; then
      log "Seed user already exists: $SEED_USER_EMAIL"
    else
      "$BIN_DIR/lore-authctl" --config "$BRIDGE_CONFIG" user add --email "$SEED_USER_EMAIL" --name "Local User"
    fi
  fi

  if [[ -n "$INVITE_USER_EMAIL" ]]; then
    if "$BIN_DIR/lore-authctl" --config "$BRIDGE_CONFIG" user list | cut -f2 | grep -Fxq "$INVITE_USER_EMAIL"; then
      log "Invited Entra user already exists: $INVITE_USER_EMAIL"
    else
      "$BIN_DIR/lore-authctl" --config "$BRIDGE_CONFIG" user invite --idp entra --email "$INVITE_USER_EMAIL"
    fi
  fi
}

write_launchers() {
  cat > "$BIN_DIR/env.sh" <<EOF
#!/usr/bin/env bash
# Source this file before using the local lore CLI.
export PATH="$BIN_DIR:\$PATH"
export SSL_CERT_FILE="$CERT_FILE"
export LORE_CONFIG_PATH="$LORE_CONFIG_DIR"
export LORE_ENV=local
export HOME="$HOME_DIR"
EOF

  cat > "$BIN_DIR/start-bridge.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$BIN_DIR/lore-auth-server" --config "$BRIDGE_CONFIG"
EOF

  cat > "$BIN_DIR/start-loreserver.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
source "$BIN_DIR/env.sh"
exec "$BIN_DIR/loreserver" --config "$LORE_CONFIG_DIR" --env local
EOF

  cat > "$BIN_DIR/healthcheck.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
curl --fail --silent --show-error "http://$HOSTNAME:8080/healthz"
curl --fail --silent --show-error "http://$HOSTNAME:41339/health_check"
EOF

  chmod 0755 "$BIN_DIR/env.sh" "$BIN_DIR/start-bridge.sh" "$BIN_DIR/start-loreserver.sh" "$BIN_DIR/healthcheck.sh"
}

write_readme() {
  cat > "$INSTALL_DIR/README-local.txt" <<EOF
Local Lore stack
================

Bridge HTTP/JWKS: http://$HOSTNAME:8080
Bridge gRPC TLS:  https://$HOSTNAME:8081
Lore remote:      lore://$HOSTNAME:41337

Terminal 1:
  $BIN_DIR/start-bridge.sh


EOF
  if [[ -n "$ENTRA_TENANT_ID" ]]; then
    cat >> "$INSTALL_DIR/README-local.txt" <<EOF
Entra ID login:
  1. Register http://localhost:8080/auth/entra/callback as the exact Entra
     web redirect URI.
  2. Run lore auth login lore://$HOSTNAME:41337 without --token. Lore opens
     the browser; complete Microsoft Entra ID sign-in there.
  3. Only users invited with --invite-user can receive a Lore token.

EOF
  fi

  cat >> "$INSTALL_DIR/README-local.txt" <<EOF
Terminal 2:
  $BIN_DIR/start-loreserver.sh

Terminal 3:
  source $BIN_DIR/env.sh
  $BIN_DIR/healthcheck.sh

The gRPC endpoint uses a self-signed certificate at:
  $CERT_FILE

env.sh sets SSL_CERT_FILE to that certificate for this local stack. Do not use
this certificate or configuration as-is for a public deployment.
EOF
}

main() {
  parse_args "$@"
  validate_idp_options
  ensure_sources
  install_packages
  ensure_rust
  prepare_build_workspace
  build_binaries
  prepare_layout
  prepare_entra_secret
  create_certificate
  write_bridge_config
  write_lore_config
  initialize_bridge
  write_launchers
  write_readme

  log "Installation completed: $INSTALL_DIR"
  log "Read $INSTALL_DIR/README-local.txt for the three-terminal startup sequence"
}

main "$@"
