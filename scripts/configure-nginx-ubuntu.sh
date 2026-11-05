#!/usr/bin/env bash
set -euo pipefail

SERVER_HOST=""
CERT=""
KEY=""
NGINX_DIR="/etc/nginx"
REBAC_ALLOW=()
ADMIN_ALLOW=()
STAGE=""
CREATED_SITE=0
CREATED_LINK=0
SUCCESS=0

usage() {
  cat <<'EOF'
Usage: configure-nginx-ubuntu.sh --server-host HOST --cert FILE --key FILE [options]

Create and enable an nginx site for bridge HTTP (:8080 -> 127.0.0.1:18080)
and gRPC (:8081 -> 127.0.0.1:18081), then run nginx -t. Nginx and the
public TLS certificate must already be installed. Existing sites are not replaced.

  --server-host HOST   Public DNS name or IPv4 address
  --cert FILE          Absolute path to the public TLS certificate
  --key FILE           Absolute path to its private key
  --rebac-allow CIDR   Additional loreserver IPv4 address or CIDR; repeatable
  --admin-allow CIDR   Additional admin IPv4 address or CIDR; repeatable
  --nginx-dir DIR      Nginx configuration directory (default: /etc/nginx)
  -h, --help           Show this help

ReBAC and /admin allow only loopback unless additional sources are specified.
No packages, certificates, bridge configuration, or services are changed.
After a successful test, reload or start nginx separately.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ "$SUCCESS" -eq 0 ]]; then
    if [[ "$CREATED_LINK" -eq 1 ]]; then rm -f -- "$ENABLED"; fi
    if [[ "$CREATED_SITE" -eq 1 ]]; then rm -f -- "$SITE"; fi
  fi
  if [[ -n "$STAGE" ]]; then rm -f -- "$STAGE"; fi
}
trap cleanup EXIT

valid_ipv4_cidr() {
  local value="$1" ip prefix part
  [[ "$value" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(/([0-9]{1,2}))?$ ]] || return 1
  ip="${BASH_REMATCH[1]}"
  prefix="${BASH_REMATCH[3]:-32}"
  (( 10#$prefix <= 32 )) || return 1
  local -a octets
  IFS=. read -r -a octets <<< "$ip"
  for part in "${octets[@]}"; do
    [[ "$part" == 0 || "$part" != 0* ]] || return 1
    (( 10#$part <= 255 )) || return 1
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-host|--cert|--key|--rebac-allow|--admin-allow|--nginx-dir)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 requires a value"
      case "$1" in
        --server-host) SERVER_HOST="$2" ;;
        --cert) CERT="$2" ;;
        --key) KEY="$2" ;;
        --rebac-allow) REBAC_ALLOW+=("$2") ;;
        --admin-allow) ADMIN_ALLOW+=("$2") ;;
        --nginx-dir) NGINX_DIR="$2" ;;
      esac
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$SERVER_HOST" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] ||
  die "--server-host must be a DNS name or IPv4 address"
for path in "$CERT" "$KEY" "$NGINX_DIR"; do
  [[ "$path" =~ ^/[a-zA-Z0-9_./-]+$ ]] ||
    die "certificate, key and nginx directory paths must be absolute and contain only letters, digits, _, ., / or -"
done
[[ -f "$CERT" && -r "$CERT" ]] || die "certificate is not a readable file: $CERT"
[[ -f "$KEY" && -r "$KEY" ]] || die "key is not a readable file: $KEY"
[[ -f "$NGINX_DIR/nginx.conf" && -d "$NGINX_DIR/sites-available" && -d "$NGINX_DIR/sites-enabled" ]] ||
  die "nginx.conf, sites-available and sites-enabled must exist in $NGINX_DIR"
command -v nginx >/dev/null 2>&1 || die "nginx is required"
for address in "${REBAC_ALLOW[@]}" "${ADMIN_ALLOW[@]}"; do
  valid_ipv4_cidr "$address" || die "invalid IPv4 address or CIDR: $address"
done

SITE="$NGINX_DIR/sites-available/lore-auth"
ENABLED="$NGINX_DIR/sites-enabled/lore-auth"
[[ ! -e "$SITE" && ! -L "$SITE" && ! -e "$ENABLED" && ! -L "$ENABLED" ]] ||
  die "lore-auth site or enabled link already exists; refusing to replace it"

umask 022
STAGE="$(mktemp "$NGINX_DIR/sites-available/.lore-auth.XXXXXXXX")"
{
  cat <<EOF
server {
    listen 8080 ssl;
    server_name $SERVER_HOST;
    ssl_certificate $CERT;
    ssl_certificate_key $KEY;
    access_log off;

    location ^~ /admin {
        allow 127.0.0.1;
EOF
  for address in "${ADMIN_ALLOW[@]}"; do printf '        allow %s;\n' "$address"; done
  cat <<'EOF'
        deny all;
        proxy_pass http://127.0.0.1:18080;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header x-lore-client-ip $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header x-lore-client-ip $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF
  cat <<EOF

server {
    listen 8081 ssl http2;
    server_name $SERVER_HOST;
    ssl_certificate $CERT;
    ssl_certificate_key $KEY;
    access_log off;

    location ^~ /ucs.auth.RebacApi/ {
        allow 127.0.0.1;
EOF
  for address in "${REBAC_ALLOW[@]}"; do printf '        allow %s;\n' "$address"; done
  cat <<'EOF'
        deny all;
        grpc_set_header x-lore-client-ip $remote_addr;
        grpc_ssl_verify off;
        grpc_pass grpcs://127.0.0.1:18081;
    }

    location / {
        grpc_set_header x-lore-client-ip $remote_addr;
        grpc_ssl_verify off;
        grpc_pass grpcs://127.0.0.1:18081;
    }
}
EOF
} > "$STAGE"
chmod 0644 "$STAGE"
ln -- "$STAGE" "$SITE"
CREATED_SITE=1
ln -sT -- "$SITE" "$ENABLED"
CREATED_LINK=1
nginx -t -p "$NGINX_DIR/" -c "$NGINX_DIR/nginx.conf"
SUCCESS=1
printf 'Created and validated %s. Reload or start nginx to apply it.\n' "$SITE"
