#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${CARGO_TARGET_DIR:-$SOURCE_DIR/target}/release"
BIN_DIR=""
CONFIG=""
INIT_DB=0
CERT_DIR=""
CERT_HOST=""
STAGE_DIR=""
CERT_STAGE=""

usage() {
  cat <<EOF
Usage: $(basename "$0") --bin-dir DIR [options]

Install previously built lore-auth-server and lore-authctl. Existing binaries
at the destination are replaced; services are not stopped or restarted.
Existing Lore binaries, configuration, databases and certificates are not
modified unless an initialization option is explicitly specified.

  --bin-dir DIR       Destination for bridge binaries (required)
  --build-dir DIR     Directory containing the built binaries
                      (default: $BUILD_DIR)
  --init-db           Run init-db with the installed lore-authctl
  --config FILE       Existing bridge configuration (required with --init-db)
  --init-cert DIR     Generate a self-signed gRPC certificate in DIR
  --cert-host HOST    DNS name or IPv4 address for the certificate (required
                      with --init-cert)
  -h, --help          Show this help

The certificate is for testing or explicitly trusted deployments. Existing
grpc.crt or grpc.key files are never replaced. Update the bridge configuration
and client trust separately. JWT signing keys are not generated.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$STAGE_DIR" ]]; then
    rm -f -- "$STAGE_DIR/lore-auth-server" "$STAGE_DIR/lore-authctl"
    rmdir -- "$STAGE_DIR" 2>/dev/null || true
  fi
  if [[ -n "$CERT_STAGE" ]]; then
    rm -f -- "$CERT_STAGE/grpc.crt" "$CERT_STAGE/grpc.key"
    rmdir -- "$CERT_STAGE" 2>/dev/null || true
  fi
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir|--build-dir|--config|--init-cert|--cert-host)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 requires a value"
      case "$1" in
        --bin-dir) BIN_DIR="$2" ;;
        --build-dir) BUILD_DIR="$2" ;;
        --config) CONFIG="$2" ;;
        --init-cert) CERT_DIR="$2" ;;
        --cert-host) CERT_HOST="$2" ;;
      esac
      shift 2
      ;;
    --init-db)
      INIT_DB=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$BIN_DIR" ]] || die "--bin-dir is required"
for binary in lore-auth-server lore-authctl; do
  [[ -f "$BUILD_DIR/$binary" && -x "$BUILD_DIR/$binary" ]] || die "built executable not found: $BUILD_DIR/$binary"
done
if [[ "$INIT_DB" -eq 1 ]]; then
  [[ -n "$CONFIG" && -f "$CONFIG" && -r "$CONFIG" ]] || die "--init-db requires a readable --config file"
elif [[ -n "$CONFIG" ]]; then
  die "--config requires --init-db"
fi
if [[ -n "$CERT_DIR" || -n "$CERT_HOST" ]]; then
  [[ -n "$CERT_DIR" && -n "$CERT_HOST" ]] || die "--init-cert and --cert-host must be used together"
  [[ "$CERT_HOST" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] || die "--cert-host must be a DNS name or IPv4 address"
  command -v openssl >/dev/null 2>&1 || die "openssl is required for --init-cert"
  [[ ! -e "$CERT_DIR/grpc.crt" && ! -L "$CERT_DIR/grpc.crt" &&
     ! -e "$CERT_DIR/grpc.key" && ! -L "$CERT_DIR/grpc.key" ]] ||
    die "certificate or key already exists in $CERT_DIR; refusing to replace it"
fi

umask 077
mkdir -p -- "$BIN_DIR"
STAGE_DIR="$(mktemp -d "$BIN_DIR/.lore-auth-install.XXXXXXXX")"
install -m 0755 -- "$BUILD_DIR/lore-auth-server" "$STAGE_DIR/lore-auth-server"
install -m 0755 -- "$BUILD_DIR/lore-authctl" "$STAGE_DIR/lore-authctl"
mv -f -- "$STAGE_DIR/lore-auth-server" "$BIN_DIR/lore-auth-server"
mv -f -- "$STAGE_DIR/lore-authctl" "$BIN_DIR/lore-authctl"
printf 'Installed bridge binaries in %s\n' "$BIN_DIR"

if [[ "$INIT_DB" -eq 1 ]]; then
  printf 'Initializing database using %s\n' "$CONFIG"
  "$BIN_DIR/lore-authctl" --config "$CONFIG" init-db
fi

if [[ -n "$CERT_DIR" ]]; then
  mkdir -p -- "$CERT_DIR"
  CERT_STAGE="$(mktemp -d "$CERT_DIR/.lore-auth-cert.XXXXXXXX")"
  if [[ "$CERT_HOST" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
    CERT_SAN="IP:$CERT_HOST"
  else
    CERT_SAN="DNS:$CERT_HOST"
  fi
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
    -subj "/CN=$CERT_HOST" \
    -addext "subjectAltName=$CERT_SAN" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$CERT_STAGE/grpc.key" -out "$CERT_STAGE/grpc.crt"
  chmod 0600 "$CERT_STAGE/grpc.key"
  chmod 0644 "$CERT_STAGE/grpc.crt"
  # Avoid clobbering certificate files created after the preflight check.
  ln -- "$CERT_STAGE/grpc.key" "$CERT_DIR/grpc.key"
  ln -- "$CERT_STAGE/grpc.crt" "$CERT_DIR/grpc.crt"
  printf 'Generated self-signed certificate: %s/grpc.crt\n' "$CERT_DIR"
fi

printf 'Configuration, client trust, signing keys, and service restart must be handled separately.\n'
