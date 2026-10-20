#!/usr/bin/env bash
# Verify that Microsoft Entra accepts a configured OAuth client secret.
set -euo pipefail

TENANT_ID=""
CLIENT_ID=""
SECRET_FILE=""

usage() {
  cat <<EOF
Usage: $(basename "$0") --tenant-id ID --client-id ID --secret-file PATH

Verify that Microsoft Entra accepts an application client ID and client secret.
The script does not print the client secret or any access token.

Options:
  --tenant-id ID      Microsoft Entra Directory (tenant) ID
  --client-id ID      Application (client) ID
  --secret-file PATH  File containing the client secret value
  -h, --help          Show this help
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tenant-id) TENANT_ID="${2:?missing value for --tenant-id}"; shift 2 ;;
    --client-id) CLIENT_ID="${2:?missing value for --client-id}"; shift 2 ;;
    --secret-file) SECRET_FILE="${2:?missing value for --secret-file}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$TENANT_ID" ]] || die "--tenant-id is required"
[[ -n "$CLIENT_ID" ]] || die "--client-id is required"
[[ -n "$SECRET_FILE" ]] || die "--secret-file is required"
[[ -r "$SECRET_FILE" ]] || die "client secret file is not readable: $SECRET_FILE"
[[ -s "$SECRET_FILE" ]] || die "client secret file is empty: $SECRET_FILE"
command -v python3 >/dev/null || die "python3 is required"

TENANT_ID="$TENANT_ID" CLIENT_ID="$CLIENT_ID" SECRET_FILE="$SECRET_FILE" python3 - <<'PY'
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

tenant_id = os.environ["TENANT_ID"]
client_id = os.environ["CLIENT_ID"]
secret_file = Path(os.environ["SECRET_FILE"])
client_secret = secret_file.read_text().strip()

if not client_secret:
    print("ERROR: client secret file is empty", file=sys.stderr)
    sys.exit(1)

body = urllib.parse.urlencode(
    {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
).encode()
request = urllib.request.Request(
    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    data=body,
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=20) as response:
        print(f"OK: Entra accepted the client ID and client secret (HTTP {response.status}).")
except urllib.error.HTTPError as error:
    try:
        payload = json.loads(error.read().decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {}
    error_name = payload.get("error", "unknown error")
    error_codes = payload.get("error_codes", [])
    print(
        f"ERROR: Entra token endpoint returned HTTP {error.code}: {error_name}"
        + (f" (codes: {', '.join(map(str, error_codes))})" if error_codes else ""),
        file=sys.stderr,
    )
    if error_name == "invalid_client":
        print(
            "The client ID and client secret do not match, or the secret has expired.",
            file=sys.stderr,
        )
    sys.exit(1)
except urllib.error.URLError as error:
    print(f"ERROR: could not reach the Entra token endpoint: {error.reason}", file=sys.stderr)
    sys.exit(1)
PY
