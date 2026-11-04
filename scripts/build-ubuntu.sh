#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$SOURCE_DIR/target}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--target-dir DIR]

Build lore-auth-server and lore-authctl in release mode.
The existing Lore server is not built or modified.
Artifacts are written to DIR/release (default: $TARGET_DIR/release).

  --target-dir DIR  Cargo target directory
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-dir)
      [[ $# -ge 2 && -n "$2" ]] || { echo "ERROR: --target-dir requires a directory" >&2; exit 1; }
      TARGET_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      exit 1
      ;;
  esac
done

command -v cargo >/dev/null 2>&1 || { echo "ERROR: cargo is required" >&2; exit 1; }
mkdir -p -- "$TARGET_DIR"
TARGET_DIR="$(cd -- "$TARGET_DIR" && pwd)"
cd -- "$SOURCE_DIR"
cargo build --locked --release --target-dir "$TARGET_DIR" -p lore-auth-server -p lore-authctl

printf 'Build completed: %s/release\n' "$TARGET_DIR"
