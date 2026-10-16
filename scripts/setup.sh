#!/usr/bin/env bash
# Install what a full scan needs: the Python dependency and the CodeQL CLI.
#
#   ./scripts/setup.sh
#
# The offline mode (`python app/scan.py --demo`) needs neither of these beyond PyYAML, so
# this script is optional -- it just removes the one real setup barrier.
#
# Override the CLI version with CODEQL_VERSION=vX.Y.Z if you need a specific one, but keep in
# mind that the Python query pack has to match the CLI version.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/_tools/codeql"

# The version has one home: the Dockerfile's ARG. A second copy here meant the image and a
# local checkout could end up on different CLIs, which makes their results incomparable.
_DOCKERFILE="$ROOT/Dockerfile"
_DEFAULT_VERSION="$(sed -n 's/^ARG CODEQL_VERSION=//p' "$_DOCKERFILE" 2>/dev/null | head -1)"
if [ -z "$_DEFAULT_VERSION" ]; then
  printf 'error: no ARG CODEQL_VERSION in %s\n' "$_DOCKERFILE" >&2
  exit 1
fi
CODEQL_VERSION="${CODEQL_VERSION:-$_DEFAULT_VERSION}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 \
  || die "python 3.10+ is required"

PY="$(command -v python3 || command -v python)"

say "==> python: $("$PY" --version)"

if [ "$("$PY" -c 'import sys; print(int(sys.version_info >= (3, 10)))')" != "1" ]; then
  die "python 3.10 or newer is required"
fi

say "==> installing python dependencies"
"$PY" -m pip install -r "$ROOT/requirements.txt"

if [ -x "$DEST/codeql" ] || [ -x "$DEST/codeql.exe" ]; then
  say "==> CodeQL already present at $DEST"
  "$DEST/codeql" version || true
  exit 0
fi

case "$(uname -s)" in
  Linux)  case "$(uname -m)" in
            aarch64|arm64) ZIP=codeql-linux-arm64.zip ;;
            *)             ZIP=codeql-linux64.zip ;;
          esac ;;
  Darwin) ZIP=codeql-osx64.zip ;;
  MINGW*|MSYS*|CYGWIN*) ZIP=codeql-win64.zip ;;
  *) die "unsupported platform: $(uname -s). Download the CLI manually and set AF_CODEQL." ;;
esac

URL="https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/${ZIP}"
say "==> downloading CodeQL CLI ${CODEQL_VERSION} ($ZIP)"
say "    this is a few hundred MB; it goes to $DEST"

mkdir -p "$ROOT/_tools"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fL --progress-bar -o "$TMP/codeql.zip" "$URL"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$TMP/codeql.zip" "$URL"
else
  die "need curl or wget to download the CLI"
fi

command -v unzip >/dev/null 2>&1 || die "need unzip to unpack the CLI"
unzip -q "$TMP/codeql.zip" -d "$ROOT/_tools"

say "==> verifying"
"$DEST/codeql" version

cat <<'EOF'

Done. A full scan now works:

    python app/scan.py --demo
    python app/scan.py --path ./your-project

The offline mode is still available with --no-codeql.
EOF
