#!/usr/bin/env bash
set -euo pipefail

# Install Bifrost MCP for Hermes Agent with explicit environment wiring.
# This script intentionally stores runtime paths in Hermes config, not .env,
# because HOME/GNUPGHOME/PASSWORD_STORE_DIR are behavioral configuration rather
# than secrets.

usage() {
  cat <<'USAGE'
Usage: scripts/setup-hermes-mcp.sh [--profile PROFILE] [--name NAME] [--home HOME]

Options:
  --profile PROFILE  Hermes profile to configure (default: current/default Hermes behavior)
  --name NAME        MCP server name (default: bifrost)
  --home HOME        Home directory whose gopass/GPG store Bifrost should use
                    (default: current user's real home from getent/passwd or $HOME)
USAGE
}

PROFILE=""
NAME="bifrost"
REAL_HOME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:?missing profile}"; shift 2 ;;
    --name) NAME="${2:?missing name}"; shift 2 ;;
    --home) REAL_HOME="${2:?missing home}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
if [[ -z "$REAL_HOME" ]]; then
  REAL_HOME="$(getent passwd "$(id -un)" | cut -d: -f6 || true)"
  REAL_HOME="${REAL_HOME:-$HOME}"
fi

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v gopass >/dev/null || { echo "gopass is required; install it with your OS package manager" >&2; exit 1; }
command -v gpg >/dev/null || { echo "gpg is required; install gnupg" >&2; exit 1; }
command -v hermes >/dev/null || { echo "hermes CLI is required on PATH" >&2; exit 1; }

cd "$REPO_ROOT"
if [[ ! -x .venv/bin/python ]]; then
  if ! python3 -m venv .venv; then
    echo "python3 -m venv failed. On Debian/Ubuntu install python3-venv, or create .venv manually." >&2
    exit 1
  fi
fi

.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e .

if ! HOME="$REAL_HOME" gopass ls >/dev/null; then
  cat >&2 <<EOF

gopass is installed but not initialized/unlocked for HOME=$REAL_HOME.
Run these from an interactive terminal, then rerun this script:

  export GPG_TTY=\$(tty)
  gopass setup

or unlock an existing store with:

  export GPG_TTY=\$(tty)
  HOME=$REAL_HOME gopass ls
EOF
  exit 1
fi

HERMES=(hermes)
if [[ -n "$PROFILE" ]]; then
  HERMES+=(--profile "$PROFILE")
fi

# Add/update registration. Piping Y accepts all discovered tools for non-interactive setup.
printf 'Y\n' | "${HERMES[@]}" mcp add "$NAME" --command "$REPO_ROOT/.venv/bin/bifrost-mcp" \
  --env "HOME=$REAL_HOME" \
  --env "GNUPGHOME=$REAL_HOME/.gnupg" || true

"${HERMES[@]}" config set "mcp_servers.$NAME.env.HOME" "$REAL_HOME"
"${HERMES[@]}" config set "mcp_servers.$NAME.env.GNUPGHOME" "$REAL_HOME/.gnupg"
"${HERMES[@]}" mcp test "$NAME"

cat <<EOF

Bifrost MCP is registered as '$NAME'.
If you are in an existing Hermes session, run /reload-mcp or start a new session.
For GPG unlocks, use an interactive shell:

  export GPG_TTY=\$(tty)
  HOME=$REAL_HOME gopass show <bifrost_mcp_record>
EOF
