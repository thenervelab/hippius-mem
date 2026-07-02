#!/usr/bin/env bash
#
# scripts/install.sh — bootstrap OR refresh a hippius-mem install for Claude Code.
#
# Mirrors illu-rs/scripts/install.sh: a thin orchestrator around the binary's own
# provisioning subcommands. It builds the server with semantic recall, writes the
# per-user config from prompted secrets, then lets `hippius-mem install` / `init`
# do the actual Claude Code wiring (mandates block, hooks, MCP registration).
#
# Idempotent across re-runs. Steps:
#   1. Verify prerequisites (cargo required; jq/git checked with guidance).
#   2. cargo install --path hippius-mem --features embeddings --force
#      (semantic recall ON; the ~90 MB model downloads on first server run).
#   3. Prompt for the six required secrets (from /dev/tty, so `curl | sh` still
#      works) and write ~/.config/hippius-mem/hippius-mem.toml at 0600. Never
#      overwrites an existing config.
#   4. hippius-mem install         (user-global: ~/.claude/CLAUDE.md + ~/.claude.json)
#   5. hippius-mem init            (provision the current repo, when it is a
#                                   different git repo — skip with --no-init-here)
#   6. hippius-mem doctor --offline (validate the bundle)
#
# Usage:
#   ./scripts/install.sh                 # everything on
#   ./scripts/install.sh --no-init-here  # skip provisioning the current repo
#   ./scripts/install.sh --no-hooks      # `init` without hook scripts
#   curl -fsSL <raw-url>/install.sh | sh # curl-pipe (prompts read from /dev/tty)
#   ./scripts/install.sh -h | --help

set -euo pipefail

INIT_HERE=true
INIT_FLAGS=()

usage() {
  cat <<'EOF'
Usage: install.sh [OPTIONS]

Build hippius-mem with semantic recall, write the per-user config, and wire it
into Claude Code (global + current repo). Idempotent.

Options:
  --no-init-here   Do not run `hippius-mem init` in the current directory.
  --no-hooks       Pass --no-hooks to `hippius-mem init` (no hook scripts).
  -h, --help       Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-init-here) INIT_HERE=false; shift ;;
    --no-hooks) INIT_FLAGS+=("--no-hooks"); shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --- Step 1: prerequisites -------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: 'cargo' is required but not in PATH. Install Rust from https://rustup.rs." >&2
  exit 1
fi
# jq is not needed by this script, but the installed hooks call it at runtime;
# warn now rather than let the recall gate silently fail-open later.
if ! command -v jq >/dev/null 2>&1; then
  echo "WARNING: 'jq' is not in PATH. The recall/remember hooks need it at runtime" >&2
  echo "         (macOS: brew install jq; Debian/Ubuntu: apt-get install -y jq)." >&2
fi

# Resolve the source root from the script location (one level up from scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Step 2: build + install the binary ------------------------------------
echo "==> cargo install --path hippius-mem --features embeddings --force"
cargo install --path "$REPO_ROOT/hippius-mem" --features embeddings --force
BIN="$(command -v hippius-mem)"
echo "    binary: $BIN"

# --- Step 3: per-user config (prompted secrets) ----------------------------
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem"
CONFIG_PATH="$CONFIG_DIR/hippius-mem.toml"

if [[ -f "$CONFIG_PATH" ]]; then
  echo "==> config already present at $CONFIG_PATH — keeping it (delete it to re-enter secrets)"
elif [[ ! -e /dev/tty ]]; then
  echo "WARNING: no TTY available; skipping config prompt." >&2
  echo "         Create $CONFIG_PATH (0600) with team/bucket/access_key_id/secret/" >&2
  echo "         team_key_hex/author_seed_hex, then re-run to validate." >&2
else
  echo "==> enter the six required values (secrets are hidden and never echoed)"
  # Read from /dev/tty explicitly so this works under `curl -fsSL ... | sh`,
  # where stdin is the piped script, not the keyboard.
  read -r  -p "team (shared namespace): "  team           </dev/tty
  read -r  -p "bucket: "                   bucket         </dev/tty
  read -r  -p "access_key_id (S3 sub-token id): " access_key_id </dev/tty
  read -rs -p "secret (S3 sub-token secret): "    secret         </dev/tty; echo
  read -rs -p "team_key_hex (64 hex chars): "     team_key_hex   </dev/tty; echo
  read -rs -p "author_seed_hex (64 hex chars): "  author_seed_hex </dev/tty; echo

  # umask 077 + explicit chmod: the file holds two secrets and must not be
  # group/world readable even for the instant between create and chmod.
  (
    umask 077
    mkdir -p "$CONFIG_DIR"
    cat >"$CONFIG_PATH" <<EOF
# hippius-mem per-user config. Contains secrets — never commit. Mode 0600.
team = "$team"
bucket = "$bucket"
access_key_id = "$access_key_id"
secret = "$secret"
team_key_hex = "$team_key_hex"
author_seed_hex = "$author_seed_hex"
EOF
  )
  chmod 600 "$CONFIG_PATH"
  echo "    wrote $CONFIG_PATH (0600)"
fi

export HIPPIUS_MEM_CONFIG="$CONFIG_PATH"

# --- Step 4: user-global Claude Code wiring --------------------------------
echo "==> hippius-mem install (global CLAUDE.md + ~/.claude.json)"
"$BIN" install

# --- Step 5: provision the current repo ------------------------------------
# Only when cwd is a git repo distinct from the hippius-mem source (running
# `init` inside the source clone is the maintainers' dogfood path, opt-in).
CWD_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "")"
if [[ "$INIT_HERE" == true && -n "$CWD_ROOT" && "$CWD_ROOT" != "$REPO_ROOT" ]]; then
  echo "==> hippius-mem init (provision $CWD_ROOT)"
  # Expand the flags array only when non-empty: under `set -u`, macOS bash 3.2
  # errors on "${arr[@]}" for an empty array.
  if [[ ${#INIT_FLAGS[@]} -gt 0 ]]; then
    (cd "$CWD_ROOT" && "$BIN" init "${INIT_FLAGS[@]}")
  else
    (cd "$CWD_ROOT" && "$BIN" init)
  fi
else
  echo "==> skipping repo init (not in a separate git repo, or --no-init-here)"
fi

# --- Step 6: validate ------------------------------------------------------
if [[ -f "$CONFIG_PATH" ]]; then
  echo "==> hippius-mem doctor --offline"
  "$BIN" doctor --offline || echo "    (doctor reported an issue — check the config above)"
fi

echo ""
echo "==> Done. Reconnect MCP in an open Claude session with /mcp, or start a new one."
