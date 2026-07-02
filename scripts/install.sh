#!/bin/sh
#
# scripts/install.sh — one-line installer for hippius-mem (Claude Code team memory).
#
# Rustup-style bootstrap. Run it any of three ways:
#   curl -fsSL https://raw.githubusercontent.com/thenervelab/hippius-mem/main/scripts/install.sh | sh
#   sh scripts/install.sh          # from a local clone
#   ./scripts/install.sh
#
# It will:
#   1. Install Rust via rustup if `cargo` is missing ("Rust is not installed…").
#   2. Build + install `hippius-mem` with semantic recall (--features embeddings)
#      — from the local clone if run inside one, else straight from git so a
#      curl-pipe needs no checkout. The ~90 MB model downloads on first serve.
#   3. Prompt for the six required secrets (read from /dev/tty, so `curl | sh`
#      still prompts) and write ~/.config/hippius-mem/hippius-mem.toml at 0600.
#      Skipped if the config already exists or no TTY is available.
#   4. Wire Claude Code: `hippius-mem install` (user-global) and, when the cwd is
#      a separate git repo, `hippius-mem init` (that repo).
#   5. Validate with `hippius-mem doctor --offline`.
#
# Written in POSIX sh (no bashisms) so `curl | sh` works on dash/ash/busybox.

set -eu

REPO_URL="https://github.com/thenervelab/hippius-mem"
INIT_HERE=1
INIT_NO_HOOKS=0

# Restore terminal echo if we are interrupted mid secret-prompt (stty -echo is
# on at that point). Harmless when stdin is not a terminal.
trap 'stty echo 2>/dev/null || true' EXIT INT TERM

log() { printf '==> %s\n' "$1"; }
warn() { printf 'WARNING: %s\n' "$1" >&2; }
die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --no-init-here) INIT_HERE=0 ;;
    --no-hooks) INIT_NO_HOOKS=1 ;;
    -h | --help)
      printf 'Usage: install.sh [--no-init-here] [--no-hooks]\n'
      exit 0
      ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# --- Step 1: Rust ----------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  log "Rust is not installed — installing it now via rustup"
  command -v curl >/dev/null 2>&1 || die "curl is required to install Rust"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
  # Load cargo into THIS shell for the remaining steps (the installer only edits
  # the login profile, which this non-login shell has not sourced).
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
command -v cargo >/dev/null 2>&1 || die "cargo still not found after the rustup install"

# jq is used by the runtime hooks, not by this script — warn, do not fail.
command -v jq >/dev/null 2>&1 ||
  warn "jq not found; the recall/remember hooks need it at runtime (brew install jq | apt-get install -y jq)"

# --- Step 2: build + install ----------------------------------------------
# Prefer a local clone (fast, offline) when this script sits inside one;
# otherwise install straight from git so a curl-pipe needs no checkout.
SOURCE_ROOT=""
case "$0" in
  */*) SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd || true) ;;
  *) SCRIPT_DIR="" ;;
esac
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/../hippius-mem/Cargo.toml" ]; then
  SOURCE_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
fi

if [ -n "$SOURCE_ROOT" ]; then
  log "building from local clone: $SOURCE_ROOT (semantic recall on)"
  cargo install --path "$SOURCE_ROOT/hippius-mem" --features embeddings --force
else
  log "installing from git: $REPO_URL (semantic recall on)"
  cargo install --git "$REPO_URL" hippius-mem --features embeddings --locked --force
fi
BIN=$(command -v hippius-mem) || die "hippius-mem not on PATH after install — is ~/.cargo/bin on your PATH?"
log "binary: $BIN"

# --- Step 3: per-user config (prompted secrets) ---------------------------
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem"
CONFIG_PATH="$CONFIG_DIR/hippius-mem.toml"
export HIPPIUS_MEM_CONFIG="$CONFIG_PATH"

# Prompt on the terminal and print one hidden secret on stdout (captured via
# command substitution). Echo is disabled around the read so the secret is not
# shown; the prompt and the closing newline go to /dev/tty, not stdout, so they
# do not contaminate the captured value.
read_secret() {
  printf '%s' "$1" >/dev/tty
  stty -echo 2>/dev/null || true
  _secret_value=""
  read -r _secret_value </dev/tty
  stty echo 2>/dev/null || true
  printf '\n' >/dev/tty
  printf '%s' "$_secret_value"
}

if [ -f "$CONFIG_PATH" ]; then
  log "config already present at $CONFIG_PATH — keeping it (delete it to re-enter secrets)"
elif [ ! -e /dev/tty ]; then
  warn "no TTY available; skipping the config prompt."
  warn "create $CONFIG_PATH (0600) with team/bucket/access_key_id/secret/team_key_hex/author_seed_hex, then re-run."
else
  log "enter the six required values (secrets are hidden and never echoed)"
  printf 'team (shared namespace): ' >/dev/tty
  read -r team </dev/tty
  printf 'bucket: ' >/dev/tty
  read -r bucket </dev/tty
  printf 'access_key_id (S3 sub-token id): ' >/dev/tty
  read -r access_key_id </dev/tty
  secret=$(read_secret 'secret (S3 sub-token secret): ')
  team_key_hex=$(read_secret 'team_key_hex (64 hex chars): ')
  author_seed_hex=$(read_secret 'author_seed_hex (64 hex chars, UNIQUE per machine): ')

  # umask 077 in a subshell so the file is never group/world readable, even for
  # the instant between create and the explicit chmod below.
  mkdir -p "$CONFIG_DIR"
  (
    umask 077
    cat >"$CONFIG_PATH" <<EOF
# hippius-mem per-user config. Holds secrets — never commit. Mode 0600.
team = "$team"
bucket = "$bucket"
access_key_id = "$access_key_id"
secret = "$secret"
team_key_hex = "$team_key_hex"
author_seed_hex = "$author_seed_hex"
EOF
  )
  chmod 600 "$CONFIG_PATH"
  log "wrote $CONFIG_PATH (0600)"
fi

# --- Step 4: wire Claude Code ---------------------------------------------
log "hippius-mem install (user-global CLAUDE.md + ~/.claude.json)"
"$BIN" install

# Provision the current repo when it is a git repo distinct from the source
# clone (running init inside the source is the maintainers' dogfood path).
CWD_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ "$INIT_HERE" -eq 1 ] && [ -n "$CWD_ROOT" ] && [ "$CWD_ROOT" != "${SOURCE_ROOT:-}" ]; then
  log "hippius-mem init (provision $CWD_ROOT)"
  if [ "$INIT_NO_HOOKS" -eq 1 ]; then
    (cd "$CWD_ROOT" && "$BIN" init --no-hooks)
  else
    (cd "$CWD_ROOT" && "$BIN" init)
  fi
else
  log "skipping repo init (not in a separate git repo, or --no-init-here)"
fi

# --- Step 5: validate ------------------------------------------------------
if [ -f "$CONFIG_PATH" ]; then
  log "hippius-mem doctor --offline"
  "$BIN" doctor --offline || warn "doctor reported an issue — check the config above"
fi

printf '\n'
log "Done. In an open Claude session run /mcp to reconnect; a new session picks it up automatically."
