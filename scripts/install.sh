#!/bin/sh
#
# scripts/install.sh — one-line installer for hippius-mem (Claude Code team memory).
#
# Rustup-style bootstrap. The repo is private, so a raw curl-pipe against
# raw.githubusercontent.com 404s without auth. Run it any of these ways:
#   sh scripts/install.sh          # from a local clone (recommended; builds from --path)
#   ./scripts/install.sh
#   gh api repos/thenervelab/hippius-mem/contents/scripts/install.sh \
#     -H 'Accept: application/vnd.github.raw' | sh   # authenticated one-liner
#
# It will:
#   1. Install Rust via rustup if `cargo` is missing ("Rust is not installed…").
#   2. Build + install `hippius-mem` with semantic recall and the browse dashboard
#      (--features embeddings,dashboard) — from the local clone if run inside one,
#      else straight from git so a curl-pipe needs no checkout. The ~90 MB model
#      downloads on first serve; the dashboard adds no runtime download.
#   3. Prompt for the primary (catch-all) team's five values + auto-generate its
#      author_seed_hex, then optionally loop to add org-routed [[teams]] profiles
#      (read from /dev/tty, so `curl | sh` still prompts). Writes
#      $HIPPIUS_MEM_CONFIG (default ~/.config/hippius-mem/hippius-mem.toml) at
#      0600. Skipped if the config already exists or no TTY is available.
#   4. Wire Claude Code: `hippius-mem install` (user-global) and, when the cwd is
#      a separate git repo, `hippius-mem init` (that repo).
#   5. Validate with `hippius-mem doctor --offline`.
#
# --update (after changing the code): rebuild in place AND re-wire. It skips the
# Rust bootstrap and the secret prompts, keeps your existing config, then re-runs
# the same idempotent install/init (Step 4) so the setup — global registration,
# CLAUDE.md sections, hooks, .mcp.json — tracks the freshly built binary, and
# re-runs doctor. Requires a local clone: the rebuild is of your working tree.
#
# --add-team: append one org-routed [[teams]] profile to an EXISTING config. The
# fresh install (Step 3) only writes a config when none exists, so this is how you
# add a team later. Prompts for the one profile, appends it 0600-safe, validates,
# and exits — no build, no re-wire.
#
# Written in POSIX sh (no bashisms) so `curl | sh` works on dash/ash/busybox.

set -eu

REPO_URL="https://github.com/thenervelab/hippius-mem"
INIT_HERE=1
INIT_NO_HOOKS=0
UPDATE=0
ADD_TEAM=0

# Restore terminal echo on exit (stty -echo is on during a secret prompt). An interrupt
# must also *abort*: a bare INT trap that only restores echo lets the script fall through
# to the next read with an empty value, so Ctrl-C would silently write a half-filled
# config instead of stopping. Exit 130 (= 128 + SIGINT) is the conventional abort code.
cleanup() { stty echo 2>/dev/null || true; }
trap cleanup EXIT
trap 'cleanup; printf "\naborted.\n" >&2; exit 130' INT TERM

log() { printf '==> %s\n' "$1"; }
warn() { printf 'WARNING: %s\n' "$1" >&2; }
die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

# Per-user config path. Defined up here (not in Step 3) because --add-team appends
# to it before the build ever runs. A pre-set HIPPIUS_MEM_CONFIG wins so every mode
# (fresh install, --add-team, --update's doctor) targets the file the user already
# chose — matching how the binary itself resolves config — and only falls back to
# the XDG default when unset. The export re-publishes it so the wiring commands
# (install/init/doctor) resolve the same path.
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem"
CONFIG_PATH="${HIPPIUS_MEM_CONFIG:-$CONFIG_DIR/hippius-mem.toml}"
export HIPPIUS_MEM_CONFIG="$CONFIG_PATH"

# --- prompt/escape helpers (defined before arg handling so --add-team can use them) ---

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

# Mint a fresh 32-byte sr25519 signing seed as 64 lowercase hex chars. Every 32-byte
# value is a valid seed, so raw CSPRNG bytes need no rejection sampling. Prefer openssl,
# fall back to /dev/urandom via od (both POSIX-common) so a minimal box still works.
gen_seed() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif [ -r /dev/urandom ]; then
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
  else
    die "cannot generate author_seed_hex: need openssl or a readable /dev/urandom"
  fi
}

# Escape a value for a TOML basic (double-quoted) string: backslash first, then
# the quote, so a secret containing `"` or `\` cannot break the string or inject a
# key. `read -r` is line-based, so a value cannot contain a raw newline.
toml_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# Turn a comma-separated list into a TOML array of quoted, escaped strings:
#   "github.com/a, github.com/b" -> ["github.com/a", "github.com/b"]
# Splits with parameter expansion (no IFS word-splitting), so it stays lint-clean
# and never glob-expands an entry.
toml_string_array() {
  _arr=""
  _rest=$1
  while [ -n "$_rest" ]; do
    case "$_rest" in
      *,*)
        _item=${_rest%%,*}
        _rest=${_rest#*,}
        ;;
      *)
        _item=$_rest
        _rest=""
        ;;
    esac
    _item=$(printf '%s' "$_item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -z "$_item" ] && continue
    _item=$(toml_escape "$_item")
    if [ -z "$_arr" ]; then _arr="\"$_item\""; else _arr="$_arr, \"$_item\""; fi
  done
  printf '[%s]' "$_arr"
}

# Reject an orgs pattern the resolver can never match, mirroring config.rs
# `validate_org_pattern`: no URL scheme, no `git@` userinfo, no `.git` suffix, and
# exactly `host/org` or `host/org/repo`. Catching it here turns the silent misroute
# (the repo falls through to the catch-all) into an at-entry hint. The Rust loader
# is the authoritative gate; this is the fast feedback. Prints a fix hint to stderr
# and returns 1 when the pattern is malformed.
check_org_pattern() {
  _p=$(printf '%s' "$1" | sed 's#/*$##') # strip trailing slashes, as the resolver does
  case "$_p" in
    *://* | *@*)
      warn "org \"$1\": looks like a URL or clone address — use the bare host/org form (e.g. github.com/acme)"
      return 1
      ;;
    *.git)
      warn "org \"$1\": drop the .git suffix — use host/org or host/org/repo"
      return 1
      ;;
    /* | *//*)
      warn "org \"$1\": no leading or doubled '/' — use host/org or host/org/repo"
      return 1
      ;;
  esac
  # The host is the first segment. normalize_remote strips a :port and rejects a
  # <2-char host, so a pattern violating either never binds a remote.
  _host=${_p%%/*}
  case "$_host" in
    *:*)
      warn "org \"$1\": the host must not carry a :port — drop it (e.g. github.com/acme)"
      return 1
      ;;
  esac
  if [ "${#_host}" -lt 2 ]; then
    warn "org \"$1\": host segment must be at least 2 characters (e.g. github.com/acme)"
    return 1
  fi
  # Segment count = slash count + 1; accept only host/org (1 slash) or
  # host/org/repo (2 slashes). Empty segments were already rejected above.
  _slashes=$(printf '%s' "$_p" | tr -cd '/' | wc -c | tr -d ' ')
  case "$_slashes" in
    1 | 2) return 0 ;;
    *)
      warn "org \"$1\": must be host/org or host/org/repo (e.g. github.com/acme)"
      return 1
      ;;
  esac
}

# Prompt for the orgs line, re-prompting until every comma-separated item is a
# valid host/org[/repo]. Echoes the accepted line on stdout (captured by the
# caller); prompts go to /dev/tty and hints to stderr so stdout stays clean. An
# empty line is returned as-is — the caller's `[]` check rejects an org-less team.
read_orgs() {
  while :; do
    printf '  orgs (comma-separated, e.g. github.com/acme): ' >/dev/tty
    read -r _orgs </dev/tty
    _bad=0
    _rest=$_orgs
    while [ -n "$_rest" ]; do
      case "$_rest" in
        *,*)
          _item=${_rest%%,*}
          _rest=${_rest#*,}
          ;;
        *)
          _item=$_rest
          _rest=""
          ;;
      esac
      _item=$(printf '%s' "$_item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
      [ -z "$_item" ] && continue
      check_org_pattern "$_item" || _bad=1
    done
    if [ "$_bad" -eq 0 ]; then
      printf '%s' "$_orgs"
      return 0
    fi
    warn "re-enter the orgs line (or press Ctrl-C to abort)"
  done
}

# Prompt for one org-routed [[teams]] profile and append it to $CONFIG_PATH.
# Returns 1 without writing when no valid org is given — an empty `orgs` would make
# the profile a second catch-all that fails validation on the next launch. Appending
# preserves the file's existing 0600 mode. Shared by the fresh-install loop and
# --add-team so both emit a byte-identical block.
append_team_profile() {
  printf '  name (this team namespace): ' >/dev/tty
  read -r _t_name </dev/tty
  _t_orgs=$(read_orgs)
  _t_orgs_toml=$(toml_string_array "$_t_orgs")
  if [ "$_t_orgs_toml" = "[]" ]; then
    warn "no valid org given; an org-routed team needs at least one — skipping this profile"
    return 1
  fi
  printf '  bucket: ' >/dev/tty
  read -r _t_bucket </dev/tty
  printf '  access_key_id: ' >/dev/tty
  read -r _t_akid </dev/tty
  _t_secret=$(read_secret '  secret: ')
  _t_key=$(read_secret '  team_key_hex (64 hex chars): ')
  # Same rule as the primary: a fresh per-machine signing seed, never pasted.
  _t_seed=$(gen_seed)
  {
    printf '\n[[teams]]\n'
    printf 'name = "%s"\n' "$(toml_escape "$_t_name")"
    printf 'orgs = %s\n' "$_t_orgs_toml"
    printf 'bucket = "%s"\n' "$(toml_escape "$_t_bucket")"
    printf 'access_key_id = "%s"\n' "$(toml_escape "$_t_akid")"
    printf 'secret = "%s"\n' "$(toml_escape "$_t_secret")"
    printf 'team_key_hex = "%s"\n' "$_t_key"
    printf 'author_seed_hex = "%s"\n' "$_t_seed"
  } >>"$CONFIG_PATH"
  log "added org-routed team profile \"$_t_name\""
}

while [ $# -gt 0 ]; do
  case "$1" in
    --no-init-here) INIT_HERE=0 ;;
    --no-hooks) INIT_NO_HOOKS=1 ;;
    --update) UPDATE=1 ;;
    --add-team) ADD_TEAM=1 ;;
    -h | --help)
      printf 'Usage: install.sh [--update | --add-team] [--no-init-here] [--no-hooks]\n'
      exit 0
      ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# --- --add-team: append one profile to an existing config, then stop --------
# Runs before the Rust/build steps on purpose: adding a team is a config edit, not
# a reinstall, so it must be fast and must not rebuild or re-wire anything.
if [ "$ADD_TEAM" -eq 1 ]; then
  [ "$UPDATE" -eq 0 ] || die "--add-team and --update are mutually exclusive"
  # --add-team does no wiring, so the wiring flags are inert — say so rather than
  # let them look effective.
  if [ "$INIT_NO_HOOKS" -eq 1 ] || [ "$INIT_HERE" -eq 0 ]; then
    warn "--no-hooks / --no-init-here have no effect with --add-team (it performs no wiring)"
  fi
  [ -f "$CONFIG_PATH" ] || die "no config at $CONFIG_PATH — run the installer (without --add-team) to create one first"
  [ -e /dev/tty ] || die "--add-team needs a terminal to prompt for the profile"
  log "adding an org-routed [[teams]] profile to $CONFIG_PATH"
  append_team_profile || die "nothing added (a [[teams]] profile needs at least one org)"
  if command -v hippius-mem >/dev/null 2>&1; then
    log "hippius-mem doctor --offline"
    hippius-mem doctor --offline || warn "doctor reported an issue — check the profile you just added"
  else
    warn "hippius-mem not on PATH — skipped validation; run 'hippius-mem doctor --offline' once it is installed"
  fi
  printf '\n'
  log "Done. Reconnect with /mcp (or start a new session) so the new profile takes effect."
  exit 0
fi

# --- Step 1: Rust ----------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  # An update rebuilds an existing install, so cargo must already be here. Bootstrapping
  # Rust silently under --update would mask a broken PATH rather than surface it.
  [ "$UPDATE" -eq 1 ] && die "cargo not found — run './scripts/install.sh' (without --update) to bootstrap Rust first"
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

# --update rebuilds the working tree in place; without a clone there is nothing to
# rebuild from, so fail loudly rather than silently reinstalling the git HEAD.
if [ "$UPDATE" -eq 1 ] && [ -z "$SOURCE_ROOT" ]; then
  die "--update must run from inside a local clone (it rebuilds your working tree) — cd into the repo and re-run"
fi

if [ -n "$SOURCE_ROOT" ]; then
  if [ "$UPDATE" -eq 1 ]; then
    log "updating hippius-mem — rebuilding from local clone: $SOURCE_ROOT"
  else
    log "building from local clone: $SOURCE_ROOT (semantic recall on)"
  fi
  cargo install --path "$SOURCE_ROOT/hippius-mem" --features embeddings,dashboard --force
else
  log "installing from git: $REPO_URL (semantic recall on)"
  cargo install --git "$REPO_URL" hippius-mem --features embeddings,dashboard --locked --force
fi
BIN=$(command -v hippius-mem) || die "hippius-mem not on PATH after install — is ~/.cargo/bin on your PATH?"
log "binary: $BIN"

# --- Step 3: per-user config (prompted secrets) ---------------------------
# CONFIG_DIR/CONFIG_PATH and the prompt/escape helpers are defined near the top so
# --add-team can reuse them; here we only write the primary profile on a fresh box.
if [ -f "$CONFIG_PATH" ]; then
  log "config already present at $CONFIG_PATH — keeping it (delete it to re-enter secrets, or add a team with --add-team)"
elif [ ! -e /dev/tty ]; then
  warn "no TTY available; skipping the config prompt."
  warn "create $CONFIG_PATH (0600) with team/bucket/access_key_id/secret/team_key_hex and a"
  warn "unique author_seed_hex (generate one with: openssl rand -hex 32), then re-run."
else
  log "primary team — the catch-all: repos matching no other team use it (secrets hidden)"
  printf 'team (primary namespace): ' >/dev/tty
  read -r team </dev/tty
  printf 'bucket: ' >/dev/tty
  read -r bucket </dev/tty
  printf 'access_key_id (S3 sub-token id): ' >/dev/tty
  read -r access_key_id </dev/tty
  secret=$(read_secret 'secret (S3 sub-token secret): ')
  team_key_hex=$(read_secret 'team_key_hex (64 hex chars): ')
  # The signing seed is this machine's op-log identity and must be UNIQUE per machine, so
  # we mint a fresh one here rather than have the user paste (and risk reusing) it.
  author_seed_hex=$(gen_seed)
  log "generated a fresh author_seed_hex — this machine's unique op-log signing identity"

  # Escape the free-form values for TOML so a `"` or `\` cannot break the config;
  # the hex key/seed are alphabet-constrained and need none.
  e_team=$(toml_escape "$team")
  e_bucket=$(toml_escape "$bucket")
  e_access_key_id=$(toml_escape "$access_key_id")
  e_secret=$(toml_escape "$secret")

  # umask 077 in a subshell so the file is never group/world readable, even for
  # the instant between create and the explicit chmod below.
  mkdir -p "$CONFIG_DIR"
  (
    umask 077
    cat >"$CONFIG_PATH" <<EOF
# hippius-mem per-user config. Holds secrets — never commit. Mode 0600.
team = "$e_team"
bucket = "$e_bucket"
access_key_id = "$e_access_key_id"
secret = "$e_secret"
team_key_hex = "$team_key_hex"
author_seed_hex = "$author_seed_hex"
EOF
  )
  chmod 600 "$CONFIG_PATH"
  log "wrote $CONFIG_PATH (0600)"

  # Optionally add org-routed team profiles beyond the primary catch-all. Each is a
  # self-contained [[teams]] block appended to the 0600 file (append keeps the mode).
  while :; do
    printf 'add an org-routed team profile? [y/N]: ' >/dev/tty
    read -r add_more </dev/tty
    case "$add_more" in
      y | Y | yes | YES) ;;
      *) break ;;
    esac
    # An empty-orgs answer warns and returns 1; `|| true` keeps the loop going so the
    # next iteration re-offers the prompt rather than aborting under `set -e`.
    append_team_profile || true
  done
fi

# --- Step 4: wire Claude Code (the "setup") --------------------------------
# install/init are idempotent and run on EVERY invocation, --update included, so the
# setup — global registration in ~/.claude.json, the CLAUDE.md sections, hooks, and
# .mcp.json — is refreshed to match the just-built binary. That is what "an update
# also updates the setup" means here: the rebuild and the re-wire happen together, no
# separate step.
[ "$UPDATE" -eq 1 ] && log "refreshing the setup to match the rebuilt binary"
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
