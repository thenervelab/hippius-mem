#!/usr/bin/env bash
#
# hippius-mem PostToolUse hook — companion to hippius-mem-recall-preflight.sh.
#
# Fires after a successful `mcp__hippius-mem__recall` and stamps the recall token
# the edit-gate checks for. This is the seam that makes "the agent consulted team
# memory" observable to a later PreToolUse edit: hippius-mem's server does not
# emit such a token server-side, so we record it here in a hook instead.
#
# I/O (Claude Code hook protocol):
#   stdin (JSON):  { session_id, cwd, tool_name, ... }
#   stdout (JSON): {"continue":true}   (PostToolUse never blocks — the tool ran)
#
# Fail-open throughout: a token-writer failure must never surface as an error.

set -u

pass_through() { printf '{"continue":true}\n'; exit 0; }
# shellcheck disable=SC2329  # invoked indirectly via trap ERR
on_error() { pass_through; }
trap on_error ERR

command -v jq >/dev/null 2>&1 || pass_through

input="$(cat || true)"
[[ -n "$input" ]] || pass_through

session_id="$(jq -r '.session_id // "unknown"' <<<"$input" 2>/dev/null || echo unknown)"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P 2>/dev/null || echo "")"
[[ -n "$repo_root" ]] || pass_through

# Key on the SESSION id (not the repo root) so each new session must recall
# before its first edit — a token must not carry across sessions. The edit-gate
# derives the same key. Hashing also sanitizes the id for use in a filename.
if command -v shasum >/dev/null 2>&1; then
  key="$(printf %s "$session_id" | shasum -a 256 | cut -c1-16)"
elif command -v sha256sum >/dev/null 2>&1; then
  key="$(printf %s "$session_id" | sha256sum | cut -c1-16)"
else
  pass_through
fi

dir="$repo_root/.hippius-mem/cache/recall-tokens"
mkdir -p "$dir" 2>/dev/null || pass_through
now="$(date +%s)"
# Assemble the token with jq (a hard dependency by this point), NOT raw printf
# interpolation: a quote or backslash in a session id would produce invalid
# JSON, and the edit-gate's `.ts // 0` read would then treat the token as
# infinitely stale — a fail-CLOSED loop that re-recalling can never clear,
# because this hook would keep rewriting the same malformed token. Ids are
# UUIDs today; this is the same defensiveness already applied to the filename.
jq -n --argjson ts "$now" --arg sid "$session_id" '{ts: $ts, session_id: $sid}' \
  >"$dir/$key.json" 2>/dev/null || true

pass_through
