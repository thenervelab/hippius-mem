#!/usr/bin/env bash
#
# hippius-mem PostToolUse hook — companion to hippius-mem-recall-preflight.sh.
#
# Fires after a `recall` call and, when that call returned a result, stamps the
# recall token the edit-gate checks for. This is the seam that makes "the agent consulted team
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
# shellcheck disable=SC2317,SC2329  # invoked indirectly via trap ERR; shellcheck
# renumbered this diagnostic (SC2317 up to 0.9.x, SC2329 from 0.10), so both
# codes are listed to stay clean whichever version a contributor has.
on_error() { pass_through; }
trap on_error ERR

command -v jq >/dev/null 2>&1 || pass_through

input="$(cat || true)"
[[ -n "$input" ]] || pass_through

# A recall that did not run, or that failed, is not evidence that the agent
# consulted team memory, so it writes no token. Claude Code fires PostToolUse
# only after a tool call succeeds, but the Cursor CLI also fires it for a call
# the user rejected and for one that returned an MCP error. Observed with
# cursor-agent 2026.09.28 on 2026-11-19, where both wrote a token and opened
# the edit-gate:
#   rejected: "tool_output": {"rejected":true,"reason":"User rejected MCP: ..."}
#   errored:  "tool_output": "{\"content\":[...],\"isError\":true}"
# The second is the MCP result as JSON text, which is also how Cursor sends a
# good result, so a string is parsed before it is read. `tool_response` is the
# field Claude Code documents for the result.
#
# A result in a shape this does not know still writes a token. Refusing those
# would leave a host that sends no result at all with every edit blocked and
# no recall able to clear it.
recall_failed="$(jq -r '
  [.tool_output, .tool_response]
  | map(if type == "string" then (try fromjson catch null) else . end)
  | any(type == "object" and (.isError == true or .rejected == true))
' <<<"$input" 2>/dev/null || echo false)"
[[ "$recall_failed" == "true" ]] && pass_through

session_id="$(jq -r '.session_id // .sessionId // "unknown"' <<<"$input" 2>/dev/null || echo unknown)"

# cd + pwd -P so a Grok-compat symlink at .claude/.claude/hooks/ → ../hooks
# still yields <repo>, not <repo>/.claude.
hook_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P 2>/dev/null || echo "")"
repo_root=""
[[ -n "$hook_dir" ]] && repo_root="$(cd "$hook_dir/../.." && pwd -P 2>/dev/null || echo "")"
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
