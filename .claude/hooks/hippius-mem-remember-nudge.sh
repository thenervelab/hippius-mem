#!/usr/bin/env bash
#
# hippius-mem Stop hook — the "remember after" half of the discipline.
#
# Once per session, prompt the agent to persist any DURABLE learning (decision,
# gotcha, convention, reference) to team memory so the next agent does not
# rediscover it. Whether something is worth remembering is a judgment a hook
# cannot make, so this does not force a WRITE — it forces the DECISION to be
# made explicitly (an "answer, don't skip" nudge).
#
# Loop safety is the whole risk with Stop hooks (blocking forces another turn,
# which triggers Stop again). Two guards prevent a loop:
#   - honor `stop_hook_active`: if this stop is already a hook-driven
#     continuation, pass through.
#   - a per-session marker file: fire the block AT MOST once per session.
# The marker is written BEFORE the block so a retry still nudges exactly once.
#
# I/O (Claude Code hook protocol):
#   stdin (JSON):  { session_id, stop_hook_active, ... }
#   stdout (JSON): {"continue":true} | {"decision":"block","reason":"..."}

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

[[ "${HIPPIUS_MEM_HOOKS_BYPASS:-0}" == "1" ]] && pass_through

# Already inside a stop-hook continuation -> do not block again (loop guard).
active="$(jq -r '.stop_hook_active // false' <<<"$input" 2>/dev/null || echo false)"
[[ "$active" == "true" ]] && pass_through

session_id="$(jq -r '.session_id // "unknown"' <<<"$input" 2>/dev/null || echo unknown)"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P 2>/dev/null || echo "")"
[[ -n "$repo_root" ]] || pass_through

dir="$repo_root/.hippius-mem/cache/remember-nudge"
mkdir -p "$dir" 2>/dev/null || pass_through
# Hash the session id for the filename so a stray "/" or ".." in it cannot
# escape the cache dir (defensive — ids are UUIDs today).
if command -v shasum >/dev/null 2>&1; then
  sid="$(printf %s "$session_id" | shasum -a 256 | cut -c1-16)"
elif command -v sha256sum >/dev/null 2>&1; then
  sid="$(printf %s "$session_id" | sha256sum | cut -c1-16)"
else
  pass_through
fi
marker="$dir/$sid.done"

# Already nudged this session -> let the stop proceed.
[[ -f "$marker" ]] && pass_through

# Record first so even a retried block nudges exactly once.
: >"$marker" 2>/dev/null || true

# Feed the reason straight into jq (-R raw, -s slurp = one string), NOT via a
# `reason="$(cat <<EOF ...)"`. Inside `$(...)` bash mis-tracks a literal
# apostrophe in the heredoc body ("teammate's") against a later single quote and
# fails to parse the whole script — a real break `bash -n` catches but shellcheck
# does not. A heredoc feeding jq's stdin directly has no command substitution, so
# the apostrophe is inert.
jq -Rs '{decision:"block", reason:.}' <<'EOF'
[hippius-mem remember checkpoint]

Before finishing: did this session produce a DURABLE, team-relevant learning —
a decision, gotcha, convention, or reference — that a teammate's agent would
benefit from and that is NOT already obvious from the code or git history?

  - If yes: call mcp__hippius-mem__remember now. One fact per note; write a
    keyword-rich summary so recall can find it later.
  - If no: say "no durable learning to record" and stop.

Fires once per session. Bypass: HIPPIUS_MEM_HOOKS_BYPASS=1.
EOF
exit 0
