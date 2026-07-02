#!/usr/bin/env bash
#
# hippius-mem PreToolUse hook for Edit/Write/MultiEdit.
#
# Enforces "recall before you mutate": an in-repo file edit is BLOCKED until the
# agent has called `mcp__hippius-mem__recall` within the refresh window, so it
# consults team memory (past decisions, gotchas) before acting and does not
# repeat a mistake a teammate already recorded. Mirrors the illu-preflight.sh
# evidence-gate pattern this repo already relies on.
#
# I/O contract (Claude Code hook protocol):
#   stdin (JSON):  { tool_name, tool_input.file_path, cwd, session_id, ... }
#   stdout (JSON): {"continue":true}
#                | {"continue":true,"additionalContext":"..."}
#                | {"decision":"block","reason":"..."}
#
# Decision tree:
#   1. HIPPIUS_MEM_HOOKS_BYPASS=1        -> pass-through
#   2. tool not Edit/Write/MultiEdit      -> pass-through
#   3. target outside THIS repo tree      -> pass-through (never block scratch/siblings)
#   4. fresh recall token                 -> allow + warn (remaining window)
#      missing / stale token              -> BLOCK with instruction packet
#   internal error / no jq / no sha tool  -> fail-open (a buggy hook must never
#                                            brick all edits)
#
# The token this gate checks is written by the PostToolUse companion hook
# (hippius-mem-recall-token.sh) after each successful `recall` — that is what
# makes "the agent recalled" observable to this gate.

set -u

REFRESH_WINDOW="${HIPPIUS_MEM_RECALL_WINDOW_SECS:-1800}"

pass_through()      { printf '{"continue":true}\n'; exit 0; }
allow_with_warn()   { jq -n --arg m "$1" '{continue:true, additionalContext:$m}'; exit 0; }
block_with_reason() { jq -n --arg r "$1" '{decision:"block", reason:$r}'; exit 0; }

# Fail-open on any unexpected error: never let a hook bug block editing.
# shellcheck disable=SC2329  # invoked indirectly via trap ERR
on_error() { pass_through; }
trap on_error ERR

command -v jq >/dev/null 2>&1 || pass_through

input="$(cat || true)"
[[ -n "$input" ]] || pass_through

[[ "${HIPPIUS_MEM_HOOKS_BYPASS:-0}" == "1" ]] && pass_through

tool_name="$(jq -r '.tool_name // empty'            <<<"$input" 2>/dev/null || echo "")"
file_path="$(jq -r '.tool_input.file_path // empty' <<<"$input" 2>/dev/null || echo "")"
cwd="$(jq -r '.cwd // empty'                        <<<"$input" 2>/dev/null || echo "")"
session_id="$(jq -r '.session_id // "unknown"'      <<<"$input" 2>/dev/null || echo unknown)"
[[ -n "$cwd" ]] || cwd="${PWD:-.}"

case "$tool_name" in
  Edit|Write|MultiEdit) : ;;
  *) pass_through ;;
esac

# Enforce only for edits inside THIS repo. The hook ships at
# <repo>/.claude/hooks/, so parent-of-parent is the repo root. `file_abs` is
# resolved by STRING join (not `cd`) so a new file in a not-yet-created subdir
# still classifies correctly — same reasoning as illu-preflight.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P 2>/dev/null || echo "")"
case "$file_path" in
  /*) file_abs="$file_path" ;;
  *)  file_abs="$cwd/$file_path" ;;
esac
case "$file_abs" in
  "$repo_root"|"$repo_root"/*) : ;;
  *) pass_through ;;
esac

# Token is keyed by the SESSION id (the companion PostToolUse hook writes it
# under the same key), so each new session must recall before its first edit
# rather than inheriting a previous session's token. The repo is still scoped by
# the token dir path; the freshness window below re-forces recall on long sessions.
if command -v shasum >/dev/null 2>&1; then
  key="$(printf %s "$session_id" | shasum -a 256 | cut -c1-16)"
elif command -v sha256sum >/dev/null 2>&1; then
  key="$(printf %s "$session_id" | sha256sum | cut -c1-16)"
else
  pass_through
fi
token_file="$repo_root/.hippius-mem/cache/recall-tokens/$key.json"

# Load the packet with `read -r -d ''` (delimiter NUL; absent, so it slurps the
# whole quoted heredoc and returns non-zero at EOF, hence `|| true`). This avoids
# the `instruction="$(cat <<EOF ...)"` command-substitution, where a literal
# apostrophe in a heredoc body breaks bash's parse (shellcheck misses it).
read -r -d '' instruction <<'EOF' || true
[hippius-mem recall gate]

RECALL-BEFORE-MUTATE not satisfied. Before editing files in this repo, consult
team memory so you do not repeat a past mistake or contradict a prior decision.

Required action:
  1. Call mcp__hippius-mem__recall with a query describing what you are about to
     do (the feature, bug, file, or subsystem). Read the returned summaries and
     `get` any that look relevant.
  2. Retry your Edit/Write call.

One recall opens the gate for the whole refresh window.
Bypass (not audit-logged): HIPPIUS_MEM_HOOKS_BYPASS=1.
EOF

[[ -f "$token_file" ]] || block_with_reason "$instruction"

token_ts="$(jq -r '.ts // 0' "$token_file" 2>/dev/null || echo 0)"
now="$(date +%s)"
age=$(( now - token_ts ))
if (( age >= REFRESH_WINDOW )); then
  block_with_reason "$instruction

(prior recall was ${age}s ago; window is ${REFRESH_WINDOW}s — recall again.)"
fi

remaining=$(( REFRESH_WINDOW - age ))
allow_with_warn "hippius-mem: recall evidence valid; ${remaining}s left in window. Recall again if the task shifts."
