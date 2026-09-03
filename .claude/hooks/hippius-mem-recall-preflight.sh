#!/usr/bin/env bash
#
# hippius-mem PreToolUse hook for Edit/Write/MultiEdit.
#
# Enforces "recall before you mutate": an in-repo file edit is BLOCKED until the
# agent has called `mcp__hippius-mem__recall` within the refresh window, so it
# consults team memory (past decisions, gotchas) before acting and does not
# repeat a mistake a teammate already recorded. An evidence-gate pattern: the
# edit is gated on proof the agent gathered the relevant context first.
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
#   4. hippius-mem absent this session    -> fail-open, VISIBLY (degraded_pass):
#      (no binary on PATH AND no MCP          this gate ships committed in
#       server registered)                    .claude/settings.json, so a teammate
#                                            who cloned the repo but never installed
#                                            or registered the server must not have
#                                            every edit blocked and be told to call
#                                            an MCP tool (recall) their session lacks
#   5. fresh recall token                 -> allow + warn (remaining window)
#      missing / stale token              -> BLOCK with instruction packet
#   internal error                        -> fail-open (a buggy hook must never
#                                            brick all edits)
#   no jq / no sha tool                   -> fail-open, but VISIBLY: a static
#                                            additionalContext names the missing
#                                            tool, so a machine where the gate is
#                                            inert says so in-session instead of
#                                            silently never enforcing
#
# The token this gate checks is written by the PostToolUse companion hook
# (hippius-mem-recall-token.sh) after each successful `recall` — that is what
# makes "the agent recalled" observable to this gate.

set -u

REFRESH_WINDOW="${HIPPIUS_MEM_RECALL_WINDOW_SECS:-1800}"

pass_through()      { printf '{"continue":true}\n'; exit 0; }
allow_with_warn()   { jq -n --arg m "$1" '{continue:true, additionalContext:$m}'; exit 0; }
# Claude honors `block`; Grok honors `deny`. Pick from the envelope style:
# Grok's hook JSON is camelCase (`toolName`), Claude's is snake_case.
block_with_reason() {
  local decision="block"
  if jq -e '.toolName' <<<"$input" >/dev/null 2>&1; then
    decision="deny"
  fi
  jq -n --arg r "$1" --arg d "$decision" '{decision:$d, reason:$r}'
  exit 0
}

# Fail-open like pass_through, but say so: without jq/sha this gate is inert on
# this machine FOREVER, and a silently disabled gate is the failure mode it
# exists to prevent. Hand-assembled static JSON (no jq available here); the only
# interpolation is the tool name this script passes itself.
degraded_pass() {
  printf '{"continue":true,"additionalContext":"[hippius-mem recall gate] INACTIVE on this machine: %s not found, so recall-before-mutate is NOT being enforced. Install it to restore the gate."}\n' "$1"
  exit 0
}

# Fail-open on any unexpected error: never let a hook bug block editing.
# shellcheck disable=SC2317,SC2329  # invoked indirectly via trap ERR; shellcheck
# renumbered this diagnostic (SC2317 up to 0.9.x, SC2329 from 0.10), so both
# codes are listed to stay clean whichever version a contributor has.
on_error() { pass_through; }
trap on_error ERR

command -v jq >/dev/null 2>&1 || degraded_pass "jq"

input="$(cat || true)"
[[ -n "$input" ]] || pass_through

[[ "${HIPPIUS_MEM_HOOKS_BYPASS:-0}" == "1" ]] && pass_through

tool_name="$(jq -r '.tool_name // .toolName // empty' <<<"$input" 2>/dev/null || echo "")"
file_path="$(jq -r '.tool_input.file_path // .toolInput.file_path // .toolInput.path // empty' <<<"$input" 2>/dev/null || echo "")"
cwd="$(jq -r '.cwd // empty'                        <<<"$input" 2>/dev/null || echo "")"
session_id="$(jq -r '.session_id // .sessionId // "unknown"' <<<"$input" 2>/dev/null || echo unknown)"
[[ -n "$cwd" ]] || cwd="${PWD:-.}"

case "$tool_name" in
  Edit|Write|MultiEdit|search_replace) : ;;
  *) pass_through ;;
esac

# Enforce only for edits inside THIS repo. The hook ships at
# <repo>/.claude/hooks/. Grok resolves command paths relative to
# settings.json, so it execs via a symlink at .claude/.claude/hooks/ →
# ../hooks; cd into the script dir then pwd -P so that path still yields
# <repo>. `file_abs` is resolved by STRING join (not `cd`) so a new file
# in a not-yet-created subdir still classifies correctly.
hook_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P 2>/dev/null || echo "")"
repo_root=""
[[ -n "$hook_dir" ]] && repo_root="$(cd "$hook_dir/../.." && pwd -P 2>/dev/null || echo "")"
# Empty repo_root would make `"$repo_root"/*` expand to `/*` and treat every
# absolute path as in-tree. Fail-open like the sibling hooks.
[[ -n "$repo_root" ]] || pass_through
case "$file_path" in
  /*) file_abs="$file_path" ;;
  *)  file_abs="$cwd/$file_path" ;;
esac
case "$file_abs" in
  "$repo_root"|"$repo_root"/*) : ;;
  *) pass_through ;;
esac

# Fail OPEN, VISIBLY, when hippius-mem is not available to THIS session at all.
# This gate ships committed in .claude/settings.json, so a teammate who clones
# the repo but has NOT installed/registered hippius-mem would otherwise have
# every in-repo Edit/Write blocked and be told to call mcp__hippius-mem__recall
# -- an MCP tool that does not exist in their session, a hard brick with no way
# to satisfy the gate. Same on a machine that never registered the server. Mirror
# the missing-jq/sha path: allow the edit, but say the gate is inactive.
#
# "Available" = EITHER a hippius-mem binary on PATH OR the MCP server registered
# somewhere this session could load the recall tool from -- global ~/.claude.json
# .mcpServers, project-local .projects["<repo>"].mcpServers (probed under this
# root AND, from a linked git worktree, under the MAIN repository root, since
# .projects is keyed by the main checkout's path), or a committed .mcp.json at
# the repo root (the same resolution the sibling session-brief hook relies
# on). We fail open ONLY when NONE of those is present, so the normal case
# (hippius-mem installed but the agent simply has not recalled yet) still BLOCKS.
# A server that IS registered but currently DOWN/erroring is deliberately NOT
# caught here -- it is indistinguishable from "registered and healthy" without
# invoking it (slow, could hang) -- and is instead covered by the server-down
# bypass guidance in the block message below.
hippius_mem_reachable() {
  command -v hippius-mem >/dev/null 2>&1 && return 0
  claude_json="${HOME:-}/.claude.json"
  if [[ -n "${HOME:-}" && -f "$claude_json" ]]; then
    [[ -n "$(jq -r '.mcpServers["hippius-mem"].command // empty' "$claude_json" 2>/dev/null || true)" ]] && return 0
    [[ -n "$(jq -r --arg r "$repo_root" '.projects[$r].mcpServers["hippius-mem"].command // empty' "$claude_json" 2>/dev/null || true)" ]] && return 0
    # In a linked git WORKTREE (e.g. .claude/worktrees/*) or under a symlinked
    # launch path, repo_root above resolves to the WORKTREE path while
    # .projects is keyed by the MAIN repo path -- the probe above misses and
    # the gate would silently fail open for a session that IS registered
    # project-locally. Resolve the main root via the shared .git dir and probe
    # that key too. Any git failure (absent, old, not a repo) just skips this
    # extra probe -- an optional probe must never error the hook.
    main_root=""
    if command -v git >/dev/null 2>&1; then
      common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "")"
      if [[ -z "$common_dir" ]]; then
        # Older gits lack --path-format and may print a path relative to
        # repo_root; resolve it the same way repo_root itself was resolved.
        common_dir="$(git -C "$repo_root" rev-parse --git-common-dir 2>/dev/null || echo "")"
        if [[ -n "$common_dir" && "$common_dir" != /* ]]; then
          common_dir="$(cd "$repo_root/$common_dir" 2>/dev/null && pwd -P || echo "")"
        fi
      fi
      [[ "$common_dir" == */.git ]] && main_root="${common_dir%/.git}"
    fi
    if [[ -n "$main_root" && "$main_root" != "$repo_root" ]]; then
      [[ -n "$(jq -r --arg r "$main_root" '.projects[$r].mcpServers["hippius-mem"].command // empty' "$claude_json" 2>/dev/null || true)" ]] && return 0
    fi
  fi
  if [[ -f "$repo_root/.mcp.json" ]]; then
    [[ -n "$(jq -r '.mcpServers["hippius-mem"].command // empty' "$repo_root/.mcp.json" 2>/dev/null || true)" ]] && return 0
  fi
  return 1
}
hippius_mem_reachable || degraded_pass "hippius-mem"

# Token is keyed by the SESSION id (the companion PostToolUse hook writes it
# under the same key), so each new session must recall before its first edit
# rather than inheriting a previous session's token. The repo is still scoped by
# the token dir path; the freshness window below re-forces recall on long sessions.
if command -v shasum >/dev/null 2>&1; then
  key="$(printf %s "$session_id" | shasum -a 256 | cut -c1-16)"
elif command -v sha256sum >/dev/null 2>&1; then
  key="$(printf %s "$session_id" | sha256sum | cut -c1-16)"
else
  degraded_pass "shasum/sha256sum"
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
  1. Call recall (mcp__hippius-mem__recall or hippius-mem__recall) with a
     query describing what you are about to do (the feature, bug, file, or
     subsystem). Read the returned summaries and `get` any that look relevant.
  2. Retry your Edit/Write call.

One recall opens the gate for the whole refresh window.
Bypass (not audit-logged): HIPPIUS_MEM_HOOKS_BYPASS=1.
Server down / recall keeps erroring? Then the token cannot refresh and edits stay
blocked -- set that bypass in this project's .claude/settings.local.json (the
session project root, not a worktree's) to proceed.
EOF

# -s (exists AND non-empty): a zero-byte token — a truncated write from a
# failed companion hook — would make `jq -r '.ts // 0'` emit NOTHING with exit
# 0, and the empty arithmetic below would ERR-trap the gate silently open.
# Blocking is safe here: a recall re-writes a fresh, valid token and clears it.
[[ -s "$token_file" ]] || block_with_reason "$instruction"

token_ts="$(jq -r '.ts // 0' "$token_file" 2>/dev/null || echo 0)"
now="$(date +%s)"
age=$(( now - token_ts ))
if (( age >= REFRESH_WINDOW )); then
  block_with_reason "$instruction

(prior recall was ${age}s ago; window is ${REFRESH_WINDOW}s — recall again.)"
fi

remaining=$(( REFRESH_WINDOW - age ))
allow_with_warn "hippius-mem: recall evidence valid; ${remaining}s left in window. Recall again if the task shifts."
