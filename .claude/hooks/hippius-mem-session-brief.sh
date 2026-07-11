#!/usr/bin/env bash
#
# hippius-mem SessionStart hook — inject a tiered digest of the team's live
# memory (its conventions, decisions, and recent gotchas) as session context.
#
# Recall is pull-only: an agent only finds a note it already suspects exists.
# This brief hands it the durable rules and recent gotchas up front, closing the
# unknown-unknowns gap. It is a nicety, never load-bearing: any failure (no
# binary, no config, offline, empty memory) injects nothing and passes through,
# so it never blocks or noisily fails a session start. SessionStart hooks cannot
# block (exit 2 is ignored), which suits an advisory injection.
#
# I/O (Claude Code hook protocol):
#   stdin (JSON):  { session_id, source, cwd, hook_event_name, ... }
#   stdout (JSON): {"continue":true}
#                | {"hookSpecificOutput":{"hookEventName":"SessionStart",
#                                         "additionalContext":"..."}}

set -u

pass_through() {
  printf '{"continue":true}\n'
  exit 0
}
# shellcheck disable=SC2329  # invoked indirectly via trap ERR
on_error() { pass_through; }
trap on_error ERR

command -v jq >/dev/null 2>&1 || pass_through
[[ "${HIPPIUS_MEM_HOOKS_BYPASS:-0}" == "1" ]] && pass_through

# Consume the hook payload so the caller's pipe closes cleanly (content unused).
cat >/dev/null 2>&1 || true

# Resolve the hippius-mem binary: prefer PATH, else the command the MCP server is
# registered with in ~/.claude.json (the global-only registration this repo uses).
bin="$(command -v hippius-mem 2>/dev/null || true)"
if [[ -z "$bin" ]]; then
  claude_json="${HOME}/.claude.json"
  [[ -f "$claude_json" ]] || pass_through
  bin="$(jq -r '.mcpServers["hippius-mem"].command // empty' "$claude_json" 2>/dev/null || true)"
fi
[[ -n "$bin" && -x "$bin" ]] || pass_through

# Render the brief, time-boxed so a slow cold sync cannot delay session start.
# `timeout`/`gtimeout` may be absent (macOS without coreutils); fall back to a
# plain run. Any non-zero exit or empty output injects nothing.
if command -v timeout >/dev/null 2>&1; then
  brief="$(timeout 8s "$bin" brief 2>/dev/null || true)"
elif command -v gtimeout >/dev/null 2>&1; then
  brief="$(gtimeout 8s "$bin" brief 2>/dev/null || true)"
else
  brief="$("$bin" brief 2>/dev/null || true)"
fi
[[ -n "$brief" ]] || pass_through

# Feed the brief to jq as a raw string so every character is JSON-escaped for the
# additionalContext field.
jq -n --arg ctx "$brief" \
  '{hookSpecificOutput:{hookEventName:"SessionStart", additionalContext:$ctx}}'
exit 0
