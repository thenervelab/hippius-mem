#!/usr/bin/env bash
#
# hippius-mem SessionStart hook — the one-time "seed existing memory" nudge.
#
# When `init` provisions a repo that ALREADY holds knowledge (a hand-written
# CLAUDE.md, or a personal Claude Code memory index under ~/.claude/projects/),
# it records the source paths in .hippius-mem/cache/seed-pending.json. On session
# start this hook reminds the agent ONCE to lift the genuinely team-durable facts
# into hippius-mem — the agent (an LLM) makes the team-relevant-vs-personal
# judgment the Rust binary cannot. It suppresses itself permanently once
# .hippius-mem/cache/seeded exists, which the agent creates when the pass is done.
#
# SessionStart hooks CANNOT block (exit 2 is ignored) and fire on
# startup/resume/clear/compact. This one only ever INJECTS context and
# self-suppresses via the seeded marker, so firing on every source is harmless.
#
# I/O (Claude Code hook protocol):
#   stdin (JSON):  { session_id, source, cwd, hook_event_name, ... }
#   stdout (JSON): {"continue":true}
#                | {"hookSpecificOutput":{"hookEventName":"SessionStart",
#                                         "additionalContext":"..."}}

set -u

pass_through() { printf '{"continue":true}\n'; exit 0; }
# shellcheck disable=SC2329  # invoked indirectly via trap ERR
on_error() { pass_through; }
trap on_error ERR

command -v jq >/dev/null 2>&1 || pass_through

input="$(cat || true)"
[[ -n "$input" ]] || pass_through

[[ "${HIPPIUS_MEM_HOOKS_BYPASS:-0}" == "1" ]] && pass_through

# The hook ships at <repo>/.claude/hooks/, so parent-of-parent is the repo root —
# the same anchor the other hippius-mem hooks use.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P 2>/dev/null || echo "")"
[[ -n "$repo_root" ]] || pass_through

cache="$repo_root/.hippius-mem/cache"
# Already curated -> never nudge again.
[[ -f "$cache/seeded" ]] && pass_through
# Nothing detected to seed -> nothing to do.
pending="$cache/seed-pending.json"
[[ -f "$pending" ]] || pass_through

# One "  - <path>" line per recorded source. `.sources[]?` tolerates a malformed
# or empty array without erroring (the ERR trap would pass through anyway).
sources="$(jq -r '.sources[]? | "  - " + .' "$pending" 2>/dev/null || echo "")"
[[ -n "$sources" ]] || pass_through

# Build the directive with `read -r -d ''` over an UNQUOTED heredoc: it expands
# $sources / $cache but, unlike `directive="$(cat <<EOF ...)"`, involves no command
# substitution, so a literal apostrophe in the body cannot break bash's parse (the
# gotcha the recall-preflight and remember-nudge hooks document). `read -d ''`
# slurps to EOF and returns non-zero there, hence `|| true`.
read -r -d '' directive <<EOF || true
[hippius-mem seed checkpoint]

This repo has existing memory not yet lifted into shared team memory:
$sources

Do a one-time curated pass: read those sources, call mcp__hippius-mem__recall to
avoid duplicating what is already stored, then mcp__hippius-mem__remember ONLY the
genuinely team-durable facts (decisions, gotchas, conventions, references) — skip
personal preferences, per-session trivia, and anything obvious from the code or
git history. One self-contained fact per note, with a keyword-rich summary.

When the pass is done (or if nothing is worth lifting), dismiss this checkpoint:
  touch "$cache/seeded"

Bypass: HIPPIUS_MEM_HOOKS_BYPASS=1.
EOF

# Feed the directive to jq as a raw string argument so every character in it is
# JSON-escaped correctly for the additionalContext field.
jq -n --arg ctx "$directive" \
  '{hookSpecificOutput:{hookEventName:"SessionStart", additionalContext:$ctx}}'
exit 0
