#!/usr/bin/env sh
# Tests .claude/hooks/hippius-mem-recall-token.sh -- the PostToolUse hook that
# stamps the recall token the edit-gate checks for. The token is the gate's only
# evidence that the agent consulted team memory, so the behaviour that matters
# is WHEN one is written:
#   1. a recall that returned a result            -> token written
#   2. a recall the user rejected (Cursor CLI)    -> no token
#   3. a recall that returned an MCP error        -> no token
#   4. the same error, result sent as JSON text   -> no token
#   5. a result whose text only mentions isError  -> token written
#
# Cases 2 to 4 are the Cursor CLI's behaviour (cursor-agent 2026.09.28, observed
# 2026-11-19): it fires PostToolUse for a rejected or failed call, where Claude
# Code fires it only after a success. Without them a failed recall opened the
# gate. Case 5 pins that the check reads the result's fields, not its text: a
# note about `isError` must not make a good recall look failed.
#
# The hook is copied into a throwaway fake repo, because it derives the repo
# root from its own location and writes the token under it.
set -eu

# shellcheck disable=SC1007 # intentional: CDPATH= prefixes `cd` (empties it for
# this command only); it is not a mistyped "VAR = value" assignment.
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REAL_HOOK="$REPO_ROOT/.claude/hooks/hippius-mem-recall-token.sh"

if [ ! -f "$REAL_HOOK" ]; then
  echo "FAIL: hook not found at $REAL_HOOK"
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

FAKE_REPO="$WORK/repo"
mkdir -p "$FAKE_REPO/.claude/hooks"
cp "$REAL_HOOK" "$FAKE_REPO/.claude/hooks/hippius-mem-recall-token.sh"
FAKE_HOOK="$FAKE_REPO/.claude/hooks/hippius-mem-recall-token.sh"
TOKEN_DIR="$FAKE_REPO/.hippius-mem/cache/recall-tokens"

# Run the hook on payload $1, then report how many tokens the fake repo holds.
# Each case starts from an empty token directory.
tokens_after() {
  rm -rf "$TOKEN_DIR"
  _out=$(printf '%s' "$1" | bash "$FAKE_HOOK")
  if [ "$_out" != '{"continue":true}' ]; then
    echo "FAIL: PostToolUse must always answer continue:true, got: $_out"
    exit 1
  fi
  find "$TOKEN_DIR" -name '*.json' 2>/dev/null | wc -l | tr -d ' '
}

# $1 case name, $2 expected token count, $3 payload.
expect_tokens() {
  _got=$(tokens_after "$3")
  if [ "$_got" != "$2" ]; then
    echo "FAIL: $1: expected $2 token(s), found $_got"
    exit 1
  fi
  echo "PASS: $1"
}

expect_tokens "a recall that returned a result writes the token" 1 \
  '{"session_id":"s1","tool_name":"mcp__hippius-mem__recall","tool_response":{"pointers":[],"returned":0}}'

expect_tokens "a recall the user rejected writes no token" 0 \
  '{"session_id":"s2","tool_name":"MCP:recall","tool_output":{"rejected":true,"reason":"User rejected MCP: hippius-mem-recall"}}'

expect_tokens "a recall that returned an MCP error writes no token" 0 \
  '{"session_id":"s3","tool_name":"MCP:recall","tool_output":{"isError":true,"content":[{"type":"text","text":"daemon is still syncing"}]}}'

expect_tokens "an MCP error sent as JSON text writes no token" 0 \
  '{"session_id":"s4","tool_name":"MCP:recall","tool_output":"{\"isError\":true}"}'

expect_tokens "a result that only mentions isError in its text writes the token" 1 \
  '{"session_id":"s5","tool_name":"MCP:recall","tool_output":{"content":[{"type":"text","text":"note: \"isError\":true means the call failed, \"rejected\":true means refused"}]}}'

echo "PASS: the recall token is written for a recall that returned a result, and only then"
