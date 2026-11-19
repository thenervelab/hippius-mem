#!/usr/bin/env sh
# Tests .claude/hooks/hippius-mem-recall-preflight.sh -- the PreToolUse edit-gate
# that BLOCKS the first in-repo Edit/Write/MultiEdit until a recall token proves
# the agent consulted team memory. The behaviour that matters and has no other
# guard: the gate must FAIL OPEN when hippius-mem is not available to the session
# at all, and only then. This gate ships committed in .claude/settings.json, so a
# teammate who clones the repo but never installed/registered hippius-mem would
# otherwise have every edit blocked and be told to call an MCP tool (recall) that
# does not exist in their session -- a hard brick. The four cases below pin:
#   1. no binary on PATH AND no MCP registration  -> ALLOW (visible degraded pass)
#   2. binary present, no recall token yet         -> BLOCK (the gate's whole point)
#   3. HIPPIUS_MEM_HOOKS_BYPASS=1                   -> ALLOW (clean pass-through)
#   4. hook under a linked git WORKTREE, server registered project-locally under
#      the MAIN repo path in ~/.claude.json         -> BLOCK (main-root probe)
#   5. fresh recall token, a note tied to the file  -> ALLOW carrying the note
#      on the first edit of the file, and not again on the second
#
# The hook is copied into a sandbox fake-repo so repo_root resolves to a throwaway
# tree (the hook derives it from its own location), HOME points at an empty dir
# (no ~/.claude.json registration), and PATH is a symlink farm of just the tools
# the hook needs -- so whether `hippius-mem` is on PATH is fully controlled here
# rather than depending on what the test machine happens to have installed.
set -eu

# shellcheck disable=SC1007 # intentional: CDPATH= prefixes `cd` (empties it for
# this command only); it is not a mistyped "VAR = value" assignment.
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REAL_HOOK="$REPO_ROOT/.claude/hooks/hippius-mem-recall-preflight.sh"

if [ ! -f "$REAL_HOOK" ]; then
  echo "FAIL: hook not found at $REAL_HOOK"
  exit 1
fi

# Absolute bash + jq resolved now, while the real PATH is still intact; the runs
# below use a shrunk PATH that must not have to find them.
BASH_BIN=$(command -v bash)
JQ_BIN=$(command -v jq)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# Resolve to the physical path: on macOS mktemp returns /var/... while the hook
# derives repo_root via `pwd -P` (/private/var/...). Matching them here keeps the
# in-tree check comparing like with like, so the JSON file_path lands in-tree.
# shellcheck disable=SC1007 # intentional CDPATH= prefix (see REPO_ROOT above).
WORK=$(CDPATH= cd -- "$WORK" && pwd -P)

# Fake repo: hook copied so `cd "$hook_dir/../.."` yields $FAKE_REPO, not the real
# tree. A fresh copy each run means the test always exercises the current hook.
FAKE_REPO="$WORK/repo"
mkdir -p "$FAKE_REPO/.claude/hooks"
cp "$REAL_HOOK" "$FAKE_REPO/.claude/hooks/hippius-mem-recall-preflight.sh"
FAKE_HOOK="$FAKE_REPO/.claude/hooks/hippius-mem-recall-preflight.sh"

# Empty HOME: no ~/.claude.json, so the registration probe finds nothing.
FAKE_HOME="$WORK/home"
mkdir -p "$FAKE_HOME"

# Tool farm: symlink only the externals the hook calls, so `hippius-mem` presence
# is decided purely by whether we add its stub dir to PATH.
BASE_BIN="$WORK/toolbin"
mkdir -p "$BASE_BIN"
for _t in jq cat dirname date shasum sha256sum cut grep; do
  _p=$(command -v "$_t" 2>/dev/null || true)
  [ -n "$_p" ] && ln -s "$_p" "$BASE_BIN/$_t"
done

# A no-op `hippius-mem` on PATH makes the binary "present" (the hook only probes
# `command -v hippius-mem`, never runs it).
HM_BIN="$WORK/hmbin"
mkdir -p "$HM_BIN"
cat > "$HM_BIN/hippius-mem" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$HM_BIN/hippius-mem"

# Build a hook payload with real jq so paths are always valid JSON.
make_json() {
  # shellcheck disable=SC2016 # $fp/$cwd/$sid are jq variables (bound by --arg),
  # not shell expansions; single quotes keep the shell from touching them.
  "$JQ_BIN" -nc \
    --arg fp "$FAKE_REPO/somefile.txt" \
    --arg cwd "$FAKE_REPO" \
    --arg sid "$1" \
    '{tool_name:"Edit", tool_input:{file_path:$fp}, cwd:$cwd, session_id:$sid}'
}

# Run the hook hermetically: env -i so only HOME/PATH (+ optional bypass) reach it.
# $1 out file, $2 PATH, $3 session id, $4 optional bypass value.
run_hook() {
  _out=$1; _path=$2; _sid=$3; _bypass=${4:-}
  _json=$(make_json "$_sid")
  if [ -n "$_bypass" ]; then
    if printf '%s' "$_json" | env -i HOME="$FAKE_HOME" PATH="$_path" \
        HIPPIUS_MEM_HOOKS_BYPASS="$_bypass" "$BASH_BIN" "$FAKE_HOOK" >"$_out" 2>&1
    then status=0; else status=$?; fi
  else
    if printf '%s' "$_json" | env -i HOME="$FAKE_HOME" PATH="$_path" \
        "$BASH_BIN" "$FAKE_HOOK" >"$_out" 2>&1
    then status=0; else status=$?; fi
  fi
}

# --- Case 1: no binary + no registration -> visible fail-open (ALLOW) ----------
run_hook "$WORK/out-absent" "$BASE_BIN" "sess-absent"

if [ "$status" -ne 0 ]; then
  echo "FAIL: hook exited $status when hippius-mem is absent (must not error)"
  cat "$WORK/out-absent"; exit 1
fi
if ! grep -q '"continue"[[:space:]]*:[[:space:]]*true' "$WORK/out-absent"; then
  echo "FAIL: absent hippius-mem did not ALLOW the edit (expected continue:true)"
  cat "$WORK/out-absent"; exit 1
fi
if grep -q '"decision"' "$WORK/out-absent"; then
  echo "FAIL: absent hippius-mem BLOCKED the edit (would brick a fresh clone)"
  cat "$WORK/out-absent"; exit 1
fi
if ! grep -q 'INACTIVE on this machine: hippius-mem not found' "$WORK/out-absent"; then
  echo "FAIL: fail-open was silent; expected the visible degraded-pass message"
  cat "$WORK/out-absent"; exit 1
fi
echo "PASS: absent hippius-mem fails OPEN with a visible degraded-pass message"

# --- Case 2: binary present, no recall token -> BLOCK --------------------------
run_hook "$WORK/out-block" "$HM_BIN:$BASE_BIN" "sess-block"

if [ "$status" -ne 0 ]; then
  echo "FAIL: hook exited $status on the block path (must emit JSON, exit 0)"
  cat "$WORK/out-block"; exit 1
fi
if ! grep -q '"decision"[[:space:]]*:[[:space:]]*"block"' "$WORK/out-block"; then
  echo "FAIL: gate did not BLOCK when hippius-mem is present but no recall token"
  cat "$WORK/out-block"; exit 1
fi
# The Cursor CLI ignores the top-level `decision` and applies the edit; it
# refuses only on `hookSpecificOutput.permissionDecision`. The reason must ride
# that shape too, or the model is refused with nothing to act on.
# shellcheck disable=SC2016 # $r is a jq variable, not a shell expansion.
if ! "$JQ_BIN" -e '.reason as $r | .hookSpecificOutput
      | .hookEventName == "PreToolUse" and .permissionDecision == "deny"
        and .permissionDecisionReason == $r and ($r | length) > 0' \
    "$WORK/out-block" >/dev/null; then
  echo "FAIL: block did not carry hookSpecificOutput.permissionDecision=deny with the reason"
  cat "$WORK/out-block"; exit 1
fi
if ! grep -q 'RECALL-BEFORE-MUTATE not satisfied' "$WORK/out-block"; then
  echo "FAIL: block reason missing the recall instruction packet"
  cat "$WORK/out-block"; exit 1
fi
# The extended block message must name the server-down bypass path.
if ! grep -q 'settings.local.json' "$WORK/out-block"; then
  echo "FAIL: block message missing the server-down bypass guidance"
  cat "$WORK/out-block"; exit 1
fi
echo "PASS: present hippius-mem + no token BLOCKS with the recall + bypass guidance"

# --- Case 3: HIPPIUS_MEM_HOOKS_BYPASS=1 -> clean pass-through (ALLOW) ----------
run_hook "$WORK/out-bypass" "$HM_BIN:$BASE_BIN" "sess-bypass" "1"

if [ "$status" -ne 0 ]; then
  echo "FAIL: hook exited $status under bypass"
  cat "$WORK/out-bypass"; exit 1
fi
if ! grep -q '"continue"[[:space:]]*:[[:space:]]*true' "$WORK/out-bypass"; then
  echo "FAIL: bypass did not ALLOW the edit"
  cat "$WORK/out-bypass"; exit 1
fi
if grep -q '"decision"' "$WORK/out-bypass"; then
  echo "FAIL: bypass still BLOCKED the edit"
  cat "$WORK/out-bypass"; exit 1
fi
if grep -q 'INACTIVE' "$WORK/out-bypass"; then
  echo "FAIL: bypass emitted a degraded-pass instead of a clean pass-through"
  cat "$WORK/out-bypass"; exit 1
fi
echo "PASS: HIPPIUS_MEM_HOOKS_BYPASS=1 passes through cleanly"

# --- Case 4: worktree install, .projects keyed by the MAIN repo root -> BLOCK --
# A linked git worktree (e.g. .claude/worktrees/*) makes the hook resolve
# repo_root to the WORKTREE path, while ~/.claude.json .projects is keyed by the
# MAIN repo path. Without the main-root probe every registration probe misses
# and the gate silently degraded-passes for a session that IS registered
# project-locally -- unenforced exactly where it should block.
GIT_BIN_PATH=$(command -v git 2>/dev/null || true)
if [ -z "$GIT_BIN_PATH" ]; then
  echo "SKIP: git not available; worktree main-root probe case not exercised"
else
  # Sandboxed git identity/config so nothing leaks in from the tester's real
  # HOME or system gitconfig (gpg signing, hooks, templates, ...).
  WT_HOME="$WORK/home-wt"
  mkdir -p "$WT_HOME"
  git_q() {
    env HOME="$WT_HOME" GIT_CONFIG_NOSYSTEM=1 "$GIT_BIN_PATH" \
      -c user.name=t -c user.email=t@example.invalid \
      -c commit.gpgsign=false -c core.hooksPath=/dev/null \
      -c init.defaultBranch=main "$@"
  }

  MAIN_REPO="$WORK/mainrepo"
  WT_REPO="$MAIN_REPO/.claude/worktrees/wt"
  if git_q init -q "$MAIN_REPO" >/dev/null 2>&1 \
    && git_q -C "$MAIN_REPO" commit -q --allow-empty -m init >/dev/null 2>&1 \
    && git_q -C "$MAIN_REPO" worktree add "$WT_REPO" >/dev/null 2>&1
  then
    # Hook installed under the WORKTREE, so its repo_root is the worktree path.
    mkdir -p "$WT_REPO/.claude/hooks"
    cp "$REAL_HOOK" "$WT_REPO/.claude/hooks/hippius-mem-recall-preflight.sh"
    WT_HOOK="$WT_REPO/.claude/hooks/hippius-mem-recall-preflight.sh"

    # ~/.claude.json registers hippius-mem ONLY under .projects[<MAIN root>];
    # no global .mcpServers, no binary on PATH, no committed .mcp.json.
    # shellcheck disable=SC2016 # $root is a jq variable (bound by --arg), not
    # a shell expansion; single quotes keep the shell from touching it.
    "$JQ_BIN" -n --arg root "$MAIN_REPO" \
      '{projects: {($root): {mcpServers: {"hippius-mem": {command: "hippius-mem"}}}}}' \
      > "$WT_HOME/.claude.json"

    # git must be reachable inside the hermetic hook run for the main-root probe.
    WT_GIT_BIN="$WORK/gitbin"
    mkdir -p "$WT_GIT_BIN"
    ln -s "$GIT_BIN_PATH" "$WT_GIT_BIN/git"

    # shellcheck disable=SC2016 # jq variables (see make_json above).
    _json=$("$JQ_BIN" -nc \
      --arg fp "$WT_REPO/somefile.txt" \
      --arg cwd "$WT_REPO" \
      '{tool_name:"Edit", tool_input:{file_path:$fp}, cwd:$cwd, session_id:"sess-worktree"}')
    if printf '%s' "$_json" | env -i HOME="$WT_HOME" GIT_CONFIG_NOSYSTEM=1 \
        PATH="$WT_GIT_BIN:$BASE_BIN" "$BASH_BIN" "$WT_HOOK" \
        >"$WORK/out-worktree" 2>&1
    then status=0; else status=$?; fi

    if [ "$status" -ne 0 ]; then
      echo "FAIL: hook exited $status on the worktree block path (must emit JSON, exit 0)"
      cat "$WORK/out-worktree"; exit 1
    fi
    if ! grep -q '"decision"[[:space:]]*:[[:space:]]*"block"' "$WORK/out-worktree"; then
      echo "FAIL: worktree edit with MAIN-root .projects registration did not BLOCK (gate fail-opened)"
      cat "$WORK/out-worktree"; exit 1
    fi
    if ! grep -q 'RECALL-BEFORE-MUTATE not satisfied' "$WORK/out-worktree"; then
      echo "FAIL: worktree block reason missing the recall instruction packet"
      cat "$WORK/out-worktree"; exit 1
    fi
    echo "PASS: worktree install + MAIN-root .projects registration BLOCKS via the main-root probe"
  else
    echo "SKIP: git worktree setup failed; worktree main-root probe case not exercised"
  fi
fi

# --- Case 5: fresh token + a note tied to the file -> ALLOW carrying it, once --
# A `hippius-mem` stub that answers `path-notes` the way the real command
# does, and records its arguments so the test can check what the hook asked.
PN_BIN="$WORK/pnbin"
mkdir -p "$PN_BIN"
cat > "$PN_BIN/hippius-mem" <<STUB
#!/bin/sh
printf '%s\\n' "\$*" >> "$WORK/pn-args"
[ "\$1" = "path-notes" ] && printf '%s\\n' '- [gotcha] quokka rebuild needs the lock (mem_1)'
exit 0
STUB
chmod +x "$PN_BIN/hippius-mem"

if command -v shasum >/dev/null 2>&1; then
  PN_KEY=$(printf %s "sess-notes" | shasum -a 256 | cut -c1-16)
else
  PN_KEY=$(printf %s "sess-notes" | sha256sum | cut -c1-16)
fi
mkdir -p "$FAKE_REPO/.hippius-mem/cache/recall-tokens"
printf '{"ts":%s}\n' "$(date +%s)" \
  > "$FAKE_REPO/.hippius-mem/cache/recall-tokens/$PN_KEY.json"

run_hook "$WORK/out-notes-1" "$PN_BIN:$BASE_BIN" "sess-notes"
if [ "$status" -ne 0 ] || grep -q '"decision"' "$WORK/out-notes-1"; then
  echo "FAIL: a fresh recall token did not ALLOW the edit"
  cat "$WORK/out-notes-1"; exit 1
fi
# Claude Code reads PreToolUse context from this nested field only.
# shellcheck disable=SC2016 # a jq program, not a shell expansion.
if ! "$JQ_BIN" -e '.hookSpecificOutput.hookEventName == "PreToolUse"
    and (.hookSpecificOutput.additionalContext | contains("quokka rebuild needs the lock"))' \
    "$WORK/out-notes-1" >/dev/null; then
  echo "FAIL: the first edit of a file did not carry the note tied to it"
  cat "$WORK/out-notes-1"; exit 1
fi
if ! grep -q -- "path-notes --repo-root $FAKE_REPO --file $FAKE_REPO/" "$WORK/pn-args"; then
  echo "FAIL: the hook did not ask for the edited file under the repository root"
  cat "$WORK/pn-args"; exit 1
fi

run_hook "$WORK/out-notes-2" "$PN_BIN:$BASE_BIN" "sess-notes"
if [ "$status" -ne 0 ] || ! grep -q 'recall evidence valid' "$WORK/out-notes-2"; then
  echo "FAIL: the second edit of the file was not a plain allow"
  cat "$WORK/out-notes-2"; exit 1
fi
if grep -q 'quokka rebuild needs the lock' "$WORK/out-notes-2"; then
  echo "FAIL: the note was repeated on the second edit of the same file"
  cat "$WORK/out-notes-2"; exit 1
fi
echo "PASS: a note tied to a file rides the first allow for that file, once"

# A lookup that could not ask the daemon (non-zero exit) must not mark the file
# seen: the next edit asks again and then carries the note.
DOWN_BIN="$WORK/downbin"
mkdir -p "$DOWN_BIN"
printf '#!/bin/sh\nexit 1\n' > "$DOWN_BIN/hippius-mem"
chmod +x "$DOWN_BIN/hippius-mem"
if command -v shasum >/dev/null 2>&1; then
  DOWN_KEY=$(printf %s "sess-down" | shasum -a 256 | cut -c1-16)
else
  DOWN_KEY=$(printf %s "sess-down" | sha256sum | cut -c1-16)
fi
printf '{"ts":%s}\n' "$(date +%s)" \
  > "$FAKE_REPO/.hippius-mem/cache/recall-tokens/$DOWN_KEY.json"

run_hook "$WORK/out-down" "$DOWN_BIN:$BASE_BIN" "sess-down"
if [ "$status" -ne 0 ] || ! grep -q 'recall evidence valid' "$WORK/out-down"; then
  echo "FAIL: a failed path-notes lookup did not leave a plain allow"
  cat "$WORK/out-down"; exit 1
fi
run_hook "$WORK/out-up" "$PN_BIN:$BASE_BIN" "sess-down"
if ! grep -q 'quokka rebuild needs the lock' "$WORK/out-up"; then
  echo "FAIL: a file whose lookup failed was marked seen and never asked again"
  cat "$WORK/out-up"; exit 1
fi
echo "PASS: a failed lookup is retried on the next edit of the file"

echo "PASS: recall-preflight gate fails open when absent, blocks when present, honors bypass, sees MAIN-root registration from a worktree, and delivers path notes once"
