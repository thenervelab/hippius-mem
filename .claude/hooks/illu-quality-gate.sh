#!/usr/bin/env bash
#
# illu PreToolUse hook for `git commit` on Rust commits.
#
# Installed by `illu init --agent claude --with-hooks` at
# `<repo>/.claude/hooks/illu-quality-gate.sh`. Gates `Bash(git commit*)`
# invocations on fresh quality-gate evidence: a recent `quality_gate`
# call with a `staged_diff_sha256` field that matches the about-to-be-
# committed content.
#
# Parallel to `illu-preflight.sh`. Same I/O contract, same fail-open
# philosophy, same trust boundary.
#
# I/O contract (Claude Code hook protocol):
#   Input  (stdin, JSON):  { tool_name, tool_input.command, cwd, session_id, ... }
#   Output (stdout, JSON):
#     Allow + warn:    { "continue": true,  "additionalContext": "..." }
#     Block:           { "decision": "block", "reason": "..." }
#     Pass-through:    { "continue": true }
#
# Decision tree:
#   1. ILLU_HOOKS_BYPASS=1?                  -> log + pass-through
#   2. tool_name != "Bash"?                  -> pass-through
#   3. command not a `git commit` invocation -> pass-through
#   4. `git diff --staged --name-only` shows no
#      `{src,tests,examples}/**/*.rs` files? -> pass-through
#   5. token file missing?                   -> BLOCK with instruction packet
#   6. token `ts` older than REFRESH_WINDOW? -> BLOCK ("token expired")
#   7. token `staged_diff_sha256` mismatch?  -> BLOCK ("staged content changed")
#   8. all checks pass                       -> ALLOW + WARN
#   Hook internal error                      -> fail-open + log
#
# Fail-open philosophy: a buggy hook should not brick all git commits.
# Errors are logged to .illu/cache/hook-errors/<date>.jsonl for the v2
# auditor.
#
# Trust boundary:
#   The hook reads `.ts` and `.staged_diff_sha256` from the cached JSON
#   and compares against the current wall-clock and a recomputed hash.
#   Any writer to .illu/cache/quality-gate-tokens/ can set both fields
#   arbitrarily. This is acceptable: write access to that directory
#   implies write access to the entire repo (and thus to the source
#   files this gate protects), so the gate adds no defense against an
#   attacker who already has it. The gate exists to enforce
#   engineer-mentality discipline against *agents*, not security
#   against humans/attackers.

set -u

REFRESH_WINDOW="${ILLU_REFRESH_WINDOW_SECS:-1800}"

pass_through() {
    printf '{"continue":true}\n'
    exit 0
}

allow_with_warn() {
    local msg="$1"
    jq -n --arg msg "$msg" '{continue:true, additionalContext:$msg}'
    exit 0
}

block_with_reason() {
    local reason="$1"
    jq -n --arg reason "$reason" '{decision:"block", reason:$reason}'
    exit 0
}

# Resolve a directory to its registered repo root (CANONICAL path) via the
# illu-rs binary, or print nothing. Lets the gate fire cross-repo: a
# `git commit` redirected into a registered sibling repo is keyed to THAT
# repo's quality-gate token, where `quality_gate repo_path:<R>
# commit_cwd:<R>` writes it. Fail-OPEN on tooling problems (mirrors the
# shasum fail-open). `ILLU_BIN` overrides the binary for tests / non-PATH
# installs.
resolve_target_repo() {
    local dir="$1" bin out
    bin="${ILLU_BIN:-}"
    if [[ -z "$bin" ]]; then
        bin="$(command -v illu-rs 2>/dev/null || echo "$HOME/.cargo/bin/illu-rs")"
    fi
    [[ -x "$bin" ]] || { printf ''; return 0; }
    # Capture stdout and honor the binary's EXIT status: `which-repo` prints
    # nothing on a miss (exit 0) and on a registry error (exit non-zero), so
    # an empty or failed result yields empty here. First line only.
    out="$("$bin" which-repo "$dir" 2>/dev/null)" || { printf ''; return 0; }
    printf '%s' "${out%%$'\n'*}"
}

# Extract the directory the git subcommand actually targets when the
# command REDIRECTS away from `$cwd`: a `git -C <path>` argument or a
# leading `cd <path> && ...` / `cd <path>; ...` prefix. Prints empty when
# the command runs git in `$cwd` unchanged (the common case). Relative
# paths are resolved against `$cwd`.
#
# Known limitations (all fail-OPEN — they bypass the cross-repo gate, they
# never produce a false block):
#   - Quoted paths containing spaces are mis-tokenized (same
#     whitespace-split limitation as the git-verb detector below).
#   - Only a SINGLE leading `cd` is honored. Chained (`cd /a && cd /b &&
#     git commit`) or guarded (`true && cd /b && git commit`) redirects are
#     not parsed and fall through to `$cwd`.
# Agents that want commit-time gating of a sibling repo should run from
# that repo's cwd or use a single `cd <repo> &&` / `git -C <repo>` form.
extract_git_cwd() {
    local cmd="$1" base="$2"
    local -a toks
    read -ra toks <<< "$cmd"
    local n=${#toks[@]} j=0 dir=""
    # `git -C <path>`: the path after a `-C` flag that precedes the
    # subcommand. Stop scanning at the first non-flag token (the verb).
    while (( j < n )); do
        if [[ "${toks[$j]}" == "git" ]]; then
            local k=$((j + 1))
            while (( k < n )); do
                if [[ "${toks[$k]}" == "-C" ]] && (( k + 1 < n )); then
                    dir="${toks[$((k + 1))]}"
                    break
                fi
                case "${toks[$k]}" in
                    -*) ;;
                    *) break ;;
                esac
                k=$((k + 1))
            done
            break
        fi
        j=$((j + 1))
    done
    # `cd <path> && ...` prefix (only when no `-C` was found).
    if [[ -z "$dir" && "${toks[0]:-}" == "cd" && -n "${toks[1]:-}" ]]; then
        dir="${toks[1]}"
    fi
    [[ -z "$dir" ]] && { printf ''; return 0; }
    case "$dir" in
        /*) printf '%s' "$dir" ;;
        *) printf '%s/%s' "$base" "$dir" ;;
    esac
}

log_error() {
    local cwd="$1"
    local msg="$2"
    # Anchor the audit record to this hook's OWN repo root
    # (parent-of-parent of the script: .../<repo>/.claude/hooks/X -> <repo>),
    # NOT the payload cwd. When a hook fires from an ephemeral scratch
    # worktree/subdir, a cwd-relative path loses the record when that dir
    # is deleted (P0-3). The hook ships inside the repo, so its own root
    # is the only stable anchor. `|| echo "$cwd"` keeps a degenerate
    # invocation logging *somewhere* rather than silently dropping.
    local audit_root
    audit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P 2>/dev/null || echo "$cwd")"
    local err_dir="$audit_root/.illu/cache/hook-errors"
    mkdir -p "$err_dir" 2>/dev/null || return 0
    local date_stamp
    date_stamp="$(date +%Y%m%d 2>/dev/null || echo unknown)"
    local ts
    ts="$(date -Iseconds 2>/dev/null || echo unknown)"
    printf '{"ts":"%s","msg":"%s"}\n' "$ts" "$msg" \
        >> "$err_dir/$date_stamp.jsonl" 2>/dev/null || true
}

log_bypass() {
    local cwd="$1"
    local session_id="$2"
    local command="$3"
    # Repo-root-anchored, same rationale as log_error (P0-3): records
    # must survive deletion of an ephemeral scratch cwd.
    local audit_root
    audit_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P 2>/dev/null || echo "$cwd")"
    local bypass_dir="$audit_root/.illu/cache/bypass-events"
    mkdir -p "$bypass_dir" 2>/dev/null || return 0
    local date_stamp
    date_stamp="$(date +%Y%m%d 2>/dev/null || echo unknown)"
    local ts
    ts="$(date -Iseconds 2>/dev/null || echo unknown)"
    # Truncate command to first 200 chars to keep the log line bounded;
    # only the leading verbs matter for forensics.
    local cmd_truncated="${command:0:200}"
    printf '{"ts":"%s","session_id":"%s","hook":"quality-gate","command":"%s"}\n' \
        "$ts" "$session_id" "$cmd_truncated" \
        >> "$bypass_dir/$date_stamp.jsonl" 2>/dev/null || true
}

# shellcheck disable=SC2329  # invoked indirectly via trap ERR
on_error() {
    log_error "${cwd:-.}" "hook internal error at line $1"
    pass_through
}
trap 'on_error $LINENO' ERR

if ! command -v jq >/dev/null 2>&1; then
    log_error "${PWD:-.}" "jq not found in PATH; fail-open"
    pass_through
fi

input="$(cat || true)"
if [[ -z "$input" ]]; then
    log_error "${PWD:-.}" "empty stdin"
    pass_through
fi

tool_name="$(jq -r '.tool_name // empty' <<< "$input" 2>/dev/null || echo "")"
command_str="$(jq -r '.tool_input.command // empty' <<< "$input" 2>/dev/null || echo "")"
cwd="$(jq -r '.cwd // empty' <<< "$input" 2>/dev/null || echo "")"
session_id="$(jq -r '.session_id // empty' <<< "$input" 2>/dev/null || echo "unknown")"

if [[ -z "$cwd" ]]; then
    cwd="${PWD:-.}"
fi

if [[ "${ILLU_HOOKS_BYPASS:-0}" == "1" ]]; then
    log_bypass "$cwd" "$session_id" "$command_str"
    pass_through
fi

if [[ "$tool_name" != "Bash" ]]; then
    pass_through
fi

# Match `git commit` and `git commit ...` variants (--amend, -m, -a, etc.),
# but NOT `git commit-tree` or other compound subcommands. The command may
# have leading whitespace, env-var prefixes (`FOO=bar git commit ...`),
# `cd <path> && git commit`, or git GLOBAL options before the subcommand
# (`git -C <repo> commit`, `git -c k=v commit`). Tokenize on whitespace,
# then from each `git` skip its global options — `-C`/`-c` each consume the
# next token as their argument — to the first non-flag token and check it
# is `commit`. This is a strict superset of "git immediately followed by
# commit", so a plain `git commit` is detected exactly as before.
is_git_commit=0
read -ra tokens <<< "$command_str"
n=${#tokens[@]}
i=0
while (( i < n )); do
    if [[ "${tokens[$i]}" == "git" ]]; then
        k=$((i + 1))
        while (( k < n )); do
            case "${tokens[$k]}" in
                -C | -c) k=$((k + 2)) ;;
                -*) k=$((k + 1)) ;;
                *) break ;;
            esac
        done
        if (( k < n )) && [[ "${tokens[$k]}" == "commit" ]]; then
            is_git_commit=1
            break
        fi
    fi
    i=$((i + 1))
done

if (( is_git_commit == 0 )); then
    pass_through
fi

# Get the about-to-be-committed Rust file list via `git diff --staged
# --name-only`. This is the diff `git commit` will actually commit;
# unstaged working-tree changes are intentionally ignored (an agent
# may have unrelated working-tree edits when committing a focused
# subset). `git commit -a` is a known sharp edge — it auto-stages at
# commit time, so the hook won't see those files here and the
# subsequent hash check will mismatch the gate's token. Recovery is
# to `git add` explicitly. If git is unavailable, fail-open.
if ! command -v git >/dev/null 2>&1; then
    log_error "$cwd" "git not in PATH; fail-open"
    pass_through
fi

# Determine the repo this commit actually lands in. When the command
# redirects git elsewhere (`cd <repo> && git commit`, `git -C <repo>
# commit`) the commit is NOT in `$cwd`, so gating `$cwd` would check the
# wrong staged diff and the wrong token. Resolve the redirect target to
# its registered repo and gate THAT one; an unregistered redirect target
# is not illu-tracked (no token could exist), so pass through rather than
# block unrecoverably. With no redirect, `git_root` stays `$cwd` and the
# behavior is byte-for-byte unchanged.
git_cwd_override="$(extract_git_cwd "$command_str" "$cwd")"
if [[ -n "$git_cwd_override" ]]; then
    git_root="$(resolve_target_repo "$git_cwd_override")"
    [[ -z "$git_root" ]] && pass_through
else
    git_root="$cwd"
fi

changed_files="$(cd "$git_root" && git diff --staged --name-only 2>/dev/null || true)"
if [[ -z "$changed_files" ]]; then
    # No diff vs HEAD (empty commit, or git is uncooperative). Nothing
    # to gate. Pass-through.
    pass_through
fi

# Filter to {src,tests,examples}/**/*.rs to mirror the preflight
# hook's scope exactly. build.rs and benches/*.rs are NOT in scope.
has_rust=0
while IFS= read -r f; do
    case "$f" in
        src/*.rs|*/src/*.rs|tests/*.rs|*/tests/*.rs|examples/*.rs|*/examples/*.rs)
            # Filter out build.rs and benches/ which the preflight hook
            # also exempts.
            case "$f" in
                */build.rs|*/benches/*.rs|build.rs|benches/*.rs) ;;
                *) has_rust=1; break ;;
            esac
            ;;
    esac
done <<< "$changed_files"

if (( has_rust == 0 )); then
    pass_through
fi

# Compute the binding hash of `git diff --staged --unified=0` — the same
# bytes the gate would hash when it last ran. The hash must match
# byte-for-byte; any change to staged-or-modified content since the
# gate ran invalidates the token.
#
# Canonical form is the TRIMMED-END content. The `$(...)` command
# substitution below strips trailing newlines unconditionally (POSIX
# shell behavior); the gate side compensates by calling `.trim_end()`
# before hashing. The 2026-05-14 live-wire dogfood of PR #121 caught
# this gap — without the trim alignment, the Rust hash includes git's
# trailing `\n` and the bash hash does not, so every commit BLOCKs
# with a hash-mismatch reason. See the regression test
# `hash_diff_bytes_canonical_form_matches_trimmed_input` in
# `src/server/quality_gate_token.rs` for the pinned invariant.
binding_diff="$(cd "$git_root" && git diff --staged --unified=0 2>/dev/null || true)"

# P0-2: a Rust file is in the `--name-only` scope (has_rust=1 above) but
# the content diff is empty (pure rename, mode-only change, an external
# diff driver, or any degenerate diff). Hashing "" yields the well-known
# sha256("") = e3b0c442...; any token the server minted while IT also
# saw an empty diff carries that same vacuous hash, so the hash check
# below would spuriously match and wave the commit through with no real
# evidence. Refuse to bind a token to the empty string here.
if [[ -z "$binding_diff" ]]; then
    log_error "$cwd" "quality-gate: empty staged diff but Rust file in name-only scope; refusing vacuous token binding"
    block_with_reason "[illu quality-gate enforcement] Staged Rust file present per --name-only but \`git diff --staged --unified=0\` is empty (rename/mode-only/degenerate diff). The gate will not bind a token to the empty string. Stage real content or use ILLU_HOOKS_BYPASS=1 (audit-logged) for a legitimate pure-rename commit."
fi

if command -v shasum >/dev/null 2>&1; then
    current_hash="$(printf %s "$binding_diff" | shasum -a 256 | cut -c1-64)"
elif command -v sha256sum >/dev/null 2>&1; then
    current_hash="$(printf %s "$binding_diff" | sha256sum | cut -c1-64)"
else
    log_error "$cwd" "neither shasum nor sha256sum found; fail-open"
    pass_through
fi

# Key the token by `git_root` (== `$cwd` with no redirect; the canonical
# registered repo root for a cross-repo commit, matching where the server
# wrote `canonicalize(commit_cwd)`'s token).
if command -v shasum >/dev/null 2>&1; then
    root_hash="$(printf %s "$git_root" | shasum -a 256 | cut -c1-16)"
elif command -v sha256sum >/dev/null 2>&1; then
    root_hash="$(printf %s "$git_root" | sha256sum | cut -c1-16)"
else
    log_error "$cwd" "neither shasum nor sha256sum found; fail-open"
    pass_through
fi

token_file="$git_root/.illu/cache/quality-gate-tokens/$root_hash.json"

if [[ ! -f "$token_file" ]]; then
    instruction_packet="$(cat <<'EOF'
[illu quality-gate enforcement]

NO QUALITY GATE EVIDENCE for this Rust commit. The bypass-surface mitigation
requires a fresh `mcp__illu__quality_gate` call before any `git commit` that
touches {src,tests,examples}/**/*.rs.

Required action:
  1. Call mcp__illu__quality_gate with the full evidence packet (task, plan,
     verified=cargo_check,clippy, all 7 self_review_* fields, all 8
     pre_code_* fields for non-trivial diffs).
  2. The gate must return PASS or WARN (not BLOCKED) to mint a token.
  3. Retry your `git commit`.

The token binds to a hash of `git diff --staged --unified=0` at the time the
gate ran. Staging additional changes after the gate call invalidates the
token; re-run the gate after your last `git add`.

Bypass (audit-logged): ILLU_HOOKS_BYPASS=1.
EOF
)"
    block_with_reason "$instruction_packet"
fi

token_ts="$(jq -r '.ts // 0' "$token_file" 2>/dev/null || echo 0)"
now="$(date +%s)"
age=$(( now - token_ts ))

if (( age >= REFRESH_WINDOW )); then
    instruction_packet="$(cat <<EOF
[illu quality-gate enforcement]

QUALITY GATE EVIDENCE EXPIRED ($age seconds old; refresh window is $REFRESH_WINDOW seconds).
Re-run mcp__illu__quality_gate before committing.

Required action:
  1. Re-call mcp__illu__quality_gate with the current evidence packet.
     The gate refreshes the token on PASS or WARN.
  2. Retry your \`git commit\`.

Bypass (audit-logged): ILLU_HOOKS_BYPASS=1.
EOF
)"
    block_with_reason "$instruction_packet"
fi

token_hash="$(jq -r '.staged_diff_sha256 // empty' "$token_file" 2>/dev/null || echo "")"

if [[ "$token_hash" != "$current_hash" ]]; then
    instruction_packet="$(cat <<EOF
[illu quality-gate enforcement]

QUALITY GATE TOKEN HASH MISMATCH. The staged-or-modified content has changed
since the last quality_gate call; the token is bound to the diff the gate
saw at that time.

  Token hash:   ${token_hash:0:16}...
  Current hash: ${current_hash:0:16}...

Required action:
  1. Make sure the working tree (staged + unstaged-modified) reflects the
     content you want committed.
  2. Re-call mcp__illu__quality_gate. The gate hashes the current
     \`git diff --staged --unified=0\` and writes a fresh token.
  3. Retry your \`git commit\`.

This includes the case where you ran the gate, then \`git add\`-ed more
files, then tried to commit — re-run the gate after the last add.

Bypass (audit-logged): ILLU_HOOKS_BYPASS=1.
EOF
)"
    block_with_reason "$instruction_packet"
fi

remaining=$(( REFRESH_WINDOW - age ))
allow_with_warn "Quality gate evidence valid; refresh window has ${remaining}s remaining. Re-call mcp__illu__quality_gate if you stage additional changes before committing."
