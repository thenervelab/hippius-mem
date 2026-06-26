#!/usr/bin/env bash
#
# illu PreToolUse hook for `git push` on Rust commits.
#
# Installed by `illu init --agent claude --with-hooks` at
# `<repo>/.claude/hooks/illu-quality-gate-prepush.sh`. Gates
# `Bash(git push*)` invocations on token-per-pushed-commit evidence:
# each commit in the push range whose introduced diff touches
# `{src,tests,examples}/**/*.rs` must have a matching entry in the
# per-cwd ledger at `.illu/cache/quality-gate-tokens-ledger.jsonl`.
#
# Parallel to `illu-quality-gate.sh` (pre-commit, PR #121) and
# `illu-preflight.sh`. Same I/O contract, same fail-open philosophy,
# same trust boundary.
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
#   3. command not a `git push` invocation   -> pass-through
#   4. push range empty                      -> pass-through
#   5. for each commit C in push range:
#        - hash sha256 of trimmed `git diff C^! --unified=0`
#        - if commit touches no Rust files -> skip
#        - else if hash not in ledger      -> collect into "ungated"
#   6. ungated list non-empty                -> BLOCK naming each commit
#   7. all gated                             -> ALLOW + warn
#   Hook internal error                      -> fail-open + log
#
# Fail-open philosophy: a buggy hook should not brick all git pushes.
# Errors are logged to .illu/cache/hook-errors/<date>.jsonl.

set -u

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
# illu-rs binary, or print nothing. Lets the pre-push gate fire cross-repo:
# a `git push` redirected into a registered sibling repo is keyed to THAT
# repo's quality-gate ledger. Fail-OPEN on tooling problems. `ILLU_BIN`
# overrides the binary for tests / non-PATH installs.
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

# Extract the directory the git subcommand targets when the command
# REDIRECTS away from `$cwd` (`git -C <path>` or a leading `cd <path> &&`
# prefix); prints empty when git runs in `$cwd` unchanged. Mirrors the
# pre-commit hook's helper. Relative paths resolve against `$cwd`.
#
# Same fail-OPEN limitations as the pre-commit helper: quoted paths with
# spaces are mis-tokenized, and only a SINGLE leading `cd` is honored
# (chained/guarded `cd` redirects fall through to `$cwd`). These bypass the
# gate but never produce a false block.
extract_git_cwd() {
    local cmd="$1" base="$2"
    local -a toks
    read -ra toks <<< "$cmd"
    local n=${#toks[@]} j=0 dir=""
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
    local cmd_truncated="${command:0:200}"
    printf '{"ts":"%s","session_id":"%s","hook":"quality-gate-prepush","command":"%s"}\n' \
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

# Match `git push`, allowing leading env-var assignments / `cd && `
# prefixes and git GLOBAL options before the subcommand (`git -C <repo>
# push`). Mirrors the commit-side hook's tokenizer: from each `git`, skip
# global options (`-C`/`-c` consume their argument) to the first non-flag
# token and check it is `push`. Strict superset of the prior adjacent-pair
# match, so a plain `git push` is detected exactly as before.
is_git_push=0
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
        if (( k < n )) && [[ "${tokens[$k]}" == "push" ]]; then
            is_git_push=1
            break
        fi
    fi
    i=$((i + 1))
done

if (( is_git_push == 0 )); then
    pass_through
fi

if ! command -v git >/dev/null 2>&1; then
    log_error "$cwd" "git not in PATH; fail-open"
    pass_through
fi

# Determine the repo this push actually sends from. A `cd <repo> && git
# push` / `git -C <repo> push` redirect means the push range and ledger
# live in <repo>, not `$cwd`. Resolve the redirect target to its
# registered repo and verify THAT one; an unregistered redirect target is
# not illu-tracked, so pass through. With no redirect, `git_root` stays
# `$cwd` and the behavior is unchanged.
git_cwd_override="$(extract_git_cwd "$command_str" "$cwd")"
if [[ -n "$git_cwd_override" ]]; then
    git_root="$(resolve_target_repo "$git_cwd_override")"
    [[ -z "$git_root" ]] && pass_through
else
    git_root="$cwd"
fi

# Compute the push range. Two scenarios:
#   (a) Branch tracks an upstream: @{u}..HEAD enumerates commits ahead
#       of the remote. This is the most precise — it's exactly what
#       `git push` will send.
#   (b) Branch has no upstream (initial push of a new branch): fall
#       back to HEAD --not --remotes which enumerates commits not yet
#       in ANY remote-tracking ref. Overshoots in some edge cases but
#       acceptable for the fail-open philosophy.
#
# Both calls go through `git -C "$cwd"` so the hook works from a
# subdirectory of the repo.
push_range="$(cd "$git_root" && git rev-list '@{u}..HEAD' 2>/dev/null || true)"
if [[ -z "$push_range" ]]; then
    push_range="$(cd "$git_root" && git rev-list HEAD --not --remotes 2>/dev/null || true)"
fi
if [[ -z "$push_range" ]]; then
    # Nothing new to push (or git couldn't enumerate). Pass-through —
    # if there's nothing to verify, there's nothing to BLOCK.
    pass_through
fi

if command -v shasum >/dev/null 2>&1; then
    cwd_hash_cmd="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then
    cwd_hash_cmd="sha256sum"
else
    log_error "$cwd" "neither shasum nor sha256sum found; fail-open"
    pass_through
fi

ledger_path="$git_root/.illu/cache/quality-gate-tokens-ledger.jsonl"
if [[ ! -f "$ledger_path" ]]; then
    # No ledger means no gate has ever run on this cwd. If we have
    # Rust-touching commits in the push range, BLOCK with the
    # standard instruction packet. Otherwise pass-through.
    ledger_hashes=""
else
    ledger_hashes="$(jq -r '.staged_diff_sha256 // empty' "$ledger_path" 2>/dev/null || true)"
fi

# Walk each commit in the push range. Collect ungated Rust-touching
# commits into a list; emit the BLOCK message naming each by short
# hash + subject if any.
ungated=""
while IFS= read -r commit; do
    [[ -z "$commit" ]] && continue
    # Does this commit touch Rust files? `git diff C^! --name-only`
    # gives the changed file list; filter to the same scope as the
    # pre-commit hook ({src,tests,examples}/**/*.rs).
    files="$(cd "$git_root" && git diff "${commit}^!" --name-only 2>/dev/null || true)"
    has_rust=0
    while IFS= read -r f; do
        case "$f" in
            src/*.rs|*/src/*.rs|tests/*.rs|*/tests/*.rs|examples/*.rs|*/examples/*.rs)
                case "$f" in
                    */build.rs|*/benches/*.rs|build.rs|benches/*.rs) ;;
                    *) has_rust=1; break ;;
                esac
                ;;
        esac
    done <<< "$files"
    if (( has_rust == 0 )); then
        continue
    fi

    # Hash the trim-end form of `git diff C^! --unified=0`. Same
    # canonical form the gate computed at the time of the original
    # `git commit`.
    commit_diff="$(cd "$git_root" && git diff "${commit}^!" --unified=0 2>/dev/null || true)"
    commit_hash="$(printf %s "$commit_diff" | $cwd_hash_cmd | cut -c1-64)"

    # Look up in the ledger. `grep -Fx` matches the whole line; since
    # ledger_hashes is one hash per line, this is the exact-match
    # check.
    if [[ -n "$ledger_hashes" ]] && grep -Fxq "$commit_hash" <<< "$ledger_hashes"; then
        continue
    fi

    short="$(cd "$git_root" && git rev-parse --short "$commit" 2>/dev/null || echo "$commit")"
    subject="$(cd "$git_root" && git log -1 --format=%s "$commit" 2>/dev/null || echo "?")"
    ungated+="  - ${short} ${subject}"$'\n'
done <<< "$push_range"

if [[ -n "$ungated" ]]; then
    # Strip trailing newline for cleaner formatting.
    ungated="${ungated%$'\n'}"
    instruction_packet="$(cat <<EOF
[illu quality-gate enforcement]

UNGATED RUST COMMITS IN PUSH RANGE. The pre-push hook requires that every
commit in the push range whose introduced diff touches
{src,tests,examples}/**/*.rs has a matching entry in the per-cwd
quality-gate token ledger. The following commit(s) do not:

${ungated}

Why this fires: either the commit was created via \`ILLU_HOOKS_BYPASS=1
git commit\` (skipping the pre-commit hook), OR the commit was rebased /
amended after the gate ran (changing its introduced-diff hash and
invalidating the ledger entry).

Required action:
  1. Re-run mcp__illu__quality_gate against the current staged state
     reflecting the content of each listed commit, then push.
  2. For rebase / amend workflows: the introduced-diff hash changed,
     so each rebased commit needs its own fresh gate call.

Bypass (audit-logged): ILLU_HOOKS_BYPASS=1.
EOF
)"
    block_with_reason "$instruction_packet"
fi

verified_count=$(grep -c . <<< "$push_range" || echo 0)
allow_with_warn "Pre-push quality-gate check passed; ${verified_count} commit(s) verified against the ledger."
