#!/usr/bin/env bash
#
# illu PreToolUse hook for Edit/Write on Rust files.
#
# Installed by `illu init --agent claude --with-hooks` at
# `<repo>/.claude/hooks/illu-preflight.sh`. Gates Edit/Write
# on {src,tests,examples}/**/*.rs against fresh preflight evidence.
#
# I/O contract (Claude Code hook protocol):
#   Input  (stdin, JSON):  { tool_name, tool_input.file_path, cwd, session_id, ... }
#   Output (stdout, JSON):
#     Allow + warn:    { "continue": true,  "additionalContext": "..." }
#     Block:           { "decision": "block", "reason": "..." }
#     Pass-through:    { "continue": true }
#
# Decision tree (spec section 6.2):
#   1. ILLU_HOOKS_BYPASS=1?              -> log + pass-through
#   2. file_path in {src,tests,examples}/**/*.rs?  No -> pass-through
#   3. token age < REFRESH_WINDOW?       Yes -> ALLOW + WARN
#                                        No  -> BLOCK with instruction packet
#   Hook internal error -> fail-open + log
#
# Fail-open philosophy: a buggy hook should not brick all Edit
# operations. Errors are logged to .illu/cache/hook-errors/<date>.jsonl
# for the v2 auditor.
#
# Trust boundary:
#   The hook reads `.ts` from the cached JSON and compares against the
#   current wall-clock time. Any writer to .illu/cache/preflight-tokens/
#   can keep the gate open indefinitely by setting `ts` arbitrarily high.
#   This is acceptable: write access to that directory implies write
#   access to the entire repo (and thus to the source files this gate
#   protects), so the gate adds no defense against an attacker who
#   already has it. The gate exists to enforce engineer-mentality
#   discipline against *agents*, not security against humans/attackers.
#
# Subagent caveat (enforcement scope — be honest about this):
#   This is a Claude Code PreToolUse hook, and PreToolUse hooks do NOT
#   fire for subagent (Task tool) Edit/Write calls. So preflight
#   enforcement is ADVISORY for subagent-authored edits, not airtight.
#   There is no git-level event for "edit", so unlike commit/push (which
#   have `.git/hooks/pre-commit` + `pre-push` wrappers that fire for every
#   committer/pusher) no git-hook backstop is possible here. The real
#   enforcement floor for subagent-authored Rust is the commit-time
#   quality-gate: `.claude/hooks/illu-quality-gate.sh` PLUS its git-native
#   `.git/hooks/pre-commit` wrapper, which DOES fire for subagents.

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

# Resolve an out-of-tree edit target to its registered repo root, printing
# the repo's CANONICAL path or nothing. This is what lets the gate fire
# cross-repo: a Rust edit to a *registered* sibling repo (e.g. editing
# `hcfs` from an `illu-rs` session) is enforced against THAT repo's
# preflight token instead of being waved through as scratch.
#
# Delegates to `illu-rs which-repo`, which canonicalizes against the
# registry — the same canonical string the token writer hashes, so both
# ends of the gate agree. Fail-OPEN on any tooling problem (binary
# missing, non-zero exit): a missing `illu-rs` must never hard-block an
# edit, mirroring the shasum fail-open below. `ILLU_BIN` overrides the
# binary path for tests and non-`PATH` installs.
resolve_target_repo() {
    local file_abs="$1" bin out
    bin="${ILLU_BIN:-}"
    if [[ -z "$bin" ]]; then
        bin="$(command -v illu-rs 2>/dev/null || echo "$HOME/.cargo/bin/illu-rs")"
    fi
    [[ -x "$bin" ]] || { printf ''; return 0; }
    # Capture stdout and honor the binary's EXIT status: only a clean exit
    # is a real answer. `which-repo` prints nothing both on a miss (exit 0)
    # and on a registry error (exit non-zero), so either way an empty or
    # failed result yields empty here. Taking only the first line guards
    # against a hypothetical multi-line print.
    out="$("$bin" which-repo "$file_abs" 2>/dev/null)" || { printf ''; return 0; }
    printf '%s' "${out%%$'\n'*}"
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
    local file_path="$3"
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
    printf '{"ts":"%s","session_id":"%s","file":"%s"}\n' \
        "$ts" "$session_id" "$file_path" \
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
file_path="$(jq -r '.tool_input.file_path // empty' <<< "$input" 2>/dev/null || echo "")"
cwd="$(jq -r '.cwd // empty' <<< "$input" 2>/dev/null || echo "")"
session_id="$(jq -r '.session_id // empty' <<< "$input" 2>/dev/null || echo "unknown")"

if [[ -z "$cwd" ]]; then
    cwd="${PWD:-.}"
fi

if [[ "${ILLU_HOOKS_BYPASS:-0}" == "1" ]]; then
    log_bypass "$cwd" "$session_id" "$file_path"
    pass_through
fi

# Enforce on every file-mutating tool. `MultiEdit` is a DISTINCT tool
# from `Edit`/`Write` but writes the same `tool_input.file_path` shape,
# so it must be gated here too — omitting it let a `MultiEdit` to a
# `{src,tests,examples}/**/*.rs` file slip the gate (P1-D). This inner
# guard must stay in lock-step with the settings.json `matcher`
# ("Edit|Write|MultiEdit"): the matcher decides which tools INVOKE the
# hook, this case decides which the hook ENFORCES on.
case "$tool_name" in
    Edit|Write|MultiEdit) : ;;
    *) pass_through ;;
esac

# Repo-root scope classification.
#
# This hook ships inside the illu-rs working tree. Its scope discipline
# is ASYMMETRIC, and that asymmetry is the whole point of this block:
#
#   - The harmful misfire (F-hook / P0-1) is the hook *BLOCKING* a Rust
#     edit in an UNRELATED repo or scratch tree, forcing a spurious
#     ILLU_HOOKS_BYPASS. The downstream `*/src/*.rs` glob is unanchored,
#     so without scope awareness the hook would block edits in ANY tree.
#   - Accepting a VALID preflight/evidence token is NEVER harmful, no
#     matter which tree the target lives in: if the EvidenceWindow flow
#     produced a fresh token for `$cwd`, acknowledging it is always
#     correct. Suppressing that acknowledgement for an out-of-tree
#     workspace breaks the EvidenceWindow contract (the regression this
#     restructure fixes).
#
# Therefore we only classify in/out-of-tree here (`in_tree`), and defer
# the decision: the scope guard gates ONLY the would-BLOCK branches
# (missing / expired token). The accept-and-warn path runs regardless of
# `in_tree`.
#
# `hook_repo_root` is the canonicalized parent-of-parent of this script
# (.../<repo>/.claude/hooks/illu-preflight.sh -> <repo>). It is the only
# path resolved with `cd`+`pwd -P`, and that is safe: the script's own
# directory always exists.
#
# `file_abs` is the edit target absolutized by STRING against the hook
# payload's `$cwd` -- deliberately NOT via `cd "$(dirname ...)"`. A new
# file in a not-yet-created in-repo subdir (e.g. src/newmod/x.rs) has no
# existing parent dir, so the old `cd` failed, left `file_abs` empty and
# was treated as out-of-tree -- letting that edit shape escape the gate
# (P0-1 regression). String absolutization has no such dependency:
# relative paths join onto `$cwd`, absolute paths are taken as-is.
#
# Segment-prefix matching via the `$root` | `$root/*` arms still ensures
# `/repo` matches `/repo/...` but NOT a sibling like `/repo-other`.
# `hook_repo_root` is canonicalized so the prefix compare is robust to
# symlinks/`..` in the script's own location; the target side is a pure
# string, which classifies an unresolved path as out-of-tree (the safe
# direction: never wrongly blocks) while the string join still classifies
# the in-repo new-dir shape correctly.
hook_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P 2>/dev/null || echo "")"
case "$file_path" in
    /*) file_abs="$file_path" ;;
    *)  file_abs="$cwd/$file_path" ;;
esac
case "$file_abs" in
    "$hook_repo_root"|"$hook_repo_root"/*) in_tree=1 ;;
    *) in_tree=0 ;;
esac

case "$file_path" in
    */src/*.rs|*/tests/*.rs|*/examples/*.rs) : ;;
    *.rs)
        case "$file_path" in
            */build.rs|*/benches/*.rs) pass_through ;;
            *) : ;;
        esac
        ;;
    *) pass_through ;;
esac

# Decide WHICH repo's token gates this edit, and whether to enforce at all.
#
#   - in-tree              -> enforce against `$cwd` (unchanged behavior).
#   - out-of-tree, but the file resolves to a REGISTERED repo
#                          -> enforce against that repo's CANONICAL root,
#                             where `rust_preflight repo_path:<root>` writes
#                             the token. This is the cross-repo gate.
#   - out-of-tree, unregistered (scratch / unrelated tree)
#                          -> do NOT block (the F-hook / P0-1 scope guard);
#                             `enforce_root` stays `$cwd` so the accept
#                             branch still honors an EvidenceWindow token
#                             keyed by cwd, exactly as before.
cross_repo_note=""
if [[ "$in_tree" == "1" ]]; then
    enforce_root="$cwd"
    enforce=1
else
    target_root="$(resolve_target_repo "$file_abs")"
    if [[ -n "$target_root" ]]; then
        enforce_root="$target_root"
        enforce=1
        cross_repo_note="

Cross-repo edit: this file lives in the registered repo at
  $enforce_root
Pass repo_path: \"$enforce_root\" to mcp__illu__rust_preflight so the token is
written for THAT repo, then retry."
    else
        enforce_root="$cwd"
        enforce=0
    fi
fi

if command -v shasum >/dev/null 2>&1; then
    enforce_hash="$(printf %s "$enforce_root" | shasum -a 256 | cut -c1-16)"
elif command -v sha256sum >/dev/null 2>&1; then
    enforce_hash="$(printf %s "$enforce_root" | sha256sum | cut -c1-16)"
else
    log_error "$cwd" "neither shasum nor sha256sum found; fail-open"
    pass_through
fi

token_file="$enforce_root/.illu/cache/preflight-tokens/$enforce_hash.json"

if [[ ! -f "$token_file" ]]; then
    # WOULD-BLOCK branch: no preflight evidence. The scope guard applies
    # HERE -- blocking an UNREGISTERED out-of-tree edit (scratch / unrelated
    # tree) is the F-hook / P0-1 misfire. In-tree OR a registered cross-repo
    # target still blocks (CASE B/C), so gate on `enforce`, not `in_tree`.
    if [[ "$enforce" != "1" ]]; then
        pass_through
    fi
    instruction_packet="$(cat <<'EOF'
[illu engineer-mentality enforcement]

PRE-WORK NOT FOUND for this Rust edit. The engineer-mentality mandates require
preflight evidence before any Edit/Write to {src,tests,examples}/**/*.rs.

Required action:
  1. Call mcp__illu__rust_preflight with the task description and the symbols
     you intend to touch. This populates evidence covering all five mentality
     axioms (research, data structures, memory model, invariants, compile-time)
     AND writes the token file this hook checks for.
  2. Retry your Edit/Write call.

Equivalent action (also accepted by this hook):
  Call any 2 distinct tools from {mcp__illu__std_docs, mcp__illu__docs,
  mcp__illu__context} on the APIs the diff touches. The server-side
  EvidenceWindow records each call and writes a token once the
  >=2-distinct threshold is met within the refresh window. The hook
  then sees the token on your next Edit/Write and allows it.

For mandate content: mcp__illu__axioms(query: "<task>", tier: "mentality").

Bypass (audit-logged): ILLU_HOOKS_BYPASS=1.
EOF
)"
    # `cross_repo_note` is empty for in-tree edits; for a registered
    # cross-repo target it names the repo and the repo_path argument.
    block_with_reason "$instruction_packet$cross_repo_note"
fi

token_ts="$(jq -r '.ts // 0' "$token_file" 2>/dev/null || echo 0)"
now="$(date +%s)"
age=$(( now - token_ts ))

if (( age >= REFRESH_WINDOW )); then
    # WOULD-BLOCK branch: token present but stale. Same scope asymmetry as
    # the missing-token branch -- an UNREGISTERED out-of-tree stale token
    # must not force a block (F-hook / P0-1), but a registered cross-repo
    # target does, so gate on `enforce`.
    if [[ "$enforce" != "1" ]]; then
        pass_through
    fi
    instruction_packet="$(cat <<EOF
[illu engineer-mentality enforcement]

PREFLIGHT EVIDENCE EXPIRED ($age seconds old; refresh window is $REFRESH_WINDOW seconds).
The engineer-mentality mandates require fresh evidence before any Edit/Write to
{src,tests,examples}/**/*.rs.

Required action:
  1. Re-call mcp__illu__rust_preflight with the current task. This refreshes
     the evidence packet and re-emits the token.
  2. Retry your Edit/Write call.

Bypass (audit-logged): ILLU_HOOKS_BYPASS=1.
EOF
)"
    block_with_reason "$instruction_packet$cross_repo_note"
fi

# ACCEPT branch: a fresh, valid token exists for `$enforce_root` (the
# session repo for in-tree edits, or the registered target repo for a
# cross-repo edit). This is reached REGARDLESS of `in_tree` --
# acknowledging valid evidence is never the harmful misfire, and an
# out-of-tree workspace driven by the EvidenceWindow flow depends on this
# acknowledgement (the regression this restructure restores). The scope
# guard deliberately does NOT gate
# here; it only gates the would-BLOCK branches above.
remaining=$(( REFRESH_WINDOW - age ))
allow_with_warn "Preflight evidence valid; refresh window has ${remaining}s remaining. Re-call mcp__illu__rust_preflight if task context shifts substantively."
