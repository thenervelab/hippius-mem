//! The instruction-file half of provisioning: inject a marker-delimited team
//! memory mandates block into `CLAUDE.md` and `AGENTS.md`.
//!
//! The block is bracketed by HTML-comment markers so a re-run replaces it in
//! place (idempotent) and any
//! user content outside the markers survives byte-for-byte. The single source of
//! truth for the block text is the embedded asset; drift-guard tests keep this
//! repo's committed `CLAUDE.md` and `AGENTS.md` in agreement with it. The
//! `AGENTS.md` variant leads with a hook-scope preamble because most of its
//! readers (Cursor, Codex CLI, generic MCP clients) get none of the Claude Code
//! hooks; Grok is the exception, via the committed `.claude/.claude/hooks` shim.

use std::path::Path;
use std::process::Command;

use anyhow::Context;

/// Opening marker delimiting the hippius-mem-owned region in an instruction file.
pub(crate) const SECTION_START: &str = "<!-- hippius-mem:start -->";

/// Closing marker for the hippius-mem-owned region — see [`SECTION_START`].
pub(crate) const SECTION_END: &str = "<!-- hippius-mem:end -->";

/// The mandates block, embedded at build time from the canonical asset.
///
/// `include_str!` makes the asset the ONE source of truth: the binary writes
/// exactly these bytes, and `committed_claude_md_contains_section` asserts this
/// repo's `CLAUDE.md` still carries them, so the two cannot silently drift.
const TEAM_MEMORY_ASSET: &str = include_str!("../../assets/team_memory_mandates.md");

/// The team-memory mandates block, marker-delimited, with no trailing newline.
///
/// Trimming the trailing newline keeps the boundary at [`SECTION_END`] so
/// [`write_md_section`]'s own formatting owns the surrounding whitespace.
pub(crate) fn team_memory_section() -> &'static str {
    TEAM_MEMORY_ASSET.trim_end()
}

/// Hook-scope caveat leading the `AGENTS.md` variant of the block.
///
/// Most `AGENTS.md` readers get none of the five Claude Code hooks — Grok is
/// the exception, running them through the committed `.claude/.claude/hooks`
/// shim — so for everyone else the recall/remember loop has no mechanical
/// enforcement and the block text is the only floor. The preamble must say so
/// up front or the hook references in the mandates would read as promises the
/// environment cannot keep.
const AGENTS_MD_PREAMBLE: &str = "\
> **Hook enforcement varies by client.** This file is read by agents other than\n\
> Claude Code. The hippius-mem hooks (recall edit-gate, recall token, remember\n\
> nudge, seed nudge, session brief) run under Claude Code — and under Grok, which\n\
> shares `.claude/settings.json` through the committed `.claude/.claude/hooks`\n\
> shim. In any other client the mandates below are honor-system: follow them\n\
> unprompted. Tool names below use Claude Code's `mcp__hippius-mem__` prefix; in\n\
> your client the same tools may appear as plain `recall` / `remember` / `get` —\n\
> map accordingly.";

/// The `AGENTS.md` variant of the mandates block: the same asset with
/// [`AGENTS_MD_PREAMBLE`] spliced in directly after [`SECTION_START`].
///
/// Inserting INSIDE the markers is what keeps every existing guarantee intact —
/// the byte-identical idempotence check, the tracked-clean guard, and
/// [`remove_md_section`] all key on the marker-delimited region, so a preamble
/// outside it would survive an uninstall. The `strip_prefix` fallback keeps the
/// function total; the asset leading with the marker is pinned by the
/// `agents_section_*` tests over the compile-time-embedded asset.
pub(crate) fn team_memory_section_agents() -> String {
    let base = team_memory_section();
    let tail = base.strip_prefix(SECTION_START).unwrap_or(base);
    format!("{SECTION_START}\n{AGENTS_MD_PREAMBLE}{tail}")
}

/// Install or refresh the hippius-mem-owned section in `<repo_path>/<file_name>`
/// (in practice `CLAUDE.md`).
///
/// If the file already contains a region bracketed by [`SECTION_START`] /
/// [`SECTION_END`], it is replaced in place; otherwise a new section preceded by
/// `heading` is appended. Content outside the markers is preserved verbatim. A
/// missing file is treated as empty (the steady state when bootstrapping a fresh
/// repo); any other read failure propagates rather than silently overwriting
/// whatever is on disk.
///
/// When `allow_overwrite_tracked` is false, a git-tracked, clean file whose block
/// would change is left intact — this is what stops a self-heal or a stale binary
/// from silently downgrading a committed `CLAUDE.md`. Fail-open: a non-git path or
/// a dirty file is written as normal, so fresh installs and in-progress edits are
/// unaffected.
///
/// # Errors
///
/// Returns an error for any I/O failure other than the file being absent.
pub(crate) fn write_md_section(
    repo_path: &Path,
    file_name: &str,
    heading: &str,
    section: &str,
    allow_overwrite_tracked: bool,
) -> anyhow::Result<()> {
    let md_path = repo_path.join(file_name);

    // NotFound is the steady state (we are creating the file); any other error
    // (permission denied, IO fault) must propagate rather than silently
    // overwriting whatever exists on disk.
    let content = match std::fs::read_to_string(&md_path) {
        Ok(existing) => existing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(e).with_context(|| format!("reading {} failed", md_path.display()));
        }
    };

    // Already present and byte-identical: nothing to do.
    if content.contains(SECTION_START) && content.contains(section) {
        return Ok(());
    }

    // Past the identical-skip, a file that still contains SECTION_START is about
    // to have its block REPLACED with different content. Refuse to do that
    // silently to a git-tracked, clean file: a stale-binary or self-heal
    // regeneration would otherwise downgrade a committed CLAUDE.md, and the
    // drift-guard test only catches it after the fact. Intentional regeneration
    // opts in via `allow_overwrite_tracked`.
    if content.contains(SECTION_START)
        && !allow_overwrite_tracked
        && is_git_tracked_and_clean(repo_path, file_name)
    {
        tracing::warn!(
            file = file_name,
            "refusing to overwrite the committed hippius-mem section in a \
             git-tracked, clean file whose regenerated content differs. Left the \
             committed version intact; pass --allow-overwrite-tracked to force it."
        );
        return Ok(());
    }

    let new_content = splice_section(&content, heading, section);
    // Atomic + symlink-safe: this path runs on every server boot (self-heal) with
    // a parent dir a co-resident process may control, so a bare `fs::write` would
    // follow a planted symlink and truncate its target (CWE-59). See `super::atomic`.
    super::atomic::atomic_write(&md_path, new_content.as_bytes())?;
    tracing::info!("updated {file_name} with the hippius-mem section");
    Ok(())
}

/// Compute the new file body with `section` spliced into `content`.
///
/// Pure string surgery, split out so it is unit- and property-testable without
/// touching the filesystem. It replaces the owned region ONLY when a well-ordered
/// `START..END` pair exists (a start followed by an end); any other marker shape — a
/// lone start, a lone or leading end, reversed markers, or a second block — is
/// treated as "no owned region": stray markers are stripped and one fresh block is
/// appended (a fresh file gets `heading` first). Searching for the end only AFTER
/// the start is what prevents a stray end BEFORE the start from producing
/// overlapping slices that would duplicate the user's prose (the malformed-marker
/// corruption this replaced).
fn splice_section(content: &str, heading: &str, section: &str) -> String {
    if let Some(start) = content.find(SECTION_START)
        && let Some(rel_end) = content[start..].find(SECTION_END)
    {
        let end = start + rel_end + SECTION_END.len();
        // Strip any OTHER markers left in the surrounding prose (a second block, a
        // reversed stray marker) so the result carries exactly one owned region and
        // a later splice cannot re-anchor to a leftover marker.
        let head = strip_markers(&content[..start]);
        let tail = strip_markers(&content[end..]);
        return format!("{head}{section}{tail}");
    }
    // No well-ordered pair: strip any orphan markers, then append one fresh block.
    let base = strip_markers(content);
    if base.trim().is_empty() {
        return format!("{heading}\n\n{section}\n");
    }
    format!("{base}\n{section}\n")
}

/// Remove every hippius-mem marker token from `text`, leaving the surrounding
/// prose. Clears the stray/orphan markers a hand-edit or merge conflict can leave so
/// they cannot re-anchor a later splice into duplicating prose.
fn strip_markers(text: &str) -> String {
    text.replace(SECTION_START, "").replace(SECTION_END, "")
}

/// Remove the entire hippius-mem marker block from `<repo_path>/<file_name>`.
///
/// A no-op when the file or the block is absent. Used by `init --uninstall`.
///
/// # Errors
///
/// Returns an error for any I/O failure other than the file being absent.
pub(crate) fn remove_md_section(repo_path: &Path, file_name: &str) -> anyhow::Result<()> {
    let md_path = repo_path.join(file_name);
    let content = match std::fs::read_to_string(&md_path) {
        Ok(existing) => existing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).with_context(|| format!("reading {} failed", md_path.display()));
        }
    };
    let (Some(start), Some(end)) = (content.find(SECTION_START), content.find(SECTION_END)) else {
        return Ok(());
    };
    let end = end + SECTION_END.len();
    // Also swallow one trailing newline so removing the block does not leave a
    // widening gap of blank lines across repeated install/uninstall cycles.
    let tail = content[end..].strip_prefix('\n').unwrap_or(&content[end..]);
    let stripped = format!("{}{tail}", &content[..start]);
    super::atomic::atomic_write(&md_path, stripped.as_bytes())?;
    Ok(())
}

/// Whether `file_name` is tracked by git under `repo_path` AND has no pending
/// modifications.
///
/// Fail-safe: if git is absent, the path is not a repo, or any git call errors,
/// this returns false. Its two callers put that bias to OPPOSITE uses, both
/// safe: the overwrite guard in [`write_md_section`] falls open and writes
/// (protecting only a provably committed file), while auto-init's preflight
/// (`setup::auto_init_preflight`) refuses to touch an EXISTING file it cannot
/// prove tracked-and-clean — on the unattended path, "cannot prove safe"
/// must read as unsafe.
pub(crate) fn is_git_tracked_and_clean(repo_path: &Path, file_name: &str) -> bool {
    if !is_git_tracked(repo_path, file_name) {
        return false;
    }
    match git_porcelain_status(repo_path, file_name) {
        // Empty porcelain output == no staged or unstaged change to this path.
        Some(stdout) => stdout.is_empty(),
        None => false,
    }
}

/// Whether git tracks `file_name` under `repo_path`. Fail-safe: git absent,
/// not a repo, or any git error all read as "not tracked".
fn is_git_tracked(repo_path: &Path, file_name: &str) -> bool {
    let tracked = Command::new("git")
        .current_dir(repo_path)
        .args(["ls-files", "--error-unmatch", "--", file_name])
        .output();
    match tracked {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// `git status --porcelain` for one path, or `None` when git itself failed —
/// callers decide what a git failure means (the two probes above disagree on
/// purpose).
fn git_porcelain_status(repo_path: &Path, file_name: &str) -> Option<Vec<u8>> {
    let status = Command::new("git")
        .current_dir(repo_path)
        .args(["status", "--porcelain", "--", file_name])
        .output();
    match status {
        Ok(out) if out.status.success() => Some(out.stdout),
        Ok(_) | Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning filesystem steps"
    )]

    use std::path::Path;

    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::{
        AGENTS_MD_PREAMBLE, SECTION_END, SECTION_START, is_git_tracked_and_clean,
        remove_md_section, splice_section, team_memory_section, team_memory_section_agents,
        write_md_section,
    };

    fn read(dir: &Path, name: &str) -> String {
        std::fs::read_to_string(dir.join(name)).expect("file must exist after write")
    }

    #[test]
    fn creates_file_with_heading_when_absent() {
        let tmp = TempDir::new().expect("tempdir");
        write_md_section(
            tmp.path(),
            "CLAUDE.md",
            "# CLAUDE.md",
            team_memory_section(),
            false,
        )
        .expect("fresh write");
        let body = read(tmp.path(), "CLAUDE.md");
        assert!(
            body.starts_with("# CLAUDE.md"),
            "heading must lead a fresh file: {body}"
        );
        assert!(body.contains(SECTION_START) && body.contains(SECTION_END));
    }

    #[test]
    fn is_idempotent_on_rerun() {
        let tmp = TempDir::new().expect("tempdir");
        let args = ("CLAUDE.md", "# CLAUDE.md", team_memory_section());
        write_md_section(tmp.path(), args.0, args.1, args.2, false).expect("first");
        let after_first = read(tmp.path(), "CLAUDE.md");
        write_md_section(tmp.path(), args.0, args.1, args.2, false).expect("second");
        let after_second = read(tmp.path(), "CLAUDE.md");
        assert_eq!(after_first, after_second, "re-run must not change the file");
    }

    #[test]
    fn preserves_content_outside_the_markers() {
        let tmp = TempDir::new().expect("tempdir");
        let preamble = "# CLAUDE.md\n\nsome user prose that must survive\n";
        std::fs::write(tmp.path().join("CLAUDE.md"), preamble).expect("seed");
        write_md_section(
            tmp.path(),
            "CLAUDE.md",
            "# CLAUDE.md",
            team_memory_section(),
            false,
        )
        .expect("append");
        let body = read(tmp.path(), "CLAUDE.md");
        assert!(
            body.contains("some user prose that must survive"),
            "user prose dropped: {body}"
        );
        assert!(
            body.contains(SECTION_START),
            "section must be appended: {body}"
        );
    }

    #[test]
    fn replaces_stale_block_in_place() {
        let tmp = TempDir::new().expect("tempdir");
        let stale = format!("# CLAUDE.md\n\n{SECTION_START}\nOLD CONTENT\n{SECTION_END}\n");
        std::fs::write(tmp.path().join("CLAUDE.md"), &stale).expect("seed stale");
        // Not a git repo -> the tracked-clean guard falls open, so the stale block
        // is replaced rather than protected.
        write_md_section(
            tmp.path(),
            "CLAUDE.md",
            "# CLAUDE.md",
            team_memory_section(),
            false,
        )
        .expect("replace");
        let body = read(tmp.path(), "CLAUDE.md");
        assert!(
            !body.contains("OLD CONTENT"),
            "stale block must be gone: {body}"
        );
        assert_eq!(
            body.matches(SECTION_START).count(),
            1,
            "exactly one block: {body}"
        );
    }

    #[test]
    fn read_error_on_a_directory_path_propagates() {
        let tmp = TempDir::new().expect("tempdir");
        // A directory named CLAUDE.md makes read_to_string fail with a non-NotFound
        // error, which must surface instead of being treated as an empty file.
        std::fs::create_dir(tmp.path().join("CLAUDE.md")).expect("dir");
        let err = write_md_section(tmp.path(), "CLAUDE.md", "# CLAUDE.md", "x", false)
            .expect_err("reading a directory as a file must fail");
        assert!(
            err.to_string().contains("reading"),
            "context should name the read: {err}"
        );
    }

    #[test]
    fn remove_is_noop_when_file_absent() {
        let tmp = TempDir::new().expect("tempdir");
        remove_md_section(tmp.path(), "CLAUDE.md").expect("no-op on absent file");
    }

    #[test]
    fn remove_deletes_the_block_and_keeps_surrounding_prose() {
        let tmp = TempDir::new().expect("tempdir");
        write_md_section(
            tmp.path(),
            "CLAUDE.md",
            "# CLAUDE.md",
            team_memory_section(),
            false,
        )
        .expect("install");
        remove_md_section(tmp.path(), "CLAUDE.md").expect("remove");
        let body = read(tmp.path(), "CLAUDE.md");
        assert!(
            !body.contains(SECTION_START),
            "block must be removed: {body}"
        );
        assert!(body.contains("# CLAUDE.md"), "heading must remain: {body}");
    }

    /// Drift guard: the committed `CLAUDE.md` in THIS repo must still carry the
    /// exact block the binary would write, so `init`/self-heal are a genuine
    /// no-op here rather than silently regenerating a divergent block.
    #[test]
    fn committed_claude_md_contains_section() {
        // CARGO_MANIFEST_DIR = <repo>/hippius-mem; the committed file is one up.
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate dir has a parent");
        let committed = std::fs::read_to_string(repo_root.join("CLAUDE.md"))
            .expect("repo CLAUDE.md must exist");
        assert!(
            committed.contains(team_memory_section()),
            "committed CLAUDE.md has drifted from assets/team_memory_mandates.md; \
             run `hippius-mem init --allow-overwrite-tracked` to regenerate it"
        );
        assert_eq!(
            committed.matches(SECTION_START).count(),
            1,
            "committed CLAUDE.md must carry exactly one hippius-mem block"
        );
    }

    /// The agents variant must keep the preamble INSIDE the marker-delimited
    /// region: everything downstream (idempotence, tracked-clean guard,
    /// `remove_md_section`) keys on the markers, so a preamble outside them
    /// would survive an uninstall and break byte-identical re-runs.
    #[test]
    fn agents_section_keeps_preamble_inside_markers() {
        let section = team_memory_section_agents();
        assert!(
            section.starts_with(SECTION_START),
            "agents section must lead with the start marker: {section}"
        );
        assert!(
            section.ends_with(SECTION_END),
            "agents section must close with the end marker"
        );
        assert!(
            section.contains(AGENTS_MD_PREAMBLE),
            "agents section must carry the no-hook-enforcement preamble"
        );
        // The preamble leads and the full mandates text follows it, so an agent
        // reading top-down sees the honor-system caveat before any hook mention.
        let preamble_at = section.find(AGENTS_MD_PREAMBLE).expect("preamble present");
        let mandates_at = section
            .find("## Team memory (hippius-mem)")
            .expect("mandates body present");
        assert!(
            preamble_at < mandates_at,
            "preamble must precede the mandates"
        );
        let inner = team_memory_section()
            .strip_prefix(SECTION_START)
            .expect("asset leads with the start marker");
        assert!(
            section.contains(inner),
            "agents section must carry the full CLAUDE.md mandates text"
        );
    }

    /// Drift guard: the committed `AGENTS.md` in THIS repo must still carry the
    /// exact agents-variant block the binary would write — same contract as
    /// `committed_claude_md_contains_section`.
    #[test]
    fn committed_agents_md_contains_section() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate dir has a parent");
        let committed = std::fs::read_to_string(repo_root.join("AGENTS.md"))
            .expect("repo AGENTS.md must exist");
        assert!(
            committed.contains(&team_memory_section_agents()),
            "committed AGENTS.md has drifted from assets/team_memory_mandates.md; \
             run `hippius-mem init --allow-overwrite-tracked` to regenerate it"
        );
        assert_eq!(
            committed.matches(SECTION_START).count(),
            1,
            "committed AGENTS.md must carry exactly one hippius-mem block"
        );
    }

    #[test]
    fn end_without_start_does_not_duplicate_prose() {
        // A stray END with no START must not corrupt the file: it is stripped and one
        // fresh block appended, with the user's prose intact and no duplication.
        let content = format!("# CLAUDE.md\n\nuser prose\n{SECTION_END}\ntrailing prose\n");
        let out = splice_section(&content, "# H", team_memory_section());
        assert_eq!(
            out.matches(SECTION_START).count(),
            1,
            "exactly one block: {out}"
        );
        assert_eq!(
            out.matches(SECTION_END).count(),
            1,
            "no stray end survives: {out}"
        );
        assert!(out.contains("user prose") && out.contains("trailing prose"));
        // The old bug surfaced only on a SECOND splice; assert idempotence.
        assert_eq!(out, splice_section(&out, "# H", team_memory_section()));
    }

    #[test]
    fn reversed_markers_do_not_corrupt() {
        // END before START (a merge-conflict shape): no well-ordered pair, so the
        // markers are stripped and one fresh block appended — never an overlapping
        // slice that duplicates prose.
        let content = format!("prefix\n{SECTION_END}\nmiddle\n{SECTION_START}\nsuffix\n");
        let out = splice_section(&content, "# H", team_memory_section());
        assert_eq!(
            out.matches(SECTION_START).count(),
            1,
            "exactly one block: {out}"
        );
        assert_eq!(
            out.matches(SECTION_END).count(),
            1,
            "exactly one end: {out}"
        );
        assert!(
            out.contains("prefix") && out.contains("middle") && out.contains("suffix"),
            "all prose survives: {out}"
        );
        assert_eq!(out, splice_section(&out, "# H", team_memory_section()));
    }

    #[test]
    fn two_blocks_collapse_to_one() {
        // Two owned regions (a hand-duplicated block) collapse to exactly one; the
        // result is idempotent and carries no leftover markers.
        let block = format!("{SECTION_START}\nOLD\n{SECTION_END}");
        let content = format!("# CLAUDE.md\n\n{block}\n\nmid prose\n\n{block}\n");
        let out = splice_section(&content, "# H", team_memory_section());
        assert_eq!(
            out.matches(SECTION_START).count(),
            1,
            "collapsed to one block: {out}"
        );
        assert_eq!(out.matches(SECTION_END).count(), 1, "one end marker: {out}");
        assert_eq!(out, splice_section(&out, "# H", team_memory_section()));
    }

    #[test]
    fn tracked_clean_file_is_protected_without_opt_in() {
        // The is_git_tracked_and_clean guard (previously only ever exercised in its
        // fall-OPEN direction): a committed, clean CLAUDE.md whose block would change
        // is left intact unless allow_overwrite_tracked is set, so a stale binary or a
        // self-heal cannot silently downgrade it.
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path();
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .expect("git runs")
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t.t"]);
        git(&["config", "user.name", "t"]);

        // Commit a CLAUDE.md carrying a STALE block (different from what the binary
        // would write), so a regeneration WOULD change it.
        let stale = format!("# CLAUDE.md\n\n{SECTION_START}\nSTALE\n{SECTION_END}\n");
        std::fs::write(dir.join("CLAUDE.md"), &stale).expect("seed");
        git(&["add", "CLAUDE.md"]);
        git(&["commit", "-q", "-m", "seed"]);

        // Without opt-in the committed stale block is left intact (guard fires).
        write_md_section(
            dir,
            "CLAUDE.md",
            "# CLAUDE.md",
            team_memory_section(),
            false,
        )
        .expect("a guarded write is a no-op, not an error");
        assert_eq!(
            read(dir, "CLAUDE.md"),
            stale,
            "a tracked-clean file must be left intact without --allow-overwrite-tracked"
        );

        // With opt-in the block IS regenerated.
        write_md_section(dir, "CLAUDE.md", "# CLAUDE.md", team_memory_section(), true)
            .expect("opt-in write");
        assert!(
            !read(dir, "CLAUDE.md").contains("STALE"),
            "allow_overwrite_tracked must regenerate the block"
        );
    }

    #[test]
    fn is_git_tracked_and_clean_true_only_for_a_committed_unmodified_file() {
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path();

        // Not a git repo at all: fail-safe false.
        std::fs::write(dir.join("CLAUDE.md"), "x\n").expect("seed");
        assert!(!is_git_tracked_and_clean(dir, "CLAUDE.md"));

        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .expect("git runs")
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t.t"]);
        git(&["config", "user.name", "t"]);

        // Untracked in a real repo: false.
        assert!(!is_git_tracked_and_clean(dir, "CLAUDE.md"));

        // Tracked and clean: the one true case.
        git(&["add", "CLAUDE.md"]);
        git(&["commit", "-q", "-m", "seed"]);
        assert!(is_git_tracked_and_clean(dir, "CLAUDE.md"));

        // Tracked with an uncommitted edit: false.
        std::fs::write(dir.join("CLAUDE.md"), "x\nedit\n").expect("dirty");
        assert!(!is_git_tracked_and_clean(dir, "CLAUDE.md"));
    }

    proptest! {
        // Idempotence over prose that may contain STRAY markers in any order: splicing
        // twice yields the same body as once. The alphabet now interleaves the literal
        // marker strings — the case the prior `[a-zA-Z0-9 \n]` alphabet deliberately
        // excluded — because `splice_section` now strips orphan markers instead of
        // re-anchoring to them. Empty prose (fresh-file branch), append, and replace
        // branches are all reached.
        #[test]
        fn splice_is_idempotent(
            segments in proptest::collection::vec(
                prop_oneof![
                    "[a-zA-Z0-9 \n]{0,40}",
                    Just(SECTION_START.to_owned()),
                    Just(SECTION_END.to_owned()),
                ],
                0..12,
            ),
        ) {
            let prose: String = segments.concat();
            let once = splice_section(&prose, "# H", team_memory_section());
            let twice = splice_section(&once, "# H", team_memory_section());
            prop_assert_eq!(once, twice);
        }
    }
}
