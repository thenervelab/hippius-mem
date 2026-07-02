//! The instruction-file half of provisioning: inject a marker-delimited team
//! memory mandates block into `CLAUDE.md`.
//!
//! Ported from illu-rs `src/agents/instruction_md.rs`. The block is bracketed by
//! HTML-comment markers so a re-run replaces it in place (idempotent) and any
//! user content outside the markers survives byte-for-byte. The single source of
//! truth for the block text is the embedded asset; a drift-guard test keeps this
//! repo's committed `CLAUDE.md` in agreement with it.

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
/// [`write_md_section`]'s own formatting owns the surrounding whitespace — the
/// same contract illu's `illu_agent_section` has with its writer.
pub(crate) fn team_memory_section() -> &'static str {
    TEAM_MEMORY_ASSET.trim_end()
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
    std::fs::write(&md_path, new_content)
        .with_context(|| format!("writing {} failed", md_path.display()))?;
    tracing::info!("updated {file_name} with the hippius-mem section");
    Ok(())
}

/// Compute the new file body with `section` spliced into `content`.
///
/// Pure string surgery, split out so it is unit- and property-testable without
/// touching the filesystem. Three cases: replace between existing markers; wrap a
/// dangling start marker (missing end) by re-anchoring to it; or append (fresh
/// file gets `heading` first, a non-empty file just gets the section).
fn splice_section(content: &str, heading: &str, section: &str) -> String {
    if let Some(start) = content.find(SECTION_START) {
        if let Some(end) = content.find(SECTION_END) {
            let end = end + SECTION_END.len();
            return format!("{}{section}{}", &content[..start], &content[end..]);
        }
        return format!("{}{section}{}", &content[..start], &content[start..]);
    }
    if content.is_empty() {
        return format!("{heading}\n\n{section}\n");
    }
    format!("{content}\n{section}\n")
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
    std::fs::write(&md_path, stripped)
        .with_context(|| format!("writing {} failed", md_path.display()))?;
    Ok(())
}

/// Whether `file_name` is tracked by git under `repo_path` AND has no pending
/// modifications.
///
/// Fail-safe: if git is absent, the path is not a repo, or any git call errors,
/// this returns false so the caller falls open and writes as normal. That is the
/// intended bias — the guard exists only to protect a *known* committed file.
fn is_git_tracked_and_clean(repo_path: &Path, file_name: &str) -> bool {
    let tracked = Command::new("git")
        .current_dir(repo_path)
        .args(["ls-files", "--error-unmatch", "--", file_name])
        .output();
    match tracked {
        Ok(out) if out.status.success() => {}
        _ => return false,
    }
    let status = Command::new("git")
        .current_dir(repo_path)
        .args(["status", "--porcelain", "--", file_name])
        .output();
    match status {
        // Empty porcelain output == no staged or unstaged change to this path.
        Ok(out) if out.status.success() => out.stdout.is_empty(),
        _ => false,
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
        SECTION_END, SECTION_START, remove_md_section, splice_section, team_memory_section,
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
    }

    proptest! {
        // Idempotence over marker-free prose: splicing the section twice yields the
        // same body as splicing once. Marker-free is the real precondition — a
        // stray `<!-- hippius-mem:end -->` in the surrounding prose would let the
        // second splice re-anchor to it, so asserting idempotence for ARBITRARY
        // prose would claim more than the function guarantees. The alphabet below
        // cannot form `<!--`, so the property is exactly true. Empty prose (the
        // fresh-file branch) and the append+replace branches are all reached.
        #[test]
        fn splice_is_idempotent(prose in "[a-zA-Z0-9 \n]{0,400}") {
            let once = splice_section(&prose, "# H", team_memory_section());
            let twice = splice_section(&once, "# H", team_memory_section());
            prop_assert_eq!(once, twice);
        }
    }
}
