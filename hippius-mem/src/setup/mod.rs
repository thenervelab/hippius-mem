//! Claude-Code agent provisioning, mirroring illu-rs's `agents` module scoped to
//! Claude Code.
//!
//! Three entry points:
//! - [`init`] — provision the current repo: inject the mandates block into
//!   `CLAUDE.md`, install the recall/remember hooks, register the MCP server in
//!   `.mcp.json`, and ignore the per-machine hook cache.
//! - [`install`] — provision user-global config (`~/.claude/CLAUDE.md` +
//!   `~/.claude.json`), so the server is available across the user's projects.
//! - [`self_heal_on_serve`] — called on every server boot; refreshes only the
//!   committed `CLAUDE.md` block when Claude Code is the active agent, so
//!   starting Claude in a provisioned repo keeps the rules current with the
//!   running binary. Never touches hooks/MCP/global (those are explicit intent).
//!
//! All provisioning is idempotent and follows the binary's `anyhow`-with-context
//! error style (see `doctor.rs`/`admin.rs`); the filesystem/JSON primitives live
//! in the `instructions`, `hooks`, and `mcp` submodules.

mod hooks;
mod instructions;
mod mcp;

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

/// Environment variable Claude Code sets in every agent process. Its presence is
/// how self-heal knows Claude Code — rather than another agent — is driving.
const CLAUDE_CODE_ENV: &str = "CLAUDECODE";

/// The per-machine hook-cache directory, ignored from version control by `init`.
const HOOK_CACHE_IGNORE: &str = ".hippius-mem/";

/// fastembed's model cache. The `embeddings` build now pins this to a
/// per-machine directory (see `hippius-mem-core`'s `default_cache_dir`), so it
/// should never land in a repo — this entry is a rollout safety net that also
/// hides any cache an older binary already wrote into the tree.
const FASTEMBED_CACHE_IGNORE: &str = ".fastembed_cache/";

/// Flags shared by `init` and `install`.
///
/// Plain `Copy` data — no interactive/agent-selection state, since this port
/// targets Claude Code only and prompts nothing.
#[derive(Debug, Default, Clone, Copy)]
struct SetupFlags {
    /// Skip installing hook scripts and their `settings.json` entries.
    no_hooks: bool,
    /// Force regeneration of a git-tracked, clean instruction block (see
    /// [`instructions::write_md_section`]).
    allow_overwrite_tracked: bool,
    /// Reverse provisioning instead of applying it.
    uninstall: bool,
}

impl SetupFlags {
    /// Parse the flags accepted by `init`/`install`.
    ///
    /// # Errors
    ///
    /// Returns an error on any unrecognized argument.
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut flags = SetupFlags::default();
        for arg in args {
            match arg.as_str() {
                "--no-hooks" => flags.no_hooks = true,
                "--allow-overwrite-tracked" => flags.allow_overwrite_tracked = true,
                "--uninstall" => flags.uninstall = true,
                other => bail!(
                    "unknown argument `{other}`; usage: init|install \
                     [--no-hooks] [--allow-overwrite-tracked] [--uninstall]"
                ),
            }
        }
        Ok(flags)
    }
}

/// Whether Claude Code is the active agent, per the injected env `lookup`.
///
/// The `lookup` seam mirrors `Config::from_sources`: production passes a closure
/// over `std::env::var`, tests pass a fixture map, so detection is verified with
/// no process-global env mutation.
fn claude_code_active(lookup: impl Fn(&str) -> Option<String>) -> bool {
    matches!(lookup(CLAUDE_CODE_ENV), Some(value) if !value.is_empty())
}

/// Run the `init` subcommand: provision the current working directory.
///
/// # Errors
///
/// Returns an error if the cwd cannot be resolved, an argument is unknown, or any
/// provisioning step fails.
pub(crate) fn init(args: &[String]) -> anyhow::Result<()> {
    let flags = SetupFlags::parse(args)?;
    let repo = std::env::current_dir().context("resolving the current directory failed")?;
    configure_repo(&repo, flags)?;
    let verb = if flags.uninstall { "uninstall" } else { "init" };
    tracing::info!(repo = %repo.display(), "hippius-mem {verb} complete");
    Ok(())
}

/// Run the `install` subcommand: provision user-global config under `$HOME`.
///
/// # Errors
///
/// Returns an error if `$HOME` is unset, an argument is unknown, or any
/// provisioning step fails.
pub(crate) fn install(args: &[String]) -> anyhow::Result<()> {
    let flags = SetupFlags::parse(args)?;
    let home = home_dir().context("$HOME is not set; cannot locate the user config directory")?;
    configure_global(&home, flags)?;
    tracing::info!(home = %home.display(), "hippius-mem install complete");
    Ok(())
}

/// Refresh the committed `CLAUDE.md` block on a server boot, best-effort.
///
/// A no-op unless Claude Code is active and the cwd is inside a git repo. It only
/// rewrites the instruction block, only when it changed, and its git-tracked-clean
/// guard refuses to silently downgrade a committed, clean `CLAUDE.md` — so a stale
/// binary cannot quietly rewrite the rules. Every failure is logged, never
/// propagated: keeping memory serving always outranks a provisioning refresh.
pub(crate) fn self_heal_on_serve() {
    if !claude_code_active(|key| std::env::var(key).ok()) {
        return;
    }
    let Some(repo) = current_repo_root() else {
        tracing::debug!("self-heal: cwd is not inside a git repo; skipping CLAUDE.md refresh");
        return;
    };
    // Self-heal REFRESHES an existing block only; it never CREATES one on boot.
    // Installing the block is `init`'s explicit job, so a repo whose CLAUDE.md has no
    // hippius-mem block — or no CLAUDE.md at all — is left untouched here. Without
    // this gate a server start would append a block to (and so dirty) a committed,
    // clean CLAUDE.md that never had one, unrequested.
    let md = repo.join("CLAUDE.md");
    let has_block = std::fs::read_to_string(&md)
        .is_ok_and(|content| content.contains(instructions::SECTION_START));
    if !has_block {
        tracing::debug!("self-heal: no hippius-mem block in CLAUDE.md; leaving creation to `init`");
        return;
    }
    if let Err(e) = instructions::write_md_section(
        &repo,
        "CLAUDE.md",
        "# CLAUDE.md",
        instructions::team_memory_section(),
        false,
    ) {
        tracing::warn!(error = %e, "self-heal: CLAUDE.md refresh failed");
    }
}

/// Apply (or reverse) per-repo provisioning under `repo`.
fn configure_repo(repo: &Path, flags: SetupFlags) -> anyhow::Result<()> {
    if flags.uninstall {
        instructions::remove_md_section(repo, "CLAUDE.md")?;
        hooks::unregister_hooks(repo)?;
        return Ok(());
    }
    instructions::write_md_section(
        repo,
        "CLAUDE.md",
        "# CLAUDE.md",
        instructions::team_memory_section(),
        flags.allow_overwrite_tracked,
    )?;
    if !flags.no_hooks {
        hooks::install_hook_scripts(repo)?;
        hooks::register_hooks_in_settings(repo)?;
    }
    mcp::register_mcp_repo(repo)?;
    mcp::ensure_gitignore_entry(repo, HOOK_CACHE_IGNORE)?;
    mcp::ensure_gitignore_entry(repo, FASTEMBED_CACHE_IGNORE)
}

/// Apply user-global provisioning under `home` (instruction block + MCP entry).
///
/// No hooks (they are per-repo) and no `.gitignore` (there is no repo). The
/// `.claude` directory is created if absent so the instruction write cannot fail
/// on a fresh machine.
fn configure_global(home: &Path, flags: SetupFlags) -> anyhow::Result<()> {
    let claude_dir = home.join(".claude");
    std::fs::create_dir_all(&claude_dir)
        .with_context(|| format!("creating {} failed", claude_dir.display()))?;
    instructions::write_md_section(
        &claude_dir,
        "CLAUDE.md",
        "# CLAUDE.md",
        instructions::team_memory_section(),
        flags.allow_overwrite_tracked,
    )?;
    mcp::register_mcp_global(home, &mcp::resolved_binary_path())
}

/// The git repo root containing the cwd, or `None` if the cwd is not in a repo.
///
/// Fail-safe: any git error (git absent, not a repo, non-UTF-8 path) yields
/// `None`, so self-heal simply skips rather than erroring.
fn current_repo_root() -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8(out.stdout).ok()?;
    let trimmed = path.trim();
    (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
}

/// The user's home directory from `$HOME`, or `None` if unset/empty.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning provisioning steps"
    )]

    use std::path::Path;

    use tempfile::TempDir;

    use super::{SetupFlags, claude_code_active, configure_global, configure_repo};

    #[test]
    fn detects_claude_code_only_when_env_is_non_empty() {
        assert!(claude_code_active(
            |k| (k == "CLAUDECODE").then(|| "1".to_string())
        ));
        assert!(
            !claude_code_active(|_| None),
            "absent env must read as inactive"
        );
        assert!(
            !claude_code_active(|_| Some(String::new())),
            "empty env must read as inactive"
        );
    }

    #[test]
    fn configure_repo_writes_every_artifact() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("configure");

        assert!(
            claude_md(tmp.path()).contains("<!-- hippius-mem:start -->"),
            "no mandates block"
        );
        assert!(
            tmp.path().join(".claude/settings.json").exists(),
            "no settings.json"
        );
        assert!(
            tmp.path()
                .join(".claude/hooks/hippius-mem-recall-preflight.sh")
                .exists(),
            "no hook script"
        );
        assert!(tmp.path().join(".mcp.json").exists(), "no .mcp.json");
        let gitignore = std::fs::read_to_string(tmp.path().join(".gitignore")).expect("gitignore");
        assert!(
            gitignore.contains(".hippius-mem/"),
            "cache dir not ignored: {gitignore}"
        );
        assert!(
            gitignore.contains(".fastembed_cache/"),
            "fastembed model cache not ignored: {gitignore}"
        );
    }

    #[test]
    fn no_hooks_flag_skips_hook_artifacts() {
        let tmp = TempDir::new().expect("tempdir");
        let flags = SetupFlags {
            no_hooks: true,
            ..SetupFlags::default()
        };
        configure_repo(tmp.path(), flags).expect("configure");
        assert!(
            claude_md(tmp.path()).contains("<!-- hippius-mem:start -->"),
            "block still expected"
        );
        assert!(
            !tmp.path()
                .join(".claude/hooks/hippius-mem-recall-preflight.sh")
                .exists(),
            "--no-hooks must not write hook scripts"
        );
    }

    #[test]
    fn uninstall_reverses_block_and_hooks() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("install");
        let undo = SetupFlags {
            uninstall: true,
            ..SetupFlags::default()
        };
        configure_repo(tmp.path(), undo).expect("uninstall");
        assert!(
            !claude_md(tmp.path()).contains("<!-- hippius-mem:start -->"),
            "block not removed"
        );
        assert!(
            !tmp.path()
                .join(".claude/hooks/hippius-mem-recall-preflight.sh")
                .exists(),
            "hook script not removed"
        );
    }

    #[test]
    fn configure_global_writes_home_instruction_and_mcp() {
        let home = TempDir::new().expect("tempdir");
        configure_global(home.path(), SetupFlags::default()).expect("global");
        let global_md = std::fs::read_to_string(home.path().join(".claude/CLAUDE.md"))
            .expect("~/.claude/CLAUDE.md must exist");
        assert!(
            global_md.contains("<!-- hippius-mem:start -->"),
            "global block missing"
        );
        assert!(
            home.path().join(".claude.json").exists(),
            "~/.claude.json must exist"
        );
    }

    fn claude_md(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("CLAUDE.md")).expect("CLAUDE.md must exist")
    }
}
