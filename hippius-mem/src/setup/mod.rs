//! Claude-Code agent provisioning, mirroring illu-rs's `agents` module scoped to
//! Claude Code.
//!
//! Three entry points:
//! - [`init`] — provision the current repo: inject the mandates block into
//!   `CLAUDE.md` and `AGENTS.md` (the convention file non-Claude agents read),
//!   install the recall/remember hooks, deregister any stale project-scope MCP
//!   entry, and ignore the per-machine hook cache.
//! - [`install`] — provision user-global config (`~/.claude/CLAUDE.md` +
//!   `~/.claude.json`), so the server is available across the user's projects.
//! - [`self_heal_on_serve`] — called on every server boot; refreshes existing
//!   instruction blocks (`CLAUDE.md` when Claude Code is the active agent,
//!   `AGENTS.md` for any client) so a provisioned repo keeps the rules current
//!   with the running binary. Never touches hooks/MCP/global (explicit intent).
//!
//! All provisioning is idempotent and follows the binary's `anyhow`-with-context
//! error style (see `doctor.rs`/`admin.rs`); the filesystem/JSON primitives live
//! in the `instructions`, `hooks`, and `mcp` submodules.

// Atomic, symlink-safe file replacement shared by the write sites below. Every
// config write in this module goes through it so a planted symlink cannot
// redirect an `init`/self-heal write (CWE-59/CWE-377).
mod atomic;
mod hooks;
mod instructions;
// `pub(crate)`: `join --bundle` reuses `mcp::resolved_global_config_path` so
// the config it writes lands exactly where the installer and dashboard look.
pub(crate) mod mcp;

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

/// The repo-default config file (`crate::config::DEFAULT_CONFIG_PATH`), which
/// `join --bundle` directs joiners to create at the repo root holding a live S3
/// secret and the team key — one `git add .` on an un-ignored copy publishes
/// both. Only the default name is covered: a custom `HIPPIUS_MEM_CONFIG` path
/// is the operator's choice and typically lives outside the repo, so it is
/// outside this repo-scoped gitignore's reach.
const CONFIG_FILE_IGNORE: &str = "hippius-mem.toml";

/// illu's generated-block markers in `CLAUDE.md`. Seed detection strips this block
/// (alongside the hippius-mem one) before deciding whether the file holds
/// hand-written knowledge worth lifting into team memory — both are
/// machine-generated rules, not seedable content.
const ILLU_SECTION_START: &str = "<!-- illu:start -->";
const ILLU_SECTION_END: &str = "<!-- illu:end -->";

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
    // hippius-mem registers ONLY in user-global `~/.claude.json`, and `configure_repo`
    // only DEregisters the project scope. So a standalone `hippius-mem init` (run
    // without `install`) would otherwise leave the server registered nowhere. Ensure
    // the global entry here — idempotent with `install`, skipped on uninstall and
    // when `$HOME` is unresolvable. (Kept out of `configure_repo` so its unit tests
    // do not touch the real `~/.claude.json`.)
    if !flags.uninstall {
        if let Some(home) = home_dir() {
            mcp::register_mcp_global(&home, &mcp::resolved_binary_path())?;
        } else {
            tracing::warn!(
                "$HOME is unset; skipped ensuring the global MCP registration — run `hippius-mem install`"
            );
        }
    }
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

/// Refresh the committed instruction blocks on a server boot, best-effort.
///
/// A no-op unless the cwd is inside a git repo. `CLAUDE.md` is refreshed only
/// when Claude Code is the active agent; `AGENTS.md` is refreshed for ANY
/// client, because its readers (Cursor, Codex CLI, generic MCP clients) set no
/// identifying env var — gating on `CLAUDECODE` would mean the one file those
/// agents read never tracks the binary. Each refresh only rewrites an existing
/// block, only when it changed, and the git-tracked-clean guard refuses to
/// silently downgrade a committed, clean file — so a stale binary cannot
/// quietly rewrite the rules. Every failure is logged, never propagated:
/// keeping memory serving always outranks a provisioning refresh.
pub(crate) fn self_heal_on_serve() {
    let Some(repo) = current_repo_root() else {
        tracing::debug!("self-heal: cwd is not inside a git repo; skipping instruction refresh");
        return;
    };
    if claude_code_active(|key| std::env::var(key).ok()) {
        refresh_existing_block(
            &repo,
            "CLAUDE.md",
            "# CLAUDE.md",
            instructions::team_memory_section(),
        );
    }
    // AGENTS.md is refreshed independently of CLAUDE.md. A previously symlinked
    // AGENTS.md <-> CLAUDE.md pair is de-linked into two regular files the first
    // time `write_md_section` (an atomic replace that never follows the link)
    // rewrites either name, so there is no shared inode to ping-pong between the
    // two block variants — each file just carries its own.
    refresh_existing_block(
        &repo,
        "AGENTS.md",
        "# AGENTS.md",
        &instructions::team_memory_section_agents(),
    );

    // NOTE: `.mcp.json` is deliberately NOT refreshed here. This runs inside the
    // server boot, so it cannot repair the case it would exist for — a stale
    // `.mcp.json` command means Claude Code never spawns the server, so this code
    // never runs; and when the server DOES boot, `current_exe()` equals the path
    // that spawned it, making any rewrite a no-op. The durable recovery is the
    // user-global `~/.claude.json` entry, refreshed by `install` (which the
    // installer's `--update` re-runs); `init` does not manage `.mcp.json` at all —
    // it deregisters any stale project entry so the global registration wins.
}

/// Refresh `<repo>/<file_name>`'s hippius-mem block if — and only if — one exists.
///
/// Self-heal REFRESHES an existing block only; it never CREATES one on boot.
/// Installing the block is `init`'s explicit job, so a file with no hippius-mem
/// block — or no file at all — is left untouched here. Without this gate a
/// server start would append a block to (and so dirty) a committed, clean file
/// that never had one, unrequested. Infallible by design: a refresh failure is
/// logged and swallowed because serving memory outranks provisioning.
fn refresh_existing_block(repo: &Path, file_name: &str, heading: &str, section: &str) {
    let has_block = std::fs::read_to_string(repo.join(file_name))
        .is_ok_and(|content| content.contains(instructions::SECTION_START));
    if !has_block {
        tracing::debug!(
            file = file_name,
            "self-heal: no hippius-mem block; leaving creation to `init`"
        );
        return;
    }
    if let Err(e) = instructions::write_md_section(repo, file_name, heading, section, false) {
        tracing::warn!(error = %e, file = file_name, "self-heal: block refresh failed");
    }
}

/// Apply (or reverse) per-repo provisioning under `repo`.
fn configure_repo(repo: &Path, flags: SetupFlags) -> anyhow::Result<()> {
    if flags.uninstall {
        instructions::remove_md_section(repo, "CLAUDE.md")?;
        instructions::remove_md_section(repo, "AGENTS.md")?;
        hooks::unregister_hooks(repo)?;
        mcp::deregister_mcp_repo(repo)?;
        return Ok(());
    }
    // Detect pre-existing knowledge BEFORE our blocks are spliced in, so a
    // freshly-written hippius-mem block is never mistaken for user content.
    let seed_sources = detect_seed_sources(repo);

    instructions::write_md_section(
        repo,
        "CLAUDE.md",
        "# CLAUDE.md",
        instructions::team_memory_section(),
        flags.allow_overwrite_tracked,
    )?;
    // AGENTS.md is the file non-Claude agents (Cursor, Codex CLI, generic MCP
    // clients) read by convention. None of them run our hooks, so this block —
    // led by its honor-system preamble — is their entire enforcement floor, so it
    // is always written. A repo that symlinked AGENTS.md and CLAUDE.md together is
    // de-linked into two regular files by these atomic writes (which replace rather
    // than follow a symlink — the CWE-59 hardening in `super::atomic`); each then
    // carries its own variant, the correct end state: a non-Claude agent reading
    // AGENTS.md gets the honor-system preamble it needs, not the CLAUDE variant.
    instructions::write_md_section(
        repo,
        "AGENTS.md",
        "# AGENTS.md",
        &instructions::team_memory_section_agents(),
        flags.allow_overwrite_tracked,
    )?;
    if !flags.no_hooks {
        hooks::install_hook_scripts(repo)?;
        hooks::register_hooks_in_settings(repo)?;
    }
    // hippius-mem registers ONLY in user-scope ~/.claude.json (via `install`); a
    // project-scope entry would merely shadow it and a stale one is the -32000/ENOENT
    // failure. Remove any entry a prior version wrote so the good global entry wins;
    // `.mcp.json` is otherwise none of our business (we neither create nor gitignore
    // it — a repo may legitimately commit it for other servers).
    mcp::deregister_mcp_repo(repo)?;
    mcp::ensure_gitignore_entry(repo, HOOK_CACHE_IGNORE)?;
    mcp::ensure_gitignore_entry(repo, FASTEMBED_CACHE_IGNORE)?;
    // Like the two cache lines above, this line survives uninstall (the
    // uninstall branch never edits .gitignore): the secret-bearing config may
    // still exist after uninstall, and dropping its ignore line would re-expose
    // it to the next `git add .`.
    mcp::ensure_gitignore_entry(repo, CONFIG_FILE_IGNORE)?;
    // Undo the `.mcp.json` gitignore line the immediately-prior version wrote:
    // hippius-mem no longer manages `.mcp.json`, so a repo must stay free to commit
    // it for other servers. No-op on a repo that never had the line.
    mcp::remove_gitignore_entry(repo, ".mcp.json")?;
    write_seed_pending(repo, &seed_sources);
    Ok(())
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
    // No user-global AGENTS.md: there is no cross-agent convention for one. Each
    // tool that supports a global file uses its own private directory (Codex:
    // `~/.codex/AGENTS.md`, droid: `~/.factory/AGENTS.md`), and the agents.md
    // spec has only an open proposal (agentsmd/agents.md#91) for
    // `~/.config/agents/AGENTS.md`. Writing into another tool's config dir is
    // not ours to do, so AGENTS.md support stays repo-level (`init`) only.
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

/// The pre-existing knowledge sources for `repo` that the seed nudge should point
/// the agent at: a personal Claude Code memory index and/or a hand-written
/// `CLAUDE.md` / `AGENTS.md`.
///
/// Best-effort and infallible — an unreadable or absent source is simply omitted.
/// Callers run this BEFORE `write_md_section` so a freshly-written hippius-mem
/// block does not itself register as user content.
fn detect_seed_sources(repo: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    if let Some(home) = home_dir()
        && let Some(memory) = personal_memory_index(&home, repo)
    {
        sources.push(memory);
    }
    // AGENTS.md prose is exactly as seedable as CLAUDE.md prose: both are
    // hand-written repo knowledge another agent already relies on.
    for name in ["CLAUDE.md", "AGENTS.md"] {
        let md = repo.join(name);
        if instruction_md_has_user_content(&md) {
            sources.push(md);
        }
    }
    sources
}

/// The personal Claude Code memory index for `repo` under `home`
/// (`~/.claude/projects/<slug>/memory/MEMORY.md`), if it exists.
fn personal_memory_index(home: &Path, repo: &Path) -> Option<PathBuf> {
    let memory = home
        .join(".claude/projects")
        .join(claude_project_slug(repo))
        .join("memory/MEMORY.md");
    memory.is_file().then_some(memory)
}

/// Claude Code's per-project directory name for `repo`: the path string with every
/// non-`[A-Za-z0-9]` character replaced by `-`.
///
/// Mirrors Claude Code's own transform (docs: the working-directory path "with
/// non-alphanumeric characters replaced by `-`"), so we resolve the same
/// `~/.claude/projects/<slug>/` directory it writes — e.g.
/// `/Volumes/Source/hippius-mem` -> `-Volumes-Source-hippius-mem`. Non-ASCII and
/// punctuation alike collapse to `-`; only ASCII alphanumerics pass through.
fn claude_project_slug(repo: &Path) -> String {
    repo.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Whether the instruction file at `md` (`CLAUDE.md` or `AGENTS.md`) holds
/// hand-written content beyond the generated blocks.
///
/// Strips the hippius-mem and illu marker blocks (both machine-generated, not
/// seedable knowledge) and reports whether any non-whitespace remains. A missing
/// or unreadable file reads as "no content".
fn instruction_md_has_user_content(md: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(md) else {
        return false;
    };
    let without_hippius = strip_marked_block(
        &content,
        instructions::SECTION_START,
        instructions::SECTION_END,
    );
    let stripped = strip_marked_block(&without_hippius, ILLU_SECTION_START, ILLU_SECTION_END);
    // Content = any non-blank line that is not a bare Markdown heading. Skipping
    // heading lines is what stops the `# CLAUDE.md` title `write_md_section` emits
    // on a fresh file — which survives block-stripping — from reading as a
    // false-positive seed source on a later re-init.
    stripped
        .lines()
        .map(str::trim)
        .any(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Remove the first well-ordered `start..end` marked block (markers included) from
/// `text`; return `text` unchanged when no such ordered pair exists.
///
/// Only a `start` followed by an `end` is removed, mirroring `splice_section`'s
/// well-ordered-pair discipline: a lone or reversed marker leaves the text intact
/// rather than slicing across an unintended span.
fn strip_marked_block(text: &str, start: &str, end: &str) -> String {
    if let Some(s) = text.find(start)
        && let Some(rel_e) = text[s..].find(end)
    {
        let e = s + rel_e + end.len();
        return format!("{}{}", &text[..s], &text[e..]);
    }
    text.to_owned()
}

/// Record (or clear) the seed-nudge pending marker for `repo`.
///
/// Writes `.hippius-mem/cache/seed-pending.json` listing `sources` so the
/// `SessionStart` seed-nudge hook can name them; removes any stale marker when
/// `sources` is empty. Best-effort and infallible: this is a cache write, and a
/// failure here must not fail `init`, so every error is logged, not propagated.
fn write_seed_pending(repo: &Path, sources: &[PathBuf]) {
    let marker = repo.join(".hippius-mem/cache/seed-pending.json");
    if sources.is_empty() {
        // Nothing to seed: drop any stale marker so the nudge does not linger.
        match std::fs::remove_file(&marker) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(error = %e, "seed: clearing stale seed-pending marker failed"),
        }
        return;
    }
    let Some(parent) = marker.parent() else {
        return;
    };
    if let Err(e) = std::fs::create_dir_all(parent) {
        tracing::warn!(error = %e, "seed: creating cache dir failed; skipping seed nudge");
        return;
    }
    let list: Vec<String> = sources
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let serialized = match serde_json::to_string_pretty(&serde_json::json!({ "sources": list })) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "seed: serializing seed-pending failed");
            return;
        }
    };
    if let Err(e) = std::fs::write(&marker, format!("{serialized}\n")) {
        tracing::warn!(error = %e, "seed: writing seed-pending marker failed");
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning provisioning steps"
    )]

    use std::path::{Path, PathBuf};

    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::instructions::{SECTION_END, SECTION_START};
    use super::{
        ILLU_SECTION_END, ILLU_SECTION_START, SetupFlags, claude_code_active, claude_project_slug,
        configure_global, configure_repo, detect_seed_sources, instruction_md_has_user_content,
        personal_memory_index, strip_marked_block, write_seed_pending,
    };

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
        let agents = agents_md(tmp.path());
        assert!(
            agents.contains("<!-- hippius-mem:start -->"),
            "no AGENTS.md mandates block"
        );
        assert!(
            agents.contains("No hook enforcement in this environment"),
            "AGENTS.md block must lead with the honor-system preamble: {agents}"
        );
        assert!(
            agents.starts_with("# AGENTS.md"),
            "fresh AGENTS.md must lead with its own heading: {agents}"
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
        // Global-only registration: init must NOT create a project .mcp.json (the
        // server is registered solely in ~/.claude.json), nor gitignore it.
        assert!(
            !tmp.path().join(".mcp.json").exists(),
            "init must not create a project .mcp.json"
        );
        let gitignore = std::fs::read_to_string(tmp.path().join(".gitignore")).expect("gitignore");
        assert!(
            gitignore.contains(".hippius-mem/"),
            "cache dir not ignored: {gitignore}"
        );
        assert!(
            gitignore.contains(".fastembed_cache/"),
            "fastembed model cache not ignored: {gitignore}"
        );
        assert!(
            gitignore.lines().any(|l| l.trim() == "hippius-mem.toml"),
            "secret-bearing config file not ignored: {gitignore}"
        );
        assert!(
            !gitignore.lines().any(|l| l.trim() == ".mcp.json"),
            "init must not gitignore .mcp.json (not ours to manage): {gitignore}"
        );
    }

    #[test]
    fn config_gitignore_line_is_idempotent_preserves_content_and_survives_uninstall() {
        let tmp = TempDir::new().expect("tempdir");
        // Pre-existing user rules must survive the append untouched.
        std::fs::write(tmp.path().join(".gitignore"), "target/\n*.log\n").expect("seed");
        configure_repo(tmp.path(), SetupFlags::default()).expect("first init");
        let first = std::fs::read_to_string(tmp.path().join(".gitignore")).expect("gitignore");
        assert!(
            first.starts_with("target/\n*.log\n"),
            "user content must be preserved: {first}"
        );
        assert_eq!(
            first
                .lines()
                .filter(|l| l.trim() == "hippius-mem.toml")
                .count(),
            1,
            "exactly one config ignore line: {first}"
        );

        configure_repo(tmp.path(), SetupFlags::default()).expect("re-run");
        let second = std::fs::read_to_string(tmp.path().join(".gitignore")).expect("gitignore");
        assert_eq!(first, second, "re-run must be byte-identical");

        // Uninstall leaves .gitignore alone for every line hippius-mem wrote —
        // for this one that is also a safety property: the secret-bearing
        // config file may still exist, so its ignore line must outlive us.
        let undo = SetupFlags {
            uninstall: true,
            ..SetupFlags::default()
        };
        configure_repo(tmp.path(), undo).expect("uninstall");
        let after = std::fs::read_to_string(tmp.path().join(".gitignore")).expect("gitignore");
        assert_eq!(second, after, "uninstall must not edit .gitignore");
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
            !agents_md(tmp.path()).contains("<!-- hippius-mem:start -->"),
            "AGENTS.md block not removed"
        );
        assert!(
            !tmp.path()
                .join(".claude/hooks/hippius-mem-recall-preflight.sh")
                .exists(),
            "hook script not removed"
        );
    }

    /// A repo that symlinked AGENTS.md and CLAUDE.md together is DE-LINKED by the
    /// atomic instruction writes (which replace, never follow, a symlink — the
    /// CWE-59 hardening), so after init each is an independent regular file
    /// carrying its OWN variant: CLAUDE.md the plain block, AGENTS.md the
    /// honor-system-preamble variant a non-Claude agent needs. Re-run is idempotent.
    #[cfg(unix)]
    #[test]
    fn symlinked_instruction_files_are_de_linked_into_independent_blocks() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("AGENTS.md"), "# shared rules\n").expect("seed");
        std::os::unix::fs::symlink("AGENTS.md", tmp.path().join("CLAUDE.md")).expect("symlink");
        configure_repo(tmp.path(), SetupFlags::default()).expect("configure");

        // The atomic write REPLACED the CLAUDE.md symlink rather than following it:
        // CLAUDE.md is now its own regular file, not a link to AGENTS.md.
        assert!(
            !std::fs::symlink_metadata(tmp.path().join("CLAUDE.md"))
                .expect("stat CLAUDE.md")
                .file_type()
                .is_symlink(),
            "the atomic write must replace the CLAUDE.md symlink, not follow it"
        );
        let claude = claude_md(tmp.path());
        let agents = agents_md(tmp.path());
        // Each file has exactly one block, of its own variant.
        assert_eq!(
            claude.matches(SECTION_START).count(),
            1,
            "one CLAUDE block: {claude}"
        );
        assert_eq!(
            agents.matches(SECTION_START).count(),
            1,
            "one AGENTS block: {agents}"
        );
        assert!(
            !claude.contains("No hook enforcement in this environment"),
            "CLAUDE.md carries the plain variant: {claude}"
        );
        assert!(
            agents.contains("No hook enforcement in this environment"),
            "AGENTS.md carries the honor-system-preamble variant: {agents}"
        );
        // User prose outside the markers survives in both files.
        assert!(
            claude.contains("# shared rules") && agents.contains("# shared rules"),
            "user prose must survive in both files"
        );
        // Re-run is idempotent (byte-identical) for both files.
        configure_repo(tmp.path(), SetupFlags::default()).expect("re-run");
        assert_eq!(
            claude,
            claude_md(tmp.path()),
            "CLAUDE.md re-run must be byte-identical"
        );
        assert_eq!(
            agents,
            agents_md(tmp.path()),
            "AGENTS.md re-run must be byte-identical"
        );
    }

    #[test]
    fn agents_md_rerun_is_idempotent_and_preserves_user_prose() {
        let tmp = TempDir::new().expect("tempdir");
        // A hand-written AGENTS.md (another agent's rules) must survive init
        // byte-for-byte outside the markers, and a re-run must change nothing.
        std::fs::write(
            tmp.path().join("AGENTS.md"),
            "# AGENTS.md\n\ncursor-specific rules that must survive\n",
        )
        .expect("seed");
        configure_repo(tmp.path(), SetupFlags::default()).expect("first init");
        let after_first = agents_md(tmp.path());
        assert!(
            after_first.contains("cursor-specific rules that must survive"),
            "user prose dropped: {after_first}"
        );
        assert!(
            after_first.contains("No hook enforcement in this environment"),
            "preamble missing: {after_first}"
        );
        configure_repo(tmp.path(), SetupFlags::default()).expect("second init");
        assert_eq!(
            after_first,
            agents_md(tmp.path()),
            "re-run must be byte-identical"
        );
    }

    #[test]
    fn agents_md_stale_block_is_refreshed() {
        let tmp = TempDir::new().expect("tempdir");
        // Not a git repo -> the tracked-clean guard falls open and the stale
        // block from an older binary is replaced in place.
        std::fs::write(
            tmp.path().join("AGENTS.md"),
            format!("# AGENTS.md\n\n{SECTION_START}\nSTALE\n{SECTION_END}\n"),
        )
        .expect("seed stale");
        configure_repo(tmp.path(), SetupFlags::default()).expect("init");
        let body = agents_md(tmp.path());
        assert!(!body.contains("STALE"), "stale block must be gone: {body}");
        assert_eq!(
            body.matches(SECTION_START).count(),
            1,
            "exactly one block: {body}"
        );
    }

    #[test]
    fn agents_md_tracked_clean_semantics_match_claude_md() {
        // Through the public path: a committed, clean AGENTS.md with a stale
        // block is protected exactly like CLAUDE.md — left intact by default,
        // regenerated only under --allow-overwrite-tracked.
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
        let stale = format!("# AGENTS.md\n\n{SECTION_START}\nSTALE\n{SECTION_END}\n");
        std::fs::write(dir.join("AGENTS.md"), &stale).expect("seed");
        git(&["add", "AGENTS.md"]);
        git(&["commit", "-q", "-m", "seed"]);

        configure_repo(dir, SetupFlags::default()).expect("guarded init");
        assert_eq!(
            agents_md(dir),
            stale,
            "a tracked-clean AGENTS.md must be left intact without opt-in"
        );

        let force = SetupFlags {
            allow_overwrite_tracked: true,
            ..SetupFlags::default()
        };
        configure_repo(dir, force).expect("forced init");
        assert!(
            !agents_md(dir).contains("STALE"),
            "--allow-overwrite-tracked must regenerate the AGENTS.md block"
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

    #[test]
    fn slug_replaces_every_non_alphanumeric() {
        // Matches Claude Code's ~/.claude/projects/<slug>/ transform, incl. the
        // leading `-` from the leading `/` and dots/underscores/spaces -> `-`.
        assert_eq!(
            claude_project_slug(Path::new("/Volumes/Source/hippius-mem")),
            "-Volumes-Source-hippius-mem"
        );
        assert_eq!(
            claude_project_slug(Path::new("/Users/foo.bar/my_proj x")),
            "-Users-foo-bar-my-proj-x"
        );
    }

    proptest! {
        // The slug is a 1:1 character normalizer: it preserves length and emits
        // only ASCII alphanumerics and `-`. (For a valid-UTF-8 String, the Path's
        // `to_string_lossy` round-trips, so the per-char map sees exactly `s`.)
        #[test]
        fn slug_preserves_length_and_charset(s in ".*") {
            let slug = claude_project_slug(Path::new(&s));
            prop_assert_eq!(slug.chars().count(), s.chars().count());
            prop_assert!(
                slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "slug had a stray char: {slug}"
            );
        }
    }

    #[test]
    fn strip_marked_block_removes_one_well_ordered_block() {
        let text = format!("before\n{SECTION_START}\ninner\n{SECTION_END}\nafter");
        let out = strip_marked_block(&text, SECTION_START, SECTION_END);
        assert_eq!(out, "before\n\nafter");
    }

    #[test]
    fn strip_marked_block_leaves_lone_or_reversed_markers() {
        // A lone start (no end after it) and an end-before-start are both "no
        // well-ordered pair" -> text returned verbatim, never sliced.
        let lone = format!("x {SECTION_START} y");
        assert_eq!(strip_marked_block(&lone, SECTION_START, SECTION_END), lone);
        let reversed = format!("{SECTION_END} mid {SECTION_START}");
        assert_eq!(
            strip_marked_block(&reversed, SECTION_START, SECTION_END),
            reversed
        );
    }

    proptest! {
        // Progress: stripping removes a block exactly when a well-ordered pair is
        // present (output strictly shorter), and is a no-op otherwise.
        #[test]
        fn strip_marked_block_makes_progress(
            segments in proptest::collection::vec(
                prop_oneof![
                    "[a-z ]{0,8}",
                    Just(SECTION_START.to_owned()),
                    Just(SECTION_END.to_owned()),
                ],
                0..10,
            ),
        ) {
            let text: String = segments.concat();
            let out = strip_marked_block(&text, SECTION_START, SECTION_END);
            let has_pair = text
                .find(SECTION_START)
                .and_then(|s| text[s..].find(SECTION_END))
                .is_some();
            if has_pair {
                prop_assert!(out.len() < text.len(), "no progress on {text:?}");
            } else {
                prop_assert_eq!(out, text);
            }
        }
    }

    #[test]
    fn instruction_md_content_detection() {
        let tmp = TempDir::new().expect("tempdir");
        let md = tmp.path().join("CLAUDE.md");

        // Absent file -> no content.
        assert!(!instruction_md_has_user_content(&md));

        // The production shape: the `# CLAUDE.md` heading write_md_section emits on
        // a fresh file, plus only the generated blocks -> no seedable content. The
        // heading must NOT be mistaken for user content (the false-positive bug).
        let generated = format!(
            "# CLAUDE.md\n\n{SECTION_START}\nmandates\n{SECTION_END}\n\n{ILLU_SECTION_START}\nrules\n{ILLU_SECTION_END}\n"
        );
        std::fs::write(&md, &generated).expect("write");
        assert!(
            !instruction_md_has_user_content(&md),
            "generated-only CLAUDE.md (with heading) must not count as content"
        );

        // Hand-written prose outside the blocks -> content.
        let with_prose =
            format!("# CLAUDE.md\n\nour team convention\n\n{SECTION_START}\nx\n{SECTION_END}\n");
        std::fs::write(&md, &with_prose).expect("write");
        assert!(
            instruction_md_has_user_content(&md),
            "hand-written prose must count as content"
        );
    }

    #[test]
    fn personal_memory_index_found_only_when_file_exists() {
        let home = TempDir::new().expect("home");
        let repo = Path::new("/some/repo/path");
        // Absent -> None.
        assert!(personal_memory_index(home.path(), repo).is_none());
        // Create the index at the exact slug path Claude Code would use.
        let dir = home
            .path()
            .join(".claude/projects")
            .join(claude_project_slug(repo))
            .join("memory");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("MEMORY.md"), "- [x](x.md) — note\n").expect("write");
        assert_eq!(
            personal_memory_index(home.path(), repo),
            Some(dir.join("MEMORY.md"))
        );
    }

    #[test]
    fn detect_seed_sources_includes_hand_written_instruction_files() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("CLAUDE.md"), "# CLAUDE.md\n\nreal notes\n").expect("write");
        std::fs::write(tmp.path().join("AGENTS.md"), "# AGENTS.md\n\nagent notes\n")
            .expect("write");
        let sources = detect_seed_sources(tmp.path());
        assert!(
            sources.contains(&tmp.path().join("CLAUDE.md")),
            "CLAUDE.md prose should be a seed source: {sources:?}"
        );
        assert!(
            sources.contains(&tmp.path().join("AGENTS.md")),
            "AGENTS.md prose should be a seed source: {sources:?}"
        );
    }

    #[test]
    fn write_seed_pending_writes_then_clears() {
        let tmp = TempDir::new().expect("tempdir");
        let marker = tmp.path().join(".hippius-mem/cache/seed-pending.json");
        let src = PathBuf::from("/a/CLAUDE.md");
        write_seed_pending(tmp.path(), std::slice::from_ref(&src));
        let raw = std::fs::read_to_string(&marker).expect("marker written");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
        assert_eq!(parsed["sources"][0], "/a/CLAUDE.md");
        // Empty source list clears the stale marker.
        write_seed_pending(tmp.path(), &[]);
        assert!(!marker.exists(), "empty sources must remove the marker");
    }

    fn claude_md(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("CLAUDE.md")).expect("CLAUDE.md must exist")
    }

    fn agents_md(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("AGENTS.md")).expect("AGENTS.md must exist")
    }
}
