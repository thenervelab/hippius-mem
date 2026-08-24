//! Claude-Code agent provisioning.
//!
//! Three entry points:
//! - [`init`] — provision the current repo: inject the mandates block into
//!   `CLAUDE.md` and `AGENTS.md` (the convention file non-Claude agents read),
//!   install the recall/remember hooks, deregister any stale project-scope MCP
//!   entry, and ignore the per-machine hook cache.
//! - [`install`] — provision user-global config (`~/.claude/CLAUDE.md` +
//!   `~/.claude.json`), so the server is available across the user's projects.
//! - [`provision_on_serve`] — called on every server boot. In a provisioned
//!   repo it refreshes the existing instruction blocks (`CLAUDE.md` when
//!   Claude Code is the active agent, `AGENTS.md` for any client) and repairs
//!   BROKEN hook pairs additively (per-pair consent — see
//!   [`repair_drifted_hooks`]); in an un-provisioned repo it either nudges
//!   (the default — zero writes) or, under the `auto_init` standing opt-in,
//!   runs the same provisioning `init` does behind a conservative preflight.
//!   Never touches MCP registration or global config (explicit intent), and
//!   never treats `$HOME` as the launch repo (the dotfiles-repo bound in
//!   [`provision_repo_on_serve`]).
//!
//! All provisioning is idempotent and follows the binary's `anyhow`-with-context
//! error style (see `doctor.rs`/`admin.rs`); the filesystem/JSON primitives live
//! in the `instructions`, `hooks`, and `mcp` submodules.

// Atomic, symlink-safe file replacement shared by the write sites below. Every
// config write in this module goes through it so a planted symlink cannot
// redirect an `init`/self-heal write (CWE-59/CWE-377). `pub(crate)`: `upgrade`
// reuses `atomic::atomic_write_private` to rewrite a trial config to
// `storage = "s3"` — the fsync-before-rename durability this module already
// provides matters there too, since `team_key_hex` in that file is the ONLY
// persisted copy of the team's encryption key.
pub(crate) mod atomic;
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

/// Boot-time provisioning policy, resolved from [`crate::config::Config`] by
/// `main.rs` and threaded into [`provision_on_serve`].
///
/// A struct (not a bare bool) so the call site names the decision it is
/// passing, and so a future boot-provisioning knob extends this rather than
/// growing a positional argument list.
#[derive(Debug, Clone)]
pub(crate) struct ServeProvisionPolicy {
    /// Provision an un-provisioned launch repo automatically (the standing
    /// consent from `auto_init` in the config — see that field's doc for the
    /// consent model).
    pub(crate) auto_init: bool,
    /// The config file the server actually LOADED (`Config::source_path`), if
    /// one was read. The nudge and boot warn name it as the place to set
    /// `auto_init = true` — see [`auto_init_remedy`] for why a generic
    /// "hippius-mem.toml" would send the user to a file the server never
    /// reads.
    pub(crate) config_source: Option<PathBuf>,
}

/// What [`provision_on_serve`] concluded about the launch repo, so `main.rs`
/// can put an HONEST provisioning note into the MCP handshake (see
/// [`provisioning_nudge_text`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServeProvisionOutcome {
    /// Nothing to tell the agent: the cwd is not in a git repo (nothing to
    /// provision), the resolved repo root is `$HOME` (out of provisioning's
    /// bounds), the repo is already provisioned (possibly just refreshed or
    /// repaired), or auto-init provisioned it this boot.
    Quiet,
    /// The launch repo is a git repo with no hippius-mem mandates block and
    /// nothing was written this boot: the handshake instructions should nudge
    /// toward `hippius-mem init` / `auto_init`.
    Unprovisioned,
    /// `auto_init` consent was in force but the preflight refused BEFORE the
    /// first write (a malformed `settings.json`, a WIP instruction file —
    /// see [`auto_init_preflight`]); nothing on disk changed. The handshake
    /// must state this reason, not the generic "not provisioned" line: the
    /// user already opted in, and the remedy is fixing the named file.
    AutoInitRefused {
        /// Human-readable refusal, naming the offending file.
        reason: String,
    },
    /// `auto_init` provisioning started and FAILED partway; the repo may hold
    /// partial artifacts. The handshake must state this rather than claim "no
    /// mandates block" — after a failed attempt, blocks may well exist.
    AutoInitFailed {
        /// Human-readable failure from the provisioning step.
        reason: String,
    },
}

/// Heal or provision the launch repo on a server boot, best-effort.
///
/// The renamed and extended successor of the old instruction-only self-heal.
/// A no-op unless the cwd is inside a git repo whose root is NOT `$HOME` (see
/// the bound in [`provision_repo_on_serve`]). Three regimes, split by whether
/// a hippius-mem mandates block already exists:
///
/// - **Provisioned repo** — refresh the existing instruction blocks
///   (`CLAUDE.md` only when Claude Code is the active agent; `AGENTS.md` for
///   ANY client, because its readers set no identifying env var), and repair
///   BROKEN hook pairs additively (Claude Code sessions only) — see
///   [`repair_drifted_hooks`] for the per-pair consent rule.
/// - **Un-provisioned repo, `auto_init` on** — run the same provisioning
///   `init` performs, gated on Claude Code being the active agent and on the
///   conservative [`auto_init_preflight`]; a refusal or failure is reported
///   with its reason so the handshake tells the truth.
/// - **Un-provisioned repo otherwise** — write nothing; log a warning and
///   report [`ServeProvisionOutcome::Unprovisioned`] so the handshake carries
///   the nudge. This closes the "enforcement silently doesn't exist" gap: a
///   repo nobody ran `init` in previously gave no signal at all.
///
/// Every failure is logged, never propagated: keeping memory serving always
/// outranks provisioning.
pub(crate) fn provision_on_serve(policy: &ServeProvisionPolicy) -> ServeProvisionOutcome {
    let Some(repo) = current_repo_root() else {
        tracing::debug!("provision: cwd is not inside a git repo; skipping");
        return ServeProvisionOutcome::Quiet;
    };
    provision_repo_on_serve(
        &repo,
        policy,
        claude_code_active(|key| std::env::var(key).ok()),
        home_dir().as_deref(),
    )
}

/// [`provision_on_serve`]'s repo-level core, with the repo root, the Claude
/// Code detection, and `$HOME` injected so tests drive it against a temp dir
/// without touching the process env or cwd.
fn provision_repo_on_serve(
    repo: &Path,
    policy: &ServeProvisionPolicy,
    claude_active: bool,
    home: Option<&Path>,
) -> ServeProvisionOutcome {
    // The $HOME bound. `git rev-parse --show-toplevel` WALKS UP from the cwd,
    // so a dotfiles-style $HOME repo (a real `$HOME/.git`) makes any non-git
    // launch directory under it resolve to $HOME itself. Provisioning there
    // would write `~/.claude/settings.json` — Claude Code's USER scope — and
    // `~/.claude/hooks/`, so the per-repo `auto_init` consent would silently
    // escalate into machine-wide hook wiring that then dangles in every
    // project; even the nudge would misname $HOME as an un-provisioned
    // "repo". Boot therefore never treats $HOME as the launch repo: no nudge,
    // no writes, auto_init or not. An explicit `hippius-mem init` run in
    // $HOME (the user present and asking) is deliberately still allowed —
    // this bound covers only the unattended serve path.
    if let Some(home) = home
        && same_directory(repo, home)
    {
        tracing::debug!(
            repo = %repo.display(),
            "provision: launch repo resolves to $HOME (a dotfiles repo?); skipping entirely"
        );
        return ServeProvisionOutcome::Quiet;
    }
    if repo_has_mandates_block(repo) {
        refresh_provisioned_repo(repo, claude_active);
        return ServeProvisionOutcome::Quiet;
    }
    // Auto-init is gated on Claude Code because most of what it writes — the
    // hook scripts and `.claude/settings.json` — is Claude Code wiring another
    // agent's session cannot run; a Cursor/Codex boot must not dirty the repo
    // with it. The NUDGE below is deliberately not gated: any client can act on
    // it by running `init`, which writes AGENTS.md for non-Claude agents too.
    if policy.auto_init && claude_active {
        match auto_init_repo(repo) {
            AutoInitAttempt::Provisioned => return ServeProvisionOutcome::Quiet,
            AutoInitAttempt::Refused(reason) => {
                tracing::warn!(
                    repo = %repo.display(),
                    %reason,
                    "auto_init: provisioning refused; fix the named file or run `hippius-mem init` explicitly"
                );
                return ServeProvisionOutcome::AutoInitRefused { reason };
            }
            AutoInitAttempt::Failed(reason) => {
                tracing::warn!(
                    repo = %repo.display(),
                    %reason,
                    "auto_init: provisioning failed; fix the cause or run `hippius-mem init` explicitly"
                );
                return ServeProvisionOutcome::AutoInitFailed { reason };
            }
        }
    }
    let remedy = auto_init_remedy(policy.config_source.as_deref());
    tracing::warn!(
        repo = %repo.display(),
        "this repo is not provisioned for team-memory enforcement — run `hippius-mem init` \
         here, or {remedy} to provision repos automatically at session start"
    );
    ServeProvisionOutcome::Unprovisioned
}

/// Whether `a` and `b` name the same directory, resolving symlinks when
/// possible (macOS reports `$HOME` under `/Users/...` while a repo root may
/// canonicalize through `/private/...`) and falling back to a raw comparison
/// when either side cannot be canonicalized. Used only for the `$HOME` bound
/// above, where a false negative (paths differ) errs toward the old behavior
/// and a false positive is impossible for distinct existing directories.
fn same_directory(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        (Ok(_) | Err(_), _) => a == b,
    }
}

/// The `auto_init` half of the un-provisioned remedy line, naming a location
/// that actually WORKS: the config file this server LOADED. The standard MCP
/// registration pins `HIPPIUS_MEM_CONFIG` to the user-global XDG config, so
/// the server never reads a repo-local `hippius-mem.toml` — a remedy naming
/// that file sent users to edit something the running server ignores (and a
/// partial cwd-local toml even shadows the global for bare-CLI runs). When no
/// config file was loaded at all (env-only boots), name the env var and its
/// standard location instead of guessing at a path.
pub(crate) fn auto_init_remedy(config_source: Option<&Path>) -> String {
    match config_source {
        Some(path) => format!("set `auto_init = true` in {}", path.display()),
        None => "set `auto_init = true` in the config file named by `HIPPIUS_MEM_CONFIG` \
                 (default: `~/.config/hippius-mem/hippius-mem.toml`), or export \
                 `HIPPIUS_MEM_AUTO_INIT=1`"
            .to_owned(),
    }
}

/// The handshake provisioning note for a boot outcome, or `None` when there
/// is nothing to say. Pre-rendered here — not in `server.rs`, which only
/// carries the finished string — so the text states the TRUTH of what boot
/// did: a refused or failed auto-init names its reason instead of the generic
/// "no mandates block" line, which after a failed (partial) attempt could be
/// outright false.
pub(crate) fn provisioning_nudge_text(
    outcome: &ServeProvisionOutcome,
    config_source: Option<&Path>,
) -> Option<String> {
    match outcome {
        ServeProvisionOutcome::Quiet => None,
        ServeProvisionOutcome::Unprovisioned => Some(format!(
            "NOTE: this repo is not provisioned for team-memory enforcement (no \
             hippius-mem mandates block in CLAUDE.md or AGENTS.md), so nothing holds \
             an agent to the recall/remember loop here. Run `hippius-mem init` in the \
             repo root, or {} to provision repos automatically at session start.",
            auto_init_remedy(config_source)
        )),
        ServeProvisionOutcome::AutoInitRefused { reason } => Some(format!(
            "NOTE: `auto_init` is enabled but boot provisioning was refused: {reason} — \
             fix that, or run `hippius-mem init` in the repo root."
        )),
        ServeProvisionOutcome::AutoInitFailed { reason } => Some(format!(
            "NOTE: `auto_init` is enabled but boot provisioning failed: {reason} — \
             fix that, or run `hippius-mem init` in the repo root."
        )),
    }
}

/// Whether `repo` carries a hippius-mem mandates block in either instruction
/// file — the provisioned/un-provisioned split [`provision_repo_on_serve`]
/// keys on.
///
/// Either file counts as provisioned: `init` writes both, but a user may have
/// legitimately deleted one, and "half-provisioned" must read as an existing
/// choice to refresh — not as an un-provisioned repo whose whole wiring
/// `auto_init` may recreate unasked.
fn repo_has_mandates_block(repo: &Path) -> bool {
    ["CLAUDE.md", "AGENTS.md"].into_iter().any(|name| {
        std::fs::read_to_string(repo.join(name))
            .is_ok_and(|content| content.contains(instructions::SECTION_START))
    })
}

/// The provisioned-repo half of boot self-heal: refresh the existing
/// instruction blocks and repair drifted hook wiring. Infallible — every
/// failure is logged where it occurs.
fn refresh_provisioned_repo(repo: &Path, claude_active: bool) {
    if claude_active {
        refresh_existing_block(
            repo,
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
        repo,
        "AGENTS.md",
        "# AGENTS.md",
        &instructions::team_memory_section_agents(),
    );
    repair_drifted_hooks(repo, claude_active);

    // NOTE: `.mcp.json` is deliberately NOT refreshed here. This runs inside the
    // server boot, so it cannot repair the case it would exist for — a stale
    // `.mcp.json` command means Claude Code never spawns the server, so this code
    // never runs; and when the server DOES boot, `current_exe()` equals the path
    // that spawned it, making any rewrite a no-op. The durable recovery is the
    // user-global `~/.claude.json` entry, refreshed by `install` (which the
    // installer's `--update` re-runs); `init` does not manage `.mcp.json` at all —
    // it deregisters any stale project entry so the global registration wins.
}

/// Repair BROKEN hook pairs — a registered hook whose script vanished, or an
/// installed script whose `settings.json` registration is gone — additively,
/// plus a drifted Grok path shim.
///
/// The PAIR is the consent line (see [`hooks::PairState`]): one present half
/// is the user's standing evidence they want THAT hook, so only its missing
/// half is restored; a pair with BOTH halves absent was removed deliberately
/// and stays removed even while a sibling pair is repaired; and an existing
/// script's CONTENT is never rewritten — a patched script with its
/// registration intact is a healthy pair, and a patched script whose
/// registration vanished gets only the registration back. (The old
/// all-or-nothing repair reran `init`'s full hook install on any drift,
/// clobbering patched scripts and resurrecting removed hooks.)
///
/// Gated on Claude Code exactly like auto-init: everything written here —
/// `.claude/hooks/` scripts and `.claude/settings.json` — is Claude Code
/// wiring another agent's session cannot run. The AGENTS.md block refresh in
/// [`refresh_provisioned_repo`] stays client-agnostic.
///
/// A `settings.json` that fails to parse skips ALL of it with one actionable
/// warn: registration state is unknowable, so any "repair" would be guesses
/// written over a file the user needs to fix first. The warn repeats each
/// boot on purpose (an honest signal) but has zero writes behind it.
///
/// Best-effort: each step is attempted independently and every failure is
/// logged, never propagated — serving memory outranks provisioning.
fn repair_drifted_hooks(repo: &Path, claude_active: bool) {
    if !claude_active {
        tracing::debug!(
            "self-heal: not a Claude Code session; leaving Claude-only hook wiring alone"
        );
        return;
    }
    let status = hooks::probe_hook_wiring(repo);
    if let Some(error) = status.settings_error() {
        tracing::warn!(
            error,
            "self-heal: cannot repair hook wiring while settings.json does not load; \
             fix (or remove) that file and the next boot will repair"
        );
        return;
    }
    if !status.needs_repair() {
        return;
    }
    tracing::info!(repo = %repo.display(), "self-heal: hook wiring drifted; repairing broken pairs");
    match hooks::repair_missing_scripts(repo, &status) {
        Ok(0) => {}
        Ok(count) => tracing::info!(count, "self-heal: reinstalled missing hook scripts"),
        Err(e) => tracing::warn!(error = %e, "self-heal: reinstalling missing hook scripts failed"),
    }
    match hooks::repair_missing_registrations(repo, &status) {
        Ok(0) => {}
        Ok(count) => tracing::info!(count, "self-heal: restored missing hook registrations"),
        Err(e) => tracing::warn!(error = %e, "self-heal: restoring hook registrations failed"),
    }
    if status.shim_drifted()
        && let Err(e) = hooks::install_grok_hook_path_shim(repo)
    {
        tracing::warn!(error = %e, "self-heal: repairing the Grok hook path shim failed");
    }
}

/// What one boot `auto_init` attempt did, threaded into
/// [`ServeProvisionOutcome`] so the handshake states the post-attempt truth.
enum AutoInitAttempt {
    /// The repo is now provisioned.
    Provisioned,
    /// The preflight refused BEFORE the first write; nothing on disk changed.
    Refused(String),
    /// Provisioning started and failed; partial artifacts may exist.
    Failed(String),
}

/// Preflight every file the unattended auto-init would touch, BEFORE the
/// first write. `Err` carries the human-readable refusal reason (it ends up
/// in the boot warn and the handshake note, so it names the offending file).
///
/// Two rules:
///
/// - **`.claude/settings.json` must be absent or loadable.** The hook merge
///   parses it; without this check a malformed file failed provisioning
///   MIDWAY, after the instruction blocks were already written — a
///   half-provisioned repo behind a warning nobody asked for.
/// - **Every text file the provisioning splices into (`CLAUDE.md`,
///   `AGENTS.md`, `.gitignore`) must be ABSENT or TRACKED-AND-CLEAN.** An
///   existing untracked file is someone's WIP draft; a dirty tracked file is
///   someone's open diff; writing into either at boot entangles work the user
///   never offered. Deliberately MORE conservative than explicit `init`
///   (which writes through both, the user present and asking): nobody is
///   watching an unattended boot, so only provably safe states proceed —
///   and the git probes fail-safe toward refusing, not acting.
fn auto_init_preflight(repo: &Path) -> Result<(), String> {
    if let Some(error) = hooks::settings_json_error(repo) {
        return Err(error);
    }
    for name in ["CLAUDE.md", "AGENTS.md", ".gitignore"] {
        let exists = repo.join(name).exists();
        if exists && !instructions::is_git_tracked_and_clean(repo, name) {
            return Err(format!(
                "{name} exists but is not git-tracked-and-clean (an untracked draft \
                 or uncommitted edits)"
            ));
        }
    }
    Ok(())
}

/// Attempt the `auto_init` boot provisioning of `repo`. Infallible — refusals
/// and failures are reported in the returned [`AutoInitAttempt`] (and logged
/// by the caller), never propagated.
///
/// Reuses [`configure_repo`]'s non-uninstall path verbatim (blocks, hooks,
/// gitignore — one provisioning implementation), with two boot-specific
/// differences from the `init` subcommand:
///
/// - **Conservative preflight.** See [`auto_init_preflight`]: nothing is
///   written unless every file it would touch is absent or tracked-and-clean
///   and `settings.json` is loadable. An explicit `init` — the user present
///   and asking — remains the way to provision through a WIP tree.
/// - **No global MCP registration.** `init` also ensures `~/.claude.json`
///   because a standalone `init` would otherwise register the server nowhere;
///   here the server is ALREADY running under whatever registration launched
///   it, so touching `$HOME` state would be a write with nothing to fix.
fn auto_init_repo(repo: &Path) -> AutoInitAttempt {
    if let Err(reason) = auto_init_preflight(repo) {
        return AutoInitAttempt::Refused(reason);
    }
    // `SetupFlags::default()`: hooks on, `allow_overwrite_tracked` OFF — the
    // tracked-clean guard inside `write_md_section` stays armed exactly as it
    // is for a plain `init`.
    match configure_repo(repo, SetupFlags::default()) {
        Ok(()) => {
            tracing::info!(
                repo = %repo.display(),
                "auto_init: provisioned this repo (mandates blocks, hooks, gitignore)"
            );
            AutoInitAttempt::Provisioned
        }
        // `{e:#}` keeps anyhow's context chain so the handshake reason names
        // the failing file/step, not just the leaf io error.
        Err(e) => AutoInitAttempt::Failed(format!("{e:#}")),
    }
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
    if flags.uninstall {
        // The inverse of the install path below: drop our `~/.claude/CLAUDE.md`
        // block and MCP registration. `remove_md_section` no-ops on a missing file,
        // and `deregister_mcp_global` never deletes `~/.claude.json` (Claude Code's
        // own state). Mirrors `configure_repo`'s uninstall branch. Without this,
        // `install --uninstall` silently RE-installed (the flag was accepted but
        // never acted on).
        instructions::remove_md_section(&claude_dir, "CLAUDE.md")?;
        return mcp::deregister_mcp_global(home);
    }
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
/// Strips the hippius-mem marker block (machine-generated, not seedable
/// knowledge) and reports whether any non-whitespace remains. A missing or
/// unreadable file reads as "no content".
fn instruction_md_has_user_content(md: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(md) else {
        return false;
    };
    let stripped = strip_marked_block(
        &content,
        instructions::SECTION_START,
        instructions::SECTION_END,
    );
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
        ServeProvisionOutcome, ServeProvisionPolicy, SetupFlags, claude_code_active,
        claude_project_slug, configure_global, configure_repo, detect_seed_sources,
        instruction_md_has_user_content, personal_memory_index, provision_repo_on_serve,
        provisioning_nudge_text, strip_marked_block, write_seed_pending,
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
            agents.contains("Hook enforcement varies by client"),
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
        #[cfg(unix)]
        assert!(
            !tmp.path().join(".claude/.claude/hooks").exists(),
            "Grok path shim not removed"
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
            !claude.contains("Hook enforcement varies by client"),
            "CLAUDE.md carries the plain variant: {claude}"
        );
        assert!(
            agents.contains("Hook enforcement varies by client"),
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
            after_first.contains("Hook enforcement varies by client"),
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
    fn configure_global_uninstall_removes_block_and_mcp_but_keeps_claude_json() {
        let home = TempDir::new().expect("tempdir");
        // Seed ~/.claude.json with an unrelated key so we can prove uninstall never
        // clobbers Claude Code's own state — only our one mcpServers entry.
        std::fs::write(
            home.path().join(".claude.json"),
            r#"{"projects":{"keep":1},"mcpServers":{"other":{"command":"x"}}}"#,
        )
        .expect("seed ~/.claude.json");

        configure_global(home.path(), SetupFlags::default()).expect("install");
        let claude_json = home.path().join(".claude.json");
        let after_install: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&claude_json).expect("read"))
                .expect("json");
        assert!(
            after_install["mcpServers"]["hippius-mem"].is_object(),
            "install registers our MCP entry"
        );

        // Uninstall must REVERSE it, not re-install (the documented no-op bug).
        configure_global(
            home.path(),
            SetupFlags {
                uninstall: true,
                ..SetupFlags::default()
            },
        )
        .expect("uninstall");

        let global_md =
            std::fs::read_to_string(home.path().join(".claude/CLAUDE.md")).unwrap_or_default();
        assert!(
            !global_md.contains("<!-- hippius-mem:start -->"),
            "uninstall must remove the CLAUDE.md block, got: {global_md:?}"
        );
        let after_uninstall: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&claude_json).expect("read"))
                .expect("json");
        assert!(
            after_uninstall["mcpServers"]["hippius-mem"].is_null(),
            "uninstall must remove our MCP entry"
        );
        // ~/.claude.json is Claude Code's own state — never deleted, other keys kept.
        assert_eq!(
            after_uninstall["projects"]["keep"], 1,
            "uninstall must preserve unrelated ~/.claude.json content"
        );
        assert!(
            after_uninstall["mcpServers"]["other"].is_object(),
            "uninstall must leave other MCP servers registered"
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
        // a fresh file, plus only the generated block -> no seedable content. The
        // heading must NOT be mistaken for user content (the false-positive bug).
        let generated = format!("# CLAUDE.md\n\n{SECTION_START}\nmandates\n{SECTION_END}\n");
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

    // ---- boot-time provisioning (`provision_on_serve`'s repo-level core) ----

    /// Convenience: the policy shapes the boot-provisioning tests exercise.
    fn auto_init_policy(auto_init: bool) -> ServeProvisionPolicy {
        ServeProvisionPolicy {
            auto_init,
            config_source: None,
        }
    }

    /// Convenience: drive the serve core with no `$HOME` bound in play.
    fn serve_on(repo: &Path, auto_init: bool, claude_active: bool) -> ServeProvisionOutcome {
        provision_repo_on_serve(repo, &auto_init_policy(auto_init), claude_active, None)
    }

    /// The refusal reason, or `None` for any other outcome — variant
    /// assertions go through this so tests need no `panic!` under the
    /// deny-wall.
    fn refused_reason(outcome: &ServeProvisionOutcome) -> Option<&str> {
        match outcome {
            ServeProvisionOutcome::AutoInitRefused { reason } => Some(reason),
            ServeProvisionOutcome::Quiet
            | ServeProvisionOutcome::Unprovisioned
            | ServeProvisionOutcome::AutoInitFailed { .. } => None,
        }
    }

    #[test]
    fn unprovisioned_repo_nudges_and_writes_nothing_by_default() {
        let tmp = TempDir::new().expect("tempdir");
        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(
            outcome,
            ServeProvisionOutcome::Unprovisioned,
            "an un-provisioned repo must surface the nudge"
        );
        // Zero writes without the standing opt-in: no instruction files, no hook
        // wiring, no gitignore — the default is a visible nudge, nothing more.
        for artifact in ["CLAUDE.md", "AGENTS.md", ".claude", ".gitignore"] {
            assert!(
                !tmp.path().join(artifact).exists(),
                "default policy must not create {artifact}"
            );
        }
    }

    #[test]
    fn auto_init_provisions_an_unprovisioned_repo_like_init() {
        let tmp = TempDir::new().expect("tempdir");
        let outcome = serve_on(tmp.path(), true, true);
        assert_eq!(
            outcome,
            ServeProvisionOutcome::Quiet,
            "a just-provisioned repo needs no nudge"
        );
        // Full `init` parity: blocks, hooks, gitignore.
        assert!(
            claude_md(tmp.path()).contains(SECTION_START),
            "auto-init must write the CLAUDE.md block"
        );
        assert!(
            agents_md(tmp.path()).contains("Hook enforcement varies by client"),
            "auto-init must write the AGENTS.md honor-system variant"
        );
        assert!(
            tmp.path()
                .join(".claude/hooks/hippius-mem-recall-preflight.sh")
                .exists(),
            "auto-init must install the hook scripts"
        );
        assert!(
            tmp.path().join(".claude/settings.json").exists(),
            "auto-init must register the hooks"
        );
        let gitignore = std::fs::read_to_string(tmp.path().join(".gitignore")).expect("gitignore");
        assert!(
            gitignore.contains(".hippius-mem/"),
            "auto-init must write the gitignore entries: {gitignore}"
        );
    }

    #[test]
    fn auto_init_is_gated_on_claude_code() {
        // The hooks and `.claude/settings.json` are Claude Code artifacts: a
        // Cursor/Codex session must not dirty a repo with wiring it cannot run.
        // The nudge still fires — any client can act on it by running `init`.
        let tmp = TempDir::new().expect("tempdir");
        let outcome = serve_on(tmp.path(), true, false);
        assert_eq!(outcome, ServeProvisionOutcome::Unprovisioned);
        for artifact in ["CLAUDE.md", "AGENTS.md", ".claude", ".gitignore"] {
            assert!(
                !tmp.path().join(artifact).exists(),
                "a non-Claude client must not trigger auto-init writes ({artifact})"
            );
        }
    }

    #[test]
    fn auto_init_refuses_a_dirty_tracked_instruction_file() {
        // A tracked file with UNCOMMITTED edits is someone's work in progress;
        // splicing generated content into it at boot would entangle their diff.
        // Auto-init refuses the whole provisioning, reporting the reason so the
        // handshake can state it — an explicit `hippius-mem init` (the user
        // present and asking) remains the way to provision through the dirt.
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
        std::fs::write(dir.join("CLAUDE.md"), "# CLAUDE.md\n\nteam prose\n").expect("seed");
        git(&["add", "CLAUDE.md"]);
        git(&["commit", "-q", "-m", "seed"]);
        let dirty = "# CLAUDE.md\n\nteam prose\n\nwork in progress\n";
        std::fs::write(dir.join("CLAUDE.md"), dirty).expect("dirty it");

        let outcome = serve_on(dir, true, true);
        let reason = refused_reason(&outcome).expect("a refused auto-init must carry its reason");
        assert!(
            reason.contains("CLAUDE.md"),
            "the refusal must name the offending file: {reason}"
        );
        assert_eq!(
            claude_md(dir),
            dirty,
            "the dirty tracked CLAUDE.md must be left byte-identical"
        );
        for artifact in ["AGENTS.md", ".claude"] {
            assert!(
                !dir.join(artifact).exists(),
                "a refused auto-init must write nothing at all ({artifact})"
            );
        }
    }

    #[test]
    fn provisioned_repo_without_hook_traces_stays_untouched() {
        // `init --no-hooks` is a legitimate standing choice: blocks, no hooks.
        // Boot self-heal must never force hooks onto that repo — only repair
        // wiring for which install evidence exists.
        let tmp = TempDir::new().expect("tempdir");
        let flags = SetupFlags {
            no_hooks: true,
            ..SetupFlags::default()
        };
        configure_repo(tmp.path(), flags).expect("provision without hooks");

        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        assert!(
            !tmp.path().join(".claude").exists(),
            "self-heal must respect a --no-hooks provisioning (no hook writes)"
        );
    }

    #[test]
    fn drifted_missing_script_is_repaired_when_registration_remains() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("full provision");
        let script = tmp
            .path()
            .join(".claude/hooks/hippius-mem-recall-preflight.sh");
        std::fs::remove_file(&script).expect("drop one script");

        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        assert!(
            script.exists(),
            "a registered hook whose script vanished must be reinstalled"
        );
    }

    #[test]
    fn drifted_missing_registration_is_repaired_when_scripts_remain() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("full provision");
        std::fs::remove_file(tmp.path().join(".claude/settings.json")).expect("drop settings");

        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        let settings = std::fs::read_to_string(tmp.path().join(".claude/settings.json"))
            .expect("settings.json must be restored");
        assert!(
            settings.contains("hippius-mem-recall-preflight.sh"),
            "the hook registration must be re-merged: {settings}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn drifted_missing_grok_shim_is_repaired() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("full provision");
        let shim = tmp.path().join(".claude/.claude/hooks");
        std::fs::remove_file(&shim).expect("drop shim");

        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        assert_eq!(
            std::fs::read_link(&shim).expect("shim symlink must be restored"),
            Path::new("../hooks"),
            "the Grok path shim must be re-planted"
        );
    }

    // ---- per-pair repair (F1/F7): repair fixes broken pairs additively ----

    /// Test helper: parse `.claude/settings.json`.
    fn settings_json(dir: &Path) -> serde_json::Value {
        let raw = std::fs::read_to_string(dir.join(".claude/settings.json"))
            .expect("settings.json must exist");
        serde_json::from_str(&raw).expect("settings.json must be valid JSON")
    }

    /// Test helper: count registrations across every event whose command string
    /// CONTAINS `needle` (matching the pair-presence rule under test).
    fn registrations_containing(settings: &serde_json::Value, needle: &str) -> usize {
        settings["hooks"]
            .as_object()
            .into_iter()
            .flat_map(serde_json::Map::values)
            .filter_map(serde_json::Value::as_array)
            .flatten()
            .filter_map(|g| g.get("hooks").and_then(serde_json::Value::as_array))
            .flatten()
            .filter(|e| {
                e.get("command")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|c| c.contains(needle))
            })
            .count()
    }

    /// Test helper: rewrite `.claude/settings.json` through `edit`.
    fn edit_settings(dir: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
        let mut settings = settings_json(dir);
        edit(&mut settings);
        std::fs::write(
            dir.join(".claude/settings.json"),
            serde_json::to_string_pretty(&settings).expect("serialize"),
        )
        .expect("write settings");
    }

    /// Test helper: drop every registration whose command equals `command_path`
    /// (the shape a user editing their settings.json by hand leaves behind).
    fn remove_registration(dir: &Path, command_path: &str) {
        edit_settings(dir, |settings| {
            let Some(events) = settings["hooks"].as_object_mut() else {
                return;
            };
            for event in events.values_mut() {
                let Some(groups) = event.as_array_mut() else {
                    continue;
                };
                for group in groups.iter_mut() {
                    if let Some(inner) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                        inner.retain(|e| {
                            e.get("command").and_then(serde_json::Value::as_str)
                                != Some(command_path)
                        });
                    }
                }
            }
        });
    }

    const PREFLIGHT: &str = ".claude/hooks/hippius-mem-recall-preflight.sh";
    const TOKEN: &str = ".claude/hooks/hippius-mem-recall-token.sh";

    /// Pins F1: repair is per-pair and additive-only. A user's PATCHED script
    /// whose registration is intact is a HEALTHY pair — repair must never
    /// rewrite its content, even while repairing a genuinely broken sibling
    /// pair (registration present, script file gone) by installing ONLY that
    /// missing script.
    #[test]
    fn repair_reinstalls_missing_script_without_rewriting_a_patched_sibling() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("full provision");
        // The user patched the token hook (registration intact) — a healthy pair.
        let patched = "#!/bin/sh\n# user patch that must survive boot repair\nexit 0\n";
        std::fs::write(tmp.path().join(TOKEN), patched).expect("patch script");
        // The preflight pair broke: its script vanished, registration remains.
        std::fs::remove_file(tmp.path().join(PREFLIGHT)).expect("drop script");

        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        assert!(
            tmp.path().join(PREFLIGHT).exists(),
            "the broken pair's missing script must be reinstalled"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(TOKEN)).expect("read token"),
            patched,
            "a patched script with an intact registration is a healthy pair; \
             repair must never overwrite its content"
        );
    }

    /// Pins F1: a pair whose BOTH halves are absent is a respected user choice
    /// (they deliberately removed that hook) — repair must leave it removed
    /// even while it repairs a different, genuinely broken pair.
    #[test]
    fn deliberately_removed_pair_stays_removed_while_a_broken_pair_is_repaired() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("full provision");
        // Pair fully removed by the user: script AND registration gone.
        std::fs::remove_file(tmp.path().join(TOKEN)).expect("drop script");
        remove_registration(tmp.path(), TOKEN);
        // A different pair broken: script gone, registration remains.
        std::fs::remove_file(tmp.path().join(PREFLIGHT)).expect("drop script");

        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        assert!(
            tmp.path().join(PREFLIGHT).exists(),
            "the broken pair must be repaired"
        );
        assert!(
            !tmp.path().join(TOKEN).exists(),
            "a fully-removed pair's script must stay removed"
        );
        assert_eq!(
            registrations_containing(&settings_json(tmp.path()), TOKEN),
            0,
            "a fully-removed pair's registration must not be re-added"
        );
    }

    /// Pins F7: a registration the user CUSTOMIZED — wrapped in an env prefix,
    /// or an absolute path — still references our script, so the pair counts
    /// as registered and repair must not append the canonical entry alongside
    /// (which would run the hook twice).
    #[test]
    fn wrapped_registration_counts_as_present_and_gets_no_duplicate() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("full provision");
        let wrapped = format!("HIPPIUS_MEM_RECALL_WINDOW_SECS=600 {PREFLIGHT}");
        edit_settings(tmp.path(), |settings| {
            let groups = settings["hooks"]["PreToolUse"]
                .as_array_mut()
                .expect("PreToolUse groups");
            for group in groups.iter_mut() {
                if let Some(inner) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                    for entry in inner.iter_mut() {
                        if entry.get("command").and_then(serde_json::Value::as_str)
                            == Some(PREFLIGHT)
                        {
                            entry["command"] = serde_json::json!(wrapped.clone());
                        }
                    }
                }
            }
        });

        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        let settings = settings_json(tmp.path());
        assert_eq!(
            registrations_containing(&settings, PREFLIGHT),
            1,
            "a wrapped registration counts as present; the canonical entry must \
             not be appended alongside it (the hook would run twice): {settings}"
        );
    }

    /// Pins F4c: a settings.json that does not PARSE makes repair skip
    /// entirely — one warn, zero writes. In particular the healthy pairs'
    /// scripts must not be rewritten (no churn behind a warn).
    #[test]
    fn malformed_settings_json_skips_repair_with_zero_writes() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("full provision");
        let patched = "#!/bin/sh\n# user patch\nexit 0\n";
        std::fs::write(tmp.path().join(TOKEN), patched).expect("patch script");
        std::fs::write(tmp.path().join(".claude/settings.json"), "{ not json").expect("break");

        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(TOKEN)).expect("read token"),
            patched,
            "repair must write nothing while settings.json is unparseable"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".claude/settings.json")).expect("read"),
            "{ not json",
            "the malformed settings.json itself must be left untouched"
        );
    }

    /// Pins F5: hook repair writes Claude Code artifacts, so — exactly like
    /// auto-init — it must not run for a non-Claude client. (The AGENTS.md
    /// block refresh stays client-agnostic; only the hook half is gated.)
    #[test]
    fn non_claude_client_gets_no_hook_repair_writes() {
        let tmp = TempDir::new().expect("tempdir");
        configure_repo(tmp.path(), SetupFlags::default()).expect("full provision");
        std::fs::remove_file(tmp.path().join(PREFLIGHT)).expect("drop script");

        let outcome = serve_on(tmp.path(), false, false);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        assert!(
            !tmp.path().join(PREFLIGHT).exists(),
            "a non-Claude client must not trigger hook repair writes"
        );
    }

    // ---- auto-init preflight (F4/F6): refuse before the first write ----

    /// Pins F4a: a malformed `.claude/settings.json` refuses auto-init BEFORE
    /// anything is written — no instruction blocks, no hooks, no gitignore,
    /// and the broken file itself untouched.
    #[test]
    fn auto_init_refuses_on_malformed_settings_json_with_zero_writes() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".claude")).expect("mkdir");
        std::fs::write(tmp.path().join(".claude/settings.json"), "{ not json").expect("seed");

        let outcome = serve_on(tmp.path(), true, true);
        let reason = refused_reason(&outcome).expect("a refused auto-init must carry its reason");
        assert!(
            reason.contains("settings.json"),
            "the refusal must name the unloadable file: {reason}"
        );
        for artifact in ["CLAUDE.md", "AGENTS.md", ".gitignore", ".claude/hooks"] {
            assert!(
                !tmp.path().join(artifact).exists(),
                "a refused auto-init must write nothing at all ({artifact})"
            );
        }
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(".claude/settings.json")).expect("read"),
            "{ not json",
            "the malformed settings.json must be left untouched"
        );
    }

    /// Test helper: a git repo in `dir` with a closure to run git commands.
    fn git_in(dir: &Path) -> impl Fn(&[&str]) + '_ {
        let git = move |args: &[&str]| {
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
        git
    }

    /// Pins F6: an EXISTING UNTRACKED instruction file (a WIP draft the user
    /// has not committed) refuses auto-init — only absent or tracked-and-clean
    /// files may be touched by the unattended path.
    #[test]
    fn auto_init_refuses_an_untracked_claude_md_with_content() {
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path();
        let _git = git_in(dir);
        let draft = "# CLAUDE.md\n\nwip draft nobody committed yet\n";
        std::fs::write(dir.join("CLAUDE.md"), draft).expect("seed draft");

        let outcome = serve_on(dir, true, true);
        let reason = refused_reason(&outcome).expect("an untracked draft must refuse auto-init");
        assert!(
            reason.contains("CLAUDE.md"),
            "the refusal must name the draft file: {reason}"
        );
        assert_eq!(
            claude_md(dir),
            draft,
            "an untracked WIP draft must be left byte-identical"
        );
        for artifact in ["AGENTS.md", ".claude", ".gitignore"] {
            assert!(
                !dir.join(artifact).exists(),
                "a refused auto-init must write nothing at all ({artifact})"
            );
        }
    }

    /// Pins F6 (the previously unpinned cell): a dirty tracked AGENTS.md
    /// refuses the WHOLE provisioning even when CLAUDE.md is tracked and
    /// clean — the preflight is all-or-nothing.
    #[test]
    fn auto_init_refuses_dirty_tracked_agents_md_even_when_claude_md_is_clean() {
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path();
        let git = git_in(dir);
        std::fs::write(dir.join("CLAUDE.md"), "# CLAUDE.md\n\nclean prose\n").expect("seed");
        std::fs::write(dir.join("AGENTS.md"), "# AGENTS.md\n\nagent prose\n").expect("seed");
        git(&["add", "CLAUDE.md", "AGENTS.md"]);
        git(&["commit", "-q", "-m", "seed"]);
        let dirty = "# AGENTS.md\n\nagent prose\n\nwork in progress\n";
        std::fs::write(dir.join("AGENTS.md"), dirty).expect("dirty it");

        let outcome = serve_on(dir, true, true);
        let reason = refused_reason(&outcome).expect("a dirty AGENTS.md must refuse auto-init");
        assert!(
            reason.contains("AGENTS.md"),
            "the refusal must name the dirty file: {reason}"
        );
        assert_eq!(
            agents_md(dir),
            dirty,
            "the dirty tracked AGENTS.md must be left byte-identical"
        );
        assert!(
            !claude_md(dir).contains(SECTION_START),
            "the clean CLAUDE.md must not be provisioned either (all-or-nothing)"
        );
    }

    /// Pins F6: a dirty tracked `.gitignore` refuses auto-init — the
    /// unattended path appends ignore lines to it, and splicing into a file
    /// with uncommitted edits entangles the user's diff.
    #[test]
    fn auto_init_refuses_a_dirty_tracked_gitignore() {
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path();
        let git = git_in(dir);
        std::fs::write(dir.join(".gitignore"), "target/\n").expect("seed");
        git(&["add", ".gitignore"]);
        git(&["commit", "-q", "-m", "seed"]);
        let dirty = "target/\n*.log\n";
        std::fs::write(dir.join(".gitignore"), dirty).expect("dirty it");

        let outcome = serve_on(dir, true, true);
        let reason = refused_reason(&outcome).expect("a dirty .gitignore must refuse auto-init");
        assert!(
            reason.contains(".gitignore"),
            "the refusal must name the dirty file: {reason}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join(".gitignore")).expect("read"),
            dirty,
            "the dirty tracked .gitignore must be left byte-identical"
        );
        assert!(
            !dir.join("CLAUDE.md").exists(),
            "a refused auto-init must write nothing at all"
        );
    }

    // ---- the $HOME bound (F2) and the honest nudge/remedy texts (F3/F4b) ----

    /// Pins F2: when the resolved repo root IS the user's home directory (a
    /// dotfiles `$HOME` repo picked up by `git rev-parse --show-toplevel`
    /// walking up from a non-git cwd), boot must skip entirely — no nudge, no
    /// writes — even with `auto_init` on. Provisioning $HOME would write
    /// Claude Code USER-scope config from per-repo consent.
    #[test]
    fn home_toplevel_is_never_provisioned_or_nudged_even_with_auto_init() {
        let tmp = TempDir::new().expect("tempdir");
        let outcome =
            provision_repo_on_serve(tmp.path(), &auto_init_policy(true), true, Some(tmp.path()));
        assert_eq!(
            outcome,
            ServeProvisionOutcome::Quiet,
            "$HOME as the launch repo must be skipped silently, not nudged"
        );
        for artifact in ["CLAUDE.md", "AGENTS.md", ".claude", ".gitignore"] {
            assert!(
                !tmp.path().join(artifact).exists(),
                "boot must never write into $HOME ({artifact})"
            );
        }
    }

    /// The $HOME comparison resolves symlinks, so a repo root reported through
    /// a symlinked prefix (macOS `/var` vs `/private/var`) still matches.
    #[cfg(unix)]
    #[test]
    fn home_bound_matches_through_a_symlinked_path() {
        let tmp = TempDir::new().expect("tempdir");
        let real = tmp.path().join("home");
        std::fs::create_dir(&real).expect("mkdir");
        let link = tmp.path().join("home-link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let outcome = provision_repo_on_serve(&link, &auto_init_policy(true), true, Some(&real));
        assert_eq!(
            outcome,
            ServeProvisionOutcome::Quiet,
            "a symlinked spelling of $HOME must still be recognized as $HOME"
        );
        assert!(
            !real.join("CLAUDE.md").exists(),
            "no writes through the link"
        );
    }

    /// Pins F3: the un-provisioned nudge names the config file the server
    /// actually LOADED — never a repo-local `hippius-mem.toml` the MCP server
    /// (whose registration pins `HIPPIUS_MEM_CONFIG`) would never read — and
    /// falls back to naming the env var when no file was loaded.
    #[test]
    fn unprovisioned_nudge_names_the_loaded_config_or_the_env_var() {
        let outcome = ServeProvisionOutcome::Unprovisioned;
        let with_path = provisioning_nudge_text(
            &outcome,
            Some(Path::new("/home/u/.config/hippius-mem/hippius-mem.toml")),
        )
        .expect("un-provisioned must nudge");
        assert!(
            with_path.contains("/home/u/.config/hippius-mem/hippius-mem.toml"),
            "the nudge must name the loaded config file: {with_path}"
        );
        assert!(
            with_path.contains("hippius-mem init") && with_path.contains("auto_init"),
            "the nudge must keep both remedies: {with_path}"
        );

        let without_path =
            provisioning_nudge_text(&outcome, None).expect("un-provisioned must nudge");
        assert!(
            without_path.contains("HIPPIUS_MEM_CONFIG"),
            "with no loaded file the nudge must name the env var: {without_path}"
        );
    }

    /// Pins F4b: a refused (or failed) auto-init handshake note states the
    /// reason and never falsely claims "no mandates block" — after a failed
    /// partial attempt, blocks may exist.
    #[test]
    fn refused_and_failed_auto_init_nudges_state_the_reason() {
        let refused = ServeProvisionOutcome::AutoInitRefused {
            reason: ".claude/settings.json is not valid JSON".to_owned(),
        };
        let text = provisioning_nudge_text(&refused, None).expect("a refusal must nudge");
        assert!(
            text.contains("refused") && text.contains(".claude/settings.json is not valid JSON"),
            "the refusal note must state the reason: {text}"
        );
        assert!(
            text.contains("hippius-mem init"),
            "the refusal note must keep the explicit remedy: {text}"
        );
        assert!(
            !text.contains("no hippius-mem mandates block"),
            "a refusal must not claim the generic un-provisioned state: {text}"
        );

        let failed = ServeProvisionOutcome::AutoInitFailed {
            reason: "creating .claude failed".to_owned(),
        };
        let text = provisioning_nudge_text(&failed, None).expect("a failure must nudge");
        assert!(
            text.contains("failed") && text.contains("creating .claude failed"),
            "the failure note must state the reason: {text}"
        );
        assert!(
            !text.contains("no hippius-mem mandates block"),
            "a failure must not claim blocks are absent — a partial attempt may \
             have written them: {text}"
        );

        assert_eq!(
            provisioning_nudge_text(&ServeProvisionOutcome::Quiet, None),
            None,
            "quiet boots carry no note"
        );
    }

    #[test]
    fn provisioned_repo_refreshes_stale_blocks_on_boot() {
        // The pre-existing self-heal behavior, preserved through the renamed
        // entry point: stale blocks are refreshed (non-git, so the tracked-clean
        // guard falls open), CLAUDE.md only under Claude Code.
        let tmp = TempDir::new().expect("tempdir");
        let stale = |heading: &str| format!("{heading}\n\n{SECTION_START}\nSTALE\n{SECTION_END}\n");
        std::fs::write(tmp.path().join("CLAUDE.md"), stale("# CLAUDE.md")).expect("seed");
        std::fs::write(tmp.path().join("AGENTS.md"), stale("# AGENTS.md")).expect("seed");

        let outcome = serve_on(tmp.path(), false, false);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        assert!(
            claude_md(tmp.path()).contains("STALE"),
            "CLAUDE.md refresh stays gated on Claude Code being the active agent"
        );
        assert!(
            !agents_md(tmp.path()).contains("STALE"),
            "AGENTS.md refreshes for ANY client"
        );

        let outcome = serve_on(tmp.path(), false, true);
        assert_eq!(outcome, ServeProvisionOutcome::Quiet);
        assert!(
            !claude_md(tmp.path()).contains("STALE"),
            "CLAUDE.md refreshes under Claude Code"
        );
    }

    fn claude_md(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("CLAUDE.md")).expect("CLAUDE.md must exist")
    }

    fn agents_md(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("AGENTS.md")).expect("AGENTS.md must exist")
    }
}
