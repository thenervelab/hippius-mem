//! The `quickstart` subcommand: a zero-decision solo trial vault.
//!
//! Refuses first if a storage-related `HIPPIUS_MEM_*` env var is set that
//! would collide with the config about to be written (see
//! [`refuse_conflicting_env_vars`]) — the wired MCP server loads via
//! `Config::from_env_and_file`, which overlays such env vars on top of the
//! file, and a conflict there would turn a valid local trial into a hard
//! error the instant the server actually starts. Then writes a fresh, flat,
//! single-profile `storage = "local"` config (no bucket, no S3 credentials —
//! [`hippius_mem_core::FsBlobStore`] lands notes on this machine's own disk)
//! whose `local_root` field PINS the resolved vault directory (see
//! [`resolve_default_trial_root`]) — so `upgrade`/`serve` always resolve to
//! this exact path later, regardless of what `XDG_DATA_HOME`/`HOME` are set
//! to when THEY run. Proves the encryption boundary holds against it via the
//! existing `doctor` probe, then — unless `--no-wire` — wires Claude Code
//! exactly the way `install`/`init` already do. `team_key_hex` and
//! `author_seed_hex` are both generated locally via the OS CSPRNG (the `join
//! --bundle` convention: a trial vault has no founder to mint the team key
//! elsewhere, so it is generated exactly like the signing seed). An existing
//! config is a refusal with guidance, never rewritten — the same join-bundle
//! conflict convention.
//!
//! Trial mode is solo-only: `invite`/`join` refuse on a `storage = "local"`
//! profile (a separate concern from this module). `hippius-mem upgrade`
//! flips a trial profile to `storage = "s3"` after copying its objects into
//! a real bucket.

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use zeroize::Zeroizing;

use crate::config::{Config, StorageBackend, TeamProfile};
use crate::join_bundle::{generate_seed_hex, resolve_target_path};

/// Default team/namespace name for a fresh trial: no decision required.
const DEFAULT_TEAM: &str = "trial";

/// Storage-related `HIPPIUS_MEM_*` env vars that would collide with the
/// `storage = "local"` config quickstart is about to write — see
/// [`refuse_conflicting_env_vars`].
const CONFLICTING_STORAGE_ENV_VARS: &[&str] = &[
    "HIPPIUS_MEM_STORAGE",
    "HIPPIUS_MEM_BUCKET",
    "HIPPIUS_MEM_ACCESS_KEY_ID",
    "HIPPIUS_MEM_SECRET",
];

/// Parsed `quickstart` arguments.
#[derive(Debug)]
struct Options {
    /// The namespace this trial's notes are scoped under (`--team <name>`);
    /// defaults to [`DEFAULT_TEAM`] so a first run needs no decision.
    team: String,
    /// Skip wiring Claude Code (`setup::install`/`setup::init`) — used by
    /// tests and by anyone driving hippius-mem outside Claude Code.
    no_wire: bool,
}

impl Options {
    /// Parse `[--team <name>] [--no-wire]`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown flag or a `--team` with no value,
    /// BEFORE any file or network operation runs — the same loud-failure
    /// rule every other subcommand's argument parser follows.
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut team = DEFAULT_TEAM.to_owned();
        let mut no_wire = false;

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--team" => {
                    team = iter
                        .next()
                        .map(ToOwned::to_owned)
                        .context("--team requires a value")?;
                }
                "--no-wire" => no_wire = true,
                other => bail!(
                    "unknown quickstart argument `{other}`; usage: quickstart [--team <name>] [--no-wire]"
                ),
            }
        }

        Ok(Self { team, no_wire })
    }
}

/// Run `quickstart`: write a zero-decision local trial vault config, probe
/// it, and (unless `--no-wire`) wire Claude Code.
///
/// # Errors
///
/// Returns an error if the arguments are malformed, a conflicting
/// storage-related `HIPPIUS_MEM_*` env var is set (see
/// [`refuse_conflicting_env_vars`]), a config already exists at the resolved
/// target path, the generated config fails to write or validate, the trial
/// store cannot be built, the doctor probe fails, or — when wiring runs —
/// `setup::install`/`setup::init` fails.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;
    refuse_conflicting_env_vars()?;
    let path = resolve_fresh_target_path()?;

    let vault_root = resolve_default_trial_root(&opts.team)?;
    let (team_key_hex, author_seed_hex) = generate_trial_material()?;
    let body = render_trial_config(&opts.team, &team_key_hex, &author_seed_hex, &vault_root)?;
    write_trial_config(&path, &body)?;

    let cfg = probe_fresh_trial(&path).await?;

    if !opts.no_wire {
        wire_claude_code()?;
    }

    // Re-derive from the just-written-and-reloaded `cfg` rather than reusing
    // `vault_root` directly: this is a round-trip proof that the persisted
    // `local_root` (finding #5) is exactly what got written to disk, not
    // merely what this process computed in memory.
    let vault_root = cfg
        .primary_profile()
        .local_trial_root()
        .context("resolving the trial vault root failed")?;
    print_next_steps(&vault_root);
    Ok(())
}

/// Step 1: refuse before writing anything if a storage-related env var is
/// set that would collide with the `storage = "local"` config about to be
/// written.
///
/// Quickstart's own probe ([`probe_fresh_trial`]) validates the config FILE
/// only (`Config::from_toml_str` — no env overlay), but the wired MCP server
/// loads via `Config::from_env_and_file`, which overlays `HIPPIUS_MEM_*`
/// env vars on top of the file (env wins). A non-empty
/// `HIPPIUS_MEM_BUCKET`/`_ACCESS_KEY_ID`/`_SECRET` would turn this
/// `storage = "local"` config into a hard `LocalStorageWithS3Field`
/// validation error the moment the server actually starts — reporting
/// quickstart success for a config that cannot serve. Refusing up front
/// avoids that gap entirely.
///
/// # Errors
///
/// Returns an error naming every conflicting var that is set, with guidance
/// to unset them (or run `hippius-mem upgrade` directly if a bucket already
/// exists).
fn refuse_conflicting_env_vars() -> anyhow::Result<()> {
    refuse_conflicting_env_vars_with(|key| std::env::var(key).ok())
}

/// The testable core of [`refuse_conflicting_env_vars`]: env access goes
/// through an injected `lookup` (the same seam `Config::apply_overrides`
/// uses) so this is unit-tested deterministically, without mutating the
/// real process environment.
///
/// # Errors
///
/// Returns an error naming every `key` in [`CONFLICTING_STORAGE_ENV_VARS`]
/// for which `lookup` returns a non-blank value.
fn refuse_conflicting_env_vars_with(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
    // Blank (set-but-empty) is not a real override: `Config::apply_overrides`
    // would set the field to an empty string, which `TeamProfile::validate`
    // still accepts for a local profile (`reject_present` also trims before
    // checking emptiness) — matching that tolerance here avoids a spurious
    // refusal.
    let set: Vec<&str> = CONFLICTING_STORAGE_ENV_VARS
        .iter()
        .copied()
        .filter(|key| lookup(key).is_some_and(|v| !v.trim().is_empty()))
        .collect();

    if set.is_empty() {
        return Ok(());
    }

    let them = if set.len() == 1 { "it" } else { "them" };
    bail!(
        "refusing to write a storage = \"local\" trial config: {vars} set in the environment. \
         hippius-mem overlays HIPPIUS_MEM_* environment variables on top of the config FILE at \
         serve time (env wins over the file), so this would turn a valid local trial into a \
         hard validation error the instant the MCP server actually starts — after quickstart \
         itself reported success. Unset {them} first; if you already have a Hippius bucket, run \
         `hippius-mem upgrade` directly (or hand-write a storage = \"s3\" config) instead of \
         quickstart.",
        vars = set.join(", "),
    );
}

/// Resolve the trial vault's default disk root for `team`, using
/// [`TeamProfile::local_trial_root`]'s own derivation (no `local_root`
/// override set) — the SAME path the written config's `local_root` field
/// then pins (finding #5), so `upgrade`/`serve` resolve to this exact
/// directory later regardless of what `XDG_DATA_HOME`/`HOME` are set to when
/// THEY run.
///
/// # Errors
///
/// Returns an error if no default root can be derived (see
/// [`TeamProfile::local_trial_root`]).
fn resolve_default_trial_root(team: &str) -> anyhow::Result<PathBuf> {
    let probe = TeamProfile {
        name: team.to_owned(),
        storage: StorageBackend::Local,
        ..TeamProfile::default()
    };
    probe
        .local_trial_root()
        .context("resolving the trial vault's default root failed")
}

/// Step 2: resolve the config target path, refusing if one already exists —
/// the join-bundle convention: a conflict refuses with guidance, it is
/// never rewritten.
///
/// # Errors
///
/// Returns an error if no config path can be resolved (see
/// [`resolve_target_path`]), or if a config already exists at the resolved
/// path.
fn resolve_fresh_target_path() -> anyhow::Result<PathBuf> {
    let path = resolve_target_path()?;
    refuse_if_exists(&path)?;
    Ok(path)
}

/// Refuse a config target that already exists, byte-untouched.
///
/// # Errors
///
/// Returns an error naming `path` and pointing the operator at `doctor` (to
/// check the existing config) or manual deletion (to start a fresh trial).
fn refuse_if_exists(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        bail!(
            "a config already exists at {path}; run `hippius-mem doctor` to check it, or delete \
             it first if you really want a fresh trial",
            path = path.display()
        );
    }
    Ok(())
}

/// Step 3: generate `(team_key_hex, author_seed_hex)` as two independent
/// CSPRNG draws via [`generate_seed_hex`] — the same mechanism `join
/// --bundle` uses for `author_seed_hex`. A trial vault has no founder to
/// mint the team key elsewhere, so it is generated locally exactly like the
/// signing seed.
///
/// # Errors
///
/// Returns an error if the OS CSPRNG is unavailable.
fn generate_trial_material() -> anyhow::Result<(Zeroizing<String>, Zeroizing<String>)> {
    let team_key_hex = generate_seed_hex()?;
    let author_seed_hex = generate_seed_hex()?;
    Ok((team_key_hex, author_seed_hex))
}

/// Serialization shape of the fresh trial config: the minimal fields a
/// `storage = "local"` primary profile needs. `bucket`/`access_key_id`/
/// `secret`/`s3_endpoint` are deliberately absent — `Config`'s
/// `#[serde(default)]` fills their defaults, which are exactly what
/// [`StorageBackend::Local`] validation requires (empty).
///
/// `local_root` IS written (finding #5), unlike those absent fields: without
/// it, `upgrade`/`serve` re-derive the vault directory from
/// `TeamProfile::local_trial_root`'s `XDG_DATA_HOME`/`HOME` fallback, which
/// can resolve to a DIFFERENT directory than this process just wrote to if
/// those env vars differ at that later, possibly-different-environment call
/// site — silently pointing `upgrade` at an empty (or wrong) directory.
/// Pinning the RESOLVED path here makes it authoritative regardless of env.
#[derive(serde::Serialize)]
struct TrialDoc<'a> {
    team: &'a str,
    team_key_hex: &'a str,
    author_seed_hex: &'a str,
    storage: StorageBackend,
    local_root: &'a Path,
}

/// Step 4a: render the trial config document (pure — no I/O). Borrowing
/// `&str` avoids a second owned copy of the generated key material; `toml`
/// serialization escapes rather than string-templates, matching every other
/// config-writing site in this crate. `local_root` is the vault directory
/// already resolved by [`resolve_default_trial_root`] — see the module docs
/// on why this is persisted rather than left to be re-derived later.
///
/// # Errors
///
/// Returns an error if serialization fails (infallible in practice for this
/// fixed field set, kept fallible to match `toml::to_string`'s signature).
fn render_trial_config(
    team: &str,
    team_key_hex: &str,
    author_seed_hex: &str,
    local_root: &Path,
) -> anyhow::Result<Zeroizing<String>> {
    let doc = TrialDoc {
        team,
        team_key_hex,
        author_seed_hex,
        storage: StorageBackend::Local,
        local_root,
    };
    let fields =
        Zeroizing::new(toml::to_string(&doc).context("serializing the trial config as TOML")?);

    Ok(Zeroizing::new(format!(
        "# hippius-mem per-user config. Holds secrets — never commit. Mode 0600.\n\
         # Written by `hippius-mem quickstart`. A local trial vault: notes live on\n\
         # this disk only, never a Hippius bucket, until `hippius-mem upgrade`.\n\
         {}",
        fields.as_str()
    )))
}

/// Step 4b: write the validated document to `path`, 0600. `create_new`
/// refuses a file that appeared since [`resolve_fresh_target_path`]
/// checked — a race, not the common case, which already refused with
/// guidance before any of this ran.
///
/// # Errors
///
/// Returns an error if the rendered document does not validate, the parent
/// directory cannot be created, or the file cannot be created/written.
fn write_trial_config(path: &Path, body: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("creating the config directory {} failed", parent.display())
        })?;
    }

    // Validate BEFORE creating the file: a refusal must leave nothing behind.
    Config::from_toml_str(body).context(
        "the generated trial config failed validation (this is a `quickstart` bug, not \
         something to fix by hand)",
    )?;

    // 0600 at create time via `mode` (umask can only clear further bits, so the
    // file is never group/world readable even transiently), then pinned to
    // exactly 0600 after the write — the join-bundle writer's discipline.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating the config at {} failed", path.display()))?;
    file.write_all(body.as_bytes())
        .with_context(|| format!("writing the config at {} failed", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting 0600 on {} failed", path.display()))?;
    Ok(())
}

/// Step 5: load the just-written config straight from its bytes on disk —
/// `join --bundle`'s own round-trip-proof pattern, not
/// `Config::from_env_and_file`'s cwd-relative default — build its store, run
/// the mnemonic-gated epoch bootstrap exactly the way `brief.rs` does, then
/// run the doctor probe so the user sees seal-put-get-open pass against
/// their disk. Returns the loaded `Config` so [`run`] can derive the trial
/// vault root for the printed next steps without a third config load.
///
/// The doctor probe runs via [`crate::doctor::run_for_config`], NOT
/// [`crate::doctor::run`]: `doctor::run` re-resolves its own config from
/// `HIPPIUS_MEM_CONFIG`/cwd, which — on a brand-new machine with no env var
/// set and a cwd with no local `hippius-mem.toml` — would miss the file this
/// function just validated (it was written to the XDG global default, not
/// cwd) and silently probe an empty `Config::default()` instead. Handing the
/// already-loaded `cfg` in directly makes the probe examine EXACTLY the
/// bytes on disk, with no re-resolution step that could disagree.
///
/// # Errors
///
/// Returns an error if the just-written config fails to re-load or
/// validate, the store cannot be built, or the doctor probe fails.
async fn probe_fresh_trial(path: &Path) -> anyhow::Result<Config> {
    let written = Zeroizing::new(std::fs::read_to_string(path).with_context(|| {
        format!(
            "re-reading the just-written config at {} failed",
            path.display()
        )
    })?);
    let cfg = Config::from_toml_str(&written).with_context(|| {
        format!(
            "the just-written config at {} failed validation",
            path.display()
        )
    })?;
    drop(written);

    build_and_bootstrap(&cfg).await?;
    crate::doctor::run_for_config(&cfg, false).await?;
    Ok(cfg)
}

/// Build `cfg`'s store and run the mnemonic-gated epoch-key bootstrap — the
/// recorded gotcha: every new entry point that builds a store and reads full
/// team memory must wire this, even though a fresh trial is epoch 0 only (a
/// local vault has no rotation history yet).
///
/// # Errors
///
/// Returns an error if the store cannot be built.
async fn build_and_bootstrap(cfg: &Config) -> anyhow::Result<()> {
    let store = cfg
        .build_store()
        .await
        .context("building the trial store failed")?;
    if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
        crate::admin::bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    }
    Ok(())
}

/// Step 6: wire Claude Code unless `--no-wire` — `setup::install` always
/// (user-global registration), then `setup::init` only when the cwd is
/// inside a git repo, mirroring how `scripts/install.sh` step 4 decides
/// whether to provision the launch repo.
///
/// # Errors
///
/// Returns an error if either provisioning step fails.
fn wire_claude_code() -> anyhow::Result<()> {
    crate::setup::install(&[])?;
    if cwd_is_git_repo() {
        crate::setup::init(&[])?;
    }
    Ok(())
}

/// Whether the current working directory is inside a git repository —
/// `git rev-parse --show-toplevel` succeeding, the same check
/// `scripts/install.sh` step 4 uses to decide whether `init` runs there.
fn cwd_is_git_repo() -> bool {
    Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Step 7: print exactly two next steps.
///
/// `root` is the trial vault's blob-storage directory (`TeamProfile::
/// local_trial_root`), not the config file: `hippius-mem upgrade`'s parallel
/// "keep/delete the trial directory" text (a later task) only makes sense
/// pointed at the directory notes actually live in.
fn print_next_steps(root: &Path) {
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "Trial vault ready at {root}. Notes are encrypted and signed on your disk.
  1. In Claude Code, ask it to remember something about this repo.
  2. When you subscribe to Hippius storage, run: hippius-mem upgrade
Trial mode is solo. Team memory (invite/join) needs a Hippius bucket.",
        root = root.display()
    );
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
    )]
    #![expect(
        clippy::expect_used,
        reason = "tests assert on hand-built fixtures where construction cannot fail"
    )]

    use super::{
        DEFAULT_TEAM, Options, refuse_conflicting_env_vars_with, refuse_if_exists,
        render_trial_config,
    };
    use crate::config::{Config, StorageBackend};

    #[test]
    fn options_default_to_the_trial_team_with_wiring_enabled() -> anyhow::Result<()> {
        let opts = Options::parse(&[])?;
        assert_eq!(opts.team, DEFAULT_TEAM);
        assert!(!opts.no_wire, "wiring must run unless --no-wire is passed");
        Ok(())
    }

    #[test]
    fn options_parse_team_and_no_wire_flags() -> anyhow::Result<()> {
        let args = vec![
            "--team".to_owned(),
            "acme".to_owned(),
            "--no-wire".to_owned(),
        ];
        let opts = Options::parse(&args)?;
        assert_eq!(opts.team, "acme");
        assert!(opts.no_wire);
        Ok(())
    }

    #[test]
    fn options_reject_unknown_flags_and_a_missing_team_value() {
        assert!(
            Options::parse(&["--bogus".to_owned()]).is_err(),
            "an unknown flag must be rejected"
        );
        assert!(
            Options::parse(&["--team".to_owned()]).is_err(),
            "--team with no value must be rejected"
        );
    }

    #[test]
    fn refuse_if_exists_bails_with_guidance_pointing_at_doctor() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hippius-mem.toml");
        std::fs::write(&path, "anything")?;

        let err = refuse_if_exists(&path).expect_err("an existing config must be refused");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("doctor"), "points at doctor: {rendered}");
        assert!(
            rendered.contains(&path.display().to_string()),
            "names the offending path: {rendered}"
        );
        Ok(())
    }

    #[test]
    fn refuse_if_exists_allows_a_fresh_path() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hippius-mem.toml");
        refuse_if_exists(&path)?;
        Ok(())
    }

    #[test]
    fn render_trial_config_produces_a_valid_local_profile() -> anyhow::Result<()> {
        let team_key_hex = "ab".repeat(32);
        let author_seed_hex = "cd".repeat(32);
        let dir = tempfile::tempdir()?;
        let body = render_trial_config("trial", &team_key_hex, &author_seed_hex, dir.path())?;

        let cfg = Config::from_toml_str(&body)?;
        assert_eq!(cfg.team, "trial");
        assert_eq!(cfg.storage, StorageBackend::Local);
        assert_eq!(cfg.team_key_hex, team_key_hex);
        assert_eq!(cfg.author_seed_hex, author_seed_hex);
        assert!(cfg.bucket.is_empty(), "bucket must default empty");
        assert!(
            cfg.access_key_id.is_empty(),
            "access_key_id must default empty"
        );
        assert!(cfg.secret.is_empty(), "secret must default empty");
        Ok(())
    }

    /// Finding #5: quickstart must persist the RESOLVED vault directory as
    /// `local_root`, so `upgrade`/`serve` always resolve the exact same path
    /// regardless of what `XDG_DATA_HOME`/`HOME` are set to when THEY run.
    #[test]
    fn render_trial_config_persists_the_resolved_local_root() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let body = render_trial_config("trial", &"ab".repeat(32), &"cd".repeat(32), dir.path())?;

        let cfg = Config::from_toml_str(&body)?;
        assert_eq!(
            cfg.local_root.as_deref(),
            Some(dir.path()),
            "the resolved vault root must be pinned into local_root, not left to be \
             re-derived from a possibly-different environment later"
        );
        Ok(())
    }

    // Finding #11: quickstart's own probe validates the config FILE only
    // (`Config::from_toml_str`), but the wired MCP server loads via
    // `from_env_and_file`, which overlays `HIPPIUS_MEM_*` env vars — a
    // conflicting one must refuse quickstart up front, not report success for
    // a config the server cannot actually start.

    #[test]
    fn refuse_conflicting_env_vars_allows_a_clean_environment() -> anyhow::Result<()> {
        refuse_conflicting_env_vars_with(|_| None)?;
        Ok(())
    }

    #[test]
    fn refuse_conflicting_env_vars_ignores_an_empty_value() -> anyhow::Result<()> {
        // Mirrors `reject_present`'s own trim-then-empty tolerance: an env var
        // that is SET but blank does not actually override anything (`apply_overrides`
        // would set the field to an empty string, which validation still accepts
        // for a local profile), so it must not trip the refusal.
        refuse_conflicting_env_vars_with(|key| {
            (key == "HIPPIUS_MEM_BUCKET").then(|| "  ".to_owned())
        })?;
        Ok(())
    }

    #[test]
    fn refuse_conflicting_env_vars_refuses_when_bucket_is_set() {
        let err = refuse_conflicting_env_vars_with(|key| {
            (key == "HIPPIUS_MEM_BUCKET").then(|| "prod-bucket".to_owned())
        })
        .expect_err("a set HIPPIUS_MEM_BUCKET must refuse quickstart");
        let rendered = err.to_string();
        assert!(
            rendered.contains("HIPPIUS_MEM_BUCKET"),
            "the refusal must name the offending var: {rendered}"
        );
        assert!(
            rendered.contains("Unset"),
            "the refusal must say to unset it: {rendered}"
        );
    }

    #[test]
    fn refuse_conflicting_env_vars_names_every_offender_at_once() {
        let err = refuse_conflicting_env_vars_with(|key| {
            matches!(key, "HIPPIUS_MEM_BUCKET" | "HIPPIUS_MEM_SECRET").then(|| "x".to_owned())
        })
        .expect_err("multiple conflicting vars must still refuse");
        let rendered = err.to_string();
        assert!(rendered.contains("HIPPIUS_MEM_BUCKET"), "{rendered}");
        assert!(rendered.contains("HIPPIUS_MEM_SECRET"), "{rendered}");
    }
}
