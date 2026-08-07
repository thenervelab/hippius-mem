//! The `quickstart` subcommand: a zero-decision solo trial vault.
//!
//! Writes a fresh, flat, single-profile `storage = "local"` config (no
//! bucket, no S3 credentials — [`hippius_mem_core::FsBlobStore`] lands notes
//! on this machine's own disk), proves the encryption boundary holds against
//! it via the existing `doctor` probe, then — unless `--no-wire` — wires
//! Claude Code exactly the way `install`/`init` already do. `team_key_hex`
//! and `author_seed_hex` are both generated locally via the OS CSPRNG (the
//! `join --bundle` convention: a trial vault has no founder to mint the team
//! key elsewhere, so it is generated exactly like the signing seed). An
//! existing config is a refusal with guidance, never rewritten — the same
//! join-bundle conflict convention.
//!
//! Trial mode is solo-only: `invite`/`join` refuse on a `storage = "local"`
//! profile (a separate concern from this module). `hippius-mem upgrade` (a
//! later task) flips a trial profile to `storage = "s3"` after copying its
//! objects into a real bucket.

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use zeroize::Zeroizing;

use crate::config::{Config, StorageBackend};
use crate::join_bundle::{generate_seed_hex, resolve_target_path};

/// Default team/namespace name for a fresh trial: no decision required.
const DEFAULT_TEAM: &str = "trial";

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
/// Returns an error if the arguments are malformed, a config already exists
/// at the resolved target path, the generated config fails to write or
/// validate, the trial store cannot be built, the doctor probe fails, or —
/// when wiring runs — `setup::install`/`setup::init` fails.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;
    let path = resolve_fresh_target_path()?;

    let (team_key_hex, author_seed_hex) = generate_trial_material()?;
    let body = render_trial_config(&opts.team, &team_key_hex, &author_seed_hex)?;
    write_trial_config(&path, &body)?;

    probe_fresh_trial(&path).await?;

    if !opts.no_wire {
        wire_claude_code()?;
    }

    print_next_steps(&path);
    Ok(())
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
#[derive(serde::Serialize)]
struct TrialDoc<'a> {
    team: &'a str,
    team_key_hex: &'a str,
    author_seed_hex: &'a str,
    storage: StorageBackend,
}

/// Step 4a: render the trial config document (pure — no I/O). Borrowing
/// `&str` avoids a second owned copy of the generated key material; `toml`
/// serialization escapes rather than string-templates, matching every other
/// config-writing site in this crate.
///
/// # Errors
///
/// Returns an error if serialization fails (infallible in practice for this
/// fixed field set, kept fallible to match `toml::to_string`'s signature).
fn render_trial_config(
    team: &str,
    team_key_hex: &str,
    author_seed_hex: &str,
) -> anyhow::Result<Zeroizing<String>> {
    let doc = TrialDoc {
        team,
        team_key_hex,
        author_seed_hex,
        storage: StorageBackend::Local,
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

/// Step 5: load the just-written config from its bytes on disk — not
/// `Config::from_env_and_file`'s cwd-relative default, `join --bundle`'s own
/// round-trip-proof pattern instead — build its store, run the
/// mnemonic-gated epoch bootstrap exactly the way `brief.rs` does, then run
/// the doctor probe so the user sees seal-put-get-open pass against their
/// disk.
///
/// # Errors
///
/// Returns an error if the just-written config fails to re-load or
/// validate, the store cannot be built, or the doctor probe fails.
async fn probe_fresh_trial(path: &Path) -> anyhow::Result<()> {
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
    crate::doctor::run(&[]).await
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
fn print_next_steps(path: &Path) {
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "Trial vault ready at {path}. Notes are encrypted and signed on your disk.
  1. In Claude Code, ask it to remember something about this repo.
  2. When you subscribe to Hippius storage, run: hippius-mem upgrade
Trial mode is solo. Team memory (invite/join) needs a Hippius bucket.",
        path = path.display()
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

    use super::{DEFAULT_TEAM, Options, refuse_if_exists, render_trial_config};
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
        let body = render_trial_config("trial", &team_key_hex, &author_seed_hex)?;

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
}
