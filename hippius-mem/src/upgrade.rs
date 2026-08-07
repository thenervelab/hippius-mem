//! The `upgrade` subcommand: flip a `quickstart` trial vault
//! (`storage = "local"`) into a paid Hippius S3 bucket.
//!
//! The flow: probe the destination bucket/credentials with a canary
//! put/get/delete BEFORE touching the trial vault (bad credentials must
//! fail loudly, not midway through copying real notes); `copy_store` every
//! object under the team prefix (put-overwrite, so re-running after a
//! partial copy is safe — see [`hippius_mem_core::copy_store`]); rewrite the
//! config in place to `storage = "s3"` with the new bucket/credentials; then
//! rebuild the store from the rewritten config, bootstrap any rotated epoch
//! keys, re-run the `doctor` probe against that EXACT config, and sync the
//! index from the bucket — proving the copied history is readable end to
//! end before the command reports success.
//!
//! Config load/rewrite deliberately mirrors `quickstart.rs`/`join_bundle.rs`,
//! not [`Config::from_env_and_file`]: it resolves the SAME path
//! `quickstart`/`join --bundle` write to
//! ([`crate::join_bundle::resolve_target_path`] — `HIPPIUS_MEM_CONFIG`, else
//! the installer's global XDG path) and loads straight from its bytes on
//! disk. `Config::from_env_and_file`'s cwd-relative default can silently
//! resolve a DIFFERENT file than the one `quickstart` actually wrote — the
//! documented Critical this mirrors the fix for (see `doctor::run_for_config`'s
//! docs). For the same reason, the post-rewrite probe below calls
//! [`crate::doctor::run_for_config`], never `doctor::run(&[])`.
//!
//! Trial mode is solo-only, so there is exactly one profile to upgrade: this
//! in-place rewrite only supports the single-profile flat shape `quickstart`
//! writes (a YAGNI boundary from the design) — a multi-profile config is
//! refused with guidance to edit it by hand.

use std::io::{IsTerminal as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use hippius_mem_core::{BlobStore, FsBlobStore, S3BlobStore, copy_store};
use zeroize::Zeroizing;

use crate::config::{Config, StorageBackend};

/// Fixed, non-secret payload the destination probe puts/gets/deletes.
const PROBE_PAYLOAD: &[u8] = b"hippius-mem upgrade destination probe";

/// Parsed `upgrade` arguments.
#[derive(Debug)]
struct Options {
    /// The new bucket's name.
    bucket: String,
    /// The new bucket's S3 sub-token id.
    access_key_id: String,
    /// `--team <name>`: an optional safety check against the config's one
    /// profile (see [`confirm_team`]) — omitted, the resolved profile's own
    /// name is used unconditionally.
    team: Option<String>,
    /// `--endpoint <url>`: overrides the config's shared `s3_endpoint` for
    /// the destination bucket. `None` uses the config's value unchanged.
    endpoint: Option<String>,
}

impl Options {
    /// Parse `--bucket <name> --access-key-id <id> [--team <name>]
    /// [--endpoint <url>]`, rejecting `--secret` explicitly.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown flag, a flag with no value, a missing
    /// `--bucket`/`--access-key-id`, or a `--secret` flag — each BEFORE any
    /// file, terminal, or network operation runs, matching every other
    /// subcommand's loud-failure rule.
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut bucket = None;
        let mut access_key_id = None;
        let mut team = None;
        let mut endpoint = None;

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--bucket" => {
                    bucket = Some(
                        iter.next()
                            .map(ToOwned::to_owned)
                            .context("--bucket requires a value")?,
                    );
                }
                "--access-key-id" => {
                    access_key_id = Some(
                        iter.next()
                            .map(ToOwned::to_owned)
                            .context("--access-key-id requires a value")?,
                    );
                }
                "--team" => {
                    team = Some(
                        iter.next()
                            .map(ToOwned::to_owned)
                            .context("--team requires a value")?,
                    );
                }
                "--endpoint" => {
                    endpoint = Some(
                        iter.next()
                            .map(ToOwned::to_owned)
                            .context("--endpoint requires a value")?,
                    );
                }
                "--secret" => bail!(
                    "the S3 secret must never be passed via --secret: it would be visible in \
                     argv (`ps`) to every user on this machine; hippius-mem upgrade prompts for \
                     it on the terminal, or reads one line from stdin when piped"
                ),
                other => bail!(
                    "unknown upgrade argument `{other}`; usage: upgrade --bucket <name> \
                     --access-key-id <id> [--team <name>] [--endpoint <url>] (the secret is \
                     read from the terminal or stdin, never argv)"
                ),
            }
        }

        let bucket = bucket.context("upgrade requires --bucket <name>")?;
        let access_key_id = access_key_id.context("upgrade requires --access-key-id <id>")?;
        Ok(Self {
            bucket,
            access_key_id,
            team,
            endpoint,
        })
    }
}

/// Run `upgrade`: copy a local trial vault into a Hippius S3 bucket, then
/// flip the config to point at it.
///
/// # Errors
///
/// Returns an error if the arguments are malformed, the secret cannot be
/// read, no config is found (or it is not the single `storage = "local"`
/// profile shape this rewrite supports), the destination probe or the copy
/// fails, the config cannot be rewritten, or rebuilding/probing/syncing the
/// upgraded store fails.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;
    let secret = read_secret()?;

    let (path, cfg) = load_trial_config()?;
    confirm_team(&cfg, opts.team.as_deref())?;

    let vault_root = cfg
        .primary_profile()
        .local_trial_root()
        .context("resolving the trial vault root failed")?;
    let endpoint = opts
        .endpoint
        .clone()
        .unwrap_or_else(|| cfg.s3_endpoint.clone());

    let fs_store = FsBlobStore::new(vault_root.clone());
    let s3_store = S3BlobStore::new(
        endpoint,
        opts.bucket.clone(),
        opts.access_key_id.clone(),
        secret.as_str().to_owned(),
        cfg.s3_region.clone(),
    );

    probe_destination(&s3_store, &cfg.team).await?;

    let copied = copy_store(&fs_store, &s3_store, &cfg.team)
        .await
        .context("copying the trial vault into the new bucket failed")?;

    let body = render_upgraded_config(
        &cfg,
        &opts.bucket,
        &opts.access_key_id,
        secret.as_str(),
        opts.endpoint.as_deref(),
    )?;
    rewrite_config_file(&path, &body)?;

    let new_cfg = reload_config(&path)?;
    finish_upgrade(&new_cfg).await?;

    print_summary(copied, &vault_root, &opts.bucket);
    Ok(())
}

/// Read the new bucket's S3 secret: prompted with the input hidden on a
/// real terminal, or one line from stdin when piped — never from argv (see
/// [`Options::parse`]'s `--secret` rejection).
///
/// # Errors
///
/// Returns an error if the terminal/stdin read fails, or the input is empty.
fn read_secret() -> anyhow::Result<Zeroizing<String>> {
    let secret = if std::io::stdin().is_terminal() {
        Zeroizing::new(
            rpassword::prompt_password("S3 secret for the new bucket: ")
                .context("reading the S3 secret from the terminal failed")?,
        )
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading the S3 secret from stdin failed")?;
        Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_owned())
    };

    ensure!(
        !secret.is_empty(),
        "no S3 secret was provided (empty terminal/stdin input)"
    );
    Ok(secret)
}

/// Resolve the SAME config path `quickstart`/`join --bundle` write to and
/// load it straight from its bytes on disk — never
/// [`Config::from_env_and_file`]'s cwd-relative default, which can silently
/// resolve a DIFFERENT file (see the module docs).
///
/// # Errors
///
/// Returns an error if no config exists at the resolved path, the config
/// cannot be read or fails validation, or [`require_single_local_profile`]
/// refuses it.
fn load_trial_config() -> anyhow::Result<(PathBuf, Config)> {
    let path = crate::join_bundle::resolve_target_path()?;
    let body = std::fs::read_to_string(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "no config found at {}; run `hippius-mem quickstart` first to create a trial \
                 vault",
                path.display()
            )
        } else {
            anyhow::Error::new(err)
                .context(format!("reading the config at {} failed", path.display()))
        }
    })?;
    let cfg = Config::from_toml_str(&body)
        .with_context(|| format!("the config at {} failed validation", path.display()))?;
    require_single_local_profile(&cfg)?;
    Ok((path, cfg))
}

/// Require the config to hold exactly one profile, with `storage =
/// "local"` — the single-profile trial shape `quickstart` writes, and the
/// only shape this in-place rewrite supports (a YAGNI boundary from the
/// design: a multi-profile config is edited by hand).
///
/// # Errors
///
/// Returns an error naming the reason: more than one profile, or a profile
/// that is already `storage = "s3"` (nothing local left to upgrade).
fn require_single_local_profile(cfg: &Config) -> anyhow::Result<()> {
    let total_profiles = 1 + cfg.teams.len();
    if total_profiles > 1 {
        bail!(
            "this config holds {total_profiles} profiles (the primary plus [[teams]] entries); \
             `upgrade` only supports the single-profile shape `quickstart` writes — edit the \
             config file by hand to add S3 credentials to the profile you want to upgrade"
        );
    }
    if cfg.storage != StorageBackend::Local {
        bail!(
            "this config's storage is already \"s3\" — there is no local trial vault to \
             upgrade (upgrade only applies to a storage = \"local\" trial config)"
        );
    }
    Ok(())
}

/// If `--team <name>` was given, require it to match the config's one
/// profile — a safety check against upgrading the wrong config by mistake
/// (the single-profile precondition already fixed which profile this is,
/// so omitting the flag uses that profile's own name unconditionally).
///
/// # Errors
///
/// Returns an error naming both the requested and the actual team when they
/// differ.
fn confirm_team(cfg: &Config, requested: Option<&str>) -> anyhow::Result<()> {
    let Some(requested) = requested else {
        return Ok(());
    };
    if requested != cfg.team {
        bail!(
            "this config's only profile is `{actual}`, not `{requested}` — omit --team to use \
             `{actual}`, or point HIPPIUS_MEM_CONFIG at the config you meant",
            actual = cfg.team
        );
    }
    Ok(())
}

/// The canary object key the destination probe uses:
/// `{team}/_upgrade_probe`. Disjoint from any real object key by shape
/// (real note/op keys always nest at least one segment deeper than this),
/// so it cannot collide with team data.
fn probe_key(team: &str) -> String {
    format!("{team}/_upgrade_probe")
}

/// Prove the destination bucket/credentials work BEFORE any copy runs: put
/// a small canary object, read it back, then delete it. Bad credentials or
/// a missing bucket fail here, not midway through copying real notes.
///
/// # Errors
///
/// Returns an error if the write, the read-back, or the byte comparison
/// fails. A failed cleanup delete is logged, not propagated — mirrors
/// `doctor::probe_encryption_boundary`'s cleanup discipline.
async fn probe_destination(dst: &dyn BlobStore, team: &str) -> anyhow::Result<()> {
    let key = probe_key(team);

    dst.put(&key, PROBE_PAYLOAD.to_vec()).await.context(
        "writing the destination probe object failed — check --bucket, --access-key-id, and \
         the secret",
    )?;

    let fetched = dst.get(&key).await;
    if let Err(err) = dst.delete(&key).await {
        tracing::debug!(%err, "destination probe cleanup delete failed; the canary object may remain");
    }
    let fetched = fetched.context("reading the destination probe object back failed")?;

    ensure!(
        fetched == PROBE_PAYLOAD,
        "the destination probe object did not round-trip byte-for-byte"
    );
    Ok(())
}

/// Serialization shape of the rewritten single-profile config: the same
/// team identity as the trial config, `storage = "s3"`, and the new
/// bucket/credentials. `local_root` is simply omitted — an S3 profile never
/// reads it.
#[derive(serde::Serialize)]
struct UpgradedDoc<'a> {
    team: &'a str,
    team_key_hex: &'a str,
    author_seed_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    founder_ss58: Option<&'a str>,
    storage: StorageBackend,
    #[serde(skip_serializing_if = "Option::is_none")]
    s3_endpoint: Option<&'a str>,
    bucket: &'a str,
    access_key_id: &'a str,
    secret: &'a str,
}

/// Render the upgraded config document (pure — no I/O). `endpoint` is
/// written only when the operator passed `--endpoint`; omitted, the
/// reloaded config falls back to [`Config::default`]'s endpoint, exactly as
/// the trial vault always did (`quickstart` never wrote `s3_endpoint`
/// either).
///
/// # Errors
///
/// Returns an error if serialization fails (infallible in practice for this
/// fixed field set, kept fallible to match `toml::to_string`'s signature —
/// mirrors `quickstart::render_trial_config`).
fn render_upgraded_config(
    cfg: &Config,
    bucket: &str,
    access_key_id: &str,
    secret: &str,
    endpoint: Option<&str>,
) -> anyhow::Result<Zeroizing<String>> {
    let doc = UpgradedDoc {
        team: &cfg.team,
        team_key_hex: &cfg.team_key_hex,
        author_seed_hex: &cfg.author_seed_hex,
        founder_ss58: cfg.founder_ss58.as_deref(),
        storage: StorageBackend::S3,
        s3_endpoint: endpoint,
        bucket,
        access_key_id,
        secret,
    };
    let fields =
        Zeroizing::new(toml::to_string(&doc).context("serializing the upgraded config as TOML")?);

    Ok(Zeroizing::new(format!(
        "# hippius-mem per-user config. Holds secrets — never commit. Mode 0600.\n\
         # Rewritten by `hippius-mem upgrade`: this trial vault's objects were copied\n\
         # into the bucket below. The local trial directory still exists on disk\n\
         # until you delete it.\n\
         {}",
        fields.as_str()
    )))
}

/// Overwrite the config at `path` with `body`: validated first (a refusal
/// must leave the existing file untouched), then written to a fresh,
/// unpredictable, `O_EXCL`-created temp file in the SAME directory — 0600
/// from the moment it exists, no window where it is briefly the default
/// mode — and renamed into place. `NamedTempFile::persist` replaces the
/// destination atomically on Unix, so a crash mid-write leaves either the
/// old file or the new one, never a half-written config. This is the one
/// config write in this crate that REPLACES an existing file rather than
/// create-fresh (`quickstart`) or append (`join --bundle`), mirroring the
/// atomic-rename discipline [`hippius_mem_core::FsBlobStore::put`] already
/// uses for blob content.
///
/// # Errors
///
/// Returns an error if `body` does not validate as a [`Config`], the temp
/// file cannot be created/written, or the rename fails.
fn rewrite_config_file(path: &Path, body: &str) -> anyhow::Result<()> {
    Config::from_toml_str(body).context(
        "the rewritten config failed validation (this is an `upgrade` bug, not something to \
         fix by hand)",
    )?;

    let parent = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::Builder::new()
        .prefix(".hippius-mem-upgrade-tmp-")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile_in(parent)
        .with_context(|| format!("creating a temp file in {} failed", parent.display()))?;
    tmp.write_all(body.as_bytes())
        .context("writing the upgraded config failed")?;
    tmp.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("replacing the config at {} failed", path.display()))?;
    Ok(())
}

/// Round-trip the just-rewritten config from its bytes on disk — the same
/// discipline `quickstart`/`join --bundle` follow: what gets probed and
/// synced below is EXACTLY what is now on disk, not an in-process value
/// that could disagree with what was actually written.
///
/// # Errors
///
/// Returns an error if the file cannot be re-read or fails validation.
fn reload_config(path: &Path) -> anyhow::Result<Config> {
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
    Ok(cfg)
}

/// Rebuild the store from the just-rewritten config, bootstrap any rotated
/// epoch keys (mirrors `brief.rs`/`quickstart.rs`), re-run the `doctor`
/// probe against this EXACT config — never `doctor::run(&[])`, which
/// re-resolves its own config from the environment/cwd (see the module
/// docs) — then a `refresh`-equivalent sync so the local index rebuilds
/// from the bucket, proving the copied history is readable end to end.
///
/// # Errors
///
/// Returns an error if the store cannot be built, the doctor probe fails,
/// or the sync fails.
async fn finish_upgrade(cfg: &Config) -> anyhow::Result<()> {
    let store = cfg
        .build_store()
        .await
        .context("building the upgraded store failed")?;
    if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
        crate::admin::bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    }
    crate::doctor::run_for_config(cfg, false).await?;
    store
        .sync()
        .await
        .context("syncing the index from the new bucket failed")?;
    Ok(())
}

/// Print exactly three lines: how many objects were copied, where the trial
/// directory is kept (and how to delete it), and that re-running `upgrade`
/// is safe.
fn print_summary(copied: u64, vault_root: &Path, bucket: &str) {
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "Copied {copied} object(s) into bucket `{bucket}`.\n\
         Trial directory kept at {root}; delete it once you are satisfied: rm -rf {root}\n\
         Re-running `hippius-mem upgrade` is safe: the copy is idempotent, so a repeat run \
         only re-copies the same objects harmlessly.",
        root = vault_root.display()
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

    use hippius_mem_core::MemError;

    use super::{
        Options, confirm_team, probe_destination, render_upgraded_config,
        require_single_local_profile,
    };
    use crate::config::{Config, StorageBackend};

    /// 64 hex chars decoding to 32 bytes — valid team-key/seed material.
    fn hex64(byte: &str) -> String {
        byte.repeat(32)
    }

    fn local_trial_toml(root: &std::path::Path) -> String {
        format!(
            "team = \"trial\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n\
             storage = \"local\"\nlocal_root = \"{root}\"\n",
            key = hex64("ab"),
            seed = hex64("cd"),
            root = root.display(),
        )
    }

    fn s3_single_profile_toml() -> String {
        format!(
            "team = \"trial\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n\
             bucket = \"b\"\naccess_key_id = \"ak\"\nsecret = \"s\"\n",
            key = hex64("ab"),
            seed = hex64("cd"),
        )
    }

    fn multi_profile_with_local_primary_toml() -> String {
        format!(
            "team = \"trial\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n\
             storage = \"local\"\n\
             \n[[teams]]\nname = \"acme\"\norgs = [\"github.com/acme\"]\nbucket = \"b\"\n\
             access_key_id = \"ak\"\nsecret = \"s\"\nteam_key_hex = \"{key}\"\n\
             author_seed_hex = \"{seed}\"\n",
            key = hex64("ab"),
            seed = hex64("cd"),
        )
    }

    #[test]
    fn options_parse_the_documented_flags() -> anyhow::Result<()> {
        let args = vec![
            "--bucket".to_owned(),
            "b".to_owned(),
            "--access-key-id".to_owned(),
            "ak".to_owned(),
            "--team".to_owned(),
            "trial".to_owned(),
            "--endpoint".to_owned(),
            "https://gw.example".to_owned(),
        ];
        let opts = Options::parse(&args)?;
        assert_eq!(opts.bucket, "b");
        assert_eq!(opts.access_key_id, "ak");
        assert_eq!(opts.team.as_deref(), Some("trial"));
        assert_eq!(opts.endpoint.as_deref(), Some("https://gw.example"));
        Ok(())
    }

    #[test]
    fn options_require_bucket_and_access_key_id() {
        assert!(
            Options::parse(&["--access-key-id".to_owned(), "ak".to_owned()]).is_err(),
            "missing --bucket must be rejected"
        );
        assert!(
            Options::parse(&["--bucket".to_owned(), "b".to_owned()]).is_err(),
            "missing --access-key-id must be rejected"
        );
    }

    #[test]
    fn options_reject_a_secret_flag_with_a_pointed_error() {
        let args = vec!["--secret".to_owned(), "shh".to_owned()];
        let err = Options::parse(&args).expect_err("--secret must be rejected");
        let rendered = err.to_string();
        assert!(
            rendered.to_lowercase().contains("argv"),
            "the refusal must explain secrets never travel via argv: {rendered}"
        );
    }

    #[test]
    fn options_reject_unknown_flags_and_missing_values() {
        assert!(Options::parse(&["--bogus".to_owned()]).is_err());
        assert!(Options::parse(&["--bucket".to_owned()]).is_err());
        assert!(Options::parse(&["--team".to_owned()]).is_err());
        assert!(Options::parse(&["--endpoint".to_owned()]).is_err());
    }

    #[test]
    fn require_single_local_profile_accepts_a_lone_local_profile() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = Config::from_toml_str(&local_trial_toml(dir.path()))?;
        require_single_local_profile(&cfg)?;
        Ok(())
    }

    #[test]
    fn require_single_local_profile_rejects_s3_storage() -> anyhow::Result<()> {
        let cfg = Config::from_toml_str(&s3_single_profile_toml())?;
        let err = require_single_local_profile(&cfg).expect_err("s3 storage must refuse upgrade");
        assert!(err.to_string().contains("no local trial vault"), "{err}");
        Ok(())
    }

    #[test]
    fn require_single_local_profile_rejects_multiple_profiles() -> anyhow::Result<()> {
        let cfg = Config::from_toml_str(&multi_profile_with_local_primary_toml())?;
        let err = require_single_local_profile(&cfg)
            .expect_err("a multi-profile config must refuse upgrade");
        assert!(err.to_string().contains("edit the config"), "{err}");
        Ok(())
    }

    #[test]
    fn confirm_team_allows_a_missing_or_matching_team() -> anyhow::Result<()> {
        let cfg = Config::from_toml_str(&s3_single_profile_toml())?;
        confirm_team(&cfg, None)?;
        confirm_team(&cfg, Some("trial"))?;
        Ok(())
    }

    #[test]
    fn confirm_team_rejects_a_mismatched_team() -> anyhow::Result<()> {
        let cfg = Config::from_toml_str(&s3_single_profile_toml())?;
        let err = confirm_team(&cfg, Some("someone-else"))
            .expect_err("a mismatched --team must be rejected");
        assert!(err.to_string().contains("trial"), "{err}");
        Ok(())
    }

    #[test]
    fn render_upgraded_config_produces_a_valid_s3_profile() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = Config::from_toml_str(&local_trial_toml(dir.path()))?;

        let body = render_upgraded_config(&cfg, "new-bucket", "AKID", "shh", None)?;
        let upgraded = Config::from_toml_str(&body)?;

        assert_eq!(upgraded.storage, StorageBackend::S3);
        assert_eq!(upgraded.bucket, "new-bucket");
        assert_eq!(upgraded.access_key_id, "AKID");
        assert_eq!(upgraded.secret, "shh");
        assert_eq!(upgraded.team, cfg.team);
        assert_eq!(upgraded.team_key_hex, cfg.team_key_hex);
        assert_eq!(upgraded.author_seed_hex, cfg.author_seed_hex);
        assert!(
            upgraded.local_root.is_none(),
            "local_root must be dropped by the rewrite"
        );
        Ok(())
    }

    #[test]
    fn render_upgraded_config_writes_an_explicit_endpoint_override() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = Config::from_toml_str(&local_trial_toml(dir.path()))?;

        let body = render_upgraded_config(
            &cfg,
            "new-bucket",
            "AKID",
            "shh",
            Some("https://gw.example"),
        )?;
        let upgraded = Config::from_toml_str(&body)?;

        assert_eq!(upgraded.s3_endpoint, "https://gw.example");
        Ok(())
    }

    #[tokio::test]
    async fn probe_destination_round_trips_and_cleans_up() -> anyhow::Result<()> {
        let dst = hippius_mem_core::MemoryBlobStore::default();
        probe_destination(&dst, "trial").await?;

        let leftover = hippius_mem_core::BlobStore::list(&dst, "").await?;
        assert!(
            leftover.is_empty(),
            "the canary object must not remain: {leftover:?}"
        );
        Ok(())
    }

    /// A destination that rejects the write must fail the probe with
    /// guidance pointing at the credentials, so bad credentials are
    /// diagnosable before any real copy runs.
    struct FailingPutStore;

    #[async_trait::async_trait]
    impl hippius_mem_core::BlobStore for FailingPutStore {
        async fn put(&self, _key: &str, _bytes: Vec<u8>) -> Result<(), MemError> {
            Err(MemError::Storage("simulated put failure".to_owned()))
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            Err(MemError::NotFound { id: key.to_owned() })
        }

        async fn list(&self, _prefix: &str) -> Result<Vec<String>, MemError> {
            Ok(Vec::new())
        }

        async fn delete(&self, _key: &str) -> Result<(), MemError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn probe_destination_surfaces_a_put_failure_with_guidance() {
        let err = probe_destination(&FailingPutStore, "trial")
            .await
            .expect_err("a destination that rejects the write must fail the probe");
        let rendered = err.to_string();
        assert!(
            rendered.contains("access-key-id") || rendered.contains("bucket"),
            "{rendered}"
        );
    }
}
