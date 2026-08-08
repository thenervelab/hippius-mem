//! The `upgrade` subcommand: flip a `quickstart` trial vault
//! (`storage = "local"`) into a paid Hippius S3 bucket.
//!
//! The flow: require the persisted trial vault directory to actually exist
//! ([`require_vault_root_exists`] — a missing one aborts before anything
//! else runs, rather than silently copying 0 objects and still flipping the
//! config); acquire the vault's advisory lock ([`acquire_upgrade_lock`],
//! refusing if a live `serve` session already holds it — a running server
//! must not keep writing to a vault mid-migration); probe the destination
//! bucket/credentials with a canary put/get/delete BEFORE touching the
//! trial vault (bad credentials must fail loudly, not midway through
//! copying real notes); `copy_store` every object under the team prefix
//! (put-overwrite, so re-running after a partial copy is safe — see
//! [`hippius_mem_core::copy_store`]); rewrite the config in place to
//! `storage = "s3"` with the new bucket/credentials, preserving every other
//! field ([`render_upgraded_config`]); then rebuild the store from the
//! rewritten config, bootstrap any rotated epoch keys, re-run the `doctor`
//! probe against that EXACT config, and sync the index from the bucket —
//! proving the copied history is readable end to end before the command
//! reports success.
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
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use hippius_mem_core::{BlobStore, FsBlobStore, S3BlobStore, copy_store};
use zeroize::Zeroizing;

use crate::config::{Config, StorageBackend, TeamProfile, VaultLock, VaultLockAttempt};

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
                // Both the bare flag (`--secret shh`) and the `=`-joined form
                // (`--secret=shh`) must hit this SAME pointed refusal — finding
                // #9a: `--secret=VALUE` used to fall through to the generic
                // unknown-argument arm below, which echoed the whole argument
                // (secret included) to stderr. Neither branch here ever names
                // the value.
                other if other == "--secret" || other.starts_with("--secret=") => bail!(
                    "the S3 secret must never be passed via --secret: it would be visible in \
                     argv (`ps`) to every user on this machine; hippius-mem upgrade prompts for \
                     it on the terminal, or reads one line from stdin when piped"
                ),
                other => {
                    // Defense in depth: even for a flag this parser does not
                    // otherwise recognize, print only the flag NAME — never
                    // anything after `=` — so no `--foo=<value>`-shaped
                    // argument can ever echo a secret into stderr, regardless
                    // of which flag it was misspelled as.
                    let name = other.split_once('=').map_or(other, |(name, _)| name);
                    bail!(
                        "unknown upgrade argument `{name}`; usage: upgrade --bucket <name> \
                         --access-key-id <id> [--team <name>] [--endpoint <url>] (the secret is \
                         read from the terminal or stdin, never argv)"
                    )
                }
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
/// profile shape this rewrite supports), the persisted trial vault directory
/// does not exist, a live `serve` process already holds its advisory lock,
/// the destination probe or the copy fails, the config cannot be rewritten,
/// or rebuilding/probing/syncing the upgraded store fails.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;
    let secret = read_secret()?;

    let (path, cfg) = load_trial_config()?;
    confirm_team(&cfg, opts.team.as_deref())?;

    let profile = cfg.primary_profile();
    let vault_root = profile
        .local_trial_root()
        .context("resolving the trial vault root failed")?;
    // Finding #5: the persisted `local_root` is authoritative — a missing
    // directory almost always means a different XDG_DATA_HOME/HOME resolved
    // here than the one `quickstart` wrote the config under, not a genuinely
    // empty trial. Abort before any copy or config rewrite.
    require_vault_root_exists(&vault_root)?;
    // Finding #6: refuse if a live `serve` process (or a concurrent
    // `upgrade`) already holds the vault's advisory lock, rather than
    // migrating a snapshot out from under writes that keep landing after it
    // was taken. Held for the rest of `run` so nothing else can bind this
    // vault mid-migration either.
    let _vault_lock = acquire_upgrade_lock(&profile)?;

    let endpoint = opts
        .endpoint
        .clone()
        .unwrap_or_else(|| cfg.s3_endpoint.clone());

    let fs_store = FsBlobStore::new(vault_root.clone());
    let s3_store = S3BlobStore::new(
        endpoint.clone(),
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
        &endpoint,
    )?;
    rewrite_config_file(&path, &body)?;

    let new_cfg = reload_config(&path)?;
    finish_upgrade(&new_cfg)
        .await
        .map_err(|err| describe_post_flip_failure(err, copied, &opts.bucket))?;

    print_summary(copied, &vault_root, &opts.bucket);
    Ok(())
}

/// Require the trial vault directory to already exist on disk before
/// `upgrade` touches anything else.
///
/// A missing root at the PERSISTED `local_root` almost always means the
/// wrong environment (a different `XDG_DATA_HOME`/`HOME` than the one
/// `quickstart` ran under) resolved a directory nothing was ever written to,
/// not a genuinely empty trial. Copying 0 objects and flipping the config to
/// `s3` in that case would silently strand any real notes at whatever path
/// they actually live under. A vault that DOES exist but genuinely holds 0
/// objects (a fresh `quickstart` nobody has used yet) is allowed through —
/// once confirmed to exist, the persisted path is authoritative and
/// [`describe_post_flip_failure`]'s sibling, the printed copy count, reports
/// the true (possibly zero) number honestly.
///
/// # Errors
///
/// Returns an error naming `root` when it does not exist.
fn require_vault_root_exists(root: &Path) -> anyhow::Result<()> {
    ensure!(
        root.exists(),
        "the trial vault directory at {root} (this config's local_root) does not exist — \
         refusing to upgrade: proceeding would silently copy 0 objects and still flip the \
         config to point at the new bucket, stranding any real notes at whatever path they \
         actually live under (a different XDG_DATA_HOME/HOME than the one `quickstart` wrote \
         this config under?). If the vault really is empty and brand new, create the directory \
         first: mkdir -p {root}",
        root = root.display(),
    );
    Ok(())
}

/// Acquire `profile`'s local-vault advisory lock before copying anything, or
/// refuse with clear guidance if a live `serve` process already holds it —
/// see [`crate::config::TeamProfile::try_lock_local_vault`]. Split out so the
/// refusal wording is unit-testable without driving the whole `run` flow.
///
/// # Errors
///
/// Returns an error if the lock is already held by another process, or if
/// the lock file itself cannot be created/opened.
fn acquire_upgrade_lock(profile: &TeamProfile) -> anyhow::Result<VaultLock> {
    match profile.try_lock_local_vault()? {
        VaultLockAttempt::Acquired(lock) => Ok(lock),
        VaultLockAttempt::Held => bail!(
            "this trial vault is in use by another process (its advisory lock is held) — \
             close any running Claude Code session using this trial vault, then re-run upgrade"
        ),
        VaultLockAttempt::NotLocal => bail!(
            "internal error: require_single_local_profile should have already guaranteed \
             storage = \"local\" before the lock was attempted"
        ),
    }
}

/// Wrap a [`finish_upgrade`] failure with context proving the migration
/// itself already succeeded: the copy and the config rewrite both ran
/// BEFORE `finish_upgrade` (rebuild the store, bootstrap epochs, the
/// `doctor` probe, the index sync — the most network-dependent step, run
/// LAST). Without this, a bare `doctor`/sync error here reads as data loss,
/// and the natural next move — re-running `upgrade` — is actively wrong:
/// [`require_single_local_profile`] will refuse it with "there is no local
/// trial vault to upgrade" (correctly — the config IS already `storage =
/// "s3"`), which without this context reads as the upgrade having silently
/// failed and lost the trial vault, when it in fact completed. Split out so
/// this exact wording is unit-testable without driving the whole `run` flow
/// (which needs a real store/network to reach this failure path for real).
fn describe_post_flip_failure(err: anyhow::Error, copied: u64, bucket: &str) -> anyhow::Error {
    err.context(format!(
        "the copy ({copied} object(s)) and the config rewrite both succeeded — this config \
         now points at bucket `{bucket}`; do NOT re-run `upgrade` (it will refuse: \"there is \
         no local trial vault to upgrade\", correctly, since the flip already happened) — run \
         `hippius-mem doctor` to diagnose and verify instead"
    ))
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
             upgrade (upgrade only applies to a storage = \"local\" trial config; this is \
             also the expected state right after a completed `upgrade` — if you just ran \
             it, this config is healthy, run `hippius-mem doctor` to confirm)"
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

/// Render the upgraded config document (pure — no I/O) by round-tripping the
/// EXISTING, already-validated `cfg` through the real [`Config`] type: clone
/// it, mutate ONLY the storage fields (`storage`, `bucket`, `access_key_id`,
/// `secret`, `s3_endpoint`, and clear `local_root`), then re-serialize.
///
/// This replaces a previous `UpgradedDoc` shadow struct that serialized a
/// fixed 9-field subset — every OTHER field (`max_epoch`,
/// `semantic_embeddings`, `relevance_floor`, `s3_region`, `chain_ws_url`,
/// `anchor_threshold`, `orgs`, `catch_all`, `teams`) was silently dropped on
/// upgrade, and `s3_endpoint` was persisted only when `--endpoint` was
/// explicitly passed (findings #7 and #12). Round-tripping through the real
/// type instead means a field this rewrite does not know about cannot be
/// dropped: it was never taken apart into a hand-picked list in the first
/// place.
///
/// `endpoint` is the RESOLVED endpoint actually used for the copy that just
/// ran — `run`'s `opts.endpoint.clone().unwrap_or_else(|| cfg.s3_endpoint...)`
/// — so the persisted value always matches what the objects were actually
/// copied to, never a stale pre-upgrade value and never silently omitted.
///
/// # Errors
///
/// Returns an error if serialization fails (infallible in practice; kept
/// fallible to match `toml::to_string`'s signature — mirrors
/// `quickstart::render_trial_config`).
fn render_upgraded_config(
    cfg: &Config,
    bucket: &str,
    access_key_id: &str,
    secret: &str,
    endpoint: &str,
) -> anyhow::Result<Zeroizing<String>> {
    let mut upgraded = cfg.clone();
    upgraded.storage = StorageBackend::S3;
    bucket.clone_into(&mut upgraded.bucket);
    access_key_id.clone_into(&mut upgraded.access_key_id);
    secret.clone_into(&mut upgraded.secret);
    endpoint.clone_into(&mut upgraded.s3_endpoint);
    // An S3 profile never reads `local_root`; clearing it (rather than
    // leaving the trial path behind) keeps the rewritten config visibly
    // honest about which backend it now binds.
    upgraded.local_root = None;

    let fields = Zeroizing::new(
        toml::to_string(&upgraded).context("serializing the upgraded config as TOML")?,
    );

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
/// must leave the existing file untouched), then written via
/// [`crate::setup::atomic::atomic_write_private`] — an `O_EXCL` temp file in
/// the SAME directory, `fsync`ed, forced to owner-only `0600`, then renamed
/// into place. Reusing that helper (rather than a hand-rolled write) is what
/// makes the new bytes DURABLE before the rename: `rename` only makes the
/// directory-entry swap atomic, not the underlying data blocks, so a plain
/// write-then-rename can still leave a renamed-but-zero-length/partial file
/// after a crash. For a `quickstart` trial config, `team_key_hex` in this
/// file is the ONLY persisted copy of the team's encryption key
/// (`TrialDoc` writes just four fields) — losing it here leaves the trial
/// directory nothing but undecryptable ciphertext. This is the one config
/// write in this crate that REPLACES an existing file rather than
/// create-fresh (`quickstart`) or append (`join --bundle`).
///
/// # Errors
///
/// Returns an error if `body` does not validate as a [`Config`], or the
/// underlying atomic write fails (temp file creation, write, fsync, mode, or
/// the rename).
fn rewrite_config_file(path: &Path, body: &str) -> anyhow::Result<()> {
    Config::from_toml_str(body).context(
        "the rewritten config failed validation (this is an `upgrade` bug, not something to \
         fix by hand)",
    )?;
    crate::setup::atomic::atomic_write_private(path, body.as_bytes())
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
        Options, acquire_upgrade_lock, confirm_team, describe_post_flip_failure, probe_destination,
        render_upgraded_config, require_single_local_profile, require_vault_root_exists,
        rewrite_config_file,
    };
    use crate::config::{Config, StorageBackend, TeamProfile};

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

    // Finding #5: a persisted `local_root` that does not exist on disk must
    // abort BEFORE any copy or config rewrite — never silently copy 0 objects
    // and still flip the config to point at the new bucket.

    #[test]
    fn require_vault_root_exists_accepts_an_existing_directory() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        require_vault_root_exists(dir.path())?;
        Ok(())
    }

    #[test]
    fn require_vault_root_exists_rejects_a_missing_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("never-created");

        let err = require_vault_root_exists(&missing)
            .expect_err("a missing persisted root must be refused");
        let rendered = err.to_string();
        assert!(
            rendered.contains(&missing.display().to_string()),
            "the refusal must name the missing path: {rendered}"
        );
        assert!(
            rendered.contains("does not exist"),
            "the refusal must say the vault does not exist: {rendered}"
        );
    }

    // Finding #6: `upgrade` must refuse — not queue behind, not silently
    // proceed — when a live `serve` process already holds the vault's
    // advisory lock.

    #[test]
    fn acquire_upgrade_lock_succeeds_over_a_free_vault() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let profile = TeamProfile {
            name: "trial".to_owned(),
            storage: StorageBackend::Local,
            local_root: Some(dir.path().to_path_buf()),
            ..TeamProfile::default()
        };

        acquire_upgrade_lock(&profile)?;
        Ok(())
    }

    #[test]
    fn acquire_upgrade_lock_refuses_when_a_live_server_holds_it() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let profile = TeamProfile {
            name: "trial".to_owned(),
            storage: StorageBackend::Local,
            local_root: Some(dir.path().to_path_buf()),
            ..TeamProfile::default()
        };

        // Simulate a live `serve` process already bound to this vault.
        let _held = profile.try_lock_local_vault()?;

        let err = acquire_upgrade_lock(&profile)
            .expect_err("upgrade must refuse when the vault lock is already held");
        let rendered = err.to_string();
        assert!(
            rendered.contains("close any running Claude Code session"),
            "the refusal must give the fix: {rendered}"
        );
        assert!(
            rendered.contains("re-run upgrade"),
            "the refusal must say to re-run upgrade once resolved: {rendered}"
        );
        Ok(())
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

    /// Finding #9a: `--secret=VALUE` (the `=`-joined form) must hit the SAME
    /// pointed refusal as the space-separated `--secret shh` form — not fall
    /// through to the generic unknown-argument bail, which used to echo the
    /// full argument (secret included) to stderr.
    #[test]
    fn options_reject_a_secret_equals_form_without_leaking_the_value() {
        let args = vec!["--secret=wJalrXUtnFEMI/K7MDENG".to_owned()];
        let err = Options::parse(&args).expect_err("--secret=VALUE must be rejected");
        let rendered = err.to_string();
        assert!(
            rendered.to_lowercase().contains("argv"),
            "the refusal must explain secrets never travel via argv: {rendered}"
        );
        assert!(
            !rendered.contains("wJalrXUtnFEMI/K7MDENG"),
            "the rejected secret value must never be echoed back: {rendered}"
        );
    }

    /// Finding #9a defense in depth: even for an argument the `--secret`
    /// prefix check does not recognize, the generic unknown-argument error
    /// must print only the flag NAME, never anything after `=` — so no
    /// value-shaped argument can ever be echoed verbatim.
    #[test]
    fn options_generic_unknown_argument_error_never_echoes_a_value() {
        let args = vec!["--totally-unknown=super-secret-value".to_owned()];
        let err = Options::parse(&args).expect_err("an unknown flag must be rejected");
        let rendered = err.to_string();
        assert!(
            rendered.contains("--totally-unknown"),
            "the refusal must still name the flag: {rendered}"
        );
        assert!(
            !rendered.contains("super-secret-value"),
            "no value after `=` may ever be echoed: {rendered}"
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
        let rendered = err.to_string();
        assert!(rendered.contains("no local trial vault"), "{rendered}");
        // This refusal is also the expected shape of a config right after a
        // completed upgrade — it must not read as unconditional failure.
        assert!(rendered.contains("doctor"), "{rendered}");
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

        let body = render_upgraded_config(&cfg, "new-bucket", "AKID", "shh", &cfg.s3_endpoint)?;
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
    fn render_upgraded_config_writes_the_resolved_endpoint() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = Config::from_toml_str(&local_trial_toml(dir.path()))?;

        // `run` resolves `--endpoint` OR `cfg.s3_endpoint` BEFORE calling this
        // function (see `run`'s `endpoint` binding) — the same value the copy
        // itself used — and passes that resolved string straight through, never
        // the raw `Option<&str>` the CLI flag arrived as.
        let body = render_upgraded_config(&cfg, "new-bucket", "AKID", "shh", "https://gw.example")?;
        let upgraded = Config::from_toml_str(&body)?;

        assert_eq!(upgraded.s3_endpoint, "https://gw.example");
        Ok(())
    }

    /// Findings #7 + #12: the previous `UpgradedDoc` shadow struct serialized
    /// a fixed 9-field subset, silently dropping everything else a trial
    /// config might hold (`max_epoch`, `semantic_embeddings`,
    /// `relevance_floor`, `s3_region`, `chain_ws_url`, `orgs`, `catch_all`).
    /// The rewrite must round-trip through the REAL `Config` type instead,
    /// mutating only the storage fields.
    #[test]
    fn render_upgraded_config_preserves_every_field_the_flip_does_not_touch() -> anyhow::Result<()>
    {
        let dir = tempfile::tempdir()?;
        let toml = format!(
            "team = \"trial\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n\
             storage = \"local\"\nlocal_root = \"{root}\"\n\
             max_epoch = 2\nsemantic_embeddings = false\nrelevance_floor = 0.4\n\
             s3_region = \"custom-region\"\ns3_endpoint = \"https://old.example\"\n\
             orgs = [\"github.com/acme\"]\ncatch_all = true\n",
            key = hex64("ab"),
            seed = hex64("cd"),
            root = dir.path().display(),
        );
        let cfg = Config::from_toml_str(&toml)?;

        let body =
            render_upgraded_config(&cfg, "new-bucket", "AKID", "shh", "https://new.example")?;
        let upgraded = Config::from_toml_str(&body)?;

        assert_eq!(
            upgraded.max_epoch, 2,
            "max_epoch must survive the upgrade rewrite"
        );
        assert!(
            !upgraded.semantic_embeddings,
            "semantic_embeddings must survive the upgrade rewrite"
        );
        assert_eq!(
            upgraded.relevance_floor,
            Some(0.4),
            "relevance_floor must survive the upgrade rewrite"
        );
        assert_eq!(
            upgraded.s3_region, "custom-region",
            "s3_region must survive the upgrade rewrite"
        );
        assert_eq!(
            upgraded.s3_endpoint, "https://new.example",
            "s3_endpoint must be the RESOLVED endpoint actually used for the copy, not the \
             stale pre-upgrade value and not silently dropped"
        );
        assert_eq!(
            upgraded.orgs,
            vec!["github.com/acme".to_owned()],
            "orgs must survive the upgrade rewrite"
        );
        assert!(
            upgraded.catch_all,
            "catch_all must survive the upgrade rewrite"
        );
        Ok(())
    }

    /// `rewrite_config_file` must go through the fsync'd, mode-forcing
    /// atomic writer (`setup::atomic::atomic_write_private`), not a
    /// hand-rolled temp-file dance: pins that a pre-existing LOOSER mode is
    /// tightened to owner-only 0600 (never preserved — this file now holds
    /// live S3 credentials), and that the written bytes round-trip as the
    /// upgraded profile.
    #[test]
    fn rewrite_config_file_forces_0600_and_round_trips_the_new_profile() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hippius-mem.toml");
        let existing = local_trial_toml(dir.path());
        std::fs::write(&path, &existing)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;

        let cfg = Config::from_toml_str(&existing)?;
        let body = render_upgraded_config(&cfg, "new-bucket", "AKID", "shh", &cfg.s3_endpoint)?;
        rewrite_config_file(&path, &body)?;

        let mode = std::fs::metadata(&path)?.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "a looser pre-existing mode must be tightened to owner-only 0600: {mode:o}"
        );
        let upgraded = Config::from_toml_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(upgraded.storage, StorageBackend::S3);
        assert_eq!(upgraded.bucket, "new-bucket");
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

    /// A `finish_upgrade` failure (build/bootstrap/doctor/sync — the most
    /// network-dependent step, run AFTER the copy and the config rewrite)
    /// must be reported as "the migration already succeeded", not as bare
    /// data loss: it must name the bucket, tell the operator NOT to re-run
    /// `upgrade`, point at `doctor` instead, and keep the underlying cause
    /// in the chain.
    #[test]
    fn describe_post_flip_failure_names_the_bucket_and_points_at_doctor() {
        let err = describe_post_flip_failure(anyhow::anyhow!("sync failed"), 5, "new-bucket");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("new-bucket"), "{rendered}");
        assert!(rendered.contains("5 object"), "{rendered}");
        assert!(rendered.contains("doctor"), "{rendered}");
        assert!(rendered.contains("do NOT re-run"), "{rendered}");
        assert!(
            rendered.contains("sync failed"),
            "the underlying cause must stay in the chain: {rendered}"
        );
    }
}
