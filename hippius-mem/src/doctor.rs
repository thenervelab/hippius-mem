//! The `hippius-mem doctor` subcommand: validate a memory-key bundle.
//!
//! Loads the same [`Config`] the server boots from and reports the non-secret
//! coordinates (bucket, `access_key_id`, author SS58), so an operator can confirm
//! a bundle is well-formed before starting the server. Secrets (`secret`,
//! `team_key_hex`, `author_seed_hex`) are never logged.

use std::sync::Arc;

use anyhow::{Context, bail, ensure};
use hippius_mem_core::{
    BlobStore, FsBlobStore, S3BlobStore, SecretKey, Signer, Ss58, highest_published_epoch,
    load_manifest, open, seal, wrapped_key_recipients,
};

use crate::config::{Config, StorageBackend, TeamProfile};
use crate::resolver::{self, GitRemoteReader, RemoteReader, Resolution};

/// Fixed, non-secret plaintext the live probe seals and reads back.
///
/// A constant sentinel — never key material — so it is safe to name in an
/// assertion message and safe to round-trip through a real gateway.
const PROBE_PLAINTEXT: &[u8] = b"hippius-mem doctor encryption-boundary probe";

/// Object key the probe writes its sealed sentinel under.
///
/// The leading `_doctor/` segment is disjoint from every real key by shape, not
/// just by convention: note keys are `{team}/{repo}/{mem_id}/ver_{ulid}` (four
/// segments) and op-log keys are `{team}/_oplog/...`, so even a team literally
/// named `_doctor` cannot mint this exact two-segment key. The probe therefore
/// cannot read or clobber a real note or op.
const PROBE_KEY: &str = "_doctor/encryption-boundary-probe";

/// Non-secret outcome of a successful encryption-boundary probe.
///
/// Carries only the sealed byte count — a size, never any key, ciphertext, or
/// plaintext — so it is safe to log. The type deliberately holds no secret so a
/// secret cannot reach a log line even by mistake.
#[derive(Debug, Clone, Copy)]
struct ProbeReport {
    /// Ciphertext bytes written to the gateway (nonce + sealed body + tag).
    bytes_written: usize,
}

/// Run the `doctor` subcommand over the args following `doctor`.
///
/// Loads the config via [`Config::from_env_and_file`] (`HIPPIUS_MEM_CONFIG`,
/// else the cwd-relative default) and delegates to [`run_for_config`]. Callers
/// that already hold a validated [`Config`] — because they just built or wrote
/// it themselves, so re-resolving it from the environment/cwd could pick up a
/// DIFFERENT file — should call [`run_for_config`] directly instead (see
/// `quickstart::probe_fresh_trial`, which must probe the exact bytes it just
/// wrote, not whatever `Config::from_env_and_file` separately resolves).
///
/// # Errors
///
/// Returns an error if an unknown argument is passed, the configuration is
/// missing or malformed, the launch repo routes to no team profile (memory
/// disabled here), or the author identity cannot be derived from
/// `author_seed_hex`.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;

    run_for_config(&cfg, opts.offline).await
}

/// Run the doctor checks against an already-resolved `cfg`, skipping
/// [`Config::from_env_and_file`]'s own env/cwd resolution entirely.
///
/// The profile diagnosed is resolved from the LAUNCH repo's git remote exactly
/// as [`crate::resolver::resolve`] does for the server ([`crate::main`]'s
/// `resolve_and_build_store`) — not the flat/primary profile — so a `[[teams]]`
/// profile whose bucket doesn't match its sub-token's scope is the one probed
/// when standing in that repo, instead of doctor silently checking a different,
/// healthy profile while the real one 403s at runtime (finding [13]). With
/// `offline = true` the check stops after the offline validation; otherwise it
/// runs the live gateway/local-disk probe.
///
/// # Errors
///
/// Returns an error if the launch repo routes to no team profile (memory
/// disabled here), the author identity cannot be derived from
/// `author_seed_hex`, or (unless `offline`) the live probe fails.
pub(crate) async fn run_for_config(cfg: &Config, offline: bool) -> anyhow::Result<()> {
    let profile = resolve_bound_profile(cfg)?;

    // Deriving the signer proves `author_seed_hex` yields a usable sr25519
    // identity and hands us the SS58 to report. The SS58 is bound to the seed by
    // construction (see `Sr25519Signer`), so it is safe, non-secret output.
    let signer = profile
        .signer()
        .context("deriving the author identity from author_seed_hex failed")?;
    let author = signer.author_ss58();

    // `offline_report_lines` is handed only public coordinates — never `&cfg` or
    // `&profile` — so a secret field cannot reach the report even by mistake. The
    // profile name is the first line, so the operator sees WHICH profile this run
    // diagnosed before the coordinates that name resolved to.
    for line in offline_report_lines(
        &profile.name,
        &profile.bucket,
        &profile.access_key_id,
        author.as_str(),
    ) {
        tracing::info!("{line}");
    }

    if offline {
        tracing::info!("offline check passed; skipping live gateway probe");
        return Ok(());
    }

    probe_live(cfg, &profile).await
}

/// Resolve the team profile bound for the current working directory's git
/// remote — the SAME routing [`crate::main`]'s `resolve_and_build_store` uses to
/// pick which profile the server binds, so `doctor` diagnoses exactly the
/// profile the server would.
///
/// Thin: reads the one live seam (the cwd's git remote) and hands off to
/// [`resolve_profile_for_remote`], which carries all the testable logic. Kept
/// separate so a test can drive the routing decision with an explicit `remote`
/// instead of depending on the test runner's own git checkout.
///
/// # Errors
///
/// Returns an error if the repo routes to no team profile (memory disabled for
/// this repo, per [`crate::resolver::DisabledReason`]).
fn resolve_bound_profile(cfg: &Config) -> anyhow::Result<TeamProfile> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let remote = GitRemoteReader.origin_url(&cwd);
    resolve_profile_for_remote(cfg, remote.as_deref())
}

/// Resolve the team profile bound for `remote` (a git `origin` URL, or `None`
/// for no/unreadable remote), the remote-independent half of
/// [`resolve_bound_profile`].
///
/// Returns an owned, cloned [`TeamProfile`] rather than a borrow of
/// [`Config::all_profiles`]'s local `Vec`: that `Vec` is rebuilt fresh on every
/// call and dropped at the end of this function, so a borrow from it cannot
/// outlive the function. `doctor` is a one-shot CLI command resolving exactly
/// one profile, so one small clone (a handful of `String` fields) is simpler
/// and cheaper than restructuring the caller around the borrow's lifetime.
///
/// # Errors
///
/// Returns an error if `remote` routes to no team profile (memory disabled for
/// this repo, per [`crate::resolver::DisabledReason`]).
fn resolve_profile_for_remote(cfg: &Config, remote: Option<&str>) -> anyhow::Result<TeamProfile> {
    let profiles = cfg.all_profiles();
    match resolver::resolve(&profiles, remote) {
        Resolution::Bound(profile) => Ok(profile.clone()),
        Resolution::Disabled(reason) => {
            bail!("team memory is disabled for this repository: {reason}")
        }
    }
}

/// Parsed `doctor` arguments.
struct Options {
    /// Run only the offline bundle validation, skipping the live gateway probe.
    offline: bool,
}

impl Options {
    /// Parse `[--offline]`.
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut offline = false;
        for arg in args {
            match arg.as_str() {
                "--offline" => offline = true,
                other => bail!("unknown doctor argument `{other}`; usage: doctor [--offline]"),
            }
        }
        Ok(Self { offline })
    }
}

/// Build the non-secret lines of the doctor report.
///
/// Takes only the four public coordinates — never `&Config`/`&TeamProfile` — so a
/// secret (`secret`, `team_key_hex`, `author_seed_hex`) is structurally
/// impossible to include in the report this produces. `profile_name` is first so
/// the report always names which profile it diagnosed (finding [13]).
fn offline_report_lines(
    profile_name: &str,
    bucket: &str,
    access_key_id: &str,
    author_ss58: &str,
) -> Vec<String> {
    vec![
        format!("profile: {profile_name}"),
        format!("bucket: {bucket}"),
        format!("access_key_id: {access_key_id}"),
        format!("author_ss58: {author_ss58}"),
    ]
}

/// Run the live encryption-boundary probe against the configured backend.
///
/// Builds the same [`SecretKey`] and blob store the server boots from FOR THE
/// RESOLVED PROFILE — `profile`'s bucket/credentials (or, for
/// [`StorageBackend::Local`], its trial-vault root), not the flat/primary
/// config — then delegates to [`probe_encryption_boundary`]. `s3_endpoint` and
/// `s3_region` are shared coordinates every S3 profile draws from `cfg`
/// (mirrors [`TeamProfile::build_store`]'s split and its storage-backend
/// branch, so this probes the exact store the server would bind). On success
/// it logs a non-secret line carrying only the sealed byte count. Also checks
/// (best-effort) whether this machine's configured `max_epoch` is stale
/// against what the bucket has actually published — see
/// [`stale_max_epoch_line`].
///
/// # Errors
///
/// Returns an error if the team key cannot be derived, the local trial root
/// cannot be resolved (`StorageBackend::Local` with no `local_root` and no
/// `XDG_CACHE_HOME`/`HOME`), or the seal/put/get/open round-trip in
/// [`probe_encryption_boundary`] fails.
async fn probe_live(cfg: &Config, profile: &TeamProfile) -> anyhow::Result<()> {
    let key = profile
        .team_key()
        .context("deriving the team key from team_key_hex failed")?;
    let blob: Arc<dyn BlobStore> = match profile.storage {
        StorageBackend::Local => Arc::new(FsBlobStore::new(
            profile
                .local_trial_root()
                .context("resolving the local trial vault root failed")?,
        )),
        StorageBackend::S3 => Arc::new(S3BlobStore::new(
            cfg.s3_endpoint.clone(),
            profile.bucket.clone(),
            profile.access_key_id.clone(),
            profile.secret.clone(),
            cfg.s3_region.clone(),
        )),
    };

    // A stale `max_epoch` is checked ahead of the encryption probe, and
    // independently of its outcome: it needs no team key, only the bucket
    // listing, so it should still be reported even when the probe below fails.
    if let Some(line) = stale_max_epoch_line(blob.as_ref(), &profile.name, cfg.max_epoch).await {
        tracing::warn!("{line}");
    }

    // Same reasoning as the stale-`max_epoch` check above: no team key
    // needed, only manifest/bucket reads, so it runs and reports
    // independently of the encryption probe's outcome below.
    let founder = profile.founder().ok().flatten();
    for line in
        removed_member_still_holds_key_lines(blob.as_ref(), &profile.name, founder.as_ref()).await
    {
        tracing::warn!("{line}");
    }

    let report = probe_encryption_boundary(blob.as_ref(), &key).await?;

    tracing::info!(
        bytes_written = report.bytes_written,
        "live encryption-boundary probe passed: the probe object was stored as ciphertext and round-tripped"
    );
    Ok(())
}

/// The stale-`max_epoch` report line for `team`, or `None` when nothing is
/// stale.
///
/// Compares `configured_max_epoch` (this machine's bootstrap ceiling) against
/// [`highest_published_epoch`]'s live read of the bucket's `_keys/` prefix: a
/// stale `max_epoch` silently hides every note sealed under a rotated epoch
/// past it (the recorded `bootstrap_epochs` gotcha's warning-side
/// counterpart), so a doctor run is exactly where an operator should learn
/// this before it bites.
///
/// Best-effort: a fetch failure (offline gateway, missing permissions) returns
/// `None` silently rather than surfacing — this check exists to add a hint on
/// top of the load-bearing live probe, never to become a new doctor failure
/// mode of its own.
async fn stale_max_epoch_line(
    blob: &dyn BlobStore,
    team: &str,
    configured_max_epoch: u64,
) -> Option<String> {
    let published = highest_published_epoch(blob, team).await.ok()?;
    if published <= configured_max_epoch {
        return None;
    }
    Some(format!(
        "WARN: max_epoch is stale (configured {configured_max_epoch}, bucket published epoch \
         {published}): raise max_epoch to {published} in the [[teams]] profile or new-epoch \
         notes stay invisible"
    ))
}

/// The "removed member still holds the current epoch key" report lines for
/// `team`: every SS58 the CURRENT epoch's team key is wrapped to (per
/// [`wrapped_key_recipients`] at [`highest_published_epoch`]) that the live
/// membership manifest (per [`load_manifest`]) no longer lists.
///
/// This is the read-side detector for the recorded `rotate --members`
/// non-atomicity gotcha: `publish_membership` can land while `rotate_key`
/// then refuses (typically `MemError::NothingToRotate` because no remaining
/// member has `join`ed yet), leaving a removed member's wrap for the CURRENT
/// epoch on the bucket even though the manifest no longer lists them —
/// `hippius-mem remove` is now resumable and reports this itself on the run
/// that hits it (see `crate::admin::remove`), but a machine that never
/// re-ran `remove`/`rotate` to finish would otherwise carry a silently
/// half-done removal forever. Running this on every `doctor` invocation
/// catches it independent of whether that original run's output was ever
/// seen.
///
/// Best-effort, mirroring [`stale_max_epoch_line`]: an open team (no
/// manifest published — nothing to compare a wrap against) or any read
/// failure yields no lines rather than becoming a new doctor failure mode.
async fn removed_member_still_holds_key_lines(
    blob: &dyn BlobStore,
    team: &str,
    founder: Option<&Ss58>,
) -> Vec<String> {
    let Ok(Some(manifest)) = load_manifest(blob, team, founder).await else {
        return Vec::new();
    };
    // A listing failure here must NOT fall back to epoch 0: epoch 0's
    // recipients are almost certainly stale (superseded by real rotations),
    // so comparing them against the live manifest would flag long-since-
    // removed members as a false "still holds the current epoch key"
    // warning on an otherwise healthy team hitting a storage hiccup. Mirrors
    // `stale_max_epoch_line`'s short-circuit exactly.
    let Ok(epoch) = highest_published_epoch(blob, team).await else {
        return Vec::new();
    };
    let Ok(recipients) = wrapped_key_recipients(blob, team, epoch).await else {
        return Vec::new();
    };

    recipients
        .into_iter()
        .filter(|ss58| !manifest.members.contains(ss58))
        .map(|ss58| {
            format!(
                "WARN: removed member {ss58} still holds the current epoch key; run: \
                 hippius-mem rotate (then revoke their sub-token in the console)",
                ss58 = ss58.as_str(),
            )
        })
        .collect()
}

/// Prove the encryption boundary holds end-to-end against `blob`: seal a known
/// plaintext, store it, read it back, and confirm the gateway only ever saw
/// ciphertext that round-trips to the original.
///
/// `blob` is injected (rather than built inside) so this is a deterministic I/O
/// seam: tests drive it against an in-memory store and against fault-injecting
/// fakes with no live gateway. The probe binds [`PROBE_KEY`] as AAD on both
/// `seal` and `open`, mirroring `MemoryStore::remember`: authenticating the key
/// the bytes live under turns a relocated or swapped ciphertext into an
/// authentication failure rather than a silent content swap.
///
/// Every error and log path here is secret-free by construction — none
/// interpolate `key`, the ciphertext, or the fetched bytes. The only literal
/// bytes named anywhere are the fixed, non-secret [`PROBE_PLAINTEXT`] sentinel.
///
/// # Errors
///
/// Returns an error if sealing fails, the store rejects the write or read, the
/// gateway hands back the plaintext verbatim (the encryption boundary is
/// broken), or the fetched ciphertext does not decrypt back to
/// [`PROBE_PLAINTEXT`].
async fn probe_encryption_boundary(
    blob: &dyn BlobStore,
    key: &SecretKey,
) -> anyhow::Result<ProbeReport> {
    let ciphertext = seal(key, PROBE_PLAINTEXT, PROBE_KEY.as_bytes())
        .context("sealing the probe plaintext failed")?;

    // Defensive guard against a future `seal` regression that forgets to
    // encrypt: the real `seal` always prepends a 24-byte nonce and appends a
    // 16-byte tag, so this can never fire today. The load-bearing boundary
    // check is `fetched != PROBE_PLAINTEXT` below, since `blob` (not `seal`) is
    // the injected, untrusted seam.
    ensure!(
        ciphertext.as_slice() != PROBE_PLAINTEXT,
        "seal returned the plaintext unchanged: the encryption layer is a no-op"
    );

    blob.put(PROBE_KEY, ciphertext.clone())
        .await
        .context("storing the probe ciphertext failed")?;

    // Read back first, then delete unconditionally: the probe must never leave
    // its object behind, even when a check below fails and returns early. Delete
    // is idempotent and best-effort, so its failure must not fail the probe — but
    // a genuine transport/permission fault leaves the sentinel object behind, so
    // log it (MemError is secret-free) to aid diagnosis.
    let fetched = blob.get(PROBE_KEY).await;
    if let Err(err) = blob.delete(PROBE_KEY).await {
        tracing::debug!(%err, "probe cleanup delete failed; sentinel object may remain");
    }
    let fetched = fetched.context("fetching the probe ciphertext back failed")?;

    ensure!(
        fetched.as_slice() != PROBE_PLAINTEXT,
        "the gateway returned plaintext — only ciphertext must ever be stored"
    );

    let opened = open(key, &fetched, PROBE_KEY.as_bytes())
        .context("decrypting the probe ciphertext failed")?;
    ensure!(
        opened.as_slice() == PROBE_PLAINTEXT,
        "decrypted probe bytes did not round-trip to the known plaintext"
    );

    Ok(ProbeReport {
        bytes_written: ciphertext.len(),
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success/failure of Result-returning probe steps"
    )]
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
    )]

    use std::collections::BTreeSet;

    use hippius_mem_core::{
        BlobStore, MemError, MemberKey, MemoryBlobStore, NetworkPrefix, SecretKey, TeamManifest,
        derive_identity, provision_team_key, publish_manifest, seal, signer_from_mnemonic,
    };

    use super::{
        PROBE_KEY, PROBE_PLAINTEXT, offline_report_lines, probe_encryption_boundary, probe_live,
        removed_member_still_holds_key_lines, resolve_profile_for_remote, stale_max_epoch_line,
    };
    use crate::config::{Config, StorageBackend};

    /// A [`BlobStore`] fake whose `get` returns whatever bytes the test seeded,
    /// independent of what was `put`. It models a gateway that violated the
    /// encryption boundary — returning plaintext or corrupted ciphertext — which
    /// a faithful store would never do, so only an injected fake can exercise
    /// those failure paths.
    struct CannedGetStore {
        /// Bytes every `get` hands back, regardless of key.
        canned: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl BlobStore for CannedGetStore {
        async fn put(&self, _key: &str, _bytes: Vec<u8>) -> Result<(), MemError> {
            Ok(())
        }

        async fn get(&self, _key: &str) -> Result<Vec<u8>, MemError> {
            Ok(self.canned.clone())
        }

        async fn list(&self, _prefix: &str) -> Result<Vec<String>, MemError> {
            Ok(Vec::new())
        }

        async fn delete(&self, _key: &str) -> Result<(), MemError> {
            Ok(())
        }
    }

    #[test]
    fn report_contains_the_four_non_secret_coordinates() {
        let lines = offline_report_lines(
            "clientx",
            "team-bucket",
            "AKIAEXAMPLE",
            "5GExampleSs58Address",
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("profile: clientx"),
            "report must name the diagnosed profile: {joined}"
        );
        assert!(
            joined.contains("team-bucket"),
            "report must name the bucket: {joined}"
        );
        assert!(
            joined.contains("AKIAEXAMPLE"),
            "report must name the access_key_id: {joined}"
        );
        assert!(
            joined.contains("5GExampleSs58Address"),
            "report must name the author SS58: {joined}"
        );
    }

    /// A minimal valid multi-profile config: primary is the catch-all
    /// (`ourovoros`), plus one org-routed `clientx` profile with a DIFFERENT
    /// bucket. Mirrors `config.rs`'s `valid_toml`/`team_block` fixtures.
    fn multi_profile_toml() -> String {
        "bucket = \"primary-bucket\"\n\
         access_key_id = \"AKID\"\n\
         secret = \"s3-sub-token-secret\"\n\
         team = \"ourovoros\"\n\
         team_key_hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n\
         author_seed_hex = \"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\"\n\
         \n\
         [[teams]]\n\
         name = \"clientx\"\n\
         orgs = [\"github.com/clientx\"]\n\
         bucket = \"clientx-bucket\"\n\
         access_key_id = \"AK-clientx\"\n\
         secret = \"s3-sub-token-secret\"\n\
         team_key_hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n\
         author_seed_hex = \"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\"\n"
            .to_owned()
    }

    #[test]
    fn resolve_profile_for_remote_routes_by_remote_not_the_primary() {
        // The bug this fixes: doctor used to always validate/probe the flat
        // PRIMARY profile (`cfg.signer()`/`cfg.bucket` etc.), never a `[[teams]]`
        // profile, so a repo routed to `clientx` would have its `clientx-bucket`
        // never checked even though that is the bucket the server actually binds
        // there (finding [13]).
        let cfg = Config::from_toml_str(&multi_profile_toml()).expect("valid multi-profile config");
        let profile = resolve_profile_for_remote(&cfg, Some("git@github.com:clientx/app.git"))
            .expect("clientx repo routes to a bound profile");
        assert_eq!(profile.name, "clientx");
        assert_eq!(
            profile.bucket, "clientx-bucket",
            "doctor must probe the CLIENTX bucket for a clientx repo, not the primary's"
        );
    }

    #[test]
    fn resolve_profile_for_remote_falls_back_to_the_catch_all() {
        // A repo whose remote matches no `orgs` still routes to the primary
        // (the effective catch-all here), exactly as the server would.
        let cfg = Config::from_toml_str(&multi_profile_toml()).expect("valid multi-profile config");
        let profile = resolve_profile_for_remote(&cfg, Some("git@github.com:someoneelse/x.git"))
            .expect("unmatched repo falls back to the catch-all");
        assert_eq!(profile.name, "ourovoros");
        assert_eq!(profile.bucket, "primary-bucket");
    }

    #[test]
    fn resolve_profile_for_remote_errors_when_memory_is_disabled() {
        // A single org-scoped profile with no catch-all: an unmatched remote must
        // surface an error naming the disabled reason, not silently fall back to
        // validating an unrelated profile.
        let toml = "bucket = \"b\"\n\
             access_key_id = \"AK\"\n\
             secret = \"s\"\n\
             team = \"ourovoros\"\n\
             team_key_hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n\
             author_seed_hex = \"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\"\n\
             orgs = [\"github.com/ourovoros\"]\n";
        let cfg = Config::from_toml_str(toml).expect("valid config");
        let err = resolve_profile_for_remote(&cfg, Some("git@github.com:someoneelse/x.git"))
            .expect_err("an unmatched repo with no catch-all must be disabled, not routed");
        assert!(
            err.to_string().contains("disabled"),
            "error must name the disabled reason: {err}"
        );
    }

    #[tokio::test]
    async fn probe_round_trips_over_clean_store() {
        let blob = MemoryBlobStore::default();
        let key = SecretKey::from_bytes([7u8; 32]);

        let report = probe_encryption_boundary(&blob, &key)
            .await
            .expect("probe must succeed over a faithful store");

        assert!(
            report.bytes_written > 0,
            "probe must report the sealed byte count"
        );
        // The probe deletes its object regardless of outcome, so a clean store is
        // empty again afterwards: a follow-up `get` must miss.
        let leftover = blob.get(PROBE_KEY).await;
        assert!(
            matches!(leftover, Err(MemError::NotFound { .. })),
            "probe must clean up its object, got {leftover:?}"
        );
    }

    #[tokio::test]
    async fn probe_rejects_a_store_that_returns_plaintext() {
        let blob = CannedGetStore {
            canned: PROBE_PLAINTEXT.to_vec(),
        };
        let key = SecretKey::from_bytes([7u8; 32]);

        let err = probe_encryption_boundary(&blob, &key)
            .await
            .expect_err("a gateway returning plaintext must fail the probe");

        // Assert it failed at the plaintext-leak check specifically, not merely
        // that some error occurred (e.g. a spurious decrypt failure would also
        // be an error but would mean the test is not exercising this boundary).
        assert!(
            err.to_string().contains("returned plaintext"),
            "expected the plaintext-leak failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn probe_rejects_a_store_that_corrupts_ciphertext() {
        let key = SecretKey::from_bytes([7u8; 32]);
        // Seal a valid blob, then flip a tag byte so `open`'s authentication
        // fails — the corruption path, distinct from the plaintext-leak path.
        let mut corrupted = seal(&key, PROBE_PLAINTEXT, PROBE_KEY.as_bytes())
            .expect("sealing the fixed probe plaintext is infallible here");
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xFF;
        let blob = CannedGetStore { canned: corrupted };

        let err = probe_encryption_boundary(&blob, &key)
            .await
            .expect_err("corrupted ciphertext must fail the round-trip");

        // Assert it failed at the `open` (decrypt) step specifically: the
        // corrupted bytes pass the `fetched != PROBE_PLAINTEXT` check but must
        // fail authentication, so the error must come from decrypting.
        assert!(
            err.to_string().contains("decrypting"),
            "expected the decrypt failure, got: {err}"
        );
    }

    /// A `storage = "local"` profile's live probe must bind an `FsBlobStore`
    /// over its trial root, never the `S3BlobStore` an S3 profile uses — the
    /// bug this pins: `probe_live` used to build an `S3BlobStore`
    /// unconditionally, so a fresh trial vault's doctor probe (no bucket, no
    /// credentials) failed against the real gateway instead of succeeding
    /// against local disk.
    #[tokio::test]
    async fn probe_live_uses_fs_blob_store_for_a_local_profile() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = Config {
            team: "trial".to_owned(),
            team_key_hex: "ab".repeat(32),
            author_seed_hex: "cd".repeat(32),
            storage: StorageBackend::Local,
            local_root: Some(dir.path().to_path_buf()),
            ..Config::default()
        };
        let profile = cfg.primary_profile();

        probe_live(&cfg, &profile).await?;

        // The probe cleans up after itself; the trial root gains only the
        // `_doctor/` directory the probe created, no leftover object.
        assert!(
            !dir.path().join(PROBE_KEY).exists(),
            "the probe object must not remain on disk"
        );
        Ok(())
    }

    /// The doctor-surface test for the stale-`max_epoch` warning: a store
    /// holding an epoch-1 wrapped key against a configured `max_epoch = 0`
    /// must produce a report line telling the operator to raise it to 1.
    #[tokio::test]
    async fn stale_max_epoch_line_warns_when_the_bucket_holds_a_newer_epoch() -> Result<(), MemError>
    {
        const TEAM: &str = "clientx";
        const PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

        let blob = MemoryBlobStore::default();

        // Publish a wrapped key at epoch 1 via the real teamkey publish path
        // (`provision_team_key`), exactly how a rotation populates the bucket.
        let signer = signer_from_mnemonic(PHRASE, NetworkPrefix::HIPPIUS)?;
        let identity = derive_identity(PHRASE, NetworkPrefix::HIPPIUS)?;
        let member = MemberKey::create_signed(&signer, &identity);
        let team_key = SecretKey::from_bytes([1u8; 32]);
        provision_team_key(&blob, TEAM, &team_key, 1, &[member], None).await?;

        // Configured max_epoch = 0 never bootstraps the epoch-1 rotation: the
        // report must warn, naming the exact fix.
        let line = stale_max_epoch_line(&blob, TEAM, 0)
            .await
            .expect("a published epoch newer than max_epoch must produce a warning line");
        assert!(
            line.contains("raise max_epoch to 1"),
            "report line must name the actionable fix: {line}"
        );

        // A max_epoch that already covers the published epoch is not stale.
        assert!(
            stale_max_epoch_line(&blob, TEAM, 1).await.is_none(),
            "max_epoch at or above the highest published epoch must not warn"
        );
        Ok(())
    }

    /// The doctor-surface test for the "removed member still holds the
    /// current epoch key" check: a member wrapped the CURRENT epoch's team
    /// key whom the live manifest no longer lists must produce a warning
    /// naming them and the fix — the read-side symptom of the recorded
    /// `rotate --members` non-atomicity gotcha (publish lands, rotation
    /// refuses, and nobody ever finishes the rotation).
    #[tokio::test]
    async fn removed_member_still_holds_key_lines_warns_and_names_the_fix() -> Result<(), MemError>
    {
        const TEAM: &str = "clientx";
        const FOUNDER_PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        const REMOVED_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                       abandon abandon abandon abandon about";

        let blob = MemoryBlobStore::default();
        let founder_signer = signer_from_mnemonic(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;

        // v0: the roster includes the member who will be removed, so
        // provisioning them the epoch-0 key is authorized.
        let removed_identity = derive_identity(REMOVED_PHRASE, NetworkPrefix::HIPPIUS)?;
        let removed_signer = signer_from_mnemonic(REMOVED_PHRASE, NetworkPrefix::HIPPIUS)?;
        let removed_key = MemberKey::create_signed(&removed_signer, &removed_identity);
        let manifest_v0 = TeamManifest::create_signed(
            &founder_signer,
            TEAM.to_owned(),
            BTreeSet::from([removed_identity.ss58.clone()]),
            0,
        );
        publish_manifest(&blob, &manifest_v0).await?;

        let team_key = SecretKey::from_bytes([3u8; 32]);
        provision_team_key(&blob, TEAM, &team_key, 0, &[removed_key], None).await?;

        // v1: the founder publishes a shrunk roster (the `remove` half that
        // landed) -- but the epoch-0 key was never rotated to a fresh epoch,
        // so the wrap above is still on the bucket at the CURRENT (highest
        // published) epoch.
        let manifest_v1 =
            TeamManifest::create_signed(&founder_signer, TEAM.to_owned(), BTreeSet::new(), 1);
        publish_manifest(&blob, &manifest_v1).await?;

        let lines = removed_member_still_holds_key_lines(&blob, TEAM, None).await;
        assert_eq!(
            lines.len(),
            1,
            "exactly the one stale wrap must be flagged: {lines:?}"
        );
        assert!(
            lines[0].contains(removed_identity.ss58.as_str())
                && lines[0].contains("run: hippius-mem rotate"),
            "the line names the stale member and the fix: {}",
            lines[0]
        );
        Ok(())
    }

    /// An open team (no manifest published yet) has no roster to compare a
    /// wrap against, so the check must stay silent rather than flag every
    /// wrap as "removed" -- it never applies before a manifest exists.
    #[tokio::test]
    async fn removed_member_still_holds_key_lines_is_silent_on_an_open_team() -> Result<(), MemError>
    {
        let blob = MemoryBlobStore::default();
        assert!(
            removed_member_still_holds_key_lines(&blob, "clientx", None)
                .await
                .is_empty(),
            "an open team (no manifest) must never be flagged"
        );
        Ok(())
    }

    /// A [`BlobStore`] wrapper whose `list` fails for exactly the TOP-LEVEL
    /// `_keys/` prefix — what `highest_published_epoch` reads — while a
    /// per-epoch `_keys/{epoch}/` listing (what `wrapped_key_recipients`
    /// reads) and everything else delegate untouched. Deliberately does NOT
    /// fail every `_keys/`-containing prefix: that would make
    /// `wrapped_key_recipients` fail too, which would ALSO yield an empty
    /// result via the function's second short-circuit regardless of whether
    /// the first one (I1's fix) is present — masking the exact bug this
    /// pins. Failing only the top-level listing isolates the one behavior
    /// under test: does a failed EPOCH lookup fall back to a hardcoded `0`?
    struct FailingTopLevelKeysListStore {
        inner: MemoryBlobStore,
        /// The exact prefix `highest_published_epoch` lists (`{team}/_keys/`);
        /// only this one fails.
        failing_prefix: String,
    }

    #[async_trait::async_trait]
    impl BlobStore for FailingTopLevelKeysListStore {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            if prefix == self.failing_prefix {
                return Err(MemError::Storage("simulated listing failure".to_owned()));
            }
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// I1 regression: a listing failure on the EPOCH lookup must not fall
    /// back to comparing the manifest against epoch 0's recipients. This is
    /// the precise reason that fallback is dangerous, not merely a
    /// hypothetical: epoch 0 here holds a genuinely STALE member — one a
    /// REAL prior rotation already excluded from epoch 1, the true current
    /// epoch, which matches the live manifest exactly (a healthy team). If
    /// the epoch lookup's failure were papered over with `0`, this stale,
    /// properly-rotated-away member would be wrongly flagged as still
    /// holding the CURRENT epoch key.
    #[tokio::test]
    async fn removed_member_still_holds_key_lines_is_silent_on_an_epoch_lookup_failure()
    -> Result<(), MemError> {
        const TEAM: &str = "clientx";
        const FOUNDER_PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        const STALE_PHRASE: &str = "letter advice cage absurd amount doctor acoustic avoid \
                                     letter advice cage above";

        let blob = FailingTopLevelKeysListStore {
            inner: MemoryBlobStore::default(),
            failing_prefix: format!("{TEAM}/_keys/"),
        };
        let founder_signer = signer_from_mnemonic(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;
        let founder_identity = derive_identity(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;
        let founder_key = MemberKey::create_signed(&founder_signer, &founder_identity);
        let stale_signer = signer_from_mnemonic(STALE_PHRASE, NetworkPrefix::HIPPIUS)?;
        let stale_identity = derive_identity(STALE_PHRASE, NetworkPrefix::HIPPIUS)?;
        let stale_key = MemberKey::create_signed(&stale_signer, &stale_identity);

        // Epoch 0 (stale history): both wrapped. Epoch 1 (the TRUE current
        // epoch, after a real prior rotation): the founder only.
        provision_team_key(
            &blob,
            TEAM,
            &SecretKey::from_bytes([1u8; 32]),
            0,
            &[founder_key.clone(), stale_key],
            None,
        )
        .await?;
        provision_team_key(
            &blob,
            TEAM,
            &SecretKey::from_bytes([2u8; 32]),
            1,
            std::slice::from_ref(&founder_key),
            None,
        )
        .await?;

        // The live manifest matches epoch 1 exactly: a healthy team with
        // nothing to flag, IF the epoch lookup succeeds.
        let manifest =
            TeamManifest::create_signed(&founder_signer, TEAM.to_owned(), BTreeSet::new(), 0);
        publish_manifest(&blob, &manifest).await?;

        assert!(
            removed_member_still_holds_key_lines(&blob, TEAM, None)
                .await
                .is_empty(),
            "an epoch-lookup failure must yield no lines -- falling back to epoch 0 would \
             wrongly flag the STALE (properly-rotated-away) member as still holding the \
             CURRENT epoch's key"
        );
        Ok(())
    }
}
