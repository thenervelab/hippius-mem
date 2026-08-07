//! The `hippius-mem doctor` subcommand: validate a memory-key bundle.
//!
//! Loads the same [`Config`] the server boots from and reports the non-secret
//! coordinates (bucket, `access_key_id`, author SS58), so an operator can confirm
//! a bundle is well-formed before starting the server. Secrets (`secret`,
//! `team_key_hex`, `author_seed_hex`) are never logged.

use std::sync::Arc;

use anyhow::{Context, bail, ensure};
use hippius_mem_core::{BlobStore, FsBlobStore, S3BlobStore, SecretKey, Signer, open, seal};

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
/// Loading [`Config::from_env_and_file`] already validates every profile
/// (required fields present, `team_key_hex` and `author_seed_hex` each decode to
/// 32 bytes), so a malformed bundle fails here with a precise `ConfigError`. The
/// profile diagnosed is then resolved from the LAUNCH repo's git remote exactly
/// as [`crate::resolver::resolve`] does for the server ([`crate::main`]'s
/// `resolve_and_build_store`) — not the flat/primary profile — so a `[[teams]]`
/// profile whose bucket doesn't match its sub-token's scope is the one probed
/// when standing in that repo, instead of doctor silently checking a different,
/// healthy profile while the real one 403s at runtime (finding [13]). With
/// `--offline` the check stops after the offline validation; otherwise it runs
/// the live gateway probe.
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

    let profile = resolve_bound_profile(&cfg)?;

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

    if opts.offline {
        tracing::info!("offline check passed; skipping live gateway probe");
        return Ok(());
    }

    probe_live(&cfg, &profile).await
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
/// it logs a non-secret line carrying only the sealed byte count.
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

    let report = probe_encryption_boundary(blob.as_ref(), &key).await?;

    tracing::info!(
        bytes_written = report.bytes_written,
        "live encryption-boundary probe passed: the probe object was stored as ciphertext and round-tripped"
    );
    Ok(())
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

    use hippius_mem_core::{BlobStore, MemError, MemoryBlobStore, SecretKey, seal};

    use super::{
        PROBE_KEY, PROBE_PLAINTEXT, offline_report_lines, probe_encryption_boundary, probe_live,
        resolve_profile_for_remote,
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
}
