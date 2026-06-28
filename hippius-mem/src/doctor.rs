//! The `hippius-mem doctor` subcommand: validate a memory-key bundle.
//!
//! Loads the same [`Config`] the server boots from and reports the non-secret
//! coordinates (bucket, `access_key_id`, author SS58), so an operator can confirm
//! a bundle is well-formed before starting the server. Secrets (`secret`,
//! `team_key_hex`, `author_seed_hex`) are never logged.

use anyhow::{Context, bail, ensure};
use hippius_mem_core::{BlobStore, S3BlobStore, SecretKey, Signer, open, seal};

use crate::config::Config;

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
/// Loading [`Config::from_env_and_file`] already validates the bundle (required
/// fields present, `team_key_hex` and `author_seed_hex` each decode to 32 bytes),
/// so a malformed bundle fails here with a precise `ConfigError`. With `--offline`
/// the check stops after the offline validation; otherwise it runs the live
/// gateway probe.
///
/// # Errors
///
/// Returns an error if an unknown argument is passed, the configuration is
/// missing or malformed, or the author identity cannot be derived from
/// `author_seed_hex`.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;

    // Deriving the signer proves `author_seed_hex` yields a usable sr25519
    // identity and hands us the SS58 to report. The SS58 is bound to the seed by
    // construction (see `Sr25519Signer`), so it is safe, non-secret output.
    let signer = cfg
        .signer()
        .context("deriving the author identity from author_seed_hex failed")?;
    let author = signer.author_ss58();

    // `offline_report_lines` is handed only the three public coordinates — never
    // `&cfg` — so a secret field cannot reach the report even by mistake.
    for line in offline_report_lines(&cfg.bucket, &cfg.access_key_id, author.as_str()) {
        tracing::info!("{line}");
    }

    if opts.offline {
        tracing::info!("offline check passed; skipping live gateway probe");
        return Ok(());
    }

    probe_live(&cfg).await
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
/// Takes only the three public coordinates — never `&Config` — so a secret
/// (`secret`, `team_key_hex`, `author_seed_hex`) is structurally impossible to
/// include in the report this produces.
fn offline_report_lines(bucket: &str, access_key_id: &str, author_ss58: &str) -> Vec<String> {
    vec![
        format!("bucket: {bucket}"),
        format!("access_key_id: {access_key_id}"),
        format!("author_ss58: {author_ss58}"),
    ]
}

/// Run the live encryption-boundary probe against the configured gateway.
///
/// Builds the same [`SecretKey`] and [`S3BlobStore`] the server boots from, then
/// delegates to [`probe_encryption_boundary`]. On success it logs a non-secret
/// line carrying only the sealed byte count.
///
/// # Errors
///
/// Returns an error if the team key cannot be derived, or if the
/// seal/put/get/open round-trip in [`probe_encryption_boundary`] fails.
async fn probe_live(cfg: &Config) -> anyhow::Result<()> {
    let key = cfg
        .team_key()
        .context("deriving the team key from team_key_hex failed")?;
    let blob = S3BlobStore::new(
        cfg.s3_endpoint.clone(),
        cfg.bucket.clone(),
        cfg.access_key_id.clone(),
        cfg.secret.clone(),
        cfg.s3_region.clone(),
    );

    let report = probe_encryption_boundary(&blob, &key).await?;

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

    use hippius_mem_core::{BlobStore, MemError, MemoryBlobStore, SecretKey, seal};

    use super::{PROBE_KEY, PROBE_PLAINTEXT, offline_report_lines, probe_encryption_boundary};

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
    fn report_contains_the_three_non_secret_coordinates() {
        let lines = offline_report_lines("team-bucket", "AKIAEXAMPLE", "5GExampleSs58Address");
        let joined = lines.join("\n");
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
}
