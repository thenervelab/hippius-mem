//! `doctor`'s live probe against a REAL S3 endpoint.
//!
//! `doctor` is the command the onboarding funnel tells every new customer to
//! run, and its live probe is what turns "the config parses" into "this machine
//! can actually reach the bucket and the bytes there are ciphertext". Only the
//! [`hippius_mem_core::FsBlobStore`] half of that probe had coverage: the
//! in-crate `probe_live_uses_fs_blob_store_for_a_local_profile` regression test
//! pins the `storage = "local"` branch, and the fault-injecting `BlobStore`
//! fakes in `src/doctor.rs` never open a socket. The `storage = "s3"` branch —
//! endpoint, sub-token credentials, and the `aws-sdk-s3` client underneath —
//! ran against nothing.
//!
//! Both tests drive the REAL binary over a real config file, following
//! `tests/upgrade_cli.rs`'s harness shape (isolated `HIPPIUS_MEM_CONFIG` and
//! `HOME`, every inherited `XDG_*`/state override removed) and reading the
//! destination from the SAME environment contract as
//! `hippius-mem-core/tests/blob_contract.rs`, so one `MinIO` job configures all
//! three suites. `#[ignore]`d, and run by the `MinIO` job in
//! `.github/workflows/rust.yml`.
//!
//! The second test is the one that matters. A `doctor` that reports healthy
//! when it cannot reach the bucket is worse than no `doctor` at all, because a
//! clean report reads as evidence — so it asserts on what the operator actually
//! sees, not merely on the exit status.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use std::process::Command;

use anyhow::Context as _;

/// The team namespace both tests diagnose.
///
/// Fixed rather than per-run unique, and it needs no cleanup: `doctor` only
/// READS this team's prefix (`_keys/`, `_manifest/`, `_oplog/`), and the one
/// object its probe writes is the non-team-scoped sentinel the probe deletes
/// again before returning.
const TEAM: &str = "hippius-mem-doctor-live";

/// 64 hex chars decoding to 32 bytes — valid team-key/seed material.
fn hex64(byte: &str) -> String {
    byte.repeat(32)
}

/// The live endpoint coordinates, read from the same environment contract
/// `hippius-mem/tests/upgrade_cli.rs` and `hippius-mem-core/tests/blob_contract.rs`
/// use, so one `MinIO` job configures every live suite. Only the bucket has no
/// default: a wrong guess would write into a bucket the operator did not create
/// for this test.
struct LiveEndpoint {
    endpoint: String,
    bucket: String,
    access_key_id: String,
    secret: String,
    region: String,
}

impl LiveEndpoint {
    /// # Errors
    ///
    /// Returns an error if `HIPPIUS_MEM_TEST_BUCKET` is unset.
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            endpoint: std::env::var("HIPPIUS_MEM_TEST_S3_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:9000".to_owned()),
            bucket: std::env::var("HIPPIUS_MEM_TEST_BUCKET").context(
                "set HIPPIUS_MEM_TEST_BUCKET to a bucket that already exists on the endpoint",
            )?,
            access_key_id: std::env::var("HIPPIUS_MEM_TEST_ACCESS_KEY_ID")
                .unwrap_or_else(|_| "test".to_owned()),
            secret: std::env::var("HIPPIUS_MEM_TEST_SECRET")
                .unwrap_or_else(|_| "testtest1".to_owned()),
            region: std::env::var("HIPPIUS_MEM_TEST_S3_REGION")
                .unwrap_or_else(|_| "us-east-1".to_owned()),
        })
    }

    /// A flat single-profile `storage = "s3"` config pointed at this endpoint,
    /// signing with `secret` — which the failure test deliberately corrupts.
    fn config_toml(&self, secret: &str) -> String {
        format!(
            "s3_endpoint = \"{endpoint}\"\ns3_region = \"{region}\"\n\
             bucket = \"{bucket}\"\naccess_key_id = \"{access_key_id}\"\nsecret = \"{secret}\"\n\
             team = \"{TEAM}\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n",
            endpoint = self.endpoint,
            region = self.region,
            bucket = self.bucket,
            access_key_id = self.access_key_id,
            key = hex64("ab"),
            seed = hex64("cd"),
        )
    }
}

/// Write `toml` to a config file under `dir` and run the real `hippius-mem
/// doctor` binary against it.
///
/// `HOME` is redirected into `dir` and every inherited state/cache override is
/// removed, so a run touches no directory outside the temporary one — the same
/// isolation `tests/upgrade_cli.rs` applies. `RUST_LOG` is pinned to `info`
/// because the report lines these tests assert on are `tracing::info!` records:
/// a developer's inherited `RUST_LOG=warn` would otherwise hide them and turn a
/// passing binary into a failing test.
fn run_doctor(dir: &std::path::Path, toml: &str) -> anyhow::Result<std::process::Output> {
    let config_path = dir.join("hippius-mem.toml");
    std::fs::write(&config_path, toml)?;

    Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .arg("doctor")
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", dir)
        .env("RUST_LOG", "info")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("HIPPIUS_MEM_CACHE_DIR")
        .env_remove("HIPPIUS_MEM_STATE_DIR")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_STATE_HOME")
        .output()
        .map_err(anyhow::Error::from)
}

/// The happy path the onboarding funnel promises: against a reachable bucket
/// with working sub-token credentials, `doctor` runs its live probe to
/// completion, reports the profile it diagnosed, and exits zero.
///
/// Diagnostics go to stderr (stdout carries the MCP protocol), so that is where
/// the report is asserted.
#[test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
fn doctor_probes_a_live_s3_profile_and_reports_healthy() -> anyhow::Result<()> {
    let dest = LiveEndpoint::from_env()?;
    let dir = tempfile::tempdir()?;

    let output = run_doctor(dir.path(), &dest.config_toml(&dest.secret))?;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "doctor must exit zero against a reachable bucket: {stderr}"
    );
    assert!(
        stderr.contains("live encryption-boundary probe passed"),
        "the operator must be told the live probe ran and passed: {stderr}"
    );

    // The report must also name WHAT it diagnosed: a healthy verdict over an
    // unnamed profile leaves an operator unable to tell which of several
    // profiles was actually reached.
    assert!(
        stderr.contains(&format!("profile: {TEAM}")),
        "the report must name the profile it diagnosed: {stderr}"
    );
    assert!(
        stderr.contains(&format!("bucket: {}", dest.bucket)),
        "the report must name the bucket it reached: {stderr}"
    );
    Ok(())
}

/// The failure that matters: with the sub-token secret corrupted, the gateway
/// rejects the probe write, and `doctor` must FAIL LOUDLY rather than let the
/// four offline coordinate lines it has already printed read as a clean bill of
/// health.
///
/// Asserted on the operator-visible output, not merely the exit status: the
/// absence of the "probe passed" line is the assertion that a check reporting
/// healthy over a real fault would break, and this branch has already produced
/// two such checks. The rejected secret must also stay out of the diagnostics,
/// matching the argv/stdin secret hygiene `upgrade` is held to.
#[test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
fn doctor_fails_loudly_when_the_s3_credential_is_wrong() -> anyhow::Result<()> {
    let dest = LiveEndpoint::from_env()?;
    let dir = tempfile::tempdir()?;

    let wrong_secret = "not-the-sub-token-secret";
    let output = run_doctor(dir.path(), &dest.config_toml(wrong_secret))?;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "doctor must exit non-zero when the credential is rejected: {stderr}"
    );
    assert!(
        !stderr.contains("live encryption-boundary probe passed"),
        "doctor must never report the probe passed when the bucket rejected it: {stderr}"
    );

    // Naming the failed step, not just failing: the operator has to know the
    // probe WRITE was refused (a credential/permission fault) rather than, say,
    // the config failing to parse.
    assert!(
        stderr.contains("storing the probe ciphertext failed"),
        "the failure must name the step that failed: {stderr}"
    );
    assert!(
        stderr.contains("SignatureDoesNotMatch") || stderr.contains("403"),
        "the failure must carry the gateway's own rejection so the cause is diagnosable: {stderr}"
    );
    assert!(
        !stderr.contains(wrong_secret),
        "the rejected secret must never be echoed into the diagnostics: {stderr}"
    );
    Ok(())
}
