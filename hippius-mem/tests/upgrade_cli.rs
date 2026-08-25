//! `upgrade` flips a `quickstart` trial profile to S3 after copying its
//! objects.
//!
//! Modeled on `tests/quickstart_cli.rs` and `tests/join_bundle_cli.rs`: the
//! real binary, the real filesystem, and a piped stdin for the secret (the
//! flow reads it from stdin when stdin is not a terminal; `Stdio::piped()`
//! guarantees that regardless of whether the test runner itself is
//! interactive). The offline refusals and the argv/stdin secret-hygiene
//! contract run unconditionally; the copy invariant itself is exercised
//! offline at the core layer (`hippius-mem-core/tests/e2e_store_copy.rs`).
//! The CLI happy path additionally needs a live S3-compatible endpoint —
//! see `upgrade_round_trips_two_notes_through_a_live_minio_bucket` below,
//! `#[ignore = "needs docker"]`d following the pattern named in
//! `docs/plans/2026-07-12-external-adoption-program.md` Task 0.3.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use std::io::Write as _;
use std::process::{Command, Stdio};

use anyhow::Context as _;

/// 64 hex chars decoding to 32 bytes — valid team-key/seed material.
fn hex64(byte: &str) -> String {
    byte.repeat(32)
}

/// Run `hippius-mem upgrade <extra>` with `secret` piped on stdin, against
/// an isolated `HIPPIUS_MEM_CONFIG`/`HOME`.
fn run_upgrade(
    config_path: &std::path::Path,
    home: &std::path::Path,
    extra: &[&str],
    secret: &str,
) -> anyhow::Result<std::process::Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .arg("upgrade")
        .args(extra)
        .env("HIPPIUS_MEM_CONFIG", config_path)
        .env("HOME", home)
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("stdin was piped"))?
        .write_all(format!("{secret}\n").as_bytes())?;
    child.wait_with_output().map_err(anyhow::Error::from)
}

#[test]
fn upgrade_refuses_a_non_local_profile() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");
    let before = format!(
        "team = \"trial\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n\
         bucket = \"old-bucket\"\naccess_key_id = \"AK\"\nsecret = \"s\"\n",
        key = hex64("ab"),
        seed = hex64("cd"),
    );
    std::fs::write(&config_path, &before)?;

    let output = run_upgrade(
        &config_path,
        dir.path(),
        &["--bucket", "new-bucket", "--access-key-id", "new-ak"],
        "new-secret",
    )?;

    assert!(
        !output.status.success(),
        "an already-s3 profile must refuse upgrade"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no local trial vault"),
        "the refusal must say there is no trial vault to upgrade: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&config_path)?,
        before,
        "a refused upgrade must leave the config byte-identical"
    );
    Ok(())
}

#[test]
fn upgrade_refuses_a_multi_profile_config() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");
    let before = format!(
        "team = \"trial\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n\
         storage = \"local\"\n\
         \n[[teams]]\nname = \"acme\"\norgs = [\"github.com/acme\"]\nbucket = \"b\"\n\
         access_key_id = \"ak\"\nsecret = \"s\"\nteam_key_hex = \"{key}\"\n\
         author_seed_hex = \"{seed}\"\n",
        key = hex64("ab"),
        seed = hex64("cd"),
    );
    std::fs::write(&config_path, &before)?;

    let output = run_upgrade(
        &config_path,
        dir.path(),
        &["--bucket", "new-bucket", "--access-key-id", "new-ak"],
        "new-secret",
    )?;

    assert!(
        !output.status.success(),
        "a multi-profile config must refuse upgrade"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("edit the config"),
        "the refusal must point at editing the config manually: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&config_path)?,
        before,
        "a refused upgrade must leave the config byte-identical (the in-place rewrite only \
         supports the single-profile shape quickstart creates)"
    );
    Ok(())
}

/// Finding #5: a persisted `local_root` that does not exist on disk must
/// abort upgrade BEFORE any copy or config rewrite — never silently copy 0
/// objects and still flip the config to point at the new bucket, which would
/// strand any real notes at whatever path they actually live under.
#[test]
fn upgrade_aborts_when_the_persisted_trial_root_does_not_exist() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");
    // Never created: this is exactly the "wrong environment resolved a
    // directory nothing was ever written to" scenario the fix guards.
    let missing_root = dir.path().join("never-created-vault");
    let before = format!(
        "team = \"trial\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n\
         storage = \"local\"\nlocal_root = \"{root}\"\n",
        key = hex64("ab"),
        seed = hex64("cd"),
        root = missing_root.display(),
    );
    std::fs::write(&config_path, &before)?;

    let output = run_upgrade(
        &config_path,
        dir.path(),
        &["--bucket", "new-bucket", "--access-key-id", "new-ak"],
        "new-secret",
    )?;

    assert!(
        !output.status.success(),
        "a missing persisted local_root must refuse upgrade"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist"),
        "the refusal must say the vault does not exist: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&config_path)?,
        before,
        "an aborted upgrade must leave the config byte-identical — never copy 0 objects and \
         still flip storage to \"s3\""
    );
    Ok(())
}

#[test]
fn upgrade_reads_secret_from_stdin_not_argv() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    // Never created: the second half of this test hits the "no config"
    // refusal, proving the run got PAST argument parsing.
    let config_path = dir.path().join("hippius-mem.toml");

    // `--secret` in argv must be refused before any config or network I/O —
    // argv parsing alone is enough, so stdin is deliberately closed (Stdio::
    // null) rather than piped: a bug that tried to read from stdin here
    // would hang instead of silently passing.
    let output = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args([
            "upgrade",
            "--bucket",
            "b",
            "--access-key-id",
            "ak",
            "--secret",
            "leaked-secret",
        ])
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", dir.path())
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .stdin(Stdio::null())
        .output()?;
    assert!(!output.status.success(), "--secret in argv must be refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("argv"),
        "the refusal must explain that secrets never travel via argv: {stderr}"
    );
    assert!(
        !stderr.contains("leaked-secret"),
        "the rejected secret value must never be echoed back: {stderr}"
    );

    // Without --secret, the identical bucket/access-key-id args must NOT
    // trip that refusal: the command instead reads the secret from stdin
    // and proceeds to (and fails at) config resolution, since no config
    // exists at this path yet.
    let output = run_upgrade(
        &config_path,
        dir.path(),
        &["--bucket", "b", "--access-key-id", "ak"],
        "piped-secret",
    )?;
    assert!(
        !output.status.success(),
        "no config exists at this path, so the command must still fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.to_lowercase().contains("argv"),
        "omitting --secret must not trip the argv refusal: {stderr}"
    );
    assert!(
        stderr.contains("no config") || stderr.contains("quickstart"),
        "the failure must be about the missing config, not the secret: {stderr}"
    );
    Ok(())
}

/// Finding #9a: the `=`-joined form `--secret=VALUE` must hit the same
/// pointed refusal as `--secret VALUE` — before this fix it fell through to
/// the generic unknown-argument bail, which echoed the whole argument
/// (secret included) to stderr.
#[test]
fn upgrade_rejects_the_secret_equals_form_without_leaking_the_value() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args([
            "upgrade",
            "--bucket",
            "b",
            "--access-key-id",
            "ak",
            "--secret=wJalrXUtnFEMI/K7MDENG",
        ])
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", dir.path())
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .stdin(Stdio::null())
        .output()?;

    assert!(
        !output.status.success(),
        "--secret=VALUE in argv must be refused"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("argv"),
        "the refusal must explain that secrets never travel via argv: {stderr}"
    );
    assert!(
        !stderr.contains("wJalrXUtnFEMI/K7MDENG"),
        "the rejected secret value must never be echoed back: {stderr}"
    );
    Ok(())
}

/// Decode a 64-hex-char field into its 32 raw bytes.
fn hex32(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hippius_mem_core::hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", bytes.len()))
}

/// Build a `MemoryStore` directly over `blob`, signing with `author_seed_hex`
/// and encrypting under `team_key_hex` — the same primitives
/// `TeamProfile::build_store` wires, reconstructed here because this
/// integration-test binary has no access to the `hippius-mem` binary
/// crate's private `Config`/`TeamProfile` (only `hippius-mem-core`'s public
/// API and the compiled `hippius-mem` binary itself).
fn build_live_store(
    blob: std::sync::Arc<dyn hippius_mem_core::BlobStore>,
    team: &str,
    team_key_hex: &str,
    author_seed_hex: &str,
) -> anyhow::Result<hippius_mem_core::MemoryStore> {
    use hippius_mem_core::{
        HashEmbedder, InMemoryIndex, MemoryStore, NetworkPrefix, NoopAnchor, OpLogStore, SecretKey,
        Signer, Sr25519Signer,
    };

    let index = std::sync::Arc::new(InMemoryIndex::new(std::sync::Arc::new(
        HashEmbedder::default(),
    )));
    let oplog = OpLogStore::new(blob.clone());
    let signer: std::sync::Arc<dyn Signer> = std::sync::Arc::new(
        Sr25519Signer::from_seed_with_prefix(&hex32(author_seed_hex)?, NetworkPrefix::HIPPIUS)?,
    );
    let team_key = SecretKey::from_bytes(hex32(team_key_hex)?);

    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        std::sync::Arc::new(NoopAnchor),
        signer,
        std::collections::BTreeMap::from([(0_u64, team_key)]),
        0,
        team.to_owned(),
        16,
    ))
}

/// The destination coordinates for the live test, read from env vars so the
/// same test runs against any throwaway S3-compatible endpoint without a
/// recompile.
struct LiveDestination {
    endpoint: String,
    bucket: String,
    access_key_id: String,
    secret: String,
    region: String,
}

impl LiveDestination {
    /// # Errors
    ///
    /// Returns an error if `HIPPIUS_MEM_TEST_BUCKET` is unset — the one
    /// coordinate with no safe default, since a wrong guess would write into
    /// a bucket the operator did not create for this test.
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
}

/// The trial identity `quickstart` wrote, parsed from the config it just
/// produced.
struct TrialIdentity {
    team: String,
    team_key_hex: String,
    author_seed_hex: String,
}

/// Run `quickstart --no-wire` for real, then parse the team identity back
/// out of the config it wrote.
fn quickstart_trial_identity(
    config_path: &std::path::Path,
    home: &std::path::Path,
) -> anyhow::Result<TrialIdentity> {
    let quickstart = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["quickstart", "--no-wire"])
        .env("HIPPIUS_MEM_CONFIG", config_path)
        .env("HOME", home)
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()?;
    anyhow::ensure!(
        quickstart.status.success(),
        "quickstart failed: {}",
        String::from_utf8_lossy(&quickstart.stderr)
    );

    let written = std::fs::read_to_string(config_path)?;
    let parsed: toml::Value = toml::from_str(&written)?;
    let field = |name: &str| -> anyhow::Result<String> {
        Ok(parsed
            .get(name)
            .and_then(toml::Value::as_str)
            .with_context(|| format!("{name} missing from the written config"))?
            .to_owned())
    };
    Ok(TrialIdentity {
        team: field("team")?,
        team_key_hex: field("team_key_hex")?,
        author_seed_hex: field("author_seed_hex")?,
    })
}

/// Seal two notes into `store`, returning their ids.
async fn seed_two_notes(
    store: &hippius_mem_core::MemoryStore,
) -> anyhow::Result<(hippius_mem_core::NoteId, hippius_mem_core::NoteId)> {
    use std::collections::BTreeSet;

    use hippius_mem_core::{NoteType, RememberInput, RepoScope};

    let repo = RepoScope::Repo("upgrade-live-test".to_owned());
    let first = store
        .remember(RememberInput {
            force: true,
            note_type: NoteType::Convention,
            repo: repo.clone(),
            tags: BTreeSet::new(),
            summary: "live upgrade test note one".to_owned(),
            body: "first note sealed into the local trial vault before upgrade".to_owned(),
        })
        .await?;
    let second = store
        .remember(RememberInput {
            force: true,
            note_type: NoteType::Convention,
            repo,
            tags: BTreeSet::new(),
            summary: "live upgrade test note two".to_owned(),
            body: "second note sealed into the local trial vault before upgrade".to_owned(),
        })
        .await?;
    Ok((first, second))
}

/// Live round-trip against a real S3-compatible endpoint: `quickstart`
/// writes a local trial vault, two notes are sealed directly into it via
/// `hippius_mem_core` (the same primitives the MCP server's `remember` tool
/// uses), `upgrade` — the real CLI subcommand under test — copies them into
/// the destination bucket and rewrites the config, and a fresh store built
/// straight over the resulting S3 profile reads both notes back.
///
/// Needs a reachable `MinIO` (or other S3-compatible) endpoint with the
/// target bucket already created, so it never runs in CI:
///
/// ```sh
/// docker run --rm -p 9000:9000 \
///   -e MINIO_ROOT_USER=test -e MINIO_ROOT_PASSWORD=testtest1 \
///   quay.io/minio/minio server /data
/// # create the bucket named by HIPPIUS_MEM_TEST_BUCKET with `mc` or the console
/// HIPPIUS_MEM_TEST_BUCKET=mem-spike \
/// HIPPIUS_MEM_TEST_ACCESS_KEY_ID=test \
/// HIPPIUS_MEM_TEST_SECRET=testtest1 \
///   cargo test -p hippius-mem --test upgrade_cli -- --ignored upgrade_round_trips
/// ```
#[tokio::test]
#[ignore = "needs docker"]
async fn upgrade_round_trips_two_notes_through_a_live_minio_bucket() -> anyhow::Result<()> {
    use hippius_mem_core::{BlobStore, FsBlobStore, S3BlobStore};

    let dest = LiveDestination::from_env()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");

    let identity = quickstart_trial_identity(&config_path, dir.path())?;
    // The XDG *data* base (finding #4), not *cache* — matches
    // `quickstart_trial_identity`'s isolated HOME with XDG_DATA_HOME removed.
    let vault_root = dir
        .path()
        .join(".local/share/hippius-mem/local")
        .join(&identity.team);
    let fs_blob: std::sync::Arc<dyn BlobStore> = std::sync::Arc::new(FsBlobStore::new(vault_root));
    let local_store = build_live_store(
        fs_blob,
        &identity.team,
        &identity.team_key_hex,
        &identity.author_seed_hex,
    )?;
    let (first, second) = seed_two_notes(&local_store).await?;

    let output = run_upgrade(
        &config_path,
        dir.path(),
        &[
            "--bucket",
            &dest.bucket,
            "--access-key-id",
            &dest.access_key_id,
            "--endpoint",
            &dest.endpoint,
        ],
        &dest.secret,
    )?;
    anyhow::ensure!(
        output.status.success(),
        "upgrade failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Copied") && stdout.contains(&dest.bucket),
        "upgrade must report the copy: {stdout}"
    );

    let s3_blob: std::sync::Arc<dyn BlobStore> = std::sync::Arc::new(S3BlobStore::new(
        dest.endpoint,
        dest.bucket,
        dest.access_key_id,
        dest.secret,
        dest.region,
    ));
    // A fresh reader identity: recall/get do not require matching the note's
    // author, only holding the team key.
    let reader_seed_hex = "11".repeat(32);
    let remote_store = build_live_store(
        s3_blob,
        &identity.team,
        &identity.team_key_hex,
        &reader_seed_hex,
    )?;
    remote_store.sync().await?;

    let recalled_first = remote_store.get(first).await?;
    let recalled_second = remote_store.get(second).await?;
    assert_eq!(recalled_first.summary, "live upgrade test note one");
    assert_eq!(recalled_second.summary, "live upgrade test note two");

    Ok(())
}
