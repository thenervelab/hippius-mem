//! `gc`'s CLI wiring — arg parse, config load, `resolve_and_build_store`, and
//! the `store.sweep_orphan_blobs(...)` call site — against a REAL
//! S3-compatible endpoint.
//!
//! Task 19 covers `MemoryStore::sweep_orphan_blobs`'s own mark-and-sweep
//! DECISION logic by calling it directly from `src/gc.rs`'s own `#[cfg(test)]`
//! module, over an in-memory `MemoryBlobStore`. `gc.rs`'s OWN delegation path —
//! everything between `main`'s subcommand dispatch and that call —
//! (`Config::from_env_and_file`, `resolve_and_build_store`, profile
//! resolution, and `TeamProfile::build_store`'s S3 branch, the
//! `CachingBlobStore` wrap included) has no coverage there: none of it runs
//! against anything but a hand-built in-memory store. This is that coverage.
//!
//! Follows `tests/doctor_s3.rs`'s shape and environment contract exactly.
//! `gc::run` is `pub(crate)` to the `hippius-mem` BINARY crate — `mod gc;`
//! lives in `main.rs`, not in the `hippius-mem` library `lib.rs` (which only
//! exposes `server`) — so an external integration test can drive it only by
//! spawning the compiled binary with the `gc` subcommand, never by calling
//! `gc::run` in-process. Reading the destination from the SAME environment
//! contract as `doctor_s3.rs`, `tests/upgrade_cli.rs`, `tests/report_cli.rs`,
//! and `hippius-mem-core/tests/blob_contract.rs` means one `MinIO` job
//! configures every live suite. `#[ignore]`d, and run by the `MinIO` job in
//! `.github/workflows/rust.yml`.
//!
//! Since `Config`/`TeamProfile` are private to the `hippius-mem` binary crate,
//! the fixture is seeded with `hippius_mem_core`'s public API directly:
//! `build_live_store` below mirrors `tests/upgrade_cli.rs::build_live_store` /
//! `tests/report_cli.rs::build_live_store` — the same primitives
//! `TeamProfile::build_store` wires (minus the `CachingBlobStore` read-through
//! cache, which only the REAL binary under test needs; it gets that from its
//! own `resolve_and_build_store` over the config file below).

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use std::collections::BTreeSet;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use hippius_mem_core::{
    BlobStore, HashEmbedder, InMemoryIndex, MemoryStore, NetworkPrefix, NoopAnchor, NoteId,
    NoteType, OpLogStore, RememberInput, RepoScope, S3BlobStore, Scope, SecretKey, Signer,
    Sr25519Signer, object_key,
};

/// The team namespace this test owns.
///
/// Fixed rather than per-run unique, matching `src/config.rs`'s own
/// `LIVE_TEAM` (`build_store_round_trips_a_note_through_a_live_s3_bucket`) and
/// `hippius-mem-core/tests/blob_contract.rs`: the run clears this prefix
/// before running, so a crashed prior run cannot leave state that poisons this
/// one, and it clears again after, so a shared bucket does not accumulate one
/// abandoned prefix per run.
const TEAM: &str = "hippius-mem-gc-live";

/// 64 hex chars decoding to 32 bytes — valid team-key/seed material.
fn hex64(byte: &str) -> String {
    byte.repeat(32)
}

/// Decode a 64-hex-char field into its 32 raw bytes.
fn hex32(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", bytes.len()))
}

/// The live endpoint coordinates, read from the same environment contract
/// `tests/doctor_s3.rs`, `tests/upgrade_cli.rs`, and
/// `hippius-mem-core/tests/blob_contract.rs` use, so one `MinIO` job
/// configures every live suite. Only the bucket has no default: a wrong guess
/// would write into a bucket the operator did not create for this test.
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

    /// A raw [`S3BlobStore`] over the same bucket, used only to seed the
    /// fixture and to verify the bucket's final state directly — never as the
    /// store `gc` itself reads through, which comes from the REAL binary's own
    /// `resolve_and_build_store` over the config file `config_toml` writes.
    fn raw_bucket(&self) -> S3BlobStore {
        S3BlobStore::new(
            self.endpoint.clone(),
            self.bucket.clone(),
            self.access_key_id.clone(),
            self.secret.clone(),
            self.region.clone(),
        )
    }

    /// A flat single-profile `storage = "s3"` config pointed at this endpoint.
    ///
    /// `semantic_embeddings = false` keeps the store lexical in an
    /// `--features embeddings` build too (matching `src/config.rs`'s own live
    /// S3 test), so this test never triggers a model download regardless of
    /// how it is invoked.
    fn config_toml(&self, team_key_hex: &str, author_seed_hex: &str) -> String {
        format!(
            "s3_endpoint = \"{endpoint}\"\ns3_region = \"{region}\"\n\
             bucket = \"{bucket}\"\naccess_key_id = \"{access_key_id}\"\nsecret = \"{secret}\"\n\
             team = \"{TEAM}\"\nteam_key_hex = \"{team_key_hex}\"\n\
             author_seed_hex = \"{author_seed_hex}\"\nsemantic_embeddings = false\n",
            endpoint = self.endpoint,
            region = self.region,
            bucket = self.bucket,
            access_key_id = self.access_key_id,
            secret = self.secret,
        )
    }
}

/// Build a `MemoryStore` directly over `blob`, signing with `author_seed_hex`
/// and encrypting under `team_key_hex` — the same primitives
/// `TeamProfile::build_store` wires, reconstructed here because this
/// integration-test binary has no access to the `hippius-mem` binary crate's
/// private `Config`/`TeamProfile` (only `hippius-mem-core`'s public API and
/// the compiled `hippius-mem` binary itself). Mirrors
/// `tests/upgrade_cli.rs::build_live_store` / `tests/report_cli.rs::build_live_store`.
fn build_live_store(
    blob: Arc<dyn BlobStore>,
    team: &str,
    team_key_hex: &str,
    author_seed_hex: &str,
) -> anyhow::Result<MemoryStore> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
        &hex32(author_seed_hex)?,
        NetworkPrefix::HIPPIUS,
    )?);
    let team_key = SecretKey::from_bytes(hex32(team_key_hex)?);

    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        std::collections::BTreeMap::from([(0_u64, team_key)]),
        0,
        team.to_owned(),
        16,
    ))
}

/// Milliseconds since the Unix epoch, for stamping a version ULID's timestamp
/// deliberately in the past — past-grace, unreferenced by any op — matching
/// `src/gc.rs`'s own `now_millis`/`plant_orphan_blob` test helpers.
fn now_millis() -> u64 {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX)
}

/// Plant an orphan note-ciphertext blob directly on `bucket` under `team`,
/// stamped with a version-ULID timestamp 48 hours in the past — well past the
/// default 24-hour grace window `gc` runs with below — and never through
/// `remember`, so no op ever names it. The bytes are arbitrary: the sweep only
/// ever lists and deletes by key, never decrypts.
async fn plant_orphan_blob(bucket: &dyn BlobStore, team: &str) -> anyhow::Result<String> {
    let past_ms = now_millis().saturating_sub(48 * 60 * 60 * 1000);
    let scope = Scope {
        team: team.to_owned(),
        repo: RepoScope::Repo("gc-live-test".to_owned()),
    };
    let key = object_key(&scope, NoteId::new(), ulid::Ulid::from_parts(past_ms, 0))?;
    bucket.put(&key, b"orphan ciphertext".to_vec()).await?;
    Ok(key)
}

/// Remove every object under `team`'s prefix, matching
/// `src/config.rs::clear_live_team`: cleared before AND after, so a crashed
/// run cannot leave state that poisons the next one, and a shared bucket does
/// not accumulate one abandoned prefix per run.
async fn clear_live_team(bucket: &dyn BlobStore, team: &str) {
    for key in bucket
        .list(&format!("{team}/"))
        .await
        .unwrap_or_else(|_| Vec::new())
    {
        let _ = bucket.delete(&key).await;
    }
}

/// Write `toml` to a config file under `dir` and run the real `hippius-mem gc`
/// binary against it.
///
/// `HOME` is redirected into `dir` and every inherited state/cache override is
/// removed, so a run touches no directory outside the temporary one, and its
/// local blob cache (the `CachingBlobStore` wrap `build_store`'s S3 branch
/// adds by default) starts empty on every run — the same isolation
/// `tests/doctor_s3.rs::run_doctor` applies. `RUST_LOG` is pinned to `info`
/// because the sweep-report line this test asserts on is a `tracing::info!`
/// record: a developer's inherited `RUST_LOG=warn` would otherwise hide it and
/// turn a passing binary into a failing test.
fn run_gc(dir: &std::path::Path, toml: &str) -> anyhow::Result<std::process::Output> {
    let config_path = dir.join("hippius-mem.toml");
    std::fs::write(&config_path, toml)?;

    Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .arg("gc")
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

/// The safety-critical end-to-end path: `gc`'s REAL CLI entry — arg parse,
/// `Config::from_env_and_file`, `resolve_and_build_store` (profile resolution
/// plus `TeamProfile::build_store`'s S3 branch), and the
/// `store.sweep_orphan_blobs(...)` call site at `src/gc.rs` — run against a
/// live bucket seeded with one past-grace orphan and one live,
/// op-log-referenced note. It must sweep exactly the orphan while leaving the
/// live note fully intact.
///
/// `MemoryStore::sweep_orphan_blobs`'s own keep/delete DECISION logic is
/// already covered in-process by `src/gc.rs`'s `#[cfg(test)]` module (Task
/// 19); this test exists to catch a regression in the WIRING around that
/// call — arg parsing, config load, and store construction — which only a
/// live backend can exercise.
///
/// Asserted two ways, like `doctor_s3.rs`: on the operator-visible sweep
/// report (`tracing::info!` on stderr), and directly against the bucket
/// afterward, so a passing assertion cannot be an artifact of a stale local
/// index or a misread log line.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn gc_sweeps_a_live_orphan_and_keeps_a_live_referenced_note() -> anyhow::Result<()> {
    let dest = LiveEndpoint::from_env()?;
    let raw = dest.raw_bucket();
    clear_live_team(&raw, TEAM).await;

    let team_key_hex = hex64("6a");
    let author_seed_hex = hex64("6b");

    let writer_blob: Arc<dyn BlobStore> = Arc::new(dest.raw_bucket());
    let writer = build_live_store(writer_blob, TEAM, &team_key_hex, &author_seed_hex)?;
    let live_id = writer
        .remember(RememberInput {
            note_type: NoteType::Decision,
            repo: RepoScope::Repo("gc-live-test".to_owned()),
            tags: BTreeSet::new(),
            summary: "gc must never delete a blob a live note points at".to_owned(),
            body: "seeded over a real S3 bucket for gc's own CLI-wiring coverage".to_owned(),
            force: true,
        })
        .await?;

    let orphan_key = plant_orphan_blob(&raw, TEAM).await?;
    assert!(
        raw.get(&orphan_key).await.is_ok(),
        "the orphan blob must exist in the live bucket before gc runs"
    );

    let dir = tempfile::tempdir()?;
    let toml = dest.config_toml(&team_key_hex, &author_seed_hex);
    let output = run_gc(dir.path(), &toml)?;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "gc must exit zero against a reachable bucket: {stderr}"
    );
    assert!(
        stderr.contains("orphan-blob sweep complete"),
        "the operator must be told the sweep ran to completion: {stderr}"
    );
    assert!(
        stderr.contains("orphans_found=1"),
        "the report must count exactly the one true orphan: {stderr}"
    );
    assert!(
        stderr.contains("orphans_reclaimed=1"),
        "the orphan must actually be deleted, not just counted: {stderr}"
    );

    // The direct, safety-critical check: verify the bucket itself, not just
    // the log line. The orphan is gone...
    assert!(
        raw.get(&orphan_key).await.is_err(),
        "the unreferenced, past-grace blob must be swept from the live bucket"
    );
    // ...and the live note is still fully retrievable through a SECOND store,
    // so it can only have come from the bucket via `sync`, not the writer's
    // own in-memory index.
    let reader_blob: Arc<dyn BlobStore> = Arc::new(dest.raw_bucket());
    let reader = build_live_store(reader_blob, TEAM, &team_key_hex, &author_seed_hex)?;
    reader.sync().await?;
    let note = reader.get(live_id).await?;
    assert_eq!(
        note.summary, "gc must never delete a blob a live note points at",
        "the live note's blob and the op naming it must both survive gc untouched"
    );

    clear_live_team(&raw, TEAM).await;
    Ok(())
}
