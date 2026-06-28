# Memory `doctor` + encryption-boundary guard — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the "paste one console bundle and run" promise *verifiable* — add a `hippius-mem doctor` subcommand that validates a memory-key bundle and proves, live, that only ciphertext leaves the MPC; and pin that encryption-boundary invariant with a regression guard.

**Architecture:** Two pieces, both in this repo (the console wizard is a separate plan in `hippius-console`). (1) A core test-only regression guard: a recording `BlobStore` that captures every `put` payload while `MemoryStore::remember` runs, asserting no payload is plaintext and each decrypts. (2) A binary `doctor` subcommand that loads `Config` (which already validates seed/key lengths), then runs a live seal→put→get→open→delete probe against the configured `S3BlobStore`, asserting the stored object is ciphertext. The probe is written over `&dyn BlobStore` so tests inject the in-memory fake.

**Tech stack:** Rust 2024, `hippius-mem-core` (XChaCha20-Poly1305 via `crypto::seal`/`open`, `BlobStore`/`S3BlobStore`/`MemoryBlobStore`), `hippius-mem` binary (anyhow, tokio, tracing), existing `Config` in `hippius-mem/src/config.rs`.

---

## Design plan (data structures, ownership, errors)

- **Data flow:** `doctor` → `Config::from_env_and_file()` (validates) → derive author SS58 + `SecretKey` → build `S3BlobStore` → `probe_encryption_boundary(&blob, &key)` seals a fixed probe plaintext, puts at a unique probe key, gets it back, asserts `stored == ciphertext` and `stored != plaintext`, `open`s and asserts equality, deletes the probe object → report PASS.
- **Data structures:**
  - `RecordingBlobStore { inner: MemoryBlobStore, puts: Mutex<Vec<(String, Vec<u8>)>> }` — test-only, in core. `Mutex` because `BlobStore::put` takes `&self` and the trait is `Send + Sync`; the recording vec needs interior mutability behind a shared ref.
  - `ProbeReport { bytes_written: usize }` — tiny value type returned by the probe so the caller can log a non-secret stat. No secrets stored.
  - No new public core API beyond the probe being reused by tests; the guard is pure test code.
- **Ownership/mutability:** `probe_encryption_boundary` borrows `blob: &dyn BlobStore` and `key: &SecretKey` (no ownership taken; the caller owns both). `RecordingBlobStore` owns its `inner` and the `Mutex<Vec<…>>`; tests read the captured puts by locking.
- **Error strategy (no matching ADR — `.illu/style/decisions/` is empty; follow the repo's existing split):** core stays `MemError` (the probe, if placed in core, returns `Result<_, MemError>` reusing `Storage`/`Crypto`); the binary `doctor` uses `anyhow` like `mint.rs`, and the two invariant failures (round-trip mismatch, plaintext-leak) become `anyhow::bail!` with explicit, secret-free messages. We keep the probe in the **binary** (`doctor.rs`) so it composes with `anyhow` and needs no new `MemError` variant; it still takes `&dyn BlobStore` for the test seam.
- **Invariants:** every byte handed to `BlobStore::put` is XChaCha20-Poly1305 ciphertext; `open(seal(x)) == x`; the probe never logs the team key, the seed, or the plaintext-vs-ciphertext bytes.

---

## Task 1: Encryption-boundary regression guard (core)

Pins "only ciphertext leaves the MPC" so the subkey work (or any future change) can't regress it.

**Files:**
- Test: `hippius-mem-core/src/store/mod.rs` (add to the existing `#[cfg(test)] mod tests`, which already drives `MemoryStore` over `MemoryBlobStore`)

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn blob_store_only_ever_receives_ciphertext() {
    // A BlobStore that forwards to the in-memory fake but records every payload
    // handed to `put`, so we can assert the MPC never emits plaintext.
    #[derive(Debug)]
    struct RecordingBlobStore {
        inner: MemoryBlobStore,
        puts: std::sync::Mutex<Vec<Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl BlobStore for RecordingBlobStore {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            // Record before forwarding: this is the exact byte stream that would
            // cross the network to the S3 gateway.
            self.puts.lock().expect("poisoned").push(bytes.clone());
            self.inner.put(key, bytes).await
        }
        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> { self.inner.get(key).await }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> { self.inner.list(prefix).await }
        async fn delete(&self, key: &str) -> Result<(), MemError> { self.inner.delete(key).await }
    }

    let plaintext_summary = "PLAINTEXT-SUMMARY-SENTINEL";
    let plaintext_body = "PLAINTEXT-BODY-SENTINEL";
    let recorder = std::sync::Arc::new(RecordingBlobStore {
        inner: MemoryBlobStore::default(),
        puts: std::sync::Mutex::new(Vec::new()),
    });
    let store = test_store_with_blob(recorder.clone()); // helper: build MemoryStore over a given blob (mirror existing test setup)

    store
        .remember(RememberInput {
            note_type: NoteType::Decision,
            repo: None,
            tags: Vec::new(),
            summary: plaintext_summary.to_owned(),
            body: plaintext_body.to_owned(),
        })
        .await
        .expect("remember succeeds");

    let puts = recorder.puts.lock().expect("poisoned");
    assert!(!puts.is_empty(), "remember must have written at least one blob");
    for payload in puts.iter() {
        let haystack = String::from_utf8_lossy(payload);
        assert!(
            !haystack.contains(plaintext_summary) && !haystack.contains(plaintext_body),
            "a blob payload leaked plaintext to the storage boundary"
        );
    }
}
```

> Adapt `test_store_with_blob` to the existing test harness in this module — reuse whatever helper currently constructs a `MemoryStore` over a `MemoryBlobStore`, parameterizing the blob. If no such helper exists, extract one (DRY).

**Step 2: Run it to verify it fails (or compiles green as a pin)**

Run: `cargo test -p hippius-mem-core blob_store_only_ever_receives_ciphertext`
Expected: compiles; PASSES (the invariant already holds). This is a *regression pin*, so a green result is correct — confirm it goes RED if you temporarily make `remember` store `note.to_json()` unsealed, then revert.

**Step 3: Confirm the guard bites**

Temporarily change `remember` to `self.blob.put(&key, json.into_bytes())` (plaintext). Re-run: expect FAIL with "leaked plaintext". Revert.

**Step 4: Commit**

```bash
git add hippius-mem-core/src/store/mod.rs
git commit -m "Pin encryption boundary: blob store only receives ciphertext"
```

---

## Task 2: `doctor` offline validation + dispatch wiring

**Files:**
- Create: `hippius-mem/src/doctor.rs`
- Modify: `hippius-mem/src/main.rs` (add `mod doctor;` and a dispatch arm next to `publish-membership`)

**Step 1: Write the failing test** (in `doctor.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_lines_redact_secrets() {
        // The human report names only public coordinates: bucket, access_key_id,
        // author SS58 — never the secret, team key, or seed.
        let lines = offline_report_lines("memories", "AKID", "5Grw...ss58");
        let joined = lines.join("\n");
        assert!(joined.contains("memories") && joined.contains("AKID") && joined.contains("5Grw"));
    }
}
```

**Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem doctor::tests::report_lines_redact_secrets`
Expected: FAIL ("cannot find function `offline_report_lines`").

**Step 3: Minimal implementation**

```rust
//! The `hippius-mem doctor` subcommand: validate a memory-key bundle and prove,
//! live, that only ciphertext leaves the MPC.

use anyhow::Context;

use crate::config::Config;

/// Build the non-secret report lines. Only public coordinates appear here — the
/// secret, team key, and seed must never reach a log line.
fn offline_report_lines(bucket: &str, access_key_id: &str, author_ss58: &str) -> Vec<String> {
    vec![
        format!("bucket         {bucket}"),
        format!("access_key_id  {access_key_id}"),
        format!("author SS58    {author_ss58}"),
    ]
}

/// Run `doctor`: load + validate the bundle, then (unless `--offline`) probe the
/// encryption boundary against the configured gateway.
///
/// # Errors
///
/// Returns an error if the configuration is missing/invalid or the live probe
/// fails. Neither the seed, the team key, nor any probe plaintext appears in an
/// error or log.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let offline = args.iter().any(|a| a == "--offline");
    // `from_env_and_file` already validates: required fields present, team_key_hex
    // and author_seed_hex each decode to exactly 32 bytes. A bad bundle stops here.
    let cfg = Config::from_env_and_file().context("loading hippius-mem configuration")?;
    let signer = cfg.signer().context("deriving the author identity from author_seed_hex")?;
    for line in offline_report_lines(&cfg.bucket, &cfg.access_key_id, &signer.ss58()) {
        tracing::info!("{line}");
    }
    if offline {
        tracing::info!("offline check passed; skipping live gateway probe (--offline)");
        return Ok(());
    }
    probe_live(&cfg).await
}
```

> Verify `Sr25519Signer`'s SS58 accessor name via `mcp__illu__context` for `Sr25519Signer` before finalizing `signer.ss58()` — adjust to the real method. `probe_live` is implemented in Task 3.

In `main.rs`, add `mod doctor;` and:

```rust
if subcommand == Some("doctor") {
    return doctor::run(&args[2..]).await;
}
```

**Step 4: Run to verify it passes** (stub `probe_live` to `Ok(())` temporarily, or land Task 3 first)

Run: `cargo test -p hippius-mem doctor::tests::report_lines_redact_secrets`
Expected: PASS.

**Step 5: Commit**

```bash
git add hippius-mem/src/doctor.rs hippius-mem/src/main.rs
git commit -m "Add hippius-mem doctor: offline bundle validation + dispatch"
```

---

## Task 3: `doctor` live encryption-boundary probe (injectable)

**Files:**
- Modify: `hippius-mem/src/doctor.rs`

**Step 1: Write the failing test** (inject the in-memory fake)

```rust
#[tokio::test]
async fn probe_round_trips_and_rejects_plaintext_store() {
    use hippius_mem_core::{MemoryBlobStore, SecretKey};
    let blob = MemoryBlobStore::default();
    let key = SecretKey::from_bytes([7u8; 32]);
    // Happy path: a clean fake round-trips and proves ciphertext != plaintext.
    let report = probe_encryption_boundary(&blob, &key).await.expect("probe passes");
    assert!(report.bytes_written > 0);
    // The probe must have cleaned up after itself (idempotent delete).
    // (Assert via a fresh list on the probe prefix being empty.)
}

#[tokio::test]
async fn probe_fails_when_store_returns_plaintext() {
    // A tampering BlobStore that returns the plaintext probe instead of the
    // stored ciphertext must be caught as a boundary violation.
    // ... construct a fake whose `get` returns the known probe plaintext bytes,
    // assert probe_encryption_boundary(..).is_err().
}
```

**Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem doctor::tests::probe_round_trips_and_rejects_plaintext_store`
Expected: FAIL ("cannot find function `probe_encryption_boundary`").

**Step 3: Minimal implementation**

```rust
use hippius_mem_core::{BlobStore, S3BlobStore, SecretKey, crypto};

/// A non-secret stat from the probe, safe to log.
pub(crate) struct ProbeReport {
    pub bytes_written: usize,
}

/// Fixed, non-secret probe plaintext. Distinct sentinel so a leak is obvious.
const PROBE_PLAINTEXT: &[u8] = b"hippius-mem doctor encryption-boundary probe";
/// Object key for the probe blob, under a dedicated prefix so it never collides
/// with real notes and is trivially cleaned up.
const PROBE_KEY: &str = "_doctor/encryption-boundary-probe";

/// Seal → put → get → open round-trip against `blob`, proving only ciphertext is
/// stored. The probe object is deleted on success and on the cleanup path.
///
/// # Errors
///
/// Returns an error if any gateway op fails, if the stored bytes equal the
/// plaintext (boundary violation), or if the round-trip does not recover the
/// plaintext. Error messages never include key material or the probe bytes
/// beyond the fixed sentinel.
async fn probe_encryption_boundary(
    blob: &dyn BlobStore,
    key: &SecretKey,
) -> anyhow::Result<ProbeReport> {
    // Bind the ciphertext to the probe key as AEAD AAD, exactly as `remember` does.
    let ciphertext = crypto::seal(key, PROBE_PLAINTEXT, PROBE_KEY.as_bytes())
        .map_err(|e| anyhow::anyhow!("sealing the probe failed: {e}"))?;
    anyhow::ensure!(
        ciphertext != PROBE_PLAINTEXT,
        "seal returned plaintext — encryption is not happening at the MPC"
    );
    blob.put(PROBE_KEY, ciphertext.clone()).await.context("probe put")?;
    let fetched = blob.get(PROBE_KEY).await.context("probe get");
    // Best-effort cleanup regardless of the get/verify outcome.
    let cleanup = blob.delete(PROBE_KEY).await;
    let fetched = fetched?;
    anyhow::ensure!(
        fetched != PROBE_PLAINTEXT,
        "the gateway returned plaintext — only ciphertext must ever be stored"
    );
    let opened = crypto::open(key, &fetched, PROBE_KEY.as_bytes())
        .map_err(|_| anyhow::anyhow!("the stored blob did not decrypt under the team key"))?;
    anyhow::ensure!(opened == PROBE_PLAINTEXT, "round-trip did not recover the probe plaintext");
    cleanup.context("probe cleanup delete")?;
    Ok(ProbeReport { bytes_written: ciphertext.len() })
}

/// Build the configured S3 store and probe it.
async fn probe_live(cfg: &Config) -> anyhow::Result<()> {
    let key = cfg.team_key().context("decoding team_key_hex")?;
    let blob = S3BlobStore::new(
        cfg.s3_endpoint.clone(),
        cfg.bucket.clone(),
        cfg.access_key_id.clone(),
        cfg.secret.clone(),
        cfg.s3_region.clone(),
    );
    let report = probe_encryption_boundary(&blob, &key).await?;
    tracing::info!(bytes_written = report.bytes_written, "live encryption-boundary probe passed: only ciphertext was stored");
    Ok(())
}
```

> Confirm `crypto` is re-exported (`hippius_mem_core::crypto::{seal,open}`) and `SecretKey::from_bytes` is public via `mcp__illu__context` before finalizing imports. `S3BlobStore::new`'s argument order is `(endpoint, bucket, access_key_id, secret, region)` per `config.rs:397-403`.

**Step 4: Run to verify it passes**

Run: `cargo test -p hippius-mem doctor::`
Expected: PASS (both probe tests).

**Step 5: Commit**

```bash
git add hippius-mem/src/doctor.rs
git commit -m "doctor: live encryption-boundary probe over an injectable blob store"
```

---

## Task 4: Lints, full build, feature matrix

**Step 1:** `cargo fmt --all`
**Step 2:** `cargo clippy -p hippius-mem -p hippius-mem-core --all-targets -- -D warnings`
Expected: clean. Fix every warning (workspace denies `unwrap_used`/`panic`/etc. — the probe uses `anyhow::ensure!`/`context`, no `unwrap`).
**Step 3:** `cargo test -p hippius-mem -p hippius-mem-core`
Expected: all pass.
**Step 4:** Confirm `doctor` builds with and without the `console` feature (it does not depend on it): `cargo build -p hippius-mem` and `cargo build -p hippius-mem --features console`.
**Step 5: Commit** any fmt/clippy fixups.

---

## Task 5: Docs

**Files:**
- Modify: `README.md` (the "New machine joins the team (runbook)" section)

**Step 1:** Replace the mint-token-first runbook with the console-bundle path: "Create a Memory key in the console → paste the bundle into `hippius-mem.toml` → run `hippius-mem doctor` to verify the bundle and that only ciphertext leaves the MPC → start the server." Keep `mint-token` documented as the no-console CLI path, noting it authors as the main account.
**Step 2:** Add a one-line `doctor` entry to the operating-model section (alongside `mint-token` / `publish-membership`), including `--offline`.
**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: console-bundle onboarding + doctor verification step"
```

---

## Out of scope (separate plans)

- The **console wizard** (`hippius-console`, TypeScript) — its own plan in that repo: `src/components/s3/service-keys/` + `useMemoryKey.ts`, reusing `useApiBuckets`/`useApiTokens`, generating the subkey client-side, rendering the bundle.
- The **v2 wrapped-key CLI** (`provision_team_key`/`rotate_team_key` as subcommands).
