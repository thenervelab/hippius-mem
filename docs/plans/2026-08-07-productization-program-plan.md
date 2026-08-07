# Productization Program Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every session starts with `mcp__hippius-mem__recall` on the task. Every subagent prompt MUST include: "Call `mcp__hippius-mem__recall` about the task before making changes, and `mcp__hippius-mem__remember` any durable decision/gotcha you discover." Every Rust-bearing task loads the `rust-style` skill before its first edit.

**Goal:** Close the product gaps inside this repo's control — local trial funnel, manifest recovery key, ROI report, release readiness — so the held release gate, once green, triggers a checklist rather than a project.

**Architecture:** Five phases per the approved design (`docs/plans/2026-08-07-productization-program-design.md`). Phases A (trial-mode quickstart) and B (trust hardening) run in parallel on disjoint surfaces; C (report) follows; D (release readiness) is last because its final verifications need a real release; E (docs) is parallel-safe. Phase B merges before any public release so the v2 manifest format ships without a migration story.

**Tech Stack:** Rust 1.97.1 workspace (`hippius-mem-core`, `hippius-mem`), tokio, async-trait, aws-sdk-s3, serde/serde_json, schnorrkel via existing `Signer`/`VerifyingKey` seams, cargo-dist + GitHub Actions, POSIX sh for `install.sh`.

## Global Constraints

- Toolchain pinned: Rust 1.97.1 (`rust-toolchain.toml`); MSRV 1.97.1.
- `#![forbid(unsafe_code)]` stays; `cargo clippy --all-targets --all-features -- -D warnings` must pass; `cargo fmt` before every commit; `cargo deny check` on dependency changes.
- rustfmt `use_small_heuristics = "Default"` — never one-line dense code; blank lines between logical steps.
- No emojis anywhere. Commit messages use the user's git identity only — no Co-Authored-By lines.
- No new op kinds anywhere in this program (design decision: "every state change stays a signed op; no side channels" and the report reads converged state only).
- No gateway/console/account changes; no free tier. Do not add or request any such endpoint.
- Any new entry point that builds a `MemoryStore` and reads full team memory MUST call `admin::bootstrap_epochs` (recorded twice-recurred gotcha). Applies to `quickstart`, `upgrade`, and `report`.
- Secrets never travel via argv (visible in `ps`); read from tty/stdin only. Conflicts refuse with guidance, never rewrite (join-bundle convention).
- TDD for every code task: failing test first, watch it fail, minimal implementation, watch it pass, commit.
- Each phase is its own PR stream off `main` with adversarial review before merge.

---

## Phase A — Trial-mode quickstart

### Task 1: `copy_store` helper and the location-independence e2e

The verification spike from the design, made permanent: prove op-log objects
are location-independent (signatures do not bind the store), and produce the
copy machinery `upgrade` (Task 5) will reuse.

**Files:**
- Create: `hippius-mem-core/src/store/copy.rs`
- Modify: `hippius-mem-core/src/store/mod.rs` (declare + re-export)
- Modify: `hippius-mem-core/src/lib.rs` (re-export `copy_store`)
- Test: `hippius-mem-core/tests/e2e_store_copy.rs`

**Interfaces:**
- Consumes: `BlobStore` trait (`put`/`get`/`list`/`delete`), `MemoryBlobStore`,
  `MemError` — all existing.
- Produces: `pub async fn copy_store(src: &dyn BlobStore, dst: &dyn BlobStore, prefix: &str) -> Result<u64, MemError>`
  — copies every object under `prefix` from `src` to `dst` (put-overwrite,
  idempotent), returns the object count copied. Task 5 calls it with the
  team-name prefix.

- [ ] **Step 1: Write the failing e2e**

In `hippius-mem-core/tests/e2e_store_copy.rs`, mirror the store-construction
pattern of the existing `hippius-mem-core/tests/e2e_sharing.rs` (read it first
— it shows how to build a `MemoryStore` over a `MemoryBlobStore` with a test
signer and team key). The test:

```rust
//! A byte copy of a team's objects between blob stores preserves the full
//! verifiable state: ops, signatures, history, and reconcile all hold on the
//! destination. This is the invariant `hippius-mem upgrade` (trial -> bucket)
//! depends on.

use std::sync::Arc;

use hippius_mem_core::{MemoryBlobStore, copy_store};

#[tokio::test]
async fn copied_store_preserves_converged_state() -> Result<(), Box<dyn std::error::Error>> {
    let src_blob = Arc::new(MemoryBlobStore::new());

    // Build a store over `src_blob` exactly as e2e_sharing.rs does, remember
    // three notes (one edited once, one linked), and sync so the op-log and
    // index are converged.
    let src_store = build_test_store(src_blob.clone()).await?;
    seed_three_notes(&src_store).await?;

    let dst_blob = Arc::new(MemoryBlobStore::new());
    let copied = copy_store(src_blob.as_ref(), dst_blob.as_ref(), "").await?;
    assert!(copied > 0, "the seeded team must have produced objects");

    // A fresh store over the COPY, same team key + a fresh reader identity,
    // must converge to identical state: same note ids and versions from
    // recall, same history (signatures verify), and reconcile passes.
    let dst_store = build_test_store(dst_blob.clone()).await?;
    assert_converged_state_matches(&src_store, &dst_store).await?;

    Ok(())
}
```

`build_test_store`, `seed_three_notes`, and `assert_converged_state_matches`
are local helper fns in this test file, written against the same public API
`e2e_sharing.rs` uses (do not invent new core API for them).

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test e2e_store_copy`
Expected: FAIL to compile — `copy_store` does not exist.

- [ ] **Step 3: Implement `copy_store`**

`hippius-mem-core/src/store/copy.rs`:

```rust
//! Bulk copy between blob stores.
//!
//! Objects are opaque sealed bytes; ops sign their content and object keys,
//! not the store holding them, so a byte-for-byte copy preserves every
//! signature and proof. Used by the trial-to-bucket upgrade path.

use crate::error::MemError;
use crate::store::BlobStore;

/// Copy every object under `prefix` from `src` to `dst`.
///
/// Put-overwrite semantics make the copy idempotent: re-running after a
/// partial failure re-copies already-transferred objects harmlessly.
///
/// # Errors
///
/// Propagates the first [`MemError`] from the source list/get or the
/// destination put.
pub async fn copy_store(
    src: &dyn BlobStore,
    dst: &dyn BlobStore,
    prefix: &str,
) -> Result<u64, MemError> {
    let keys = src.list(prefix).await?;

    let mut copied = 0_u64;
    for key in keys {
        let bytes = src.get(&key).await?;
        dst.put(&key, bytes).await?;
        copied += 1;
    }

    Ok(copied)
}
```

Declare `pub mod copy;`  in `store/mod.rs` (follow its existing module list
style) and re-export `copy_store` from `lib.rs` next to the other store
re-exports.

- [ ] **Step 4: Run the e2e to verify it passes**

Run: `cargo test --test e2e_store_copy`
Expected: PASS.

- [ ] **Step 5: Read the signing code and record the argument**

Read `hippius-mem-core/src/oplog/op.rs` signing-bytes construction and confirm
in the module doc of `copy.rs` (one sentence, already drafted above) that no
signed field names the store/bucket. If anything DOES bind the location, STOP
— the design's upgrade path is invalid; raise it before proceeding.

- [ ] **Step 6: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/store/copy.rs hippius-mem-core/src/store/mod.rs \
  hippius-mem-core/src/lib.rs hippius-mem-core/tests/e2e_store_copy.rs
git commit -m "feat(core): copy_store bulk blob copy with location-independence e2e"
```

### Task 2: `FsBlobStore`

**Files:**
- Create: `hippius-mem-core/src/store/fs.rs`
- Modify: `hippius-mem-core/src/store/mod.rs`, `hippius-mem-core/src/lib.rs` (re-export)
- Test: `hippius-mem-core/tests/blob_contract.rs` (new shared contract suite)
- Test: unit tests inside `fs.rs` for the key-path mapping

**Interfaces:**
- Consumes: `BlobStore` trait, `MemError` (`Io` has `#[from] std::io::Error`;
  `NotFound { id }`; `Storage(String)`).
- Produces: `pub struct FsBlobStore` with
  `pub fn new(root: PathBuf) -> Self` (creates nothing until first `put`) and
  a `BlobStore` impl. Task 3 constructs it in `config.rs`.

- [ ] **Step 1: Write the failing contract suite**

`hippius-mem-core/tests/blob_contract.rs` — one generic suite, run against
both fakes so every impl obeys the trait's documented contract:

```rust
//! Contract tests every BlobStore impl must pass: the trait doc's promises
//! (lexicographic list, idempotent delete, NotFound on absent get,
//! put-overwrite) checked against each implementation.

use std::sync::Arc;

use hippius_mem_core::{BlobStore, FsBlobStore, MemError, MemoryBlobStore};

async fn exercise_contract(store: Arc<dyn BlobStore>) {
    // Absent get is NotFound, not Storage.
    let missing = store.get("team/none").await;
    assert!(matches!(missing, Err(MemError::NotFound { .. })));

    // Put then get round-trips bytes exactly.
    store.put("team/b", vec![2]).await.expect("put b");
    store.put("team/a/deep", vec![1]).await.expect("put a");
    assert_eq!(store.get("team/b").await.expect("get b"), vec![2]);

    // Overwrite replaces.
    store.put("team/b", vec![9]).await.expect("overwrite");
    assert_eq!(store.get("team/b").await.expect("get b2"), vec![9]);

    // List is prefix-filtered and lexicographic.
    let keys = store.list("team/").await.expect("list");
    assert_eq!(keys, vec!["team/a/deep".to_owned(), "team/b".to_owned()]);

    // Delete is idempotent: absent key deletes are success.
    store.delete("team/b").await.expect("delete");
    store.delete("team/b").await.expect("delete twice");
    assert!(matches!(
        store.get("team/b").await,
        Err(MemError::NotFound { .. })
    ));
}

#[tokio::test]
async fn memory_store_honors_the_contract() {
    exercise_contract(Arc::new(MemoryBlobStore::new())).await;
}

#[tokio::test]
async fn fs_store_honors_the_contract() {
    let dir = std::env::temp_dir().join(format!("hippius-mem-fs-{}", std::process::id()));
    exercise_contract(Arc::new(FsBlobStore::new(dir.clone()))).await;
    let _ = std::fs::remove_dir_all(dir);
}
```

If the workspace already has a tempdir dev-dependency (check `Cargo.toml`
dev-dependencies first), use it instead of the pid-suffixed temp path. Do not
add a new dependency without checking the latest release and `cargo deny`.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --test blob_contract`
Expected: FAIL to compile — `FsBlobStore` does not exist.

- [ ] **Step 3: Implement `FsBlobStore`**

`hippius-mem-core/src/store/fs.rs`. The essentials the implementation must
get right (mirror the module-doc voice of `blob.rs`):

```rust
//! Filesystem BlobStore for the local trial vault.
//!
//! Keys map to files under a root directory: slash-separated key segments
//! become subdirectories. The mapping is validated, not trusted — a key is
//! rejected unless every segment is non-empty, is not `.` or `..`, and
//! contains no path separator or NUL, so no key can escape the root.
//! `put` is atomic (temp file + rename in the same directory); `list`
//! reconstructs keys from relative paths and sorts them so ordering matches
//! the trait's lexicographic promise; `delete` is idempotent.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::error::MemError;
use crate::store::BlobStore;

#[derive(Debug, Clone)]
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Resolve `key` to a path under the root, rejecting escape attempts.
    fn key_path(&self, key: &str) -> Result<PathBuf, MemError> {
        if key.is_empty() {
            return Err(MemError::Storage("empty object key".to_owned()));
        }

        let mut path = self.root.clone();
        for segment in key.split('/') {
            let unsafe_segment = segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.contains('\\')
                || segment.contains('\0');
            if unsafe_segment {
                return Err(MemError::Storage(format!(
                    "object key {key:?} contains an unsafe path segment"
                )));
            }
            path.push(segment);
        }

        Ok(path)
    }
}
```

The `BlobStore` impl uses `tokio::fs` throughout:

- `put`: `create_dir_all(parent)`, write to `{final}.tmp-{pid}` in the same
  directory, `tokio::fs::rename` into place (atomic on the same filesystem).
- `get`: `read`; map `ErrorKind::NotFound` to `MemError::NotFound { id: key }`,
  everything else through `MemError::Io`.
- `list`: iterative directory walk with an explicit `Vec<PathBuf>` stack
  (`read_dir`/`next_entry`), reconstruct keys with `/` separators from paths
  relative to the root via `Path::strip_prefix`, skip `.tmp-` leftovers,
  collect and `sort_unstable`. A missing root returns `Ok(vec![])` — an empty
  store, matching `MemoryBlobStore`.
- `delete`: `remove_file`, treating `ErrorKind::NotFound` as success.

Unit tests in `fs.rs` for `key_path` (adversarial keys, hand-enumerated —
no new property-test dependency):

```rust
#[test]
fn key_path_rejects_escapes() {
    let store = FsBlobStore::new(PathBuf::from("/tmp/root"));
    for bad in ["", "/abs", "a//b", "..", "a/../b", "a/.", "a\\b", "a\0b", "a/"] {
        assert!(store.key_path(bad).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn key_path_maps_segments_to_directories() {
    let store = FsBlobStore::new(PathBuf::from("/tmp/root"));
    let path = store.key_path("team/_oplog/000001").expect("valid key");
    assert_eq!(path, PathBuf::from("/tmp/root/team/_oplog/000001"));
}
```

- [ ] **Step 4: Run the suite to verify it passes**

Run: `cargo test --test blob_contract && cargo test -p hippius-mem-core fs`
Expected: PASS (both impls).

- [ ] **Step 5: Cross-check real key shapes**

Read `hippius-mem-core/src/objkey.rs` and confirm every produced key shape
(notes, op-log, manifests, snapshots, epochs) passes `key_path`. Add any
shape found there to the unit test's valid list.

- [ ] **Step 6: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/store/fs.rs hippius-mem-core/src/store/mod.rs \
  hippius-mem-core/src/lib.rs hippius-mem-core/tests/blob_contract.rs
git commit -m "feat(core): FsBlobStore local filesystem backend with contract suite"
```

### Task 3: `storage` discriminator in config

**Files:**
- Modify: `hippius-mem/src/config.rs` (`TeamProfile` struct ~line 100s; `validate`; `build_store` ~line 994)
- Test: existing config unit tests module in `config.rs` (follow its patterns)

**Interfaces:**
- Consumes: `FsBlobStore::new(root: PathBuf)` from Task 2.
- Produces: `TeamProfile.storage: StorageBackend` (`#[serde(default)]`),
  `pub(crate) enum StorageBackend { S3, Local }`, and a `build_store` that
  branches on it. `TeamProfile.local_root: Option<PathBuf>` overrides the
  default trial root. Tasks 4-6 read `profile.storage`.

- [ ] **Step 1: Write the failing tests**

In `config.rs`'s test module, following its existing test style (the file has
`build_store_validates_before_constructing` and friends as models):

```rust
#[test]
fn storage_defaults_to_s3_when_absent() {
    // Parse a minimal profile TOML WITHOUT a storage key (reuse the file's
    // existing fixture helper for a valid profile) and assert
    // profile.storage == StorageBackend::S3 — existing configs are untouched.
}

#[test]
fn local_profile_needs_no_bucket_or_credentials() {
    // storage = "local", bucket/access_key_id/secret all empty: validate()
    // passes. The same empty fields with storage = "s3" (or absent): the
    // existing validation errors still fire.
}

#[test]
fn local_profile_rejects_bucket_values() {
    // storage = "local" AND a non-empty bucket: typed ConfigError telling the
    // user a local profile takes no bucket (contradictory config refused,
    // never silently ignored).
}

#[tokio::test]
async fn build_store_uses_fs_backend_for_local_profiles() {
    // A local profile with local_root pointing at a temp dir builds a store,
    // and a remember/get round-trip lands files under that dir.
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hippius-mem config`
Expected: FAIL — `StorageBackend` does not exist.

- [ ] **Step 3: Implement**

Add to `config.rs` next to `TeamProfile`:

```rust
/// Which blob backend a team profile binds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StorageBackend {
    /// Hippius S3 gateway (the default; absent field means this).
    #[default]
    S3,
    /// Local filesystem trial vault — solo only, no credentials.
    Local,
}
```

`TeamProfile` gains (with doc comments in the struct's existing voice):

```rust
    #[serde(default)]
    pub(crate) storage: StorageBackend,
    #[serde(default)]
    pub(crate) local_root: Option<PathBuf>,
```

`validate()` branches: `Local` requires `bucket`, `access_key_id`, and
`secret` to be empty (a non-empty value is a typed error naming the field and
the fix) and ignores `s3_endpoint` concerns; `S3` keeps today's checks
unchanged. `build_store` branches at the construction site (~line 1004):

```rust
        let blob: Arc<dyn BlobStore> = match self.storage {
            StorageBackend::Local => {
                // No cache wrap: the store IS local disk already, and the
                // cache's value (avoiding gateway round-trips) does not apply.
                Arc::new(FsBlobStore::new(self.local_trial_root()?))
            }
            StorageBackend::S3 => {
                // ... existing S3BlobStore + CachingBlobStore construction,
                // unchanged, moved into this arm.
            }
        };
```

`local_trial_root(&self) -> Result<PathBuf, ConfigError>` returns
`self.local_root` when set, else the default derived the same way
`blob_cache_dir` (config.rs:31) derives its base — read that fn and mirror
its XDG/home resolution, ending in `.../hippius-mem/local/{team-name}`.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p hippius-mem config`
Expected: PASS, including all pre-existing config tests (backward
compatibility is the point).

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/config.rs
git commit -m "feat(cli): storage discriminator selects fs or s3 backend per team profile"
```

### Task 4: `quickstart` subcommand

**Files:**
- Create: `hippius-mem/src/quickstart.rs`
- Modify: `hippius-mem/src/main.rs` (dispatch arm + help text)
- Modify: `hippius-mem/src/join_bundle.rs` (raise `generate_seed_hex` and
  `resolve_target_path` to `pub(crate)` if not already)
- Test: `hippius-mem/tests/quickstart_cli.rs`

**Interfaces:**
- Consumes: `join_bundle::{generate_seed_hex, resolve_target_path, write_config}`
  (config-writing machinery, 0600, refuse-on-conflict), `StorageBackend::Local`
  (Task 3), `doctor::run` (`pub(crate) async fn run(args: &[String])`),
  `setup::{install, init}`, `admin::bootstrap_epochs`.
- Produces: `pub(crate) async fn run(args: &[String]) -> anyhow::Result<()>`
  dispatched as `"quickstart"` in `main.rs`.

- [ ] **Step 1: Write the failing CLI test**

`hippius-mem/tests/quickstart_cli.rs`, modeled on the existing
`hippius-mem/tests/join_bundle_cli.rs` (read it first — it shows how the CLI
binary is driven with `HIPPIUS_MEM_CONFIG` pointed at a temp path):

```rust
//! quickstart writes a zero-decision local trial profile and refuses to
//! touch an existing config.

#[test]
fn quickstart_writes_a_local_trial_profile() {
    // Run the binary with HIPPIUS_MEM_CONFIG at tempdir/config.toml and
    // HOME at tempdir (so setup wiring stays inside the sandbox), args:
    // ["quickstart", "--no-wire"].
    // Assert exit 0; config file exists with mode 0600; parsed TOML has
    // storage = "local", non-empty team_key_hex and author_seed_hex,
    // empty bucket/access_key_id/secret; stdout mentions "hippius-mem upgrade".
}

#[test]
fn quickstart_refuses_an_existing_config() {
    // Pre-write any config file at the target path; run quickstart; assert
    // non-zero exit and stderr pointing at doctor, and the file is untouched
    // (byte-identical before and after).
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem --test quickstart_cli`
Expected: FAIL — unknown subcommand.

- [ ] **Step 3: Implement `quickstart.rs`**

Flow, in order (each its own small fn; no big functions):

1. Parse args: `--team <name>` (default `"trial"`), `--no-wire` (skip Claude
   Code wiring — used by tests and non-Claude users). Reject unknown flags
   with the same `reject_args` style `admin.rs` uses.
2. `resolve_target_path()`; if the file exists, bail:
   `anyhow::bail!("a config already exists at {path}; run `hippius-mem doctor` to check it, or delete it first if you really want a fresh trial")`.
3. Generate `team_key_hex` (32 CSPRNG bytes, hex — same mechanism as
   `generate_seed_hex`) and `author_seed_hex` via `generate_seed_hex()`.
4. Render and write the config through the join-bundle writer with
   `storage = "local"` and empty bucket/credentials, 0600.
5. Build the store from the freshly loaded config, call
   `admin::bootstrap_epochs` exactly the way `brief.rs` does (the recorded
   gotcha: every new entry point wires it, even though a fresh trial is
   epoch 0 only), then run the doctor probe (`doctor::run(&[])`) so the user
   sees seal-put-get-open pass against their disk.
6. Unless `--no-wire`: `setup::install(&[])`, and `setup::init(&[])` when the
   cwd is a git repo (mirror how `install.sh` step 4 decides this).
7. Print exactly two next steps (no more):

```text
Trial vault ready at {root}. Notes are encrypted and signed on your disk.
  1. In Claude Code, ask it to remember something about this repo.
  2. When you subscribe to Hippius storage, run: hippius-mem upgrade
Trial mode is solo. Team memory (invite/join) needs a Hippius bucket.
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p hippius-mem --test quickstart_cli`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/quickstart.rs hippius-mem/src/main.rs \
  hippius-mem/src/join_bundle.rs hippius-mem/tests/quickstart_cli.rs
git commit -m "feat(cli): quickstart writes a zero-decision local trial profile"
```

### Task 5: `upgrade` subcommand

**Files:**
- Create: `hippius-mem/src/upgrade.rs`
- Modify: `hippius-mem/src/main.rs` (dispatch arm + help text)
- Test: `hippius-mem/tests/upgrade_cli.rs` and an e2e in
  `hippius-mem-core/tests/e2e_store_copy.rs` already covers the copy invariant

**Interfaces:**
- Consumes: `copy_store` (Task 1), `FsBlobStore` (Task 2),
  `StorageBackend` (Task 3), `S3BlobStore::new(endpoint, bucket, access_key_id, secret, region)`,
  `join_bundle::write_config` machinery, `admin::bootstrap_epochs`,
  `doctor::run`.
- Produces: `pub(crate) async fn run(args: &[String]) -> anyhow::Result<()>`
  dispatched as `"upgrade"`.

- [ ] **Step 1: Write the failing CLI test**

`hippius-mem/tests/upgrade_cli.rs`:

```rust
//! upgrade flips a quickstart trial profile to S3 after copying its objects.

#[test]
fn upgrade_refuses_a_non_local_profile() {
    // Config with storage = "s3": run ["upgrade", ...]; expect non-zero exit
    // and a message saying there is no trial vault to upgrade.
}

#[test]
fn upgrade_refuses_a_multi_profile_config() {
    // Config with two [[teams]] blocks, one local: expect non-zero exit and
    // guidance to edit the config manually (the in-place rewrite only
    // supports the single-profile shape quickstart creates — YAGNI boundary
    // from the design).
}

#[test]
fn upgrade_reads_secret_from_stdin_not_argv() {
    // Run ["upgrade", "--bucket", "b", "--access-key-id", "ak"] with the
    // secret piped on stdin; assert argv parsing rejects a --secret flag
    // (secrets never travel via argv).
}
```

The happy-path copy is exercised at the core layer (Task 1 e2e); the CLI
happy path is verified in Step 5 manually against a MinIO container because
it needs a live S3 endpoint (`#[ignore]`-gate an integration test for it,
following the `#[ignore = "needs docker"]` pattern named in the adoption
plan).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem --test upgrade_cli`
Expected: FAIL — unknown subcommand.

- [ ] **Step 3: Implement `upgrade.rs`**

Flow:

1. Parse `--bucket`, `--access-key-id`, `--team <name>` (default: the one
   local profile); `--endpoint` optional (default: shared `s3_endpoint`
   already in config). Secret: prompt on tty / read one line from stdin.
   Reject `--secret` in argv explicitly with a pointed error.
2. Load config. Require: exactly one `[[teams]]` profile AND
   `storage == Local` — else the typed refusals from the tests.
3. Build `FsBlobStore` from the profile and `S3BlobStore` from the new
   values. Probe the destination first (put/get/delete one canary object
   under `{team}/_upgrade_probe`) so bad credentials fail BEFORE any copy.
4. `copy_store(&fs, &s3, &team_prefix)` — print the object count.
5. Rewrite the config: same team/author keys, `storage = "s3"`, the new
   bucket/credentials, `local_root` dropped. Write via the same
   render-fresh-config path quickstart used (single-profile shape is
   guaranteed by step 2), 0600, to a temp file + rename.
6. Rebuild the store from the new config, `admin::bootstrap_epochs` (mirror
   `brief.rs`), run `doctor::run(&[])`, then a `refresh`-equivalent sync so
   the index rebuilds from the bucket.
7. Print: objects copied, "trial directory kept at {root}; delete it once
   you are satisfied: rm -rf {root}", and that re-running `upgrade` is safe
   (idempotent copy).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p hippius-mem --test upgrade_cli`
Expected: PASS.

- [ ] **Step 5: Live MinIO verification (manual, once)**

Start the throwaway MinIO from the adoption plan (Task 0.1 there documents
the command), `quickstart`, remember two notes via a live serve session,
`upgrade` into the MinIO bucket, `recall` both notes back. Record any
surprise as a `remember` note.

- [ ] **Step 6: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/upgrade.rs hippius-mem/src/main.rs hippius-mem/tests/upgrade_cli.rs
git commit -m "feat(cli): upgrade copies the trial vault into a Hippius bucket"
```

### Task 6: team commands refuse local profiles

**Files:**
- Modify: `hippius-mem/src/invite.rs`, `hippius-mem/src/mint.rs`,
  `hippius-mem/src/admin.rs` (`join`, `provision`)
- Test: extend `hippius-mem/tests/quickstart_cli.rs`

**Interfaces:**
- Consumes: `profile.storage` (Task 3).
- Produces: a shared `pub(crate) fn require_s3(profile: &TeamProfile, verb: &str) -> anyhow::Result<()>`
  in `config.rs` used by all four commands.

- [ ] **Step 1: Write the failing test**

In `quickstart_cli.rs`:

```rust
#[test]
fn team_commands_refuse_a_local_profile() {
    // With a quickstart-created config, run each of ["invite"], ["join"],
    // ["provision"], ["mint-token"]; every one exits non-zero with a message
    // containing "team mode needs a Hippius bucket" and "hippius-mem upgrade".
}
```

- [ ] **Step 2: Run to verify it fails** — the commands currently fail on
empty bucket values with a generic validation error, not the pointed message.

Run: `cargo test -p hippius-mem --test quickstart_cli team_commands`
Expected: FAIL on the message assertion.

- [ ] **Step 3: Implement `require_s3` and call it**

```rust
/// Team lifecycle needs a shared bucket; a local trial vault is solo by
/// design. Refuse with the upgrade pointer instead of a generic validation
/// error.
pub(crate) fn require_s3(profile: &TeamProfile, verb: &str) -> anyhow::Result<()> {
    if profile.storage == StorageBackend::Local {
        anyhow::bail!(
            "cannot {verb} on the local trial profile {name:?}: team mode needs a \
             Hippius bucket. Subscribe, then run: hippius-mem upgrade",
            name = profile.name,
        );
    }

    Ok(())
}
```

Call it first thing in `invite::run`, `mint::run`, `admin::join`, and
`admin::provision` (after profile resolution, before any work).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p hippius-mem --test quickstart_cli`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit — then open the Phase A PR**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings && cargo test
git add -A && git commit -m "feat(cli): team lifecycle commands refuse local trial profiles"
```

Open the Phase A PR with an adversarial review (repo pattern), hostile-critic
focus: key-path escapes in `FsBlobStore`, secret handling in `upgrade`, and
the config backward-compatibility claim.

---

## Phase B — Trust hardening (merges before any public release)

### Task 7: v1 manifest compatibility guarantees, as tests

Lock today's behavior in tests BEFORE touching the format, so Task 8 has a
tripwire for every compatibility promise.

**Files:**
- Test: `hippius-mem-core/src/identity/manifest.rs` tests module

**Interfaces:**
- Consumes: `TeamManifest`, `publish_manifest`, `load_manifest` — existing.
- Produces: a pinned v1 JSON fixture (const in the test module) Tasks 8-9
  must keep loading.

- [ ] **Step 1: Write the tests (they should pass TODAY)**

```rust
#[test]
fn v1_fixture_still_verifies() {
    // Build a manifest with a deterministic test signer, serialize it, and
    // pin the JSON as a const fixture. Deserialize the fixture and assert
    // verify() — if Task 8 changes signing bytes for recovery-free
    // manifests, this fixture breaks and the change is wrong.
}

#[tokio::test]
async fn load_manifest_skips_unknown_field_objects_rather_than_failing() {
    // Put a JSON object with an extra unknown field and a garbage sig under
    // the manifest prefix alongside one valid manifest; load_manifest
    // returns the valid one (skip-not-fatal is what makes an OLD binary
    // fail closed when it meets a v2 manifest).
}
```

- [ ] **Step 2: Run, verify both PASS, commit**

Run: `cargo test -p hippius-mem-core manifest`

```bash
git add hippius-mem-core/src/identity/manifest.rs
git commit -m "test(core): pin v1 manifest fixture and skip-not-fatal loading"
```

### Task 8: recovery key on the manifest (format v2)

**Files:**
- Modify: `hippius-mem-core/src/identity/manifest.rs`
- Test: same file's tests module

**Interfaces:**
- Consumes: `VerifyingKey`, `Signer`, `push_framed` — existing.
- Produces: `TeamManifest.recovery_key: Option<VerifyingKey>`;
  `TeamManifest::create_signed_with_recovery(signer, team, members, version, recovery_key) -> Self`;
  `create_signed` unchanged in signature (delegates with `None`). Task 9's
  chain rule and Task 10's CLI consume both.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn recovery_manifest_signs_under_v2_domain() {
    // create_signed_with_recovery(.., Some(recovery_pub)): verify() passes;
    // signing_bytes() starts with b"hippius-memory-manifest/v2" and differs
    // from the same manifest with recovery stripped.
}

#[test]
fn recovery_free_manifest_is_bitwise_v1() {
    // create_signed_with_recovery(.., None) produces signing_bytes identical
    // to a pre-change manifest (the Task 7 fixture still verifies) and
    // serializes WITHOUT a recovery_key field (skip_serializing_if).
}

#[test]
fn tampered_recovery_key_breaks_the_signature() {
    // Take a signed v2 manifest, replace recovery_key with another key:
    // verify() fails — the recovery key is inside the signed bytes.
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hippius-mem-core manifest`
Expected: FAIL — no `recovery_key` field.

- [ ] **Step 3: Implement**

```rust
/// v2 domain tag: manifests that NAME a recovery key sign under this tag,
/// with the recovery key bytes appended to the v1 layout. A manifest with no
/// recovery key keeps the v1 tag and byte layout exactly, so every existing
/// manifest and signature stays valid without migration.
const MANIFEST_DOMAIN_V2: &[u8] = b"hippius-memory-manifest/v2";
```

Struct field (after `founder_key`):

```rust
    /// Founder-named recovery verifying key, if any. Part of the signed
    /// bytes (v2 domain): naming it is a founder-authorized act, and the
    /// chain rule (load_manifest) lets this key advance the manifest chain
    /// if the founder key is lost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<VerifyingKey>,
```

`signing_bytes` branches on `self.recovery_key`: `None` emits exactly the
current bytes; `Some(key)` emits `MANIFEST_DOMAIN_V2`, the identical framed
fields, then `buf.extend_from_slice(key.as_bytes())`. `create_signed`
delegates to `create_signed_with_recovery(signer, team, members, version, None)`.
`verify()` is UNCHANGED — the signature is always under the manifest's own
`founder_key`; authorization to be at version N is the chain rule's job
(Task 9), not `verify`'s.

- [ ] **Step 4: Run to verify all manifest tests pass (incl. Task 7 fixture)**

Run: `cargo test -p hippius-mem-core manifest`
Expected: PASS.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/identity/manifest.rs
git commit -m "feat(core): manifest v2 names an optional recovery key inside the signed bytes"
```

### Task 9: chain-of-custody load rule

**Files:**
- Modify: `hippius-mem-core/src/identity/manifest.rs` (`load_manifest`, lines ~280-320)
- Test: same file's tests module + `hippius-mem-core/tests/e2e_sharing.rs`
  if it asserts founder behavior (read it; extend, do not duplicate)

**Interfaces:**
- Consumes: Task 8's `recovery_key`.
- Produces: `load_manifest` with the chain rule. Same signature — callers are
  untouched.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn recovery_key_can_advance_the_chain_to_a_new_founder() {
    // v1: founder A signs version 1 naming recovery key R (v2 manifest).
    // v2: R's keypair signs version 2 as the NEW founder (founder = R's
    // ss58, founder_key = R's public key), naming a fresh recovery key R2.
    // load_manifest(None) returns version 2.
}

#[tokio::test]
async fn unauthorized_key_cannot_advance_the_chain() {
    // Version 2 signed by a random keypair X (self-consistent, verify()
    // passes) is SKIPPED: load_manifest returns version 1. This is the seize
    // attempt the chain rule exists to stop.
}

#[tokio::test]
async fn chain_rule_without_recovery_matches_today() {
    // All-v1 manifests by one founder: highest version wins, foreign-founder
    // manifests skipped — behavior identical to the pre-change rule (the
    // existing load_manifest tests keep passing untouched).
}

#[tokio::test]
async fn pinned_founder_anchors_the_chain_start() {
    // Pinned founder A; genesis overwritten by attacker B naming themselves:
    // chain anchors on A's lowest manifest, B is never elected — the
    // existing pin guarantee, restated over the chain walk.
}
```

- [ ] **Step 2: Run to verify the new ones fail**

Run: `cargo test -p hippius-mem-core manifest`
Expected: the two recovery tests FAIL (chain not implemented); the two
compatibility tests PASS already.

- [ ] **Step 3: Implement the chain walk**

Replace the current "filter by trusted founder, take max version" tail of
`load_manifest` with:

```rust
    // Anchor the chain: the pinned founder's lowest-version manifest when a
    // pin is configured, else the genesis (lowest-version) survivor —
    // exactly the two trust modes documented above, unchanged.
    // Then WALK: from the anchor, repeatedly accept the lowest version
    // strictly greater than the current live version whose founder_key is
    // authorized by the current live manifest — its own founder_key
    // (re-publish / membership change) or its named recovery_key (recovery
    // takeover). Anything else under the prefix is skipped + warned, never
    // fatal, preserving this function's contract.
```

Concretely: sort `valid` by version ascending; pick the anchor as today;
loop over the remainder, tracking `live: TeamManifest`; a candidate at
`version > live.version` is accepted iff
`candidate.founder_key == live.founder_key || Some(&candidate.founder_key) == live.recovery_key.as_ref()`;
accepted candidates replace `live`; rejected ones get the existing
`tracing::warn!` treatment with a "does not chain from the live manifest"
message. Keep the function under the repo's size discipline by extracting
the walk into a private `fn elect_live(valid: Vec<TeamManifest>, anchor_founder: &Ss58) -> Option<TeamManifest>`
with its own unit tests.

- [ ] **Step 4: Run the full core suite**

Run: `cargo test -p hippius-mem-core`
Expected: PASS — including every pre-existing manifest and sharing test.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/identity/manifest.rs
git commit -m "feat(core): manifest election walks a chain of custody through recovery keys"
```

### Task 10: recovery in the CLI — `provision` generates, `recover` consumes

**Files:**
- Modify: `hippius-mem/src/admin.rs` (`provision`; new `recover`)
- Modify: `hippius-mem/src/main.rs` (dispatch arm `"recover" => Some(admin::recover(rest).await)`)
- Test: `hippius-mem-core/tests/e2e_sharing.rs` gains the founder-loss e2e;
  CLI arg tests in `admin.rs`'s test module

**Interfaces:**
- Consumes: `create_signed_with_recovery` (Task 8), chain rule (Task 9),
  `publish_manifest`, `load_manifest`.
- Produces: `pub(crate) async fn recover(args: &[String]) -> anyhow::Result<()>`;
  `provision` prints a recovery seed by default (`--no-recovery` opts out).

- [ ] **Step 1: Write the failing e2e**

In `e2e_sharing.rs` (core layer, where the store fixtures live):

```rust
#[tokio::test]
async fn founder_loss_recovers_through_the_recovery_key() {
    // provision-equivalent: founder A publishes v1 naming recovery R.
    // Simulate loss: A's signer is dropped. R signs v2 as new founder
    // naming fresh recovery R2 (the exact manifest `recover` will build).
    // Assert: load_manifest elects v2; a further manifest signed by OLD
    // founder A at v3 is SKIPPED (the old key cannot advance the chain);
    // one signed by R at v3 is accepted.
}
```

- [ ] **Step 2: Run to verify it fails** (it exercises Task 9's rule with the
exact manifests the CLI will produce; if Tasks 8-9 are correct it may already
pass — in that case treat it as a pinned regression test and continue).

Run: `cargo test -p hippius-mem-core --test e2e_sharing founder_loss`

- [ ] **Step 3: Implement `provision` recovery generation**

In `admin::provision`, after the existing manifest publish succeeds: generate
a fresh sr25519 keypair (same seed mechanism as `generate_seed_hex`), rebuild
the manifest via `create_signed_with_recovery(.., Some(recovery_public))` at
the same version, publish, and print ONCE:

```text
RECOVERY SEED (write this down, store offline, it is shown exactly once):
  {seed_hex}
If the founder key is ever lost: hippius-mem recover
```

The seed is never written to config or disk. `--no-recovery` skips all of
this. Wrap the seed in `Zeroizing` (the pattern `join_bundle.rs` already
uses for secrets).

- [ ] **Step 4: Implement `recover`**

`admin::recover(args)`: no argv secrets — prompt for the recovery seed on
tty/stdin (reuse the tty-reading pattern `install.sh`/`join_bundle` use).
Flow: load the live manifest; derive the recovery keypair from the seed;
check it matches `live.recovery_key` (typed error if not); generate a fresh
recovery keypair; build
`create_signed_with_recovery(recovery_signer, team, live.members, live.version + 1, Some(fresh_public))`;
publish; print the new founder SS58, the fresh recovery seed (once), and
LOUDLY: "update founder_ss58 to {new} in every teammate's config — the old
pin no longer matches" (pinned mode anchors the chain start; the pin update
is the operator half of recovery).

- [ ] **Step 5: Run everything, fmt, clippy, commit**

```bash
cargo test && cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/admin.rs hippius-mem/src/main.rs hippius-mem-core/tests/e2e_sharing.rs
git commit -m "feat(cli): provision names a recovery key; recover rotates the founder through it"
```

### Task 11: stale `max_epoch` warning

**Files:**
- Create: helper in `hippius-mem-core/src/identity/teamkey.rs` (where the
  wrapped-key publishing lives — read it first to find the epoch object
  prefix)
- Modify: `hippius-mem/src/doctor.rs`, `hippius-mem/src/brief.rs`,
  `hippius-mem/src/server.rs` (warmup path, ~line 240 where sync logging
  lives)
- Test: unit test beside the helper; doctor CLI assertion

**Interfaces:**
- Produces: `pub async fn highest_published_epoch(blob: &dyn BlobStore, team: &str) -> Result<u64, MemError>`
  in `teamkey.rs` — lists the wrapped-key/epoch prefix and returns the
  highest epoch number found (0 when none).

- [ ] **Step 1: Write the failing test**

Beside the helper (using `MemoryBlobStore` seeded with wrapped-key objects at
epochs 0..=2 through the existing publish path in `teamkey.rs`):

```rust
#[tokio::test]
async fn highest_published_epoch_reads_the_epoch_objects() {
    // Publish wrapped keys for epochs 0, 1, 2 via the existing teamkey
    // publish fn; assert highest_published_epoch == 2; an empty store
    // reports 0.
}
```

- [ ] **Step 2: Run to verify it fails, implement, run to verify it passes**

Run: `cargo test -p hippius-mem-core teamkey`

Implementation: `list` the epoch prefix `teamkey.rs` already writes under,
parse the epoch number out of each key with the same parsing the read path
uses (do not re-derive the format — call or extract the existing parser),
`max()` with default 0.

- [ ] **Step 3: Wire the warning into doctor, brief, and serve warmup**

At each site, after the store is built (config's `max_epoch` is in scope):

```rust
    let published = highest_published_epoch(blob.as_ref(), &profile.name).await;
    if let Ok(published) = published
        && published > max_epoch
    {
        tracing::warn!(
            configured = max_epoch,
            published,
            "this machine's max_epoch hides rotated notes: raise max_epoch to {published} \
             in the [[teams]] profile or new-epoch notes stay invisible"
        );
    }
```

(`doctor` prints it as a WARN line in its report output rather than a
tracing event — follow doctor's existing output style. A fetch failure is
silent here: the warning is best-effort, never a new failure mode.)

- [ ] **Step 4: Test the doctor surface**

Extend doctor's test (or a CLI test if doctor has one — check
`hippius-mem/src`) with: config `max_epoch = 0`, store holding epoch-1
wrapped keys, doctor output contains "raise max_epoch to 1".

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/identity/teamkey.rs hippius-mem/src/doctor.rs \
  hippius-mem/src/brief.rs hippius-mem/src/server.rs
git commit -m "feat: warn loudly when a stale max_epoch hides rotated notes"
```

### Task 12: resumable `remove` and the half-done doctor check

**Files:**
- Modify: `hippius-mem/src/admin.rs` (`remove`, `plan_removal`,
  `publish_and_rotate` — lines ~199-440)
- Modify: `hippius-mem/src/doctor.rs`
- Test: `admin.rs` test module + the rotate e2e named in the adoption plan
  (`provision -> join -> rotate` exists; extend it)

**Interfaces:**
- Consumes: `MemError::NothingToRotate` (exists in the error enum),
  `load_manifest`, `highest_published_epoch` (Task 11).
- Produces: `remove` that is safe to re-run; a doctor check
  "removed member still holds the current epoch key".

- [ ] **Step 1: Write the failing tests**

In `admin.rs`'s test module (it already unit-tests `plan_removal` and arg
parsing — follow that style):

```rust
#[tokio::test]
async fn remove_skips_republish_when_member_already_gone() {
    // Manifest already lacks the target: plan_removal must produce a plan
    // whose republish step is Skip (already done), not an error — the
    // re-run-after-partial-failure case.
}

#[tokio::test]
async fn remove_treats_nothing_to_rotate_as_done() {
    // publish_and_rotate hitting NothingToRotate after a successful
    // republish completes the command successfully (with the revoke
    // reminder printed), instead of leaving the recorded gotcha state:
    // membership shrunk, key un-rotated, command failed.
}
```

And the doctor check test: seed a store where the current epoch's wrapped-key
recipient set contains an SS58 absent from the live manifest; doctor output
contains "run: hippius-mem rotate".

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hippius-mem admin`

- [ ] **Step 3: Implement resumability**

Rework `remove`'s flow into explicit idempotent steps:

1. Load live manifest. If the target is still a member: republish without
   them (as today). If already absent: print "membership already excludes
   {ss58} (resuming)" and continue.
2. Rotate. `Ok` and `Err(NothingToRotate)` both count as success —
   `NothingToRotate` means a prior run (or a manual rotate) already advanced
   the epoch past the removal.
3. Always end with `pending_revoke_reminder(&target)` (the existing fn) —
   the one manual console step, printed on every run including resumed ones.

- [ ] **Step 4: Implement the doctor check**

In doctor: load the live manifest and the current epoch's wrapped-key
recipient set (the read path in `teamkey.rs` exposes who the epoch key is
wrapped for — read it and reuse). For any recipient not in the manifest:

```text
WARN removed member {ss58} still holds the current epoch key
     run: hippius-mem rotate   (then revoke their sub-token in the console)
```

- [ ] **Step 5: Run all tests, fmt, clippy, commit — then open the Phase B PR**

```bash
cargo test && cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/admin.rs hippius-mem/src/doctor.rs
git commit -m "feat(cli): remove is resumable and doctor flags half-done removals"
```

Adversarial review focus for the PR: can the chain rule be walked to a
manifest an attacker controls; can `recover` be replayed; does resumable
`remove` ever skip a still-needed rotation.

---

## Phase C — ROI report

### Task 13: report aggregation in core

**Files:**
- Create: `hippius-mem-core/src/report.rs`
- Modify: `hippius-mem-core/src/lib.rs` (module + re-exports)
- Test: unit tests in `report.rs` over a seeded `MemoryStore`

**Interfaces:**
- Consumes: converged `MemoryStore` state (read-only; find the reinforce
  distinct-author data where `recall`'s Sybil-bounded counting already lives
  — grep `Reinforce` in `hippius-mem-core/src` and read that module first).
- Produces:

```rust
pub struct ReportWindow {
    /// Milliseconds since epoch, inclusive.
    pub since_ms: u64,
    /// Milliseconds since epoch, exclusive.
    pub until_ms: u64,
}

pub struct NoteReuse {
    pub id: String,
    pub summary: String,
    pub distinct_reinforcers: u64,
}

pub struct ActivityCounts {
    pub added: u64,
    pub edited: u64,
    pub linked: u64,
    pub tombstoned: u64,
    pub redacted: u64,
}

pub struct TeamReport {
    pub window: ReportWindow,
    pub reuse: Vec<NoteReuse>,
    pub activity: ActivityCounts,
}

pub async fn build_report(
    store: &MemoryStore,
    window: ReportWindow,
) -> Result<TeamReport, MemError>;
```

- [ ] **Step 1: Write the failing unit tests**

```rust
#[tokio::test]
async fn report_counts_window_activity() {
    // Seed: 3 remembers, 1 edit, 1 link, 1 forget inside the window; 1
    // remember outside it. Assert added == 3, edited == 1, linked == 1,
    // tombstoned == 1, and the outside op is excluded.
}

#[tokio::test]
async fn reuse_ranks_by_distinct_reinforcers() {
    // Two notes; note A reinforced by 2 distinct authors, note B by 1 (and
    // by the same author twice — must still count 1). reuse[0] is A with
    // distinct_reinforcers == 2.
}

#[tokio::test]
async fn empty_window_is_a_valid_quiet_report() {
    // A window with no ops: all counts zero, reuse empty, no error.
}
```

- [ ] **Step 2: Run to verify they fail, implement, run to verify they pass**

Run: `cargo test -p hippius-mem-core report`

Implementation notes: pure fold over the already-converged op replay state —
no blob fetches, no new op kinds, no mutation. Reuse the existing
Sybil-bounded distinct-author logic rather than re-implementing it (call the
fn where it lives; extract it `pub(crate)` if needed). `reuse` sorted by
`distinct_reinforcers` descending, capped at 20 entries (log the cap in the
markdown, Task 14 — no silent truncation).

- [ ] **Step 3: fmt, clippy, commit**

```bash
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem-core/src/report.rs hippius-mem-core/src/lib.rs
git commit -m "feat(core): build_report aggregates reuse and activity from converged state"
```

### Task 14: `report` CLI and dashboard panel

**Files:**
- Create: `hippius-mem/src/report.rs`
- Modify: `hippius-mem/src/main.rs` (dispatch arm `"report"`),
  `hippius-mem/src/dashboard/mod.rs` + `dashboard.html` (panel)
- Test: `hippius-mem/tests/report_cli.rs`

**Interfaces:**
- Consumes: `build_report` (Task 13), `admin::bootstrap_epochs` (mirror
  `brief.rs` — `report` is a new full-memory entry point, the recorded
  gotcha applies).
- Produces: `pub(crate) async fn run(args: &[String]) -> anyhow::Result<()>`;
  dashboard JSON endpoint `/api/report` returning the `TeamReport` shape.

- [ ] **Step 1: Write the failing CLI test**

```rust
//! report renders the converged-data digest with the honesty label.

#[test]
fn report_renders_markdown_leading_with_reuse() {
    // Seeded local-profile store (quickstart fixture from Phase A), two
    // reinforced notes. Run ["report"]. Assert exit 0 and stdout: first
    // section header is reuse ("saved" phrasing), then activity; the string
    // "this machine only" labels the local-recall section; a "top 20" cap
    // note appears when the cap truncates.
}

#[test]
fn report_supports_since() {
    // ["report", "--since", "30d"] parses; ["report", "--since", "bogus"]
    // exits non-zero naming the accepted forms (7d default, Nd, Nw).
}
```

- [ ] **Step 2: Run to verify it fails, implement CLI, run to verify it passes**

Run: `cargo test -p hippius-mem --test report_cli`

Implementation: parse `--since` (default `7d`); resolve the profile, build
the store, `bootstrap_epochs` exactly as `brief.rs` does, `build_report`,
render markdown in this order: window header; reuse ("`{summary}` — saved
{n} teammates"); activity table; a final "This machine" section for local
recall counts with the literal label "this machine only". Renderer is a pure
`fn render_markdown(report: &TeamReport) -> String` with its own unit test.

- [ ] **Step 3: Dashboard panel**

Add `/api/report` to `dashboard/mod.rs` serving `build_report` over the same
store the dashboard already holds, serialized with serde. In
`dashboard.html`, add a "This week" panel fetching it and rendering the same
three sections (follow the file's existing fetch/render idiom). Test: extend
the dashboard's existing endpoint tests (see how `mod.rs` tests routes) to
assert `/api/report` returns the seeded counts — the same numbers the CLI
rendered (the design's parity requirement).

- [ ] **Step 4: fmt, clippy, commit — then open the Phase C PR**

```bash
cargo test && cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/src/report.rs hippius-mem/src/main.rs \
  hippius-mem/src/dashboard/ hippius-mem/tests/report_cli.rs
git commit -m "feat: hippius-mem report renders the team ROI digest from converged data"
```

---

## Phase D — Release readiness

### Task 15: `install.sh` binary fast path

**Files:**
- Modify: `scripts/install.sh`

**Interfaces:**
- Consumes: cargo-dist artifact naming from `docs/RELEASING.md`'s matrix:
  `hippius-mem` app for aarch64-apple-darwin / x86_64-unknown-linux-gnu /
  aarch64-unknown-linux-gnu; `hippius-mem-lean` for x86_64-apple-darwin;
  `.tar.xz` archives + `sha256` files per cargo-dist convention; public repo
  `thenervelab/hippius-mem-releases`.
- Produces: `install.sh` that prefers binary download; source build becomes
  the fallback.

- [ ] **Step 1: Write the fast path**

New function before the existing rust bootstrap, POSIX sh (the file is
`#!/bin/sh` — no bashisms), structured:

```sh
# Binary fast path: resolve target triple from uname, download the latest
# release artifact + checksum from the public releases repo, verify, unpack
# into ~/.local/bin (or $HIPPIUS_MEM_BIN_DIR). Falls through to the source
# build when: no matching artifact, no curl, checksum mismatch (mismatch
# also prints a loud warning), or --from-source was passed.
resolve_target() {
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) echo "aarch64-apple-darwin" ;;
        Darwin-x86_64) echo "x86_64-apple-darwin" ;;
        Linux-x86_64) echo "x86_64-unknown-linux-gnu" ;;
        Linux-aarch64) echo "aarch64-unknown-linux-gnu" ;;
        *) echo "" ;;
    esac
}
```

Download URL shape:
`https://github.com/thenervelab/hippius-mem-releases/releases/latest/download/{app}-{target}.tar.xz`
where `{app}` is `hippius-mem-lean` for `x86_64-apple-darwin` (print one
line explaining lexical-only recall on that target, per Retrieval honesty)
and `hippius-mem` otherwise. Verify with `shasum -a 256 -c` / `sha256sum -c`
(whichever exists). After unpack: the SAME steps 3-5 the script already runs
(config prompts, `install`/`init` wiring, `doctor --offline`) — extract them
into functions if needed so both paths share them; do not duplicate the
prompt logic.

Update the header comment block: binary path first, source build second,
`--from-source` documented.

- [ ] **Step 2: Lint and dry-run**

Run: `shellcheck scripts/install.sh` — clean.
Run: `sh scripts/install.sh --from-source --update` on this machine —
the source path still works end-to-end (binary path returns 404 until a
release exists; verify the fallthrough message is clear by running plain
`sh scripts/install.sh` and watching it fall through gracefully).

- [ ] **Step 3: Commit**

```bash
git add scripts/install.sh
git commit -m "feat(install): prefer release-binary download, source build as fallback"
```

### Task 16: enable Homebrew publish, dry-run dist, rewrite the checklist

**Files:**
- Modify: `dist-workspace.toml` (publish-jobs)
- Modify: `docs/RELEASING.md` (the HELD section becomes the ready-to-fire
  checklist)

- [ ] **Step 1: Enable the homebrew publish job**

In `dist-workspace.toml`, add `publish-jobs = ["homebrew"]` where the
comment at lines 17-19 says it is deliberately absent, and delete that
comment (the tap repo `thenervelab/homebrew-tap` already exists; this was
Task 1.2's remaining wiring).

- [ ] **Step 2: Dry-run what the held gate allows**

Run: `dist plan` — must succeed and list all four artifacts.
Run: `dist build` — host-target artifact builds; run `./target/distrib/.../hippius-mem doctor --offline` from the raw artifact.
Run: `zizmor .github/workflows/release.yml && actionlint` — clean.
Record versions/output in the commit message body if anything surprises.

- [ ] **Step 3: Rewrite the HELD section as the ready-to-fire checklist**

Replace `docs/RELEASING.md` section 1's HELD block with a numbered
checklist, preserving the token preflight and adding the two verifications
that need a live release:

```markdown
## 1. Ready-to-fire checklist (run top to bottom when the green light lands)

1. Create the public repo `thenervelab/hippius-mem-releases` (one commit on
   the default branch).
2. Create a `repo`-scoped PAT for it; store as `GH_RELEASES_TOKEN` in
   `thenervelab/hippius-mem`.
3. Preflight: `GH_TOKEN=$THE_PAT gh api repos/thenervelab/hippius-mem-releases` returns the repo.
4. Version-lockstep PR: 0.1.0 in `hippius-mem/Cargo.toml`,
   `hippius-mem-core/Cargo.toml`, `dist-lean/dist.toml`; confirm the
   `version-lockstep` workflow passed BEFORE tagging.
5. Tag the merged commit `v0.1.0` and push the tag.
6. Verify on a clean machine: `brew install thenervelab/tap/hippius-mem && hippius-mem doctor --offline`.
7. Verify `sh scripts/install.sh` takes the binary path on a machine with no
   Rust toolchain.
8. Flip the README Install section to binary-first (brew, then install.sh,
   then source).
```

Keep the rest of the runbook (sections 2+) as is.

- [ ] **Step 4: Commit — then open the Phase D PR**

```bash
git add dist-workspace.toml docs/RELEASING.md
git commit -m "chore(release): enable homebrew publish and write the ready-to-fire checklist"
```

---

## Phase E — Docs and stated limits

### Task 17: scale ceiling, multi-admin design doc, packaging statement

**Files:**
- Create: `docs/plans/2026-08-XX-multi-admin-design.md` (date it when written)
- Modify: `docs/REFERENCE.md` (new "Operational limits" section)
- Modify: `README.md` (packaging statement in the pitch/install area)

- [ ] **Step 1: Operational limits section in `docs/REFERENCE.md`**

State plainly: the index is in-memory and rebuilt from the op-log;
history/sync re-verify op signatures; the measured data point (a ~590-op log
took ~20s to fetch cold because the gateway saturates on small-object
fan-out); what this means operationally (teams with long histories see slow
cold syncs before anything else degrades); and the plan of record — port the
op-log to S4/hippius-log when it lands (deletes the fan-out), LanceDB ANN
for the index after that. Cite the perf notes under `docs/perf/` if the
measurement lives there (check; otherwise cite the team-memory note id).

- [ ] **Step 2: Multi-admin design doc**

Write `docs/plans/2026-08-XX-multi-admin-design.md` using what Phase B
taught: the chain-of-custody rule generalized from {founder, recovery} to an
m-of-n signer set; admin add/remove as chain acts; how `verify()` stays
per-manifest while authorization stays in the walk; migration from v2
(recovery) manifests; open questions (threshold signatures vs multi-sig
lists; recovery among admins). Design only — mark it explicitly as not
scheduled in this program.

- [ ] **Step 3: Packaging statement in README**

One short block in the pitch area: the binary is free and installable by
anyone; the product is your team's Hippius storage subscription (the bucket
memory lives in); no per-seat pricing. Keep the positioning line from the
docs split ("memory your security team will actually approve") intact.

- [ ] **Step 4: Link check and commit**

Run the docs link checker the drift guard uses (see
`.github/workflows/` docs job) locally over the touched files.

```bash
git add docs/REFERENCE.md docs/plans/2026-08-XX-multi-admin-design.md README.md
git commit -m "docs: stated scale ceiling, multi-admin design, packaging statement"
```

---

## Completion

After all phases merge: `mcp__hippius-mem__remember` the durable decisions
this program created (no-free-tier trial posture; manifest v2 chain rule;
report honesty labeling), one note each, keyword-rich summaries. Then the
program's remaining work is exactly one item: the green-light decision that
fires the Task 16 checklist.
