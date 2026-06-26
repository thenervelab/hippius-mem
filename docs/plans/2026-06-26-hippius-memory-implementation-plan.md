# Hippius Memory Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
>
> **Rust workflow (per repo CLAUDE.md):** before each Rust task run `mcp__illu__rust_preflight`,
> consult `mcp__illu__project_style` + `mcp__illu__decisions`, pull `mcp__illu__exemplars` when the
> task hits a trigger keyword (newtype, thiserror, RAII, typestate…), and finish each Rust diff with
> `mcp__illu__critique` then `mcp__illu__quality_gate` (with the seven `self_review_*` answers).

**Goal:** Build a Rust MCP server that gives a team's coding agents shared, cross-machine,
context-efficient memory stored on the Hippius S3 gateway, with per-dev cryptographic
attribution and an on-chain audit trail.

**Architecture:** A Cargo workspace with a `hippius-mem-core` library (domain types, crypto,
S3 blob store, LanceDB hybrid index, op-log) and a `hippius-mem` binary (the `rmcp` MCP server +
config). Memory notes are ChaCha20-Poly1305-encrypted client-side and stored as objects in one
shared team bucket keyed `team/repo/mem_id/rev_N`. A local embedded LanceDB holds the mutable
hybrid (vector + BM25) index keyed by object key; `recall` returns pointers + summaries, `get`
hydrates bodies. Multi-writer convergence rides a dev-signed append-only op-log in the bucket;
batched Merkle roots anchor on-chain via `subxt` + `frame_system.remark`.

**Tech Stack (versions verified against crates.io on 2026-06-26):**
- `rmcp` 1.8.0 — official Anthropic Rust MCP SDK (server + tools, async/Tokio)
- `aws-sdk-s3` 1.137.0 — S3 client pointed at the Hippius S3 gateway endpoint
- `lancedb` 0.30.0 — embedded vector DB with **native BM25 full-text + hybrid search**
- `fastembed` 5.17.2 — local ONNX embeddings + reranking (no external API key)
- `chacha20poly1305` 0.10.1 — AEAD (matches the cipher hcfs already uses)
- `blake3` 1.x — content hash for integrity + audit-anchor input
- `subxt` 0.50.1 + `subxt-signer` — chain client + sr25519 signing (Phase 2)
- `ulid` 1.x — sortable note ids; `tokio` 1.x; `serde`/`serde_json` 1.x; `thiserror` 2.x; `anyhow` 1.x

**Phasing:** Phase 1 (this plan, detailed) = the memory core + MCP tools, no chain. Phases 2–4
are outlined at the end and get their own detailed plans once Phase 1 is dogfooded.

---

## Core types & ownership (build this mental model first)

```rust
// hippius-mem-core/src/domain.rs
pub struct NoteId(ulid::Ulid);                 // renders as "mem_<ulid>"
pub struct Ss58(String);                       // validated SS58 account string
pub struct Blake3Hash([u8; 32]);               // ciphertext content hash

pub enum RepoScope { Global, Repo(String) }
pub struct Scope { pub team: String, pub repo: RepoScope }

pub enum NoteType { Decision, Convention, Gotcha, Reference, Context }

pub struct Note {
    pub id: NoteId,
    pub scope: Scope,
    pub note_type: NoteType,
    pub author: Ss58,
    pub created: time::OffsetDateTime,
    pub updated: time::OffsetDateTime,
    pub tags: std::collections::BTreeSet<String>,   // deterministic frontmatter
    pub links: std::collections::BTreeSet<NoteId>,
    pub summary: String,                            // <= 1 sentence, returned by recall
    pub body: String,                               // full text, returned by get
}
```

- **Ownership:** `MemoryStore { s3: aws_sdk_s3::Client, index: lancedb::Connection, key: SecretKey, cfg: Config }`
  is built once and shared as `Arc<MemoryStore>`; the rmcp handler holds the `Arc` and each tool
  borrows `&MemoryStore`. Tokio async throughout; `Arc` gives Send+Sync.
- **Invariants:** invalid states unrepresentable — `NoteType`/`RepoScope` are enums not strings;
  `NoteId` only constructible from a valid ULID; `Ss58` validates on construction.
- **Errors:** `MemError` (thiserror, `#[non_exhaustive]`) with `#[from]` for S3, LanceDB, serde,
  crypto, io; `anyhow` only in `main`. (Per global standard: thiserror in libs, anyhow in apps.)

---

## Task 0: Workspace scaffolding

**Files:**
- Create: `Cargo.toml` (workspace), `hippius-mem-core/Cargo.toml`, `hippius-mem-core/src/lib.rs`
- Create: `hippius-mem/Cargo.toml`, `hippius-mem/src/main.rs`
- Create: `rust-toolchain.toml`, `.gitignore`, `rustfmt.toml`

**Step 1: Create the workspace manifest**

```toml
# Cargo.toml
[workspace]
members = ["hippius-mem-core", "hippius-mem"]
resolver = "3"

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "warn"
panic = "deny"
todo = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
module_name_repetitions = "allow"

[workspace.lints.rust]
missing_docs = "warn"
unreachable_pub = "warn"
```

The core crate's `lib.rs` starts with:
```rust
#![deny(missing_docs)]
#![warn(rust_2018_idioms, missing_debug_implementations, unreachable_pub, rustdoc::broken_intra_doc_links)]
//! Hippius Memory core: domain types, crypto, S3 blob store, hybrid index, op-log.
```
(Strict crate lints from axiom `rust_quality_20_standard_crate_lints`.)

**Step 2: Build the empty workspace**

Run: `cargo build`
Expected: PASS (two empty crates compile).

**Step 3: Commit**

```bash
git add Cargo.toml hippius-mem-core hippius-mem rust-toolchain.toml .gitignore rustfmt.toml
git commit -m "Scaffold hippius-mem workspace (core lib + server bin)"
```

---

## Task 1: Domain types + serde JSON round-trip

> **Decided 2026-06-26 (supersedes the YAML-frontmatter sketch below):** the canonical
> blob format is **JSON via serde**, not a YAML `---` frontmatter block. The stored blob
> is ChaCha20-Poly1305 ciphertext, so a human-readable on-disk format buys nothing, and
> `serde_yaml` is unmaintained. `Note::to_json`/`from_json` replace `frontmatter::serialize`/
> `parse`; no `frontmatter.rs`. A frontmatter rendering for human export is a deferred
> display concern. The round-trip proptest below applies to the JSON form.

**Files:**
- Create: `hippius-mem-core/src/domain.rs` (types + `to_json`/`from_json`)
- Test: in-file `#[cfg(test)]` modules + a `proptest!` block

**Step 1: Write the failing tests**

```rust
// domain.rs tests
#[test]
fn note_id_renders_with_prefix() {
    let id = NoteId::new();
    assert!(id.to_string().starts_with("mem_"));
}

#[test]
fn note_type_parses_known_kinds_and_rejects_unknown() {
    assert_eq!("decision".parse::<NoteType>().unwrap(), NoteType::Decision);
    assert!("banana".parse::<NoteType>().is_err());
}

// frontmatter.rs proptest: serialize -> parse is identity
proptest::proptest! {
    #[test]
    fn frontmatter_round_trips(note in any_note_strategy()) {
        let text = frontmatter::serialize(&note);
        let parsed = frontmatter::parse(&text).unwrap();
        prop_assert_eq!(note, parsed);
    }
}
```

**Step 2: Run to verify failure**

Run: `cargo test -p hippius-mem-core domain frontmatter`
Expected: FAIL (types/functions not defined).

**Step 3: Implement** the types from "Core types & ownership" plus `serialize`/`parse` (YAML
frontmatter `---` block + prose body). Use `BTreeSet` so tag/link order is deterministic
(round-trip stability). `FromStr` for `NoteType` returns a typed error, never panics.

**Step 4: Run to verify pass**

Run: `cargo test -p hippius-mem-core`
Expected: PASS.

**Step 5: Commit**

```bash
git add hippius-mem-core/src/domain.rs hippius-mem-core/src/frontmatter.rs hippius-mem-core/src/lib.rs
git commit -m "Add note domain types and frontmatter round-trip (proptest)"
```

> Rust-gate reminder: this task adds a non-trivial pure function (frontmatter parse/serialize) →
> the `proptest!` round-trip above is mandatory (axiom `rust_quality_111`).

---

## Task 2: Error type

**Files:** Create `hippius-mem-core/src/error.rs`

**Step 1–4 (TDD):** test that each variant `Display`s with actionable context and that `?`
propagation from an `io::Error` produces `MemError::Io`. Then implement:

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MemError {
    #[error("note {id} not found")]
    NotFound { id: String },
    #[error("storage error: {0}")]
    Storage(String),                          // wraps aws-sdk-s3 SdkError display
    #[error("index error: {0}")]
    Index(#[from] lancedb::Error),
    #[error("serialize error: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("crypto error: ciphertext failed authentication")]
    Crypto,                                    // never leak key/nonce detail
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
```
(S3 `SdkError` is generic over the operation, so it is mapped to `Storage(String)` rather than a
single `#[from]` — verify the exact `SdkError` shape via `mcp__illu__docs` for `aws-sdk-s3` before
implementing.)

**Step 5: Commit** — `git commit -m "Add MemError type"`

---

## Task 3: Crypto module (encrypt/decrypt + content hash)

**Files:** Create `hippius-mem-core/src/crypto.rs`

**Step 1: Write the failing tests** (round-trip + tamper-detection + edge cases)

```rust
proptest::proptest! {
    #[test]
    fn encrypt_then_decrypt_is_identity(plaintext in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let key = SecretKey::from_bytes([7u8; 32]);
        let blob = crypto::seal(&key, &plaintext);
        prop_assert_eq!(crypto::open(&key, &blob).unwrap(), plaintext);
    }
}

#[test]
fn tampered_ciphertext_fails_auth() {
    let key = SecretKey::from_bytes([7u8; 32]);
    let mut blob = crypto::seal(&key, b"hello");
    *blob.last_mut().unwrap() ^= 0xff;
    assert!(matches!(crypto::open(&key, &blob), Err(MemError::Crypto)));
}

#[test]
fn empty_plaintext_round_trips() {              // ChaCha20-Poly1305 edge: empty input is valid
    let key = SecretKey::from_bytes([7u8; 32]);
    assert_eq!(crypto::open(&key, &crypto::seal(&key, b"")).unwrap(), b"");
}
```

**Step 2: Run to verify failure.** Run: `cargo test -p hippius-mem-core crypto` → FAIL.

**Step 3: Implement** `seal` (random 24-byte XNonce via `OsRng`, prepend nonce to ciphertext) and
`open` over `XChaCha20Poly1305`, plus `content_hash(bytes) -> Blake3Hash`.

> External-library edges (axiom `rust_quality_110`): verify in the `chacha20poly1305` 0.10 docs that
> `XChaCha20Poly1305::encrypt` accepts empty plaintext and that the 24-byte `XNonce` must be unique
> per key; the tests above exercise empty input + tamper. Hold the key in `zeroize::Zeroizing`.

**Step 4: Pass.** **Step 5: Commit** — `git commit -m "Add ChaCha20-Poly1305 seal/open + blake3 hash (proptest)"`

---

## Task 4: Object-key derivation

**Files:** Create `hippius-mem-core/src/objkey.rs`

Pure function `object_key(scope, note_id, rev) -> String` = `"{team}/{repo}/{mem_id}/rev_{n}"`
(`repo` = `"global"` for `RepoScope::Global`). 

**TDD:** a `proptest!` asserting the key is stable, contains no `..`/leading-slash (path-safety),
and that `(scope, id, rev)` are recoverable by a parser `parse_object_key` (round-trip). Commit.

---

## Task 5: S3 blob store

**Files:** Create `hippius-mem-core/src/store/blob.rs`

**Step 1: Define the seam as a trait** so unit tests use an in-memory fake and only an opt-in
integration test hits a real gateway:

```rust
#[async_trait::async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError>;
    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError>;
}
```

**Step 2: Unit-test against an in-memory `HashMap` fake** (put/get round-trip, get-missing →
`NotFound`, list-by-prefix). These run in CI with no network.

**Step 3: Implement `S3BlobStore`** wrapping `aws_sdk_s3::Client` built with a custom
`endpoint_url` (the Hippius S3 gateway), `force_path_style(true)`, and static credentials from the
sub-token (`access_key_id` + `secret`). Map `SdkError` → `MemError::Storage`.

> Verify via `mcp__illu__docs` / `mcp__illu__cross_query repo:"hippius-s3"`: the exact endpoint,
> whether path-style is required, and the `GetObject` not-found error shape (so `get` maps a missing
> key to `NotFound`, not a generic storage error). Edge cases to test: empty object, missing key,
> prefix with no matches.

**Step 4: Integration test** behind `#[cfg(feature = "s3-integration")]` against MinIO/testcontainers
or a real bucket from env. **Step 5: Commit.**

---

## Task 6: Hybrid index (in-memory, behind a trait)

> **Decided 2026-06-26 (supersedes the LanceDB-now sketch):** Phase 1 ships an
> **in-memory** hybrid index behind a `MemoryIndex` trait, plus an `Embedder` trait
> (deterministic fake for tests; real `fastembed` behind an optional `embeddings`
> feature). LanceDB + fastembed are heavy native deps (large native lib; ONNX runtime
> + runtime model download) — premature for dogfood scale and they make unit tests
> network-dependent. The index is rebuildable, so swapping in LanceDB later (scale phase)
> behind the same trait is clean. This keeps the default build light and tests deterministic.

**Files:** Create `hippius-mem-core/src/index/mod.rs`

The index record: `{ note_id, object_key, cid, scope, note_type, author, updated_ts,
tags, summary, embedding }`.

Traits:
```rust
pub trait Embedder: Send + Sync {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError>;  // batch
    fn dim(&self) -> usize;
}
// HashEmbedder: deterministic, fixed small dim — for tests + offline fallback.
// FastEmbedder (behind `embeddings` feature, optional `fastembed` dep) — real semantics.

pub trait MemoryIndex: Send + Sync {
    fn upsert(&self, record: IndexRecord) -> Result<(), MemError>;
    fn search(&self, q: &Query) -> Result<Vec<Pointer>, MemError>;  // pointers, never bodies
    fn remove(&self, id: NoteId) -> Result<(), MemError>;
}
// InMemoryIndex: Mutex<Vec<IndexRecord>>; scope-filter → (keyword BM25-lite + cosine)
// → RRF fuse → recency decay by note_type → pack to token_budget.
```

**Steps (TDD):**
1. Test: `upsert` one record; `search` returns its `Pointer` (note_id + summary + score), **not** its body.
2. Test: scope filter — a `repo: thebrain` query does not return a `repo: other` note.
3. Test: recency — two equally-relevant notes; the more recently `updated` ranks first.
4. `proptest!` on RRF fusion: fusing two rankings is order-stable and a doc ranked top of both legs ranks first.
5. Implement: scope filter first, keyword leg (token-overlap/BM25-lite) + cosine leg over `Embedder` vectors, RRF fuse (rank-constant ~60), recency multiplier keyed on `note_type`, pack to `token_budget`.

**Commit** — `git commit -m "Add in-memory hybrid MemoryIndex + Embedder trait (RRF + recency, proptest)"`

---

## Task 7: MemoryStore (wire crypto + blob + index)

**Files:** Create `hippius-mem-core/src/store/mod.rs`

`MemoryStore::remember(input) -> NoteId`: build `Note` → `frontmatter::serialize` →
`crypto::seal` → `blob.put(object_key, …)` → `index.upsert(record_with_summary)`.
`recall(query, scope, token_budget) -> Vec<Pointer>`: index search → pack summaries to budget.
`get(ids) -> Vec<Note>`: `blob.get` → `crypto::open` → `frontmatter::parse`.

**TDD:** an end-to-end test using the in-memory `BlobStore` fake + a temp LanceDB: `remember`
three notes, `recall` returns pointers (no bodies), `get` on a chosen id returns the full note.
Assert `recall`'s payload size honors `token_budget`. **Commit.**

---

## Task 8: MCP server (rmcp tools)

**Files:** Create `hippius-mem/src/server.rs`, `hippius-mem/src/main.rs`

Expose `remember`, `recall`, `get` as `rmcp` tools over stdio (Phase 1 transport). Each tool
deserializes its params, calls the `Arc<MemoryStore>`, and returns JSON. `recall` returns pointers
+ summaries only.

> Verify the `rmcp` 1.8 tool-handler API via `mcp__context7__query-docs /websites/rs_rmcp`
> ("define a tool with the #[tool] macro and serve over stdio"). Do NOT assume the macro shape from
> memory.

**TDD:** an integration test that drives the server in-process through the rmcp client, calls
`remember` then `recall`, and asserts the round-trip. **Commit.**

---

## Task 9: Configuration

**Files:** Create `hippius-mem/src/config.rs`

Load from env / a `hippius-mem.toml`: S3 `endpoint_url`, `bucket`, `access_key_id`, `secret`
(the sub-token), `team`, and the team encryption key (read from the OS keychain via `keyring`,
env fallback for headless). Validate on startup; fail fast with an actionable message naming the
missing field. **TDD** the validation paths (missing field, malformed key). **Commit.**

---

## Task 10: End-to-end smoke test + README

A `#[cfg(feature = "s3-integration")]` end-to-end test: real (or MinIO) bucket, real LanceDB,
`remember` → `recall` → `get` across two `MemoryStore` instances sharing the bucket (simulating
two machines) to prove cross-machine sharing. Write a short `README.md` with run instructions and
the first-run embedding-model-download note. **Commit.**

---

## Phases 2–4 (outline — detailed plans follow Phase 1 dogfooding)

**Phase 2 — Accountability + multi-writer convergence.** Dev-signed `Op` records in an append-only
op-log object stream in the bucket; hash-chaining (`prev_op_hash`); op-log tailing to refresh each
machine's index; field convergence (Lamport + author-ss58 tie-break; OR-Set tags/links; tombstone
wins). `history` tool. Batched Merkle anchoring via `subxt` 0.50.1 + `frame_system.remark_with_event`
signed by the dev's sr25519 key; Merkle inclusion proofs in `history`. **Resolve open item: the
`remark` fee + whether the public RPC node accepts extrinsic submission** (verify against `thebrain`
+ a testnet node before building).

**Phase 3 — Identity & team.** Per-dev sub-token minting flow (`/api/objectstore/sub-tokens/`),
mnemonic→sr25519/ETH derivation (reuse the desktop `derive_keys` pattern), signed `team-manifest`,
**team-key provisioning/rotation** (the open item), `forget` tombstones, `link`, membership-change
auditing.

**Phase 4 — Hardening & cold start.** Index snapshot/restore from the bucket for new machines;
convergence stress tests (concurrent writers, partition replay); team-key rotation; performance
pass with a criterion baseline before any optimization (axiom `illu_perf_01`).

---

## Verification discipline (every Rust task)

- `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --all` clean before commit.
- `proptest!` on every pure function (frontmatter, crypto, objkey, RRF fusion, Merkle proofs).
- Tests go through the public API (`MemoryStore::remember`), not direct LanceDB/S3 writes (axiom `rust_quality_111`).
- `mcp__illu__critique` then `mcp__illu__quality_gate` (with the seven `self_review_*` answers) on each diff.
- No `unsafe` is expected; if any appears, `cargo +nightly miri test` the module (axiom `rust_quality_112`).
