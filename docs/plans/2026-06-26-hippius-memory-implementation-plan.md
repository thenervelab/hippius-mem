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

## Phase 2 — Accountability + multi-writer convergence (detailed)

All logic is unit-testable with fakes; only live-chain submission needs a node, so the chain
layer sits behind an `AuditAnchor` trait (fake for CI, real `subxt` impl behind a `chain` feature),
mirroring the `BlobStore` pattern. Pure pieces get `proptest!` blocks.

### Task 11: Op-log data model + sr25519 signing
`hippius-mem-core/src/oplog/op.rs`. `enum OpKind { Remember, Edit, Forget, Link { to: NoteId } }`;
`struct Op { op_id: Ulid, author: Ss58, lamport: u64, kind: OpKind, note_id: NoteId, object_key:
String, cid: Blake3Hash, prev_op_hash: Blake3Hash, sig: Signature }`. A `Signer` trait (sign bytes
→ sig) + `Verifier`; sr25519 via `schnorrkel`/`subxt-signer` (verify the API from docs). `op.signing_bytes()`
is the canonical serialization signed. `op.hash()` = blake3 over the signed bytes (the chain link).
TDD: sign→verify round-trip (proptest), tamper→verify fails, wrong-key→fails.

### Task 12: Op-log store (append-only, in the bucket)
`oplog/store.rs`. Ops are blobs at `{team}/_oplog/{lamport:020}_{op_id}` (lexicographically sortable).
`append(op)` via `BlobStore::put`; `read_all(team)` lists+gets+deserializes, ordered. Verifies the
hash-chain (`prev_op_hash`) on read; a break → `MemError`. TDD with `MemoryBlobStore`: append several,
read back in order, detect a tampered chain.

### Task 13: Lamport clock + CRDT convergence
`oplog/converge.rs`. Pure `fn converge(ops: &[Op]) -> ConvergedState` (map `NoteId → NoteState`):
Lamport max+1 on apply; body/edit = latest by `(lamport, author)` tie-break; tags/links = OR-Set
(add on Remember/Link, remove on Forget-of-link); Forget = tombstone that wins. **MANDATORY proptest:**
`converge` is order-independent — any permutation of the same op multiset yields the same state.

### Task 14: Split convergence clock from recency clock
Add `lamport: u64` to `IndexRecord`/`Pointer` for convergence "latest"; keep wall-clock `updated`
for recency decay only (resolves review Issue 3). Wire `remember` to assign a lamport (clock from
the op-log tip).

### Task 15: Op-log-driven index (replace poll rebuild)
`MemoryStore` gains `sync(&self)`: read the op-log, `converge`, rebuild the index from converged
state (incremental: track last-seen lamport; full replay if cold). `remember`/`edit`/`forget`/`link`
now append a signed op AND update the index. `rebuild_index` becomes `sync`'s cold path. TDD: two
stores sharing a bucket converge after `sync`; a `forget` op hides a note from recall on both.

### Task 16: Merkle tree + inclusion proofs
`audit/merkle.rs`, pure. `merkle_root(hashes) -> Blake3Hash`; `inclusion_proof(hashes, i) -> Proof`;
`verify_proof(root, leaf, proof) -> bool`. **MANDATORY proptest:** every leaf's proof verifies against
the root; a wrong leaf/root fails. Document the domain-separation + odd-node duplication rule.

### Task 17: AuditAnchor trait + fake + subxt impl
`audit/anchor.rs`. `trait AuditAnchor { async fn anchor(&self, root: Blake3Hash, meta: BatchMeta)
-> Result<AnchorReceipt, MemError>; }`. `NoopAnchor`/`RecordingAnchor` fakes for tests. Real
`SubxtAnchor` behind `[features] chain` using `subxt` 0.50.1 + `subxt-signer`: submit
`frame_system::remark_with_event(root ++ meta)` signed by the dev's sr25519 key; classify the
submission result. **Resolve the open item here:** verify the `remark` fee/weight + extrinsic-submission
policy via `mcp__illu__cross_query repo:"thebrain"` and the subxt docs (do NOT need live submission for
CI — the fake covers logic; the real impl must compile under `--features chain`).

### Task 18: Batch + anchor scheduler
`audit/batch.rs`. Accumulate op hashes; when N ops or T elapsed, build a Merkle root and call
`AuditAnchor::anchor`; persist the batch→root mapping (a blob under `{team}/_anchors/`) so `history`
can produce inclusion proofs. Wire into `MemoryStore` (anchor on a threshold). TDD with `RecordingAnchor`.

### Task 19: `history` tool + forget/link tools
`history(note_id)` reconstructs the note's ops from the op-log, and for anchored ops returns a Merkle
inclusion proof + the on-chain anchor reference (block/extrinsic if `chain` on). Add MCP tools
`forget`, `link`, `history` to the server. TDD: handler-level + an e2e (`remember`→`forget`→`history`
shows the tombstone and a verifiable proof).

### Task 20: Phase 2 e2e + docs
Cross-machine e2e: machine A `remember`+`forget`, machine B `sync`s, converges, `history` verifies
inclusion against a `RecordingAnchor` root. Update README/design for the op-log + anchoring. Then the
Phase 2 spec + code-quality review.

---

## Phase 3 — Identity & team (detailed)

Closes the Phase-2 seams (self-asserted author; team-key distribution) and adds team membership.
Pure crypto/logic is unit/proptest-tested; the api.hippius.com integration sits behind a `console`
feature (fake/CLI for CI), mirroring `chain`/`s3-integration`.

### Task 21: Identity primitives — mnemonic derivation + SS58 codec
`hippius-mem-core/src/identity/mod.rs`. BIP-39 mnemonic → sr25519 mini-secret seed (substrate
derivation) + the ETH secp256k1 key (the desktop `derive_keys` shape). `Identity { ss58: Ss58,
sr25519_seed: [u8;32], verifying_key: VerifyingKey, eth_address: String }`. **SS58 codec**:
`ss58_encode(&VerifyingKey, prefix: u16) -> Ss58` (base58 of `prefix ++ pubkey ++ blake2b("SS58PRE"++data)[..2]`) and `ss58_decode(&Ss58) -> Result<(VerifyingKey, u16), MemError>` (checksum-verified).
Deps: `bip39`, `blake2` (for the SS58 checksum), reuse `schnorrkel`. **MANDATORY proptest:**
`ss58_decode(ss58_encode(key)) == key`; tamper-a-char → checksum error. Verify the exact
substrate derivation + checksum from the `sp-core`/desktop reference before coding.

### Task 22: Bind identity + derive author from signer (close the Phase-2 seam)
`Sr25519Signer` gains `from_mnemonic` (via Task 21) and exposes a derived `Ss58` (= `ss58_encode(verifying_key)`).
`OpLogStore::read_verified` now asserts `ss58_decode(op.author)? == op.author_key` (the human label
is cryptographically bound to the signing key — closes the self-asserted-author gap). `MemoryStore`
DROPS the separate `author` arg: it is derived from `signer.ss58()` (the 9-arg `new` → 8). Update all
call sites + config (`author_ss58` no longer separately configured — derived from `author_seed_hex`/mnemonic;
validate they match if both given). Tests: a forged `author` (ss58 not matching `author_key`) → op rejected.

### Task 23: Signed team manifest + membership enforcement
`identity/manifest.rs`. `TeamManifest { team, members: BTreeSet<Ss58>, version: u64, founder: Ss58,
sig }` signed by the founder, stored at `{team}/_manifest/{version:020}`. `load_manifest(blob, team)`
returns the latest valid (founder-signed) version. `OpLogStore::read_all`/`converge` (or the store)
**rejects/ignores ops from authors not in the current manifest** (a non-member's ops don't converge).
Membership changes = a new signed manifest version (audited by version history). Tests: a non-member's
op is excluded; a manifest with a bad founder sig is rejected; latest-version wins.

### Task 24: Team-key provisioning + rotation (the open item)
`identity/teamkey.rs`. The shared ChaCha key is wrapped per-member: for each member, encrypt the team
key to their public key (x25519 ECDH from their sr25519 key, or an explicit per-member x25519 key —
verify what's derivable) → `WrappedKey` stored at `{team}/_keys/{member_ss58}/{epoch}`. A new member
`unwrap`s with their private key. **Rotation:** on member removal, generate a new team-key epoch and
re-wrap for remaining members; new writes use the new epoch (the note/op records its key epoch).
Deps: `x25519-dalek` + `crypto_box`/`hpke` (verify the maintained choice). **MANDATORY proptest:**
`unwrap(wrap(key, recipient), recipient_secret) == key`; a non-recipient cannot unwrap. Document the
epoch model + that old epochs stay readable (forward-readable history) while removed members lose new epochs.

### Task 25: Sub-token minting client (behind `console` feature)
`identity/console.rs` (gated `[features] console`). The api.hippius.com flow: `POST /api/auth/mnemonic/`
→ `POST /api/auth/verify/` (EIP-191 sign the challenge with the ETH key) → session token; then
`POST /api/objectstore/sub-tokens/` → `{access_key_id, secret}` scoped to the team bucket. Deps
(gated): `reqwest` (rustls), `alloy-signer`/the ETH signer. A `mint_sub_token(mnemonic, bucket) ->
Result<S3Creds, MemError>` + a small CLI subcommand. Live calls need real creds → an `#[ignore]`
integration test; CI covers the request/response (de)serialization with a mocked client. Verify the
endpoints/shapes against the `hippius-console` repo via `mcp__illu__cross_query`.

### Task 26: Phase 3 e2e + docs + review
e2e: a member joins (gets wrapped team key + sub-token), reads existing memory; a removed member's
new ops don't converge after rotation; a forged-author op is rejected. Update README/design (identity
binding, manifest, team-key epochs, sub-token minting). Then the Phase 3 spec + code-quality review.

## Phase 4 — Hardening & cold start (outline — detailed breakdown follows Phase 3)

Index snapshot/restore from the bucket for new machines (fast cold start vs full op-log replay);
incremental op-log tailing (`read_since` + a verified checkpoint, resolving the read-amplification
debt); convergence stress tests (concurrent writers, partition replay); an on-chain reconciliation
/ independent-verifier tool (converts the suppression-detection mitigation from latent to real);
team-key rotation hardening; `history`/anchor perf (the O(ops×records×leaves) debt) with a criterion
baseline before any optimization (axiom `illu_perf_01`); a final full-system review.

---

## Verification discipline (every Rust task)

- `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --all` clean before commit.
- `proptest!` on every pure function (frontmatter, crypto, objkey, RRF fusion, Merkle proofs).
- Tests go through the public API (`MemoryStore::remember`), not direct LanceDB/S3 writes (axiom `rust_quality_111`).
- `mcp__illu__critique` then `mcp__illu__quality_gate` (with the seven `self_review_*` answers) on each diff.
- No `unsafe` is expected; if any appears, `cargo +nightly miri test` the module (axiom `rust_quality_112`).
