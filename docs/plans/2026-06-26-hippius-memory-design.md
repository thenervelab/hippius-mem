# Hippius Memory — Design

**Date:** 2026-06-26
**Status:** Validated design, pre-implementation
**Author:** Georgios Delkos (with Claude Code)

## Problem

Claude Code's memory is local to one machine. That means: (1) teams can't share
agent memory, (2) memory can't move from computer to computer, (3) local memory
stores grow heavy on disk and bloat the agent's context window, and (4) there is
no accountability for what an agent recorded, changed, or removed.

Hippius Memory is an MCP server that stores agent memory on Hippius decentralized
storage, shares it across a team's machines, records a tamper-evident audit trail
on the Hippius blockchain, and indexes memory so an agent retrieves only what's
relevant — never the whole store.

## Locked decisions

| Decision | Choice |
|----------|--------|
| First user | Our own team's coding agents (dogfood on the Hippius repos) |
| Memory model | Remote-first, thin local cache (Hippius is the source of truth) |
| On-chain scope | Hash-per-action, batched as a Merkle root (anchored periodically) |
| Retrieval | Hybrid vector + keyword (BM25), server-side, pointers-not-bodies |
| Identity | Per-dev Hippius sr25519 wallet; team = shared namespace |
| Server language | Rust (links the S3 SDK, subxt, crypto stack, embedded index) |
| **Storage path** | **Hippius S3 gateway via per-dev S3 sub-tokens (the "API token"); not the hcfs/Arion manifest path** |
| **Storage topology** | **One team-owned bucket = the shared namespace; each dev has their own write sub-token scoped to it** |
| **Billing / attribution** | **Team account (bucket owner) pays storage; per-dev sub-token + per-dev sr25519 key = cryptographic attribution; each dev anchors their own batches** |

## Architecture

```
   Claude Code (each dev, each machine)
            │  MCP tools: remember / recall / get / link / forget / history
            ▼
   ┌─────────────────────────────────────────────┐
   │         Hippius Memory server (Rust)         │
   │                                              │
   │  ① Index plane   embedded LanceDB: vectors + │
   │                  BM25 (FTS5) + metadata,     │
   │                  object-key as pointer       │
   │  ② Blob plane    S3 SDK → Hippius S3 gateway  │
   │                  (shared team bucket;         │
   │                  we E2E-encrypt before put)   │
   │  ③ Audit plane   subxt → frame_system.remark │
   │                  (per-dev batched Merkle      │
   │                  anchor, dev's own key)       │
   │  ④ Identity      BIP-39 → sr25519 + ETH keys; │
   │                  per-dev S3 sub-token         │
   └─────────────────────────────────────────────┘
```

Each dev's server instance writes with that dev's own credentials, so every memory
mutation is attributable (per-dev sub-token + per-dev signature) and tamper-evident
(on-chain anchor signed by the dev's key) by construction.

### Core data flow

- **Write (`remember`):** note → **ChaCha20-Poly1305 encrypt (team key)** → `PutObject`
  to the shared team bucket at key `team/repo/mem_id` → embed + index locally →
  append a dev-signed op to the audit log → periodically anchor a Merkle root
  on-chain via `remark` (signed by the dev's sr25519 key).
- **Read (`recall`):** query hits the local hybrid index → returns *pointers +
  summaries* ranked by relevance + recency → agent picks → `get` does a `GetObject`
  + decrypt for only the chosen blobs. The agent's context never sees the whole store.

## Memory data model

Every memory is an **atomic note** (one self-contained fact) stored as an
encrypted blob on Hippius:

```
---
id:        mem_<ulid>           # stable, sortable, machine-generated
team:      hippius-core         # the shared namespace
repo:      thebrain             # scope: which repo (or "global")
type:      decision | convention | gotcha | reference | context
author:    5Grw...ss58          # the dev's sr25519 account (the on-chain "who")
created:   2026-06-26T...Z
updated:   2026-06-26T...Z
tags:      [pallet, weights]
links:     [mem_01h..., mem_01j...]
cid:       bafy...              # content address of THIS blob
---
<the fact, in prose>
```

- **Two-tier content:** each note carries a one-sentence **summary** (generated at
  write time) plus the **full body**. `recall` returns summaries; `get` fetches
  bodies. This is what keeps the context window small.
- **Scoping is the retrieval shortcut:** queries filter by `team` + `repo` first
  (cheap, correct), then rank semantically. `repo: global` is team-wide.
- **Edit = new object version:** we never mutate a stored blob in place. An edit
  writes a new object at a versioned key (`team/repo/mem_id/rev_N`); the `id` stays
  stable and the index points to the latest revision. This gives free version
  history and keeps every revision auditable. The `cid` field records the
  BLAKE3 hash of the ciphertext we computed at write time (content integrity +
  audit-anchor input), independent of how S3 addresses the object.

**What lives where:**
- *Blob (immutable object, on the Hippius S3 gateway):* the **ChaCha20-Poly1305
  ciphertext** of the **JSON-serialized note**, stored in the shared team bucket at
  key `team/repo/mem_id/rev_N`. We choose the key, so retrieval is a direct
  `GetObject` — no separate address to persist. (Decided 2026-06-26: the canonical
  blob format is JSON via serde, not YAML frontmatter — the blob is encrypted, so a
  human-readable on-disk format buys nothing, and `serde_yaml` is unmaintained. A
  frontmatter *rendering* for human export is a deferred display concern, not the
  storage format.)
- *Index (mutable, server-owned, snapshotted to the team bucket):*
  `id → {latest object key, cid, embedding, tags, scope, summary, recency}`.
  Rebuildable by listing + decrypting the bucket if lost.

## MCP tool surface

| Tool | Purpose | Returns |
|------|---------|---------|
| `remember` | Save a note (text + optional type/repo/tags) | `id`, `cid` |
| `recall` | Search within team/repo scope, token-budgeted | ranked **pointers + summaries** |
| `get` | Hydrate full body for one or more `id`s | full note content |
| `link` | Connect two notes (`a` relates-to `b`) | confirmation |
| `forget` | Soft-delete a note (tombstone, audited) | confirmation |
| `history` | Audit trail for a note or author | who/what/when + on-chain proof |

- `recall` **never returns bodies** — only `[{id, summary, score, repo, author,
  updated}]`; the agent calls `get` for what it needs (progressive hydration).
- `recall` is **token-budgeted** — packs highest-ranked summaries until the budget
  is hit, reports how many more matched.
- `forget` is a **tombstone**, never a hard delete — blob + history stay; the index
  stops surfacing it.
- **Auto-scope:** `repo` defaults to the agent's current repo (cwd/git); `team`
  from server config.
- **Deliberately not tools (YAGNI):** no `update` (it's `remember` with the same
  `id`), no `list-all`, no manual `embed`/`index`.

## Retrieval pipeline (the "smart index")

```
query "how do we set pallet weights?"
   │
   ├─ scope filter:  team=hippius-core AND repo IN (thebrain, global)   ← first, cheap
   │
   ├─ leg A: BM25 / FTS5 lexical   ─┐   over-fetch ~80 each
   ├─ leg B: dense vector ANN      ─┘   (anchors exact IDs vs. semantic)
   │
   ├─ fuse: Reciprocal Rank Fusion (RRF)   ← no score calibration needed
   │
   ├─ recency re-weight: score × decay(updated)   ← stale gotchas sink
   │
   └─ pack to token_budget → pointers + summaries
```

- **Hybrid, not pure vector:** memories are full of exact identifiers
  (`remark_with_event`, `ProxyType`, pallet names) that BM25 nails and vectors
  fumble; paraphrase queries need the vector leg. RRF fuses both by rank, so no
  cosine-vs-BM25 score calibration.
- **Embeddings run locally** (Rust `candle`/ONNX, e.g. BGE-M3 or EmbeddingGemma) —
  no external API key, memories stay in team control, works offline. BGE-M3 emits
  both dense and sparse vectors, collapsing both legs into one model.
- **Index store.** Rebuildable from blobs; periodically snapshotted to Hippius so a
  cold machine starts warm. **Phasing (decided 2026-06-26):** Phase 1 ships an
  **in-memory hybrid index** behind a `MemoryIndex` trait (brute-force cosine + keyword
  + RRF + recency) with an `Embedder` trait (deterministic fake for tests; real
  `fastembed` behind an optional feature) — YAGNI-correct for dogfood scale, keeps the
  build light and unit tests deterministic, and swaps cleanly since the index is
  rebuildable. **Embedded LanceDB** (Rust-native, disk-based ANN, dataset versioning) is
  deferred to the scale phase behind that same trait.
- **Recency is directional** — decisions/conventions decay slowly; volatile
  `context` notes decay fast (tunable per `type`).

Open item: first-run embedding-model download adds latency on a new machine; ship
a small default model.

## Sync & concurrency

Because each dev runs their own local MCP server writing to the **one shared team
bucket** with their own sub-token, the system is **multi-writer from day one** — the
shared bucket is the convergence point, not a single server process. The
coordination substrate is an **append-only operation log living in the shared
bucket**:

- Every mutation is an immutable, **dev-signed** op:
  `{op_id, author_ss58, lamport_clock, kind, id, object_key, cid, sig}`, written as
  its own object so the log is shared, durable, and replayable by every member.
- Convergence by field: note bodies never conflict (edit = new object version,
  "latest" by the total order `(lamport, op_id, author_key)` — no wall-clock
  trust; `author_key` is the final tiebreak so the order stays total even if a
  Byzantine author reuses another's `(lamport, op_id)`); tags and links are
  OR-Sets; tombstones win over un-deletes.
- Each dev's server tails the op-log to rebuild/refresh its local index, so a
  teammate's new note becomes searchable without a central coordinator.

Not using full rich-text CRDTs (Loro/Yjs RGA) — notes are write-new-object, not
collaboratively-typed paragraphs, so sequence CRDTs are overkill. Lamport clocks
sidestep the unverified cross-machine wall-clock risk.

A small team could optionally point every member at **one shared server instance**
(simpler: that process serializes writes), but the op-log substrate means the
default per-dev-server topology needs no central coordinator.

## Accountability plane (on-chain audit)

**Off-chain (full detail, hash-chained local log):** every action appends an audit
record `{op_id, author_ss58, action, mem_id, cid, timestamp, prev_op_hash}`. The
`prev_op_hash` makes the log itself tamper-evident.

**On-chain (cheap, tamper-proof):**
- The server batches op-record hashes into a **Merkle tree** (every N ops or every
  few minutes).
- It submits one `frame_system::remark_with_event(merkle_root ++ batch_meta)`
  extrinsic, **signed by the acting dev's sr25519 key**, so `System.Remarked{sender}`
  records who anchored.
- The chain provides: immutable timestamp (block), cryptographic signer identity,
  and a root committing to every action in the batch.

**Proving "who did what":** `history` reconstructs the action from the local log,
produces a **Merkle inclusion proof** that the exact record is committed under an
on-chain root, and shows the block/signer. Anyone verifies the proof against the
public chain without trusting our server.

**Cost control:** batching means N actions cost one length-weighted `remark` fee.
Each member's key holds a small balance (`remark` is `Pays::Yes`).

**Risks to verify before building:** (1) whether the public RPC node accepts
external extrinsic submission (else run our own node); (2) exact `remark`
fee/length limits (caps batch metadata size).

## Identity, keys & team membership

- **One mnemonic, two identities (per dev):** a BIP-39 master mnemonic derives an
  **sr25519 key** (SS58 — the on-chain "who" that signs audit anchors) and an
  **ETH secp256k1 key** (account auth: challenge/response against api.hippius.com —
  `POST /api/auth/mnemonic/` → `POST /api/auth/verify/` with an EIP-191 signature →
  session bearer token). This is the desktop's `derive_keys(mnemonic)` pattern,
  reused not reinvented.

- **Storage credential — the per-dev S3 sub-token:** with the session token, each
  dev mints an object-store sub-token (`POST /api/objectstore/sub-tokens/` →
  `{ access_key_id, secret }`) scoped to the **shared team bucket**, `actions:
  [read, write]`, non-expiring (or rotated). That access key + secret is the
  durable credential the dev's MCP server uses for `PutObject`/`GetObject`. The
  access key identifies the writing dev (storage-layer attribution), complementing
  the per-op sr25519 signature (audit-layer attribution).

- **Storage topology & billing:** one team-owned account creates the memory bucket
  and pays its storage bill (the gateway enforces credit eligibility — a write
  fails if the team account is out of credits). Every dev holds their own write
  sub-token to that one bucket, and anchors their own audit batches with their own
  funded sr25519 key. So reads are simple (one bucket), attribution is per-dev, and
  on-chain anchoring cost is borne per-dev.
- **Key storage:** master mnemonic encrypted at rest (ChaCha20-Poly1305 over
  HKDF-SHA256), bearer token in the OS keychain (`keyring`) with a SQLite fallback
  for headless servers, plaintext secrets in `zeroize::Zeroizing`. Lifted from the
  desktop `crypto::store` + `token_keychain`.
- **Team = shared namespace (no new pallet):** a namespace string scoping every
  blob/index-row/op-log, plus a membership list of allowed sr25519 accounts. For
  the MVP this is a signed `team-manifest` note (founder lists members, signs with
  their key); membership changes are themselves audited ops.
- **Why this suffices:** the chain records that account `5Grw…` anchored batch X;
  the off-chain signed manifest maps that account to "Alice on the core team."
  On-chain governance of membership (`pallet_multisig`/`pallet_proxy`) is deferred
  (YAGNI).
- **Trust boundary, stated plainly:** a teammate's server writes with *their* key,
  so they can only attribute actions to themselves — no forging another dev's
  signature. A rogue member can still write junk *as themselves*; the audit trail
  makes that visible, crypto doesn't prevent it.

## Phase 2 — as built

Phase 2 shipped. Where the implementation diverged from the design above, the
shipped behaviour is authoritative; this note reconciles the two so the design
is not read as a contradicting spec.

- **Per-author hash chains, not one global chain.** The "hash-chained log" is
  chained *per author* — each op's `prev` points to that author's previous op,
  not a single global predecessor. This is what lets two developers append
  concurrently without a coordinator while each chain stays independently
  verifiable; replay verifies every author's chain.
- **Latest-action-wins tombstones, not field-level CRDT merge.** Lifecycle
  convergence is "the latest lifecycle op (by the total order
  `(lamport, op_id, author_key)`) wins," and a `Forget` tombstone beats earlier
  ops. The richer field-level
  OR-Set merge sketched under *Sync & concurrency* was not needed for the
  shipped op kinds; bodies are write-new-object and tags ride the latest content
  op.
- **Grow-only links (no unlink yet).** `Link` appends a directed edge; there is
  no unlink op, so the converged link set is grow-only. Removing a link is
  deferred. Links feed `history`/graph views, not recall ranking, in this phase.
- **Full re-converge sync, not incremental tailing.** `refresh` (`MemoryStore::sync`)
  reads the whole log, converges it, and rebuilds the index from scratch each
  call. The design's "op-log tailing" (replay only the suffix since the last
  cursor) is deferred to Phase 4 — full re-converge is correct and simple, and
  the log is small at team scale.
- **Anchoring is opt-in and uses a generic FRAME `remark`.** Merkle batch
  anchoring and the persisted batch records are always on; on-chain submission is
  the `chain` Cargo feature wiring a `SubxtAnchor` to `chain_ws_url`. It submits
  `System::remark_with_event` via the **generic FRAME** contract.
- **Inclusion proofs are trust-minimized only with `chain` anchoring.** In the
  default local/`NoopAnchor` mode a `history` inclusion proof proves INTERNAL
  consistency only: the root it verifies against comes from the same bucket this
  server controls, so the proof shows the op is consistent with a root the server
  asserts — not that the root is independently committed. Trust-minimization
  requires (a) `chain` anchoring AND (b) a verifier that fetches the root from the
  chain (via the proof's `reference`) and compares it to `proof.root`. Anchor
  records are now namespaced per author (`{team}/_anchors/{author_key}/{seq}`)
  with `seq` seeded from existing records, so concurrent writers and restarts no
  longer overwrite each other's proof material.
- **The chain detects in-chain tampering, not suppression.** The per-author hash
  chain catches in-place edits, mid-chain deletion, and intra-author reordering;
  it does NOT catch tail-truncation, whole-author suppression, or
  split-view/equivocation. On-chain anchoring plus a future reconciliation tool
  (not yet built) is the intended suppression mitigation.
- **Residual open item — thebrain's `remark` fee/weight is unverified.**
  `thebrain` (the Hippius runtime) is not illu-indexed, so its runtime-specific
  `remark` fee/length limits and extrinsic-submission policy (Open risk #1) were
  *not* verified against the actual runtime; the implementation targets the
  generic FRAME `System::remark_with_event` contract. Confirming the live
  runtime's weights, fees, and public-node submission policy remains open.

## Build sequence

**Phase 0 — RESOLVED (storage de-risked, 2026-06-26).** The spike is done by reading
the indexed `hcfs`, `hippius-console`, and `hippius-s3` repos directly. Confirmed:
object-level storage with a caller-chosen key works for ~1KB notes; the chosen path
is the **Hippius S3 gateway** (`PutObject`/`GetObject` into a shared bucket) using a
per-dev **S3 sub-token** minted via `POST /api/objectstore/sub-tokens/`. We supply
our own ChaCha20-Poly1305 encryption before upload. The hcfs/Arion manifest path
(`HcfsClient::upload` returning `UploadResult { upload_id, revision_id }`, with
XChaCha20-Poly1305 and ed25519 manifest signing) remains a documented fallback if
we later want hcfs's built-in erasure/pinning, but it is **not** the MVP path.

**Phase 1 — Memory core (no chain yet).** Wire the S3 sub-token + shared bucket;
implement `remember`/`recall`/`get` with client-side encryption + embedded LanceDB
hybrid index, single local server. Delivers cross-machine sharing + context-efficient
recall — the two biggest pains. Dogfood on this repo.

**Phase 2 — Accountability + multi-writer convergence.** Dev-signed op-log in the
shared bucket, hash-chaining, op-log tailing for index refresh, field-level
convergence (Lamport + OR-Sets + tombstones), `history`, and batched Merkle
anchoring via `subxt` + `remark`. Pin one subxt version (in-repo references skew
between 0.41 and 0.38).

**Phase 3 — Identity & team.** Per-dev sub-token minting, signed team manifest,
team-key provisioning, `forget` tombstones, membership-change auditing.

**Phase 4 — Hardening & cold start.** Index snapshot/restore from the bucket for new
machines, convergence stress tests (concurrent writers, partition replay), team-key
rotation on membership change, performance pass.

**Verification discipline:** `proptest` on the pure pieces (Merkle proofs, RRF
fusion, op-log convergence, frontmatter round-trip); `miri` if any `unsafe` appears
(none expected); illu Rust quality gate on every diff.

## Reused Hippius primitives (verified against indexed repos, 2026-06-26)

- **Storage (chosen path):** the Hippius S3 gateway (`hippius-s3` repo, S3-compatible,
  CRUSH placement). Credential = an object-store sub-token from
  `POST /api/objectstore/sub-tokens/` (`hippius-console`: `useApiTokens.ts`,
  returns `{ access_key_id, secret }`, scoped, rotatable, revocable). Access via any
  standard S3 SDK.
- **Account / billing API (api.hippius.com, fronted by `hippius-console`):**
  `POST /api/auth/mnemonic/` + `POST /api/auth/verify/` (EIP-191 challenge/response →
  session token); `GET /api/billing/credits/balance/` for credit checks. The real
  backend is api.hippius.com — the console is a frontend proxy.
- **Storage (documented fallback):** `hcfs-client::client::HcfsClient::upload`
  (returns `UploadResult { upload_id /* BLAKE3 arion_hash */, revision_id: [u8;32] }`)
  / `download(ss58, folder_hash, file_id = BLAKE3(relative_path))`, with
  `crypto::encrypt_stream_with_hash` (XChaCha20-Poly1305) and ed25519 `Manifest`
  signing. Use only if we later want hcfs's built-in Arion erasure/pinning.
- **Chain:** `subxt` `OnlineClient<PolkadotConfig>` over `wss://rpc.hippius.network`
  with pinned genesis hash; `frame_system::remark_with_event` as the audit sink.
  Reference clients: `hcfs-chain-reporter` (subxt 0.41), hippius-desktop (subxt 0.38).
- **Crypto/identity:** desktop `auth::service::derive_keys` (mnemonic → sr25519 + ETH),
  `crypto::store` (ChaCha20-Poly1305 + HKDF), `token_keychain` (keyring + DB fallback).

## Open risks

1. **No storage is recorded on-chain today** — the audit trail is net-new code;
   `remark` fee and public-node extrinsic-submission policy still unverified.
2. **Long-lived "account API token":** the console mints **S3 sub-tokens** (scoped,
   non-expiring or rotatable) — those are the durable credential. A separate
   developer-style account token, if any, lives on api.hippius.com and is unconfirmed.
   Sub-tokens are sufficient for the MVP.
3. **Cross-machine clocks** are untrusted — Lamport clocks chosen to avoid the
   wall-clock dependency.
4. **Summary freshness** vs. immutable blob on edit — summary regeneration / index
   cache-invalidation policy is an open operational item.
5. **Embedding model first-run latency** on new machines.
6. **Team-shared encryption key distribution:** notes are encrypted with a team key so
   any member can decrypt; how that key is provisioned to each member (and rotated on
   membership change) is an open operational item.
