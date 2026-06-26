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
| Server language | Rust (links hcfs-client, subxt, crypto stack, embedded index) |

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
   │                  CID as foreign key          │
   │  ② Blob plane    hcfs-client → Hippius        │
   │                  storage (encrypted notes)   │
   │  ③ Audit plane   subxt → frame_system.remark │
   │                  (batched Merkle anchor)     │
   │  ④ Identity      BIP-39 → sr25519 + ETH keys │
   └─────────────────────────────────────────────┘
```

The server is the only writer to the audit chain, so every memory mutation is
attributable and tamper-evident by construction.

### Core data flow

- **Write (`remember`):** note → encrypt → store blob on Hippius (get content
  address) → embed + index locally → append to audit log → periodically anchor a
  Merkle root on-chain via `remark`.
- **Read (`recall`):** query hits the local hybrid index → returns *pointers +
  summaries* ranked by relevance + recency → agent picks → `get` hydrates only the
  chosen blobs. The agent's context never sees the whole store.

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
- **Edit = new blob/CID:** content-addressed storage is immutable, so editing a
  note writes a new blob; the `id` stays stable and the index points to the latest
  CID. This gives free version history.

**What lives where:**
- *Blob (immutable, on Hippius):* note content + frontmatter, addressed by `cid`.
- *Index (mutable, server-owned, snapshotted to Hippius):*
  `id → {latest cid, embedding, tags, scope, summary, recency}`. Rebuildable by
  walking blobs if lost.

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
- **Index store: embedded LanceDB** (Rust-native, disk-based, dataset versioning
  usable as index rollback/audit). Rebuildable from blobs; periodically snapshotted
  to Hippius so a cold machine starts warm.
- **Recency is directional** — decisions/conventions decay slowly; volatile
  `context` notes decay fast (tunable per `type`).

Open item: first-run embedding-model download adds latency on a new machine; ship
a small default model.

## Sync & concurrency

Remote-first with a server means the server is the ordering authority.

- **A. One team, one server process:** the server serializes writes, assigns
  canonical order, sole audit-chain writer. Simplest dogfood deployment; start here.
- **B. Multiple instances / offline machines:** convergence via an **append-only
  operation log**:
  - Every mutation is an immutable op:
    `{op_id, author, lamport_clock, kind, id, cid}`, itself a content-addressed
    blob on Hippius (shared, durable, replayable).
  - Convergence by field: bodies never conflict (edit = new CID, "latest" by
    Lamport clock + author-id tie-break — no wall-clock trust); tags/links are
    OR-Sets; tombstones win over un-deletes.

Not using full rich-text CRDTs (Loro/Yjs RGA) — notes are write-new-blob, not
collaboratively-typed paragraphs, so sequence CRDTs are overkill. Lamport clocks
sidestep the unverified cross-machine wall-clock risk.

Ship **A** for the MVP; build the op-log substrate from day one so **B** is a
config flag, not a rewrite.

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
  **ETH secp256k1 key** (storage-API challenge/response → 30-day bearer token).
  This is the desktop's `derive_keys(mnemonic)` pattern, reused not reinvented.
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

## Build sequence

**Phase 0 — De-risk the storage primitive (spike, ~1 day).** Read `thenervelab/hcfs`
directly and confirm: (1) does a write return a stable content address / CID we can
use as the index foreign key? (2) smallest practical storage unit — store ~1KB notes
individually, or pack many per blob? (3) is client-side encryption already applied,
or do we add a layer? If CIDs aren't exposed, fall back to a server-owned
`id → storage-key` mapping table. **The index design is finalized only after this spike.**

**Phase 1 — Memory core (no chain yet).** `remember`/`recall`/`get` against Hippius
blobs + embedded LanceDB hybrid index, single local server. Delivers cross-machine
sharing + context-efficient recall — the two biggest pains. Dogfood on this repo.

**Phase 2 — Accountability.** Op-log substrate, hash-chaining, `history`, batched
Merkle anchoring via `subxt` + `remark`. Pin one subxt version (in-repo references
skew between 0.41 and 0.38).

**Phase 3 — Identity & team.** Multi-dev keys, signed team manifest, `forget`
tombstones, membership-change auditing.

**Phase 4 — Multi-instance.** Op-log convergence across server instances; index
snapshot/restore from Hippius for cold starts.

**Verification discipline:** `proptest` on the pure pieces (Merkle proofs, RRF
fusion, op-log convergence, frontmatter round-trip); `miri` if any `unsafe` appears
(none expected); illu Rust quality gate on every diff.

## Reused Hippius primitives (from grounding research)

- **Storage:** `hcfs-client` + `hcfs-shared` crates (thenervelab/hcfs), driven via
  `DriveManager` / `SyncRunner::trigger_sync` as in hippius-desktop. *Black box —
  Phase 0 verifies the CID contract.*
- **Chain:** `subxt` `OnlineClient<PolkadotConfig>` over `wss://rpc.hippius.network`
  with pinned genesis hash; `frame_system::remark_with_event` as the audit sink.
  Reference clients: `hcfs-chain-reporter` (subxt 0.41), hippius-desktop (subxt 0.38).
- **Crypto/identity:** desktop `auth::service::derive_keys`, `crypto::store`
  (ChaCha20-Poly1305 + HKDF), `token_keychain` (keyring + DB fallback).

## Open risks

1. **hcfs-client CID contract** is unverified (Phase 0 blocker).
2. **No storage is recorded on-chain today** — the audit trail is net-new code;
   `remark` fee and public-node submission policy unverified.
3. **Cross-machine clocks** are untrusted — Lamport clocks chosen to avoid the
   wall-clock dependency.
4. **Summary freshness** vs. immutable blob on edit — summary regeneration / index
   cache-invalidation policy is an open operational item.
5. **Embedding model first-run latency** on new machines.
