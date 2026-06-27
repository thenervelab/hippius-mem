# Hippius Memory

Hippius Memory is an MCP server that gives a team's coding agents shared,
cross-machine memory. Agents record notes (decisions, conventions, gotchas,
references, context) and manage them through seven tools — `remember`, `recall`,
`get`, `refresh`, `forget`, `link`, `history` — and those notes are encrypted
client-side and stored as objects on the Hippius S3 gateway in one shared team
bucket, with every mutation captured in a signed, hash-chained op-log. Because
the bucket is the source of truth,
any teammate's agent on any machine reads the same memory, and because `recall`
returns short pointers and summaries rather than full bodies, an agent pulls
only what it needs into its context window instead of carrying the whole store.

## Architecture

The server is organized into four planes:

| Plane | Responsibility | Phase 1 status |
|-------|----------------|----------------|
| Index | Hybrid (vector + keyword) retrieval over note summaries; maps a note id to its object key, content hash, scope, tags, and recency. Returns pointers, never bodies. | Implemented, in-memory (`InMemoryIndex` behind the `MemoryIndex` trait). Rebuildable from the bucket. |
| Blob | Stores each note as ChaCha20-Poly1305 ciphertext at key `team/repo/mem_id/rev_N` on the Hippius S3 gateway. | Implemented (`S3BlobStore`; `MemoryBlobStore` fake for tests). |
| Audit | On-chain tamper-evident trail: per-developer signed op-log batched into a periodic Merkle anchor on the Hippius chain. | Implemented (Phase 2). Op-log + convergence + Merkle anchoring are always on; on-chain submission is the opt-in `chain` feature. See [Phase 2](#phase-2--shared-op-log-convergence-and-verifiable-history). |
| Identity | Per-developer SS58 author identity (stamped on every note) and the per-developer S3 sub-token used to write. | Phase 1 wires identity through configuration; key/team provisioning is Phase 3. |

A note is a single self-contained fact. Each carries a one-line `summary`
(surfaced by `recall`) and a full `body` (returned only by `get`). Notes are
scoped by `team` (the shared namespace) and `repo` (`global` for team-wide),
which is the cheap first filter applied before semantic ranking.

The index is a derived, disposable cache: it can be rebuilt at any time from the
shared team op-log. `MemoryStore::sync` (the `refresh` tool) replays the signed,
hash-chained op-log, converges it, and rebuilds the local index from the
converged state — applying teammates' tombstones, not just their additions. This
is how a machine with an empty index discovers what teammates have written. The
op-log replaced Phase 1's blob-listing rebuild as the source of truth; see
[Phase 2](#phase-2--shared-op-log-convergence-and-verifiable-history).

## Configuration

The server loads a TOML file (path from `HIPPIUS_MEM_CONFIG`, default
`./hippius-mem.toml`), then overlays `HIPPIUS_MEM_*` environment variables,
which win over file values. Fields:

| TOML field | Env var | Meaning |
|------------|---------|---------|
| `s3_endpoint` | `HIPPIUS_MEM_S3_ENDPOINT` | S3 gateway URL (default `https://s3.hippius.com`). |
| `s3_region` | `HIPPIUS_MEM_S3_REGION` | Gateway region label (default `decentralized`; a Hippius marker, not an AWS region). |
| `bucket` | `HIPPIUS_MEM_BUCKET` | Team-owned bucket holding the memory blobs. |
| `access_key_id` | `HIPPIUS_MEM_ACCESS_KEY_ID` | S3 sub-token id used to sign requests. |
| `secret` | `HIPPIUS_MEM_SECRET` | S3 sub-token secret. Redacted in logs. |
| `team` | `HIPPIUS_MEM_TEAM` | Shared namespace scoping every note. |
| `author_ss58` | `HIPPIUS_MEM_AUTHOR_SS58` | This developer's SS58 identity, attributed to each note. |
| `team_key_hex` | `HIPPIUS_MEM_TEAM_KEY_HEX` | 64 hex characters decoding to the 32-byte shared team encryption key. Redacted in logs. |
| `author_seed_hex` | `HIPPIUS_MEM_AUTHOR_SEED_HEX` | 64 hex characters decoding to this developer's 32-byte sr25519 signing seed. Every op this machine appends is signed with it; its public half must match `author_ss58`. Redacted in logs. |
| `chain_ws_url` | `HIPPIUS_MEM_CHAIN_WS_URL` | WebSocket URL of a Hippius node. Only honoured when the `chain` feature is compiled in; when set, Merkle roots are anchored on-chain instead of locally. |

Example `hippius-mem.toml`:

```toml
bucket = "ourovoros-memory"
access_key_id = "AKID..."
secret = "<s3-sub-token-secret>"
team = "ourovoros"
author_ss58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
team_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
author_seed_hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
# chain_ws_url = "wss://rpc.hippius.network"   # only with --features chain
```

**Getting an S3 sub-token.** The `access_key_id` / `secret` pair is a Hippius
object-store sub-token scoped to the team bucket. Mint it through the
hippius-console flow: authenticate, then `POST /api/objectstore/sub-tokens/`,
which returns `{ access_key_id, secret }` with `read`/`write` actions on the
bucket. Each developer holds their own sub-token to the one shared bucket.

**The team key.** `team_key_hex` is a 64-hex-character (32-byte) secret shared
by every team member. All notes are encrypted under it, so any member can
decrypt any member's notes. It is the same value on every machine; distributing
and rotating it is an operational concern that hardens in a later phase.

## Running

Build the release binary:

```bash
cargo build --release
```

Register it as a stdio MCP server in Claude Code. Either run:

```bash
claude mcp add hippius-mem -- /absolute/path/to/target/release/hippius-mem
```

or add it to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "hippius-mem": {
      "command": "/absolute/path/to/target/release/hippius-mem",
      "env": {
        "HIPPIUS_MEM_CONFIG": "/absolute/path/to/hippius-mem.toml"
      }
    }
  }
}
```

The server speaks the MCP stdio protocol on stdout; diagnostics go to stderr
via `tracing` (control verbosity with `RUST_LOG`, e.g. `RUST_LOG=info`), so
stdout stays a clean protocol channel.

## MCP tools

| Tool | Purpose | Returns |
|------|---------|---------|
| `remember` | Store a note: `note_type` (`decision`/`convention`/`gotcha`/`reference`/`context`), optional `repo`, optional `tags`, `summary`, `body`. Appends a signed `Remember` op to the shared op-log. | The new note's `mem_...` id. |
| `recall` | Search team memory: `text`, optional `repo`, optional `k`, optional `token_budget`. | Ranked pointers — `id`, `summary`, `score`, `repo`, `author`, `updated`. Never note bodies. |
| `get` | Hydrate one note by `id`. | The full note, including its `body`. |
| `refresh` | Replay the shared team op-log into this machine's index, pulling in teammates' new notes and applying their tombstones. | The number of live notes indexed. |
| `forget` | Tombstone a note by `id` (logical delete). Appends a signed `Forget` op; the note stops surfacing in `recall`. | `{ forgotten: true }`. |
| `link` | Assert a directed link from one note to another by `id`. Appends a signed `Link` op. | `{ linked: true }`. |
| `history` | Return the full op history of a note — who did what, in convergence order — each anchored op carrying a verifiable Merkle inclusion proof. | The ordered op entries with per-op anchor proofs. |

The `recall`/`get` split is the context-efficiency mechanism: an agent searches
with `recall`, reads the summaries, and calls `get` only for the notes it
actually needs. `remember`/`forget`/`link` mutate through the signed op-log;
`refresh` pulls teammates' mutations into the local index; `history` exposes the
verifiable chain of custody.

## Phase 2 — shared op-log, convergence, and verifiable history

Phase 1 stored each note as an encrypted blob and rebuilt the index by listing
the bucket. Phase 2 makes the team's *mutations* the source of truth and gives
every op an independently verifiable chain of custody.

**Op-log (signed, hash-chained).** Every mutation — `Remember`, `Forget`,
`Link` — appends a signed `Op` to a per-developer, append-only log living in the
shared bucket. Each op is signed with the developer's sr25519 key
(`author_seed_hex`) and chained to that author's previous op by hash, so the log
is tamper-evident: a reader verifies each signature and each `prev` link while
replaying, and a forged or reordered op fails verification.

**Convergence (Lamport clock, tombstones).** Each op carries a Lamport clock
value; replaying the log and converging it yields a deterministic per-note state
regardless of the order teammates' ops arrive in. A `Forget` is a tombstone, and
the latest lifecycle op wins — so a forgotten note is actively *removed* from a
syncing machine's index, never merely absent. Two developers writing
concurrently both converge: after each calls `refresh`, both machines hold both
notes. Links are grow-only in this phase (there is no unlink op yet).

**Merkle batch anchoring (on-chain).** Each op's hash is a Merkle leaf. Once a
configurable number of ops accumulate, the batch is sealed into a Merkle root and
anchored, and the batch record (root + leaves + receipt) is persisted to the
shared bucket so any teammate can build inclusion proofs. Anchoring the root
on-chain is the opt-in `chain` Cargo feature: build with `--features chain` and
set `chain_ws_url`, and the root is submitted to a Hippius node as a signed
FRAME `System::remark_with_event` extrinsic. Live anchoring needs a **funded
sr25519 account** (the `author_seed_hex` identity) and a **reachable Hippius
node**. With the feature off (the default), roots anchor locally — the op-log and
proofs still work end-to-end, only the on-chain submission is skipped.

**Chain of custody (`history`).** `history` reconstructs a note's full op
sequence directly from the shared log (not the local index), in convergence
order, attaching each anchored op's Merkle inclusion proof. Anyone — including a
machine that never wrote the op — can call `verify_proof(root, op_hash, proof)`
to confirm the op was committed under that root **without trusting the server**;
when chain anchoring is on, the root is on-chain, so the whole "which op, under
which root, in which block" trail is publicly checkable. The cross-machine proof
path is exercised end-to-end in `hippius-mem-core/tests/e2e_phase2.rs`.

## Scope by phase

This is an honest statement of what is built now versus planned.

- **Phase 1.** Single-machine memory engine — `remember`/`recall`/`get`
  with client-side ChaCha20-Poly1305 encryption, an in-memory hybrid index, and
  the S3 blob store — plus shared blob storage and cross-machine discovery.
- **Phase 2 (current). Done.** Developer-signed append-only op-log in the shared
  bucket, convergence with tombstones (replacing blob-listing rebuild), Merkle
  batch anchoring with opt-in on-chain submission (`chain` feature), and the
  `refresh` / `forget` / `link` / `history` tools.
- **Phase 3.** Identity and team-key provisioning (per-developer sub-token
  minting, signed team manifest, key distribution).
- **Phase 4.** Hardening, cold-start index snapshot/restore, convergence stress
  testing, incremental op-log tailing (replacing full re-converge sync), and
  disk-based ANN (LanceDB) for scale.

## Design and plan

- [Design](docs/plans/2026-06-26-hippius-memory-design.md)
- [Implementation plan](docs/plans/2026-06-26-hippius-memory-implementation-plan.md)
