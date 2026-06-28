# Hippius Memory

Hippius Memory is an MCP server that gives a team's coding agents shared,
cross-machine memory. Agents record notes (decisions, conventions, gotchas,
references, context) and manage them through nine tools — `remember`, `recall`,
`get`, `refresh`, `forget`, `link`, `history`, `reconcile`, `edit` — and those
notes are encrypted client-side and stored as objects on the Hippius S3 gateway
in one shared team bucket, with every mutation captured in a signed, hash-chained
op-log. Because the bucket is the source of truth,
any teammate's agent on any machine reads the same memory, and because `recall`
returns short pointers and summaries rather than full bodies, an agent pulls
only what it needs into its context window instead of carrying the whole store.

`recall` ranking is currently **lexical/keyword overlap**, not semantic: it runs
a deterministic 64-dim bag-of-tokens hash embedder (`HashEmbedder`) fused with
keyword and recency scoring — there is no neural/semantic embedding model wired
in (see [Retrieval honesty](#retrieval-honesty)).

## Architecture

The server is organized into four planes:

| Plane | Responsibility | Phase 1 status |
|-------|----------------|----------------|
| Index | Hybrid retrieval over note summaries: a deterministic lexical hash embedder (`HashEmbedder`, keyword-overlap proxy — *not* semantic) fused with keyword and recency scoring; maps a note id to its object key, content hash, scope, tags, and recency. Returns pointers, never bodies. | Implemented, in-memory (`InMemoryIndex` behind the `MemoryIndex` trait). Rebuildable from the bucket. |
| Blob | Stores each note as ChaCha20-Poly1305 ciphertext at key `team/repo/mem_id/rev_N` on the Hippius S3 gateway. | Implemented (`S3BlobStore`; `MemoryBlobStore` fake for tests). |
| Audit | On-chain tamper-evident trail: per-developer signed op-log batched into a periodic Merkle anchor on the Hippius chain. | Implemented (Phase 2). Op-log + convergence + Merkle anchoring are always on; on-chain submission is the opt-in `chain` feature. See [Phase 2](#phase-2--shared-op-log-convergence-and-verifiable-history). |
| Identity | Per-developer SS58 author identity (stamped on every note) and the per-developer S3 sub-token used to write. | Implemented (Phase 3). Mnemonic-derived SS58 + x25519, author bound to key, founder-signed team manifest, and team-key wrapping/rotation. See [Phase 3](#phase-3--identity-teams-and-key-distribution). |

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
| `team_key_hex` | `HIPPIUS_MEM_TEAM_KEY_HEX` | 64 hex characters decoding to the 32-byte shared team encryption key. Redacted in logs. |
| `author_seed_hex` | `HIPPIUS_MEM_AUTHOR_SEED_HEX` | 64 hex characters decoding to this developer's 32-byte sr25519 signing seed. Every op this machine appends is signed with it; the SS58 identity attributed to each note is derived from it, so there is no separate address to configure. Redacted in logs. |
| `chain_ws_url` | `HIPPIUS_MEM_CHAIN_WS_URL` | WebSocket URL of a Hippius node. Only honoured when the `chain` feature is compiled in; when set, Merkle roots are anchored on-chain instead of locally. |

Example `hippius-mem.toml`:

```toml
bucket = "ourovoros-memory"
access_key_id = "AKID..."
secret = "<s3-sub-token-secret>"
team = "ourovoros"
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
decrypt any member's notes. A statically configured `team_key_hex` is still
supported, but Phase 3 replaces hand-copying it with cryptographic distribution:
the founder wraps the key to each member's published x25519 key and a joining
member bootstraps it with `fetch_team_key`; rotation re-wraps a new epoch to the
current members only. See [Phase 3](#phase-3--identity-teams-and-key-distribution).

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

## Operating model

What is driveable from the shipped binary versus what is still only a library
call, stated plainly:

**Wired into the binary:**

- **The MCP server** — the nine memory tools, the default mode (no subcommand).
  On startup it syncs the index from the op-log and best-effort bootstraps the
  epoch key-ring.
- **`mint-token`** — mints a per-developer S3 sub-token from a mnemonic. Only
  compiled with the `console` feature.
- **`publish-membership --members <ss58,...>`** — publishes a founder-signed team
  manifest to close membership.
- **`doctor [--offline]`** — validates a configured bundle and proves the
  encryption boundary. It loads the config (checking the required fields and that
  `team_key_hex` / `author_seed_hex` each decode to 32 bytes), reports the
  non-secret coordinates (bucket, `access_key_id`, author SS58), then — unless
  `--offline` — runs a live seal→put→get→open probe against the bucket that
  asserts only ciphertext is ever stored. Always available (no feature gate).
- **Startup epoch-key bootstrap** — best-effort, gated on `HIPPIUS_MEM_MNEMONIC`:
  on boot the server loads every team-key epoch this member can unwrap so a member
  provisioned after a rotation starts able to read newer-epoch notes. A fresh or
  un-provisioned bucket is warned and skipped, never fatal.

**Library-only (no subcommand yet):**

- **Key provisioning / rotation for new or removed members** —
  `provision_team_key` / `rotate_team_key` are core-library functions, not CLI
  subcommands. Onboarding a member onto wrapped-key distribution, or rotating the
  key after a removal, is currently a Rust call against `hippius-mem-core`.
- **Write-epoch advancement** — `MemoryStore::set_current_epoch` (which epoch new
  writes seal under) is a library method, not exposed on the binary.

**The operable default** is therefore the simplest one: a statically configured
`team_key_hex` shared out of band, with an **open** team (every signature-verified
op converges). Publish a manifest with `publish-membership` to close the team to a
fixed member set. The cryptographic key-distribution path (per-member wrapped keys,
rotation) works and is tested, but is reached through the library rather than the
CLI.

## New machine joins the team (runbook)

A concrete path to put a teammate's machine on the shared memory:

1. **Configure.** Create `hippius-mem.toml` (or set `HIPPIUS_MEM_*`) with the S3
   coordinates (`s3_endpoint`, `bucket`, `access_key_id`, `secret`), the `team`
   namespace, the encryption key (`team_key_hex`, shared out of band — or set
   `HIPPIUS_MEM_MNEMONIC` to bootstrap a wrapped epoch key on startup), this
   developer's `author_seed_hex` (the SS58 identity is derived from it), and
   optionally the chain anchor (`chain_ws_url`, `chain` feature).
2. **Mint a sub-token** (if this developer has none): build with `--features
   console` and run `hippius-mem mint-token` to derive the ETH key from the
   mnemonic, run the api.hippius.com challenge/verify flow, and mint a
   bucket-scoped `{ access_key_id, secret }`. Put those in the config.
3. **Verify the bundle.** Run `hippius-mem doctor`. It validates the configured
   bundle (fields present, key and seed lengths, derivable author SS58) and runs a
   live probe that proves only ciphertext is written to the bucket — so a bad
   sub-token, a wrong-length key, or a broken encryption boundary is caught here,
   not at the first tool call. Use `hippius-mem doctor --offline` to validate
   without the network probe.
4. **Start the server.** On boot it bootstraps the epoch key-ring (when
   `HIPPIUS_MEM_MNEMONIC` is set) and syncs the index from the shared op-log, so
   the machine comes up already aware of teammates' notes. `refresh` re-syncs at
   any time.
5. **Optionally close the team.** A founder runs `hippius-mem publish-membership
   --members <ss58,...>` so only listed members' ops converge.

> **Where this is headed.** The target onboarding is a single "Memory key" minted
> in the hippius-console that yields one paste-ready bundle (the
> `hippius-mem.toml` above) — so a developer mints one subkey and runs `doctor`
> rather than assembling the sub-token, seed, and team key by hand. That console
> wizard is not built yet; see
> [`docs/plans/2026-06-28-memory-subkey-console-design.md`](docs/plans/2026-06-28-memory-subkey-console-design.md)
> for the design. Encryption stays entirely inside this server regardless: only
> ciphertext ever leaves it for the gateway.

Caveat: onboarding a member onto **wrapped-key distribution** (so they fetch the
team key cryptographically rather than receiving `team_key_hex` out of band) is
currently a library call (`provision_team_key`), not a subcommand — see
[Operating model](#operating-model).

## Retrieval honesty

`recall` is **not** semantic search today. The vector leg uses `HashEmbedder`, a
deterministic 64-dimension bag-of-tokens FNV-1a hash embedder: it captures word
co-occurrence (keyword overlap), not meaning, so a paraphrase that shares no
tokens with a stored summary will not match well. Ranking fuses this lexical
vector with keyword and per-note-type recency scoring. There is **no** neural
embedding model and **no** `embeddings`/`fastembed` Cargo feature — the only
features are `s3-integration`, `chain`, and `console`. Real semantic embeddings
(e.g. fastembed/ONNX) behind a not-yet-built feature are a documented future
enhancement; the index is rebuildable, so swapping the `Embedder` is clean when
that work lands.

## MCP tools

| Tool | Purpose | Returns |
|------|---------|---------|
| `remember` | Store a note: `note_type` (`decision`/`convention`/`gotcha`/`reference`/`context`), optional `repo`, optional `tags`, `summary`, `body`. Appends a signed `Remember` op to the shared op-log. | The new note's `mem_...` id. |
| `recall` | Search team memory: `text`, optional `repo`, optional `k`, optional `token_budget`. | Ranked pointers — `id`, `summary`, `score`, `repo`, `author`, `updated`. Never note bodies. |
| `get` | Hydrate one note by `id`. | The full note, including its `body`. |
| `refresh` | Replay the shared team op-log into this machine's index, pulling in teammates' new notes and applying their tombstones. | The number of live notes indexed. |
| `forget` | Tombstone a note by `id` (logical delete). Appends a signed `Forget` op; the note stops surfacing in `recall`. | `{ forgotten: true }`. |
| `link` | Assert a directed link from one note to another by `id`. Appends a signed `Link` op. | `{ linked: true }`. |
| `history` | Return the full op history of a note — who did what, in convergence order — plus its converged links, the verifiable chain of custody: each anchored op carries a Merkle inclusion proof. | The ordered op entries (with per-op anchor proofs) and the note's links. |
| `reconcile` | Integrity check: reconcile the visible op-log against the anchored Merkle roots, reporting any anchored op now missing and any root that disagrees with its leaves. **Local mode detects accidental/partial op-log loss only, not adversarial suppression** — that needs the `chain` feature plus chain readback. | `{ ok, checked_batches, total_anchored_ops, missing_ops, root_mismatches }`. |
| `edit` | Update a note in place by `id` (any of `summary`/`body`/`tags`; omitted fields keep their value), preserving its identity, `created`, and links. Appends a signed `Edit` op. | `{ edited: true }`. |

The `recall`/`get` split is the context-efficiency mechanism: an agent searches
with `recall`, reads the summaries, and calls `get` only for the notes it
actually needs. `remember`/`edit`/`forget`/`link` mutate through the signed
op-log; `refresh` pulls teammates' mutations into the local index; `history`
exposes the verifiable chain of custody; `reconcile` cross-checks that the
op-log still matches what was anchored.

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

## Phase 3 — identity, teams, and key distribution

Phase 2 made *what teammates wrote* the source of truth. Phase 3 makes *who is
on the team* and *how they get the key to read* cryptographic rather than
operational — one mnemonic per developer, a founder-signed membership list, and
team keys wrapped to each member's encryption key.

**Identity (one mnemonic → SS58 + x25519).** A developer's BIP-39 mnemonic
derives an sr25519 signing key whose public half is their **SS58 address**
(`ss58_encode` / `ss58_decode`, Substrate prefix 42 — the same codec the chain
uses, so the address is the on-chain identity). The same seed *separately*
derives an x25519 encryption key (domain-separated KDF, so the encryption key is
independent of any signing use of the seed). Attribution is **bound to the key**:
`MemoryStore` derives the author SS58 from the signer it holds, and the op-log
read path rejects any op whose `author` SS58 does not decode to its signing key —
a writer cannot sign with one key and claim another identity's address.

**Founder-signed team manifest + membership.** A team is **open** until a founder
publishes a manifest: with no manifest every signature-verified op converges (so
a team dogfoods before it is formalized). Once a founder publishes a signed
`TeamManifest`, `sync` converges only current members' ops — a non-member's
well-formed, signed op is filtered out before it enters converged state. Only the
founder may change membership (`publish_membership`), and the founder is always
included, so they cannot lock themselves out. Removing a member hides **all** of
that member's ops on any index rebuilt from the post-removal log.

**Team-key wrapping, provisioning, and rotation (forward-readable epochs).** The
symmetric team key is no longer a hand-copied hex string. Each member publishes a
signed `MemberKey` (their x25519 public key, bound to their SS58 by an sr25519
signature). The founder `provision_team_key`s by sealing the team key to every
member's x25519 key (sealed-box: a fresh ephemeral keypair per wrap, ECDH, AEAD —
forward-secret per wrap). A joining member who was never handed the key
**bootstraps** it: `fetch_team_key` unwraps the wrap addressed to them using only
their own x25519 secret. `rotate_team_key` mints a new epoch and wraps it to the
*current* members only — a removed member gets no wrap of the new epoch and
cannot read writes sealed under it, while older epochs stay wrapped so previously
shared notes remain readable. The full lifecycle (join, removal, rotation,
forged-author rejection) is exercised in
`hippius-mem-core/tests/e2e_phase3.rs`.

**Sub-token minting (`console` feature).** Minting a per-developer S3 sub-token
from the same mnemonic is wired behind the opt-in `console` Cargo feature: it
derives an ETH key from the mnemonic, runs the api.hippius.com challenge/verify
flow, and mints a bucket-scoped sub-token. The `mint-token` CLI drives this
end-to-end. Off by default so neither the library nor CI pulls the HTTP/ETH
stack; minting needs a network and a real mnemonic.

**Cargo features.**

| Feature | Compiles | Needs at runtime |
|---------|----------|------------------|
| `chain` | `SubxtAnchor` — submits Merkle roots on-chain via signed `System::remark_with_event`. | A funded sr25519 account and a reachable Hippius node. |
| `console` | `ConsoleClient` + `eth_signer_from_mnemonic` + the `mint-token` CLI (api.hippius.com sub-token minting). | A network and a real mnemonic. |
| `s3-integration` | The `S3BlobStore` live round-trip test (stays `#[ignore]`d). | A real gateway endpoint and sub-token credentials. |

## Threat model — honest limits

The shared bucket is treated as **untrusted**: a peer or the storage provider may
add, edit, or drop objects. Trust is re-derived from signatures and hash chains on
every read. What that does and does not buy you, stated plainly:

- **Removing a member does not revoke their access by itself.** Membership
  filtering stops a removed member's *new ops from converging*, but they keep their
  S3 sub-token and the current team key until **both** are dealt with out of band:
  the sub-token must be revoked at the gateway and the team key must be rotated
  (`rotate_team_key`). Until then, a removed member can still read and write the
  bucket directly and decrypt notes sealed under the un-rotated key.
- **`reconcile` (local mode) detects accidental loss, not adversarial
  suppression.** It cross-checks the visible op-log against anchored Merkle roots
  and flags an anchored op that has gone missing or a record whose root disagrees
  with its leaves — i.e. accidental or partial op-log loss. It does **not** catch a
  bucket that drops an op together with its anchor record (nothing is left to
  reconcile against). Trust-minimized suppression detection needs the `chain`
  feature plus chain readback (`reconcile_with_chain`), which reads the committed
  root back from the chain the bucket cannot forge.
- **The incremental snapshot path gates on epoch-key *presence*, not
  correctness.** `sync` takes the fast snapshot-restore path only when it holds the
  current epoch's key to open the checkpoint; a member lacking that key falls back
  to a full replay. The gate checks that a key exists, not that the snapshot is
  itself trustworthy — the snapshot is still server-produced state.
- **The per-author hash chain catches in-chain tampering, not suppression.** It
  detects in-place edits, mid-chain deletion, and intra-author reordering; it does
  **not** detect tail-truncation, whole-author suppression, or split-view /
  equivocation.
- **Anchoring is after-the-fact, so never-anchored ops have no commitment.**
  `reconcile` can only check ops that were batched and anchored; an op dropped
  before its batch anchored leaves no anchored leaf, so its absence is
  indistinguishable from "never written". A lower anchor threshold shrinks this
  window but never closes it.
- **Local-mode inclusion proofs prove internal consistency only.** With the default
  `NoopAnchor`, a `history` Merkle proof verifies against a root from the same
  bucket this server controls — it shows the op is consistent with a root the
  server asserts, not that the root was independently committed. Trust-minimization
  requires `chain` anchoring **and** a verifier that fetches the root from the chain.
- **The genesis manifest object is not pinned.** Founder consistency is enforced by
  treating the lowest-version manifest's founder as authoritative, but an attacker
  who overwrites the *genesis manifest object itself* can reset the trusted founder
  — defending that is on-chain anchoring's job (future work), not this layer's.
- **thebrain's `remark` fee/weight is unverified.** The Hippius runtime is not
  illu-indexed, so the on-chain `remark` fee/length limits and public-node
  submission policy were not verified against the live runtime; the implementation
  targets the generic FRAME `System::remark_with_event` contract.

## Scope by phase

This is an honest statement of what is built now versus planned.

- **Phase 1.** Single-machine memory engine — `remember`/`recall`/`get`
  with client-side ChaCha20-Poly1305 encryption, an in-memory hybrid index, and
  the S3 blob store — plus shared blob storage and cross-machine discovery.
- **Phase 2. Done.** Developer-signed append-only op-log in the shared
  bucket, convergence with tombstones (replacing blob-listing rebuild), Merkle
  batch anchoring with opt-in on-chain submission (`chain` feature), and the
  `refresh` / `forget` / `link` / `history` tools.
- **Phase 3. Done.** Mnemonic-derived identity (SS58 + x25519, author
  bound to key), founder-signed team manifest with membership filtering,
  team-key wrapping / provisioning / forward-readable rotation, and `console`-gated
  sub-token minting (`mint-token` CLI).
- **Phase 4 (current). Done, except disk-based ANN.** Built: **epoch-tagged note
  encryption** with an in-store key-ring (each note seals under its write epoch's
  key; readers decrypt with whichever epoch key they hold, so notes from an old
  epoch stay readable after rotation), **authoritative sync** (`MemoryStore::sync`
  prunes the *live* index down to the converged set via `MemoryIndex::retain`, so a
  removed member's or tombstoned note is dropped on the next sync — not only on a
  cold rebuild), **cold-start index snapshot/restore** plus **incremental op-log
  tailing** (restore the latest snapshot and converge only newer ops, with a
  full-rebuild fallback when a late/out-of-order op or membership change is
  detected), the **`reconcile` integrity tool** (local op-log-vs-anchors check;
  trust-minimized suppression detection via `reconcile_with_chain` under `chain`),
  the **`edit` tool**, a **convergence/partition stress suite**, and **criterion
  benches** for the measured perf pass. Still deferred: **disk-based ANN (LanceDB)**
  for scale.

## Design and plan

- [Design](docs/plans/2026-06-26-hippius-memory-design.md)
- [Implementation plan](docs/plans/2026-06-26-hippius-memory-implementation-plan.md)
