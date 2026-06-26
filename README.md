# Hippius Memory

Hippius Memory is an MCP server that gives a team's coding agents shared,
cross-machine memory. Agents record notes (decisions, conventions, gotchas,
references, context) through three tools — `remember`, `recall`, `get` — and
those notes are encrypted client-side and stored as objects on the Hippius S3
gateway in one shared team bucket. Because the bucket is the source of truth,
any teammate's agent on any machine reads the same memory, and because `recall`
returns short pointers and summaries rather than full bodies, an agent pulls
only what it needs into its context window instead of carrying the whole store.

## Architecture

The server is organized into four planes:

| Plane | Responsibility | Phase 1 status |
|-------|----------------|----------------|
| Index | Hybrid (vector + keyword) retrieval over note summaries; maps a note id to its object key, content hash, scope, tags, and recency. Returns pointers, never bodies. | Implemented, in-memory (`InMemoryIndex` behind the `MemoryIndex` trait). Rebuildable from the bucket. |
| Blob | Stores each note as ChaCha20-Poly1305 ciphertext at key `team/repo/mem_id/rev_N` on the Hippius S3 gateway. | Implemented (`S3BlobStore`; `MemoryBlobStore` fake for tests). |
| Audit | On-chain tamper-evident trail: per-developer signed op-log batched into a periodic Merkle anchor on the Hippius chain. | Phase 2. |
| Identity | Per-developer SS58 author identity (stamped on every note) and the per-developer S3 sub-token used to write. | Phase 1 wires identity through configuration; key/team provisioning is Phase 3. |

A note is a single self-contained fact. Each carries a one-line `summary`
(surfaced by `recall`) and a full `body` (returned only by `get`). Notes are
scoped by `team` (the shared namespace) and `repo` (`global` for team-wide),
which is the cheap first filter applied before semantic ranking.

The index is a derived, disposable cache: it can be rebuilt at any time by
listing and decrypting the bucket. `MemoryStore::rebuild_index` does exactly
this, which is how a machine with an empty index discovers what teammates have
already written. In Phase 1, cross-machine discovery is poll-based — a machine
calls `rebuild_index` to catch up. Phase 2 replaces polling with incremental
op-log tailing.

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

Example `hippius-mem.toml`:

```toml
bucket = "ourovoros-memory"
access_key_id = "AKID..."
secret = "<s3-sub-token-secret>"
team = "ourovoros"
author_ss58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
team_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
| `remember` | Store a note: `note_type` (`decision`/`convention`/`gotcha`/`reference`/`context`), optional `repo`, optional `tags`, `summary`, `body`. | The new note's `mem_...` id. |
| `recall` | Search team memory: `text`, optional `repo`, optional `k`, optional `token_budget`. | Ranked pointers — `id`, `summary`, `score`, `repo`, `author`, `updated`. Never note bodies. |
| `get` | Hydrate one note by `id`. | The full note, including its `body`. |

The `recall`/`get` split is the context-efficiency mechanism: an agent searches
with `recall`, reads the summaries, and calls `get` only for the notes it
actually needs.

## Scope by phase

This is an honest statement of what is built now versus planned.

- **Phase 1 (current).** Single-machine memory engine — `remember`/`recall`/`get`
  with client-side ChaCha20-Poly1305 encryption, an in-memory hybrid index, and
  the S3 blob store — plus shared blob storage and poll-based cross-machine
  discovery via `rebuild_index`.
- **Phase 2.** Developer-signed append-only op-log in the shared bucket for
  incremental sync (replacing polling), on-chain Merkle-anchor audit, and a
  `history` tool.
- **Phase 3.** Identity and team-key provisioning (per-developer sub-token
  minting, signed team manifest, key distribution) and `forget` / `link` tools.
- **Phase 4.** Hardening, cold-start index snapshot/restore, convergence stress
  testing, and disk-based ANN (LanceDB) for scale.

## Design and plan

- [Design](docs/plans/2026-06-26-hippius-memory-design.md)
- [Implementation plan](docs/plans/2026-06-26-hippius-memory-implementation-plan.md)
