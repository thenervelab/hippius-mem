# Non-blocking `serve` boot: background warmup + concurrent sync + batch embed

Date: 2026-07-06
Branch: `fix/serve-boot-nonblocking`

## Problem

`hippius-mem serve` takes ~46 s to answer the MCP `initialize` handshake, so
Claude Code's 30 s connection timeout fires and the server "fails to connect".
Measured split (42 notes, remote `s3.hippius.com`):

| Phase | Cost |
|-------|------|
| ONNX embedding (42 notes) | ~13 s |
| S3 op-log read + blob decode + converge | ~33 s |

Root cause: `main.rs` runs `store.sync().await` to completion **before**
`MemoryServer::new(store).serve(stdio())`, so the whole cold sync is on the
handshake critical path. The sync itself is slow because every S3 GET is serial
and every note is re-embedded one at a time.

## Goals

1. **#2 Background warmup** — answer `initialize` immediately; run the initial
   sync in a background task. Reads (`recall`/`get`) await the first warmup
   exactly once, then normal `refresh_if_stale` freshness governs.
2. **#3a Concurrent S3 fetches** — parallelize op-log object GETs
   (`read_verified`) and note blob decodes (`replay_full`/`sync_incremental`)
   with a bounded degree of concurrency.
3. **#3b Batch embedding** — embed all summaries in one `Embedder::embed(&[..])`
   call instead of per-note `upsert`.

## Non-goals

- Persisting embedding vectors across boots (a later optimization; batching +
  concurrency already take cold boot from ~46 s to a few seconds).
- Changing the retrieval ranking, crypto, or op-log verification semantics.

## Key correctness facts (from the code)

- `read_verified` **decouples fetch from verify**: the fetch loop only collects
  bytes; dedup, per-op signature/identity/team checks, and per-author chain
  quarantine all run afterward on the whole set and end with a total-order
  `sort_by_key((lamport, op_id, author_key))`. Fetch order is therefore
  irrelevant — concurrent GETs produce a byte-identical `VerifiedOps`.
- `replay_full` / `sync_incremental` decode each note independently
  (`decode_pointer` is a pure fetch+decrypt→`IndexRecord`); order only matters
  at `index.retain` + insert, both order-independent. So decodes parallelize.
- The index is in-memory, rebuilt from the op-log; a decode/embed fault on one
  note is skip-with-warn, never a whole-sync abort. Batch embed must preserve
  that per-note resilience (a note whose blob failed to decode never reaches the
  embed batch).

## Architecture constraint

`hippius-mem-core` intentionally carries `tokio` with only `features = ["sync"]`
— no runtime in the core crate. So:

- Concurrency in core uses `futures-util` stream combinators
  (`buffer_unordered`), which are polled by the caller's runtime and need no
  runtime in core. New dependency justified by the ~33 s → few-s win.
- Batch embedding stays **synchronous** in the index (no `spawn_blocking`/`rt`
  in core). ONNX batch inference amortizes the per-call overhead that dominates
  the ~13 s, and it runs inside the background warmup task, off the handshake.
- The warmup task + readiness gate live in the **binary** (`main.rs` /
  `server.rs`), which has the full multi-thread runtime.

## Data structures

- `Warmup` (binary, `server.rs`): a readiness gate the read handlers await once.
  `tokio::sync::watch::<bool>` — background task sends `true` when the initial
  sync attempt completes (success OR failure — "attempt done", not "succeeded",
  matching today's non-fatal startup-sync behavior). `wait_for(|&w| w)` is
  race-free (no missed-notification hazard). Held as `watch::Receiver<bool>` in
  `MemoryServer`; the sender moves into the spawned task.
- `MemoryIndex::upsert_batch(&self, records: Vec<IndexRecord>) -> Result<(), MemError>`
  (core, index trait): one `embed(&summaries)` call, then insert all entries
  under one lock acquisition. Preserves the "misbehaving embedder degrades that
  record's vector to zero" fallback per record.
- Bounded concurrency constants: `OPLOG_FETCH_CONCURRENCY` and
  `NOTE_DECODE_CONCURRENCY` (start at 16) — the axiom-176 explicit bound.

## Ownership / concurrency

- Concurrent fetch clones the `Arc<dyn BlobStore>` into each stream future so no
  `&self` borrow crosses the `buffer_unordered` stream; nothing is spawned, so
  the futures need not be `'static`-by-spawn — they are driven inline.
- The index guard is `std::sync::Mutex` (axiom 74): `upsert_batch` embeds
  BEFORE taking the guard, then inserts without any `.await` under the guard.
- Warmup task holds `Arc<MemoryStore>` + `watch::Sender<bool>`. On serve exit the
  runtime drops the task; the sync is idempotent and the op-log persists, so an
  interrupted warmup just re-syncs next boot (same rationale as the existing
  "flush-on-shutdown omitted" note in `main.rs`). Documented, not a leak.

## Error strategy

- No new error variants. Concurrent fetch preserves the existing split: a GET
  failure propagates (`MemError::Storage`, systemic), a per-object
  deserialize/decode fault is skip-with-warn.
- `upsert_batch` propagates only a real index fault (as `upsert` does today).

## Test plan

- Core unit: `upsert_batch` indexes the same set as N single `upsert`s
  (search-equivalence through the public index API); a record whose summary the
  embedder rejects still inserts (zero vector), others unaffected.
- Core: concurrent `read_verified` over a fake blob store returns the identical
  `VerifiedOps` ordering as the serial version for a mixed set (valid + junk +
  duplicate ops); a GET error still aborts.
- Core: `sync` over a fake store with K notes indexes all K via the concurrent
  decode path; a single undecodable blob is skipped, the rest indexed.
- Binary: a read issued before warmup completes waits for it (deterministic via
  a store whose first sync blocks on a barrier); after warmup, reads don't wait.
- Existing e2e (`e2e_*`, `stress_convergence`) must stay green — they exercise
  sync/converge through the public path.
