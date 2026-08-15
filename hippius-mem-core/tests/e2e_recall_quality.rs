//! End-to-end recall-quality guarantees through the full [`MemoryStore`].
//!
//! These are black-box integration tests: they build a real store over an
//! in-memory (or on-disk `FsBlobStore`) backend, `remember` notes through the
//! public API, and assert on what `recall` ranks and what `get` hydrates. They
//! run on the DEFAULT lexical build (`HashEmbedder`, keyword-only) — the build
//! every teammate actually ships — so they pin the guarantees CI protects
//! without the `--features embeddings` ONNX download.
//!
//! Scope of what is proven here (the store wiring): a remembered note is
//! recoverable byte-exact; a relevant note outranks and an irrelevant note never
//! surfaces beside it; scope isolation holds with distinct summaries; `recall`
//! reports the honest `total_matched` while `k` truncates; the dedup gate refuses
//! a duplicate unless forced. Ranking *magnitudes* that need a controllable clock
//! (per-type recency decay, exact demotion factor) live in `retrieval_ranking.rs`,
//! which drives the index directly.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but assert on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, FsBlobStore, HashEmbedder, InMemoryIndex, MemError, MemoryBlobStore, MemoryStore,
    NetworkPrefix, NoopAnchor, NoteType, OpLogStore, RecallInput, RememberInput, RepoScope,
    SecretKey, Signer, Sr25519Signer,
};

const TEAM: &str = "team";
const TEAM_KEY: [u8; 32] = [7_u8; 32];

/// Above any op count these tests write, so the `NoopAnchor` batch path stays
/// inert and never perturbs timing or op-log shape.
const ANCHOR_THRESHOLD: usize = usize::MAX;

/// A default seed: a fixed seed yields a fixed author SS58 (derived inside
/// `MemoryStore::new` from the signer), so every run signs as the same identity.
const SEED: [u8; 32] = [5_u8; 32];

/// Build a solo store over `blob`, signing with `seed`, single-epoch key ring.
///
/// This is the whole hermetic surface: one store, one epoch, the lexical
/// `HashEmbedder`. A note the store `remember`s is upserted into its own index
/// synchronously, so it is recallable the instant `remember` returns — no
/// `sync`, membership, or manifest machinery is involved for a store reading its
/// own notes.
fn build_store(
    blob: Arc<dyn BlobStore>,
    seed: [u8; 32],
) -> Result<MemoryStore, Box<dyn std::error::Error>> {
    let oplog = OpLogStore::new(blob.clone());
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
        &seed,
        NetworkPrefix::HIPPIUS,
    )?);

    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        BTreeMap::from([(0_u64, SecretKey::from_bytes(TEAM_KEY))]),
        0,
        TEAM.to_owned(),
        ANCHOR_THRESHOLD,
    ))
}

/// A `RememberInput` with the boilerplate defaulted, so each test states only
/// the fields it cares about.
fn remember_input(
    note_type: NoteType,
    repo: RepoScope,
    summary: &str,
    body: &str,
    force: bool,
) -> RememberInput {
    RememberInput {
        force,
        note_type,
        repo,
        tags: BTreeSet::new(),
        summary: summary.to_owned(),
        body: body.to_owned(),
    }
}

fn recall_input(text: &str, repo: RepoScope, k: usize) -> RecallInput {
    RecallInput {
        text: text.to_owned(),
        repo,
        k,
        token_budget: None,
    }
}

fn repo(name: &str) -> RepoScope {
    RepoScope::Repo(name.to_owned())
}

/// "Stores valuable information": a note written through `remember` is
/// recoverable byte-exact. `recall` surfaces its pointer by keyword, and `get`
/// hydrates the exact body that was stored — the round trip a team relies on.
#[tokio::test]
async fn remembered_note_round_trips_through_recall_and_get()
-> Result<(), Box<dyn std::error::Error>> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = build_store(blob, SEED)?;

    let body = "drain and close every pooled connection before exit";
    let id = store
        .remember(remember_input(
            NoteType::Gotcha,
            repo("thebrain"),
            "release pooled database handles on clean shutdown",
            body,
            false,
        ))
        .await?;

    let hits = store.recall(recall_input(
        "close pooled database connections",
        repo("thebrain"),
        10,
    ))?;
    assert!(
        hits.pointers.iter().any(|p| p.note_id == id),
        "the remembered note must surface for a keyword-overlapping query"
    );

    // `get` after a `recall` that surfaced this id appends a signed Reinforce op
    // (maybe_reinforce). Harmless here — one store, and we assert on body bytes,
    // not on op-log/history diffs. A future edit that starts diffing op-logs
    // across stores in this test must avoid get-after-recall or it will diverge.
    let note = store.get(id).await?;
    assert_eq!(
        note.body, body,
        "get must hydrate the exact body that was stored, byte for byte"
    );

    Ok(())
}

/// "Recalls the RIGHT ones" — the centerpiece. With a relevant note and an
/// irrelevant note coexisting in one store, recall must rank the relevant one
/// first AND leave the irrelevant one out entirely: on the lexical build a note
/// sharing no query token scores zero in both legs, and the relevance floor
/// keeps it from floating up on recency alone.
///
/// Discriminates: if the relevance floor regressed (recency floating unrelated
/// notes), the off-topic note would appear and `total_matched` would be 2.
#[tokio::test]
async fn recall_ranks_the_relevant_note_and_excludes_the_irrelevant_one()
-> Result<(), Box<dyn std::error::Error>> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = build_store(blob, SEED)?;

    let relevant = store
        .remember(remember_input(
            NoteType::Decision,
            RepoScope::Global,
            "postgres connection pool sizing for the api",
            "cap the pool at cpu count times two",
            false,
        ))
        .await?;
    let _irrelevant = store
        .remember(remember_input(
            NoteType::Decision,
            RepoScope::Global,
            "frontend button hover animation easing curve",
            "use ease-in-out over 150ms",
            false,
        ))
        .await?;

    let hits = store.recall(recall_input(
        "postgres connection pool",
        RepoScope::Global,
        10,
    ))?;

    assert_eq!(
        hits.total_matched, 1,
        "only the relevant note shares tokens with the query; the irrelevant one \
         must not clear the relevance floor"
    );
    assert_eq!(
        hits.pointers.first().map(|p| p.note_id),
        Some(relevant),
        "the relevant note must rank first"
    );
    Ok(())
}

/// The new `FsBlobStore` trial vault must give the same round-trip guarantee as
/// the in-memory backend: a note written to an on-disk vault is recalled and its
/// body hydrated intact. This guards the paid-upgrade funnel's storage substrate.
///
/// The `TempDir` binding is held for the whole test on purpose — dropping it
/// deletes the vault out from under the store.
#[tokio::test]
async fn recall_round_trips_over_the_fs_vault() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let blob: Arc<dyn BlobStore> = Arc::new(FsBlobStore::new(dir.path().to_path_buf()));
    let store = build_store(blob, SEED)?;

    let body = "the merkle root is anchored once per batch, not per op";
    let id = store
        .remember(remember_input(
            NoteType::Reference,
            repo("thebrain"),
            "audit anchoring batches merkle roots on chain",
            body,
            false,
        ))
        .await?;

    let hits = store.recall(recall_input("merkle anchoring batch", repo("thebrain"), 10))?;
    assert!(
        hits.pointers.iter().any(|p| p.note_id == id),
        "the note stored in the fs vault must be recallable"
    );

    let note = store.get(id).await?;
    assert_eq!(note.body, body, "fs-vault body must hydrate byte-exact");

    // Bind kept alive to here; the vault lives as long as `dir`.
    drop(dir);
    Ok(())
}

/// Scope isolation with DISTINCT summaries: a repo-scoped query must not surface
/// a note living in a different repo, even when that note shares the query's
/// keywords. The existing scope test uses identical summaries, so it cannot tell
/// a scope-filter regression from a ranking one; distinct, both-matching
/// summaries make the scope boundary the only thing under test.
#[tokio::test]
async fn recall_does_not_leak_notes_from_another_repo() -> Result<(), Box<dyn std::error::Error>> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = build_store(blob, SEED)?;

    let mine = store
        .remember(remember_input(
            NoteType::Gotcha,
            repo("alpha"),
            "kafka consumer rebalance storm on deploy",
            "pin the group instance id",
            false,
        ))
        .await?;
    let _theirs = store
        .remember(remember_input(
            NoteType::Gotcha,
            repo("beta"),
            "kafka consumer lag alert thresholds",
            "page at ten thousand messages behind",
            false,
        ))
        .await?;

    let hits = store.recall(recall_input("kafka consumer", repo("alpha"), 10))?;

    let surfaced: BTreeSet<_> = hits.pointers.iter().map(|p| p.note_id).collect();
    assert!(surfaced.contains(&mine), "the in-scope note must surface");
    assert_eq!(
        hits.total_matched, 1,
        "the other repo's note shares the query keywords but must be filtered by scope"
    );
    Ok(())
}

/// An empty query must recall nothing — it must NOT dump the whole corpus.
/// Tokenizing "" yields no terms, so every note scores zero in the lexical leg
/// and nothing clears the floor.
#[tokio::test]
async fn empty_query_recalls_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = build_store(blob, SEED)?;

    store
        .remember(remember_input(
            NoteType::Context,
            RepoScope::Global,
            "some note that clearly exists in the corpus",
            "body",
            false,
        ))
        .await?;

    let hits = store.recall(recall_input("", RepoScope::Global, 10))?;
    assert_eq!(hits.total_matched, 0, "an empty query matches nothing");
    assert!(
        hits.pointers.is_empty(),
        "an empty query returns no pointers"
    );
    Ok(())
}

/// Recall against an empty corpus is empty, not an error.
#[tokio::test]
async fn empty_corpus_recalls_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = build_store(blob, SEED)?;

    let hits = store.recall(recall_input("anything at all", RepoScope::Global, 10))?;
    assert_eq!(hits.total_matched, 0);
    assert!(hits.pointers.is_empty());
    Ok(())
}

/// Efficiency/honesty: `k` truncates the returned pointers, but `total_matched`
/// reports every in-scope relevant note, so a caller can tell it saw only a
/// prefix. Five notes share the query token; `k = 2` returns two pointers while
/// `total_matched` stays 5.
#[tokio::test]
async fn recall_truncates_to_k_but_reports_full_total_matched()
-> Result<(), Box<dyn std::error::Error>> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = build_store(blob, SEED)?;

    for i in 0..5 {
        // `force` bypasses the dedup gate: these summaries deliberately share
        // tokens (so all five match), which would otherwise trip near-duplicate.
        store
            .remember(remember_input(
                NoteType::Reference,
                RepoScope::Global,
                &format!("database shard rebalancing note number {i}"),
                &format!("body {i}"),
                true,
            ))
            .await?;
    }

    let hits = store.recall(recall_input(
        "database shard rebalancing",
        RepoScope::Global,
        2,
    ))?;
    assert_eq!(hits.pointers.len(), 2, "k caps the returned pointers");
    assert_eq!(
        hits.total_matched, 5,
        "total_matched counts every relevant match before the k cap"
    );
    Ok(())
}

/// `k = 0` returns no pointers while still reporting the true match count, so a
/// caller probing "how many match?" without wanting bodies gets an honest answer.
#[tokio::test]
async fn recall_with_zero_k_returns_no_pointers_but_counts_matches()
-> Result<(), Box<dyn std::error::Error>> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = build_store(blob, SEED)?;

    store
        .remember(remember_input(
            NoteType::Decision,
            RepoScope::Global,
            "unique retrieval marker token zebra",
            "body",
            false,
        ))
        .await?;

    let hits = store.recall(recall_input("zebra", RepoScope::Global, 0))?;
    assert!(hits.pointers.is_empty(), "k=0 yields no pointers");
    assert_eq!(hits.total_matched, 1, "the match is still counted");
    Ok(())
}

/// The dedup gate protects memory quality: a second note whose summary duplicates
/// an existing one is refused with [`MemError::NearDuplicate`] unless `force` is
/// set. This is why "stores valuable information" does not degrade into "stores
/// the same thing ten times".
#[tokio::test]
async fn duplicate_summary_is_refused_unless_forced() -> Result<(), Box<dyn std::error::Error>> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = build_store(blob, SEED)?;

    let summary = "graceful shutdown drains the request queue first";
    store
        .remember(remember_input(
            NoteType::Convention,
            RepoScope::Global,
            summary,
            "first body",
            false,
        ))
        .await?;

    let dup = store
        .remember(remember_input(
            NoteType::Convention,
            RepoScope::Global,
            summary,
            "second body",
            false,
        ))
        .await;
    assert!(
        matches!(dup, Err(MemError::NearDuplicate { .. })),
        "an unforced duplicate summary must be refused, got {dup:?}"
    );

    let forced = store
        .remember(remember_input(
            NoteType::Convention,
            RepoScope::Global,
            summary,
            "third body",
            true,
        ))
        .await;
    assert!(
        forced.is_ok(),
        "force must override the dedup gate: {forced:?}"
    );
    Ok(())
}

/// An edit is not stored until *recall* sees the new wording.
///
/// `edit_updates_note_body` (store unit tests) and `edit_updates_via_handler`
/// only hydrate through `get`, which reads the sealed blob. If edit resealed
/// the body but left the index summary stale, those tests would stay green
/// and every agent `recall` would keep serving the old pointer.
#[tokio::test]
async fn edit_then_recall_surfaces_the_new_summary_not_the_old()
-> Result<(), Box<dyn std::error::Error>> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let store = build_store(blob, SEED)?;

    // Old and new summaries share no content tokens (only the stop-words
    // "use"/"for"). A query built from the old unique terms must therefore
    // miss after the edit — if it still hits, the index kept the stale
    // summary. Shared leftovers like "session cache" would keep matching
    // the new wording and make this assertion vacuous.
    let id = store
        .remember(remember_input(
            NoteType::Decision,
            RepoScope::Global,
            "use redis for session storage",
            "original body",
            false,
        ))
        .await?;

    store
        .edit(
            id,
            remember_input(
                NoteType::Decision,
                RepoScope::Global,
                "use memcached for request caching",
                "rewritten body",
                true,
            ),
        )
        .await?;

    // `get` after a `recall` that surfaced this id appends a Reinforce op.
    // Hydrate first so a later edit of this test that diffs history cannot
    // be contaminated by that side effect.
    let note = store.get(id).await?;
    assert_eq!(note.body, "rewritten body");
    assert_eq!(note.summary, "use memcached for request caching");

    let new_hits = store.recall(recall_input(
        "memcached request caching",
        RepoScope::Global,
        10,
    ))?;
    assert_eq!(
        new_hits.pointers.first().map(|p| p.note_id),
        Some(id),
        "recall must find the edited wording"
    );
    assert_eq!(
        new_hits.pointers.first().map(|p| p.summary.as_str()),
        Some("use memcached for request caching"),
    );

    let old_hits = store.recall(recall_input("redis session storage", RepoScope::Global, 10))?;
    assert!(
        old_hits.pointers.iter().all(|p| p.note_id != id),
        "the pre-edit wording must no longer surface this note"
    );
    Ok(())
}
