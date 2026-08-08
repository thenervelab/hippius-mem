//! Team-wide activity and reuse aggregation — Phase C's read-only report pass.
//!
//! [`build_report`] folds a [`MemoryStore`]'s already-converged, signed op-log
//! state into a [`TeamReport`]: how much the team wrote / edited / linked /
//! tombstoned / redacted inside a caller-supplied [`ReportWindow`], plus which
//! notes earned the most distinct reinforcers — the same Sybil-bounded
//! distinct-author count `recall`'s reinforcement boost reads (see
//! [`crate::oplog::converge`] and its `NoteState::reinforcers`). It is a pure
//! fold: no blob fetches, no mutation, no new op kinds, and it never reads the
//! system clock — `window` is an input the caller (the CLI, Task 14) computes,
//! never derived here.
//!
//! `reuse` is built from [`MemoryStore::list_records`], the same converged
//! local index `recall` and `history` trust. A tombstoned or redacted note is
//! already absent from it: `forget`/`redact` remove the note from the index
//! immediately, and a full replay never re-admits a tombstoned-or-redacted
//! note into the live set (see `store::MemoryStore::replay_full`), so a
//! scrubbed note's summary cannot leak into a reuse ranking here.

use serde::Serialize;

use crate::error::MemError;
use crate::index::IndexRecord;
use crate::oplog::{OpKind, VerifiedOps};
use crate::store::MemoryStore;

/// The half-open time window a [`TeamReport`]'s activity tally covers:
/// `[since_ms, until_ms)`.
///
/// `Serialize` (not `Deserialize`): this type is a report OUTPUT — the CLI's
/// `report` subcommand and the dashboard's `/api/vaults/{vault}/report`
/// endpoint both render it, so both surfaces need the wire shape, but nothing
/// reads a `TeamReport` back in from JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReportWindow {
    /// Milliseconds since epoch, inclusive.
    pub since_ms: u64,
    /// Milliseconds since epoch, exclusive.
    pub until_ms: u64,
}

impl ReportWindow {
    /// Whether `ms` falls inside this half-open window.
    fn contains(self, ms: u64) -> bool {
        ms >= self.since_ms && ms < self.until_ms
    }
}

/// One note's reuse signal: how many DISTINCT identities reinforced it.
///
/// `distinct_reinforcers` is read straight from the note's converged
/// reinforcer set, so a repeat reinforcement from the same author never
/// inflates it (the Sybil bound convergence already enforces).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoteReuse {
    /// The reinforced note's id, in its canonical string form.
    pub id: String,
    /// The note's one-line summary, for display without a further fetch.
    pub summary: String,
    /// Count of distinct authors who reinforced this note.
    pub distinct_reinforcers: u64,
}

/// Per-op-kind tallies of every mutation inside a [`TeamReport`]'s window.
///
/// Each field counts OPS, not distinct notes: editing the same note three
/// times inside the window counts `edited = 3` — activity volume, not reach.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ActivityCounts {
    /// `Remember` ops: new notes created.
    pub added: u64,
    /// `Edit` ops: an existing note's body was replaced.
    pub edited: u64,
    /// `Link` and `Relate` ops: a relationship was asserted between notes.
    pub linked: u64,
    /// `Forget` ops: a note was tombstoned.
    pub tombstoned: u64,
    /// `Redact` ops: a note's content was permanently scrubbed.
    pub redacted: u64,
}

/// Maximum number of entries [`TeamReport::reuse`] carries.
///
/// A team can accumulate far more reinforced notes than a report should
/// render; [`TeamReport::reuse_total`] carries the pre-cap count so a
/// renderer can say "top 20 of N" instead of truncating silently.
pub const MAX_REUSE_ENTRIES: usize = 20;

/// The full team-wide report: a window, its activity tally, and the
/// highest-reuse notes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TeamReport {
    /// The window `activity` was computed over.
    pub window: ReportWindow,
    /// Up to [`MAX_REUSE_ENTRIES`] reinforced notes, descending by
    /// `distinct_reinforcers`.
    pub reuse: Vec<NoteReuse>,
    /// How many notes had at least one reinforcer before the
    /// [`MAX_REUSE_ENTRIES`] cap — the "N" in "top 20 of N".
    pub reuse_total: u64,
    /// Per-op-kind activity counts inside `window`.
    pub activity: ActivityCounts,
}

/// Build a [`TeamReport`] over `store`'s converged op-log state for `window`.
///
/// A pure, read-only fold. `activity` tallies every op naming a note in
/// `store`'s team whose `op_id` ULID timestamp falls inside `window`; `reuse`
/// ranks `store`'s current converged index by distinct-reinforcer count,
/// independent of `window` — it reports which notes have earned reuse to
/// date, not only reuse inside the window (reuse has no reinforcement-time
/// field to window-filter on; the last-reinforced instant is not the same
/// question as "how many distinct people found this useful").
///
/// `store` is read as-is; call [`MemoryStore::sync`] first if `store` should
/// reflect teammates' latest writes rather than only its own.
///
/// # Errors
///
/// Whatever reading `store`'s op-log or converged index reports (storage,
/// deserialization, or a signature/chain violation).
pub async fn build_report(
    store: &MemoryStore,
    window: ReportWindow,
) -> Result<TeamReport, MemError> {
    let ops = store.read_all_ops().await?;
    let activity = tally_activity(&ops, window);
    let (reuse, reuse_total) = rank_reuse(&store.list_records()?);

    Ok(TeamReport {
        window,
        reuse,
        reuse_total,
        activity,
    })
}

/// Tally every op in `ops` whose `op_id` ULID timestamp falls inside
/// `window`, by kind.
///
/// [`OpKind::Reinforce`] is deliberately unmatched: it is a usage signal, not
/// an activity-volume op — its distinct-author count feeds `reuse` via the
/// converged index instead, so counting it here would double-book it under a
/// different name.
fn tally_activity(ops: &VerifiedOps, window: ReportWindow) -> ActivityCounts {
    let mut counts = ActivityCounts::default();

    for op in ops
        .iter()
        .filter(|op| window.contains(op.op_id.timestamp_ms()))
    {
        match &op.kind {
            OpKind::Remember => counts.added += 1,
            OpKind::Edit => counts.edited += 1,
            OpKind::Link { .. } | OpKind::Relate { .. } => counts.linked += 1,
            OpKind::Forget => counts.tombstoned += 1,
            OpKind::Redact => counts.redacted += 1,
            OpKind::Reinforce => {}
        }
    }

    counts
}

/// Rank `records` by distinct-reinforcer count, descending, breaking ties on
/// note id for a deterministic order. Returns the capped top
/// [`MAX_REUSE_ENTRIES`] alongside the pre-cap total, so a caller can report
/// "top 20 of N" instead of truncating silently.
///
/// Records with no reinforcer are excluded: `reuse` answers "which notes got
/// reused", not "every live note", so a note nobody has reinforced yet has
/// nothing to rank.
fn rank_reuse(records: &[IndexRecord]) -> (Vec<NoteReuse>, u64) {
    let mut reused: Vec<NoteReuse> = records
        .iter()
        .filter(|record| !record.reinforcers.is_empty())
        .map(|record| NoteReuse {
            id: record.note_id.to_string(),
            summary: record.summary.clone(),
            distinct_reinforcers: u64::try_from(record.reinforcers.len()).unwrap_or(u64::MAX),
        })
        .collect();

    reused.sort_by(|a, b| {
        b.distinct_reinforcers
            .cmp(&a.distinct_reinforcers)
            .then_with(|| a.id.cmp(&b.id))
    });

    let reuse_total = u64::try_from(reused.len()).unwrap_or(u64::MAX);
    reused.truncate(MAX_REUSE_ENTRIES);
    (reused, reuse_total)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{ReportWindow, build_report};
    use crate::audit::NoopAnchor;
    use crate::crypto::SecretKey;
    use crate::domain::{NetworkPrefix, NoteType, RepoScope};
    use crate::error::MemError;
    use crate::index::{HashEmbedder, InMemoryIndex};
    use crate::oplog::{OpLogStore, Signer, Sr25519Signer};
    use crate::store::{BlobStore, MemoryBlobStore, MemoryStore, RecallInput, RememberInput};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEAM: &str = "team";
    const TEST_KEY: [u8; 32] = [7_u8; 32];
    const AUTHOR_ONE_SEED: [u8; 32] = [21_u8; 32];
    const AUTHOR_TWO_SEED: [u8; 32] = [22_u8; 32];

    /// Build a store over `blob` (the op-log shares the same backend), signing
    /// from `seed`. Mirrors `store::tests::store_over`; report.rs needs its
    /// own copy since that helper is private to `store`'s test module.
    fn store_over(blob: Arc<dyn BlobStore>, seed: [u8; 32]) -> Result<MemoryStore, MemError> {
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &seed,
            NetworkPrefix::HIPPIUS,
        )?);
        let oplog = OpLogStore::new(blob.clone());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));

        Ok(MemoryStore::new(
            blob,
            index,
            oplog,
            Arc::new(NoopAnchor),
            signer,
            BTreeMap::from([(0, SecretKey::from_bytes(TEST_KEY))]),
            0,
            TEAM.to_string(),
            usize::MAX,
        ))
    }

    fn test_store() -> Result<MemoryStore, Box<dyn std::error::Error>> {
        Ok(store_over(
            Arc::new(MemoryBlobStore::default()),
            AUTHOR_ONE_SEED,
        )?)
    }

    fn note_input(summary: &str) -> RememberInput {
        RememberInput {
            note_type: NoteType::Reference,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: summary.to_string(),
            body: "detail in the body".to_string(),
            force: true,
        }
    }

    /// "Now" in epoch milliseconds. Falls back to `0` / `u64::MAX` on the
    /// practically-impossible clock-before-epoch / clock-past-`u64::MAX`
    /// edges, mirroring `store::current_millis`, rather than panicking.
    fn now_ms() -> u64 {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
    }

    /// An unbounded window, for tests that only care about `reuse`.
    fn all_time_window() -> ReportWindow {
        ReportWindow {
            since_ms: 0,
            until_ms: u64::MAX,
        }
    }

    fn recall_for(text: &str) -> RecallInput {
        RecallInput {
            text: text.to_string(),
            repo: RepoScope::Global,
            k: 10,
            token_budget: None,
        }
    }

    #[tokio::test]
    async fn report_counts_window_activity() -> TestResult {
        let store = test_store()?;

        // Outside the window: an op minted BEFORE `since_ms`.
        store
            .remember(note_input("outside note excluded from the window"))
            .await?;
        tokio::time::sleep(Duration::from_millis(5)).await;
        let since_ms = now_ms();

        // Inside the window: 3 remembers, 1 edit, 1 link, 1 forget.
        let a = store
            .remember(note_input("first note added inside the window"))
            .await?;
        let b = store
            .remember(note_input("second note added inside the window"))
            .await?;
        let c = store
            .remember(note_input("third note added inside the window"))
            .await?;
        store
            .edit(a, note_input("first note, revised inside the window"))
            .await?;
        store.link(a, b).await?;
        store.forget(c).await?;

        tokio::time::sleep(Duration::from_millis(5)).await;
        let until_ms = now_ms();

        let report = build_report(&store, ReportWindow { since_ms, until_ms }).await?;

        assert_eq!(report.activity.added, 3, "3 remembers inside the window");
        assert_eq!(report.activity.edited, 1, "1 edit inside the window");
        assert_eq!(report.activity.linked, 1, "1 link inside the window");
        assert_eq!(report.activity.tombstoned, 1, "1 forget inside the window");
        assert_eq!(report.activity.redacted, 0, "no redact ops were minted");
        Ok(())
    }

    #[tokio::test]
    async fn reuse_ranks_by_distinct_reinforcers() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let author_one = store_over(blob.clone(), AUTHOR_ONE_SEED)?;
        let author_two = store_over(blob.clone(), AUTHOR_TWO_SEED)?;

        let note_a = author_one
            .remember(note_input("distinct incident postmortem template"))
            .await?;
        let note_b = author_one
            .remember(note_input("release checklist for the gateway service"))
            .await?;

        // `author_two` needs the notes in its own local index before it can
        // recall/get them.
        author_two.sync().await?;

        // Note A: reinforced by TWO distinct authors.
        author_one.recall(recall_for("postmortem"))?;
        author_one.get(note_a).await?;
        author_two.recall(recall_for("postmortem"))?;
        author_two.get(note_a).await?;

        // Note B: reinforced by `author_one` TWICE — the second use is either
        // rate-limited or folds into the same distinct-author set; either way
        // it must still count as ONE distinct reinforcer.
        author_one.recall(recall_for("checklist"))?;
        author_one.get(note_b).await?;
        author_one.get(note_b).await?;

        // Converge every author's Reinforce op into `author_one`'s index.
        author_one.sync().await?;

        let report = build_report(&author_one, all_time_window()).await?;

        assert_eq!(report.reuse.len(), 2);
        assert_eq!(report.reuse[0].id, note_a.to_string());
        assert_eq!(report.reuse[0].distinct_reinforcers, 2);
        assert_eq!(report.reuse[1].id, note_b.to_string());
        assert_eq!(report.reuse[1].distinct_reinforcers, 1);
        assert_eq!(report.reuse_total, 2);
        Ok(())
    }

    #[tokio::test]
    async fn empty_window_is_a_valid_quiet_report() -> TestResult {
        let store = test_store()?;

        let report = build_report(&store, all_time_window()).await?;

        assert_eq!(report.activity, super::ActivityCounts::default());
        assert!(report.reuse.is_empty());
        assert_eq!(report.reuse_total, 0);
        Ok(())
    }
}
