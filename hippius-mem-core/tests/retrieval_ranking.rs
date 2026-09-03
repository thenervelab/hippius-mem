//! Ranking-magnitude guarantees, proven against the [`InMemoryIndex`] directly.
//!
//! These integration tests drive the index through its public API with fully
//! controlled `updated`/`now` timestamps, relations, and reinforcer sets —
//! control the store path cannot give (it stamps `updated` from the wall clock
//! and hardwires `now`). That control is what lets these tests pin *magnitudes*:
//! the per-`NoteType` recency half-lives, the exact relation-demotion factor,
//! and the "reinforcement re-ranks within the relevant set, never floats an
//! off-topic note" boundary.
//!
//! All run on the lexical `HashEmbedder` (keyword-only, `contributes_semantic_leg
//! == false`), the default build, so no ONNX download is needed.

#![expect(
    clippy::panic_in_result_fn,
    clippy::expect_used,
    reason = "Result-returning tests assert on outcomes; expect documents invariants on throwaway fixtures whose construction cannot fail"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use hippius_mem_core::{
    Blake3Hash, HashEmbedder, InMemoryIndex, IndexRecord, LinkRel, MemoryIndex, NoteId, NoteType,
    Pointer, Query, RepoScope, Scope, Ss58, Timestamp, TypedLink,
};

const TEAM: &str = "team";

/// A fixed "now" far above any note age these tests use, so `now - age` never
/// underflows and recency is deterministic.
const NOW: i64 = 1_000_000_000_000;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// Base58 alphabet (Bitcoin flavor: no `0`, `O`, `I`, `l`) — every char is a
/// legal `Ss58` byte, so a single-char run of length 48 is a valid, distinct
/// identity. `Ss58::new` validates length and charset only (no checksum), so
/// this is the cheapest way to mint many distinct reinforcer authors.
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn index() -> InMemoryIndex {
    InMemoryIndex::new(Arc::new(HashEmbedder::default()))
}

/// The i-th distinct valid `Ss58` identity.
fn author_n(i: usize) -> Ss58 {
    let ch = BASE58[i % BASE58.len()] as char;
    let s: String = std::iter::repeat_n(ch, 48).collect();
    Ss58::new(s).expect("single-char base58 run of length 48 is a valid Ss58")
}

/// A set of `n` distinct reinforcer identities.
fn reinforcers(n: usize) -> BTreeSet<Ss58> {
    (0..n).map(author_n).collect()
}

/// A minimal in-scope record; callers mutate the public fields (tags, relations,
/// reinforcers) they want to exercise.
fn record(repo: RepoScope, note_type: NoteType, summary: &str, updated: i64) -> IndexRecord {
    IndexRecord {
        note_id: NoteId::new(),
        object_key: "team/repo/mem/ver_0".to_owned(),
        cid: Blake3Hash::new([0_u8; 32]),
        scope: Scope {
            team: TEAM.to_owned(),
            repo,
        },
        note_type,
        author: author_n(0),
        updated: Timestamp::new(updated),
        lamport: 0,
        key_epoch: 0,
        tags: BTreeSet::new(),
        summary: summary.to_owned(),
        relations: Vec::new(),
        reinforcers: BTreeSet::new(),
        last_reinforced: None,
        embedding: None,
    }
}

fn query(text: &str, repo: RepoScope, k: usize, now: i64) -> Query {
    Query {
        text: text.to_owned(),
        team: TEAM.to_owned(),
        repo,
        k,
        token_budget: None,
        now: Timestamp::new(now),
    }
}

/// The score the index assigns `id`, or `None` if it did not surface.
fn score_of(pointers: &[Pointer], id: NoteId) -> Option<f32> {
    pointers.iter().find(|p| p.note_id == id).map(|p| p.score)
}

fn ranked_ids(pointers: &[Pointer]) -> Vec<NoteId> {
    pointers.iter().map(|p| p.note_id).collect()
}

/// The analytic recency weight `0.5 ^ (age / half_life)`, computed in f64 from
/// the DOCUMENTED half-lives (Decision/Convention/Reference 365d, Gotcha 90d,
/// Context 7d). The test compares the index's actual decay against this, so a
/// change to the code's half-life table diverges from these constants and fails.
fn expected_weight(age_days: f64, half_life_days: f64) -> f64 {
    0.5_f64.powf(age_days / half_life_days)
}

/// The lone score a single-note index assigns for a query the note matches. With
/// exactly one candidate it is always RRF rank 0, so the RRF base (and the
/// `RANK_CONSTANT`) is identical across calls and cancels in any ratio — leaving
/// the per-type recency weight the only moving part.
fn solo_score_of(
    rec: IndexRecord,
    query_text: &str,
    now: i64,
) -> Result<f32, Box<dyn std::error::Error>> {
    let idx = index();
    let id = rec.note_id;
    idx.upsert(rec)?;
    let hits = idx.search(&query(query_text, RepoScope::Global, 10, now))?;
    score_of(&hits.pointers, id).ok_or_else(|| "note must surface".into())
}

fn solo_score(
    note_type: NoteType,
    summary: &str,
    query_text: &str,
    updated: i64,
    now: i64,
) -> Result<f32, Box<dyn std::error::Error>> {
    solo_score_of(
        record(RepoScope::Global, note_type, summary, updated),
        query_text,
        now,
    )
}

/// The per-`NoteType` recency half-lives decay by the DOCUMENTED magnitudes, not
/// merely "slower or faster". Each type is scored ALONE (RRF rank 0, so the base
/// cancels), and the ratio of two solo scores at equal age must equal the ratio
/// of the analytic decay weights. This pins the actual half-lives: Decision decays
/// slowest, Gotcha next, Context fastest.
///
/// Discriminates any change to the half-life table — including small ones an
/// order-only assertion misses (a three-note single-index ranking would let the
/// RRF rank spread from random note ids swamp a modest half-life change).
#[test]
fn recency_half_lives_decay_by_the_documented_magnitudes() -> Result<(), Box<dyn std::error::Error>>
{
    let age_days_int = 30_i64;
    let age_days = 30.0_f64;
    let updated = NOW - age_days_int * DAY_MS;

    // Same single query token so relevance is identical across the three; only
    // the note type (hence half-life) differs.
    let decision = solo_score(NoteType::Decision, "kafka decision", "kafka", updated, NOW)?;
    let gotcha = solo_score(NoteType::Gotcha, "kafka gotcha", "kafka", updated, NOW)?;
    let context = solo_score(NoteType::Context, "kafka context", "kafka", updated, NOW)?;

    // Strict ordering: slower half-life => higher retained score.
    assert!(
        decision > gotcha && gotcha > context,
        "decay order must be Decision > Gotcha > Context; got {decision}, {gotcha}, {context}"
    );

    // Magnitude: the score ratio equals the analytic decay-weight ratio, since
    // the RRF base cancels. Tolerance covers only f32 rounding.
    let dg_actual = f64::from(decision / gotcha);
    let dg_expected = expected_weight(age_days, 365.0) / expected_weight(age_days, 90.0);
    assert!(
        (dg_actual - dg_expected).abs() < 1e-3,
        "Decision/Gotcha decay ratio: expected {dg_expected:.5}, got {dg_actual:.5}"
    );

    let gc_actual = f64::from(gotcha / context);
    let gc_expected = expected_weight(age_days, 90.0) / expected_weight(age_days, 7.0);
    assert!(
        (gc_actual - gc_expected).abs() < 1e-2,
        "Gotcha/Context decay ratio: expected {gc_expected:.5}, got {gc_actual:.5}"
    );
    Ok(())
}

/// A `Supersedes` relation demotes its target by the documented hard factor
/// (0.2x), not merely "somewhere below". Measured as a RATIO: the same target
/// note's score with an incoming supersede versus alone. The superseding note is
/// crafted NOT to match the query, so it never enters the ranked output and the
/// target's own RRF rank is unchanged — isolating the demotion multiplier.
///
/// Discriminates a regression that weakens the demotion (e.g. 0.2 -> 0.9): the
/// "supersede only checks new > old" style test would still pass, this will not.
#[test]
fn supersedes_demotes_the_target_by_the_documented_factor() -> Result<(), Box<dyn std::error::Error>>
{
    let repo = RepoScope::Repo("svc".to_owned());

    // Baseline: the target alone.
    let target = record(
        repo.clone(),
        NoteType::Decision,
        "postgres pool sizing",
        NOW,
    );
    let target_id = target.note_id;
    let base_idx = index();
    base_idx.upsert(target.clone())?;
    let base = score_of(
        &base_idx
            .search(&query("postgres pool", repo.clone(), 10, NOW))?
            .pointers,
        target_id,
    )
    .expect("target surfaces alone");

    // With an incoming supersede from a note that does NOT match the query.
    let demoted_idx = index();
    let mut superseder = record(
        repo.clone(),
        NoteType::Decision,
        "unrelated marker text",
        NOW,
    );
    superseder.relations = vec![TypedLink {
        to: target_id,
        rel: LinkRel::Supersedes,
    }];
    demoted_idx.upsert(target)?;
    demoted_idx.upsert(superseder)?;
    let demoted = score_of(
        &demoted_idx
            .search(&query("postgres pool", repo, 10, NOW))?
            .pointers,
        target_id,
    )
    .expect("demoted target still surfaces (demoted, never dropped)");

    let ratio = demoted / base;
    assert!(
        (ratio - 0.2).abs() < 1e-4,
        "supersede must demote to 0.2x; got ratio {ratio}"
    );
    Ok(())
}

/// `Duplicates` shares the demotion path with `Supersedes` — same 0.2x factor —
/// so a note flagged a duplicate sinks below its canonical peer without
/// vanishing. This pins the second demoting relation, which no existing test
/// exercises in ranking.
#[test]
fn duplicates_demotes_the_target_like_supersedes() -> Result<(), Box<dyn std::error::Error>> {
    let repo = RepoScope::Repo("svc".to_owned());

    let target = record(
        repo.clone(),
        NoteType::Reference,
        "grpc retry backoff policy",
        NOW,
    );
    let target_id = target.note_id;

    let base_idx = index();
    base_idx.upsert(target.clone())?;
    let base = score_of(
        &base_idx
            .search(&query("grpc retry backoff", repo.clone(), 10, NOW))?
            .pointers,
        target_id,
    )
    .expect("target surfaces alone");

    let dup_idx = index();
    let mut duplicate = record(
        repo.clone(),
        NoteType::Reference,
        "wholly different phrasing",
        NOW,
    );
    duplicate.relations = vec![TypedLink {
        to: target_id,
        rel: LinkRel::Duplicates,
    }];
    dup_idx.upsert(target)?;
    dup_idx.upsert(duplicate)?;
    let demoted = score_of(
        &dup_idx
            .search(&query("grpc retry backoff", repo, 10, NOW))?
            .pointers,
        target_id,
    )
    .expect("duplicate target still surfaces");

    let ratio = demoted / base;
    assert!(
        (ratio - 0.2).abs() < 1e-4,
        "Duplicates must demote to 0.2x like Supersedes; got ratio {ratio}"
    );
    Ok(())
}

/// `Refines` only TAGs — it must not change the target's score. The refining
/// note is crafted not to match the query, so any score change could come only
/// from a wrongful demotion. The target must also carry the incoming relation tag
/// so a reader sees the decision trail. (`Contradicts`, the other tag-only
/// relation, has distinct MUTUAL tagging, covered in its own test below.)
#[test]
fn refines_tags_without_demoting() -> Result<(), Box<dyn std::error::Error>> {
    let repo = RepoScope::Repo("svc".to_owned());

    let target = record(
        repo.clone(),
        NoteType::Decision,
        "retention window policy",
        NOW,
    );
    let target_id = target.note_id;

    let base_idx = index();
    base_idx.upsert(target.clone())?;
    let base = score_of(
        &base_idx
            .search(&query("retention window", repo.clone(), 10, NOW))?
            .pointers,
        target_id,
    )
    .expect("target surfaces alone");

    let refine_idx = index();
    let mut refiner = record(
        repo.clone(),
        NoteType::Decision,
        "off topic phrasing here",
        NOW,
    );
    let refiner_id = refiner.note_id;
    refiner.relations = vec![TypedLink {
        to: target_id,
        rel: LinkRel::Refines,
    }];
    refine_idx.upsert(target)?;
    refine_idx.upsert(refiner)?;
    let hits = refine_idx.search(&query("retention window", repo, 10, NOW))?;
    let tagged = hits
        .pointers
        .iter()
        .find(|p| p.note_id == target_id)
        .expect("refined target still surfaces");

    assert!(
        (tagged.score - base).abs() < 1e-6,
        "Refines must not change the target score: base {base}, got {}",
        tagged.score
    );
    assert!(
        tagged
            .relations
            .iter()
            .any(|r| r.from == refiner_id && r.rel == LinkRel::Refines),
        "the target must be tagged with the incoming Refines relation"
    );
    Ok(())
}

/// A note whose SUMMARY lacks the query token but whose TAGS carry it is still
/// recallable — the lexical leg tokenizes summary AND tags. A user who tags a
/// note expects that tag to make it findable.
///
/// Discriminates a regression that drops tags from the lexical bag: the note
/// would then score zero and never surface.
#[test]
fn a_tag_only_token_makes_a_note_recallable() -> Result<(), Box<dyn std::error::Error>> {
    let idx = index();
    let mut note = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "message broker rebalance storm",
        NOW,
    );
    let id = note.note_id;
    note.tags = BTreeSet::from(["kafka".to_owned()]);
    idx.upsert(note)?;

    // "kafka" appears only in the tags, never in the summary.
    let hits = idx.search(&query("kafka", RepoScope::Global, 10, NOW))?;
    assert_eq!(
        hits.total_matched, 1,
        "the tag token must make the note match"
    );
    assert_eq!(hits.pointers.first().map(|p| p.note_id), Some(id));
    Ok(())
}

/// Reinforcement re-ranks WITHIN the relevant set: an on-topic note with no
/// endorsements outranks nothing it shouldn't, and a heavily reinforced but
/// OFF-topic note never floats into the results at all. The boost multiplies a
/// relevance score of zero by nothing — relevance is the gate, reinforcement is
/// only a tiebreaker above it.
///
/// Discriminates a regression that added reinforcement as additive mass (which
/// could surface an off-topic but popular note).
#[test]
fn reinforcement_never_floats_an_off_topic_note() -> Result<(), Box<dyn std::error::Error>> {
    let idx = index();

    let on_topic = record(
        RepoScope::Global,
        NoteType::Decision,
        "kubernetes ingress routing",
        NOW,
    );
    let on_id = on_topic.note_id;

    // Off-topic (shares no token with the query) but reinforced by 50 distinct
    // identities and freshly updated.
    let mut off_topic = record(
        RepoScope::Global,
        NoteType::Decision,
        "espresso grind size",
        NOW,
    );
    off_topic.reinforcers = reinforcers(50);

    idx.upsert(on_topic)?;
    idx.upsert(off_topic)?;

    let hits = idx.search(&query("kubernetes ingress", RepoScope::Global, 10, NOW))?;
    assert_eq!(
        hits.total_matched, 1,
        "only the on-topic note is relevant; reinforcement must not float the off-topic one"
    );
    assert_eq!(hits.pointers.first().map(|p| p.note_id), Some(on_id));
    Ok(())
}

/// More distinct reinforcers yield a higher score. Each note is scored ALONE
/// (RRF rank 0, so the base cancels), so only the reinforcement boost separates
/// them — a deterministic isolation, not a shared-index ranking whose order would
/// collapse to random `note_id` if the boost were removed.
///
/// Discriminates a regression that drops reinforcement from ranking: with the
/// boost gone, both solo scores are exactly equal and the assertion fails
/// deterministically. (The distinct-author-vs-op-count folding lives upstream in
/// convergence; the index receives a `BTreeSet` and reads its len, so that
/// distinction is not exercised here.)
#[test]
fn more_distinct_reinforcers_rank_higher() -> Result<(), Box<dyn std::error::Error>> {
    let mut few = record(
        RepoScope::Global,
        NoteType::Reference,
        "terraform state locking",
        NOW,
    );
    few.reinforcers = reinforcers(1);
    let few_score = solo_score_of(few, "terraform state", NOW)?;

    let mut many = record(
        RepoScope::Global,
        NoteType::Reference,
        "terraform state migration",
        NOW,
    );
    many.reinforcers = reinforcers(20);
    let many_score = solo_score_of(many, "terraform state", NOW)?;

    assert!(
        many_score > few_score,
        "more distinct reinforcers must yield a higher score: few {few_score}, many {many_score}"
    );
    Ok(())
}

/// A superseding note in ANOTHER scope must not demote an in-scope target: the
/// relation scan runs only over in-scope candidates, so a cross-repo superseder
/// is filtered out before demotion and its id never leaks onto the target's tags.
///
/// Discriminates a regression that builds the incoming-relation map before the
/// scope filter — which would let a note in repo B silently bury a note in repo A.
#[test]
fn a_cross_scope_superseder_does_not_demote_an_in_scope_note()
-> Result<(), Box<dyn std::error::Error>> {
    let repo_a = RepoScope::Repo("alpha".to_owned());
    let repo_b = RepoScope::Repo("beta".to_owned());

    let target = record(
        repo_a.clone(),
        NoteType::Decision,
        "feature flag rollout plan",
        NOW,
    );
    let target_id = target.note_id;

    // Baseline in repo A alone.
    let base_idx = index();
    base_idx.upsert(target.clone())?;
    let base = score_of(
        &base_idx
            .search(&query("feature flag", repo_a.clone(), 10, NOW))?
            .pointers,
        target_id,
    )
    .expect("target surfaces");

    // A superseder living in repo B, out of scope for the repo-A query.
    let cross_idx = index();
    let mut superseder = record(repo_b, NoteType::Decision, "feature flag rollout plan", NOW);
    superseder.relations = vec![TypedLink {
        to: target_id,
        rel: LinkRel::Supersedes,
    }];
    cross_idx.upsert(target)?;
    cross_idx.upsert(superseder)?;
    let hits = cross_idx.search(&query("feature flag", repo_a, 10, NOW))?;
    let tagged = hits
        .pointers
        .iter()
        .find(|p| p.note_id == target_id)
        .expect("in-scope target surfaces");

    assert!(
        (tagged.score - base).abs() < 1e-6,
        "a cross-scope superseder must not demote the in-scope note: base {base}, got {}",
        tagged.score
    );
    assert!(
        tagged.relations.is_empty(),
        "the out-of-scope superseder's id must not leak onto the target"
    );
    Ok(())
}

/// The tokenizer splits on any non-alphanumeric boundary and lowercases, so a
/// summary joined by punctuation is recallable by its sub-tokens, and matching is
/// case-insensitive. Multibyte (CJK) runs are alphanumeric, so they stay one
/// token and match exactly rather than corrupting.
#[test]
fn tokenization_handles_punctuation_case_and_multibyte() -> Result<(), Box<dyn std::error::Error>> {
    let idx = index();

    let punct = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "async_cancellation-safety in PostgreSQL",
        NOW,
    );
    let punct_id = punct.note_id;
    idx.upsert(punct)?;

    let cjk = record(RepoScope::Global, NoteType::Reference, "日本語メモ", NOW);
    let cjk_id = cjk.note_id;
    idx.upsert(cjk)?;

    // Sub-token from a punctuation/underscore-joined summary.
    let by_subtoken = idx.search(&query("cancellation", RepoScope::Global, 10, NOW))?;
    assert_eq!(
        by_subtoken.pointers.first().map(|p| p.note_id),
        Some(punct_id),
        "a punctuation-joined summary must be recallable by a sub-token"
    );

    // Case-insensitive match on a mixed-case token.
    let by_case = idx.search(&query("postgresql", RepoScope::Global, 10, NOW))?;
    assert!(
        by_case.pointers.iter().any(|p| p.note_id == punct_id),
        "matching must be case-insensitive"
    );

    // Multibyte exact match survives tokenization intact.
    let by_cjk = idx.search(&query("日本語メモ", RepoScope::Global, 10, NOW))?;
    assert_eq!(
        by_cjk.pointers.first().map(|p| p.note_id),
        Some(cjk_id),
        "a multibyte token must match exactly"
    );
    Ok(())
}

/// Recall order is deterministic: the same query returns the same pointer order
/// across calls, and two near-identical notes come out in a stable, reproducible
/// (ascending `note_id`) order. This is a determinism smoke test — it pins that
/// recall never shuffles between calls; it does not isolate the final-sort
/// `note_id` tie-break clause on its own (the `BTreeMap` iteration order and a
/// stable sort already yield ascending ids here), so it catches a shuffle or a
/// reversal, not the removal of that single comparator.
#[test]
fn recall_order_is_deterministic_and_reproducible() -> Result<(), Box<dyn std::error::Error>> {
    let idx = index();

    // Two notes identical but for identity; a stable, reproducible order is the
    // property under test.
    let a = record(
        RepoScope::Global,
        NoteType::Decision,
        "identical ranking payload",
        NOW,
    );
    let b = record(
        RepoScope::Global,
        NoteType::Decision,
        "identical ranking payload",
        NOW,
    );
    let (a_id, b_id) = (a.note_id, b.note_id);
    idx.upsert(a)?;
    idx.upsert(b)?;

    let q = query("identical ranking payload", RepoScope::Global, 10, NOW);
    let first = ranked_ids(&idx.search(&q)?.pointers);
    let second = ranked_ids(&idx.search(&q)?.pointers);

    assert_eq!(
        first, second,
        "recall order must be reproducible across calls"
    );
    let mut expected = vec![a_id, b_id];
    expected.sort();
    assert_eq!(
        first, expected,
        "equal scores must order by ascending note_id"
    );
    Ok(())
}

/// Demotion composes along a supersede CHAIN. With C supersedes B supersedes A,
/// and all three matching the query equally, only the chain head C is undemoted;
/// A and B each carry an incoming supersede, so both are demoted and rank below
/// C. This proves demotion is applied per incoming relation, not just to a single
/// pair.
///
/// Discriminates a regression that demotes only the direct target of the newest
/// op, leaving the middle of a chain wrongly undemoted.
#[test]
fn demotion_composes_along_a_supersede_chain() -> Result<(), Box<dyn std::error::Error>> {
    let idx = index();
    let repo = RepoScope::Repo("svc".to_owned());

    let a = record(
        repo.clone(),
        NoteType::Decision,
        "rollout payload note",
        NOW,
    );
    let b = record(
        repo.clone(),
        NoteType::Decision,
        "rollout payload note",
        NOW,
    );
    let c = record(
        repo.clone(),
        NoteType::Decision,
        "rollout payload note",
        NOW,
    );
    let (a_id, b_id, c_id) = (a.note_id, b.note_id, c.note_id);

    // C supersedes B, B supersedes A.
    let mut b = b;
    b.relations = vec![TypedLink {
        to: a_id,
        rel: LinkRel::Supersedes,
    }];
    let mut c = c;
    c.relations = vec![TypedLink {
        to: b_id,
        rel: LinkRel::Supersedes,
    }];

    idx.upsert(a)?;
    idx.upsert(b)?;
    idx.upsert(c)?;

    let hits = idx.search(&query("rollout payload", repo, 10, NOW))?;
    assert_eq!(
        hits.pointers.first().map(|p| p.note_id),
        Some(c_id),
        "the undemoted chain head must rank first"
    );

    let demoted: BTreeSet<NoteId> = hits
        .pointers
        .iter()
        .filter(|p| p.relations.iter().any(|r| r.rel.demotes_target()))
        .map(|p| p.note_id)
        .collect();
    assert_eq!(
        demoted,
        BTreeSet::from([a_id, b_id]),
        "both the tail and the middle of the chain must be demoted"
    );
    Ok(())
}

/// `Contradicts` is MUTUAL: it tags BOTH notes (the tension runs both ways) and
/// demotes neither. The target's score is unchanged from a no-relation baseline,
/// and each note carries an incoming `Contradicts` from the other.
///
/// Discriminates a regression that made Contradicts demote (it would drop the
/// score below baseline) or that tagged only one side (the mutual tag is the
/// distinct part of this relation's logic).
#[test]
fn contradicts_tags_both_notes_without_demoting() -> Result<(), Box<dyn std::error::Error>> {
    let repo = RepoScope::Repo("svc".to_owned());

    // Baseline: two equally-relevant notes, no relation between them.
    let a = record(
        repo.clone(),
        NoteType::Decision,
        "cache invalidation strategy",
        NOW,
    );
    let b = record(
        repo.clone(),
        NoteType::Decision,
        "cache invalidation strategy",
        NOW,
    );
    let (a_id, b_id) = (a.note_id, b.note_id);

    let base_idx = index();
    base_idx.upsert(a.clone())?;
    base_idx.upsert(b.clone())?;
    let base_a = score_of(
        &base_idx
            .search(&query("cache invalidation", repo.clone(), 10, NOW))?
            .pointers,
        a_id,
    )
    .ok_or("a surfaces at baseline")?;

    // Now A contradicts B. A and B share the same tokens and ids, so A's RRF rank
    // is unchanged from the baseline — only the mutual tag/demotion is under test.
    let mut a = a;
    a.relations = vec![TypedLink {
        to: b_id,
        rel: LinkRel::Contradicts,
    }];
    let con_idx = index();
    con_idx.upsert(a)?;
    con_idx.upsert(b)?;
    let hits = con_idx.search(&query("cache invalidation", repo, 10, NOW))?;

    let pa = hits
        .pointers
        .iter()
        .find(|p| p.note_id == a_id)
        .ok_or("a surfaces")?;
    let pb = hits
        .pointers
        .iter()
        .find(|p| p.note_id == b_id)
        .ok_or("b surfaces")?;

    assert!(
        (pa.score - base_a).abs() < 1e-6,
        "Contradicts must not demote: baseline {base_a}, got {}",
        pa.score
    );
    assert!(
        pa.relations
            .iter()
            .any(|r| r.from == b_id && r.rel == LinkRel::Contradicts),
        "A must be tagged with the contradiction from B"
    );
    assert!(
        pb.relations
            .iter()
            .any(|r| r.from == a_id && r.rel == LinkRel::Contradicts),
        "B must be tagged with the contradiction from A (the tag is mutual)"
    );
    Ok(())
}

/// Recency ages on `max(updated, last_reinforced)`, so a note written long ago
/// but reinforced recently decays as if fresh — use, not just authorship, keeps a
/// note current. Scored alone (base cancels) against the same old note with no
/// reinforcement time; the ratio is the analytic decay the stale note suffers.
///
/// Discriminates a regression that ages on `updated` alone, ignoring use.
#[test]
fn a_recent_reinforcement_time_keeps_an_old_note_fresh() -> Result<(), Box<dyn std::error::Error>> {
    // 180 days = two Gotcha half-lives (90d): aged on `updated` alone the weight
    // is 0.5^2 = 0.25; freshened to `now` it is 1.0.
    let old = NOW - 180 * DAY_MS;

    let mut fresh_use = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "kafka rebalance fix",
        old,
    );
    fresh_use.last_reinforced = Some(Timestamp::new(NOW));
    let fresh_score = solo_score_of(fresh_use, "kafka rebalance", NOW)?;

    let stale = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "kafka rebalance fix",
        old,
    );
    let stale_score = solo_score_of(stale, "kafka rebalance", NOW)?;

    let ratio = fresh_score / stale_score;
    assert!(
        (ratio - 4.0).abs() < 0.05,
        "a recently-reinforced old note must decay like fresh (ratio ~4), got {ratio}"
    );
    Ok(())
}

/// A `last_reinforced` in the FUTURE of `now` is IGNORED for recency, not clamped:
/// a forged far-future reinforcement must not pin a note's age at zero forever, so
/// the forged note decays on its real (old) `updated`, exactly like a note with no
/// reinforcement time.
///
/// Discriminates a regression that trusts or clamps a future reinforcement time
/// (which would let a forgery keep a stale note permanently fresh).
#[test]
fn a_future_reinforcement_time_is_ignored_for_recency() -> Result<(), Box<dyn std::error::Error>> {
    let old = NOW - 180 * DAY_MS;

    let mut forged = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "audit anchor cadence",
        old,
    );
    forged.last_reinforced = Some(Timestamp::new(NOW + 3650 * DAY_MS));
    let forged_score = solo_score_of(forged, "audit anchor", NOW)?;

    let honest = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "audit anchor cadence",
        old,
    );
    let honest_score = solo_score_of(honest, "audit anchor", NOW)?;

    assert!(
        (forged_score - honest_score).abs() < 1e-6,
        "a future reinforcement time must be inert: forged {forged_score}, honest {honest_score}"
    );
    Ok(())
}

/// Relevance ordering with genuinely competing notes: several differently-worded
/// notes that all match the query, ranked in ONE index. A note matching more of
/// the query's terms must outrank one matching fewer.
///
/// This is the property nothing else in the suite covers. Every other ordering
/// assertion here is either over a result set of size one — where "ranks first"
/// is vacuous — or over notes with IDENTICAL summaries, where lexical relevance
/// is held constant on purpose so a recency or demotion multiplier is the only
/// moving part. Both shapes stay green if the relevance signal itself regresses.
///
/// Type and `updated` are identical across the three notes, so the per-type
/// recency weight is a common factor and relevance is the only thing that can
/// order them.
#[test]
fn a_note_matching_more_query_terms_outranks_one_matching_fewer()
-> Result<(), Box<dyn std::error::Error>> {
    let idx = index();

    let all_terms = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "cache invalidation redis timeout",
        NOW,
    );
    let two_terms = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "cache invalidation policy",
        NOW,
    );
    let one_term = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "redis deployment guide",
        NOW,
    );
    let no_terms = record(
        RepoScope::Global,
        NoteType::Gotcha,
        "gardening notes for spring",
        NOW,
    );

    let (all_id, two_id, one_id, none_id) = (
        all_terms.note_id,
        two_terms.note_id,
        one_term.note_id,
        no_terms.note_id,
    );

    idx.upsert(all_terms)?;
    idx.upsert(two_terms)?;
    idx.upsert(one_term)?;
    idx.upsert(no_terms)?;

    let hits = idx.search(&query(
        "cache invalidation redis timeout",
        RepoScope::Global,
        10,
        NOW,
    ))?;

    assert_eq!(
        ranked_ids(&hits.pointers),
        vec![all_id, two_id, one_id],
        "notes must rank by how much of the query they match, best first",
    );
    assert!(
        score_of(&hits.pointers, none_id).is_none(),
        "a note sharing no term with the query must not surface at all",
    );

    Ok(())
}

/// The RRF rank constant is pinned to its documented value by ABSOLUTE
/// magnitude, not by a ratio.
///
/// Every other magnitude test in this file divides two solo scores, which
/// cancels the RRF base out by construction — so `RANK_CONSTANT` could move by
/// an order of magnitude with the whole suite green. Verified by mutation:
/// changing it from `60.0` to `5.0` left all 480 core tests passing.
///
/// A single candidate is RRF rank 0 in the only leg a lexical build has, and at
/// age zero the recency weight is exactly 1, so its score is `1 / RANK_CONSTANT`
/// with no other factor in play.
#[test]
fn the_rrf_rank_constant_is_pinned_to_its_documented_value()
-> Result<(), Box<dyn std::error::Error>> {
    let score = solo_score(
        NoteType::Decision,
        "cache invalidation",
        "cache invalidation",
        NOW,
        NOW,
    )?;

    let expected = 1.0_f32 / 60.0;
    assert!(
        (score - expected).abs() < 1e-6,
        "a lone age-zero candidate must score 1/RANK_CONSTANT = {expected}, got {score}",
    );

    Ok(())
}
