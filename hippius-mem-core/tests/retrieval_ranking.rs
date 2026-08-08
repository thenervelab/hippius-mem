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
fn solo_score(
    note_type: NoteType,
    summary: &str,
    query_text: &str,
    updated: i64,
    now: i64,
) -> Result<f32, Box<dyn std::error::Error>> {
    let idx = index();
    let rec = record(RepoScope::Global, note_type, summary, updated);
    let id = rec.note_id;
    idx.upsert(rec)?;
    let hits = idx.search(&query(query_text, RepoScope::Global, 10, now))?;
    score_of(&hits.pointers, id).ok_or_else(|| "note must surface".into())
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

/// `Refines` and `Contradicts` only TAG — they must not change the target's
/// score. The refining note is crafted not to match the query, so any score
/// change could come only from a wrongful demotion. The target must also carry
/// the incoming relation tag so a reader sees the decision trail.
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

/// Among EQUALLY relevant, equally recent notes, more distinct reinforcers ranks
/// higher — the boost is driven by the distinct-author count. Twenty endorsers
/// beat one.
///
/// Discriminates a regression that ignores reinforcement in ranking, or that
/// counts ops instead of distinct authors.
#[test]
fn more_distinct_reinforcers_rank_higher() -> Result<(), Box<dyn std::error::Error>> {
    let idx = index();

    let mut few = record(
        RepoScope::Global,
        NoteType::Reference,
        "terraform state locking",
        NOW,
    );
    few.reinforcers = reinforcers(1);
    let few_id = few.note_id;

    let mut many = record(
        RepoScope::Global,
        NoteType::Reference,
        "terraform state migration",
        NOW,
    );
    many.reinforcers = reinforcers(20);
    let many_id = many.note_id;

    idx.upsert(few)?;
    idx.upsert(many)?;

    let hits = idx.search(&query("terraform state", RepoScope::Global, 10, NOW))?;
    let ranked = ranked_ids(&hits.pointers);
    assert_eq!(
        ranked,
        vec![many_id, few_id],
        "the note with more distinct reinforcers must rank first"
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

/// Recall is deterministic: equally-scored notes come back in a stable,
/// reproducible order (ascending `note_id`), so the same query never shuffles
/// results between calls. Two identical notes (same summary, type, and
/// timestamp) score exactly equal, and the tie-break orders them by id.
#[test]
fn equal_scores_break_ties_deterministically_by_note_id() -> Result<(), Box<dyn std::error::Error>>
{
    let idx = index();

    // Same everything except identity -> exactly equal final score.
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
