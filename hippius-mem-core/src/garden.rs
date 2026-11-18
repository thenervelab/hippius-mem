//! What in a vault needs a person's attention: a read-only pass over the
//! converged index.
//!
//! A vault only grows. Nothing in recall or the brief tells a team that half
//! its notes sit in the team-wide pool, that a note has been replaced and
//! never forgotten, or that two notes say the same thing. [`garden`] lists
//! those, so someone can forget, link or move them. It changes nothing.
//!
//! It reads summaries and tags only, as recall does, so it never needs a body
//! or a key beyond what the index already holds.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::domain::{NoteId, RepoScope, Timestamp};
use crate::index::{IndexRecord, half_life_millis, tokenize};

/// Token-set Jaccard at or above which two summaries are listed as a likely
/// duplicate pair. Stricter than nothing, looser than the write-time gate's
/// `0.9`: the gate must not refuse a legitimate new note, while this list is
/// read by a person who decides. Arbitrary within that.
const DUPLICATE_JACCARD: f32 = 0.8;

/// Most entries each list holds. The counts beside them are never capped.
pub const MAX_GARDEN_ENTRIES: usize = 20;

/// One note in a [`GardenReport`] list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GardenNote {
    /// The note's id.
    pub id: String,
    /// `global`, or the repository name.
    pub repo: String,
    /// The note's summary.
    pub summary: String,
}

/// A note that another live note supersedes or duplicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Replaced {
    /// The note that was replaced and is still live.
    pub note: GardenNote,
    /// The id of the note that replaces it.
    pub by: String,
}

/// Two notes in one scope whose summaries share most of their words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LikelyDuplicate {
    /// The older note.
    pub older: GardenNote,
    /// The newer note.
    pub newer: GardenNote,
}

/// What [`garden`] found. Each list holds at most [`MAX_GARDEN_ENTRIES`]; the
/// `*_total` beside it is the full count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GardenReport {
    /// Live notes in the index.
    pub notes: usize,
    /// Live notes per scope, largest first (`global` is the team-wide pool,
    /// which every repository's recall and brief read).
    pub scopes: Vec<(String, usize)>,
    /// Notes another live note supersedes or duplicates: candidates to forget.
    pub replaced: Vec<Replaced>,
    /// How many such notes there are.
    pub replaced_total: usize,
    /// Pairs that probably say the same thing: candidates to link or merge.
    pub likely_duplicates: Vec<LikelyDuplicate>,
    /// How many such pairs were found. A lower bound: a pair whose summaries
    /// differ and share only words common in their scope is not compared, and
    /// notes with identical summaries count as a chain (n - 1 pairs), not as
    /// every pair.
    pub likely_duplicates_total: usize,
    /// Notes older than two recency half-lives of their type that nobody has
    /// reused and no note has replaced, oldest first: candidates to check or
    /// forget.
    pub stale: Vec<GardenNote>,
    /// How many such notes there are.
    pub stale_total: usize,
}

fn repo_label(repo: &RepoScope) -> String {
    match repo {
        RepoScope::Global => "global".to_owned(),
        RepoScope::Repo(name) => name.clone(),
    }
}

fn garden_note(record: &IndexRecord) -> GardenNote {
    GardenNote {
        id: record.note_id.to_string(),
        repo: repo_label(&record.scope.repo),
        summary: record.summary.clone(),
    }
}

/// Survey `records` (a team's converged index) as of `now`.
#[must_use]
pub fn garden(records: &[IndexRecord], now: Timestamp) -> GardenReport {
    let by_id: BTreeMap<NoteId, &IndexRecord> = records
        .iter()
        .map(|record| (record.note_id, record))
        .collect();

    let mut scope_counts: BTreeMap<String, usize> = BTreeMap::new();
    for record in records {
        *scope_counts
            .entry(repo_label(&record.scope.repo))
            .or_default() += 1;
    }
    let mut scopes: Vec<(String, usize)> = scope_counts.into_iter().collect();
    scopes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    // A relation names its target by id; only a target still in the index is
    // live and so still worth forgetting.
    let mut replaced: Vec<Replaced> = records
        .iter()
        .flat_map(|record| {
            record
                .relations
                .iter()
                .filter(|link| link.rel.demotes_target())
                .filter_map(|link| by_id.get(&link.to))
                .map(|target| Replaced {
                    note: garden_note(target),
                    by: record.note_id.to_string(),
                })
        })
        .collect();
    // Several notes can replace one; the newest replacement is the one to
    // read, and note ids sort by creation time.
    replaced.sort_by(|a, b| a.note.id.cmp(&b.note.id).then(b.by.cmp(&a.by)));
    replaced.dedup_by(|a, b| a.note.id == b.note.id);
    let replaced_ids: BTreeSet<NoteId> = records
        .iter()
        .flat_map(|record| &record.relations)
        .filter(|link| link.rel.demotes_target())
        .map(|link| link.to)
        .collect();

    let mut likely_duplicates = likely_duplicates(records, &replaced_ids);
    let likely_duplicates_total = likely_duplicates.len();
    likely_duplicates.truncate(MAX_GARDEN_ENTRIES);

    let mut stale: Vec<&IndexRecord> = records
        .iter()
        .filter(|record| record.reinforcers.is_empty())
        // A replaced note is already listed above with what to do about it.
        .filter(|record| !replaced_ids.contains(&record.note_id))
        .filter(|record| {
            let age = now.as_millis().saturating_sub(record.updated.as_millis());
            age > half_life_millis(record.note_type).saturating_mul(2)
        })
        .collect();
    stale.sort_by(|a, b| {
        a.updated
            .as_millis()
            .cmp(&b.updated.as_millis())
            .then(a.note_id.cmp(&b.note_id))
    });
    let stale_total = stale.len();

    let replaced_total = replaced.len();
    replaced.truncate(MAX_GARDEN_ENTRIES);
    GardenReport {
        notes: records.len(),
        scopes,
        replaced,
        replaced_total,
        likely_duplicates,
        likely_duplicates_total,
        stale: stale
            .into_iter()
            .take(MAX_GARDEN_ENTRIES)
            .map(garden_note)
            .collect(),
        stale_total,
    }
}

/// Pairs of notes in the same scope whose summaries' word sets overlap by at
/// least [`DUPLICATE_JACCARD`], newest pair first. A note already listed as
/// replaced is skipped: its relation says the team has dealt with it.
///
/// Only the summary's words count, not the tags: two notes with one summary
/// are duplicates whatever each is tagged, and two different notes that share
/// a long `path:` tag are not.
///
/// Comparing every pair in a scope is quadratic, so candidates are found two
/// ways and only those are scored:
///
/// - notes whose word sets are identical, however common the words;
/// - notes that share a word found in at most `COMMON_TOKEN_BUCKET` notes of
///   the scope.
///
/// A pair with different summaries whose shared words are all more common
/// than that is not compared, so the list can miss it. Notes with identical
/// summaries are listed as a chain (n - 1 pairs), not as every pair.
fn likely_duplicates(
    records: &[IndexRecord],
    replaced_ids: &BTreeSet<NoteId>,
) -> Vec<LikelyDuplicate> {
    /// A word in more notes of one scope than this is too common to pair
    /// notes by. Arbitrary: it bounds the pairs one word can produce (1,225).
    const COMMON_TOKEN_BUCKET: usize = 50;

    let candidates: Vec<(&IndexRecord, BTreeSet<String>)> = records
        .iter()
        .filter(|record| !replaced_ids.contains(&record.note_id))
        .map(|record| (record, tokenize(&record.summary).into_iter().collect()))
        .collect();

    let mut by_word: BTreeMap<(String, &str), Vec<usize>> = BTreeMap::new();
    let mut by_word_set: BTreeMap<(String, &BTreeSet<String>), Vec<usize>> = BTreeMap::new();
    for (index, (record, words)) in candidates.iter().enumerate() {
        let scope = repo_label(&record.scope.repo);
        for word in words {
            by_word
                .entry((scope.clone(), word.as_str()))
                .or_default()
                .push(index);
        }
        if !words.is_empty() {
            by_word_set.entry((scope, words)).or_default().push(index);
        }
    }

    let mut pairs: BTreeSet<(usize, usize)> = BTreeSet::new();
    for members in by_word.values().filter(|m| m.len() <= COMMON_TOKEN_BUCKET) {
        for (position, &left) in members.iter().enumerate() {
            for &right in &members[position + 1..] {
                // Identical word sets are left to the chain below, or a
                // group of them would be paired all against all here.
                let same = candidates.get(left).map(|(_, words)| words)
                    == candidates.get(right).map(|(_, words)| words);
                if !same {
                    pairs.insert((left, right));
                }
            }
        }
    }
    // Identical word sets are paired in a chain (first with second, second
    // with third), not all against all: a scope of templated summaries would
    // otherwise produce a quadratic list that says one thing.
    for members in by_word_set.values() {
        for pair in members.windows(2) {
            if let [left, right] = *pair {
                pairs.insert((left, right));
            }
        }
    }

    let mut found: Vec<(&IndexRecord, &IndexRecord)> = pairs
        .into_iter()
        .filter_map(|(left, right)| {
            let (a, a_words) = candidates.get(left)?;
            let (b, b_words) = candidates.get(right)?;
            let shared = a_words.intersection(b_words).count();
            // Both sets hold the shared word that made this a candidate, so
            // the union is never empty.
            let union = a_words.len() + b_words.len() - shared;
            #[expect(
                clippy::cast_precision_loss,
                reason = "word-set cardinalities are small counts; f32 represents them exactly"
            )]
            let overlap = shared as f32 / union as f32;
            (overlap >= DUPLICATE_JACCARD).then(|| {
                if (a.updated.as_millis(), a.note_id) <= (b.updated.as_millis(), b.note_id) {
                    (*a, *b)
                } else {
                    (*b, *a)
                }
            })
        })
        .collect();
    found.sort_by(|a, b| {
        (b.1.updated.as_millis(), b.1.note_id, b.0.note_id).cmp(&(
            a.1.updated.as_millis(),
            a.1.note_id,
            a.0.note_id,
        ))
    });
    found
        .into_iter()
        .map(|(older, newer)| LikelyDuplicate {
            older: garden_note(older),
            newer: garden_note(newer),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use super::*;
    use crate::domain::{Blake3Hash, NoteType, Scope, Ss58};
    use crate::oplog::{LinkRel, TypedLink};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const DAY_MS: i64 = 24 * 60 * 60 * 1000;

    fn note(
        repo: RepoScope,
        note_type: NoteType,
        summary: &str,
        updated: i64,
    ) -> Result<IndexRecord, Box<dyn std::error::Error>> {
        Ok(IndexRecord {
            note_id: NoteId::new(),
            object_key: "team/repo/mem/ver_0".to_owned(),
            cid: Blake3Hash::new([0_u8; 32]),
            scope: Scope {
                team: "team".to_owned(),
                repo,
            },
            note_type,
            author: Ss58::new("5".repeat(48))?,
            updated: Timestamp::new(updated),
            lamport: 0,
            key_epoch: 0,
            tags: BTreeSet::new(),
            summary: summary.to_owned(),
            relations: Vec::new(),
            reinforcers: BTreeSet::new(),
            last_reinforced: None,
            embedding: None,
        })
    }

    fn widget() -> RepoScope {
        RepoScope::Repo("widget".to_owned())
    }

    /// The scope table is what shows a team its team-wide pool, so the counts
    /// must be per scope and the largest first.
    #[test]
    fn scopes_are_counted_largest_first() -> TestResult {
        let records = vec![
            note(RepoScope::Global, NoteType::Gotcha, "alpha one", 1)?,
            note(RepoScope::Global, NoteType::Gotcha, "beta two", 1)?,
            note(widget(), NoteType::Gotcha, "gamma three", 1)?,
        ];
        let report = garden(&records, Timestamp::new(2));
        assert_eq!(report.notes, 3);
        assert_eq!(
            report.scopes,
            [("global".to_owned(), 2), ("widget".to_owned(), 1)]
        );
        Ok(())
    }

    /// A superseded note that is still live is listed with its replacement,
    /// and is not also offered as that replacement's duplicate. A relation
    /// whose target is gone lists nothing.
    #[test]
    fn a_superseded_live_note_is_listed_once() -> TestResult {
        let old = note(
            widget(),
            NoteType::Gotcha,
            "cache warming needs the lock",
            1,
        )?;
        let mut new = note(
            widget(),
            NoteType::Gotcha,
            "cache warming needs the lock",
            2,
        )?;
        new.relations.push(TypedLink {
            to: old.note_id,
            rel: LinkRel::Supersedes,
        });
        new.relations.push(TypedLink {
            to: NoteId::new(),
            rel: LinkRel::Supersedes,
        });
        let (old_id, new_id) = (old.note_id.to_string(), new.note_id.to_string());
        let (older_copy, newer_copy) = (old.clone(), new.clone());
        let report = garden(&[old, new], Timestamp::new(3));

        assert_eq!(report.replaced_total, 1);
        assert_eq!(report.replaced[0].note.id, old_id);
        assert_eq!(report.replaced[0].by, new_id);
        assert_eq!(report.likely_duplicates_total, 0);
        assert_eq!(
            garden(&[older_copy, newer_copy], Timestamp::new(900 * DAY_MS)).stale_total,
            1,
            "a replaced note is listed as replaced, not also as stale"
        );
        Ok(())
    }

    /// When two notes replace one, the newer replacement is the one named:
    /// it is the one to read.
    #[test]
    fn the_newest_of_several_replacements_is_named() -> TestResult {
        let old = note(
            widget(),
            NoteType::Gotcha,
            "cache warming needs the lock",
            1,
        )?;
        let mut replacers = Vec::new();
        for i in 0..2 {
            let mut replacer = note(widget(), NoteType::Gotcha, &format!("replacement{i}"), 2)?;
            replacer.relations.push(TypedLink {
                to: old.note_id,
                rel: LinkRel::Supersedes,
            });
            replacers.push(replacer);
        }
        let newest = replacers
            .iter()
            .map(|record| record.note_id)
            .max()
            .ok_or("two replacers")?
            .to_string();
        replacers.push(old);

        let report = garden(&replacers, Timestamp::new(3));
        assert_eq!(report.replaced_total, 1);
        assert_eq!(report.replaced[0].by, newest);
        Ok(())
    }

    /// Two notes of one scope with nearly the same words are a pair, older
    /// first; the same words in another scope are not, and neither are two
    /// notes that share only a few words.
    #[test]
    fn near_identical_summaries_in_one_scope_are_a_pair() -> TestResult {
        let older = note(
            widget(),
            NoteType::Gotcha,
            "uploader retry budget capped at three attempts",
            1,
        )?;
        let newer = note(
            widget(),
            NoteType::Gotcha,
            "uploader retry budget capped at three attempts now",
            2,
        )?;
        let elsewhere = note(
            RepoScope::Repo("gadget".to_owned()),
            NoteType::Gotcha,
            "uploader retry budget capped at three attempts",
            3,
        )?;
        let related = note(
            widget(),
            NoteType::Gotcha,
            "uploader retry jitter is disabled",
            4,
        )?;
        let (older_id, newer_id) = (older.note_id.to_string(), newer.note_id.to_string());

        let report = garden(&[newer, related, elsewhere, older], Timestamp::new(5));
        assert_eq!(report.likely_duplicates_total, 1);
        assert_eq!(report.likely_duplicates[0].older.id, older_id);
        assert_eq!(report.likely_duplicates[0].newer.id, newer_id);
        Ok(())
    }

    /// Two notes with the same summary are a pair even when every word in it
    /// is common in the scope and one of them carries tags. The bugs this
    /// catches: pairing only through rare words, which drops exactly the
    /// short generic summaries a large team-wide pool is full of, and counting
    /// tag words, which halves the overlap of two identical summaries.
    #[test]
    fn identical_summaries_of_common_words_are_a_pair_whatever_their_tags() -> TestResult {
        let mut records = Vec::new();
        for i in 0..60 {
            records.push(note(
                widget(),
                NoteType::Gotcha,
                &format!("gateway token rule{i}"),
                1,
            )?);
        }
        let first = note(widget(), NoteType::Gotcha, "gateway token", 2)?;
        let mut second = note(widget(), NoteType::Gotcha, "gateway token", 3)?;
        second.tags = BTreeSet::from(["path:src/store/mod.rs".to_owned()]);
        let (first_id, second_id) = (first.note_id.to_string(), second.note_id.to_string());
        records.push(first);
        records.push(second);

        let report = garden(&records, Timestamp::new(4));
        assert_eq!(report.likely_duplicates_total, 1);
        assert_eq!(report.likely_duplicates[0].older.id, first_id);
        assert_eq!(report.likely_duplicates[0].newer.id, second_id);
        Ok(())
    }

    /// Three copies of one summary are two pairs, a chain, and not three:
    /// a scope of templated summaries must not produce a quadratic list.
    #[test]
    fn identical_summaries_are_chained_not_paired_all_against_all() -> TestResult {
        let records = (0..3)
            .map(|i| note(widget(), NoteType::Gotcha, "quokka ledger rebuild", i))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            garden(&records, Timestamp::new(9)).likely_duplicates_total,
            2
        );
        Ok(())
    }

    /// Stale means older than two half-lives of the note's own type and never
    /// reused. A context note (7-day half-life) goes stale long before a
    /// decision (365 days), and a reused note is never stale.
    #[test]
    fn stale_is_measured_against_the_notes_own_half_life() -> TestResult {
        let now = 400 * DAY_MS;
        let old_context = note(
            widget(),
            NoteType::Context,
            "sprint plan alpha",
            now - 15 * DAY_MS,
        )?;
        let fresh_context = note(
            widget(),
            NoteType::Context,
            "sprint plan beta",
            now - 13 * DAY_MS,
        )?;
        let old_decision = note(
            widget(),
            NoteType::Decision,
            "use postgres gamma",
            now - 300 * DAY_MS,
        )?;
        let mut reused = note(
            widget(),
            NoteType::Context,
            "sprint plan delta",
            now - 30 * DAY_MS,
        )?;
        reused.reinforcers.insert(Ss58::new("5".repeat(48))?);
        let stale_id = old_context.note_id.to_string();

        let report = garden(
            &[old_context, fresh_context, old_decision, reused],
            Timestamp::new(now),
        );
        assert_eq!(report.stale_total, 1);
        assert_eq!(report.stale[0].id, stale_id);
        Ok(())
    }

    /// The lists are capped and the totals are not.
    #[test]
    fn lists_are_capped_and_totals_are_not() -> TestResult {
        let now = 100 * DAY_MS;
        let records = (0..MAX_GARDEN_ENTRIES + 5)
            .map(|i| {
                note(
                    widget(),
                    NoteType::Context,
                    &format!("unique{i} topic{i}"),
                    0,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let report = garden(&records, Timestamp::new(now));
        assert_eq!(report.stale.len(), MAX_GARDEN_ENTRIES);
        assert_eq!(report.stale_total, MAX_GARDEN_ENTRIES + 5);
        Ok(())
    }
}
