//! Notes tied to a place in a repository's tree.
//!
//! A note carries a tag `path:<prefix>` to say "read this before changing code
//! under `<prefix>`", where the prefix is a file or a directory relative to
//! the repository root. [`notes_for_path`] answers which notes are tied to one
//! file, so an edit hook can hand them to an agent that never thought to
//! search for them.
//!
//! The tie is a tag, not a field of the note: tags are already signed, synced
//! and indexed, so this adds nothing to the persisted format, and a teammate
//! on an older build still sees the tag as plain text.
//!
//! A prefix matches whole path segments only: `path:src/index` covers
//! `src/index/mod.rs` and `src/index`, and does not cover `src/index_old.rs`.
//! Globs are deliberately absent. A prefix says "this file" or "this
//! directory", which is what the notes written so far would need, and a glob
//! dialect is a parser to specify and keep compatible.

use crate::domain::RepoScope;
use crate::index::IndexRecord;

/// The tag prefix that ties a note to a path.
pub const PATH_TAG_PREFIX: &str = "path:";

/// Most notes [`notes_for_path`] returns. Arbitrary: an edit hook injects them
/// into an agent's context on every first edit of a file, so the list has to
/// stay short enough to be read.
pub const MAX_PATH_NOTES: usize = 5;

/// A path as the tags spell it: no leading `./`, no leading or trailing `/`.
fn normalized(path: &str) -> &str {
    let path = path.trim();
    path.strip_prefix("./").unwrap_or(path).trim_matches('/')
}

/// The length of the longest `path:` tag of `record` that covers `file`, or
/// `None` when no tag does. `file` is already [`normalized`].
fn covering_prefix_len(record: &IndexRecord, file: &str) -> Option<usize> {
    record
        .tags
        .iter()
        .filter_map(|tag| tag.strip_prefix(PATH_TAG_PREFIX))
        .map(normalized)
        .filter(|prefix| !prefix.is_empty())
        .filter(|prefix| {
            file.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .map(str::len)
        .max()
}

/// The notes of repository `repo` tied to `file` (a path relative to the
/// repository root), at most [`MAX_PATH_NOTES`]: the most specific tie first,
/// then the newest, then by note id.
///
/// Team-wide notes are never returned. A path means something inside one
/// repository only, so a `path:src` tag on a team-wide note would match every
/// repository's `src`.
#[must_use]
pub fn notes_for_path<'a>(
    records: &'a [IndexRecord],
    repo: &str,
    file: &str,
) -> Vec<&'a IndexRecord> {
    let file = normalized(file);
    let mut matches: Vec<(usize, &IndexRecord)> = records
        .iter()
        .filter(|record| matches!(&record.scope.repo, RepoScope::Repo(name) if name == repo))
        .filter_map(|record| Some((covering_prefix_len(record, file)?, record)))
        .collect();
    matches.sort_by(|(a_len, a), (b_len, b)| {
        b_len
            .cmp(a_len)
            .then(b.updated.as_millis().cmp(&a.updated.as_millis()))
            .then(a.note_id.cmp(&b.note_id))
    });
    matches
        .into_iter()
        .take(MAX_PATH_NOTES)
        .map(|(_, record)| record)
        .collect()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use super::*;
    use crate::domain::{Blake3Hash, NoteId, NoteType, Scope, Ss58, Timestamp};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn note(
        repo: RepoScope,
        tags: &[&str],
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
            note_type: NoteType::Gotcha,
            author: Ss58::new("5".repeat(48))?,
            updated: Timestamp::new(updated),
            lamport: 0,
            key_epoch: 0,
            tags: tags
                .iter()
                .map(|&tag| tag.to_owned())
                .collect::<BTreeSet<_>>(),
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

    fn summaries(found: &[&IndexRecord]) -> Vec<String> {
        found.iter().map(|record| record.summary.clone()).collect()
    }

    /// Catches a prefix compared as a string, which ties `src/index` to
    /// `src/index_old.rs`.
    #[test]
    fn a_prefix_covers_whole_path_segments_only() -> TestResult {
        let records = vec![note(widget(), &["path:src/index"], "index note", 1)?];
        for (file, covered) in [
            ("src/index/mod.rs", true),
            ("src/index", true),
            ("./src/index/mod.rs", true),
            ("src/index_old.rs", false),
            ("src", false),
            ("other/src/index/mod.rs", false),
        ] {
            assert_eq!(
                notes_for_path(&records, "widget", file).len(),
                usize::from(covered),
                "{file}"
            );
        }
        Ok(())
    }

    /// Catches a lookup that ignores scope: another repository's note, or a
    /// team-wide one, would be injected into an unrelated repository's edits.
    #[test]
    fn only_the_repositorys_own_notes_are_tied() -> TestResult {
        let records = vec![
            note(widget(), &["path:src"], "ours", 1)?,
            note(
                RepoScope::Repo("gadget".to_owned()),
                &["path:src"],
                "theirs",
                2,
            )?,
            note(RepoScope::Global, &["path:src"], "team-wide", 3)?,
            note(widget(), &["db", "src"], "untagged", 4)?,
        ];
        assert_eq!(
            summaries(&notes_for_path(&records, "widget", "src/lib.rs")),
            ["ours"]
        );
        Ok(())
    }

    /// Catches the cap cutting the wrong notes: the file's own note must
    /// survive a directory with many newer notes.
    #[test]
    fn the_most_specific_tie_comes_first_then_the_newest() -> TestResult {
        let mut records = vec![note(
            widget(),
            &["path:src/index/mod.rs"],
            "the file itself",
            1,
        )?];
        for i in 0..MAX_PATH_NOTES {
            let updated = 10 + i64::try_from(i)?;
            records.push(note(
                widget(),
                &["path:src/"],
                &format!("dir {i}"),
                updated,
            )?);
        }

        let found = summaries(&notes_for_path(&records, "widget", "src/index/mod.rs"));
        assert_eq!(found.len(), MAX_PATH_NOTES);
        assert_eq!(found[0], "the file itself");
        assert_eq!(found[1], format!("dir {}", MAX_PATH_NOTES - 1));
        Ok(())
    }

    /// An empty prefix (`path:` or `path:/`) would otherwise cover every file.
    #[test]
    fn an_empty_prefix_ties_nothing() -> TestResult {
        let records = vec![note(widget(), &["path:", "path:/", "path:./"], "all", 1)?];
        assert!(notes_for_path(&records, "widget", "src/lib.rs").is_empty());
        Ok(())
    }

    proptest! {
        /// A note tied to a directory covers every file below it, and a note
        /// tied to a sibling does not.
        #[test]
        fn a_directory_tie_covers_exactly_its_subtree(
            dir in proptest::collection::vec("[a-z]{1,4}", 1..4),
            rest in proptest::collection::vec("[a-z]{1,4}", 0..3),
        ) {
            let dir = dir.join("/");
            let inside = std::iter::once(dir.clone()).chain(rest).collect::<Vec<_>>().join("/");
            let records = vec![
                note(widget(), &[&format!("path:{dir}")], "tied", 1)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?,
            ];
            prop_assert_eq!(notes_for_path(&records, "widget", &inside).len(), 1);
            let sibling = format!("{dir}x/file");
            prop_assert!(notes_for_path(&records, "widget", &sibling).is_empty());
        }
    }
}
