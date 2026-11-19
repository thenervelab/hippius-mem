//! What this process has itself read out of note blobs.
//!
//! A checkpoint is sealed with the team key but not signed, and a signed op
//! attests a note's content hash, not its text. So a checkpoint record's
//! `summary`, `tags`, `updated` and `note_type` are the word of whichever
//! member wrote the checkpoint: a current member can rewrite another member's
//! summary there, and recall would show it.
//!
//! [`DecodedLedger`] is the check. Decoding a note's blob verifies the bytes
//! against the op-attested content hash, so the fields that come out are the
//! author's. The ledger remembers a digest of them per note. A checkpoint
//! record is taken on its word only when it agrees with the ledger; any other
//! record is decoded from its blob, which is the authoritative answer and adds
//! the note to the ledger.
//!
//! An optional author signature over these fields was considered and dropped:
//! a forger removes the signature along with rewriting the summary, and
//! nothing a signed op carries says whether a note should have one, so every
//! unsigned record would still need this ledger.
//!
//! Not durable. A new process starts empty and decodes each live note once on
//! its first sync, which the local blob cache serves from disk on a machine
//! that has synced before. A file would save that pass and add a second local
//! format to keep in step with the blob cache.
//!
//! Embeddings are outside this check: nothing ties a persisted vector to its
//! summary, and confirming one means running the model again.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};

use crate::crypto::content_hash;
use crate::domain::{Blake3Hash, NoteId};
use crate::framing::push_framed;
use crate::index::IndexRecord;

/// The content hash of the blob a note's fields were decoded from, and a
/// digest of those fields ([`index_fields_digest`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Decoded {
    cid: Blake3Hash,
    fields: Blake3Hash,
}

impl Decoded {
    fn of(record: &IndexRecord) -> Self {
        Self {
            cid: record.cid,
            fields: index_fields_digest(record),
        }
    }
}

/// A digest of the four fields of `record` that exist only inside the note
/// blob (`updated`, `note_type`, `summary` and `tags`), and of where that blob
/// sits (`key_epoch`, `object_key`).
///
/// The location is in so that an entry speaks for one revision. The content
/// hash alone does not name one: an op can point a new object key at bytes
/// copied from an older revision, which then fail to open there, and a record
/// for that revision must not be attested by the older one's entry.
///
/// The fixed-width fields go first and the tags last, each variable-length
/// field length-prefixed by [`push_framed`], so two different field sets cannot
/// produce the same bytes: the tag list needs no count because nothing follows
/// it.
fn index_fields_digest(record: &IndexRecord) -> Blake3Hash {
    let mut buf = Vec::new();
    buf.extend_from_slice(&record.updated.as_millis().to_le_bytes());
    buf.extend_from_slice(&record.key_epoch.to_le_bytes());
    push_framed(&mut buf, record.object_key.as_bytes());
    push_framed(&mut buf, record.note_type.to_string().as_bytes());
    push_framed(&mut buf, record.summary.as_bytes());
    for tag in &record.tags {
        push_framed(&mut buf, tag.as_bytes());
    }
    content_hash(&buf)
}

/// The notes this process has decoded from their blobs, each with what the
/// blob held. See the module docs.
///
/// One entry per note: a newer revision replaces the older one. The lock is
/// held for one map operation and never across an `.await`.
#[derive(Debug, Default)]
pub(crate) struct DecodedLedger {
    by_note: Mutex<HashMap<NoteId, Decoded>>,
}

impl DecodedLedger {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<NoteId, Decoded>> {
        // A map of plain values: no panic can leave an entry half-written.
        self.by_note.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Remember `record` as decoded from the blob with content hash
    /// `record.cid`. Call it only with a record built from a blob whose bytes
    /// were checked against the op-attested hash.
    pub(crate) fn record(&self, record: &IndexRecord) {
        let decoded = Decoded::of(record);
        self.lock().insert(record.note_id, decoded);
    }

    /// Whether this process decoded the same revision of the note (same content
    /// hash, object key and key epoch) and read the same `summary`, `tags`,
    /// `updated` and `note_type` that `claim` states.
    pub(crate) fn attests(&self, claim: &IndexRecord) -> bool {
        // Hashed before the lock is taken: a claim's summary has no size bound.
        let claimed = Decoded::of(claim);
        self.lock().get(&claim.note_id) == Some(&claimed)
    }

    /// Drop the entries of notes that are no longer live. An entry stays true
    /// after its note is forgotten, so this only bounds memory.
    pub(crate) fn retain(&self, live: &BTreeSet<NoteId>) {
        self.lock().retain(|note_id, _| live.contains(note_id));
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use super::*;
    use crate::domain::{NoteType, RepoScope, Scope, Ss58, Timestamp};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn record(summary: &str, tags: &[&str]) -> Result<IndexRecord, Box<dyn std::error::Error>> {
        Ok(IndexRecord {
            note_id: "mem_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse()?,
            object_key: "team/global/mem_01ARZ3NDEKTSV4RRFFQ69G5FAV/ver_1".to_owned(),
            cid: content_hash(b"blob"),
            scope: Scope {
                team: "team".to_owned(),
                repo: RepoScope::Global,
            },
            note_type: NoteType::Decision,
            author: Ss58::new("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")?,
            updated: Timestamp::new(1_000),
            lamport: 1,
            key_epoch: 0,
            tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
            summary: summary.to_owned(),
            relations: Vec::new(),
            reinforcers: BTreeSet::new(),
            last_reinforced: None,
            embedding: None,
        })
    }

    /// Each field the op-log does not attest must change the verdict by
    /// itself: a digest that left one out would let a checkpoint rewrite it.
    /// So must each field that names the revision, or one revision's entry
    /// would speak for another.
    #[test]
    fn a_claim_that_differs_in_any_blob_only_field_is_not_attested() -> TestResult {
        let decoded = record("use the lock", &["db", "locks"])?;
        let ledger = DecodedLedger::default();
        ledger.record(&decoded);
        assert!(ledger.attests(&decoded), "the decoded record itself");

        let mut summary = decoded.clone();
        summary.summary = "skip the lock".to_owned();
        let mut tags = decoded.clone();
        tags.tags.insert("path:src".to_owned());
        // The first tag in set order: a digest that skipped one end of the set
        // would miss either this change or the one above.
        let mut first_tag = decoded.clone();
        first_tag.tags.remove("db");
        first_tag.tags.insert("da".to_owned());
        let mut updated = decoded.clone();
        updated.updated = Timestamp::new(9_000);
        let mut note_type = decoded.clone();
        note_type.note_type = NoteType::Gotcha;
        let mut revision = decoded.clone();
        revision.cid = content_hash(b"another blob");
        let mut object_key = decoded.clone();
        object_key.object_key = "team/global/mem_01ARZ3NDEKTSV4RRFFQ69G5FAV/ver_2".to_owned();
        let mut key_epoch = decoded.clone();
        key_epoch.key_epoch = 1;

        for (field, claim) in [
            ("summary", summary),
            ("tags", tags),
            ("the first tag", first_tag),
            ("updated", updated),
            ("note_type", note_type),
            ("cid", revision),
            ("object_key", object_key),
            ("key_epoch", key_epoch),
        ] {
            assert!(!ledger.attests(&claim), "a claim with another {field}");
        }
        Ok(())
    }

    /// Moving a boundary between two fields must change the digest, or a
    /// forger could trade text between the summary and a tag.
    #[test]
    fn text_moved_between_the_summary_and_a_tag_changes_the_digest() -> TestResult {
        let ledger = DecodedLedger::default();
        ledger.record(&record("ab", &["c"])?);
        assert!(!ledger.attests(&record("a", &["bc"])?));
        assert!(!ledger.attests(&record("ab", &["c", ""])?));
        assert!(!ledger.attests(&record("abc", &[])?));
        Ok(())
    }

    #[test]
    fn a_note_never_decoded_is_not_attested_and_retain_forgets_dead_notes() -> TestResult {
        let decoded = record("use the lock", &[])?;
        let ledger = DecodedLedger::default();
        assert!(!ledger.attests(&decoded), "nothing decoded yet");

        ledger.record(&decoded);
        ledger.retain(&BTreeSet::from([decoded.note_id]));
        assert!(ledger.attests(&decoded), "a live note is kept");
        ledger.retain(&BTreeSet::new());
        assert!(
            !ledger.attests(&decoded),
            "a note no longer live is dropped"
        );
        Ok(())
    }
}
