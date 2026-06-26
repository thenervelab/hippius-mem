//! Storage seams plus the [`MemoryStore`] that composes them.
//!
//! [`blob`] is the object store; the hybrid index lives in [`crate::index`].
//! [`MemoryStore`] wires crypto + blob store + index into the three core memory
//! operations — `remember`, `recall`, and `get` — that the rest of the system
//! drives. The op-log arrives in a later task.

pub mod blob;

pub use blob::{BlobStore, MemoryBlobStore, S3BlobStore};

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{SecretKey, content_hash, open, seal};
use crate::domain::{Note, NoteId, NoteType, RepoScope, Scope, Ss58, Timestamp};
use crate::error::MemError;
use crate::index::{IndexRecord, MemoryIndex, Pointer, Query};
use crate::objkey::object_key;

/// Phase 1 writes every note as revision 1.
///
/// Editing a note (revision > 1) is a later task, so the revision is a fixed
/// constant here rather than a field threaded through [`RememberInput`].
const PHASE1_REVISION: u32 = 1;

/// What to remember: the caller-supplied half of a new note.
///
/// Identity, timestamps, author, and scope-team are filled in by
/// [`MemoryStore::remember`]; the caller provides only the knowledge itself.
#[derive(Debug, Clone)]
pub struct RememberInput {
    /// The kind of knowledge being recorded.
    pub note_type: NoteType,
    /// Repository dimension within the store's team.
    pub repo: RepoScope,
    /// Free-form tags, indexed alongside the summary.
    pub tags: BTreeSet<String>,
    /// One-line summary surfaced by `recall`.
    pub summary: String,
    /// Full note text returned by `get`.
    pub body: String,
}

/// What to recall: a retrieval request scoped to one repository dimension.
#[derive(Debug, Clone)]
pub struct RecallInput {
    /// Natural-language query text.
    pub text: String,
    /// Repository dimension to retrieve for (team-global notes always match).
    pub repo: RepoScope,
    /// Maximum number of pointers to return.
    pub k: usize,
    /// Optional cap on the summed estimated token cost of returned summaries.
    pub token_budget: Option<usize>,
}

/// The core memory store: crypto + blob store + index behind one team identity.
///
/// One `MemoryStore` is bound to a single team (the shared namespace), its
/// encryption key, and the local developer's author identity. All three core
/// operations take `&self`: the blob store and index carry their own interior
/// mutability, and `MemoryStore` itself holds no lock across an `.await`, so it
/// stays cheap to share behind an `Arc` across tasks.
pub struct MemoryStore {
    blob: Arc<dyn BlobStore>,
    index: Arc<dyn MemoryIndex>,
    // The team encryption key. Owned, never cloned: `SecretKey` deliberately is
    // not `Clone`, so the bytes live in exactly one place.
    key: SecretKey,
    // The shared namespace every note in this store belongs to.
    team: String,
    // This developer's on-chain identity, stamped as the author of every note
    // this store writes.
    author: Ss58,
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `dyn BlobStore`/`dyn MemoryIndex` are not `Debug`, and the key must
        // never be printed; surface only the non-secret identity fields.
        f.debug_struct("MemoryStore")
            .field("team", &self.team)
            .field("author", &self.author)
            .finish_non_exhaustive()
    }
}

impl MemoryStore {
    /// Build a store over `blob` and `index`, sealing notes under `key` for
    /// team `team`, attributing each to `author`.
    #[must_use]
    pub fn new(
        blob: Arc<dyn BlobStore>,
        index: Arc<dyn MemoryIndex>,
        key: SecretKey,
        team: String,
        author: Ss58,
    ) -> Self {
        Self {
            blob,
            index,
            key,
            team,
            author,
        }
    }

    /// Record a new note: build it, seal it, persist the blob, then index it.
    ///
    /// Returns the freshly minted [`NoteId`].
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Crypto`] if sealing fails, [`MemError::Storage`] if
    /// the object key is invalid or the blob write fails, or any error the
    /// index reports while upserting.
    pub async fn remember(&self, input: RememberInput) -> Result<NoteId, MemError> {
        let id = NoteId::new();
        let now = current_millis();
        let scope = Scope {
            team: self.team.clone(),
            repo: input.repo,
        };
        let note = Note {
            id,
            scope: scope.clone(),
            note_type: input.note_type,
            author: self.author.clone(),
            created: now,
            updated: now,
            tags: input.tags,
            links: BTreeSet::new(),
            summary: input.summary,
            body: input.body,
        };

        let json = note.to_json();
        let ciphertext = seal(&self.key, json.as_bytes())?;
        let cid = content_hash(&ciphertext);
        let key = object_key(&scope, id, PHASE1_REVISION)?;

        // Persist the blob BEFORE indexing so the index can never reference a
        // missing object. A crash between these two steps leaves an orphan blob
        // (harmless, reclaimable) rather than an index pointer to a body that
        // was never written.
        self.blob.put(&key, ciphertext).await?;
        self.index.upsert(IndexRecord {
            note_id: id,
            object_key: key,
            cid,
            scope,
            note_type: note.note_type,
            author: note.author,
            updated: now,
            tags: note.tags,
            summary: note.summary,
        })?;
        Ok(id)
    }

    /// Retrieve ranked pointers for `input`. Pure index access — never the body.
    ///
    /// # Errors
    ///
    /// Returns any error the index reports while searching (e.g. embedding the
    /// query text).
    pub fn recall(&self, input: RecallInput) -> Result<Vec<Pointer>, MemError> {
        let query = Query {
            text: input.text,
            team: self.team.clone(),
            repo: input.repo,
            k: input.k,
            token_budget: input.token_budget,
            now: current_millis(),
        };
        self.index.search(&query)
    }

    /// Hydrate the full [`Note`] behind `id`: locate, fetch, verify, decrypt.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::NotFound`] if `id` is not indexed, [`MemError::Storage`]
    /// if the fetched ciphertext does not match the indexed content hash,
    /// [`MemError::Crypto`] if decryption or UTF-8 decoding fails, or
    /// [`MemError::Serialize`] if the decrypted JSON is not a valid note.
    pub async fn get(&self, id: NoteId) -> Result<Note, MemError> {
        let located = self
            .index
            .locate(id)?
            .ok_or_else(|| MemError::NotFound { id: id.to_string() })?;
        let ciphertext = self.blob.get(&located.object_key).await?;

        // Integrity gate before decryption: if the stored object was corrupted
        // or a different object was swapped under this key, its hash will not
        // match the cid the index recorded at write time. Reject it here so a
        // mismatch surfaces as a clear storage error instead of an opaque AEAD
        // failure — or, worse, a successful decrypt of a substituted ciphertext
        // under the shared team key.
        if content_hash(&ciphertext) != located.cid {
            return Err(MemError::Storage(
                "ciphertext hash does not match the indexed content hash".to_string(),
            ));
        }

        let plaintext = open(&self.key, &ciphertext)?;
        let json = std::str::from_utf8(&plaintext).map_err(|_| MemError::Crypto)?;
        Ok(Note::from_json(json)?)
    }
}

/// "Now" as a [`Timestamp`].
///
/// On the practically-impossible event of a system clock set before the Unix
/// epoch, `duration_since` errors; we fall back to the epoch (0) rather than
/// panic, so a misconfigured clock degrades a timestamp instead of crashing a
/// write. A clock past `i64::MAX` milliseconds (year ~292 million) saturates
/// likewise — both paths avoid `unwrap`/`panic` entirely.
fn current_millis() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    Timestamp::new(millis)
}

#[cfg(test)]
mod tests {
    use super::{MemoryStore, RecallInput, RememberInput};
    use crate::crypto::SecretKey;
    use crate::domain::{Note, NoteId, NoteType, RepoScope, Ss58};
    use crate::error::MemError;
    use crate::index::{HashEmbedder, InMemoryIndex};
    use crate::store::blob::MemoryBlobStore;
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEST_KEY: [u8; 32] = [7_u8; 32];
    const TEAM: &str = "team";
    // A distinctive phrase that lives only in the note body, so the
    // ciphertext-leakage test can search the at-rest bytes for it.
    const BODY_MARKER: &str = "half-read frame is lost";

    fn build_store() -> Result<MemoryStore, MemError> {
        let author = Ss58::new("5".repeat(48)).map_err(|e| MemError::Storage(e.to_string()))?;
        Ok(MemoryStore::new(
            Arc::new(MemoryBlobStore::default()),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            SecretKey::from_bytes(TEST_KEY),
            TEAM.to_string(),
            author,
        ))
    }

    fn test_store() -> Result<MemoryStore, Box<dyn std::error::Error>> {
        Ok(build_store()?)
    }

    fn sample_input() -> RememberInput {
        RememberInput {
            note_type: NoteType::Gotcha,
            repo: RepoScope::Repo("thebrain".to_string()),
            tags: BTreeSet::from(["async".to_string(), "tokio".to_string()]),
            summary: "select drops the losing branch future".to_string(),
            body: format!(
                "Under tokio::select! the unpicked branch is dropped, so a {BODY_MARKER} unless partial state lives in the receiver."
            ),
        }
    }

    #[tokio::test]
    async fn remember_then_recall_returns_pointer_not_body() -> TestResult {
        let store = test_store()?;
        let input = sample_input();
        let summary = input.summary.clone();
        let body = input.body.clone();
        let id = store.remember(input).await?;

        let pointers = store.recall(RecallInput {
            text: "select losing branch".to_string(),
            repo: RepoScope::Repo("thebrain".to_string()),
            k: 5,
            token_budget: None,
        })?;

        let pointer = pointers
            .iter()
            .find(|p| p.note_id == id)
            .ok_or("recall did not surface the remembered note")?;
        // Recall yields the summary as a pointer; `Pointer` structurally has no
        // body field, so the body is only reachable through `get`.
        assert_eq!(pointer.summary, summary);
        let note = store.get(id).await?;
        assert_eq!(note.body, body);
        Ok(())
    }

    #[tokio::test]
    async fn remember_then_get_round_trips() -> TestResult {
        let store = test_store()?;
        let input = sample_input();
        let expected = input.clone();
        let id = store.remember(input).await?;

        let note = store.get(id).await?;
        assert_eq!(note.id, id);
        assert_eq!(note.body, expected.body);
        assert_eq!(note.summary, expected.summary);
        assert_eq!(note.tags, expected.tags);
        assert_eq!(note.note_type, expected.note_type);
        Ok(())
    }

    #[tokio::test]
    async fn get_unknown_id_is_not_found() -> TestResult {
        let store = test_store()?;
        let missing = NoteId::new();
        match store.get(missing).await {
            Err(MemError::NotFound { id }) => assert_eq!(id, missing.to_string()),
            Err(other) => return Err(format!("expected NotFound, got {other:?}").into()),
            Ok(_) => return Err("unknown id unexpectedly resolved".into()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn recall_scope_isolation() -> TestResult {
        let store = test_store()?;
        let topic = "shared retrieval topic about scope".to_string();
        let remember_in = |repo: RepoScope, body: &str| RememberInput {
            note_type: NoteType::Reference,
            repo,
            tags: BTreeSet::new(),
            summary: topic.clone(),
            body: body.to_string(),
        };

        let thebrain = store
            .remember(remember_in(RepoScope::Repo("thebrain".to_string()), "b1"))
            .await?;
        let other = store
            .remember(remember_in(RepoScope::Repo("other".to_string()), "b2"))
            .await?;
        let global = store.remember(remember_in(RepoScope::Global, "b3")).await?;

        let pointers = store.recall(RecallInput {
            text: topic,
            repo: RepoScope::Repo("thebrain".to_string()),
            k: 10,
            token_budget: None,
        })?;
        let ids: BTreeSet<NoteId> = pointers.iter().map(|p| p.note_id).collect();

        // A repo:thebrain recall sees thebrain + team-global, never repo:other.
        assert!(ids.contains(&thebrain));
        assert!(ids.contains(&global));
        assert!(!ids.contains(&other));
        Ok(())
    }

    #[tokio::test]
    async fn stored_blob_is_ciphertext_not_plaintext() -> TestResult {
        let store = test_store()?;
        let input = sample_input();
        // Guard the test's own premise: the marker really is in the body.
        assert!(input.body.contains(BODY_MARKER));
        let id = store.remember(input).await?;

        // Reach past the public API to the raw at-rest object via the store's
        // own index + blob seams (accessible because tests are a child module).
        let located = store
            .index
            .locate(id)?
            .ok_or("note not indexed after remember")?;
        let raw = store.blob.get(&located.object_key).await?;

        let needle = BODY_MARKER.as_bytes();
        let leaked = raw.windows(needle.len()).any(|window| window == needle);
        assert!(!leaked, "plaintext body leaked into the stored object");
        Ok(())
    }

    #[tokio::test]
    async fn get_detects_tampered_blob() -> TestResult {
        let store = test_store()?;
        let id = store.remember(sample_input()).await?;
        let located = store
            .index
            .locate(id)?
            .ok_or("note not indexed after remember")?;

        // Swap the stored object for unrelated bytes whose hash cannot match the
        // cid the index recorded. `get` must reject this at the integrity gate
        // before ever attempting to decrypt under the shared team key.
        store.blob.put(&located.object_key, vec![0_u8; 64]).await?;

        match store.get(id).await {
            Err(MemError::Storage(message)) => assert!(message.contains("content hash")),
            Err(other) => return Err(format!("expected Storage, got {other:?}").into()),
            Ok(_) => return Err("tampered blob unexpectedly resolved".into()),
        }
        Ok(())
    }

    fn arb_note_type() -> impl Strategy<Value = NoteType> {
        prop_oneof![
            Just(NoteType::Decision),
            Just(NoteType::Convention),
            Just(NoteType::Gotcha),
            Just(NoteType::Reference),
            Just(NoteType::Context),
        ]
    }

    fn arb_repo() -> impl Strategy<Value = RepoScope> {
        prop_oneof![
            Just(RepoScope::Global),
            // Repo names restricted to safe object-key components, and `global`
            // is filtered out because it is reserved for the team-global scope.
            "[a-z]{1,12}"
                .prop_filter("'global' is reserved", |name: &String| name.as_str()
                    != "global")
                .prop_map(RepoScope::Repo),
        ]
    }

    fn arb_input() -> impl Strategy<Value = RememberInput> {
        (
            arb_note_type(),
            arb_repo(),
            proptest::collection::btree_set("[a-z]{1,8}", 0..4),
            ".*",
            ".*",
        )
            .prop_map(|(note_type, repo, tags, summary, body)| RememberInput {
                note_type,
                repo,
                tags,
                summary,
                body,
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// For an arbitrary input, `get(remember(input))` yields a note equal in
        /// body/summary/tags/type to the input. The async path is driven by a
        /// per-case current-thread tokio runtime built inside the closure
        /// (proptest needs a synchronous body); the `MemoryBlobStore` ops are
        /// trivial, so a single-threaded runtime is sufficient.
        #[test]
        fn remember_get_round_trips(input in arb_input()) {
            let outcome: Result<(Note, RememberInput), MemError> = (|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .map_err(MemError::from)?;
                let store = build_store()?;
                let expected = input.clone();
                let note = runtime.block_on(async {
                    let id = store.remember(input).await?;
                    store.get(id).await
                })?;
                Ok((note, expected))
            })();

            let (note, expected) =
                outcome.map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(note.body, expected.body);
            prop_assert_eq!(note.summary, expected.summary);
            prop_assert_eq!(note.tags, expected.tags);
            prop_assert_eq!(note.note_type, expected.note_type);
        }
    }
}
