//! Crate-wide error type for Hippius Memory core.

use crate::domain::NoteId;

/// The single error type returned across the Hippius Memory core library.
///
/// # Stability
///
/// Every variant is a stable contract callers may match on. `#[non_exhaustive]`
/// reserves room to add categories without a breaking change as the crate grows.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MemError {
    /// A memory note was requested by id but does not exist in the store.
    #[error("note {id} not found")]
    NotFound {
        /// The note id that was looked up.
        id: String,
    },
    /// An object-storage (S3 gateway) operation failed.
    //
    // A `String`, not `#[from]` a concrete S3 error: `aws_sdk_s3`'s `SdkError`
    // is generic over the per-operation error type, so a single `#[from]`
    // cannot cover every operation. The S3-store task maps each `SdkError`
    // into this variant via `.to_string()` at the call site.
    #[error("storage error: {0}")]
    Storage(String),
    /// (De)serialization of a note to/from JSON failed.
    #[error("serialize error: {0}")]
    Serialize(#[from] serde_json::Error),
    /// A ciphertext failed authentication or could not be decrypted.
    //
    // Deliberately carries no inner detail: an AEAD failure must never leak
    // key, nonce, or plaintext material into an error message or log line.
    // The fixed `Display` string is the entire contract.
    #[error("crypto error: ciphertext failed authentication")]
    Crypto,
    /// A filesystem / IO operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Deriving a cryptographic identity from a mnemonic, or decoding an SS58
    /// address, failed.
    //
    // The payload is `&'static str`, not `String`, on purpose: a mnemonic and
    // its derived seed are secret, so no part of either may reach an error
    // string or log line. A `&'static str` cannot interpolate runtime data, so
    // the no-leak guarantee is enforced by the type, not by a convention every
    // future call site must remember.
    #[error("identity error: {0}")]
    Identity(&'static str),
    /// A value (object key, anchor payload, on-the-wire field) was malformed: it
    /// did not parse or did not meet a format/structure rule.
    //
    // Distinct from `Storage` (the backend worked; the bytes are wrong) and from
    // `Serialize` (a serde failure with a typed source). A caller should surface
    // this as bad input and never retry it.
    #[error("malformed: {0}")]
    Malformed(String),
    /// An operation was refused because a signature, membership, or founder
    /// authorization check failed.
    //
    // Distinct from `Crypto` (a ciphertext that would not decrypt): the bytes are
    // intact but the signer is not permitted. A caller should surface this, not
    // retry it.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// The team key for a given epoch is not in this member's key-ring — they were
    /// never provisioned it (e.g. a member added after the epoch rotated).
    //
    // Distinct from `Crypto`: nothing failed to decrypt; the key is simply absent.
    // The epoch is carried so a caller can report or fetch exactly which key is
    // missing.
    #[error("key unavailable: no team key for epoch {epoch} in this member's ring")]
    KeyUnavailable {
        /// The epoch whose key is missing from the ring.
        epoch: u64,
    },
    /// A semantic-embedding model could not be loaded or failed to embed text.
    //
    // Its own category, not `Storage` (the S3 gateway) or `Malformed` (bad
    // bytes): a model failure is a distinct fault a caller may treat differently
    // — a load failure is fatal at startup, an inference failure is per-call. The
    // payload is the model backend's own message (`fastembed`/`ort` surface an
    // `anyhow::Error`); it carries no secret material, so a `String` is safe here.
    // Only the opt-in `embeddings` feature ever constructs it, but the variant is
    // always present so the error surface does not change with the feature flag.
    #[error("embedding error: {0}")]
    Embedding(String),
    /// A chain-anchor readback found the block an on-chain
    /// [`AnchorRecord`](crate::audit::batch::AnchorRecord) names, but it is not
    /// on the finalized chain: either its height is above the current
    /// finalized head, or the canonical block at its height has a different
    /// hash (an orphaned/reorged-out block an archive node still retains).
    //
    // Distinct from `Storage` (the RPC/backend call itself failed): every call
    // in the finality check succeeded and disagreed. A bucket can anchor a
    // remark on a block later reorged out; trusting that remark without this
    // check would let the bucket forge an on-chain anchor the reconciler
    // exists to catch. A caller should surface this as an anchor-forgery
    // signal, not retry it — the named block will never become canonical at
    // its height.
    #[error("anchor block {block_hash} is not on the finalized chain")]
    AnchorNotFinalized {
        /// The anchor block hash that failed the finality check.
        block_hash: String,
    },
    /// An [`edit`](crate::MemoryStore::edit_with_precondition) carried a
    /// compare-and-swap precondition that did not hold: the note's current content
    /// differs from the version the caller expected, so the write was refused
    /// before any change was made.
    //
    // Optimistic-concurrency guard for agent read-modify-write: the caller passes
    // the content version it read (the ciphertext's hex BLAKE3, from `get`); a
    // mismatch means a concurrent write landed first. A caller should re-read and
    // retry, never blind-retry — the same precondition would fail again. The
    // hashes are rendered hex (not raw `Blake3Hash`) so the whole contract lives
    // in the `Display` string. Scope: the check is against this machine's converged
    // state, so it catches the realistic post-`sync` race, not an unsynced
    // concurrent writer (those still converge last-writer-wins).
    #[error(
        "edit precondition failed: note changed since it was read (expected {expected}, now {actual})"
    )]
    Conflict {
        /// The content version the caller expected (hex BLAKE3 of the ciphertext).
        expected: String,
        /// The note's actual current content version.
        actual: String,
    },
    /// A [`remember`](crate::MemoryStore::remember) was refused because the
    /// candidate summary is a near-duplicate of an existing live note — the
    /// write-time dedup gate protecting recall precision from accumulation.
    //
    // A soft refusal, not a hard fault: the caller has three good moves the
    // message names — edit the existing note, `link` it with a supersedes /
    // duplicates rel, or set `force` to write anyway. The message names the
    // MCP tool (`link`), not the core method (`relate`): at the LLM boundary
    // this string is the agent's instruction sheet, and no tool named `relate`
    // exists on the wire. `existing` is a typed
    // `NoteId` (not a `String` like `NotFound`) because it always comes from the
    // index as a real id the caller can act on directly, never from unparsed wire
    // input. `similarity` is in `[0, 1]`: cosine on a semantic build, token-set
    // Jaccard on a lexical build (which only catches near-identical summaries).
    #[error(
        "near-duplicate of note {existing} (similarity {similarity:.3}): edit that note, link it with rel=supersedes/duplicates, or retry with force to write anyway"
    )]
    NearDuplicate {
        /// The existing live note the candidate most resembles.
        existing: NoteId,
        /// Similarity in `[0, 1]` to `existing` — cosine on a semantic build,
        /// token-set Jaccard on a lexical build.
        similarity: f32,
    },
    /// A key rotation found no published member key the current manifest
    /// authorizes, so the new epoch's key would be wrapped to no one.
    //
    // Refused BEFORE the write epoch advances: sealing future notes under a key
    // that exists only in the rotating process would make them unreadable to the
    // entire team once that process exits. Distinct from `Unauthorized` (the
    // caller IS permitted to rotate; there is simply no one to rotate for) — the
    // fix is operational (`join` + manifest), not a permission change.
    #[error(
        "nothing to rotate for team {team}: no published member key is authorized by the current \
         manifest; members must `join` (and the manifest must list them) before a rotation can \
         wrap the new epoch key to anyone"
    )]
    NothingToRotate {
        /// The team whose rotation found no authorized wrap target.
        team: String,
    },
    /// A pinned-founder team has no membership manifest signed by that founder,
    /// so a membership-shaped operation (e.g. key rotation) fails closed.
    //
    // Distinct from `Unauthorized` (the caller may well be the pinned founder)
    // and from `Storage` (the bucket answered; the trusted object is absent).
    // The pin makes "no manifest" indistinguishable from "the untrusted bucket
    // withheld or replaced the manifest", so the safe behaviour is refusal; the
    // fix the message names is publishing membership under the pin.
    #[error(
        "no trusted membership manifest for team {team}: the pinned founder has published none \
         (or the bucket withheld it); publish membership (e.g. `publish-membership` or \
         `rotate --members`) before rotating"
    )]
    ManifestUnavailable {
        /// The team whose pinned founder has no trusted manifest.
        team: String,
    },

    /// A fetched blob exceeded the in-memory read cap.
    ///
    /// A DISTINCT variant (not [`MemError::Storage`]) precisely so callers that can
    /// degrade gracefully on an oversized object match it: snapshot loading falls
    /// back to an older checkpoint or a full op-log replay rather than aborting,
    /// while a note fetch treats it as the fault it is. The cap bounds a
    /// hostile/compromised gateway, whose bytes are otherwise buffered before any
    /// integrity check runs.
    #[error("blob {key} exceeds the {cap}-byte read cap")]
    BlobTooLarge {
        /// The object key whose body exceeded the cap.
        key: String,
        /// The byte cap that was exceeded.
        cap: usize,
    },
}

/// Convenience alias for fallible core operations.
pub type Result<T> = std::result::Result<T, MemError>;

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests call unwrap_err on Results known to be Err in this branch"
)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    /// Drives the `?` operator through `From<serde_json::Error>` so the test
    /// exercises the real propagation path, not just a manual `.into()`.
    fn reparse(raw: &str) -> Result<crate::domain::Note> {
        let note = serde_json::from_str::<crate::domain::Note>(raw)?;
        Ok(note)
    }

    #[test]
    fn not_found_displays_id() {
        let err = MemError::NotFound { id: "mem_x".into() };
        assert!(err.to_string().contains("mem_x"), "got: {err}");
    }

    #[test]
    fn serialize_error_converts_via_from() {
        let err = reparse("not json").unwrap_err();
        assert!(matches!(err, MemError::Serialize(_)), "got: {err:?}");

        let source = StdError::source(&err);
        assert!(
            source
                .and_then(|cause| cause.downcast_ref::<serde_json::Error>())
                .is_some(),
            "expected serde_json::Error preserved in source chain, got: {source:?}",
        );
    }

    #[test]
    fn io_error_converts_via_from() {
        let err = MemError::from(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(matches!(err, MemError::Io(_)), "got: {err:?}");

        let source = StdError::source(&err);
        assert!(
            source
                .and_then(|cause| cause.downcast_ref::<std::io::Error>())
                .is_some(),
            "expected std::io::Error preserved in source chain, got: {source:?}",
        );
    }

    #[test]
    fn key_unavailable_names_the_epoch() {
        let err = MemError::KeyUnavailable { epoch: 7 };
        assert!(
            err.to_string().contains("epoch 7"),
            "the error must name the missing epoch: {err}"
        );
        // Distinct category from Crypto: a caller can branch on it.
        assert!(matches!(err, MemError::KeyUnavailable { epoch: 7 }));
    }

    #[test]
    fn embedding_error_is_its_own_category() {
        // A model failure must be a distinct, matchable variant (not folded into
        // Storage), and its Display must carry the backend's detail for diagnosis.
        let err = MemError::Embedding("model file not found".to_owned());
        assert!(matches!(err, MemError::Embedding(_)), "got: {err:?}");
        assert!(
            err.to_string().contains("model file not found"),
            "the embedding error must surface the backend detail: {err}"
        );
    }

    #[test]
    fn anchor_not_finalized_names_the_block_and_is_its_own_category() {
        // Must be distinct from `Storage` so a reconciler caller can branch on
        // "the chain disagreed" (forgery signal) vs. "the RPC call failed"
        // (retryable infra fault) — collapsing the two would hide the forgery
        // case behind a generic backend-error message.
        let err = MemError::AnchorNotFinalized {
            block_hash: "0xdead".to_owned(),
        };
        assert!(matches!(err, MemError::AnchorNotFinalized { .. }));
        assert!(
            err.to_string().contains("0xdead"),
            "the error must name the offending block hash: {err}"
        );
    }

    #[test]
    fn crypto_error_leaks_no_detail() {
        let rendered = MemError::Crypto.to_string();
        assert!(
            !rendered.contains("key"),
            "crypto error must not leak key material: {rendered}",
        );
        assert_eq!(rendered, "crypto error: ciphertext failed authentication");
    }
}
