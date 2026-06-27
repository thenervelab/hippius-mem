//! Crate-wide error type for Hippius Memory core.

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
    // The payload is one of a fixed set of static category messages, never
    // formatted from caller input: a mnemonic and its derived seed are secret,
    // so no part of either may reach an error string or log line.
    #[error("identity error: {0}")]
    Identity(String),
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
    fn crypto_error_leaks_no_detail() {
        let rendered = MemError::Crypto.to_string();
        assert!(
            !rendered.contains("key"),
            "crypto error must not leak key material: {rendered}",
        );
        assert_eq!(rendered, "crypto error: ciphertext failed authentication");
    }
}
