//! Client-side authenticated encryption for memory-note blobs.
//!
//! Hippius Memory is end-to-end encrypted: a team's notes are sealed on the
//! client and the S3 gateway only ever stores opaque ciphertext. This module
//! provides the two primitives the storage layer builds on — [`seal`] and
//! [`open`] (XChaCha20-Poly1305 AEAD) — plus [`content_hash`] for the BLAKE3
//! integrity anchor over a sealed blob.

use core::fmt;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::domain::Blake3Hash;
use crate::error::MemError;

/// Length in bytes of the XChaCha20-Poly1305 extended nonce.
///
/// Derived from the cipher's own [`XNonce`] type rather than hard-coded: an
/// `XNonce` is a `GenericArray<u8, U24>`, a plain 24-byte array with no
/// padding, so its size *is* the nonce length. Tying the constant to the type
/// means a future change of cipher variant would update the blob layout in
/// lockstep instead of silently desyncing the `seal`/`open` split point.
const NONCE_LEN: usize = core::mem::size_of::<XNonce>();

/// A 32-byte symmetric key used to seal and open memory-note blobs.
///
/// The key bytes live inside [`Zeroizing`] so they are overwritten with a
/// volatile write on drop instead of being left behind in freed memory. The
/// type deliberately derives neither `Clone`, `Copy`, nor `Debug`: the bytes
/// must never be copied casually nor printed. The hand-written [`fmt::Debug`]
/// impl redacts them, and there is no accessor that hands the raw key back out
/// by value.
pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    /// Wrap raw key bytes in a zeroizing container.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the raw key bytes for the in-crate team-key wrapping path.
    ///
    /// Crate-private and borrow-only on purpose: the bytes never leave the
    /// crate and are never handed back by value. The team-key provisioning
    /// layer ([`crate::identity::teamkey`]) needs the plaintext team-key bytes
    /// to seal them under a per-recipient ECDH key, and the round-trip tests
    /// compare keys by their bytes; no other caller should reach for this.
    pub(crate) fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Build the AEAD cipher bound to this key.
    ///
    /// `Key::from_slice` panics on a wrong-length slice, but the backing array
    /// is statically `[u8; 32]` — exactly `XChaCha20Poly1305`'s key size — so
    /// that branch is unreachable here and no error path is exposed.
    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(&self.0[..]))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Encrypt `plaintext` under `key`, returning `nonce ‖ ciphertext+tag`.
///
/// A fresh 24-byte nonce is drawn from the OS CSPRNG on every call, so two
/// seals of identical input produce different blobs. Nonce reuse would break
/// XChaCha20-Poly1305's confidentiality guarantee, which is exactly why the
/// nonce is generated here and never cached or supplied by the caller.
///
/// `aad` is the additional authenticated data: it is *not* encrypted, but it is
/// folded into the Poly1305 tag, so [`open`] only succeeds when given the exact
/// same `aad`. Callers pass the object key here, which binds the ciphertext to
/// the identity it is stored under. Without this binding a malicious or buggy
/// gateway could serve note A's bytes at note B's key and — because the content
/// hash is recomputed from the relocated bytes and they decrypt under the shared
/// team key — `get(B)` would silently return A's content. Authenticating the key
/// as AAD turns that relocation/replay into an authentication failure.
///
/// # Errors
///
/// Returns [`MemError::Crypto`] if the AEAD layer rejects the message. Per the
/// `aead` contract, `encrypt` only fails when the plaintext exceeds the
/// cipher's maximum length (~256 GiB); that path is propagated rather than
/// asserted away, so the function contains no explicit `unwrap`/`panic`.
///
/// # Panics
///
/// Nonce generation draws from the OS CSPRNG (`OsRng`), which panics (unwinding by
/// default) if the operating system cannot supply randomness — a catastrophic,
/// unrecoverable condition, not a normal error. This is the one panic path; it is
/// intrinsic to needing a secure random nonce and is not something a caller can
/// handle, so it is documented rather than wrapped in a `Result`.
pub fn seal(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, MemError> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = key
        .cipher()
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| MemError::Crypto)?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(nonce.as_slice());
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt a blob produced by [`seal`] under the same `key` and `aad`.
///
/// `aad` must equal the additional authenticated data passed to [`seal`] — the
/// object key the bytes are stored under. A mismatch fails authentication, which
/// is the defense against a gateway relocating or replaying a ciphertext under a
/// different key (see [`seal`] for the threat model).
///
/// # Errors
///
/// Returns [`MemError::Crypto`] if the blob is shorter than a nonce, if the
/// authentication tag does not verify (wrong key, tampered bytes, or mismatched
/// `aad`), or if the key is wrong. The error carries no detail by design, so it
/// never reveals which check failed.
pub fn open(key: &SecretKey, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, MemError> {
    if blob.len() < NONCE_LEN {
        return Err(MemError::Crypto);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    key.cipher()
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| MemError::Crypto)
}

/// BLAKE3 digest of `bytes`, wrapped in the domain [`Blake3Hash`] newtype.
///
/// This is an UNKEYED, untagged hash reused across two domains — the ciphertext
/// content id (`cid = content_hash(ciphertext)`) and the op-log chain link
/// (`Op::hash = content_hash(signing_bytes ++ sig)`). They never share an input
/// space and are never compared across domains: `Op::signing_bytes` already
/// prepends the `hippius-memory-op/...` domain tag, so an op digest's preimage is
/// disjoint from a raw-ciphertext preimage by construction. The two domains are
/// kept apart by that op-side tag plus collision resistance, not by a tag on this
/// function; do not introduce a cross-domain hash comparison without adding one.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> Blake3Hash {
    Blake3Hash::new(blake3::hash(bytes).into())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::*;
    use proptest::prelude::*;

    // A representative object key, reused as AAD across the round-trip tests so
    // seal and open agree on the authenticated identity.
    const AAD: &[u8] = b"team/global/mem_01J/rev_1";

    proptest! {
        #[test]
        fn seal_open_round_trips(
            pt in proptest::collection::vec(any::<u8>(), 0..4096usize),
            aad in proptest::collection::vec(any::<u8>(), 0..64usize),
            key_bytes in proptest::array::uniform32(any::<u8>()),
        ) {
            let key = SecretKey::from_bytes(key_bytes);
            let blob = seal(&key, &pt, &aad).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let opened = open(&key, &blob, &aad).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(opened, pt);
        }
    }

    #[test]
    fn empty_plaintext_round_trips() -> Result<(), MemError> {
        let key = SecretKey::from_bytes([9u8; 32]);
        let blob = seal(&key, b"", AAD)?;
        // Empty plaintext still yields a 24-byte nonce + 16-byte Poly1305 tag.
        assert_eq!(blob.len(), 24 + 16);
        let opened = open(&key, &blob, AAD)?;
        assert_eq!(opened, b"");
        Ok(())
    }

    #[test]
    fn tampered_ciphertext_fails_auth() -> Result<(), MemError> {
        let key = SecretKey::from_bytes([3u8; 32]);
        let mut blob = seal(&key, b"top secret note", AAD)?;
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(open(&key, &blob, AAD), Err(MemError::Crypto)));
        Ok(())
    }

    #[test]
    fn wrong_key_fails_auth() -> Result<(), MemError> {
        let key_a = SecretKey::from_bytes([1u8; 32]);
        let key_b = SecretKey::from_bytes([2u8; 32]);
        let blob = seal(&key_a, b"secret", AAD)?;
        assert!(matches!(open(&key_b, &blob, AAD), Err(MemError::Crypto)));
        Ok(())
    }

    #[test]
    fn mismatched_aad_fails_auth() -> Result<(), MemError> {
        // The threat model in `seal`: a ciphertext sealed for object key "k1"
        // must NOT open when presented under a different key "k2", even though
        // the key and ciphertext bytes are otherwise valid. This is the AEAD-level
        // defeat of gateway relocation/replay.
        let key = SecretKey::from_bytes([5u8; 32]);
        let blob = seal(&key, b"bound to its location", b"k1")?;
        assert!(matches!(open(&key, &blob, b"k2"), Err(MemError::Crypto)));
        // Sanity: the correct AAD still opens it, so the failure above is the
        // AAD, not a broken round trip.
        assert_eq!(open(&key, &blob, b"k1")?, b"bound to its location");
        Ok(())
    }

    #[test]
    fn short_blob_is_crypto_error_not_panic() {
        let key = SecretKey::from_bytes([0u8; 32]);
        assert!(matches!(open(&key, &[0u8; 5], AAD), Err(MemError::Crypto)));
    }

    #[test]
    fn sub_tag_ciphertext_is_crypto_error_not_panic() {
        // The window the explicit `len < NONCE_LEN` guard does NOT cover: a blob of
        // length in [NONCE_LEN, NONCE_LEN + 16) passes that guard and reaches
        // chacha20poly1305's `decrypt` with a ciphertext slice shorter than the
        // 16-byte Poly1305 tag. Per the RustCrypto `aead` contract, `decrypt`
        // returns Err (never panics) for an input too short to contain its tag;
        // these are the exact attacker-controlled lengths the existing 5-byte test
        // (which trips the explicit guard) never exercises.
        let key = SecretKey::from_bytes([0u8; 32]);
        for len in [NONCE_LEN, NONCE_LEN + 1, NONCE_LEN + 8, NONCE_LEN + 15] {
            let blob = vec![0u8; len];
            assert!(
                matches!(open(&key, &blob, AAD), Err(MemError::Crypto)),
                "a {len}-byte blob (below a full nonce+tag frame) must be a Crypto error, not a panic"
            );
        }
    }

    proptest! {
        /// No blob shorter than a complete nonce+16-byte-tag frame may open or
        /// panic: across the whole sub-frame length range, `open` returns
        /// Err(Crypto). Probes the documented `aead` short-input edge for every
        /// length, not just the hand-picked ones above.
        #[test]
        fn no_sub_frame_blob_opens(
            bytes in proptest::collection::vec(any::<u8>(), 0..(NONCE_LEN + 16)),
        ) {
            let key = SecretKey::from_bytes([7u8; 32]);
            prop_assert!(matches!(open(&key, &bytes, AAD), Err(MemError::Crypto)));
        }
    }

    #[test]
    fn nonce_is_random() -> Result<(), MemError> {
        let key = SecretKey::from_bytes([4u8; 32]);
        let first = seal(&key, b"same plaintext", AAD)?;
        let second = seal(&key, b"same plaintext", AAD)?;
        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn content_hash_is_deterministic_and_sensitive() {
        let a = content_hash(b"hello world");
        let b = content_hash(b"hello world");
        assert_eq!(a, b);
        // "hello world" vs "hello worle": the final byte differs by one bit.
        let c = content_hash(b"hello worle");
        assert_ne!(a, c);
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let key = SecretKey::from_bytes([1u8; 32]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "SecretKey(<redacted>)");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains('1'));
    }
}
