//! Client-side authenticated encryption for memory-note blobs.
//!
//! Hippius Memory is end-to-end encrypted: a team's notes are sealed on the
//! client and the S3 gateway only ever stores opaque ciphertext. This module
//! provides the two primitives the storage layer builds on — [`seal`] and
//! [`open`] (XChaCha20-Poly1305 AEAD) — plus [`content_hash`] for the BLAKE3
//! integrity anchor over a sealed blob.

use core::fmt;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
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
/// # Errors
///
/// Returns [`MemError::Crypto`] if the AEAD layer rejects the message. Per the
/// `aead` contract, `encrypt` only fails when the plaintext exceeds the
/// cipher's maximum length (~256 GiB); that path is propagated rather than
/// asserted away so the function carries no panic/unwrap.
pub fn seal(key: &SecretKey, plaintext: &[u8]) -> Result<Vec<u8>, MemError> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = key
        .cipher()
        .encrypt(&nonce, plaintext)
        .map_err(|_| MemError::Crypto)?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(nonce.as_slice());
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt a blob produced by [`seal`] under the same `key`.
///
/// # Errors
///
/// Returns [`MemError::Crypto`] if the blob is shorter than a nonce, if the
/// authentication tag does not verify, or if the key is wrong. The error
/// carries no detail by design, so it never reveals which check failed.
pub fn open(key: &SecretKey, blob: &[u8]) -> Result<Vec<u8>, MemError> {
    if blob.len() < NONCE_LEN {
        return Err(MemError::Crypto);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    key.cipher()
        .decrypt(nonce, ciphertext)
        .map_err(|_| MemError::Crypto)
}

/// BLAKE3 digest of `bytes`, wrapped in the domain [`Blake3Hash`] newtype.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> Blake3Hash {
    Blake3Hash::new(blake3::hash(bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn seal_open_round_trips(
            pt in proptest::collection::vec(any::<u8>(), 0..4096usize),
            key_bytes in proptest::array::uniform32(any::<u8>()),
        ) {
            let key = SecretKey::from_bytes(key_bytes);
            let blob = seal(&key, &pt).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let opened = open(&key, &blob).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(opened, pt);
        }
    }

    #[test]
    fn empty_plaintext_round_trips() -> Result<(), MemError> {
        let key = SecretKey::from_bytes([9u8; 32]);
        let blob = seal(&key, b"")?;
        // Empty plaintext still yields a 24-byte nonce + 16-byte Poly1305 tag.
        assert_eq!(blob.len(), 24 + 16);
        let opened = open(&key, &blob)?;
        assert_eq!(opened, b"");
        Ok(())
    }

    #[test]
    fn tampered_ciphertext_fails_auth() -> Result<(), MemError> {
        let key = SecretKey::from_bytes([3u8; 32]);
        let mut blob = seal(&key, b"top secret note")?;
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(open(&key, &blob), Err(MemError::Crypto)));
        Ok(())
    }

    #[test]
    fn wrong_key_fails_auth() -> Result<(), MemError> {
        let key_a = SecretKey::from_bytes([1u8; 32]);
        let key_b = SecretKey::from_bytes([2u8; 32]);
        let blob = seal(&key_a, b"secret")?;
        assert!(matches!(open(&key_b, &blob), Err(MemError::Crypto)));
        Ok(())
    }

    #[test]
    fn short_blob_is_crypto_error_not_panic() {
        let key = SecretKey::from_bytes([0u8; 32]);
        assert!(matches!(open(&key, &[0u8; 5]), Err(MemError::Crypto)));
    }

    #[test]
    fn nonce_is_random() -> Result<(), MemError> {
        let key = SecretKey::from_bytes([4u8; 32]);
        let first = seal(&key, b"same plaintext")?;
        let second = seal(&key, b"same plaintext")?;
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
