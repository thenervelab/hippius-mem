//! Client-side authenticated encryption for memory-note blobs.
//!
//! Hippius Memory is end-to-end encrypted: a team's notes are sealed on the
//! client and the S3 gateway only ever stores opaque ciphertext. This module
//! provides the two primitives the storage layer builds on — [`seal`] and
//! [`open`] (XChaCha20-Poly1305 AEAD) — plus [`content_hash`] for the BLAKE3
//! integrity anchor over a sealed blob.

use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::domain::Blake3Hash;
use crate::error::MemError;

/// Length in bytes of the XChaCha20-Poly1305 extended nonce.
///
/// Derived from the cipher's own [`XNonce`] type rather than hard-coded: an
/// `XNonce` is a `hybrid_array::Array<u8, U24>`, a plain 24-byte array with no
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

    /// Draw a fresh key from the OS CSPRNG — the source a team-key rotation
    /// mints its new epoch key from.
    ///
    /// Uses the same `getrandom::fill` as the [`seal`] nonce path, so key
    /// generation adds no second randomness dependency to audit. The bytes are
    /// written straight into the zeroizing container, so no unwiped copy of the
    /// key is left behind.
    ///
    /// # Panics
    ///
    /// Like [`seal`]'s nonce draw, it panics if the operating system cannot
    /// supply randomness — a catastrophic condition no caller can handle, so it
    /// is documented rather than wrapped in a `Result`.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "OS CSPRNG failure is unrecoverable; documented under # Panics"
    )]
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut bytes[..]).expect("OS CSPRNG unavailable");
        Self(bytes)
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
    /// The backing array is statically `[u8; 32]`, exactly `XChaCha20Poly1305`'s
    /// key size, so it converts to `&Key` by reference with no length check to
    /// fail. The cipher keeps its own copy of the key, which it wipes on drop
    /// only with chacha20poly1305's `zeroize` feature; the `ZeroizeOnDrop`
    /// check in the tests fails to compile if that feature is ever dropped.
    fn cipher(&self) -> XChaCha20Poly1305 {
        let key: &Key = (&*self.0).into();
        XChaCha20Poly1305::new(key)
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
/// Nonce generation draws from the OS CSPRNG (`getrandom`), which panics (unwinding by
/// default) if the operating system cannot supply randomness — a catastrophic,
/// unrecoverable condition, not a normal error. This is the one panic path; it is
/// intrinsic to needing a secure random nonce and is not something a caller can
/// handle, so it is documented rather than wrapped in a `Result`.
#[expect(
    clippy::expect_used,
    reason = "OS CSPRNG failure is unrecoverable; documented under # Panics"
)]
pub fn seal(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, MemError> {
    let mut nonce = XNonce::default();
    getrandom::fill(&mut nonce[..]).expect("OS CSPRNG unavailable");
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
    let Some((nonce, ciphertext)) = blob.split_first_chunk::<NONCE_LEN>() else {
        return Err(MemError::Crypto);
    };

    key.cipher()
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| MemError::Crypto)
}

/// BLAKE3 digest of `bytes`, wrapped in the domain [`Blake3Hash`] newtype.
///
/// This is an UNKEYED, untagged hash reused across three domains — the
/// ciphertext content id (`cid = content_hash(ciphertext)`), the op-log chain
/// link (`Op::hash = content_hash(signing_bytes ++ sig)`), and the manifest
/// election's same-version tie-break rank (`identity::manifest::content_rank`,
/// over `TeamManifest::signing_bytes`). They never share an input space and are
/// never compared across domains: `Op::signing_bytes` prepends the
/// `hippius-memory-op/...` domain tag and `TeamManifest::signing_bytes` prepends
/// `hippius-memory-manifest/...`, so each digest's preimage is disjoint from the
/// others' — and from a raw-ciphertext preimage — by construction. The domains
/// are kept apart by those caller-side tags plus collision resistance, not by a
/// tag on this function; do not introduce a cross-domain hash comparison without
/// adding one.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> Blake3Hash {
    Blake3Hash::new(blake3::hash(bytes).into())
}

/// Derive a local-cache encryption key from the team key.
///
/// Domain-separated via `blake3::derive_key`, so the cache key is cryptographically
/// independent of every other use of the team key (note sealing, team-key
/// wrapping): recovering the cache key reveals nothing about the team key or the
/// other derived keys, and vice versa. Binding it to the team key means a local
/// cache is unreadable — and useless — to anyone without the team key, so cache
/// files on disk leak nothing even though op metadata is cleartext in the bucket.
#[must_use]
pub fn derive_cache_key(team_key: &SecretKey) -> SecretKey {
    SecretKey::from_bytes(blake3::derive_key(
        "hippius-mem local blob cache v1",
        team_key.expose_bytes(),
    ))
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
    const AAD: &[u8] = b"team/global/mem_01J/ver_1";

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

    /// A blob `seal` produced under hippius-mem 0.5.0 (chacha20poly1305 0.10),
    /// key `[0x42; 32]`, plaintext `RELEASE_PLAINTEXT`, AAD `AAD`. Every note,
    /// snapshot and cache entry already in a bucket has this layout
    /// (`nonce ‖ ciphertext+tag`), so a cipher upgrade that cannot open it would
    /// strand existing vaults.
    const RELEASE_0_5_0_BLOB: &str = "04520495dd13931b2c204883ef9d36b2e0bb8392981bef2d\
        4b0b4fba3f6a4c9f982c30e157a6f04adbbeb62963f31ba0406fe08d249fc58d09a460e65277bbcc\
        45d80a33421c9652";
    const RELEASE_PLAINTEXT: &[u8] = b"note sealed by hippius-mem 0.5.0";

    #[test]
    fn opens_a_blob_sealed_by_release_0_5_0() -> Result<(), Box<dyn std::error::Error>> {
        let key = SecretKey::from_bytes([0x42; 32]);
        let blob = crate::hex::decode(RELEASE_0_5_0_BLOB)?;

        assert_eq!(open(&key, &blob, AAD)?, RELEASE_PLAINTEXT);
        Ok(())
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

    // Compiles only while the cipher wipes its copy of the key on drop.
    // chacha20poly1305 0.11 made that opt-in (the `zeroize` feature), and an
    // upgrade that silently lost it would leave the team key in freed memory
    // after every seal and open.
    const _: fn() = || {
        fn wipes_key_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wipes_key_on_drop::<XChaCha20Poly1305>();
    };

    #[test]
    fn short_blob_is_crypto_error_not_panic() {
        let key = SecretKey::from_bytes([0u8; 32]);
        assert!(matches!(open(&key, &[0u8; 5], AAD), Err(MemError::Crypto)));
    }

    #[test]
    fn sub_tag_ciphertext_is_crypto_error_not_panic() {
        // The window `open`'s `split_first_chunk` length check does NOT cover: a
        // blob of length in [NONCE_LEN, NONCE_LEN + 16) splits into a full nonce
        // and reaches chacha20poly1305's `decrypt` with a ciphertext slice shorter
        // than the 16-byte Poly1305 tag. Per the RustCrypto `aead` contract,
        // `decrypt` returns Err (never panics) for an input too short to contain
        // its tag; these are the exact attacker-controlled lengths the existing
        // 5-byte test (which fails the split) never exercises.
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
    fn derive_cache_key_differs_from_team_key_and_is_deterministic() {
        // Both properties here are trivially true of any KDF that is not the
        // identity function and is pure: "differs from its own input" and
        // "deterministic" cannot fail for an interesting reason, and are kept
        // only as documentation of the API contract. The actual
        // domain-separation claim -- that derive_cache_key's output does not
        // collide with any OTHER derivation over the identical input bytes --
        // is asserted in
        // `identity::teamkey::tests::derive_cache_key_does_not_collide_with_derive_aead_key_on_the_same_input`,
        // which lives there because `derive_aead_key` (the only other same-shaped
        // KDF in this crate: a bare 32-byte secret plus a domain tag in, a new
        // 32-byte secret out) is private to that module.
        let team_key = SecretKey::from_bytes([42u8; 32]);
        let cache_key = derive_cache_key(&team_key);
        assert_ne!(cache_key.expose_bytes(), team_key.expose_bytes());

        let cache_key_again = derive_cache_key(&SecretKey::from_bytes([42u8; 32]));
        assert_eq!(cache_key.expose_bytes(), cache_key_again.expose_bytes());
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
