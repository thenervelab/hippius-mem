//! The op-log [`Op`] record: a cryptographically signed, hash-chained memory
//! mutation, plus the sr25519 signing seam ([`Signer`], [`Sr25519Signer`],
//! [`verify`]).
//!
//! # Why this exists
//!
//! Phase 2 turns every memory mutation into an append-only, tamper-evident
//! operation. An [`Op`] binds *who* (`author_key`), *what* ([`OpKind`] +
//! `note_id` / `object_key` / `cid`), and *when in causal order* (`lamport`)
//! together under one sr25519 signature, and links to its predecessor by
//! `prev_op_hash`. Verifying a chain therefore proves both attribution (the
//! signature) and integrity (the hash links).
//!
//! # Canonical bytes and the chain link
//!
//! Two byte definitions are load-bearing and documented at their sites:
//! [`Op::signing_bytes`] (the bytes that are signed and verified) and
//! [`Op::hash`] (the value the *next* op stores in its `prev_op_hash`). Both are
//! deterministic and host-independent so signatures and chains agree across
//! machines.

use std::fmt;

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{Blake3Hash, NoteId, Ss58, content_hash};

/// The domain-separation tag prefixed onto [`Op::signing_bytes`].
///
/// Ties the canonical bytes to *this* record shape and version, so a signature
/// produced here can never be replayed as a different length-framed message.
const SIGNING_DOMAIN: &[u8] = b"hippius-memory-op/v1";

/// The schnorrkel signing context shared by [`Sr25519Signer::sign`] and
/// [`verify`].
///
/// sr25519 binds the signature to this context string; **sign and verify must
/// use the identical context** or every verification fails. Keep it fixed.
const SIGNING_CONTEXT: &[u8] = b"hippius-memory-oplog";

/// An sr25519 public key (32 bytes): the cryptographic identity a signature is
/// verified against.
///
/// Serializes as a 64-character lowercase hex string, matching [`Blake3Hash`]'s
/// canonical wire form. Any 32 bytes are a representationally valid key; an
/// actually-invalid curve point is rejected later by [`verify`] (which returns
/// `false`), not at construction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    /// Wrap raw public-key bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32 key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// This key as a 64-character lowercase hex string.
    ///
    /// The same canonical form the serde impl emits; used to namespace per-author
    /// object keys (e.g. anchor records) so two authors never collide on a key.
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl Serialize for VerifyingKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        decode_hex::<32>(&s)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// An sr25519 signature (64 bytes) over [`Op::signing_bytes`].
///
/// Serializes as a 128-character lowercase hex string. [`Debug`] is hand-written
/// to print only a short hex prefix: a signature is not secret, but a full
/// 64-byte dump bloats logs and test output for no benefit.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wrap raw signature bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 64 signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted-by-brevity: show only an 8-hex-char prefix so two signatures
        // are still distinguishable in output without dumping all 64 bytes.
        let hex = encode_hex(&self.0);
        write!(f, "Signature({}…)", &hex[..8])
    }
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        decode_hex::<64>(&s)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// The kind of memory mutation an [`Op`] records.
///
/// # Wire shape
///
/// Internally tagged via `#[serde(tag = "kind")]` (serde axiom
/// `rust_quality_115`: the tagging representation is part of the wire contract).
/// Unit variants serialize as `{"kind":"Remember"}`; [`OpKind::Link`] adds its
/// field: `{"kind":"Link","to":"mem_…"}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum OpKind {
    /// A new note was created.
    Remember,
    /// An existing note's body was replaced (a new ciphertext blob).
    Edit,
    /// A note was tombstoned (logically deleted).
    Forget,
    /// A directed relationship was asserted from this note to another.
    Link {
        /// The note this op's `note_id` now links to.
        to: NoteId,
    },
}

/// The signable content of an [`Op`] — every field except the author identity
/// (filled from the [`Signer`]) and the signature.
///
/// Grouped into one parameter object rather than passed as eight positional
/// arguments to [`Op::create_signed`]: it keeps the call within the project's
/// positional-parameter limit and, crucially, names `cid` and `prev_op_hash`
/// (both [`Blake3Hash`]) so they cannot be silently swapped at a call site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpContent {
    /// Unique, time-sortable id for this operation.
    pub op_id: Ulid,
    /// Lamport clock value establishing causal order across writers.
    pub lamport: u64,
    /// What this operation does.
    pub kind: OpKind,
    /// The note this operation acts on.
    pub note_id: NoteId,
    /// The object-store key of the note's ciphertext blob.
    pub object_key: String,
    /// BLAKE3 digest of the note's ciphertext at this operation.
    pub cid: Blake3Hash,
    /// The [`Op::hash`] of the predecessor op (a zero hash for a chain root).
    pub prev_op_hash: Blake3Hash,
}

/// One signed, hash-chained entry in the op-log.
///
/// Fields are public because an `Op` is a data record consumed by later layers
/// (the op-log store, convergence, the `history` tool) and by deserialization;
/// its integrity is guaranteed by [`Op::verify_sig`], not by private fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    /// Unique, time-sortable id for this operation.
    pub op_id: Ulid,
    /// Human-facing SS58 address of the author.
    ///
    /// `author` (display) and `author_key` (crypto) are kept separate on
    /// purpose: this task verifies against `author_key` directly. Checking that
    /// `author` and `author_key` are consistent (SS58 ↔ key) is Phase 3 identity
    /// work.
    pub author: Ss58,
    /// The sr25519 public key the signature is verified against.
    pub author_key: VerifyingKey,
    /// Lamport clock value establishing causal order across writers.
    pub lamport: u64,
    /// What this operation does.
    pub kind: OpKind,
    /// The note this operation acts on.
    pub note_id: NoteId,
    /// The object-store key of the note's ciphertext blob.
    pub object_key: String,
    /// BLAKE3 digest of the note's ciphertext at this operation.
    pub cid: Blake3Hash,
    /// The [`Op::hash`] of the predecessor op (a zero hash for a chain root).
    pub prev_op_hash: Blake3Hash,
    /// sr25519 signature over [`Op::signing_bytes`].
    pub sig: Signature,
}

impl Op {
    /// The exact bytes that are signed and verified.
    ///
    /// A domain-tagged, length-framed concatenation of every field **except**
    /// `sig`. Hand-built rather than `serde_json` so it is total (no fallible
    /// serialization step), and host-independent: each variable-length field is
    /// prefixed with a fixed 8-byte little-endian length (see [`push_framed`])
    /// and fixed-width fields are emitted verbatim, so the bytes — and thus the
    /// signature — agree across 32- and 64-bit machines.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(SIGNING_DOMAIN);
        push_framed(&mut buf, self.op_id.to_string().as_bytes());
        push_framed(&mut buf, self.author.as_str().as_bytes());
        buf.extend_from_slice(self.author_key.as_bytes());
        buf.extend_from_slice(&self.lamport.to_le_bytes());
        push_op_kind(&mut buf, &self.kind);
        push_framed(&mut buf, self.note_id.to_string().as_bytes());
        push_framed(&mut buf, self.object_key.as_bytes());
        buf.extend_from_slice(self.cid.as_bytes());
        buf.extend_from_slice(self.prev_op_hash.as_bytes());
        buf
    }

    /// The chain link value: BLAKE3 over [`Op::signing_bytes`] followed by the
    /// 64 signature bytes.
    ///
    /// Including `sig` means the link commits to the signature too, so the next
    /// op's `prev_op_hash` pins this op in full. The successor stores this value
    /// in its own `prev_op_hash`.
    #[must_use]
    pub fn hash(&self) -> Blake3Hash {
        let mut buf = self.signing_bytes();
        buf.extend_from_slice(self.sig.as_bytes());
        content_hash(&buf)
    }

    /// Build an [`Op`] signed by `signer`.
    ///
    /// Fills `author` / `author_key` from the signer, computes
    /// [`Op::signing_bytes`], and signs them. `sig` is the only field not taken
    /// from `content`.
    ///
    /// `S: ?Sized` so a `&dyn Signer` (the store holds its signer behind an
    /// `Arc<dyn Signer>`) is accepted as readily as a concrete signer; every
    /// method called on it is object-safe.
    #[must_use]
    pub fn create_signed<S: Signer + ?Sized>(signer: &S, content: OpContent) -> Self {
        let mut op = Self {
            op_id: content.op_id,
            author: signer.author_ss58(),
            author_key: signer.verifying_key(),
            lamport: content.lamport,
            kind: content.kind,
            note_id: content.note_id,
            object_key: content.object_key,
            cid: content.cid,
            prev_op_hash: content.prev_op_hash,
            // Placeholder: `signing_bytes` excludes `sig`, so its value here
            // does not affect the message that gets signed.
            sig: Signature([0u8; 64]),
        };
        let msg = op.signing_bytes();
        op.sig = signer.sign(&msg);
        op
    }

    /// Verify this op's signature against its own `author_key`.
    #[must_use]
    pub fn verify_sig(&self) -> bool {
        verify(&self.author_key, &self.signing_bytes(), &self.sig)
    }
}

/// Append a variable-length field, length-prefixed with a fixed 8-byte u64 (LE).
///
/// The fixed width is deliberate: `usize::to_le_bytes` is 8 bytes on 64-bit and
/// 4 on 32-bit hosts, which would make the canonical bytes — and the signature
/// over them — disagree across platforms. `try_from` cannot realistically fail
/// (no in-memory slice exceeds `u64::MAX` bytes); the saturating fallback keeps
/// the function total without `unwrap`/`panic` (denied by crate lints).
fn push_framed(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Append an [`OpKind`] as a 1-byte discriminant plus, for [`OpKind::Link`], the
/// framed target id. Deterministic and exhaustive (a new variant forces a
/// compile error here).
fn push_op_kind(buf: &mut Vec<u8>, kind: &OpKind) {
    match kind {
        OpKind::Remember => buf.push(0),
        OpKind::Edit => buf.push(1),
        OpKind::Forget => buf.push(2),
        OpKind::Link { to } => {
            buf.push(3);
            push_framed(buf, to.to_string().as_bytes());
        }
    }
}

/// The signing seam: anything that can sign op bytes and name its identity.
///
/// `Send + Sync` so a signer can be shared across the async store. The trait is
/// deliberately narrow (it knows nothing about [`Op`]) so alternative key
/// backends (HSM, remote signer) can implement it later.
pub trait Signer: Send + Sync {
    /// Sign `msg` with this identity's secret key.
    fn sign(&self, msg: &[u8]) -> Signature;
    /// This identity's public key, for verification.
    fn verifying_key(&self) -> VerifyingKey;
    /// This identity's human-facing SS58 address.
    fn author_ss58(&self) -> Ss58;
}

/// Verify `sig` over `msg` for `key`, using the fixed [`SIGNING_CONTEXT`].
///
/// Returns `false` for any failure, including a `key` or `sig` whose bytes are
/// not a valid curve point / signature — verification simply does not pass.
/// **The context must match the one used to sign** or this always returns
/// `false`.
#[must_use]
pub fn verify(key: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    let Ok(public) = schnorrkel::PublicKey::from_bytes(key.as_bytes()) else {
        return false;
    };
    let Ok(signature) = schnorrkel::Signature::from_bytes(sig.as_bytes()) else {
        return false;
    };
    let ctx = schnorrkel::signing_context(SIGNING_CONTEXT);
    public.verify(ctx.bytes(msg), &signature).is_ok()
}

/// A 32-byte seed could not be expanded into an sr25519 keypair.
///
/// In practice unreachable for a fixed `[u8; 32]` (schnorrkel only rejects a
/// wrong *length*), but [`schnorrkel::MiniSecretKey::from_bytes`] is fallible,
/// so the failure is surfaced honestly rather than unwrapped.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("seed is not a valid sr25519 mini secret key")]
#[non_exhaustive]
pub struct InvalidSeed;

/// An sr25519 [`Signer`] built from a 32-byte seed.
pub struct Sr25519Signer {
    keypair: schnorrkel::Keypair,
    author: Ss58,
}

impl Sr25519Signer {
    /// Expand `seed` into an sr25519 keypair and pair it with `author`.
    ///
    /// Uses `ExpansionMode::Ed25519` to match Substrate, whose sr25519 keys are
    /// derived this way — so a key minted here is compatible with the wider
    /// Hippius/Substrate tooling. (Deriving `author` from the key is Phase 3;
    /// here it is supplied.)
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSeed`] if schnorrkel rejects the seed.
    pub fn from_seed(seed: [u8; 32], author: Ss58) -> Result<Self, InvalidSeed> {
        let mini = schnorrkel::MiniSecretKey::from_bytes(&seed).map_err(|_| InvalidSeed)?;
        let keypair = mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
        Ok(Self { keypair, author })
    }
}

impl fmt::Debug for Sr25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret half: show only the public key and address.
        f.debug_struct("Sr25519Signer")
            .field("public", &VerifyingKey(self.keypair.public.to_bytes()))
            .field("author", &self.author)
            .finish()
    }
}

impl Signer for Sr25519Signer {
    fn sign(&self, msg: &[u8]) -> Signature {
        let ctx = schnorrkel::signing_context(SIGNING_CONTEXT);
        Signature(self.keypair.sign(ctx.bytes(msg)).to_bytes())
    }

    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.keypair.public.to_bytes())
    }

    fn author_ss58(&self) -> Ss58 {
        self.author.clone()
    }
}

/// Errors when decoding a fixed-width lowercase-hex string.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HexError {
    /// The string length was not twice the expected byte count.
    #[error("hex length {actual} is not the expected {expected}")]
    BadLength {
        /// The required character count (`2 * N`).
        expected: usize,
        /// The length actually seen.
        actual: usize,
    },
    /// A character outside `0-9a-f` was present (uppercase is rejected to keep
    /// one canonical form).
    #[error("hex contains non-lowercase-hex character `{ch}`")]
    IllegalDigit {
        /// The first offending character.
        ch: char,
    },
}

/// Encode `bytes` as a `2*N`-character lowercase hex string.
fn encode_hex<const N: usize>(bytes: &[u8; N]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(N * 2);
    for &byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

/// Decode a `2*N`-character lowercase-hex string into `N` bytes.
///
/// # Errors
///
/// [`HexError::BadLength`] if the length is not `2*N`, [`HexError::IllegalDigit`]
/// for any character outside `0-9a-f`.
fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    let raw = s.as_bytes();
    if raw.len() != N * 2 {
        return Err(HexError::BadLength {
            expected: N * 2,
            actual: raw.len(),
        });
    }
    let mut bytes = [0u8; N];
    for (slot, pair) in bytes.iter_mut().zip(raw.chunks_exact(2)) {
        *slot = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(bytes)
}

/// Decode one lowercase-hex byte into its `0..=15` nibble value.
fn hex_nibble(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(HexError::IllegalDigit { ch: char::from(c) }),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;

    use super::{
        HexError, Op, OpContent, OpKind, Signature, Signer, Sr25519Signer, VerifyingKey,
        decode_hex, encode_hex, verify,
    };
    use crate::{Blake3Hash, NoteId, Ss58, content_hash};
    use ulid::Ulid;

    /// Tests return `Result` and use `?` for fallible fixtures: a fixture
    /// failure surfaces as a test error without tripping the crate's
    /// panic-prevention lints.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Adapt a fallible fixture call into proptest's error type (proptest
    /// closures cannot use `?` on arbitrary errors directly).
    fn tce(e: impl std::fmt::Display) -> TestCaseError {
        TestCaseError::fail(e.to_string())
    }

    // Panic-free assertions: the crate denies `panic_in_result_fn`, so these
    // `Result`-returning tests report failures by returning `Err` rather than
    // via `assert!`/`assert_eq!` (which expand to panics).
    fn ensure(cond: bool, msg: &str) -> TestResult {
        if cond { Ok(()) } else { Err(msg.into()) }
    }

    fn ensure_eq<T: PartialEq + std::fmt::Debug>(left: &T, right: &T, msg: &str) -> TestResult {
        if left == right {
            Ok(())
        } else {
            Err(format!("{msg}: {left:?} != {right:?}").into())
        }
    }

    fn ensure_ne<T: PartialEq + std::fmt::Debug>(left: &T, right: &T, msg: &str) -> TestResult {
        if left == right {
            Err(format!("{msg}: both equal {left:?}").into())
        } else {
            Ok(())
        }
    }

    // A valid SS58 v42 address (Alice), 48 base58 chars — passes `Ss58::new`.
    const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        let author = Ss58::new(ALICE_SS58)?;
        Ok(Sr25519Signer::from_seed([seed; 32], author)?)
    }

    fn content(prev: Blake3Hash) -> OpContent {
        OpContent {
            op_id: Ulid::from(1u128),
            lamport: 7,
            kind: OpKind::Remember,
            note_id: NoteId::from(Ulid::from(2u128)),
            object_key: "team/global/notes/abc".to_string(),
            cid: content_hash(b"ciphertext-bytes"),
            prev_op_hash: prev,
        }
    }

    fn root() -> Blake3Hash {
        Blake3Hash::new([0u8; 32])
    }

    #[test]
    fn sign_verify_round_trips() -> TestResult {
        let s = signer(7)?;
        let op = Op::create_signed(&s, content(root()));
        ensure(op.verify_sig(), "a freshly signed op must verify")
    }

    proptest! {
        #[test]
        fn raw_sign_verify_round_trips(msg in prop::collection::vec(any::<u8>(), 0..256)) {
            let s = signer(9).map_err(tce)?;
            let sig = s.sign(&msg);
            prop_assert!(verify(&s.verifying_key(), &msg, &sig));
        }
    }

    #[test]
    fn tampered_op_fails_verification() -> TestResult {
        let s = signer(7)?;
        let op = Op::create_signed(&s, content(root()));
        // Same signature, one field changed: signing_bytes no longer match.
        let mut tampered = op.clone();
        tampered.lamport = op.lamport.wrapping_add(1);
        ensure(
            !tampered.verify_sig(),
            "mutating a signed field must break verification",
        )?;

        let mut retargeted = op.clone();
        retargeted.note_id = NoteId::from(Ulid::from(999u128));
        ensure(
            !retargeted.verify_sig(),
            "changing note_id must break verification",
        )
    }

    #[test]
    fn wrong_key_fails_verification() -> TestResult {
        let op = Op::create_signed(&signer(7)?, content(root()));
        let other = signer(8)?;
        ensure(
            !verify(&other.verifying_key(), &op.signing_bytes(), &op.sig),
            "a signature must not verify under a different key",
        )
    }

    #[test]
    fn hash_is_deterministic_and_chain_sensitive() -> TestResult {
        let op = Op::create_signed(&signer(7)?, content(root()));
        ensure_eq(
            &op.hash(),
            &op.hash(),
            "hash must be a pure function of the op",
        )?;

        let mut changed = op.clone();
        changed.lamport = op.lamport.wrapping_add(1);
        ensure_ne(
            &op.hash(),
            &changed.hash(),
            "a one-field change must change the hash",
        )
    }

    #[test]
    fn verifying_key_and_signature_hex_round_trip() -> TestResult {
        let s = signer(7)?;
        let vk = s.verifying_key();
        let json = serde_json::to_string(&vk)?;
        // 32 bytes -> 64 hex chars, plus the two JSON quotes.
        ensure(json.len() == 66, "vk hex must be 64 chars + quotes")?;
        let back: VerifyingKey = serde_json::from_str(&json)?;
        ensure_eq(&vk, &back, "vk must survive a hex round-trip")?;

        let sig = s.sign(b"message");
        let json = serde_json::to_string(&sig)?;
        ensure(json.len() == 130, "sig hex must be 128 chars + quotes")?;
        let back: Signature = serde_json::from_str(&json)?;
        ensure_eq(&sig, &back, "signature must survive a hex round-trip")
    }

    #[test]
    fn decode_hex_rejects_bad_length_and_uppercase() {
        assert!(matches!(
            decode_hex::<32>("abcd"),
            Err(HexError::BadLength {
                expected: 64,
                actual: 4
            })
        ));
        let mut upper = encode_hex(&[0xABu8; 32]);
        upper.make_ascii_uppercase();
        assert!(matches!(
            decode_hex::<32>(&upper),
            Err(HexError::IllegalDigit { .. })
        ));
    }

    proptest! {
        #[test]
        fn verifying_key_hex_round_trips(bytes in prop::array::uniform32(any::<u8>())) {
            let vk = VerifyingKey::new(bytes);
            let json = serde_json::to_string(&vk).map_err(tce)?;
            let back: VerifyingKey = serde_json::from_str(&json).map_err(tce)?;
            prop_assert_eq!(vk, back);
        }

        #[test]
        fn signature_hex_round_trips(
            lo in prop::array::uniform32(any::<u8>()),
            hi in prop::array::uniform32(any::<u8>()),
        ) {
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&lo);
            bytes[32..].copy_from_slice(&hi);
            let sig = Signature::new(bytes);
            let json = serde_json::to_string(&sig).map_err(tce)?;
            let back: Signature = serde_json::from_str(&json).map_err(tce)?;
            prop_assert_eq!(sig, back);
        }

        // Pure-function round-trip on the const-generic hex codec itself.
        #[test]
        fn hex_codec_round_trips(bytes in prop::array::uniform32(any::<u8>())) {
            let decoded = decode_hex::<32>(&encode_hex(&bytes)).map_err(tce)?;
            prop_assert_eq!(decoded, bytes);
        }
    }
}
