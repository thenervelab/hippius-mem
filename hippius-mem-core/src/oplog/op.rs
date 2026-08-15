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

use crate::{Blake3Hash, MemError, NetworkPrefix, NoteId, Ss58, content_hash};

/// The domain-separation tag prefixed onto [`Op::signing_bytes`].
///
/// Ties the canonical bytes to *this* record shape and version, so a signature
/// produced here can never be replayed as a different length-framed message.
/// Bumped `/v1`→`/v2` when `key_epoch` joined the signed fields: no op bytes are
/// persisted across the change, so the version bump is purely defensive — a `/v1`
/// signature (over the shorter field set) can never be confused with a `/v2` one.
pub(crate) const SIGNING_DOMAIN: &[u8] = b"hippius-memory-op/v2";

/// The schnorrkel signing context shared by [`Sr25519Signer::sign`] and
/// [`verify`].
///
/// sr25519 binds the signature to this context string; **sign and verify must
/// use the identical context** or every verification fails. Keep it fixed.
///
/// This one context is shared by EVERY signed type in the crate — [`Op`],
/// [`crate::TeamManifest`], and [`crate::MemberKey`] all sign and verify through
/// [`verify`]/[`Sr25519Signer::sign`]. Cross-type non-interchangeability does NOT
/// rest on the context: it rests on each type prefixing a UNIQUE domain tag onto
/// its `signing_bytes` ([`SIGNING_DOMAIN`] `hippius-memory-op/v2`,
/// `MANIFEST_DOMAIN` `hippius-memory-manifest/v1`, `MEMBERKEY_DOMAIN`
/// `hippius-memory-memberkey-v1`). Because the signed MESSAGES differ in their
/// leading bytes, a signature minted for one type can never verify as another,
/// so a per-type context would be redundant. The `cross_type_signature_does_not_verify`
/// test pins that property; do not remove a domain prefix without replacing it
/// with a distinct context here.
const SIGNING_CONTEXT: &[u8] = b"hippius-memory-oplog";

/// The SS58 network prefix Hippius identities use (generic Substrate / Bittensor).
///
/// [`Op::verify_identity`] requires the `author` address to decode under exactly
/// this prefix: membership is matched on the SS58 *string*, so the same key
/// encoded under a different network prefix is a different string and would
/// silently fall outside the team. Pinning the prefix rejects that op up front.
///
/// `pub(super)` so [`crate::oplog::HeadPointer::verify_identity`] can mirror that
/// check against the SAME constant instead of restating the convention — two
/// independently-written prefix pins could drift apart, and the weaker one would
/// then admit an address the other rejects.
pub(super) const HIPPIUS_SS58_PREFIX: NetworkPrefix = NetworkPrefix::HIPPIUS;

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

    /// Whether this is the Ristretto **identity point** (32 zero bytes) — the one
    /// public key that authenticates nobody.
    ///
    /// schnorrkel accepts the all-zero encoding as a public key, and with the
    /// identity as the public key `A` the Schnorr verification equation
    /// `R == s*G - c*A` collapses to `R == s*G`, which `s = 0` satisfies for ANY
    /// message. A signature anyone can type out therefore "verifies" under it,
    /// with no key material ever involved — an authentication bypass at every
    /// site that treats a passing signature as proof of identity. No signer can
    /// ever legitimately hold it: it corresponds to the private scalar zero, which
    /// [`Sr25519Signer`] cannot produce.
    ///
    /// [`verify`] rejects it for exactly that reason, so every verification site
    /// in this crate is covered by construction. This predicate is public so
    /// authorization layers that treat a key as a *trust root* — the manifest
    /// chain-of-custody election, which lets a named `recovery_key` transfer
    /// control of a team — can screen it explicitly rather than relying on that
    /// single choke point.
    ///
    /// Ristretto is a prime-order group with canonical encodings, so the identity
    /// has exactly one valid byte string and no cofactor family of equivalents:
    /// this single comparison is both sufficient and complete.
    #[must_use]
    pub fn is_identity_point(&self) -> bool {
        self.0 == [0u8; 32]
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

/// The typed relationship one note asserts over another via [`OpKind::Relate`].
///
/// A named relation, not a bool, so a call site and the wire form both read as
/// intent (`LinkRel::Supersedes`, not `true`). `#[non_exhaustive]` reserves room
/// for future relations without a breaking change; every exhaustive match must
/// already carry a wildcard arm.
///
/// # Recall effect
///
/// `Supersedes` and `Duplicates` demote the *target* note in recall (it is still
/// returned, tagged — never dropped, so the decision trail stays auditable).
/// `Contradicts` flags both notes as in tension (no demotion). `Refines` tags
/// the target as refined (no demotion). `Related` is a plain link with no
/// ranking effect — it is emitted as the legacy [`OpKind::Link`] op, not
/// `Relate`, so `Relate` always carries a ranking-relevant relation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum LinkRel {
    /// A plain, untyped relationship (the default). No recall effect.
    #[default]
    Related,
    /// This note replaces the target: a stale decision the target's author or a
    /// teammate has rescinded. Demotes the target in recall.
    Supersedes,
    /// This note and the target are in tension. Tags both (no demotion) so a
    /// reader sees the conflict rather than silently trusting one.
    Contradicts,
    /// This note refines (extends/sharpens) the target without replacing it. Tags
    /// the target as refined (no demotion).
    Refines,
    /// The target is a duplicate of this note. Demotes the target in recall, like
    /// `Supersedes`, but names the reason.
    Duplicates,
}

impl LinkRel {
    /// The 1-byte wire tag mixed into [`Op::signing_bytes`]. Assigned explicitly
    /// (not by declaration order) so a value can never shift the signed bytes of
    /// a previously-signed op; add new relations with a fresh, never-reused byte.
    #[must_use]
    pub fn wire_tag(self) -> u8 {
        match self {
            LinkRel::Related => 0,
            LinkRel::Supersedes => 1,
            LinkRel::Contradicts => 2,
            LinkRel::Refines => 3,
            LinkRel::Duplicates => 4,
        }
    }

    /// Whether this relation demotes its target in recall ([`LinkRel::Supersedes`]
    /// / [`LinkRel::Duplicates`]). Central so the ranking rule lives in one place.
    #[must_use]
    pub fn demotes_target(self) -> bool {
        matches!(self, LinkRel::Supersedes | LinkRel::Duplicates)
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
    /// A note's content was permanently scrubbed: every ciphertext version is
    /// deleted from storage, but this signed op — and its anchored Merkle leaf —
    /// remain, so the redaction itself stays provable. Unlike [`OpKind::Forget`],
    /// redaction is **absorbing**: convergence never lets a later op resurrect a
    /// redacted note (the content is physically gone), so a redacted note is the
    /// terminal state regardless of Lamport order. Used for leaked-secret / PII
    /// erasure where a tombstone (which keeps the blob) is not enough.
    Redact,
    /// A directed relationship was asserted from this note to another.
    Link {
        /// The note this op's `note_id` now links to.
        to: NoteId,
    },
    /// A *typed* directed relationship (supersede / contradict / refine /
    /// duplicate) from this note to another. Distinct from [`OpKind::Link`] so the
    /// latter's signed bytes stay unchanged for every op written before typed
    /// relations existed; a plain [`LinkRel::Related`] is still emitted as `Link`.
    Relate {
        /// The note this op's `note_id` relates to.
        to: NoteId,
        /// How this note relates to `to`.
        rel: LinkRel,
    },
    /// A usage signal: this op's `author` reinforced this op's `note_id` (it
    /// proved useful on a `recall`-then-`get`). Carries no payload — the note and
    /// the reinforcing identity are the op's own `note_id` and `author`. Distinct
    /// discriminant so it is append-only; convergence counts DISTINCT authors
    /// (a [`BTreeSet`] of `author`), so a single agent re-reinforcing cannot
    /// inflate a note's strength (Sybil bound). The reinforce TIME is read from
    /// `op_id`'s ULID timestamp, so no new signed field is needed.
    Reinforce,
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
    /// Which team-key epoch sealed the ciphertext this op names.
    ///
    /// Recorded so a reader can pick the right key from the store's key-ring
    /// after team-key rotation: a pre-rotation note stays readable because its
    /// op remembers the epoch it was sealed under. Signed (part of
    /// [`Op::signing_bytes`]) so it is tamper-evident like every other field.
    pub key_epoch: u64,
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
    /// `author` (display) and `author_key` (crypto) are bound: [`Op::verify_identity`]
    /// requires `author` to decode to exactly `author_key`, and the op-log read path
    /// rejects any op where it does not. Attribution is therefore cryptographic — a
    /// writer cannot sign with one key and claim another identity's SS58.
    pub author: Ss58,
    /// The sr25519 public key the signature is verified against.
    pub author_key: VerifyingKey,
    /// Lamport clock value establishing causal order across writers.
    pub lamport: u64,
    /// Which team-key epoch sealed the ciphertext this op names (see
    /// [`OpContent::key_epoch`]). Signed, so a rotation cannot be spoofed.
    pub key_epoch: u64,
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
        buf.extend_from_slice(&self.key_epoch.to_le_bytes());

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
            key_epoch: content.key_epoch,
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

    /// Verify the human SS58 label is cryptographically bound to the signing key:
    /// `author` must decode to exactly `author_key`.
    ///
    /// This is what makes attribution cryptographic rather than self-asserted.
    /// [`Op::verify_sig`] proves the bytes were signed by `author_key`; this proves
    /// `author_key` is the identity `author` names — so a writer cannot sign with one
    /// key and claim another's SS58. The decoded network prefix must also be
    /// [`HIPPIUS_SS58_PREFIX`]: membership is matched on the SS58 string, so the
    /// same key under a different prefix is a different string that would silently
    /// fall outside the team — reject it here instead. A malformed `author`, a
    /// wrong-key `author`, or a non-Hippius prefix all yield `false` (the
    /// [`crate::identity::ss58_decode`] error is collapsed to a failed check).
    #[must_use]
    pub fn verify_identity(&self) -> bool {
        crate::identity::ss58_decode(&self.author)
            .is_ok_and(|(key, prefix)| key == self.author_key && prefix == HIPPIUS_SS58_PREFIX)
    }
}

use crate::framing::push_framed;

/// Append an [`OpKind`] as a 1-byte discriminant plus, for [`OpKind::Link`], the
/// framed target id. Deterministic and exhaustive (a new variant forces a
/// compile error here).
fn push_op_kind(buf: &mut Vec<u8>, kind: &OpKind) {
    match kind {
        OpKind::Remember => buf.push(0),
        OpKind::Edit => buf.push(1),
        OpKind::Forget => buf.push(2),
        // `Link` keeps discriminant 3 and `Redact` takes 4 (not insertion order):
        // the discriminant is the signed wire tag, so a previously-signed Link op
        // must still hash to the same bytes after `Redact` was added above it.
        OpKind::Link { to } => {
            buf.push(3);
            push_framed(buf, to.to_string().as_bytes());
        }
        OpKind::Redact => buf.push(4),
        // Discriminant 5, then the framed target and the relation's 1-byte tag.
        // A fresh discriminant (not a new field on `Link`) is what keeps every
        // pre-existing `Link` op hashing to the same bytes.
        OpKind::Relate { to, rel } => {
            buf.push(5);
            push_framed(buf, to.to_string().as_bytes());
            buf.push(rel.wire_tag());
        }
        // Discriminant 6, no payload: the reinforced note and reinforcing identity
        // are the op's own `note_id`/`author`, already in the signed frame around
        // this tag. Append-only, so every pre-existing op still hashes unchanged.
        OpKind::Reinforce => buf.push(6),
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
///
/// The [identity point](VerifyingKey::is_identity_point) is rejected up front,
/// before schnorrkel is consulted at all. schnorrkel would *accept* it: the
/// verification equation degenerates so that a signature anyone can type out
/// passes for any message, making it an authentication bypass rather than a
/// weak key. Screening it in this one function covers every present and future
/// caller — ops, member keys, and manifests all verify through here — and no
/// legitimate signer can produce that key, so nothing valid is refused.
#[must_use]
pub fn verify(key: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    if key.is_identity_point() {
        return false;
    }

    let Ok(public) = schnorrkel::PublicKey::from_bytes(key.as_bytes()) else {
        return false;
    };
    let Ok(signature) = schnorrkel::Signature::from_bytes(sig.as_bytes()) else {
        return false;
    };
    let ctx = schnorrkel::signing_context(SIGNING_CONTEXT);
    public.verify(ctx.bytes(msg), &signature).is_ok()
}

/// An sr25519 [`Signer`] built from a 32-byte seed.
///
/// Its `author` SS58 is always derived from its own key (see
/// [`Sr25519Signer::from_seed_with_prefix`]), so the two cannot disagree — there
/// is no constructor that accepts a caller-supplied, mismatchable address.
pub struct Sr25519Signer {
    keypair: schnorrkel::Keypair,
    author: Ss58,
}

impl Sr25519Signer {
    /// Expand `seed` into an sr25519 keypair and derive its `author` SS58 from the
    /// resulting public key under network `prefix` ([`NetworkPrefix::HIPPIUS`] for
    /// Hippius / Substrate).
    ///
    /// Deriving the address from the key is the binding guarantee: the signer's
    /// `author_ss58` always decodes back to its `verifying_key`, so an op minted by
    /// it passes [`Op::verify_identity`] by construction. Uses
    /// `ExpansionMode::Ed25519` to match Substrate, so a key minted here is
    /// compatible with the wider Hippius/Substrate tooling.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Identity`] if schnorrkel rejects the seed (in practice
    /// unreachable for a fixed `&[u8; 32]`, which is only ever a length error, but
    /// [`schnorrkel::MiniSecretKey::from_bytes`] is fallible so the failure is
    /// surfaced honestly rather than unwrapped).
    //
    // Borrows the seed rather than taking it by value: the function only reads it
    // (`from_bytes` wants `&[u8]`) and never stores it, so a by-value `[u8; 32]`
    // would force callers holding secret seed material to drop an un-zeroized
    // `Copy` onto this stack frame for no reason.
    pub fn from_seed_with_prefix(seed: &[u8; 32], prefix: NetworkPrefix) -> Result<Self, MemError> {
        let mini = schnorrkel::MiniSecretKey::from_bytes(seed)
            .map_err(|_| MemError::Identity("sr25519 seed could not be expanded"))?;
        let keypair = mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
        let verifying_key = VerifyingKey(keypair.public.to_bytes());
        let author = crate::identity::ss58_encode(&verifying_key, prefix);
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
        HexError, LinkRel, Op, OpContent, OpKind, Signature, Signer, Sr25519Signer, VerifyingKey,
        decode_hex, encode_hex, push_framed, verify,
    };
    use crate::NetworkPrefix;
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

    fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        Ok(Sr25519Signer::from_seed_with_prefix(
            &[seed; 32],
            NetworkPrefix::HIPPIUS,
        )?)
    }

    fn content(prev: Blake3Hash) -> OpContent {
        OpContent {
            op_id: Ulid::from(1u128),
            lamport: 7,
            key_epoch: 0,
            kind: OpKind::Remember,
            note_id: NoteId::from(Ulid::from(2u128)),
            object_key: "team/global/notes/abc".to_string(),
            cid: content_hash(b"ciphertext-bytes"),
            prev_op_hash: prev,
        }
    }

    /// `content` with the `kind` swapped, holding every other field fixed so a
    /// test can isolate the kind as the only signed difference.
    fn content_with_kind(prev: Blake3Hash, kind: OpKind) -> OpContent {
        OpContent {
            kind,
            ..content(prev)
        }
    }

    /// Strategy over every [`OpKind`] variant — `Link`/`Relate` targets and the
    /// `Relate` relation vary — so a property genuinely quantifies over the full
    /// kind space. `Relate` matters doubly: it is the only variant mixing a
    /// framed field with a raw trailing byte in `push_op_kind`, so a framing
    /// regression there is invisible to the other six kinds.
    fn op_kind_strategy() -> impl Strategy<Value = OpKind> {
        let rel = prop_oneof![
            Just(LinkRel::Related),
            Just(LinkRel::Supersedes),
            Just(LinkRel::Contradicts),
            Just(LinkRel::Refines),
            Just(LinkRel::Duplicates),
        ];
        prop_oneof![
            Just(OpKind::Remember),
            Just(OpKind::Edit),
            Just(OpKind::Forget),
            Just(OpKind::Redact),
            Just(OpKind::Reinforce),
            any::<u128>().prop_map(|n| OpKind::Link {
                to: NoteId::from(Ulid::from(n))
            }),
            (any::<u128>(), rel).prop_map(|(n, rel)| OpKind::Relate {
                to: NoteId::from(Ulid::from(n)),
                rel,
            }),
        ]
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

    #[test]
    fn signer_from_seed_with_prefix_binds_ss58() -> TestResult {
        // The derived constructor computes the SS58 from its own key, so the two
        // can never disagree — the property a caller-supplied address cannot give.
        let s = Sr25519Signer::from_seed_with_prefix(&[7u8; 32], NetworkPrefix::HIPPIUS)?;
        let derived = crate::identity::ss58_encode(&s.verifying_key(), NetworkPrefix::HIPPIUS);
        ensure_eq(
            &s.author_ss58(),
            &derived,
            "signer ss58 is derived from its key",
        )
    }

    #[test]
    fn op_with_non_hippius_prefix_is_rejected() -> TestResult {
        let s = signer(7)?;
        let op = Op::create_signed(&s, content(root()));
        // Sanity: the genuine op (author under prefix 42) binds author to key.
        ensure(op.verify_identity(), "the genuine op binds author to key")?;

        // Re-encode the SAME key under a different network prefix (0). The address
        // still decodes back to `author_key`, isolating the prefix as the only
        // change — but membership is matched on the SS58 string, so an op carrying
        // a non-Hippius prefix must be rejected by the identity check.
        let mut wrong_prefix = op.clone();
        // Prefix 0 is a valid NetworkPrefix but not Hippius (42), so the address
        // decodes yet verify_identity must still reject the non-Hippius prefix.
        wrong_prefix.author = crate::identity::ss58_encode(&op.author_key, NetworkPrefix::new(0)?);
        ensure(
            !wrong_prefix.verify_identity(),
            "an author encoded under a non-Hippius prefix must be rejected",
        )
    }

    #[test]
    fn every_op_kind_signs_and_verifies() -> TestResult {
        // M10 regression: `push_op_kind` is the canonicalization that makes a
        // signed op's KIND tamper-evident, yet the rest of the suite only ever
        // signs `OpKind::Remember`. Sign and verify one op of each variant so a
        // regression in the discriminant encoding (a variant dropped from the
        // match, or two collapsed) is caught here rather than in production.
        let s = signer(30)?;
        let kinds = [
            OpKind::Remember,
            OpKind::Edit,
            OpKind::Forget,
            OpKind::Redact,
            OpKind::Link {
                to: NoteId::from(Ulid::from(42u128)),
            },
            OpKind::Relate {
                to: NoteId::from(Ulid::from(42u128)),
                rel: LinkRel::Supersedes,
            },
            OpKind::Reinforce,
        ];
        for kind in kinds {
            let op = Op::create_signed(&s, content_with_kind(root(), kind.clone()));
            ensure(
                op.verify_sig(),
                "an op of every kind must verify under its own signature",
            )?;
            ensure_eq(&op.kind, &kind, "the signed op preserves its kind")?;
        }
        Ok(())
    }

    #[test]
    fn op_kind_is_tamper_evident() -> TestResult {
        // The dangerous regression M10 guards: if two kinds signed identical bytes
        // (e.g. Edit and Forget pushing the same discriminant), ONE signature would
        // verify for both — a body-replace op replayable as a tombstone, an
        // unauthorized deletion. Assert the kinds sign distinct bytes and that an
        // Edit signature does not verify an otherwise-identical Forget op.
        let s = signer(31)?;
        let edit = Op::create_signed(&s, content_with_kind(root(), OpKind::Edit));
        let forget = Op::create_signed(&s, content_with_kind(root(), OpKind::Forget));

        ensure_ne(
            &edit.signing_bytes(),
            &forget.signing_bytes(),
            "ops differing only in kind must sign distinct bytes",
        )?;

        // Splice Edit's signature onto an otherwise-Forget op: the signature commits
        // to the kind, so this must not verify.
        let mut spliced = forget.clone();
        spliced.sig = edit.sig;
        ensure(
            !spliced.verify_sig(),
            "an Edit signature must not verify a Forget op",
        )
    }

    proptest! {
        /// Across the full kind space, two ops that differ only in `kind` sign
        /// equal bytes IFF the kinds are equal — the biconditional that makes the
        /// kind a non-malleable, non-collapsible part of the signed message.
        #[test]
        fn distinct_kinds_sign_distinct_bytes(
            a in op_kind_strategy(),
            b in op_kind_strategy(),
        ) {
            let s = signer(32).map_err(tce)?;
            let oa = Op::create_signed(&s, content_with_kind(root(), a.clone()));
            let ob = Op::create_signed(&s, content_with_kind(root(), b.clone()));
            prop_assert_eq!(oa.signing_bytes() == ob.signing_bytes(), a == b);
        }
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
    fn cross_type_signature_does_not_verify() -> TestResult {
        // oplog-3: every signed type shares SIGNING_CONTEXT, so cross-type
        // non-interchangeability rests on each prefixing a UNIQUE domain tag onto
        // its signed bytes. A signature over an op-tagged message must NOT verify
        // over the same payload under a manifest tag — proving the prefix, not the
        // context, is the type barrier.
        let s = signer(13)?;
        let payload = b"shared-body-bytes";
        let op_tagged = [super::SIGNING_DOMAIN, payload].concat();
        let manifest_tagged = [b"hippius-memory-manifest/v1".as_slice(), payload].concat();

        let sig = s.sign(&op_tagged);
        ensure(
            verify(&s.verifying_key(), &op_tagged, &sig),
            "the op-tagged message verifies under its own bytes",
        )?;
        ensure(
            !verify(&s.verifying_key(), &manifest_tagged, &sig),
            "an op signature must not verify over a manifest-tagged message",
        )
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

    /// One signed field's name paired with a mutation of just that field, so
    /// tamper-evidence can be asserted field by field from a single table.
    type FieldMutation<'a> = (&'a str, Box<dyn Fn(&mut Op) + 'a>);

    #[test]
    fn every_signed_field_is_tamper_evident() -> TestResult {
        // `tampered_op_fails_verification` above covers `lamport` and `note_id`
        // only, leaving the rest of the signed set unguarded. `cid` is the one
        // that matters most: it binds the op to the exact ciphertext blob it
        // names, and `Op::hash` — hence every successor's `prev_op_hash` — is
        // taken over `signing_bytes`. Were `cid` to stop being signed, an actor
        // with bucket write access could repoint an op at different ciphertext
        // with both the signature and the hash chain still verifying. Deleting
        // the `cid` push from `signing_bytes` left the whole suite green before
        // this test existed.
        let s = signer(7)?;
        let other = signer(8)?;
        let op = Op::create_signed(&s, content(root()));

        ensure(op.verify_sig(), "the pristine op must verify")?;

        // One entry per field `signing_bytes` covers. Adding a signed field
        // without adding it here leaves that field untested, so keep this list in
        // step with `Op::signing_bytes`.
        let mutations: Vec<FieldMutation<'_>> = vec![
            (
                "op_id",
                Box::new(|o: &mut Op| o.op_id = Ulid::from(999u128)),
            ),
            (
                "author",
                Box::new(|o: &mut Op| o.author = other.author_ss58()),
            ),
            (
                "author_key",
                Box::new(|o: &mut Op| o.author_key = other.verifying_key()),
            ),
            (
                "lamport",
                Box::new(|o: &mut Op| o.lamport = o.lamport.wrapping_add(1)),
            ),
            (
                "key_epoch",
                Box::new(|o: &mut Op| o.key_epoch = o.key_epoch.wrapping_add(1)),
            ),
            ("kind", Box::new(|o: &mut Op| o.kind = OpKind::Forget)),
            (
                "note_id",
                Box::new(|o: &mut Op| o.note_id = NoteId::from(Ulid::from(999u128))),
            ),
            (
                "object_key",
                Box::new(|o: &mut Op| o.object_key = "team/global/notes/zzz".to_string()),
            ),
            (
                "cid",
                Box::new(|o: &mut Op| o.cid = content_hash(b"a-different-ciphertext")),
            ),
            (
                "prev_op_hash",
                Box::new(|o: &mut Op| o.prev_op_hash = content_hash(b"a-different-predecessor")),
            ),
        ];

        for (field, mutate) in mutations {
            let mut tampered = op.clone();
            mutate(&mut tampered);

            ensure(
                !tampered.verify_sig(),
                &format!("mutating the signed field `{field}` must break verification"),
            )?;
        }

        Ok(())
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
    fn verify_rejects_the_identity_point_key() -> TestResult {
        // The authentication bypass this guard closes, demonstrated end to end
        // against the real primitive rather than asserted from theory.
        //
        // The forged signature is 64 zero bytes with schnorrkel's marker bit
        // (byte 63 = 0x80) set — the bit that distinguishes a schnorrkel
        // signature from an ed25519 one. It is cleared before the scalar is
        // parsed, so `s` reads as zero, and with the identity as the public key
        // the verification equation collapses to `R == s*G`, satisfied for every
        // message. No private key exists for it.
        let identity = VerifyingKey::new([0u8; 32]);
        let mut forged = [0u8; 64];
        forged[63] = 0x80;
        let forged = Signature::new(forged);

        // schnorrkel itself ACCEPTS this: the guard, not the primitive, is what
        // stands between the codebase and the bypass. If this ever stops holding
        // the guard has merely become redundant, never wrong.
        // `schnorrkel::SignatureError` does not implement `std::error::Error`, so
        // these convert through `ok()` rather than `?`.
        let public = schnorrkel::PublicKey::from_bytes(identity.as_bytes())
            .ok()
            .ok_or("schnorrkel parses the all-zero encoding as a public key")?;
        let parsed = schnorrkel::Signature::from_bytes(forged.as_bytes())
            .ok()
            .ok_or("schnorrkel parses the forged signature")?;
        let ctx = schnorrkel::signing_context(super::SIGNING_CONTEXT);
        ensure(
            public
                .verify(ctx.bytes(b"any message at all"), &parsed)
                .is_ok(),
            "schnorrkel accepts the forged identity-point signature (the hazard being guarded)",
        )?;

        // Our verifier refuses it, for any message, so no caller can be fooled.
        for msg in [b"any message at all".as_slice(), b"", b"another message"] {
            ensure(
                !verify(&identity, msg, &forged),
                "verify must reject the identity-point public key for every message",
            )?;
        }

        // A genuine key and signature still verify: the guard is targeted, not a
        // blanket rejection.
        let s = signer(3)?;
        let good = s.sign(b"real message");
        ensure(
            verify(&s.verifying_key(), b"real message", &good),
            "a genuine signature must still verify",
        )
    }

    #[test]
    fn verify_rejects_a_key_that_is_not_a_valid_ristretto_point() -> TestResult {
        // `verify` returns `bool`, never `Result`: the fallible step inside it,
        // `schnorrkel::PublicKey::from_bytes`, returns
        // `SignatureResult<PublicKey>`, and its `Err` arm is collapsed via
        // `let Ok(public) = ... else { return false; };` — so a key that fails
        // to parse as a Ristretto point makes `verify` return `false`, not
        // propagate an error or panic.
        //
        // All-0xFF is not a valid canonical Ristretto encoding. Per
        // curve25519-dalek's own `CompressedRistretto::decompress` (ristretto.rs
        // `step_1`, pinned curve25519-dalek 4.1.3 via this crate's schnorrkel
        // 0.11.5 dependency): decoding ignores the encoding's top bit, so
        // all-0xFF (with that bit cleared) reads as the integer 2^255 - 1,
        // which is >= the field prime p = 2^255 - 19. `decompress` re-encodes
        // that reduced value and requires it to match the ORIGINAL input
        // byte-for-byte; an out-of-range value can never round-trip that way,
        // so decompression fails outright and produces no point at all —
        // confirmed empirically:
        // `schnorrkel::PublicKey::from_bytes(&[0xff; 32])` returns
        // `Err(SignatureError::PointDecompressionError)` under this crate's
        // pinned dependency versions.
        //
        // [0xff; 32] also is not the identity point ([0u8; 32]), so this
        // exercises the `from_bytes` arm specifically, not the earlier
        // `is_identity_point` guard.
        let bad_key = VerifyingKey::new([0xffu8; 32]);

        let s = signer(11)?;
        let msg = b"drive the invalid-ristretto-point arm";
        let sig = s.sign(msg);

        ensure(
            !verify(&bad_key, msg, &sig),
            "verify must return false, not panic, for a key that is not a valid Ristretto point",
        )?;

        // Positive control, same call shape: a genuine key/signature pair over
        // the identical message still verifies, so the rejection above is
        // attributable to the invalid-point bytes specifically, not to some
        // earlier guard (or a broken `verify`) that would reject any input.
        ensure(
            verify(&s.verifying_key(), msg, &sig),
            "a genuine key must still verify with the same call shape",
        )
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

    /// A fixed placeholder signature shared by every `Op` the injectivity
    /// machinery below constructs. `Op` derives `PartialEq` over `sig`
    /// (see `Op`'s `#[derive]`), and sr25519 signing is randomized —
    /// schnorrkel mixes CSPRNG output into the nonce, so two independently
    /// *signed* ops with byte-identical signed content still compare
    /// unequal via `sig` for a reason `signing_bytes` cannot see (this bit
    /// D3's manifest injectivity proptest; see that commit's notes). Every
    /// `Op` below is a struct literal, never routed through
    /// [`Op::create_signed`]/[`Signer::sign`], and always carries this one
    /// constant `sig`, so `==` reduces to exactly the field set
    /// `signing_bytes` covers — the only set this property is about.
    const ALL_ZERO_SIG: Signature = Signature::new([0u8; 64]);

    /// Recovered fields of an [`Op::signing_bytes`] buffer, compared
    /// field-by-field by [`op_signing_bytes_is_injective`]'s round-trip
    /// check.
    struct ParsedOp {
        op_id: Vec<u8>,
        author: Vec<u8>,
        author_key: Vec<u8>,
        lamport: u64,
        key_epoch: u64,
        /// The 1-byte [`OpKind`] discriminant [`super::push_op_kind`] wrote.
        kind_tag: u8,
        /// [`OpKind::Link`]/[`OpKind::Relate`]'s framed `to` target, when the
        /// tag carries one.
        kind_to: Option<Vec<u8>>,
        /// [`OpKind::Relate`]'s raw 1-byte [`LinkRel`] wire tag (tag `5`
        /// only).
        kind_rel: Option<u8>,
        note_id: Vec<u8>,
        object_key: Vec<u8>,
        cid: Vec<u8>,
        prev_op_hash: Vec<u8>,
    }

    fn read_u64(buf: &[u8]) -> Option<(u64, &[u8])> {
        let head = buf.get(..8)?;
        let arr = <[u8; 8]>::try_from(head).ok()?;
        Some((u64::from_le_bytes(arr), &buf[8..]))
    }

    fn read_framed(buf: &[u8]) -> Option<(Vec<u8>, &[u8])> {
        let (len, buf) = read_u64(buf)?;
        let len = usize::try_from(len).ok()?;
        let field = buf.get(..len)?;
        Some((field.to_vec(), &buf[len..]))
    }

    /// Inverse of [`Op::signing_bytes`], reading the exact layout it writes:
    /// the domain tag, framed `op_id`, framed `author`, raw 32-byte
    /// `author_key`, raw 8-byte `lamport`, raw 8-byte `key_epoch`, the
    /// [`OpKind`] tag (plus, for `Link`/`Relate`, a framed target and — for
    /// `Relate` only — a further raw relation byte), framed `note_id`,
    /// framed `object_key`, and raw 32-byte `cid`/`prev_op_hash`. Any bytes
    /// left over after `prev_op_hash` are rejected as trailing garbage
    /// rather than silently ignored.
    ///
    /// That this inverse exists at all is the injectivity proof:
    /// `signing_bytes` interleaves four framed fields with raw fixed-width
    /// ones (plus, inside `Link`/`Relate`, a framed field followed by more
    /// raw bytes), so no PER-FIELD round trip (like `framing.rs`'s own, or
    /// `push_framed`'s) can show the FULL composite layout is unambiguous —
    /// only walking the whole thing back, in order, can, exactly as
    /// `parse_manifest` does for `TeamManifest`.
    ///
    /// TEST-ONLY: never linked into the production binary. Production
    /// [`Op::verify_sig`] never parses bytes back — it always RECOMPUTES
    /// `signing_bytes()` from `self`, so there is no path by which this
    /// parser could launder attacker-supplied bytes into acceptance.
    ///
    /// Returns `None` on any truncation, an unrecognized `OpKind` tag, or
    /// trailing bytes; never panics (the crate denies `unwrap`/`panic`).
    fn parse_op(buf: &[u8]) -> Option<ParsedOp> {
        let buf = buf.strip_prefix(super::SIGNING_DOMAIN)?;
        let (op_id, buf) = read_framed(buf)?;
        let (author, buf) = read_framed(buf)?;
        let author_key = buf.get(..32)?.to_vec();
        let buf = buf.get(32..)?;
        let (lamport, buf) = read_u64(buf)?;
        let (key_epoch, buf) = read_u64(buf)?;

        let (&kind_tag, buf) = buf.split_first()?;
        let (kind_to, kind_rel, buf) = match kind_tag {
            0 | 1 | 2 | 4 | 6 => (None, None, buf),
            3 => {
                let (to, rest) = read_framed(buf)?;
                (Some(to), None, rest)
            }
            5 => {
                let (to, rest) = read_framed(buf)?;
                let (&rel, rest) = rest.split_first()?;
                (Some(to), Some(rel), rest)
            }
            _ => return None,
        };

        let (note_id, buf) = read_framed(buf)?;
        let (object_key, buf) = read_framed(buf)?;
        let cid = buf.get(..32)?.to_vec();
        let buf = buf.get(32..)?;
        let prev_op_hash = buf.get(..32)?.to_vec();
        let buf = buf.get(32..)?;

        if !buf.is_empty() {
            // Trailing bytes: not a layout `signing_bytes` ever produces.
            return None;
        }

        Some(ParsedOp {
            op_id,
            author,
            author_key,
            lamport,
            key_epoch,
            kind_tag,
            kind_to,
            kind_rel,
            note_id,
            object_key,
            cid,
            prev_op_hash,
        })
    }

    /// The `(tag, to, rel)` triple [`super::push_op_kind`] would write for
    /// `kind` — compared against what [`parse_op`] reads back.
    fn expected_kind_wire(kind: &OpKind) -> (u8, Option<Vec<u8>>, Option<u8>) {
        match kind {
            OpKind::Remember => (0, None, None),
            OpKind::Edit => (1, None, None),
            OpKind::Forget => (2, None, None),
            OpKind::Link { to } => (3, Some(to.to_string().into_bytes()), None),
            OpKind::Redact => (4, None, None),
            OpKind::Relate { to, rel } => {
                (5, Some(to.to_string().into_bytes()), Some(rel.wire_tag()))
            }
            OpKind::Reinforce => (6, None, None),
        }
    }

    /// A [`Strategy`] producing a fully-formed [`Op`], randomizing eight of
    /// its ten signed fields: `op_id`, `lamport`, `key_epoch`, `kind` (via
    /// [`op_kind_strategy`], reused here rather than varying `kind` alone),
    /// `note_id`, `object_key`, `cid`, and `prev_op_hash`. `author` and
    /// `author_key` are fixed constants here (`"proptest-author"` and
    /// `[0x11u8; 32]`) — their coverage comes from elsewhere:
    /// [`one_field_variants`] gives each a deterministic one-field diff
    /// against `base` on every run, and, for `author` specifically,
    /// [`boundary_shift_pair`] is what actually exercises its
    /// length-variance (the property this test exists to prove correct),
    /// since a randomly-drawn `author` could never land on the exact
    /// 47-byte-longer boundary that mutation needs. Built directly as an
    /// `Op` literal carrying [`ALL_ZERO_SIG`], never through
    /// [`Op::create_signed`]; see that constant's doc for why.
    ///
    /// This is deliberately NOT drawn twice and compared directly (the
    /// brief's original `a in op_strategy(), b in op_strategy()` shape):
    /// `op_id` alone is a ULID, so two independent draws are equal with
    /// probability ~0. `a == b` would then be false and
    /// `a.signing_bytes() == b.signing_bytes()` would also be false on
    /// virtually every case, so the biconditional would hold trivially
    /// without ever exercising "equal bytes force equal ops" — the
    /// direction that actually matters. [`op_signing_bytes_is_injective`]
    /// instead draws ONE random `Op` from this strategy as a background
    /// base and builds a small, deliberately curated candidate set around
    /// it (see [`one_field_variants`] and [`boundary_shift_pair`]) so the
    /// interesting cells of the biconditional are reachable on every run,
    /// not merely by chance.
    fn op_strategy() -> impl Strategy<Value = Op> {
        (
            any::<u128>(),
            any::<u64>(),
            any::<u64>(),
            op_kind_strategy(),
            any::<u128>(),
            "[ -~]{0,32}",
            any::<u64>(),
            any::<u64>(),
        )
            .prop_map(
                |(
                    op_id_seed,
                    lamport,
                    key_epoch,
                    kind,
                    note_id_seed,
                    object_key,
                    cid_seed,
                    prev_seed,
                )| {
                    Op {
                        op_id: Ulid::from(op_id_seed),
                        author: Ss58::from_trusted("proptest-author".to_owned()),
                        author_key: VerifyingKey::new([0x11u8; 32]),
                        lamport,
                        key_epoch,
                        kind,
                        note_id: NoteId::from(Ulid::from(note_id_seed)),
                        object_key,
                        cid: content_hash(&cid_seed.to_le_bytes()),
                        prev_op_hash: content_hash(&prev_seed.to_le_bytes()),
                        sig: ALL_ZERO_SIG,
                    }
                },
            )
    }

    /// `base` with exactly one signed field changed, one entry per field
    /// [`Op::signing_bytes`] covers (the same ten fields
    /// `every_signed_field_is_tamper_evident` mutates). This is the
    /// "different ops must differ in bytes" direction of the biconditional,
    /// exercised per field deliberately rather than hoping two independent
    /// `op_strategy()` draws happen to differ in only one place.
    fn one_field_variants(base: &Op) -> Vec<Op> {
        let base_author = base.author.as_str();
        let base_object_key = base.object_key.as_str();

        vec![
            {
                let mut v = base.clone();
                v.op_id = Ulid::from(base.op_id.0 ^ 1);
                v
            },
            {
                let mut v = base.clone();
                v.author = Ss58::from_trusted(format!("{base_author}-x"));
                v
            },
            {
                let mut v = base.clone();
                v.author_key = VerifyingKey::new([0x22u8; 32]);
                v
            },
            {
                let mut v = base.clone();
                v.lamport = base.lamport.wrapping_add(1);
                v
            },
            {
                let mut v = base.clone();
                v.key_epoch = base.key_epoch.wrapping_add(1);
                v
            },
            {
                let mut v = base.clone();
                v.kind = if base.kind == OpKind::Remember {
                    OpKind::Edit
                } else {
                    OpKind::Remember
                };
                v
            },
            {
                let mut v = base.clone();
                v.note_id = NoteId::from(Ulid::from(base.note_id.as_ulid().0 ^ 1));
                v
            },
            {
                let mut v = base.clone();
                v.object_key = format!("{base_object_key}-x");
                v
            },
            {
                let mut v = base.clone();
                v.cid = content_hash(b"one-field-variant-cid");
                v
            },
            {
                let mut v = base.clone();
                v.prev_op_hash = content_hash(b"one-field-variant-prev");
                v
            },
        ]
    }

    /// A hand-constructed pair of DISTINCT ops whose `signing_bytes` collide
    /// under one, and only one, specific framing regression: `author`
    /// losing its own length prefix (`push_framed(&mut buf,
    /// self.author.as_str().as_bytes())` in [`Op::signing_bytes`] replaced
    /// by a raw `buf.extend_from_slice(...)`).
    ///
    /// # Why this pair, and why it is reachable only by construction
    ///
    /// `author` (an [`Ss58`], built here via [`Ss58::from_trusted`] so its
    /// length is not pinned to the validated 47..=49-byte range) is itself
    /// variable-length — that variability is exactly what this collision
    /// exploits, by making `long`'s `author` 47 bytes longer than
    /// `short`'s. It is immediately followed by fixed-width raw fields
    /// (`author_key` 32B, `lamport` 8B, `key_epoch` 8B), a 1-byte `kind`
    /// tag, then `note_id` (framed, but every value renders to a FIXED
    /// byte length, so it can never itself be the source of a boundary
    /// shift). Of the fields DOWNSTREAM of `author`, only `object_key` has
    /// genuinely unconstrained length. If `author` loses its length
    /// prefix, a LONGER author string that "borrows" the bytes which would
    /// otherwise be `short`'s `author_key` + `lamport` + the first 7 bytes
    /// of `key_epoch` (32+8+7 = 47 bytes) produces the exact same overall
    /// buffer as a SHORTER author string, provided `object_key` is built to
    /// absorb the resulting length difference — which, being free-form, it
    /// always can. Concretely: `long`'s author is `short`'s author plus
    /// those 47 bytes; `long`'s `author_key`/`lamport`/`key_epoch` are what
    /// remains of `short`'s bytes just past that 47-byte shift; and
    /// `short.object_key` is built to contain exactly `long`'s kind tag,
    /// framed `note_id`, and framed `object_key` — so the two streams
    /// realign perfectly.
    ///
    /// Random independent draws essentially never land two ops on this
    /// exact boundary (`op_id` alone makes an accidental match
    /// astronomically unlikely), so this is exactly the kind of
    /// deliberately-constructed pair the brief's own example
    /// (`("ab","c")` vs. `("a","bc")`) describes, applied to the real field
    /// layout.
    ///
    /// Every downstream value (`long`'s `author`, `author_key`, `lamport`,
    /// `key_epoch`) is derived by SLICING a REFERENCE encoding of `short`'s
    /// `author_key`/`lamport`/`key_epoch`/`kind`/`note_id`/`object_key`-length
    /// fields, assembled here directly with [`push_framed`] and
    /// `extend_from_slice` — deliberately NOT by calling
    /// `short.signing_bytes()`. Reading the split out of the REAL
    /// `signing_bytes()` would make this helper depend on the very method
    /// the mutation test exists to break: under the "drop author's length
    /// prefix" mutation, `short.signing_bytes()` no longer frames `author`
    /// either, so re-parsing it here would fail to build `long` at all
    /// (confirmed empirically — the first version of this helper did
    /// exactly that, and the mutation surfaced as `boundary_shift_pair`
    /// itself returning `Err`, not as the pairwise assertion catching a
    /// collision). The reference encoding below always reflects the
    /// CORRECT layout, so `short`/`long` are always the same fixed pair,
    /// and it is `short.signing_bytes()`/`long.signing_bytes()` — called
    /// only by the caller, against the pair this function returns — that
    /// actually exercises whatever `Op::signing_bytes` currently does. An
    /// arithmetic mistake in the reference encoding fails a `?` here (or
    /// the caller's own assertions) rather than silently shipping a pair
    /// that does not test what this doc claims.
    fn boundary_shift_pair() -> Result<(Op, Op), Box<dyn std::error::Error>> {
        let op_id = Ulid::from(0xB0u128);
        let cid = content_hash(b"boundary-shift-shared-cid");
        let prev_op_hash = content_hash(b"boundary-shift-shared-prev");

        let note_id_long = NoteId::from(Ulid::from(0xB1u128));
        let object_key_long = "z".to_owned();

        // Chosen so the 47 bytes `long`'s author borrows from them (below)
        // are printable ASCII, hence trivially valid UTF-8 once appended to
        // a `str`.
        let author_key_short = VerifyingKey::new([b'A'; 32]);
        let lamport_short = u64::from_le_bytes([b'A'; 8]);
        let key_epoch_short = u64::from_le_bytes([b'A', b'A', b'A', b'A', b'A', b'A', b'A', 0]);
        let note_id_short = NoteId::from(Ulid::from(0xB2u128));

        // `short.object_key`'s content is exactly `long`'s kind tag
        // (Remember, 0x00) followed by `long`'s framed `note_id` and framed
        // `object_key` — the bytes that, after the 47-byte shift, become
        // `long`'s tail. Built with the crate's own `push_framed` rather
        // than hand-written hex, so this stays correct if the framing width
        // ever changes.
        let mut object_key_short_bytes = vec![0u8];
        push_framed(
            &mut object_key_short_bytes,
            note_id_long.to_string().as_bytes(),
        );
        push_framed(&mut object_key_short_bytes, object_key_long.as_bytes());
        let object_key_short = String::from_utf8(object_key_short_bytes)?;

        let short = Op {
            op_id,
            author: Ss58::from_trusted("boundary-short".to_owned()),
            author_key: author_key_short,
            lamport: lamport_short,
            key_epoch: key_epoch_short,
            kind: OpKind::Remember,
            note_id: note_id_short,
            object_key: object_key_short,
            cid,
            prev_op_hash,
            sig: ALL_ZERO_SIG,
        };

        // The reference encoding: exactly the CORRECT (never-mutated-here)
        // author_key + lamport + key_epoch + kind-tag + framed note_id +
        // object_key's own length prefix, in the order `Op::signing_bytes`
        // writes them. Independent of `short.signing_bytes()` -- see this
        // function's doc for why that independence is load-bearing.
        let mut rest = Vec::new();
        rest.extend_from_slice(short.author_key.as_bytes());
        rest.extend_from_slice(&short.lamport.to_le_bytes());
        rest.extend_from_slice(&short.key_epoch.to_le_bytes());
        rest.push(0); // OpKind::Remember's wire tag.
        push_framed(&mut rest, short.note_id.to_string().as_bytes());
        let object_key_short_len = u64::try_from(short.object_key.len()).unwrap_or(u64::MAX);
        rest.extend_from_slice(&object_key_short_len.to_le_bytes());

        let borrowed = rest
            .get(..47)
            .ok_or("reference rest is shorter than the 47-byte shift")?;
        let rest_after_shift = rest
            .get(47..)
            .ok_or("reference rest is shorter than the 47-byte shift")?;

        let short_author = short.author.as_str();
        let borrowed_str = std::str::from_utf8(borrowed)?;
        let author_long = format!("{short_author}{borrowed_str}");

        let author_key_bytes = rest_after_shift
            .get(..32)
            .ok_or("rest-after-shift is shorter than a 32-byte author_key")?;
        let author_key_long = VerifyingKey::new(<[u8; 32]>::try_from(author_key_bytes)?);
        let after_author_key = rest_after_shift
            .get(32..)
            .ok_or("rest-after-shift is shorter than author_key")?;
        let (lamport_long, after_lamport) =
            read_u64(after_author_key).ok_or("rest-after-shift is missing lamport")?;
        let (key_epoch_long, _) =
            read_u64(after_lamport).ok_or("rest-after-shift is missing key_epoch")?;

        let long = Op {
            op_id,
            author: Ss58::from_trusted(author_long),
            author_key: author_key_long,
            lamport: lamport_long,
            key_epoch: key_epoch_long,
            kind: OpKind::Remember,
            note_id: note_id_long,
            object_key: object_key_long,
            cid,
            prev_op_hash,
            sig: ALL_ZERO_SIG,
        };

        Ok((short, long))
    }

    #[test]
    fn boundary_shift_pair_is_reachable_and_distinct() -> TestResult {
        // Sanity on `boundary_shift_pair` itself, independent of any
        // mutation: the two ops it builds are structurally distinct, and —
        // under TODAY's correctly-framed `signing_bytes` — sign distinct
        // bytes. This assertion is exactly the one that flips (and so
        // catches the mutation) if `author`'s length prefix is ever
        // dropped; see this file's mutation-testing notes.
        let (short, long) = boundary_shift_pair()?;
        ensure_ne(&short, &long, "boundary_shift_pair must build distinct ops")?;
        ensure_ne(
            &short.signing_bytes(),
            &long.signing_bytes(),
            "under correctly-framed signing_bytes, the boundary-shift pair must NOT collide",
        )?;

        // Both must still round-trip through `parse_op` under today's code,
        // confirming the pair is well-formed, not merely non-colliding.
        for op in [&short, &long] {
            let bytes = op.signing_bytes();
            let parsed = parse_op(&bytes).ok_or("boundary-shift op must parse back")?;
            ensure_eq(
                &parsed.author,
                &op.author.as_str().as_bytes().to_vec(),
                "boundary-shift op author must round-trip",
            )?;
        }
        Ok(())
    }

    proptest! {
        /// `signing_bytes` is injective over the real field set it signs:
        /// two ops produce equal signed bytes if and only if they are
        /// equal. A framing bug that let two distinct ops share bytes
        /// would let a signature transfer between them.
        ///
        /// Checked two ways over a small candidate set built around one
        /// random `base` (see [`op_strategy`] for why two independently
        /// drawn ops are not compared directly):
        ///
        /// 1. **Round trip** (every candidate): [`parse_op`] recovers every
        ///    field, so no field can be mistaken for another.
        /// 2. **Pairwise biconditional** (every ordered pair, including
        ///    self-pairs — the trivial `true<=>true` cell): `base` itself,
        ///    [`one_field_variants`] (ten ops each differing from `base` in
        ///    exactly one signed field — the "different ops must differ in
        ///    bytes" direction, exercised per field), and
        ///    [`boundary_shift_pair`]'s `short`/`long` (a pair specifically
        ///    reachable by the mutation this test is built to catch: `author`
        ///    losing its own length-prefix framing).
        ///
        /// This does NOT prove injectivity for every conceivable pair of
        /// ops (that would require the intractable `a in .., b in ..`
        /// independent-draw shape the brief's original property used,
        /// which cannot exercise the collision-relevant cells at all). It
        /// proves the composite layout is unambiguous at every field
        /// boundary `signing_bytes` actually has, including the one
        /// boundary (`author`/`object_key`, via `object_key`'s
        /// unconstrained length) where an ambiguity is structurally
        /// possible.
        #[test]
        fn op_signing_bytes_is_injective(base in op_strategy()) {
            let mut candidates = vec![base.clone()];
            candidates.extend(one_field_variants(&base));

            let (boundary_short, boundary_long) = boundary_shift_pair().map_err(tce)?;
            candidates.push(boundary_short);
            candidates.push(boundary_long);

            // Check 1: round trip, for every candidate.
            for c in &candidates {
                let bytes = c.signing_bytes();
                let parsed =
                    parse_op(&bytes).ok_or_else(|| tce("op signing bytes did not parse back"))?;

                prop_assert_eq!(parsed.op_id, c.op_id.to_string().into_bytes());
                prop_assert_eq!(parsed.author, c.author.as_str().as_bytes().to_vec());
                prop_assert_eq!(parsed.author_key, c.author_key.as_bytes().to_vec());
                prop_assert_eq!(parsed.lamport, c.lamport);
                prop_assert_eq!(parsed.key_epoch, c.key_epoch);

                let (expected_tag, expected_to, expected_rel) = expected_kind_wire(&c.kind);
                prop_assert_eq!(parsed.kind_tag, expected_tag);
                prop_assert_eq!(parsed.kind_to, expected_to);
                prop_assert_eq!(parsed.kind_rel, expected_rel);

                prop_assert_eq!(parsed.note_id, c.note_id.to_string().into_bytes());
                prop_assert_eq!(parsed.object_key, c.object_key.as_bytes().to_vec());
                prop_assert_eq!(parsed.cid, c.cid.as_bytes().to_vec());
                prop_assert_eq!(parsed.prev_op_hash, c.prev_op_hash.as_bytes().to_vec());
            }

            // Check 2: the pairwise biconditional, over every ordered pair
            // (including each candidate against itself).
            for i in 0..candidates.len() {
                for j in 0..candidates.len() {
                    let bytes_eq = candidates[i].signing_bytes() == candidates[j].signing_bytes();
                    let struct_eq = candidates[i] == candidates[j];
                    prop_assert_eq!(
                        bytes_eq,
                        struct_eq,
                        "signing_bytes equality must exactly track Op equality \
                         (candidates {} and {})",
                        i,
                        j
                    );
                }
            }
        }
    }
}
