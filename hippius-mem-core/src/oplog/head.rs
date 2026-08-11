//! A signed, per-author head pointer: the object that pins "this is my latest op".
//!
//! # The gap this narrows
//!
//! The per-author hash chain in [`crate::oplog::OpLogStore`] makes a MID-chain
//! deletion evident — the next op's `prev_op_hash` dangles, so the read path
//! quarantines the branch and `reconcile` names the author. It cannot make a TAIL
//! deletion evident, because nothing points at the newest op: a truncated view is
//! indistinguishable from a view where that op was never written (the op-log
//! store's own module doc concedes exactly this). [`crate::audit::reconcile`]
//! catches suppression of an *anchored* op, but a bucket that drops an op together
//! with the anchor record covering it leaves nothing to reconcile against.
//!
//! A [`HeadPointer`] is the missing claim. Each author publishes one signed object
//! naming their current chain tip, so hiding that tip requires the bucket to ALSO
//! drop or roll back a signed object rather than silently omit one, and
//! [`crate::audit::reconcile`] reports an author whose signed head names a tip the
//! visible op-log does not contain.
//!
//! # What this does NOT buy
//!
//! It does not make tail truncation impossible to hide. A hostile bucket can still
//! drop the head object entirely — an author with ops and no head makes no claim,
//! and this module has nothing to compare against — or serve an OLDER,
//! still-validly-signed head consistent with the truncated view. Both are silent
//! here. What this adds is a durable, verifiable, signed claim that a reader can
//! compare against a locally-remembered high-water mark across syncs; on a machine
//! that has already seen the newer head, a dropped or rolled-back head is then a
//! reportable regression. A machine that has never seen the newer head stays
//! blind, and that residual is irreducible without state the bucket does not
//! control.
//!
//! # The one mutable key
//!
//! A head lives at `{team}/_heads/{author_key_hex}` — ONE key per author,
//! overwritten on every write. That makes it the first MUTABLE key in a store
//! whose other keys are immutable once written: ops, note versions, and anchor
//! records are each minted at a fresh key and never rewritten.
//!
//! It is safe for two reasons, and both must hold. The object is SIGNED by the
//! author, so the bucket cannot forge a head for an identity whose secret key it
//! does not hold — the worst it can do is drop or roll back one, which is the
//! documented residual above. And every reader re-verifies the object's own
//! contents ([`read_heads`]) rather than trusting the key path it was found
//! under: the path is a lookup convenience, never evidence. A head found at
//! another author's path, or carrying another team's name, is skipped.

use std::sync::Arc;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

use crate::domain::{Blake3Hash, Ss58};
use crate::error::MemError;
use crate::framing::push_framed;
use crate::oplog::op::{HIPPIUS_SS58_PREFIX, Signature, Signer, VerifyingKey, verify};
use crate::store::BlobStore;

/// Domain tag for head-pointer signing bytes.
///
/// Distinct from the op tag (`hippius-memory-op/v2`) and from the manifest and
/// member-key tags, so a signature over a head can never verify as an op and vice
/// versa. Every signed type in this crate shares ONE sr25519 signing context (see
/// `oplog::op`'s `SIGNING_CONTEXT` doc), so this leading prefix — not the context
/// — is the whole cross-type barrier. Do not remove it without replacing it with a
/// distinct context.
const HEAD_DOMAIN: &[u8] = b"hippius-memory-head/v1";

/// Bounded concurrency for the head-object fetch, matching
/// `read_anchor_records`' `ANCHOR_FETCH_CONCURRENCY` and the op-log read's
/// `OPLOG_FETCH_CONCURRENCY`.
///
/// An honest team publishes exactly one head per author, so this prefix is
/// normally tiny — but it is a bucket-writable prefix, and an untrusted bucket can
/// plant arbitrarily many objects under it. The listing size is therefore NOT
/// bounded by team size, and an explicit in-flight cap (never an unbounded
/// fan-out) is what keeps a poisoned prefix from opening thousands of simultaneous
/// connections while still overlapping the gateway's per-GET latency.
const HEAD_FETCH_CONCURRENCY: usize = 64;

/// One author's signed claim about their own current op-log chain tip.
///
/// Fields are public because a `HeadPointer` is a data record consumed by the
/// audit layer and by deserialization; its integrity comes from
/// [`HeadPointer::verify_sig`] and [`HeadPointer::verify_identity`], not from
/// private fields — the same rationale as [`crate::oplog::Op`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadPointer {
    /// The team namespace this head belongs to.
    ///
    /// Signed, and re-checked by [`read_heads`] against the team actually being
    /// read, so a head lifted out of one team's prefix and replanted in another's
    /// is rejected instead of being counted as that team's claim.
    pub team: String,
    /// Human-facing SS58 address of the author making the claim.
    ///
    /// Bound to `author_key` by [`HeadPointer::verify_identity`], exactly as
    /// [`crate::oplog::Op`]'s `author` is: a writer cannot sign with one key and
    /// claim another identity's address.
    pub author: Ss58,
    /// The sr25519 public key the signature is verified against.
    pub author_key: VerifyingKey,
    /// The Lamport time of the op named by `tip_hash`.
    ///
    /// Carried so a reader can order two heads from the same author (which one is
    /// newer) without needing the ops themselves — the comparison a durable
    /// high-water mark makes across syncs.
    pub lamport: u64,
    /// The [`crate::oplog::Op::hash`] of the author's chain tip at publish time.
    pub tip_hash: Blake3Hash,
    /// sr25519 signature over [`HeadPointer::signing_bytes`].
    pub sig: Signature,
}

impl HeadPointer {
    /// The exact bytes that are signed and verified.
    ///
    /// A domain-tagged, length-framed concatenation of every field except `sig`,
    /// built exactly as [`crate::oplog::Op::signing_bytes`] is: hand-built rather
    /// than `serde_json` so it is total (no fallible serialization step), each
    /// variable-length field prefixed with a fixed 8-byte little-endian length
    /// (see [`push_framed`]), fixed-width fields emitted verbatim. The bytes — and
    /// therefore the signature — agree across 32- and 64-bit machines.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(HEAD_DOMAIN);

        push_framed(&mut buf, self.team.as_bytes());
        push_framed(&mut buf, self.author.as_str().as_bytes());
        buf.extend_from_slice(self.author_key.as_bytes());
        buf.extend_from_slice(&self.lamport.to_le_bytes());
        buf.extend_from_slice(self.tip_hash.as_bytes());

        buf
    }

    /// Build a [`HeadPointer`] signed by `signer`, claiming `tip_hash` at
    /// `lamport` as this author's current chain tip in `team`.
    ///
    /// `author` / `author_key` are filled from the signer, so a head minted here
    /// passes [`HeadPointer::verify_identity`] by construction — there is no
    /// constructor taking a caller-supplied, mismatchable address.
    #[must_use]
    pub fn create_signed(
        signer: &dyn Signer,
        team: &str,
        lamport: u64,
        tip_hash: Blake3Hash,
    ) -> Self {
        let mut head = Self {
            team: team.to_owned(),
            author: signer.author_ss58(),
            author_key: signer.verifying_key(),
            lamport,
            tip_hash,
            // Placeholder: `signing_bytes` excludes `sig`, so its value here does
            // not affect the message that gets signed.
            sig: Signature::new([0u8; 64]),
        };

        let msg = head.signing_bytes();
        head.sig = signer.sign(&msg);

        head
    }

    /// Verify the human SS58 label is cryptographically bound to the signing key:
    /// `author` must decode to exactly `author_key`, under the Hippius network
    /// prefix.
    ///
    /// Mirrors [`crate::oplog::Op::verify_identity`] — and shares its
    /// `HIPPIUS_SS58_PREFIX` constant rather than restating the convention — for
    /// the same reason: [`HeadPointer::verify_sig`] proves the bytes were signed
    /// by `author_key`, and this proves `author_key` is the identity `author`
    /// names. Without it a writer could sign a head with their own key while
    /// labelling it with a teammate's address, so the claim "this teammate's tip
    /// is X" would be attributable to the wrong person. A malformed `author`, a
    /// wrong-key `author`, or a non-Hippius prefix all yield `false`.
    #[must_use]
    pub fn verify_identity(&self) -> bool {
        crate::identity::ss58_decode(&self.author)
            .is_ok_and(|(key, prefix)| key == self.author_key && prefix == HIPPIUS_SS58_PREFIX)
    }

    /// Verify this head's signature against its own `author_key`.
    ///
    /// Goes through [`crate::oplog::verify`], which screens the Ristretto identity
    /// point before schnorrkel is consulted — so an all-zero `author_key`, under
    /// which a typed-out signature would otherwise pass for any message, cannot
    /// mint a head that verifies.
    #[must_use]
    pub fn verify_sig(&self) -> bool {
        verify(&self.author_key, &self.signing_bytes(), &self.sig)
    }
}

/// A set of head pointers that passed [`read_heads`]' checks — signature,
/// author-SS58 binding, team match, and canonical-key placement — held so
/// [`crate::audit::find_suppressed_tails`] can demand it by type.
///
/// Mirrors [`VerifiedOps`](crate::oplog::VerifiedOps), for the same reason. The
/// suppression check trusts its input completely: it reports an author whose head
/// names a tip the log cannot produce, and reporting that is an ACCUSATION against
/// a named identity. Fed raw bucket objects it would launder an unsigned or
/// misattributed claim into evidence — the bucket could then manufacture a
/// suppression report against any author by planting one object. `find_suppressed_tails`
/// is `pub` because `doctor` calls it across the crate boundary, so a doc-comment
/// precondition would be the only thing standing between an outside caller and that
/// laundering.
///
/// This is a *witness*, not a validate-at-construction value: re-proving the
/// signatures cheaply is not possible, so the invariant is upheld by restricting
/// construction. The inner `Vec` is private and the only route that produces one is
/// [`read_heads`], via a module-private constructor.
///
/// Deliberately absent (each would mint the witness without the checks):
/// `DerefMut`, `Default`, `Deserialize`, and any `From<Vec<HeadPointer>>`. Read
/// access is `Deref` to `[HeadPointer]`.
#[derive(Debug)]
pub struct VerifiedHeads(Vec<HeadPointer>);

impl VerifiedHeads {
    /// Wrap `heads` as verified. THE trust boundary.
    ///
    /// Module-private — tighter than [`VerifiedOps`](crate::oplog::VerifiedOps)'s
    /// `pub(in crate::oplog)`, which it only needs because its producer lives in a
    /// sibling module. [`read_heads`] is right here, so nothing outside this file
    /// can mint a witness, and the audit surface is this one call site.
    fn from_verified(heads: Vec<HeadPointer>) -> Self {
        Self(heads)
    }
}

impl std::ops::Deref for VerifiedHeads {
    type Target = [HeadPointer];

    fn deref(&self) -> &[HeadPointer] {
        &self.0
    }
}

/// Object-key prefix under which a team's head pointers live.
fn heads_prefix(team: &str) -> String {
    format!("{team}/_heads/")
}

/// Object key for `author_key`'s head pointer in `team`.
///
/// `{team}/_heads/{author_key_hex}`: one key per author, rewritten on every
/// write. The author's public key — not their SS58 — is the path segment because
/// it is the value [`read_heads`] can compare byte-for-byte against the object's
/// own `author_key` with no decoding step in between.
fn head_key(team: &str, author_key: &VerifyingKey) -> String {
    format!("{team}/_heads/{}", author_key.to_hex())
}

/// Persist `head` as JSON at its author's head key, replacing any previous head.
///
/// # Errors
///
/// Returns [`MemError::Serialize`] if the head cannot be encoded, or
/// [`MemError::Storage`] if the blob write fails.
pub async fn publish_head(
    blob: &Arc<dyn BlobStore>,
    team: &str,
    head: &HeadPointer,
) -> Result<(), MemError> {
    let bytes = serde_json::to_vec(head)?;
    blob.put(&head_key(team, &head.author_key), bytes).await
}

/// Read every VERIFIED head pointer for `team`, in a deterministic `author_key`
/// order.
///
/// A single malformed or unattributable object under the heads prefix is SKIPPED
/// with a warn, not fatal — the I2 discipline the op-log, manifest, and
/// `read_anchor_records` readers already follow. An object is dropped when it:
/// does not decode as a [`HeadPointer`]; fails its signature; fails the
/// `author`-to-`author_key` identity binding; carries a `team` other than the one
/// requested (a head transplanted from another team's prefix — defense in depth
/// beside the AEAD-AAD binding, exactly as the op read rejects an `object_key`
/// outside `{team}/`); or does not sit at the canonical key for the `author_key`
/// it claims (a head planted under someone else's namespace, or nested one level
/// deeper to dodge a same-segment comparison).
///
/// Aborting the whole read on any of those would let one planted object blind the
/// team's suppression check — and, worse, let an attacker who does not want a
/// suppression reported simply make the read error instead. The explicit
/// `sort_by_key` fixes a stable order independent of backend listing quirks, so
/// the report reads identically on every machine.
///
/// # A residual this policy deliberately keeps
///
/// A listed-but-unGETtable object hard-errors the whole read, which hands a
/// hostile bucket exactly the lever the paragraph above argues against: it can
/// suppress the REPORT instead of the op, by listing a `_heads/` key it then
/// refuses to serve. That is a real, open tension, not an oversight. It is kept
/// because the alternative is worse in the other direction — silently skipping an
/// unfetchable head would let the bucket hide a genuine claim by making one GET
/// fail, converting an accusation into silence with no error anywhere — and
/// because the same split is the settled policy at `read_anchor_records`
/// (`audit/batch.rs`), whose reasoning this mirrors: a GET failure is transient and
/// retried, a malformed object is permanent and plantable. Diverging here alone
/// would leave two prefixes with two policies for the same class of fault. Closing
/// it properly needs something neither reader has: a way to tell "the bucket cannot
/// serve this" from "the bucket will not serve this".
///
/// # Errors
///
/// Returns [`MemError::Storage`] only if the prefix listing fails or a listed
/// object's GET fails — a transient fault, retried on the next read, distinct from
/// the permanent malformations skipped above. See the residual above.
pub async fn read_heads(blob: &Arc<dyn BlobStore>, team: &str) -> Result<VerifiedHeads, MemError> {
    let keys = blob.list(&heads_prefix(team)).await?;
    // Fetch every head object with bounded concurrency rather than one blocking
    // GET at a time — fetch order does not affect the result (the whole set is
    // validated and then sorted below). Mirrors `read_anchor_records`: `blob` is a
    // `&Arc` that outlives the stream, so each future clones from it directly.
    let mut fetched: Vec<(String, Result<Vec<u8>, MemError>)> =
        futures_util::stream::iter(keys.into_iter().map(|key| {
            let blob = Arc::clone(blob);
            async move {
                let bytes = blob.get(&key).await;
                (key, bytes)
            }
        }))
        .buffer_unordered(HEAD_FETCH_CONCURRENCY)
        .collect()
        .await;
    // `buffer_unordered` yields in completion order; sort by key so that when
    // several fetches fail, the same object's error surfaces on every machine.
    fetched.sort_by(|left, right| left.0.cmp(&right.0));

    let mut heads = Vec::with_capacity(fetched.len());
    for (key, bytes) in fetched {
        // A GET failure of a listed key stays a hard error, matching
        // `read_anchor_records`: it is transient (an eventually-consistent bucket, a
        // momentary auth blip) and retried on the next read, so surfacing it is
        // correct. Every check BELOW rejects a PERMANENTLY malformed or
        // unattributable object — the kind any bucket writer can plant ONCE to
        // poison the prefix forever — so those skip-and-warn instead.
        let bytes = bytes?;
        let head: HeadPointer = match serde_json::from_slice(&bytes) {
            Ok(head) => head,
            Err(err) => {
                tracing::warn!(object_key = %key, error = %err, "skipping heads-prefix object that does not deserialize as a HeadPointer");
                continue;
            }
        };
        // The signed `team` must be the team being read. The listing prefix already
        // constrains WHERE the object was found; this constrains what it CLAIMS, so
        // a head lifted from another team's prefix and replanted here cannot be
        // counted as this team's claim about its own tip.
        if head.team != team {
            tracing::warn!(object_key = %key, claimed_team = %head.team, "skipping head pointer that claims a different team");
            continue;
        }
        // The object must sit at the canonical key for the `author_key` it claims.
        // The listing prefix is fixed, so this is the final-segment check plus a
        // rejection of any deeper nesting: a head planted under another author's
        // namespace is not that author's claim, whatever it says inside.
        if key != head_key(team, &head.author_key) {
            tracing::warn!(object_key = %key, author_key = %head.author_key.to_hex(), "skipping head pointer found outside its own author's key path");
            continue;
        }
        // Attribution: `author` must decode to `author_key`. Checked BEFORE the
        // signature only because it is the cheaper of the two; both must pass.
        if !head.verify_identity() {
            tracing::warn!(object_key = %key, author = %head.author.as_str(), "skipping head pointer whose author does not decode to its author_key");
            continue;
        }
        // Authenticity: the bucket cannot mint this without the author's secret key.
        // Everything the suppression check reports rests on this line.
        if !head.verify_sig() {
            tracing::warn!(object_key = %key, author = %head.author.as_str(), "skipping head pointer whose signature does not verify");
            continue;
        }
        heads.push(head);
    }
    heads.sort_by_key(|head| *head.author_key.as_bytes());
    // The one place a `VerifiedHeads` witness is minted: every head in `heads`
    // reached this line only by passing all four checks above.
    Ok(VerifiedHeads::from_verified(heads))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::{HEAD_DOMAIN, HeadPointer, head_key, publish_head, read_heads};
    use crate::crypto::content_hash;
    use crate::domain::{Blake3Hash, NetworkPrefix};
    use crate::oplog::{Signer, Sr25519Signer, VerifyingKey, verify};
    use crate::store::{BlobStore, MemoryBlobStore};
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEAM: &str = "team";

    fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        Ok(Sr25519Signer::from_seed_with_prefix(
            &[seed; 32],
            NetworkPrefix::HIPPIUS,
        )?)
    }

    fn tip() -> Blake3Hash {
        content_hash(b"the author's current chain tip")
    }

    #[test]
    fn head_round_trips_through_json_and_verifies() -> TestResult {
        let signer = signer(7)?;
        let head = HeadPointer::create_signed(&signer, TEAM, 42, tip());

        assert!(head.verify_sig(), "a freshly signed head must verify");
        assert!(
            head.verify_identity(),
            "a head minted from a signer binds author to key by construction"
        );

        let json = serde_json::to_string(&head)?;
        let back: HeadPointer = serde_json::from_str(&json)?;

        assert_eq!(back, head, "a head must survive a JSON round-trip");
        assert!(
            back.verify_sig(),
            "the round-tripped head must still verify"
        );
        Ok(())
    }

    #[test]
    fn head_signature_does_not_verify_under_a_sibling_types_tag() -> TestResult {
        // Mirrors `oplog::op::cross_type_signature_does_not_verify` and D7's
        // `memberkey_signature_does_not_verify_under_op_or_manifest_tag`. Every
        // signed type in this crate shares ONE sr25519 signing context, so
        // cross-type non-interchangeability rests entirely on the leading domain
        // tag. Both directions are asserted: a head signature must not verify as an
        // op, and an op signature must not verify as a head.
        //
        // The sibling tags are the REAL constants, not string literals. With
        // literals, a future edit that moved `SIGNING_DOMAIN` or `MEMBERKEY_DOMAIN`
        // onto the head tag's value would leave this test comparing the head tag
        // against a stale string it no longer collides with — green while the
        // barrier it exists to prove was gone.
        let signer = signer(13)?;
        let payload = b"shared-body-bytes";
        let head_tagged = [HEAD_DOMAIN, payload].concat();
        let op_tagged = [crate::oplog::op::SIGNING_DOMAIN, payload].concat();
        let manifest_tagged = [crate::identity::MANIFEST_DOMAIN, payload].concat();
        let memberkey_tagged = [crate::identity::MEMBERKEY_DOMAIN, payload].concat();

        // The premise the assertions below rest on: the tags genuinely differ. If a
        // future edit collapsed two of them this fails HERE, naming the cause,
        // rather than as a confusing signature-verified failure downstream.
        for (name, sibling) in [
            ("op", crate::oplog::op::SIGNING_DOMAIN),
            ("manifest", crate::identity::MANIFEST_DOMAIN),
            ("memberkey", crate::identity::MEMBERKEY_DOMAIN),
        ] {
            assert_ne!(
                HEAD_DOMAIN, sibling,
                "the head domain tag must differ from the {name} tag"
            );
        }

        let head_sig = signer.sign(&head_tagged);
        assert!(
            verify(&signer.verifying_key(), &head_tagged, &head_sig),
            "the head-tagged message verifies under its own bytes"
        );
        for (name, tagged) in [
            ("op", &op_tagged),
            ("manifest", &manifest_tagged),
            ("memberkey", &memberkey_tagged),
        ] {
            assert!(
                !verify(&signer.verifying_key(), tagged, &head_sig),
                "a head signature must not verify over a {name}-tagged message"
            );
        }

        let op_sig = signer.sign(&op_tagged);
        assert!(
            !verify(&signer.verifying_key(), &head_tagged, &op_sig),
            "an op signature must not verify over a head-tagged message"
        );
        Ok(())
    }

    #[test]
    fn verify_identity_rejects_a_head_labelled_with_another_identity() -> TestResult {
        // The attribution property. The head is re-signed AFTER the swap, so its
        // signature genuinely verifies — that is what proves `verify_identity` is
        // doing the work here rather than riding on a broken signature.
        let mine = signer(7)?;
        let theirs = signer(8)?;
        let mut head = HeadPointer::create_signed(&mine, TEAM, 42, tip());

        head.author = theirs.author_ss58();
        head.sig = mine.sign(&head.signing_bytes());

        assert!(
            head.verify_sig(),
            "the re-signed head's signature must still verify, isolating the identity check"
        );
        assert!(
            !head.verify_identity(),
            "a head whose author names a different identity than its author_key must be rejected"
        );
        Ok(())
    }

    /// One signed field's name paired with a mutation of just that field, so
    /// tamper-evidence can be asserted field by field from a single table.
    type FieldMutation<'a> = (&'a str, Box<dyn Fn(&mut HeadPointer) + 'a>);

    #[test]
    fn every_signed_field_is_tamper_evident() -> TestResult {
        // `tip_hash` is the one that matters most: it IS the claim. Were it to stop
        // being signed, a bucket could rewrite a head to name the truncated tip and
        // the suppression check would report nothing. Keep this table in step with
        // `HeadPointer::signing_bytes` — a signed field missing from it is untested.
        let mine = signer(7)?;
        let other = signer(8)?;
        let head = HeadPointer::create_signed(&mine, TEAM, 42, tip());

        assert!(head.verify_sig(), "the pristine head must verify");

        let mutations: Vec<FieldMutation<'_>> = vec![
            (
                "team",
                Box::new(|head: &mut HeadPointer| head.team = "another-team".to_owned()),
            ),
            (
                "author",
                Box::new(|head: &mut HeadPointer| head.author = other.author_ss58()),
            ),
            (
                "author_key",
                Box::new(|head: &mut HeadPointer| head.author_key = other.verifying_key()),
            ),
            (
                "lamport",
                Box::new(|head: &mut HeadPointer| head.lamport = head.lamport.wrapping_add(1)),
            ),
            (
                "tip_hash",
                Box::new(|head: &mut HeadPointer| head.tip_hash = content_hash(b"a-different-tip")),
            ),
        ];

        for (field, mutate) in mutations {
            let mut tampered = head.clone();
            mutate(&mut tampered);

            assert!(
                !tampered.verify_sig(),
                "mutating the signed field `{field}` must break verification"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn read_heads_is_empty_when_none_published() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        assert!(read_heads(&blob, TEAM).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn published_head_round_trips_through_the_blob_store() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let head = HeadPointer::create_signed(&signer(7)?, TEAM, 42, tip());

        publish_head(&blob, TEAM, &head).await?;

        assert_eq!(read_heads(&blob, TEAM).await?.to_vec(), vec![head]);
        Ok(())
    }

    #[tokio::test]
    async fn republishing_replaces_the_authors_single_head() -> TestResult {
        // The mutable-key property, asserted rather than assumed: a second publish
        // by the same author overwrites the first, so an author never accumulates
        // two competing claims about their own tip.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let signer = signer(7)?;
        let first = HeadPointer::create_signed(&signer, TEAM, 1, content_hash(b"tip-one"));
        let second = HeadPointer::create_signed(&signer, TEAM, 2, content_hash(b"tip-two"));

        publish_head(&blob, TEAM, &first).await?;
        publish_head(&blob, TEAM, &second).await?;

        assert_eq!(
            read_heads(&blob, TEAM).await?.to_vec(),
            vec![second],
            "the newer head replaces the older at the author's one key"
        );
        Ok(())
    }

    /// Assert a planted object is SKIPPED while a valid sibling still reads back —
    /// one poison object must not blind the whole read. The sibling is signed by
    /// seed 7; the planted bytes go to `key`.
    async fn assert_planted_object_is_skipped(key: &str, bytes: Vec<u8>) -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let good = HeadPointer::create_signed(&signer(7)?, TEAM, 42, tip());
        publish_head(&blob, TEAM, &good).await?;
        blob.put(key, bytes).await?;

        assert_eq!(
            read_heads(&blob, TEAM).await?.to_vec(),
            vec![good],
            "the planted object must be skipped and the valid sibling returned"
        );
        Ok(())
    }

    #[tokio::test]
    async fn undecodable_heads_object_is_skipped() -> TestResult {
        let planted = format!("{TEAM}/_heads/{}", VerifyingKey::new([0xAA; 32]).to_hex());
        assert_planted_object_is_skipped(&planted, b"not a head pointer".to_vec()).await
    }

    #[tokio::test]
    async fn head_with_a_broken_signature_is_skipped() -> TestResult {
        // A head whose signed bytes were rewritten after signing: the bucket moved
        // the claimed tip backward. Without the signature check this would be
        // accepted as the author's claim.
        let mut forged = HeadPointer::create_signed(&signer(9)?, TEAM, 7, tip());
        forged.tip_hash = content_hash(b"a tip the author never signed");
        assert!(!forged.verify_sig(), "the fixture must be unverifiable");

        let key = head_key(TEAM, &forged.author_key);
        assert_planted_object_is_skipped(&key, serde_json::to_vec(&forged)?).await
    }

    #[tokio::test]
    async fn head_whose_author_key_disagrees_with_its_path_is_skipped() -> TestResult {
        // A validly-signed head of author 9, planted under author 0xAA's key path.
        // Everything about the object itself is sound; only its LOCATION lies. If
        // the reader trusted the path it would attribute this claim to 0xAA.
        let head = HeadPointer::create_signed(&signer(9)?, TEAM, 7, tip());
        assert!(head.verify_sig(), "the planted head is genuinely signed");

        let wrong_path = head_key(TEAM, &VerifyingKey::new([0xAA; 32]));
        assert_planted_object_is_skipped(&wrong_path, serde_json::to_vec(&head)?).await
    }

    #[tokio::test]
    async fn head_labelled_with_another_identity_is_skipped() -> TestResult {
        // The attribution check AT THE READER, not just on the method. This object
        // passes every other gate: it is signed by seed 9 and re-signed after the
        // swap (so `verify_sig` holds), it claims the right team, and it sits at the
        // canonical key for the `author_key` it carries. Only `verify_identity`
        // rejects it — without that call the reader would report a claim about the
        // TAIL OF ANOTHER AUTHOR, attributed to an SS58 that never made it.
        let mine = signer(9)?;
        let theirs = signer(8)?;
        let mut head = HeadPointer::create_signed(&mine, TEAM, 7, tip());
        head.author = theirs.author_ss58();
        head.sig = mine.sign(&head.signing_bytes());

        assert!(
            head.verify_sig(),
            "the mislabelled head is genuinely signed, isolating the identity check"
        );

        let key = head_key(TEAM, &head.author_key);
        assert_planted_object_is_skipped(&key, serde_json::to_vec(&head)?).await
    }

    #[tokio::test]
    async fn head_claiming_another_team_is_skipped() -> TestResult {
        // A validly-signed head for team "other", replanted under this team's
        // prefix at its own author's key path. Only the signed `team` gives it away.
        let head = HeadPointer::create_signed(&signer(9)?, "other", 7, tip());
        assert!(
            head.verify_sig(),
            "the transplanted head is genuinely signed"
        );

        let key = head_key(TEAM, &head.author_key);
        assert_planted_object_is_skipped(&key, serde_json::to_vec(&head)?).await
    }

    #[tokio::test]
    async fn read_heads_sorts_by_author_key() -> TestResult {
        // Deterministic order across machines: the report built from these must not
        // depend on backend listing order.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let mut published = Vec::new();
        for seed in [3_u8, 1, 2] {
            let head = HeadPointer::create_signed(&signer(seed)?, TEAM, 1, tip());
            publish_head(&blob, TEAM, &head).await?;
            published.push(head);
        }
        published.sort_by_key(|head| *head.author_key.as_bytes());

        assert_eq!(read_heads(&blob, TEAM).await?.to_vec(), published);
        Ok(())
    }
}
