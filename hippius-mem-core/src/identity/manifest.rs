//! The founder-signed [`TeamManifest`]: who may write to a team's op-log.
//!
//! # Why this exists
//!
//! A "team" is a shared namespace, and without a manifest *any* signer could
//! append ops to a team's op-log and have them converge (the open-team default).
//! The manifest closes that: a
//! team's **founder** signs a list of member SS58 addresses, and
//! [`crate::store::MemoryStore::sync`] only converges ops whose author is a
//! current member. The manifest is the single source of truth for membership,
//! re-derived from storage (never trusted from local cache) on every sync.
//!
//! # Trust model and its limits
//!
//! Like the op-log, the manifest store lives in an untrusted bucket. Trust is
//! re-derived from the signatures on read: [`load_manifest`] keeps only
//! manifests that [`TeamManifest::verify`] AND name the team they are loaded
//! under (the team-binding check, mirroring the op-log's `verify_team_binding`),
//! then elects the live one by walking a **chain of custody**: it anchors on the
//! trusted founder's lowest-version manifest and advances only to a
//! higher-versioned manifest that the manifest live at that moment authorized —
//! signed either by the live founder's own key, or by the recovery key that
//! manifest NAMES. Anything else is skipped, not fatal. So a non-member can
//! neither seize the team (an unauthorized manifest never wins, however high its
//! version) nor deny service to it (an inconsistency never errors a member's
//! `sync`), while a team whose founder key is lost can still move on through the
//! recovery key its founder committed to in advance.
//!
//! A signature proving a manifest is *authentic* is therefore never enough to
//! make it *authoritative*: the election asks who authorized this key, and
//! answers only from the chain. That distinction is what keeps a self-signed
//! manifest from governing a team, however high a version it claims.
//!
//! One corollary shapes the code below: object keys are attacker-chosen, so
//! nothing about the election may depend on them. Three rules enforce that, and
//! each defeats the replay takeover on its own:
//!
//! 1. **A manifest is valid only at the object key its own signed `version`
//!    designates** ([`load_manifest`]). An object planted at `!a` to list first
//!    is not a low-ranked candidate, it is not a candidate. This is the
//!    storage-layer sibling of the team binding: the untrusted bucket may not
//!    say where a manifest lives any more than it may say which team it governs.
//! 2. **Ties between authority classes go to the founder** ([`elect_from_group`]).
//! 3. **Ties within one authority class are broken by CONTENT**
//!    ([`content_rank`]) — a hash of the signed bytes, so two rivals order the
//!    same way for every reader in every listing order, and no attacker can win
//!    a tie by choosing where to put an object.
//!
//! Ordering across versions comes from the signed `version` field throughout.
//!
//! What it deliberately does NOT defend against (same shape as the op-log's
//! documented gaps): an attacker who *overwrites the genesis object itself* can
//! reset the trusted founder, because nothing pins the genesis. Defending that
//! is on-chain anchoring's job (future work), not this layer's.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::domain::{NetworkPrefix, Ss58};
use crate::error::MemError;
use crate::oplog::{Signature, Signer, VerifyingKey, verify};
use crate::store::BlobStore;

/// The domain-separation tag prefixed onto [`TeamManifest::signing_bytes`].
///
/// Distinct from the op-log's tag, so a manifest signature can never be replayed
/// as an op signature even though both run through the same schnorrkel signing
/// context — the signed message shapes differ from their first bytes.
pub(crate) const MANIFEST_DOMAIN: &[u8] = b"hippius-memory-manifest/v1";

/// v2 domain tag: manifests that NAME a recovery key sign under this tag,
/// with the recovery key bytes appended to the v1 layout. A manifest with no
/// recovery key keeps the v1 tag and byte layout exactly, so every existing
/// manifest and signature stays valid without migration.
const MANIFEST_DOMAIN_V2: &[u8] = b"hippius-memory-manifest/v2";

/// A founder-signed statement of a team's membership at a given version.
///
/// Fields are public because a manifest is a data record consumed by later
/// layers (the membership filter in `sync`) and by deserialization; its
/// integrity is guaranteed by [`TeamManifest::verify`], not by private fields —
/// exactly the discipline [`crate::oplog::Op`] follows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamManifest {
    /// The team (shared namespace) this manifest governs.
    pub team: String,
    /// The current member set, by SS58 address.
    ///
    /// A [`BTreeSet`] so iteration is sorted (the signed bytes are a
    /// deterministic function of the *set*, not an insertion order) and
    /// membership tests in `sync` are `O(log n)`.
    pub members: BTreeSet<Ss58>,
    /// Monotonic version; the highest valid version is the live membership.
    pub version: u64,
    /// The founder's SS58 address — the only identity permitted to change
    /// membership. Bound to `founder_key` exactly like [`crate::oplog::Op`]'s
    /// `author`/`author_key`: [`TeamManifest::verify`] requires it to decode to
    /// `founder_key`.
    pub founder: Ss58,
    /// The sr25519 public key the signature is verified against.
    pub founder_key: VerifyingKey,
    /// Founder-named recovery verifying key, if any. Part of the signed
    /// bytes (v2 domain): naming it is a founder-authorized act, and the
    /// chain rule (`load_manifest`) lets this key advance the manifest chain
    /// if the founder key is lost.
    ///
    /// SECURITY: this field is UNVALIDATED at both construction and
    /// deserialization — nothing here rejects the Ristretto identity point
    /// (32 all-zero bytes), which trivially "verifies" a forged sr25519
    /// signature over ANY message. [`crate::oplog::verify`] now rejects that
    /// key outright, before schnorrkel is even consulted, so any manifest that
    /// tries to use it as an authorization root — a candidate "signed by the
    /// recovery key," which becomes that candidate's own `founder_key` — fails
    /// [`TeamManifest::verify`] and never reaches this module's election at
    /// all. The screens here ([`TeamManifest::trusted_recovery_key`],
    /// [`authority_of`], [`elect_live`]'s anchor check) are kept anyway, as
    /// defense in depth: this field is an authorization ROOT, and a trust root
    /// should not depend solely on a guard living in another module to stay
    /// safe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<VerifyingKey>,
    /// sr25519 signature over [`TeamManifest::signing_bytes`].
    pub sig: Signature,
}

impl TeamManifest {
    /// The exact bytes that are signed and verified.
    ///
    /// A domain-tagged, length-framed concatenation of every field **except**
    /// `sig`. Hand-built (not `serde_json`) so it is total and host-independent:
    /// each variable-length field carries a fixed 8-byte little-endian length
    /// prefix and fixed-width fields are emitted verbatim, so the bytes — and
    /// thus the signature — agree across 32- and 64-bit machines. The member
    /// count is framed explicitly so the encoding is injective: without it the
    /// raw `version` bytes could be mistaken for an extra framed member.
    ///
    /// The domain tag branches on `recovery_key`: `None` emits [`MANIFEST_DOMAIN`]
    /// (the v1 tag) and stops at `founder_key`, byte-for-byte what a pre-recovery
    /// manifest always signed, so every existing manifest and signature stays
    /// valid with no migration. `Some(key)` emits [`MANIFEST_DOMAIN_V2`] instead
    /// and appends the recovery key's raw bytes after the v1 layout.
    ///
    /// Cross-version replay is impossible, and the precise reason matters: it is
    /// NOT that the two tags differ at their first byte (they do not — they
    /// share the 25-byte prefix `b"hippius-memory-manifest/v"`). What actually
    /// rules out a collision is that [`MANIFEST_DOMAIN`] and
    /// [`MANIFEST_DOMAIN_V2`] are the SAME length (26 bytes each) and differ at
    /// a FIXED byte offset (index 25, their last byte) that is written before
    /// any variable-length framed field follows — so for any `team`/`members`/
    /// `founder` content, a v1 message and a v2 message diverge at that fixed
    /// offset and can never be byte-identical. Equal length is the load-bearing
    /// half of that argument: it is what pins the divergence to a FIXED offset
    /// rather than letting one tag become a variable-length prefix of the
    /// other. A future domain tag of a *different* length (e.g. a hypothetical
    /// `b"hippius-memory-manifest/v10"`, 27 bytes) would make the shorter tag a
    /// strict byte-prefix of the longer one, and this disjointness argument
    /// would have to be re-derived for that pair before it could be trusted —
    /// equal length cannot simply be assumed of the next domain tag added here.
    ///
    /// Naming a recovery key this way makes it a founder-authorized act: it
    /// rides inside the signed bytes, so tampering with it after signing breaks
    /// [`TeamManifest::verify`] like tampering with any other field.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.recovery_key {
            None => buf.extend_from_slice(MANIFEST_DOMAIN),
            Some(_) => buf.extend_from_slice(MANIFEST_DOMAIN_V2),
        }
        push_framed(&mut buf, self.team.as_bytes());
        // Length-prefix the member count, then each member in sorted order, so
        // the encoding commits to the whole set unambiguously.
        let count = u64::try_from(self.members.len()).unwrap_or(u64::MAX);
        buf.extend_from_slice(&count.to_le_bytes());
        for member in &self.members {
            push_framed(&mut buf, member.as_str().as_bytes());
        }
        buf.extend_from_slice(&self.version.to_le_bytes());
        push_framed(&mut buf, self.founder.as_str().as_bytes());
        buf.extend_from_slice(self.founder_key.as_bytes());
        if let Some(recovery_key) = &self.recovery_key {
            buf.extend_from_slice(recovery_key.as_bytes());
        }
        buf
    }

    /// Build a manifest signed by `signer`, who becomes the `founder`, with no
    /// recovery key named.
    ///
    /// Delegates to [`Self::create_signed_with_recovery`] with `recovery_key:
    /// None`, so the v1 and v2 signing paths share one implementation and can
    /// never drift apart into two competing encodings of the same layout.
    #[must_use]
    pub fn create_signed<S: Signer + ?Sized>(
        signer: &S,
        team: String,
        members: BTreeSet<Ss58>,
        version: u64,
    ) -> Self {
        Self::create_signed_with_recovery(signer, team, members, version, None)
    }

    /// Build a manifest signed by `signer`, who becomes the `founder`,
    /// optionally naming `recovery_key` as a second identity the chain rule
    /// (Task 9's `load_manifest` election) may let advance the manifest chain
    /// if the founder key is ever lost.
    ///
    /// `founder`/`founder_key` are filled from the signer, and the founder is
    /// always inserted into `members` (a founder who is not a member of their
    /// own team is a nonsensical state, so it is made unrepresentable here).
    /// A `Some` `recovery_key` moves signing onto the [`MANIFEST_DOMAIN_V2`]
    /// tag (see [`Self::signing_bytes`]): naming a recovery key is a
    /// founder-authorized act, so it must ride inside the signed bytes rather
    /// than being a field an attacker could bolt on after the fact without
    /// invalidating the signature. `None` signs under the unchanged v1 layout.
    ///
    /// SECURITY: `recovery_key` is accepted here WITHOUT validation — this
    /// constructor will happily sign a manifest naming the Ristretto identity
    /// point (all-zero public key), which trivially "verifies" a forged
    /// signature over any message (see [`TeamManifest::recovery_key`]'s doc).
    /// It is deliberately not validated HERE: a bucket-crafted manifest
    /// bypasses this constructor entirely, so validating at construction would
    /// not close the hole anyway. [`crate::oplog::verify`] now rejects the
    /// identity point globally, so a manifest that tries to use it as an
    /// authorization root fails [`TeamManifest::verify`] outright; this
    /// module's load-side screens ([`TeamManifest::trusted_recovery_key`],
    /// [`authority_of`], [`load_manifest`]'s chain-of-custody election) are
    /// kept regardless, as defense in depth — a trust root must not depend
    /// solely on a guard living in another module to stay safe.
    ///
    /// `S: ?Sized` so a `&dyn Signer` is accepted as readily as a concrete
    /// signer, mirroring [`crate::oplog::Op::create_signed`].
    #[must_use]
    pub fn create_signed_with_recovery<S: Signer + ?Sized>(
        signer: &S,
        team: String,
        mut members: BTreeSet<Ss58>,
        version: u64,
        recovery_key: Option<VerifyingKey>,
    ) -> Self {
        let founder = signer.author_ss58();
        let founder_key = signer.verifying_key();
        members.insert(founder.clone());
        let mut manifest = Self {
            team,
            members,
            version,
            founder,
            founder_key,
            recovery_key,
            // Placeholder: `signing_bytes` excludes `sig`, so its value here does
            // not affect the message that gets signed.
            sig: Signature::new([0u8; 64]),
        };
        let msg = manifest.signing_bytes();
        manifest.sig = signer.sign(&msg);
        manifest
    }

    /// The recovery key this manifest names, but only if it is one that could
    /// authorize anything.
    ///
    /// A named [identity point](VerifyingKey::is_identity_point) is reported as
    /// NO recovery key: honouring it would mean any passer-by could mint the
    /// takeover manifest it "authorizes". `recovery_key` is unvalidated at both
    /// construction and deserialization (see [`TeamManifest::recovery_key`]), and
    /// a bucket-crafted manifest bypasses this crate's constructors entirely, so
    /// screening at every point of USE is the only guard an attacker cannot route
    /// around.
    ///
    /// Every consumer that carries a recovery key forward or acts on one should
    /// go through this accessor rather than reading the field, so a degenerate
    /// key is dropped rather than propagated.
    #[must_use]
    pub fn trusted_recovery_key(&self) -> Option<&VerifyingKey> {
        self.recovery_key
            .as_ref()
            .filter(|key| !key.is_identity_point())
    }

    /// Whether `key` is authorized to provision this team's key: either this
    /// manifest's `founder_key`, or its [`TeamManifest::trusted_recovery_key`]
    /// — never the raw `recovery_key` field, which [`Self::trusted_recovery_key`]
    /// screens for the Ristretto identity point.
    ///
    /// The single source of truth for this rule: `hippius_mem_core::identity::teamkey::fetch_team_key`
    /// calls this to decide whether to accept a [`crate::WrappedKey`] on the READ
    /// path, and `hippius-mem doctor`'s proactive wrap-integrity check calls the
    /// SAME method to decide whether to warn about one — so the two enforcement
    /// points can never silently diverge on what "authorized" means.
    #[must_use]
    pub fn authorizes_provisioner(&self, key: &VerifyingKey) -> bool {
        *key == self.founder_key || self.trusted_recovery_key() == Some(key)
    }

    /// Whether this manifest is authentic: the signature verifies under
    /// `founder_key`, AND `founder` decodes to exactly `founder_key`.
    ///
    /// The second check binds the human SS58 label to the signing key (same
    /// guarantee as [`crate::oplog::Op::verify_identity`]) so a writer cannot
    /// sign with one key while claiming another's founder address.
    #[must_use]
    pub fn verify(&self) -> bool {
        verify(&self.founder_key, &self.signing_bytes(), &self.sig)
            && crate::identity::ss58_decode(&self.founder).is_ok_and(|(key, prefix)| {
                // Bind the network prefix to Hippius, as Op::verify_identity does:
                // membership is matched on the founder's ss58 string, so the same
                // key under a different prefix is a different (foreign) identity.
                key == self.founder_key && prefix == NetworkPrefix::HIPPIUS
            })
    }
}

use crate::framing::push_framed;

/// The object key a manifest at `version` is stored under.
///
/// `{team}/_manifest/{version:020}`: zero-padded to 20 digits (the width of
/// `u64::MAX`) so the key is fixed-width and one object exists per version — a
/// re-published version overwrites rather than forks.
fn manifest_key(team: &str, version: u64) -> String {
    format!("{team}/_manifest/{version:020}")
}

/// The object-key prefix under which `team`'s manifests live.
fn manifest_prefix(team: &str) -> String {
    format!("{team}/_manifest/")
}

/// Publish `manifest` to `blob`, after verifying it.
///
/// Refusing to store an unverifiable manifest keeps the bucket from ever holding
/// a manifest the founder did not sign through this path.
///
/// # Errors
///
/// [`MemError::Unauthorized`] if `manifest` does not [`TeamManifest::verify`]
/// (the founder did not sign it through this path — a permission failure, not a
/// backend one), [`MemError::Serialize`] if it cannot be encoded, or
/// [`MemError::Storage`] if the backend write fails.
pub async fn publish_manifest(
    blob: &dyn BlobStore,
    manifest: &TeamManifest,
) -> Result<(), MemError> {
    if !manifest.verify() {
        return Err(MemError::Unauthorized(format!(
            "refusing to publish an unverifiable manifest for team {:?} version {}",
            manifest.team, manifest.version
        )));
    }
    let key = manifest_key(&manifest.team, manifest.version);
    let bytes = serde_json::to_vec(manifest)?;
    blob.put(&key, bytes).await
}

/// Load the current (highest valid version) manifest for `team`, or `None` if
/// none exists.
///
/// Trust is re-derived from storage: every object under the manifest prefix is
/// fetched, and a manifest is kept only if it (a) deserializes, (b) passes
/// [`TeamManifest::verify`], (c) names *this* `team` in its signed `team` field,
/// (d) does not name the [identity point](VerifyingKey::is_identity_point) as
/// its `founder_key`, and (e) is stored under the object key its own signed
/// `version` designates ([`manifest_key`]).
///
/// Check (c) is the manifest analogue of the op-log's `verify_team_binding`: the
/// bucket is untrusted, so a validly-signed manifest copied out of *another*
/// team's storage must not be allowed to govern this one. Check (d) is subsumed
/// by (b) — [`crate::oplog::verify`] screens that key for every caller — and is
/// kept anyway, because this function's election treats `founder_key` as an
/// authorization root and says so where it is read. Check (e) is (c)'s
/// storage-layer sibling: the bucket may not decide WHERE a manifest lives any
/// more than it may decide which team it governs, and it collapses "plant a
/// replayed manifest under any key you like" into "overwrite the one canonical
/// key for that version" — an access level that is already a documented
/// residual (see [`elect_live`]) rather than a fresh write-only primitive.
/// Anything failing (a)–(e) is skipped (logged, never fatal — one junk, foreign,
/// or off-key upload must not blind the team).
///
/// The survivors are then handed to [`elect_live`], which walks the chain of
/// custody from an anchor. Only the ANCHOR depends on `expected_founder`; the
/// walk itself is identical in both trust modes:
///
/// - `Some(founder)` — the founder is PINNED out of band (operator config, which
///   the untrusted bucket cannot rewrite). The chain starts at that address's
///   LOWEST-version manifest. A bucket that overwrites the genesis (version-0)
///   object with a self-signed manifest naming a different founder can no longer
///   seize the team — that manifest anchors nothing, and neither does any
///   recovery key it names. If no manifest is signed by the pinned founder yet,
///   the team reads as open (`None`), never as the attacker's.
/// - `None` — trust-on-genesis (backward compatible): the genesis
///   (lowest-version) survivor fixes the trusted founder. This is the documented
///   residual gap — a bucket with write access CAN overwrite the genesis object
///   to elect itself — closed only by pinning a founder.
///
/// In both modes a manifest the live one did not authorize is dropped (skipped +
/// warned), never honoured and never fatal — a single `?`-propagated error here
/// would otherwise break every member's `sync`. A pin fixes only where the chain
/// STARTS, so a pinned team that later recovers through its recovery key elects a
/// manifest whose `founder` is the recovery identity, not the pin; the operator's
/// pin should be updated to the new founder after a recovery.
///
/// # Errors
///
/// [`MemError::Storage`] / [`MemError::NotFound`] only from the prefix `list`. A
/// per-object fetch failure is skipped + warned (not returned), and manifest
/// inconsistencies are filtered out, so neither aborts a member's sync.
pub async fn load_manifest(
    blob: &dyn BlobStore,
    team: &str,
    expected_founder: Option<&Ss58>,
) -> Result<Option<TeamManifest>, MemError> {
    let prefix = manifest_prefix(team);
    let keys = blob.list(&prefix).await?;

    let mut valid: Vec<TeamManifest> = Vec::with_capacity(keys.len());
    for key in &keys {
        // A per-object fetch fault — a transient NotFound/Storage on one of the
        // many manifest versions a team accumulates — must not abort the whole
        // team's sync. The `list` succeeded, so skip this object and keep the
        // rest, mirroring the skip-and-continue every other failure in this loop
        // already uses and honoring this function's "never fatal" contract.
        let bytes = match blob.get(key).await {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!(
                    object_key = %key,
                    error = %err,
                    "skipping a manifest object that could not be fetched"
                );
                continue;
            }
        };
        match serde_json::from_slice::<TeamManifest>(&bytes) {
            // The identity-point key validates a signature anyone can forge.
            // `crate::oplog::verify` now rejects it outright, so `verify()` below
            // would already refuse this manifest; the explicit screen stays
            // because this function's election treats `founder_key` as an
            // authorization root, and it keeps such a manifest out of the genesis
            // founder derivation with a diagnostic that names the real cause
            // rather than a generic signature failure.
            Ok(manifest) if manifest.founder_key.is_identity_point() => tracing::warn!(
                object_key = %key,
                manifest_version = manifest.version,
                "skipping a team manifest whose founder key is the identity point (it authenticates no one)"
            ),
            // The OBJECT-KEY binding, and the reason the election below never
            // has to reason about where an object sits. `manifest_key` is a
            // total function of two SIGNED fields (`team`, `version`), so
            // "this manifest is stored where it says it belongs" is a check the
            // bucket cannot talk its way around. Without it, a write-only
            // attacker can replay any manifest object they ever saw under a key
            // of their choosing — e.g. `{team}/_manifest/!a`, which lists ahead
            // of every zero-padded canonical key — and thereby put a manifest
            // the founder has since superseded back into the candidate set at
            // its old version. With it, placing a manifest at version N means
            // writing the ONE key for N, which is the delete/overwrite-access
            // attack `elect_live` documents as an operational residual, not a
            // new write-only primitive.
            Ok(manifest) if key != &manifest_key(team, manifest.version) => tracing::warn!(
                object_key = %key,
                canonical_key = %manifest_key(team, manifest.version),
                manifest_version = manifest.version,
                "skipping a team manifest stored under a key its own signed version does not designate"
            ),
            Ok(manifest) if manifest.verify() && manifest.team == team => valid.push(manifest),
            // Validly signed but bound to a different team — an attacker copying
            // their own manifest into this team's prefix to hijack it. Refuse it.
            Ok(manifest) if manifest.verify() => tracing::warn!(
                object_key = %key,
                manifest_team = %manifest.team,
                loading_team = %team,
                "skipping a team manifest bound to a different team"
            ),
            Ok(_) => tracing::warn!(
                object_key = %key,
                "skipping a team manifest that fails signature/identity verification"
            ),
            Err(err) => tracing::warn!(
                object_key = %key,
                error = %err,
                "skipping object under the manifest prefix that does not deserialize as a TeamManifest"
            ),
        }
    }

    // Fix the founder the chain ANCHORS on. A PINNED founder (operator config) is
    // the trust anchor the bucket cannot rewrite, so it wins outright; otherwise
    // fall back to the genesis (lowest-version) survivor. Check (e) above makes
    // versions unique among survivors — one object exists per canonical key — so
    // the minimum is already unambiguous; ranking by `content_rank` as well
    // costs nothing and means NO step of this module, not even a step that
    // cannot currently tie, decides anything by the order the bucket listed its
    // objects in. Cloned so the borrow of `valid` ends before it is moved into
    // `elect_live`, which consumes it to walk the chain without copying.
    let trusted_founder: Ss58 = if let Some(pinned) = expected_founder {
        pinned.clone()
    } else {
        let Some(genesis) = valid
            .iter()
            .min_by_key(|manifest| (manifest.version, content_rank(manifest)))
        else {
            return Ok(None);
        };
        genesis.founder.clone()
    };

    Ok(elect_live(valid, &trusted_founder))
}

/// Which of the live manifest's two authorities permits a candidate to become
/// the next link in the chain.
///
/// Founder outranking Recovery is NOT encoded by declaration order — no `Ord`
/// is derived here, and nothing compares variants by discriminant. Precedence
/// lives entirely in [`elect_from_group`]'s two passes: it looks for an
/// [`Authority::Founder`] match first and only falls back to
/// [`Authority::Recovery`] if none exists. Reordering these variants has no
/// effect on the election.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Authority {
    /// The candidate is signed by the live founder's own key: a re-publish —
    /// a membership change, or naming a different recovery key.
    Founder,
    /// The candidate is signed by the recovery key the live manifest NAMES: a
    /// takeover after the founder key is lost.
    Recovery,
}

/// Which authority in `live` permits `candidate` to become the next link, or
/// `None` if neither does.
///
/// Exactly two authorities exist, and no others. Both compare keys rather than
/// SS58 strings — [`TeamManifest::verify`] has already bound each manifest's
/// `founder` to its `founder_key`, so the two tests are equivalent and the key
/// is the tighter one to state.
///
/// The candidate's own key is screened against the
/// [identity point](VerifyingKey::is_identity_point) FIRST, before either
/// comparison. [`crate::oplog::verify`] now rejects that key outright, so a
/// manifest carrying it cannot reach this function through [`load_manifest`] at
/// all; the screen is kept because this file treats `founder_key` and
/// `recovery_key` as authorization ROOTS, and a trust root should not depend on
/// a guard living in another module to be safe.
fn authority_of(live: &TeamManifest, candidate: &TeamManifest) -> Option<Authority> {
    if candidate.founder_key.is_identity_point() {
        return None;
    }

    if candidate.founder_key == live.founder_key {
        return Some(Authority::Founder);
    }

    if live.trusted_recovery_key() == Some(&candidate.founder_key) {
        return Some(Authority::Recovery);
    }

    None
}

/// The tie-break rank of a manifest among same-version rivals of the SAME
/// authority class: a BLAKE3 digest of its [signing bytes](TeamManifest::signing_bytes).
///
/// # Why content, and not the order the candidates arrived in
///
/// Object keys are attacker-chosen. A manifest planted under a non-canonical key
/// (`{team}/_manifest/!a` rather than the canonical zero-padded version) sorts
/// BEFORE every legitimate object, so whoever writes to the bucket would pick
/// which same-version candidate is examined first. Where the two rivals were
/// signed by DIFFERENT authorities, [`elect_from_group`]'s founder-beats-recovery
/// rank already settles it; where they were signed by the SAME authority — the
/// state a manifest version that was ever rewritten IN PLACE leaves behind, so
/// that a saved copy of the superseded object and its replacement both claim one
/// version — that rank is silent, and only content can separate them.
///
/// So the rank is a pure function of the SIGNED bytes. Every reader computes the
/// same order for the same set, in any listing order, and an attacker cannot
/// improve their standing by choosing where to write: the only way to change a
/// rank is to change a manifest, which breaks its signature.
///
/// It ranks, it does not adjudicate. Two rivals of one authority at one version
/// are BOTH signed by a key the chain trusts, so no rule can tell which the
/// founder meant; determinism is the whole guarantee, and it is what makes the
/// choice unbuyable rather than merely arbitrary. `load_manifest` keeps that
/// situation out of reach anyway — it accepts a manifest only at the canonical
/// key for its own signed version, so the bucket holds at most one candidate per
/// version — and the honest protocol no longer creates it either: every publish
/// path takes a FRESH version (see `MemoryStore::publish_recovery_key`, which
/// used to rewrite the live version in place). This is the third, innermost of
/// those three layers.
///
/// The digest is [`crate::crypto::content_hash`], whose preimage here is a
/// `hippius-memory-manifest/*`-tagged message: disjoint from that function's
/// other two domains (raw ciphertext, op-log signing bytes), and never compared
/// against them — these ranks are only ever compared with each other.
fn content_rank(manifest: &TeamManifest) -> [u8; 32] {
    *crate::crypto::content_hash(&manifest.signing_bytes()).as_bytes()
}

/// Elect the next link from `group` — candidates that all carry the SAME
/// version — or `None` if `live` authorizes none of them.
///
/// Precedence is fixed by AUTHORITY: a candidate the live manifest's own founder
/// key signs beats one authorized only by its recovery key, every time. A
/// founder re-publishing at version N therefore always defeats a recovery-key
/// holder racing for the same N, which is the revoke-before-use semantics the
/// retirement rule needs to actually mean something. Within one authority class
/// [`content_rank`] settles it — never the order `group` happens to be in, which
/// an attacker with bucket write access would otherwise choose.
fn elect_from_group<'a>(
    live: &TeamManifest,
    group: &'a [TeamManifest],
) -> Option<&'a TeamManifest> {
    let lowest_ranked = |wanted: Authority| {
        group
            .iter()
            .filter(|candidate| authority_of(live, candidate) == Some(wanted))
            .min_by_key(|candidate| content_rank(candidate))
    };
    let elected =
        lowest_ranked(Authority::Founder).or_else(|| lowest_ranked(Authority::Recovery))?;

    // One object exists per version under the canonical key layout, and
    // `load_manifest` enforces that layout, so a version with rivals means this
    // function was called with a set assembled some other way. Worth an
    // operator's attention even though the election itself is not fooled by it.
    if group.len() > 1 {
        tracing::warn!(
            manifest_version = elected.version,
            candidates = group.len(),
            elected_founder = %elected.founder.as_str(),
            "multiple team manifests share one version; electing the one the live manifest authorizes most directly"
        );
    }

    Some(elected)
}

/// Whether `manifest` may serve as the chain's anchor for `anchor_founder`.
///
/// The anchor governs like every other link, so it is screened for the
/// [identity point](VerifyingKey::is_identity_point) exactly like every
/// candidate: [`load_manifest`] already refuses such manifests, but [`elect_live`]
/// must be safe on any input it is handed.
fn can_anchor(manifest: &TeamManifest, anchor_founder: &Ss58) -> bool {
    &manifest.founder == anchor_founder && !manifest.founder_key.is_identity_point()
}

/// The chain's anchor within `group` — candidates that all carry the SAME
/// version — or `None` if `anchor_founder` signed none of them.
///
/// The anchor decides which manifest's `founder_key` and `recovery_key` govern
/// the first hop, so an attacker who can choose it can choose the whole chain.
/// It therefore gets the same content-ordered tie-break every later link gets
/// ([`content_rank`]), rather than the listing-order `position()` scan it once
/// used.
fn elect_anchor<'a>(group: &'a [TeamManifest], anchor_founder: &Ss58) -> Option<&'a TeamManifest> {
    let anchor = group
        .iter()
        .filter(|manifest| can_anchor(manifest, anchor_founder))
        .min_by_key(|manifest| content_rank(manifest))?;

    let rivals = group
        .iter()
        .filter(|manifest| can_anchor(manifest, anchor_founder))
        .count();
    if rivals > 1 {
        tracing::warn!(
            manifest_version = anchor.version,
            candidates = rivals,
            anchor_founder = %anchor_founder.as_str(),
            "multiple team manifests claim the chain's anchor version; anchoring on the one the content order fixes"
        );
    }

    Some(anchor)
}

/// Elect the live manifest out of `valid` by walking the team's chain of
/// custody, or `None` if no chain starts at `anchor_founder`.
///
/// # The rule
///
/// ANCHOR on `anchor_founder`'s lowest-version manifest — the pinned founder's
/// first manifest when a founder is pinned, else the genesis survivor's, the two
/// trust modes [`load_manifest`] documents (it derives `anchor_founder` for
/// both, so this walk is identical in either). Then WALK, in ascending version
/// order, one VERSION at a time: among all candidates sharing the next version,
/// [`elect_from_group`] picks the one the currently live manifest authorizes most
/// directly. The elected candidate becomes live, and its own recovery key — not
/// its predecessor's — governs the next hop. Everything else is skipped and
/// warned, never fatal, preserving [`load_manifest`]'s contract.
///
/// # Why a walk replaced a filter
///
/// Filtering to a single founder can never let a team survive a lost founder
/// key: the only identity permitted to publish is the one that disappeared. The
/// walk lets authority MOVE, but one hop at a time and only where the manifest
/// live at that moment authorized the move. Three consequences worth stating
/// plainly, because each is load-bearing:
///
/// - **A recovery key is only as live as the manifest naming it.** A recovery
///   key named by a manifest the walk never reached — an attacker's genesis
///   under a pin, or a version already superseded — authorizes nothing. Naming a
///   different recovery key (or none) in a later manifest retires the old one,
///   PROVIDED the retiring manifest is reached: see the residual below.
/// - **Versions come from the SIGNED `version` field**, never from the object
///   key, so copying a manifest object to a higher-numbered key cannot promote
///   it; `version` is inside the signature and a re-publish would have to be
///   signed by an authorized key anyway.
/// - **Nothing here reads the order the candidates arrived in.** Object keys
///   are attacker-chosen, hence so is listing order. Across authority classes
///   the tie goes to the founder ([`elect_from_group`]); within one class — and
///   at the anchor, where it matters most — it goes to the lower
///   [`content_rank`]. Feed this function the same set in any two orders and it
///   elects the same manifest.
///
/// # The residual: retirement is only as durable as the objects
///
/// Retirement is expressed by a later manifest, and the bucket is untrusted, so
/// an attacker who holds a compromised recovery key AND has DELETE access can
/// delete the manifests that retired it, rewinding the chain's anchor to a
/// version that still names their key, and re-chain from there. Nothing in this
/// walk can detect that: the remaining objects are genuine and mutually
/// consistent.
///
/// [`crate::MemoryStore`]'s monotonic version watermark does NOT blunt this — the
/// attacker re-chains to a HIGHER version, and the watermark only refuses LOWER
/// ones. The real mitigations are operational: bucket object retention or
/// versioning so the retiring manifest cannot be deleted, plus pin hygiene.
/// Without delete access this attack does not exist: version numbers are
/// contiguous (each publish is `version + 1`), so an attacker who can only WRITE
/// finds no unused version to insert at; at a used one the canonical-key binding
/// means writing at all requires overwriting the genuine object, and the
/// founder's own signature wins the tie regardless.
fn elect_live(mut valid: Vec<TeamManifest>, anchor_founder: &Ss58) -> Option<TeamManifest> {
    // Order by the SIGNED version, then by content. Ascending version lets the
    // walk consider one version group at a time, in order, so the next link is
    // always ahead of the cursor; `content_rank` fixes the order WITHIN a group
    // as a function of the manifests themselves, so no part of this election can
    // inherit the order `valid` arrived in. `sort_by_cached_key` hashes each
    // manifest once rather than once per comparison.
    valid.sort_by_cached_key(|manifest| (manifest.version, content_rank(manifest)));

    // Version groups in ascending order. The search below CONSUMES the anchor's
    // own group, so the walk that follows only ever sees strictly higher
    // versions: "the next link must out-version the live one" is structural
    // here, and a rival sharing the anchor's version cannot displace it.
    let mut groups = valid.chunk_by(|a, b| a.version == b.version);

    let mut anchor = None;
    for group in groups.by_ref() {
        anchor = elect_anchor(group, anchor_founder);
        if anchor.is_some() {
            break;
        }
        for skipped in group {
            tracing::warn!(
                manifest_version = skipped.version,
                founder = %skipped.founder.as_str(),
                anchor_founder = %anchor_founder.as_str(),
                "skipping a team manifest that predates the trusted founder's chain anchor"
            );
        }
    }
    let mut live = anchor?;

    for group in groups {
        match elect_from_group(live, group) {
            Some(next) => live = next,
            None => {
                for candidate in group {
                    tracing::warn!(
                        manifest_version = candidate.version,
                        live_version = live.version,
                        founder = %candidate.founder.as_str(),
                        "skipping a team manifest that does not chain from the live manifest"
                    );
                }
            }
        }
    }

    Some(live.clone())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for fallible fixtures but still assert on outcomes; the assertions are the test"
    )]

    use super::{TeamManifest, elect_live, load_manifest, manifest_key, publish_manifest};
    use crate::NetworkPrefix;
    use crate::error::MemError;
    use crate::oplog::{Signature, Signer, VerifyingKey};
    use crate::store::{BlobStore, MemoryBlobStore};
    use crate::{Sr25519Signer, Ss58};
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A [`BlobStore`] that errors `get` for one key, delegating everything else —
    /// drives the per-object fetch-fault path so a test can prove one unfetchable
    /// manifest version does not abort the whole load.
    struct GetFailing {
        inner: Arc<MemoryBlobStore>,
        fail_key: String,
    }

    #[async_trait::async_trait]
    impl BlobStore for GetFailing {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }
        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            if key == self.fail_key {
                return Err(MemError::Storage("injected get failure".to_owned()));
            }
            self.inner.get(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }
        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    fn tce(e: impl std::fmt::Display) -> TestCaseError {
        TestCaseError::fail(e.to_string())
    }

    /// A signer whose author SS58 is derived from its seed (so it is bound to
    /// its key) — `seed` selects a distinct identity.
    fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        Ok(Sr25519Signer::from_seed_with_prefix(
            &[seed; 32],
            NetworkPrefix::HIPPIUS,
        )?)
    }

    fn ss58_of(seed: u8) -> Result<Ss58, Box<dyn std::error::Error>> {
        Ok(signer(seed)?.author_ss58())
    }

    fn members(seeds: &[u8]) -> Result<BTreeSet<Ss58>, Box<dyn std::error::Error>> {
        seeds.iter().map(|&s| ss58_of(s)).collect()
    }

    /// Recovered fields of a `TeamManifest::signing_bytes`, compared field-by-field
    /// by the injectivity proptest below.
    struct ParsedManifest {
        team: Vec<u8>,
        members: Vec<Vec<u8>>,
        version: u64,
        founder: Vec<u8>,
        founder_key: Vec<u8>,
        /// `Some` only when the buffer carried [`super::MANIFEST_DOMAIN_V2`]
        /// (in which case it is exactly the trailing 32 raw bytes), `None`
        /// under [`super::MANIFEST_DOMAIN`].
        recovery_key: Option<Vec<u8>>,
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

    /// Inverse of [`TeamManifest::signing_bytes`], reading the exact layout it
    /// writes: EITHER domain tag ([`super::MANIFEST_DOMAIN`] or
    /// [`super::MANIFEST_DOMAIN_V2`] — the two are the same length, so
    /// stripping either uses `MANIFEST_DOMAIN.len()`), framed team, an
    /// 8-byte member count, that many framed members, an 8-byte version, the
    /// framed founder, a raw 32-byte founder key, and — ONLY when the tag was
    /// `MANIFEST_DOMAIN_V2` — a further trailing raw 32-byte recovery key.
    /// Under `MANIFEST_DOMAIN`, any bytes left after the founder key (rather
    /// than exactly zero) are rejected as trailing garbage, mirroring the
    /// exact-32-bytes check `<[u8; 32]>::try_from` already performed here
    /// before this function knew about a second domain. That this inverse
    /// exists IS the proof the composite encoding is injective, now across
    /// both domains. Returns `None` on any truncation, trailing garbage, or
    /// an unrecognized tag rather than panicking (the crate denies
    /// `unwrap`/`panic`).
    ///
    /// TEST-ONLY, and that is exactly why accepting either tag here is safe:
    /// this function is never linked into the production binary (it lives in
    /// `mod tests`, `#[cfg(test)]`), and production [`TeamManifest::verify`]
    /// never calls it or anything like it — `verify` always RECOMPUTES
    /// `signing_bytes()` from `self`, whose domain branch reads
    /// `self.recovery_key`'s CURRENT state, never a tag sniffed from
    /// attacker-supplied bytes. So there is no path by which this parser
    /// accepting both tags could let a stripped-recovery-key manifest launder
    /// its v2 signature back into v1-shaped acceptance; see
    /// `a_downgraded_v2_manifest_does_not_verify` for the production-side
    /// proof of that.
    fn parse_manifest(buf: &[u8]) -> Option<ParsedManifest> {
        let is_v2 = if buf.starts_with(super::MANIFEST_DOMAIN_V2) {
            true
        } else if buf.starts_with(super::MANIFEST_DOMAIN) {
            false
        } else {
            return None;
        };
        let buf = buf.get(super::MANIFEST_DOMAIN.len()..)?;
        let (team, buf) = read_framed(buf)?;
        let (count, mut buf) = read_u64(buf)?;
        let mut members = Vec::new();
        for _ in 0..count {
            let (member, rest) = read_framed(buf)?;
            members.push(member);
            buf = rest;
        }
        let (version, buf) = read_u64(buf)?;
        let (founder, buf) = read_framed(buf)?;
        let founder_key = buf.get(..32)?.to_vec();
        let buf = buf.get(32..)?;
        let recovery_key = if is_v2 {
            Some(<[u8; 32]>::try_from(buf).ok()?.to_vec())
        } else if buf.is_empty() {
            None
        } else {
            // Trailing bytes after the founder key under the v1 tag: not a
            // layout this encoding ever produces.
            return None;
        };
        Some(ParsedManifest {
            team,
            members,
            version,
            founder,
            founder_key,
            recovery_key,
        })
    }

    proptest! {
        /// The composite manifest encoding is injective across BOTH domains,
        /// checked two ways:
        ///
        /// 1. **Round trip** (per candidate): parsing `signing_bytes` back
        ///    recovers every field — team, member set, version, founder,
        ///    founder key, and now `recovery_key` — so no field can be
        ///    mistaken for another. This is the forgery-resistance property
        ///    the per-field `push_framed` round-trip cannot prove alone,
        ///    because `signing_bytes` interleaves framed fields with raw
        ///    fixed-width ones (the member count, the version, the 32-byte
        ///    keys) — exactly the boundary ambiguity the explicit framed
        ///    member count exists to close. It is checked under EITHER domain
        ///    tag here, closing the gap left when this proptest only ever
        ///    built candidates through `create_signed` (always
        ///    `recovery_key: None`) and `parse_manifest` hard-required the v1
        ///    tag, so the v2 layout — the one carrying an authorization root
        ///    — was entirely outside this proof.
        /// 2. **Pairwise biconditional** (across a mixed set): `a.signing_bytes()
        ///    == b.signing_bytes() <=> a == b`. The forward half is trivial —
        ///    `signing_bytes` is a pure function of `self`, so equal manifests
        ///    trivially produce equal bytes — and proves nothing on its own.
        ///    The reverse half is the real property under test: equal bytes
        ///    force equal manifests. The sharpest instance of that is a
        ///    `None`-recovery candidate (v1-tagged) against a `Some`-recovery
        ///    candidate (v2-tagged) that otherwise carries the SAME team,
        ///    members, version and founder, plus two `Some`-recovery
        ///    candidates that differ ONLY in which key they name. Left to two
        ///    independently drawn `version`s, that exact pairing would
        ///    essentially never occur (the chance of an accidental collision
        ///    across the full `u64` range is negligible), so it would be
        ///    impossible to claim the extension actually exercised the
        ///    v1-vs-v2 boundary by relying on that alone. Instead all three
        ///    candidates below are built from the SAME (team, members,
        ///    version, founder) and differ ONLY in `recovery_key`, so
        ///    `signing_bytes` has nothing else left to discriminate them by
        ///    except the field the v2 domain exists to protect — the
        ///    collision case is reachable on every single run, not merely by
        ///    chance.
        #[test]
        fn manifest_signing_bytes_is_injective(
            member_seeds in proptest::collection::btree_set(1u8..=8u8, 0..6),
            version in any::<u64>(),
        ) {
            let founder = signer(1).map_err(tce)?;
            let recovery_a = signer(9).map_err(tce)?.verifying_key();
            let recovery_b = signer(10).map_err(tce)?.verifying_key();
            let member_set = member_seeds
                .iter()
                .copied()
                .map(ss58_of)
                .collect::<Result<BTreeSet<Ss58>, _>>()
                .map_err(tce)?;

            // Same team/members/version/founder throughout; only recovery_key
            // varies, across all three values a manifest can carry it as.
            let candidates: [(TeamManifest, Option<VerifyingKey>); 3] = [
                (
                    TeamManifest::create_signed_with_recovery(
                        &founder,
                        "team".to_owned(),
                        member_set.clone(),
                        version,
                        None,
                    ),
                    None,
                ),
                (
                    TeamManifest::create_signed_with_recovery(
                        &founder,
                        "team".to_owned(),
                        member_set.clone(),
                        version,
                        Some(recovery_a),
                    ),
                    Some(recovery_a),
                ),
                (
                    TeamManifest::create_signed_with_recovery(
                        &founder,
                        "team".to_owned(),
                        member_set.clone(),
                        version,
                        Some(recovery_b),
                    ),
                    Some(recovery_b),
                ),
            ];

            // Check 1: round trip, for every candidate (both domains).
            for (manifest, recovery_key) in &candidates {
                let bytes = manifest.signing_bytes();
                let parsed = parse_manifest(&bytes)
                    .ok_or_else(|| tce("manifest signing bytes did not parse back"))?;

                prop_assert_eq!(&parsed.team, b"team");
                let expected_members: Vec<Vec<u8>> = manifest
                    .members
                    .iter()
                    .map(|m| m.as_str().as_bytes().to_vec())
                    .collect();
                prop_assert_eq!(&parsed.members, &expected_members);
                prop_assert_eq!(parsed.version, version);
                prop_assert_eq!(&parsed.founder, &manifest.founder.as_str().as_bytes().to_vec());
                prop_assert_eq!(&parsed.founder_key, &manifest.founder_key.as_bytes().to_vec());
                prop_assert_eq!(
                    parsed.recovery_key,
                    recovery_key.map(|k| k.as_bytes().to_vec())
                );
            }

            // Check 2: the pairwise biconditional, over every ordered pair
            // drawn from the mixed set (including each candidate against
            // itself, which is the trivial true<=>true cell).
            for i in 0..candidates.len() {
                for j in 0..candidates.len() {
                    let a = &candidates[i].0;
                    let b = &candidates[j].0;
                    let bytes_eq = a.signing_bytes() == b.signing_bytes();
                    let struct_eq = a == b;
                    prop_assert_eq!(
                        bytes_eq,
                        struct_eq,
                        "signing_bytes equality must exactly track manifest equality \
                         (candidates {} and {})",
                        i,
                        j
                    );
                }
            }
        }
    }

    #[test]
    fn manifest_create_verify_roundtrip() -> TestResult {
        let founder = signer(1)?;
        let manifest =
            TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2])?, 0);
        assert!(manifest.verify(), "a founder-signed manifest must verify");

        // Tamper: add a member without re-signing — `signing_bytes` change, the
        // old signature no longer matches.
        let mut tampered = manifest.clone();
        tampered.members.insert(ss58_of(3)?);
        assert!(
            !tampered.verify(),
            "an added member with a stale signature must fail verification"
        );
        Ok(())
    }

    #[test]
    fn manifest_founder_identity_bound() -> TestResult {
        // Sign as A (so the signature is sound), then relabel `founder` to B's
        // address and re-sign with A's key. The signature verifies under A's
        // key, but B's SS58 does not decode to A's key, so the identity binding
        // must reject it — exactly the op-log's mismatched-author case.
        let a = signer(1)?;
        let b_ss58 = ss58_of(2)?;
        let mut manifest = TeamManifest::create_signed(&a, "team".to_owned(), members(&[1])?, 0);
        manifest.founder = b_ss58;
        manifest.sig = a.sign(&manifest.signing_bytes());

        assert!(
            crate::verify(
                &manifest.founder_key,
                &manifest.signing_bytes(),
                &manifest.sig
            ),
            "the re-signed manifest still carries a valid signature under founder_key"
        );
        assert!(
            !manifest.verify(),
            "a founder SS58 that does not decode to founder_key must fail verification"
        );
        Ok(())
    }

    #[test]
    fn manifest_rejects_non_hippius_founder_prefix() -> TestResult {
        // Defense-in-depth, mirroring Op::verify_identity / MemberKey::verify: a
        // manifest whose founder ss58 is under a non-Hippius prefix must fail
        // verification even with a valid signature — membership is matched on the
        // founder's ss58 string, so a foreign prefix is a different identity.
        let founder = signer(1)?;
        let mut manifest =
            TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1])?, 0);
        assert!(manifest.verify(), "the genuine manifest verifies");

        // Re-encode the SAME founder key under prefix 0 and re-sign: the signature
        // is sound and the key still decodes, but the prefix is not Hippius.
        manifest.founder =
            crate::identity::ss58_encode(&manifest.founder_key, NetworkPrefix::new(0)?);
        manifest.sig = founder.sign(&manifest.signing_bytes());
        assert!(
            !manifest.verify(),
            "a manifest under a non-Hippius founder prefix must be rejected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn load_returns_highest_valid_version() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let v0 = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2])?, 0);
        let v1 = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2, 3])?, 1);
        publish_manifest(blob.as_ref(), &v0).await?;
        publish_manifest(blob.as_ref(), &v1).await?;

        let loaded = load_manifest(blob.as_ref(), "team", None)
            .await?
            .ok_or("expected a manifest to load")?;
        assert_eq!(loaded.version, 1, "the highest version wins");
        assert!(
            loaded.members.contains(&ss58_of(3)?),
            "the loaded manifest is v1, which added member 3"
        );
        Ok(())
    }

    #[tokio::test]
    async fn non_founder_higher_version_is_ignored_not_fatal() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let a = signer(1)?;
        let b = signer(2)?;
        // A founds at v0; B (not the founder) self-signs a v1 naming themselves
        // founder. Each manifest verifies in isolation, but founder consistency
        // must IGNORE B's seizure WITHOUT erroring: an error here would propagate
        // through `sync` (`?`) and DoS every member of the team.
        let v0 = TeamManifest::create_signed(&a, "team".to_owned(), members(&[1, 2])?, 0);
        let v1 = TeamManifest::create_signed(&b, "team".to_owned(), members(&[1, 2])?, 1);
        publish_manifest(blob.as_ref(), &v0).await?;
        publish_manifest(blob.as_ref(), &v1).await?;

        let loaded = load_manifest(blob.as_ref(), "team", None)
            .await?
            .ok_or("the genesis founder's manifest must still load (not error)")?;
        assert_eq!(
            loaded.version, 0,
            "the live manifest is the genesis founder's highest version (v0), not B's v1"
        );
        assert_eq!(
            loaded.founder,
            a.author_ss58(),
            "the founder remains A; B's higher-version seizure is filtered out"
        );
        Ok(())
    }

    #[tokio::test]
    async fn load_manifest_skips_an_unfetchable_object() -> TestResult {
        // M5 regression: load_manifest re-fetches every manifest version on each
        // sync. A transient get failure on ONE version must be skipped, not abort
        // the whole load — the function's documented "never fatal" contract, and
        // the same skip-and-continue every other per-object failure already uses.
        let inner = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let v0 = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2])?, 0);
        let v1 = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2, 3])?, 1);
        publish_manifest(inner.as_ref(), &v0).await?;
        publish_manifest(inner.as_ref(), &v1).await?;

        // Make v1's object unfetchable; the readable v0 must still load.
        let blob: Arc<dyn BlobStore> = Arc::new(GetFailing {
            inner: inner.clone(),
            fail_key: manifest_key("team", 1),
        });
        let loaded = load_manifest(blob.as_ref(), "team", None)
            .await?
            .ok_or("the readable manifest must still load despite a sibling fetch failure")?;
        assert_eq!(
            loaded.version, 0,
            "v0 survives; v1's fetch failure is skipped, not propagated"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pinned_founder_survives_genesis_overwrite() -> TestResult {
        // The HIGH-severity takeover: a malicious bucket overwrites the genesis
        // (version-0) object with a self-signed manifest naming the attacker as
        // founder. With trust-on-genesis the attacker would be elected founder and
        // the real founder's higher versions filtered out (seizure + DoS). A PINNED
        // founder anchors trust locally, so the attacker's v0 is ignored and the
        // real founder's manifest still governs.
        let real = signer(1)?;
        let attacker = signer(2)?;
        // The attacker controls the single v0 key; the real founder published v1.
        let attacker_v0 =
            TeamManifest::create_signed(&attacker, "team".to_owned(), members(&[2])?, 0);
        let real_v1 = TeamManifest::create_signed(&real, "team".to_owned(), members(&[1, 3])?, 1);

        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        publish_manifest(blob.as_ref(), &attacker_v0).await?;
        publish_manifest(blob.as_ref(), &real_v1).await?;

        let real_ss58 = real.author_ss58();

        // Unpinned: trust-on-genesis elects the attacker's v0 — the vulnerability.
        let unpinned = load_manifest(blob.as_ref(), "team", None)
            .await?
            .ok_or("a manifest loads")?;
        assert_eq!(
            unpinned.founder,
            attacker.author_ss58(),
            "unpinned, the genesis overwrite seizes the team (the bug being fixed)"
        );

        // Pinned to the real founder: the attacker's v0 is filtered out and the
        // real founder's v1 governs — the seizure is defeated.
        let pinned = load_manifest(blob.as_ref(), "team", Some(&real_ss58))
            .await?
            .ok_or("the real founder's manifest must still load under the pin")?;
        assert_eq!(
            pinned.version, 1,
            "the real founder's v1 wins under the pin"
        );
        assert_eq!(
            pinned.founder, real_ss58,
            "the pinned founder governs; the attacker's genesis overwrite is ignored"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pinned_founder_with_only_attacker_manifests_reads_open_not_seized() -> TestResult {
        // If the bucket holds ONLY attacker-founded manifests (no manifest by the
        // pinned founder yet), the team must read as open (None) — never as the
        // attacker's. Open degrades availability under a write-capable bucket (a
        // conceded gap) but does NOT hand the attacker the founder role.
        let attacker = signer(2)?;
        let real = signer(1)?;
        let real_ss58 = real.author_ss58();
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let attacker_v0 =
            TeamManifest::create_signed(&attacker, "team".to_owned(), members(&[2])?, 0);
        publish_manifest(blob.as_ref(), &attacker_v0).await?;

        assert!(
            load_manifest(blob.as_ref(), "team", Some(&real_ss58))
                .await?
                .is_none(),
            "with no manifest by the pinned founder, the team reads open, not seized"
        );
        Ok(())
    }

    #[tokio::test]
    async fn manifest_for_wrong_team_is_ignored() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        // A perfectly valid manifest — but it names team "other". Planted directly
        // under team "t"'s prefix, the way an attacker copies their own signed
        // manifest into an open team's bucket to hijack it.
        let foreign = TeamManifest::create_signed(&founder, "other".to_owned(), members(&[1])?, 0);
        assert!(foreign.verify(), "the foreign manifest is itself valid");
        blob.put(&manifest_key("t", 0), serde_json::to_vec(&foreign)?)
            .await?;
        assert!(
            load_manifest(blob.as_ref(), "t", None).await?.is_none(),
            "a manifest naming a different team must not govern team t"
        );
        Ok(())
    }

    #[test]
    fn founder_is_always_a_member() -> TestResult {
        let founder = signer(1)?;
        // Members deliberately exclude the founder (seed 1); create_signed must
        // still insert them.
        let manifest = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[2])?, 0);
        assert!(
            manifest.members.contains(&founder.author_ss58()),
            "the founder is always a member of their own team"
        );
        Ok(())
    }

    #[tokio::test]
    async fn no_manifest_loads_none() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        assert!(
            load_manifest(blob.as_ref(), "team", None).await?.is_none(),
            "an empty manifest prefix loads as None (open team)"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unverifiable_manifest_is_not_published() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let mut manifest =
            TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1])?, 0);
        manifest.version = 99; // mutate after signing: signature no longer matches
        let err = publish_manifest(blob.as_ref(), &manifest)
            .await
            .err()
            .ok_or("expected publish to refuse an unverifiable manifest")?;
        assert!(format!("{err}").contains("unverifiable"), "got: {err}");
        // Nothing was written under the (tampered) key.
        assert!(
            blob.get(&manifest_key("team", 99)).await.is_err(),
            "a refused manifest must not be stored"
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// The core contract under fuzzing: every freshly created manifest
        /// verifies, and the founder is always a member — regardless of version
        /// or the supplied member set.
        #[test]
        fn created_manifest_verifies_and_includes_founder(
            version in any::<u64>(),
            member_seeds in prop::collection::vec(any::<u8>(), 0..5),
        ) {
            let founder = signer(200).map_err(tce)?;
            let member_set: BTreeSet<Ss58> = member_seeds
                .iter()
                .map(|&s| signer(s).map(|sg| sg.author_ss58()))
                .collect::<Result<_, _>>()
                .map_err(tce)?;
            let manifest =
                TeamManifest::create_signed(&founder, "team".to_owned(), member_set, version);
            prop_assert!(manifest.verify());
            prop_assert!(manifest.members.contains(&founder.author_ss58()));
        }
    }

    /// A PINNED v1 [`TeamManifest`] fixture — the exact bytes `serde_json`
    /// produced for `TeamManifest::create_signed(&signer(9), "acme".to_owned(),
    /// members(&[9, 7])?, 5)` under today's `signing_bytes` layout (team "acme",
    /// members from seeds 9 and 7, version 5).
    ///
    /// MUST NEVER BE REGENERATED. Its entire value is that it was produced
    /// ONCE, by hand, from the v1 code, and then inlined here as a literal — it
    /// does not get re-derived from `create_signed` at test time. If a future
    /// phase (Task 8's recovery key, Task 9's chain-of-custody election) changes
    /// `signing_bytes` or the wire shape, re-running `create_signed` would
    /// silently sign under the NEW bytes and this test would keep passing for
    /// the wrong reason — exactly the trap this fixture exists to avoid. If a
    /// new compatible fixture is ever needed, add a SECOND const beside this
    /// one; never overwrite it.
    const V1_MANIFEST_JSON: &str = concat!(
        r#"{"team":"acme","#,
        r#""members":["5ETmuXSyBiDHwabzdAxmbyj1A25asAmNXm5gtzf7edxxQYaq","#,
        r#""5EsNLFaGe9XK5LzWH3i6eC2Wqv6YqZS1442N1C4yeSdP6uxy"],"#,
        r#""version":5,"#,
        r#""founder":"5ETmuXSyBiDHwabzdAxmbyj1A25asAmNXm5gtzf7edxxQYaq","#,
        r#""founder_key":"6a10be029d1ed283446587145a4f885225489b490424a0328dcce2a48ae6fe61","#,
        r#""sig":"588a69374e8696edd394629044918c6b89bd401cc79fd11d15d77f00a871a95ab8b815afb9352e3a4b0a3e37828e3e3ec8197fc65987ef8b1e524b871ea73186"}"#,
    );

    #[test]
    fn v1_fixture_still_verifies() -> TestResult {
        // Pins today's compatibility contract: a v1 manifest byte-for-byte
        // preserved from `create_signed` must still deserialize AND verify under
        // the current code. If Task 8 changes `signing_bytes` for
        // recovery-key-free manifests (it must not), this fixture breaks loudly
        // instead of silently re-signing under new bytes.
        let manifest: TeamManifest = serde_json::from_str(V1_MANIFEST_JSON)?;
        assert!(
            manifest.verify(),
            "the pinned v1 fixture must still verify under today's signing_bytes"
        );
        assert_eq!(
            manifest.team, "acme",
            "the fixture's team field is unchanged"
        );
        assert_eq!(
            manifest.version, 5,
            "the fixture's version field is unchanged"
        );
        assert_eq!(
            manifest.members.len(),
            2,
            "the fixture's member set is unchanged"
        );
        Ok(())
    }

    #[tokio::test]
    async fn load_manifest_skips_unknown_field_objects_rather_than_failing() -> TestResult {
        // Two distinct forward-compat properties, each needing its own planted
        // object, both landing on the same "skipped, not fatal" outcome via
        // different code paths:
        //
        // (1) A field this binary has genuinely never heard of (`future_field`,
        //     standing in for whatever a LATER format adds) must not choke
        //     deserialize: serde has no `deny_unknown_fields` on `TeamManifest`,
        //     so the field is silently ignored, and the object is only skipped
        //     afterward because its garbage signature fails `verify()`.
        // (2) `recovery_key` is, as of this format version, a field this binary
        //     DOES know about. A well-formed `recovery_key` paired with a
        //     signature that does not match it must ALSO be skipped, not
        //     fatal — the v2-shaped analogue of (1), exercising the same
        //     `verify()`-fails skip path but via the `Ok(manifest)` branch
        //     rather than the deserialize-error branch a malformed hex value
        //     would take (a malformed `recovery_key` fails to deserialize at
        //     all, which is a different — already-covered — code path, not
        //     this "unknown/forward-compat field" property).
        //
        // Both must leave the valid v0 manifest loadable: an OLD binary fails
        // CLOSED (skip the object it cannot trust or does not recognize)
        // rather than crashing `sync` for every member.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let valid = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2])?, 0);
        publish_manifest(blob.as_ref(), &valid).await?;

        // (1) Planted directly (not through `publish_manifest`, which would
        // refuse an unverifiable manifest): a well-formed JSON object under the
        // same prefix, shaped like a manifest but carrying a field NO version of
        // `TeamManifest` defines, plus a garbage signature that cannot possibly
        // verify.
        let unknown_field_object = serde_json::json!({
            "team": "team",
            "members": [founder.author_ss58().as_str()],
            "version": 1,
            "founder": founder.author_ss58().as_str(),
            "founder_key": founder.verifying_key().to_hex(),
            "sig": "00".repeat(64),
            "future_field": "a field this binary has never heard of",
        });
        blob.put(
            &manifest_key("team", 1),
            serde_json::to_vec(&unknown_field_object)?,
        )
        .await?;

        // (2) A second planted object: a WELL-FORMED (valid hex, correct
        // length) `recovery_key` — a real v2 field — but still a garbage
        // signature. Deserializes cleanly into `Some(recovery_key)`, then is
        // skipped for failing `verify()`, exercising the v2-shaped case of the
        // same "skipped, not fatal" contract.
        let v2_shaped_object = serde_json::json!({
            "team": "team",
            "members": [founder.author_ss58().as_str()],
            "version": 2,
            "founder": founder.author_ss58().as_str(),
            "founder_key": founder.verifying_key().to_hex(),
            "recovery_key": signer(9)?.verifying_key().to_hex(),
            "sig": "00".repeat(64),
        });
        blob.put(
            &manifest_key("team", 2),
            serde_json::to_vec(&v2_shaped_object)?,
        )
        .await?;

        let loaded = load_manifest(blob.as_ref(), "team", None).await?.ok_or(
            "the valid v0 manifest must still load despite the sibling unrecognized-field and unverifiable-v2-shaped objects",
        )?;
        assert_eq!(
            loaded.version, 0,
            "both the unknown-field object and the well-formed-but-unverifiable v2-shaped object are skipped, not fatal"
        );
        Ok(())
    }

    #[test]
    fn recovery_manifest_signs_under_v2_domain() -> TestResult {
        let founder = signer(1)?;
        let recovery_key = signer(9)?.verifying_key();
        let manifest = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            0,
            Some(recovery_key),
        );
        assert!(
            manifest.verify(),
            "a manifest naming a recovery key still verifies under founder_key"
        );

        let bytes = manifest.signing_bytes();
        assert!(
            bytes.starts_with(super::MANIFEST_DOMAIN_V2),
            "a manifest naming a recovery key signs under the v2 domain tag"
        );

        // Stripping the recovery key (without re-signing) must change the
        // signed bytes: the key is part of the message, not a decoration.
        let mut stripped = manifest.clone();
        stripped.recovery_key = None;
        assert_ne!(
            bytes,
            stripped.signing_bytes(),
            "signing bytes must differ once the recovery key is stripped"
        );
        Ok(())
    }

    /// A v2 manifest with its `recovery_key` stripped must FAIL verification —
    /// not merely produce different bytes. `recovery_manifest_signs_under_v2_domain`
    /// (above) asserts only that the bytes changed, which a downgrade attacker
    /// does not care about: they strip the field from a genuinely-signed v2
    /// manifest and hope the ORIGINAL signature still validates. It must not,
    /// because `verify()` always RECOMPUTES `signing_bytes()` from `self` —
    /// after stripping, `self.recovery_key` is `None`, so it recomputes under
    /// the v1 domain tag and layout, which is not the message the v2 signature
    /// was ever computed over. This test cannot detect a downgrade path that
    /// bypasses `verify()` entirely (e.g. a caller that trusts a manifest
    /// without calling it); it only proves `verify()` itself rejects the
    /// stripped manifest.
    #[test]
    fn a_downgraded_v2_manifest_does_not_verify() -> TestResult {
        let founder = signer(1)?;
        let recovery_key = signer(9)?.verifying_key();
        let manifest = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            0,
            Some(recovery_key),
        );
        assert!(
            manifest.verify(),
            "the genuine v2 manifest verifies before any tampering"
        );

        let mut downgraded = manifest.clone();
        downgraded.recovery_key = None;
        assert!(
            !downgraded.verify(),
            "a v2 manifest with its recovery_key stripped, but the ORIGINAL v2 \
             signature kept, must fail verification — accepting it would let \
             anyone who can only DELETE a field (no forgery needed) silently \
             discard the authorization root a founder committed to"
        );
        Ok(())
    }

    /// Hand-assembled expected v1 `signing_bytes` layout, built WITHOUT calling
    /// `push_framed` or `signing_bytes` — an independent re-derivation of the
    /// layout `signing_bytes`'s doc comment describes (domain tag, framed team,
    /// framed member count + members, raw LE version, framed founder, raw
    /// founder key), so a regression in the real implementation cannot pass by
    /// silently agreeing with itself. Comparing two calls into the SAME
    /// production code path (as a prior version of this test did) can never
    /// fail on any implementation; this can.
    fn expected_v1_signing_bytes(
        team: &str,
        member_set: &BTreeSet<Ss58>,
        version: u64,
        founder: &Ss58,
        founder_key: &crate::oplog::VerifyingKey,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(super::MANIFEST_DOMAIN);

        let team_bytes = team.as_bytes();
        buf.extend_from_slice(
            &u64::try_from(team_bytes.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        buf.extend_from_slice(team_bytes);

        buf.extend_from_slice(
            &u64::try_from(member_set.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for member in member_set {
            let bytes = member.as_str().as_bytes();
            buf.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
            buf.extend_from_slice(bytes);
        }

        buf.extend_from_slice(&version.to_le_bytes());

        let founder_bytes = founder.as_str().as_bytes();
        buf.extend_from_slice(
            &u64::try_from(founder_bytes.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        buf.extend_from_slice(founder_bytes);

        buf.extend_from_slice(founder_key.as_bytes());
        buf
    }

    #[test]
    fn recovery_free_manifest_is_bitwise_v1() -> TestResult {
        let founder = signer(1)?;
        let team = "team".to_owned();
        let member_set = members(&[1, 2])?;

        let manifest =
            TeamManifest::create_signed_with_recovery(&founder, team.clone(), member_set, 0, None);

        assert!(
            manifest.recovery_key.is_none(),
            "a None recovery key is stored as None"
        );

        // The discriminating check: an independently reassembled v1 layout,
        // not a comparison against `create_signed`'s own delegated call into
        // the identical code path (which cannot detect a v1 layout change).
        let expected = expected_v1_signing_bytes(
            &team,
            &manifest.members,
            0,
            &manifest.founder,
            &manifest.founder_key,
        );
        assert_eq!(
            manifest.signing_bytes(),
            expected,
            "a None recovery key must sign under the exact v1 byte layout, independently reassembled"
        );
        assert!(
            manifest.signing_bytes().starts_with(super::MANIFEST_DOMAIN),
            "a None recovery key keeps the v1 domain tag"
        );

        let json = serde_json::to_string(&manifest)?;
        assert!(
            !json.contains("recovery_key"),
            "a None recovery key must not serialize a recovery_key field at all: {json}"
        );
        Ok(())
    }

    #[test]
    fn tampered_recovery_key_breaks_the_signature() -> TestResult {
        let founder = signer(1)?;
        let recovery_key = signer(9)?.verifying_key();
        let other_recovery_key = signer(10)?.verifying_key();
        let manifest = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            0,
            Some(recovery_key),
        );
        assert!(manifest.verify(), "the genuine recovery manifest verifies");

        let mut tampered = manifest.clone();
        tampered.recovery_key = Some(other_recovery_key);
        assert!(
            !tampered.verify(),
            "swapping the named recovery key without re-signing must break verification, \
             because the recovery key rides inside the signed bytes"
        );
        Ok(())
    }

    #[test]
    fn recovery_key_round_trips_through_json() -> TestResult {
        // The brief's three tests exercise the None direction's JSON shape
        // (field absent) but not a full serialize/deserialize round trip on
        // the Some side. Close that gap directly: a named recovery key must
        // survive a JSON round trip byte-for-byte and the reloaded manifest
        // must still verify, exactly like every other signed field.
        let founder = signer(1)?;
        let recovery_key = signer(9)?.verifying_key();
        let manifest = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            0,
            Some(recovery_key),
        );

        let json = serde_json::to_string(&manifest)?;
        assert!(
            json.contains("\"recovery_key\""),
            "a Some recovery key must be present in the JSON: {json}"
        );
        let reloaded: TeamManifest = serde_json::from_str(&json)?;
        assert_eq!(
            reloaded, manifest,
            "a recovery-key manifest round-trips through JSON unchanged"
        );
        assert_eq!(
            reloaded.recovery_key,
            Some(recovery_key),
            "the recovery key itself survives the round trip"
        );
        assert!(
            reloaded.verify(),
            "the reloaded recovery-key manifest still verifies"
        );
        Ok(())
    }

    /// A manifest whose `founder_key` is the Ristretto identity point (32 zero
    /// bytes), carrying the signature anyone can forge under it: 64 zero bytes
    /// with schnorrkel's marker bit (byte 63 = `0x80`) set. The marker bit is
    /// cleared before the scalar is parsed, so `s` reads as zero and the Schnorr
    /// verification equation degenerates to `R == s*G` — satisfied for ANY
    /// message. No private key exists or was used.
    ///
    /// [`crate::oplog::verify`] now screens this key out, so
    /// [`TeamManifest::verify`] REJECTS these — the tests below assert that, since
    /// it is the outermost line of defence. They still drive the election with
    /// them (planted objects, and `elect_live` inputs that bypass verification
    /// entirely) because the election treats `founder_key` and `recovery_key` as
    /// authorization roots and must be safe on its own.
    fn forged_identity_point_manifest(
        team: &str,
        version: u64,
    ) -> Result<TeamManifest, Box<dyn std::error::Error>> {
        let founder_key = VerifyingKey::new([0u8; 32]);
        let mut sig = [0u8; 64];
        sig[63] = 0x80;

        Ok(TeamManifest {
            team: team.to_owned(),
            members: members(&[1, 2])?,
            version,
            founder: crate::identity::ss58_encode(&founder_key, NetworkPrefix::HIPPIUS),
            founder_key,
            recovery_key: None,
            sig: Signature::new(sig),
        })
    }

    #[tokio::test]
    async fn recovery_key_can_advance_the_chain_to_a_new_founder() -> TestResult {
        // What a recovery key is FOR: the founder's signing key is lost, and the
        // team must move on without abandoning its namespace. Version 1 (signed
        // by the founder) NAMES the recovery key; version 2 is signed BY that
        // key, which becomes the new founder and names a fresh recovery key of
        // its own so the escape hatch stays open.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let recovery = signer(9)?;
        let next_recovery = signer(10)?;

        let v1 = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            1,
            Some(recovery.verifying_key()),
        );
        let v2 = TeamManifest::create_signed_with_recovery(
            &recovery,
            "team".to_owned(),
            members(&[2])?,
            2,
            Some(next_recovery.verifying_key()),
        );
        publish_manifest(blob.as_ref(), &v1).await?;
        publish_manifest(blob.as_ref(), &v2).await?;

        let loaded = load_manifest(blob.as_ref(), "team", None)
            .await?
            .ok_or("expected the recovered manifest to load")?;
        assert_eq!(
            loaded.version, 2,
            "the recovery key's manifest advances the chain past the lost founder's"
        );
        assert_eq!(
            loaded.founder,
            recovery.author_ss58(),
            "the recovery identity becomes the new founder"
        );
        assert!(
            !loaded.members.contains(&founder.author_ss58()),
            "recovery may evict the lost identity: the old founder is no longer a member"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unauthorized_key_cannot_advance_the_chain() -> TestResult {
        // The seizure the chain rule exists to stop: a random keypair publishes a
        // HIGHER version that is perfectly self-consistent — it verifies, and it
        // names this team. It is neither the live founder's key nor the recovery
        // key the live manifest names, so it is skipped (and never fatal).
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let recovery = signer(9)?;
        let attacker = signer(3)?;

        let v1 = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            1,
            Some(recovery.verifying_key()),
        );
        let v2 = TeamManifest::create_signed(&attacker, "team".to_owned(), members(&[3])?, 2);
        assert!(v2.verify(), "the attacker's manifest verifies in isolation");
        publish_manifest(blob.as_ref(), &v1).await?;
        publish_manifest(blob.as_ref(), &v2).await?;

        let loaded = load_manifest(blob.as_ref(), "team", None)
            .await?
            .ok_or("the founder's manifest must still load (a seizure attempt is never fatal)")?;
        assert_eq!(
            loaded.version, 1,
            "an unauthorized higher version does not advance the chain"
        );
        assert_eq!(
            loaded.founder,
            founder.author_ss58(),
            "the founder is unchanged; the attacker's key was authorized by nothing"
        );
        Ok(())
    }

    #[tokio::test]
    async fn chain_rule_without_recovery_matches_today() -> TestResult {
        // Every manifest here names NO recovery key, so the chain walk must be
        // indistinguishable from the pre-chain rule: the genesis founder's
        // highest version wins and a foreign founder's manifest is skipped.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let stranger = signer(2)?;

        for version in 0..=2 {
            let manifest =
                TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1])?, version);
            publish_manifest(blob.as_ref(), &manifest).await?;
        }
        let foreign = TeamManifest::create_signed(&stranger, "team".to_owned(), members(&[2])?, 3);
        publish_manifest(blob.as_ref(), &foreign).await?;

        let loaded = load_manifest(blob.as_ref(), "team", None)
            .await?
            .ok_or("expected the genesis founder's manifest to load")?;
        assert_eq!(
            loaded.version, 2,
            "the genesis founder's highest version is live, exactly as before the chain rule"
        );
        assert_eq!(
            loaded.founder,
            founder.author_ss58(),
            "the foreign founder's higher version is skipped, exactly as before"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pinned_founder_anchors_the_chain_start() -> TestResult {
        // The pin guarantee, restated over the chain walk. The attacker owns the
        // genesis object (version 0) and names THEIR OWN recovery key in it, then
        // publishes a later version signed by that recovery key. Pinned to the
        // real founder, the chain anchors on the real founder's LOWEST manifest,
        // so neither the attacker's genesis nor the recovery key it names is ever
        // in the chain — a recovery key confers authority only from a manifest
        // that is actually live.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let real = signer(1)?;
        let attacker = signer(2)?;
        let attacker_recovery = signer(4)?;
        let real_ss58 = real.author_ss58();

        let attacker_v0 = TeamManifest::create_signed_with_recovery(
            &attacker,
            "team".to_owned(),
            members(&[2])?,
            0,
            Some(attacker_recovery.verifying_key()),
        );
        let real_v1 = TeamManifest::create_signed(&real, "team".to_owned(), members(&[1])?, 1);
        let real_v2 = TeamManifest::create_signed(&real, "team".to_owned(), members(&[1, 3])?, 2);
        let attacker_v3 =
            TeamManifest::create_signed(&attacker_recovery, "team".to_owned(), members(&[4])?, 3);

        publish_manifest(blob.as_ref(), &attacker_v0).await?;
        publish_manifest(blob.as_ref(), &real_v1).await?;
        publish_manifest(blob.as_ref(), &real_v2).await?;
        publish_manifest(blob.as_ref(), &attacker_v3).await?;

        let pinned = load_manifest(blob.as_ref(), "team", Some(&real_ss58))
            .await?
            .ok_or("the pinned founder's manifest must load")?;
        assert_eq!(
            pinned.version, 2,
            "the chain anchors on the pinned founder's lowest version and walks to their highest"
        );
        assert_eq!(
            pinned.founder, real_ss58,
            "the attacker's genesis never anchors the chain"
        );
        Ok(())
    }

    #[tokio::test]
    async fn identity_point_founder_is_never_a_valid_manifest() -> TestResult {
        // A manifest that needs NO key material at all: the Ristretto identity
        // point as founder_key plus a hand-typed signature. It passes
        // `verify()`, so signature verification alone cannot keep it out of the
        // bucket's trusted set — the load rule must reject the key by value or
        // an attacker seizes a team without owning a keypair.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let forged = forged_identity_point_manifest("team", 0)?;
        assert!(
            !forged.verify(),
            "oplog::verify screens the identity point, so the forgery no longer even verifies"
        );
        blob.put(&manifest_key("team", 0), serde_json::to_vec(&forged)?)
            .await?;

        assert!(
            load_manifest(blob.as_ref(), "team", None).await?.is_none(),
            "an identity-point founder key must never anchor a chain: the team reads open, not seized"
        );
        Ok(())
    }

    #[tokio::test]
    async fn identity_point_recovery_key_cannot_advance_the_chain() -> TestResult {
        // The foot-gun the recovery-key guard exists for: a founder names the
        // identity point as their recovery key (by accident, or because an
        // attacker supplied the "key"). ANYONE can then mint a manifest signed by
        // "that key", so honouring it would hand the team to the first passer-by.
        // The election rule must treat a named identity-point recovery key as no
        // recovery key at all.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let v0 = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            0,
            Some(VerifyingKey::new([0u8; 32])),
        );
        publish_manifest(blob.as_ref(), &v0).await?;

        let forged = forged_identity_point_manifest("team", 1)?;
        assert!(
            !forged.verify(),
            "the forged takeover manifest is refused at the signature layer too"
        );
        blob.put(&manifest_key("team", 1), serde_json::to_vec(&forged)?)
            .await?;

        let loaded = load_manifest(blob.as_ref(), "team", None)
            .await?
            .ok_or("the founder's manifest must still load")?;
        assert_eq!(
            loaded.version, 0,
            "an identity-point recovery key authorizes nothing; the forged takeover is skipped"
        );
        assert_eq!(
            loaded.founder,
            founder.author_ss58(),
            "the founder is unchanged"
        );
        Ok(())
    }

    #[test]
    fn trusted_recovery_key_refuses_the_identity_point() -> TestResult {
        // The braces half of the identity-point guard, unit-tested where it can
        // be OBSERVED. Through `load_manifest` this check is masked: the only
        // candidate that could ever match an identity-point recovery key is one
        // whose own founder_key is the identity point, which two earlier screens
        // already reject. Testing the helper directly is the only way to prove
        // this layer works rather than merely being unreachable today.
        let founder = signer(1)?;
        let named = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1])?,
            0,
            Some(signer(9)?.verifying_key()),
        );
        assert_eq!(
            named.trusted_recovery_key(),
            Some(&signer(9)?.verifying_key()),
            "a genuine recovery key is reported as-is"
        );

        let degenerate = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1])?,
            0,
            Some(VerifyingKey::new([0u8; 32])),
        );
        assert!(
            degenerate.trusted_recovery_key().is_none(),
            "a named identity point must be reported as NO recovery key"
        );
        Ok(())
    }

    #[test]
    fn elect_live_rejects_an_identity_point_candidate() -> TestResult {
        // `elect_live`'s own screen, proven without `load_manifest`'s help: hand
        // the walk a candidate whose founder_key is the identity point AND whose
        // key matches the recovery key the live manifest names — the strongest
        // input an attacker could construct — and it must still not be elected.
        let founder = signer(1)?;
        let live = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1])?,
            0,
            Some(VerifyingKey::new([0u8; 32])),
        );
        let forged = forged_identity_point_manifest("team", 1)?;

        let elected = elect_live(vec![live, forged], &founder.author_ss58())
            .ok_or("the founder's own manifest must still be elected")?;
        assert_eq!(
            elected.version, 0,
            "a candidate whose founder key is the identity point is never elected"
        );
        Ok(())
    }

    #[test]
    fn elect_live_ignores_a_recovery_key_the_live_manifest_no_longer_names() -> TestResult {
        // Recovery authority is held by the LIVE manifest, not inherited down the
        // chain: the founder names R at v0, then republishes at v1 WITHOUT naming
        // it. R's v2 must no longer chain — this is how a compromised recovery
        // key gets retired.
        let founder = signer(1)?;
        let recovery = signer(9)?;
        let v0 = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1])?,
            0,
            Some(recovery.verifying_key()),
        );
        let v1 = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1])?, 1);
        let v2 = TeamManifest::create_signed(&recovery, "team".to_owned(), members(&[9])?, 2);

        let elected = elect_live(vec![v0, v1, v2], &founder.author_ss58())
            .ok_or("the founder's chain must still elect")?;
        assert_eq!(
            elected.version, 1,
            "a recovery key retired by the live manifest authorizes nothing"
        );
        Ok(())
    }

    #[test]
    fn elect_live_needs_a_strictly_higher_version_to_advance() -> TestResult {
        // Versions are unique per object KEY, but the bucket may hold an off-key
        // object carrying a duplicate signed version. The link already accepted
        // must not be displaced by a same-version rival, even one the live
        // manifest would otherwise authorize (here: the founder's own key).
        let founder = signer(1)?;
        let anchor = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1])?, 0);
        let rival = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 3])?, 0);

        let elected = elect_live(vec![anchor, rival], &founder.author_ss58())
            .ok_or("the anchor must be elected")?;
        assert!(
            !elected.members.contains(&ss58_of(3)?),
            "a same-version rival does not displace the link already accepted"
        );
        Ok(())
    }

    #[test]
    fn founder_signed_beats_recovery_signed_at_the_same_version() -> TestResult {
        // The takeover a listing-order tie-break would have allowed, with NO
        // delete access and against a PINNED founder.
        //
        // The genesis names recovery key R0. R0 is later compromised, but the
        // founder retires it at v2. The attacker cannot delete anything — so
        // instead they sign their OWN version 1 with R0 and plant it under a
        // non-canonical object key that lists BEFORE every real one. If
        // first-examined won, the walk would take the attacker's v1 at live=v0,
        // and the genuine v1 (and with it v2's retirement, and everything after)
        // would fail to chain: permanent seizure.
        //
        // Authority-ordered election defeats it: at version 1 the founder's own
        // signature outranks anything the recovery key signs, whatever the order.
        let founder = signer(1)?;
        let compromised = signer(9)?;
        let anchor = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1])?,
            0,
            Some(compromised.verifying_key()),
        );
        let genuine_v1 = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            1,
            Some(compromised.verifying_key()),
        );
        // The retirement: v2 names a different recovery key.
        let retiring_v2 = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            2,
            Some(signer(10)?.verifying_key()),
        );
        let attacker_v1 =
            TeamManifest::create_signed(&compromised, "team".to_owned(), members(&[9])?, 1);

        // Both orders: the attacker controls listing order, so neither may decide
        // the outcome.
        let orders = [
            vec![
                anchor.clone(),
                attacker_v1.clone(),
                genuine_v1.clone(),
                retiring_v2.clone(),
            ],
            vec![
                anchor.clone(),
                genuine_v1.clone(),
                attacker_v1.clone(),
                retiring_v2.clone(),
            ],
        ];
        for valid in orders {
            let elected = elect_live(valid, &founder.author_ss58())
                .ok_or("the founder's chain must still elect")?;
            assert_eq!(
                elected.version, 2,
                "the chain must reach the retiring manifest regardless of listing order"
            );
            assert_eq!(
                elected.founder,
                founder.author_ss58(),
                "a recovery-signed rival must never outrank the founder's own manifest at one version"
            );
            assert_eq!(
                elected.trusted_recovery_key(),
                Some(&signer(10)?.verifying_key()),
                "the retirement took effect: the compromised key is no longer named"
            );
        }
        Ok(())
    }

    /// The residual the authority tie-break did NOT cover, exercised as the
    /// full attack it enables: a same-version tie WITHIN one authority class.
    ///
    /// The founder names recovery key R1, then later retires it by naming R2.
    /// While that retirement was published AT THE SAME VERSION (the old
    /// `publish_recovery_key` behaviour), the bucket briefly held — and any
    /// bucket reader could save — the pre-retirement manifest object naming
    /// R1. Both manifests are signed by the SAME founder key at the SAME
    /// version, so the authority tie-break cannot separate them.
    ///
    /// A write-only attacker replays the saved object under a non-canonical
    /// key that lists FIRST (`!` sorts below `0`), then publishes their own
    /// manifest signed by the leaked R1 at the next version. If listing order
    /// decided the tie, the replayed object would anchor the chain, the
    /// retirement would be discarded, and R1 would be elected: permanent
    /// takeover from write access alone, against a PINNED founder.
    #[tokio::test]
    async fn a_replayed_pre_retirement_manifest_cannot_resurrect_a_retired_key() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let leaked = signer(9)?;
        let fresh = signer(10)?;

        // What the bucket held before the retirement, and what the attacker saved.
        let pre_retirement = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            0,
            Some(leaked.verifying_key()),
        );
        // The retirement itself, at the canonical key for version 0.
        let retirement = TeamManifest::create_signed_with_recovery(
            &founder,
            "team".to_owned(),
            members(&[1, 2])?,
            0,
            Some(fresh.verifying_key()),
        );
        publish_manifest(blob.as_ref(), &retirement).await?;

        // The replay: the saved object, under an attacker-chosen key that sorts
        // ahead of every canonical zero-padded one.
        blob.put("team/_manifest/!a", serde_json::to_vec(&pre_retirement)?)
            .await?;
        // The takeover manifest, signed by the leaked key the replay re-names.
        let takeover = TeamManifest::create_signed(&leaked, "team".to_owned(), members(&[9])?, 1);
        publish_manifest(blob.as_ref(), &takeover).await?;

        let founder_ss58 = founder.author_ss58();
        for pin in [None, Some(&founder_ss58)] {
            let live = load_manifest(blob.as_ref(), "team", pin)
                .await?
                .ok_or("the founder's chain must still elect")?;
            assert_eq!(
                live.founder, founder_ss58,
                "a replayed manifest must never hand the team to the leaked recovery key"
            );
            assert_eq!(
                live.trusted_recovery_key(),
                Some(&fresh.verifying_key()),
                "the retirement governs: the leaked key is no longer named"
            );
            assert!(
                !live.members.contains(&ss58_of(9)?),
                "the takeover manifest's membership must never take effect"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_manifest_off_its_canonical_key_is_not_a_candidate_at_all() -> TestResult {
        // The object-key binding on its own, isolated from any tie: a
        // perfectly genuine, founder-signed, higher-version manifest that
        // simply is not stored where its own signed `version` says it belongs.
        //
        // The bucket does not get to decide where a manifest lives. Honouring
        // an off-key object is what lets a write-only attacker re-present any
        // manifest they ever saw, at any moment they choose, and that primitive
        // has to be gone entirely rather than merely out-ranked.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let v0 = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1])?, 0);
        let v1 = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2])?, 1);
        publish_manifest(blob.as_ref(), &v0).await?;

        // Same bytes `publish_manifest` would have written, at a key it never
        // would have chosen.
        blob.put("team/_manifest/zzz", serde_json::to_vec(&v1)?)
            .await?;

        let live = load_manifest(blob.as_ref(), "team", None)
            .await?
            .ok_or("the genesis must still elect")?;
        assert_eq!(
            live.version, 0,
            "an off-key manifest never enters the election, however valid it is"
        );
        assert!(
            !live.members.contains(&ss58_of(2)?),
            "and its contents never take effect"
        );
        Ok(())
    }

    #[test]
    fn elect_live_breaks_a_same_authority_tie_by_content_not_by_listing_order() -> TestResult {
        // Object keys are attacker-chosen, so listing order is attacker-chosen,
        // so no election may read it — including WITHIN one authority class,
        // where the founder-beats-recovery rank has nothing to say. Feed the
        // walk the same four manifests in two orders (rivals at the ANCHOR
        // version and at a WALKED version, all signed by the same founder key)
        // and demand one identical answer.
        let founder = signer(1)?;
        let anchor_a = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1])?, 0);
        let anchor_b =
            TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2])?, 0);
        let next_a = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 3])?, 1);
        let next_b = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 4])?, 1);

        let forward = vec![
            anchor_a.clone(),
            anchor_b.clone(),
            next_a.clone(),
            next_b.clone(),
        ];
        let reversed = vec![next_b, next_a, anchor_b, anchor_a];

        let from_forward =
            elect_live(forward, &founder.author_ss58()).ok_or("the chain must elect")?;
        let from_reversed =
            elect_live(reversed, &founder.author_ss58()).ok_or("the chain must elect")?;
        assert_eq!(
            from_forward, from_reversed,
            "the election must be a function of the manifests, not of the order they arrived in"
        );
        Ok(())
    }

    #[test]
    fn elect_live_rejection_does_not_consume_the_version_slot() -> TestResult {
        // Denial-of-service resistance in the walk: an attacker cannot SQUAT the
        // version the founder's next manifest will use. A rejected candidate does
        // not advance the live cursor, so the legitimate manifest at that same
        // version is still strictly greater and is still accepted — examined
        // second here, because a stable sort preserves the attacker-first order.
        let founder = signer(1)?;
        let attacker = signer(3)?;
        let anchor = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1])?, 0);
        let squatter = TeamManifest::create_signed(&attacker, "team".to_owned(), members(&[3])?, 1);
        let genuine =
            TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2])?, 1);

        let elected = elect_live(vec![anchor, squatter, genuine], &founder.author_ss58())
            .ok_or("the founder's chain must still elect")?;
        assert_eq!(
            elected.version, 1,
            "the founder's manifest is still accepted at the squatted version"
        );
        assert_eq!(
            elected.founder,
            founder.author_ss58(),
            "the squatter is rejected without blocking the genuine link"
        );
        Ok(())
    }

    #[test]
    fn elect_live_without_an_anchor_is_none() -> TestResult {
        // No manifest by the anchor founder means no chain to walk: the team
        // reads open rather than electing whoever else happens to be present.
        let founder = signer(1)?;
        let stranger = ss58_of(2)?;
        let manifest = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1])?, 0);

        assert!(
            elect_live(vec![manifest], &stranger).is_none(),
            "a chain that never starts elects nobody"
        );
        Ok(())
    }
}
