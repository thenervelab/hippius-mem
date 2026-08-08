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
//! then enforces **founder consistency** by *filtering* — the live manifest is
//! the highest version signed by the genesis (lowest-version) founder, and a
//! higher-versioned manifest naming a different founder is skipped, not fatal.
//! So a non-member can neither seize the team (their manifest never wins) nor
//! deny service to it (an inconsistency never errors a member's `sync`).
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
const MANIFEST_DOMAIN: &[u8] = b"hippius-memory-manifest/v1";

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
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MANIFEST_DOMAIN);
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
        buf
    }

    /// Build a manifest signed by `signer`, who becomes the `founder`.
    ///
    /// `founder`/`founder_key` are filled from the signer, and the founder is
    /// always inserted into `members` (a founder who is not a member of their
    /// own team is a nonsensical state, so it is made unrepresentable here).
    ///
    /// `S: ?Sized` so a `&dyn Signer` is accepted as readily as a concrete
    /// signer, mirroring [`crate::oplog::Op::create_signed`].
    #[must_use]
    pub fn create_signed<S: Signer + ?Sized>(
        signer: &S,
        team: String,
        mut members: BTreeSet<Ss58>,
        version: u64,
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
            // Placeholder: `signing_bytes` excludes `sig`, so its value here does
            // not affect the message that gets signed.
            sig: Signature::new([0u8; 64]),
        };
        let msg = manifest.signing_bytes();
        manifest.sig = signer.sign(&msg);
        manifest
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
/// [`TeamManifest::verify`], and (c) names *this* `team` in its signed `team`
/// field. Check (c) is the manifest analogue of the op-log's
/// `verify_team_binding`: the bucket is untrusted, so a validly-signed manifest
/// copied out of *another* team's storage must not be allowed to govern this
/// one. Anything failing (a)–(c) is skipped (logged, never fatal — one junk or
/// foreign upload must not blind the team).
///
/// **Founder consistency** is then enforced by *filtering*, not erroring, and the
/// trusted founder is chosen by `expected_founder`:
///
/// - `Some(founder)` — the founder is PINNED out of band (operator config, which
///   the untrusted bucket cannot rewrite). Only manifests signed by that exact
///   address are honoured; the live manifest is the highest version among them.
///   A bucket that overwrites the genesis (version-0) object with a self-signed
///   manifest naming a different founder can no longer seize the team — its
///   manifest is filtered out, never elected. If no manifest is signed by the
///   pinned founder yet, the team reads as open (`None`), never as the attacker's.
/// - `None` — trust-on-genesis (backward compatible): the genesis (lowest-version)
///   survivor fixes the trusted founder. This is the documented residual gap — a
///   bucket with write access CAN overwrite the genesis object to elect itself —
///   closed only by pinning a founder.
///
/// In both modes a manifest by any other founder is dropped (skipped + warned),
/// never honoured and never fatal — a single `?`-propagated error here would
/// otherwise break every member's `sync`.
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

    // Fix the trusted founder. A PINNED founder (operator config) is the trust
    // anchor the bucket cannot rewrite, so it wins outright; otherwise fall back
    // to the genesis (lowest-version) survivor — one object exists per version
    // (`manifest_key`), so versions are unique and the minimum is unambiguous.
    // Clone so the borrow of `valid` is released before the filtering re-borrow.
    let trusted_founder: Ss58 = if let Some(pinned) = expected_founder {
        pinned.clone()
    } else {
        let Some(genesis) = valid.iter().min_by_key(|manifest| manifest.version) else {
            return Ok(None);
        };
        genesis.founder.clone()
    };

    // The live manifest is the highest version among manifests signed by the
    // trusted founder. A manifest by any other founder is an attempted seizure: it
    // is filtered (skipped + warned), never honored and never fatal. When the
    // founder is pinned and NO manifest is signed by it, `latest` stays `None` and
    // the team reads as open — the attacker's manifest is ignored, not elected.
    let mut latest: Option<&TeamManifest> = None;
    for manifest in &valid {
        if manifest.founder == trusted_founder {
            if latest.is_none_or(|live| manifest.version > live.version) {
                latest = Some(manifest);
            }
        } else {
            tracing::warn!(
                manifest_version = manifest.version,
                founder = %manifest.founder.as_str(),
                trusted_founder = %trusted_founder.as_str(),
                "skipping a team manifest whose founder differs from the trusted founder"
            );
        }
    }
    Ok(latest.cloned())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for fallible fixtures but still assert on outcomes; the assertions are the test"
    )]

    use super::{TeamManifest, load_manifest, manifest_key, publish_manifest};
    use crate::NetworkPrefix;
    use crate::error::MemError;
    use crate::oplog::Signer;
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
    /// writes: the domain tag, framed team, an 8-byte member count, that many
    /// framed members, an 8-byte version, the framed founder, and a trailing raw
    /// 32-byte founder key. That this inverse exists IS the proof the composite
    /// encoding is injective. Returns `None` on any truncation rather than
    /// panicking (the crate denies `unwrap`/`panic`).
    fn parse_manifest(buf: &[u8]) -> Option<ParsedManifest> {
        let domain = super::MANIFEST_DOMAIN;
        if !buf.starts_with(domain) {
            return None;
        }
        let buf = buf.get(domain.len()..)?;
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
        let founder_key = <[u8; 32]>::try_from(buf).ok()?.to_vec();
        Some(ParsedManifest {
            team,
            members,
            version,
            founder,
            founder_key,
        })
    }

    proptest! {
        /// The composite manifest encoding is injective: parsing `signing_bytes`
        /// back recovers every field, so two manifests differing in ANY field
        /// (team, member set, version, founder, founder key) cannot collide into
        /// the same signed bytes. This is the forgery-resistance property the
        /// per-field `push_framed` round-trip cannot prove alone, because
        /// `signing_bytes` interleaves framed fields with raw fixed-width ones
        /// (the member count, the version, the 32-byte founder key) — exactly the
        /// boundary ambiguity the explicit framed member count exists to close.
        #[test]
        fn manifest_signing_bytes_is_injective(
            member_seeds in proptest::collection::btree_set(1u8..=8u8, 0..6),
            version in any::<u64>(),
        ) {
            let founder = signer(1).map_err(tce)?;
            let member_set = member_seeds
                .iter()
                .copied()
                .map(ss58_of)
                .collect::<Result<BTreeSet<Ss58>, _>>()
                .map_err(tce)?;
            let manifest =
                TeamManifest::create_signed(&founder, "team".to_owned(), member_set, version);

            let bytes = manifest.signing_bytes();
            let parsed = parse_manifest(&bytes)
                .ok_or_else(|| tce("manifest signing bytes did not parse back"))?;

            prop_assert_eq!(parsed.team, b"team".to_vec());
            let expected_members: Vec<Vec<u8>> = manifest
                .members
                .iter()
                .map(|m| m.as_str().as_bytes().to_vec())
                .collect();
            prop_assert_eq!(parsed.members, expected_members);
            prop_assert_eq!(parsed.version, version);
            prop_assert_eq!(parsed.founder, manifest.founder.as_str().as_bytes().to_vec());
            prop_assert_eq!(parsed.founder_key, manifest.founder_key.as_bytes().to_vec());
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
        // A v1 binary meeting a NEWER manifest shape (e.g. a future recovery-key
        // field) must not choke on it: serde has no `deny_unknown_fields` on
        // `TeamManifest`, so an extra field is silently ignored on deserialize,
        // and a signature that does not match the object it rides in on then
        // fails `verify()` — the object is skipped, not a hard error. This is
        // exactly what makes an OLD binary fail CLOSED (skip the unknown
        // manifest) rather than crash `sync` for every member when it meets a
        // v2 manifest.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let valid = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2])?, 0);
        publish_manifest(blob.as_ref(), &valid).await?;

        // Planted directly (not through `publish_manifest`, which would refuse
        // an unverifiable manifest): a well-formed JSON object under the same
        // prefix, shaped like a manifest but carrying an extra unknown field and
        // a garbage signature that cannot possibly verify.
        let unknown_field_object = serde_json::json!({
            "team": "team",
            "members": [founder.author_ss58().as_str()],
            "version": 1,
            "founder": founder.author_ss58().as_str(),
            "founder_key": founder.verifying_key().to_hex(),
            "sig": "00".repeat(64),
            "recovery_key": "a-field-v1-does-not-know-about",
        });
        blob.put(
            &manifest_key("team", 1),
            serde_json::to_vec(&unknown_field_object)?,
        )
        .await?;

        let loaded = load_manifest(blob.as_ref(), "team", None).await?.ok_or(
            "the valid v0 manifest must still load despite the sibling unknown-field object",
        )?;
        assert_eq!(
            loaded.version, 0,
            "the unknown-field, garbage-sig object is skipped, not fatal"
        );
        Ok(())
    }
}
