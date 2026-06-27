//! The founder-signed [`TeamManifest`]: who may write to a team's op-log.
//!
//! # Why this exists
//!
//! A "team" is a shared namespace, and until Phase 3 *any* signer could append
//! ops to a team's op-log and have them converge. The manifest closes that: a
//! team's **founder** signs a list of member SS58 addresses, and
//! [`crate::store::MemoryStore::sync`] only converges ops whose author is a
//! current member. The manifest is the single source of truth for membership,
//! re-derived from storage (never trusted from local cache) on every sync.
//!
//! # Trust model and its limits
//!
//! Like the op-log, the manifest store lives in an untrusted bucket. Trust is
//! re-derived from the signatures on read: [`load_manifest`] keeps only
//! [`TeamManifest::verify`]-passing manifests and enforces **founder
//! consistency** — the highest version's founder must equal the genesis
//! (lowest-version) manifest's founder — so a non-member cannot seize the team
//! by publishing a higher-versioned manifest naming themselves as founder.
//!
//! What it deliberately does NOT defend against (same shape as the op-log's
//! documented gaps): an attacker who *overwrites the genesis object itself* can
//! reset the trusted founder, because nothing pins the genesis. Defending that
//! is on-chain anchoring's job (future work), not this layer's.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::domain::Ss58;
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
            && crate::identity::ss58_decode(&self.founder)
                .is_ok_and(|(key, _prefix)| key == self.founder_key)
    }
}

/// Append a variable-length field, length-prefixed with a fixed 8-byte u64 (LE).
///
/// Fixed width on purpose: `usize::to_le_bytes` differs between 32- and 64-bit
/// hosts, which would make the signed bytes — and the signature over them —
/// disagree across platforms. The saturating fallback keeps the function total
/// without `unwrap`/`panic` (denied by crate lints); no in-memory slice can
/// realistically exceed `u64::MAX` bytes.
fn push_framed(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

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
/// [`MemError::Storage`] if `manifest` does not [`TeamManifest::verify`],
/// [`MemError::Serialize`] if it cannot be encoded, or [`MemError::Storage`] if
/// the backend write fails.
pub async fn publish_manifest(
    blob: &dyn BlobStore,
    manifest: &TeamManifest,
) -> Result<(), MemError> {
    if !manifest.verify() {
        return Err(MemError::Storage(format!(
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
/// fetched, objects that do not deserialize or fail [`TeamManifest::verify`] are
/// skipped (logged, never fatal — one junk upload must not blind the team), and
/// among the survivors the highest `version` wins. **Founder consistency** is
/// then enforced: the highest version's `founder` must equal the genesis
/// (lowest-version) manifest's founder, so a non-founder cannot seize the team
/// by publishing a higher-versioned manifest.
///
/// # Errors
///
/// [`MemError::Storage`] / [`MemError::NotFound`] from the backend, or
/// [`MemError::Storage`] when the founder-consistency check fails.
pub async fn load_manifest(
    blob: &dyn BlobStore,
    team: &str,
) -> Result<Option<TeamManifest>, MemError> {
    let prefix = manifest_prefix(team);
    let keys = blob.list(&prefix).await?;

    let mut valid: Vec<TeamManifest> = Vec::with_capacity(keys.len());
    for key in &keys {
        let bytes = blob.get(key).await?;
        match serde_json::from_slice::<TeamManifest>(&bytes) {
            Ok(manifest) if manifest.verify() => valid.push(manifest),
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

    // Single pass for both extremes; references into `valid` (Copy, so the
    // `is_none_or` shorthands do not move the Options).
    let mut genesis: Option<&TeamManifest> = None;
    let mut latest: Option<&TeamManifest> = None;
    for manifest in &valid {
        if genesis.is_none_or(|g| manifest.version < g.version) {
            genesis = Some(manifest);
        }
        if latest.is_none_or(|l| manifest.version > l.version) {
            latest = Some(manifest);
        }
    }
    let (Some(genesis), Some(latest)) = (genesis, latest) else {
        return Ok(None);
    };

    if latest.founder != genesis.founder {
        return Err(MemError::Storage(format!(
            "team {team:?} manifest founder inconsistency: genesis (v{}) founder {:?} != latest (v{}) founder {:?}",
            genesis.version,
            genesis.founder.as_str(),
            latest.version,
            latest.founder.as_str(),
        )));
    }
    Ok(Some(latest.clone()))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for fallible fixtures but still assert on outcomes; the assertions are the test"
    )]

    use super::{TeamManifest, load_manifest, manifest_key, publish_manifest};
    use crate::oplog::Signer;
    use crate::store::blob::{BlobStore, MemoryBlobStore};
    use crate::{Sr25519Signer, Ss58};
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn tce(e: impl std::fmt::Display) -> TestCaseError {
        TestCaseError::fail(e.to_string())
    }

    /// A signer whose author SS58 is derived from its seed (so it is bound to
    /// its key) — `seed` selects a distinct identity.
    fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
        Ok(Sr25519Signer::from_seed_with_prefix([seed; 32], 42)?)
    }

    fn ss58_of(seed: u8) -> Result<Ss58, Box<dyn std::error::Error>> {
        Ok(signer(seed)?.author_ss58())
    }

    fn members(seeds: &[u8]) -> Result<BTreeSet<Ss58>, Box<dyn std::error::Error>> {
        seeds.iter().map(|&s| ss58_of(s)).collect()
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

    #[tokio::test]
    async fn load_returns_highest_valid_version() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let founder = signer(1)?;
        let v0 = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2])?, 0);
        let v1 = TeamManifest::create_signed(&founder, "team".to_owned(), members(&[1, 2, 3])?, 1);
        publish_manifest(blob.as_ref(), &v0).await?;
        publish_manifest(blob.as_ref(), &v1).await?;

        let loaded = load_manifest(blob.as_ref(), "team")
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
    async fn non_founder_higher_version_is_rejected() -> TestResult {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        let a = signer(1)?;
        let b = signer(2)?;
        // A founds at v0; B (not the founder) self-signs a v1 naming themselves
        // founder. Each manifest verifies in isolation, but founder consistency
        // across versions must reject the seizure.
        let v0 = TeamManifest::create_signed(&a, "team".to_owned(), members(&[1, 2])?, 0);
        let v1 = TeamManifest::create_signed(&b, "team".to_owned(), members(&[1, 2])?, 1);
        publish_manifest(blob.as_ref(), &v0).await?;
        publish_manifest(blob.as_ref(), &v1).await?;

        let err = load_manifest(blob.as_ref(), "team")
            .await
            .err()
            .ok_or("expected a founder-consistency rejection")?;
        assert!(
            format!("{err}").contains("founder inconsistency"),
            "a higher version by a non-founder must be rejected, got: {err}"
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
            load_manifest(blob.as_ref(), "team").await?.is_none(),
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
}
