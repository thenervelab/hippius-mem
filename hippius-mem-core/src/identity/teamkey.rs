//! Team-key provisioning and rotation: distributing the shared symmetric team
//! key to members cryptographically, and rotating it when membership changes.
//!
//! # Why this exists
//!
//! Notes are sealed under one 32-byte team [`SecretKey`] ([`crate::crypto`]).
//! Earlier phases hand-configured that key out of band. This module distributes
//! it instead: the founder *wraps* the team key to each member's x25519 public
//! key, a member *unwraps* it with their own x25519 secret, and removing a
//! member is handled by *rotating* to a new key at a new epoch that only the
//! remaining members receive a wrap of.
//!
//! # Per-member encryption key (x25519)
//!
//! Each [`Identity`] carries an x25519 encryption keypair *derived* from the
//! same mnemonic seed as its sr25519 signing key, but domain-separated by the
//! KDF info string [`X25519_KDF_INFO`] so the two are cryptographically
//! independent — compromising one does not yield the other, and a member never
//! manages a second secret. See [`Identity::x25519_public`].
//!
//! # Sealed-box construction
//!
//! [`wrap_team_key`] is an ephemeral-static ECDH sealed box:
//!
//! 1. Draw a fresh ephemeral x25519 keypair from the OS CSPRNG.
//! 2. ECDH the ephemeral secret against the recipient's static public key.
//! 3. Derive a 32-byte AEAD key from the shared secret with a Blake2b KDF,
//!    domain-separated ([`KDF_DOMAIN`]) and bound to both public keys so the
//!    key is unique to this exact (ephemeral, recipient) transcript.
//! 4. Seal the team-key bytes under that AEAD key with the existing
//!    XChaCha20-Poly1305 layer ([`crate::crypto::seal`]), authenticating the
//!    epoch and both public keys as additional data.
//!
//! Only the ephemeral public key travels in the [`WrappedKey`]; the ephemeral
//! secret is discarded, so each wrap is forward-secret — recovering one
//! recipient's static secret later does not expose the team keys wrapped to
//! *other* recipients. [`unwrap_team_key`] reverses the ECDH with the
//! recipient's static secret and recovers the team key; any other party gets a
//! detail-free [`MemError::Crypto`].
//!
//! # Forward-readable rotation
//!
//! [`rotate_team_key`] provisions a *new* team key at a *new* epoch for the
//! current members only. A removed member is simply absent from the new
//! epoch's wraps, so they cannot read notes written under the new key. They
//! retain the wraps for *older* epochs, so previously shared notes stay
//! readable to them — the model is forward-readable, not retroactively
//! revoking. Re-encrypting historical notes is out of scope here.
//!
//! Wiring ops/notes to record their key epoch and decrypt across multiple
//! epochs on `get`/`sync` is deferred to Phase 4; this module delivers the
//! distribution, rotation, and bootstrap primitives.

use blake2::{Blake2b512, Digest};
use chacha20poly1305::aead::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, SecretKey};
use crate::domain::{NetworkPrefix, Ss58};
use crate::error::MemError;
use crate::oplog::{Signature, Signer, VerifyingKey, verify};
use crate::store::BlobStore;

use super::Identity;

/// Domain-separation tag for the x25519 encryption key derivation. Distinct
/// from any sr25519 use of the seed, so the two keys are independent.
const X25519_KDF_INFO: &[u8] = b"hippius-memory-x25519";
/// Domain-separation tag for the sealed-box AEAD key derivation.
const KDF_DOMAIN: &[u8] = b"hippius-memory-teamkey-kdf-v1";
/// Domain-separation tag mixed into the sealed-box additional authenticated
/// data, so a wrap cannot be reinterpreted under a different protocol.
const WRAP_AAD_DOMAIN: &[u8] = b"hippius-memory-teamkey-wrap-v1";
/// Domain-separation tag for a [`MemberKey`]'s signed bytes.
const MEMBERKEY_DOMAIN: &[u8] = b"hippius-memory-memberkey-v1";

impl Identity {
    /// This identity's x25519 encryption public key.
    ///
    /// Derived deterministically from the same mnemonic seed as the sr25519
    /// signing key but domain-separated by [`X25519_KDF_INFO`], so it is
    /// independent of [`Identity::verifying_key`]: the same mnemonic always
    /// yields the same x25519 public key, and it is what other members wrap the
    /// team key to.
    #[must_use]
    pub fn x25519_public(&self) -> [u8; 32] {
        PublicKey::from(&self.x25519_secret()).to_bytes()
    }

    /// This identity's x25519 encryption secret, used to unwrap a team key.
    ///
    /// Returned as an [`x25519_dalek::StaticSecret`], which is zeroized on drop
    /// and carries no `Debug` impl, so the secret cannot leak through logs or
    /// error chains. Hold it briefly: per the zeroize contract, copies left by
    /// moves cannot be reclaimed. The bytes are derived (not stored) from the
    /// mnemonic seed on each call, domain-separated from the signing key.
    #[must_use]
    pub fn x25519_secret(&self) -> StaticSecret {
        let mut hasher = Blake2b512::new();
        hasher.update(X25519_KDF_INFO);
        // The sr25519 mini-secret seed (private to the `identity` module, read
        // here from a descendant module). The KDF domain tag keeps the x25519
        // key independent of any sr25519 use of the same seed.
        hasher.update(&self.sr25519_seed[..]);
        let mut digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest[..32]);
        // The lower 32 bytes of the digest ARE the secret; wipe the hasher output.
        digest.as_mut_slice().zeroize();
        let secret = StaticSecret::from(bytes);
        // `bytes` is `Copy`, so `StaticSecret::from` copied rather than moved it;
        // wipe the residual stack copy (identity-4). The `StaticSecret` holds its
        // own zeroize-on-drop copy and clamps on use.
        bytes.zeroize();
        secret
    }
}

/// A member's published x25519 encryption key, signed by their sr25519 key.
///
/// Publishing this lets other members wrap the team key to `x25519_public`
/// while the sr25519 signature binds that encryption key to the member's
/// identity: an attacker cannot substitute their own x25519 key for a member's
/// without also forging that member's sr25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberKey {
    /// The member's SS58 account address.
    pub ss58: Ss58,
    /// The member's x25519 encryption public key.
    pub x25519_public: [u8; 32],
    /// The sr25519 public key that signed this record.
    pub key_owner: VerifyingKey,
    /// The sr25519 signature over [`MemberKey::signing_bytes`].
    pub sig: Signature,
}

impl MemberKey {
    /// The exact bytes that are signed and verified.
    ///
    /// A domain-tagged, length-framed concatenation of every field except
    /// `sig`. Hand-built (not `serde_json`) so it is total and host-independent,
    /// mirroring [`crate::TeamManifest::signing_bytes`]: the variable-length
    /// `ss58` is length-prefixed, the fixed-width 32-byte keys are emitted
    /// verbatim, so the bytes — and the signature over them — agree across
    /// 32- and 64-bit machines.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MEMBERKEY_DOMAIN);
        push_framed(&mut buf, self.ss58.as_str().as_bytes());
        buf.extend_from_slice(&self.x25519_public);
        buf.extend_from_slice(self.key_owner.as_bytes());
        buf
    }

    /// Build a [`MemberKey`] for `identity`, signed by `signer`.
    ///
    /// `ss58`/`key_owner` come from the `signer` and `x25519_public` from the
    /// `identity`; the caller is expected to pass a `signer` and `identity`
    /// derived from the same mnemonic so the published encryption key is the
    /// one the member actually controls. `S: ?Sized` so a `&dyn Signer` is
    /// accepted, mirroring [`crate::TeamManifest::create_signed`].
    #[must_use]
    pub fn create_signed<S: Signer + ?Sized>(signer: &S, identity: &Identity) -> Self {
        let mut member_key = Self {
            ss58: signer.author_ss58(),
            x25519_public: identity.x25519_public(),
            key_owner: signer.verifying_key(),
            // Placeholder: `signing_bytes` excludes `sig`, so this value does
            // not affect the message that gets signed.
            sig: Signature::new([0u8; 64]),
        };
        let msg = member_key.signing_bytes();
        member_key.sig = signer.sign(&msg);
        member_key
    }

    /// Whether this record is authentic: the signature verifies under
    /// `key_owner`, AND `ss58` decodes to exactly `key_owner`.
    ///
    /// The second check is the identity binding — without it a writer could
    /// publish someone else's `ss58` alongside their own key.
    #[must_use]
    pub fn verify(&self) -> bool {
        verify(&self.key_owner, &self.signing_bytes(), &self.sig)
            && super::ss58_decode(&self.ss58).is_ok_and(|(key, prefix)| {
                // Bind the network prefix to Hippius, exactly as Op::verify_identity
                // does: the ss58 string is the wrap lookup key, so the same key
                // under a different prefix is a different (wrong) slot.
                key == self.key_owner && prefix == NetworkPrefix::HIPPIUS
            })
    }
}

/// A team key sealed to one recipient's x25519 public key at a given epoch.
///
/// Holds only public material plus ciphertext: the ephemeral public key of the
/// sealed box and the AEAD blob. Safe to store and serve publicly — only the
/// matching x25519 secret can unwrap it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// The key epoch this wrap belongs to.
    pub epoch: u64,
    /// The sender's per-wrap ephemeral x25519 public key.
    pub ephemeral_public: [u8; 32],
    /// `nonce ‖ ciphertext+tag` over the team-key bytes (see [`crate::crypto`]).
    pub ciphertext: Vec<u8>,
}

/// Wrap `team_key` to `recipient_x25519_public` for `team` at `epoch`,
/// sealed-box style.
///
/// Generates a fresh ephemeral x25519 keypair, performs ECDH against the
/// recipient public key, derives an AEAD key from the shared secret, and seals
/// the team-key bytes. The result is forward-secret per wrap: the ephemeral
/// secret is never stored. `team` is bound into the AEAD AAD so a wrap cannot be
/// relocated to a different team's slot (see [`wrap_aad`]).
///
/// # Errors
///
/// Returns [`MemError::Crypto`] if the AEAD layer rejects the message (only the
/// documented max-length path; see [`crate::crypto::seal`]).
pub fn wrap_team_key(
    team: &str,
    team_key: &SecretKey,
    recipient_x25519_public: &[u8; 32],
    epoch: u64,
) -> Result<WrappedKey, MemError> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_x25519_public));
    let aead_key = derive_aead_key(
        shared.as_bytes(),
        &ephemeral_public,
        recipient_x25519_public,
    );
    let aad = wrap_aad(team, epoch, &ephemeral_public, recipient_x25519_public);
    let ciphertext = crypto::seal(&aead_key, team_key.expose_bytes(), &aad)?;
    Ok(WrappedKey {
        epoch,
        ephemeral_public,
        ciphertext,
    })
}

/// Unwrap a [`WrappedKey`] with the recipient's x25519 static secret, requiring
/// it to be the wrap for `expected_epoch`.
///
/// Reverses the ECDH against the wrap's ephemeral public key, re-derives the
/// AEAD key, and opens the ciphertext.
///
/// `team`/`expected_epoch` are what the CALLER asked for (the slot it read the
/// wrap from), not the wrap's self-asserted `epoch`. Both are bound into the AEAD
/// AAD (I1, I-team): a wrap could be relocated by an untrusted bucket across epoch
/// slots — a member's epoch-N wrap copied over their epoch-M slot — or across team
/// slots — teamA's wrap served from teamB's slot for a member of both. Deriving
/// the AAD from the caller's `team`/`expected_epoch` makes either relocation fail
/// authentication instead of silently returning the wrong key (an epoch downgrade
/// that defeats forward-readable rotation, or cross-team key confusion).
///
/// # Errors
///
/// Returns [`MemError::Crypto`] — with no detail — if `wrapped.epoch` is not
/// `expected_epoch`, if the wrap was relocated from another team's slot, if
/// `recipient_secret` is not the wrap's intended recipient, if the ciphertext was
/// tampered with, or if the recovered plaintext is not exactly 32 bytes.
pub fn unwrap_team_key(
    team: &str,
    wrapped: &WrappedKey,
    recipient_secret: &StaticSecret,
    expected_epoch: u64,
) -> Result<SecretKey, MemError> {
    // Reject a wrap served from the wrong epoch slot before spending the ECDH;
    // the AAD binding below would also catch it, but this gives the cheap, clear
    // rejection.
    if wrapped.epoch != expected_epoch {
        return Err(MemError::Crypto);
    }
    let recipient_public = PublicKey::from(recipient_secret).to_bytes();
    let shared = recipient_secret.diffie_hellman(&PublicKey::from(wrapped.ephemeral_public));
    let aead_key = derive_aead_key(
        shared.as_bytes(),
        &wrapped.ephemeral_public,
        &recipient_public,
    );
    // Bind the caller's expected team + epoch, not the wrap's self-asserted ones.
    let aad = wrap_aad(
        team,
        expected_epoch,
        &wrapped.ephemeral_public,
        &recipient_public,
    );
    // The opened plaintext is the raw team key; keep it in a zeroizing buffer
    // so the heap copy is wiped once it has been moved into the `SecretKey`.
    let plaintext = Zeroizing::new(crypto::open(&aead_key, &wrapped.ciphertext, &aad)?);
    let mut bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| MemError::Crypto)?;
    let secret = SecretKey::from_bytes(bytes);
    // Wipe the residual stack copy (identity-4): `bytes` is `Copy`, so
    // `from_bytes` copied rather than moved it; the `SecretKey` holds its own
    // zeroize-on-drop copy.
    bytes.zeroize();
    Ok(secret)
}

/// Provision `team_key` at `epoch` to every VERIFIED member in `member_keys`.
///
/// Wraps the key to each member's x25519 public key and publishes the
/// [`WrappedKey`] under that member's per-epoch object key. A member key that
/// fails [`MemberKey::verify`] is skipped with a warning (never wrapped to), so
/// the team key is never handed to an x25519 key not cryptographically bound to
/// its claimed ss58.
///
/// # Errors
///
/// Returns [`MemError::Crypto`] if a wrap fails, [`MemError::Serialize`] if a
/// wrap cannot be encoded, or [`MemError::Storage`] if a backend write fails.
pub async fn provision_team_key(
    blob: &dyn BlobStore,
    team: &str,
    team_key: &SecretKey,
    epoch: u64,
    member_keys: &[MemberKey],
) -> Result<(), MemError> {
    for member in member_keys {
        // Re-verify each member key before wrapping the team key TO it: an
        // unverified record's `x25519_public` is not bound to its `ss58`, so
        // wrapping to it could hand the team key to an attacker's encryption key
        // published under a member's address. Skip-with-warn (not abort), matching
        // load_member_keys — one forged record must not deny provisioning to the
        // rest. (Callers that pass load_member_keys output already verified; this
        // is defense-in-depth for callers that assemble the list themselves.)
        if !member.verify() {
            tracing::warn!(
                ss58 = %member.ss58.as_str(),
                "skipping a member key that fails verification while provisioning the team key"
            );
            continue;
        }
        let wrapped = wrap_team_key(team, team_key, &member.x25519_public, epoch)?;
        let key = wrapped_key_key(team, epoch, member.ss58.as_str());
        blob.put(&key, serde_json::to_vec(&wrapped)?).await?;
    }
    Ok(())
}

/// Bootstrap a team key from the bucket: load this member's [`WrappedKey`] for
/// `epoch` and unwrap it.
///
/// This is how a member who was never pre-shared the key obtains it — they only
/// need their own x25519 secret.
///
/// # Errors
///
/// Returns [`MemError::NotFound`] if no wrap exists for `recipient_ss58` at
/// `epoch` (e.g. a non-member, or a member removed before this epoch),
/// [`MemError::Serialize`] if the stored wrap cannot be decoded,
/// [`MemError::Storage`] for other backend failures, or [`MemError::Crypto`] if
/// `recipient_secret` cannot unwrap it.
pub async fn fetch_team_key(
    blob: &dyn BlobStore,
    team: &str,
    epoch: u64,
    recipient_ss58: &Ss58,
    recipient_secret: &StaticSecret,
) -> Result<SecretKey, MemError> {
    let key = wrapped_key_key(team, epoch, recipient_ss58.as_str());
    let bytes = blob.get(&key).await?;
    let wrapped: WrappedKey = serde_json::from_slice(&bytes)?;
    unwrap_team_key(team, &wrapped, recipient_secret, epoch)
}

/// Rotate the team key: provision `new_team_key` at `new_epoch` for the current
/// members only.
///
/// Removed members are simply absent from `current_member_keys`, so they get no
/// wrap of the new epoch and cannot read notes written under it. Their wraps
/// for older epochs remain, so previously shared notes stay readable — the
/// forward-readable model documented at the module level.
///
/// # Errors
///
/// Same as [`provision_team_key`].
pub async fn rotate_team_key(
    blob: &dyn BlobStore,
    team: &str,
    new_team_key: &SecretKey,
    new_epoch: u64,
    current_member_keys: &[MemberKey],
) -> Result<(), MemError> {
    provision_team_key(blob, team, new_team_key, new_epoch, current_member_keys).await
}

/// Publish a member's signed x25519 key, after verifying it.
///
/// Refusing to store an unverifiable record keeps the bucket from holding a
/// member key that does not bind to its claimed identity.
///
/// # Errors
///
/// Returns [`MemError::Unauthorized`] if `member_key` does not [`MemberKey::verify`],
/// [`MemError::Serialize`] if it cannot be encoded, or [`MemError::Storage`] if
/// the backend write fails.
pub async fn publish_member_key(
    blob: &dyn BlobStore,
    team: &str,
    member_key: &MemberKey,
) -> Result<(), MemError> {
    if !member_key.verify() {
        return Err(MemError::Unauthorized(format!(
            "refusing to publish an unverifiable member key for {:?}",
            member_key.ss58.as_str()
        )));
    }
    let key = member_key_key(team, member_key.ss58.as_str());
    blob.put(&key, serde_json::to_vec(member_key)?).await
}

/// Load every verified member key for `team`.
///
/// Trust is re-derived from storage: records that do not deserialize or fail
/// [`MemberKey::verify`] are skipped (logged, never fatal — one junk upload must
/// not blind the team), mirroring [`crate::load_manifest`].
///
/// # Errors
///
/// Returns [`MemError::Storage`] / [`MemError::NotFound`] from the backend.
pub async fn load_member_keys(
    blob: &dyn BlobStore,
    team: &str,
) -> Result<Vec<MemberKey>, MemError> {
    let prefix = member_keys_prefix(team);
    let keys = blob.list(&prefix).await?;
    let mut verified = Vec::with_capacity(keys.len());
    for key in &keys {
        let bytes = blob.get(key).await?;
        match serde_json::from_slice::<MemberKey>(&bytes) {
            Ok(member_key) if member_key.verify() => verified.push(member_key),
            Ok(_) => tracing::warn!(
                object_key = %key,
                "skipping a member key that fails signature/identity verification"
            ),
            Err(err) => tracing::warn!(
                object_key = %key,
                error = %err,
                "skipping object under the member-key prefix that does not deserialize as a MemberKey"
            ),
        }
    }
    Ok(verified)
}

/// Derive the 32-byte AEAD key for a wrap from the ECDH shared secret.
///
/// The shared secret is never used as the AEAD key directly: it is run through
/// a domain-separated Blake2b KDF and bound to both public keys, so the key is
/// unique to this exact transcript and carries the domain tag.
fn derive_aead_key(
    shared_secret: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> SecretKey {
    let mut hasher = Blake2b512::new();
    hasher.update(KDF_DOMAIN);
    hasher.update(shared_secret);
    hasher.update(ephemeral_public);
    hasher.update(recipient_public);
    let mut digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    // Wipe the hasher output: its first 32 bytes are the AEAD key.
    digest.as_mut_slice().zeroize();
    let secret = SecretKey::from_bytes(key);
    // `key` is `Copy`, so `from_bytes` copied rather than moved it; wipe the
    // residual stack copy (identity-4) — the `SecretKey` owns a zeroize-on-drop one.
    key.zeroize();
    secret
}

/// The additional authenticated data binding a wrap to its team, epoch, and both
/// public keys, so none can be altered without failing authentication.
///
/// `team` is length-framed first (I-team): a member of two teams holds wraps to
/// the SAME x25519 key at the same epoch, so without the team bound an untrusted
/// bucket could serve teamA's wrap from teamB's slot and `unwrap_team_key` would
/// accept it — returning teamA's key for teamB and silently making teamB's writes
/// unreadable (cross-team key confusion). Binding the team makes that relocation
/// fail authentication, exactly as the epoch binding defeats cross-epoch reuse.
fn wrap_aad(
    team: &str,
    epoch: u64,
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Vec<u8> {
    let team_bytes = team.as_bytes();
    let mut aad = Vec::with_capacity(WRAP_AAD_DOMAIN.len() + 8 + team_bytes.len() + 8 + 32 + 32);
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    // Length-framed so a `team` containing the next field's bytes cannot be
    // confused with a different (team, epoch) split.
    push_framed(&mut aad, team_bytes);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(recipient_public);
    aad
}

use crate::framing::push_framed;

/// The object key a member's signed x25519 key is stored under.
fn member_key_key(team: &str, ss58: &str) -> String {
    format!("{team}/_memberkeys/{ss58}")
}

/// The object-key prefix under which `team`'s member keys live.
fn member_keys_prefix(team: &str) -> String {
    format!("{team}/_memberkeys/")
}

/// The object key a member's wrapped team key is stored under.
///
/// `{team}/_keys/{epoch:020}/{ss58}`: the epoch is zero-padded to 20 digits
/// (the width of `u64::MAX`) so keys sort by epoch lexicographically.
fn wrapped_key_key(team: &str, epoch: u64, ss58: &str) -> String {
    format!("{team}/_keys/{epoch:020}/{ss58}")
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::*;
    use crate::identity::{derive_identity, signer_from_mnemonic};
    use crate::store::MemoryBlobStore;
    use proptest::prelude::*;

    // Three distinct, valid 12-word BIP-39 mnemonics (Substrate dev phrase +
    // two canonical Trezor test vectors) standing in for three members.
    const PHRASE_A: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
    const PHRASE_B: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const PHRASE_C: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const TEAM: &str = "team";

    fn member_key_for(phrase: &str) -> Result<MemberKey, MemError> {
        let identity = derive_identity(phrase, NetworkPrefix::HIPPIUS)?;
        let signer = signer_from_mnemonic(phrase, NetworkPrefix::HIPPIUS)?;
        Ok(MemberKey::create_signed(&signer, &identity))
    }

    proptest! {
        /// The correctness proof: any team key wrapped to a recipient's public
        /// key unwraps back to the identical bytes with that recipient's secret.
        #[test]
        fn wrap_unwrap_roundtrips(
            key_bytes in proptest::array::uniform32(any::<u8>()),
            secret_bytes in proptest::array::uniform32(any::<u8>()),
            epoch in any::<u64>(),
        ) {
            let team_key = SecretKey::from_bytes(key_bytes);
            let recipient_secret = StaticSecret::from(secret_bytes);
            let recipient_public = PublicKey::from(&recipient_secret).to_bytes();
            let wrapped = wrap_team_key(TEAM, &team_key, &recipient_public, epoch)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let unwrapped = unwrap_team_key(TEAM, &wrapped, &recipient_secret, epoch)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(unwrapped.expose_bytes(), &key_bytes);
        }
    }

    #[test]
    fn non_recipient_cannot_unwrap() -> Result<(), MemError> {
        let team_key = SecretKey::from_bytes([7u8; 32]);
        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let mallory = derive_identity(PHRASE_B, NetworkPrefix::HIPPIUS)?;
        let wrapped = wrap_team_key(TEAM, &team_key, &alice.x25519_public(), 0)?;

        // The wrong secret yields a detail-free crypto error, never a panic.
        assert!(matches!(
            unwrap_team_key(TEAM, &wrapped, &mallory.x25519_secret(), 0),
            Err(MemError::Crypto)
        ));
        // Sanity: the intended recipient still recovers the exact key.
        assert_eq!(
            unwrap_team_key(TEAM, &wrapped, &alice.x25519_secret(), 0)?.expose_bytes(),
            &[7u8; 32]
        );
        Ok(())
    }

    #[test]
    fn tampered_wrapped_key_fails() -> Result<(), MemError> {
        let team_key = SecretKey::from_bytes([4u8; 32]);
        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let mut wrapped = wrap_team_key(TEAM, &team_key, &alice.x25519_public(), 0)?;
        let last = wrapped.ciphertext.len() - 1;
        wrapped.ciphertext[last] ^= 0x01;
        assert!(matches!(
            unwrap_team_key(TEAM, &wrapped, &alice.x25519_secret(), 0),
            Err(MemError::Crypto)
        ));
        Ok(())
    }

    #[test]
    fn relocated_wrap_from_another_epoch_is_rejected() -> Result<(), MemError> {
        // I1 regression: an untrusted bucket copies a member's validly-sealed
        // epoch-0 wrap over their epoch-1 slot. Unwrapping it as epoch 1 must fail
        // — otherwise a member is silently downgraded to the epoch-0 key a removed
        // member still holds, defeating forward-readable rotation.
        let team_key = SecretKey::from_bytes([5u8; 32]);
        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let epoch0_wrap = wrap_team_key(TEAM, &team_key, &alice.x25519_public(), 0)?;

        // The wrap opens correctly at its true epoch...
        assert!(unwrap_team_key(TEAM, &epoch0_wrap, &alice.x25519_secret(), 0).is_ok());
        // ...but presented as epoch 1 (relocated slot) it is rejected.
        assert!(matches!(
            unwrap_team_key(TEAM, &epoch0_wrap, &alice.x25519_secret(), 1),
            Err(MemError::Crypto)
        ));
        Ok(())
    }

    #[test]
    fn relocated_wrap_from_another_team_is_rejected() -> Result<(), MemError> {
        // M2 regression: a member of two teams holds wraps to the SAME x25519 key
        // at the same epoch. An untrusted bucket serves team-a's wrap from team-b's
        // slot. Unwrapping it as team-b must fail — otherwise team-b silently adopts
        // team-a's key and every team-b write becomes unreadable (cross-team key
        // confusion). The team is bound into the AEAD AAD, so the open fails.
        let team_key = SecretKey::from_bytes([6u8; 32]);
        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let team_a_wrap = wrap_team_key("team-a", &team_key, &alice.x25519_public(), 0)?;

        // Opens correctly for the team it was sealed for...
        assert!(unwrap_team_key("team-a", &team_a_wrap, &alice.x25519_secret(), 0).is_ok());
        // ...but presented as a different team's wrap it is rejected.
        assert!(matches!(
            unwrap_team_key("team-b", &team_a_wrap, &alice.x25519_secret(), 0),
            Err(MemError::Crypto)
        ));
        Ok(())
    }

    #[test]
    fn member_key_create_verify_roundtrip() -> Result<(), MemError> {
        let member_key = member_key_for(PHRASE_A)?;
        assert!(
            member_key.verify(),
            "a freshly created member key must verify"
        );
        Ok(())
    }

    #[test]
    fn member_key_identity_bound() -> Result<(), MemError> {
        // Build a record whose signature is valid under Alice's key, but whose
        // claimed ss58 is Bob's. The signature check passes; the ss58-binds-key
        // check must fail.
        let signer_alice = signer_from_mnemonic(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let bob = derive_identity(PHRASE_B, NetworkPrefix::HIPPIUS)?;
        let mut tampered = member_key_for(PHRASE_A)?;
        tampered.ss58 = bob.ss58.clone();
        tampered.sig = signer_alice.sign(&tampered.signing_bytes());

        assert!(
            !tampered.verify(),
            "ss58 that does not decode to key_owner must be rejected"
        );
        Ok(())
    }

    #[test]
    fn member_key_rejects_non_hippius_prefix() -> Result<(), Box<dyn std::error::Error>> {
        // Defense-in-depth, mirroring Op::verify_identity: a member key whose ss58
        // is under a non-Hippius prefix must fail verification even with a valid
        // signature and key binding — the ss58 string is the wrap lookup slot.
        let signer = signer_from_mnemonic(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let identity = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let mut member_key = MemberKey::create_signed(&signer, &identity);
        assert!(member_key.verify(), "the genuine member key verifies");

        // Re-encode the SAME key under prefix 0 and re-sign: the signature is sound
        // and the key still decodes, but the prefix is not Hippius.
        member_key.ss58 = super::super::ss58_encode(&member_key.key_owner, NetworkPrefix::new(0)?);
        member_key.sig = signer.sign(&member_key.signing_bytes());
        assert!(
            !member_key.verify(),
            "a member key under a non-Hippius prefix must be rejected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn provision_skips_an_unverifiable_member_key() -> Result<(), MemError> {
        // The team key is wrapped only to verified members: a forged member key
        // (x25519 no longer bound to its ss58) is skipped, so no wrap is written
        // for it, while the verified member still receives one.
        let blob = MemoryBlobStore::new();
        let team_key = SecretKey::from_bytes([3u8; 32]);
        let good = member_key_for(PHRASE_A)?;
        let mut forged = member_key_for(PHRASE_B)?;
        forged.x25519_public[0] ^= 0x01; // breaks the signature binding
        assert!(
            !forged.verify(),
            "the tampered member key fails verification"
        );

        provision_team_key(&blob, TEAM, &team_key, 0, &[good.clone(), forged.clone()]).await?;

        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        assert!(
            fetch_team_key(&blob, TEAM, 0, &good.ss58, &alice.x25519_secret())
                .await
                .is_ok(),
            "the verified member received a wrap"
        );
        let bob_id = derive_identity(PHRASE_B, NetworkPrefix::HIPPIUS)?;
        assert!(
            matches!(
                fetch_team_key(&blob, TEAM, 0, &forged.ss58, &bob_id.x25519_secret()).await,
                Err(MemError::NotFound { .. })
            ),
            "no wrap was written for the unverifiable member"
        );
        Ok(())
    }

    #[tokio::test]
    async fn provision_then_fetch() -> Result<(), MemError> {
        let blob = MemoryBlobStore::new();
        let team_key = SecretKey::from_bytes([1u8; 32]);
        let key_alice = member_key_for(PHRASE_A)?;
        let key_bob = member_key_for(PHRASE_B)?;
        provision_team_key(
            &blob,
            TEAM,
            &team_key,
            0,
            &[key_alice.clone(), key_bob.clone()],
        )
        .await?;

        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let fetched =
            fetch_team_key(&blob, TEAM, 0, &key_alice.ss58, &alice.x25519_secret()).await?;
        assert_eq!(fetched.expose_bytes(), &[1u8; 32]);

        // Charlie was never provisioned: there is no wrap to fetch.
        let charlie = derive_identity(PHRASE_C, NetworkPrefix::HIPPIUS)?;
        let charlie_ss58 = charlie.ss58.clone();
        let missing = fetch_team_key(&blob, TEAM, 0, &charlie_ss58, &charlie.x25519_secret()).await;
        assert!(matches!(missing, Err(MemError::NotFound { .. })));
        Ok(())
    }

    #[tokio::test]
    async fn rotate_excludes_removed_member() -> Result<(), MemError> {
        let blob = MemoryBlobStore::new();
        let key_epoch0 = SecretKey::from_bytes([1u8; 32]);
        let key_epoch1 = SecretKey::from_bytes([2u8; 32]);
        let key_alice = member_key_for(PHRASE_A)?;
        let key_bob = member_key_for(PHRASE_B)?;
        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let bob_id = derive_identity(PHRASE_B, NetworkPrefix::HIPPIUS)?;

        provision_team_key(
            &blob,
            TEAM,
            &key_epoch0,
            0,
            &[key_alice.clone(), key_bob.clone()],
        )
        .await?;
        // Rotate to epoch 1 for Alice only — Bob is removed.
        rotate_team_key(
            &blob,
            TEAM,
            &key_epoch1,
            1,
            std::slice::from_ref(&key_alice),
        )
        .await?;

        // Alice reads the new epoch.
        let alice_new =
            fetch_team_key(&blob, TEAM, 1, &key_alice.ss58, &alice.x25519_secret()).await?;
        assert_eq!(alice_new.expose_bytes(), &[2u8; 32]);

        // Bob has no wrap for epoch 1...
        let bob_new = fetch_team_key(&blob, TEAM, 1, &key_bob.ss58, &bob_id.x25519_secret()).await;
        assert!(matches!(bob_new, Err(MemError::NotFound { .. })));

        // ...but can still read epoch 0 (forward-readable).
        let bob_old =
            fetch_team_key(&blob, TEAM, 0, &key_bob.ss58, &bob_id.x25519_secret()).await?;
        assert_eq!(bob_old.expose_bytes(), &[1u8; 32]);
        Ok(())
    }

    #[test]
    fn x25519_public_is_deterministic() -> Result<(), MemError> {
        let first = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let again = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        assert_eq!(
            first.x25519_public(),
            again.x25519_public(),
            "same mnemonic must yield the same x25519 public key"
        );

        // A different member derives a different encryption key.
        let other = derive_identity(PHRASE_B, NetworkPrefix::HIPPIUS)?;
        assert_ne!(first.x25519_public(), other.x25519_public());
        Ok(())
    }
}
