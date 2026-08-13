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

use std::collections::BTreeSet;

use blake2::{Blake2b512, Digest};
use chacha20poly1305::aead::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, SecretKey};
use crate::domain::{NetworkPrefix, Ss58};
use crate::error::MemError;
use crate::identity::manifest::load_manifest;
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
/// Domain tag for the provisioner signature over a [`WrappedKey`]. Distinct from
/// `WRAP_AAD_DOMAIN` (the AEAD AAD tag): the AAD binds the AEAD open; this binds
/// the signature that proves an AUTHORIZED provisioner produced the wrap.
const WRAP_SIGN_DOMAIN: &[u8] = b"hippius-memory-teamkey-wrap-sign/v1";
/// Domain-separation tag for a [`MemberKey`]'s signed bytes.
pub(crate) const MEMBERKEY_DOMAIN: &[u8] = b"hippius-memory-memberkey-v1";

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

/// A team key sealed to one recipient's x25519 public key at a given epoch,
/// signed by the provisioner who sealed it.
///
/// Holds only public material plus ciphertext: the ephemeral public key of the
/// sealed box, the AEAD blob, and the provisioner's signature over both. Safe to
/// store and serve publicly — only the matching x25519 secret can unwrap it, and
/// [`WrappedKey::verify`] proves the wrap was produced by whoever holds
/// `provisioner`'s secret key, not merely planted by a bucket writer who knows
/// the recipient's PUBLIC x25519 key (see [`unwrap_team_key`]'s docs for why
/// that gap mattered before this signature existed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// The key epoch this wrap belongs to.
    pub epoch: u64,
    /// The sender's per-wrap ephemeral x25519 public key.
    pub ephemeral_public: [u8; 32],
    /// `nonce ‖ ciphertext+tag` over the team-key bytes (see [`crate::crypto`]).
    pub ciphertext: Vec<u8>,
    /// The sr25519 public key of the provisioner who produced this wrap.
    pub provisioner: VerifyingKey,
    /// The provisioner's signature over [`WrappedKey::signing_bytes`].
    pub sig: Signature,
}

impl WrappedKey {
    /// The exact bytes that are signed and verified.
    ///
    /// A domain-tagged, length-framed concatenation of every field an attacker
    /// could vary except `sig` itself: `epoch`, `ephemeral_public`, `ciphertext`,
    /// and `provisioner`. Every field is length-framed (not just the
    /// variable-length `ciphertext`) so the concatenation stays unambiguous even
    /// though most of these fields are fixed-width — cheap insurance against a
    /// future field reordering silently colliding two distinct wraps onto the
    /// same signed bytes.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(WRAP_SIGN_DOMAIN);
        buf.extend_from_slice(&self.epoch.to_le_bytes());
        push_framed(&mut buf, &self.ephemeral_public);
        push_framed(&mut buf, &self.ciphertext);
        push_framed(&mut buf, self.provisioner.as_bytes());
        buf
    }

    /// Whether the provisioner signature is valid over the wrap's signed fields.
    ///
    /// This closes the finding that [`WrappedKey`] was the only bucket-stored
    /// type with no author signature: every other input to the AEAD open
    /// (`epoch`, both public keys) is public, so without this check a bucket
    /// writer who merely knows a recipient's PUBLIC x25519 key could seal an
    /// attacker-chosen team key to them and have it accepted as genuine.
    /// [`unwrap_team_key`] calls this FIRST, before any ECDH work is spent, so a
    /// forged wrap is rejected on the cheapest possible check.
    #[must_use]
    pub fn verify(&self) -> bool {
        verify(&self.provisioner, &self.signing_bytes(), &self.sig)
    }
}

/// Wrap `team_key` to `recipient_x25519_public` for `team` at `epoch`,
/// sealed-box style, and sign the result with `signer`.
///
/// Generates a fresh ephemeral x25519 keypair, performs ECDH against the
/// recipient public key, derives an AEAD key from the shared secret, and seals
/// the team-key bytes. The result is forward-secret per wrap: the ephemeral
/// secret is never stored. `team` is bound into the AEAD AAD so a wrap cannot be
/// relocated to a different team's slot (see [`wrap_aad`]).
///
/// `signer` is the PROVISIONER performing this wrap (the founder, or whoever the
/// caller trusts to provision) — never the recipient. Its public key is recorded
/// as [`WrappedKey::provisioner`] and its signature over
/// [`WrappedKey::signing_bytes`] is what [`unwrap_team_key`] checks before
/// trusting the wrap: without it, every input to the AEAD open is public, so a
/// bucket writer who merely knows the recipient's public x25519 key could forge
/// a wrap installing an attacker-chosen team key. `S: ?Sized` so a `&dyn Signer`
/// is accepted, mirroring [`MemberKey::create_signed`].
///
/// # Errors
///
/// Returns [`MemError::Crypto`] if `recipient_x25519_public` is a low-order
/// point (the ECDH would not be contributory — see the check below), or if the
/// AEAD layer rejects the message (only the documented max-length path; see
/// [`crate::crypto::seal`]).
pub fn wrap_team_key<S: Signer + ?Sized>(
    team: &str,
    team_key: &SecretKey,
    recipient_x25519_public: &[u8; 32],
    epoch: u64,
    signer: &S,
) -> Result<WrappedKey, MemError> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_x25519_public));

    // Contributory check: a low-order recipient point yields an all-zero shared
    // secret, and every OTHER input to `derive_aead_key` is public — so a wrap
    // to such a point would be openable by anyone, publishing the team key.
    // Reaching here requires a manifest-authorized member to publish a signed
    // low-order MemberKey (an insider who could leak the key anyway), so this
    // is defense-in-depth, not a primary barrier — but it is one line.
    if !shared.was_contributory() {
        return Err(MemError::Crypto);
    }

    let aead_key = derive_aead_key(
        shared.as_bytes(),
        &ephemeral_public,
        recipient_x25519_public,
    );
    let aad = wrap_aad(team, epoch, &ephemeral_public, recipient_x25519_public);
    let ciphertext = crypto::seal(&aead_key, team_key.expose_bytes(), &aad)?;

    let mut wrapped = WrappedKey {
        epoch,
        ephemeral_public,
        ciphertext,
        provisioner: signer.verifying_key(),
        // Placeholder: `signing_bytes` excludes `sig`, so this value does not
        // affect the message that gets signed.
        sig: Signature::new([0u8; 64]),
    };

    let msg = wrapped.signing_bytes();
    wrapped.sig = signer.sign(&msg);

    Ok(wrapped)
}

/// Unwrap a [`WrappedKey`] with the recipient's x25519 static secret, requiring
/// it to be the wrap for `expected_epoch`.
///
/// The FIRST check is [`WrappedKey::verify`]: a wrap whose provisioner signature
/// does not check out is rejected before any ECDH work is spent on it. This is
/// the security-critical fix for `WrappedKey` having been the only
/// bucket-stored type with no author signature — every OTHER input to the AEAD
/// open below (`team`, `expected_epoch`, both public keys) is public, so without
/// this check a bucket writer who merely knows the recipient's public x25519 key
/// could seal an attacker-chosen team key to them and have it accepted.
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
/// Returns [`MemError::Crypto`] — with no detail — if the wrap's provisioner
/// signature fails [`WrappedKey::verify`], if `wrapped.epoch` is not
/// `expected_epoch`, if `wrapped.ephemeral_public` is a low-order point (the
/// ECDH would not be contributory), if the wrap was relocated from another
/// team's slot, if `recipient_secret` is not the wrap's intended recipient, if
/// the ciphertext was tampered with, or if the recovered plaintext is not
/// exactly 32 bytes.
pub fn unwrap_team_key(
    team: &str,
    wrapped: &WrappedKey,
    recipient_secret: &StaticSecret,
    expected_epoch: u64,
) -> Result<SecretKey, MemError> {
    // Cheapest possible rejection: an unsigned or forged wrap never reaches the
    // ECDH/AEAD work below at all. See `WrappedKey::verify`'s docs for why this
    // check exists.
    if !wrapped.verify() {
        return Err(MemError::Crypto);
    }

    // Reject a wrap served from the wrong epoch slot before spending the ECDH;
    // the AAD binding below would also catch it, but this gives the cheap, clear
    // rejection.
    if wrapped.epoch != expected_epoch {
        return Err(MemError::Crypto);
    }

    let recipient_public = PublicKey::from(recipient_secret).to_bytes();
    let shared = recipient_secret.diffie_hellman(&PublicKey::from(wrapped.ephemeral_public));

    // Mirror of the wrap-side contributory check: a bucket-supplied WrappedKey
    // carrying a low-order `ephemeral_public` would force an all-zero shared
    // secret, collapsing the AEAD key to a function of public inputs.
    if !shared.was_contributory() {
        return Err(MemError::Crypto);
    }

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

/// Provision `team_key` at `epoch` to every VERIFIED, MANIFEST-AUTHORIZED
/// member in `member_keys`.
///
/// Wraps the key to each member's x25519 public key and publishes the
/// [`WrappedKey`] under that member's per-epoch object key. A member key that
/// fails [`MemberKey::verify`] is skipped with a warning (never wrapped to), so
/// the team key is never handed to an x25519 key not cryptographically bound to
/// its claimed ss58.
///
/// # Membership authorization
///
/// `verify()` proves an x25519 key is cryptographically bound to its claimed
/// `ss58` — it proves nothing about whether that `ss58` is a CURRENT team
/// member. The untrusted bucket lets anyone with write access plant a
/// self-signed [`MemberKey`] under `{team}/_memberkeys/` for their own
/// address, so `verify()` alone would let a bucket writer get the team key
/// wrapped to them without ever appearing in the founder-signed roster.
/// Authorization instead comes from the [`crate::TeamManifest`]: this function loads
/// the current one ([`load_manifest`], trust-on-genesis — no founder pinned,
/// matching this crate's default when `HIPPIUS_MEM_FOUNDER_SS58`-style pinning
/// is not threaded through) and skips any verified member whose `ss58` is not
/// in `manifest.members`. When no manifest has been published yet, the load
/// returns `None` and every verified member is still provisioned — matching
/// the documented "a team is open until a founder publishes a signed
/// `crate::TeamManifest`" model.
///
/// Returns the addresses that actually RECEIVED a wrap. Skipped members
/// (unverifiable or unauthorized) are absent, so a caller can distinguish "the
/// call succeeded" from "anyone was actually provisioned" — the seam the
/// rotation flow's nothing-to-rotate guard hangs off.
///
/// # Provisioner signature
///
/// `provisioner` signs every wrap this call produces (recorded as
/// [`WrappedKey::provisioner`]/[`WrappedKey::sig`]) — it is the identity
/// PERFORMING the provision (the founder, or whoever the caller trusts to act),
/// never the recipient. This is orthogonal to `expected_founder`: that gates WHO
/// receives a wrap (manifest membership), while `provisioner` proves WHO sealed
/// it. This call signs unconditionally and does not itself check that
/// `provisioner` is authorized — [`fetch_team_key`] is where that cross-check
/// against the live manifest's founder/recovery key happens, on the READ side,
/// once the manifest a bucket-planted wrap must be checked against is knowable.
///
/// # Errors
///
/// Returns [`MemError::Crypto`] if a wrap fails, [`MemError::Serialize`] if a
/// wrap cannot be encoded, or [`MemError::Storage`] if the manifest listing or
/// a wrap write fails.
pub async fn provision_team_key<S: Signer + ?Sized>(
    blob: &dyn BlobStore,
    team: &str,
    team_key: &SecretKey,
    epoch: u64,
    member_keys: &[MemberKey],
    expected_founder: Option<&Ss58>,
    provisioner: &S,
) -> Result<BTreeSet<Ss58>, MemError> {
    // Loaded once, outside the loop: every member is checked against the SAME
    // manifest snapshot, so a manifest published mid-loop cannot admit one
    // member under an old view and another under a new one.
    //
    // `expected_founder` must be the SAME operator pin `MemoryStore::sync` threads
    // into its own `load_manifest`. Provisioning grants READ access (a team-key
    // wrap), so gating it on trust-on-genesis (`None`) while the write path is
    // pinned would let a genesis-overwrite attacker — blocked from writing — still
    // be elected a member here and receive the key. Passing the pin closes that
    // read-seizure; `None` keeps the backward-compatible trust-on-genesis.
    let manifest = load_manifest(blob, team, expected_founder).await?;

    let mut wrapped_to = BTreeSet::new();
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
        // Authorization gate: once a trusted manifest exists, only its signed
        // members may receive a wrap. A key that verifies but is absent is exactly
        // the "planted self-signed MemberKey" forgery this catches — the bucket
        // cannot forge manifest membership the way it can forge an unlisted
        // MemberKey. When NO trusted manifest is found the fallback depends on the
        // pin: an UNPINNED team is genuinely open (every verified key authorized,
        // backward-compatible), but a PINNED team with no founder-signed manifest
        // is fail-closed — an attacker who destroyed or replaced the pin's manifest
        // must not thereby downgrade the team to open and be wrapped the key.
        let authorized = match &manifest {
            Some(manifest) => manifest.members.contains(&member.ss58),
            None => expected_founder.is_none(),
        };
        if !authorized {
            tracing::warn!(
                ss58 = %member.ss58.as_str(),
                team,
                "skipping a verified member key not present in the team manifest"
            );
            continue;
        }
        let wrapped = wrap_team_key(team, team_key, &member.x25519_public, epoch, provisioner)?;
        let key = wrapped_key_key(team, epoch, member.ss58.as_str());
        blob.put(&key, serde_json::to_vec(&wrapped)?).await?;
        wrapped_to.insert(member.ss58.clone());
    }
    Ok(wrapped_to)
}

/// Bootstrap a team key from the bucket: load this member's [`WrappedKey`] for
/// `epoch`, unwrap it, and check that whoever sealed it was AUTHORIZED to.
///
/// This is how a member who was never pre-shared the key obtains it — they only
/// need their own x25519 secret.
///
/// # Provisioner authorization
///
/// [`WrappedKey::verify`] (checked first, inside [`unwrap_team_key`]) proves
/// the wrap was signed by SOME key; it proves nothing about whether that key
/// was ever entitled to provision the team key. The untrusted bucket lets
/// anyone with write access plant a wrap that verifies under their OWN
/// self-consistent signature — every input `wrap_team_key` needs
/// (`recipient_ss58`'s public x25519 key, published under `_memberkeys/`; the
/// epoch; the team name) is public. So after a successful unwrap, this loads
/// the live [`crate::TeamManifest`] the same way [`provision_team_key`] does
/// ([`load_manifest`], honoring `expected_founder` exactly like every other
/// manifest-consuming call in this crate) and requires the wrap's
/// [`WrappedKey::provisioner`] to be either the manifest's `founder_key` or its
/// [`TeamManifest::trusted_recovery_key`] — never the raw `recovery_key` field,
/// which is unvalidated and could name the Ristretto identity point. When no
/// trusted manifest exists yet, the check is skipped (every wrap is accepted):
/// this matches [`provision_team_key`]'s "a team is open until a founder
/// publishes a signed manifest" fallback, so an unpinned, not-yet-founded team
/// behaves exactly as it did before this check existed.
///
/// # Errors
///
/// Returns [`MemError::NotFound`] if no wrap exists for `recipient_ss58` at
/// `epoch` (e.g. a non-member, or a member removed before this epoch),
/// [`MemError::Serialize`] if the stored wrap cannot be decoded,
/// [`MemError::Storage`] for other backend failures, [`MemError::Crypto`] if
/// `recipient_secret` cannot unwrap it, or [`MemError::Unauthorized`] if the
/// wrap unwraps cleanly but its provisioner is neither the live manifest's
/// founder nor its named recovery key.
pub async fn fetch_team_key(
    blob: &dyn BlobStore,
    team: &str,
    epoch: u64,
    recipient_ss58: &Ss58,
    recipient_secret: &StaticSecret,
    expected_founder: Option<&Ss58>,
) -> Result<SecretKey, MemError> {
    let key = wrapped_key_key(team, epoch, recipient_ss58.as_str());
    let bytes = blob.get(&key).await?;
    let wrapped: WrappedKey = serde_json::from_slice(&bytes)?;
    let secret = unwrap_team_key(team, &wrapped, recipient_secret, epoch)?;

    // Loaded AFTER the unwrap succeeds: a wrap that fails to even decrypt is
    // rejected on the cheaper crypto check first, and the manifest fetch below
    // is spent only on a wrap that already proved SOME key sealed it.
    let manifest = load_manifest(blob, team, expected_founder).await?;
    if let Some(manifest) = &manifest {
        let authorized = wrapped.provisioner == manifest.founder_key
            || manifest.trusted_recovery_key() == Some(&wrapped.provisioner);
        if !authorized {
            return Err(MemError::Unauthorized(format!(
                "wrap for team {team:?} epoch {epoch} recipient {:?} was sealed by a provisioner \
                 the current manifest does not authorize (neither its founder nor its named \
                 recovery key)",
                recipient_ss58.as_str(),
            )));
        }
    }

    Ok(secret)
}

/// Rotate the team key: provision `new_team_key` at `new_epoch` for the current
/// members only.
///
/// Removed members are simply absent from `current_member_keys`, so they get no
/// wrap of the new epoch and cannot read notes written under it. Their wraps
/// for older epochs remain, so previously shared notes stay readable — the
/// forward-readable model documented at the module level. Inherits
/// [`provision_team_key`]'s manifest-membership gate: a `current_member_keys`
/// entry not in the current [`crate::TeamManifest`] receives no wrap either, so a
/// caller cannot re-admit a removed member by omitting them from the
/// manifest update but still passing their key here.
///
/// Returns the addresses wrapped the new epoch's key, exactly as
/// [`provision_team_key`] does.
///
/// Prefer [`crate::MemoryStore::rotate_key`] over calling this primitive
/// directly: it layers founder authorization, safe new-epoch selection, and —
/// critically — the write-epoch advance on top, so post-rotation writes
/// actually seal under the new key.
///
/// `provisioner` is threaded straight through to [`provision_team_key`], which
/// signs every wrap of `new_team_key` with it — see that function's docs for
/// what the signature does and does not (yet) prove.
///
/// # Errors
///
/// Same as [`provision_team_key`].
pub async fn rotate_team_key<S: Signer + ?Sized>(
    blob: &dyn BlobStore,
    team: &str,
    new_team_key: &SecretKey,
    new_epoch: u64,
    current_member_keys: &[MemberKey],
    expected_founder: Option<&Ss58>,
    provisioner: &S,
) -> Result<BTreeSet<Ss58>, MemError> {
    provision_team_key(
        blob,
        team,
        new_team_key,
        new_epoch,
        current_member_keys,
        expected_founder,
        provisioner,
    )
    .await
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

/// The object-key prefix under which `team`'s wrapped team keys live, one
/// path segment up from [`wrapped_key_key`]'s per-epoch/per-member leaf.
///
/// Shared by [`wrapped_key_key`] (writes) and [`highest_published_epoch`]
/// (lists) so the two can never disagree about what a wrapped-key object key
/// looks like.
fn wrapped_keys_prefix(team: &str) -> String {
    format!("{team}/_keys/")
}

/// The object key a member's wrapped team key is stored under.
///
/// `{team}/_keys/{epoch:020}/{ss58}`: the epoch is zero-padded to 20 digits
/// (the width of `u64::MAX`) so keys sort by epoch lexicographically.
fn wrapped_key_key(team: &str, epoch: u64, ss58: &str) -> String {
    format!("{}{epoch:020}/{ss58}", wrapped_keys_prefix(team))
}

/// Parse the `{epoch:020}` segment out of an object key listed under
/// [`wrapped_keys_prefix`], the exact inverse of the format [`wrapped_key_key`]
/// writes. `None` for a key that does not match that shape (foreign object
/// under the prefix, or a listing bug) — the caller skips it rather than
/// treating it as epoch 0.
fn parse_epoch_segment(team: &str, object_key: &str) -> Option<u64> {
    let rest = object_key.strip_prefix(&wrapped_keys_prefix(team))?;
    let epoch_str = rest.split('/').next()?;
    epoch_str.parse().ok()
}

/// The highest team-key epoch this team has actually published a wrapped key
/// at, by listing the `_keys/` prefix `wrapped_key_key` writes under. `0`
/// when the team has published nothing (a fresh or pre-provision team).
///
/// This is the on-bucket epoch discovery [`crate::MemoryStore::bootstrap_epoch_keys`]'s
/// docs call out as left to the caller: that method only tries the epochs it is
/// TOLD about, with no way to see what actually exists on the bucket. This gives
/// that visibility — in particular to the stale-`max_epoch` warning: a
/// misconfigured, un-raised `max_epoch` silently hides every note sealed under a
/// rotated epoch past it, so comparing this against the configured `max_epoch`
/// is how that gets caught instead of rediscovered.
///
/// # Errors
///
/// Returns [`MemError::Storage`] if the backend listing fails. A key present
/// under the prefix that does not parse as `{epoch:020}/...` is skipped, not
/// fatal (mirrors [`load_member_keys`]'s tolerance of a foreign object under
/// its own prefix).
pub async fn highest_published_epoch(blob: &dyn BlobStore, team: &str) -> Result<u64, MemError> {
    let prefix = wrapped_keys_prefix(team);
    let keys = blob.list(&prefix).await?;

    Ok(keys
        .iter()
        .filter_map(|key| parse_epoch_segment(team, key))
        .max()
        .unwrap_or(0))
}

/// The object-key prefix under which `team`'s wrapped keys for `epoch`
/// live — one path segment below [`wrapped_keys_prefix`], holding exactly the
/// SS58 leaves [`wrapped_key_key`] writes members under.
fn wrapped_key_epoch_prefix(team: &str, epoch: u64) -> String {
    format!("{}{epoch:020}/", wrapped_keys_prefix(team))
}

/// The SS58 addresses `team` has published a [`WrappedKey`] to at `epoch`, by
/// listing the epoch's `_keys/{epoch:020}/` prefix — the read-side
/// counterpart of what [`provision_team_key`]/[`rotate_team_key`] write under
/// [`wrapped_key_key`].
///
/// This is who can currently DECRYPT `epoch`'s team key, independent of the
/// membership manifest: a member the founder-signed roster no longer lists
/// but whose wrap for `epoch` was never rotated away still appears here — the
/// read-side symptom of the recorded `rotate --members` non-atomicity gotcha
/// (`publish_membership` can land while `rotate_key` then refuses, most often
/// with [`MemError::NothingToRotate`] because no remaining member has
/// published a [`MemberKey`] yet). Comparing this set against the live
/// [`crate::TeamManifest`]'s members at the CURRENT epoch (the one
/// [`highest_published_epoch`] reports) is exactly the check `hippius-mem
/// doctor` runs to catch a half-completed removal that a later run never
/// finished.
///
/// # Errors
///
/// Returns [`MemError::Storage`] if the backend listing fails. An object
/// under the prefix whose leaf does not decode as an SS58 address is
/// skipped, not fatal (mirrors [`load_member_keys`]'s tolerance of a foreign
/// object under its own prefix).
pub async fn wrapped_key_recipients(
    blob: &dyn BlobStore,
    team: &str,
    epoch: u64,
) -> Result<BTreeSet<Ss58>, MemError> {
    let prefix = wrapped_key_epoch_prefix(team, epoch);
    let keys = blob.list(&prefix).await?;

    Ok(keys
        .iter()
        .filter_map(|key| key.strip_prefix(prefix.as_str()))
        .filter_map(|ss58| Ss58::new(ss58).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test, not a crash to avoid"
    )]

    use super::*;
    use crate::TeamManifest;
    use crate::identity::manifest::publish_manifest;
    use crate::identity::{derive_identity, signer_from_mnemonic};
    use crate::oplog::Sr25519Signer;
    use crate::store::MemoryBlobStore;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

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

    /// A cheap, deterministic signer standing in for "the provisioner" in tests
    /// that only need SOME valid signature over a [`WrappedKey`], not a specific
    /// member identity. Built directly from a fixed 32-byte seed (skips the
    /// mnemonic/BIP-39 derivation `signer_from_mnemonic` does), so it is cheap
    /// enough to call once per proptest case.
    #[expect(
        clippy::expect_used,
        reason = "a fixed 32-byte seed cannot fail to produce a valid sr25519 keypair; this \
                  is test-only setup, not a reachable panic path"
    )]
    fn test_provisioner() -> Sr25519Signer {
        Sr25519Signer::from_seed_with_prefix(&[7u8; 32], NetworkPrefix::HIPPIUS)
            .expect("a fixed 32-byte seed always yields a valid sr25519 keypair")
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
            let provisioner = test_provisioner();
            let wrapped = wrap_team_key(TEAM, &team_key, &recipient_public, epoch, &provisioner)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let unwrapped = unwrap_team_key(TEAM, &wrapped, &recipient_secret, epoch)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(unwrapped.expose_bytes(), &key_bytes);
        }
    }

    /// Every X25519 u-coordinate byte encoding that MUST be treated as low
    /// order by `wrap_team_key`/`unwrap_team_key`'s `was_contributory` check.
    ///
    /// # Source and completeness
    ///
    /// This is the industry-standard Curve25519 low-order blacklist shipped by
    /// libsodium (`crypto_scalarmult/curve25519/ref10/x25519_ref10.c`,
    /// `blacklist[]`) and reused by `WireGuard`, Signal, and `Monocypher`. It is
    /// mathematically the COMPLETE set, not just a commonly-cited one:
    /// Curve25519's cofactor is 8, so its order-dividing-8 torsion subgroup is
    /// cyclic of order 8; folding each point together with its negation (the
    /// Montgomery u-coordinate cannot distinguish P from -P) collapses those 8
    /// points to exactly 5 distinct canonical u-coordinates — 0, 1, two
    /// order-8 points, and `p-1` (the order-2 point) — entries 1-5 below.
    /// Because field elements are only required to fit in 255 bits, not to be
    /// `< p = 2^255-19`, values `0..=18` have a SECOND, non-canonical encoding
    /// as `p..=p+18`; of the 5 low-order values, only 0 and 1 are small enough
    /// (`<19`) to fall in that window, giving exactly two extra non-canonical
    /// encodings (`p`, `p+1` — entries 6-7). No other low-order value, and no
    /// non-low-order value, has room for a second in-range encoding, so 7 is
    /// exhaustive.
    ///
    /// Independently confirmed empirically against this crate's pinned
    /// `x25519-dalek 2.0.1`: every entry below drives
    /// `SharedSecret::was_contributory()` to `false` (an all-zero ECDH output)
    /// against four different secret scalars, while a freshly generated key
    /// does not.
    const LOW_ORDER_U_COORDINATES: &[(&str, [u8; 32])] = &[
        ("0 (canonical, order 1)", [0u8; 32]),
        ("1 (canonical, order 1 variant)", {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        }),
        (
            "order-8 point A",
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
        ),
        (
            "order-8 point B",
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
        ),
        (
            "p-1 (canonical, order 2)",
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
        ),
        (
            "p (non-canonical encoding of 0)",
            [
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
        ),
        (
            "p+1 (non-canonical encoding of 1)",
            [
                0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
        ),
    ];

    #[test]
    fn low_order_points_are_refused_on_wrap_and_unwrap() -> Result<(), MemError> {
        // Every low-order u-coordinate is a point x25519 collapses to an
        // all-zero shared secret against ANY clamped scalar, and every other
        // input to the AEAD key derivation is public — a wrap to (or from) one
        // would publish the team key to anyone. Both directions must refuse
        // (was_contributory), with the same detail-free Crypto error as every
        // other crypto refusal, for EVERY entry in the table above.
        let team_key = SecretKey::from_bytes([9u8; 32]);
        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let alice_secret = alice.x25519_secret();
        let alice_public = alice.x25519_public();
        let provisioner = test_provisioner();

        for (label, low_order) in LOW_ORDER_U_COORDINATES {
            // Wrap side: a low-order RECIPIENT point must be refused.
            assert!(
                matches!(
                    wrap_team_key(TEAM, &team_key, low_order, 0, &provisioner),
                    Err(MemError::Crypto)
                ),
                "wrapping to low-order recipient point `{label}` must be refused"
            );

            // Unwrap side: a low-order EPHEMERAL point in a received wrap must
            // be refused. The ciphertext is a GENUINE seal under the exact AEAD
            // key this low-order ECDH produces (not a garbage placeholder), and
            // the forged wrap carries a GENUINE provisioner signature over its
            // own (low-order) fields, so `WrappedKey::verify` passes and
            // rejection is attributable to the `was_contributory` check itself
            // — an unsigned wrap, or a bogus ciphertext, would "pass" this
            // assertion for the wrong reason, exactly the unattributable-
            // rejection trap this table must not fall into.
            let shared = alice_secret.diffie_hellman(&PublicKey::from(*low_order));
            let aead_key = derive_aead_key(shared.as_bytes(), low_order, &alice_public);
            let aad = wrap_aad(TEAM, 0, low_order, &alice_public);
            let ciphertext = crypto::seal(&aead_key, team_key.expose_bytes(), &aad)?;
            let mut forged = WrappedKey {
                epoch: 0,
                ephemeral_public: *low_order,
                ciphertext,
                provisioner: provisioner.verifying_key(),
                // Placeholder: `signing_bytes` excludes `sig`, so this value does
                // not affect the message that gets signed below.
                sig: Signature::new([0u8; 64]),
            };
            forged.sig = provisioner.sign(&forged.signing_bytes());
            assert!(
                forged.verify(),
                "the forged wrap must itself carry a genuine signature, or the \
                 rejection below would be attributable to `verify` instead of \
                 `was_contributory`"
            );
            assert!(
                matches!(
                    unwrap_team_key(TEAM, &forged, &alice_secret, 0),
                    Err(MemError::Crypto)
                ),
                "unwrapping against low-order ephemeral point `{label}` must be refused"
            );
        }

        // Positive control, same call shape as the loop above: a genuinely
        // valid recipient/ephemeral point must wrap and unwrap successfully.
        // Without this, "some rejection happened" for every table entry would
        // not distinguish the low-order check from a guard that rejects
        // everything.
        let wrapped = wrap_team_key(TEAM, &team_key, &alice_public, 0, &provisioner)?;
        assert_eq!(
            unwrap_team_key(TEAM, &wrapped, &alice_secret, 0)?.expose_bytes(),
            team_key.expose_bytes(),
            "a genuine recipient/ephemeral point must wrap and unwrap successfully"
        );

        Ok(())
    }

    #[test]
    fn non_recipient_cannot_unwrap() -> Result<(), MemError> {
        let team_key = SecretKey::from_bytes([7u8; 32]);
        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let mallory = derive_identity(PHRASE_B, NetworkPrefix::HIPPIUS)?;
        let provisioner = test_provisioner();
        let wrapped = wrap_team_key(TEAM, &team_key, &alice.x25519_public(), 0, &provisioner)?;

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
        let provisioner = test_provisioner();
        let mut wrapped = wrap_team_key(TEAM, &team_key, &alice.x25519_public(), 0, &provisioner)?;
        let last = wrapped.ciphertext.len() - 1;
        wrapped.ciphertext[last] ^= 0x01;
        assert!(matches!(
            unwrap_team_key(TEAM, &wrapped, &alice.x25519_secret(), 0),
            Err(MemError::Crypto)
        ));
        Ok(())
    }

    #[test]
    fn signed_wrap_round_trips_and_rejects_a_forge() -> Result<(), MemError> {
        let team = "acme";
        let team_key = SecretKey::from_bytes([7u8; 32]);
        let provisioner = test_provisioner();
        let recipient = StaticSecret::from([9u8; 32]);
        let recipient_pub = PublicKey::from(&recipient).to_bytes();

        let wrap = wrap_team_key(team, &team_key, &recipient_pub, 3, &provisioner)?;
        assert!(wrap.verify(), "a freshly signed wrap verifies");
        let opened = unwrap_team_key(team, &wrap, &recipient, 3)?;
        assert_eq!(opened.expose_bytes(), team_key.expose_bytes());

        // The review's forge: an attacker who knows `recipient_pub` crafts a wrap
        // with an arbitrary key and NO valid provisioner signature.
        let mut forged = wrap.clone();
        forged.sig = Signature::new([0u8; 64]);
        assert!(
            !forged.verify(),
            "an unsigned/garbage-sig wrap fails verify"
        );
        assert!(
            unwrap_team_key(team, &forged, &recipient, 3).is_err(),
            "unwrap must reject a wrap that fails signature verification"
        );
        Ok(())
    }

    #[test]
    fn tampering_wrap_fields_breaks_the_signature() -> Result<(), MemError> {
        let team = "acme";
        let team_key = SecretKey::from_bytes([1u8; 32]);
        let provisioner = test_provisioner();
        let recipient_pub = PublicKey::from(&StaticSecret::from([2u8; 32])).to_bytes();
        let mut wrap = wrap_team_key(team, &team_key, &recipient_pub, 5, &provisioner)?;

        wrap.epoch = 6; // any signed field
        assert!(
            !wrap.verify(),
            "mutating a signed field invalidates the signature"
        );
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
        let provisioner = test_provisioner();
        let epoch0_wrap = wrap_team_key(TEAM, &team_key, &alice.x25519_public(), 0, &provisioner)?;

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
        let provisioner = test_provisioner();
        let team_a_wrap =
            wrap_team_key("team-a", &team_key, &alice.x25519_public(), 0, &provisioner)?;

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

    #[test]
    fn memberkey_signature_does_not_verify_under_op_or_manifest_tag() -> Result<(), MemError> {
        // Mirrors oplog::op::cross_type_signature_does_not_verify, which
        // exercises the op tag against the manifest tag but never
        // MEMBERKEY_DOMAIN against either sibling -- the gap D7 closes. All
        // three signed types share one sr25519 signing context
        // (SIGNING_CONTEXT in oplog/op.rs); cross-type non-interchangeability
        // rests entirely on each type prefixing a unique domain tag onto its
        // signed bytes, so a signature over member-key-tagged bytes must not
        // verify under the op or manifest tag for the identical payload.
        let signer = signer_from_mnemonic(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let payload = b"shared-body-bytes";
        let memberkey_tagged = [MEMBERKEY_DOMAIN, payload].concat();
        let op_tagged = [b"hippius-memory-op/v2".as_slice(), payload].concat();
        let manifest_tagged = [b"hippius-memory-manifest/v1".as_slice(), payload].concat();

        let sig = signer.sign(&memberkey_tagged);
        assert!(
            verify(&signer.verifying_key(), &memberkey_tagged, &sig),
            "the member-key-tagged message verifies under its own bytes"
        );
        assert!(
            !verify(&signer.verifying_key(), &op_tagged, &sig),
            "a member-key signature must not verify over an op-tagged message"
        );
        assert!(
            !verify(&signer.verifying_key(), &manifest_tagged, &sig),
            "a member-key signature must not verify over a manifest-tagged message"
        );
        Ok(())
    }

    #[test]
    fn wrap_sign_signature_does_not_verify_under_memberkey_op_or_manifest_tag()
    -> Result<(), MemError> {
        // Same defense-in-depth as
        // `memberkey_signature_does_not_verify_under_op_or_manifest_tag`, extended
        // to the newest signed type: `WRAP_SIGN_DOMAIN` must be just as exclusive
        // as every sibling domain tag, or a signature minted for one signed type
        // could be replayed as if it were another.
        let signer = signer_from_mnemonic(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let payload = b"shared-body-bytes";
        let wrap_tagged = [WRAP_SIGN_DOMAIN, payload].concat();
        let memberkey_tagged = [MEMBERKEY_DOMAIN, payload].concat();
        let op_tagged = [b"hippius-memory-op/v2".as_slice(), payload].concat();
        let manifest_tagged = [b"hippius-memory-manifest/v1".as_slice(), payload].concat();

        let sig = signer.sign(&wrap_tagged);
        assert!(
            verify(&signer.verifying_key(), &wrap_tagged, &sig),
            "the wrap-tagged message verifies under its own bytes"
        );
        assert!(
            !verify(&signer.verifying_key(), &memberkey_tagged, &sig),
            "a wrap signature must not verify over a member-key-tagged message"
        );
        assert!(
            !verify(&signer.verifying_key(), &op_tagged, &sig),
            "a wrap signature must not verify over an op-tagged message"
        );
        assert!(
            !verify(&signer.verifying_key(), &manifest_tagged, &sig),
            "a wrap signature must not verify over a manifest-tagged message"
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
        let provisioner = test_provisioner();
        let good = member_key_for(PHRASE_A)?;
        let mut forged = member_key_for(PHRASE_B)?;
        forged.x25519_public[0] ^= 0x01; // breaks the signature binding
        assert!(
            !forged.verify(),
            "the tampered member key fails verification"
        );

        provision_team_key(
            &blob,
            TEAM,
            &team_key,
            0,
            &[good.clone(), forged.clone()],
            None,
            &provisioner,
        )
        .await?;

        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        assert!(
            fetch_team_key(&blob, TEAM, 0, &good.ss58, &alice.x25519_secret(), None)
                .await
                .is_ok(),
            "the verified member received a wrap"
        );
        let bob_id = derive_identity(PHRASE_B, NetworkPrefix::HIPPIUS)?;
        assert!(
            matches!(
                fetch_team_key(&blob, TEAM, 0, &forged.ss58, &bob_id.x25519_secret(), None).await,
                Err(MemError::NotFound { .. })
            ),
            "no wrap was written for the unverifiable member"
        );
        Ok(())
    }

    #[tokio::test]
    async fn provision_skips_a_verified_member_not_in_the_manifest() -> Result<(), MemError> {
        // The auth-boundary regression this closes: `MemberKey::verify` proves
        // an x25519 key is bound to its claimed ss58, NOT that the ss58 is an
        // authorized team member — a bucket writer can plant a self-signed
        // MemberKey for any address under `{team}/_memberkeys/`. Once a
        // founder-signed manifest exists, a verified-but-unlisted key must get
        // no wrap, while a manifest member still does.
        let blob = MemoryBlobStore::new();
        let team_key = SecretKey::from_bytes([8u8; 32]);

        // Alice is the founder (create_signed always inserts the signer as a
        // member); the manifest names no one else, so Charlie is a verified
        // but unauthorized outsider despite a perfectly valid self-signed key.
        let founder_signer = signer_from_mnemonic(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let manifest =
            TeamManifest::create_signed(&founder_signer, TEAM.to_owned(), BTreeSet::new(), 0);
        publish_manifest(&blob, &manifest).await?;

        let key_alice = member_key_for(PHRASE_A)?;
        let key_charlie = member_key_for(PHRASE_C)?;
        assert!(key_charlie.verify(), "Charlie's self-signed key is valid");

        provision_team_key(
            &blob,
            TEAM,
            &team_key,
            0,
            &[key_alice.clone(), key_charlie.clone()],
            None,
            &founder_signer,
        )
        .await?;

        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        assert!(
            fetch_team_key(
                &blob,
                TEAM,
                0,
                &key_alice.ss58,
                &alice.x25519_secret(),
                None
            )
            .await
            .is_ok(),
            "the founder, a manifest member, received a wrap"
        );

        let charlie = derive_identity(PHRASE_C, NetworkPrefix::HIPPIUS)?;
        assert!(
            matches!(
                fetch_team_key(
                    &blob,
                    TEAM,
                    0,
                    &key_charlie.ss58,
                    &charlie.x25519_secret(),
                    None
                )
                .await,
                Err(MemError::NotFound { .. })
            ),
            "a verified key outside the manifest must not receive a wrap"
        );
        Ok(())
    }

    #[tokio::test]
    async fn provision_with_a_pinned_founder_fails_closed_without_that_founders_manifest()
    -> Result<(), MemError> {
        // Threading the operator's founder pin (the same one `MemoryStore::sync`
        // uses) makes provisioning a READ-authz gate. With a pin set but no manifest
        // signed by that founder — e.g. an attacker destroyed or replaced it — no
        // verified key is wrapped the team key, so a bucket writer cannot downgrade
        // the team to "open" and receive it. Unpinned, that same no-manifest state
        // is the genuinely-open team and every verified key is provisioned.
        let blob = MemoryBlobStore::new();
        let team_key = SecretKey::from_bytes([9u8; 32]);
        let provisioner = test_provisioner();
        let founder = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let key_alice = member_key_for(PHRASE_A)?;

        provision_team_key(
            &blob,
            TEAM,
            &team_key,
            0,
            std::slice::from_ref(&key_alice),
            Some(&founder.ss58),
            &provisioner,
        )
        .await?;
        assert!(
            matches!(
                fetch_team_key(
                    &blob,
                    TEAM,
                    0,
                    &key_alice.ss58,
                    &founder.x25519_secret(),
                    None
                )
                .await,
                Err(MemError::NotFound { .. })
            ),
            "a pinned founder with no trusted manifest wraps to no one (fail-closed)"
        );

        provision_team_key(
            &blob,
            TEAM,
            &team_key,
            0,
            std::slice::from_ref(&key_alice),
            None,
            &provisioner,
        )
        .await?;
        assert!(
            fetch_team_key(
                &blob,
                TEAM,
                0,
                &key_alice.ss58,
                &founder.x25519_secret(),
                None
            )
            .await
            .is_ok(),
            "unpinned, the open-team fallback still provisions a verified key"
        );
        Ok(())
    }

    #[tokio::test]
    async fn provision_then_fetch() -> Result<(), MemError> {
        let blob = MemoryBlobStore::new();
        let team_key = SecretKey::from_bytes([1u8; 32]);
        let provisioner = test_provisioner();
        let key_alice = member_key_for(PHRASE_A)?;
        let key_bob = member_key_for(PHRASE_B)?;
        provision_team_key(
            &blob,
            TEAM,
            &team_key,
            0,
            &[key_alice.clone(), key_bob.clone()],
            None,
            &provisioner,
        )
        .await?;

        let alice = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let fetched = fetch_team_key(
            &blob,
            TEAM,
            0,
            &key_alice.ss58,
            &alice.x25519_secret(),
            None,
        )
        .await?;
        assert_eq!(fetched.expose_bytes(), &[1u8; 32]);

        // Charlie was never provisioned: there is no wrap to fetch.
        let charlie = derive_identity(PHRASE_C, NetworkPrefix::HIPPIUS)?;
        let charlie_ss58 = charlie.ss58.clone();
        let missing = fetch_team_key(
            &blob,
            TEAM,
            0,
            &charlie_ss58,
            &charlie.x25519_secret(),
            None,
        )
        .await;
        assert!(matches!(missing, Err(MemError::NotFound { .. })));
        Ok(())
    }

    #[tokio::test]
    async fn fetch_rejects_a_wrap_from_an_unauthorized_provisioner() -> Result<(), MemError> {
        // Founder A publishes a manifest naming Victim as a member.
        // `WrappedKey::verify` (Task 2) proves SOME key signed a wrap — it says
        // nothing about whether that key was ever entitled to. An ATTACKER key
        // (`test_provisioner`, a self-consistent signer that is neither the
        // manifest's founder nor its named recovery key) wraps the team key to
        // Victim using only PUBLIC inputs (Victim's published x25519 key, the
        // team name, the epoch) — exactly what a bucket writer with write access
        // could reconstruct without ever holding the founder's key.
        // `provision_team_key` signs unconditionally and does not itself check
        // the provisioner's identity (see its "Provisioner signature" docs), so
        // this call is a faithful stand-in for a bucket-planted wrap, not a
        // shortcut around the attack. `fetch_team_key` must refuse the result.
        let blob = MemoryBlobStore::new();
        let team_key = SecretKey::from_bytes([4u8; 32]);
        let founder_signer = signer_from_mnemonic(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let victim = member_key_for(PHRASE_B)?;
        let victim_identity = derive_identity(PHRASE_B, NetworkPrefix::HIPPIUS)?;
        let attacker = test_provisioner();

        let manifest = TeamManifest::create_signed(
            &founder_signer,
            TEAM.to_owned(),
            BTreeSet::from([victim.ss58.clone()]),
            0,
        );
        publish_manifest(&blob, &manifest).await?;

        provision_team_key(
            &blob,
            TEAM,
            &team_key,
            0,
            std::slice::from_ref(&victim),
            None,
            &attacker,
        )
        .await?;

        let result = fetch_team_key(
            &blob,
            TEAM,
            0,
            &victim.ss58,
            &victim_identity.x25519_secret(),
            None,
        )
        .await;
        assert!(
            matches!(result, Err(MemError::Unauthorized(_))),
            "a wrap signed by a provisioner the manifest does not authorize must be refused, \
             got {result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn fetch_accepts_a_wrap_from_the_recovery_key() -> Result<(), MemError> {
        // The manifest names recovery key R (v2). A wrap PROVISIONED BY R for
        // Victim both verifies (Task 2) AND is authorized (this task) — the
        // check that keeps `recover` working: once a founder key is lost and a
        // recovery key takes over, wraps IT provisions must still be fetchable.
        let blob = MemoryBlobStore::new();
        let team_key = SecretKey::from_bytes([5u8; 32]);
        let founder_signer = signer_from_mnemonic(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let recovery_signer = signer_from_mnemonic(PHRASE_C, NetworkPrefix::HIPPIUS)?;
        let victim = member_key_for(PHRASE_B)?;
        let victim_identity = derive_identity(PHRASE_B, NetworkPrefix::HIPPIUS)?;

        let manifest = TeamManifest::create_signed_with_recovery(
            &founder_signer,
            TEAM.to_owned(),
            BTreeSet::from([victim.ss58.clone()]),
            0,
            Some(recovery_signer.verifying_key()),
        );
        publish_manifest(&blob, &manifest).await?;

        provision_team_key(
            &blob,
            TEAM,
            &team_key,
            0,
            std::slice::from_ref(&victim),
            None,
            &recovery_signer,
        )
        .await?;

        let fetched = fetch_team_key(
            &blob,
            TEAM,
            0,
            &victim.ss58,
            &victim_identity.x25519_secret(),
            None,
        )
        .await?;
        assert_eq!(fetched.expose_bytes(), &[5u8; 32]);
        Ok(())
    }

    #[tokio::test]
    async fn rotate_excludes_removed_member() -> Result<(), MemError> {
        let blob = MemoryBlobStore::new();
        let key_epoch0 = SecretKey::from_bytes([1u8; 32]);
        let key_epoch1 = SecretKey::from_bytes([2u8; 32]);
        let provisioner = test_provisioner();
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
            None,
            &provisioner,
        )
        .await?;
        // Rotate to epoch 1 for Alice only — Bob is removed.
        rotate_team_key(
            &blob,
            TEAM,
            &key_epoch1,
            1,
            std::slice::from_ref(&key_alice),
            None,
            &provisioner,
        )
        .await?;

        // Alice reads the new epoch.
        let alice_new = fetch_team_key(
            &blob,
            TEAM,
            1,
            &key_alice.ss58,
            &alice.x25519_secret(),
            None,
        )
        .await?;
        assert_eq!(alice_new.expose_bytes(), &[2u8; 32]);

        // Bob has no wrap for epoch 1...
        let bob_new =
            fetch_team_key(&blob, TEAM, 1, &key_bob.ss58, &bob_id.x25519_secret(), None).await;
        assert!(matches!(bob_new, Err(MemError::NotFound { .. })));

        // ...but can still read epoch 0 (forward-readable).
        let bob_old =
            fetch_team_key(&blob, TEAM, 0, &key_bob.ss58, &bob_id.x25519_secret(), None).await?;
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

    #[test]
    fn derive_cache_key_does_not_collide_with_derive_aead_key_on_the_same_input() {
        // The load-bearing half of derive_cache_key's domain-separation claim
        // (crypto.rs: "cryptographically independent of every other use of the
        // team key"); the trivial half (differs from its own input,
        // deterministic) is pinned separately in crypto.rs purely as
        // documentation and cannot fail for an interesting reason.
        //
        // This is the actual claim under test: feed the IDENTICAL 32 bytes
        // into derive_cache_key and into derive_aead_key -- grep-verified to
        // be the only OTHER function in this crate that takes a bare 32-byte
        // secret plus a domain tag and produces a new 32-byte secret (`fn
        // .*SecretKey` across hippius-mem-core/hippius-mem finds exactly one
        // `&SecretKey -> SecretKey` function, derive_cache_key itself; `fn
        // .*-> SecretKey` more broadly finds only derive_aead_key alongside
        // it) -- and confirm they do not collide even on a shared input.
        let shared_bytes = [77u8; 32];
        let cache_key = crypto::derive_cache_key(&SecretKey::from_bytes(shared_bytes));
        let aead_key = derive_aead_key(&shared_bytes, &[1u8; 32], &[2u8; 32]);

        assert_ne!(cache_key.expose_bytes(), aead_key.expose_bytes());
    }

    #[test]
    fn x25519_secret_is_not_a_trivial_transform_of_the_sr25519_seed() -> Result<(), MemError> {
        // What this establishes, and what it explicitly does NOT: non-derivability
        // of one secret from another is not a property any finite test can
        // prove, so this does NOT establish that x25519_secret is
        // cryptographically independent of the sr25519 seed -- that headline
        // claim (module docs: "cryptographically independent -- compromising
        // one does not yield the other") rests on the KDF's domain separation
        // and Blake2b512's preimage resistance, neither of which a test can
        // exercise directly. What this DOES establish: the derived secret does
        // not equal four specific, nameable relations to the seed that a
        // reviewer might plausibly suspect from a copy-paste or off-by-one
        // bug -- the seed verbatim (identity), the seed byte-reversed, the
        // seed XORed with a fixed constant, and the seed's first half
        // zero-padded back to 32 bytes (standing in for "someone truncated the
        // seed instead of hashing it").
        let identity = derive_identity(PHRASE_A, NetworkPrefix::HIPPIUS)?;
        let seed = *identity.sr25519_seed;
        let x25519_bytes = identity.x25519_secret().to_bytes();

        assert_ne!(
            x25519_bytes, seed,
            "identity: must not equal the sr25519 seed verbatim"
        );

        let mut reversed = seed;
        reversed.reverse();
        assert_ne!(
            x25519_bytes, reversed,
            "reversal: must not equal the byte-reversed seed"
        );

        let mut xored = seed;
        for byte in &mut xored {
            *byte ^= 0xFF;
        }
        assert_ne!(
            x25519_bytes, xored,
            "XOR: must not equal the seed XORed with the constant 0xFF"
        );

        let mut truncated = [0u8; 32];
        truncated[..16].copy_from_slice(&seed[..16]);
        assert_ne!(
            x25519_bytes, truncated,
            "truncation: must not equal the seed's first half, zero-padded to 32 bytes"
        );

        Ok(())
    }

    /// Build an [`Identity`] carrying an arbitrary 32-byte sr25519 seed, for
    /// probing [`Identity::x25519_secret`]'s dependence on that seed directly
    /// rather than through a mnemonic. `ss58`/`verifying_key` are filled from
    /// a cheap, non-cryptographic encoding and are irrelevant to the property
    /// under test: `x25519_secret` reads only `sr25519_seed`.
    fn identity_with_seed(seed: [u8; 32]) -> Identity {
        let verifying_key = VerifyingKey::new([0u8; 32]);
        let ss58 = super::super::ss58_encode(&verifying_key, NetworkPrefix::HIPPIUS);
        Identity {
            ss58,
            verifying_key,
            sr25519_seed: Zeroizing::new(seed),
        }
    }

    proptest! {
        /// x25519_secret's dependence on the sr25519 seed does not degenerate
        /// into a near-identity or otherwise localized relationship: flipping
        /// a single seed bit changes a large fraction of the derived x25519
        /// secret's bits.
        ///
        /// This is NOT an avalanche/PRF proof and does NOT establish
        /// cryptographic independence: it is one bit-difference measurement
        /// per sampled seed pair against a KDF this crate did not design
        /// (Blake2b512), not a statistical claim over the whole 2^256 input
        /// space. What a large observed difference rules out is a derivation
        /// that is linear, a fixed permutation, or otherwise leaves most bits
        /// fixed or correlated for a single flipped input bit.
        ///
        /// The threshold: 80 of 256 bits (31.25%) against the Binomial(256, 0.5)
        /// an input-INDEPENDENT output would follow by chance (mean 128, sd 8).
        ///
        /// The bound is chosen from the probability of a spurious failure across
        /// the WHOLE test, not across one sampled pair -- proptest draws 256 cases
        /// per run, so the per-draw tail has to be multiplied out. It previously
        /// sat at 96, whose per-draw tail is 3.8e-5; over 256 draws that is a
        /// 9.7e-3 chance of a red run, i.e. a spurious failure roughly every 103
        /// runs, and one duly occurred. Reasoning about a single draw and then
        /// sampling 256 times is the mistake, not the arithmetic.
        ///
        /// At 80 the exact tail is P(X <= 80) = 9.4e-10, so the union over 256
        /// draws is 2.4e-7 -- about one spurious failure per four million runs.
        ///
        /// What that costs, stated rather than waved at. The measured control --
        /// bypassing the KDF so the secret IS the seed, giving 1 differing bit of
        /// 256 -- is one EXTREME point, not the boundary, so it says nothing about
        /// where discrimination actually ends. Model a PARTIALLY degenerate
        /// derivation as one leaving k of the 32 secret bytes constant, which makes
        /// the difference Binomial(256 - 8k, 0.5). At k = 4 (mean 112) the old
        /// bound caught it on ~99.3% of runs and this one catches it on ~0.3%; at
        /// k = 8 (a QUARTER of the output fixed, mean 96) this bound is back to
        /// ~96%. So the 96-128 band is out of reach for THIS test, and the claim it
        /// supports is exactly the one its scope sentence above makes and no more:
        /// it rules out a derivation leaving MOST bits fixed or correlated. A
        /// derivation freezing an eighth of the output would pass here.
        ///
        /// That band is NARROWED -- not closed -- by
        /// `adjacent_seed_avalanche_averages_near_half_over_many_pairs` below,
        /// which asserts on the MEAN across a fixed sample instead of on each pair,
        /// because the mean's spread shrinks with the sample size while a per-pair
        /// bound must widen to keep the union tail small. See that test for what it
        /// reaches and what it still does not.
        #[test]
        fn adjacent_seeds_do_not_yield_near_identical_x25519_keys(
            seed in proptest::array::uniform32(any::<u8>()),
            bit_index in 0u32..256,
        ) {
            let mut flipped = seed;
            flipped[(bit_index / 8) as usize] ^= 1u8 << (bit_index % 8);

            let secret_a = identity_with_seed(seed).x25519_secret().to_bytes();
            let secret_b = identity_with_seed(flipped).x25519_secret().to_bytes();

            let differing_bits: u32 = secret_a
                .iter()
                .zip(secret_b.iter())
                .map(|(a, b)| (a ^ b).count_ones())
                .sum();

            prop_assert!(
                differing_bits > 80,
                "seeds one bit apart produced x25519 secrets differing in only {differing_bits}/256 bits"
            );
        }
    }

    /// The band the per-pair bound above cannot reach, NARROWED by averaging.
    ///
    /// Narrowed, not closed, and the residual is named below. A per-PAIR bound has
    /// to sit far enough out that 256 draws essentially never trip it, which is what
    /// forces it down to 80 and leaves a partially degenerate derivation (mean
    /// anywhere in 96..128) passing. Averaging does not have that problem: the
    /// spread of a mean SHRINKS with the sample size instead of the tail widening.
    ///
    /// # The null model is a DESIGN-TIME argument, not a run-time probability
    ///
    /// State this plainly, because the previous bound was mis-derived by blurring
    /// the two. This test is DETERMINISTIC: fixed seeds (`content_hash(i)`), a fixed
    /// flipped-bit walk, one fixed sample. There is no run-to-run chance at all, and
    /// that is precisely what removes the flake the proptest above had. "Unreachable
    /// by chance" below describes a HYPOTHETICAL resample under the
    /// input-independent null -- it is how the bound was chosen, not a claim about
    /// what this test does when it runs. What it does when it runs is recompute the
    /// same number and compare it.
    ///
    /// # Choosing the bound, and what it reaches
    ///
    /// Under that null the total over 256 pairs is Binomial(65536, 0.5): mean 32768,
    /// sd 128 (equivalently a per-pair mean of 128 with sample-mean sd 0.5). A floor
    /// of 126 puts the threshold at 32256, four sd below that null mean. Model a
    /// partially degenerate derivation as one freezing k of the 32 secret bytes,
    /// giving a per-pair mean of 128 - 4k: k = 1 (mean 124) has a total mean of
    /// 31744 with sd 126, so the same threshold sits 4.1 sd ABOVE it and catches it.
    /// The measured total for the real derivation is 32863 (mean 128.371, per-pair
    /// range 109..149), clearing the threshold by 607 -- 4.8 sd of natural spread.
    ///
    /// # The residual, named
    ///
    /// A previous floor of 120 did NOT catch k = 1: its mean of 124 passed both this
    /// test and the proptest, so a derivation freezing a whole secret byte was
    /// invisible to the entire suite. At 126 it is caught. What remains out of reach
    /// is a mean in roughly 125..128 -- a derivation freezing fewer than about eight
    /// bits of the output. That band is not closable by moving this floor further
    /// up: it would run into the natural spread of the real sample (already only 4.8
    /// sd away) and start failing on an honest KDF. Closing it needs more pairs, not
    /// a higher bound.
    ///
    /// Deliberately NOT a proptest: the point is a fixed, adequately sized sample
    /// whose statistics are known, so it takes deterministic seeds rather than a
    /// generator, and needs no shrinking. It is still not a PRF proof -- see the
    /// scope sentence on the proptest above, which applies here unchanged.
    #[test]
    fn adjacent_seed_avalanche_averages_near_half_over_many_pairs() {
        const PAIRS: u32 = 256;
        /// The per-pair mean the sample must exceed. Compared against the TOTAL
        /// below, never against `total / PAIRS`: that division truncates, so the
        /// previous `mean > 120` form actually enforced a true mean of 121 or more.
        /// A bound whose effective value is one higher than the constant naming it
        /// is exactly the kind of quiet discrepancy this test exists to avoid.
        const MEAN_FLOOR: u32 = 126;

        let mut total_differing = 0u32;

        for i in 0..PAIRS {
            let seed: [u8; 32] = *crate::crypto::content_hash(&i.to_le_bytes()).as_bytes();

            // Walk the flipped bit across the whole 256-bit input as i advances, so
            // the sample is not concentrated on one byte of the seed.
            let bit = (i % 256) as usize;
            let mut flipped = seed;
            flipped[bit / 8] ^= 1u8 << (bit % 8);

            let secret_a = identity_with_seed(seed).x25519_secret().to_bytes();
            let secret_b = identity_with_seed(flipped).x25519_secret().to_bytes();

            total_differing += secret_a
                .iter()
                .zip(secret_b.iter())
                .map(|(a, b)| (a ^ b).count_ones())
                .sum::<u32>();
        }

        let mean = f64::from(total_differing) / f64::from(PAIRS);
        assert!(
            total_differing > MEAN_FLOOR * PAIRS,
            "over {PAIRS} adjacent-seed pairs the x25519 secrets differed in a mean of \
             {mean:.3}/256 bits ({total_differing} total, floor {floor}); an \
             input-independent derivation totals 32768 with sd 128, so a total at or below \
             the floor means the derivation leaves a large fraction of the output \
             correlated with its input",
            floor = MEAN_FLOOR * PAIRS,
        );
    }

    #[tokio::test]
    async fn highest_published_epoch_reads_the_epoch_objects() -> Result<(), MemError> {
        let blob = MemoryBlobStore::new();

        // A team with no wrapped-key objects at all has published nothing.
        assert_eq!(
            highest_published_epoch(&blob, TEAM).await?,
            0,
            "an empty store reports epoch 0"
        );

        // Publish wrapped keys for epochs 0, 1, 2 via the existing teamkey
        // publish path (`provision_team_key`), exactly how a real rotation
        // populates the `_keys/` prefix.
        let member = member_key_for(PHRASE_A)?;
        let provisioner = test_provisioner();
        for epoch in 0..=2u64 {
            let team_key = SecretKey::from_bytes([u8::try_from(epoch).unwrap_or(0); 32]);
            provision_team_key(
                &blob,
                TEAM,
                &team_key,
                epoch,
                std::slice::from_ref(&member),
                None,
                &provisioner,
            )
            .await?;
        }

        assert_eq!(
            highest_published_epoch(&blob, TEAM).await?,
            2,
            "the highest epoch actually published on the bucket must be reported"
        );
        Ok(())
    }

    #[tokio::test]
    async fn wrapped_key_recipients_reads_the_epoch_objects() -> Result<(), MemError> {
        let blob = MemoryBlobStore::new();

        // No wraps at all: the epoch has no recipients.
        assert!(
            wrapped_key_recipients(&blob, TEAM, 0).await?.is_empty(),
            "an empty store reports no recipients"
        );

        let alice = member_key_for(PHRASE_A)?;
        let bob_key = member_key_for(PHRASE_B)?;
        let team_key_0 = SecretKey::from_bytes([1u8; 32]);
        let team_key_1 = SecretKey::from_bytes([2u8; 32]);
        let provisioner = test_provisioner();
        provision_team_key(
            &blob,
            TEAM,
            &team_key_0,
            0,
            &[alice.clone(), bob_key.clone()],
            None,
            &provisioner,
        )
        .await?;
        // Epoch 1 is rotated to Alice only — Bob is excluded from it.
        provision_team_key(
            &blob,
            TEAM,
            &team_key_1,
            1,
            std::slice::from_ref(&alice),
            None,
            &provisioner,
        )
        .await?;

        let epoch0 = wrapped_key_recipients(&blob, TEAM, 0).await?;
        assert_eq!(
            epoch0,
            BTreeSet::from([alice.ss58.clone(), bob_key.ss58.clone()]),
            "epoch 0 was wrapped to both members"
        );

        let epoch1 = wrapped_key_recipients(&blob, TEAM, 1).await?;
        assert_eq!(
            epoch1,
            BTreeSet::from([alice.ss58.clone()]),
            "epoch 1 was wrapped to Alice only; Bob's epoch-0 wrap must not leak in"
        );
        Ok(())
    }
}
