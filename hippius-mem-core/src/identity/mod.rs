//! Cryptographic identity primitives: BIP-39 mnemonic derivation and the
//! Substrate SS58 address codec.
//!
//! # Derivation scheme
//!
//! One mnemonic yields one sr25519 account, matching `subxt_signer` /
//! `sp_core` (verified against `subxt_signer::sr25519::Keypair::from_phrase`):
//!
//! 1. Parse the BIP-39 mnemonic and take its **entropy** (not the standard
//!    BIP-39 seed) — Substrate keys differ from generic BIP-39 wallets here.
//! 2. `seed = PBKDF2-HMAC-SHA512(password = entropy, salt = b"mnemonic", 2048
//!    rounds, 64 bytes)`; the sr25519 mini-secret is `seed[..32]`. This is the
//!    `substrate-bip39 seed_from_entropy` algorithm.
//! 3. Expand the mini-secret with [`schnorrkel::ExpansionMode::Ed25519`] (the
//!    Substrate convention, mirrored by [`crate::oplog::Sr25519Signer`]).
//!
//! Hippius mnemonics carry no BIP-39 passphrase, matching the desktop's
//! `from_phrase(&mnemonic, None)`; the password is fixed to empty.
//!
//! # SS58 address format
//!
//! `base58( prefix ++ pubkey(32) ++ checksum(2) )` where the checksum is the
//! first two bytes of `blake2b_512(b"SS58PRE" ++ prefix ++ pubkey)`. The prefix
//! is a SCALE-style varint: one byte for idents `0..=63`, two bytes (the
//! `0b01xxxxxx` form) for `64..=16383`. Verified against Substrate's
//! `Ss58Codec` and the canonical `//Alice` vector. Hippius uses prefix **42**
//! (generic Substrate / Bittensor), matching `hcfs` and the desktop.

mod console;
mod manifest;
mod marker;
mod teamkey;

// The plain wire types and `S3Creds` compile unconditionally so CI pins the
// api.hippius.com contract even without the `console` feature; the HTTP client
// and ETH-key derivation need reqwest/alloy and so are feature-gated.
pub use console::{
    ChallengeResp, DEFAULT_CONSOLE_BASE_URL, MnemonicChallengeReq, S3Creds, SessionData,
    SubTokenReq, SubTokenResp, VerifyReq, VerifyResp,
};
#[cfg(feature = "console")]
pub use console::{ConsoleClient, eth_signer_from_mnemonic};
pub use manifest::{TeamManifest, load_manifest, publish_manifest};
// Crate-internal, NOT part of the public API: the two signing-domain tags, so a
// cross-type domain-separation test can assert against the REAL constants instead
// of retyping their values. A test that hardcodes a sibling's tag stays green if
// that sibling later moves onto a colliding value — exactly the barrier such a test
// exists to prove. Re-exporting the two constants (rather than opening `mod
// manifest` / `mod teamkey` to the crate) keeps the widened surface to these two
// items. `#[cfg(test)]` because the only consumer is that test — an unconditional
// re-export would be dead code in a release build.
#[cfg(test)]
pub(crate) use manifest::MANIFEST_DOMAIN;
pub use marker::{FileManifestMarker, ManifestMarker};
#[cfg(test)]
pub(crate) use teamkey::MEMBERKEY_DOMAIN;
pub use teamkey::{
    MemberKey, WrappedKey, fetch_team_key, highest_published_epoch, load_member_keys,
    provision_team_key, publish_member_key, rotate_team_key, unwrap_team_key, wrap_team_key,
    wrapped_key_recipients,
};

use blake2::{Blake2b512, Digest};
use zeroize::{Zeroize, Zeroizing};

use crate::domain::{NetworkPrefix, Ss58};
use crate::error::MemError;
use crate::oplog::{Sr25519Signer, VerifyingKey};

/// Domain-separation tag hashed into every SS58 checksum.
const SS58_PRE: &[u8] = b"SS58PRE";
/// Length of an sr25519 public key, in bytes.
const PUBKEY_LEN: usize = 32;
/// Length of the SS58 trailing checksum, in bytes.
const CHECKSUM_LEN: usize = 2;
/// PBKDF2 round count fixed by the Substrate BIP-39 scheme.
const PBKDF2_ROUNDS: u32 = 2048;
/// PBKDF2 salt prefix fixed by the BIP-39 / Substrate scheme (no passphrase).
const BIP39_SALT: &[u8] = b"mnemonic";

/// A cryptographic identity derived from one BIP-39 mnemonic.
///
/// Binds the human-facing [`Ss58`] address to the sr25519 [`VerifyingKey`] it
/// was computed from, so attribution can be checked cryptographically rather
/// than trusted. The 32-byte sr25519 mini-secret seed is private and held in
/// [`Zeroizing`] so it is wiped on drop; [`Debug`] redacts it.
pub struct Identity {
    /// The SS58 account address, computed from [`Identity::verifying_key`].
    pub ss58: Ss58,
    /// The sr25519 public key — the identity a signature verifies against.
    pub verifying_key: VerifyingKey,
    // Secret. Never logged, never exposed: the field is private and `Debug`
    // redacts it. `signer_from_mnemonic` reads it within this module to build a
    // signer whose key is guaranteed to match `ss58`.
    sr25519_seed: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("ss58", &self.ss58)
            .field("verifying_key", &self.verifying_key)
            .field("sr25519_seed", &"<redacted>")
            .finish()
    }
}

/// Encode an sr25519 public key as an SS58 address with the given network
/// `prefix` ([`NetworkPrefix::HIPPIUS`] for Hippius / generic Substrate).
///
/// Infallible by type: a [`NetworkPrefix`] is validated to the `0..=16383` ident
/// space at construction, so the out-of-range case the old `debug_assert!`
/// guarded (and which vanished in release) is now unrepresentable.
#[must_use]
pub fn ss58_encode(key: &VerifyingKey, prefix: NetworkPrefix) -> Ss58 {
    let mut body = encode_prefix(prefix.get());
    body.extend_from_slice(key.as_bytes());

    let checksum = ss58_checksum(&body);
    body.extend_from_slice(&checksum);

    Ss58::from_trusted(bs58::encode(body).into_string())
}

/// Decode an SS58 address back into its sr25519 public key and network prefix.
///
/// # Errors
///
/// Returns [`MemError::Identity`] if the address is not valid base58, has a
/// reserved prefix byte, has the wrong length, or fails the recomputed
/// blake2b checksum.
pub fn ss58_decode(address: &Ss58) -> Result<(VerifyingKey, NetworkPrefix), MemError> {
    let data = bs58::decode(address.as_str())
        .into_vec()
        .map_err(|_| MemError::Identity("ss58 address is not valid base58"))?;

    let (prefix_len, ident) = decode_prefix(&data)?;
    if data.len() != prefix_len + PUBKEY_LEN + CHECKSUM_LEN {
        return Err(MemError::Identity("ss58 address has the wrong length"));
    }

    let body = &data[..prefix_len + PUBKEY_LEN];
    if data[prefix_len + PUBKEY_LEN..] != ss58_checksum(body) {
        return Err(MemError::Identity("ss58 checksum mismatch"));
    }

    // `decode_prefix` only yields idents in 0..=16383 (the reserved high bits are
    // masked off), so this never fails; mapping it keeps the function total.
    let prefix = NetworkPrefix::new(ident)
        .map_err(|_| MemError::Identity("ss58 address has an out-of-range network prefix"))?;

    let mut key = [0u8; PUBKEY_LEN];
    key.copy_from_slice(&data[prefix_len..prefix_len + PUBKEY_LEN]);

    Ok((VerifyingKey::new(key), prefix))
}

/// Encode a network ident into its 1- or 2-byte SS58 prefix form.
fn encode_prefix(ident: u16) -> Vec<u8> {
    if ident < 64 {
        // Idents below 64 fit in one byte; the low byte equals the ident.
        vec![ident.to_le_bytes()[0]]
    } else {
        let [hi, lo] = ident.to_be_bytes();
        let first = (lo >> 2) | 0b0100_0000;
        let second = hi | ((lo & 0b0000_0011) << 6);
        vec![first, second]
    }
}

/// Split the leading SS58 prefix off `data`, returning its byte length and the
/// decoded network ident.
fn decode_prefix(data: &[u8]) -> Result<(usize, u16), MemError> {
    let &first = data
        .first()
        .ok_or(MemError::Identity("ss58 address is empty"))?;
    match first {
        0..=63 => Ok((1, u16::from(first))),
        64..=127 => {
            let &second = data
                .get(1)
                .ok_or(MemError::Identity("ss58 address is truncated"))?;
            let lower = (first << 2) | (second >> 6);
            let upper = second & 0b0011_1111;
            Ok((2, u16::from(lower) | (u16::from(upper) << 8)))
        }
        _ => Err(MemError::Identity("ss58 address has a reserved prefix")),
    }
}

/// The 2-byte SS58 checksum over `body` (`prefix ++ pubkey`).
fn ss58_checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Blake2b512::new();
    hasher.update(SS58_PRE);
    hasher.update(body);

    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

/// Derive a full [`Identity`] from a BIP-39 `mnemonic` and SS58 `ss58_prefix`.
///
/// See the [module docs](self) for the exact derivation scheme.
///
/// # Errors
///
/// Returns [`MemError::Identity`] if the mnemonic is not a valid BIP-39 phrase
/// or the derived seed cannot be expanded into an sr25519 key.
pub fn derive_identity(mnemonic: &str, ss58_prefix: NetworkPrefix) -> Result<Identity, MemError> {
    let sr25519_seed = sr25519_seed_from_mnemonic(mnemonic)?;
    let verifying_key = verifying_key_from_seed(&sr25519_seed)?;
    let ss58 = ss58_encode(&verifying_key, ss58_prefix);

    Ok(Identity {
        ss58,
        verifying_key,
        sr25519_seed,
    })
}

/// Build an [`Sr25519Signer`] from a BIP-39 `mnemonic`.
///
/// The signer's SS58 author address is derived from its own key, so it is
/// guaranteed to match — closing the Phase-2 gap where an author address was
/// self-asserted.
///
/// # Errors
///
/// Returns [`MemError::Identity`] for the same reasons as [`derive_identity`].
pub fn signer_from_mnemonic(
    mnemonic: &str,
    ss58_prefix: NetworkPrefix,
) -> Result<Sr25519Signer, MemError> {
    let identity = derive_identity(mnemonic, ss58_prefix)?;
    Sr25519Signer::from_seed_with_prefix(&identity.sr25519_seed, ss58_prefix)
}

/// Derive the 32-byte sr25519 mini-secret seed from a mnemonic (Substrate
/// entropy → PBKDF2 scheme). The entropy and 64-byte intermediate are wiped on
/// drop; only the mini-secret leaves this function (also zeroizing).
fn sr25519_seed_from_mnemonic(mnemonic: &str) -> Result<Zeroizing<[u8; 32]>, MemError> {
    let parsed = bip39::Mnemonic::parse(mnemonic)
        .map_err(|_| MemError::Identity("invalid BIP-39 mnemonic"))?;

    let (entropy_buf, entropy_len) = parsed.to_entropy_array();
    let entropy = Zeroizing::new(entropy_buf);

    let mut seed = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
        &entropy[..entropy_len],
        BIP39_SALT,
        PBKDF2_ROUNDS,
        &mut seed[..],
    );

    let mut mini = [0u8; 32];
    mini.copy_from_slice(&seed[..32]);
    let wrapped = Zeroizing::new(mini);

    // `mini` is `Copy`, so `Zeroizing::new` copied rather than moved it; wipe the
    // residual stack copy (identity-4) of the sr25519 root seed. The returned
    // `Zeroizing` owns its own copy, wiped on drop.
    mini.zeroize();

    Ok(wrapped)
}

/// Expand a 32-byte mini-secret seed into its sr25519 public key, using the
/// same `ExpansionMode::Ed25519` as [`Sr25519Signer::from_seed`] so the key a
/// signer holds matches the one encoded into the [`Identity`]'s address.
fn verifying_key_from_seed(seed: &[u8; 32]) -> Result<VerifyingKey, MemError> {
    let mini = schnorrkel::MiniSecretKey::from_bytes(seed)
        .map_err(|_| MemError::Identity("sr25519 seed could not be expanded"))?;
    let keypair = mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);

    Ok(VerifyingKey::new(keypair.public.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oplog::Signer;
    use proptest::prelude::*;

    /// Tests return `Result` and use `?` for fallible fixtures rather than
    /// `unwrap`, matching the op-log test style: a fixture failure surfaces as a
    /// failed test, never an unwrap panic the lints forbid.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Adapt a fallible call into proptest's error type (proptest bodies return
    /// `Result<(), TestCaseError>`, so `?` needs this bridge).
    fn tce(e: impl std::fmt::Display) -> TestCaseError {
        TestCaseError::fail(e.to_string())
    }

    /// Return `Err` instead of panicking when `cond` is false: assertions in a
    /// `Result`-returning fn trip `clippy::panic_in_result_fn`, so the op-log
    /// tests funnel checks through `ensure`/`ensure_eq` and these do too.
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

    /// The publicly known Substrate development phrase. Its keys are public, so
    /// it is safe to pin as an interoperability fixture.
    const DEV_PHRASE: &str =
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
    /// `//Alice`'s sr25519 public key — the canonical SS58 codec test vector.
    const ALICE_HEX: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    /// The base `DEV_PHRASE` sr25519 account (no derivation junction), verified
    /// against `subxt_signer::sr25519::Keypair::from_phrase`.
    const DEV_PUBKEY_HEX: &str = "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";
    const DEV_SS58: &str = "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV";

    fn alice_key() -> Result<VerifyingKey, Box<dyn std::error::Error>> {
        let bytes: [u8; 32] = hex::decode(ALICE_HEX)?
            .try_into()
            .map_err(|_| "alice fixture is not 32 bytes")?;
        Ok(VerifyingKey::new(bytes))
    }

    proptest! {
        #[test]
        fn ss58_roundtrips(raw in any::<[u8; 32]>()) {
            let key = VerifyingKey::new(raw);
            let (decoded, prefix) = ss58_decode(&ss58_encode(&key, NetworkPrefix::HIPPIUS)).map_err(tce)?;
            prop_assert_eq!(decoded, key);
            prop_assert_eq!(prefix, NetworkPrefix::HIPPIUS);
        }

        #[test]
        fn ss58_roundtrips_across_prefixes(raw in any::<[u8; 32]>(), prefix in 0u16..16384) {
            let key = VerifyingKey::new(raw);
            let network_prefix = NetworkPrefix::new(prefix).map_err(tce)?;
            let (decoded, got) = ss58_decode(&ss58_encode(&key, network_prefix)).map_err(tce)?;
            prop_assert_eq!(decoded, key);
            prop_assert_eq!(got.get(), prefix);
        }

        /// F2: the 1-/2-byte SS58 prefix codec, isolated from the checksum/key
        /// layers the round-trips above also touch. `decode(encode(ident)) == ident`
        /// for every accepted ident, with the 1-byte form below 64 and the 2-byte
        /// form at/above it, so a codec regression surfaces here directly.
        #[test]
        fn prefix_codec_round_trips(ident in 0u16..16384) {
            let encoded = encode_prefix(ident);
            let expected_len = if ident < 64 { 1 } else { 2 };
            prop_assert_eq!(encoded.len(), expected_len);
            prop_assert_eq!(decode_prefix(&encoded).ok(), Some((expected_len, ident)));
        }
    }

    proptest! {
        /// M3 regression: an SS58 address minted under a multi-byte prefix
        /// (`ident >= 64`, ~49 chars) must survive a serde JSON round-trip through
        /// the `Ss58` newtype. `ss58_encode` builds it via the trusted path; the
        /// previous 47..=48 deserialize bound rejected exactly these, so a note
        /// authored under such a prefix serialized but could not be re-read.
        #[test]
        fn ss58_under_multibyte_prefix_round_trips_through_json(
            raw in any::<[u8; 32]>(),
            prefix in 64u16..16384,
        ) {
            let network_prefix = NetworkPrefix::new(prefix).map_err(tce)?;
            let address = ss58_encode(&VerifyingKey::new(raw), network_prefix);
            let json = serde_json::to_string(&address).map_err(tce)?;
            let back: crate::domain::Ss58 = serde_json::from_str(&json).map_err(tce)?;
            prop_assert_eq!(address, back);
        }
    }

    #[test]
    fn known_vector_codec() -> TestResult {
        ensure_eq(
            &ss58_encode(&alice_key()?, NetworkPrefix::HIPPIUS).as_str(),
            &ALICE_SS58,
            "alice codec vector",
        )
    }

    #[test]
    fn known_vector_derivation() -> TestResult {
        let id = derive_identity(DEV_PHRASE, NetworkPrefix::HIPPIUS)?;
        ensure_eq(
            &id.verifying_key.to_hex().as_str(),
            &DEV_PUBKEY_HEX,
            "dev-phrase pubkey",
        )?;
        ensure_eq(&id.ss58.as_str(), &DEV_SS58, "dev-phrase ss58")
    }

    #[test]
    fn ss58_detects_tampered_checksum() -> TestResult {
        let good = ss58_encode(&alice_key()?, NetworkPrefix::HIPPIUS);
        let mut chars: Vec<char> = good.as_str().chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'Y' { 'Z' } else { 'Y' };
        let tampered = Ss58::new(chars.into_iter().collect::<String>())?;
        ensure(
            ss58_decode(&tampered).is_err(),
            "tampered checksum must be rejected",
        )
    }

    #[test]
    fn ss58_rejects_wrong_length() -> TestResult {
        // A truncated address: drop the final checksum byte before re-encoding.
        let good = ss58_encode(&alice_key()?, NetworkPrefix::HIPPIUS);
        let mut bytes = bs58::decode(good.as_str()).into_vec()?;
        bytes.pop();
        let short = Ss58::from_trusted(bs58::encode(bytes).into_string());
        ensure(
            ss58_decode(&short).is_err(),
            "wrong-length address must be rejected",
        )
    }

    #[test]
    fn derive_identity_is_deterministic() -> TestResult {
        let a = derive_identity(DEV_PHRASE, NetworkPrefix::HIPPIUS)?;
        let b = derive_identity(DEV_PHRASE, NetworkPrefix::HIPPIUS)?;
        ensure_eq(&a.ss58, &b.ss58, "ss58 is deterministic")?;
        ensure_eq(&a.verifying_key, &b.verifying_key, "key is deterministic")
    }

    #[test]
    fn seed_expansion_agrees_across_derivation_sites() -> TestResult {
        // `verifying_key_from_seed` (the `derive_identity` path) and
        // `Sr25519Signer::from_seed_with_prefix` (the signer path) each expand the
        // same 32-byte mini-secret independently. They MUST agree, or an
        // identity's SS58 address would not decode to the key its signer signs
        // with — the binding `Op::verify_identity` relies on. Pin the agreement so
        // the two sites cannot silently diverge.
        let seed = [13u8; 32];
        let from_identity = verifying_key_from_seed(&seed)?;
        let from_signer =
            Sr25519Signer::from_seed_with_prefix(&seed, NetworkPrefix::HIPPIUS)?.verifying_key();
        ensure_eq(
            &from_identity,
            &from_signer,
            "the two seed-expansion sites must derive the same key",
        )
    }

    #[test]
    fn signer_from_mnemonic_ss58_matches_key() -> TestResult {
        let signer = signer_from_mnemonic(DEV_PHRASE, NetworkPrefix::HIPPIUS)?;
        let derived = ss58_encode(&signer.verifying_key(), NetworkPrefix::HIPPIUS);
        ensure_eq(
            &signer.author_ss58(),
            &derived,
            "signer ss58 matches its key",
        )?;
        ensure_eq(
            &signer.author_ss58().as_str(),
            &DEV_SS58,
            "signer ss58 vector",
        )
    }

    #[test]
    fn identity_debug_redacts_seed() -> TestResult {
        let id = derive_identity(DEV_PHRASE, NetworkPrefix::HIPPIUS)?;
        let shown = format!("{id:?}");
        ensure(
            shown.contains("redacted"),
            "debug must mark the seed redacted",
        )?;
        // The seed field must be a redaction marker, never a raw byte dump.
        ensure(
            !shown.contains("sr25519_seed: ["),
            "seed must not be a raw byte dump",
        )
    }

    #[test]
    fn rejects_invalid_mnemonic() -> TestResult {
        ensure(
            derive_identity("not a valid mnemonic phrase at all", NetworkPrefix::HIPPIUS).is_err(),
            "an invalid mnemonic must be rejected",
        )
    }
}
