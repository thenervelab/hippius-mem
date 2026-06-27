//! Server configuration: load + validate, then build the real store.
//!
//! The key currently arrives as hex from config/env. Moving it into the OS
//! keychain (the `keyring` crate) is a later hardening step, deliberately
//! deferred so Phase 1 has no extra dependency or platform-specific code path.

use std::fmt;
use std::io::ErrorKind;
use std::sync::Arc;

#[cfg(feature = "chain")]
use hippius_mem_core::SubxtAnchor;
use hippius_mem_core::{
    AuditAnchor, BlobStore, HashEmbedder, InMemoryIndex, MemoryIndex, MemoryStore, NoopAnchor,
    OpLogStore, S3BlobStore, SecretKey, Signer, Sr25519Signer,
};

/// Path consulted when `HIPPIUS_MEM_CONFIG` is unset.
const DEFAULT_CONFIG_PATH: &str = "./hippius-mem.toml";

/// SS58 network prefix for Hippius / generic Substrate identities (Bittensor).
///
/// The author address is derived from the signing seed under this prefix, so the
/// two cannot disagree — there is no separately configured address to drift.
const HIPPIUS_SS58_PREFIX: u16 = 42;

/// Resolved server configuration.
///
/// This is the *raw* half of the two-phase config split: serde fills it from
/// untrusted TOML/env, and it only becomes trustworthy after passing through
/// [`Config::validate`]. Every public load path ([`Config::from_toml_str`],
/// [`Config::from_env_and_file`]) runs that validation, so a `Config` reaching
/// [`Config::build_store`] has already been checked. Secrets (`secret`,
/// `team_key_hex`) live here in plaintext; the hand-written [`fmt::Debug`] impl
/// redacts them so they never reach a log or panic message.
#[derive(serde::Deserialize)]
#[serde(default)]
pub(crate) struct Config {
    /// S3 gateway endpoint URL.
    pub(crate) s3_endpoint: String,
    /// Gateway region label (a Hippius marker, not an AWS region).
    pub(crate) s3_region: String,
    /// Target bucket holding the team's memory blobs.
    pub(crate) bucket: String,
    /// S3 sub-token id used to sign requests.
    pub(crate) access_key_id: String,
    /// S3 sub-token secret. Redacted in `Debug`.
    pub(crate) secret: String,
    /// Shared namespace that scopes every note.
    pub(crate) team: String,
    /// 64 hex chars decoding to the 32-byte team `ChaCha` key. Redacted in `Debug`.
    pub(crate) team_key_hex: String,
    /// 64 hex chars decoding to the dev's 32-byte sr25519 signing seed. Redacted
    /// in `Debug`.
    ///
    /// This is the *signing* key behind every op this machine appends — distinct
    /// from `team_key_hex` (the shared encryption key). The author SS58 identity is
    /// derived from this seed (under [`HIPPIUS_SS58_PREFIX`]), so it is bound to the
    /// signing key by construction and is not configured separately.
    pub(crate) author_seed_hex: String,
    /// How many op-log ops accumulate before their batch's Merkle root is anchored.
    ///
    /// Defaults to 16. Anchoring one root per batch — rather than one extrinsic
    /// per op — is what keeps on-chain anchoring cheap.
    pub(crate) anchor_threshold: usize,
    /// WebSocket URL of the chain to anchor batch roots on.
    ///
    /// `None` (the default) disables on-chain anchoring: a local
    /// [`hippius_mem_core::NoopAnchor`] is used and roots are recorded without a
    /// chain reference. Only honoured when the `chain` feature is compiled in.
    pub(crate) chain_ws_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        // Only the endpoint/region carry real defaults; the remaining fields
        // default to empty so a missing key surfaces as a `MissingField`
        // validation error rather than an opaque serde "missing field" error.
        Self {
            s3_endpoint: "https://s3.hippius.com".to_owned(),
            s3_region: "decentralized".to_owned(),
            bucket: String::new(),
            access_key_id: String::new(),
            secret: String::new(),
            team: String::new(),
            team_key_hex: String::new(),
            author_seed_hex: String::new(),
            anchor_threshold: 16,
            chain_ws_url: None,
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written so `secret` and `team_key_hex` never leak; deriving Debug
        // would print both in full.
        f.debug_struct("Config")
            .field("s3_endpoint", &self.s3_endpoint)
            .field("s3_region", &self.s3_region)
            .field("bucket", &self.bucket)
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .field("team", &self.team)
            .field("team_key_hex", &"<redacted>")
            .field("author_seed_hex", &"<redacted>")
            .field("anchor_threshold", &self.anchor_threshold)
            .field("chain_ws_url", &self.chain_ws_url)
            .finish()
    }
}

impl Config {
    /// Parse and validate a configuration from a TOML document.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Toml`] if the document is malformed, or any
    /// validation variant (see [`Config::validate`]) if a field is missing or
    /// malformed.
    // The binary loads through `from_env_and_file`; this pure parse+validate
    // entry point exists for the unit tests (and future library callers).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "config API exercised by tests; production uses from_env_and_file"
        )
    )]
    pub(crate) fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load from an optional TOML file then overlay `HIPPIUS_MEM_*` env vars.
    ///
    /// The file path comes from `HIPPIUS_MEM_CONFIG` (default
    /// [`DEFAULT_CONFIG_PATH`]); a missing file is not an error (defaults plus
    /// env are used). Environment variables win over file values.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] if the file exists but cannot be read,
    /// [`ConfigError::Toml`] if it is malformed, or a validation variant if the
    /// merged result is incomplete.
    pub(crate) fn from_env_and_file() -> Result<Self, ConfigError> {
        let path =
            std::env::var("HIPPIUS_MEM_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_owned());
        let toml_str = match std::fs::read_to_string(&path) {
            Ok(contents) => Some(contents),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => return Err(ConfigError::Io(err)),
        };
        Self::from_sources(toml_str.as_deref(), |key| std::env::var(key).ok())
    }

    /// Build a validated config from an optional TOML body and an env lookup.
    ///
    /// Split out from [`Config::from_env_and_file`] so the merge-then-validate
    /// logic is exercised deterministically in tests without mutating the
    /// process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Toml`] if `toml_str` is malformed, or a validation
    /// variant if the merged result is incomplete.
    fn from_sources(
        toml_str: Option<&str>,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let mut cfg = match toml_str {
            Some(body) => toml::from_str(body)?,
            None => Self::default(),
        };
        cfg.apply_overrides(lookup);
        cfg.validate()?;
        Ok(cfg)
    }

    /// Overlay `HIPPIUS_MEM_*` environment values; present keys win.
    fn apply_overrides(&mut self, lookup: impl Fn(&str) -> Option<String>) {
        if let Some(v) = lookup("HIPPIUS_MEM_S3_ENDPOINT") {
            self.s3_endpoint = v;
        }
        if let Some(v) = lookup("HIPPIUS_MEM_S3_REGION") {
            self.s3_region = v;
        }
        if let Some(v) = lookup("HIPPIUS_MEM_BUCKET") {
            self.bucket = v;
        }
        if let Some(v) = lookup("HIPPIUS_MEM_ACCESS_KEY_ID") {
            self.access_key_id = v;
        }
        if let Some(v) = lookup("HIPPIUS_MEM_SECRET") {
            self.secret = v;
        }
        if let Some(v) = lookup("HIPPIUS_MEM_TEAM") {
            self.team = v;
        }
        if let Some(v) = lookup("HIPPIUS_MEM_TEAM_KEY_HEX") {
            self.team_key_hex = v;
        }
        if let Some(v) = lookup("HIPPIUS_MEM_AUTHOR_SEED_HEX") {
            self.author_seed_hex = v;
        }
        if let Some(v) = lookup("HIPPIUS_MEM_ANCHOR_THRESHOLD") {
            // A malformed numeric override leaves the file/default value in place.
            // The primary config path (typed TOML) fails fast on a bad value; this
            // env overlay deliberately degrades rather than abort on a stray typo.
            if let Ok(parsed) = v.parse::<usize>() {
                self.anchor_threshold = parsed;
            }
        }
        if let Some(v) = lookup("HIPPIUS_MEM_CHAIN_WS_URL") {
            self.chain_ws_url = Some(v);
        }
    }

    /// Check that every required field is present and well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MissingField`] for an empty required string,
    /// [`ConfigError::InvalidKey`] if `team_key_hex` does not decode to exactly 32
    /// bytes, or [`ConfigError::InvalidSeed`] if `author_seed_hex` does not.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        require(&self.bucket, "bucket")?;
        require(&self.access_key_id, "access_key_id")?;
        require(&self.secret, "secret")?;
        require(&self.team, "team")?;
        // Decoding the key both validates it and is the single source of truth
        // for the 32-byte length rule; the constructed key is dropped here.
        self.team_key()?;
        // Same for the signing seed: decoding is the length check, dropped here.
        // The author SS58 is derived from this seed, so validating the seed is the
        // only identity check needed.
        self.author_seed()?;
        Ok(())
    }

    /// Decode `author_seed_hex` into the 32-byte sr25519 signing seed.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidSeed`] if the hex is malformed or does not
    /// decode to exactly 32 bytes.
    fn author_seed(&self) -> Result<[u8; 32], ConfigError> {
        let bytes = hex::decode(&self.author_seed_hex).map_err(|err| ConfigError::InvalidSeed {
            detail: err.to_string(),
        })?;
        bytes
            .try_into()
            .map_err(|got: Vec<u8>| ConfigError::InvalidSeed {
                detail: format!("expected 32 bytes (64 hex chars), got {} bytes", got.len()),
            })
    }

    /// Build the dev's [`Sr25519Signer`] from the configured seed, deriving its
    /// author SS58 from the resulting key under [`HIPPIUS_SS58_PREFIX`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidSeed`] if the seed is malformed or rejected
    /// by schnorrkel.
    pub(crate) fn signer(&self) -> Result<Sr25519Signer, ConfigError> {
        let seed = self.author_seed()?;
        Sr25519Signer::from_seed_with_prefix(seed, HIPPIUS_SS58_PREFIX).map_err(|err| {
            ConfigError::InvalidSeed {
                detail: err.to_string(),
            }
        })
    }

    /// Decode `team_key_hex` into the 32-byte symmetric key.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidKey`] if the hex is malformed or does not
    /// decode to exactly 32 bytes.
    pub(crate) fn team_key(&self) -> Result<SecretKey, ConfigError> {
        let bytes = hex::decode(&self.team_key_hex).map_err(|err| ConfigError::InvalidKey {
            detail: err.to_string(),
        })?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|got: Vec<u8>| ConfigError::InvalidKey {
                detail: format!("expected 32 bytes (64 hex chars), got {} bytes", got.len()),
            })?;
        Ok(SecretKey::from_bytes(key))
    }

    /// Assemble the real S3-backed [`MemoryStore`] described by this config.
    ///
    /// Async because building the configured anchor may connect to a chain node
    /// (under the `chain` feature, when `chain_ws_url` is set); the default
    /// no-chain build resolves to a [`NoopAnchor`] with nothing to await.
    ///
    /// # Errors
    ///
    /// Returns any validation variant (see [`Config::validate`]). Validation runs
    /// first, so this can never construct an [`S3BlobStore`] with an empty bucket
    /// or other missing field even if a caller hands in an unvalidated `Config`.
    /// Under the `chain` feature, also returns `ConfigError::ChainConnect` if the
    /// anchoring node is unreachable.
    pub(crate) async fn build_store(&self) -> Result<MemoryStore, ConfigError> {
        // Validate before constructing anything: the load paths already validate,
        // but `build_store` must be self-sufficient so it cannot build a store
        // over an empty bucket (which would fail only later, at the first S3 call)
        // when called directly with a raw config.
        self.validate()?;
        let key = self.team_key()?;
        let blob: Arc<dyn BlobStore> = Arc::new(S3BlobStore::new(
            self.s3_endpoint.clone(),
            self.bucket.clone(),
            self.access_key_id.clone(),
            self.secret.clone(),
            self.s3_region.clone(),
        ));
        let index: Arc<dyn MemoryIndex> =
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        // The op-log lives in the SAME bucket as the note blobs: one shared
        // backend, the op-log under its own key prefix.
        let oplog = OpLogStore::new(blob.clone());
        let signer: Arc<dyn Signer> = Arc::new(self.signer()?);
        let anchor = self.build_anchor().await?;
        Ok(MemoryStore::new(
            blob,
            index,
            oplog,
            anchor,
            signer,
            key,
            self.team.clone(),
            self.anchor_threshold,
        ))
    }

    /// Construct the configured anchor: a `SubxtAnchor` connected to
    /// `chain_ws_url` when the `chain` feature is on and the URL is set, else a
    /// [`NoopAnchor`].
    ///
    /// # Errors
    ///
    /// Under the `chain` feature, returns `ConfigError::ChainConnect` if the node
    /// is unreachable or the signing seed is rejected.
    #[cfg_attr(
        not(feature = "chain"),
        expect(
            clippy::unused_async,
            reason = "the async signature exists for the `chain`-feature `SubxtAnchor::connect().await`; the default `NoopAnchor` path has nothing to await"
        )
    )]
    async fn build_anchor(&self) -> Result<Arc<dyn AuditAnchor>, ConfigError> {
        #[cfg(feature = "chain")]
        if let Some(ws_url) = self.chain_ws_url.as_deref() {
            // Reuse the dev's sr25519 signing seed as the anchoring account.
            let seed = self.author_seed()?;
            let anchor = SubxtAnchor::connect(ws_url, seed).await.map_err(|err| {
                ConfigError::ChainConnect {
                    detail: err.to_string(),
                }
            })?;
            return Ok(Arc::new(anchor));
        }
        Ok(Arc::new(NoopAnchor))
    }
}

/// Reject an empty (or all-whitespace) required field.
fn require(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        Err(ConfigError::MissingField { field })
    } else {
        Ok(())
    }
}

/// Why a configuration could not be loaded into a usable [`Config`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum ConfigError {
    /// A required field was missing or empty.
    #[error(
        "configuration field `{field}` is required but empty; set HIPPIUS_MEM_{field} \
         (uppercased) or add it to hippius-mem.toml"
    )]
    MissingField {
        /// The offending field name.
        field: &'static str,
    },

    /// `team_key_hex` did not decode to a 32-byte key.
    #[error("team_key_hex is invalid: {detail}; expected 64 hex characters (32 bytes)")]
    InvalidKey {
        /// What was wrong with the supplied key.
        detail: String,
    },

    /// `author_seed_hex` did not decode to a usable 32-byte sr25519 seed.
    #[error("author_seed_hex is invalid: {detail}; expected 64 hex characters (32 bytes)")]
    InvalidSeed {
        /// What was wrong with the supplied seed.
        detail: String,
    },

    /// Connecting to the configured anchoring chain failed.
    #[cfg(feature = "chain")]
    #[error("could not connect to the anchoring chain at the configured ws url: {detail}")]
    ChainConnect {
        /// What went wrong connecting to the node or loading the signer.
        detail: String,
    },

    /// The TOML document was malformed.
    #[error("could not parse configuration TOML")]
    Toml(#[from] toml::de::Error),

    /// The configuration file existed but could not be read.
    #[error("could not read configuration file")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert on hand-built fixtures where construction cannot fail"
    )]

    use super::{Config, ConfigError};
    use hippius_mem_core::{Signer, verify};

    const VALID_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    // A distinct 64-hex value so a test swapping one key cannot accidentally
    // collide with the other.
    const VALID_SEED: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const SECRET: &str = "s3-sub-token-secret";

    fn valid_toml() -> String {
        format!(
            "bucket = \"memories\"\n\
             access_key_id = \"AKID\"\n\
             secret = \"{SECRET}\"\n\
             team = \"ourovoros\"\n\
             team_key_hex = \"{VALID_KEY}\"\n\
             author_seed_hex = \"{VALID_SEED}\"\n"
        )
    }

    #[test]
    fn parses_minimal_valid_toml() {
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert_eq!(cfg.bucket, "memories");
        assert_eq!(cfg.team, "ourovoros");
    }

    #[test]
    fn defaults_endpoint_and_region() {
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert_eq!(cfg.s3_endpoint, "https://s3.hippius.com");
        assert_eq!(cfg.s3_region, "decentralized");
    }

    #[test]
    fn rejects_missing_bucket() {
        let toml = valid_toml().replace("bucket = \"memories\"\n", "");
        let err = Config::from_toml_str(&toml).expect_err("missing bucket is rejected");
        assert!(
            matches!(err, ConfigError::MissingField { field } if field == "bucket"),
            "expected MissingField(bucket), got {err:?}"
        );
    }

    #[test]
    fn rejects_empty_team() {
        let toml = valid_toml().replace("team = \"ourovoros\"", "team = \"\"");
        let err = Config::from_toml_str(&toml).expect_err("empty team is rejected");
        assert!(
            matches!(err, ConfigError::MissingField { field } if field == "team"),
            "expected MissingField(team), got {err:?}"
        );
    }

    #[test]
    fn rejects_bad_key_length() {
        let toml = valid_toml().replace(VALID_KEY, "00112233aa");
        let err = Config::from_toml_str(&toml).expect_err("short key is rejected");
        assert!(
            matches!(err, ConfigError::InvalidKey { .. }),
            "expected InvalidKey, got {err:?}"
        );
    }

    #[test]
    fn rejects_non_hex_key() {
        let non_hex = "z".repeat(64);
        let toml = valid_toml().replace(VALID_KEY, &non_hex);
        let err = Config::from_toml_str(&toml).expect_err("non-hex key is rejected");
        assert!(
            matches!(err, ConfigError::InvalidKey { .. }),
            "expected InvalidKey, got {err:?}"
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains(SECRET),
            "Debug leaked the S3 secret: {rendered}"
        );
        assert!(
            !rendered.contains(VALID_KEY),
            "Debug leaked the team key: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "Debug did not mark redaction: {rendered}"
        );
    }

    #[test]
    fn rejects_bad_author_seed() {
        // A 10-hex (5-byte) seed decodes as hex but is the wrong length: the
        // signing-seed length rule must reject it as InvalidSeed, the same way a
        // short team key is InvalidKey.
        let toml = valid_toml().replace(VALID_SEED, "00112233aa");
        let err = Config::from_toml_str(&toml).expect_err("short seed is rejected");
        assert!(
            matches!(err, ConfigError::InvalidSeed { .. }),
            "expected InvalidSeed, got {err:?}"
        );
    }

    #[test]
    fn signer_round_trips() {
        // A signer built from a valid config signs a message that verifies under
        // its own public key — proving the seed -> keypair path is wired and the
        // signing context matches the verifier.
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        let signer = cfg.signer().expect("valid seed yields a signer");
        let msg = b"convergence clock op bytes";
        let sig = signer.sign(msg);
        assert!(
            verify(&signer.verifying_key(), msg, &sig),
            "a signer's own signature must verify under its own key"
        );
    }

    #[test]
    fn team_key_decodes_to_32_bytes() {
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert!(
            cfg.team_key().is_ok(),
            "valid 64-hex key yields a SecretKey"
        );
    }

    #[tokio::test]
    async fn build_store_validates_before_constructing() {
        // A default Config has empty required fields. build_store must reject it
        // via validation (before any anchor/await) rather than constructing an S3
        // store over an empty bucket (which would surface only later, at the first
        // gateway call).
        let cfg = Config::default();
        let err = cfg
            .build_store()
            .await
            .expect_err("an unvalidated empty config must not build a store");
        assert!(
            matches!(err, ConfigError::MissingField { field } if field == "bucket"),
            "expected MissingField(bucket), got {err:?}"
        );
    }

    #[test]
    fn defaults_anchor_threshold_and_chain_url() {
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert_eq!(cfg.anchor_threshold, 16, "absent threshold defaults to 16");
        assert!(
            cfg.chain_ws_url.is_none(),
            "absent chain url defaults to no on-chain anchoring"
        );
    }

    #[test]
    fn parses_explicit_anchor_threshold() {
        let toml = format!("{}anchor_threshold = 4\n", valid_toml());
        let cfg = Config::from_toml_str(&toml).expect("valid config parses");
        assert_eq!(cfg.anchor_threshold, 4);
    }

    #[test]
    fn overrides_win_over_file() {
        let lookup = |key: &str| match key {
            "HIPPIUS_MEM_BUCKET" => Some("env-bucket".to_owned()),
            _ => None,
        };
        let cfg = Config::from_sources(Some(&valid_toml()), lookup).expect("overlay validates");
        assert_eq!(
            cfg.bucket, "env-bucket",
            "env override beats the file value"
        );
    }
}
