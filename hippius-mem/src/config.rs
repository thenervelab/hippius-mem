//! Server configuration: load + validate, then build the real store.
//!
//! The key currently arrives as hex from config/env. Moving it into the OS
//! keychain (the `keyring` crate) is a later hardening step, deliberately
//! deferred so Phase 1 has no extra dependency or platform-specific code path.

use std::fmt;
use std::io::ErrorKind;
use std::sync::Arc;

use hippius_mem_core::{
    BlobStore, HashEmbedder, InMemoryIndex, MemoryIndex, MemoryStore, S3BlobStore, SecretKey, Ss58,
};

/// Path consulted when `HIPPIUS_MEM_CONFIG` is unset.
const DEFAULT_CONFIG_PATH: &str = "./hippius-mem.toml";

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
    /// This developer's SS58 identity, attributed to each note.
    pub(crate) author_ss58: String,
    /// 64 hex chars decoding to the 32-byte team `ChaCha` key. Redacted in `Debug`.
    pub(crate) team_key_hex: String,
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
            author_ss58: String::new(),
            team_key_hex: String::new(),
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
            .field("author_ss58", &self.author_ss58)
            .field("team_key_hex", &"<redacted>")
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
        if let Some(v) = lookup("HIPPIUS_MEM_AUTHOR_SS58") {
            self.author_ss58 = v;
        }
        if let Some(v) = lookup("HIPPIUS_MEM_TEAM_KEY_HEX") {
            self.team_key_hex = v;
        }
    }

    /// Check that every required field is present and well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MissingField`] for an empty required string,
    /// [`ConfigError::InvalidAuthor`] if `author_ss58` is not a valid SS58
    /// address, or [`ConfigError::InvalidKey`] if `team_key_hex` does not decode
    /// to exactly 32 bytes.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        require(&self.bucket, "bucket")?;
        require(&self.access_key_id, "access_key_id")?;
        require(&self.secret, "secret")?;
        require(&self.team, "team")?;
        Ss58::new(self.author_ss58.as_str()).map_err(|err| ConfigError::InvalidAuthor {
            detail: err.to_string(),
        })?;
        // Decoding the key both validates it and is the single source of truth
        // for the 32-byte length rule; the constructed key is dropped here.
        self.team_key()?;
        Ok(())
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
    /// # Errors
    ///
    /// Returns a validation variant if the key or author cannot be resolved.
    /// Callers should hold an already-validated config (every load path
    /// validates), but the key/author are re-derived here and report their own
    /// errors regardless.
    pub(crate) fn build_store(&self) -> Result<MemoryStore, ConfigError> {
        let key = self.team_key()?;
        let author =
            Ss58::new(self.author_ss58.as_str()).map_err(|err| ConfigError::InvalidAuthor {
                detail: err.to_string(),
            })?;
        let blob: Arc<dyn BlobStore> = Arc::new(S3BlobStore::new(
            self.s3_endpoint.clone(),
            self.bucket.clone(),
            self.access_key_id.clone(),
            self.secret.clone(),
            self.s3_region.clone(),
        ));
        let index: Arc<dyn MemoryIndex> =
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        Ok(MemoryStore::new(
            blob,
            index,
            key,
            self.team.clone(),
            author,
        ))
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

    /// `author_ss58` was not a valid SS58 address.
    #[error("author_ss58 is not a valid SS58 address: {detail}")]
    InvalidAuthor {
        /// What was wrong with the supplied address.
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

    const AUTHOR: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    const VALID_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SECRET: &str = "s3-sub-token-secret";

    fn valid_toml() -> String {
        format!(
            "bucket = \"memories\"\n\
             access_key_id = \"AKID\"\n\
             secret = \"{SECRET}\"\n\
             team = \"ourovoros\"\n\
             author_ss58 = \"{AUTHOR}\"\n\
             team_key_hex = \"{VALID_KEY}\"\n"
        )
    }

    #[test]
    fn parses_minimal_valid_toml() {
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert_eq!(cfg.bucket, "memories");
        assert_eq!(cfg.team, "ourovoros");
        assert_eq!(cfg.author_ss58, AUTHOR);
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
    fn rejects_bad_author() {
        let toml = valid_toml().replace(AUTHOR, "not-a-real-ss58-address");
        let err = Config::from_toml_str(&toml).expect_err("bad author is rejected");
        assert!(
            matches!(err, ConfigError::InvalidAuthor { .. }),
            "expected InvalidAuthor, got {err:?}"
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
    fn team_key_decodes_to_32_bytes() {
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert!(
            cfg.team_key().is_ok(),
            "valid 64-hex key yields a SecretKey"
        );
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
