//! Server configuration: load + validate, then build the real store.
//!
//! The key currently arrives as hex from config/env. Moving it into the OS
//! keychain (the `keyring` crate) is a later hardening step, deliberately
//! deferred so Phase 1 has no extra dependency or platform-specific code path.

use std::fmt;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;

use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "chain")]
use hippius_mem_core::SubxtAnchor;
use hippius_mem_core::{
    AuditAnchor, BlobStore, CachingBlobStore, Embedder, FileManifestMarker, FsBlobStore,
    HashEmbedder, HeadWatermarks, InMemoryIndex, ManifestMarker, MemoryIndex, MemoryStore,
    NetworkPrefix, NoopAnchor, OpLogStore, S3BlobStore, SecretKey, Signer, Sr25519Signer, Ss58,
    derive_cache_key, ss58_decode,
};
#[cfg(feature = "embeddings")]
use hippius_mem_core::{EmbedModel, FastEmbedder};

/// The local blob-cache directory for `team`, or `None` when caching is disabled.
///
/// `HIPPIUS_MEM_CACHE_DIR` controls it: unset uses the XDG cache root
/// (`$XDG_CACHE_HOME`, else `~/.cache`) under `hippius-mem/<team>`; a path overrides
/// that root; the literal `off` (or an empty value, or no resolvable home) disables
/// the cache. The per-team subdir keeps profiles from sharing cache files, and the
/// files are encrypted under a per-team key regardless (see `derive_cache_key`).
fn blob_cache_dir(team: &str) -> Option<PathBuf> {
    match std::env::var_os("HIPPIUS_MEM_CACHE_DIR") {
        Some(v) if v.is_empty() || v.eq_ignore_ascii_case("off") => None,
        Some(dir) => Some(PathBuf::from(dir).join(team)),
        None => {
            let base = std::env::var_os("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
            Some(base.join("hippius-mem").join(team))
        }
    }
}

/// The local head-watermark file for `team`, or `None` when no base directory
/// resolves.
///
/// `HIPPIUS_MEM_STATE_DIR` overrides the base; otherwise `XDG_STATE_HOME`, then
/// `XDG_DATA_HOME`, then `$HOME/.local/share`. Whichever wins is joined with
/// `hippius-mem/state/{team}/head-watermarks.json`, so the base is a base in every
/// case (mirroring [`blob_cache_dir`], where the override is likewise a root the
/// team segment hangs off) and two profiles never share a file.
///
/// # Deliberately NOT under the blob cache directory
///
/// The obvious home for a small local file is beside the blob cache, and it would
/// be wrong. That directory is disposable by design — XDG documents the cache base
/// as safe for a user or a cleanup job to purge, `HIPPIUS_MEM_CACHE_DIR=off`
/// disables it outright, and the blob cache is a regenerable mirror of data the
/// bucket also holds. This file is neither: it is the ONLY copy of what this
/// machine has already verified, and losing it silently downgrades a security
/// check to "no rollback detected" — a false clean report, which is worse than
/// having no check at all, because it reads as evidence. `XDG_STATE_HOME` is the
/// base XDG designates for exactly this class (state that should persist between
/// restarts but is not portable user data), with the durable `XDG_DATA_HOME` as
/// the fallback [`TeamProfile::local_trial_root`] already uses.
///
/// There is deliberately no `off` sentinel either. Turning this off is
/// indistinguishable in the report from "nothing was rolled back", so it is not
/// offered as a setting; a machine that genuinely wants to forget deletes the file.
///
/// # Keyed on the TEAM NAME only, deliberately
///
/// Not on the bucket, endpoint or backend. The consequence is real and is
/// documented on every operator surface: the same team name pointed at a restored
/// backup, a staging mirror, or a different endpoint inherits the marks of the one
/// before it, and every author then reads as regressed until the file is deleted.
///
/// Keying the path on the endpoint or bucket would be cheap and WAS considered. It
/// is rejected because of the direction each failure points. As it stands, pointing
/// a name somewhere else produces a LOUD false positive that names the state file
/// and its remedy. Keyed on a config string instead, a cosmetic edit to that string
/// — a trailing slash, `http` to `https`, a gateway rename — silently relocates the
/// file, so the machine starts from no marks and reports a clean
/// `head_regressions` for a bucket that has genuinely rolled a head back. That is a
/// false CLEAN, on the very check whose entire purpose is to stop a silent
/// rollback, and it is the same argument that keeps this file out of the cache
/// directory. It also would not fix the case most likely to bite — a backup
/// restored INTO the same bucket, which is the same endpoint and the same name.
/// A loud, documented, one-command-to-clear false positive is the better trade.
fn head_watermarks_path(team: &str) -> Option<PathBuf> {
    let base = std::env::var_os("HIPPIUS_MEM_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_STATE_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("XDG_DATA_HOME").map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
        })?;

    Some(
        base.join("hippius-mem")
            .join("state")
            .join(team)
            .join("head-watermarks.json"),
    )
}

/// Path consulted when `HIPPIUS_MEM_CONFIG` is unset. `pub(crate)` so the
/// `dashboard` subcommand can reuse it as its own fall-back when no global config
/// exists (see `dashboard::dashboard_config_default`).
pub(crate) const DEFAULT_CONFIG_PATH: &str = "./hippius-mem.toml";

/// SS58 network prefix for Hippius / generic Substrate identities (Bittensor).
///
/// The author address is derived from the signing seed under this prefix, so the
/// two cannot disagree — there is no separately configured address to drift.
const HIPPIUS_SS58_PREFIX: NetworkPrefix = NetworkPrefix::HIPPIUS;

/// Resolved server configuration.
///
/// This is the *raw* half of the two-phase config split: serde fills it from
/// untrusted TOML/env, and it only becomes trustworthy after passing through
/// [`Config::validate`]. Every public load path ([`Config::from_toml_str`],
/// [`Config::from_env_and_file`]) runs that validation, so a `Config` reaching
/// [`Config::build_store`] has already been checked. Secrets (`secret`,
/// `team_key_hex`) live here in plaintext; the hand-written [`fmt::Debug`] impl
/// redacts them so they never reach a log or panic message.
// `Serialize` is derived (not just `Deserialize`) so `upgrade` can round-trip
// an EXISTING `Config` through `toml::to_string` — load, mutate only the
// storage fields, re-serialize — instead of hand-listing a fixed field subset
// that silently drops every field the writer forgot (see the module docs on
// `upgrade`'s `render_upgraded_config` for the incident this replaced).
// `Clone` lets `render_upgraded_config` copy-then-mutate rather than needing
// a second, hand-built `Config`.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
// `default` fills absent fields; `deny_unknown_fields` rejects a typo'd key
// (e.g. `ancho_threshold`) as a parse error instead of silently ignoring it, so
// a misconfiguration cannot look applied when it was dropped. Both attributes
// are Deserialize-only and simply unused by the derived Serialize impl.
#[serde(default, deny_unknown_fields)]
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
    /// Highest team-key epoch to bootstrap from the bucket at startup.
    ///
    /// Defaults to 0 (only the founding epoch). When `HIPPIUS_MEM_MNEMONIC` is
    /// set, startup attempts to load the wrapped keys for epochs `0..=max_epoch`
    /// this member can unwrap, so a member provisioned after a team-key rotation
    /// can read notes sealed under the newer epochs. Key discovery is not
    /// automatic — set this to the highest epoch the team has rotated to.
    pub(crate) max_epoch: u64,
    /// The team founder's SS58 address, pinned out of band.
    ///
    /// The founder is the only identity permitted to change membership. The
    /// membership manifest lives in the *untrusted* bucket, so the genesis
    /// (version-0) manifest that would otherwise fix the founder can be
    /// overwritten by a malicious gateway to seize the team. Pinning the founder
    /// here — a value the bucket cannot rewrite — anchors that trust locally:
    /// [`MemoryStore`] then honours only manifests signed by this address.
    ///
    /// `None` (the default) preserves trust-on-genesis (backward compatible, with
    /// the documented takeover gap); a startup warning is logged when it is unset.
    /// Not a secret — an SS58 address is public — so it is not redacted in `Debug`.
    pub(crate) founder_ss58: Option<String>,
    /// Which blob backend the primary (flat-config) profile binds. Absent
    /// (the default) means [`StorageBackend::S3`] — see [`primary_profile`]
    /// for how this reaches [`TeamProfile::storage`].
    ///
    /// [`primary_profile`]: Self::primary_profile
    #[serde(default)]
    pub(crate) storage: StorageBackend,
    /// Override the primary profile's derived local trial root when `storage
    /// = "local"`. Ignored for `s3`. See [`TeamProfile::local_trial_root`].
    #[serde(default)]
    pub(crate) local_root: Option<PathBuf>,
    /// Use real semantic embeddings for `recall` instead of the lexical fallback.
    ///
    /// A plain on/off switch: which dense model runs is chosen by
    /// [`embedding_model`](Self::embedding_model), not this flag. When `true`
    /// AND the binary was built `--features embeddings`, [`Config::build_store`]
    /// wires a [`FastEmbedder`] over the selected local ONNX model (default
    /// `bge-small-en-v1.5`); when `true` but the feature is absent, it warns and
    /// falls back to the lexical [`HashEmbedder`], so the degradation is
    /// observable rather than silent.
    ///
    /// **The default tracks the build:** `true` when compiled `--features
    /// embeddings`, `false` otherwise (see [`Config::default`]). Compiling the
    /// model in is the opt-in; once it is in, semantic recall is the experience
    /// without a second flag. Set `semantic_embeddings = false` to force the
    /// lexical fallback in a feature build (for determinism, or to skip the model
    /// download).
    pub(crate) semantic_embeddings: bool,
    /// Which local embedding model to use when `semantic_embeddings` is on.
    ///
    /// `None` (default) selects `bge-small-en-v1.5`. Accepts `bge-small` /
    /// `minilm` (or their full ids). Only honoured under `--features
    /// embeddings`; an unknown name is a startup error, not a silent fallback.
    pub(crate) embedding_model: Option<String>,
    /// Override the model's calibrated semantic relevance floor (minimum cosine
    /// for a match) when `semantic_embeddings` is on.
    ///
    /// `None` (default) uses the model's own calibrated floor. A higher value is
    /// stricter (fewer, more confident matches); a lower value surfaces looser
    /// paraphrases at the cost of more noise. Must be within `[0.0, 1.0]`.
    pub(crate) relevance_floor: Option<f32>,
    /// Remote patterns the primary (flat-config) profile owns: `host/org` or
    /// `host/org/repo`. Empty (the default) makes the primary a catch-all that
    /// matches every repo — so a flat config with no `orgs` behaves exactly as
    /// before this field existed.
    #[serde(default)]
    pub(crate) orgs: Vec<String>,
    /// Force the primary profile to be the catch-all even when it has `orgs`.
    /// The *effective* catch-all is `catch_all || orgs.is_empty()`, so an unset
    /// value on a flat config still catches every repo.
    #[serde(default)]
    pub(crate) catch_all: bool,
    /// Additional team profiles beyond the primary (flat) one, each with its own
    /// bucket, sub-token, key, and seed. Empty by default; a repo is routed to the
    /// first profile whose `orgs` match its git remote (see [`crate::resolver`]).
    #[serde(default)]
    pub(crate) teams: Vec<TeamProfile>,
    /// Directory of the config file this was loaded from, if any — runtime
    /// metadata, not a config key (`#[serde(skip)]`).
    ///
    /// [`build_store`](Self::build_store) places the durable manifest marker here
    /// (a local file the untrusted bucket cannot roll back). Set by
    /// [`from_env_and_file`](Self::from_env_and_file); `None` when the config came
    /// from anywhere but a file (tests, in-memory overlays), in which case no
    /// marker is wired and the store keeps its in-memory-only rollback guard.
    #[serde(skip)]
    pub(crate) source_dir: Option<std::path::PathBuf>,
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
            max_epoch: 0,
            founder_ss58: None,
            storage: StorageBackend::S3,
            local_root: None,
            // Default ON when the model is compiled in: building `--features
            // embeddings` is the deliberate opt-in, so a second config flag to
            // actually use it is redundant. A lean build (no feature) stays
            // lexical. `cfg!` resolves this binary crate's `embeddings` feature,
            // which forwards to the core crate's.
            semantic_embeddings: cfg!(feature = "embeddings"),
            embedding_model: None,
            relevance_floor: None,
            orgs: Vec::new(),
            catch_all: false,
            teams: Vec::new(),
            source_dir: None,
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
            .field("max_epoch", &self.max_epoch)
            .field("founder_ss58", &self.founder_ss58)
            .field("storage", &self.storage)
            .field("local_root", &self.local_root)
            .field("semantic_embeddings", &self.semantic_embeddings)
            .field("embedding_model", &self.embedding_model)
            .field("relevance_floor", &self.relevance_floor)
            .field("orgs", &self.orgs)
            .field("catch_all", &self.catch_all)
            // TeamProfile's own Debug redacts each profile's secrets.
            .field("teams", &self.teams)
            .field("source_dir", &self.source_dir)
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
    // The server loads through `from_env_and_file`; this pure parse+validate
    // entry point is `join --bundle`'s pre-write/post-write check (and the
    // unit tests'): it must judge exactly the file's bytes, no env overlay.
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
        Self::from_env_and_file_with_default(DEFAULT_CONFIG_PATH)
    }

    /// Like [`Config::from_env_and_file`] but with a caller-chosen `default_path`
    /// consulted only when `HIPPIUS_MEM_CONFIG` is unset. The MCP server uses the
    /// cwd-local [`DEFAULT_CONFIG_PATH`] so a repo's own `hippius-mem.toml` scopes it
    /// to that team; the `dashboard` subcommand passes the user's global config path
    /// so its vault list shows every namespace regardless of the launch directory.
    ///
    /// # Errors
    ///
    /// Same as [`Config::from_env_and_file`].
    pub(crate) fn from_env_and_file_with_default(default_path: &str) -> Result<Self, ConfigError> {
        let explicit_path = std::env::var("HIPPIUS_MEM_CONFIG").ok();
        let path = explicit_path
            .clone()
            .unwrap_or_else(|| default_path.to_owned());
        let toml_str = match std::fs::read_to_string(&path) {
            Ok(contents) => Some(contents),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                // A missing file at the IMPLICIT default is normal (env-only config).
                // But when the operator EXPLICITLY set HIPPIUS_MEM_CONFIG and it
                // points at a nonexistent file, silently degrading to defaults+env
                // hides a typo — the store then fails obscurely later as "bucket is
                // required but empty", never naming the file it could not find. Warn,
                // naming the path, so the misdirection is visible. (A warn, not an
                // error: an env-only setup that sets the var to a not-yet-created
                // path stays valid, and this path also feeds the dashboard/doctor.)
                if let Some(explicit) = &explicit_path {
                    tracing::warn!(
                        path = %explicit,
                        "HIPPIUS_MEM_CONFIG points at a file that does not exist; falling back to defaults plus environment overrides"
                    );
                }
                None
            }
            Err(err) => return Err(ConfigError::Io(err)),
        };
        let mut config = Self::from_sources(toml_str.as_deref(), |key| std::env::var(key).ok())?;
        // Record the config's directory so `build_store` can place the durable
        // manifest marker beside it. A bare filename (no directory) means the cwd;
        // only keep a directory that actually exists, so a marker is wired only
        // where it can be written (and no per-sync warn otherwise).
        let dir = std::path::Path::new(&path).parent().map(|parent| {
            if parent.as_os_str().is_empty() {
                std::path::PathBuf::from(".")
            } else {
                parent.to_path_buf()
            }
        });
        config.source_dir = dir.filter(|d| d.is_dir());
        Ok(config)
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
            // The env overlay deliberately degrades rather than abort on a stray
            // typo — but it WARNS so the degradation is observable, not silent.
            match v.parse::<usize>() {
                Ok(parsed) => self.anchor_threshold = parsed,
                Err(err) => tracing::warn!(
                    value = %v,
                    error = %err,
                    "ignoring malformed HIPPIUS_MEM_ANCHOR_THRESHOLD; keeping the file/default value"
                ),
            }
        }
        if let Some(v) = lookup("HIPPIUS_MEM_CHAIN_WS_URL") {
            self.chain_ws_url = Some(v);
        }
        if let Some(v) = lookup("HIPPIUS_MEM_FOUNDER_SS58") {
            self.founder_ss58 = Some(v);
        }
        if let Some(v) = lookup("HIPPIUS_MEM_SEMANTIC_EMBEDDINGS") {
            // Accept the common truthy spellings; anything else (including a typo)
            // keeps the file/default value and WARNS, so a misremembered "yes" does
            // not silently leave retrieval lexical when the operator asked for
            // semantic — symmetric with the lenient numeric overrides above.
            match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => self.semantic_embeddings = true,
                "0" | "false" | "no" | "off" => self.semantic_embeddings = false,
                other => tracing::warn!(
                    value = %other,
                    "ignoring unrecognized HIPPIUS_MEM_SEMANTIC_EMBEDDINGS (expected true/false); keeping the file/default value"
                ),
            }
        }
        if let Some(v) = lookup("HIPPIUS_MEM_EMBEDDING_MODEL") {
            self.embedding_model = Some(v);
        }
        if let Some(v) = lookup("HIPPIUS_MEM_RELEVANCE_FLOOR") {
            // A malformed float leaves the file/default value in place and WARNS,
            // matching the lenient numeric overlays above — the model's calibrated
            // floor is then used rather than a silently-dropped override.
            match v.parse::<f32>() {
                Ok(parsed) => self.relevance_floor = Some(parsed),
                Err(err) => tracing::warn!(
                    value = %v,
                    error = %err,
                    "ignoring malformed HIPPIUS_MEM_RELEVANCE_FLOOR; keeping the file/default value"
                ),
            }
        }
        if let Some(v) = lookup("HIPPIUS_MEM_MAX_EPOCH") {
            // A malformed override leaves the file/default value in place, matching
            // the lenient `anchor_threshold` overlay above — and WARNS, because a
            // silent fallback to 0 caps epoch-key bootstrap and makes every note
            // under a rotated epoch undecryptable with no diagnostic.
            match v.parse::<u64>() {
                Ok(parsed) => self.max_epoch = parsed,
                Err(err) => tracing::warn!(
                    value = %v,
                    error = %err,
                    "ignoring malformed HIPPIUS_MEM_MAX_EPOCH; keeping the file/default value (this caps epoch-key bootstrap)"
                ),
            }
        }
    }

    /// Check that every required field is present and well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MissingField`] for an empty required string,
    /// [`ConfigError::InvalidKey`] if `team_key_hex` does not decode to exactly 32
    /// bytes, [`ConfigError::InvalidSeed`] if `author_seed_hex` does not, or
    /// [`ConfigError::LocalStorageWithS3Field`] if `storage = "local"` also
    /// sets a bucket/credential.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        self.validate_shared()?;
        // Primary profile (flat top-level fields). Validated inline — not routed
        // through `TeamProfile::validate` — so a flat config still reports the
        // original error field names (`bucket`/`team`, not `name`).
        match self.storage {
            StorageBackend::S3 => {
                require(&self.bucket, "bucket")?;
                require(&self.access_key_id, "access_key_id")?;
                require(&self.secret, "secret")?;
            }
            // A local trial vault has no gateway: bucket/credentials are not
            // just unneeded, they are a contradiction — refuse rather than
            // silently ignore them.
            StorageBackend::Local => {
                reject_present(&self.bucket, "bucket")?;
                reject_present(&self.access_key_id, "access_key_id")?;
                reject_present(&self.secret, "secret")?;
            }
        }
        require(&self.team, "team")?;
        // `team` becomes the first object-key component of every note this profile
        // writes (see `objkey::object_key`); catching a charset violation here turns
        // it into a load-time `ConfigError` instead of a `MemError::Malformed` at the
        // first `remember`/`sync`, far from the config that caused it.
        validate_namespace(&self.team, "team")?;
        // Decoding the key/seed both validates and is the single source of truth for
        // the 32-byte length rule; the constructed values are dropped here. The
        // author SS58 is derived from the seed, so validating it is the only
        // identity check needed.
        self.team_key()?;
        self.author_seed()?;
        // Surface a malformed founder pin at config time, not at the first sync.
        self.founder()?;
        // Each additional profile is validated exactly as the primary's fields are.
        for profile in &self.teams {
            profile.validate()?;
        }
        self.validate_routing()?;
        Ok(())
    }

    /// Validate the shared, non-per-profile settings: gateway coordinates and the
    /// numeric ranges.
    ///
    /// Split out so [`TeamProfile::build_store`] can validate the bound profile
    /// plus these shared settings without re-validating every OTHER profile.
    /// Whole-config validation still runs once at load (see [`Config::validate`]),
    /// so a malformed profile is still caught at startup — this only keeps a direct
    /// `build_store` on one profile from failing on an unrelated profile.
    ///
    /// # Errors
    ///
    /// [`ConfigError::MissingField`] for a blank endpoint/region, or
    /// [`ConfigError::OutOfRange`] for `anchor_threshold` / `max_epoch` /
    /// `relevance_floor` outside their bounds.
    fn validate_shared(&self) -> Result<(), ConfigError> {
        // Non-empty defaults exist, but an explicit empty value in TOML/env would
        // otherwise slip past — an S3 store over a blank endpoint/region fails only
        // at the first gateway call, far from the config.
        require(&self.s3_endpoint, "s3_endpoint")?;
        require(&self.s3_region, "s3_region")?;
        // A 0 threshold would anchor every op as its own batch; an unbounded
        // max_epoch makes startup load one wrapped key per epoch (one S3 GET each),
        // turning a config typo into a startup denial of service. Bound both.
        if self.anchor_threshold == 0 {
            return Err(ConfigError::OutOfRange {
                field: "anchor_threshold",
                detail: "must be at least 1 (0 would anchor every op individually)".to_owned(),
            });
        }
        if self.max_epoch > MAX_BOOTSTRAP_EPOCH {
            return Err(ConfigError::OutOfRange {
                field: "max_epoch",
                detail: format!(
                    "must be <= {MAX_BOOTSTRAP_EPOCH}; startup loads one wrapped key per epoch 0..=max_epoch"
                ),
            });
        }
        // A relevance floor is a cosine threshold; outside [0.0, 1.0] it is either a
        // no-op or rejects every match, so catch a typo at config time.
        if let Some(floor) = self.relevance_floor
            && !(0.0..=1.0).contains(&floor)
        {
            return Err(ConfigError::OutOfRange {
                field: "relevance_floor",
                detail: format!("must be within [0.0, 1.0]; got {floor}"),
            });
        }
        Ok(())
    }

    /// Validate the routing invariants across all profiles.
    ///
    /// # Errors
    ///
    /// [`ConfigError::MultipleCatchAll`] if more than one profile is the effective
    /// catch-all, [`ConfigError::MalformedOrg`] if an `orgs` pattern is a shape the
    /// resolver could never match a real remote against, or
    /// [`ConfigError::DuplicateOrg`] if two profiles claim the same org pattern
    /// (first-match-wins would make the later one dead).
    fn validate_routing(&self) -> Result<(), ConfigError> {
        let profiles = self.all_profiles();
        // `all_profiles` normalizes each profile's effective catch-all (empty `orgs`
        // implies catch-all), so this counts what the resolver sees.
        let catch_alls = profiles.iter().filter(|p| p.catch_all).count();
        if catch_alls > 1 {
            return Err(ConfigError::MultipleCatchAll { count: catch_alls });
        }
        // Normalize each org the way the resolver's `matches` does (trim whitespace
        // and a trailing slash, lowercase) so a duplicate is caught even if spelled
        // with different casing or a stray slash.
        let mut seen = std::collections::BTreeSet::new();
        for profile in &profiles {
            for org in &profile.orgs {
                // Reject a URL-shaped or wrong-arity pattern before deduping: the
                // resolver compares patterns verbatim, so such a pattern matches
                // nothing and the repo silently falls through to the catch-all —
                // the exact misroute behind the 2026-07 "service error" incident.
                validate_org_pattern(org)?;
                let pattern = org.trim().trim_end_matches('/').to_ascii_lowercase();
                if !seen.insert(pattern.clone()) {
                    return Err(ConfigError::DuplicateOrg { pattern });
                }
            }
        }
        Ok(())
    }

    /// Decode the optional pinned team-founder SS58 address.
    ///
    /// Returns `Ok(None)` when no founder is pinned (trust-on-genesis, backward
    /// compatible). When set, the address is fully validated — base58 structure
    /// AND the recomputed SS58 checksum via [`ss58_decode`] — and required to be
    /// under the Hippius network prefix, because it is the team's trust anchor:
    /// silently accepting a typo'd or wrong-network address would defeat the pin.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidFounder`] if a non-empty value is not a valid
    /// Hippius SS58 address.
    pub(crate) fn founder(&self) -> Result<Option<Ss58>, ConfigError> {
        decode_founder(self.founder_ss58.as_deref())
    }

    /// Decode `author_seed_hex` into the 32-byte sr25519 signing seed.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidSeed`] if the hex is malformed or does not
    /// decode to exactly 32 bytes.
    fn author_seed(&self) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
        decode_author_seed(&self.author_seed_hex)
    }

    /// Decode `team_key_hex` into the 32-byte symmetric key.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidKey`] if the hex is malformed or does not
    /// decode to exactly 32 bytes.
    pub(crate) fn team_key(&self) -> Result<SecretKey, ConfigError> {
        decode_team_key(&self.team_key_hex)
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
        // The flat fields ARE the primary profile; build its store. Multi-profile
        // startup instead resolves a profile from the repo remote and calls
        // `TeamProfile::build_store` directly (see `crate::resolver` and `main`).
        self.primary_profile().build_store(self).await
    }

    /// The primary profile assembled from the flat top-level fields — the sole
    /// profile of a legacy flat config, and the first candidate when routing.
    pub(crate) fn primary_profile(&self) -> TeamProfile {
        TeamProfile {
            name: self.team.clone(),
            orgs: self.orgs.clone(),
            catch_all: self.catch_all,
            bucket: self.bucket.clone(),
            access_key_id: self.access_key_id.clone(),
            secret: self.secret.clone(),
            team_key_hex: self.team_key_hex.clone(),
            author_seed_hex: self.author_seed_hex.clone(),
            founder_ss58: self.founder_ss58.clone(),
            storage: self.storage,
            local_root: self.local_root.clone(),
        }
    }

    /// Every profile — the primary followed by the additional `[[teams]]` — with
    /// each profile's `catch_all` normalized to its *effective* value (an empty
    /// `orgs` implies catch-all). This is the ordered candidate list the resolver
    /// routes against; order is the tie-break, so the primary wins a tie.
    pub(crate) fn all_profiles(&self) -> Vec<TeamProfile> {
        let mut profiles = Vec::with_capacity(1 + self.teams.len());
        profiles.push(self.primary_profile().into_effective());
        profiles.extend(self.teams.iter().cloned().map(TeamProfile::into_effective));
        profiles
    }

    /// A durable manifest marker in the config directory, or `None` when the
    /// config did not come from a file (so [`source_dir`](Self::source_dir) is
    /// unset).
    ///
    /// The file is `<config-dir>/<team>.manifest.json`; `team` is drawn from the
    /// object-key alphabet `[A-Za-z0-9_-]`, so it is filename-safe. It holds the
    /// highest applied `TeamManifest`, so a cold restart refuses a bucket rolled
    /// back to older membership — the store re-verifies it before trusting it.
    fn manifest_marker(&self, namespace: &str) -> Option<Arc<dyn ManifestMarker>> {
        let dir = self.source_dir.as_ref()?;
        let path = dir.join(format!("{namespace}.manifest.json"));
        Some(Arc::new(FileManifestMarker::new(path)))
    }

    /// Select the retrieval [`Embedder`].
    ///
    /// Returns a [`FastEmbedder`] (local ONNX, [`EmbedModel::default`] —
    /// `bge-small-en-v1.5` — unless `embedding_model` overrides it) when
    /// `semantic_embeddings` is set AND the binary was built `--features
    /// embeddings`; otherwise the deterministic lexical [`HashEmbedder`]. A
    /// `semantic_embeddings` request on a binary built without the feature is not
    /// an error — it warns and falls back, so the absence of the feature is
    /// observable rather than a silent downgrade.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Embedder`] if a requested [`FastEmbedder`] cannot
    /// load its model (e.g. a failed download on an offline first run), so an
    /// embeddings-unavailable startup fails loudly instead of silently serving
    /// lexical results.
    // Under the default (no-`embeddings`) build the `FastEmbedder::try_new`
    // failure path is compiled out, leaving an infallible body — the `Result` is
    // kept for the feature build's fallible path, the same way `build_anchor`
    // keeps its async signature for the `chain` build. Expect the resulting
    // pedantic lint only in that config.
    #[cfg_attr(
        not(feature = "embeddings"),
        expect(
            clippy::unnecessary_wraps,
            reason = "the Result carries the `embeddings`-feature FastEmbedder::try_new failure; the default lexical build is infallible"
        )
    )]
    fn build_embedder(&self) -> Result<Arc<dyn Embedder>, ConfigError> {
        if self.semantic_embeddings {
            #[cfg(feature = "embeddings")]
            {
                // Resolve the model ([`EmbedModel::default`]). An unknown name is a
                // config error, not a silent fallback to a model the operator did not pick.
                let model = match self.embedding_model.as_deref() {
                    None => EmbedModel::default(),
                    Some(name) => EmbedModel::parse(name).ok_or_else(|| ConfigError::Embedder {
                        detail: format!(
                            "unknown embedding_model {name:?}; expected `minilm` or `bge-small`"
                        ),
                    })?,
                };
                // The floor lives with the model unless the deployment overrides it.
                let floor = self
                    .relevance_floor
                    .unwrap_or_else(|| model.default_floor());
                let embedder =
                    FastEmbedder::try_with(model, floor).map_err(|err| ConfigError::Embedder {
                        detail: err.to_string(),
                    })?;
                tracing::info!(model = %model, floor, "semantic recall enabled");
                return Ok(Arc::new(embedder));
            }
            #[cfg(not(feature = "embeddings"))]
            tracing::warn!(
                "semantic_embeddings is set but this binary was built without the `embeddings` \
                 feature; falling back to lexical recall — rebuild with `--features embeddings`"
            );
        }
        Ok(Arc::new(HashEmbedder::default()))
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
            unused_variables,
            reason = "the async signature and `seed` exist for the `chain`-feature `SubxtAnchor::connect().await`; the default `NoopAnchor` path has nothing to await and no seed to use"
        )
    )]
    async fn build_anchor(
        &self,
        seed: &Zeroizing<[u8; 32]>,
    ) -> Result<Arc<dyn AuditAnchor>, ConfigError> {
        #[cfg(feature = "chain")]
        if let Some(ws_url) = self.chain_ws_url.as_deref() {
            // The anchoring account is the bound profile's own signing seed.
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

/// Decode an optional pinned team-founder SS58 address.
///
/// `Ok(None)` when unset/blank (trust-on-genesis). When set it is fully validated
/// — base58 structure AND the recomputed SS58 checksum via [`ss58_decode`] — and
/// required to be under the Hippius prefix, because it is the team's trust anchor.
///
/// # Errors
///
/// [`ConfigError::InvalidFounder`] if a non-empty value is not a valid Hippius SS58.
fn decode_founder(raw: Option<&str>) -> Result<Option<Ss58>, ConfigError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    let address = Ss58::new(raw).map_err(|err| ConfigError::InvalidFounder {
        detail: err.to_string(),
    })?;
    let (_, prefix) = ss58_decode(&address).map_err(|err| ConfigError::InvalidFounder {
        detail: err.to_string(),
    })?;

    if prefix != HIPPIUS_SS58_PREFIX {
        return Err(ConfigError::InvalidFounder {
            detail: format!(
                "address is under network prefix {prefix:?}, expected the Hippius prefix"
            ),
        });
    }

    Ok(Some(address))
}

/// Decode a hex signing seed into the 32-byte sr25519 seed.
///
/// # Errors
///
/// [`ConfigError::InvalidSeed`] if the hex is malformed or not exactly 32 bytes.
fn decode_author_seed(author_seed_hex: &str) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    // Fixed detail, never the hex crate's message: it names the offending character
    // and position, which for a SECRET seed would leak key material into a log or
    // error chain. `Zeroizing` wraps every copy of the raw seed — decoded heap
    // buffer and returned array — so each is wiped on drop rather than left in
    // freed memory. The hex source string stays a plain `String` for the config's
    // lifetime, a known gap this does not close.
    let bytes =
        Zeroizing::new(
            hex::decode(author_seed_hex).map_err(|_| ConfigError::InvalidSeed {
                detail: "not valid hex".to_owned(),
            })?,
        );

    if bytes.len() != 32 {
        return Err(ConfigError::InvalidSeed {
            detail: format!(
                "expected 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            ),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let wrapped = Zeroizing::new(seed);
    // `seed` is `Copy`, so `Zeroizing::new` copied rather than moved it; wipe the
    // residual stack copy. `wrapped` owns its own, wiped on drop.
    seed.zeroize();
    Ok(wrapped)
}

/// Build an [`Sr25519Signer`] from a decoded seed under the Hippius prefix.
///
/// # Errors
///
/// [`ConfigError::InvalidSeed`] if schnorrkel rejects the seed.
fn signer_from_seed(seed: &Zeroizing<[u8; 32]>) -> Result<Sr25519Signer, ConfigError> {
    Sr25519Signer::from_seed_with_prefix(seed, HIPPIUS_SS58_PREFIX).map_err(|err| {
        ConfigError::InvalidSeed {
            detail: err.to_string(),
        }
    })
}

/// Decode a hex team key into the 32-byte symmetric [`SecretKey`].
///
/// # Errors
///
/// [`ConfigError::InvalidKey`] if the hex is malformed or not exactly 32 bytes.
fn decode_team_key(team_key_hex: &str) -> Result<SecretKey, ConfigError> {
    // Fixed detail, never the hex crate's message (it names the offending SECRET
    // char/position). `Zeroizing` wraps each transient copy of the raw key;
    // `SecretKey` takes the array by value and zeroizes its own copy, so the
    // residual stack array is wiped here.
    let bytes = Zeroizing::new(
        hex::decode(team_key_hex).map_err(|_| ConfigError::InvalidKey {
            detail: "not valid hex".to_owned(),
        })?,
    );
    if bytes.len() != 32 {
        return Err(ConfigError::InvalidKey {
            detail: format!(
                "expected 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            ),
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    let secret = SecretKey::from_bytes(key);
    key.zeroize();
    Ok(secret)
}

/// Which blob backend a team profile binds.
///
/// `S3` talks to the Hippius gateway, exactly as every profile did before this
/// type existed. `Local` is the solo trial vault: notes are sealed and signed
/// exactly the same way, but land on this machine's disk (see
/// [`hippius_mem_core::FsBlobStore`]) instead of a bucket, so it needs no
/// gateway credentials. `hippius-mem upgrade` (a later task) flips a `Local`
/// profile to `S3` after copying its objects into a real bucket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StorageBackend {
    /// Hippius S3 gateway. The default: an absent `storage` key means this,
    /// so every profile written before this field existed is unaffected.
    #[default]
    S3,
    /// Local filesystem trial vault. Solo only; takes no bucket or
    /// credentials — see [`Config::validate`] / [`TeamProfile::validate`].
    Local,
}

/// Name of the advisory lock file inside a local trial vault root
/// (`{root}/.lock`). See [`TeamProfile::try_lock_local_vault`].
const VAULT_LOCK_FILE: &str = ".lock";

/// Holds an OS advisory lock (`flock` on Unix, via [`std::fs::File::lock`] —
/// stabilized in the standard library, so this needs no `fs2`/`fd-lock`-style
/// dependency) on a local trial vault's [`VAULT_LOCK_FILE`] for as long as
/// this value is alive. Released automatically when it is dropped —
/// including on a crash, since the OS reclaims the lock the moment the
/// holding file descriptor closes — so a crashed `serve`/`upgrade` can never
/// leave a stale lock a later run must work around.
#[derive(Debug)]
// The `File` is held only for the OS advisory lock attached to its
// underlying fd (released on drop); its contents are never read.
#[expect(
    dead_code,
    reason = "the wrapped File is held purely for its Drop-released flock, never read"
)]
pub(crate) struct VaultLock(std::fs::File);

/// Outcome of [`TeamProfile::try_lock_local_vault`].
pub(crate) enum VaultLockAttempt {
    /// The profile is not [`StorageBackend::Local`]: there is no local vault
    /// directory to lock, so the caller should proceed unguarded.
    NotLocal,
    /// The lock was free and is now held by this attempt's [`VaultLock`].
    Acquired(VaultLock),
    /// Another process already holds the lock.
    Held,
}

/// One team's memory profile: routing (`name`, `orgs`, `catch_all`) plus the
/// credentials that build its store.
///
/// `name` is both the profile label and the note-scoping namespace (the object-key
/// prefix). A flat config's primary profile takes its `name` from the old `team`
/// field, so existing object keys are unchanged. Secrets are redacted in
/// [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TeamProfile {
    /// Profile label AND note-scoping namespace (the object-key prefix).
    pub(crate) name: String,
    /// Remote patterns this profile owns: `host/org` or `host/org/repo`.
    pub(crate) orgs: Vec<String>,
    /// Whether this profile absorbs repos matching no `orgs` (and no-remote repos).
    /// See [`TeamProfile::into_effective`] for the empty-`orgs`-implies-catch-all rule.
    pub(crate) catch_all: bool,
    /// Team-owned bucket holding this profile's memory blobs.
    pub(crate) bucket: String,
    /// S3 sub-token id used to sign requests.
    pub(crate) access_key_id: String,
    /// S3 sub-token secret. Redacted in `Debug`.
    pub(crate) secret: String,
    /// 64 hex chars decoding to this team's 32-byte encryption key. Redacted.
    pub(crate) team_key_hex: String,
    /// 64 hex chars decoding to this machine's 32-byte sr25519 signing seed. Redacted.
    pub(crate) author_seed_hex: String,
    /// Optional pinned founder SS58 for this team. Not a secret.
    pub(crate) founder_ss58: Option<String>,
    /// Which blob backend this profile binds. Absent (the default) means
    /// [`StorageBackend::S3`], so a config written before this field existed
    /// parses identically.
    #[serde(default)]
    pub(crate) storage: StorageBackend,
    /// Override the derived local trial root when `storage = "local"`.
    /// Ignored for `s3`. `None` (the default) derives
    /// `.../hippius-mem/local/{name}` — see [`TeamProfile::local_trial_root`].
    #[serde(default)]
    pub(crate) local_root: Option<PathBuf>,
}

impl fmt::Debug for TeamProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written so `secret`/`team_key_hex`/`author_seed_hex` never leak.
        f.debug_struct("TeamProfile")
            .field("name", &self.name)
            .field("orgs", &self.orgs)
            .field("catch_all", &self.catch_all)
            .field("bucket", &self.bucket)
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .field("team_key_hex", &"<redacted>")
            .field("author_seed_hex", &"<redacted>")
            .field("founder_ss58", &self.founder_ss58)
            .field("storage", &self.storage)
            .field("local_root", &self.local_root)
            .finish()
    }
}

impl TeamProfile {
    /// Normalize `catch_all` to its *effective* value: a profile with no `orgs`
    /// catches every otherwise-unmatched repo, so an empty-`orgs` profile is a
    /// catch-all even if `catch_all` was left false. This is what the resolver
    /// routes against, so a legacy flat config (no `orgs`) still matches every repo.
    fn into_effective(mut self) -> Self {
        self.catch_all = self.catch_all || self.orgs.is_empty();
        self
    }

    /// Validate this profile's required fields and decode its key material.
    ///
    /// # Errors
    ///
    /// [`ConfigError::MissingField`] for a blank required field,
    /// [`ConfigError::LocalStorageWithS3Field`] for a `storage = "local"`
    /// profile that also sets a bucket/credential, or a malformed
    /// key/seed/founder variant — the same shapes the primary's flat fields
    /// yield.
    fn validate(&self) -> Result<(), ConfigError> {
        // `bucket` first so `Config::default().build_store()` (which routes through
        // the empty primary profile) reports `MissingField { bucket }`, matching the
        // flat-config error order the tests pin.
        match self.storage {
            StorageBackend::S3 => {
                require(&self.bucket, "bucket")?;
                require(&self.access_key_id, "access_key_id")?;
                require(&self.secret, "secret")?;
            }
            // A local trial vault has no gateway: bucket/credentials are not
            // just unneeded, they are a contradiction — refuse rather than
            // silently ignore them.
            StorageBackend::Local => {
                reject_present(&self.bucket, "bucket")?;
                reject_present(&self.access_key_id, "access_key_id")?;
                reject_present(&self.secret, "secret")?;
            }
        }
        require(&self.name, "name")?;
        // Same object-key charset rule as the primary's `team` (see
        // `Config::validate`): `name` is this profile's object-key namespace too.
        validate_namespace(&self.name, "name")?;
        self.team_key()?;
        self.author_seed()?;
        self.founder()?;
        Ok(())
    }

    /// Decode `team_key_hex` into this profile's 32-byte symmetric key.
    ///
    /// `pub(crate)`: `doctor` calls this on the RESOLVED profile (not always the
    /// primary) so its live probe exercises the same key the server would bind for
    /// the launch repo — see [`crate::doctor`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidKey`] if the hex is malformed or not exactly 32 bytes.
    pub(crate) fn team_key(&self) -> Result<SecretKey, ConfigError> {
        decode_team_key(&self.team_key_hex)
    }

    fn author_seed(&self) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
        decode_author_seed(&self.author_seed_hex)
    }

    /// Build this profile's [`Sr25519Signer`], deriving its author SS58 from the
    /// resulting key under [`HIPPIUS_SS58_PREFIX`].
    ///
    /// `pub(crate)` for the same reason as [`TeamProfile::team_key`]: `doctor`
    /// derives the author identity of the RESOLVED profile, not always the primary.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidSeed`] if the seed is malformed or rejected by
    /// schnorrkel.
    pub(crate) fn signer(&self) -> Result<Sr25519Signer, ConfigError> {
        signer_from_seed(&self.author_seed()?)
    }

    /// This profile's pinned founder, decoded from `founder_ss58`.
    ///
    /// `pub(crate)` for the same reason as [`TeamProfile::signer`]: `doctor`
    /// reads the founder pin of the RESOLVED profile directly (its own
    /// `removed_member_still_holds_key_lines` check calls `load_manifest`
    /// itself rather than going through a built [`MemoryStore`]), so it must
    /// thread the same pin [`TeamProfile::build_store`] does internally —
    /// otherwise doctor's manifest read would silently fall back to
    /// trust-on-genesis on a pinned team.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidFounder`] if `founder_ss58` is set but not a
    /// valid Hippius SS58 address.
    pub(crate) fn founder(&self) -> Result<Option<Ss58>, ConfigError> {
        decode_founder(self.founder_ss58.as_deref())
    }

    /// The local trial vault root: `local_root` when set, else the default
    /// derived from `XDG_DATA_HOME` (else `HOME/.local/share`), ending in
    /// `.../hippius-mem/local/{name}`.
    ///
    /// Deliberately the XDG *data* base, NOT [`blob_cache_dir`]'s *cache*
    /// base (`XDG_CACHE_HOME`/`HOME/.cache`), even though the two functions
    /// are otherwise structurally identical: this directory is the trial
    /// vault's ONLY copy of the user's notes (`storage = "local"` has no
    /// bucket to re-sync from), whereas `blob_cache_dir` is a disposable,
    /// regenerable mirror of data that also lives in the bucket. XDG
    /// explicitly documents `XDG_CACHE_HOME` as "not required to persist
    /// between (application) restarts" and safe for a user or tool to purge —
    /// exactly the class of directory a cache-cleaning cron job or a low-disk
    /// GC targets. Putting the trial vault there means such a cleaner can
    /// silently delete a user's only copy of their memory. `XDG_DATA_HOME` is
    /// the base XDG designates for exactly this: durable, user-specific data
    /// a purge must not touch. The `.../hippius-mem/local/{name}` suffix
    /// still ends in `local` rather than `blob_cache_dir`'s bare
    /// `.../hippius-mem/{name}`, so a trial vault and a blob cache can never
    /// collide on the same directory even though they now root under
    /// different XDG bases entirely.
    ///
    /// `pub(crate)`: `doctor`'s live probe binds the same
    /// [`hippius_mem_core::FsBlobStore`] root [`TeamProfile::build_store`]
    /// does for a [`StorageBackend::Local`] profile, so the probe exercises
    /// the exact directory the server would use — see [`crate::doctor`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::UnresolvedLocalRoot`] when `local_root` is unset and
    /// neither `XDG_DATA_HOME` nor `HOME` is set, so no default exists.
    pub(crate) fn local_trial_root(&self) -> Result<PathBuf, ConfigError> {
        if let Some(root) = &self.local_root {
            return Ok(root.clone());
        }
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
            })
            .ok_or(ConfigError::UnresolvedLocalRoot)?;
        Ok(base.join("hippius-mem").join("local").join(&self.name))
    }

    /// This profile's local head watermarks, or `None` when no state directory
    /// resolves (see [`head_watermarks_path`]).
    ///
    /// Loaded, never created empty: a missing or unusable file starts with no
    /// marks and repopulates from the next verified head read, so a first run and
    /// a wiped state directory behave identically and neither errors.
    ///
    /// `pub(crate)`: `doctor` builds its own marks for the SAME team rather than
    /// going through a built [`MemoryStore`], exactly as it does for the founder
    /// pin and the trial-vault root, so both surfaces read and advance one file.
    ///
    /// A `None` here means the check is inert — every other check still runs and
    /// `head_regressions` stays empty. [`TeamProfile::build_store`] warns when
    /// that happens, because an empty vector for that reason is indistinguishable
    /// from an empty vector because nothing regressed.
    pub(crate) fn head_watermarks(&self) -> Option<Arc<HeadWatermarks>> {
        head_watermarks_path(&self.name).map(|path| Arc::new(HeadWatermarks::load(path)))
    }

    /// Try to acquire this profile's local-trial-vault advisory lock without
    /// blocking. `Ok(`[`VaultLockAttempt::NotLocal`]`)` for a
    /// [`StorageBackend::S3`] profile — there is no local vault directory to
    /// lock, so callers treat that as "proceed unguarded".
    ///
    /// The SERVE path (`main.rs::acquire_serve_vault_lock`, called by `main`
    /// right after `resolve_and_build_store` builds the store) calls this once
    /// per boot for a `storage = "local"` profile and holds the returned
    /// [`VaultLock`] for the server's whole lifetime; `upgrade` calls it right
    /// before copying and holds it through the copy and the config rewrite,
    /// refusing outright — never blocking — on [`VaultLockAttempt::Held`].
    /// Together these close the gap where `upgrade` could copy a snapshot
    /// while a live server kept appending to the same vault and then flip the
    /// config out from under it: whichever side asks second sees the lock
    /// already held and refuses, rather than two processes silently
    /// interleaving writes to the same files. The one-shot commands
    /// (`brief`/`gc`/`report`/`import`) deliberately never call this: they
    /// share `resolve_and_build_store` with `serve` but not its lock
    /// acquisition, since they are transient and never conflict with a live
    /// serve session in any data-losing way (see `resolve_and_build_store`'s
    /// doc).
    ///
    /// Never blocks (`std::fs::File::try_lock`, backed by `flock` on Unix):
    /// the serve path calls this before the MCP handshake, and a blocking
    /// wait here would reproduce the exact "looks hung" failure the op-log
    /// warmup task in `main.rs` was already restructured to avoid.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Io`] if the vault directory or the lock file cannot be
    /// created/opened, or the underlying `flock` call itself fails for a
    /// reason other than "already held" (that outcome is
    /// [`VaultLockAttempt::Held`], not an `Err`).
    pub(crate) fn try_lock_local_vault(&self) -> Result<VaultLockAttempt, ConfigError> {
        if self.storage != StorageBackend::Local {
            return Ok(VaultLockAttempt::NotLocal);
        }

        let root = self.local_trial_root()?;
        std::fs::create_dir_all(&root).map_err(ConfigError::Io)?;
        // The lock file's CONTENT is never read or written — only its inode
        // matters, as the `flock` target — so opening an existing one must
        // not truncate it (there is nothing to clear, and doing so would be
        // pointless I/O on the common "already exists" path).
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(root.join(VAULT_LOCK_FILE))
            .map_err(ConfigError::Io)?;

        match file.try_lock() {
            Ok(()) => Ok(VaultLockAttempt::Acquired(VaultLock(file))),
            Err(std::fs::TryLockError::WouldBlock) => Ok(VaultLockAttempt::Held),
            Err(std::fs::TryLockError::Error(err)) => Err(ConfigError::Io(err)),
        }
    }

    /// Assemble this profile's real [`MemoryStore`], drawing shared settings
    /// (endpoint, region, threshold, embedder, anchor chain, marker dir) from
    /// `shared`. Binds an [`hippius_mem_core::FsBlobStore`] for
    /// [`StorageBackend::Local`] or the usual gateway-backed store for
    /// [`StorageBackend::S3`] — see [`TeamProfile::storage`].
    ///
    /// # Errors
    ///
    /// Any validation variant (see [`Config::validate`]); under the `chain`
    /// feature, `ConfigError::ChainConnect` if the anchoring node is unreachable.
    pub(crate) async fn build_store(&self, shared: &Config) -> Result<MemoryStore, ConfigError> {
        // Validate the whole configuration before constructing anything: the load
        // paths already validate, but this keeps `build_store` self-sufficient so a
        // caller handing in a raw config cannot build a store over an empty bucket.
        // Validate only THIS profile plus the shared settings — not every other
        // profile — so an unrelated stale/bad profile does not block the one being
        // bound. Whole-config validation still runs once at load.
        self.validate()?;
        shared.validate_shared()?;
        let key = self.team_key()?;
        let blob: Arc<dyn BlobStore> = match self.storage {
            // A trial vault IS local disk already, so the cache's whole value
            // (avoiding a gateway round-trip) does not apply — no cache wrap.
            StorageBackend::Local => Arc::new(FsBlobStore::new(self.local_trial_root()?)),
            StorageBackend::S3 => {
                let s3: Arc<dyn BlobStore> = Arc::new(S3BlobStore::new(
                    shared.s3_endpoint.clone(),
                    self.bucket.clone(),
                    self.access_key_id.clone(),
                    self.secret.clone(),
                    shared.s3_region.clone(),
                ));
                // Wrap the gateway in a local encrypted cache of immutable objects
                // (op-log entries + note version blobs) when a cache dir is
                // configured (the default). The cache key is DERIVED from the team
                // key so cache files are ciphertext at rest and useless without it;
                // `derive_cache_key` borrows `key`, which still moves into the
                // epoch key-ring below.
                match blob_cache_dir(&self.name) {
                    Some(dir) => {
                        tracing::debug!(team = %self.name, cache = %dir.display(), "local blob cache enabled");
                        Arc::new(CachingBlobStore::new(s3, dir, derive_cache_key(&key)))
                    }
                    None => s3,
                }
            }
        };
        let index: Arc<dyn MemoryIndex> = Arc::new(InMemoryIndex::new(shared.build_embedder()?));
        // The op-log lives in the SAME bucket as the note blobs, under its own prefix.
        let oplog = OpLogStore::new(blob.clone());
        let signer: Arc<dyn Signer> = Arc::new(self.signer()?);
        let anchor = shared.build_anchor(&self.author_seed()?).await?;
        // The configured team key is the founding epoch (0); rotation epochs are
        // added at runtime via `MemoryStore::bootstrap_epoch_keys`.
        let keys = std::collections::BTreeMap::from([(0_u64, key)]);
        let founder = self.founder()?;
        if founder.is_none() {
            tracing::warn!(
                team = %self.name,
                "no founder pinned: team founder trust falls back to the genesis manifest, \
                 which an untrusted bucket can overwrite to seize the team; set founder_ss58"
            );
        }
        // Local head marks, so a head the bucket drops or rolls back is reported
        // rather than silently accepted. `None` (no resolvable state directory) is
        // warned rather than swallowed: the resulting empty `head_regressions` reads
        // exactly like "nothing regressed", so its absence must be visible somewhere.
        let head_watermarks = self.head_watermarks();
        if head_watermarks.is_none() {
            tracing::warn!(
                team = %self.name,
                "no local state directory resolves (set HIPPIUS_MEM_STATE_DIR, XDG_STATE_HOME, \
                 XDG_DATA_HOME or HOME): this machine cannot remember the head pointers it has \
                 verified, so reconcile's head_regressions stays empty even if the bucket rolls \
                 a signed head back"
            );
        }
        Ok(MemoryStore::new(
            blob,
            index,
            oplog,
            anchor,
            signer,
            keys,
            0,
            self.name.clone(),
            shared.anchor_threshold,
        )
        .with_pinned_founder(founder)
        .with_manifest_marker(shared.manifest_marker(&self.name))
        .with_head_watermarks(head_watermarks))
    }
}

/// Refuse a team-lifecycle command (`invite`/`join`/`provision`/`mint-token`)
/// against a local trial profile.
///
/// Team lifecycle needs a shared bucket; a local trial vault is solo by
/// design. Refuse with the upgrade pointer instead of a generic validation
/// error.
///
/// # Errors
///
/// Returns an error naming `verb` and the profile when `profile.storage` is
/// [`StorageBackend::Local`]; `Ok(())` for [`StorageBackend::S3`].
pub(crate) fn require_s3(profile: &TeamProfile, verb: &str) -> anyhow::Result<()> {
    if profile.storage == StorageBackend::Local {
        anyhow::bail!(
            "cannot {verb} on the local trial profile {name:?}: team mode needs a \
             Hippius bucket. Subscribe, then run: hippius-mem upgrade",
            name = profile.name,
        );
    }

    Ok(())
}

/// Reject an empty (or all-whitespace) required field.
fn require(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        Err(ConfigError::MissingField { field })
    } else {
        Ok(())
    }
}

/// Reject a non-empty value on a field `storage = "local"` must leave unset.
///
/// The dual of [`require`]: a local trial vault has no gateway to hold a
/// bucket/credential for, so a non-empty value here is a contradiction in the
/// config, not a harmless leftover to silently ignore.
fn reject_present(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        Ok(())
    } else {
        Err(ConfigError::LocalStorageWithS3Field { field })
    }
}

/// Reject a `team`/`name` value that the object-key layer would refuse at write
/// time.
///
/// `hippius_mem_core::objkey::validate_component` is the single source of truth
/// for the object-key alphabet (non-empty, <= 256 bytes, `[A-Za-z0-9_-]`) — every
/// note this namespace ever writes gets `{team}/{repo}/{mem_id}/ver_{ulid}` as its
/// key, and `team` is the first segment. That function is private to
/// `hippius-mem-core`, so this mirrors its three rules exactly rather than
/// calling it, keeping the two in lockstep by inspection (`objkey.rs` is the
/// canonical definition; a future change there must be mirrored here). Without
/// this check an invalid `team`/`name` (spaces, `/`, unicode, a stray `.`) passes
/// `Config::validate` and `doctor`, then fails every `remember`/`sync` at runtime
/// with an opaque `MemError::Malformed` far from the config that caused it.
///
/// # Errors
///
/// [`ConfigError::InvalidName`] if `value` is empty, exceeds 256 bytes, or
/// contains a byte outside `[A-Za-z0-9_-]`.
fn validate_namespace(value: &str, field: &'static str) -> Result<(), ConfigError> {
    // Mirrors objkey::validate_component::MAX_COMPONENT_LEN.
    const MAX_LEN: usize = 256;
    if value.is_empty() {
        return Err(ConfigError::InvalidName {
            field,
            value: value.to_owned(),
            detail: "must not be empty".to_owned(),
        });
    }
    if value.len() > MAX_LEN {
        return Err(ConfigError::InvalidName {
            field,
            value: value.to_owned(),
            detail: format!(
                "{} bytes exceeds the {MAX_LEN}-byte object-key component limit",
                value.len()
            ),
        });
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ConfigError::InvalidName {
            field,
            value: value.to_owned(),
            detail: "must match [A-Za-z0-9_-] (the object-key component alphabet)".to_owned(),
        });
    }
    Ok(())
}

/// Reject an `orgs` routing pattern the resolver could never match a real remote
/// against.
///
/// [`resolver::matches`](crate::resolver) compares each pattern *verbatim* (trimming
/// whitespace and any trailing slashes, case-insensitively) against a remote that
/// [`resolver::normalize_remote`](crate::resolver) reduced to bare `host/org` /
/// `host/org/repo` — lowercased host, `:port` stripped, host of at least 2 chars, no
/// empty path segments. So the pattern must itself be that shape; a scheme
/// (`https://…`), `git@` userinfo, a `.git` suffix, a `:port` on the host, an empty
/// segment (leading/doubled `/`), a <2-char host, or the wrong segment count can
/// never bind — and because an unmatched repo falls through to the catch-all, the
/// misroute is silent. This turns that silent fall-through into a loud config error
/// naming the corrected form. Each check below mirrors a specific rule in
/// `normalize_remote`, so the accepted set is exactly what the resolver can match.
fn validate_org_pattern(raw: &str) -> Result<(), ConfigError> {
    let pattern = raw.trim().trim_end_matches('/');
    let malformed = |reason: String| ConfigError::MalformedOrg {
        pattern: raw.to_owned(),
        reason,
    };
    // Copying a browser URL (`https://…`), a clone address (`git@host:org/repo`),
    // or a `.git` remote is the common mistake; the hint reconstructs the bare form.
    // `strip_suffix(...).is_some()` rather than `ends_with(".git")` mirrors
    // `normalize_remote`'s exact (case-sensitive) suffix handling and sidesteps
    // clippy's file-extension lint, which misreads this URL check as a path check.
    if pattern.contains("://") || pattern.contains('@') || pattern.strip_suffix(".git").is_some() {
        return Err(malformed(format!(
            "looks like a URL or clone address; use the bare `host/org` form \
             `{}` (no scheme, no `git@`, no `.git`)",
            canonical_org_hint(pattern)
        )));
    }
    // An empty segment (`host//org`, `/host/org`) is compared literally by `matches`
    // and so never binds — the trailing slash is already trimmed above, so any empty
    // segment now is a leading or interior doubled slash.
    if pattern.split('/').any(str::is_empty) {
        return Err(malformed(
            "must not contain an empty path segment (no leading or doubled `/`); \
             use `host/org` or `host/org/repo`"
                .to_owned(),
        ));
    }
    // `matches` compares against `host/org` (2 segments) or `host/org/repo` (3); the
    // host is the first segment, so peel it off and count the rest.
    let mut segments = pattern.split('/');
    let host = segments.next().unwrap_or_default();
    let count = 1 + segments.count();
    if !(2..=3).contains(&count) {
        return Err(malformed(
            "must be `host/org` (whole org) or `host/org/repo` (one repo), \
             e.g. `github.com/acme`"
                .to_owned(),
        ));
    }
    // `normalize_remote` strips a `:port` from a remote's host, so a coord host never
    // contains `:` — a pattern whose host does could not match. (Only the host is
    // checked: an org/repo segment may legitimately contain a colon.)
    if host.contains(':') {
        return Err(malformed(
            "the host must not carry a `:port` — the resolver strips ports from \
             remotes, so a port here would match nothing; drop it"
                .to_owned(),
        ));
    }
    // `normalize_remote` rejects a host under 2 bytes (a 1-char host is a Windows
    // drive letter like `C:` from a local path), so such a pattern never binds.
    if host.len() < 2 {
        return Err(malformed(
            "the host segment must be at least 2 characters, e.g. `github.com/acme`".to_owned(),
        ));
    }
    Ok(())
}

/// Best-effort `host/org[/repo]` hint recovered from a URL-ish org pattern, for the
/// error message only — strips a scheme, `git@` userinfo, a host `:port`, and a
/// trailing `.git`. Not a validator: it never fails, and its output is only ever
/// shown to the user, not matched against — but it must not suggest a form that
/// would itself be wrong (e.g. leaving a port as a fake org segment), so it mirrors
/// `normalize_remote`'s host/port handling rather than blindly folding colons.
///
/// The trailing-suffix strip loops to a fixed point so the hint is idempotent: a
/// single pass would leak on doubled suffixes like `repo.git.git`, re-hinting to a
/// different string.
fn canonical_org_hint(pattern: &str) -> String {
    // Whether this was a URL must be decided BEFORE stripping the scheme: after the
    // strip, `host:0/org` is ambiguous — a URL `:port` of 0, or an scp remote whose
    // org is literally `0`. The `://` presence is the only disambiguator, so capture
    // it first.
    let is_url = pattern.contains("://");
    let after_scheme = pattern.split_once("://").map_or(pattern, |(_, rest)| rest);
    let authority_path = after_scheme.rsplit('@').next().unwrap_or(after_scheme);

    // Separate host from path per form. URL: `host[:port]/path` — host ends at the
    // first `/` and a `:` before it is a port to drop (never part of the routing
    // key, matching `normalize_remote`). scp: `host:org/repo` — the first `:` is the
    // host/path separator. A bare `host/org[/repo]` (no scheme, no scp colon) falls
    // through to the plain slash split.
    let (host, path) = if is_url {
        let slash = authority_path.find('/').unwrap_or(authority_path.len());
        let authority = &authority_path[..slash];
        let host = authority
            .split_once(':')
            .map_or(authority, |(bare, _port)| bare);
        (host, authority_path.get(slash + 1..).unwrap_or(""))
    } else if let Some(colon) = authority_path.find(':')
        && authority_path.find('/').is_none_or(|slash| colon < slash)
    {
        (&authority_path[..colon], &authority_path[colon + 1..])
    } else {
        let slash = authority_path.find('/').unwrap_or(authority_path.len());
        (
            &authority_path[..slash],
            authority_path.get(slash + 1..).unwrap_or(""),
        )
    };

    // Peel trailing `/` and `.git` from the path until neither shrinks it. Each
    // iteration strictly shortens `view` or stops, so the loop reaches a fixed point;
    // `view` only re-slices `path`, so this stays allocation-free until the format.
    let mut view: &str = path;
    loop {
        let trimmed = view.trim_end_matches('/').trim_end_matches(".git");
        if trimmed.len() == view.len() {
            break;
        }
        view = trimmed;
    }
    if view.is_empty() {
        host.to_owned()
    } else {
        format!("{host}/{view}")
    }
}

/// Upper bound on `max_epoch`: startup loads one wrapped team key per epoch in
/// `0..=max_epoch` (one S3 GET each), so an unbounded value is a startup denial
/// of service via a config typo. 1024 epochs is far beyond any realistic
/// key-rotation count while keeping the bootstrap bounded.
const MAX_BOOTSTRAP_EPOCH: u64 = 1024;

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

    /// `founder_ss58` was set but is not a valid Hippius SS58 address.
    #[error("founder_ss58 is invalid: {detail}; expected a Hippius-prefixed SS58 address")]
    InvalidFounder {
        /// What was wrong with the supplied founder address.
        detail: String,
    },

    /// `team` (or a `[[teams]]` profile's `name`) is not a valid object-key
    /// namespace component.
    #[error("configuration field `{field}` value {value:?} is invalid: {detail}")]
    InvalidName {
        /// The offending field name (`team` for the primary, `name` for a
        /// `[[teams]]` profile).
        field: &'static str,
        /// The rejected value, quoted in the message for easy diffing against the
        /// config file.
        value: String,
        /// Which rule was violated (empty / too long / bad character).
        detail: String,
    },

    /// `storage = "local"` was combined with a non-empty S3-only field
    /// (`bucket`, `access_key_id`, or `secret`) — a local trial vault has no
    /// gateway to hold a credential for, so this is a contradiction, not
    /// something to silently ignore.
    #[error(
        "configuration field `{field}` is set but storage = \"local\" takes no bucket or \
         credentials; remove `{field}` or set storage = \"s3\""
    )]
    LocalStorageWithS3Field {
        /// The offending S3-only field name.
        field: &'static str,
    },

    /// `storage = "local"` with no `local_root` and no resolvable default
    /// location (`XDG_DATA_HOME` and `HOME` both unset).
    #[error(
        "storage = \"local\" needs a trial root but none could be derived (XDG_DATA_HOME and \
         HOME are both unset); set `local_root` explicitly in the config"
    )]
    UnresolvedLocalRoot,

    /// Connecting to the configured anchoring chain failed.
    #[cfg(feature = "chain")]
    #[error("could not connect to the anchoring chain at the configured ws url: {detail}")]
    ChainConnect {
        /// What went wrong connecting to the node or loading the signer.
        detail: String,
    },

    /// A numeric field is outside its valid range.
    #[error("configuration field `{field}` is out of range: {detail}")]
    OutOfRange {
        /// The offending field name.
        field: &'static str,
        /// Why the value is rejected.
        detail: String,
    },

    /// More than one profile is (effectively) the catch-all, so an unmatched repo
    /// cannot be routed unambiguously.
    #[error(
        "{count} profiles are catch-all (empty `orgs` or `catch_all = true`); at most \
         one may be — give the others an `orgs` filter"
    )]
    MultipleCatchAll {
        /// How many catch-all profiles were found.
        count: usize,
    },

    /// An `orgs` pattern is a shape the resolver matches verbatim and so could
    /// never bind a real remote to — a URL scheme, `git@` userinfo, a `.git`
    /// suffix, or the wrong number of `/`-segments. Left unvalidated it misroutes
    /// silently (the repo falls through to the catch-all), so it is rejected at load
    /// with the corrected form named in `reason`.
    #[error("org pattern `{pattern}` is malformed: {reason}")]
    MalformedOrg {
        /// The offending pattern, exactly as written in config.
        pattern: String,
        /// What is wrong, and the `host/org` form to use instead.
        reason: String,
    },

    /// Two profiles claim the same `orgs` pattern; first-match-wins would make the
    /// later one dead, silently misrouting its repos.
    #[error(
        "org pattern `{pattern}` is claimed by more than one profile; first-match-wins \
         would make the later profile dead — give each org to exactly one profile"
    )]
    DuplicateOrg {
        /// The doubly-claimed org pattern, normalized (trimmed, lowercased).
        pattern: String,
    },

    /// `semantic_embeddings` was requested but the embedding model could not be
    /// loaded (only reachable under the `embeddings` feature).
    #[cfg(feature = "embeddings")]
    #[error("could not load the semantic embedding model: {detail}")]
    Embedder {
        /// What went wrong loading the model (download or ONNX init failure).
        detail: String,
    },

    /// The TOML document was malformed.
    #[error("could not parse configuration TOML: {0}")]
    Toml(TomlParseError),

    /// The configuration file existed but could not be read.
    #[error("could not read configuration file")]
    Io(#[from] std::io::Error),
}

/// Span- and value-free capture of a [`toml::de::Error`], taken at
/// conversion time.
///
/// The toml error itself is deliberately NOT stored (no `#[from]`, no
/// `source()`): once toml has the input attached, its span rendering quotes
/// the offending SOURCE LINE, and the documents this type parses carry live
/// secrets (`secret`, `team_key_hex`) — so any surface that renders the error
/// chain (anyhow's `{:?}` in `main`, `{:#}` contexts, `serve`/`doctor`
/// stderr) would echo a malformed `secret = "..."` line verbatim. Nor is
/// `message()` alone safe: serde type errors embed the document VALUE
/// (`invalid type: string "SECRET", expected u64`), so the message is
/// scrubbed of value payloads too (see [`scrub_value_payload`]). Capturing
/// the scrubbed message and the byte position here makes that sanitization
/// structural: no call site can forget it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TomlParseError {
    /// The parser's span-free, value-free diagnosis (e.g. ``unknown field
    /// `x` `` or `value has the wrong type, expected u64`).
    message: String,
    /// Byte range of the offending region in the source document. A position
    /// is safe to echo; the source text at that position is not.
    span: Option<std::ops::Range<usize>>,
}

impl fmt::Display for TomlParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(span) = &self.span {
            write!(f, " (at bytes {}..{})", span.start, span.end)?;
        }
        Ok(())
    }
}

// Manual `From` (rather than thiserror's `#[from]`) so `?` keeps working at
// every parse site while the secret-bearing `toml::de::Error` never enters
// the error value at all.
impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self {
        Self::Toml(TomlParseError {
            message: scrub_value_payload(err.message()),
            span: err.span(),
        })
    }
}

/// Drop the document-value payload from serde's `invalid type:` / `invalid
/// value:` messages, keeping only the schema-side expectation.
///
/// serde renders these as `invalid type: {unexpected}, expected {expected}`
/// where `{unexpected}` embeds the DOCUMENT VALUE — a string value renders in
/// double quotes (`string "SECRET"`), bool/int/char values in backticks — so
/// `message()` alone is not value-free: a secret pasted into a wrong-typed
/// field (`max_epoch = "SECRET"`) survives into every rendering. Everything
/// between the prefix and the LAST `, expected ` is dropped (`rfind`, so a
/// value containing `", expected "` cannot smuggle a fragment of itself into
/// the kept tail); `{expected}` is the visitor's own expectation text
/// (`u64`, `a boolean`) and never document content. Field NAMES in other
/// serde messages (``unknown field `x` ``) are schema words, not values, and
/// pass through untouched — as do toml's syntax messages (``invalid basic
/// string, expected `"` ``), which share the `, expected` tail but not the
/// `invalid type:` / `invalid value:` prefix.
pub(crate) fn scrub_value_payload(message: &str) -> String {
    const SHAPES: [(&str, &str); 2] = [
        ("invalid type: ", "value has the wrong type"),
        ("invalid value: ", "value is invalid"),
    ];
    const EXPECTED: &str = ", expected ";
    for (prefix, replacement) in SHAPES {
        let Some(rest) = message.strip_prefix(prefix) else {
            continue;
        };
        return match rest.rfind(EXPECTED) {
            Some(pos) => {
                let expectation = &rest[pos + EXPECTED.len()..];
                format!("{replacement}{EXPECTED}{expectation}")
            }
            // No expectation tail: keep nothing of the payload.
            None => replacement.to_owned(),
        };
    }
    message.to_owned()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert on hand-built fixtures where construction cannot fail"
    )]
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
    )]

    use super::{Config, ConfigError, StorageBackend, TeamProfile, VaultLockAttempt};
    use hippius_mem_core::{BlobStore, NoteType, RememberInput, RepoScope, Signer, verify};
    // Only the offline `build_store_uses_fs_backend_for_local_profiles` test
    // below needs this one; the round-trip imports above are shared with the
    // live `build_store_round_trips_a_note_through_a_live_s3_bucket`, which is
    // not feature-gated.
    #[cfg(not(feature = "embeddings"))]
    use hippius_mem_core::FsBlobStore;
    use proptest::prelude::*;

    /// Guardrail against the recurring config-table drift: every
    /// `HIPPIUS_MEM_*` key this file reads must have a row in
    /// the Configuration table, which lives in `docs/REFERENCE.md` since the
    /// README was split into a landing page + reference docs (PR #56). Adding a
    /// config knob without documenting it fails HERE at `cargo test`, rather
    /// than shipping an undocumented key (the 2026-07-12 doc audit found three
    /// such gaps). Both files are `include_str!`'d at compile time, so the
    /// check is hermetic — no runtime I/O, no dependence on the working
    /// directory. Only compiled under `#[test]`, so a `cargo install` that
    /// lacks the sibling docs tree is unaffected.
    ///
    /// TWO needles, because two reading styles exist here and only one used to be
    /// scanned. [`Config::apply_overrides`] reads through `lookup("...")`, but the
    /// path helpers at the top of this file read `std::env::var_os("...")`
    /// directly — which is how `HIPPIUS_MEM_STATE_DIR` (the head-watermark state
    /// directory, named as the remedy on every `head_regressions` surface) and
    /// `HIPPIUS_MEM_CACHE_DIR` shipped undocumented while this test passed.
    /// `std::env::var("...")` is deliberately NOT scanned: the only such reads in
    /// this file are the `HIPPIUS_MEM_TEST_*` fixtures in this very module, which
    /// are a test harness input rather than a config knob and have no place in the
    /// user-facing table.
    #[test]
    fn every_config_env_key_is_documented_in_the_reference() {
        // This source file (holds both the `lookup(...)` and the `var_os(...)` env
        // reads) and the reference doc holding the Configuration table, both
        // embedded at build time. `../../` climbs `src/` then the crate dir to the
        // workspace root.
        let config_src = include_str!("config.rs");
        let reference = include_str!("../../docs/REFERENCE.md");

        // The scan needles are assembled from pieces so this test's own text cannot
        // self-match — only the real call sites are counted.
        let mut keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for open in [concat!("lookup", "(\""), concat!("var_os", "(\"")] {
            let mut rest = config_src;
            while let Some(pos) = rest.find(open) {
                rest = &rest[pos + open.len()..];
                let Some(end) = rest.find('"') else { break };
                let key = &rest[..end];
                // Capture the whole key up to the closing quote — including digits, so
                // `HIPPIUS_MEM_S3_ENDPOINT` / `_FOUNDER_SS58` are not silently missed.
                // The `HIPPIUS_MEM_` filter also drops the `XDG_*`/`HOME` fallbacks
                // the `var_os` needle sees, which are not this product's knobs.
                if key.starts_with("HIPPIUS_MEM_") {
                    keys.insert(key);
                }
            }
        }

        // Sanity floor: if the scan finds far fewer than the known set, the needle
        // broke — fail loudly rather than pass a vacuous empty check.
        assert!(
            keys.len() >= 10,
            "config env-key scan found only {} keys ({keys:?}); the needle likely broke",
            keys.len()
        );

        let undocumented: Vec<&str> = keys
            .iter()
            .copied()
            .filter(|key| !reference.contains(key))
            .collect();
        assert!(
            undocumented.is_empty(),
            "these env vars are read by Config::apply_overrides but have no \
             docs/REFERENCE.md Configuration-table row — add a row for each: {undocumented:?}"
        );
    }

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
    fn rejects_team_outside_the_object_key_alphabet() {
        // Before this fix, `team = "acme/mem"` (or spaces, or unicode) passed
        // `Config::validate` and `doctor`, then failed every `remember`/`sync` at
        // runtime with an opaque `MemError::Malformed` from `objkey::object_key` —
        // finding [14]. It must now fail at load time with a config error naming
        // the field.
        for bad_team in ["acme/mem", "has spaces", "caf\u{e9}", "a.b", ""] {
            let toml =
                valid_toml().replace("team = \"ourovoros\"", &format!("team = \"{bad_team}\""));
            let err = Config::from_toml_str(&toml)
                .expect_err(&format!("team {bad_team:?} must be rejected"));
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidName { field: "team", .. }
                        | ConfigError::MissingField { field: "team" }
                ),
                "expected InvalidName(team) or MissingField(team) for {bad_team:?}, got {err:?}"
            );
        }
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
        let signer = cfg
            .primary_profile()
            .signer()
            .expect("valid seed yields a signer");
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
    fn manifest_marker_is_wired_only_with_a_source_dir() {
        // A durable manifest marker is placed in the config directory, so it is
        // wired only when the config came from a file (source_dir is set) — an
        // in-memory/overlay config (tests) gets none and keeps the in-memory guard.
        let mut cfg = Config {
            team: "team".to_owned(),
            ..Config::default()
        };
        assert!(
            cfg.manifest_marker("team").is_none(),
            "no source_dir means no durable marker"
        );
        cfg.source_dir = Some(std::path::PathBuf::from("/tmp"));
        assert!(
            cfg.manifest_marker("team").is_some(),
            "a source_dir wires the durable marker"
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
    fn defaults_max_epoch_to_zero() {
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert_eq!(
            cfg.max_epoch, 0,
            "absent max_epoch defaults to the founding epoch"
        );
    }

    #[test]
    fn max_epoch_env_override_wins() {
        let lookup = |key: &str| match key {
            "HIPPIUS_MEM_MAX_EPOCH" => Some("3".to_owned()),
            _ => None,
        };
        let cfg = Config::from_sources(Some(&valid_toml()), lookup).expect("overlay validates");
        assert_eq!(cfg.max_epoch, 3, "env override sets the bootstrap ceiling");
    }

    #[test]
    fn malformed_max_epoch_env_is_ignored() {
        let lookup = |key: &str| match key {
            "HIPPIUS_MEM_MAX_EPOCH" => Some("not-a-number".to_owned()),
            _ => None,
        };
        let cfg = Config::from_sources(Some(&valid_toml()), lookup).expect("overlay validates");
        assert_eq!(
            cfg.max_epoch, 0,
            "a malformed override leaves the default in place"
        );
    }

    #[test]
    fn parses_explicit_anchor_threshold() {
        let toml = format!("{}anchor_threshold = 4\n", valid_toml());
        let cfg = Config::from_toml_str(&toml).expect("valid config parses");
        assert_eq!(cfg.anchor_threshold, 4);
    }

    #[test]
    fn rejects_zero_anchor_threshold() {
        // binary-2: 0 would anchor every op as its own batch.
        let toml = format!("{}anchor_threshold = 0\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("zero threshold is rejected");
        assert!(matches!(
            err,
            ConfigError::OutOfRange {
                field: "anchor_threshold",
                ..
            }
        ));
    }

    #[test]
    fn rejects_out_of_range_max_epoch() {
        // binary-1: an unbounded max_epoch is a startup DoS (one S3 GET per epoch).
        let lookup = |key: &str| match key {
            "HIPPIUS_MEM_MAX_EPOCH" => Some((super::MAX_BOOTSTRAP_EPOCH + 1).to_string()),
            _ => None,
        };
        let err = Config::from_sources(Some(&valid_toml()), lookup)
            .expect_err("an over-large max_epoch is rejected");
        assert!(matches!(
            err,
            ConfigError::OutOfRange {
                field: "max_epoch",
                ..
            }
        ));
    }

    #[test]
    fn rejects_unknown_field() {
        // deny_unknown_fields: a typo'd key must be a parse error, not silently
        // ignored — otherwise a misconfiguration looks applied when it was dropped.
        let toml = format!("{}ancho_threshold = 4\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("an unknown field is rejected");
        assert!(
            matches!(err, ConfigError::Toml(_)),
            "expected a Toml parse error, got {err:?}"
        );
        // The payload is captured span-free AND value-scrubbed at conversion
        // (see `scrub_value_payload`), so not even Debug can reach the
        // document's secret values.
        let rendered = format!("{err} / {err:?}");
        assert!(
            !rendered.contains(SECRET),
            "a parse error must never carry document content: {rendered}"
        );
    }

    #[test]
    fn wrong_typed_field_error_never_echoes_the_value() {
        // Reviewer-demonstrated leak (PR #65): serde type errors embed the
        // DOCUMENT VALUE in `message()` itself — `max_epoch = "SECRET"` renders
        // as `invalid type: string "SECRET", expected u64` — so span-freedom
        // alone is not value-freedom. A secret pasted into any wrong-typed
        // field (max_epoch: u64, anchor_threshold: usize, semantic_embeddings /
        // catch_all: bool) must still never survive into any rendering.
        let toml = format!("{}max_epoch = \"WRONGFIELDSENTINEL\"\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("a wrong-typed field is rejected");
        for rendering in [format!("{err}"), format!("{err:?}")] {
            assert!(
                !rendering.contains("WRONGFIELDSENTINEL"),
                "the mistyped value must never be echoed: {rendering}"
            );
        }
        let chain = anyhow::Error::new(err).context(
            "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
        );
        for rendering in [format!("{chain:#}"), format!("{chain:?}")] {
            assert!(
                !rendering.contains("WRONGFIELDSENTINEL"),
                "the mistyped value must never be echoed in the chain: {rendering}"
            );
        }
    }

    #[test]
    fn scrub_drops_value_payloads_but_keeps_schema_messages() {
        // The two serde shapes that embed the document value are rewritten to
        // expectation-only text…
        assert_eq!(
            super::scrub_value_payload("invalid type: string \"SECRET\", expected u64"),
            "value has the wrong type, expected u64"
        );
        assert_eq!(
            super::scrub_value_payload(
                "invalid value: integer `-5`, expected a nonnegative integer"
            ),
            "value is invalid, expected a nonnegative integer"
        );
        // …a value containing the `, expected ` separator cannot smuggle a
        // fragment of itself into the kept tail (rfind takes the LAST one)…
        let smuggler = format!(
            "invalid type: string {:?}, expected u64",
            "A, expected u64, B"
        );
        assert_eq!(
            super::scrub_value_payload(&smuggler),
            "value has the wrong type, expected u64"
        );
        // …while schema-side messages pass through untouched: field names are
        // backticked schema words, and toml's syntax messages share the
        // `, expected` tail but not the value-bearing prefix.
        for schema_message in [
            "unknown field `nme`, expected one of `bucket`, `team`",
            "invalid basic string, expected `\"`",
            "missing field `bucket`",
        ] {
            assert_eq!(super::scrub_value_payload(schema_message), schema_message);
        }
    }

    #[test]
    fn broken_config_error_chain_never_echoes_the_secret() {
        // The previously-unprotected surface: `serve`/`doctor`/bare `join` load
        // via `Config::from_env_and_file`, which reads the file and funnels its
        // text through `from_sources`; `main` then renders the anyhow chain
        // with `{:?}`. Before the span-free payload, `ConfigError::Toml`'s
        // `source()` was the toml error, whose span rendering quotes the
        // offending line — here an unterminated `secret = "...` string.
        // `from_sources` is the seam under test because `from_env_and_file*`
        // reads the real `HIPPIUS_MEM_CONFIG` env var, which tests must not
        // depend on.
        let text = "bucket = \"b\"\nteam = \"t\"\nsecret = \"SERVEPATHSENTINEL789\n";
        let err =
            Config::from_sources(Some(text), |_| None).expect_err("an unterminated string fails");
        let chain = anyhow::Error::new(err).context(
            "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
        );
        for rendering in [format!("{chain:#}"), format!("{chain:?}")] {
            assert!(
                !rendering.contains("SERVEPATHSENTINEL789"),
                "the secret must never be echoed: {rendering}"
            );
        }
    }

    #[test]
    fn rejects_empty_s3_endpoint() {
        // An explicit empty endpoint must be caught at config time, not at the
        // first gateway call.
        let toml = format!("{}s3_endpoint = \"\"\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("empty s3_endpoint is rejected");
        assert!(
            matches!(err, ConfigError::MissingField { field } if field == "s3_endpoint"),
            "expected MissingField(s3_endpoint), got {err:?}"
        );
    }

    #[test]
    fn rejects_empty_s3_region() {
        let toml = format!("{}s3_region = \"\"\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("empty s3_region is rejected");
        assert!(
            matches!(err, ConfigError::MissingField { field } if field == "s3_region"),
            "expected MissingField(s3_region), got {err:?}"
        );
    }

    #[test]
    fn invalid_seed_detail_omits_offending_char() {
        // Secret hygiene, symmetric with the team-key path: a non-hex SECRET seed
        // must not leak the offending character or position into the error.
        let non_hex = format!("zz{}", &VALID_SEED[2..]);
        let toml = valid_toml().replace(VALID_SEED, &non_hex);
        let err = Config::from_toml_str(&toml).expect_err("non-hex seed is rejected");
        let rendered = err.to_string();
        assert!(
            !rendered.contains('z') && !rendered.contains("position"),
            "the error leaked secret-hex detail: {rendered}"
        );
    }

    #[test]
    fn invalid_key_detail_omits_offending_char() {
        // Secret hygiene: a non-hex SECRET must not leak the offending character or
        // position (which the hex crate's message includes) into the error.
        let non_hex = format!("zz{}", &VALID_KEY[2..]);
        let toml = valid_toml().replace(VALID_KEY, &non_hex);
        let err = Config::from_toml_str(&toml).expect_err("non-hex key is rejected");
        let rendered = err.to_string();
        assert!(
            !rendered.contains('z') && !rendered.contains("position"),
            "the error leaked secret-hex detail: {rendered}"
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

    #[test]
    fn founder_defaults_to_none() {
        // Unpinned is the default: backward-compatible trust-on-genesis.
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert!(
            cfg.founder().expect("absent founder is valid").is_none(),
            "an absent founder_ss58 yields None (unpinned)"
        );
    }

    #[test]
    fn valid_hippius_founder_is_accepted() {
        // A real Hippius SS58 — the author the config's own seed derives — must
        // pass full validation (structure + checksum + Hippius prefix) and round
        // trip through `founder()`.
        let base = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        let address = base
            .primary_profile()
            .signer()
            .expect("valid seed yields a signer")
            .author_ss58();
        let toml = format!("{}founder_ss58 = \"{}\"\n", valid_toml(), address.as_str());
        let cfg = Config::from_toml_str(&toml).expect("a valid Hippius founder is accepted");
        assert_eq!(
            cfg.founder()
                .expect("valid founder")
                .map(|f| f.as_str().to_owned()),
            Some(address.as_str().to_owned()),
            "the pinned founder round-trips through founder()"
        );
    }

    #[test]
    fn default_semantic_embeddings_tracks_the_feature() {
        // Default ON in a feature build (the model is compiled in, so use it),
        // OFF in a lean build (lexical, no model). This mirrors `cfg!` so the
        // test stays correct under both feature configurations.
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert_eq!(
            cfg.semantic_embeddings,
            cfg!(feature = "embeddings"),
            "absent semantic_embeddings should follow the compiled feature"
        );
    }

    #[test]
    fn parses_explicit_semantic_embeddings() {
        let toml = format!("{}semantic_embeddings = true\n", valid_toml());
        let cfg = Config::from_toml_str(&toml).expect("valid config parses");
        assert!(cfg.semantic_embeddings, "explicit true is honoured");
    }

    #[test]
    fn semantic_embeddings_env_override_truthy_wins() {
        // The file leaves it default (false); a truthy env override flips it on.
        let lookup = |key: &str| match key {
            "HIPPIUS_MEM_SEMANTIC_EMBEDDINGS" => Some("yes".to_owned()),
            _ => None,
        };
        let cfg = Config::from_sources(Some(&valid_toml()), lookup).expect("overlay validates");
        assert!(cfg.semantic_embeddings, "a truthy env override enables it");
    }

    #[test]
    fn unrecognized_semantic_embeddings_env_keeps_default() {
        // A typo'd value must not silently flip the setting either way: the
        // file/default value (true here) is kept and the override is ignored.
        let toml = format!("{}semantic_embeddings = true\n", valid_toml());
        let lookup = |key: &str| match key {
            "HIPPIUS_MEM_SEMANTIC_EMBEDDINGS" => Some("maybe".to_owned()),
            _ => None,
        };
        let cfg = Config::from_sources(Some(&toml), lookup).expect("overlay validates");
        assert!(
            cfg.semantic_embeddings,
            "an unrecognized override leaves the file value in place"
        );
    }

    #[test]
    fn defaults_embedding_model_and_floor_to_none() {
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert!(
            cfg.embedding_model.is_none(),
            "model defaults to the model's own choice"
        );
        assert!(
            cfg.relevance_floor.is_none(),
            "floor defaults to the model's calibrated value"
        );
    }

    #[test]
    fn parses_embedding_model_and_relevance_floor() {
        let toml = format!(
            "{}embedding_model = \"bge-small\"\nrelevance_floor = 0.4\n",
            valid_toml()
        );
        let cfg = Config::from_toml_str(&toml).expect("valid config parses");
        assert_eq!(cfg.embedding_model.as_deref(), Some("bge-small"));
        assert_eq!(cfg.relevance_floor, Some(0.4));
    }

    #[test]
    fn rejects_out_of_range_relevance_floor() {
        // A cosine floor above 1.0 would reject every possible match — catch it now.
        let toml = format!("{}relevance_floor = 1.5\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("an out-of-range floor is rejected");
        assert!(
            matches!(
                err,
                ConfigError::OutOfRange {
                    field: "relevance_floor",
                    ..
                }
            ),
            "expected OutOfRange(relevance_floor), got {err:?}"
        );
    }

    #[test]
    fn relevance_floor_env_override_wins() {
        let lookup = |key: &str| match key {
            "HIPPIUS_MEM_RELEVANCE_FLOOR" => Some("0.2".to_owned()),
            _ => None,
        };
        let cfg = Config::from_sources(Some(&valid_toml()), lookup).expect("overlay validates");
        assert_eq!(cfg.relevance_floor, Some(0.2));
    }

    // Without the `embeddings` feature, a config that asks for semantic recall
    // must still build a store — falling back to the lexical embedder rather than
    // failing. With the feature on, build_embedder would download the model, so
    // this offline-deterministic assertion is scoped to the default build.
    #[cfg(not(feature = "embeddings"))]
    #[tokio::test]
    async fn build_store_falls_back_to_lexical_without_feature() {
        let toml = format!("{}semantic_embeddings = true\n", valid_toml());
        let cfg = Config::from_toml_str(&toml).expect("valid config parses");
        assert!(
            cfg.build_store().await.is_ok(),
            "semantic_embeddings without the feature must fall back, not fail"
        );
    }

    #[test]
    fn malformed_founder_is_rejected_at_config_time() {
        // A founder that is not a structurally valid SS58 (wrong length / non-base58)
        // must be caught by `validate`, not deferred to the first sync.
        for bad in ["not-a-valid-ss58", "5555", &"5".repeat(60)] {
            let toml = format!("{}founder_ss58 = \"{bad}\"\n", valid_toml());
            let err =
                Config::from_toml_str(&toml).expect_err("a malformed founder must be rejected");
            assert!(
                matches!(err, ConfigError::InvalidFounder { .. }),
                "expected InvalidFounder for {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn founder_with_valid_shape_but_bad_checksum_is_rejected() {
        // F3: a founder that IS a structurally valid SS58 (right length, base58
        // alphabet) but whose checksum is corrupted must be rejected by the config
        // trust anchor — exercising `ss58_decode`'s checksum guard, which the
        // wrong-length fixtures above trip before ever reaching.
        let base = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        let valid = base
            .primary_profile()
            .signer()
            .expect("valid seed yields a signer")
            .author_ss58();
        let valid = valid.as_str();

        // Flip one base58 char in the pubkey region: the body changes so the stored
        // checksum no longer matches, while length + alphabet stay valid so the
        // string reaches the checksum check rather than the length guard.
        let mut chars: Vec<char> = valid.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();
        assert_eq!(
            corrupted.len(),
            valid.len(),
            "same length as the valid address"
        );
        assert_ne!(corrupted, valid, "exactly one character differs");

        let toml = format!("{}founder_ss58 = \"{corrupted}\"\n", valid_toml());
        let err = Config::from_toml_str(&toml)
            .expect_err("a valid-shape bad-checksum founder must be rejected");
        assert!(
            matches!(err, ConfigError::InvalidFounder { .. }),
            "expected InvalidFounder for a bad checksum, got {err:?}"
        );
    }

    // A `[[teams]]` block with `name`, the given `extra` routing lines, and valid
    // credentials — the building block for the multi-profile tests below.
    fn team_block(name: &str, extra: &str) -> String {
        format!(
            "\n[[teams]]\n\
             name = \"{name}\"\n\
             {extra}\
             bucket = \"{name}-mem\"\n\
             access_key_id = \"AK-{name}\"\n\
             secret = \"{SECRET}\"\n\
             team_key_hex = \"{VALID_KEY}\"\n\
             author_seed_hex = \"{VALID_SEED}\"\n"
        )
    }

    #[test]
    fn flat_config_is_a_single_catch_all_profile() {
        // Backward compatibility: a flat config (no orgs, no teams) is one profile
        // that catches every repo, keyed by the flat `team` as its namespace.
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        let all = cfg.all_profiles();
        assert_eq!(all.len(), 1, "a flat config yields exactly one profile");
        assert!(
            all[0].catch_all,
            "the sole profile catches every repo (unchanged behavior)"
        );
        assert_eq!(
            all[0].name, "ourovoros",
            "namespace is the flat `team` value, so object keys are unchanged"
        );
    }

    #[test]
    fn parses_additional_team_profiles_in_order() {
        let toml = format!(
            "{}{}",
            valid_toml(),
            team_block("clientx", "orgs = [\"github.com/clientx\"]\n")
        );
        let cfg = Config::from_toml_str(&toml).expect("multi-profile config parses");
        assert_eq!(cfg.teams.len(), 1, "one additional profile");
        let all = cfg.all_profiles();
        assert_eq!(all.len(), 2, "primary + one additional, in order");
        assert_eq!(all[0].name, "ourovoros", "primary first (the tie-break)");
        assert!(
            all[0].catch_all,
            "primary with no orgs is the effective catch-all"
        );
        assert_eq!(all[1].name, "clientx");
        assert!(
            !all[1].catch_all,
            "an org-routed profile is not the catch-all"
        );
    }

    #[test]
    fn all_profiles_route_by_git_remote() {
        // End-to-end wiring: all_profiles() feeds the resolver, which selects by the
        // repo's remote — the clientx org to clientx, everything else to the primary.
        let toml = format!(
            "{}{}",
            valid_toml(),
            team_block("clientx", "orgs = [\"github.com/clientx\"]\n")
        );
        let cfg = Config::from_toml_str(&toml).expect("parses");
        let profiles = cfg.all_profiles();
        let in_client = crate::resolver::resolve(&profiles, Some("git@github.com:clientx/app.git"));
        assert!(
            matches!(in_client, crate::resolver::Resolution::Bound(p) if p.name == "clientx"),
            "a clientx repo routes to the clientx profile"
        );
        let elsewhere =
            crate::resolver::resolve(&profiles, Some("git@github.com:someoneelse/x.git"));
        assert!(
            matches!(elsewhere, crate::resolver::Resolution::Bound(p) if p.name == "ourovoros"),
            "an unmatched repo falls back to the primary catch-all"
        );
    }

    #[test]
    fn rejects_two_catch_all_profiles() {
        // The primary (no orgs) is a catch-all; an explicit catch_all profile makes
        // two, so routing an unmatched repo would be ambiguous.
        let toml = format!(
            "{}{}",
            valid_toml(),
            team_block("personal", "catch_all = true\n")
        );
        let err = Config::from_toml_str(&toml).expect_err("two catch-alls are rejected");
        assert!(
            matches!(err, ConfigError::MultipleCatchAll { count } if count == 2),
            "expected MultipleCatchAll(2), got {err:?}"
        );
    }

    #[test]
    fn rejects_additional_profile_with_bad_key() {
        // Per-profile validation: a malformed key in an additional profile is caught
        // at config time, exactly as it is for the primary's flat fields.
        let block = team_block("clientx", "orgs = [\"github.com/clientx\"]\n")
            .replace(VALID_KEY, "00112233aa");
        let toml = format!("{}{block}", valid_toml());
        let err = Config::from_toml_str(&toml)
            .expect_err("a bad key in an additional profile is rejected");
        assert!(
            matches!(err, ConfigError::InvalidKey { .. }),
            "expected InvalidKey, got {err:?}"
        );
    }

    #[test]
    fn rejects_additional_profile_with_invalid_name_charset() {
        // Same object-key charset rule as the primary's `team` field (see
        // `rejects_team_outside_the_object_key_alphabet`), applied to a `[[teams]]`
        // profile's `name` — finding [14].
        let block = team_block("acme/mem", "orgs = [\"github.com/acme\"]\n");
        let toml = format!("{}{block}", valid_toml());
        let err = Config::from_toml_str(&toml)
            .expect_err("a name outside the object-key alphabet is rejected");
        assert!(
            matches!(err, ConfigError::InvalidName { field: "name", .. }),
            "expected InvalidName(name), got {err:?}"
        );
    }

    #[test]
    fn validate_namespace_fixtures() {
        // Direct unit coverage of the three rules, independent of TOML plumbing.
        assert!(super::validate_namespace("ourovoros", "team").is_ok());
        assert!(super::validate_namespace("Team_9-x", "team").is_ok());
        assert!(matches!(
            super::validate_namespace("", "team"),
            Err(ConfigError::InvalidName { field: "team", .. })
        ));
        assert!(matches!(
            super::validate_namespace("has space", "team"),
            Err(ConfigError::InvalidName { field: "team", .. })
        ));
        assert!(matches!(
            super::validate_namespace("a/b", "team"),
            Err(ConfigError::InvalidName { field: "team", .. })
        ));
        // 256 bytes is the boundary and accepted; 257 is rejected.
        assert!(super::validate_namespace(&"a".repeat(256), "team").is_ok());
        assert!(matches!(
            super::validate_namespace(&"a".repeat(257), "team"),
            Err(ConfigError::InvalidName { field: "team", .. })
        ));
    }

    #[test]
    fn rejects_unknown_field_in_a_profile() {
        // deny_unknown_fields on TeamProfile: a typo'd profile key is a parse error.
        let block = team_block("clientx", "nme = \"typo\"\n");
        let toml = format!("{}{block}", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("an unknown profile field is rejected");
        assert!(
            matches!(err, ConfigError::Toml(_)),
            "expected a Toml parse error, got {err:?}"
        );
        // The payload is captured span-free AND value-scrubbed at conversion
        // (see `scrub_value_payload`), so not even Debug can reach the
        // document's secret values.
        let rendered = format!("{err} / {err:?}");
        assert!(
            !rendered.contains(SECRET),
            "a parse error must never carry document content: {rendered}"
        );
    }

    #[test]
    fn rejects_duplicate_org_across_profiles() {
        // The primary claims github.com/acme and an additional team claims it too;
        // first-match-wins would make the additional team dead, so it is rejected.
        let toml = format!(
            "{}orgs = [\"github.com/acme\"]\n{}",
            valid_toml(),
            team_block("clientx", "orgs = [\"github.com/acme\"]\n")
        );
        let err =
            Config::from_toml_str(&toml).expect_err("a duplicate org across profiles is rejected");
        assert!(
            matches!(err, ConfigError::DuplicateOrg { ref pattern } if pattern == "github.com/acme"),
            "expected DuplicateOrg(github.com/acme), got {err:?}"
        );
    }

    #[test]
    fn rejects_org_pattern_with_url_scheme() {
        // The 2026-07 "service error" incident: `orgs` was pasted as a browser URL,
        // so the verbatim resolver matched no remote and the repo silently fell
        // through to the (separately mis-secreted) catch-all. Reject it at load.
        let toml = format!("{}orgs = [\"https://github.com/acme\"]\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("a URL-form org is rejected");
        assert!(
            matches!(err, ConfigError::MalformedOrg { ref pattern, .. } if pattern == "https://github.com/acme"),
            "expected MalformedOrg for a URL, got {err:?}"
        );
        // The message must name the corrected bare form so the fix is copy-pasteable.
        assert!(
            err.to_string().contains("github.com/acme"),
            "error should suggest the bare host/org form: {err}"
        );
    }

    #[test]
    fn rejects_org_pattern_with_clone_userinfo() {
        // A copied `git@host:org/repo.git` clone address carries userinfo and a
        // `.git` suffix — both shapes the resolver never matches.
        let block = team_block("clientx", "orgs = [\"git@github.com:clientx/app.git\"]\n");
        let toml = format!("{}{block}", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("an scp clone address is rejected");
        assert!(
            matches!(err, ConfigError::MalformedOrg { .. }),
            "expected MalformedOrg for a clone address, got {err:?}"
        );
    }

    #[test]
    fn rejects_org_pattern_with_git_suffix() {
        let toml = format!("{}orgs = [\"github.com/acme/app.git\"]\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("a .git suffix is rejected");
        assert!(
            matches!(err, ConfigError::MalformedOrg { .. }),
            "expected MalformedOrg for a .git suffix, got {err:?}"
        );
    }

    #[test]
    fn rejects_org_pattern_with_wrong_segment_count() {
        // Four segments is too specific for `host/org/repo`; one is missing the org.
        for bad in ["github.com/acme/app/extra", "github.com"] {
            let toml = format!("{}orgs = [\"{bad}\"]\n", valid_toml());
            let err = Config::from_toml_str(&toml).expect_err("a wrong-arity org is rejected");
            assert!(
                matches!(err, ConfigError::MalformedOrg { .. }),
                "expected MalformedOrg for `{bad}`, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_org_pattern_with_host_port() {
        // A `:port` belongs to the remote URL, not the routing key — normalize_remote
        // strips it, so a port in the pattern would silently match nothing.
        let toml = format!("{}orgs = [\"github.com:22/acme\"]\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("a host port is rejected");
        assert!(
            matches!(err, ConfigError::MalformedOrg { .. }),
            "expected MalformedOrg for a host port, got {err:?}"
        );
    }

    #[test]
    fn rejects_org_pattern_with_empty_segment() {
        // A leading or doubled slash yields an empty segment that matches() compares
        // literally and never binds — it would silently fall through to the catch-all.
        for bad in ["/github.com/acme", "github.com//acme"] {
            let toml = format!("{}orgs = [\"{bad}\"]\n", valid_toml());
            let err = Config::from_toml_str(&toml).expect_err("an empty segment is rejected");
            assert!(
                matches!(err, ConfigError::MalformedOrg { .. }),
                "expected MalformedOrg for `{bad}`, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_org_pattern_with_single_char_host() {
        // normalize_remote rejects a host under 2 chars (a drive letter like `C:`),
        // so a 1-char host in a pattern never binds.
        let toml = format!("{}orgs = [\"a/org\"]\n", valid_toml());
        let err = Config::from_toml_str(&toml).expect_err("a 1-char host is rejected");
        assert!(
            matches!(err, ConfigError::MalformedOrg { .. }),
            "expected MalformedOrg for a 1-char host, got {err:?}"
        );
    }

    #[test]
    fn canonical_org_hint_drops_port_and_doubled_git() {
        // The hint must never suggest a form that is itself wrong: a URL `:port` is
        // dropped (not left as a fake org segment), and a doubled `.git` peels fully.
        assert_eq!(
            super::canonical_org_hint("https://github.com:8443/acme/app"),
            "github.com/acme/app"
        );
        assert_eq!(
            super::canonical_org_hint("github.com/acme/app.git.git"),
            "github.com/acme/app"
        );
    }

    #[test]
    fn accepts_canonical_org_patterns() {
        // Regression guard: the validator must not over-reject the shapes the
        // resolver actually matches — whole org and single repo, case- and
        // trailing-slash-insensitive. A primary with `orgs` is simply not the
        // catch-all; zero catch-alls is a valid (memory-off-for-unmatched) config.
        for org in [
            "github.com/acme",
            "github.com/acme/app",
            "GitHub.com/Acme/",
            "gitlab.example.com/grp/sub",
        ] {
            let toml = format!("{}orgs = [\"{org}\"]\n", valid_toml());
            assert!(
                Config::from_toml_str(&toml).is_ok(),
                "`{org}` should be accepted by the org-pattern validator"
            );
        }
    }

    proptest! {
        /// No document value survives the scrub: for ANY string value serde
        /// might report (arbitrary content, including quotes, unicode, and the
        /// `, expected ` separator itself), the scrubbed invalid-type message
        /// collapses to exactly the expectation-only form. Exact equality is
        /// the strongest possible "value absent" claim — the shrinker hunts
        /// for an escape the fixtures did not think of.
        #[test]
        fn scrub_erases_any_string_value(value in ".{0,40}") {
            let message = format!("invalid type: string {value:?}, expected u64");
            prop_assert_eq!(
                super::scrub_value_payload(&message),
                "value has the wrong type, expected u64"
            );
        }

        /// The scrub is idempotent: its outputs never re-match the
        /// value-bearing prefixes, so double-conversion cannot mangle a
        /// message (`f(f(x)) == f(x)` for arbitrary input).
        #[test]
        fn scrub_is_idempotent(message in ".{0,80}") {
            let once = super::scrub_value_payload(&message);
            prop_assert_eq!(super::scrub_value_payload(&once), once.clone());
        }

        /// `canonical_org_hint` recovers the same bare `host/org/repo` from every
        /// real remote shape a user might paste into `orgs` — the parser-agreement
        /// property, mirroring `resolver::normalize_agrees_across_url_shapes`. The
        /// charset holds no `.`/`:`/`@`/`/`, so a generated token can't fold into
        /// the scheme/userinfo/suffix stripping.
        #[test]
        fn canonical_org_hint_recovers_bare_form(
            host in "[a-z0-9]{2,8}",
            org in "[a-z0-9]{1,8}",
            repo in "[a-z0-9]{1,8}",
        ) {
            let want = format!("{host}/{org}/{repo}");
            let forms = [
                format!("https://{host}/{org}/{repo}.git"),
                format!("https://{host}:8443/{org}/{repo}"),
                format!("git@{host}:{org}/{repo}.git"),
                format!("ssh://git@{host}/{org}/{repo}"),
                want.clone(),
            ];
            for form in forms {
                prop_assert_eq!(super::canonical_org_hint(&form), want.clone(), "from {}", form);
            }
        }

        /// Validator/resolver agreement: every canonical `host/org` or
        /// `host/org/repo` the resolver can match is accepted, so a real remote's
        /// pattern is never falsely rejected. The dual of the rejection fixtures.
        #[test]
        fn validator_accepts_canonical_forms(
            host in "[a-z0-9]{2,8}",
            org in "[a-z0-9]{1,8}",
            repo in proptest::option::of("[a-z0-9]{1,8}"),
        ) {
            let pattern = match &repo {
                Some(repo) => format!("{host}.com/{org}/{repo}"),
                None => format!("{host}.com/{org}"),
            };
            prop_assert!(
                super::validate_org_pattern(&pattern).is_ok(),
                "canonical pattern falsely rejected: {}",
                pattern
            );
        }

        /// `validate_namespace` agrees with `objkey::validate_component`'s
        /// alphabet: any 1-256 byte string drawn entirely from `[A-Za-z0-9_-]` is
        /// accepted (mirrors `objkey::key_round_trips`'s `"[a-z0-9-]{1,20}"`
        /// generator, widened to the full allowlist `validate_namespace` mirrors).
        #[test]
        fn validate_namespace_accepts_the_object_key_alphabet(
            value in "[A-Za-z0-9_-]{1,256}",
        ) {
            prop_assert!(super::validate_namespace(&value, "team").is_ok());
        }

        /// Any value containing at least one byte outside the allowlist is
        /// rejected — the dual of the accept property above. The prefix/suffix
        /// keep the value non-empty and within the length cap so only the
        /// disallowed byte is under test.
        #[test]
        fn validate_namespace_rejects_a_disallowed_byte(
            prefix in "[A-Za-z0-9_-]{0,8}",
            bad in prop_oneof![Just('/'), Just('.'), Just(' '), Just('@'), Just('\\')],
            suffix in "[A-Za-z0-9_-]{0,8}",
        ) {
            let value = format!("{prefix}{bad}{suffix}");
            // An explicit message, not a bare `prop_assert!(matches!(...))`: proptest's
            // default failure message stringifies the condition and feeds it through
            // `format!`, and the struct-pattern `{ field: ..., .. }` braces in the
            // `matches!` arm are misread as format placeholders (`invalid format
            // string: expected `}`, found `f``) without one.
            let rejected = matches!(
                super::validate_namespace(&value, "team"),
                Err(ConfigError::InvalidName { field: "team", .. })
            );
            prop_assert!(rejected, "{value:?} should have been rejected");
        }
    }

    // Under the `embeddings` feature `build_store` would download the model; scope
    // this offline-deterministic assertion to the default lexical build.
    #[cfg(not(feature = "embeddings"))]
    #[tokio::test]
    async fn build_store_ignores_an_unrelated_bad_profile() {
        // A hand-built config (bypassing load validation) with a VALID primary and a
        // malformed additional team: building the PRIMARY's store must succeed,
        // because build_store validates only the bound profile plus shared settings.
        let mut cfg = Config::from_toml_str(&valid_toml()).expect("primary valid");
        cfg.teams = vec![TeamProfile {
            name: "clientx".to_owned(),
            orgs: vec!["github.com/clientx".to_owned()],
            catch_all: false,
            bucket: "cx".to_owned(),
            access_key_id: "AK".to_owned(),
            secret: "s".to_owned(),
            team_key_hex: "00".to_owned(), // too short — whole-config validate would reject
            author_seed_hex: VALID_SEED.to_owned(),
            founder_ss58: None,
            storage: StorageBackend::S3,
            local_root: None,
        }];
        assert!(
            cfg.primary_profile().build_store(&cfg).await.is_ok(),
            "the bound profile builds even when an unrelated profile is malformed"
        );
        assert!(
            matches!(cfg.validate(), Err(ConfigError::InvalidKey { .. })),
            "whole-config validate still catches the malformed profile at load time"
        );
    }

    #[test]
    fn require_s3_refuses_a_local_profile_and_names_the_verb_and_upgrade() {
        let profile = TeamProfile {
            name: "acme".to_owned(),
            storage: StorageBackend::Local,
            ..TeamProfile::default()
        };

        let err = super::require_s3(&profile, "join").expect_err("a local profile must be refused");
        let message = err.to_string();
        assert!(
            message.contains("team mode needs a Hippius bucket"),
            "the refusal must name why: {message}"
        );
        assert!(
            message.contains("hippius-mem upgrade"),
            "the refusal must point at the upgrade path: {message}"
        );
        assert!(
            message.contains("join") && message.contains("acme"),
            "the refusal must name the verb and the profile: {message}"
        );
    }

    #[test]
    fn require_s3_allows_an_s3_profile() {
        let profile = TeamProfile {
            name: "acme".to_owned(),
            storage: StorageBackend::S3,
            ..TeamProfile::default()
        };

        assert!(
            super::require_s3(&profile, "join").is_ok(),
            "an S3 profile must not be refused"
        );
    }

    /// `valid_toml()` with the S3 credential fields (`bucket`, `access_key_id`,
    /// `secret`) stripped out — the shape a `storage = "local"` profile takes,
    /// since a local trial vault has no gateway to hold credentials for.
    fn valid_toml_without_credentials() -> String {
        valid_toml()
            .replace("bucket = \"memories\"\n", "")
            .replace("access_key_id = \"AKID\"\n", "")
            .replace(&format!("secret = \"{SECRET}\"\n"), "")
    }

    #[test]
    fn storage_defaults_to_s3_when_absent() {
        // A minimal profile TOML with no `storage` key: absent means S3, so
        // every config written before this field existed is untouched.
        let cfg = Config::from_toml_str(&valid_toml()).expect("valid config parses");
        assert_eq!(
            cfg.primary_profile().storage,
            StorageBackend::S3,
            "an absent storage key must default to S3"
        );
    }

    #[test]
    fn local_profile_needs_no_bucket_or_credentials() {
        // storage = "local" with bucket/access_key_id/secret all empty: a local
        // trial vault has no gateway, so validation must not demand credentials
        // for one.
        let toml = format!("storage = \"local\"\n{}", valid_toml_without_credentials());
        let cfg = Config::from_toml_str(&toml)
            .expect("empty credentials must validate under storage = \"local\"");
        assert_eq!(cfg.storage, StorageBackend::Local);

        // The SAME empty fields with storage = "s3" (the default): today's
        // MissingField errors still fire — local mode does not silently relax
        // validation for an s3 profile.
        let err = Config::from_toml_str(&valid_toml_without_credentials())
            .expect_err("empty bucket must still be rejected when storage = \"s3\"");
        assert!(
            matches!(err, ConfigError::MissingField { field } if field == "bucket"),
            "expected MissingField(bucket), got {err:?}"
        );
    }

    #[test]
    fn local_profile_rejects_bucket_values() {
        // storage = "local" AND a non-empty bucket: a contradiction that must
        // be refused with a typed error naming the field, never silently
        // ignored.
        let toml = format!("storage = \"local\"\n{}", valid_toml());
        let err = Config::from_toml_str(&toml)
            .expect_err("a local profile with a bucket set must be rejected");
        assert!(
            matches!(
                err,
                ConfigError::LocalStorageWithS3Field { field: "bucket" }
            ),
            "expected LocalStorageWithS3Field(bucket), got {err:?}"
        );
    }

    // Under the `embeddings` feature `build_store` would download the model; scope
    // this offline-deterministic assertion to the default lexical build, matching
    // `build_store_ignores_an_unrelated_bad_profile` above.
    #[cfg(not(feature = "embeddings"))]
    #[tokio::test]
    async fn build_store_uses_fs_backend_for_local_profiles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let toml = format!(
            "storage = \"local\"\nlocal_root = \"{}\"\n{}",
            dir.path().display(),
            valid_toml_without_credentials()
        );
        let cfg = Config::from_toml_str(&toml).expect("local profile with a root parses");

        let store = cfg
            .build_store()
            .await
            .expect("a local profile with local_root must build a store");

        let id = store
            .remember(RememberInput {
                note_type: NoteType::Convention,
                repo: RepoScope::Repo("vault".to_owned()),
                tags: std::collections::BTreeSet::new(),
                summary: "local trial vault round-trips".to_owned(),
                body: "written to disk, not to a bucket".to_owned(),
                force: true,
            })
            .await
            .expect("remember must succeed against the local backend");
        let note = store
            .get(id)
            .await
            .expect("get must succeed against the local backend");
        assert_eq!(note.body, "written to disk, not to a bucket");

        // The round trip must have landed real files under `local_root`, not an
        // in-memory fake: a fresh FsBlobStore over the SAME directory sees them.
        let fs = FsBlobStore::new(dir.path().to_path_buf());
        let keys = fs.list("").await.expect("list must succeed");
        assert!(
            !keys.is_empty(),
            "remember/get must have written objects under local_root"
        );
    }

    /// The team namespace the live `build_store` round trip below owns.
    ///
    /// Fixed rather than per-run unique, matching
    /// `hippius-mem-core/tests/blob_contract.rs`: the run clears this prefix
    /// before AND after, so a crashed run cannot leave state that poisons the
    /// next one, and a shared bucket does not accumulate one abandoned prefix
    /// per run.
    const LIVE_TEAM: &str = "hippius-mem-buildstore-live";

    /// The live endpoint coordinates, read from the same environment contract
    /// `hippius-mem-core/tests/blob_contract.rs` and `tests/upgrade_cli.rs` use,
    /// so one `MinIO` job configures every live suite. Only the bucket has no
    /// default: a wrong guess would write into a bucket the operator did not
    /// create for this test.
    struct LiveS3 {
        endpoint: String,
        bucket: String,
        access_key_id: String,
        secret: String,
        region: String,
    }

    impl LiveS3 {
        fn from_env() -> Self {
            Self {
                endpoint: std::env::var("HIPPIUS_MEM_TEST_S3_ENDPOINT")
                    .unwrap_or_else(|_| "http://127.0.0.1:9000".to_owned()),
                bucket: std::env::var("HIPPIUS_MEM_TEST_BUCKET").expect(
                    "set HIPPIUS_MEM_TEST_BUCKET to a bucket that already exists on the endpoint",
                ),
                access_key_id: std::env::var("HIPPIUS_MEM_TEST_ACCESS_KEY_ID")
                    .unwrap_or_else(|_| "test".to_owned()),
                secret: std::env::var("HIPPIUS_MEM_TEST_SECRET")
                    .unwrap_or_else(|_| "testtest1".to_owned()),
                region: std::env::var("HIPPIUS_MEM_TEST_S3_REGION")
                    .unwrap_or_else(|_| "us-east-1".to_owned()),
            }
        }

        /// A raw [`hippius_mem_core::S3BlobStore`] over the same bucket, used
        /// only to seed the fixture and to clean up — never as the store under
        /// test, which must come from [`Config::build_store`] itself.
        fn raw_bucket(&self) -> hippius_mem_core::S3BlobStore {
            hippius_mem_core::S3BlobStore::new(
                self.endpoint.clone(),
                self.bucket.clone(),
                self.access_key_id.clone(),
                self.secret.clone(),
                self.region.clone(),
            )
        }
    }

    /// Remove every object under `team`'s prefix, so the round trip neither
    /// inherits a previous run's objects nor leaves its own behind.
    async fn clear_live_team(bucket: &dyn BlobStore, team: &str) {
        for key in bucket
            .list(&format!("{team}/"))
            .await
            .unwrap_or_else(|_| Vec::new())
        {
            let _ = bucket.delete(&key).await;
        }
    }

    /// Remove the LOCAL directories `build_store`'s S3 branch creates for
    /// `team`: the encrypted blob cache and the head-watermark state file.
    ///
    /// Located by calling the very functions the production wiring calls, so
    /// this deletes exactly what the wiring created rather than a hand-copied
    /// path that could drift. Both are per-team subdirectories, so neither
    /// removal can reach another team's state. Best-effort: an absent directory
    /// is the normal first-run case, not a failure.
    fn clear_live_team_local_state(team: &str) {
        if let Some(cache) = super::blob_cache_dir(team) {
            let _ = std::fs::remove_dir_all(cache);
        }
        if let Some(marks) = super::head_watermarks_path(team)
            && let Some(dir) = marks.parent()
        {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// Live round trip through the PRODUCTION store wiring — the
    /// [`StorageBackend::S3`] branch of [`TeamProfile::build_store`] — against a
    /// real bucket.
    ///
    /// Every other end-to-end test rebuilds an *equivalent* store by hand
    /// (`build_live_store` in `tests/upgrade_cli.rs` and `tests/report_cli.rs`)
    /// because `Config`/`TeamProfile` are private to this binary crate, so a
    /// divergence between `build_store` and that hand-wiring was invisible to
    /// the suite. This test is in-crate precisely so it can call the real thing.
    ///
    /// What the round trip covers, beyond "a note comes back":
    ///
    /// - The **pinned founder** is load-bearing here, not incidental. The bucket
    ///   is seeded with an attacker-founded genesis (version-0) manifest naming
    ///   only the attacker as a member — the takeover shape
    ///   `pinned_founder_survives_genesis_overwrite` pins at the core layer.
    ///   With the pin `build_store` wires, that manifest is ignored and the
    ///   team reads open, so this author's ops survive the membership filter.
    ///   Without it, trust-on-genesis elects the attacker and `sync` filters
    ///   this author's ops away, so the note never reaches the reader's index.
    ///   A round trip over an empty bucket would pass either way and would not
    ///   be testing the wiring at all.
    /// - The **`CachingBlobStore` wrap** the S3 branch adds (keyed by a
    ///   team-key-derived cache key) sits under both stores.
    /// - The **signed head publish** every write performs, asserted by the
    ///   `_heads/` object landing in the bucket. That wiring and the
    ///   `with_head_watermarks` attachment beside it are recent; the marks
    ///   themselves are only read by `reconcile`, so this exercises the publish
    ///   path without asserting on regression reporting.
    ///
    /// The note is read back through a SECOND `build_store` call, so it must
    /// come from the bucket via `sync` rather than from the writer's own index.
    ///
    /// `semantic_embeddings = false` keeps the store lexical in an
    /// `--features embeddings` build too, so this test never triggers a model
    /// download regardless of how it is invoked.
    #[tokio::test]
    #[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
    async fn build_store_round_trips_a_note_through_a_live_s3_bucket() {
        use std::collections::BTreeSet;

        use hippius_mem_core::{Sr25519Signer, TeamManifest, publish_manifest};

        let live = LiveS3::from_env();
        let bucket = live.raw_bucket();

        clear_live_team(&bucket, LIVE_TEAM).await;
        clear_live_team_local_state(LIVE_TEAM);

        let toml = format!(
            "s3_endpoint = \"{endpoint}\"\n\
             s3_region = \"{region}\"\n\
             bucket = \"{bucket_name}\"\n\
             access_key_id = \"{access_key_id}\"\n\
             secret = \"{secret}\"\n\
             team = \"{LIVE_TEAM}\"\n\
             team_key_hex = \"{VALID_KEY}\"\n\
             author_seed_hex = \"{VALID_SEED}\"\n\
             semantic_embeddings = false\n",
            endpoint = live.endpoint,
            region = live.region,
            bucket_name = live.bucket,
            access_key_id = live.access_key_id,
            secret = live.secret,
        );
        let mut cfg = Config::from_toml_str(&toml).expect("the live s3 profile parses");

        // Pin THIS author as the founder. Derived from the configured seed
        // rather than written as a literal, so the pin cannot drift from the
        // identity that actually signs the ops.
        let author = cfg
            .primary_profile()
            .signer()
            .expect("the configured seed yields an author identity")
            .author_ss58();
        cfg.founder_ss58 = Some(author.as_str().to_owned());

        // The seizure attempt: a genesis manifest signed by someone else, whose
        // member set excludes this author.
        let attacker =
            Sr25519Signer::from_seed_with_prefix(&[9_u8; 32], super::HIPPIUS_SS58_PREFIX)
                .expect("the attacker seed yields an identity");
        let seized =
            TeamManifest::create_signed(&attacker, LIVE_TEAM.to_owned(), BTreeSet::new(), 0);
        assert_ne!(
            seized.founder, author,
            "the fixture is only meaningful if the attacker is a different identity"
        );
        publish_manifest(&bucket, &seized)
            .await
            .expect("the attacker's genesis manifest publishes");

        let writer = cfg
            .build_store()
            .await
            .expect("the s3 profile must build a store against the live endpoint");
        let id = writer
            .remember(RememberInput {
                note_type: NoteType::Convention,
                repo: RepoScope::Repo("build-store-live".to_owned()),
                tags: BTreeSet::new(),
                summary: "build_store round-trips through a live bucket".to_owned(),
                body: "sealed by the production S3 wiring, not a hand-built store".to_owned(),
                force: true,
            })
            .await
            .expect("remember must succeed against the live bucket");

        let published_heads: Vec<String> = bucket
            .list(&format!("{LIVE_TEAM}/_heads/"))
            .await
            .expect("listing the published heads must succeed");
        assert!(
            !published_heads.is_empty(),
            "the write must have published this author's signed head pointer"
        );

        // A SECOND store from the same profile: its index starts empty, so the
        // note can only arrive through `sync` reading the bucket.
        let reader = cfg
            .build_store()
            .await
            .expect("a second store must build from the same profile");
        reader
            .sync()
            .await
            .expect("sync must read the live bucket back");
        let note = reader
            .get(id)
            .await
            .expect("the note must survive the round trip through the live bucket");
        assert_eq!(
            note.body,
            "sealed by the production S3 wiring, not a hand-built store"
        );

        clear_live_team(&bucket, LIVE_TEAM).await;
        clear_live_team_local_state(LIVE_TEAM);
    }

    #[test]
    fn team_profile_debug_redacts_secrets() {
        let toml = format!(
            "{}{}",
            valid_toml(),
            team_block("clientx", "orgs = [\"github.com/clientx\"]\n")
        );
        let cfg = Config::from_toml_str(&toml).expect("valid config parses");
        let rendered = format!("{:?}", cfg.teams[0]);
        assert!(
            !rendered.contains(SECRET),
            "profile Debug leaked the secret: {rendered}"
        );
        assert!(
            !rendered.contains(VALID_KEY),
            "profile Debug leaked the team key: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "profile Debug did not mark redaction: {rendered}"
        );
    }

    // Finding #6: upgrade must refuse to migrate a local trial vault a live
    // `serve` process is still writing to. These pin the advisory-lock
    // primitive both sides share.

    #[test]
    fn try_lock_local_vault_is_a_noop_for_an_s3_profile() {
        let profile = TeamProfile {
            name: "acme".to_owned(),
            storage: StorageBackend::S3,
            ..TeamProfile::default()
        };
        assert!(
            matches!(
                profile.try_lock_local_vault(),
                Ok(VaultLockAttempt::NotLocal)
            ),
            "an S3 profile has no local vault to lock"
        );
    }

    #[test]
    fn try_lock_local_vault_refuses_a_second_holder_then_frees_on_drop() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let profile = TeamProfile {
            name: "trial".to_owned(),
            storage: StorageBackend::Local,
            local_root: Some(dir.path().to_path_buf()),
            ..TeamProfile::default()
        };

        let held = match profile.try_lock_local_vault()? {
            VaultLockAttempt::Acquired(lock) => lock,
            VaultLockAttempt::Held => {
                anyhow::bail!("a free vault must not report its lock as already held")
            }
            VaultLockAttempt::NotLocal => {
                anyhow::bail!("a storage = \"local\" profile must not report NotLocal")
            }
        };

        assert!(
            matches!(profile.try_lock_local_vault()?, VaultLockAttempt::Held),
            "a concurrent attempt on the same vault must see the lock already held, not error \
             or silently succeed"
        );

        drop(held);

        assert!(
            matches!(
                profile.try_lock_local_vault()?,
                VaultLockAttempt::Acquired(_)
            ),
            "the lock must be free again once the holder is dropped (including on a crash: the \
             OS reclaims an flock the moment the holding fd closes)"
        );
        Ok(())
    }

    /// Finding #7/#12: `Config`/`TeamProfile` must round-trip through
    /// `Serialize` (not just `Deserialize`) so `upgrade` can rewrite an
    /// EXISTING config by mutating only the storage fields, instead of
    /// hand-listing a fixed subset that silently drops every other field
    /// (`max_epoch`, `semantic_embeddings`, `relevance_floor`, `s3_region`,
    /// `chain_ws_url`, `orgs`, `catch_all`, `teams`, ...).
    #[test]
    fn config_round_trips_every_field_through_serialize_then_deserialize() -> anyhow::Result<()> {
        let toml = format!(
            "{}\nmax_epoch = 2\nsemantic_embeddings = false\nrelevance_floor = 0.4\n\
             s3_region = \"custom-region\"\nchain_ws_url = \"wss://chain.example\"\n\
             orgs = [\"github.com/acme\"]\n{}",
            valid_toml(),
            team_block("clientx", "orgs = [\"github.com/clientx\"]\n")
        );
        let cfg = Config::from_toml_str(&toml)?;

        let rewritten = toml::to_string(&cfg)?;
        let reloaded = Config::from_toml_str(&rewritten)?;

        assert_eq!(reloaded.max_epoch, 2);
        assert!(!reloaded.semantic_embeddings);
        assert_eq!(reloaded.relevance_floor, Some(0.4));
        assert_eq!(reloaded.s3_region, "custom-region");
        assert_eq!(
            reloaded.chain_ws_url.as_deref(),
            Some("wss://chain.example")
        );
        assert_eq!(reloaded.orgs, vec!["github.com/acme".to_owned()]);
        assert_eq!(
            reloaded.teams.len(),
            1,
            "the [[teams]] profile must survive"
        );
        assert_eq!(reloaded.teams[0].name, "clientx");
        Ok(())
    }
}
