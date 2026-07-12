//! The invite-bundle wire type shared by the founder's `invite` (mint + emit,
//! behind the `console` feature) and the joiner's `join --bundle` (parse +
//! config write, available in EVERY build).
//!
//! This module is compiled unconditionally on purpose: a joiner consuming a
//! bundle must not need the founder-side console stack (reqwest/alloy), so the
//! type and its parse surface live outside the `console` gate while minting
//! stays behind it (`crate::invite`).

use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

/// The paste-ready invite bundle: exactly the fields the joiner's primary
/// profile (or a `[[teams]]` entry, with `team` renamed to `name`) needs.
///
/// `author_seed_hex` is deliberately NOT a field: the joiner's signing seed is
/// generated on THEIR machine and never travels — the type cannot represent a
/// bundle that leaks it. Serialized through `toml`/`serde` rather than string
/// templating so values containing TOML metacharacters (`"`, `\`, newline)
/// are escaped instead of corrupting the document or injecting keys. Task
/// 4.3's `join --bundle` parses this same shape back with `toml::from_str`.
///
/// Deliberately NO `deny_unknown_fields` — that leniency is part of the 4.3
/// contract: the header tells the joiner to amend this same text with their
/// `author_seed_hex`, so the parser must accept the amended file rather than
/// reject the very document the instructions produce. Pinned by
/// `amended_bundle_with_author_seed_still_parses`.
#[derive(Serialize, Deserialize)]
pub(crate) struct InviteBundle {
    /// Gateway endpoint — present only when it differs from the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) s3_endpoint: Option<String>,
    /// Team-owned bucket the sub-token is scoped to.
    pub(crate) bucket: String,
    /// Shared namespace scoping every note (a `[[teams]]` profile's `name`).
    pub(crate) team: String,
    /// The founder's pinned SS58 address — present only when the founder's own
    /// config pins it. Public (not a secret), and the invite's out-of-band
    /// channel is exactly the right conduit: a joiner bootstrapping without
    /// the pin is back on trust-on-genesis, the documented open-team takeover
    /// caveat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) founder_ss58: Option<String>,
    /// Highest team-key epoch — present only when the team has rotated. A
    /// parsed FIELD, not a comment: an automated `join --bundle` on a rotated
    /// team must not default to 0, or notes sealed after the rotation
    /// silently never appear on the joiner's machine. `NonZeroU64` makes the
    /// presence rule the type — `Some(0)` is unrepresentable, and serde
    /// rejects a hand-edited `max_epoch = 0` at 4.3's parse boundary (pinned
    /// by `max_epoch_zero_is_rejected_at_the_parse_boundary`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_epoch: Option<NonZeroU64>,
    /// Shared team encryption key. Redacted in `Debug`.
    pub(crate) team_key_hex: String,
    /// The freshly minted per-teammate sub-token id.
    pub(crate) access_key_id: String,
    /// The sub-token secret — shown once by the console. Redacted in `Debug`.
    pub(crate) secret: String,
}

/// Redact the secrets, mirroring `Config`'s hand-written `Debug`: a stray
/// `{bundle:?}` in a log or panic message must never print the S3 secret or
/// the team encryption key.
impl std::fmt::Debug for InviteBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteBundle")
            .field("s3_endpoint", &self.s3_endpoint)
            .field("bucket", &self.bucket)
            .field("team", &self.team)
            .field("founder_ss58", &self.founder_ss58)
            .field("max_epoch", &self.max_epoch)
            .field("team_key_hex", &"<redacted>")
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::InviteBundle;

    #[test]
    fn debug_never_leaks_the_secret_or_team_key() {
        // A stray `{bundle:?}` in a log or panic message must redact, exactly
        // as `Config`'s hand-written `Debug` does for the same two fields.
        let bundle = InviteBundle {
            s3_endpoint: None,
            bucket: "team-bucket".to_owned(),
            team: "acme".to_owned(),
            founder_ss58: None,
            max_epoch: None,
            team_key_hex: "ab".repeat(32),
            access_key_id: "AKIAINVITE".to_owned(),
            secret: "shown-once".to_owned(),
        };
        let debug = format!("{bundle:?}");
        assert!(!debug.contains("shown-once"));
        assert!(!debug.contains(&"ab".repeat(32)));
        assert!(debug.contains("<redacted>"));
    }
}
