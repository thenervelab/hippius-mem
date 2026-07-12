//! The `hippius-mem invite` subcommand (gated behind the `console` feature).
//!
//! Founder-only onboarding: mints a fresh per-teammate S3 sub-token against
//! the team bucket from the founder's own config (reusing the `mint-token`
//! console flow) and prints ONE paste-ready TOML bundle — the exact fields the
//! joiner's primary profile needs. The bundle goes to stdout ONLY: it is never
//! written to a file (a secret-on-disk hazard the operator did not ask for),
//! and neither the secret nor the team key ever reaches `tracing` — only the
//! public `access_key_id` is logged.
//!
//! Scope: like `join`/`provision`/`rotate`, this reads the PRIMARY (flat,
//! top-level) profile only — invite for a secondary team from a config whose
//! primary IS that team.

use std::io::Write;

use anyhow::{Context, bail};
use hippius_mem_core::{ConsoleClient, DEFAULT_CONSOLE_BASE_URL};
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Default sub-token label when `--name` is omitted. Distinct from
/// `mint-token`'s default so founder-minted invite tokens are recognizable
/// (and individually revocable) in the console's sub-token list.
const DEFAULT_TOKEN_NAME: &str = "hippius-mem-invite";

/// Run the `invite` subcommand over the args following `invite`.
///
/// # Errors
///
/// Returns an error if the arguments are malformed, the founder's
/// configuration cannot be loaded, `HIPPIUS_MEM_MNEMONIC` is unset, or the
/// mint flow fails (a non-owner mnemonic surfaces as the console's typed
/// refusal — sub-tokens can only be minted by the bucket-owning account).
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;
    // The founder's own validated config is the source of truth for every
    // shared bundle field — no flags to mistype a bucket or team key.
    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    let mnemonic = std::env::var("HIPPIUS_MEM_MNEMONIC")
        .context("set HIPPIUS_MEM_MNEMONIC to the bucket owner's mnemonic before inviting")?;
    let base_url = std::env::var("HIPPIUS_MEM_CONSOLE_URL")
        .unwrap_or_else(|_| DEFAULT_CONSOLE_BASE_URL.to_owned());

    let client = ConsoleClient::new(base_url);
    let creds = client
        .mint_sub_token(&mnemonic, &cfg.bucket, &opts.name)
        .await?;

    // A default endpoint is omitted so the joiner's config stays minimal and
    // keeps tracking the binary's default; a custom gateway must travel.
    let default_endpoint = Config::default().s3_endpoint;
    let bundle = InviteBundle {
        s3_endpoint: (cfg.s3_endpoint != default_endpoint).then(|| cfg.s3_endpoint.clone()),
        bucket: cfg.bucket.clone(),
        team: cfg.team.clone(),
        team_key_hex: cfg.team_key_hex.clone(),
        access_key_id: creds.access_key_id.clone(),
        secret: creds.secret,
    };
    // Zeroize the assembled secret-bearing text once written, matching
    // `mint::write_secret_file`'s discipline for the longest-lived plaintext
    // copy this process materializes.
    let rendered = zeroize::Zeroizing::new(render_bundle(&bundle, cfg.max_epoch)?);

    // Operator-facing output goes to the stdout handle directly (the workspace
    // denies the `print!` family; stdout normally carries the MCP protocol,
    // but one-shot subcommands own it). Write failures are ignored like
    // `rotate`'s — there is no better channel to report them on.
    let mut out = std::io::stdout();
    let _ = out.write_all(rendered.as_bytes());

    // The access_key_id is public; the secret and team key exist only in the
    // bundle text above — never in a log line.
    tracing::info!(
        access_key_id = %creds.access_key_id,
        name = %opts.name,
        "minted invite sub-token; the bundle above is shown once — share it out of band, then delete it"
    );
    Ok(())
}

/// Parsed `invite` arguments. No secrets here, so `Debug` is derivable.
#[derive(Debug)]
struct Options {
    /// Human-facing sub-token label — name it after the teammate so their
    /// token can be revoked individually later.
    name: String,
}

impl Options {
    /// Parse `[--name <label>]`.
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut name = None;
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--name" => {
                    name = Some(
                        iter.next()
                            .map(ToOwned::to_owned)
                            .context("--name requires a value")?,
                    );
                }
                other => bail!("unknown invite argument `{other}`; usage: invite [--name <label>]"),
            }
        }
        Ok(Self {
            name: name.unwrap_or_else(|| DEFAULT_TOKEN_NAME.to_owned()),
        })
    }
}

/// The paste-ready invite bundle: exactly the fields the joiner's primary
/// profile (or a `[[teams]]` entry, with `team` renamed to `name`) needs.
///
/// `author_seed_hex` is deliberately NOT a field: the joiner's signing seed is
/// generated on THEIR machine and never travels — the type cannot represent a
/// bundle that leaks it. Serialized through `toml`/`serde` rather than string
/// templating so values containing TOML metacharacters (`"`, `\`, newline)
/// are escaped instead of corrupting the document or injecting keys. Task
/// 4.3's `join --bundle` parses this same shape back with `toml::from_str`.
#[derive(Serialize, Deserialize)]
struct InviteBundle {
    /// Gateway endpoint — present only when it differs from the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    s3_endpoint: Option<String>,
    /// Team-owned bucket the sub-token is scoped to.
    bucket: String,
    /// Shared namespace scoping every note (a `[[teams]]` profile's `name`).
    team: String,
    /// Shared team encryption key. Redacted in `Debug`.
    team_key_hex: String,
    /// The freshly minted per-teammate sub-token id.
    access_key_id: String,
    /// The sub-token secret — shown once by the console. Redacted in `Debug`.
    secret: String,
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
            .field("team_key_hex", &"<redacted>")
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Render the bundle as one copy-paste block: a `#`-comment header plus the
/// fields serialized by `toml`.
///
/// Every non-field line is a TOML comment so the WHOLE block — exactly what
/// the founder copies — parses as a TOML document; Task 4.3's `join --bundle`
/// needs no marker-stripping. The header is static text (no injection
/// surface); only field values are untrusted and `toml::to_string` escapes
/// them, exactly as `mint::render_creds_file` established.
///
/// `max_epoch` is the founder's configured epoch ceiling: when the team has
/// rotated (`> 0`) the epoch-0 `team_key_hex` alone cannot read newer notes,
/// so the header tells the joiner the extra steps — as a comment, keeping the
/// parsed field surface fixed.
///
/// # Errors
///
/// Returns an error if `toml` serialization fails.
fn render_bundle(bundle: &InviteBundle, max_epoch: u64) -> anyhow::Result<String> {
    let body = toml::to_string(bundle).context("serializing the invite bundle as TOML")?;
    let rotated_note = if max_epoch > 0 {
        format!(
            "#\n\
             # This team has ROTATED its key: set max_epoch = {max_epoch} in your config,\n\
             # then run `hippius-mem join` and have the founder run `provision` so the\n\
             # newer epoch keys are wrapped to you — without them, notes sealed after\n\
             # the rotation silently never appear on your machine.\n"
        )
    } else {
        String::new()
    };
    Ok(format!(
        "# =================== HIPPIUS-MEM INVITE ===================\n\
         # Contains a live S3 secret and the team encryption key. Share with ONE\n\
         # teammate over a secure out-of-band channel, then DELETE this text —\n\
         # the secret is shown once and cannot be re-fetched.\n\
         #\n\
         # Joiner: paste this as the top-level (primary) profile of your\n\
         # hippius-mem.toml — or into a [[teams]] entry, renaming `team` to\n\
         # `name` — then add your own signing seed, generated ON YOUR machine\n\
         # and never shared:\n\
         #\n\
         #   author_seed_hex = \"<output of: openssl rand -hex 32>\"\n\
         #\n\
         # Wrapped-key alternative: with your own HIPPIUS_MEM_MNEMONIC set you\n\
         # can also run `hippius-mem join` (and have the founder run `provision`)\n\
         # to receive rotated epoch keys; team_key_hex is included regardless so\n\
         # this config boots either way.\n\
         {rotated_note}\
         # ===========================================================\n\
         {body}"
    ))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
    )]
    #![expect(
        clippy::expect_used,
        reason = "tests assert on hand-built fixtures where construction cannot fail"
    )]

    use anyhow::Context;
    use proptest::prelude::*;

    use super::{InviteBundle, Options, render_bundle};

    /// A representative bundle with plain values.
    fn sample(endpoint: Option<&str>) -> InviteBundle {
        InviteBundle {
            s3_endpoint: endpoint.map(ToOwned::to_owned),
            bucket: "team-bucket".to_owned(),
            team: "acme".to_owned(),
            team_key_hex: "ab".repeat(32),
            access_key_id: "AKIAINVITE".to_owned(),
            secret: "shown-once".to_owned(),
        }
    }

    #[test]
    fn bundle_renders_exactly_the_primary_profile_keys() -> anyhow::Result<()> {
        // The parsed field surface is Task 4.3's contract: exactly the config
        // schema keys, never author_seed_hex (generated on the joiner's
        // machine) and no stray keys a header edit could inject.
        let rendered = render_bundle(&sample(Some("https://gw.example")), 0)?;
        let value: toml::Value = toml::from_str(&rendered)?;
        let table = value.as_table().context("bundle must parse as a table")?;
        let mut keys: Vec<&str> = table.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "access_key_id",
                "bucket",
                "s3_endpoint",
                "secret",
                "team",
                "team_key_hex",
            ]
        );
        Ok(())
    }

    #[test]
    fn bundle_omits_the_default_endpoint() -> anyhow::Result<()> {
        // With no endpoint override the joiner's config should keep tracking
        // the binary default rather than pinning today's value.
        let rendered = render_bundle(&sample(None), 0)?;
        assert!(!rendered.contains("s3_endpoint"));
        let parsed: InviteBundle = toml::from_str(&rendered)?;
        assert_eq!(parsed.s3_endpoint, None);
        Ok(())
    }

    #[test]
    fn bundle_header_is_all_comments_and_warns_share_once() -> anyhow::Result<()> {
        // Secret-handling contract: the one-shot warning and the
        // seed-on-joiner-machine note must be present, and every non-field
        // line must be a `#` comment so the copied block parses as TOML
        // without stripping.
        let rendered = render_bundle(&sample(None), 0)?;
        assert!(rendered.contains("shown once"));
        assert!(rendered.contains("DELETE"));
        assert!(rendered.contains("author_seed_hex"));
        for line in rendered.lines() {
            let ok = line.is_empty() || line.starts_with('#') || line.contains('=');
            assert!(
                ok,
                "non-comment, non-field line breaks parseability: {line:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn bundle_notes_the_rotated_epoch_only_when_positive() -> anyhow::Result<()> {
        // A rotated team's joiner must be told about max_epoch, or notes
        // sealed after the rotation silently never appear (the documented
        // rotate gotcha) — but as a comment, keeping the field surface fixed.
        let rotated = render_bundle(&sample(None), 3)?;
        assert!(rotated.contains("max_epoch = 3"));
        let value: toml::Value = toml::from_str(&rotated)?;
        let table = value.as_table().context("bundle must parse as a table")?;
        assert!(!table.contains_key("max_epoch"));
        let founding = render_bundle(&sample(None), 0)?;
        assert!(!founding.contains("max_epoch"));
        Ok(())
    }

    #[test]
    fn bundle_with_toml_metacharacters_round_trips() -> anyhow::Result<()> {
        // Axiom rust_quality_110: probe toml's documented string edges — the
        // quote/backslash/newline/tab set that corrupts a hand-built literal,
        // plus unicode and the empty string — through the real serializer.
        let bundle = InviteBundle {
            s3_endpoint: Some("https://gw\"weird\\host".to_owned()),
            bucket: String::new(),
            team: "équipe-日本".to_owned(),
            team_key_hex: "ke\ty".to_owned(),
            access_key_id: "AKIA\"WEIRD".to_owned(),
            secret: "s3\"cr\\et\nwith\ttabs".to_owned(),
        };
        let rendered = render_bundle(&bundle, 0)?;
        let parsed: InviteBundle = toml::from_str(&rendered)?;
        assert_eq!(parsed.secret, bundle.secret);
        assert_eq!(parsed.team_key_hex, bundle.team_key_hex);
        assert_eq!(parsed.access_key_id, bundle.access_key_id);
        assert_eq!(parsed.team, bundle.team);
        assert_eq!(parsed.bucket, bundle.bucket);
        assert_eq!(parsed.s3_endpoint, bundle.s3_endpoint);
        Ok(())
    }

    #[test]
    fn debug_never_leaks_the_secret_or_team_key() {
        // A stray `{bundle:?}` in a log or panic message must redact, exactly
        // as `Config`'s hand-written `Debug` does for the same two fields.
        let bundle = sample(None);
        let debug = format!("{bundle:?}");
        assert!(!debug.contains("shown-once"));
        assert!(!debug.contains(&"ab".repeat(32)));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn invite_args_default_the_token_label() -> anyhow::Result<()> {
        let opts = Options::parse(&[])?;
        assert_eq!(opts.name, "hippius-mem-invite");
        Ok(())
    }

    #[test]
    fn invite_args_accept_a_name() -> anyhow::Result<()> {
        let opts = Options::parse(&["--name".to_owned(), "alice".to_owned()])?;
        assert_eq!(opts.name, "alice");
        Ok(())
    }

    #[test]
    fn invite_args_reject_junk() {
        let err = Options::parse(&["--bucket".to_owned(), "b".to_owned()])
            .expect_err("unknown flags must be rejected, not ignored");
        assert!(err.to_string().contains("unknown invite argument"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Task 4.3's parser contract: whatever values the founder's config and
        /// the console hand us, the rendered block parses back to the same
        /// profile fields (`toml::from_str(render(b)) == b`, field by field —
        /// the shrinker probes escapes no hand-picked fixture thought of).
        #[test]
        fn bundle_round_trips_through_toml(
            endpoint in proptest::option::of(any::<String>()),
            bucket in any::<String>(),
            team in any::<String>(),
            team_key_hex in any::<String>(),
            access_key_id in any::<String>(),
            secret in any::<String>(),
            max_epoch in any::<u64>(),
        ) {
            let bundle = InviteBundle {
                s3_endpoint: endpoint,
                bucket,
                team,
                team_key_hex,
                access_key_id,
                secret,
            };
            let rendered = render_bundle(&bundle, max_epoch).expect("toml can encode any string");
            let parsed: InviteBundle = toml::from_str(&rendered).expect("rendered bundle must parse");
            prop_assert_eq!(parsed.s3_endpoint, bundle.s3_endpoint);
            prop_assert_eq!(parsed.bucket, bundle.bucket);
            prop_assert_eq!(parsed.team, bundle.team);
            prop_assert_eq!(parsed.team_key_hex, bundle.team_key_hex);
            prop_assert_eq!(parsed.access_key_id, bundle.access_key_id);
            prop_assert_eq!(parsed.secret, bundle.secret);
        }
    }
}
