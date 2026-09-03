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
use std::num::NonZeroU64;

use anyhow::{Context, bail};
use hippius_mem_core::{ConsoleClient, DEFAULT_CONSOLE_BASE_URL};

use crate::bundle::InviteBundle;
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
/// configuration cannot be loaded, the resolved profile is a local trial
/// vault (see [`crate::config::require_s3`] — team mode needs a Hippius
/// bucket; run `hippius-mem upgrade` first), `HIPPIUS_MEM_MNEMONIC` is unset,
/// or the mint flow fails (a non-owner mnemonic surfaces as the console's
/// typed refusal — sub-tokens can only be minted by the bucket-owning
/// account).
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;

    // The founder's own validated config is the source of truth for every
    // shared bundle field — no flags to mistype a bucket or team key.
    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    crate::config::require_s3(&cfg.primary_profile(), "invite")?;

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
        founder_ss58: cfg.founder_ss58.clone(),
        // The presence rule IS the constructor: a founding-epoch (0) config
        // yields None, so `max_epoch = 0` can never be emitted.
        max_epoch: NonZeroU64::new(cfg.max_epoch),
        team_key_hex: cfg.team_key_hex.clone(),
        access_key_id: creds.access_key_id.clone(),
        secret: creds.secret,
    };

    // Zeroize the assembled secret-bearing text once written, matching
    // `mint::write_secret_file`'s discipline for the longest-lived plaintext
    // copy this process materializes.
    let rendered = zeroize::Zeroizing::new(render_bundle(&bundle)?);

    // Operator-facing output goes to the stdout handle directly (the workspace
    // denies the `print!` family; stdout normally carries the MCP protocol,
    // but one-shot subcommands own it). Unlike `rotate`'s advisory lines this
    // output IS the product, and the secret is already minted and shown-once:
    // a swallowed EPIPE (`invite | head`) or a full disk on redirect must not
    // exit 0 with the bundle lost. Propagate write AND flush failures (stdout
    // is buffered, so an error can surface only at flush), naming the orphaned
    // token so the founder knows to revoke it in the console and re-run.
    let mut out = std::io::stdout();
    out.write_all(rendered.as_bytes())
        .and_then(|()| out.flush())
        .with_context(|| {
            format!(
                "failed to print the invite bundle; sub-token {} was ALREADY MINTED — \
                 revoke it in the console and re-run",
                creds.access_key_id
            )
        })?;

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

/// Render the bundle as one copy-paste block: a `#`-comment header plus the
/// fields serialized by `toml`.
///
/// Every non-field line is a TOML comment so the WHOLE block — exactly what
/// the founder copies — parses as a TOML document; Task 4.3's `join --bundle`
/// needs no marker-stripping. The header is static text (no injection
/// surface); only field values are untrusted and `toml::to_string` escapes
/// them, exactly as `mint::render_creds_file` established.
///
/// When the team has rotated (`max_epoch` present) the epoch-0 `team_key_hex`
/// alone cannot read newer notes, so the header adds the join/provision
/// instruction; the epoch VALUE itself travels as a parsed field so an
/// automated `join --bundle` cannot lose it to a discarded comment.
///
/// # Errors
///
/// Returns an error if `toml` serialization fails. (The TOML spec's integers
/// are signed 64-bit, but the `toml` crate's serde layer round-trips the full
/// `u64` range — verified empirically and pinned by
/// `max_epoch_u64_max_round_trips`, so no epoch value is unrepresentable.)
fn render_bundle(bundle: &InviteBundle) -> anyhow::Result<String> {
    let body = toml::to_string(bundle).context("serializing the invite bundle as TOML")?;

    let rotated_note = if bundle.max_epoch.is_some() {
        "#\n\
         # This team has ROTATED its key (see max_epoch below): run\n\
         # `hippius-mem join` and have the founder run `provision` so the\n\
         # newer epoch keys are wrapped to you — without them, notes sealed\n\
         # after the rotation silently never appear on your machine.\n"
    } else {
        ""
    };

    Ok(format!(
        "# =================== HIPPIUS-MEM INVITE ===================\n\
         # Contains a live S3 secret and the team encryption key. Share with ONE\n\
         # teammate over a secure out-of-band channel, then DELETE this text —\n\
         # the secret is shown once and cannot be re-fetched.\n\
         #\n\
         # Joiner — one command (recommended): save this block to a file (or\n\
         # pipe it) and run `hippius-mem join --bundle <file>` (or `--bundle -`\n\
         # for stdin). It writes your config (0600) and generates your signing\n\
         # seed for you; add `--orgs <host/org>` if you already have a config.\n\
         #\n\
         # Joiner — manual alternative:\n\
         #   1. Save this whole block as `./hippius-mem.toml` in the repo root\n\
         #      (or at the path your HIPPIUS_MEM_CONFIG env var points to).\n\
         #   2. Add your own signing seed, generated ON YOUR machine and never\n\
         #      shared:  author_seed_hex = \"<output of: openssl rand -hex 32>\"\n\
         #   3. NEVER commit this file: it holds the live secret and team key,\n\
         #      and `hippius-mem init` does NOT gitignore it — add\n\
         #      hippius-mem.toml to your .gitignore.\n\
         #   4. Verify the setup with `hippius-mem doctor`.\n\
         #\n\
         # Pasting into a [[teams]] entry instead? Rename `team` to `name`.\n\
         # If `s3_endpoint` or `max_epoch` appear below, they are TOP-LEVEL\n\
         # config keys — keep them at the top level of the file, never inside\n\
         # the [[teams]] entry.\n\
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

    use std::num::NonZeroU64;

    use anyhow::Context;
    use proptest::prelude::*;

    use super::{Options, render_bundle};
    use crate::bundle::InviteBundle;

    /// A minimal bundle: no endpoint override, un-pinned founder, un-rotated
    /// team — the six always-present keys only.
    fn sample(endpoint: Option<&str>) -> InviteBundle {
        InviteBundle {
            s3_endpoint: endpoint.map(ToOwned::to_owned),
            bucket: "team-bucket".to_owned(),
            team: "acme".to_owned(),
            founder_ss58: None,
            max_epoch: None,
            team_key_hex: "ab".repeat(32),
            access_key_id: "AKIAINVITE".to_owned(),
            secret: "shown-once".to_owned(),
        }
    }

    #[test]
    fn bundle_renders_exactly_the_conditional_key_surface() -> anyhow::Result<()> {
        // The parsed field surface is Task 4.3's contract: six always-present
        // config-schema keys, plus s3_endpoint / founder_ss58 / max_epoch only
        // under their presence rules — never author_seed_hex (generated on the
        // joiner's machine) and no stray keys a header edit could inject.
        let key_set = |bundle: &InviteBundle| -> anyhow::Result<Vec<String>> {
            let rendered = render_bundle(bundle)?;
            let value: toml::Value = toml::from_str(&rendered)?;
            let table = value.as_table().context("bundle must parse as a table")?;
            let mut keys: Vec<String> = table.keys().cloned().collect();
            keys.sort_unstable();
            Ok(keys)
        };
        assert_eq!(
            key_set(&sample(None))?,
            ["access_key_id", "bucket", "secret", "team", "team_key_hex"].map(ToOwned::to_owned)
        );
        let mut full = sample(Some("https://gw.example"));
        full.founder_ss58 = Some("5GCNV7KK1Y".to_owned());
        full.max_epoch = NonZeroU64::new(2);
        assert_eq!(
            key_set(&full)?,
            [
                "access_key_id",
                "bucket",
                "founder_ss58",
                "max_epoch",
                "s3_endpoint",
                "secret",
                "team",
                "team_key_hex",
            ]
            .map(ToOwned::to_owned)
        );
        Ok(())
    }

    #[test]
    fn bundle_omits_the_default_endpoint() -> anyhow::Result<()> {
        // With no endpoint override the joiner's config should keep tracking
        // the binary default rather than pinning today's value.
        // Key-based check: the header COMMENTS legitimately mention
        // `s3_endpoint` (the [[teams]] top-level-key instruction), so absence
        // is asserted on the parsed table, not the raw text.
        let rendered = render_bundle(&sample(None))?;
        let value: toml::Value = toml::from_str(&rendered)?;
        let table = value.as_table().context("bundle must parse as a table")?;
        assert!(!table.contains_key("s3_endpoint"));
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
        let rendered = render_bundle(&sample(None))?;
        assert!(rendered.contains("shown once"));
        assert!(rendered.contains("DELETE"));
        assert!(rendered.contains("author_seed_hex"));
        // Reviewer finding: TeamProfile is deny_unknown_fields with no
        // s3_endpoint/max_epoch — a [[teams]] paste must be told those keys
        // stay at the top level of the config file.
        assert!(rendered.contains("TOP-LEVEL"));
        // Joiner UX lines: where the file lives, how to verify, and that a
        // repo-root secret file must never be committed (init does not
        // gitignore it).
        assert!(rendered.contains("./hippius-mem.toml"));
        assert!(rendered.contains("HIPPIUS_MEM_CONFIG"));
        assert!(rendered.contains("hippius-mem doctor"));
        assert!(rendered.contains("NEVER commit"));
        assert!(rendered.contains(".gitignore"));
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
    fn rotated_epoch_survives_parsing_and_keeps_its_instruction() -> anyhow::Result<()> {
        // A rotated team's max_epoch must be a parsed FIELD (an automated
        // `join --bundle` defaulting to 0 silently hides post-rotation notes
        // — the documented rotate gotcha), and the join/provision instruction
        // must accompany it; an un-rotated team carries neither.
        let mut bundle = sample(None);
        bundle.max_epoch = NonZeroU64::new(3);
        let rotated = render_bundle(&bundle)?;
        let parsed: InviteBundle = toml::from_str(&rotated)?;
        assert_eq!(parsed.max_epoch, NonZeroU64::new(3));
        assert!(rotated.contains("ROTATED"));
        assert!(rotated.contains("provision"));
        // Key-based check (the header comments always mention `max_epoch` in
        // the top-level-key instruction): the founding-epoch bundle must carry
        // neither the FIELD nor the rotation instruction.
        let founding = render_bundle(&sample(None))?;
        let value: toml::Value = toml::from_str(&founding)?;
        let table = value.as_table().context("bundle must parse as a table")?;
        assert!(!table.contains_key("max_epoch"));
        assert!(!founding.contains("ROTATED"));
        Ok(())
    }

    #[test]
    fn founder_pin_travels_only_when_the_founder_config_pins_it() -> anyhow::Result<()> {
        // The anti-takeover pin is public and the invite's out-of-band channel
        // is the right conduit — but an unpinned founder config must not
        // fabricate a key the joiner would then trust.
        let mut bundle = sample(None);
        bundle.founder_ss58 = Some("5GCNV7KK1Y62v1WNsV4rdvn81".to_owned());
        let pinned = render_bundle(&bundle)?;
        let parsed: InviteBundle = toml::from_str(&pinned)?;
        assert_eq!(parsed.founder_ss58, bundle.founder_ss58);
        let unpinned = render_bundle(&sample(None))?;
        assert!(!unpinned.contains("founder_ss58"));
        Ok(())
    }

    #[test]
    fn max_epoch_u64_max_round_trips() -> anyhow::Result<()> {
        // Axiom rust_quality_110 probe with a surprising outcome: the TOML
        // SPEC caps integers at signed 64-bit, but the toml crate's serde
        // layer serializes AND parses the full u64 range (verified against
        // toml 1.1.2). Pin that behavior — if a toml upgrade regresses to
        // spec-range integers, this failing test flags the epoch ceiling
        // silently shrinking rather than a joiner discovering it in the field.
        let mut bundle = sample(None);
        bundle.max_epoch = NonZeroU64::new(u64::MAX);
        let rendered = render_bundle(&bundle)?;
        let parsed: InviteBundle = toml::from_str(&rendered)?;
        assert_eq!(parsed.max_epoch, NonZeroU64::new(u64::MAX));
        Ok(())
    }

    #[test]
    fn max_epoch_zero_is_rejected_at_the_parse_boundary() -> anyhow::Result<()> {
        // Reviewer could not verify serde's NonZero zero-rejection from local
        // rustdoc — pin it empirically: a hand-edited `max_epoch = 0` must be
        // a parse ERROR for 4.3 (Some(0) is unrepresentable in the type, and
        // the founder's construction site never emits the key for epoch 0).
        let rendered = render_bundle(&sample(None))?;
        let amended = format!("{rendered}max_epoch = 0\n");
        let err = toml::from_str::<InviteBundle>(&amended)
            .expect_err("serde must reject a zero NonZeroU64");
        assert!(err.to_string().contains('0'));
        Ok(())
    }

    #[test]
    fn amended_bundle_with_author_seed_still_parses() -> anyhow::Result<()> {
        // The 4.3 leniency contract (no deny_unknown_fields): the header tells
        // the joiner to append author_seed_hex to THIS text, so the parser
        // must accept the very file the instructions produce.
        let rendered = render_bundle(&sample(None))?;
        let amended = format!("{rendered}author_seed_hex = \"{}\"\n", "cd".repeat(32));
        let parsed: InviteBundle = toml::from_str(&amended)?;
        assert_eq!(parsed.team, "acme");
        assert_eq!(parsed.secret, "shown-once");
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
            founder_ss58: Some("5G\"pin\\ned".to_owned()),
            max_epoch: NonZeroU64::new(1),
            team_key_hex: "ke\ty".to_owned(),
            access_key_id: "AKIA\"WEIRD".to_owned(),
            secret: "s3\"cr\\et\nwith\ttabs".to_owned(),
        };
        let rendered = render_bundle(&bundle)?;
        let parsed: InviteBundle = toml::from_str(&rendered)?;
        assert_eq!(parsed.secret, bundle.secret);
        assert_eq!(parsed.team_key_hex, bundle.team_key_hex);
        assert_eq!(parsed.access_key_id, bundle.access_key_id);
        assert_eq!(parsed.team, bundle.team);
        assert_eq!(parsed.bucket, bundle.bucket);
        assert_eq!(parsed.s3_endpoint, bundle.s3_endpoint);
        assert_eq!(parsed.founder_ss58, bundle.founder_ss58);
        assert_eq!(parsed.max_epoch, bundle.max_epoch);
        Ok(())
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
            founder_ss58 in proptest::option::of(any::<String>()),
            // Presence is the type (`NonZeroU64`), so the strategy spans the
            // full nonzero range. The full u64 range round-trips — the toml
            // crate exceeds the TOML spec's signed-64-bit integers (pinned by
            // `max_epoch_u64_max_round_trips`; zero rejection pinned by
            // `max_epoch_zero_is_rejected_at_the_parse_boundary`).
            max_epoch in proptest::option::of(
                (1u64..=u64::MAX).prop_map(|n| NonZeroU64::new(n).expect("range starts at 1"))
            ),
            team_key_hex in any::<String>(),
            access_key_id in any::<String>(),
            secret in any::<String>(),
        ) {
            let bundle = InviteBundle {
                s3_endpoint: endpoint,
                bucket,
                team,
                founder_ss58,
                max_epoch,
                team_key_hex,
                access_key_id,
                secret,
            };
            let rendered = render_bundle(&bundle).expect("toml can encode any string");
            let parsed: InviteBundle = toml::from_str(&rendered).expect("rendered bundle must parse");
            prop_assert_eq!(parsed.s3_endpoint, bundle.s3_endpoint);
            prop_assert_eq!(parsed.bucket, bundle.bucket);
            prop_assert_eq!(parsed.team, bundle.team);
            prop_assert_eq!(parsed.founder_ss58, bundle.founder_ss58);
            prop_assert_eq!(parsed.max_epoch, bundle.max_epoch);
            prop_assert_eq!(parsed.team_key_hex, bundle.team_key_hex);
            prop_assert_eq!(parsed.access_key_id, bundle.access_key_id);
            prop_assert_eq!(parsed.secret, bundle.secret);
        }
    }
}
