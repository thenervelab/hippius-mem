//! The `hippius-mem doctor` subcommand: validate a memory-key bundle.
//!
//! Loads the same [`Config`] the server boots from and reports the non-secret
//! coordinates (bucket, `access_key_id`, author SS58), so an operator can confirm
//! a bundle is well-formed before starting the server. Secrets (`secret`,
//! `team_key_hex`, `author_seed_hex`) are never logged.

use anyhow::{Context, bail};
use hippius_mem_core::Signer;

use crate::config::Config;

/// Run the `doctor` subcommand over the args following `doctor`.
///
/// Loading [`Config::from_env_and_file`] already validates the bundle (required
/// fields present, `team_key_hex` and `author_seed_hex` each decode to 32 bytes),
/// so a malformed bundle fails here with a precise `ConfigError`. With `--offline`
/// the check stops after the offline validation; otherwise it runs the live
/// gateway probe.
///
/// # Errors
///
/// Returns an error if an unknown argument is passed, the configuration is
/// missing or malformed, or the author identity cannot be derived from
/// `author_seed_hex`.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;

    // Deriving the signer proves `author_seed_hex` yields a usable sr25519
    // identity and hands us the SS58 to report. The SS58 is bound to the seed by
    // construction (see `Sr25519Signer`), so it is safe, non-secret output.
    let signer = cfg
        .signer()
        .context("deriving the author identity from author_seed_hex failed")?;
    let author = signer.author_ss58();

    // `offline_report_lines` is handed only the three public coordinates — never
    // `&cfg` — so a secret field cannot reach the report even by mistake.
    for line in offline_report_lines(&cfg.bucket, &cfg.access_key_id, author.as_str()) {
        tracing::info!("{line}");
    }

    if opts.offline {
        tracing::info!("offline check passed; skipping live gateway probe");
        return Ok(());
    }

    probe_live(&cfg).await
}

/// Parsed `doctor` arguments.
struct Options {
    /// Run only the offline bundle validation, skipping the live gateway probe.
    offline: bool,
}

impl Options {
    /// Parse `[--offline]`.
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut offline = false;
        for arg in args {
            match arg.as_str() {
                "--offline" => offline = true,
                other => bail!("unknown doctor argument `{other}`; usage: doctor [--offline]"),
            }
        }
        Ok(Self { offline })
    }
}

/// Build the non-secret lines of the doctor report.
///
/// Takes only the three public coordinates — never `&Config` — so a secret
/// (`secret`, `team_key_hex`, `author_seed_hex`) is structurally impossible to
/// include in the report this produces.
fn offline_report_lines(bucket: &str, access_key_id: &str, author_ss58: &str) -> Vec<String> {
    vec![
        format!("bucket: {bucket}"),
        format!("access_key_id: {access_key_id}"),
        format!("author_ss58: {author_ss58}"),
    ]
}

/// Run the live encryption-boundary probe against the configured gateway.
///
/// The live probe is implemented in the doctor live-probe step; this placeholder
/// keeps `doctor` wired end-to-end so the offline path and dispatch land and can
/// be exercised independently. It performs no I/O and always succeeds.
///
/// # Errors
///
/// The stub is infallible; the live implementation returns an error when the
/// seal/put/get/open round-trip fails.
#[expect(
    clippy::unused_async,
    reason = "the live probe is async I/O; the awaited signature is fixed now so wiring the real probe is a body-only change"
)]
async fn probe_live(_cfg: &Config) -> anyhow::Result<()> {
    tracing::warn!(
        "live encryption-boundary probe not yet wired; pass `--offline` to skip the live probe and exit cleanly on the offline checks alone"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::offline_report_lines;

    #[test]
    fn report_contains_the_three_non_secret_coordinates() {
        let lines = offline_report_lines("team-bucket", "AKIAEXAMPLE", "5GExampleSs58Address");
        let joined = lines.join("\n");
        assert!(
            joined.contains("team-bucket"),
            "report must name the bucket: {joined}"
        );
        assert!(
            joined.contains("AKIAEXAMPLE"),
            "report must name the access_key_id: {joined}"
        );
        assert!(
            joined.contains("5GExampleSs58Address"),
            "report must name the author SS58: {joined}"
        );
    }
}
