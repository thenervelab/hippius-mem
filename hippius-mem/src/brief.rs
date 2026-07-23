//! The `brief` subcommand: print the `SessionStart` brief — a deterministic,
//! tiered digest of the team's live memory — to stdout, for a `SessionStart` hook
//! to inject as `additionalContext`.
//!
//! Recall is pull-only, so an agent only finds a note it already suspects exists.
//! The brief hands it the durable rules and recent gotchas up front, closing the
//! unknown-unknowns gap. It is a nicety, never load-bearing: every failure path
//! prints nothing and exits 0 so a mis-provisioned or offline machine still
//! starts its session cleanly.

use hippius_mem_core::render_brief;

use crate::config::Config;
use crate::resolve_and_build_store;

/// Default token budget: a small ambient digest, not a data dump.
const DEFAULT_TOKEN_BUDGET: usize = 1500;

/// Build the bound store, freshen it best-effort, and print the rendered brief.
///
/// `--tokens N` overrides the budget. Every fallible step degrades to empty
/// output (a `SessionStart` hook must not block or noisily fail): a missing
/// config, a repo with memory disabled, a failed store build, or a store with no
/// live notes all print nothing.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let token_budget = parse_tokens(args).unwrap_or(DEFAULT_TOKEN_BUDGET);

    let Ok(cfg) = Config::from_env_and_file() else {
        return Ok(());
    };
    // `resolve_and_build_store` errors when this repo routes to no team profile
    // (memory is off here) — a clean "nothing to brief", not a failure.
    let Ok((store, _launch_repo)) = resolve_and_build_store(&cfg).await else {
        return Ok(());
    };
    // Load the epoch key-ring before reading, so a member provisioned after a
    // team-key rotation briefs on rotated-epoch notes too — without this the
    // digest silently omits every note sealed under an epoch past the founding
    // one (the recorded `bootstrap_epochs` gotcha; the dashboard bootstraps for
    // the same reason). Best-effort + mnemonic-gated, matching the server warmup.
    if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
        crate::admin::bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    }
    // Freshen from the bucket if the local view is stale; an offline/failed sync
    // just renders the last local view rather than blocking session start.
    let _ = store.refresh_if_stale().await;
    let Ok(records) = store.list_records() else {
        return Ok(());
    };

    let brief = render_brief(&records, token_budget);
    if !brief.is_empty() {
        // Write to the stdout handle directly: this subcommand's whole purpose is
        // to emit the brief for the hook to capture, but the workspace denies the
        // `print!` family, and `write_all` is not one of them. Best-effort — a
        // broken pipe (the hook closed stdout early) must not fail the command.
        use std::io::Write;
        let _ = std::io::stdout().write_all(brief.as_bytes());
    }
    Ok(())
}

/// Parse an optional `--tokens N` flag; `None` if absent or unparseable (the
/// caller then uses [`DEFAULT_TOKEN_BUDGET`]).
fn parse_tokens(args: &[String]) -> Option<usize> {
    let idx = args.iter().position(|arg| arg == "--tokens")?;
    args.get(idx + 1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_tokens;

    #[test]
    fn parses_the_tokens_flag() {
        let args = vec!["--tokens".to_string(), "800".to_string()];
        assert_eq!(parse_tokens(&args), Some(800));
    }

    #[test]
    fn missing_or_bad_tokens_flag_is_none() {
        assert_eq!(parse_tokens(&[]), None);
        assert_eq!(
            parse_tokens(&["--tokens".to_string(), "notanumber".to_string()]),
            None
        );
        assert_eq!(parse_tokens(&["--tokens".to_string()]), None);
    }
}
