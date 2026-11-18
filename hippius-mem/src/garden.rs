//! The `garden` subcommand: print what in the vault needs a person's
//! attention (see [`hippius_mem_core::garden`]). Read-only.
//!
//! Like `report`, it is a deliberate operator command that reads the full
//! team op-log: a bad config or an unbuildable store is an error, and the
//! epoch key-ring is bootstrapped first so notes written after a key rotation
//! are surveyed too.

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use hippius_mem_core::{GardenNote, GardenReport, Timestamp, garden};

use crate::config::Config;
use crate::resolve_and_build_store;

/// Survey the bound team's vault and print the result: markdown, or the
/// report as JSON with `--json`.
///
/// # Errors
///
/// Returns an error for an unknown argument, a config that cannot be loaded,
/// or a store that cannot be built or listed.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => anyhow::bail!("usage: hippius-mem garden [--json]"),
    };

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (store, _launch_repo, _profile) = resolve_and_build_store(&cfg).await?;
    if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
        crate::admin::bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    }
    crate::admin::warn_if_max_epoch_stale(&store, cfg.max_epoch).await;
    let _ = store.refresh_if_stale().await;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0);
    let report = garden(&store.list_records()?, Timestamp::new(now));
    let text = if json {
        let mut text = serde_json::to_string_pretty(&report)?;
        text.push('\n');
        text
    } else {
        render_markdown(&report)
    };
    std::io::stdout().write_all(text.as_bytes())?;
    Ok(())
}

fn note_line(note: &GardenNote) -> String {
    format!("`{}` ({}) {}", note.id, note.repo, note.summary)
}

/// "showing the first N of M" when a list was cut, else nothing.
fn cut_note(shown: usize, total: usize) -> String {
    if shown < total {
        format!(" (showing {shown} of {total})")
    } else {
        String::new()
    }
}

fn render_markdown(report: &GardenReport) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ = writeln!(out, "# Hippius Memory — Garden\n");
    let _ = writeln!(out, "{} live notes.\n", report.notes);

    let _ = writeln!(out, "## Notes per scope\n");
    let _ = writeln!(
        out,
        "`global` is the team-wide pool: every repository's recall and brief read it.\n"
    );
    for (scope, count) in &report.scopes {
        let _ = writeln!(out, "- {scope}: {count}");
    }

    let _ = writeln!(
        out,
        "\n## Replaced and still live: {}{}\n",
        report.replaced_total,
        cut_note(report.replaced.len(), report.replaced_total)
    );
    let _ = writeln!(
        out,
        "Another note supersedes or duplicates each of these. `forget` it once nothing needs it.\n"
    );
    for entry in &report.replaced {
        let _ = writeln!(
            out,
            "- {}, replaced by `{}`",
            note_line(&entry.note),
            entry.by
        );
    }

    let _ = writeln!(
        out,
        "\n## Likely duplicates: {}{}\n",
        report.likely_duplicates_total,
        cut_note(
            report.likely_duplicates.len(),
            report.likely_duplicates_total
        )
    );
    let _ = writeln!(
        out,
        "Summaries in one scope that share most of their words. `link` the newer to the older \
         with rel `supersedes` or `duplicates`, or leave them.\n"
    );
    for pair in &report.likely_duplicates {
        let _ = writeln!(out, "- {}", note_line(&pair.newer));
        let _ = writeln!(out, "  and {}", note_line(&pair.older));
    }

    let _ = writeln!(
        out,
        "\n## Stale and never reused: {}{}\n",
        report.stale_total,
        cut_note(report.stale.len(), report.stale_total)
    );
    let _ = writeln!(
        out,
        "Older than two recency half-lives of their type, and no one has opened them after a \
         recall. Oldest first.\n"
    );
    for note in &report.stale {
        let _ = writeln!(out, "- {}", note_line(note));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cut list says so; a whole one does not.
    #[test]
    fn a_cut_list_is_labelled() {
        assert_eq!(cut_note(20, 31), " (showing 20 of 31)");
        assert_eq!(cut_note(3, 3), "");
    }
}
