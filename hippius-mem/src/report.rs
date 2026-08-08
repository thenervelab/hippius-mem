//! The `report` subcommand: render the team's converged-memory digest to
//! stdout — the artifact a champion pastes into a buying conversation.
//!
//! Reuse leads: the design's argument order is proof first (teammates keep
//! coming back to specific notes, all-time), then volume (how much the team
//! is writing right now, windowed). [`render_markdown`] renders that order
//! from a [`TeamReport`] built by [`hippius_mem_core::build_report`]; the
//! dashboard's `/api/vaults/{vault}/report` endpoint (`dashboard/mod.rs`)
//! serves the identical `TeamReport` as JSON so the two surfaces can never
//! silently diverge — both are thin wrappers over the one aggregation.
//!
//! `report` is a new entry point that reads the FULL team op-log, exactly
//! like `brief` (`brief.rs`) and the server's warmup (`main.rs`): it wires
//! [`crate::admin::bootstrap_epochs`] before reading, mirroring `brief.rs`'s
//! sequence, so a member provisioned after a team-key rotation reports on
//! rotated-epoch notes too — the recorded gotcha (omitting this silently
//! drops every note sealed under an epoch past the founding one) has already
//! recurred twice. Unlike `brief`, which is a best-effort `SessionStart` hook
//! that must never fail, `report` is a deliberate operator command: a bad
//! config or an unbuildable store is a real error, not a silent empty output.

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use hippius_mem_core::{ActivityCounts, MAX_REUSE_ENTRIES, NoteReuse, ReportWindow, TeamReport};

use crate::config::Config;
use crate::resolve_and_build_store;

/// Default `--since` span when the flag is omitted: one week.
pub(crate) const DEFAULT_SINCE: Duration = Duration::from_hours(7 * 24);

/// Seconds in a day, for [`parse_since_value`]'s day/week arithmetic.
const SECS_PER_DAY: u64 = 86_400;

/// Parse `--since`, build the team's report over the trailing window, and
/// print its rendered markdown to stdout.
///
/// `--since` is parsed BEFORE any config or store is touched, so a bogus
/// value fails fast — a `hippius-mem report --since bogus` run against a
/// broken or absent config still reports the flag error, not a confusing
/// config error.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let since = parse_since(args)?;

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    let (store, _launch_repo) = resolve_and_build_store(&cfg).await?;

    // Mirrors `brief.rs` exactly: load the epoch key-ring before reading, so
    // a member provisioned after a team-key rotation reports on rotated-epoch
    // notes too (the recorded `bootstrap_epochs` gotcha). Best-effort and
    // mnemonic-gated, matching the server warmup and the dashboard's
    // per-vault `store_for`.
    if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
        crate::admin::bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    }
    crate::admin::warn_if_max_epoch_stale(&store, cfg.max_epoch).await;
    let _ = store.refresh_if_stale().await;

    let window = window_since(SystemTime::now(), since);
    let report = hippius_mem_core::build_report(&store, window).await?;
    let markdown = render_markdown(&report);

    // Direct handle write: `report`'s whole purpose is emitting the digest to
    // stdout for a human (or a paste into a chat) to read, but the workspace
    // denies the `print!` family.
    std::io::stdout().write_all(markdown.as_bytes())?;
    Ok(())
}

/// Parse the optional `--since Nd|Nw` flag; `Ok(DEFAULT_SINCE)` when the flag
/// is absent.
///
/// # Errors
///
/// Returns an error naming the accepted forms when `--since` is present but
/// its value is neither `Nd` (days) nor `Nw` (weeks).
fn parse_since(args: &[String]) -> anyhow::Result<Duration> {
    let Some(idx) = args.iter().position(|arg| arg == "--since") else {
        return Ok(DEFAULT_SINCE);
    };
    let value = args.get(idx + 1).map_or("", String::as_str);

    parse_since_value(value).ok_or_else(|| {
        anyhow::anyhow!(
            "unrecognized --since value `{value}`; accepted forms: Nd (days) or Nw \
             (weeks) — e.g. `7d`, `2w`; default 7d"
        )
    })
}

/// Parse a single `--since` value: a positive integer followed by `d` (days)
/// or `w` (weeks). `None` for anything else, including a bare number with no
/// unit suffix — the brief accepts only the two suffixed forms.
///
/// `count` is bounded by `checked_mul` rather than `saturating_mul`: a
/// saturated multiply would silently hand `Duration::from_secs` a value one
/// multiplication away from overflowing again, so an absurdly large `--since`
/// (nobody's real use case) cleanly falls through to the "unrecognized"
/// error instead of risking a panic deeper in the `Duration` arithmetic.
fn parse_since_value(value: &str) -> Option<Duration> {
    let split_at = value.len().checked_sub(1)?;
    let (digits, unit) = value.split_at(split_at);
    let count: u64 = digits.parse().ok()?;

    let secs = match unit {
        "d" => count.checked_mul(SECS_PER_DAY)?,
        "w" => count.checked_mul(7)?.checked_mul(SECS_PER_DAY)?,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

/// Compute the half-open [`ReportWindow`] ending at `now` and spanning back
/// `since`. Core never reads the clock (see `hippius-mem-core/src/report.rs`
/// module docs) — this is the one place "now" is read, and only the CLI (and
/// the dashboard, which calls this same helper via `crate::report::window_since`
/// for its own "This week" panel) does it.
pub(crate) fn window_since(now: SystemTime, since: Duration) -> ReportWindow {
    let start = now.checked_sub(since).unwrap_or(UNIX_EPOCH);
    ReportWindow {
        since_ms: to_millis(start),
        until_ms: to_millis(now),
    }
}

/// Milliseconds since the epoch, saturating rather than panicking on the
/// practically-impossible clock-before-epoch edge.
fn to_millis(t: SystemTime) -> u64 {
    let elapsed = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// Render `report` as markdown, reuse leading (all-time, cumulative) and
/// activity following (windowed) — the design's argument order — with a
/// trailing honesty caveat grounding both in what this machine's local,
/// synced copy of team memory actually holds.
///
/// A pure function of `report`: no I/O, no clock read, so it is exhaustively
/// unit-tested below without needing a store. Every `writeln!` below discards
/// its `Result` with `let _ =`: `fmt::Write` on a `String` is infallible, so
/// there is nothing to propagate.
pub(crate) fn render_markdown(report: &TeamReport) -> String {
    let mut out = String::new();

    write_header(&mut out, report);
    write_reuse_section(&mut out, report);
    write_activity_section(&mut out, report);
    write_machine_section(&mut out, report);

    out
}

/// Human-readable description of a [`ReportWindow`]'s span, e.g. "the last 7
/// days". Duration-only (no calendar dates): `ReportWindow` carries only
/// epoch milliseconds, and rendering a correct calendar date needs a
/// date/time dependency this module has no other reason to pull in.
fn describe_span(window: ReportWindow) -> String {
    let span_ms = window.until_ms.saturating_sub(window.since_ms);
    let days = span_ms / 86_400_000;
    match days {
        0 => "less than a day".to_owned(),
        1 => "the last day".to_owned(),
        n => format!("the last {n} days"),
    }
}

fn write_header(out: &mut String, report: &TeamReport) {
    let _ = writeln!(out, "# Hippius Memory — Team Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "Window: {}", describe_span(report.window));
    let _ = writeln!(out);
}

/// "Reused notes" leads the report — all-time, cumulative by design (the
/// controller ruling recorded against Task 13): `NoteReuse` carries no
/// reinforcement timestamps, so it cannot be window-filtered, and the header
/// says so explicitly rather than let a reader assume it is scoped to the
/// window like activity below it.
fn write_reuse_section(out: &mut String, report: &TeamReport) {
    let _ = writeln!(out, "## Reused notes (all-time, cumulative)");
    let _ = writeln!(out);

    if report.reuse.is_empty() {
        let _ = writeln!(out, "No notes have been reused yet.");
    } else {
        for entry in &report.reuse {
            write_reuse_entry(out, entry);
        }
        write_reuse_cap_note(out, report);
    }
    let _ = writeln!(out);
}

fn write_reuse_entry(out: &mut String, entry: &NoteReuse) {
    let _ = writeln!(
        out,
        "- `{}` — saved {}",
        entry.summary,
        teammate_count(entry.distinct_reinforcers)
    );
}

/// "top 20 of N" — never a silent truncation: printed only when `reuse_total`
/// (the pre-cap count `build_report` carries) exceeds the entries actually
/// shown.
fn write_reuse_cap_note(out: &mut String, report: &TeamReport) {
    let shown = u64::try_from(report.reuse.len()).unwrap_or(u64::MAX);
    if report.reuse_total > shown {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "_top {MAX_REUSE_ENTRIES} of {} reused notes shown._",
            report.reuse_total
        );
    }
}

fn teammate_count(n: u64) -> String {
    if n == 1 {
        "1 teammate".to_owned()
    } else {
        format!("{n} teammates")
    }
}

fn write_activity_section(out: &mut String, report: &TeamReport) {
    let _ = writeln!(out, "## Activity ({})", describe_span(report.window));
    let _ = writeln!(out);
    let _ = writeln!(out, "| Metric | Count |");
    let _ = writeln!(out, "| --- | --- |");
    let a = &report.activity;
    let _ = writeln!(out, "| Added | {} |", a.added);
    let _ = writeln!(out, "| Edited | {} |", a.edited);
    let _ = writeln!(out, "| Linked | {} |", a.linked);
    let _ = writeln!(out, "| Tombstoned | {} |", a.tombstoned);
    let _ = writeln!(out, "| Redacted | {} |", a.redacted);
    let _ = writeln!(out);
}

/// The trailing honesty caveat: both sections above are read from THIS
/// machine's local, best-effort-synced copy of the team op-log (`build_report`
/// never fetches from teammates itself — see the core module docs), so the
/// numbers can lag behind a teammate's not-yet-synced write. The literal
/// phrase "this machine only" is a controller-mandated carry-forward — do
/// not reword it away.
fn write_machine_section(out: &mut String, report: &TeamReport) {
    let _ = writeln!(out, "## This machine");
    let _ = writeln!(out);
    let total = total_activity(&report.activity);
    let _ = writeln!(
        out,
        "This machine's locally synced memory logged {total} update(s) in this \
         window (this machine only) — run a fresh sync before reporting for the \
         most current picture."
    );
}

fn total_activity(a: &ActivityCounts) -> u64 {
    a.added
        .saturating_add(a.edited)
        .saturating_add(a.linked)
        .saturating_add(a.tombstoned)
        .saturating_add(a.redacted)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert on markers whose absence IS the failure; a panic-with-\
                  message here is the assertion, not a crash to avoid"
    )]

    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use hippius_mem_core::{ActivityCounts, NoteReuse, ReportWindow, TeamReport};

    use super::{parse_since_value, render_markdown, window_since};

    fn window(days: u64) -> ReportWindow {
        ReportWindow {
            since_ms: 0,
            until_ms: days * 86_400_000,
        }
    }

    fn report_with(
        reuse: Vec<NoteReuse>,
        reuse_total: u64,
        activity: ActivityCounts,
    ) -> TeamReport {
        TeamReport {
            window: window(7),
            reuse,
            reuse_total,
            activity,
        }
    }

    fn note_reuse(id: &str, summary: &str, distinct_reinforcers: u64) -> NoteReuse {
        NoteReuse {
            id: id.to_owned(),
            summary: summary.to_owned(),
            distinct_reinforcers,
        }
    }

    // ---- render_markdown ----------------------------------------------

    #[test]
    fn reuse_section_leads_activity_which_leads_this_machine() {
        let report = report_with(
            vec![note_reuse("mem_a", "a reused note", 2)],
            1,
            ActivityCounts {
                added: 1,
                ..ActivityCounts::default()
            },
        );
        let markdown = render_markdown(&report);

        let reuse_at = markdown.find("## Reused").expect("reuse header present");
        let activity_at = markdown
            .find("## Activity")
            .expect("activity header present");
        let machine_at = markdown
            .find("## This machine")
            .expect("this-machine header present");
        assert!(reuse_at < activity_at, "reuse must lead: {markdown}");
        assert!(
            activity_at < machine_at,
            "activity must precede the this-machine section: {markdown}"
        );
    }

    #[test]
    fn reuse_section_is_labeled_all_time_distinct_from_windowed_activity() {
        let report = report_with(vec![], 0, ActivityCounts::default());
        let markdown = render_markdown(&report);

        assert!(
            markdown.contains("## Reused notes (all-time, cumulative)"),
            "reuse must be labeled all-time/cumulative: {markdown}"
        );
        assert!(
            markdown.contains("## Activity (the last 7 days)"),
            "activity must be labeled with the window span, not all-time: {markdown}"
        );
    }

    #[test]
    fn reuse_entry_uses_saved_phrasing_and_pluralizes_teammates() {
        let report = report_with(
            vec![
                note_reuse("mem_a", "singular teammate note", 1),
                note_reuse("mem_b", "plural teammates note", 3),
            ],
            2,
            ActivityCounts::default(),
        );
        let markdown = render_markdown(&report);

        assert!(markdown.contains("`singular teammate note` — saved 1 teammate\n"));
        assert!(markdown.contains("`plural teammates note` — saved 3 teammates\n"));
    }

    #[test]
    fn cap_note_appears_only_when_reuse_total_exceeds_shown_entries() {
        let truncated = report_with(
            vec![note_reuse("mem_a", "shown note", 5)],
            25,
            ActivityCounts::default(),
        );
        let markdown = render_markdown(&truncated);
        assert!(
            markdown.contains("top 20 of 25 reused notes shown"),
            "a truncated reuse list must say so, not silently drop entries: {markdown}"
        );

        let untruncated = report_with(
            vec![note_reuse("mem_a", "shown note", 5)],
            1,
            ActivityCounts::default(),
        );
        let markdown = render_markdown(&untruncated);
        assert!(
            !markdown.contains("top 20"),
            "no cap note when nothing was truncated: {markdown}"
        );
    }

    #[test]
    fn empty_reuse_says_so_rather_than_an_empty_list() {
        let report = report_with(vec![], 0, ActivityCounts::default());
        let markdown = render_markdown(&report);
        assert!(markdown.contains("No notes have been reused yet."));
    }

    #[test]
    fn this_machine_section_carries_the_literal_label() {
        let report = report_with(vec![], 0, ActivityCounts::default());
        let markdown = render_markdown(&report);
        assert!(
            markdown.contains("this machine only"),
            "the mandated literal label must appear verbatim: {markdown}"
        );
    }

    #[test]
    fn this_machine_section_totals_the_activity_counts() {
        let report = report_with(
            vec![],
            0,
            ActivityCounts {
                added: 2,
                edited: 1,
                linked: 1,
                tombstoned: 1,
                redacted: 0,
            },
        );
        let markdown = render_markdown(&report);
        assert!(
            markdown.contains("logged 5 update(s)"),
            "2+1+1+1+0 = 5: {markdown}"
        );
    }

    #[test]
    fn activity_table_renders_every_metric() {
        let report = report_with(
            vec![],
            0,
            ActivityCounts {
                added: 3,
                edited: 2,
                linked: 1,
                tombstoned: 4,
                redacted: 5,
            },
        );
        let markdown = render_markdown(&report);
        assert!(markdown.contains("| Added | 3 |"));
        assert!(markdown.contains("| Edited | 2 |"));
        assert!(markdown.contains("| Linked | 1 |"));
        assert!(markdown.contains("| Tombstoned | 4 |"));
        assert!(markdown.contains("| Redacted | 5 |"));
    }

    // ---- parse_since_value ---------------------------------------------

    #[test]
    fn parses_days_and_weeks() {
        let one_day = Duration::from_hours(24);
        assert_eq!(parse_since_value("7d"), Some(one_day * 7));
        assert_eq!(parse_since_value("2w"), Some(one_day * 14));
        assert_eq!(parse_since_value("0d"), Some(Duration::ZERO));
    }

    #[test]
    fn rejects_bare_numbers_and_unknown_units() {
        assert_eq!(parse_since_value("7"), None, "no unit suffix");
        assert_eq!(
            parse_since_value("7m"),
            None,
            "months is not an accepted unit"
        );
        assert_eq!(parse_since_value("bogus"), None);
        assert_eq!(parse_since_value(""), None);
        assert_eq!(parse_since_value("d"), None, "no digits");
    }

    // ---- window_since ----------------------------------------------------

    #[test]
    fn window_since_spans_back_from_now() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let window = window_since(now, Duration::from_secs(100));
        assert_eq!(window.until_ms, 1_000_000_000);
        assert_eq!(window.since_ms, 999_900_000);
    }

    #[test]
    fn window_since_clamps_to_the_epoch_rather_than_underflowing() {
        let now = UNIX_EPOCH + Duration::from_secs(10);
        let window = window_since(now, Duration::from_secs(100));
        assert_eq!(window.since_ms, 0, "clamped to the epoch, not a panic");
        assert_eq!(window.until_ms, 10_000);
    }

    // Kept for completeness even though `SystemTime::now()` is not itself
    // deterministic: proves `window_since` composes with the real clock
    // without panicking and produces a sane (non-empty, ending "now"-ish) span.
    #[test]
    fn window_since_composes_with_the_real_clock() {
        let before = SystemTime::now();
        let window = window_since(SystemTime::now(), super::DEFAULT_SINCE);
        let after = SystemTime::now();
        assert!(window.since_ms < window.until_ms);
        assert!(window.until_ms >= super::to_millis(before));
        assert!(window.until_ms <= super::to_millis(after));
    }
}
