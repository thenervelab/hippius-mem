//! Minimal `tracing` subscriber: level-filtered, plain-text lines on stderr.
//!
//! Replaces `tracing-subscriber` (`fmt` + `env-filter`), which cost the lean
//! binary ten crates — `regex-automata`, `regex-syntax`, `matchers`,
//! `nu-ansi-term`, `sharded-slab`, `thread_local`, `tracing-log`, `log`,
//! `lazy_static`, itself — for one call in `main`: install a `RUST_LOG`-filtered
//! formatter writing to stderr. This module is that call.
//!
//! Kept: `RUST_LOG` directives of the two forms in use — a bare level (`info`)
//! and `target=level` (`hippius_mem=debug,rmcp=warn`), where the longest
//! matching target prefix wins and targets no directive names are off (a bare
//! level names every target). Lines carry a UTC timestamp, the level, the
//! target, the message, then `key=value` fields, in `tracing-subscriber`'s
//! default order. Dropped: span-scoped directives (`[span{..}]`), ANSI colour
//! (stderr is a captured pipe under the MCP host, and the integration tests
//! had to set `NO_COLOR` to defeat it), and the `log`-crate bridge (nothing in
//! the lean graph emits `log` records).
//!
//! stdout is never touched: it carries the MCP stdio protocol.

use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata};

/// The variable [`Filter::from_env_or_info`] reads, as `EnvFilter` did.
pub(crate) const ENV_VAR: &str = "RUST_LOG";

/// A parsed `RUST_LOG`-style filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Filter {
    /// Applies to a target no directive names.
    default: LevelFilter,
    /// `(target prefix, level)`, longest prefix first so the first match is the
    /// most specific.
    directives: Vec<(String, LevelFilter)>,
}

/// A directive [`Filter::parse`] could not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterParseError(String);

impl fmt::Display for FilterParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unreadable {ENV_VAR} directive {:?}", self.0)
    }
}

impl std::error::Error for FilterParseError {}

impl Filter {
    /// Everything at `level` and above, for every target.
    pub(crate) const fn at_least(level: LevelFilter) -> Self {
        Self {
            default: level,
            directives: Vec::new(),
        }
    }

    /// Parse comma-separated directives: `level`, `target=level`, or a bare
    /// `target` (meaning `target=trace`, as in `EnvFilter`). Levels are
    /// case-insensitive `off` / `error` / `warn` / `info` / `debug` / `trace`.
    /// With no bare level, unnamed targets are off.
    ///
    /// # Errors
    ///
    /// The first directive that is neither form, including `EnvFilter`'s
    /// span-scoped syntax, which this filter does not support.
    pub(crate) fn parse(spec: &str) -> Result<Self, FilterParseError> {
        let mut default = LevelFilter::OFF;
        let mut directives = Vec::new();

        for directive in spec.split(',').map(str::trim).filter(|d| !d.is_empty()) {
            let unreadable = || FilterParseError(directive.to_owned());
            if directive.contains(['[', '{', ']', '}']) {
                return Err(unreadable());
            }
            match directive.split_once('=') {
                Some((target, level)) => {
                    let target = target.trim();
                    if target.is_empty() {
                        return Err(unreadable());
                    }
                    let level = parse_level(level.trim()).ok_or_else(unreadable)?;
                    directives.push((target.to_owned(), level));
                }
                None => match parse_level(directive) {
                    Some(level) => default = level,
                    None => directives.push((directive.to_owned(), LevelFilter::TRACE)),
                },
            }
        }

        directives.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.len()));
        Ok(Self {
            default,
            directives,
        })
    }

    /// The filter `RUST_LOG` describes, or plain `info` when the variable is
    /// unset, empty, or unreadable — the same fallback `main` always had.
    pub(crate) fn from_env_or_info() -> Self {
        std::env::var(ENV_VAR)
            .ok()
            .filter(|spec| !spec.trim().is_empty())
            .and_then(|spec| Self::parse(&spec).ok())
            .unwrap_or(Self::at_least(LevelFilter::INFO))
    }

    fn enabled(&self, level: Level, target: &str) -> bool {
        let allowed = self
            .directives
            .iter()
            .find(|(prefix, _)| target.starts_with(prefix.as_str()))
            .map_or(self.default, |(_, level)| *level);
        // `tracing` orders levels by verbosity: TRACE is the greatest, so a
        // filter admits every level at or below it.
        allowed >= level
    }

    /// The most verbose level any directive admits, for `tracing`'s static
    /// max-level fast path.
    fn max_level(&self) -> LevelFilter {
        self.directives
            .iter()
            .map(|(_, level)| *level)
            .fold(self.default, LevelFilter::max)
    }
}

fn parse_level(text: &str) -> Option<LevelFilter> {
    match text.to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::OFF),
        "error" => Some(LevelFilter::ERROR),
        "warn" => Some(LevelFilter::WARN),
        "info" => Some(LevelFilter::INFO),
        "debug" => Some(LevelFilter::DEBUG),
        "trace" => Some(LevelFilter::TRACE),
        _ => None,
    }
}

/// A [`tracing::Subscriber`] that writes one line per event to `W`.
///
/// Spans are accepted (they get ids) but never printed: this codebase logs
/// with events only, and the MCP/AWS dependencies' spans carry nothing an
/// operator reads on stderr.
#[derive(Debug)]
pub(crate) struct Subscriber<W> {
    filter: Filter,
    writer: Mutex<W>,
    next_span: AtomicU64,
}

impl<W: Write + Send + 'static> Subscriber<W> {
    pub(crate) fn new(filter: Filter, writer: W) -> Self {
        Self {
            filter,
            writer: Mutex::new(writer),
            // Span ids must be non-zero.
            next_span: AtomicU64::new(1),
        }
    }
}

impl<W: Write + Send + 'static> tracing::Subscriber for Subscriber<W> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.filter.enabled(*metadata.level(), metadata.target())
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(self.filter.max_level())
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed))
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let line = format_event(event, SystemTime::now());
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        // A failed stderr write has nowhere left to be reported.
        let _ = writer.write_all(line.as_bytes());
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Install the `RUST_LOG`-filtered stderr subscriber as the process-global
/// default.
///
/// # Errors
///
/// If a global subscriber is already installed.
pub(crate) fn init_stderr() -> anyhow::Result<()> {
    tracing::subscriber::set_global_default(Subscriber::new(
        Filter::from_env_or_info(),
        io::stderr(),
    ))
    .context("installing the tracing subscriber")
}

/// `<timestamp> <LEVEL> <target>: <message> <key>=<value>...\n`.
fn format_event(event: &Event<'_>, now: SystemTime) -> String {
    let metadata = event.metadata();
    let mut line = String::with_capacity(128);
    write_timestamp(&mut line, now);
    // `fmt::Write` for `String` cannot fail.
    let _ = write!(line, " {:>5} {}:", metadata.level(), metadata.target());
    event.record(&mut FieldWriter(&mut line));
    line.push('\n');
    line
}

/// Renders fields the way `tracing-subscriber`'s default formatter did: the
/// `message` bare, every other field as `name=value` with `Debug` values (so
/// strings are quoted) and errors via `Display`.
struct FieldWriter<'a>(&'a mut String);

impl Visit for FieldWriter<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _ = if field.name() == "message" {
            write!(self.0, " {value:?}")
        } else {
            write!(self.0, " {}={value:?}", field.name())
        };
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.push(' ');
            self.0.push_str(value);
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        let _ = write!(self.0, " {}={value}", field.name());
    }
}

/// `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC, microseconds), the shape
/// `tracing-subscriber` printed. A clock before the epoch prints the epoch.
fn write_timestamp(out: &mut String, now: SystemTime) {
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let seconds = since_epoch.as_secs();
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let second_of_day = seconds % 86_400;
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:06}Z",
        second_of_day / 3600,
        second_of_day % 3600 / 60,
        second_of_day % 60,
        since_epoch.subsec_micros()
    );
}

/// Proleptic-Gregorian `(year, month, day)` for a day count since 1970-01-01
/// (Howard Hinnant's `civil_from_days`, unsigned form).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests assert on fixed, known-valid filter specs"
    )]

    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, UNIX_EPOCH};

    use tracing::Level;
    use tracing::level_filters::LevelFilter;

    use super::{Filter, Subscriber, civil_from_days, write_timestamp};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn capture(spec: &str, f: impl FnOnce()) -> String {
        let buf = Buf::default();
        let subscriber = Subscriber::new(Filter::parse(spec).unwrap(), buf.clone());
        tracing::subscriber::with_default(subscriber, f);
        buf.text()
    }

    #[test]
    fn bare_level_names_every_target() {
        let filter = Filter::parse("info").unwrap();
        assert_eq!(filter, Filter::at_least(LevelFilter::INFO));
        assert!(filter.enabled(Level::INFO, "anything"));
        assert!(filter.enabled(Level::ERROR, "anything"));
        assert!(!filter.enabled(Level::DEBUG, "anything"));
        assert_eq!(filter.max_level(), LevelFilter::INFO);
    }

    #[test]
    fn target_directives_match_by_longest_prefix_and_unnamed_targets_are_off() {
        let filter = Filter::parse("hippius_mem=warn, hippius_mem::gc=trace,rmcp=INFO").unwrap();
        assert!(filter.enabled(Level::TRACE, "hippius_mem::gc"));
        assert!(!filter.enabled(Level::INFO, "hippius_mem::brief"));
        assert!(filter.enabled(Level::WARN, "hippius_mem::brief"));
        assert!(filter.enabled(Level::INFO, "rmcp::service"));
        assert!(!filter.enabled(Level::DEBUG, "rmcp::service"));
        assert!(
            !filter.enabled(Level::ERROR, "hyper"),
            "unnamed targets are off"
        );
        assert_eq!(filter.max_level(), LevelFilter::TRACE);
    }

    #[test]
    fn a_bare_level_plus_directives_sets_the_floor_for_the_rest() {
        let filter = Filter::parse("info,hippius_mem=debug").unwrap();
        assert!(filter.enabled(Level::DEBUG, "hippius_mem"));
        assert!(!filter.enabled(Level::DEBUG, "hyper"));
        assert!(filter.enabled(Level::INFO, "hyper"));
        assert_eq!(filter.max_level(), LevelFilter::DEBUG);
        // A bare target means trace for it, as in EnvFilter.
        let filter = Filter::parse("warn,hippius_mem").unwrap();
        assert!(filter.enabled(Level::TRACE, "hippius_mem::x"));
        assert!(!filter.enabled(Level::INFO, "other"));
    }

    #[test]
    fn off_and_empty_specs_enable_nothing() {
        assert_eq!(Filter::parse("off").unwrap().max_level(), LevelFilter::OFF);
        assert!(!Filter::parse("off").unwrap().enabled(Level::ERROR, "x"));
        assert!(!Filter::parse("").unwrap().enabled(Level::ERROR, "x"));
    }

    #[test]
    fn unreadable_directives_are_errors() {
        for spec in ["[span]=info", "hippius_mem=loud", "=info", "a{b}=warn"] {
            assert!(Filter::parse(spec).is_err(), "{spec:?} must not parse");
        }
    }

    #[test]
    fn lines_carry_timestamp_level_target_message_and_fields() {
        let out = capture("trace", || {
            tracing::info!(target: "t", count = 3, name = "x", "hello {}", 1);
        });
        let (stamp, rest) = out.split_once(' ').unwrap();
        assert_eq!(stamp.len(), "2026-08-25T10:00:00.123456Z".len(), "{stamp}");
        assert_eq!(&stamp[10..11], "T");
        assert!(stamp.ends_with('Z'));
        assert_eq!(rest, " INFO t: hello 1 count=3 name=\"x\"\n");

        let err = io::Error::other("boom");
        let out = capture("trace", || {
            tracing::warn!(target: "t", error = &err as &dyn std::error::Error, "failed");
        });
        assert!(out.ends_with("  WARN t: failed error=boom\n"), "{out}");
    }

    #[test]
    fn filtered_events_produce_no_output() {
        let out = capture("warn", || {
            tracing::info!(target: "t", "hidden");
            tracing::warn!(target: "t", "shown");
        });
        assert!(!out.contains("hidden"));
        assert!(out.contains("shown"));
    }

    #[test]
    fn timestamps_render_utc_calendar_dates() {
        // (seconds since the epoch, expected) — checked against Python's datetime.
        let vectors = [
            (0, "1970-01-01T00:00:00.000000Z"),
            (86_399, "1970-01-01T23:59:59.000000Z"),
            (951_782_400, "2000-02-29T00:00:00.000000Z"),
            (1_700_000_000, "2023-11-14T22:13:20.000000Z"),
            (1_709_164_800, "2024-02-29T00:00:00.000000Z"),
            (4_102_444_800, "2100-01-01T00:00:00.000000Z"),
            (253_402_300_799, "9999-12-31T23:59:59.000000Z"),
        ];
        for (seconds, expected) in vectors {
            let mut out = String::new();
            write_timestamp(&mut out, UNIX_EPOCH + Duration::from_secs(seconds));
            assert_eq!(out, expected);
        }
        let mut out = String::new();
        write_timestamp(
            &mut out,
            UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789),
        );
        assert_eq!(
            out, "2023-11-14T22:13:20.123456Z",
            "microsecond precision, truncated"
        );
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(59), (1970, 3, 1));
    }
}
