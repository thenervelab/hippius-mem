//! Minimal `tracing` subscriber: level-filtered, plain-text lines on stderr.
//!
//! Replaces `tracing-subscriber` (`fmt` + `env-filter`), which cost the lean
//! binary ten crates — `regex-automata`, `regex-syntax`, `matchers`,
//! `nu-ansi-term`, `sharded-slab`, `thread_local`, `tracing-log`, `log`,
//! `lazy_static`, itself — for one call in `main`: install a `RUST_LOG`-filtered
//! formatter writing to stderr. This module is that call.
//!
//! `RUST_LOG` keeps `EnvFilter`'s semantics for the forms in use: a bare level
//! (a name, or `0`..`5`) names every target; `target=level` names one target
//! and its descendants, the longest matching prefix winning; a bare target
//! means `target=trace`; targets no directive names are off unless a bare level
//! is given; a set-but-empty variable disables logging; an unset one means
//! `info`. The one `EnvFilter` form not supported is the span-scoped directive
//! (`target[span{..}]=level`): it is skipped and reported with a `WARN` line
//! while the rest of the spec is honoured, and a spec with nothing readable
//! falls back to `info` — also reported.
//!
//! Lines carry a UTC timestamp, the level, the target, the message, then
//! `key=value` fields, in `tracing-subscriber`'s default order, and never ANSI
//! colour (stderr is a captured pipe under the MCP host, and the integration
//! tests had to set `NO_COLOR` to defeat it).
//!
//! Dependencies that log through the `log` facade rather than `tracing`
//! (rustls, hf-hub, tokenizers, ureq, reqwest, soketto) reach the same writer
//! and filter through [`bridge`], compiled only under the features that pull
//! such a crate in; the lean graph has none and carries no `log` dependency.
//!
//! stdout is never touched: it carries the MCP stdio protocol.

use std::cmp::Reverse;
use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata};

use crate::calendar::civil_from_days;

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

/// A directive [`Filter::parse`] could not read: malformed, or the span-scoped
/// form this filter does not support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterParseError(String);

impl fmt::Display for FilterParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unreadable {ENV_VAR} directive {:?}", self.0)
    }
}

impl std::error::Error for FilterParseError {}

/// One readable directive.
enum Directive {
    /// A bare level: the floor for every target.
    Default(LevelFilter),
    /// `target=level`, or a bare target (which means `trace`).
    Target(String, LevelFilter),
}

/// What a lenient parse made of a spec.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Parsed {
    filter: Filter,
    /// How many directives were readable.
    readable: usize,
    /// The directives that were not.
    skipped: Vec<FilterParseError>,
}

/// What reading a `RUST_LOG` spec produced — see [`Filter::from_spec_or_info`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecOutcome {
    pub(crate) filter: Filter,
    /// Directives that were skipped; each deserves one warning.
    pub(crate) skipped: Vec<FilterParseError>,
    /// True when a non-blank spec had NO readable directive, so `filter` is the
    /// `info` fallback rather than what the operator wrote.
    pub(crate) fell_back: bool,
}

impl Filter {
    /// Everything at `level` and above, for every target.
    pub(crate) const fn at_least(level: LevelFilter) -> Self {
        Self {
            default: level,
            directives: Vec::new(),
        }
    }

    /// Parse comma-separated directives strictly: every one must be readable.
    /// Test-only: production reads specs leniently through
    /// [`from_spec_or_info`](Self::from_spec_or_info).
    ///
    /// # Errors
    ///
    /// The first unreadable directive.
    #[cfg(test)]
    pub(crate) fn parse(spec: &str) -> Result<Self, FilterParseError> {
        let Parsed {
            filter, skipped, ..
        } = Self::parse_lenient(spec);
        match skipped.into_iter().next() {
            Some(err) => Err(err),
            None => Ok(filter),
        }
    }

    /// Parse every readable directive, collecting the rest.
    fn parse_lenient(spec: &str) -> Parsed {
        let mut default = LevelFilter::OFF;
        let mut directives = Vec::new();
        let mut readable = 0;
        let mut skipped = Vec::new();

        for directive in spec.split(',').map(str::trim).filter(|d| !d.is_empty()) {
            match Self::parse_directive(directive) {
                Some(Directive::Default(level)) => default = level,
                Some(Directive::Target(target, level)) => directives.push((target, level)),
                None => {
                    skipped.push(FilterParseError(directive.to_owned()));
                    continue;
                }
            }
            readable += 1;
        }

        directives.sort_by_key(|(prefix, _)| Reverse(prefix.len()));
        Parsed {
            filter: Self {
                default,
                directives,
            },
            readable,
            skipped,
        }
    }

    /// `level`, `target=level`, or a bare `target` (meaning `target=trace`, as
    /// in `EnvFilter`); `None` for anything else, including `EnvFilter`'s
    /// span-scoped syntax.
    fn parse_directive(directive: &str) -> Option<Directive> {
        if directive.contains(['[', ']', '{', '}']) {
            return None;
        }
        match directive.split_once('=') {
            Some((target, level)) => {
                let target = target.trim();
                if target.is_empty() {
                    return None;
                }
                let level = parse_level(level.trim())?;
                Some(Directive::Target(target.to_owned(), level))
            }
            None => Some(match parse_level(directive) {
                Some(level) => Directive::Default(level),
                None => Directive::Target(directive.to_owned(), LevelFilter::TRACE),
            }),
        }
    }

    /// The filter `RUST_LOG` describes — see [`from_spec_or_info`](Self::from_spec_or_info).
    pub(crate) fn from_env_or_info() -> SpecOutcome {
        Self::from_spec_or_info(std::env::var(ENV_VAR).ok().as_deref())
    }

    /// `spec` with `EnvFilter`'s fallbacks: absent means `info` (the default
    /// `main` always had); set but blank means off, as `EnvFilter` treated an
    /// empty variable; unreadable directives are skipped and reported while the
    /// readable ones apply; a spec with nothing readable falls back to `info`
    /// (what a parse error produced before) and says so.
    pub(crate) fn from_spec_or_info(spec: Option<&str>) -> SpecOutcome {
        let Some(spec) = spec else {
            return SpecOutcome {
                filter: Self::at_least(LevelFilter::INFO),
                skipped: Vec::new(),
                fell_back: false,
            };
        };
        if spec.trim().is_empty() {
            return SpecOutcome {
                filter: Self::at_least(LevelFilter::OFF),
                skipped: Vec::new(),
                fell_back: false,
            };
        }

        let Parsed {
            filter,
            readable,
            skipped,
        } = Self::parse_lenient(spec);
        if readable == 0 {
            SpecOutcome {
                filter: Self::at_least(LevelFilter::INFO),
                skipped,
                fell_back: true,
            }
        } else {
            SpecOutcome {
                filter,
                skipped,
                fell_back: false,
            }
        }
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

/// A level name (any case) or `0`..`5`, exactly the tokens `EnvFilter` accepted.
fn parse_level(text: &str) -> Option<LevelFilter> {
    text.parse::<LevelFilter>().ok()
}

/// A [`tracing::Subscriber`] that writes one line per event to `W`.
///
/// Spans are accepted (they get ids) but never printed: this codebase logs
/// with events only, and the MCP/AWS dependencies' spans carry nothing an
/// operator reads on stderr.
#[derive(Debug)]
pub(crate) struct Subscriber<W> {
    filter: Filter,
    writer: Arc<Mutex<W>>,
    next_span: AtomicU64,
}

impl<W: Write + Send + 'static> Subscriber<W> {
    /// Over a writer of its own. Test-only: production shares the writer with
    /// the `log` bridge via [`shared`](Self::shared).
    #[cfg(test)]
    pub(crate) fn new(filter: Filter, writer: W) -> Self {
        Self::shared(filter, Arc::new(Mutex::new(writer)))
    }

    /// Over a writer shared with another producer of lines (the `log` bridge).
    pub(crate) fn shared(filter: Filter, writer: Arc<Mutex<W>>) -> Self {
        Self {
            filter,
            writer,
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
        write_line(&self.writer, &line);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// One whole line under the writer's lock. A failed stderr write has nowhere
/// left to be reported, so it is dropped.
fn write_line<W: Write>(writer: &Mutex<W>, line: &str) {
    let mut writer = writer.lock().unwrap_or_else(PoisonError::into_inner);
    let _ = writer.write_all(line.as_bytes());
}

/// Install the `RUST_LOG`-filtered stderr subscriber (and, where compiled in,
/// the `log` bridge) as the process-global defaults, then report anything in
/// `RUST_LOG` that was not honoured.
///
/// # Errors
///
/// If a global subscriber is already installed.
pub(crate) fn init_stderr() -> anyhow::Result<()> {
    let outcome = Filter::from_env_or_info();
    let writer = Arc::new(Mutex::new(io::stderr()));
    tracing::subscriber::set_global_default(Subscriber::shared(
        outcome.filter.clone(),
        Arc::clone(&writer),
    ))
    .context("installing the tracing subscriber")?;
    #[cfg(feature = "log-bridge")]
    bridge::install(outcome.filter.clone(), writer);

    if outcome.fell_back {
        let skipped = joined(&outcome.skipped);
        tracing::warn!(skipped, "{ENV_VAR} was not understood; logging at info");
    } else {
        for err in &outcome.skipped {
            tracing::warn!(%err, "{ENV_VAR} directive ignored; the rest of the spec applies");
        }
    }
    Ok(())
}

/// The raw text of every skipped directive, comma-separated.
fn joined(skipped: &[FilterParseError]) -> String {
    skipped
        .iter()
        .map(|err| err.0.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `<timestamp> <LEVEL> <target>: <message> <key>=<value>...\n`.
fn format_event(event: &Event<'_>, now: SystemTime) -> String {
    let metadata = event.metadata();
    let mut line = String::with_capacity(128);
    write_prefix(&mut line, now, *metadata.level(), metadata.target());
    event.record(&mut FieldWriter(&mut line));
    line.push('\n');
    line
}

/// `<timestamp> <LEVEL> <target>:` — the head every line shares, whichever
/// facade the record came through.
fn write_prefix(line: &mut String, now: SystemTime, level: Level, target: &str) {
    write_timestamp(line, now);
    // `fmt::Write` for `String` cannot fail.
    let _ = write!(line, " {level:>5} {target}:");
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

/// `log` -> this subscriber's writer and filter, for dependencies on the `log`
/// facade. Replaces the `tracing-log` `LogTracer` the old `fmt().init()`
/// installed as a default feature, without which rustls TLS diagnostics and
/// model-download warnings would vanish from the feature builds that carry
/// those crates.
#[cfg(feature = "log-bridge")]
pub(crate) mod bridge {
    use std::fmt::Write as _;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    use tracing::Level;
    use tracing::level_filters::LevelFilter;

    use super::{Filter, write_line, write_prefix};

    /// The `log::Log` half of the subscriber: same filter, same writer, same
    /// line shape (a record has a message and no fields).
    pub(crate) struct LogBridge<W> {
        filter: Filter,
        writer: Arc<Mutex<W>>,
    }

    impl<W: Write + Send + 'static> LogBridge<W> {
        pub(crate) fn new(filter: Filter, writer: Arc<Mutex<W>>) -> Self {
            Self { filter, writer }
        }
    }

    impl<W: Write + Send + 'static> log::Log for LogBridge<W> {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            self.filter
                .enabled(level_of(metadata.level()), metadata.target())
        }

        fn log(&self, record: &log::Record<'_>) {
            if !self.enabled(record.metadata()) {
                return;
            }
            let mut line = String::with_capacity(128);
            write_prefix(
                &mut line,
                SystemTime::now(),
                level_of(record.level()),
                record.target(),
            );
            let _ = write!(line, " {}", record.args());
            line.push('\n');
            write_line(&self.writer, &line);
        }

        fn flush(&self) {}
    }

    /// Install as the process-global `log` logger. Only one logger can ever
    /// be set, so a second install is a no-op rather than an error.
    pub(crate) fn install<W: Write + Send + 'static>(filter: Filter, writer: Arc<Mutex<W>>) {
        log::set_max_level(max_level_of(filter.max_level()));
        let _ = log::set_boxed_logger(Box::new(LogBridge::new(filter, writer)));
    }

    fn level_of(level: log::Level) -> Level {
        match level {
            log::Level::Error => Level::ERROR,
            log::Level::Warn => Level::WARN,
            log::Level::Info => Level::INFO,
            log::Level::Debug => Level::DEBUG,
            log::Level::Trace => Level::TRACE,
        }
    }

    fn max_level_of(filter: LevelFilter) -> log::LevelFilter {
        match filter.into_level() {
            None => log::LevelFilter::Off,
            Some(Level::ERROR) => log::LevelFilter::Error,
            Some(Level::WARN) => log::LevelFilter::Warn,
            Some(Level::INFO) => log::LevelFilter::Info,
            Some(Level::DEBUG) => log::LevelFilter::Debug,
            Some(_) => log::LevelFilter::Trace,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::{Arc, Mutex};

        use log::Log as _;
        use tracing::level_filters::LevelFilter;

        use super::LogBridge;
        use crate::logging::Filter;
        use crate::logging::tests::Buf;

        #[test]
        fn records_render_like_events_and_obey_the_filter() {
            let buf = Buf::default();
            let bridge = LogBridge::new(
                Filter::at_least(LevelFilter::INFO),
                Arc::new(Mutex::new(buf.clone())),
            );

            bridge.log(
                &log::Record::builder()
                    .level(log::Level::Warn)
                    .target("rustls::conn")
                    .args(format_args!("tls {}", "alert"))
                    .build(),
            );
            bridge.log(
                &log::Record::builder()
                    .level(log::Level::Debug)
                    .target("rustls::conn")
                    .args(format_args!("hidden"))
                    .build(),
            );

            let out = buf.text();
            assert!(out.ends_with("  WARN rustls::conn: tls alert\n"), "{out:?}");
            assert_eq!(
                out.lines().count(),
                1,
                "a debug record is filtered: {out:?}"
            );
            assert_eq!(
                out.find('Z'),
                Some(26),
                "a UTC stamp leads the line: {out:?}"
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests assert on fixed, known-valid filter specs"
    )]

    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, UNIX_EPOCH};

    use tracing::Level;
    use tracing::level_filters::LevelFilter;

    use super::{Filter, FilterParseError, SpecOutcome, Subscriber, write_timestamp};

    #[derive(Clone, Default)]
    pub(crate) struct Buf(Arc<Mutex<Vec<u8>>>);

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
        pub(crate) fn text(&self) -> String {
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
    fn numeric_levels_parse_like_env_filter() {
        assert_eq!(
            Filter::parse("3").unwrap(),
            Filter::at_least(LevelFilter::INFO)
        );
        assert_eq!(
            Filter::parse("0").unwrap(),
            Filter::at_least(LevelFilter::OFF)
        );
        assert_eq!(
            Filter::parse("5").unwrap(),
            Filter::at_least(LevelFilter::TRACE)
        );
        let filter = Filter::parse("hippius_mem=4").unwrap();
        assert!(filter.enabled(Level::DEBUG, "hippius_mem::gc"));
        assert!(!filter.enabled(Level::TRACE, "hippius_mem::gc"));
        assert!(
            Filter::parse("6").unwrap().enabled(Level::TRACE, "6"),
            "not a level: a target"
        );
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
    fn unreadable_directives_are_errors_under_strict_parse() {
        for spec in [
            "[span]=info",
            "hippius_mem=loud",
            "=info",
            "a{b}=warn",
            "t[s]=info",
        ] {
            assert!(Filter::parse(spec).is_err(), "{spec:?} must not parse");
        }
    }

    #[test]
    fn env_spec_keeps_env_filter_fallbacks() {
        let info = Filter::at_least(LevelFilter::INFO);
        let clean = |filter: Filter| SpecOutcome {
            filter,
            skipped: Vec::new(),
            fell_back: false,
        };

        // Unset: info. Set but blank: off, as EnvFilter treated an empty variable.
        assert_eq!(Filter::from_spec_or_info(None), clean(info.clone()));
        assert_eq!(
            Filter::from_spec_or_info(Some("")),
            clean(Filter::at_least(LevelFilter::OFF))
        );
        assert_eq!(
            Filter::from_spec_or_info(Some(" \t ")),
            clean(Filter::at_least(LevelFilter::OFF))
        );

        let outcome = Filter::from_spec_or_info(Some("warn,hippius_mem=debug"));
        assert!(!outcome.fell_back && outcome.skipped.is_empty());
        assert!(outcome.filter.enabled(Level::DEBUG, "hippius_mem::gc"));
        assert!(!outcome.filter.enabled(Level::INFO, "hyper"));

        // Nothing readable: info, and the fallback is flagged for a warning.
        for bad in ["hippius_mem=loud", "[span]=info"] {
            let outcome = Filter::from_spec_or_info(Some(bad));
            assert_eq!(outcome.filter, info, "{bad:?} falls back to info");
            assert!(outcome.fell_back);
            assert_eq!(outcome.skipped, vec![FilterParseError(bad.to_owned())]);
        }
    }

    #[test]
    fn an_unsupported_directive_is_skipped_and_the_rest_still_applies() {
        // On EnvFilter this was `error` everywhere plus debug inside `recall`
        // spans; here the span directive is skipped, and `error` still holds —
        // verbosity is never raised above what the operator asked for.
        let outcome = Filter::from_spec_or_info(Some("error,hippius_mem[recall]=debug,rmcp=warn"));
        assert!(!outcome.fell_back);
        assert_eq!(
            outcome.skipped,
            vec![FilterParseError("hippius_mem[recall]=debug".to_owned())]
        );
        assert!(outcome.filter.enabled(Level::ERROR, "hippius_mem::server"));
        assert!(!outcome.filter.enabled(Level::WARN, "hippius_mem::server"));
        assert!(outcome.filter.enabled(Level::WARN, "rmcp::service"));
        assert!(!outcome.filter.enabled(Level::INFO, "rmcp::service"));
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
    fn timestamps_render_utc_with_microseconds() {
        let mut out = String::new();
        write_timestamp(
            &mut out,
            UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789),
        );
        assert_eq!(
            out, "2023-11-14T22:13:20.123456Z",
            "microseconds, truncated"
        );
        let mut out = String::new();
        write_timestamp(&mut out, UNIX_EPOCH);
        assert_eq!(out, "1970-01-01T00:00:00.000000Z");
    }
}
