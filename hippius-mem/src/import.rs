//! The `hippius-mem import claude-mem` subcommand.
//!
//! Lifts durable observations from a local claude-mem `SQLite` store
//! (`~/.claude-mem/claude-mem.db`) into shared team memory as hippius-mem notes.
//!
//! claude-mem records per-session *observations* — decisions, bugfixes,
//! discoveries — in a local `SQLite` `observations` table. This subcommand maps the
//! genuinely team-durable ones (by default only `decision` and `bugfix`, the two
//! that carry a lasting lesson rather than per-session narration) onto hippius-mem
//! notes and appends them through the same signed op-log every `remember` uses.
//!
//! # Why a filter, not a firehose
//!
//! A single project can hold thousands of observations, ~75% of which are
//! `discovery`/`change` session narration that would drown recall. So the default
//! is the durable subset; `--all` / `--type` widen it deliberately. Team-relevance
//! is the one judgment a mechanical importer cannot make, so the safe default is
//! narrow and the operator opts into more.
//!
//! # Idempotency
//!
//! Every imported note carries a provenance tag `cmem:<session>:<obs_id>` (plus a
//! flat `source:claude-mem`). Before importing, the store is synced and its
//! existing notes scanned for those tags, so a re-run — or an incremental
//! `--since` run as claude-mem grows — never duplicates a note already lifted.
//!
//! The live-index scan alone is not enough: `forget`-tombstoning a note removes
//! it from the converged index, so a later re-run would read its tag as "never
//! imported" and resurrect it under a brand-new id. A local ledger file (see
//! [`load_ledger`]/[`save_ledger`]) records every provenance tag this command has
//! ever written, independent of whether the note is still live, closing that
//! gap — see the module's tests for the resurrection scenario this prevents.

use std::collections::BTreeSet;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use hippius_mem_core::{NoteType, RememberInput, RepoScope};
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags};

use crate::config::Config;
use crate::resolve_and_build_store;

/// claude-mem `SQLite` path relative to `$HOME` when `--db` is not given.
const DEFAULT_DB_REL: &str = ".claude-mem/claude-mem.db";

/// The observation types imported by default: the two that carry a durable lesson
/// (a decision and its rationale, a bug and its fix) rather than session narration.
const DEFAULT_TYPES: &[&str] = &["decision", "bugfix"];

/// Every claude-mem observation type, selected by `--all`. Mirrors the `CHECK`
/// constraint on `observations.type`; an unknown `--type` is rejected against it.
const ALL_TYPES: &[&str] = &[
    "decision",
    "bugfix",
    "feature",
    "refactor",
    "discovery",
    "change",
];

/// Run the `import claude-mem` subcommand over the args following `import`.
///
/// Loads the same [`Config`] the server boots from, builds the routed team's
/// store, and appends a note per selected observation — skipping any already
/// imported (by provenance tag) so the command is safe to re-run. With
/// `--dry-run` it reports what it would import and writes nothing.
///
/// # Errors
///
/// Returns an error if the first positional argument is not `claude-mem`, an
/// argument is malformed, the configuration is missing/malformed, the store
/// cannot be built, the `SQLite` database cannot be opened or queried, or a note
/// write fails.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    // The only supported source today is claude-mem; require it explicitly so a
    // future `import <other>` cannot silently resolve to this path.
    match args.first().map(String::as_str) {
        Some("claude-mem") => {}
        Some(other) => bail!(
            "unknown import source `{other}`; usage: import claude-mem [--project P]... \
             [--type T,...] [--all] [--since YYYY-MM-DD] [--query TEXT] [--limit N] \
             [--db PATH] [--dry-run]"
        ),
        None => bail!(
            "import needs a source; usage: import claude-mem [--project P]... [--type T,...] \
             [--all] [--since YYYY-MM-DD] [--query TEXT] [--limit N] [--db PATH] [--dry-run]"
        ),
    }
    let opts = Options::parse(&args[1..])?;

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    // `import` ingests into the store regardless of the launch repo, so the
    // recall-scope default it carries is irrelevant here.
    let (store, _launch_repo) = resolve_and_build_store(&cfg).await?;

    // Sync first so idempotency sees teammates' and prior-run notes, not just this
    // machine's local index. Best-effort: a fresh/empty bucket or transient read
    // error must not abort the import — it only means dedup is done against
    // whatever is already indexed, so we warn rather than fail.
    match store.sync().await {
        Ok(count) => tracing::info!(count, "synced index from op-log before import"),
        Err(err) => tracing::warn!(
            error = %err,
            "op-log sync failed; dedup runs against the local index only (a re-run may re-add notes)"
        ),
    }
    let mut already: HashSet<String> = store
        .list_records()
        .context("listing existing notes for dedup failed")?
        .into_iter()
        .flat_map(|record| record.tags.into_iter())
        .filter(|tag| tag.starts_with("cmem:"))
        .collect();

    // The live-index scan misses a note the operator `forget`-tombstoned since it
    // was imported: a tombstone drops the note from the converged index, so its
    // tag vanishes from `already` even though it was genuinely imported before.
    // The local ledger is this command's own durable memory of every tag it has
    // ever written, independent of the shared index's current membership — union
    // it in so a re-run never resurrects a tombstoned note as a new one.
    let ledger_file = resolved_ledger_path(store.team());
    let mut ledger = ledger_file.as_deref().map(load_ledger).unwrap_or_default();
    already.extend(ledger.iter().cloned());
    tracing::info!(
        existing = already.len(),
        ledgered = ledger.len(),
        "found already-imported claude-mem notes"
    );

    let observations = read_observations(&opts)?;
    tracing::info!(
        matched = observations.len(),
        types = opts.types.join(","),
        dry_run = opts.dry_run,
        "matched claude-mem observations"
    );

    let mut imported = 0_usize;
    let mut skipped = 0_usize;
    for obs in &observations {
        let tag = provenance_tag(&obs.session, obs.id);
        let input = to_remember_input(obs);
        if already.contains(&tag) {
            skipped += 1;
            continue;
        }
        if opts.dry_run {
            imported += 1;
            // Sample the first few so a dry run shows the shape of what would land,
            // not just a count. All output goes through tracing (stdout is reserved
            // for the MCP protocol channel).
            if imported <= 10 {
                tracing::info!(note_type = ?input.note_type, summary = %input.summary, "would import");
            }
            continue;
        }
        store
            .remember(input)
            .await
            .with_context(|| format!("importing observation {} failed", obs.id))?;
        ledger.insert(tag);
        imported += 1;
        if imported.is_multiple_of(50) {
            tracing::info!(imported, "import progress");
        }
    }

    // `--dry-run` writes nothing (per its docs above) — that includes the ledger:
    // a dry run must leave no trace that would make a REAL re-run skip a note it
    // never actually imported.
    if !opts.dry_run
        && let Some(path) = ledger_file.as_deref()
        && let Err(err) = save_ledger(path, &ledger)
    {
        tracing::warn!(
            error = %err,
            path = %path.display(),
            "failed to persist the import ledger; a future re-run's dedup falls back to \
             the live index only, so a note tombstoned before that re-run may be resurrected"
        );
    }

    tracing::info!(
        imported,
        skipped_existing = skipped,
        dry_run = opts.dry_run,
        "import complete"
    );
    Ok(())
}

/// Where the local claude-mem import ledger for `team` lives, honoring
/// `XDG_STATE_HOME` then `$HOME` — application state that must survive a cache
/// wipe, so it is deliberately NOT under `Config::blob_cache_dir`'s cache root
/// (whose whole purpose is to be safely disposable; disposing of the ledger
/// would defeat the fix this file exists to make). `None` when neither var
/// yields a usable base dir, in which case dedup falls back to the live-index
/// scan alone — the pre-existing behavior — rather than erroring.
fn ledger_path(
    team: &str,
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    let base = xdg_state_home
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".local/state"))
        })?;
    Some(
        base.join("hippius-mem")
            .join("import-claude-mem")
            .join(format!("{team}.json")),
    )
}

/// [`ledger_path`] resolved from the current environment, for `team`.
fn resolved_ledger_path(team: &str) -> Option<PathBuf> {
    ledger_path(
        team,
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// Load the local import ledger: provenance tags (`cmem:<session>:<id>`) of
/// observations imported in a PRIOR run of this command, live or tombstoned.
///
/// A missing ledger is the normal first run and degrades silently to an empty
/// set. A ledger that EXISTS but cannot be read or parsed also degrades (never
/// blocking the import) — but with a loud warn, because it disarms exactly the
/// tombstone-resurrection guard this file is for: dedup falls back to the
/// live-index scan, which cannot see previously-imported notes the operator has
/// since `forget`-tombstoned, so this run may re-import them under new ids.
fn load_ledger(path: &Path) -> BTreeSet<String> {
    let body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return BTreeSet::new(),
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "import ledger exists but cannot be read; previously imported notes that were \
                 since tombstoned may be resurrected by this run"
            );
            return BTreeSet::new();
        }
    };
    // Stored as a JSON array of strings (not a JSON object/set — `serde_json` has
    // no bare "set" wire shape) so the file is a plain, inspectable list.
    match serde_json::from_str::<Vec<String>>(&body) {
        Ok(tags) => tags.into_iter().collect(),
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "import ledger is malformed (corrupt or hand-edited); previously imported notes \
                 that were since tombstoned may be resurrected by this run"
            );
            BTreeSet::new()
        }
    }
}

/// Persist `tags` (the ledger) to `path`, creating parent directories as needed.
///
/// # Errors
///
/// Returns an error if the parent directory cannot be created or the file
/// cannot be written. Callers treat this as best-effort (see [`run`]): a
/// note already imported into the shared store is not lost if the LOCAL ledger
/// write fails, only this command's own resurrection guard for a future run.
fn save_ledger(path: &Path, tags: &BTreeSet<String>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {} failed", parent.display()))?;
    }
    let sorted: Vec<&str> = tags.iter().map(String::as_str).collect();
    let body = serde_json::to_string_pretty(&sorted).context("serializing import ledger failed")?;
    std::fs::write(path, body).with_context(|| format!("writing {} failed", path.display()))
}

/// Parsed `import claude-mem` arguments.
struct Options {
    /// `SQLite` database to read (resolved: `--db` or `$HOME/.claude-mem/...`).
    db: PathBuf,
    /// Project (repo) names to include; empty means every project.
    projects: Vec<String>,
    /// Resolved claude-mem observation types to import.
    types: Vec<String>,
    /// Lower bound on `created_at_epoch` (Unix millis), from `--since`.
    since_epoch_ms: Option<i64>,
    /// Case-insensitive substring filter over title/narrative/text.
    query: Option<String>,
    /// Cap on the number of observations selected.
    limit: Option<i64>,
    /// Report what would be imported without writing anything.
    dry_run: bool,
}

impl Options {
    /// Parse the flags after `import claude-mem`.
    ///
    /// `--all` and `--type` both set the type list; the last one on the command
    /// line wins (so `--all --type decision` narrows back to decisions). Absent
    /// both, the durable default ([`DEFAULT_TYPES`]) applies.
    ///
    /// # Errors
    ///
    /// Returns an error on an unknown flag, a flag missing its value, a `--type`
    /// naming an unknown observation type, or a malformed `--since` / `--limit`.
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut db: Option<PathBuf> = None;
        let mut projects = Vec::new();
        let mut types: Option<Vec<String>> = None;
        let mut since_epoch_ms = None;
        let mut query = None;
        let mut limit = None;
        let mut dry_run = false;

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            // Flags taking a value pull the next token; a missing value is an error
            // rather than a silent bind to the following flag.
            let mut value = |flag: &str| -> anyhow::Result<String> {
                iter.next()
                    .cloned()
                    .with_context(|| format!("`{flag}` needs a value"))
            };
            match arg.as_str() {
                "--db" => db = Some(PathBuf::from(value("--db")?)),
                "--project" => projects.push(value("--project")?),
                "--type" => types = Some(parse_types(&value("--type")?)?),
                "--all" => types = Some(ALL_TYPES.iter().map(|t| (*t).to_owned()).collect()),
                "--since" => since_epoch_ms = Some(parse_since(&value("--since")?)?),
                "--query" => query = Some(value("--query")?),
                "--limit" => {
                    let raw = value("--limit")?;
                    let n = raw
                        .parse::<i64>()
                        .with_context(|| format!("`--limit` must be an integer, got `{raw}`"))?;
                    // A negative LIMIT means "no limit" in SQLite — a silent surprise
                    // for someone who fat-fingered a `-`, so reject it here.
                    if n < 0 {
                        bail!("`--limit` must be non-negative, got {n}");
                    }
                    limit = Some(n);
                }
                "--dry-run" => dry_run = true,
                other => bail!("unknown import argument `{other}`"),
            }
        }

        let db = if let Some(path) = db {
            path
        } else {
            let home = std::env::var_os("HOME")
                .context("HOME is unset; pass --db to point at the claude-mem database")?;
            PathBuf::from(home).join(DEFAULT_DB_REL)
        };
        let types =
            types.unwrap_or_else(|| DEFAULT_TYPES.iter().map(|t| (*t).to_owned()).collect());

        Ok(Self {
            db,
            projects,
            types,
            since_epoch_ms,
            query,
            limit,
            dry_run,
        })
    }
}

/// Validate a comma-separated `--type` list against the known observation types.
///
/// # Errors
///
/// Returns an error naming the offending value if any entry is not one of
/// [`ALL_TYPES`], so a typo (`--type bugfixes`) fails loudly instead of silently
/// matching nothing.
fn parse_types(raw: &str) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if !ALL_TYPES.contains(&part) {
            bail!(
                "unknown observation type `{part}`; valid types: {}",
                ALL_TYPES.join(", ")
            );
        }
        out.push(part.to_owned());
    }
    if out.is_empty() {
        bail!("`--type` listed no valid types");
    }
    Ok(out)
}

/// Parse a `YYYY-MM-DD` date into Unix epoch **milliseconds** at UTC midnight —
/// the unit claude-mem stores in `created_at_epoch`.
///
/// # Errors
///
/// Returns an error if the string is not exactly three `-`-separated integer
/// fields, the year falls outside `1970..=9999`, or the month/day is not a real
/// calendar date (leap years respected — `2026-02-31` is rejected, not silently
/// shifted into March).
fn parse_since(raw: &str) -> anyhow::Result<i64> {
    let parts: Vec<&str> = raw.split('-').collect();
    let [y, m, d] = parts.as_slice() else {
        bail!("`--since` must be YYYY-MM-DD, got `{raw}`");
    };
    let year: i64 = y.parse().with_context(|| format!("bad year in `{raw}`"))?;
    let month: i64 = m.parse().with_context(|| format!("bad month in `{raw}`"))?;
    let day: i64 = d.parse().with_context(|| format!("bad day in `{raw}`"))?;
    // claude-mem timestamps are Unix-epoch milliseconds, so a pre-1970 filter is
    // meaningless and a five-digit year is a typo. The bound also keeps
    // `days_from_civil`'s era arithmetic far from i64 overflow — without it, an
    // absurd year overflows `era * 146_097` (panic under debug, wrap in release).
    if !(1970..=9999).contains(&year) {
        bail!("`--since` year must be within 1970..=9999 in `{raw}`");
    }
    if !(1..=12).contains(&month) {
        bail!("`--since` month out of range in `{raw}`");
    }
    // Validate against the REAL month length: `days_from_civil` is exact for any
    // (y, m, d) triple but happily maps an impossible day (2026-02-31) into the
    // next month, silently shifting the operator's filter by days.
    if !(1..=days_in_month(year, month)).contains(&day) {
        bail!("`--since` day {day} is not a real date in {year}-{month:02} (`{raw}`)");
    }
    Ok(days_from_civil(year, month, day) * 86_400_000)
}

/// Days in `month` (`1..=12`) of proleptic-Gregorian `year`, leap-aware —
/// the input-validation gate in front of [`days_from_civil`].
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        // February — the only month whose length depends on the year. The
        // caller has already bounded month to 1..=12.
        _ => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
    }
}

/// Days from the Unix epoch (1970-01-01) to the given proleptic-Gregorian date.
///
/// Howard Hinnant's `days_from_civil` — exact and branch-cheap for any date,
/// which is why it is preferred over a month-length loop. Pure arithmetic, so it
/// is property-testable against its inverse.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // Shift so March is month 0: the leap day then falls at the year's end, which
    // is what makes the era arithmetic below closed-form.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // year of era, [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 }; // March-based month, [0, 11]
    let doy = (153 * mp + 2) / 5 + day - 1; // day of year, [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day of era, [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Escape `%`, `_`, and `\` in operator text bound into a `LIKE ? ESCAPE '\'`
/// pattern, so those characters match literally instead of as `SQLite` LIKE
/// wildcards. Parameterization already prevents injection; this preserves the
/// literal-substring meaning the `--query` flag promises.
fn escape_like(q: &str) -> String {
    let mut out = String::with_capacity(q.len());
    for ch in q.chars() {
        if ch == '%' || ch == '_' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// One claude-mem observation row, before mapping to a note.
struct Observation {
    /// Primary key in the `observations` table.
    id: i64,
    /// The memory-session this observation belongs to (provenance tag component).
    session: String,
    /// Project name → note `repo` scope.
    project: String,
    /// claude-mem observation type (`decision`/`bugfix`/…) → [`NoteType`].
    cmem_type: String,
    /// Short headline → note summary.
    title: Option<String>,
    /// Optional one-line elaboration.
    subtitle: Option<String>,
    /// Free text body, if any.
    text: Option<String>,
    /// JSON array of fact strings, if any.
    facts: Option<String>,
    /// The main narrative body.
    narrative: Option<String>,
    /// JSON array of concept tags, if any.
    concepts: Option<String>,
    /// JSON array of modified file paths, if any.
    files_modified: Option<String>,
    /// ISO-8601 creation timestamp (for the note's provenance footer).
    created_at: String,
}

/// Read the selected observations from the claude-mem `SQLite` store.
///
/// Opens the database read-only (we never mutate claude-mem's store) and builds a
/// parameterized query from `opts` — type/project `IN` lists, an optional
/// `created_at_epoch` floor, and an optional case-insensitive text filter.
///
/// # Errors
///
/// Returns an error if the database cannot be opened (e.g. missing file) or the
/// query fails.
fn read_observations(opts: &Options) -> anyhow::Result<Vec<Observation>> {
    // Read-only: the -wal/-shm files are our own (0644, same uid), so `SQLite` can
    // map the shared-memory index without write access to the main db, and we
    // never issue a write. This keeps the importer safe to run while claude-mem's
    // own process is live.
    let conn = Connection::open_with_flags(&opts.db, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| {
            format!(
                "opening claude-mem database at {} failed",
                opts.db.display()
            )
        })?;
    query_observations(&conn, opts)
}

/// Build and run the parameterized observations query against `conn`.
///
/// Split from [`read_observations`] (which owns opening the file read-only) so the
/// query construction — the `IN` lists, the `created_at_epoch` floor, the text
/// filter, ordering, and `LIMIT` — is exercised directly against an in-memory
/// database in tests, with no file or claude-mem process involved.
///
/// # Errors
///
/// Returns an error if the statement cannot be prepared or a row cannot be read.
fn query_observations(conn: &Connection, opts: &Options) -> anyhow::Result<Vec<Observation>> {
    let mut sql = String::from(
        "SELECT id, memory_session_id, project, type, title, subtitle, text, facts, \
         narrative, concepts, files_modified, created_at FROM observations WHERE ",
    );
    let mut params: Vec<Value> = Vec::new();

    // type IN (?, ?, ...)
    sql.push_str("type IN (");
    push_placeholders(&mut sql, opts.types.len());
    sql.push(')');
    for t in &opts.types {
        params.push(Value::Text(t.clone()));
    }

    if !opts.projects.is_empty() {
        sql.push_str(" AND project IN (");
        push_placeholders(&mut sql, opts.projects.len());
        sql.push(')');
        for p in &opts.projects {
            params.push(Value::Text(p.clone()));
        }
    }
    if let Some(since) = opts.since_epoch_ms {
        sql.push_str(" AND created_at_epoch >= ?");
        params.push(Value::Integer(since));
    }
    if let Some(q) = &opts.query {
        // LIKE is case-insensitive for ASCII in `SQLite` by default; a bounded
        // substring match is enough for the operator's topic filter here. The
        // operator's text is escaped (and ESCAPE declared) so `%`/`_` match
        // literally — SQLite gives them wildcard meaning inside LIKE, which
        // would silently turn `--query "100%"` into a prefix match.
        sql.push_str(
            " AND (title LIKE ? ESCAPE '\\' OR narrative LIKE ? ESCAPE '\\' \
             OR text LIKE ? ESCAPE '\\')",
        );
        let pattern = format!("%{}%", escape_like(q));
        params.push(Value::Text(pattern.clone()));
        params.push(Value::Text(pattern.clone()));
        params.push(Value::Text(pattern));
    }
    sql.push_str(" ORDER BY created_at_epoch DESC");
    if let Some(limit) = opts.limit {
        sql.push_str(" LIMIT ?");
        params.push(Value::Integer(limit));
    }

    let mut stmt = conn
        .prepare(&sql)
        .context("preparing the observations query failed")?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |row| {
            Ok(Observation {
                id: row.get(0)?,
                session: row.get(1)?,
                project: row.get(2)?,
                cmem_type: row.get(3)?,
                title: row.get(4)?,
                subtitle: row.get(5)?,
                text: row.get(6)?,
                facts: row.get(7)?,
                narrative: row.get(8)?,
                concepts: row.get(9)?,
                files_modified: row.get(10)?,
                created_at: row.get(11)?,
            })
        })
        .context("running the observations query failed")?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row.context("reading an observation row failed")?);
    }
    Ok(out)
}

/// Append `count` comma-separated `?` placeholders to `sql`.
fn push_placeholders(sql: &mut String, count: usize) {
    for i in 0..count {
        if i > 0 {
            sql.push(',');
        }
        sql.push('?');
    }
}

/// The provenance tag uniquely identifying a claude-mem observation, used both to
/// stamp an imported note and to detect it on a re-run.
fn provenance_tag(session: &str, id: i64) -> String {
    format!("cmem:{session}:{id}")
}

/// Map a claude-mem observation type onto a hippius-mem [`NoteType`].
///
/// `decision` and `bugfix` carry the two durable shapes team memory most wants (a
/// decision + rationale, a gotcha + fix); everything else is narration mapped to
/// the neutral `context` bucket.
fn map_note_type(cmem_type: &str) -> NoteType {
    match cmem_type {
        "decision" => NoteType::Decision,
        "bugfix" => NoteType::Gotcha,
        // feature / refactor / change / discovery: durable-but-not-a-lesson.
        _ => NoteType::Context,
    }
}

/// Map an [`Observation`] onto the caller half of a note.
///
/// Pure and total (no I/O, never fails): summary falls back through
/// title → subtitle → narrative so a note is never empty-titled, the body
/// concatenates the observation's prose plus a provenance footer, and the tags
/// carry the concept list plus the two provenance markers that make re-runs
/// idempotent.
fn to_remember_input(obs: &Observation) -> RememberInput {
    let mut tags: BTreeSet<String> = parse_json_string_array(obs.concepts.as_deref());
    tags.insert("source:claude-mem".to_owned());
    tags.insert(format!("cmem-type:{}", obs.cmem_type));
    tags.insert(provenance_tag(&obs.session, obs.id));

    let repo = if obs.project.is_empty() {
        RepoScope::Global
    } else {
        RepoScope::Repo(obs.project.clone())
    };

    RememberInput {
        note_type: map_note_type(&obs.cmem_type),
        repo,
        tags,
        summary: build_summary(obs),
        body: build_body(obs),
        // A bulk import is a trusted, one-shot lift of an existing store, so it
        // bypasses the write-time dedup gate: the gate would abort the import loop
        // on the first near-duplicate, and the source already curated these notes.
        // De-duplication of imported content, if wanted, is a later `gardener` pass.
        force: true,
    }
}

/// One-line summary for the note: the first non-empty of title, subtitle, or the
/// leading line of the narrative, truncated to a sane length so `recall`'s pointer
/// list stays readable.
///
/// The result must satisfy `store::validate_summary` — a single, non-blank,
/// control-character-free line — because ingestion rejects anything else and
/// `run` aborts the whole import on a rejected observation. So each candidate is
/// reduced to its FIRST line before the non-empty pick (a multi-line title would
/// otherwise reach ingestion), and any stray control character is dropped from
/// the winner. The body carries the full multi-line text; this is only the
/// headline.
fn build_summary(obs: &Observation) -> String {
    let raw = first_non_empty(&[
        obs.title.as_deref().map(first_line),
        obs.subtitle.as_deref().map(first_line),
        obs.narrative.as_deref().map(first_line),
    ]);
    // Strip control chars from the chosen first line, THEN fall back to the
    // placeholder if nothing printable survives. The fallback has to run after
    // the strip, not before: `first_non_empty` rejects a candidate only when it
    // is WHITESPACE-empty (`str::trim`), so a title of all non-whitespace control
    // characters (NUL/BEL/ESC/DEL) wins selection yet strips to "" — and a blank
    // summary aborts the whole import at `validate_summary`.
    let headline: String = raw
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let headline = headline.trim();
    let headline = if headline.is_empty() {
        "(untitled claude-mem observation)"
    } else {
        headline
    };
    truncate_chars(headline, 200)
}

/// Assemble the note body from the observation's prose, ending with a provenance
/// footer naming the source so a reader can trace it back to claude-mem.
fn build_body(obs: &Observation) -> String {
    let mut body = String::new();
    let mut section = |label: &str, value: &str| {
        let value = value.trim();
        if !value.is_empty() {
            if !body.is_empty() {
                body.push_str("\n\n");
            }
            body.push_str(label);
            body.push_str(value);
        }
    };

    if let Some(subtitle) = obs.subtitle.as_deref() {
        section("", subtitle);
    }
    if let Some(narrative) = obs.narrative.as_deref() {
        section("", narrative);
    }
    let facts = parse_json_string_array(obs.facts.as_deref());
    if !facts.is_empty() {
        let bullets = facts
            .iter()
            .map(|f| format!("- {f}"))
            .collect::<Vec<_>>()
            .join("\n");
        section("Facts:\n", &bullets);
    }
    if let Some(text) = obs.text.as_deref() {
        // Skip text that merely repeats the narrative verbatim.
        if obs.narrative.as_deref() != Some(text) {
            section("", text);
        }
    }
    let files = parse_json_string_array(obs.files_modified.as_deref());
    if !files.is_empty() {
        section(
            "Files modified:\n",
            &files.iter().cloned().collect::<Vec<_>>().join("\n"),
        );
    }

    let footer = format!(
        "(imported from claude-mem: project={}, type={}, observation={}, session={}, created={})",
        obs.project, obs.cmem_type, obs.id, obs.session, obs.created_at
    );
    section("", &footer);
    body
}

/// Parse a claude-mem JSON string-array column (`concepts`, `facts`,
/// `files_modified`) into a set. Best-effort: a NULL, empty, or non-array value
/// yields an empty set rather than an error — the columns are advisory metadata,
/// not load-bearing, so a malformed one must not abort an import.
fn parse_json_string_array(raw: Option<&str>) -> BTreeSet<String> {
    let Some(raw) = raw else {
        return BTreeSet::new();
    };
    match serde_json::from_str::<Vec<String>>(raw) {
        Ok(items) => items
            .into_iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(_) => BTreeSet::new(),
    }
}

/// First `Some(non-empty-after-trim)` string from the candidates, if any.
fn first_non_empty<'a>(candidates: &[Option<&'a str>]) -> Option<&'a str> {
    candidates
        .iter()
        .flatten()
        .copied()
        .find(|s| !s.trim().is_empty())
}

/// The first line of `text` (up to the first `\n`), for a headline fallback.
fn first_line(text: &str) -> &str {
    text.split('\n').next().unwrap_or(text)
}

/// Truncate to at most `max` characters on a char boundary, appending `…` when
/// cut. Operates on `char`s (not bytes) so a multibyte character is never split.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success/failure of Result-returning helpers"
    )]

    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;

    use super::{
        ALL_TYPES, DEFAULT_TYPES, Observation, Options, build_body, build_summary, days_from_civil,
        days_in_month, escape_like, ledger_path, load_ledger, map_note_type,
        parse_json_string_array, parse_since, parse_types, provenance_tag, query_observations,
        save_ledger, to_remember_input, truncate_chars,
    };
    use hippius_mem_core::{NoteType, RepoScope};
    use rusqlite::Connection;
    use tempfile::TempDir;

    /// Build a `Vec<String>` args slice for [`Options::parse`] from string literals.
    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_owned()).collect()
    }

    /// An [`Options`] with explicit filters, for driving `query_observations` in
    /// tests without touching the filesystem or `HOME`.
    fn opts(
        types: &[&str],
        projects: &[&str],
        since_epoch_ms: Option<i64>,
        query: Option<&str>,
        limit: Option<i64>,
    ) -> Options {
        Options {
            db: PathBuf::from(":memory:"),
            projects: projects.iter().map(|p| (*p).to_owned()).collect(),
            types: types.iter().map(|t| (*t).to_owned()).collect(),
            since_epoch_ms,
            query: query.map(str::to_owned),
            limit,
            dry_run: false,
        }
    }

    /// An in-memory claude-mem-shaped `observations` table for query tests.
    fn seed_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(
            "CREATE TABLE observations (
                id INTEGER PRIMARY KEY,
                memory_session_id TEXT NOT NULL,
                project TEXT NOT NULL,
                type TEXT NOT NULL,
                title TEXT,
                subtitle TEXT,
                text TEXT,
                facts TEXT,
                narrative TEXT,
                concepts TEXT,
                files_modified TEXT,
                created_at TEXT NOT NULL,
                created_at_epoch INTEGER NOT NULL
            );",
        )
        .expect("create observations table");
        conn
    }

    /// Insert one observation row; the columns not exercised by a given test are
    /// left NULL to prove the reader tolerates them.
    fn insert(conn: &Connection, id: i64, project: &str, typ: &str, title: &str, epoch: i64) {
        conn.execute(
            "INSERT INTO observations
                (id, memory_session_id, project, type, title, created_at, created_at_epoch)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                id,
                "sess",
                project,
                typ,
                title,
                "2026-01-01T00:00:00Z",
                epoch
            ],
        )
        .expect("insert observation");
    }

    fn sample(cmem_type: &str) -> Observation {
        Observation {
            id: 42,
            session: "sess-abc".to_owned(),
            project: "hippius-s3".to_owned(),
            cmem_type: cmem_type.to_owned(),
            title: Some("Fixed the janitor I/O storm".to_owned()),
            subtitle: Some("full-scan replaced by an index".to_owned()),
            text: None,
            facts: Some(r#"["query full-scanned 52M rows","added a partial index"]"#.to_owned()),
            narrative: Some("The delete query full-scanned three tables.".to_owned()),
            concepts: Some(r#"["problem-solution","pattern"]"#.to_owned()),
            files_modified: Some(r#"["hippius_s3/sql/find.sql"]"#.to_owned()),
            created_at: "2026-02-03T15:02:11.189Z".to_owned(),
        }
    }

    #[test]
    fn note_type_mapping() {
        assert_eq!(map_note_type("decision"), NoteType::Decision);
        assert_eq!(map_note_type("bugfix"), NoteType::Gotcha);
        assert_eq!(map_note_type("discovery"), NoteType::Context);
        assert_eq!(map_note_type("anything-else"), NoteType::Context);
    }

    #[test]
    fn maps_observation_with_provenance_and_scope() {
        let input = to_remember_input(&sample("bugfix"));
        assert_eq!(input.note_type, NoteType::Gotcha);
        assert_eq!(input.repo, RepoScope::Repo("hippius-s3".to_owned()));
        assert_eq!(input.summary, "Fixed the janitor I/O storm");
        // Provenance + source markers make re-runs idempotent and traceable.
        assert!(input.tags.contains("source:claude-mem"));
        assert!(input.tags.contains("cmem-type:bugfix"));
        assert!(input.tags.contains(&provenance_tag("sess-abc", 42)));
        // Concept tags are carried across.
        assert!(input.tags.contains("problem-solution"));
        // Body carries the prose, the facts, and a provenance footer.
        assert!(input.body.contains("full-scanned three tables"));
        assert!(input.body.contains("- query full-scanned 52M rows"));
        assert!(input.body.contains("imported from claude-mem"));
        assert!(input.body.contains("observation=42"));
    }

    #[test]
    fn empty_project_maps_to_global() {
        let mut obs = sample("decision");
        obs.project = String::new();
        assert_eq!(to_remember_input(&obs).repo, RepoScope::Global);
    }

    #[test]
    fn summary_falls_back_and_truncates() {
        let mut obs = sample("decision");
        obs.title = None;
        obs.subtitle = None;
        obs.narrative = Some("First line is the headline\nsecond line ignored".to_owned());
        assert_eq!(build_summary(&obs), "First line is the headline");

        obs.narrative = Some("x".repeat(500));
        let s = build_summary(&obs);
        assert_eq!(s.chars().count(), 200);
        assert!(s.ends_with('…'));
    }

    #[test]
    fn summary_reduces_a_multiline_or_control_char_title_to_one_clean_line() {
        // A multi-line or control-char-bearing imported title must not reach
        // ingestion: store::validate_summary rejects it and `run` aborts the
        // whole import on a rejected observation. build_summary must therefore
        // always emit a single, control-character-free headline.
        let mut obs = sample("decision");
        obs.title = Some("Headline line\nburied detail".to_owned());
        assert_eq!(build_summary(&obs), "Headline line");

        obs.title = Some("tabbed\ttitle".to_owned());
        let s = build_summary(&obs);
        assert!(
            !s.chars().any(char::is_control),
            "no control character survives into the summary: {s:?}"
        );
        assert_eq!(s, "tabbedtitle");

        // An all-control-char winner (control chars are not whitespace, so it
        // survives `first_non_empty`) must NOT strip to a blank summary — that
        // would abort the whole import at `validate_summary`. It falls back to
        // the placeholder instead.
        obs.title = Some("\u{7}\u{7}".to_owned());
        obs.subtitle = None;
        obs.narrative = None;
        let s = build_summary(&obs);
        assert_eq!(s, "(untitled claude-mem observation)");
    }

    #[test]
    fn body_skips_text_equal_to_narrative() {
        let mut obs = sample("decision");
        obs.narrative = Some("same body".to_owned());
        obs.text = Some("same body".to_owned());
        let body = build_body(&obs);
        // "same body" appears once (the narrative), not duplicated by text.
        assert_eq!(body.matches("same body").count(), 1);
    }

    #[test]
    fn json_array_parse_is_best_effort() {
        assert!(parse_json_string_array(None).is_empty());
        assert!(parse_json_string_array(Some("not json")).is_empty());
        let got = parse_json_string_array(Some(r#"["a"," b ",""]"#));
        assert!(got.contains("a"));
        assert!(got.contains("b"));
        assert_eq!(got.len(), 2); // empty entry dropped
    }

    #[test]
    fn type_validation_rejects_typos() {
        assert!(parse_types("decision,bugfix").is_ok());
        assert!(parse_types("bugfixes").is_err());
        assert!(parse_types("").is_err());
    }

    #[test]
    fn since_parses_to_utc_midnight_millis() {
        // 1970-01-01 is epoch 0.
        assert_eq!(parse_since("1970-01-01").expect("valid date"), 0);
        // 1970-01-02 is exactly one day of milliseconds later.
        assert_eq!(parse_since("1970-01-02").expect("valid date"), 86_400_000);
        assert!(parse_since("not-a-date").is_err());
        assert!(parse_since("2026-13-01").is_err());
    }

    #[test]
    fn since_rejects_impossible_calendar_dates_and_absurd_years() {
        // days_from_civil would silently map these into the NEXT month, shifting
        // the operator's filter — they must be rejected instead.
        assert!(parse_since("2026-02-31").is_err(), "Feb 31 is not a date");
        assert!(parse_since("2026-04-31").is_err(), "Apr 31 is not a date");
        assert!(
            parse_since("2023-02-29").is_err(),
            "2023 is not a leap year"
        );
        // Leap-year rules: divisible-by-4 yes, by-100 no, by-400 yes again.
        assert!(parse_since("2024-02-29").is_ok(), "2024 is a leap year");
        assert!(
            parse_since("1900-02-29").is_err(),
            "1900 was not a leap year"
        );
        assert!(parse_since("2000-02-29").is_ok(), "2000 was a leap year");
        // Year bounds: pre-epoch is meaningless for epoch-ms data; a huge year
        // would overflow the era arithmetic (debug panic / release wrap).
        assert!(parse_since("1969-12-31").is_err(), "pre-epoch year");
        assert!(
            parse_since("9223372036854775-01-01").is_err(),
            "an absurd year must be rejected, not overflow"
        );
    }

    proptest! {
        /// Consecutive valid dates are exactly one day of milliseconds apart —
        /// agreement between `parse_since` and the day-length constant across
        /// month and year boundaries (the shape a month-length bug would break).
        #[test]
        fn since_is_dense_over_valid_dates(
            year in 1970_i64..=9998,
            month in 1_i64..=12,
            day in 1_i64..=31,
        ) {
            prop_assume!(day <= days_in_month(year, month));
            let here = parse_since(&format!("{year:04}-{month:02}-{day:02}"))
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            // The day after: roll over month/year when needed.
            let (ny, nm, nd) = if day < days_in_month(year, month) {
                (year, month, day + 1)
            } else if month < 12 {
                (year, month + 1, 1)
            } else {
                (year + 1, 1, 1)
            };
            let next = parse_since(&format!("{ny:04}-{nm:02}-{nd:02}"))
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(next - here, 86_400_000);
        }
    }

    #[test]
    fn like_query_matches_percent_and_underscore_literally() {
        // `%`/`_` are LIKE wildcards; unescaped they silently widen the match
        // (`100%` would match any "100…" title).
        let db = seed_db();
        insert(&db, 1, "p", "decision", "rollout is 100% done", 100);
        insert(&db, 2, "p", "decision", "rollout is 1000 done-ish", 200);
        insert(&db, 3, "p", "decision", "uses a_b naming", 300);
        insert(&db, 4, "p", "decision", "uses aXb naming", 400);

        let ids = |query: &str| -> Vec<i64> {
            query_observations(&db, &opts(&["decision"], &[], None, Some(query), None))
                .expect("query")
                .iter()
                .map(|o| o.id)
                .collect()
        };
        assert_eq!(ids("100%"), vec![1], "% must match literally");
        assert_eq!(ids("a_b"), vec![3], "_ must match literally");
    }

    proptest! {
        /// `escape_like` round-trips: stripping the escapes it inserted yields
        /// the original text, and no `%`/`_` in its output is left unescaped.
        #[test]
        fn escape_like_round_trips(q in ".{0,40}") {
            let escaped = escape_like(&q);
            let mut unescaped = String::new();
            let mut pending_escape = false;
            for ch in escaped.chars() {
                if pending_escape {
                    unescaped.push(ch);
                    pending_escape = false;
                } else if ch == '\\' {
                    pending_escape = true;
                } else {
                    prop_assert!(ch != '%' && ch != '_', "unescaped wildcard survived: {escaped}");
                    unescaped.push(ch);
                }
            }
            prop_assert!(!pending_escape, "a trailing bare escape would corrupt the pattern");
            prop_assert_eq!(unescaped, q);
        }
    }

    #[test]
    fn days_from_civil_matches_known_epochs() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate_chars("hello", 10), "hello");
        assert_eq!(truncate_chars("hello", 3), "he…");
        // Multibyte characters are counted, never split.
        let s = truncate_chars("日本語テキスト", 3);
        assert_eq!(s.chars().count(), 3);
    }

    // ---- query_observations: the SQL filter/order/limit construction ----

    #[test]
    fn query_filters_by_type() {
        let db = seed_db();
        insert(&db, 1, "p", "decision", "d", 100);
        insert(&db, 2, "p", "bugfix", "b", 200);
        insert(&db, 3, "p", "discovery", "x", 300);
        let got = query_observations(&db, &opts(&["decision", "bugfix"], &[], None, None, None))
            .expect("query");
        let ids: Vec<i64> = got.iter().map(|o| o.id).collect();
        // The discovery row is excluded; the two durable rows are kept.
        assert_eq!(ids, vec![2, 1]); // also proves DESC-by-epoch ordering
    }

    #[test]
    fn query_filters_by_project() {
        let db = seed_db();
        insert(&db, 1, "keep", "decision", "d", 100);
        insert(&db, 2, "drop", "decision", "d", 200);
        let got =
            query_observations(&db, &opts(&["decision"], &["keep"], None, None, None)).expect("q");
        assert_eq!(got.iter().map(|o| o.id).collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn query_filters_by_since_and_respects_limit() {
        let db = seed_db();
        insert(&db, 1, "p", "decision", "old", 1_000);
        insert(&db, 2, "p", "decision", "mid", 3_000);
        insert(&db, 3, "p", "decision", "new", 5_000);
        // since=2000 drops the epoch-1000 row; limit=1 keeps only the newest of the rest.
        let got = query_observations(&db, &opts(&["decision"], &[], Some(2_000), None, Some(1)))
            .expect("q");
        assert_eq!(got.iter().map(|o| o.id).collect::<Vec<_>>(), vec![3]);
    }

    #[test]
    fn query_filters_by_substring() {
        let db = seed_db();
        insert(&db, 1, "p", "bugfix", "gateway 403 fix", 100);
        insert(&db, 2, "p", "bugfix", "unrelated change", 200);
        let got = query_observations(&db, &opts(&["bugfix"], &[], None, Some("gateway"), None))
            .expect("q");
        assert_eq!(got.iter().map(|o| o.id).collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn query_multiple_projects_are_unioned() {
        let db = seed_db();
        insert(&db, 1, "a", "decision", "d", 100);
        insert(&db, 2, "b", "decision", "d", 200);
        insert(&db, 3, "c", "decision", "d", 300);
        let got = query_observations(&db, &opts(&["decision"], &["a", "c"], None, None, None))
            .expect("q");
        assert_eq!(got.iter().map(|o| o.id).collect::<Vec<_>>(), vec![3, 1]);
    }

    // ---- Options::parse: flag handling ----

    #[test]
    fn parse_defaults_to_durable_types() {
        let o = Options::parse(&args(&["--db", "/x"])).expect("parse");
        assert_eq!(o.types, DEFAULT_TYPES);
        assert_eq!(o.db, PathBuf::from("/x"));
        assert!(!o.dry_run);
        assert!(o.projects.is_empty(), "no --project means all repos");
    }

    #[test]
    fn parse_all_selects_every_type() {
        let o = Options::parse(&args(&["--db", "/x", "--all"])).expect("parse");
        assert_eq!(o.types, ALL_TYPES);
    }

    #[test]
    fn parse_type_and_all_last_wins() {
        // --all after --type widens back to everything...
        let widened =
            Options::parse(&args(&["--db", "/x", "--type", "decision", "--all"])).expect("parse");
        assert_eq!(widened.types, ALL_TYPES);
        // ...and --type after --all narrows back down.
        let narrowed =
            Options::parse(&args(&["--db", "/x", "--all", "--type", "decision"])).expect("parse");
        assert_eq!(narrowed.types, vec!["decision".to_owned()]);
    }

    #[test]
    fn parse_collects_repeated_projects() {
        let o = Options::parse(&args(&["--db", "/x", "--project", "a", "--project", "b"]))
            .expect("parse");
        assert_eq!(o.projects, vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(
            Options::parse(&args(&["--db", "/x", "--nope"])).is_err(),
            "unknown flag"
        );
        assert!(Options::parse(&args(&["--db"])).is_err(), "missing value");
        assert!(
            Options::parse(&args(&["--db", "/x", "--limit", "abc"])).is_err(),
            "non-integer limit"
        );
        assert!(
            Options::parse(&args(&["--db", "/x", "--limit", "-3"])).is_err(),
            "negative limit is a silent SQLite no-op, so reject it"
        );
    }

    #[test]
    fn parse_accepts_full_flag_set() {
        let o = Options::parse(&args(&[
            "--db",
            "/db",
            "--project",
            "p",
            "--type",
            "decision",
            "--since",
            "2026-01-01",
            "--query",
            "gateway",
            "--limit",
            "5",
            "--dry-run",
        ]))
        .expect("parse");
        assert_eq!(o.db, PathBuf::from("/db"));
        assert_eq!(o.types, vec!["decision".to_owned()]);
        assert_eq!(o.projects, vec!["p".to_owned()]);
        assert_eq!(o.query.as_deref(), Some("gateway"));
        assert_eq!(o.limit, Some(5));
        assert!(o.since_epoch_ms.is_some());
        assert!(o.dry_run);
    }

    // ---- import ledger: dedup survives a tombstoned note (finding [15]) ----

    #[test]
    fn ledger_path_honors_xdg_then_home() {
        // Mirrors `config.rs`'s `global_config_path_honors_xdg_then_home`: XDG wins
        // when set and non-empty, else `$HOME/.local/state`, else `None`.
        assert_eq!(
            ledger_path(
                "acme",
                Some(OsStr::new("/xdg")),
                Some(OsStr::new("/home/u"))
            ),
            Some("/xdg/hippius-mem/import-claude-mem/acme.json".into())
        );
        assert_eq!(
            ledger_path("acme", None, Some(OsStr::new("/home/u"))),
            Some("/home/u/.local/state/hippius-mem/import-claude-mem/acme.json".into())
        );
        assert_eq!(
            ledger_path("acme", Some(OsStr::new("")), Some(OsStr::new("/home/u"))),
            Some("/home/u/.local/state/hippius-mem/import-claude-mem/acme.json".into())
        );
        assert_eq!(ledger_path("acme", None, None), None);
    }

    #[test]
    fn load_ledger_is_empty_for_a_missing_or_malformed_file() {
        let tmp = TempDir::new().expect("tempdir");
        // Missing file: no error, empty set (first run).
        assert!(load_ledger(&tmp.path().join("absent.json")).is_empty());
        // Malformed JSON: degrades to empty rather than propagating an error, so a
        // corrupted ledger never blocks an import.
        let bad = tmp.path().join("bad.json");
        std::fs::write(&bad, "not json").expect("seed");
        assert!(load_ledger(&bad).is_empty());
    }

    #[test]
    fn save_then_load_ledger_round_trips() {
        let tmp = TempDir::new().expect("tempdir");
        // Nested, not-yet-existing parent directories must be created.
        let path = tmp.path().join("nested").join("dir").join("acme.json");
        let tags: BTreeSet<String> = ["cmem:sess-a:1", "cmem:sess-b:2"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        save_ledger(&path, &tags).expect("save");
        assert_eq!(load_ledger(&path), tags);
    }

    #[test]
    fn ledger_prevents_resurrecting_a_tombstoned_tag() {
        // The exact bug this fixes: the live-index scan alone (`already`, built
        // from `store.list_records()` in `run`) misses a tag whose note was
        // `forget`-tombstoned, because a tombstone removes the note from the
        // converged index. This test proves the LEDGER half of the union
        // independently: a tag recorded in a prior run's ledger is still
        // considered "already imported" even though the live-index scan (modeled
        // here by an EMPTY `HashSet`, standing in for a fully tombstoned note) no
        // longer carries it.
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("acme.json");
        let tag = provenance_tag("sess-abc", 42);
        let mut ledger = BTreeSet::new();
        ledger.insert(tag.clone());
        save_ledger(&path, &ledger).expect("save");

        // Simulate a fresh run: the live index no longer carries the tag (as if
        // the note had been forgotten), but the ledger does.
        let reloaded = load_ledger(&path);
        let mut already: std::collections::HashSet<String> = std::collections::HashSet::new();
        already.extend(reloaded.iter().cloned());
        assert!(
            already.contains(&tag),
            "a tombstoned-but-ledgered tag must still read as already-imported"
        );
    }

    proptest! {
        /// `save_ledger` then `load_ledger` is the identity on any set of tags —
        /// the round-trip invariant for this file's one serializer/deserializer
        /// pair (axiom `rust_quality_111_proptest_for_pure_functions`).
        #[test]
        fn ledger_round_trip(tags in prop::collection::btree_set("cmem:[a-z0-9]{1,8}:[0-9]{1,6}", 0..8)) {
            let tmp = TempDir::new().expect("tempdir");
            let path = tmp.path().join("roundtrip.json");
            save_ledger(&path, &tags).expect("save");
            prop_assert_eq!(load_ledger(&path), tags);
        }
    }
}
