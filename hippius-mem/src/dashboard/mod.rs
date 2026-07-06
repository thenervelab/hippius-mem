//! Local browse/search dashboard served over loopback HTTP.
//!
//! This module is compiled ONLY under the `dashboard` feature so the default
//! stdio MCP binary never links axum. The `hippius-mem dashboard` command binds
//! loopback and speaks plain HTTP; the handlers return *decrypted plaintext*
//! (note bodies the team stores encrypted at rest), so exposure of this surface
//! is exposure of the team's cleartext memory. The security boundary is
//! therefore two-fold and non-negotiable: bind loopback only, and gate every
//! route behind a per-launch token (`require_token`). Neither alone suffices —
//! loopback stops the network, the token stops other local users and CSRF-style
//! drive-by requests from a browser tab.
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use anyhow::Context as _;
use axum::Router;
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::get;
use hippius_mem_core::{
    HistoryEntry, IndexRecord, MemError, MemoryStore, Note, NoteHistory, NoteId, ParseNoteIdError,
    RecallInput, RepoScope,
};
use serde::Serialize;

use crate::config::Config;
use crate::resolver::{self, GitRemoteReader, RemoteReader, Resolution};

/// Run the `hippius-mem dashboard` subcommand: bind a loopback HTTP server that
/// browses and searches this machine's decrypted team memory.
///
/// The boot recipe mirrors the MCP server's own boot (`main`) so the dashboard
/// reads the SAME team the server would serve from this directory: load config,
/// route the git remote to a team profile, build that profile's store. It then
/// syncs once (best-effort) and serves. The security boundary is loopback + the
/// per-launch token generated here (see the module docs and `require_token`).
///
/// # Errors
///
/// Returns an error if configuration cannot be loaded, the repo routes to no team
/// profile (memory is disabled here), the store cannot be built, the OS CSPRNG is
/// unavailable, or the loopback socket cannot be bound.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let port = parse_port(args)?;

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;

    // Route the launch repo to a team profile by its git `origin` remote, exactly
    // as the server boot does. Binding a different profile than the MCP server binds
    // from the same cwd would silently show a different team's memory.
    let profiles = cfg.all_profiles();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let remote = GitRemoteReader.origin_url(&cwd);
    let profile = match resolver::resolve(&profiles, remote.as_deref()) {
        Resolution::Bound(profile) => profile,
        Resolution::Disabled(reason) => {
            anyhow::bail!("team memory is disabled for this repository: {reason}");
        }
    };
    let store = Arc::new(profile.build_store(&cfg).await?);

    // Best-effort freshen before serving. The dashboard is a read surface, not a
    // write path, so a sync error (offline, S3 hiccup) must not stop it — the op-log
    // is durable and each route runs `refresh_if_stale`, so the index self-heals.
    match store.sync().await {
        Ok(count) => tracing::info!(count, "synced index from op-log"),
        Err(err) => {
            tracing::warn!(error = %err, "op-log sync failed; serving whatever is indexed");
        }
    }

    // The launch token is the dashboard's ONLY auth capability; a fresh CSPRNG draw
    // per launch means a leaked URL dies with the process rather than granting
    // standing access to the team's decrypted memory.
    let token = generate_token()?;

    // Loopback only: the served bodies are decrypted plaintext, so binding a
    // non-loopback interface would expose the team's cleartext memory on the network.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("failed to bind loopback dashboard port {port}"))?;
    // Read the port back from the socket: with `--port 0` the OS chose an ephemeral
    // port, so the bound address — not the requested one — is what the operator needs.
    let bound = listener
        .local_addr()
        .context("resolving the bound dashboard address")?;

    // The operator copies this URL; the token rides in the query string so a plain
    // browser navigation authenticates. Emitted through `tracing` (stderr) rather
    // than `println!`/`eprintln!` because the workspace denies the print macros —
    // diagnostics uniformly go through the subscriber, keeping stdout a clean
    // channel as the MCP server requires.
    let url = format!("http://127.0.0.1:{}/?t={token}", bound.port());
    tracing::info!(
        profile = %profile.name,
        %url,
        "Hippius Memory dashboard listening — open this URL in a browser"
    );

    axum::serve(
        listener,
        router(DashboardState {
            store,
            token: Arc::from(token.as_str()),
        }),
    )
    .await
    .context("dashboard HTTP server error")?;
    Ok(())
}

/// Parse an optional `--port <n>` from the subcommand args. Absent means port `0`,
/// which asks the OS for an ephemeral port (the actual port is read back from the
/// bound socket). A present-but-unparseable value is a hard error, not a silent
/// fall-back to `0`: an operator who asked for a fixed port must not be handed a
/// random one and left wondering why their bookmark 404s.
fn parse_port(args: &[String]) -> anyhow::Result<u16> {
    // A slice match rather than a loop: Phase 1 accepts exactly the optional
    // `--port <n>` and nothing else, so pattern-matching the whole arg list states
    // that shape directly (and sidesteps a single-pass "loop" clippy rightly flags).
    match args {
        [] => Ok(0),
        [flag, value, rest @ ..] if flag.as_str() == "--port" => {
            if let Some(extra) = rest.first() {
                anyhow::bail!("unexpected trailing dashboard argument `{extra}`");
            }
            value
                .parse::<u16>()
                .with_context(|| format!("invalid --port value `{value}`"))
        }
        [flag] if flag.as_str() == "--port" => anyhow::bail!("--port requires a value"),
        [other, ..] => {
            anyhow::bail!("unknown dashboard argument `{other}`; usage: dashboard [--port <n>]")
        }
    }
}

/// Generate the per-launch dashboard token: 16 CSPRNG bytes as 32 lowercase hex
/// characters.
///
/// The token MUST come from a CSPRNG. It is the dashboard's ONLY authentication
/// capability — every route is gated behind exact equality against it
/// (`require_token`) — so a predictable or low-entropy token would let any local
/// process, or a drive-by request from a malicious browser tab, guess it and read
/// the team's decrypted memory, defeating the loopback+token boundary. 128 bits of
/// OS entropy makes that guess computationally infeasible. `hex::encode` yields 32
/// lowercase hex chars, which is inherently non-empty (satisfying `router`'s
/// `debug_assert!(!token.is_empty())`) and URL-safe (so `require_token` compares
/// the raw, un-percent-decoded `?t=` value correctly).
///
/// # Errors
///
/// Returns an error if the OS CSPRNG is unavailable (`getrandom::fill` fails). The
/// failure is never downgraded to a weaker source: no token is safer than a
/// guessable one.
fn generate_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|err| anyhow::anyhow!("OS CSPRNG unavailable for dashboard token: {err}"))?;
    Ok(hex::encode(bytes))
}

/// Shared handler state. Both fields are reference-counted so `Clone` (required
/// by axum for state) is two atomic increments, not a deep copy: the store is a
/// single process-wide instance and the token is an immutable per-launch secret.
#[derive(Clone)]
pub(crate) struct DashboardState {
    /// The one live memory store; handlers read notes/pointers through it.
    pub store: Arc<MemoryStore>,
    /// Per-launch secret compared by `require_token`. `Arc<str>` (not `String`)
    /// because it is read-only and cloned into every request via the state.
    pub token: Arc<str>,
}

/// Build the dashboard router with the token gate applied to *every* route.
///
/// The `.layer(require_token)` sits above all routes, so there is no path — not
/// even `/api/health` — reachable without presenting the token. Task 4 replaces
/// the stub handler bodies with real DTOs; the routing and the gate are stable.
pub(crate) fn router(state: DashboardState) -> Router {
    // An empty token would make `presented == Some("")` authorize any request
    // that sends `?t=` (or the header) with an empty value — the gate would be
    // open. Pin the hazard at the boundary; Task 6 supplies the real CSPRNG
    // token, so a violation here is a construction bug, not a runtime input.
    debug_assert!(
        !state.token.is_empty(),
        "dashboard launch token must be non-empty"
    );
    Router::new()
        .route("/", get(index_html))
        .route("/api/overview", get(overview))
        .route("/api/notes", get(list_notes))
        // axum 0.8 path-param syntax is `{id}` (0.7's `:id` no longer parses).
        .route("/api/notes/{id}", get(get_note))
        .route("/api/health", get(health))
        .layer(from_fn_with_state(state.clone(), require_token))
        .with_state(state)
}

/// Reject any request that does not present the launch token, before it reaches
/// a handler. The token may arrive as the `?t=<token>` query parameter (so a
/// plain browser navigation works) or the `x-dashboard-token` header (so
/// programmatic clients need not leak it into logs via the URL). Comparison is
/// exact equality against `state.token`; a miss returns `401` and the request
/// never touches the store.
///
/// The `?t=` value is NOT percent-decoded. That is correct ONLY because the
/// launch token is CSPRNG bytes rendered as hex (already URL-safe, no reserved
/// characters to escape). If the token encoding ever changes to base64 (which
/// contains `+` and `/`), this must switch to `form_urlencoded` or a wrong-but-
/// look-alike raw value would be compared and legitimate tokens would 401.
///
/// A present-but-wrong `?t=` short-circuits the header fallback: `or_else` only
/// runs when the query lookup yields `None`, so a bad query token returns `401`
/// without consulting `x-dashboard-token`. Intended — a client that sends a
/// query token at all should not be sending a wrong one and silently retried
/// against the header.
async fn require_token(State(state): State<DashboardState>, req: Request, next: Next) -> Response {
    let presented = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix("t=").map(str::to_owned))
        })
        .or_else(|| {
            req.headers()
                .get("x-dashboard-token")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        });

    if presented.as_deref() == Some(state.token.as_ref()) {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "missing or invalid dashboard token",
        )
            .into_response()
    }
}

/// Default recall breadth for the search box: enough rows to fill a browse table
/// without paging, matching the MCP server's own recall default order of
/// magnitude. Phase 1 has no pagination, so this is the whole search result.
const DEFAULT_LIST_K: usize = 50;

/// One browse row — deliberately body-free. `note_type`/`tags` power the browse
/// filters that the recall [`Pointer`](hippius_mem_core::Pointer) does not carry,
/// which is why this is a dashboard-local DTO and not the server's `PointerDto`.
/// The absence of a `body` field is the point: browse never ships plaintext
/// bodies, only summaries (a body is fetched one-at-a-time via `get_note`).
#[derive(Serialize)]
struct NoteRow {
    id: String,
    summary: String,
    note_type: String,
    repo: String,
    author: String,
    updated: i64,
    tags: Vec<String>,
}

/// The one-shot browse payload rendered on page load.
#[derive(Serialize)]
struct OverviewDto {
    team: String,
    note_count: usize,
    /// Whether recall runs the semantic leg — drives the honesty badge; a lexical
    /// (`HashEmbedder`) build reports `false` so the UI never claims paraphrase
    /// matching it cannot do.
    semantic: bool,
    notes: Vec<NoteRow>,
}

/// The `GET /api/notes` response — a single `notes` array so the browse and
/// search paths share one wire shape.
#[derive(Serialize)]
struct NotesDto {
    notes: Vec<NoteRow>,
}

/// The full detail for one note, including its decrypted body and op history —
/// the detail-drawer payload behind a row click.
#[derive(Serialize)]
struct NoteDetailDto {
    id: String,
    note_type: String,
    repo: String,
    author: String,
    created: i64,
    updated: i64,
    tags: Vec<String>,
    summary: String,
    body: String,
    /// Current content version (hex BLAKE3 of the ciphertext) — the compare-and-
    /// swap token a Phase 2 edit will round-trip; surfaced now so the contract is
    /// stable.
    version: String,
    /// The note's converged outbound links, as `mem_...` ids.
    links: Vec<String>,
    history: NoteHistoryDto,
}

/// A note's op history, projected for the UI. This is a compact projection of the
/// core [`NoteHistory`], NOT the server's full `HistoryDto`: the drawer shows who
/// did what and whether it is anchored, so the per-op Merkle proof is reduced to
/// an `anchored` boolean rather than carrying the whole inclusion path.
#[derive(Serialize)]
struct NoteHistoryDto {
    tombstoned: bool,
    redacted: bool,
    links: Vec<String>,
    entries: Vec<HistoryEntryRow>,
}

/// One op in a note's history, reduced to the fields the drawer renders.
#[derive(Serialize)]
struct HistoryEntryRow {
    op_id: String,
    author: String,
    lamport: u64,
    kind: String,
    cid: String,
    /// Whether this op has been committed to an anchored Merkle batch yet.
    anchored: bool,
}

/// The health panel payload.
#[derive(Serialize)]
struct HealthDto {
    team: String,
    semantic: bool,
    /// Whether the best-effort staleness probe actually ran a sync on this
    /// request (`false` if the index was already fresh OR the probe failed —
    /// health never fails on a probe error).
    synced: bool,
    note_count: usize,
}

/// The dashboard's HTTP error surface, mapped to status codes by
/// [`IntoResponse`]. Typed rather than stringly so each failure category renders
/// its own status, and a store error is never silently downgraded to a 200.
enum ApiError {
    /// 404 — a well-formed id names no note indexed on this machine.
    NotFound,
    /// 400 — a request value was malformed (e.g. an unparseable note id). Carries
    /// the parser's own detail so the caller sees exactly what was wrong.
    BadRequest(String),
    /// 500 — the memory store failed servicing the read.
    Internal(MemError),
    /// 500 — the blocking recall task panicked or the runtime is shutting down.
    /// A distinct category from [`Internal`](ApiError::Internal): a task-join
    /// failure is a runtime fault, not a store fault, so it is not collapsed into
    /// a `MemError` (whose `Storage` variant specifically denotes an S3-gateway
    /// failure).
    Recall,
}

impl From<MemError> for ApiError {
    /// Route the store's own not-found to a 404; every other store failure is an
    /// internal 500. `MemError` is `#[non_exhaustive]`, so the catch-all arm is
    /// mandatory, not a style lapse.
    fn from(err: MemError) -> Self {
        match err {
            MemError::NotFound { .. } => ApiError::NotFound,
            other => ApiError::Internal(other),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "note not found".to_owned()),
            ApiError::BadRequest(detail) => (StatusCode::BAD_REQUEST, detail),
            // Surface the store's own message: `MemError`'s `Display` is
            // deliberately secret-free (the `Crypto`/`Identity` variants carry no
            // key material), so echoing it aids local debugging on a loopback-only
            // surface without leaking anything the bodies do not already expose.
            ApiError::Internal(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            ApiError::Recall => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "recall task failed".to_owned(),
            ),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

/// Project one [`IndexRecord`] onto a browse row. Shared by the overview, the
/// unfiltered list, and the search-result enrichment so every row — however it
/// was found — carries the identical field set.
fn row_from(record: &IndexRecord) -> NoteRow {
    NoteRow {
        id: record.note_id.to_string(),
        summary: record.summary.clone(),
        note_type: record.note_type.to_string(),
        repo: repo_to_dto(&record.scope.repo),
        author: record.author.as_str().to_owned(),
        updated: record.updated.as_millis(),
        tags: record.tags.iter().cloned().collect(),
    }
}

/// Render a [`RepoScope`] as the string the browse filters compare against —
/// mirrors `server.rs`'s private mapper (duplicated, not re-exported, so the
/// dashboard's wire strings are pinned here rather than coupled to the MCP crate).
fn repo_to_dto(repo: &RepoScope) -> String {
    match repo {
        RepoScope::Global => "global".to_owned(),
        RepoScope::Repo(name) => name.clone(),
    }
}

/// Parse the browse `repo` filter into the recall scope. Absent or `"global"`
/// means the team-global dimension; any other value is a named repo.
fn parse_repo(repo: Option<&str>) -> RepoScope {
    match repo {
        None | Some("global") => RepoScope::Global,
        Some(name) => RepoScope::Repo(name.to_owned()),
    }
}

/// Treat an absent OR empty query parameter as "no filter": an empty `?type=`
/// from a cleared UI input must not filter to notes whose type is the empty
/// string (which would match nothing).
fn non_empty(value: Option<&String>) -> Option<&str> {
    value.map(String::as_str).filter(|s| !s.is_empty())
}

/// Order a browse list newest-first, with the id as a stable tiebreak so equal
/// timestamps do not reorder between requests.
fn sort_rows(rows: &mut [NoteRow]) {
    rows.sort_by(|a, b| b.updated.cmp(&a.updated).then_with(|| a.id.cmp(&b.id)));
}

async fn index_html() -> Html<&'static str> {
    // The whole UI is one self-contained file — inline CSS + vanilla JS, no build
    // step and no external asset — so `include_str!` bakes it into the binary and
    // the `/` route serves it verbatim. The page reads the launch token from its
    // own URL and re-presents it on every API call, so it works behind the same
    // token gate every other route sits behind.
    Html(include_str!("dashboard.html"))
}

/// Page-load browse payload: best-effort freshen, then enumerate every note.
async fn overview(State(state): State<DashboardState>) -> Result<Json<OverviewDto>, ApiError> {
    // Best-effort: a stale probe failure must not fail the page — serve the
    // current index and let health surface sync state.
    let _ = state.store.refresh_if_stale().await;
    let mut notes: Vec<NoteRow> = state.store.list_records()?.iter().map(row_from).collect();
    sort_rows(&mut notes);
    Ok(Json(OverviewDto {
        team: state.store.team().to_owned(),
        note_count: notes.len(),
        semantic: state.store.is_semantic(),
        notes,
    }))
}

/// Browse or search. With `q` present the rows are recall-ranked; otherwise they
/// are the enumeration filtered in-memory by `type`/`repo`/`tag`.
async fn list_notes(
    State(state): State<DashboardState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<NotesDto>, ApiError> {
    let _ = state.store.refresh_if_stale().await;
    let notes = match non_empty(params.get("q")) {
        // Search and browse must apply the SAME `type`/`tag` matching: recall
        // scopes `repo` itself, but `type`/`tag` are post-filters here so a
        // `?q=foo&type=gotcha&tag=x` narrows the ranked hits the identical way a
        // filter-only browse would — via `row_matches` — while preserving recall
        // order (`Iterator::filter` is order-preserving).
        Some(query) => {
            let ranked = search_rows(&state, query, non_empty(params.get("repo"))).await?;
            let type_filter = non_empty(params.get("type"));
            let tag_filter = non_empty(params.get("tag"));
            ranked
                .into_iter()
                .filter(|row| row_matches(row, type_filter, tag_filter))
                .collect()
        }
        None => filter_rows(&state, &params)?,
    };
    Ok(Json(NotesDto { notes }))
}

/// The `type`/`tag` match predicate shared by browse (`filter_rows`) and search
/// (`list_notes`'s `q` arm), so both narrow a row set identically. An absent
/// filter matches everything; a present `tag` matches when the row carries it.
fn row_matches(row: &NoteRow, type_filter: Option<&str>, tag_filter: Option<&str>) -> bool {
    type_filter.is_none_or(|want| row.note_type == want)
        && tag_filter.is_none_or(|want| row.tags.iter().any(|tag| tag == want))
}

/// Enumerate and filter in-memory by the optional `type`/`repo`/`tag` params.
fn filter_rows(
    state: &DashboardState,
    params: &HashMap<String, String>,
) -> Result<Vec<NoteRow>, ApiError> {
    let type_filter = non_empty(params.get("type"));
    let repo_filter = non_empty(params.get("repo"));
    let tag_filter = non_empty(params.get("tag"));
    let mut rows: Vec<NoteRow> = state
        .store
        .list_records()?
        .iter()
        .map(row_from)
        // `repo` is filtered inline here (browse enumerates every repo); `type`/`tag`
        // go through `row_matches`, the same predicate the search arm applies, so
        // the two paths narrow identically.
        .filter(|row| repo_filter.is_none_or(|want| row.repo == want))
        .filter(|row| row_matches(row, type_filter, tag_filter))
        .collect();
    sort_rows(&mut rows);
    Ok(rows)
}

/// Rank rows against `query` via `recall`, preserving relevance order.
///
/// `recall` returns body-free [`Pointer`](hippius_mem_core::Pointer)s that lack
/// `note_type`/`tags`, so each ranked hit is joined back to its [`IndexRecord`]
/// (via a one-shot `list_records` map) to fill the full browse row — the search
/// and browse paths therefore yield identical row shapes.
async fn search_rows(
    state: &DashboardState,
    query: &str,
    repo: Option<&str>,
) -> Result<Vec<NoteRow>, ApiError> {
    let by_id: BTreeMap<NoteId, IndexRecord> = state
        .store
        .list_records()?
        .into_iter()
        .map(|record| (record.note_id, record))
        .collect();
    // Asymmetry, acceptable in Phase 1: browse (`filter_rows`) enumerates the
    // whole index unbounded, but search caps at `DEFAULT_LIST_K` and has no
    // pagination — so with >50 matches search shows only the top-ranked subset
    // while browse shows all. Pagination is a later phase.
    let input = RecallInput {
        text: query.to_owned(),
        repo: parse_repo(repo),
        k: DEFAULT_LIST_K,
        token_budget: None,
    };
    let store = Arc::clone(&state.store);
    // `recall` is synchronous CPU work — BM25 over every in-scope note always,
    // plus an ONNX query embedding under `--features embeddings` — so it runs on
    // the blocking pool, never on an async worker (mirrors `server.rs::logic_recall`).
    // Outer `?`: a JoinError (panic / shutdown) becomes `ApiError::Recall`; inner
    // `?`: the recall's own `MemError` propagates via `From`.
    let result = tokio::task::spawn_blocking(move || store.recall(input))
        .await
        .map_err(|_| ApiError::Recall)??;
    let rows = result
        .pointers
        .iter()
        .filter_map(|pointer| by_id.get(&pointer.note_id).map(row_from))
        .collect();
    Ok(rows)
}

/// Detail drawer for one note: parse the id, freshen, then hydrate body +
/// version + history.
async fn get_note(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Result<Json<NoteDetailDto>, ApiError> {
    let note_id: NoteId = id
        .parse()
        .map_err(|err: ParseNoteIdError| ApiError::BadRequest(err.to_string()))?;
    let _ = state.store.refresh_if_stale().await;
    // `get` errors `MemError::NotFound` for an unindexed id, which `From` maps to
    // a 404; `history` reads the op-log directly and yields an empty history for
    // an unknown note rather than erroring, so both are ordered after `get`.
    let note = state.store.get(note_id).await?;
    let history = state.store.history(note_id).await?;
    let version = state.store.current_version(note_id)?.to_hex();
    Ok(Json(detail_from(&note, &history, version)))
}

/// Project a hydrated [`Note`] + its [`NoteHistory`] onto the detail DTO.
fn detail_from(note: &Note, history: &NoteHistory, version: String) -> NoteDetailDto {
    NoteDetailDto {
        id: note.id.to_string(),
        note_type: note.note_type.to_string(),
        repo: repo_to_dto(&note.scope.repo),
        author: note.author.as_str().to_owned(),
        created: note.created.as_millis(),
        updated: note.updated.as_millis(),
        tags: note.tags.iter().cloned().collect(),
        summary: note.summary.clone(),
        body: note.body.clone(),
        version,
        links: note.links.iter().map(NoteId::to_string).collect(),
        history: history_from(history),
    }
}

/// Project the core [`NoteHistory`] onto the compact drawer DTO.
fn history_from(history: &NoteHistory) -> NoteHistoryDto {
    NoteHistoryDto {
        tombstoned: history.tombstoned,
        redacted: history.redacted,
        links: history.links.iter().map(NoteId::to_string).collect(),
        entries: history.entries.iter().map(entry_from).collect(),
    }
}

/// Project one core [`HistoryEntry`] onto its drawer row, reducing the anchor
/// proof to a committed/pending boolean.
fn entry_from(entry: &HistoryEntry) -> HistoryEntryRow {
    HistoryEntryRow {
        op_id: entry.op_id.clone(),
        author: entry.author.as_str().to_owned(),
        lamport: entry.lamport,
        kind: entry.kind.as_str().to_owned(),
        cid: entry.cid.to_hex(),
        anchored: entry.anchor.is_some(),
    }
}

/// Health panel: team, retrieval mode, sync freshness, and note count.
async fn health(State(state): State<DashboardState>) -> Result<Json<HealthDto>, ApiError> {
    // `synced` reports whether THIS request triggered a sync; a probe error is
    // swallowed to `false` so the health route itself never fails on staleness.
    let synced = state.store.refresh_if_stale().await.unwrap_or(false);
    let note_count = state.store.list_records()?.len();
    Ok(Json(HealthDto {
        team: state.store.team().to_owned(),
        semantic: state.store.is_semantic(),
        synced,
        note_count,
    }))
}

// The enclosing `mod dashboard` is itself `#[cfg(feature = "dashboard")]` in
// main.rs, so `feature = "dashboard"` is already guaranteed inside this file;
// a plain `#[cfg(test)]` here is equivalent (and canonical for tooling).
#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on in-memory fixtures where construction cannot fail"
    )]

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use hippius_mem_core::{
        BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, NetworkPrefix,
        NoopAnchor, NoteId, NoteType, OpLogStore, RememberInput, RepoScope, SecretKey, Signer,
        Sr25519Signer,
    };
    use tower::ServiceExt;

    use super::{DashboardState, generate_token, router};

    #[test]
    fn generate_token_is_thirty_two_lowercase_hex_and_unique() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_eq!(
            a.len(),
            32,
            "16 CSPRNG bytes hex-encode to exactly 32 chars"
        );
        assert!(
            !a.is_empty(),
            "router's debug_assert rejects an empty token"
        );
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "token must be lowercase hex so require_token compares the raw ?t= value: {a}"
        );
        // Two independent CSPRNG draws over 128 bits collide with negligible
        // probability, so inequality confirms the token is drawn per call, not fixed.
        assert_ne!(a, b, "each launch must draw a fresh token");
    }

    /// Anchor threshold high enough that the token tests never trip anchoring;
    /// mirrors the fixture in `src/server.rs`'s test module.
    const ANCHOR_THRESHOLD: usize = 16;

    fn test_state(token: &str) -> DashboardState {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        let key = SecretKey::from_bytes([7u8; 32]);
        let oplog = OpLogStore::new(blob.clone());
        let signer: Arc<dyn Signer> = Arc::new(
            Sr25519Signer::from_seed_with_prefix(&[5u8; 32], NetworkPrefix::HIPPIUS)
                .expect("valid test seed"),
        );
        let store = Arc::new(MemoryStore::new(
            blob,
            index,
            oplog,
            Arc::new(NoopAnchor),
            signer,
            std::collections::BTreeMap::from([(0_u64, key)]),
            0,
            "test-team".to_owned(),
            ANCHOR_THRESHOLD,
        ));
        DashboardState {
            store,
            token: Arc::from(token),
        }
    }

    #[tokio::test]
    async fn missing_token_is_unauthorized() {
        let app = router(test_state("secret-token"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn correct_token_is_authorized() {
        let app = router(test_state("secret-token"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/overview?t=secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_token_is_unauthorized() {
        let app = router(test_state("secret-token"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/overview?t=not-the-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn header_token_is_authorized() {
        let app = router(test_state("secret-token"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/overview")
                    .header("x-dashboard-token", "secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A token-bearing GET request for `uri`. Every data route is gated, so tests
    /// always carry `?t=t` (the `test_state` token).
    fn get_req(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    /// Decode a JSON response body. `usize::MAX` is safe here: the fixtures are
    /// tiny in-memory payloads, not untrusted network input.
    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Seed one note through the PUBLIC ingestion path (`remember`), so the tests
    /// exercise what a real write puts in the index rather than a direct insert.
    async fn seed(state: &DashboardState, note_type: NoteType, summary: &str) -> NoteId {
        state
            .store
            .remember(RememberInput {
                note_type,
                repo: RepoScope::Global,
                tags: BTreeSet::new(),
                summary: summary.to_owned(),
                body: format!("body of {summary}"),
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn overview_lists_seeded_notes() {
        let state = test_state("t");
        seed(&state, NoteType::Decision, "the first note").await;
        seed(&state, NoteType::Gotcha, "the second note").await;
        let app = router(state);

        let resp = app.oneshot(get_req("/api/overview?t=t")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;

        assert_eq!(body["note_count"], 2, "both seeded notes are counted");
        let notes = body["notes"].as_array().unwrap();
        assert_eq!(notes.len(), 2);
        let types: BTreeSet<&str> = notes
            .iter()
            .map(|n| n["note_type"].as_str().unwrap())
            .collect();
        assert_eq!(
            types,
            BTreeSet::from(["decision", "gotcha"]),
            "each row carries the note_type the browse filter needs"
        );
    }

    #[tokio::test]
    async fn list_notes_filters_by_type() {
        let state = test_state("t");
        seed(&state, NoteType::Decision, "a decision note").await;
        seed(&state, NoteType::Gotcha, "a gotcha note").await;
        let app = router(state);

        let resp = app
            .oneshot(get_req("/api/notes?t=t&type=gotcha"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;

        let notes = body["notes"].as_array().unwrap();
        assert_eq!(notes.len(), 1, "only the gotcha survives the type filter");
        assert_eq!(notes[0]["note_type"], "gotcha");
    }

    #[tokio::test]
    async fn get_note_returns_body_and_version() {
        let state = test_state("t");
        let id = seed(&state, NoteType::Decision, "a note with a body").await;
        let app = router(state);

        let resp = app
            .oneshot(get_req(&format!("/api/notes/{id}?t=t")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;

        assert_eq!(body["id"], id.to_string());
        assert_eq!(body["body"], "body of a note with a body");
        // The version is the hex BLAKE3 of the ciphertext: 32 bytes -> 64 hex chars.
        assert_eq!(body["version"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn get_note_unknown_id_is_404() {
        let state = test_state("t");
        let app = router(state);

        // A valid-format ULID that was never remembered: the id parses (not a 400),
        // but no note is indexed, so `get` reports NotFound -> 404.
        let resp = app
            .oneshot(get_req("/api/notes/mem_01ARZ3NDEKTSV4RRFFQ69G5FAV?t=t"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn health_reports_lexical_for_hash_embedder() {
        let state = test_state("t");
        let app = router(state);

        let resp = app.oneshot(get_req("/api/health?t=t")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;

        assert_eq!(
            body["semantic"], false,
            "the HashEmbedder test store ranks lexically, not semantically"
        );
        assert_eq!(body["team"], "test-team");
    }

    #[tokio::test]
    async fn list_notes_search_ranks_matching_note() {
        // Exercises the `q` path: `search_rows` + `spawn_blocking(recall)`. Under
        // the HashEmbedder the recall is deterministic lexical BM25, so a query
        // token present in exactly one summary returns exactly that note (the
        // other scores 0 in the only leg and is not relevant).
        let state = test_state("t");
        seed(&state, NoteType::Decision, "alpha widget design").await;
        seed(&state, NoteType::Gotcha, "beta gadget failure").await;
        let app = router(state);

        let resp = app
            .oneshot(get_req("/api/notes?t=t&q=widget"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;

        let notes = body["notes"].as_array().unwrap();
        assert_eq!(
            notes.len(),
            1,
            "only the note whose summary has 'widget' ranks"
        );
        assert_eq!(notes[0]["summary"], "alpha widget design");
    }

    #[tokio::test]
    async fn list_notes_search_and_type_filter_compose() {
        // Search and the type filter must compose: `q` matches the note, but a
        // non-matching `type` excludes it (empty); the matching `type` keeps it.
        // Shares one seeded store across two requests via a `DashboardState` clone.
        let state = test_state("t");
        seed(&state, NoteType::Decision, "composable filter probe").await;

        let wrong_type = router(state.clone())
            .oneshot(get_req("/api/notes?t=t&q=probe&type=gotcha"))
            .await
            .unwrap();
        assert_eq!(wrong_type.status(), StatusCode::OK);
        let body = json_body(wrong_type).await;
        assert_eq!(
            body["notes"].as_array().unwrap().len(),
            0,
            "a matching search hit is dropped by a non-matching type filter"
        );

        let right_type = router(state)
            .oneshot(get_req("/api/notes?t=t&q=probe&type=decision"))
            .await
            .unwrap();
        assert_eq!(right_type.status(), StatusCode::OK);
        let body = json_body(right_type).await;
        assert_eq!(
            body["notes"].as_array().unwrap().len(),
            1,
            "the same hit survives when the type filter matches"
        );
    }

    #[tokio::test]
    async fn get_note_malformed_id_is_400() {
        let state = test_state("t");
        let app = router(state);

        // Not a `mem_...` ULID: the id fails to parse, so `get_note` returns
        // BadRequest -> 400, distinct from the absent-but-valid id -> 404 path.
        let resp = app
            .oneshot(get_req("/api/notes/not-a-valid-id?t=t"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn index_serves_html() {
        // Proves `include_str!` wired `dashboard.html` into the binary and the
        // token-gated `/` route serves it: a stable id from the page markup must
        // survive the round-trip. If the file were missing the crate would not
        // compile, so reaching this assertion already means the include resolved.
        let app = router(test_state("t"));
        let resp = app.oneshot(get_req("/?t=t")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            html.contains("id=\"notes-table\""),
            "served page must be the real dashboard, not a stub"
        );
        assert!(html.contains("<title>Hippius Memory"));
    }
}
