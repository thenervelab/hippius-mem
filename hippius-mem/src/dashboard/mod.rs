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
use std::ffi::OsStr;
use std::path::PathBuf;
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

use crate::config::{Config, ConfigError, DEFAULT_CONFIG_PATH};
use crate::resolver::{self, GitRemoteReader, RemoteReader, Resolution};

/// Run the `hippius-mem dashboard` subcommand: bind a loopback HTTP server that
/// browses and searches every configured team memory as a selectable "vault".
///
/// Unlike the MCP server boot, this builds NO store up front. It loads config,
/// records which vault THIS cwd's git remote routes to (`current_vault`, for the
/// UI's "current" badge — a repo that routes nowhere is simply `None`, not an
/// error, since the user can still open another vault), mints the launch token, and
/// serves. Each vault's store is built, epoch-bootstrapped, and synced lazily on
/// first access and then cached (see [`DashboardState::store_for`]), so opening the
/// dashboard is instant and a vault's sync cost is paid only when it is entered.
///
/// The security boundary is loopback + the per-launch token generated here (see the
/// module docs and `require_token`).
///
/// # Errors
///
/// Returns an error if configuration cannot be loaded, the OS CSPRNG is
/// unavailable, or the loopback socket cannot be bound. A repo routing to no
/// profile is NOT an error here (the user picks a vault); a vault's store-build
/// failure surfaces per-request via `store_for`, not at launch.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let DashboardArgs { port, no_open } = parse_args(args)?;

    // The dashboard is a browse-EVERYTHING view, so it defaults to the user's global
    // config (all namespaces) rather than the cwd-local `./hippius-mem.toml` the MCP
    // server uses for per-repo team routing. `HIPPIUS_MEM_CONFIG` still overrides.
    let cfg = Config::from_env_and_file_with_default(&dashboard_config_default()).context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;

    // Which vault does THIS directory route to? Used only for the "current" badge; a
    // repo matching no profile (or a disabled resolution) leaves it `None` — the
    // dashboard still lists and serves every other vault, so unlike the server boot
    // we do NOT bail on a disabled resolution.
    let current_vault = resolve_current_vault(&cfg);

    // The launch token is the dashboard's ONLY auth capability; a fresh CSPRNG draw
    // per launch means a leaked URL dies with the process rather than granting
    // standing access to the team's decrypted memory.
    let token = generate_token()?;

    // Capture a log-friendly label before `current_vault` moves into the state.
    let vault_label = current_vault
        .clone()
        .unwrap_or_else(|| "(none — choose a vault in the UI)".to_owned());
    let state = DashboardState {
        cfg: Arc::new(cfg),
        token: Arc::from(token.as_str()),
        // No stores built yet: every vault is materialized lazily by `store_for`.
        stores: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        current_vault,
    };

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
        current_vault = %vault_label,
        %url,
        "Hippius Memory dashboard listening — open this URL in a browser"
    );

    // Convenience: open the URL so launching the dashboard is one command, not a
    // copy-paste. Suppressed by `--no-open`, and auto-skipped on a headless/remote
    // box (SSH, or Linux with no display) where a browser launch would fail or hang.
    // The URL was already logged above, so every path still leaves the operator a
    // clickable link; the open itself is best-effort and never fatal (see
    // `open_in_browser`).
    if no_open {
        tracing::info!("--no-open set; not launching a browser");
    } else if is_headless(&BrowserEnv::from_process()) {
        tracing::info!(
            "headless environment detected; not launching a browser — open the URL above"
        );
    } else {
        open_in_browser(&url);
    }

    // No graceful-shutdown signal is wired: this is a Phase 1 loopback, read-only
    // CLI with no write path or in-flight state to drain, so Ctrl-C terminating the
    // process is correct — the op-log is durable and there is nothing to flush.
    axum::serve(listener, router(state))
        .await
        .context("dashboard HTTP server error")?;
    Ok(())
}

/// Resolve which configured vault THIS cwd's git remote routes to, for the UI's
/// "current" badge. Mirrors the server boot's routing but returns `Option`: a
/// disabled resolution (no matching profile and no catch-all) is `None`, not a
/// bail — the dashboard still lists and serves every other vault.
fn resolve_current_vault(cfg: &Config) -> Option<String> {
    let profiles = cfg.all_profiles();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let remote = GitRemoteReader.origin_url(&cwd);
    match resolver::resolve(&profiles, remote.as_deref()) {
        Resolution::Bound(profile) => Some(profile.name.clone()),
        Resolution::Disabled(_) => None,
    }
}

/// The dashboard's default config path when `HIPPIUS_MEM_CONFIG` is unset: the user's
/// GLOBAL config, so the vault list shows EVERY namespace no matter which repo the
/// command is launched from. A repo-local `./hippius-mem.toml` is the MCP server's
/// per-repo routing override, not the browse-everything view. Falls back to the
/// cwd-local [`DEFAULT_CONFIG_PATH`] when no global config exists (a dev / local-only
/// setup); `HIPPIUS_MEM_CONFIG` still overrides both inside the loader.
fn dashboard_config_default() -> String {
    let xdg = std::env::var_os("XDG_CONFIG_HOME");
    let home = std::env::var_os("HOME");
    match global_config_path(xdg.as_deref(), home.as_deref()) {
        Some(path) if path.exists() => path.to_string_lossy().into_owned(),
        _ => DEFAULT_CONFIG_PATH.to_owned(),
    }
}

/// Compute the global config path from the two env values, mirroring the installer's
/// `${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem/hippius-mem.toml` (`scripts/install.sh`).
/// Pure — no env or filesystem access — so the precedence is unit-testable; an empty
/// value is treated as unset to match the shell `:-` fallback. `None` when neither var
/// yields a base directory.
fn global_config_path(xdg_config_home: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    let base = xdg_config_home
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        })?;
    Some(base.join("hippius-mem").join("hippius-mem.toml"))
}

/// Parsed `hippius-mem dashboard` arguments: the bind port and whether to suppress
/// the browser auto-open. A struct rather than a bare `u16` return so adding a second
/// flag did not turn the parser's result into a positional `(u16, bool)` tuple whose
/// fields are easy to transpose at the call site (axiom `illu_design_02`).
struct DashboardArgs {
    /// Loopback bind port. `0` asks the OS for an ephemeral port, read back from the
    /// bound socket.
    port: u16,
    /// The operator's explicit `--no-open` override. Headless detection can suppress
    /// the auto-open independently; this is the deliberate "never open" switch.
    no_open: bool,
}

/// Parse the optional `--port <n>` and `--no-open` flags, in any order. Absent
/// `--port` means port `0` (ephemeral). A present-but-unparseable port is a hard
/// error, not a silent fall-back to `0`: an operator who asked for a fixed port must
/// not be handed a random one and left wondering why their bookmark 404s. An unknown
/// argument is rejected so a typo (`--no-opn`) fails loudly rather than being ignored.
fn parse_args(args: &[String]) -> anyhow::Result<DashboardArgs> {
    // A hand-walked index, not a slice match: the two flags are order-independent and
    // `--port` consumes the following token, so enumerating every permutation as a
    // slice pattern would be unreadable — a plain accumulator loop states the grammar
    // directly.
    let mut port = 0u16;
    let mut no_open = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--no-open" => {
                no_open = true;
                i += 1;
            }
            "--port" => {
                let Some(value) = args.get(i + 1) else {
                    anyhow::bail!("--port requires a value");
                };
                port = value
                    .parse::<u16>()
                    .with_context(|| format!("invalid --port value `{value}`"))?;
                i += 2;
            }
            other => anyhow::bail!(
                "unknown dashboard argument `{other}`; usage: dashboard [--port <n>] [--no-open]"
            ),
        }
    }
    Ok(DashboardArgs { port, no_open })
}

/// Environment inputs to the headless decision, snapshotted so [`is_headless`] is a
/// pure function testable without mutating the real process environment.
struct BrowserEnv {
    ssh_connection: Option<String>,
    ssh_tty: Option<String>,
    display: Option<String>,
    wayland_display: Option<String>,
}

impl BrowserEnv {
    /// Snapshot the four relevant variables. Emptiness is interpreted by
    /// [`is_headless`], not here, so the predicate owns the whole rule.
    fn from_process() -> Self {
        Self {
            ssh_connection: std::env::var("SSH_CONNECTION").ok(),
            ssh_tty: std::env::var("SSH_TTY").ok(),
            display: std::env::var("DISPLAY").ok(),
            wayland_display: std::env::var("WAYLAND_DISPLAY").ok(),
        }
    }
}

/// Whether auto-opening a browser would be wrong or would hang: an SSH session (the
/// display is on the remote operator's machine, not this host) or a Linux host with
/// neither X11 nor Wayland. macOS and Windows always carry a windowing system when a
/// user is present, so the display check is Linux-only — there `open`/`start` address
/// the GUI session directly.
fn is_headless(env: &BrowserEnv) -> bool {
    // `std::env::var` returns `Ok("")` for a set-but-empty variable; an empty
    // `SSH_CONNECTION` or `DISPLAY` is not a real session/display, so treat empty as
    // absent. This is the documented env-var edge the test fixtures probe.
    let present = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.is_empty());
    if present(&env.ssh_connection) || present(&env.ssh_tty) {
        return true;
    }
    if cfg!(target_os = "linux") {
        return !present(&env.display) && !present(&env.wayland_display);
    }
    false
}

/// The platform command that opens `url` in the default browser, as `(program,
/// args)`. Pure — spawning is [`open_in_browser`]'s job — so the per-OS mapping is
/// unit-testable. The Windows form is `cmd /C start "" <url>`: `start` treats a first
/// quoted argument as the window title, so the empty `""` title keeps a URL bearing
/// `&`/`?` from being misparsed as one.
fn browser_command(url: &str) -> (&'static str, Vec<String>) {
    if cfg!(target_os = "macos") {
        ("open", vec![url.to_owned()])
    } else if cfg!(target_os = "windows") {
        (
            "cmd",
            vec![
                "/C".to_owned(),
                "start".to_owned(),
                String::new(),
                url.to_owned(),
            ],
        )
    } else {
        ("xdg-open", vec![url.to_owned()])
    }
}

/// Best-effort: launch the default browser at `url`. Never fatal — the URL was
/// already logged, so a spawn failure (no `xdg-open`, a sandbox) degrades to the
/// operator clicking the printed link. Uses `spawn` (not `status`/`output`) so the
/// dashboard never blocks on the browser process; the short-lived child is left for
/// the OS to reap when this foreground CLI exits.
fn open_in_browser(url: &str) {
    let (program, args) = browser_command(url);
    match std::process::Command::new(program).args(&args).spawn() {
        Ok(_child) => tracing::info!(%url, "opened the dashboard in your default browser"),
        Err(error) => tracing::warn!(
            %error,
            program,
            "could not launch a browser automatically; open the URL above manually"
        ),
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

/// Shared handler state for the multi-vault dashboard. Every field is cheap to
/// `Clone` (axum requires `State: Clone`): `cfg`/`token`/`stores` are reference
/// counts and `current_vault` is a short owned label.
#[derive(Clone)]
pub(crate) struct DashboardState {
    /// The whole resolved configuration. `all_profiles()` enumerates the vaults for
    /// `/api/vaults`, and `store_for` builds a chosen vault's store from the
    /// matching profile.
    pub cfg: Arc<Config>,
    /// Per-launch secret compared by `require_token`. `Arc<str>` (not `String`)
    /// because it is read-only and cloned into every request via the state.
    pub token: Arc<str>,
    /// Lazily-built stores keyed by vault name. An async [`tokio::sync::Mutex`]
    /// because building/syncing a store is async and the guard is held across those
    /// awaits: a `std::sync::Mutex` guard is `!Send`, which would make the handler
    /// future `!Send` and axum's multi-thread runtime would reject it (axiom
    /// `rust_quality_74_mutex_guard_await`).
    ///
    /// This is ONE process-global lock taken on EVERY store access (see
    /// `store_for`), not a per-vault lock: while any vault is building+syncing (~a
    /// few seconds), a request for an already-cached DIFFERENT vault — or a
    /// first-open of any other vault — also blocks on it. That is a conscious
    /// Phase-1 tradeoff for a local single-user dashboard: it guarantees build-once,
    /// and a browser firing overview+notes+health for one vault on entry collapses
    /// to a single build. The deferred fix, if multi-user or slow-network access
    /// ever matters, is a per-vault lock (a map of `OnceCell`/`Semaphore`, or
    /// double-checked locking that drops the map guard before building).
    pub stores: Arc<tokio::sync::Mutex<HashMap<String, Arc<MemoryStore>>>>,
    /// The vault THIS cwd's git remote routes to, if any — drives the "current"
    /// badge in the vault list. `None` when the repo matches no profile.
    pub current_vault: Option<String>,
}

impl DashboardState {
    /// Return the store for `vault`, building it lazily on first access and caching
    /// it for the rest of the process. An unknown vault is [`ApiError::NotFound`]
    /// (404, no build attempted); a build failure is [`ApiError::VaultUnavailable`]
    /// (500).
    ///
    /// The build mirrors the server boot exactly (parity): construct the store, run
    /// the mnemonic-gated epoch-key bootstrap (so a rotated team's newer-epoch notes
    /// decrypt — see `admin::bootstrap_epochs`), then a best-effort sync.
    ///
    /// The `stores` guard is held across the whole build+bootstrap+sync, and it is a
    /// SINGLE process-global lock (not per-vault): every call — cache hit or miss —
    /// takes it, so while one vault builds (~seconds) a request for an
    /// already-cached different vault also blocks here. That is the deliberate
    /// Phase-1 tradeoff documented on the `stores` field: it guarantees build-once
    /// (a racing double-build would only waste an S3 round-trip) and collapses a
    /// browser's overview+notes+health burst on vault entry into one build. It is
    /// sound to hold across the awaits only because `tokio::sync::Mutex`'s guard is
    /// `Send`, keeping the handler future `Send` for axum's runtime.
    async fn store_for(&self, vault: &str) -> Result<Arc<MemoryStore>, ApiError> {
        let mut guard = self.stores.lock().await;
        if let Some(store) = guard.get(vault) {
            return Ok(Arc::clone(store));
        }
        // Unknown vault: 404 without building anything. `all_profiles` is cheap (it
        // clones the config's profile list); the match is by profile name, which is
        // the vault identifier the routes are scoped under.
        let profile = self
            .cfg
            .all_profiles()
            .into_iter()
            .find(|profile| profile.name == vault)
            .ok_or(ApiError::NotFound)?;
        let store = Arc::new(
            profile
                .build_store(&self.cfg)
                .await
                .map_err(ApiError::VaultUnavailable)?,
        );
        // Parity with the server boot: without this a rotated team's newer-epoch
        // notes stay sealed and are silently omitted. Non-fatal by contract.
        if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
            crate::admin::bootstrap_epochs(&store, &mnemonic, self.cfg.max_epoch).await;
        }
        // Best-effort freshen so the first view reflects teammates' latest notes; a
        // sync error is non-fatal (the op-log is durable and reads self-heal).
        match store.sync().await {
            Ok(count) => tracing::info!(vault, count, "synced vault index from op-log"),
            Err(err) => {
                tracing::warn!(vault, error = %err, "vault sync failed; serving whatever is indexed");
            }
        }
        guard.insert(vault.to_owned(), Arc::clone(&store));
        Ok(store)
    }
}

/// Build the dashboard router with the token gate applied to *every* route.
///
/// The `.layer(require_token)` sits above all routes, so there is no path — not
/// even `/api/vaults` or `/` — reachable without presenting the token. The note
/// routes are vault-scoped: each resolves `{vault}` to a lazily-built store via
/// [`DashboardState::store_for`]; only `/api/vaults` (the landing list) is
/// store-free.
pub(crate) fn router(state: DashboardState) -> Router {
    // An empty token would make `presented == Some("")` authorize any request that
    // sends `?t=` (or the header) with an empty value — the gate would be open. Pin
    // the hazard at the boundary; `run` supplies the real CSPRNG token, so a
    // violation here is a construction bug, not a runtime input.
    debug_assert!(
        !state.token.is_empty(),
        "dashboard launch token must be non-empty"
    );
    Router::new()
        .route("/", get(index_html))
        // The vault list is the landing data — no store is built to serve it.
        .route("/api/vaults", get(vaults))
        // Every note route is vault-scoped; the handler resolves `{vault}` to a
        // (lazily-built) store. axum 0.8 path-param syntax is `{param}` (0.7's
        // `:param` no longer parses), and a tuple `Path` extracts the two segments.
        .route("/api/vaults/{vault}/overview", get(overview))
        .route("/api/vaults/{vault}/repos", get(list_repos))
        .route("/api/vaults/{vault}/notes", get(list_notes))
        .route("/api/vaults/{vault}/notes/{id}", get(get_note))
        .route(
            "/api/vaults/{vault}/notes/{id}/history",
            get(get_note_history),
        )
        .route("/api/vaults/{vault}/health", get(health))
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

    // Deferred hardening: a `==` compare is not constant-time, so it leaks timing
    // about how many leading bytes matched. Negligible here — the token is a
    // per-launch 128-bit CSPRNG value on a loopback-only surface, so a timing oracle
    // buys nothing over brute force — and a constant-time compare would add a dep for
    // no Phase 1 benefit. Revisit if the token ever becomes long-lived or non-local.
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
    updated: i64,
    tags: Vec<String>,
}

/// One selectable vault in the landing list. Built purely from config
/// (`all_profiles`), so listing vaults never builds or syncs a store.
#[derive(Serialize)]
struct VaultDto {
    /// Profile name — also the path segment the note routes are scoped under.
    name: String,
    /// The remote patterns this vault owns; empty for the catch-all profile.
    orgs: Vec<String>,
    bucket: String,
    /// Whether this is the vault THIS cwd's git remote routes to.
    is_current: bool,
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

/// The detail for one note: its decrypted body, version, and links — the payload
/// behind a row click.
///
/// The op **history** is deliberately NOT here. It is served by a separate,
/// lazily-loaded endpoint (`get_note_history`) because building it re-reads and
/// re-verifies the WHOLE op-log plus every anchor record — seconds of gateway I/O
/// that would otherwise block simply opening a note to read its body. The drawer
/// fetches it on demand only when the audit trail is expanded.
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
}

/// A note's op history, projected for the UI. This is a compact projection of the
/// core [`NoteHistory`], NOT the server's full `HistoryDto`: the drawer shows who
/// did what and whether it is anchored, so the per-op Merkle proof is reduced to
/// an `anchored` boolean rather than carrying the whole inclusion path. Links live
/// only on [`NoteDetailDto`] (which the drawer reads); duplicating them here would
/// be a second, unread copy.
#[derive(Serialize)]
struct NoteHistoryDto {
    tombstoned: bool,
    redacted: bool,
    entries: Vec<HistoryEntryRow>,
}

/// One op in a note's history, reduced to the fields the drawer renders: who
/// (`author`), when (`lamport`), what (`kind`), and whether it is anchored. The
/// op id and content cid are intentionally omitted — the drawer does not surface
/// them, so shipping them would be dead wire weight.
#[derive(Serialize)]
struct HistoryEntryRow {
    author: String,
    lamport: u64,
    kind: String,
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
    /// 500 — a vault's store could not be built (bad credentials, unreachable
    /// anchoring chain, malformed key). Carries the [`ConfigError`] so the loopback
    /// caller sees which coordinate was wrong; `ConfigError`'s `Display` is
    /// secret-free (it names fields, never key material).
    VaultUnavailable(ConfigError),
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
            // Secret-free by construction: `ConfigError` names the offending field
            // and the fix, never the key/secret value.
            ApiError::VaultUnavailable(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
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

/// List every configured vault. A pure config projection — no store is built, so
/// the landing page is instant regardless of vault count or size.
async fn vaults(State(state): State<DashboardState>) -> Json<Vec<VaultDto>> {
    let current = state.current_vault.as_deref();
    let cfg = &state.cfg;
    // Project the vault labels from BORROWED config fields, cloning only
    // name/orgs/bucket. `all_profiles()` would deep-clone every `TeamProfile` —
    // secret fields (`secret`/`team_key_hex`/`author_seed_hex`) included — just to
    // drop them here; never allocate key material to render the landing list.
    // Membership mirrors `all_profiles()`: the flat primary profile, then `[[teams]]`.
    let mut vaults = Vec::with_capacity(1 + cfg.teams.len());
    vaults.push(vault_dto(&cfg.team, &cfg.orgs, &cfg.bucket, current));
    for team in &cfg.teams {
        vaults.push(vault_dto(&team.name, &team.orgs, &team.bucket, current));
    }
    Json(vaults)
}

/// Build a [`VaultDto`] from one profile's borrowed label fields, cloning only the
/// three non-secret strings (name/orgs/bucket) — never the profile's key material.
fn vault_dto(name: &str, orgs: &[String], bucket: &str, current: Option<&str>) -> VaultDto {
    VaultDto {
        is_current: current == Some(name),
        name: name.to_owned(),
        orgs: orgs.to_vec(),
        bucket: bucket.to_owned(),
    }
}

/// Page-load browse payload for one vault: resolve the vault's store, best-effort
/// freshen, then enumerate every note.
async fn overview(
    State(state): State<DashboardState>,
    Path(vault): Path<String>,
) -> Result<Json<OverviewDto>, ApiError> {
    let store = state.store_for(&vault).await?;
    // Best-effort: a stale probe failure must not fail the page — serve the current
    // index and let health surface sync state. On a FIRST access `store_for` just
    // synced, so this probe is a no-op (the index is fresh); on a cached access it is
    // the normal staleness check — so it is not redundant, do not remove it.
    let _ = store.refresh_if_stale().await;
    let mut notes: Vec<NoteRow> = store.list_records()?.iter().map(row_from).collect();
    sort_rows(&mut notes);
    Ok(Json(OverviewDto {
        team: store.team().to_owned(),
        note_count: notes.len(),
        semantic: store.is_semantic(),
        notes,
    }))
}

/// Browse or search. With `q` present the rows are recall-ranked; otherwise they
/// are the enumeration filtered in-memory by `type`/`repo`/`tag`.
async fn list_notes(
    State(state): State<DashboardState>,
    Path(vault): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<NotesDto>, ApiError> {
    let store = state.store_for(&vault).await?;
    let _ = store.refresh_if_stale().await;
    let notes = match non_empty(params.get("q")) {
        // Search and browse must apply the SAME `type`/`tag` matching: recall
        // scopes `repo` itself, but `type`/`tag` are post-filters here so a
        // `?q=foo&type=gotcha&tag=x` narrows the ranked hits the identical way a
        // filter-only browse would — via `row_matches` — while preserving recall
        // order (`Iterator::filter` is order-preserving).
        Some(query) => {
            let ranked = search_rows(&store, query, non_empty(params.get("repo"))).await?;
            let type_filter = non_empty(params.get("type"));
            let tag_filter = non_empty(params.get("tag"));
            ranked
                .into_iter()
                .filter(|row| row_matches(row, type_filter, tag_filter))
                .collect()
        }
        None => filter_rows(&store, &params)?,
    };
    Ok(Json(NotesDto { notes }))
}

/// One entry on a vault's repos page: a repo (the `global` sentinel for team-wide
/// notes) and its live-note count. Body-free — the repos page is pure navigation, so
/// like [`NoteRow`] it never carries a summary or body.
#[derive(Serialize)]
struct RepoRow {
    repo: String,
    count: usize,
}

/// The repos-drill-down payload for one vault.
#[derive(Serialize)]
struct ReposDto {
    repos: Vec<RepoRow>,
}

/// List the distinct repos in a vault with their live-note counts — the middle level
/// of the Vault → Repos → Notes drill-down. `global` is the team-wide bucket (notes
/// scoped to no repo). Ordering is `global` first, then most-populated repos, then
/// name, so the busiest repos surface without scanning.
///
/// Reuses [`repo_to_dto`] for the group key so a row's `repo` is byte-identical to the
/// value `list_notes`'s `?repo=` filter expects — the page can hand it straight back.
async fn list_repos(
    State(state): State<DashboardState>,
    Path(vault): Path<String>,
) -> Result<Json<ReposDto>, ApiError> {
    let store = state.store_for(&vault).await?;
    let _ = store.refresh_if_stale().await;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for record in &store.list_records()? {
        *counts.entry(repo_to_dto(&record.scope.repo)).or_default() += 1;
    }
    let mut repos: Vec<RepoRow> = counts
        .into_iter()
        .map(|(repo, count)| RepoRow { repo, count })
        .collect();
    // `global` pinned first, then count descending, then name — a total order, so the
    // list is stable across calls (BTreeMap already gave us name order to break ties).
    repos.sort_by(|a, b| {
        (b.repo == "global")
            .cmp(&(a.repo == "global"))
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.repo.cmp(&b.repo))
    });
    Ok(Json(ReposDto { repos }))
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
    store: &MemoryStore,
    params: &HashMap<String, String>,
) -> Result<Vec<NoteRow>, ApiError> {
    let type_filter = non_empty(params.get("type"));
    let repo_filter = non_empty(params.get("repo"));
    let tag_filter = non_empty(params.get("tag"));
    let mut rows: Vec<NoteRow> = store
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
    store: &Arc<MemoryStore>,
    query: &str,
    repo: Option<&str>,
) -> Result<Vec<NoteRow>, ApiError> {
    let by_id: BTreeMap<NoteId, IndexRecord> = store
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
        // The one canonical scope parser (trims, maps ""/whitespace/"global" to
        // the global dimension) — shared with the MCP `recall` path so the
        // browse UI and the tool cannot disagree on what a `repo` filter means.
        repo: crate::server::parse_repo(repo),
        k: DEFAULT_LIST_K,
        token_budget: None,
    };
    let store = Arc::clone(store);
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
/// version. This is the FAST path — one blob fetch + an index lookup — so opening
/// a note to read it is instant. The op history is served separately by
/// [`get_note_history`] and loaded lazily, because it re-reads the whole op-log.
async fn get_note(
    State(state): State<DashboardState>,
    Path((vault, id)): Path<(String, String)>,
) -> Result<Json<NoteDetailDto>, ApiError> {
    // Resolve the vault BEFORE parsing the id so an unknown vault is a 404 even when
    // the id is also malformed — the vault is the outer resource.
    let store = state.store_for(&vault).await?;
    let note_id: NoteId = id
        .parse()
        .map_err(|err: ParseNoteIdError| ApiError::BadRequest(err.to_string()))?;
    let _ = store.refresh_if_stale().await;
    // `get` errors `MemError::NotFound` for an unindexed id, which `From` maps to a 404.
    let note = store.get(note_id).await?;
    let version = store.current_version(note_id)?.to_hex();
    Ok(Json(detail_from(&note, version)))
}

/// The op history + audit proofs for one note, loaded lazily by the drawer's
/// "audit trail" section.
///
/// Separated from [`get_note`] on purpose: [`MemoryStore::history`] reads and
/// crypto-verifies the ENTIRE op-log and every anchor record to reconstruct one
/// note's ~handful of ops — seconds of gateway I/O. Keeping it off the note-open
/// path means reading a note never pays for the audit trail; you pay only when you
/// ask to see it.
async fn get_note_history(
    State(state): State<DashboardState>,
    Path((vault, id)): Path<(String, String)>,
) -> Result<Json<NoteHistoryDto>, ApiError> {
    let store = state.store_for(&vault).await?;
    let note_id: NoteId = id
        .parse()
        .map_err(|err: ParseNoteIdError| ApiError::BadRequest(err.to_string()))?;
    // `history` reads the op-log directly and yields an empty history for an unknown
    // note rather than erroring, so an unknown-but-well-formed id returns an empty
    // trail rather than a 404 — matching the tool's contract.
    let history = store.history(note_id).await?;
    Ok(Json(history_from(&history)))
}

/// Project a hydrated [`Note`] onto the detail DTO (no history — see
/// [`NoteDetailDto`]).
fn detail_from(note: &Note, version: String) -> NoteDetailDto {
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
    }
}

/// Project the core [`NoteHistory`] onto the compact drawer DTO.
fn history_from(history: &NoteHistory) -> NoteHistoryDto {
    NoteHistoryDto {
        tombstoned: history.tombstoned,
        redacted: history.redacted,
        entries: history.entries.iter().map(entry_from).collect(),
    }
}

/// Project one core [`HistoryEntry`] onto its drawer row, reducing the anchor
/// proof to a committed/pending boolean.
fn entry_from(entry: &HistoryEntry) -> HistoryEntryRow {
    HistoryEntryRow {
        author: entry.author.as_str().to_owned(),
        lamport: entry.lamport,
        kind: entry.kind.as_str().to_owned(),
        anchored: entry.anchor.is_some(),
    }
}

/// Health panel for one vault: team, retrieval mode, sync freshness, and note count.
async fn health(
    State(state): State<DashboardState>,
    Path(vault): Path<String>,
) -> Result<Json<HealthDto>, ApiError> {
    let store = state.store_for(&vault).await?;
    // `synced` reports whether THIS request triggered a sync; a probe error is
    // swallowed to `false` so the health route itself never fails on staleness.
    let synced = store.refresh_if_stale().await.unwrap_or(false);
    let note_count = store.list_records()?.len();
    Ok(Json(HealthDto {
        team: store.team().to_owned(),
        semantic: store.is_semantic(),
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

    use std::collections::{BTreeSet, HashMap};
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

    use crate::config::{Config, TeamProfile};

    use std::ffi::OsStr;
    use std::path::PathBuf;

    use super::{
        BrowserEnv, DashboardState, browser_command, generate_token, global_config_path,
        is_headless, parse_args, router,
    };

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

    /// An in-memory `MemoryStore` named "test-team" — the vault the route tests
    /// pre-seed into `DashboardState::stores` so `store_for` hits the cache and
    /// never builds from config/S3.
    fn test_store() -> Arc<MemoryStore> {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        let key = SecretKey::from_bytes([7u8; 32]);
        let oplog = OpLogStore::new(blob.clone());
        let signer: Arc<dyn Signer> = Arc::new(
            Sr25519Signer::from_seed_with_prefix(&[5u8; 32], NetworkPrefix::HIPPIUS)
                .expect("valid test seed"),
        );
        Arc::new(MemoryStore::new(
            blob,
            index,
            oplog,
            Arc::new(NoopAnchor),
            signer,
            std::collections::BTreeMap::from([(0_u64, key)]),
            0,
            "test-team".to_owned(),
            ANCHOR_THRESHOLD,
        ))
    }

    /// A minimal config whose sole profile is named "test-team". Route tests never
    /// build from it (the store is pre-seeded into the map), so the credentials stay
    /// empty; it exists only so `all_profiles()` / `store_for` can resolve the vault
    /// name. Relies on `Config: Default` (required by its `#[serde(default)]`).
    fn test_cfg() -> Config {
        Config {
            team: "test-team".to_owned(),
            ..Config::default()
        }
    }

    /// Build a multi-vault state with the "test-team" vault pre-seeded and marked
    /// current. Token-only tests use this via [`test_state`]; seeding tests use
    /// [`test_state_seeded`] to also get the store `Arc`.
    fn test_state(token: &str) -> DashboardState {
        test_state_seeded(token).0
    }

    /// Like [`test_state`] but also returns the store `Arc` so a test can `seed`
    /// notes into the very instance the vault-scoped routes read.
    fn test_state_seeded(token: &str) -> (DashboardState, Arc<MemoryStore>) {
        let store = test_store();
        let mut stores = HashMap::new();
        stores.insert("test-team".to_owned(), Arc::clone(&store));
        let state = DashboardState {
            cfg: Arc::new(test_cfg()),
            token: Arc::from(token),
            stores: Arc::new(tokio::sync::Mutex::new(stores)),
            current_vault: Some("test-team".to_owned()),
        };
        (state, store)
    }

    #[tokio::test]
    async fn missing_token_is_unauthorized() {
        let app = router(test_state("secret-token"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/vaults/test-team/overview")
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
                    .uri("/api/vaults/test-team/overview?t=secret-token")
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
                    .uri("/api/vaults/test-team/overview?t=not-the-token")
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
                    .uri("/api/vaults/test-team/overview")
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
    async fn seed(store: &MemoryStore, note_type: NoteType, summary: &str) -> NoteId {
        seed_repo(store, note_type, RepoScope::Global, summary).await
    }

    /// Seed a note under a specific repo scope through the public `remember` path, so
    /// the repos-drill-down test exercises the real ingestion rather than a fixture
    /// insert.
    async fn seed_repo(
        store: &MemoryStore,
        note_type: NoteType,
        repo: RepoScope,
        summary: &str,
    ) -> NoteId {
        store
            .remember(RememberInput {
                force: false,
                note_type,
                repo,
                tags: BTreeSet::new(),
                summary: summary.to_owned(),
                body: format!("body of {summary}"),
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn repos_lists_distinct_repos_with_counts_global_first() {
        let (state, store) = test_state_seeded("t");
        seed_repo(
            &store,
            NoteType::Gotcha,
            RepoScope::Repo("alpha".to_owned()),
            "a1",
        )
        .await;
        seed_repo(
            &store,
            NoteType::Decision,
            RepoScope::Repo("alpha".to_owned()),
            "a2",
        )
        .await;
        seed_repo(
            &store,
            NoteType::Reference,
            RepoScope::Repo("beta".to_owned()),
            "b1",
        )
        .await;
        seed_repo(&store, NoteType::Convention, RepoScope::Global, "g1").await;
        let app = router(state);

        let resp = app
            .oneshot(get_req("/api/vaults/test-team/repos?t=t"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let repos = body["repos"].as_array().unwrap();

        // `global` pinned first, then count descending: alpha (2) before beta (1).
        let ordered: Vec<(&str, u64)> = repos
            .iter()
            .map(|r| (r["repo"].as_str().unwrap(), r["count"].as_u64().unwrap()))
            .collect();
        assert_eq!(ordered, vec![("global", 1), ("alpha", 2), ("beta", 1)]);
    }

    #[tokio::test]
    async fn overview_lists_seeded_notes() {
        let (state, store) = test_state_seeded("t");
        seed(&store, NoteType::Decision, "the first note").await;
        seed(&store, NoteType::Gotcha, "the second note").await;
        let app = router(state);

        let resp = app
            .oneshot(get_req("/api/vaults/test-team/overview?t=t"))
            .await
            .unwrap();
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
        let (state, store) = test_state_seeded("t");
        seed(&store, NoteType::Decision, "a decision note").await;
        seed(&store, NoteType::Gotcha, "a gotcha note").await;
        let app = router(state);

        let resp = app
            .oneshot(get_req("/api/vaults/test-team/notes?t=t&type=gotcha"))
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
        let (state, store) = test_state_seeded("t");
        let id = seed(&store, NoteType::Decision, "a note with a body").await;
        let app = router(state);

        let resp = app
            .oneshot(get_req(&format!("/api/vaults/test-team/notes/{id}?t=t")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;

        assert_eq!(body["id"], id.to_string());
        assert_eq!(body["body"], "body of a note with a body");
        // The version is the hex BLAKE3 of the ciphertext: 32 bytes -> 64 hex chars.
        assert_eq!(body["version"].as_str().unwrap().len(), 64);
        // The detail is the FAST path: it must NOT carry the history, which is now
        // fetched lazily from its own endpoint (re-reading the whole op-log).
        assert!(
            body.get("history").is_none(),
            "note detail must not include the op history: {body}"
        );
    }

    #[tokio::test]
    async fn note_history_endpoint_returns_the_op_trail() {
        let (state, store) = test_state_seeded("t");
        let id = seed(&store, NoteType::Decision, "a note").await;
        let app = router(state);

        let resp = app
            .oneshot(get_req(&format!(
                "/api/vaults/test-team/notes/{id}/history?t=t"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;

        let entries = body["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 1, "one Remember op in the trail");
        assert_eq!(entries[0]["kind"], "Remember");
        assert_eq!(body["tombstoned"], false);
        assert_eq!(body["redacted"], false);
    }

    #[tokio::test]
    async fn get_note_unknown_id_is_404() {
        let state = test_state("t");
        let app = router(state);

        // A valid-format ULID that was never remembered: the id parses (not a 400),
        // but no note is indexed, so `get` reports NotFound -> 404.
        let resp = app
            .oneshot(get_req(
                "/api/vaults/test-team/notes/mem_01ARZ3NDEKTSV4RRFFQ69G5FAV?t=t",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn health_reports_lexical_for_hash_embedder() {
        let state = test_state("t");
        let app = router(state);

        let resp = app
            .oneshot(get_req("/api/vaults/test-team/health?t=t"))
            .await
            .unwrap();
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
        let (state, store) = test_state_seeded("t");
        seed(&store, NoteType::Decision, "alpha widget design").await;
        seed(&store, NoteType::Gotcha, "beta gadget failure").await;
        let app = router(state);

        let resp = app
            .oneshot(get_req("/api/vaults/test-team/notes?t=t&q=widget"))
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
        // Shares one seeded store across two requests via a `DashboardState` clone
        // (the clone shares the same `stores` map Arc, so the pre-seeded vault and
        // its notes are visible to both requests).
        let (state, store) = test_state_seeded("t");
        seed(&store, NoteType::Decision, "composable filter probe").await;

        let wrong_type = router(state.clone())
            .oneshot(get_req(
                "/api/vaults/test-team/notes?t=t&q=probe&type=gotcha",
            ))
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
            .oneshot(get_req(
                "/api/vaults/test-team/notes?t=t&q=probe&type=decision",
            ))
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

        // Not a `mem_...` ULID: the vault resolves (pre-seeded), then the id fails to
        // parse, so `get_note` returns BadRequest -> 400, distinct from the
        // absent-but-valid id -> 404 path.
        let resp = app
            .oneshot(get_req("/api/vaults/test-team/notes/not-a-valid-id?t=t"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn vaults_lists_configured_profiles() {
        // The landing list is a pure config projection: the test config's sole
        // profile appears as a vault, flagged current because `current_vault` was
        // set to it. No store is built to serve this.
        let app = router(test_state("t"));
        let resp = app.oneshot(get_req("/api/vaults?t=t")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;

        let vaults = body.as_array().unwrap();
        let test_vault = vaults
            .iter()
            .find(|vault| vault["name"] == "test-team")
            .expect("the configured profile is listed as a vault");
        assert_eq!(
            test_vault["is_current"], true,
            "the vault this cwd resolves to is flagged current"
        );
    }

    #[tokio::test]
    async fn unknown_vault_is_404() {
        let app = router(test_state("t"));
        // A vault name absent from the config: `store_for` finds no matching profile
        // and returns NotFound -> 404, WITHOUT attempting any store build.
        let resp = app
            .oneshot(get_req("/api/vaults/nope/overview?t=t"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_vault_beats_malformed_id() {
        let app = router(test_state("t"));
        // Unknown vault AND malformed id: `get_note` resolves the vault first, so the
        // vault-not-found 404 wins over the id-parse 400. Locks the precedence the
        // handler implements (vault is the outer resource).
        let resp = app
            .oneshot(get_req("/api/vaults/nope/notes/not-a-valid-id?t=t"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn vault_build_failure_is_500() {
        // A config whose "broken" vault is present (so `store_for` finds the profile
        // and attempts a build) but INVALID (empty bucket/keys). `build_store` runs
        // `validate()` synchronously before any network I/O, so this exercises the
        // store_for -> build_store validate-fail -> VaultUnavailable -> 500 path with
        // no S3. "broken" is NOT pre-seeded, forcing the build.
        let mut stores = HashMap::new();
        stores.insert("test-team".to_owned(), test_store());
        let cfg = Config {
            team: "test-team".to_owned(),
            teams: vec![TeamProfile {
                name: "broken".to_owned(),
                ..TeamProfile::default()
            }],
            ..Config::default()
        };
        let state = DashboardState {
            cfg: Arc::new(cfg),
            token: Arc::from("t"),
            stores: Arc::new(tokio::sync::Mutex::new(stores)),
            current_vault: Some("test-team".to_owned()),
        };
        let app = router(state);

        let resp = app
            .oneshot(get_req("/api/vaults/broken/health?t=t"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
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

    // --- argument parsing + browser-launch decision (the auto-open feature) ---

    #[test]
    fn parse_args_defaults_to_ephemeral_port_and_auto_open() {
        let parsed = parse_args(&[]).unwrap();
        assert_eq!(parsed.port, 0);
        assert!(!parsed.no_open);
    }

    #[test]
    fn parse_args_reads_no_open_flag() {
        let parsed = parse_args(&["--no-open".to_owned()]).unwrap();
        assert!(parsed.no_open);
        assert_eq!(parsed.port, 0);
    }

    #[test]
    fn parse_args_accepts_port_and_no_open_in_either_order() {
        let a = parse_args(&[
            "--port".to_owned(),
            "8899".to_owned(),
            "--no-open".to_owned(),
        ])
        .unwrap();
        let b = parse_args(&[
            "--no-open".to_owned(),
            "--port".to_owned(),
            "8899".to_owned(),
        ])
        .unwrap();
        assert_eq!((a.port, a.no_open), (8899, true));
        assert_eq!((b.port, b.no_open), (8899, true));
    }

    #[test]
    fn parse_args_rejects_bad_port_and_unknown_flags() {
        assert!(parse_args(&["--port".to_owned()]).is_err(), "missing value");
        assert!(
            parse_args(&["--port".to_owned(), "notaport".to_owned()]).is_err(),
            "unparseable value"
        );
        assert!(parse_args(&["--no-opn".to_owned()]).is_err(), "typo'd flag");
    }

    #[test]
    fn browser_command_targets_the_platform_opener_with_url_last() {
        let url = "http://127.0.0.1:8899/?t=abc&x=1";
        let (program, args) = browser_command(url);
        // The URL must be the final argv element on every platform, and the empty
        // Windows title must never displace it.
        assert!(!program.is_empty());
        assert_eq!(args.last().map(String::as_str), Some(url));
        #[cfg(target_os = "macos")]
        assert_eq!(program, "open");
        #[cfg(target_os = "linux")]
        assert_eq!(program, "xdg-open");
    }

    #[test]
    fn ssh_session_is_headless_even_with_a_display() {
        let env = BrowserEnv {
            ssh_connection: Some("10.0.0.1 22 10.0.0.2 22".to_owned()),
            ssh_tty: None,
            display: Some(":0".to_owned()),
            wayland_display: None,
        };
        assert!(is_headless(&env), "SSH dominates the display heuristic");
    }

    #[test]
    fn empty_ssh_var_is_not_a_session() {
        // `std::env::var` yields `Ok("")` for a set-but-empty variable; an empty
        // SSH_CONNECTION/SSH_TTY must not read as a session. On Linux the present
        // display keeps it non-headless; on macOS/Windows the display is irrelevant —
        // both resolve to not-headless, so the assertion holds on every target.
        let env = BrowserEnv {
            ssh_connection: Some(String::new()),
            ssh_tty: Some(String::new()),
            display: Some(":0".to_owned()),
            wayland_display: None,
        };
        assert!(!is_headless(&env));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_without_any_display_is_headless() {
        let env = BrowserEnv {
            ssh_connection: None,
            ssh_tty: None,
            display: None,
            wayland_display: None,
        };
        assert!(is_headless(&env));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn desktop_without_display_var_is_not_headless() {
        let env = BrowserEnv {
            ssh_connection: None,
            ssh_tty: None,
            display: None,
            wayland_display: None,
        };
        assert!(!is_headless(&env), "macOS/Windows need no display var");
    }

    // --- global config path resolution (the "see all namespaces" fix) ---

    #[test]
    fn global_config_path_prefers_xdg_over_home() {
        let p = global_config_path(Some(OsStr::new("/xdg")), Some(OsStr::new("/home/u"))).unwrap();
        assert_eq!(p, PathBuf::from("/xdg/hippius-mem/hippius-mem.toml"));
    }

    #[test]
    fn global_config_path_falls_back_to_home_dot_config() {
        let p = global_config_path(None, Some(OsStr::new("/home/u"))).unwrap();
        assert_eq!(
            p,
            PathBuf::from("/home/u/.config/hippius-mem/hippius-mem.toml")
        );
    }

    #[test]
    fn global_config_path_treats_empty_as_unset() {
        // Mirrors the installer's `${XDG_CONFIG_HOME:-$HOME/.config}`: an empty XDG
        // value falls through to HOME, and empty-everywhere yields None so the caller
        // drops to the cwd-local default.
        let via_home =
            global_config_path(Some(OsStr::new("")), Some(OsStr::new("/home/u"))).unwrap();
        assert_eq!(
            via_home,
            PathBuf::from("/home/u/.config/hippius-mem/hippius-mem.toml")
        );
        assert!(global_config_path(Some(OsStr::new("")), Some(OsStr::new(""))).is_none());
        assert!(global_config_path(None, None).is_none());
    }
}
