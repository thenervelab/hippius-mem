//! Loopback streamable-HTTP MCP daemon (`hippius-mem serve`).
//!
//! Compiled only under `http-mcp`. N agent sessions share one process, one
//! ONNX embedder, and one op-log writer. The security boundary is loopback
//! bind + a standing bearer token (file next to the config, 0600) on every
//! route but `/health` and `/token-proof`, plus rmcp's Host allow-list on `/mcp`. `/path-notes`
//! and `/call/{tool}` have the token alone: a web page cannot send the
//! `Authorization` header cross-origin without a preflight this server never
//! answers. The dashboard is a different HTTP surface (browse UI); this module
//! is the MCP data plane.
use std::future::IntoFuture as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use hippius_mem::server::{MemoryServer, PlainCallError};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::secret_token::constant_time_eq;
use crate::setup::mcp::{
    DEFAULT_HTTP_PORT, HEALTH_BODY, default_token_path, http_listen_url, load_or_create_token,
    response_proves_token, token_proof_request,
};

/// How long a token-proof probe may block before we treat the occupant as not us.
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Retries after `AddrInUse` so a dying previous job can release the port
/// before we take the exit-0 "already listening" shortcut.
const BIND_ATTEMPTS: u32 = 8;
const BIND_RETRY_PAUSE: Duration = Duration::from_millis(150);
/// Idle window before rmcp evicts a session. rmcp defaults to 5 minutes, which
/// an agent window left alone over a coffee exceeds: the next tool call then
/// carries a dead `Mcp-Session-Id` and 404s. A day still reaps the zombies a
/// vanished client leaves behind, which `None` would keep forever.
const SESSION_IDLE_KEEP_ALIVE: Duration = Duration::from_hours(24);

/// Parsed `hippius-mem serve` arguments.
#[derive(Debug)]
struct ServeArgs {
    /// Loopback bind port. `0` asks the OS for an ephemeral port.
    port: u16,
    /// Bearer-token file. `None` means the sibling of the loaded config.
    token_file: Option<PathBuf>,
}

/// A bound loopback listener plus the token it will require.
///
/// Produced by [`bind`] BEFORE the store boots, so a second `serve`, a typo'd
/// flag, or a foreign occupant of the port fails in milliseconds instead of
/// after an ONNX load, a vault-lock contest, and an op-log sync.
pub(crate) struct BoundListener {
    listener: tokio::net::TcpListener,
    token: String,
    port: u16,
}

/// Parse `serve` arguments, load the bearer token, and bind loopback.
///
/// `Ok(None)` means a daemon holding this token already owns the port: the
/// caller exits 0 so the user service (`SuccessfulExit=false`) does not
/// crash-loop.
///
/// # Errors
///
/// Returns an error if arguments are unknown, the token cannot be loaded, or
/// the loopback socket cannot be bound, including when the process holding the
/// port does not prove it holds this token (another user's daemon on a shared
/// host, an older `serve`, or another program).
pub(crate) async fn bind(args: &[String]) -> anyhow::Result<Option<BoundListener>> {
    let ServeArgs { port, token_file } = parse_args(args)?;
    let token_path = match token_file {
        Some(path) => path,
        None => default_token_path_from_env(),
    };
    let token = load_or_create_token(&token_path)?;

    let Some(listener) = bind_loopback(port, &token).await? else {
        tracing::info!(
            url = %http_listen_url(port),
            "hippius-mem MCP already listening"
        );
        return Ok(None);
    };
    let bound = listener
        .local_addr()
        .context("resolving the bound MCP address")?;
    if !is_loopback_addr(bound) {
        anyhow::bail!("MCP daemon refused to serve on non-loopback {bound}; bind 127.0.0.1 only");
    }

    let url = http_listen_url(bound.port());
    tracing::info!(%url, token_path = %token_path.display(), "hippius-mem MCP bound");

    Ok(Some(BoundListener {
        listener,
        token,
        port: bound.port(),
    }))
}

/// Serve streamable HTTP MCP over `server` on an already-bound listener.
///
/// Each HTTP session clones `server` (its `Arc<MemoryStore>` is the shared
/// ONNX / op-log). The caller's vault lock must stay alive for the listen
/// lifetime — this function does not hold it.
///
/// Returns once `shutdown` resolves and the open connections have finished.
///
/// # Errors
///
/// Returns an error if the HTTP server itself fails.
pub(crate) async fn serve(
    bound: BoundListener,
    server: MemoryServer,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let BoundListener {
        listener,
        token,
        port,
    } = bound;

    let router = router(server, token, port);
    let (drain, drained) = tokio::sync::oneshot::channel::<()>();
    let serving = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = drained.await;
        })
        .into_future();
    tokio::pin!(serving);
    tokio::select! {
        finished = &mut serving => return finished.context("MCP HTTP server error"),
        () = shutdown => {}
    }
    let _ = drain.send(());
    // A long-lived SSE stream would hold the graceful drain open past the
    // supervisor's patience, and its SIGKILL would skip the caller's exit work
    // (anchoring the last ops). So the drain is bounded.
    if let Ok(drained) = tokio::time::timeout(SHUTDOWN_DRAIN, serving).await {
        return drained.context("MCP HTTP server error");
    }
    tracing::warn!("open MCP connections did not close within the shutdown window");
    Ok(())
}

/// How long `serve` waits for open connections after a shutdown signal.
/// Arbitrary, well under systemd's default 90 s stop timeout.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(10);

/// The bearer-token file `serve` uses when `--token-file` is not given: the
/// sibling of the config it loads. `path-notes` reads the same file.
pub(crate) fn default_token_path_from_env() -> PathBuf {
    let config = std::env::var_os("HIPPIUS_MEM_CONFIG")
        .map(PathBuf::from)
        .or_else(crate::setup::mcp::resolved_global_config_path)
        .unwrap_or_else(|| PathBuf::from("hippius-mem.toml"));
    default_token_path(&config)
}

fn parse_args(args: &[String]) -> anyhow::Result<ServeArgs> {
    let mut port = DEFAULT_HTTP_PORT;
    let mut token_file = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                let Some(value) = args.get(i + 1) else {
                    anyhow::bail!("--port requires a value");
                };
                port = value
                    .parse::<u16>()
                    .with_context(|| format!("invalid --port value `{value}`"))?;
                i += 2;
            }
            "--token-file" => {
                let Some(value) = args.get(i + 1) else {
                    anyhow::bail!("--token-file requires a path");
                };
                token_file = Some(PathBuf::from(value));
                i += 2;
            }
            other => anyhow::bail!(
                "unknown serve argument `{other}`; usage: serve [--port <n>] [--token-file <path>]"
            ),
        }
    }
    Ok(ServeArgs { port, token_file })
}

fn is_loopback_addr(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Bind `127.0.0.1:port`. `None` means a peer holding `token` already owns the
/// port (exit 0 so the user service `SuccessfulExit=false` does not
/// crash-loop). Any other occupant is an error: exiting 0 there would leave
/// this user's clients sending their token and tool calls to it, and stop the
/// service from retrying the port.
async fn bind_loopback(port: u16, token: &str) -> anyhow::Result<Option<tokio::net::TcpListener>> {
    let mut attempt = 1;
    loop {
        let err = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return Ok(Some(listener)),
            Err(err) => err,
        };
        if err.kind() != std::io::ErrorKind::AddrInUse || port == 0 {
            return Err(err).with_context(|| format!("failed to bind loopback MCP port {port}"));
        }
        if attempt < BIND_ATTEMPTS {
            attempt += 1;
            tokio::time::sleep(BIND_RETRY_PAUSE).await;
            continue;
        }
        if peer_holds_token(port, token).await {
            return Ok(None);
        }
        return Err(err).with_context(|| {
            format!(
                "loopback MCP port {port} is held by a process that does not prove it holds \
                 this user's token (another user's hippius-mem serve, an older one, or another \
                 program); stop it, or keep this user's clients on stdio"
            )
        });
    }
}

/// True when something already bound to `port` answers a fresh
/// `/token-proof` challenge with the proof of `token` within
/// [`HEALTH_PROBE_TIMEOUT`].
///
/// `/health` is not enough: every user's daemon on a shared host answers it
/// alike, and an unrelated service can copy it.
async fn peer_holds_token(port: u16, token: &str) -> bool {
    matches!(
        tokio::time::timeout(HEALTH_PROBE_TIMEOUT, probe_token(port, token)).await,
        Ok(true)
    )
}

async fn probe_token(port: u16, token: &str) -> bool {
    let Ok(mut stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
        return false;
    };
    let nonce = hippius_mem_core::Ulid::new().to_string();
    let request = token_proof_request(port, &nonce);
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    response_proves_token(&buf, token, &nonce)
}

fn router(server: MemoryServer, token: String, port: u16) -> Router {
    let plain_server = server.clone();
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(session_manager()),
        StreamableHttpServerConfig::default()
            .with_allowed_hosts([
                "127.0.0.1".to_owned(),
                "localhost".to_owned(),
                "::1".to_owned(),
                format!("127.0.0.1:{port}"),
                format!("localhost:{port}"),
                format!("[::1]:{port}"),
            ])
            // Keep-alive pings would hold the POST SSE stream open; clients
            // that read to EOF (and our tests) would hang. Grok reconnects
            // via GET + Last-Event-ID when it needs a long-lived stream.
            .with_sse_keep_alive(None),
    );
    let token: Arc<str> = Arc::from(token);
    let proof_token = Arc::clone(&token);
    let mcp_router = Router::new()
        .route("/path-notes", get(path_notes))
        .route("/call/{tool}", post(call_tool))
        .with_state(plain_server)
        .nest_service("/mcp", mcp)
        .layer(from_fn_with_state(token, require_bearer));
    Router::new()
        .route("/health", get(health))
        // Unauthenticated: it answers with a proof of the token, never the
        // token, so `install` can tell this user's daemon from another's.
        .route(
            "/token-proof",
            get(move |Query(query): Query<TokenProofQuery>| {
                let token = Arc::clone(&proof_token);
                async move { hippius_mem_core::token_proof(&token, &query.nonce) }
            }),
        )
        .merge(mcp_router)
}

fn session_manager() -> LocalSessionManager {
    let mut manager = LocalSessionManager::default();
    manager.session_config.keep_alive = Some(SESSION_IDLE_KEEP_ALIVE);
    manager
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, HEALTH_BODY)
}

/// Query of `GET /token-proof`: the challenge the caller picked.
#[derive(Debug, serde::Deserialize)]
struct TokenProofQuery {
    nonce: String,
}

/// Query of `GET /path-notes`.
#[derive(Debug, serde::Deserialize)]
struct PathNotesQuery {
    /// Bare repository name, as notes are scoped.
    repo: String,
    /// File path relative to the repository root.
    path: String,
}

/// The notes tied to one file, for `hippius-mem path-notes` (an edit hook).
/// Behind the same bearer token as `/mcp`: summaries are team data.
async fn path_notes(
    State(server): State<MemoryServer>,
    Query(query): Query<PathNotesQuery>,
) -> Response {
    match server.path_notes(&query.repo, &query.path) {
        Ok(Some(notes)) => Json(notes).into_response(),
        // Still syncing: an empty answer here would tell the hook this file
        // has no notes for the whole session.
        Ok(None) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(err) => {
            tracing::warn!(%err, "path-notes lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Run one memory tool outside an MCP session, for `hippius-mem call`. The
/// body is the tool's JSON arguments.
///
/// `200` with the tool's JSON result, `404` for an unknown tool, and `422`
/// with the tool's own message when the arguments or the tool fail.
async fn call_tool(
    State(server): State<MemoryServer>,
    Path(tool): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let arguments = match serde_json::from_slice(&body) {
        Ok(arguments) => arguments,
        Err(err) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("invalid JSON: {err}"),
            )
                .into_response();
        }
    };
    // The tool runs in its own task, not in this handler's future. hyper drops
    // the handler when the client disconnects (Ctrl-C, or the command's read
    // timeout), and a write dropped between its op PUT and its bookkeeping
    // forks the author's chain: the store's append must never run in a future
    // that can be cancelled (see `MemoryStore::mint_and_append`). rmcp spawns
    // its tool calls for `/mcp`; this route has to do the same itself.
    let name = tool.clone();
    let call = tokio::spawn(async move { server.call_plain(&name, arguments).await });
    match call.await {
        Ok(Ok(result)) => Json(result).into_response(),
        Ok(Err(PlainCallError::UnknownTool)) => {
            (StatusCode::NOT_FOUND, format!("unknown tool `{tool}`")).into_response()
        }
        Ok(Err(PlainCallError::Failed(message))) => {
            (StatusCode::UNPROCESSABLE_ENTITY, message).into_response()
        }
        Err(err) => {
            tracing::error!(%err, %tool, "a tool call panicked or was aborted");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn require_bearer(State(token): State<Arc<str>>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match presented {
        Some(got) if constant_time_eq(got, token.as_ref()) => next.run(request).await,
        _ => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests assert on fixtures where construction cannot fail"
    )]

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse as _;
    use tower::ServiceExt;

    use super::{SESSION_IDLE_KEEP_ALIVE, health, parse_args, require_bearer, session_manager};
    use crate::setup::mcp::DEFAULT_HTTP_PORT;

    #[test]
    fn parse_args_defaults_and_rejects_unknown() {
        let empty = parse_args(&[]).expect("empty");
        assert_eq!(empty.port, DEFAULT_HTTP_PORT);
        assert!(empty.token_file.is_none());

        let args = [
            "--port".into(),
            "0".into(),
            "--token-file".into(),
            "/t".into(),
        ];
        let parsed = parse_args(&args).expect("flags");
        assert_eq!(parsed.port, 0);
        assert_eq!(
            parsed.token_file.as_deref(),
            Some(std::path::Path::new("/t"))
        );

        let err = parse_args(&["--nope".into()]).expect_err("unknown");
        assert!(format!("{err:#}").contains("unknown serve argument"));
    }

    #[test]
    fn sessions_outlive_rmcps_five_minute_idle_default() {
        let keep_alive = session_manager().session_config.keep_alive;

        assert_eq!(keep_alive, Some(SESSION_IDLE_KEEP_ALIVE));
        assert!(
            SESSION_IDLE_KEEP_ALIVE > std::time::Duration::from_hours(1),
            "an agent window idle over lunch must keep its MCP session"
        );
    }

    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use hippius_mem::server::MemoryServer;
    use hippius_mem_core::{
        BlobStore, HashEmbedder, InMemoryIndex, MemError, MemoryBlobStore, MemoryStore,
        NetworkPrefix, NoopAnchor, OpLogStore, SecretKey, Signer, Sr25519Signer,
    };

    fn store_over(blob: Arc<dyn BlobStore>) -> Arc<MemoryStore> {
        let signer: Arc<dyn Signer> = Arc::new(
            Sr25519Signer::from_seed_with_prefix(&[3_u8; 32], NetworkPrefix::HIPPIUS).unwrap(),
        );
        Arc::new(MemoryStore::new(
            Arc::clone(&blob),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(blob),
            Arc::new(NoopAnchor),
            signer,
            BTreeMap::from([(0_u64, SecretKey::from_bytes([7_u8; 32]))]),
            0,
            "team".to_owned(),
            usize::MAX,
        ))
    }

    /// A warm server over `blob`, behind the bearer token `secret`.
    fn warm_app(blob: Arc<dyn BlobStore>) -> (axum::Router, MemoryServer) {
        let (_warm_tx, warm_rx) = tokio::sync::watch::channel(true);
        let server = MemoryServer::with_warmup(store_over(blob), warm_rx);
        (
            super::router(server.clone(), "secret".to_owned(), 0),
            server,
        )
    }

    fn remember_request(token: Option<&str>) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri("/call/remember")
            .header("Content-Type", "application/json");
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        request
            .body(Body::from(
                r#"{"note_type":"gotcha","summary":"quokka gate note","body":"b"}"#,
            ))
            .unwrap()
    }

    async fn recalled(server: &MemoryServer) -> u64 {
        let found = server
            .call_plain("recall", serde_json::json!({ "text": "quokka gate" }))
            .await
            .unwrap();
        found["returned"].as_u64().unwrap()
    }

    /// While the first sync runs the index is empty, and `/path-notes` must
    /// say so (503), not answer an empty list: the edit hook remembers "no
    /// notes" for the whole session. Once warm, the same request is a 200.
    #[tokio::test]
    async fn path_notes_answers_503_until_the_first_sync_ends() {
        let (warm_tx, warm_rx) = tokio::sync::watch::channel(false);
        let store = store_over(Arc::new(MemoryBlobStore::default()));
        let app = super::router(
            MemoryServer::with_warmup(store, warm_rx),
            "secret".to_owned(),
            0,
        );
        let ask = || {
            Request::builder()
                .uri("/path-notes?repo=widget&path=src%2Flib.rs")
                .header("Authorization", "Bearer secret")
                .body(Body::empty())
                .unwrap()
        };

        let warming = app.clone().oneshot(ask()).await.unwrap();
        assert_eq!(warming.status(), StatusCode::SERVICE_UNAVAILABLE);

        warm_tx.send(true).unwrap();
        let warm = app.oneshot(ask()).await.unwrap();
        assert_eq!(warm.status(), StatusCode::OK);
    }

    /// `/call/{tool}` can run every tool, `forget` and `redact` included, so it
    /// must sit behind the bearer token. Catches the route being mounted
    /// outside the layer: without or with a wrong token nothing is written.
    #[tokio::test]
    async fn the_call_route_requires_the_bearer_token() {
        let (app, server) = warm_app(Arc::new(MemoryBlobStore::default()));
        for token in [None, Some("wrong")] {
            let response = app.clone().oneshot(remember_request(token)).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{token:?}");
        }
        assert_eq!(
            recalled(&server).await,
            0,
            "an unauthenticated call wrote a note"
        );

        let ok = app.oneshot(remember_request(Some("secret"))).await.unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(recalled(&server).await, 1);
    }

    /// A blob store whose `put` waits until the test opens the gate.
    struct GatedBlob {
        inner: MemoryBlobStore,
        entered: tokio::sync::Notify,
        gate: tokio::sync::Semaphore,
    }

    #[async_trait::async_trait]
    impl BlobStore for GatedBlob {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.entered.notify_one();
            let _permit = self.gate.acquire().await;
            self.inner.put(key, bytes).await
        }
        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }
        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// A client that disconnects mid-call does not cancel the write. hyper
    /// drops the handler future then, and a store append dropped half way
    /// forks the author's op chain. The request is aborted while its first
    /// `put` is parked; the write must still finish once the gate opens.
    #[tokio::test]
    async fn a_disconnected_client_does_not_cancel_the_write() {
        let blob = Arc::new(GatedBlob {
            inner: MemoryBlobStore::default(),
            entered: tokio::sync::Notify::new(),
            gate: tokio::sync::Semaphore::new(0),
        });
        let (app, server) = warm_app(Arc::<GatedBlob>::clone(&blob));

        let request = tokio::spawn(app.oneshot(remember_request(Some("secret"))));
        blob.entered.notified().await;
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());

        blob.gate.add_permits(1_000);
        let written = async {
            while recalled(&server).await == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), written)
            .await
            .expect("the write was cancelled with its client");
    }

    #[tokio::test]
    async fn health_is_unauthenticated() {
        let response = health().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_middleware_rejects_missing_and_wrong_tokens() {
        use axum::middleware::from_fn_with_state;
        use axum::routing::get;
        use std::sync::Arc;

        let app = axum::Router::new()
            .route("/mcp", get(|| async { "ok" }))
            .layer(from_fn_with_state(Arc::from("secret"), require_bearer));

        let missing = app
            .clone()
            .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let wrong = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header("Authorization", "Bearer other")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let ok = app
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header("Authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn peer_probe_times_out_on_a_silent_listener() {
        use std::time::Instant;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(stream);
        });
        let started = Instant::now();
        assert!(
            !super::peer_holds_token(port, "mine").await,
            "a listener that never answers must not count as our daemon"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the token probe must time out instead of hanging serve"
        );
    }
}
