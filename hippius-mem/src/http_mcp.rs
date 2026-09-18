//! Loopback streamable-HTTP MCP daemon (`hippius-mem serve`).
//!
//! Compiled only under `http-mcp`. N agent sessions share one process, one
//! ONNX embedder, and one op-log writer. The security boundary is loopback
//! bind + a standing bearer token (file next to the config, 0600) + rmcp's
//! Host allow-list. The dashboard is a different HTTP surface (browse UI);
//! this module is the MCP data plane.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use hippius_mem::server::MemoryServer;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::setup::mcp::{
    DEFAULT_HTTP_PORT, default_token_path, http_listen_url, load_or_create_token,
};

/// How long a `/health` probe may block before we treat the occupant as not us.
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Retries after `AddrInUse` so a dying previous job can release the port
/// before we take the exit-0 "already listening" shortcut.
const BIND_ATTEMPTS: u32 = 8;
const BIND_RETRY_PAUSE: Duration = Duration::from_millis(150);

/// Parsed `hippius-mem serve` arguments.
#[derive(Debug)]
struct ServeArgs {
    /// Loopback bind port. `0` asks the OS for an ephemeral port.
    port: u16,
    /// Bearer-token file. `None` means the sibling of the loaded config.
    token_file: Option<PathBuf>,
}

/// Bind loopback and serve streamable HTTP MCP over `server`.
///
/// Each HTTP session clones `server` (its `Arc<MemoryStore>` is the shared
/// ONNX / op-log). The caller's vault lock must stay alive for the listen
/// lifetime — this function does not hold it.
///
/// # Errors
///
/// Returns an error if arguments are unknown, the token cannot be loaded,
/// the loopback socket cannot be bound, or the HTTP server itself fails.
pub(crate) async fn listen(server: MemoryServer, args: &[String]) -> anyhow::Result<()> {
    let ServeArgs { port, token_file } = parse_args(args)?;
    let token_path = match token_file {
        Some(path) => path,
        None => default_token_path_from_env(),
    };
    let token = load_or_create_token(&token_path)?;

    let Some(listener) = bind_loopback(port).await? else {
        tracing::info!(
            url = %http_listen_url(port),
            "hippius-mem MCP already listening"
        );
        return Ok(());
    };
    let bound = listener
        .local_addr()
        .context("resolving the bound MCP address")?;
    if !is_loopback_addr(bound) {
        anyhow::bail!("MCP daemon refused to serve on non-loopback {bound}; bind 127.0.0.1 only");
    }

    let url = http_listen_url(bound.port());
    tracing::info!(%url, token_path = %token_path.display(), "hippius-mem MCP listening");

    let router = router(server, token, bound.port());
    axum::serve(listener, router)
        .await
        .context("MCP HTTP server error")?;
    Ok(())
}

fn default_token_path_from_env() -> PathBuf {
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

/// Bind `127.0.0.1:port`. `None` means a healthy peer already owns the port
/// (exit 0 so the user service `SuccessfulExit=false` does not crash-loop).
async fn bind_loopback(port: u16) -> anyhow::Result<Option<tokio::net::TcpListener>> {
    let mut last_err = None;
    for attempt in 1..=BIND_ATTEMPTS {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return Ok(Some(listener)),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse && port != 0 => {
                last_err = Some(err);
                if attempt == BIND_ATTEMPTS {
                    if peer_is_our_daemon(port).await {
                        return Ok(None);
                    }
                    break;
                }
                tokio::time::sleep(BIND_RETRY_PAUSE).await;
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to bind loopback MCP port {port}"));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrInUse, "loopback MCP port in use")
    }))
    .with_context(|| format!("failed to bind loopback MCP port {port}"))
}

/// True when something already bound to `port` answers our unauthenticated
/// `/health` with `ok` within [`HEALTH_PROBE_TIMEOUT`].
async fn peer_is_our_daemon(port: u16) -> bool {
    matches!(
        tokio::time::timeout(HEALTH_PROBE_TIMEOUT, probe_health(port)).await,
        Ok(true)
    )
}

async fn probe_health(port: u16) -> bool {
    let Ok(stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
        return false;
    };
    let mut stream = stream;
    let req =
        format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).contains("\r\n\r\nok")
}

fn router(server: MemoryServer, token: String, port: u16) -> Router {
    let mcp = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
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
    let mcp_router = Router::new()
        .nest_service("/mcp", mcp)
        .layer(from_fn_with_state(Arc::from(token), require_bearer));
    Router::new()
        .route("/health", get(health))
        .merge(mcp_router)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn require_bearer(State(token): State<Arc<str>>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match presented {
        Some(got) if tokens_equal(got, token.as_ref()) => next.run(request).await,
        _ => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
}

fn tokens_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut acc = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        acc |= a ^ b;
    }
    acc == 0
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

    use super::{health, parse_args, require_bearer, tokens_equal};
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
    fn tokens_equal_rejects_prefix_and_length_mismatch() {
        assert!(tokens_equal("abcd", "abcd"));
        assert!(!tokens_equal("abcd", "abce"));
        assert!(!tokens_equal("abcd", "abc"));
        assert!(!tokens_equal("abcd", "abcde"));
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
            !super::peer_is_our_daemon(port).await,
            "a listener that never answers /health must not count as our daemon"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the health probe must time out instead of hanging serve"
        );
    }
}
