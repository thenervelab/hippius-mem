//! Shared harness for driving [`MemoryServer`] through the REAL MCP router.
//!
//! Every `server.rs` unit test calls the transport-free `logic_*` methods
//! directly, so the macro-generated `call_tool` dispatch, the schemars
//! parameter schemas, and the exact `CallToolResult` shape an agent receives
//! were never exercised. This harness drives a real client<->server pair
//! over an in-memory duplex byte stream (`tokio::io::duplex`) instead: the
//! same pattern rmcp's own test suite uses to test `ServerHandler::call_tool`
//! (see `rmcp-1.8.0/tests/test_tool_macros.rs::test_minimal_server_tool_call`).
//!
//! `ServerHandler::call_tool` cannot be called directly here: it needs a
//! `RequestContext<RoleServer>`, whose `peer: Peer<RoleServer>` field only has
//! a `pub(crate)`-to-rmcp constructor (`Peer::new` in `rmcp::service`), so an
//! external integration test cannot build one by hand. Driving the CLIENT
//! side's `call_tool` instead exercises the full path anyway: JSON-RPC
//! framing over the duplex stream, the `#[tool_router]`/`#[tool_handler]`
//! macro-generated dispatch, tool lookup by name, parameter deserialization
//! against the schemars schema, and `into_call_result`'s mapping back into
//! `CallToolResult` — a superset of "just call the dispatch function".

#![expect(
    clippy::expect_used,
    reason = "test fixture construction over fixed, known-valid inputs cannot fail"
)]

use std::sync::Arc;

use hippius_mem::server::MemoryServer;
use hippius_mem_core::{
    BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, NetworkPrefix,
    NoopAnchor, OpLogStore, SecretKey, Signer, Sr25519Signer,
};
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientInfo};
use rmcp::service::RunningService;
use rmcp::{ClientHandler, RoleClient, ServiceExt};

/// Anchor threshold high enough that these tests never anchor a batch;
/// anchoring is unrelated to what this harness exercises.
const ANCHOR_THRESHOLD: usize = 16;

/// An in-memory, network-free [`MemoryStore`] over `blob`, signing as `seed`.
/// Same fixture shape as `server.rs`'s own `test_store()`, duplicated here
/// because that helper is private to `server.rs`'s unit test module.
pub(crate) fn store_over(blob: Arc<dyn BlobStore>, seed: [u8; 32]) -> Arc<MemoryStore> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let key = SecretKey::from_bytes([7u8; 32]);
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(
        Sr25519Signer::from_seed_with_prefix(&seed, NetworkPrefix::HIPPIUS)
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

fn test_store() -> Arc<MemoryStore> {
    store_over(Arc::new(MemoryBlobStore::default()), [5u8; 32])
}

/// A client handler with no capabilities of its own: it only issues
/// `tools/call` requests and never needs to answer a server-initiated
/// request (sampling, roots, elicitation), so the default `ClientHandler`
/// methods (each `method_not_found`) are exactly right.
#[derive(Debug, Clone, Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::default()
    }
}

/// A live client<->server pair, connected over an in-memory duplex byte
/// stream and already past the MCP `initialize` handshake (`ServiceExt::serve`
/// performs it for both sides). [`call`] drives `tools/call` through this pair.
///
/// `pub(crate)`, not `pub`: `mod harness;` in `mcp_protocol.rs` is a private
/// module of that integration test's own crate, so nothing here is reachable
/// beyond it regardless of visibility; `pub(crate)` says so honestly.
pub(crate) struct McpSession {
    client: RunningService<RoleClient, TestClient>,
    // Kept alive for the session's lifetime, never sent on: dropping this
    // sender would close the `warm` channel the server holds a receiver on,
    // which would silently swap the intended "already warm" path for
    // `await_warm`'s error-fallback path (see `in_memory_server`'s comment).
    _warm_tx: tokio::sync::watch::Sender<bool>,
}

/// Build an already-warm [`MemoryServer`] over a fresh in-memory store, wire
/// it to a client over an in-memory duplex stream, and return the connected
/// session. Network-free and config-file-free: the transport is
/// `tokio::io::duplex` and the store is entirely in-process.
/// Already-warm server over `store`. `default_repo` is the omitted-`repo`
/// fallback [`MemoryServer::with_default_repo`] binds; `None` keeps today's
/// Global-only default.
pub(crate) async fn session_over(
    store: Arc<MemoryStore>,
    default_repo: Option<String>,
) -> Result<McpSession, Box<dyn std::error::Error>> {
    // Already-warm: `with_warmup` normally blocks reads until a background
    // sync signals once, but a channel that already holds `true` satisfies
    // that wait immediately, so `recall`/`get` never block on it here. The
    // sender MUST outlive the server: `watch::Receiver::wait_for` checks the
    // current value before observing a closed channel, so a dropped sender
    // happens to still return `true` on the very first read here, but every
    // read after that would instead go through `await_warm`'s degraded
    // error-fallback path (server.rs's `await_warm`) instead of the
    // already-warm path this harness claims to exercise. Returned inside
    // `McpSession` so it lives exactly as long as the session does.
    let (warm_tx, warm_rx) = tokio::sync::watch::channel(true);
    let mut server = MemoryServer::with_warmup(store, warm_rx);
    if let Some(repo) = default_repo {
        server = server.with_default_repo(repo);
    }
    connect(server, warm_tx).await
}

/// Like [`session_over`], but the server is marked READ-ONLY over a local
/// trial vault named `profile` — the shape `main.rs::acquire_serve_vault_lock`
/// produces for a second concurrent session that lost the vault's write role.
/// The write tools must refuse in-band through the real router; reads work.
pub(crate) async fn read_only_session_over(
    store: Arc<MemoryStore>,
    profile: &str,
) -> Result<McpSession, Box<dyn std::error::Error>> {
    // Same already-warm channel discipline as `session_over` (see its
    // comment for why the sender must outlive the server).
    let (warm_tx, warm_rx) = tokio::sync::watch::channel(true);
    let server = MemoryServer::with_warmup(store, warm_rx).with_read_only_vault(profile.to_owned());
    connect(server, warm_tx).await
}

/// Wire `server` to a fresh client over an in-memory duplex stream and run
/// the MCP `initialize` handshake — the shared tail of both session
/// constructors above, split out so the read-only variant cannot drift from
/// the writable one's transport wiring.
async fn connect(
    server: MemoryServer,
    warm_tx: tokio::sync::watch::Sender<bool>,
) -> Result<McpSession, Box<dyn std::error::Error>> {
    let (server_transport, client_transport) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        // The router under test: `serve` answers every request the client
        // below sends through the macro-generated `call_tool` dispatch.
        // `serve` itself only completes the `initialize` handshake and
        // returns a handle; dropping that handle immediately (as a bare
        // `.await` here would) cancels the connection right after the
        // handshake, so `waiting()` is required to keep serving until the
        // client disconnects.
        if let Ok(running) = server.serve(server_transport).await {
            let _ = running.waiting().await;
        }
    });

    let client = TestClient.serve(client_transport).await?;
    Ok(McpSession {
        client,
        _warm_tx: warm_tx,
    })
}

pub(crate) async fn in_memory_server() -> Result<McpSession, Box<dyn std::error::Error>> {
    session_over(test_store(), None).await
}

/// Call `tool_name` with `arguments` (a JSON object, or `null` for no
/// arguments) through the real MCP router and return the raw
/// [`CallToolResult`], or the concrete [`rmcp::ServiceError`] the client sees
/// (e.g. an unknown tool name, which rmcp's `ToolRouter::call` surfaces as
/// `ServiceError::McpError` with `ErrorCode::INVALID_PARAMS` and message
/// `"tool not found"` — a protocol-level error, not a result). Returning the
/// concrete error type, rather than boxing it away, is what lets a caller
/// assert on that exact shape instead of only "some error happened".
pub(crate) async fn call(
    session: &McpSession,
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<CallToolResult, rmcp::ServiceError> {
    // `CallToolRequestParams` is `#[non_exhaustive]`, so it cannot be built
    // with struct-literal syntax outside rmcp; `new` + the `with_*` builder
    // methods are the only construction path available here.
    let mut params = CallToolRequestParams::new(tool_name.to_owned());
    if !arguments.is_null() {
        let arguments = arguments
            .as_object()
            .cloned()
            .expect("harness misuse: tool arguments must be a JSON object or null");
        params = params.with_arguments(arguments);
    }

    session.client.call_tool(params).await
}

/// List every tool the server advertises, through the real MCP router.
///
/// Drives `tools/call`'s sibling request, `tools/list`, over the CLIENT
/// peer's `list_all_tools` (a thin pagination-following wrapper around
/// `Peer<RoleClient>::list_tools`) — the same "go through the client, not an
/// internal accessor" pattern [`call`] uses for `tools/call`. This is what
/// makes a schema-drift test here catch what an agent actually sees, rather
/// than an internal representation the wire format never exposes.
pub(crate) async fn list_tools(
    session: &McpSession,
) -> Result<Vec<rmcp::model::Tool>, rmcp::ServiceError> {
    session.client.list_all_tools().await
}

/// Concatenate every text content block of a [`CallToolResult`] into one
/// string, for substring assertions against what an agent would actually see.
pub(crate) fn result_text(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|content| content.raw.as_text())
        .map(|text| text.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}
