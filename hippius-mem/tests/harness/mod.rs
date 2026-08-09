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

/// A signer whose author SS58 decodes back to its own signing key, mirroring
/// `server.rs`'s own `test_signer` fixture: every op the store mints must
/// pass the op-log identity binding, real store or not.
fn test_signer() -> Arc<dyn Signer> {
    Arc::new(
        Sr25519Signer::from_seed_with_prefix(&[5u8; 32], NetworkPrefix::HIPPIUS)
            .expect("valid test seed"),
    )
}

/// An in-memory, network-free [`MemoryStore`]: memory-backed blobs, a
/// lexical (hash) embedder, and a no-op anchor. Same fixture shape as
/// `server.rs`'s own `test_store()`, duplicated here because that helper is
/// private to `server.rs`'s unit test module and this crate cannot reach it.
fn test_store() -> Arc<MemoryStore> {
    let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let key = SecretKey::from_bytes([7u8; 32]);
    let oplog = OpLogStore::new(blob.clone());
    let signer = test_signer();

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
}

/// Build an already-warm [`MemoryServer`] over a fresh in-memory store, wire
/// it to a client over an in-memory duplex stream, and return the connected
/// session. Network-free and config-file-free: the transport is
/// `tokio::io::duplex` and the store is entirely in-process.
pub(crate) async fn in_memory_server() -> Result<McpSession, Box<dyn std::error::Error>> {
    let (server_transport, client_transport) = tokio::io::duplex(4096);

    // Already-warm: `with_warmup` normally blocks reads until a background
    // sync signals once, but a channel that already holds `true` satisfies
    // that wait immediately, so `recall`/`get` never block on it here.
    let (_warm_tx, warm_rx) = tokio::sync::watch::channel(true);
    let server = MemoryServer::with_warmup(test_store(), warm_rx);

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
    Ok(McpSession { client })
}

/// Call `tool_name` with `arguments` (a JSON object, or `null` for no
/// arguments) through the real MCP router and return the raw
/// [`CallToolResult`], or the transport/protocol-level error (e.g. an unknown
/// tool name, which rmcp surfaces as `METHOD_NOT_FOUND` rather than a result).
pub(crate) async fn call(
    session: &McpSession,
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<CallToolResult, Box<dyn std::error::Error>> {
    let arguments = match arguments {
        serde_json::Value::Object(map) => Some(map),
        serde_json::Value::Null => None,
        other => {
            return Err(
                format!("tool arguments must be a JSON object or null, got: {other}").into(),
            );
        }
    };

    // `CallToolRequestParams` is `#[non_exhaustive]`, so it cannot be built
    // with struct-literal syntax outside rmcp; `new` + the `with_*` builder
    // methods are the only construction path available here.
    let mut params = CallToolRequestParams::new(tool_name.to_owned());
    if let Some(arguments) = arguments {
        params = params.with_arguments(arguments);
    }

    Ok(session.client.call_tool(params).await?)
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
