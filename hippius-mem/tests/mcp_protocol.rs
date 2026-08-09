//! The MCP surface exercised through the REAL router, not the `logic_*`
//! functions the unit tests call.
//!
//! Every server unit test calls `logic_remember`/`logic_recall`/... directly,
//! so the generated `call_tool` dispatch, the schemars parameter schemas, and
//! the `CallToolResult` shape an agent actually receives were untested. An rmcp
//! upgrade that changed any of them would keep every other job green and break
//! every connected agent.
//!
//! `tools/call` coverage is deliberately narrow, not a survey of all ten
//! tools: a `remember`-then-`recall` happy-path round trip, `get`'s
//! handler-error path, and one made-up tool name. `refresh`/`forget`/
//! `redact`/`link`/`edit`/`history`/`reconcile` are NOT exercised here
//! through the `tools/call` router (their `logic_*` bodies are covered by
//! `server.rs`'s own unit tests, just not their `call_tool` dispatch
//! wrapper) — do not assume their router wiring is tested by this file.
//!
//! `tools/list` coverage is a full survey, not a sample: the committed
//! `tool_schemas.json` snapshot pins the advertised schema of all ten tools,
//! since a renamed field or a changed `required` list is a public-contract
//! break regardless of whether that tool's `call_tool` dispatch is exercised
//! above.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use rmcp::ServiceError;
use rmcp::model::ErrorCode;
use serde_json::json;

mod harness;

/// Mutation-verified: `hippius-mem/src/server.rs`'s `into_call_result`
/// mapping `Ok(value)` into `CallToolResult::success(..)` — and `remember`'s
/// underlying id generation — are both on this test's success path, so a
/// regression in either fails it. See the commit message for the exact
/// mutation and its failure.
#[tokio::test]
async fn remember_then_recall_through_call_tool() -> Result<(), Box<dyn std::error::Error>> {
    let server = harness::in_memory_server().await?;

    let stored = harness::call(
        &server,
        "remember",
        json!({
            "note_type": "decision",
            "summary": "prefer BTreeMap for deterministic snapshot ordering",
            "body": "ordering must not depend on hash seed",
        }),
    )
    .await?;
    assert!(
        !stored.is_error.unwrap_or(false),
        "remember must succeed: {stored:?}"
    );

    let found = harness::call(
        &server,
        "recall",
        json!({ "text": "deterministic ordering" }),
    )
    .await?;
    assert!(
        !found.is_error.unwrap_or(false),
        "recall must succeed: {found:?}"
    );

    let text = harness::result_text(&found);
    assert!(
        text.contains("BTreeMap"),
        "recall through the router must surface the stored note, got: {text}"
    );

    Ok(())
}

/// NOT mutation-verified against this repo's production code: "tool not
/// found" is raised entirely inside rmcp's own `ToolRouter::call`
/// (`rmcp-1.8.0/src/handler/server/router/tool.rs`), which hippius-mem does
/// not own — there is no line in this repo to mutate that this test's
/// assertion would catch. Confirmed instead that the assertion discriminates:
/// temporarily pointing this call at `"reconcile"` (a real tool) made the
/// test fail (`is_err()` was false and `is_ok_and(is_error)` was false too),
/// then reverted back to `"no_such_tool"`. See the commit message.
#[tokio::test]
async fn an_unknown_tool_is_a_protocol_error_not_a_panic() -> Result<(), Box<dyn std::error::Error>>
{
    let server = harness::in_memory_server().await?;

    let result = harness::call(&server, "no_such_tool", json!({})).await;

    // Not just "any Err": `harness::call` swallows the spawned server task's
    // outcome, so a panicked server would also close the transport and look
    // like an `Err` here. Pin the exact protocol-level shape instead — a
    // `ServiceError::McpError` with `INVALID_PARAMS` and "tool not found" —
    // so a dead-server transport error cannot pass as a healthy dispatch miss.
    assert!(
        matches!(&result, Err(ServiceError::McpError(_))),
        "an unknown tool must fail via ServiceError::McpError, got: {result:?}"
    );
    if let Err(ServiceError::McpError(error)) = &result {
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS, "got: {error:?}");
        assert!(
            error.message.contains("tool not found"),
            "expected a 'tool not found' protocol error, got: {error:?}"
        );
    }

    Ok(())
}

/// Mutation-verified: `hippius-mem/src/server.rs`'s `into_call_result`
/// mapping `Err(err)` into `CallToolResult::error(..)`. See the commit
/// message for the exact mutation and its failure.
#[tokio::test]
async fn a_handler_error_maps_to_is_error_not_a_transport_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let server = harness::in_memory_server().await?;

    // A malformed note id: the handler rejects it, and the agent must see a
    // tool-level error result rather than a dropped connection.
    let result = harness::call(&server, "get", json!({ "id": "not-a-ulid" })).await?;

    assert_eq!(
        result.is_error,
        Some(true),
        "a rejected argument must come back as is_error: true, got {result:?}"
    );
    Ok(())
}

/// The advertised tool schemas are a public contract: an agent validates its
/// arguments against them before ever calling us. schemars generates them from
/// the parameter structs, so a renamed field or a changed `required` list is a
/// silent breaking change that no `logic_*` test can see.
///
/// The snapshot is committed. Regenerate deliberately with
/// `UPDATE_TOOL_SCHEMAS=1 cargo test -p hippius-mem --test mcp_protocol`
/// and review the diff as an API change.
#[tokio::test]
async fn advertised_tool_schemas_match_the_committed_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let server = harness::in_memory_server().await?;
    let tools = harness::list_tools(&server).await?;

    // Sort by name so the snapshot does not depend on router iteration order.
    let mut rendered: Vec<serde_json::Value> = tools
        .into_iter()
        .map(|t| json!({ "name": t.name, "input_schema": t.input_schema }))
        .collect();
    rendered.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    let actual = serde_json::to_string_pretty(&rendered)? + "\n";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/snapshots/tool_schemas.json"
    );

    if std::env::var_os("UPDATE_TOOL_SCHEMAS").is_some() {
        std::fs::write(path, &actual)?;
        return Ok(());
    }

    let expected = std::fs::read_to_string(path)?;
    assert_eq!(
        actual, expected,
        "the advertised tool schemas changed. If deliberate, regenerate with \
         UPDATE_TOOL_SCHEMAS=1 and review the diff as a public API change."
    );
    Ok(())
}
