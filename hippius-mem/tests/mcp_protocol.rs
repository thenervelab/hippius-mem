//! The MCP surface exercised through the REAL router, not the `logic_*`
//! functions the unit tests call.
//!
//! Every server unit test calls `logic_remember`/`logic_recall`/... directly,
//! so the generated `call_tool` dispatch, the schemars parameter schemas, and
//! the `CallToolResult` shape an agent actually receives were untested. An rmcp
//! upgrade that changed any of them would keep every other job green and break
//! every connected agent.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use serde_json::json;

mod harness;

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

#[tokio::test]
async fn an_unknown_tool_is_a_protocol_error_not_a_panic() -> Result<(), Box<dyn std::error::Error>>
{
    let server = harness::in_memory_server().await?;

    let result = harness::call(&server, "no_such_tool", json!({})).await;

    assert!(
        result.is_err() || result.is_ok_and(|r| r.is_error.unwrap_or(false)),
        "an unknown tool must surface as an error, never a panic or a success"
    );
    Ok(())
}

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
