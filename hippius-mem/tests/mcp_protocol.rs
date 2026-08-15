//! The MCP surface exercised through the REAL router, not the `logic_*`
//! functions the unit tests call.
//!
//! Every server unit test calls `logic_remember`/`logic_recall`/... directly,
//! so the generated `call_tool` dispatch, the schemars parameter schemas, and
//! the `CallToolResult` shape an agent actually receives were untested. An rmcp
//! upgrade that changed any of them would keep every other job green and break
//! every connected agent.
//!
//! `tools/call` coverage is the agent loop plus the two error shapes, not a
//! survey of all ten tools: `remember` → `get` → `recall` (target over a
//! distractor) → `edit` → `recall` (new summary) → `forget` → `recall`
//! (gone); `get`'s handler-error path; and one made-up tool name.
//! `refresh`/`redact`/`link`/`history`/`reconcile` are NOT exercised here
//! through the `tools/call` router (their `logic_*` bodies are covered by
//! `server.rs`'s own unit tests, just not their `call_tool` dispatch
//! wrapper) — do not assume their router wiring is tested by this file.
//!
//! `tools/list` coverage is a full survey, not a sample: the committed
//! `tool_schemas.json` snapshot pins the advertised name, description, and
//! schema of all ten tools, since a renamed field, a changed `required`
//! list, or a softened description is a public-contract break regardless of
//! whether that tool's `call_tool` dispatch is exercised above.

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

/// Pull the `mem_...` id out of a `remember` `CallToolResult`.
///
/// `into_call_result` serializes `RememberOutput` as a JSON text block
/// `{"id":"mem_..."}`. Parsing that object — rather than grepping a
/// `mem_` substring out of mixed prose — fails if the wire shape changes.
fn extract_mem_id(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or("remember result has no id field")?;
    if !id.starts_with("mem_") {
        return Err(format!("remember id must start with mem_, got {id}").into());
    }
    Ok(id.to_owned())
}

/// The loop an agent actually runs, through `call_tool`, not `logic_*`.
///
/// `remember_then_recall_through_call_tool` only checks that the recall text
/// contains `BTreeMap`. It never hydrates the body, never stores a
/// distractor, never edits, never forgets. Those paths have `logic_*` tests;
/// their router wrappers did not.
#[tokio::test]
async fn remember_get_recall_edit_forget_through_call_tool()
-> Result<(), Box<dyn std::error::Error>> {
    let server = harness::in_memory_server().await?;

    let stored = harness::call(
        &server,
        "remember",
        json!({
            "note_type": "gotcha",
            "repo": "thebrain",
            "tags": ["pool"],
            "summary": "release pooled database handles on clean shutdown",
            "body": "drain and close every pooled connection before exit",
        }),
    )
    .await?;
    assert!(!stored.is_error.unwrap_or(false), "remember: {stored:?}");
    let mem_id = extract_mem_id(&harness::result_text(&stored))?;

    let distractor = harness::call(
        &server,
        "remember",
        json!({
            "note_type": "context",
            "repo": "thebrain",
            "summary": "espresso machine descaling schedule",
            "body": "descale monthly",
        }),
    )
    .await?;
    assert!(
        !distractor.is_error.unwrap_or(false),
        "distractor remember: {distractor:?}"
    );

    let got = harness::call(&server, "get", json!({ "id": mem_id })).await?;
    assert!(!got.is_error.unwrap_or(false), "get: {got:?}");
    let got_text = harness::result_text(&got);
    assert!(
        got_text.contains("drain and close every pooled connection"),
        "get through the router must return the stored body, got {got_text}"
    );
    assert!(
        got_text.contains("gotcha"),
        "note_type must round-trip, got {got_text}"
    );

    let found = harness::call(
        &server,
        "recall",
        json!({ "text": "pooled database connections", "repo": "thebrain" }),
    )
    .await?;
    let found_text = harness::result_text(&found);
    assert!(
        found_text.contains("release pooled database handles"),
        "recall must surface the target summary, got {found_text}"
    );
    assert!(
        !found_text.contains("espresso"),
        "recall must not dump the distractor, got {found_text}"
    );

    let edited = harness::call(
        &server,
        "edit",
        json!({
            "id": mem_id,
            "summary": "close the sql pool on process exit",
            "body": "rewritten body",
        }),
    )
    .await?;
    assert!(!edited.is_error.unwrap_or(false), "edit: {edited:?}");

    let after_edit = harness::call(
        &server,
        "recall",
        json!({ "text": "sql pool process exit", "repo": "thebrain" }),
    )
    .await?;
    assert!(
        harness::result_text(&after_edit).contains("close the sql pool"),
        "recall after edit must surface the new summary"
    );

    let forgotten = harness::call(&server, "forget", json!({ "id": mem_id })).await?;
    assert!(
        !forgotten.is_error.unwrap_or(false),
        "forget: {forgotten:?}"
    );

    let after_forget = harness::call(
        &server,
        "recall",
        json!({ "text": "sql pool process exit", "repo": "thebrain" }),
    )
    .await?;
    assert!(
        !harness::result_text(&after_forget).contains("close the sql pool"),
        "a forgotten note must not recall"
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

/// Format a short, reviewable summary of the first line where `actual` and
/// `expected` diverge, with a couple of lines of surrounding context.
///
/// The snapshot is one JSON document rendered as a single `to_string_pretty`
/// call, so `assert_eq!`'s default diff — the whole ~9 KB value, twice, each
/// on its own escaped single line — is unreadable exactly when it matters
/// most. This is what the test reports instead.
fn first_diff_context(actual: &str, expected: &str) -> String {
    use std::fmt::Write as _;

    let actual_lines: Vec<&str> = actual.lines().collect();
    let expected_lines: Vec<&str> = expected.lines().collect();

    let first_mismatch = actual_lines
        .iter()
        .zip(expected_lines.iter())
        .position(|(a, e)| a != e);

    let Some(line_no) = first_mismatch else {
        return format!(
            "line counts differ: actual has {} lines, expected has {} lines \
             (one output is a strict prefix of the other)",
            actual_lines.len(),
            expected_lines.len(),
        );
    };

    let context_start = line_no.saturating_sub(2);
    let context_end = (line_no + 3)
        .min(actual_lines.len())
        .min(expected_lines.len());

    let mut context = format!("first differing line {line_no} (0-indexed):\n");
    for i in context_start..context_end {
        let marker = if i == line_no { ">" } else { " " };
        // `write!` into the already-allocated `String` rather than
        // `format!` + `push_str`, which would allocate a throwaway
        // intermediate `String` per line (`clippy::format_push_string`).
        let _ = writeln!(context, "{marker} expected[{i}]: {}", expected_lines[i]);
        let _ = writeln!(context, "{marker} actual[{i}]:   {}", actual_lines[i]);
    }
    context
}

/// Recursively rebuild every JSON object in `value` with its keys inserted
/// in sorted order, leaving array element order untouched.
///
/// `serde_json::Map` is a `BTreeMap` (always key-sorted) by default, but
/// becomes an insertion-order-preserving `IndexMap` when the crate's
/// `preserve_order` feature is enabled. Neither hippius-mem's nor
/// hippius-mem-core's own `[dependencies]`/`[dev-dependencies]` request that
/// feature directly, but `hippius-mem-core`'s `aws-sdk-s3`/`aws-smithy-mocks`
/// dev-dependencies (offline S3 mock tests) pull in `aws-smithy-http-client`,
/// which does — and Cargo's workspace-wide feature unification turns that on
/// for every `serde_json` use in the build the moment hippius-mem-core is
/// compiled alongside hippius-mem, i.e. under `cargo test --all` /
/// `--workspace` (what CI runs), but never under a package-scoped `cargo
/// test -p hippius-mem` (confirmed via `cargo tree --workspace -e features -i
/// serde_json`). Left unhandled, the very same server output renders in a
/// different key order purely depending on which of those two commands built
/// it — a false snapshot failure with no schema change behind it. Rebuilding
/// every object by inserting its own entries in sorted order fixes the
/// render itself rather than the ambient feature: a no-op under `BTreeMap`
/// (already sorted) and a pin to sorted order under `IndexMap` (which
/// otherwise keeps whatever order it happened to receive).
fn canonicalize(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));

            let mut sorted = serde_json::Map::new();
            for (key, val) in entries {
                sorted.insert(key, canonicalize(val));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(canonicalize).collect())
        }
        scalar => scalar,
    }
}

/// The advertised tool name, description, and schema are a public contract:
/// an agent decides WHETHER to call a tool from its description and validates
/// its arguments against the schema before ever calling us. schemars
/// generates the schema from the parameter structs and `#[tool(description =
/// ..)]` supplies the description, so a renamed field, a changed `required`
/// list, or a softened/deleted description is a silent breaking change that
/// no `logic_*` test can see. The description matters as much as the schema
/// here: several of this server's descriptions are load-bearing honesty
/// caveats (`reconcile`'s "NOT adversarial suppression", `edit`'s "not a
/// distributed lock") that nothing else in CI checks.
///
/// The snapshot is committed and MUST churn whenever a tool's doc comment
/// changes, not only when its params struct does — that churn is the point:
/// a description edit should force deliberate regeneration and review, the
/// same as a schema edit, rather than silently passing every job in CI.
/// Regenerate deliberately with `UPDATE_TOOL_SCHEMAS=1 cargo test -p
/// hippius-mem --test mcp_protocol`; that run fails on purpose (see below) so
/// a rewrite can never be mistaken for a pass, and a second, plain run
/// confirms the rewritten snapshot now matches what the server advertises.
#[tokio::test]
async fn advertised_tool_schemas_match_the_committed_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let server = harness::in_memory_server().await?;
    let tools = harness::list_tools(&server).await?;

    // Sort by name so the snapshot does not depend on router iteration order,
    // and canonicalize every object's key order (see `canonicalize`'s doc
    // comment) so the snapshot does not also depend on whether this test was
    // built alone or alongside the rest of the workspace.
    let mut rendered: Vec<serde_json::Value> = tools
        .into_iter()
        .map(|t| {
            canonicalize(json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }))
        })
        .collect();
    rendered.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    let actual = serde_json::to_string_pretty(&rendered)? + "\n";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/snapshots/tool_schemas.json"
    );

    // Gate on a genuinely non-empty value, not merely a set-but-empty one
    // (`UPDATE_TOOL_SCHEMAS=` would otherwise still trip `var_os(..).is_some()`).
    let update_requested = std::env::var("UPDATE_TOOL_SCHEMAS").is_ok_and(|v| !v.is_empty());

    if update_requested {
        std::fs::write(path, &actual)?;
        // A write is never a pass: failing here is what stops a developer who
        // left UPDATE_TOOL_SCHEMAS exported from silently self-approving a
        // contract break — CI runs this test without the var set, so this
        // branch cannot mask a real drift there, but a local run must not
        // report green just because it just rewrote the reference.
        return Err(format!(
            "UPDATE_TOOL_SCHEMAS was set: rewrote {path} from the live server. \
             This is a write, not a pass. Review the change (git diff {path}) as a \
             public API change, then re-run this test WITHOUT UPDATE_TOOL_SCHEMAS \
             set to confirm the rewritten snapshot now matches."
        )
        .into());
    }

    let expected = std::fs::read_to_string(path)?;

    if actual != expected {
        let actual_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/snapshots/tool_schemas.json.actual"
        );
        std::fs::write(actual_path, &actual)?;

        let context = first_diff_context(&actual, &expected);
        return Err(format!(
            "the advertised tool schemas changed. Wrote the actual output to \
             {actual_path} — diff it against tests/snapshots/tool_schemas.json to \
             review the full change. If deliberate, regenerate with \
             UPDATE_TOOL_SCHEMAS=1 and review the diff as a public API change.\n\n{context}"
        )
        .into());
    }

    Ok(())
}
