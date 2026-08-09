# Test Coverage Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every session starts with `mcp__hippius-mem__recall` on the task. Every subagent prompt MUST include: "Call `mcp__hippius-mem__recall` about the task before making changes, and `mcp__hippius-mem__remember` any durable decision/gotcha you discover." Every Rust-bearing task loads the `rust-style` skill before its first edit.

**Goal:** Close every coverage gap the 2026-08-09 audit found — the untested deployment paths, the unexercised feature-gated suites, the missing adversarial cases at the crypto and convergence boundaries — so that a regression in any behaviour this product promises fails a test instead of reaching a user.

**Architecture:** Eight phases. Phase A executes code that is already written and already passing but which no CI job runs — the highest value-per-line work in the plan, and a prerequisite for trusting anything else. Phase B covers the MCP protocol surface, which is the actual product interface and today is tested only as direct function calls. Phases C and D close convergence and cryptographic edge cases, and each contains one genuine implementation fix rather than a test-only change (C8 hostile snapshots, D8 chain-break visibility). Phase E adds adversarial-input coverage on the pinned stable toolchain. Phase F finishes real-backend coverage on the MinIO job PR #76 introduced. Phase G finishes retrieval quality. Phase H adds the tooling that would have caught all of this automatically.

**Tech Stack:** Rust 1.97.1 workspace (`hippius-mem-core`, `hippius-mem`), tokio, proptest 1.11, wiremock 0.6, tempfile 3, criterion 0.8, rmcp (MCP server), aws-sdk-s3, MinIO in CI, GitHub Actions.

## Global Constraints

- Toolchain pinned: Rust 1.97.1 (`rust-toolchain.toml`); MSRV 1.97.1. **`cargo-fuzz` requires nightly and is therefore NOT the primary fuzzing mechanism** — see Phase E.
- `#![forbid(unsafe_code)]` stays. `cargo clippy --all-targets --all-features -- -D warnings` must pass; `cargo fmt` before every commit; `cargo deny check` on any dependency change.
- rustfmt `use_small_heuristics = "Default"` — never one-line dense code. Blank lines between logical steps inside non-trivial function bodies, and between imports/consts/types/impls/functions.
- No emojis anywhere. Commit messages use the user's git identity only — no `Co-Authored-By` lines.
- **Every new test must be mutation-verified.** Before committing, break the specific behaviour the test targets, watch the new test fail, restore, watch it pass. Record the mutation in the commit message. A test that cannot be shown to fail is not evidence.
- Do not weaken an assertion to make a test pass. If a test fails against real behaviour, that is a finding — report it rather than adjusting the threshold.
- Test names must not overpromise. If a test asserts a narrower property than its name implies, rename the test or widen the assertion. The audit found seven such names; do not add an eighth.
- New CI jobs pin actions by commit SHA and container images by digest, matching the existing style in `.github/workflows/rust.yml`.
- `actionlint` and `zizmor --config .github/zizmor.yml` must be clean on any touched workflow.
- Base branch: this plan stacks on `test/quality-gates` (PR #76). If #76 and #75 have merged, branch from `main` instead.

## Baseline (measured 2026-08-09, do not re-derive)

- `cargo test --workspace` (default features): 19 binaries, 0 failures.
- `cargo test --all --all-features --locked`: **918 tests, 0 failures** — the feature-gated suites are healthy today. Two binaries take ~35s and ~32s (console `wiremock` and dashboard), so the all-features job needs a timeout above the default.
- CI currently executes default features only, so ~102 written tests never run: dashboard 33, import 31, console 17, invite 13, anchor/chain 6, mint 2.

## File Structure

New files, each with one responsibility:

| File | Responsibility |
|---|---|
| `hippius-mem/tests/mcp_protocol.rs` | Drives the real MCP router (`call_tool`/`list_tools`) in-process: dispatch, error mapping, schema shape. |
| `hippius-mem/tests/mcp_stdio.rs` | Spawns the built binary in MCP mode and speaks JSON-RPC over stdio. Transport only. |
| `hippius-mem-core/tests/wire_fuzz.rs` | Proptest over arbitrary bytes into every wire type's deserializer. |
| `hippius-mem-core/tests/convergence_edges.rs` | Divergence-then-healing, missing blobs, partial-outage index pruning. |
| `hippius-mem-core/tests/shared/mod.rs` | Shared multi-machine test harness used by `convergence_edges.rs` and `stress_convergence.rs`. |
| `.github/workflows/nightly.yml` | Long-running jobs: mutation testing, extended stress seeds, coverage report. |
| `scripts/tests/install_sh_test.sh` | Shell-level tests for `scripts/install.sh` against a faked download. |

Modified files: `.github/workflows/rust.yml` (all-features job, shellcheck job, MinIO job extensions), `.github/workflows/semantic-nightly.yml` (extra stress seeds), `hippius-mem-core/src/audit/reconcile.rs` (D8 quarantine reporting), `hippius-mem-core/src/store/mod.rs` (C8 snapshot record cross-check), `hippius-mem-core/src/oplog/op.rs` (D4 `parse_op`), `hippius-mem-core/src/identity/manifest.rs` (D3 v2 parse branch).

---

## Phase A — Execute the tests that already exist

Nothing in this phase writes a test. It runs code that is already written, already passing, and currently unexecuted by CI. Do this first: every later phase's value depends on CI actually running what we write.

### Task A1: CI job for the full feature set

**Files:**
- Modify: `.github/workflows/rust.yml`

**Interfaces:**
- Produces: a required check named `cargo test (all features)`.

- [ ] **Step 1: Add the job**

Insert after the existing `test:` job in `.github/workflows/rust.yml`:

```yaml
  # The shipped release binary is built with `embeddings,dashboard` (see
  # hippius-mem/Cargo.toml), but the `test` job above runs DEFAULT features, so
  # ~102 written tests behind dashboard/import/console/chain never executed
  # anywhere: dashboard 33, import 31, console 17, invite 13, anchor 6, mint 2.
  # Measured 2026-08-09, all 918 all-features tests pass — this job runs code
  # that was already correct and already unverified, which is the cheapest
  # coverage in the repo.
  #
  # Timeout is generous because the console `wiremock` and dashboard binaries
  # take ~35s and ~32s respectively, and ort-sys downloads the ONNX Runtime
  # archive at BUILD time (the same cost the clippy-all-features job pays).
  test-all-features:
    name: cargo test (all features)
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false
      - name: Install pinned toolchain
        run: rustup toolchain install
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
      # The embeddings and live-backend tests inside this set are #[ignore]d and
      # stay unrun here; the nightly and MinIO jobs own those.
      - run: cargo test --all --all-features --locked
```

- [ ] **Step 2: Correct the stale justification comment**

The `clippy-all-features` job comment in the same file claims an all-features test run is pointless because "every embeddings-gated test is `#[ignore]`d". That reasoning only ever covered `embeddings` and ignored the other four features. Replace that clause with:

```yaml
  # - `cargo test --all-features` IS run, in the `test-all-features` job below.
  #   An earlier comment here claimed it was pointless because every
  #   embeddings-gated test is #[ignore]d; that accounted only for `embeddings`
  #   and missed dashboard/import/console/chain, which together hold ~102
  #   executable tests.
```

- [ ] **Step 3: Verify locally**

Run: `cargo test --all --all-features --locked`
Expected: PASS, 918 tests, 0 failures.

- [ ] **Step 4: Lint the workflow**

Run: `actionlint .github/workflows/rust.yml && zizmor --config .github/zizmor.yml .github/workflows/rust.yml`
Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/rust.yml
git commit -m "ci: execute the feature-gated test suites

The shipped binary enables embeddings+dashboard, but CI only ever ran default
features, so ~102 written tests never executed: dashboard 33, import 31,
console 17, invite 13, anchor 6, mint 2. All 918 pass today, so this job runs
code that was already correct and already unverified."
```

### Task A2: Extended stress seeds in the nightly

`stress_convergence.rs` reads `STRESS_CONVERGENCE_EXTRA_SEEDS` and its own doc suggests seeding from the commit SHA, but nothing in the repo ever sets it — randomized convergence coverage is permanently 8 fixed seeds.

**Files:**
- Modify: `.github/workflows/semantic-nightly.yml`

- [ ] **Step 1: Add a stress job to the nightly workflow**

```yaml
  stress-seeds:
    name: stress_convergence (extra seeds)
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false
      - name: Install pinned toolchain
        run: rustup toolchain install
      - uses: Swatinem/rust-cache@23869a5bd66c73db3c0ac40331f3206eb23791dc # v2.9.1
      # The suite's 8 committed seeds are the PR-time gate; these derive four
      # more from the commit SHA so the nightly explores schedules no PR run
      # has, while staying replayable — a failure prints its seed and
      # `STRESS_CONVERGENCE_EXTRA_SEEDS=<seed> cargo test` reproduces it exactly.
      - name: Derive extra seeds from the commit SHA
        env:
          SHA: ${{ github.sha }}
        run: |
          seeds=""
          for offset in 0 8 16 24; do
            chunk="${SHA:$offset:16}"
            seeds="${seeds:+$seeds,}0x${chunk}"
          done
          echo "STRESS_CONVERGENCE_EXTRA_SEEDS=$seeds" >> "$GITHUB_ENV"
      - run: cargo test -p hippius-mem-core --locked --test stress_convergence -- --nocapture
```

- [ ] **Step 2: Verify the seed parser accepts this format**

Read `hippius-mem-core/tests/stress_convergence.rs:439-455` and confirm `extra_scenario_seeds()` parses a comma-separated list with `0x` prefixes. If it does not, fix the emitted format to match the parser rather than changing the parser.

Run locally: `STRESS_CONVERGENCE_EXTRA_SEEDS=0x1234567890abcdef cargo test -p hippius-mem-core --test stress_convergence -- --nocapture`
Expected: PASS, and the output names the extra seed.

- [ ] **Step 3: Lint and commit**

```bash
actionlint .github/workflows/semantic-nightly.yml
git add .github/workflows/semantic-nightly.yml
git commit -m "ci: run stress_convergence with commit-derived extra seeds nightly

The suite has read STRESS_CONVERGENCE_EXTRA_SEEDS since it was written and
nothing has ever set it, so randomized convergence coverage was permanently the
8 committed seeds. Deriving four more from the commit SHA explores fresh
schedules while staying exactly replayable from the printed seed."
```

### Task A3: Shell-script linting and an `install.sh` test

`scripts/install.sh` is 642 lines, is the first thing every new user executes (`curl | sh`), and has no test, no lint, and no CI job. The `.claude/hooks/*.sh` scripts ship into user repos via `include_str!` and are equally unlinted.

**Files:**
- Create: `scripts/tests/install_sh_test.sh`
- Modify: `.github/workflows/rust.yml`

**Interfaces:**
- Produces: a required check named `shellcheck`.

- [ ] **Step 1: Write the failing shell test**

Create `scripts/tests/install_sh_test.sh`. It must not touch the network: it stubs `curl`/`uname` on `PATH` and asserts `install.sh` picks the right artifact and fails loudly on a bad checksum.

```sh
#!/usr/bin/env sh
# Tests scripts/install.sh WITHOUT network access, by putting stub `curl`,
# `uname`, and `tar` earlier on PATH than the real ones. The installer is the
# first thing a new user runs, so a wrong target triple or a swallowed download
# failure is a first-impression bug with no other test guarding it.
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

STUBS="$WORK/stubs"
mkdir -p "$STUBS"

# Stub uname so the script believes it is on a known platform.
cat > "$STUBS/uname" <<'STUB'
#!/usr/bin/env sh
case "$1" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  *)  echo Linux ;;
esac
STUB
chmod +x "$STUBS/uname"

# Stub curl: record the URL it was asked for, emit a fake archive.
cat > "$STUBS/curl" <<STUB
#!/usr/bin/env sh
echo "\$@" >> "$WORK/curl-calls"
for arg in "\$@"; do
  case "\$arg" in
    https://*) echo "\$arg" >> "$WORK/urls" ;;
  esac
done
exit 0
STUB
chmod +x "$STUBS/curl"

PATH="$STUBS:$PATH"
export PATH

# Assertion 1: the resolved download URL names the Linux x86_64 target triple.
sh "$REPO_ROOT/scripts/install.sh" --dry-run > "$WORK/out" 2>&1 || true
if ! grep -q "x86_64-unknown-linux-gnu" "$WORK/urls" 2>/dev/null; then
  echo "FAIL: installer did not resolve the x86_64-unknown-linux-gnu artifact"
  cat "$WORK/out"
  exit 1
fi

echo "PASS: install.sh resolves the expected target triple"
```

**Note for the implementer:** read `scripts/install.sh` FIRST. If it has no `--dry-run` flag, add one whose only effect is to print the resolved URL and exit before downloading — that is the smallest change that makes the script testable, and it is useful to operators independently. Do not restructure the installer.

- [ ] **Step 2: Run it to verify it fails**

Run: `sh scripts/tests/install_sh_test.sh`
Expected: FAIL — either `--dry-run` is unrecognized, or no URL was resolved.

- [ ] **Step 3: Add `--dry-run` to `install.sh`**

Add the flag to the argument parser and, after target-triple resolution and URL construction, print the URL and `exit 0` before any download. Keep it beside the existing flag handling; do not reorganize the file.

- [ ] **Step 4: Run to verify it passes**

Run: `sh scripts/tests/install_sh_test.sh`
Expected: `PASS: install.sh resolves the expected target triple`

- [ ] **Step 5: Add the shellcheck CI job**

```yaml
  shellcheck:
    name: shellcheck
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false
      # `scripts/install.sh` is the curl|sh onboarding path and the hooks ship
      # into user repos via include_str!, so a syntax error in either is a
      # user-facing break with no compiler to catch it.
      - name: shellcheck
        run: |
          sudo apt-get update && sudo apt-get install -y shellcheck
          shellcheck scripts/install.sh scripts/tests/install_sh_test.sh .claude/hooks/*.sh
      - name: install.sh behaviour test
        run: sh scripts/tests/install_sh_test.sh
```

- [ ] **Step 6: Fix whatever shellcheck reports, then commit**

Run shellcheck locally first and fix real findings. Suppress only with a specific `# shellcheck disable=SCxxxx` plus a reason comment; never a blanket disable.

```bash
git add scripts/install.sh scripts/tests/install_sh_test.sh .github/workflows/rust.yml
git commit -m "ci: lint the shell scripts and test install.sh's target resolution

install.sh is 642 lines, is what `curl | sh` runs for every new user, and had
no test and no lint. The hooks ship into user repos via include_str! with the
same exposure. Adds a network-free test of target-triple resolution (via a new
--dry-run flag) and a shellcheck job over the installer, its test, and the
hooks."
```

---

## Phase B — The MCP protocol surface

All 31 server tests call `logic_*` directly. Nothing dispatches through the generated `call_tool`, nothing checks the advertised schemas, and nothing speaks the wire protocol. An rmcp upgrade that changed the handshake, the parameter schema emission, or the `CallToolResult` shape would pass every CI job and break every agent.

### Task B1: Dispatch through the real router

**Files:**
- Create: `hippius-mem/tests/mcp_protocol.rs`

**Interfaces:**
- Consumes: `MemoryServer` and its `tool_router()`, already used by `server_advertises_ten_tools` (`hippius-mem/src/server.rs:1539`).
- Produces: nothing other tasks depend on.

- [ ] **Step 1: Read how the server is constructed in tests**

Read `hippius-mem/src/server.rs` around lines 420-460 (the `tool_router` field and both constructors) and the existing test-construction helper. The integration test must build a `MemoryServer` over an in-memory store the same way, without a config file or network.

**If `MemoryServer`'s constructor is not public**, add a `#[doc(hidden)] pub` test constructor rather than making the integration test reach into private state — and note in its doc comment that it exists for `tests/mcp_protocol.rs`.

- [ ] **Step 2: Write the failing test**

```rust
//! The MCP surface exercised through the REAL router, not the `logic_*`
//! functions the unit tests call.
//!
//! Every server unit test calls `logic_remember`/`logic_recall`/... directly,
//! so the generated `call_tool` dispatch, the schemars parameter schemas, and
//! the `CallToolResult` shape an agent actually receives were untested. An rmcp
//! upgrade that changed any of them would keep every other job green and break
//! every connected agent.

use rmcp::model::{CallToolRequestParam, CallToolResult};
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
    assert!(!stored.is_error.unwrap_or(false), "remember must succeed: {stored:?}");

    let found = harness::call(&server, "recall", json!({ "text": "deterministic ordering" })).await?;
    assert!(!found.is_error.unwrap_or(false), "recall must succeed: {found:?}");

    let text = harness::result_text(&found);
    assert!(
        text.contains("BTreeMap"),
        "recall through the router must surface the stored note, got: {text}"
    );

    Ok(())
}

#[tokio::test]
async fn an_unknown_tool_is_a_protocol_error_not_a_panic() -> Result<(), Box<dyn std::error::Error>> {
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
```

Create `hippius-mem/tests/harness/mod.rs` with `in_memory_server()`, `call()` (which builds a `CallToolRequestParam` and drives the server's `call_tool`), and `result_text()` (which concatenates the text content of a `CallToolResult`). Consult the rmcp version in `hippius-mem/Cargo.toml` and read its `ServerHandler::call_tool` signature before writing `call()`; do not guess the argument type.

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p hippius-mem --test mcp_protocol`
Expected: FAIL to compile — the harness does not exist yet.

- [ ] **Step 4: Implement the harness, then run**

Run: `cargo test -p hippius-mem --test mcp_protocol`
Expected: PASS, 3 tests.

- [ ] **Step 5: Mutation-verify**

Break dispatch deliberately — in `server.rs`, rename one tool in its `#[tool(...)]` attribute (e.g. `recall` to `recall2`) and confirm `remember_then_recall_through_call_tool` fails. Restore.

- [ ] **Step 6: fmt, clippy, commit**

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
git add hippius-mem/tests/mcp_protocol.rs hippius-mem/tests/harness/mod.rs
git commit -m "test(server): exercise the MCP tools through the real router

All 31 server tests call logic_* directly, so the generated call_tool dispatch
and the CallToolResult shape an agent receives were untested; the one router
test only listed tool NAMES. An rmcp upgrade changing dispatch or the result
shape would pass CI and break every connected agent.

Mutation-verified: renaming a tool in its #[tool] attribute fails the
round-trip test."
```

### Task B2: Pin the advertised tool schemas

The schemas are generated by schemars from the parameter structs. A wrong `required` list or a changed type is invisible to `logic_*` tests but breaks agent argument validation.

**Files:**
- Modify: `hippius-mem/tests/mcp_protocol.rs`
- Create: `hippius-mem/tests/snapshots/tool_schemas.json`

- [ ] **Step 1: Write the failing snapshot test**

```rust
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
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots/tool_schemas.json");

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
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem --test mcp_protocol advertised_tool_schemas`
Expected: FAIL — the snapshot file does not exist.

- [ ] **Step 3: Generate and REVIEW the snapshot**

Run: `UPDATE_TOOL_SCHEMAS=1 cargo test -p hippius-mem --test mcp_protocol advertised_tool_schemas`

Then read `hippius-mem/tests/snapshots/tool_schemas.json` in full. Confirm every tool is present, that `required` lists match the non-`Option` fields of each params struct, and that no field carrying a secret appears. A generated snapshot is only as good as the review it gets — do not commit it unread.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p hippius-mem --test mcp_protocol advertised_tool_schemas`
Expected: PASS.

- [ ] **Step 5: Mutation-verify**

Add a throwaway field to one params struct, confirm the test fails, remove it.

- [ ] **Step 6: fmt, clippy, commit**

```bash
git add hippius-mem/tests/mcp_protocol.rs hippius-mem/tests/snapshots/tool_schemas.json
git commit -m "test(server): pin the advertised MCP tool schemas

The schemas are the contract an agent validates arguments against, generated by
schemars from the params structs — so a renamed field or a changed required
list is a silent breaking change no logic_* test can see. Committed snapshot,
regenerated deliberately via UPDATE_TOOL_SCHEMAS=1."
```

### Task B3: The stdio transport and `serve` boot

`server.serve(stdio())` is never reached by any test. A stdout pollution regression (a stray `println!`) corrupts the JSON-RPC stream and breaks every client.

**Files:**
- Create: `hippius-mem/tests/mcp_stdio.rs`

- [ ] **Step 1: Write the failing test**

```rust
//! The binary spoken to exactly as a client speaks to it: JSON-RPC over stdio.
//!
//! `main.rs`'s `server.serve(stdio())` had no test. The failure this guards is
//! specific and has bitten other MCP servers: anything that writes to stdout
//! outside the protocol — a stray println!, a progress bar, a dependency's
//! banner — corrupts the stream and breaks every client, while every in-process
//! test stays green.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Command, Stdio};

#[test]
fn the_binary_completes_an_mcp_handshake_over_stdio() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;

    // An isolated HOME and config so the server boots a throwaway local vault
    // and never reads the developer's real configuration.
    let mut child = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .arg("serve")
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("HIPPIUS_MEM_CONFIG", dir.path().join("hippius-mem.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdin = child.stdin.take().ok_or("stdin")?;
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "hippius-mem-test", "version": "0" }
        }
    });
    writeln!(stdin, "{request}")?;
    stdin.flush()?;

    let mut line = String::new();
    BufReader::new(child.stdout.take().ok_or("stdout")?).read_line(&mut line)?;
    let _ = child.kill();

    let parsed: serde_json::Value = serde_json::from_str(line.trim()).map_err(|e| {
        format!("the FIRST line of stdout must be JSON-RPC, not log or banner output: {e}; got {line:?}")
    })?;

    assert_eq!(parsed["jsonrpc"], "2.0", "handshake reply must be JSON-RPC 2.0: {parsed}");
    assert_eq!(parsed["id"], 1, "reply must correlate to the request id: {parsed}");
    assert!(
        parsed["result"]["serverInfo"]["name"].is_string(),
        "initialize must return serverInfo: {parsed}"
    );

    Ok(())
}
```

**Note for the implementer:** confirm the exact subcommand (`serve`) and the config env var names against `hippius-mem/src/main.rs` before writing this. If `serve` requires a configured team, seed a trial config first the way `hippius-mem/tests/quickstart_cli.rs` does — read that file; do not invent a config format.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem --test mcp_stdio`
Expected: FAIL — most likely a timeout or a non-JSON first line, depending on boot behaviour.

- [ ] **Step 3: Make it pass**

If the first stdout line is not JSON, that is a real bug: find what writes to stdout during boot and route it to stderr via `tracing`. If boot needs config, seed it in the test.

- [ ] **Step 4: Run to verify it passes, then mutation-verify**

Add a temporary `println!("boot")` at the top of the serve path, confirm the test fails with the "FIRST line of stdout" message, and remove it.

- [ ] **Step 5: fmt, clippy, commit**

```bash
git add hippius-mem/tests/mcp_stdio.rs
git commit -m "test(server): handshake with the real binary over stdio

server.serve(stdio()) had no test. The guarded failure is stdout pollution: a
stray println! or a dependency banner corrupts the JSON-RPC stream and breaks
every client while every in-process test stays green.

Mutation-verified: a println! in the serve path fails the test."
```

---

## Phase C — Convergence and durability edge cases

### Task C1: Compare index-side state across machines

`stress_convergence.rs` hydrates through `MemoryStore::get`, which reads every field from the sealed blob. With all machines sharing one blob store, agreeing on the winning pointer makes agreement on the contents trivially true — so `relations`, `reinforcers`, `last_reinforced`, and `lamport` are never actually compared across machines.

**Files:**
- Modify: `hippius-mem-core/tests/stress_convergence.rs`

**Interfaces:**
- Consumes: `MemoryStore::list_records() -> Result<Vec<IndexRecord>, MemError>` (`hippius-mem-core/src/store/mod.rs:1617`).

- [ ] **Step 1: Add the index-state comparison**

Add beside the existing `live_view` comparison:

```rust
/// The index-side converged state, which `live_view` cannot see: `live_view`
/// hydrates through `get`, and every field it returns comes out of the sealed
/// blob, so with one shared bucket the machines agree trivially once they agree
/// on the winning pointer. Relations, reinforcers, and recency signals live
/// only in the index and were never compared.
///
/// Sorted by note id, with volatile fields dropped, so two machines that
/// converged are byte-equal here.
fn index_view(store: &MemoryStore) -> Result<Vec<(NoteId, Vec<TypedLink>, BTreeSet<Ss58>, Option<Timestamp>)>, MemError> {
    let mut records = store.list_records()?;
    records.sort_by_key(|r| r.note_id);

    Ok(records
        .into_iter()
        .map(|r| (r.note_id, r.relations, r.reinforcers, r.last_reinforced))
        .collect())
}
```

And in each scenario's assertion block, after the existing `views` comparisons:

```rust
    let index_views: Vec<_> = machines
        .iter()
        .map(|m| index_view(&m.store))
        .collect::<Result<_, _>>()?;

    assert_eq!(
        index_views[0], index_views[1],
        "machines A and B must converge on identical INDEX state, not just identical blobs (seed {seed:#x})"
    );
    assert_eq!(
        index_views[1], index_views[2],
        "machines B and C must converge on identical INDEX state (seed {seed:#x})"
    );
```

**Gotcha the implementer must respect:** a `get` of a note can emit a `Reinforce` op when it follows a `recall` of the same note within the use-signal window. Call `index_view` BEFORE any `get`-based `live_view` in the same assertion block, or the comparison races the side effect it is measuring.

- [ ] **Step 2: Run to verify it passes**

Run: `cargo test -p hippius-mem-core --test stress_convergence`
Expected: PASS. If it FAILS, stop — that is a genuine convergence bug in relations or reinforcers and is a finding to report, not a test to soften.

- [ ] **Step 3: Mutation-verify**

In `converge.rs`, make relation merging order-dependent (e.g. `truncate(1)` the relations vector). Confirm the new assertion fails. Restore.

- [ ] **Step 4: Fix the module's overpromising header**

`stress_convergence.rs`'s header claims "byte-identical memory" and convergence "regardless of the order each observed the log". With this task the first claim becomes true for index state; the second is still not what the scenarios do (they observe different PREFIXES of one identically-sorted log, not different orders). Correct the header to say exactly that.

- [ ] **Step 5: fmt, clippy, commit**

```bash
git commit -m "test(core): compare index state across machines, not just blobs

live_view hydrates through get, whose every field comes from the sealed blob —
so with one shared bucket, agreement on the winning pointer made agreement on
contents trivially true. Relations, reinforcers, and last_reinforced live only
in the index and were never compared across machines.

Also corrects the module header, which claimed byte-identical convergence
'regardless of the order each observed the log'; the scenarios vary observed
PREFIXES, not orders."
```

### Task C2: Order-independence of the composed read path

`converge` is proptested for order-independence, and `longest_rooted_chain` separately for fetch-order independence, but the composition (`read_verified` then `converge`) — which is what `sync` actually runs — is never asserted end to end.

**Files:**
- Create: `hippius-mem-core/tests/convergence_edges.rs`

- [ ] **Step 1: Write the failing proptest**

```rust
//! Edge cases at the seam between the op-log reader and convergence: the
//! composed pipeline, partial outages, and divergence-then-healing.
//!
//! The halves are each well covered — `converge` has order-independence
//! proptests and `longest_rooted_chain` has a fetch-order proptest — but
//! `sync`'s actual path is list -> fetch (unordered) -> verify -> quarantine ->
//! sort -> converge, and the composition was never asserted.

use proptest::prelude::*;

proptest! {
    /// The same op objects presented to the reader in any listing order must
    /// converge to identical state. This composes what the unit proptests test
    /// separately, over the real `OpLogStore` read path rather than a
    /// hand-assembled `VerifiedOps`.
    #[test]
    fn composed_read_and_converge_is_listing_order_independent(rotation in 0_usize..8) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

        runtime.block_on(async move {
            let bucket = seeded_bucket().await;

            let baseline = read_and_converge(&bucket).await;
            let rotated = read_and_converge(&rotate_listing(&bucket, rotation)).await;

            prop_assert_eq!(baseline, rotated, "listing order must not change converged state");
            Ok(())
        })?;
    }
}
```

The implementer writes `seeded_bucket()` (a `MemoryBlobStore` holding a small multi-author op set produced through the public API), `rotate_listing()` (a `BlobStore` decorator whose `list` returns the same keys rotated), and `read_and_converge()` (`OpLogStore::read_all` then `converge`, returning `ConvergedState`).

**Note:** `MemoryBlobStore`'s `list` is sorted, so the rotation decorator is what actually varies the order. Confirm `OpLogStore::read_verified` does not re-sort before `converge` in a way that makes the property vacuous — read `hippius-mem-core/src/oplog/store.rs:179-320` first. If it does re-sort totally (it does, via `sort_by_cached_key`), then say so in the test's doc comment and assert the weaker-but-real property: that the SORT is what provides the independence, by asserting the pre-sort fetch order varies and the post-sort order does not.

- [ ] **Step 2: Run to verify it fails, implement, run to verify it passes**

- [ ] **Step 3: Mutation-verify**

Remove the total sort in `read_verified` and confirm the property fails.

- [ ] **Step 4: fmt, clippy, commit**

### Task C3: A missing note blob, and recovery when it returns

The corrupt-blob path is tested (`get_detects_tampered_blob`); the missing-blob path is not, and neither has a recovery assertion.

**Files:**
- Modify: `hippius-mem-core/tests/convergence_edges.rs`

- [ ] **Step 1: Write the failing test**

```rust
/// A note's ciphertext blob vanishing from the bucket must degrade cleanly —
/// the note is skipped with a warning, the rest of the log still converges —
/// and the note must come BACK on the next sync once the blob is restored.
///
/// The corrupt-blob path has a test; the missing-blob path did not, and neither
/// asserted recovery. Recovery is the half that matters operationally: a
/// transient gateway 404 must not permanently drop a note from the index.
#[tokio::test]
async fn a_missing_blob_is_skipped_and_returns_on_the_next_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let store = store_over(bucket.clone())?;

    let kept = store.remember(input("kept note", "kept body")).await?;
    let vanishing = store.remember(input("vanishing note", "vanishing body")).await?;

    // Take the blob out of the bucket, keeping a copy to restore.
    let key = store.object_key_of(vanishing)?;
    let saved = bucket.get(&key).await?;
    bucket.delete(&key).await?;

    let fresh = store_over(bucket.clone())?;
    fresh.sync().await?;

    assert!(fresh.get(kept).await.is_ok(), "an unrelated note must still converge");
    assert!(
        fresh.get(vanishing).await.is_err(),
        "a note whose blob is gone must not be served"
    );

    // Restore and re-sync: the note must come back, not stay permanently pruned.
    bucket.put(&key, saved).await?;
    fresh.sync().await?;

    assert_eq!(
        fresh.get(vanishing).await?.summary,
        "vanishing note",
        "a restored blob must repopulate the index on the next sync"
    );
    Ok(())
}
```

**Note:** `object_key_of` may not exist. If not, obtain the key from `list_records()` (`IndexRecord.object_key`) rather than adding public API.

- [ ] **Step 2: Run to verify it fails**

Expect the RECOVERY assertion to be the one that fails if `sync`'s `index.retain(&live_ids)` prunes and a later sync does not re-add. If it does fail, that is a real bug: fix `sync` so a note whose blob returns is re-indexed, then re-run.

- [ ] **Step 3: Implement or fix, run to verify it passes, mutation-verify, commit**

### Task C4: A minority fetch outage must not permanently prune a warm index

`read_verified` errors only at >= 50% GET failure; below that it returns fewer ops, and `replay_full`'s `index.retain(&live_ids)` prunes the transiently-unfetched notes out of a warm index. The threshold is tested three ways; the consequence below it is not.

**Files:**
- Modify: `hippius-mem-core/tests/convergence_edges.rs`

- [ ] **Step 1: Write the failing test**

```rust
/// A minority fetch outage must be TRANSIENT, not destructive.
///
/// `read_verified` errors only at >= 50% GET failure; below that it returns
/// fewer ops, and `replay_full`'s `index.retain(&live_ids)` then prunes the
/// notes whose ops were not fetched out of a warm index. The threshold itself
/// is tested three ways; what happens BELOW it — where the reader deliberately
/// tolerates the failure — was never asserted. If the pruned note does not come
/// back, a single flaky GET permanently drops a note from this machine.
#[tokio::test]
async fn a_transient_minority_fetch_failure_heals_on_the_next_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let writer = store_over(bucket.clone())?;

    let a = writer.remember(input("alpha note", "alpha body")).await?;
    let b = writer.remember(input("beta note", "beta body")).await?;
    let c = writer.remember(input("gamma note", "gamma body")).await?;

    // A reader with a warm index holding all three.
    let reader_bucket = Arc::new(FailOneGet::new(bucket.clone()));
    let reader = store_over(reader_bucket.clone())?;
    reader.sync().await?;
    assert_eq!(reader.list_records()?.len(), 3, "the warm index must hold all three");

    // Fail exactly ONE op object's GET — a strict minority, so the reader
    // tolerates it rather than erroring.
    reader_bucket.fail_one_op_get();
    reader.sync().await?;

    // Then clear the fault and sync again: the full set must return.
    reader_bucket.clear_fault();
    reader.sync().await?;

    let ids: BTreeSet<NoteId> = reader.list_records()?.into_iter().map(|r| r.note_id).collect();
    assert_eq!(
        ids,
        BTreeSet::from([a, b, c]),
        "a transient minority GET failure must not permanently drop a note"
    );
    Ok(())
}
```

`FailOneGet` is a `BlobStore` decorator in this test file holding an `AtomicBool` fault flag and the key of one op object; `get` returns `MemError::Storage` for that key while the flag is set and delegates otherwise. Model it on the existing `GetFailBlob` in `hippius-mem-core/src/oplog/store.rs:645` — read that first rather than inventing a new shape.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem-core --test convergence_edges a_transient_minority`
Expected: FAIL on the final assertion if the pruned note stays pruned.

- [ ] **Step 3: Fix or confirm**

If it fails, the fix is in `sync`: a note pruned by `retain` during a degraded read must be re-indexed once its op is fetchable again. **If it passes on the first run, keep it as a guard test and say so in the commit message** — an assertion nobody had written is worth having either way.

- [ ] **Step 4: Mutation-verify**

Make `replay_full` skip the re-index on a subsequent sync (or make `retain` permanent) and confirm the test fails.

- [ ] **Step 5: fmt, clippy, commit**

### Task C5: Cross-machine quarantine divergence and healing

A forked or gapped author chain quarantines that author's tail on the machine that sees it. Nothing asserts the machine re-converges with a healthy peer once the object is visible again.

**Files:**
- Modify: `hippius-mem-core/tests/convergence_edges.rs`

- [ ] **Step 1: Write the test**

```rust
/// Quarantine must be a temporary, self-healing divergence.
///
/// A gap in one author's chain makes the reader quarantine that author's tail —
/// correct, since an unverifiable chain must not be trusted. But the machine
/// that quarantined now holds strictly less than a healthy peer, and NOTHING
/// asserted that it re-converges once the missing object is visible again. A
/// quarantine that never heals is indistinguishable from silent data loss.
#[tokio::test]
async fn a_quarantined_author_tail_reconverges_once_the_gap_closes()
-> Result<(), Box<dyn std::error::Error>> {
    let bucket = Arc::new(MemoryBlobStore::default());
    let a = store_over(bucket.clone(), SEED_A)?;

    // One author writes a chain several ops long.
    for i in 0..4 {
        a.remember(input(&format!("note {i}"), "body")).await?;
    }

    // B reads with one MID-CHAIN op object unfetchable, so everything after the
    // gap is quarantined rather than trusted.
    let gapped = Arc::new(FailOneGet::new(bucket.clone()));
    gapped.fail_mid_chain_op();
    let b = store_over_blob(gapped.clone(), SEED_B)?;
    b.sync().await?;

    let a_ids: BTreeSet<NoteId> = a.list_records()?.into_iter().map(|r| r.note_id).collect();
    let b_ids: BTreeSet<NoteId> = b.list_records()?.into_iter().map(|r| r.note_id).collect();
    assert!(
        b_ids.is_subset(&a_ids) && b_ids.len() < a_ids.len(),
        "the quarantining machine must hold strictly less than the healthy one: {b_ids:?} vs {a_ids:?}"
    );

    // Close the gap and re-sync: the two machines must agree on INDEX state,
    // not merely on note ids (see Task C1 for why blob-derived views cannot
    // tell these apart).
    gapped.clear_fault();
    b.sync().await?;

    assert_eq!(
        index_view(&a)?,
        index_view(&b)?,
        "a healed quarantine must re-converge to identical index state"
    );
    Ok(())
}
```

Reuse `index_view` from Task C1 by moving it into `hippius-mem-core/tests/shared/mod.rs` and `include!`ing it from both files, following the pattern PR #76 established for the calibration corpus.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hippius-mem-core --test convergence_edges a_quarantined_author`
Expected: FAIL to compile first (the shared helper), then a real failure if healing does not occur.

- [ ] **Step 3: Fix or confirm, then mutation-verify**

Make quarantine sticky (cache the quarantined author set across syncs) and confirm the test fails. Restore.

- [ ] **Step 4: fmt, clippy, commit**

### Task C6: A truncated op-log object

Only `b"{ not json"` is tested. A truncated-but-valid JSON prefix is the realistic torn-write shape.

**Files:**
- Modify: `hippius-mem-core/src/oplog/store.rs` (tests module)

- [ ] **Step 1: Write the test**

```rust
    /// A torn write leaves a VALID PREFIX, not garbage.
    ///
    /// The undecodable-object path is covered by a `b"{ not json"` fixture, but
    /// that is the easy shape: it fails at the first byte. A write interrupted
    /// partway leaves a well-formed JSON prefix that fails somewhere in the
    /// middle, which is the shape a real torn write or a truncated range read
    /// produces. Both must be skipped with a warning, never fatal to the read.
    #[tokio::test]
    async fn a_truncated_op_object_is_skipped_not_fatal() -> TestResult {
        let bucket = MemoryBlobStore::default();
        let store = oplog_store_over(&bucket);

        let good = signed_op(1);
        let torn = signed_op(2);
        store.append(TEAM, &good).await?;
        store.append(TEAM, &torn).await?;

        // Truncate the SECOND object to 60% of its bytes, in place.
        let torn_key = op_object_key(TEAM, &torn);
        let full = bucket.get(&torn_key).await?;
        let cut = full.len() * 6 / 10;
        bucket.put(&torn_key, full[..cut].to_vec()).await?;

        let ops = store.read_all(TEAM).await?;

        let ids: Vec<_> = ops.as_slice().iter().map(|o| o.op_id).collect();
        ensure_eq(
            &ids,
            &vec![good.op_id],
            "a truncated object must be skipped while every intact op still reads",
        )
    }
```

Read `hippius-mem-core/src/oplog/store.rs`'s existing tests for the real names of `oplog_store_over`, `signed_op`, and the op-key helper before writing this; do not invent them.

- [ ] **Step 2: Run**

Run: `cargo test -p hippius-mem-core --lib a_truncated_op_object`
Expected: PASS is the likely outcome — the decode path is shared with the undecodable case. **If it passes first time, keep it and say so in the commit message**: it pins a distinct input shape that nothing else covered.

- [ ] **Step 3: Mutation-verify**

Make the decode failure propagate instead of skipping (turn the `warn + continue` into a `?`) and confirm this test fails.

- [ ] **Step 4: fmt, clippy, commit**

### Task C7: Hostile snapshot — cross-check the sealed record body

**This task contains an implementation fix, not only a test.**

The snapshot safety valve validates only the CLEAR envelope fields (`note_id`, `lamport`, `object_key`). The sealed record body — carrying `summary`, `tags`, `author`, `cid`, `updated`, and what actually gets indexed — is never cross-checked against the op-log. A holder of the current epoch key can therefore forge a snapshot that passes the valve but misattributes a note or shows a different summary; `recall` surfaces the forgery while `get` returns the true body.

**Files:**
- Modify: `hippius-mem-core/src/store/mod.rs` (`collect_live_snapshot_records`, around the valve at 3220 and the collection at 3344)

- [ ] **Step 1: Write the failing test**

Build a store, sync to produce a snapshot, then rewrite the snapshot with a record whose envelope matches the op-log but whose sealed body carries a different `summary` and `author`, resealed under the same epoch key. Assert that `sync` rejects or ignores the forged record — that `recall` never surfaces the forged summary and `list_records()` shows the true author.

- [ ] **Step 2: Run to verify it fails**

Expected: FAIL — the forged summary is surfaced by `recall`.

- [ ] **Step 3: Implement the cross-check**

In `collect_live_snapshot_records`, require each snapshot record's `cid` to equal the `cid` the converged op-log names for that `object_key`, and drop the record otherwise. Document that this closes the forged-body path and that the snapshot remains an optimization, never a source of truth.

- [ ] **Step 4: Run to verify it passes and that the fast path still works**

Run the full snapshot suite: `cargo test -p hippius-mem-core --lib snapshot` plus `cargo test -p hippius-mem-core --test e2e_durability`.
Expected: PASS, and `sync_with_snapshot_equals_full_replay` still takes the incremental path (it asserts no full rebuild) — a cross-check that accidentally rejects every record would still pass equality-with-full-replay while destroying the optimization, so confirm the restore path is still exercised.

- [ ] **Step 5: fmt, clippy, commit**

```bash
git commit -m "fix(core): cross-check snapshot record bodies against the op-log

The snapshot safety valve authenticated only the clear envelope (note_id,
lamport, object_key). The sealed body — summary, tags, author, cid, and what
actually gets indexed — was never checked against the op-log, so a current-epoch
key holder could forge a snapshot that passed the valve and misattributed a note
or changed its summary: recall would surface the forgery while get returned the
true body.

collect_live_snapshot_records now requires a record's cid to match the cid the
converged op-log names for that object_key."
```

---

## Phase D — Cryptographic and authorization edge cases

### Task D1: A superseded op cannot be replayed to roll a note back

Byte-identical replay is covered by dedup and idempotence. Replanting a STALE lower-Lamport `Edit` to regress a note's content is not asserted anywhere; the invariant rests on `op_outranks` and is only ever tested positively.

**Files:**
- Modify: `hippius-mem-core/src/oplog/converge.rs` (tests module)

- [ ] **Step 1: Write the test**

Converge a note that has been edited twice. Re-present the FIRST edit's op (still validly signed, lower Lamport) alongside the full set, converge again, and assert the note's pointer still names the second edit. Name it `a_replayed_superseded_edit_cannot_roll_a_note_back`.

- [ ] **Step 2: Run — expect PASS (a guard test), then mutation-verify**

Invert the comparison in `op_outranks` and confirm this test fails. Restore.

- [ ] **Step 3: fmt, clippy, commit**

### Task D2: Removed-member undecryptability, asserted at the crypto layer

`rotate_key_excludes_removed_member_from_post_rotation_notes` proves the removed member gets no wrap and indexes zero notes. Both are index-mediated; nothing opens a post-rotation ciphertext with the pre-rotation key and asserts a crypto failure.

**Files:**
- Modify: `hippius-mem-core/tests/e2e_phase3.rs`

- [ ] **Step 1: Add the direct assertion**

After the existing rotation and post-rotation write, fetch the post-rotation blob's raw bytes from the bucket and call `open(epoch0_key, &bytes, aad)` directly. Assert `Err(MemError::Crypto { .. })`.

```rust
    // Direct, crypto-layer proof. Everything above is index-mediated: `sync`
    // returning 0 and `get` returning NotFound would also be satisfied by an
    // unrelated bug. This asserts the actual guarantee — the old key cannot
    // open the new ciphertext.
    let raw = bucket.get(&post_rotation_key).await?;
    let opened = hippius_mem_core::open(&epoch0_key, &raw, post_rotation_key.as_bytes());
    assert!(
        matches!(opened, Err(MemError::Crypto { .. })),
        "the pre-rotation key must not open a post-rotation blob, got {opened:?}"
    );
```

Confirm the exact `open` signature and AAD convention by reading `hippius-mem-core/src/crypto.rs` and the seal call site in `store/mod.rs` before writing this; the AAD is the object key.

- [ ] **Step 2: Run to verify it passes**

Run: `cargo test -p hippius-mem-core --test e2e_phase3 rotate_key_excludes_removed_member`
Expected: PASS — this is a guard over an invariant that already holds.

- [ ] **Step 3: Mutation-verify**

Make `rotate_team_key` reuse the existing epoch key instead of generating a fresh one, and confirm the new direct assertion fails (the index-mediated assertions above it may still pass, which is exactly the point). Restore.

- [ ] **Step 4: fmt, clippy, commit**

### Task D3: Manifest v2 injectivity and v1/v2 cross-verification

`manifest_signing_bytes_is_injective` builds candidates via `create_signed`, which always passes `recovery_key: None`, and its inverse `parse_manifest` hard-requires the v1 domain — so the v2 layout, the one carrying an authorization root, is entirely outside the injectivity proof. `recovery_manifest_signs_under_v2_domain` checks the tag prefix and that stripping the key changes the bytes, but never that the stripped manifest FAILS `verify()`.

**Files:**
- Modify: `hippius-mem-core/src/identity/manifest.rs`

- [ ] **Step 1: Extend `parse_manifest` with a v2 branch**

Accept either domain tag, and parse the trailing `recovery_key` when the tag is v2. Keep it in the tests module if it is test-only today.

- [ ] **Step 2: Extend the injectivity proptest to cover v2**

Generate candidates with `recovery_key` both `None` and `Some(key)` via `create_signed_with_recovery`, and assert the biconditional `a.signing_bytes() == b.signing_bytes() <=> a == b` across the mixed set.

- [ ] **Step 3: Add the downgrade test**

```rust
    /// A v2 manifest with its `recovery_key` stripped must FAIL verification —
    /// not merely produce different bytes. The prior test asserted only that
    /// the bytes changed, which a downgrade attacker does not care about.
    #[test]
    fn a_downgraded_v2_manifest_does_not_verify() -> TestResult { /* ... */ }
```

- [ ] **Step 4: run, mutation-verify, commit**

### Task D4: `parse_op` and op injectivity

`Op::signing_bytes` interleaves framed fields with raw fixed-width ones — the ambiguity the manifest's explicit member-count framing exists to close — and has no parse-back inverse, so it has no injectivity proof over its real field set.

**Files:**
- Modify: `hippius-mem-core/src/oplog/op.rs`

- [ ] **Step 1: Write `parse_op`, mirroring `parse_manifest`**

A test-module function that parses `signing_bytes` back into its fields, rejecting a trailing-byte mismatch.

- [ ] **Step 2: Add the injectivity proptest**

```rust
        /// `signing_bytes` is injective over the full field space: two ops
        /// produce equal signed bytes if and only if they are equal. A framing
        /// bug that let two distinct ops share bytes would let a signature
        /// transfer between them.
        #[test]
        fn op_signing_bytes_is_injective(a in op_strategy(), b in op_strategy()) {
            prop_assert_eq!(a.signing_bytes() == b.signing_bytes(), a == b);
        }
```

Extend the existing `op_kind_strategy()` to vary every field, not only the kind.

- [ ] **Step 3: run, mutation-verify (drop the length prefix from one framed field and confirm a collision is found), commit**

### Task D5: Merkle leaf/node second-preimage

`merkle.rs`'s header argues the `0x00`/`0x01` prefixes prevent leaf-versus-node preimage confusion. No test constructs that attack.

**Files:**
- Modify: `hippius-mem-core/src/audit/merkle.rs`

- [ ] **Step 1: Write the test**

Build a two-leaf tree, take the 64-byte concatenation that forms its internal node, present those 64 bytes AS A LEAF in a second tree, and assert the roots differ and no proof from one verifies against the other. Name it `an_internal_node_preimage_is_not_a_valid_leaf`.

- [ ] **Step 2: run, mutation-verify (remove the domain prefixes and confirm the roots collide), commit**

### Task D6: The full low-order point set and invalid curve points

`low_order_points_are_refused_on_wrap_and_unwrap` tests only the all-zero u-coordinate despite its plural name; `verify`'s `PublicKey::from_bytes` error arm is never driven.

**Files:**
- Modify: `hippius-mem-core/src/identity/teamkey.rs`, `hippius-mem-core/src/oplog/op.rs`

- [ ] **Step 1: Table-drive the low-order test**

Cover all canonical low-order x25519 u-coordinates (the standard set of five, plus the two non-canonical encodings). Keep the name accurate to what it now covers.

- [ ] **Step 2: Drive the invalid-curve-point arm**

Construct a `VerifyingKey` from bytes that are not a valid Ristretto point and assert `verify` returns false rather than panicking.

- [ ] **Step 3: run, mutation-verify, commit**

### Task D7: The remaining domain-separation gaps

Three small, real gaps: `MEMBERKEY_DOMAIN` is never exercised against the other two tags; `derive_cache_key` has no direct domain-separation test; and `Identity::x25519_secret`'s independence from the sr25519 key — the module's headline claim — rests on nothing.

**Files:**
- Modify: `hippius-mem-core/src/crypto.rs`, `hippius-mem-core/src/identity/teamkey.rs`

- [ ] **Step 1: Write the three tests**

1. A signature over member-key-tagged bytes must not verify under the op or manifest tag.
2. `derive_cache_key(team_key)` must differ from `team_key` and from any other derivation over the same input, and must be deterministic.
3. `x25519_secret` must not be derivable from, or equal to, the sr25519 secret bytes; two identities with adjacent seeds must produce unrelated x25519 keys.

- [ ] **Step 2: run, mutation-verify, commit**

### Task D8: Surface quarantined authors to the operator

**This task contains an API change, not only a test.**

`quarantine_broken_chains` drops ops with a `tracing::warn!` and nothing else. `ReconcileReport` has no field for it. An attacker who forks one author's chain silently suppresses that author's tail, and no API surfaces it — so `doctor` and `reconcile` both report healthy.

**Files:**
- Modify: `hippius-mem-core/src/oplog/store.rs`, `hippius-mem-core/src/audit/reconcile.rs`, `hippius-mem/src/server.rs` (the `reconcile` tool description), `hippius-mem/src/doctor.rs`

**Interfaces:**
- Produces: `ReconcileReport.quarantined_authors: Vec<QuarantinedAuthor>` where `QuarantinedAuthor { author: Ss58, dropped_ops: usize }`; `ok` becomes false when it is non-empty.

- [ ] **Step 1: Write the failing test**

Fork one author's chain in a seeded bucket, run `reconcile`, and assert the report names that author with the dropped-op count and that `ok` is false.

- [ ] **Step 2: Run to verify it fails**

Expected: FAIL — no such field.

- [ ] **Step 3: Implement**

Have `quarantine_broken_chains` return the per-author drop counts, thread them to `ReconcileReport`, and include them in `ok`. Update the `reconcile` tool description to document the new evidence vector in the same honest style the existing SCOPE sentence uses. Add a `doctor` line reporting it.

- [ ] **Step 4: run, mutation-verify, commit**

```bash
git commit -m "feat(core): report quarantined authors from reconcile

A forked author chain silently drops that author's tail with only a
tracing::warn — no API surfaced it, so reconcile and doctor both reported
healthy while an attacker suppressed a member's history. ReconcileReport now
carries quarantined_authors and ok is false when it is non-empty."
```

### Task D9: The chain anchor readback

This was the audit's single highest-priority crypto finding and is the only place the product makes a trust-minimized claim. `Verification::ChainVerified` is the sole non-bucket-only attestation, and the reader that supplies its inputs — `SubxtAnchor::read_anchored_root` (`hippius-mem-core/src/audit/anchor.rs:385-489`) — has no test at all. Untested inside it: the finality gate (`:415`), the canonical-hash-at-height comparison that defends against a reorg (`:429`), and the `MultiAddress::Id` byte parsing every `ChainSignerMismatch` verdict depends on (`:472`). A subxt change to `address_bytes()` encoding would silently break attribution with CI green.

The node round-trip genuinely cannot run in CI. The byte parsing can, once it is separated from the I/O.

**Files:**
- Modify: `hippius-mem-core/src/audit/anchor.rs`

**Interfaces:**
- Produces: `fn decode_remark_signer(extrinsic_bytes: &[u8]) -> Result<Ss58, MemError>` and `fn decode_remark_payload(extrinsic_bytes: &[u8]) -> Result<Blake3Hash, MemError>` — pure functions, no `subxt` client, testable against committed SCALE fixtures.

- [ ] **Step 1: Read the reader and identify the pure core**

Read `anchor.rs:385-489`. Separate what needs a live client (fetching a block, asking for finality) from what is pure decoding of bytes already in hand (extracting the signer from `MultiAddress::Id`, extracting the remark payload). Only the latter moves.

- [ ] **Step 2: Write the failing test with committed fixtures**

```rust
    /// The signer and payload decode paths, exercised without a node.
    ///
    /// `read_anchored_root` is the ONLY trust-minimized claim in the product —
    /// every other verdict is bucket-only — and it had no test of any kind. The
    /// node round-trip cannot run in CI, but the byte parsing can, and the byte
    /// parsing is what a subxt upgrade would silently change: every
    /// `ChainSignerMismatch` verdict rests on `MultiAddress::Id` decoding
    /// exactly as it does today.
    ///
    /// The fixture is a captured SCALE-encoded `System::remark_with_event`
    /// extrinsic, committed as a hex constant. Do NOT regenerate it by calling
    /// the current encoder — that would re-encode under whatever the new
    /// behaviour is and could never catch a compat break (the same trap the
    /// TeamManifest v1 fixture documents).
    #[test]
    fn a_remark_extrinsic_decodes_to_its_signer_and_payload() -> TestResult {
        let bytes = hex_decode(REMARK_EXTRINSIC_FIXTURE)?;

        let signer = decode_remark_signer(&bytes)?;
        ensure_eq(
            &signer.as_str(),
            &REMARK_FIXTURE_SIGNER_SS58,
            "the decoded signer must match the account that submitted the fixture",
        )?;

        let payload = decode_remark_payload(&bytes)?;
        ensure_eq(
            &payload.to_hex(),
            &REMARK_FIXTURE_ROOT_HEX,
            "the decoded remark payload must be the anchored Merkle root",
        )
    }

    /// Truncated or foreign extrinsic bytes must be an error, never a panic and
    /// never a confidently wrong signer — a wrong signer here produces a false
    /// `ChainSignerMismatch`, which is an accusation.
    #[test]
    fn a_malformed_extrinsic_is_rejected_not_misread() -> TestResult {
        let bytes = hex_decode(REMARK_EXTRINSIC_FIXTURE)?;

        for cut in [1_usize, 4, 16, bytes.len() / 2, bytes.len() - 1] {
            let truncated = &bytes[..cut];
            ensure(
                decode_remark_signer(truncated).is_err(),
                &format!("a {cut}-byte prefix must not decode to a signer"),
            )?;
        }
        Ok(())
    }
```

**Obtaining the fixture:** capture one real `System::remark_with_event` extrinsic's bytes from the Hippius chain (or a local dev node) once, by hand, and paste them as a hex constant with a comment recording the block and account it came from. If capturing one is not possible now, construct it once with the current subxt encoder, paste the RESULT as a constant, and record in the comment that it was encoder-derived on 2026-08-09 — an encoder-derived fixture still catches a future encoding change, it just cannot prove today's encoding is right.

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p hippius-mem-core --features chain --lib anchor`
Expected: FAIL to compile — the two decode functions do not exist yet.

- [ ] **Step 4: Extract the pure functions and run**

Move the decoding out of `read_anchored_root` into the two functions, leaving the client call to fetch bytes and hand them over.

Run: `cargo test -p hippius-mem-core --features chain --lib anchor`
Expected: PASS.

- [ ] **Step 5: Mutation-verify**

Change the `MultiAddress` variant index the decoder expects and confirm the signer test fails. Restore.

- [ ] **Step 6: Correct the stale doc comment and commit**

`anchor.rs:289` claims the anchoring path "is exercised only by an `#[ignore]`d integration test" that does not exist. Say what is true: the decode paths are unit-tested against fixtures, and the live submission and finality gate remain CI-untested.

```bash
git add hippius-mem-core/src/audit/anchor.rs
git commit -m "test(audit): decode-path tests for the chain anchor readback

read_anchored_root underwrites Verification::ChainVerified, the only
trust-minimized claim in the product, and had no test at all. The node
round-trip cannot run in CI; the byte parsing can, and it is what a subxt
upgrade would silently change — every ChainSignerMismatch verdict rests on
MultiAddress::Id decoding as it does today.

Extracts decode_remark_signer/decode_remark_payload as pure functions and pins
them against a committed SCALE fixture. Also corrects a doc comment claiming an
ignored integration test exercises this path; no such test exists."
```

---

## Phase E — Adversarial deserialization

Every hostile input in the suite today is a hand-constructed Rust struct re-serialized to JSON. The untrusted bucket's actual primitive is arbitrary bytes at an attacker-chosen key, and no test feeds arbitrary bytes into any wire type's deserializer.

**Toolchain decision:** `cargo-fuzz` requires nightly Rust, and this workspace pins stable 1.97.1. The primary mechanism is therefore a proptest over arbitrary bytes, which runs in the normal suite on the pinned toolchain. A nightly `cargo-fuzz` job is optional follow-up, not a prerequisite.

### Task E1: Byte-level proptest over every wire type

**Files:**
- Create: `hippius-mem-core/tests/wire_fuzz.rs`

- [ ] **Step 1: Write the test**

```rust
//! Arbitrary bytes into every deserializer that reads from the untrusted
//! bucket. The contract is total: any input either parses to a value that then
//! FAILS verification, or is rejected — never a panic, never an accepted forgery.
//!
//! Everything else in the suite hands these types hand-built Rust structs
//! re-serialized to JSON. The bucket's real primitive is arbitrary bytes at an
//! attacker-chosen key, and nothing tested that.
//!
//! `cargo-fuzz` needs nightly and this workspace pins stable 1.97.1, so the
//! mechanism is proptest over byte vectors: it runs in the normal suite on the
//! pinned toolchain, every PR, with a shrinking counterexample on failure.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// An `Op` decoded from arbitrary bytes must never panic, and must never
    /// arrive already-verified: anything that parses must still fail
    /// `verify_sig` unless it carries a genuine signature.
    #[test]
    fn arbitrary_bytes_never_yield_a_verified_op(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(op) = serde_json::from_slice::<hippius_mem_core::Op>(&bytes) {
            prop_assert!(!op.verify_sig(), "arbitrary bytes must not produce a verifying op");
        }
    }

    /// The same for the manifest, whose `verify()` is the team's authorization root.
    #[test]
    fn arbitrary_bytes_never_yield_a_verified_manifest(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(manifest) = serde_json::from_slice::<hippius_mem_core::TeamManifest>(&bytes) {
            prop_assert!(!manifest.verify(), "arbitrary bytes must not produce a verifying manifest");
        }
    }
}
```

Add equivalent properties for `WrappedKey` and `AnchorRecord`. For sealed types whose "verification" is an AEAD open, assert `open` with a fixed key returns `Err` rather than panicking.

**Structured-input note:** pure random bytes rarely parse as JSON, so also add a *structurally* biased strategy — take a valid serialized value and mutate k random bytes within it — so the properties actually reach the verification code rather than bouncing off the JSON parser. Assert the same invariant for both strategies, and state in the doc comment which one reaches which depth.

- [ ] **Step 2: Run to verify it passes**

Run: `cargo test -p hippius-mem-core --test wire_fuzz`
Expected: PASS. If a case FAILS, proptest prints a shrunk counterexample — that is a real finding about a wire type accepting hostile bytes, not a test to relax.

- [ ] **Step 3: Confirm the properties reach real code**

Add a temporary counter (or a `dbg!`) recording how many generated inputs actually deserialized. If the pure-random strategy parses essentially never, the biased mutate-a-valid-value strategy is doing all the work — record that honestly in the doc comment rather than implying both strategies reach the verifier.

- [ ] **Step 4: Mutation-verify**

Make `Op::verify_sig` return `true` unconditionally and confirm `arbitrary_bytes_never_yield_a_verified_op` fails. Restore.

- [ ] **Step 5: fmt, clippy, commit**

### Task E2: Optional nightly `cargo-fuzz` job

- [ ] **Step 1: Decide and record**

If the team accepts a nightly toolchain in a nightly-only job, add `fuzz/` targets for the same four types with a 5-minute-per-target budget in `.github/workflows/nightly.yml`. If not, record the decision in `docs/SECURITY.md` beside the threat model so the absence is deliberate and visible, and close this task.

---

## Phase F — Finish real-backend coverage

PR #76 added the MinIO job. Three paths still have no coverage against a real endpoint.

### Task F1: `doctor` against a real S3 profile

`doctor`'s `probe_live` has a test for the Local branch only. The S3 branch is what the onboarding funnel tells every new customer to run, and a previous bug there is already recorded in the code comments.

**Files:**
- Modify: `hippius-mem/tests/upgrade_cli.rs` or a new `hippius-mem/tests/doctor_s3.rs`
- Modify: `.github/workflows/rust.yml` (the MinIO job)

- [ ] **Step 1: Write the `#[ignore]`d test**

After the existing upgrade round-trip leaves a populated S3 profile, run the real binary's `doctor` against it and assert a healthy report and a zero exit code. Then corrupt the credential and assert `doctor` fails loudly rather than reporting healthy.

- [ ] **Step 2: Add it to the MinIO job, run locally against MinIO, commit**

Local MinIO for verification:
```sh
mkdir -p /tmp/minio-data/mem-test
MINIO_ROOT_USER=test MINIO_ROOT_PASSWORD=testtest1 minio server /tmp/minio-data --address 127.0.0.1:9000
```

### Task F2: `TeamProfile::build_store`'s S3 branch

The integration tests hand-build their store because the binary crate's `Config`/`TeamProfile` are private, so the production wiring — anchor, pinned founder, manifest marker, cache key — can diverge from the tested wiring invisibly.

**Files:**
- Modify: `hippius-mem/src/config.rs`

- [ ] **Step 1: Write the test**

An in-crate test (where `TeamProfile` is visible) that builds an S3 profile pointed at the MinIO endpoint, calls `build_store`, and asserts a remember/sync/get round trip. `#[ignore]`d, added to the MinIO job.

- [ ] **Step 2: run against MinIO, mutation-verify (drop the pinned founder from the built store and confirm failure), commit**

### Task F3: S3 list pagination past the continuation boundary

`S3BlobStore::list`'s pagination is covered by two `aws-smithy-mocks` tests, including the gateway's missing-`IsTruncated` shape. It has never run against a real endpoint with enough objects to paginate.

**Files:**
- Modify: `hippius-mem-core/tests/blob_contract.rs`

- [ ] **Step 1: Write the `#[ignore]`d test**

Put 1,050 small objects under one prefix, list them, and assert all 1,050 come back in lexicographic order. Clear the prefix before and after, like the other S3 contract tests.

- [ ] **Step 2: run against MinIO, add to the MinIO job, commit**

---

## Phase G — Finish retrieval quality

### Task G1: The semantic dedup path

The cosine dedup path has zero coverage: the only `embeddings`-gated e2e sets `force: true` on every remember and bypasses the gate entirely. PR #76 corrected the comment that claimed otherwise; this closes the gap itself.

**Files:**
- Modify: `hippius-mem-core/tests/retrieval_quality.rs`

- [ ] **Step 1: Write the `#[ignore]`d test**

With the real embedder: remember a note, then remember a PARAPHRASE with `force: false` and assert it is refused as a near-duplicate; then remember a genuinely distinct note and assert it is accepted. This is the semantic analogue of the lexical boundary test PR #76 added.

- [ ] **Step 2: run with `--features embeddings`, mutation-verify, commit**

### Task G2: Measure the lean-versus-embeddings delta

The product ships two builds with materially different recall, and the difference is measured nowhere. The lean build is what Intel macOS gets and what `cargo test` exercises.

**Files:**
- Modify: `hippius-mem-core/tests/retrieval_quality.rs`

- [ ] **Step 1: Write the test**

Over the shared calibration corpus, compute recall@floor for the lexical `HashEmbedder` and for the real model, and assert the documented relationship: the lexical build recovers strictly fewer paraphrase targets. Print both numbers with `--nocapture` so the nightly log carries the current delta.

- [ ] **Step 2: Feed the measured numbers back into `docs/SECURITY.md`**

Replace any prose figure that disagrees with the measurement. The docs and the test must not state different numbers.

- [ ] **Step 3: run, commit**

---

## Phase H — Tooling that prevents the regression

Everything above was found by hand-mutating source. That should not be how the next gap is found.

### Task H1: Coverage reporting

**Files:**
- Create/modify: `.github/workflows/nightly.yml`

- [ ] **Step 1: Add a `cargo-llvm-cov` job**

Nightly, all features, producing an lcov summary in the job log and a run artifact. **Report only — do not add a coverage percentage gate.** A percentage target rewards testing easy code; this plan's whole finding is that the untested code was the code that mattered.

- [ ] **Step 2: Record the first measurement in `docs/perf/` or the plan's completion note, so later runs have a baseline**

### Task H2: Mutation testing

**Files:**
- Modify: `.github/workflows/nightly.yml`

- [ ] **Step 1: Add a `cargo-mutants` job scoped to the modules that matter**

Scope to `hippius-mem-core/src/{index,oplog,identity,audit,store}` with a per-run timeout. Full-workspace mutation testing is too slow for a nightly; these are the modules whose correctness the product rests on.

- [ ] **Step 2: Triage the first run and record the surviving mutants**

Expect survivors. File them as follow-up tasks rather than fixing all of them in this task — the goal is a standing signal, not a one-time cleanup.

### Task H3: Performance regression signal

The criterion benches (`recall`, `history`, `sync_cold_rebuild`) are deterministic and have a documented 2026-06-27 baseline, but no job runs them, so a slowdown reaches production silently.

**Files:**
- Modify: `.github/workflows/nightly.yml`

- [ ] **Step 1: Add a nightly bench run**

`cargo bench -p hippius-mem-core` with results uploaded as an artifact. Criterion's own comparison against its saved baseline is the signal; do not fail the build on variance from a noisy hosted runner. State that explicitly in the job comment so nobody later mistakes the job for a gate.

---

---

## Deliberately not covered by this plan

Named explicitly so they are decisions rather than oversights. Each one was in the audit findings and is being left open on purpose.

**Live chain submission and the finality gate.** Task D9 covers the decode paths against fixtures. Actually submitting a `remark_with_event` and reading it back past finality needs a funded account on a reachable node, which no CI job can have. `SubxtAnchor::anchor` and the finality/canonical-hash checks stay CI-untested; `anchor.rs:371` already says so and must keep saying so.

**Live Hippius gateway.** The MinIO job proves S3 *protocol* conformance. It does not prove the Hippius gateway specifically behaves like MinIO — and the missing-`IsTruncated` bug is evidence the two differ. Closing this needs a staging bucket and a credential in CI; until then `s3_round_trips_against_live_gateway` stays `#[ignore]`d and the risk stays real.

**Multi-process and power-cut crash recovery.** Every durability test injects faults in-process. A real power cut mid-`fsync` is not reproducible in a hosted runner, and `store/fs.rs:428-430` already concedes this in a comment. Simulating it properly needs a filesystem fault injector (dm-flakey or similar) and is out of proportion to the risk here.

**Release artifact build on pull requests.** `dist-workspace.toml` sets no `pr-run-mode`, so the four release artifacts — including the `embeddings,dashboard` binary users actually download and the Intel-mac lean build — are only built on a version tag. Turning on `pr-run-mode = "plan"` would at least validate the plan on every PR without paying the full build. This is a small change with real value, deliberately left out of this plan because it belongs to the release workstream, not the test workstream. Raise it there.

**A coverage percentage gate.** Task H1 reports coverage and deliberately does not gate on it. This entire plan exists because the untested code was the code that mattered, not because a percentage was low; a threshold would reward the opposite behaviour.

**IDF and document-length normalization in `keyword_score`.** The function drops both, which is a real departure from textbook BM25. PR #76's ranking test pins that more matched query terms wins, and the existing saturation test pins term-frequency behaviour, but nothing asserts what dropping IDF costs. That is a design question — whether to reintroduce IDF — not a test gap, and should be answered before a test pins the current choice as intended.

## Completion

After all phases merge:

1. Re-run the four coverage audits from 2026-08-09 against the new tree and record which findings are closed. Any that remain open should be listed explicitly in `docs/SECURITY.md` beside the threat model, so the gaps that are deliberate are visible rather than merely unmentioned.
2. `mcp__hippius-mem__remember` the durable outcomes: the stable-toolchain fuzzing decision (Phase E), the snapshot body cross-check (C7), and the quarantine reporting API (D8).
3. Update this plan's status line and the PR #76 "Known gaps this does NOT close" list, which is the current public statement of what is untested.
