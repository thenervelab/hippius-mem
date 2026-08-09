//! The binary spoken to exactly as a real client speaks to it: JSON-RPC over
//! its own stdio, in its own process — not the in-process router
//! (`tests/mcp_protocol.rs`) and not the `logic_*` functions the unit tests
//! call.
//!
//! `main.rs`'s `server.serve(stdio())` had no test at any level. The failure
//! this guards is specific and has bitten other MCP servers: anything that
//! writes to stdout outside the protocol — a stray `println!`, a progress
//! bar, a dependency's banner — corrupts the JSON-RPC stream and breaks
//! every client, while every in-process test (which never touches the real
//! transport) stays green.
//!
//! The test below completes a REAL handshake, not just a probe of the first
//! reply: `initialize`, then the `initialized` notification the MCP spec
//! requires before a client may issue further requests, then `tools/list` —
//! asserting all ten tools come back, tying this test to the same contract
//! `tests/mcp_protocol.rs`'s committed snapshot pins. A test that stopped at
//! `initialize` alone would not have earned a name claiming the handshake was
//! completed.
//!
//! # Hang safety
//!
//! `cargo test` has no per-test timeout, and this machine has no `timeout(1)`
//! binary, so a test that blocks forever wedges the entire run with no way to
//! interrupt it short of killing the whole process tree. A plain, synchronous
//! `BufReader::read_line` on the child's stdout is exactly that hazard: if
//! the binary never emits a line (a quiet boot failure, or a regression that
//! makes it wait for more input before replying), the read blocks forever.
//!
//! Every read here instead happens on a background thread that streams lines
//! to the test thread over an `mpsc` channel, read with
//! [`mpsc::Receiver::recv_timeout`] against [`STDOUT_LINE_DEADLINE`] — a
//! bound, not an estimate of the happy path (a warm local run answers
//! `initialize` in well under 100ms; twenty seconds leaves headroom for a
//! cold `cargo test` binary under CI load without letting a real hang run
//! indefinitely). `stderr` is drained on its own thread into a shared buffer
//! for the same reason: a server that logs anything at boot fills the pipe's
//! kernel buffer once nobody reads it, and a full pipe blocks the writer —
//! that failure mode is indistinguishable from a hang without a dedicated
//! drain, and the captured text is what turns a bare timeout into a
//! diagnosable failure. [`ChildGuard`] kills and reaps the process on
//! `Drop` so neither an early `?` return nor an assertion panic (both of
//! which unwind through this scope) can leak a zombie or an orphaned server.
//!
//! # Network safety under `--all-features`
//!
//! CI's `test-all-features` job runs `cargo test --all --all-features
//! --locked`, which builds this binary with the `embeddings` feature. Two
//! facts about that build matter here, both confirmed by reading the source
//! (`hippius-mem/src/config.rs`) and by an empirical probe, not assumed:
//!
//! 1. `Config`'s `semantic_embeddings` field is `#[serde(default)]` at the
//!    struct level, and `Config::default()` sets it to `cfg!(feature =
//!    "embeddings")`. So a config that omits the key resolves it to `true`
//!    under an `--all-features` build.
//! 2. Unlike the op-log sync — which `main.rs` deliberately backgrounds in a
//!    `tokio::spawn` task so the MCP handshake never waits on it — the
//!    embedder itself is built SYNCHRONOUSLY, before the handshake, inside
//!    `resolve_and_build_store` -> `TeamProfile::build_store` ->
//!    `Config::build_embedder`. When `semantic_embeddings` is `true` and the
//!    feature is compiled in, that call constructs a real `FastEmbedder`,
//!    which downloads the ONNX model into the process's cache directory on
//!    first construction. Measured directly against this binary (built
//!    `--features embeddings`, isolated `HOME`): a single `quickstart` run
//!    downloaded 128 MB in ~17s on this machine's network. A CI job must
//!    never depend on that succeeding, still less on it succeeding within
//!    this test's bounded stdout-line deadline.
//!
//! The fix used here: the seeded config below sets `semantic_embeddings =
//! false` EXPLICITLY, so the server always constructs the deterministic
//! `HashEmbedder` fallback regardless of which features this binary was
//! built with — no network access, no timing dependency, in either CI job.
//!
//! This is also why the config is written directly by this test rather than
//! by shelling out to the real `quickstart` subcommand the way
//! `tests/quickstart_cli.rs` seeds its fixtures: `quickstart`'s own store
//! build (`hippius-mem/src/quickstart.rs`'s `probe_fresh_trial`) resolves its
//! config via `Config::from_toml_str`, which — unlike `serve`'s
//! `Config::from_env_and_file` — never applies `HIPPIUS_MEM_*` environment
//! overrides. Confirmed empirically: setting `HIPPIUS_MEM_SEMANTIC_EMBEDDINGS=0`
//! around a `quickstart --no-wire` invocation built `--features embeddings`
//! did NOT prevent the model download. Seeding via `quickstart` would only be
//! safe here if `quickstart` itself grew a way to write `semantic_embeddings
//! = false`, which it does not. The config below still uses exactly the field
//! set `quickstart`'s `TrialDoc` writes (`team`, `team_key_hex`,
//! `author_seed_hex`, `storage`, `local_root`) plus this one addition, so it
//! is not an invented format — it is that format, serialized the same way
//! (`toml::to_string`), with the one field this test needs pinned explicitly.
//!
//! # The subcommand is not `serve`
//!
//! `hippius-mem/src/main.rs` has no `"serve"` match arm anywhere in its
//! dispatch chain; passing `serve` as `argv[1]` hits the final `unknown
//! subcommand` bail path and exits immediately (see `USAGE`: "hippius-mem
//! start the MCP stdio server (requires config)" — no subcommand named). The
//! MCP server starts on a BARE invocation, no arguments at all.
//!
//! # No stdout-pollution bug found
//!
//! Grepped `hippius-mem/src`/`hippius-mem-core/src` for `println!`/`print!`/
//! `dbg!`/direct `io::stdout()` writes reachable from the `serve` boot path
//! (as opposed to the one-shot subcommands, which are never reached on a bare
//! invocation): none exist outside the `help`/`--version` arms, which this
//! test never takes. `main`'s `tracing_subscriber` is wired to stderr
//! explicitly. Empirically confirmed too: a manual probe against the real
//! debug binary produced exactly one line of stdout — the `initialize`
//! reply — for the whole boot-through-handshake sequence. This test still
//! asserts on it (Step 3 of the original brief) so a future regression is
//! caught here rather than by a client in the field.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use std::io::{BufRead as _, Write as _};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::json;

/// How long to wait for a single line on the child's stdout. Generous for a
/// cold `cargo test` binary spawn under CI load, bounded so a genuine hang —
/// including a future regression that reintroduces a synchronous network
/// call ahead of the handshake — fails this one test instead of wedging the
/// whole `cargo test` run. See the module docs' "Hang safety" section.
const STDOUT_LINE_DEADLINE: Duration = Duration::from_secs(20);

/// A fixed 32-byte team key, hex-encoded — not a real secret, just a
/// well-formed fixture for a throwaway local trial vault this test creates
/// and discards.
const TEAM_KEY_HEX: &str = "24acd7ca317cb31b657364ac6aa260e1a3ed469a2c296973ad21d5b42e0b1835";

/// A second, independent fixture seed for `author_seed_hex` — deliberately
/// distinct from [`TEAM_KEY_HEX`], mirroring `quickstart`'s own invariant
/// that the two are independent draws.
const AUTHOR_SEED_HEX: &str = "65e2d246684f2abdc3bf908cae0896b5900d1d873d6f8a39a29bbf14f425c2c5";

/// Kills and reaps the wrapped child on drop, so an early `?` return or an
/// assertion panic — both of which unwind through this scope — can never
/// leak a running process or a zombie. Errors from `kill`/`wait` are
/// discarded: by the time `Drop` runs the process may already be gone (this
/// test also closes stdin on its own successful path, which the server reads
/// as EOF and exits on), and there is nothing more useful to do with a
/// teardown failure than ignore it.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The same field set `hippius-mem quickstart` writes for a
/// `storage = "local"` trial profile (see `hippius-mem/src/quickstart.rs`'s
/// `TrialDoc`), plus `semantic_embeddings = false`. See the module docs'
/// "Network safety" section for why that addition is required here and why
/// it cannot be supplied by an environment variable instead.
#[derive(serde::Serialize)]
struct TrialConfig<'a> {
    team: &'a str,
    team_key_hex: &'a str,
    author_seed_hex: &'a str,
    storage: &'a str,
    local_root: &'a std::path::Path,
    semantic_embeddings: bool,
}

/// Write a validated, minimal local-trial config at `config_path` whose
/// vault lives under `local_root`.
fn seed_trial_config(
    config_path: &std::path::Path,
    local_root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let doc = TrialConfig {
        team: "trial",
        team_key_hex: TEAM_KEY_HEX,
        author_seed_hex: AUTHOR_SEED_HEX,
        storage: "local",
        local_root,
        semantic_embeddings: false,
    };
    std::fs::write(config_path, toml::to_string(&doc)?)?;

    Ok(())
}

/// Spawn a background thread that reads lines from `stdout` and forwards
/// each one over the returned channel. Owning the blocking read on its own
/// thread — rather than calling `read_line` on the test thread — is what
/// lets the caller bound the wait with `recv_timeout` instead of blocking
/// indefinitely.
fn spawn_line_reader(stdout: std::process::ChildStdout) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
        // `tx` drops here (EOF or a broken channel), which is what turns a
        // subsequent `recv_timeout` into `Disconnected` instead of hanging.
    });

    rx
}

/// Spawn a background thread that continuously drains `stderr` into a
/// shared buffer the caller can read at any time (not only after the child
/// exits), so a timeout failure can report exactly what the server logged
/// before it stopped responding. Never blocks the caller: if the server logs
/// enough at boot to fill the pipe's kernel buffer, this thread is what keeps
/// draining it so the server's write does not block — starving stderr would
/// otherwise be a second, indistinguishable-from-a-hang failure mode.
fn spawn_stderr_drain(stderr: std::process::ChildStderr) -> Arc<Mutex<String>> {
    let captured = Arc::new(Mutex::new(String::new()));
    let writer = Arc::clone(&captured);

    thread::spawn(move || {
        let reader = std::io::BufReader::new(stderr);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let Ok(mut buf) = writer.lock() else { break };
            buf.push_str(&line);
            buf.push('\n');
        }
    });

    captured
}

/// Snapshot whatever `stderr_captured` holds right now, for inclusion in a
/// failure message. Lock poisoning (the drain thread panicking) degrades to
/// an empty string rather than propagating — a missing diagnostic must never
/// mask the real assertion failure that is already in flight.
fn captured_stderr(stderr_captured: &Arc<Mutex<String>>) -> String {
    stderr_captured
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

/// Wait up to [`STDOUT_LINE_DEADLINE`] for one line on `rx`. On timeout or a
/// closed channel, kill `child` immediately (no reason to let a doomed
/// process keep running for the rest of the test) and fail with a message
/// naming what was expected and everything `stderr` captured in the
/// meantime.
fn recv_line_or_fail(
    rx: &mpsc::Receiver<String>,
    child: &mut ChildGuard,
    stderr_captured: &Arc<Mutex<String>>,
    what: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match rx.recv_timeout(STDOUT_LINE_DEADLINE) {
        Ok(line) => Ok(line),
        Err(RecvTimeoutError::Timeout) => {
            let _ = child.0.kill();
            Err(format!(
                "the binary produced no {what} within {STDOUT_LINE_DEADLINE:?}; \
                 stderr captured so far:\n{}",
                captured_stderr(stderr_captured)
            )
            .into())
        }
        Err(RecvTimeoutError::Disconnected) => {
            let _ = child.0.kill();
            Err(format!(
                "the binary closed stdout before producing {what}; \
                 stderr captured so far:\n{}",
                captured_stderr(stderr_captured)
            )
            .into())
        }
    }
}

/// The binary, spoken to as a real client speaks to it: `initialize`, the
/// `initialized` notification, then `tools/list` — asserting all ten tools
/// come back over the real stdio transport `server.serve(stdio())` runs.
///
/// Mutation-verified: see the commit message for the exact mutation (a
/// temporary `println!` ahead of the handshake) and its failure.
#[test]
fn the_binary_completes_the_mcp_handshake_and_advertises_ten_tools_over_stdio()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");
    let vault_root = dir.path().join("vault");
    std::fs::create_dir_all(&vault_root)?;
    seed_trial_config(&config_path, &vault_root)?;

    // No `serve` argument: the MCP server starts on a bare invocation (see
    // the module docs' "The subcommand is not `serve`" section).
    // `current_dir` and the isolated `HOME`/`XDG_DATA_HOME`/config path keep
    // this test from ever touching the real developer machine's git remote,
    // config, or trial vault.
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("HIPPIUS_MEM_CONFIG", &config_path)
            .env_remove("XDG_CACHE_HOME")
            .env_remove("HIPPIUS_MEM_MNEMONIC")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );

    let stdout = child.0.stdout.take().ok_or("child stdout was not piped")?;
    let stderr = child.0.stderr.take().ok_or("child stderr was not piped")?;
    let mut stdin = child.0.stdin.take().ok_or("child stdin was not piped")?;

    let stderr_captured = spawn_stderr_drain(stderr);
    let stdout_lines = spawn_line_reader(stdout);

    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "hippius-mem-test", "version": "0" }
        }
    });
    writeln!(stdin, "{initialize}")?;
    stdin.flush()?;

    let reply_line = recv_line_or_fail(
        &stdout_lines,
        &mut child,
        &stderr_captured,
        "an initialize reply",
    )?;
    let reply: serde_json::Value = serde_json::from_str(reply_line.trim()).map_err(|e| {
        format!(
            "the FIRST line of stdout must be JSON-RPC, not log or banner \
             output: {e}; got {reply_line:?}"
        )
    })?;
    assert_eq!(
        reply["jsonrpc"], "2.0",
        "handshake reply must be JSON-RPC 2.0: {reply}"
    );
    assert_eq!(
        reply["id"], 1,
        "reply must correlate to the request id: {reply}"
    );
    assert!(
        reply["result"]["serverInfo"]["name"].is_string(),
        "initialize must return serverInfo: {reply}"
    );

    // Complete the handshake for real: a client must send `initialized`
    // before issuing further requests. It is a notification — no `id`, and
    // the server sends no reply — so nothing is read back here.
    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    writeln!(stdin, "{initialized}")?;
    stdin.flush()?;

    let list_tools = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    writeln!(stdin, "{list_tools}")?;
    stdin.flush()?;

    let list_line = recv_line_or_fail(
        &stdout_lines,
        &mut child,
        &stderr_captured,
        "a tools/list reply",
    )?;
    let list_reply: serde_json::Value = serde_json::from_str(list_line.trim())
        .map_err(|e| format!("the tools/list reply must be JSON-RPC: {e}; got {list_line:?}"))?;
    assert_eq!(
        list_reply["id"], 2,
        "tools/list reply must correlate to its request id: {list_reply}"
    );

    let tools = list_reply["result"]["tools"]
        .as_array()
        .ok_or_else(|| format!("tools/list must return a tools array: {list_reply}"))?;
    assert_eq!(
        tools.len(),
        10,
        "the real binary must advertise all ten memory tools over stdio: {list_reply}"
    );

    Ok(())
}
