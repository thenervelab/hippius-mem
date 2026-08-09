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
//! transport) stays green. Direct inspection found nothing on this boot path
//! currently does that (`main`'s tracing goes to stderr, and every stray
//! `io::stdout()` write in this crate belongs to a one-shot subcommand never
//! reached by a bare invocation; see the task report for the full grep) —
//! this test is what keeps that true going forward.
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
//! interrupt it short of killing the whole process tree. Every blocking read
//! here runs on its own background thread instead of the test thread, so the
//! test thread only ever waits on a bounded [`mpsc::Receiver::recv_timeout`]:
//! [`STDOUT_LINE_DEADLINE`] for a stdout line, [`STDERR_DRAIN_GRACE`] for the
//! stderr snapshot that decorates a failure. `stderr` is drained continuously
//! on its own thread too: an undrained piped stderr fills its kernel buffer
//! once the server logs anything at boot, and a full pipe blocks the writer —
//! a second hang indistinguishable from the first. [`ChildGuard`] kills and
//! reaps the process on `Drop`, so neither an early `?` return nor an
//! assertion panic (both of which unwind through this scope) can leak a
//! zombie or an orphaned server. Worst case — both deadlines on both
//! reads all expiring — this test still terminates in well under a minute.
//!
//! # Network safety
//!
//! Boot is not network-free by default. This test pins three things to keep
//! it that way:
//!
//! 1. `resolve_and_build_store` builds the embedder SYNCHRONOUSLY, ahead of
//!    the handshake (unlike the op-log sync, which `main.rs` explicitly
//!    backgrounds so the handshake never waits on it). `Config::
//!    semantic_embeddings` defaults to `cfg!(feature = "embeddings")`, so an
//!    omitted key downloads the ONNX model on first construction under an
//!    `--all-features` build — tens of seconds and well over a hundred MB on
//!    a real run (see the task report for the measured figure; a
//!    machine-specific number does not belong in source). The seeded config
//!    below sets `semantic_embeddings = false`.
//! 2. `Config::build_anchor` (`hippius-mem/src/config.rs:781-796`) is a
//!    SECOND synchronous pre-handshake network call, gated on `chain_ws_url`
//!    under the `chain` feature. Safe here only because the seeded config
//!    omits that key — do not add one without reconsidering this test.
//! 3. Both of those are settings the seeded config file controls, and
//!    `main`'s bare-invocation boot path loads config via
//!    `Config::from_env_and_file`, which overlays every `HIPPIUS_MEM_*`
//!    variable found in the process's OWN environment on top of that file —
//!    env wins (`config.rs:376-464`). Left alone, the invoking shell's own
//!    `HIPPIUS_MEM_SEMANTIC_EMBEDDINGS` or `HIPPIUS_MEM_CHAIN_WS_URL` would
//!    silently reopen either hazard above. The spawn below strips every
//!    `HIPPIUS_MEM_*` key from the inherited environment first, rather than
//!    allowlisting the couple of names known today — a per-variable fix
//!    would reopen with the next key `Config::apply_overrides` learns to
//!    read.
//!
//! With all three pinned, this test never touches the network — confirmed
//! empirically (see the task report) at well under a second under
//! `--all-features`. It does NOT, however, exercise the boot path a shipped
//! release binary (`embeddings` + `dashboard`) actually takes:
//! `FastEmbedder` construction ahead of the handshake remains untested at
//! every level in this repo. Disabling it here is still the correct call —
//! a CI job must not depend on a large, unbounded download — but that
//! coverage gap is real, not merely deferred to another file.
//!
//! This is also why the config below is written directly by this test
//! rather than by shelling out to the real `quickstart` subcommand the way
//! `tests/quickstart_cli.rs` seeds its fixtures: `quickstart`'s own store
//! build resolves its config via `Config::from_toml_str`, which — unlike
//! `from_env_and_file` — applies no environment overlay at all, so an env
//! var cannot patch its safety the way it can for a bare `serve` invocation.
//! The config below uses exactly the field set `quickstart`'s own
//! `TrialDoc` writes (`team`, `team_key_hex`, `author_seed_hex`, `storage`,
//! `local_root`, via `toml::to_string`) plus the one field this test needs
//! pinned explicitly.
//!
//! # The subcommand is not `serve`
//!
//! `hippius-mem/src/main.rs` has no `"serve"` match arm anywhere in its
//! dispatch chain; passing `serve` as `argv[1]` hits the final `unknown
//! subcommand` bail path and exits immediately (see `USAGE`: "hippius-mem
//! start the MCP stdio server (requires config)" — no subcommand named). The
//! MCP server starts on a BARE invocation, no arguments at all.

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

/// How long to give the stderr-drain thread to catch up, after the child has
/// been killed, before a failure message snapshots whatever it captured.
/// Short and bounded on purpose: once the child is dead its own end of the
/// pipe closes almost immediately in the common case, so this only needs to
/// absorb ordinary thread-scheduling jitter, not the child's remaining
/// lifetime. See [`StderrDrain::snapshot_after_grace`] for why this cannot
/// be an unconditional join instead.
const STDERR_DRAIN_GRACE: Duration = Duration::from_millis(500);

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
/// it cannot be supplied by an environment variable alone.
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

/// A background thread continuously draining the child's `stderr` into a
/// shared buffer, paired with a completion signal so a failure message can
/// know whether that buffer is final before it snapshots one.
struct StderrDrain {
    captured: Arc<Mutex<String>>,
    done: mpsc::Receiver<()>,
}

impl StderrDrain {
    /// Snapshot the captured text after giving the drain thread up to
    /// [`STDERR_DRAIN_GRACE`] to finish, closing the race where the stdout
    /// reader sees EOF (or a write to stdin fails) before the drain thread
    /// has consumed a fatal error line the server already flushed. Bounded,
    /// not joined: a grandchild that inherited the write end of the stderr
    /// pipe could hold it open forever, which an unconditional join would
    /// wait on — exactly the hang correction 2 (see the module docs) removed
    /// from the stdout side. A timed-out grace period still returns
    /// whatever has been captured so far, since the buffer is updated
    /// incrementally, not only at completion.
    fn snapshot_after_grace(&self) -> String {
        let _ = self.done.recv_timeout(STDERR_DRAIN_GRACE);
        self.captured
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

/// Spawn a background thread that continuously drains `stderr` into a
/// shared buffer the caller can read at any time (not only after the child
/// exits), so a timeout failure can report exactly what the server logged
/// before it stopped responding. Never blocks the caller: if the server logs
/// enough at boot to fill the pipe's kernel buffer, this thread is what keeps
/// draining it so the server's write does not block — starving stderr would
/// otherwise be a second, indistinguishable-from-a-hang failure mode.
fn spawn_stderr_drain(stderr: std::process::ChildStderr) -> StderrDrain {
    let captured = Arc::new(Mutex::new(String::new()));
    let writer = Arc::clone(&captured);
    let (done_tx, done_rx) = mpsc::channel();

    thread::spawn(move || {
        let reader = std::io::BufReader::new(stderr);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let Ok(mut buf) = writer.lock() else { break };
            buf.push_str(&line);
            buf.push('\n');
        }
        // An explicit completion signal, not just the sender's eventual
        // drop: `snapshot_after_grace` reads intent more directly this way,
        // and behaves identically either way once the receiver is waiting.
        let _ = done_tx.send(());
    });

    StderrDrain {
        captured,
        done: done_rx,
    }
}

/// Wait up to [`STDOUT_LINE_DEADLINE`] for one line on `rx`. On timeout or a
/// closed channel, kill `child` immediately (no reason to let a doomed
/// process keep running for the rest of the test) and fail with a message
/// naming what was expected and everything `stderr` captured in the
/// meantime.
fn recv_line_or_fail(
    rx: &mpsc::Receiver<String>,
    child: &mut ChildGuard,
    stderr: &StderrDrain,
    what: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match rx.recv_timeout(STDOUT_LINE_DEADLINE) {
        Ok(line) => Ok(line),
        Err(RecvTimeoutError::Timeout) => {
            let _ = child.0.kill();
            Err(format!(
                "the binary produced no {what} within {STDOUT_LINE_DEADLINE:?}; \
                 stderr captured so far:\n{}",
                stderr.snapshot_after_grace()
            )
            .into())
        }
        Err(RecvTimeoutError::Disconnected) => {
            let _ = child.0.kill();
            Err(format!(
                "the binary closed stdout before producing {what}; \
                 stderr captured so far:\n{}",
                stderr.snapshot_after_grace()
            )
            .into())
        }
    }
}

/// Write one JSON-RPC line to the child's stdin and flush it, folding a bare
/// `io::Error` (e.g. "Broken pipe" when the child has already died) into the
/// same stderr-attaching diagnostic [`recv_line_or_fail`] produces, rather
/// than surfacing a context-free `?` propagation.
///
/// Safe against the pipe-buffer deadlock this file's whole design exists to
/// avoid: every message this test sends totals under 300 bytes (the
/// largest single write, `initialize`, is ~160 bytes) — far under the
/// smallest POSIX guarantee (`PIPE_BUF`, 512 bytes atomically) and far under
/// any real kernel pipe buffer (at least 4 KiB, typically 16-64 KiB), so a
/// single `write` here can never block waiting for a reader. A future edit
/// that sends a large payload (a multi-KB `tools/call` body, say) must not
/// assume that still holds.
fn send_line(
    stdin: &mut std::process::ChildStdin,
    value: &serde_json::Value,
    child: &mut ChildGuard,
    stderr: &StderrDrain,
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = writeln!(stdin, "{value}").and_then(|()| stdin.flush());

    if let Err(err) = sent {
        let _ = child.0.kill();
        return Err(format!(
            "writing {value} to the child's stdin failed: {err}; stderr \
             captured so far:\n{}",
            stderr.snapshot_after_grace()
        )
        .into());
    }

    Ok(())
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

    // `Config::from_env_and_file` overlays every `HIPPIUS_MEM_*` variable
    // found in THIS process's own environment on top of the seeded file
    // below, env winning — see the module docs' "Network safety" section,
    // point 3. Strip the whole family before setting the handful this test
    // needs, rather than allowlisting the couple of names known today.
    let mut command = Command::new(env!("CARGO_BIN_EXE_hippius-mem"));
    for (name, _) in std::env::vars_os() {
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("HIPPIUS_MEM_"))
        {
            command.env_remove(name);
        }
    }

    // No `serve` argument: the MCP server starts on a bare invocation (see
    // the module docs' "The subcommand is not `serve`" section).
    // `current_dir` and the isolated `HOME`/`XDG_DATA_HOME`/config path keep
    // this test from ever touching the real developer machine's git remote,
    // config, or trial vault.
    command
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env_remove("XDG_CACHE_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = ChildGuard(command.spawn()?);

    let stdout = child.0.stdout.take().ok_or("child stdout was not piped")?;
    let stderr = child.0.stderr.take().ok_or("child stderr was not piped")?;
    let mut stdin = child.0.stdin.take().ok_or("child stdin was not piped")?;

    let stderr_drain = spawn_stderr_drain(stderr);
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
    send_line(&mut stdin, &initialize, &mut child, &stderr_drain)?;

    let reply_line = recv_line_or_fail(
        &stdout_lines,
        &mut child,
        &stderr_drain,
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
    send_line(&mut stdin, &initialized, &mut child, &stderr_drain)?;

    let list_tools = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    send_line(&mut stdin, &list_tools, &mut child, &stderr_drain)?;

    let list_line = recv_line_or_fail(
        &stdout_lines,
        &mut child,
        &stderr_drain,
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
