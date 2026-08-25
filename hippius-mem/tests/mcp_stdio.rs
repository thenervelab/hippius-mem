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
//! Handshake coverage: `initialize`, the `initialized` notification, then
//! `tools/list` — asserting all ten tools come back. A second test then
//! drives `remember` / `recall` / `get` over the same stdio stream, which
//! in-process `call_tool` tests cannot see.
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
/// avoid: every message this file sends is a few hundred bytes (handshake
/// plus a short `tools/call`) — under the smallest POSIX `PIPE_BUF` (512
/// bytes atomically) and far under any real kernel pipe buffer. A future
/// edit that sends a multi-KB body must not assume that still holds.
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

/// Isolated local-trial child, already past `initialize` + `initialized`.
/// `dir` is held so the vault lives as long as the session — shared
/// (`Arc`) so [`spawn_sharing_vault`](Self::spawn_sharing_vault) can bind a
/// SECOND live session to the same vault without either owning its
/// lifetime alone.
struct StdioSession {
    dir: Arc<tempfile::TempDir>,
    child: ChildGuard,
    stdin: std::process::ChildStdin,
    stdout: mpsc::Receiver<String>,
    stderr: StderrDrain,
}

impl StdioSession {
    fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_with_env(&[])
    }

    /// [`spawn`](Self::spawn) with extra environment for the child — how the
    /// logging test drives `RUST_LOG`, which every other spawn strips.
    fn spawn_with_env(extra_env: &[(&str, &str)]) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = Arc::new(tempfile::tempdir()?);
        let config_path = dir.path().join("hippius-mem.toml");
        let vault_root = dir.path().join("vault");
        std::fs::create_dir_all(&vault_root)?;
        seed_trial_config(&config_path, &vault_root)?;
        Self::spawn_bound(dir, extra_env)
    }

    /// Spawn a SECOND live server over the SAME seeded config and trial
    /// vault this session is bound to — the concurrent-Claude-Code-sessions
    /// shape the N-reader-1-writer split exists for. The new child re-reads
    /// the config this session's `spawn` already seeded; nothing is
    /// re-seeded, so the two processes contend on the very same vault root.
    fn spawn_sharing_vault(&self) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_bound(Arc::clone(&self.dir), &[])
    }

    /// The shared tail of [`spawn`](Self::spawn) and
    /// [`spawn_sharing_vault`](Self::spawn_sharing_vault): launch the binary
    /// against the config at `{dir}/hippius-mem.toml` and complete the MCP
    /// handshake.
    fn spawn_bound(
        dir: Arc<tempfile::TempDir>,
        extra_env: &[(&str, &str)],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = dir.path().join("hippius-mem.toml");

        // `Config::from_env_and_file` overlays every `HIPPIUS_MEM_*` variable
        // found in THIS process's own environment on top of the seeded file,
        // env winning — see the module docs' "Network safety" section, point 3.
        let mut command = Command::new(env!("CARGO_BIN_EXE_hippius-mem"));
        for (name, _) in std::env::vars_os() {
            if name
                .to_str()
                .is_some_and(|name| name.starts_with("HIPPIUS_MEM_"))
            {
                command.env_remove(name);
            }
        }

        // No `serve` argument: the MCP server starts on a bare invocation.
        command
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("HIPPIUS_MEM_CONFIG", &config_path)
            .env_remove("XDG_CACHE_HOME")
            // A developer's ambient `RUST_LOG` must not shape the child's
            // stderr: the default filter is part of what the logging test
            // asserts, and a `warn` inherited from the shell would hide it.
            .env_remove("RUST_LOG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in extra_env {
            command.env(name, value);
        }

        let mut child = ChildGuard(command.spawn()?);
        let stdout = child.0.stdout.take().ok_or("child stdout was not piped")?;
        let stderr = child.0.stderr.take().ok_or("child stderr was not piped")?;
        let stdin = child.0.stdin.take().ok_or("child stdin was not piped")?;
        let stderr_drain = spawn_stderr_drain(stderr);
        let stdout_lines = spawn_line_reader(stdout);

        let mut session = Self {
            dir,
            child,
            stdin,
            stdout: stdout_lines,
            stderr: stderr_drain,
        };
        session.handshake()?;
        Ok(session)
    }

    fn send(&mut self, value: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
        send_line(&mut self.stdin, value, &mut self.child, &self.stderr)
    }

    /// Stop the server and return everything it wrote to stderr. Consumes
    /// the session: the drain thread only finishes once the child's stderr
    /// closes, which is what makes the returned text complete rather than a
    /// racy mid-run snapshot.
    fn into_stderr(mut self) -> String {
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        self.stderr.snapshot_after_grace()
    }

    fn recv_json(&mut self, what: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let line = recv_line_or_fail(&self.stdout, &mut self.child, &self.stderr, what)?;
        serde_json::from_str(line.trim()).map_err(|err| {
            format!("stdout line must be JSON-RPC, not log or banner: {err}; got {line:?}").into()
        })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "hippius-mem-test", "version": "0" }
            }
        }))?;
        let reply = self.recv_json("an initialize reply")?;
        assert_eq!(
            reply["jsonrpc"], "2.0",
            "handshake must be JSON-RPC 2.0: {reply}"
        );
        assert_eq!(reply["id"], 1, "initialize reply must correlate: {reply}");
        assert!(
            reply["result"]["serverInfo"]["name"].is_string(),
            "initialize must return serverInfo: {reply}"
        );
        // Notification: no id, no reply.
        self.send(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))?;
        Ok(())
    }

    fn call_tool(
        &mut self,
        id: u64,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }))?;
        let reply = self.recv_json(&format!("a {name} tools/call reply"))?;
        assert_eq!(reply["id"], id, "{name} reply must correlate: {reply}");
        if reply["result"]["isError"].as_bool() == Some(true) {
            return Err(format!("{name} returned isError: {reply}").into());
        }
        Ok(reply)
    }
}

/// Number of committed op-log objects in the session's trial vault, counted
/// directly on disk.
///
/// `FsBlobStore` maps slash-separated key segments to directories, so the
/// `trial` team's op objects are exactly the files under
/// `{vault}/trial/_oplog/` (one file per appended op; temp files from an
/// interrupted `put` carry a reserved dot-prefix and are skipped the same
/// way the store's own `list` skips them). Counted on disk rather than
/// through a tool because the property under test is precisely "no process
/// but the writer APPENDS": an in-band read could not distinguish "no op
/// appended" from "an op appended and then compensated".
fn count_oplog_objects(session: &StdioSession) -> usize {
    let oplog = session
        .dir
        .path()
        .join("vault")
        .join("trial")
        .join("_oplog");
    match std::fs::read_dir(oplog) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
            .count(),
        // The directory does not exist until the first append lands.
        Err(_) => 0,
    }
}

/// Concatenate `result.content[*].text` from a `tools/call` reply.
fn call_text(reply: &serde_json::Value) -> String {
    reply["result"]["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|block| block["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
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
    let mut session = StdioSession::spawn()?;

    session.send(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }))?;
    let list_reply = session.recv_json("a tools/list reply")?;
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

/// Remember, recall, and get over the real binary's stdio. In-process
/// `call_tool` tests cannot see a stray `println!` or a serve-path
/// dispatch miss; this can.
#[test]
fn the_binary_remembers_recalls_and_gets_over_stdio() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = StdioSession::spawn()?;

    let remembered = session.call_tool(
        3,
        "remember",
        &json!({
            "note_type": "gotcha",
            "summary": "quokka-cache eviction storm",
            "body": "pin the group instance id",
        }),
    )?;
    let stored: serde_json::Value = serde_json::from_str(&call_text(&remembered))?;
    let id = stored["id"].as_str().ok_or("remember must return an id")?;
    assert!(
        id.starts_with("mem_"),
        "remember must return a mem_ id, got {id}"
    );

    let found = session.call_tool(4, "recall", &json!({ "text": "quokka-cache" }))?;
    let found_text = call_text(&found);
    assert!(
        found_text.contains("quokka-cache"),
        "stdio recall must surface the stored summary, got {found_text}"
    );

    let got = session.call_tool(5, "get", &json!({ "id": id }))?;
    let got_text = call_text(&got);
    assert!(
        got_text.contains("pin the group instance id"),
        "stdio get must return the stored body, got {got_text}"
    );
    Ok(())
}

/// The whole N-reader-1-writer finding, end to end over two REAL server
/// processes sharing one trial vault: the first session keeps read-write;
/// a second concurrent session must still complete the handshake (it used
/// to be refused outright, leaving every session but the first with no
/// memory at all and the reason visible only in MCP logs), its `remember`
/// must refuse IN-BAND with the read-only message, its reads must work
/// (surfacing the first session's note), and the first session must keep
/// its write role throughout.
#[test]
fn a_second_live_session_over_one_vault_reads_but_refuses_writes_in_band()
-> Result<(), Box<dyn std::error::Error>> {
    let mut writer = StdioSession::spawn()?;

    writer.call_tool(
        3,
        "remember",
        &json!({
            "note_type": "decision",
            "summary": "wombat-queue drains oldest first",
            "body": "FIFO was chosen over LIFO for fairness",
        }),
    )?;

    // The second session: same config file, same vault root, booted while
    // the first is still alive. Completing `spawn` at all (it runs the
    // handshake) is the availability half of the fix.
    let mut reader = writer.spawn_sharing_vault()?;

    // The write refusal must be in the TOOL RESULT the agent reads —
    // `isError: true` plus an actionable message — not a boot failure or a
    // log line. Sent raw (not via `call_tool`, which treats `isError` as a
    // test failure).
    reader.send(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": { "name": "remember", "arguments": {
            "note_type": "decision",
            "summary": "this write must never land",
            "body": "a read-only session cannot append ops",
        }}
    }))?;
    let refusal = reader.recv_json("a remember tools/call reply")?;
    assert_eq!(refusal["id"], 4, "remember reply must correlate: {refusal}");
    assert_eq!(
        refusal["result"]["isError"].as_bool(),
        Some(true),
        "the second session's remember must refuse in-band: {refusal}"
    );
    let refusal_text = call_text(&refusal);
    assert!(
        refusal_text.contains("read-only") && refusal_text.contains("trial"),
        "the refusal must say read-only and name the profile: {refusal_text}"
    );
    assert!(
        refusal_text.contains("write lock"),
        "the refusal must name the cause: {refusal_text}"
    );

    // The one-appender pin: a read-only session's SYNC paths (the explicit
    // `refresh` tool and the pre-read auto-refresh inside `recall`) must
    // append NO op-log objects. Read-only sessions still write the vault —
    // every sync PUTs/prunes `{team}/_snapshots/` checkpoint objects, which
    // are concurrent-writer-safe by design — so the guaranteed invariant is
    // "at most one op-log APPENDER", and that is what this counts. The
    // writer stays alive (and idle) across the window, so any count delta
    // could only come from the reader; with the write-role re-contest, a
    // reader stays read-only only WHILE the writer lives, so the writer
    // must not be dropped before this assertion.
    let ops_before = count_oplog_objects(&reader);
    reader.call_tool(5, "refresh", &json!({}))?;

    // Reads on the second session work: it surfaces the note the FIRST
    // session stored (recall syncs from the shared op-log before answering).
    let found = reader.call_tool(6, "recall", &json!({ "text": "wombat-queue" }))?;
    let found_text = call_text(&found);
    assert!(
        found_text.contains("drains oldest first"),
        "the second session's recall must surface the writer's note: {found_text}"
    );

    assert_eq!(
        count_oplog_objects(&reader),
        ops_before,
        "a read-only session's refresh + recall must append no op-log objects"
    );

    // And the first session keeps its write role for its whole lifetime.
    writer.call_tool(
        6,
        "remember",
        &json!({
            "note_type": "decision",
            "summary": "wombat-queue caps at 128 entries",
            "body": "bounded to keep worst-case drain time flat",
        }),
    )?;

    Ok(())
}

/// The write role is NOT for life: a session that booted read-only (the
/// writer was alive) must win the role by re-contest once the writer exits
/// — the very next write attempt on the SAME surviving session simply
/// succeeds, with no restart and no error the agent has to interpret.
/// Before the re-contest fix this session refused writes forever while the
/// vault's write lock sat free, and its refusal text pointed the agent at a
/// session that no longer existed.
///
/// The writer's exit is deterministic here: dropping its [`StdioSession`]
/// SIGKILLs and reaps the process (`ChildGuard`), and the OS releases an
/// flock the moment no fd holds it — the reader was spawned by THIS test
/// process (which holds no vault lock fds), so no duplicated descriptor can
/// keep the writer's lock alive past the reap.
#[test]
fn a_read_only_session_wins_the_write_role_after_its_writer_exits()
-> Result<(), Box<dyn std::error::Error>> {
    let writer = StdioSession::spawn()?;
    let mut reader = writer.spawn_sharing_vault()?;

    // Precondition, not the point: while the writer LIVES the reader still
    // refuses (the full refusal contract is pinned by
    // `a_second_live_session_over_one_vault_reads_but_refuses_writes_in_band`).
    reader.send(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "remember", "arguments": {
            "note_type": "decision",
            "summary": "must still refuse while the writer lives",
            "body": "the re-contest must lose against a live writer",
        }}
    }))?;
    let refusal = reader.recv_json("a remember tools/call reply")?;
    assert_eq!(
        refusal["result"]["isError"].as_bool(),
        Some(true),
        "the reader must stay read-only while the writer lives: {refusal}"
    );

    // The writer exits (killed and reaped by ChildGuard's Drop), releasing
    // the vault's write-role flock.
    drop(writer);

    // The surviving session's next write must WIN the freed role and land —
    // one attempt, no retry loop: the reap above is synchronous, so the
    // lock is already free when this call is made.
    let stored = reader.call_tool(
        4,
        "remember",
        &json!({
            "note_type": "decision",
            "summary": "numbat-ledger settles hourly",
            "body": "written by the session that inherited the write role",
        }),
    )?;
    let stored: serde_json::Value = serde_json::from_str(&call_text(&stored))?;
    let id = stored["id"]
        .as_str()
        .ok_or("the inherited-role remember must return an id")?;
    assert!(
        id.starts_with("mem_"),
        "the inherited-role remember must return a mem_ id, got {id}"
    );

    // And the write really landed: the same session reads its note back.
    let got = reader.call_tool(5, "get", &json!({ "id": id }))?;
    let got_text = call_text(&got);
    assert!(
        got_text.contains("inherited the write role"),
        "the note written after winning the role must be readable: {got_text}"
    );

    Ok(())
}

/// The line the server logs once it has bound its team profile, if any.
fn bound_profile_line(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .find(|line| line.contains("bound team profile"))
}

/// Check one stderr line against the exact shape `src/logging.rs` promises:
/// a 27-character UTC timestamp (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), then
/// `expected_after_stamp` (which starts with the padded level).
fn assert_timestamped_line(
    line: &str,
    expected_after_stamp: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (stamp, rest) = line
        .split_at_checked(27)
        .ok_or_else(|| format!("line shorter than a timestamp: {line:?}"))?;
    let stamp_ok = stamp.bytes().enumerate().all(|(i, b)| match i {
        4 | 7 => b == b'-',
        10 => b == b'T',
        13 | 16 => b == b':',
        19 => b == b'.',
        26 => b == b'Z',
        _ => b.is_ascii_digit(),
    });
    if !stamp_ok {
        return Err(format!("not a UTC timestamp: {stamp:?} in {line:?}").into());
    }
    if !rest.starts_with(expected_after_stamp) {
        return Err(
            format!("expected {expected_after_stamp:?} after the stamp in {line:?}").into(),
        );
    }
    Ok(())
}

/// The binary's own stderr logging (`src/logging.rs`) end to end, through the
/// real process: `RUST_LOG` is honoured in both documented forms, an
/// unreadable value falls back to `info` AND says so, `off` silences the
/// process, and at maximum verbosity a full request round trip still leaves
/// stdout pure JSON-RPC (every `recv_json` rejects a non-JSON line).
#[test]
fn rust_log_shapes_stderr_and_never_reaches_stdout() -> Result<(), Box<dyn std::error::Error>> {
    // Unset: the `info` default, in the documented line shape.
    let stderr = StdioSession::spawn_with_env(&[])?.into_stderr();
    let line = bound_profile_line(&stderr)
        .ok_or_else(|| format!("no startup info line under the default filter:\n{stderr}"))?;
    assert_timestamped_line(line, "  INFO hippius_mem: bound team profile profile=")?;
    assert!(
        line.contains(" bucket="),
        "fields render as key=value: {line:?}"
    );
    assert!(
        !stderr.contains(" DEBUG "),
        "the info default admits no debug lines:\n{stderr}"
    );

    // A directive naming only another crate leaves this crate's events off...
    let stderr = StdioSession::spawn_with_env(&[("RUST_LOG", "rmcp=info")])?.into_stderr();
    assert!(
        bound_profile_line(&stderr).is_none(),
        "an unnamed target must be off:\n{stderr}"
    );
    // ...while a prefix of this crate's target admits them.
    let stderr = StdioSession::spawn_with_env(&[("RUST_LOG", "hippius=info")])?.into_stderr();
    assert!(
        bound_profile_line(&stderr).is_some(),
        "a prefix directive must match:\n{stderr}"
    );

    // `off`: nothing at all reaches stderr, so nothing else in the process
    // writes there behind tracing's back either.
    let stderr = StdioSession::spawn_with_env(&[("RUST_LOG", "off")])?.into_stderr();
    assert!(
        stderr.trim().is_empty(),
        "RUST_LOG=off must leave stderr empty:\n{stderr}"
    );

    // Unreadable: `info`, plus one warning saying so — never a silent fallback.
    let stderr = StdioSession::spawn_with_env(&[("RUST_LOG", "hippius_mem=loud")])?.into_stderr();
    let warning = stderr
        .lines()
        .find(|line| line.contains("RUST_LOG was not understood"))
        .ok_or_else(|| format!("no fallback warning for an unreadable RUST_LOG:\n{stderr}"))?;
    assert_timestamped_line(
        warning,
        "  WARN hippius_mem::logging: RUST_LOG was not understood; logging at info err=",
    )?;
    assert!(
        bound_profile_line(&stderr).is_some(),
        "info still applies:\n{stderr}"
    );

    // Maximum verbosity, then a real request: stdout stays JSON-RPC only.
    let mut session = StdioSession::spawn_with_env(&[("RUST_LOG", "trace")])?;
    session.call_tool(2, "recall", &json!({ "text": "logging probe" }))?;
    let stderr = session.into_stderr();
    assert!(
        bound_profile_line(&stderr).is_some(),
        "trace admits info:\n{stderr}"
    );
    Ok(())
}
