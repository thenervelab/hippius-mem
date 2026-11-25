//! The binary spoken to over loopback streamable HTTP, the way Grok/Claude
//! talk to `hippius-mem serve` — not stdio, not the in-process router.
//!
//! Pins issue #108: N HTTP sessions share ONE process (one ONNX load, one
//! writer). Two clients remember/recall through the same bound port.
//!
//! Network safety matches `mcp_stdio.rs`: the seeded config sets
//! `semantic_embeddings = false`, and every ambient `HIPPIUS_MEM_*` is
//! stripped before spawn.

#![cfg(feature = "http-mcp")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes"
)]

mod support;

use std::io::BufRead as _;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::json;

const TEAM_KEY_HEX: &str = "24acd7ca317cb31b657364ac6aa260e1a3ed469a2c296973ad21d5b42e0b1835";
const AUTHOR_SEED_HEX: &str = "65e2d246684f2abdc3bf908cae0896b5900d1d873d6f8a39a29bbf14f425c2c5";
const STDERR_LINE_DEADLINE: Duration = Duration::from_secs(20);
const TOKEN: &str = "0123456789abcdef0123456789abcdef";

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct HttpDaemon {
    dir: tempfile::TempDir,
    child: ChildGuard,
    url: String,
    token: String,
    _stderr: StderrDrain,
}

struct StderrDrain {
    rx: mpsc::Receiver<String>,
    buf: Arc<Mutex<String>>,
}

impl HttpDaemon {
    fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_on_port(0)
    }

    /// [`spawn`](Self::spawn) on `port`; `0` lets the OS pick one.
    fn spawn_on_port(port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("hippius-mem.toml");
        let vault_root = dir.path().join("vault");
        let token_path = dir.path().join("mcp-token");
        std::fs::create_dir_all(&vault_root)?;
        seed_trial_config(&config_path, &vault_root)?;
        std::fs::write(&token_path, format!("{TOKEN}\n"))?;

        let mut command = support::binary();
        command
            .args(["serve", "--port", &port.to_string(), "--token-file"])
            .arg(&token_path)
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("HIPPIUS_MEM_CONFIG", &config_path)
            .env_remove("XDG_CACHE_HOME")
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = ChildGuard(command.spawn()?);
        let stderr = child.0.stderr.take().ok_or("child stderr was not piped")?;
        let drain = spawn_stderr_drain(stderr);
        let url = wait_for_listen_url(&drain)?;
        Ok(Self {
            dir,
            child,
            url,
            token: TOKEN.to_owned(),
            _stderr: drain,
        })
    }

    fn rpc(
        &self,
        session: Option<&str>,
        body: &serde_json::Value,
    ) -> Result<(Option<String>, serde_json::Value), Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::new();
        let mut req = client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("Authorization", format!("Bearer {}", self.token))
            .json(body);
        if let Some(id) = session {
            req = req.header("mcp-session-id", id);
        }
        let response = req.send()?;
        if !response.status().is_success() {
            return Err(format!("HTTP {}: {}", response.status(), response.text()?).into());
        }
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let text = response.text()?;
        let json = parse_sse_or_json(&text)?;
        Ok((session_id, json))
    }
}

fn seed_trial_config(path: &std::path::Path, vault: &std::path::Path) -> std::io::Result<()> {
    let body = format!(
        "team = \"trial\"\n\
         team_key_hex = \"{TEAM_KEY_HEX}\"\n\
         author_seed_hex = \"{AUTHOR_SEED_HEX}\"\n\
         storage = \"local\"\n\
         local_root = \"{}\"\n\
         semantic_embeddings = false\n",
        vault.display()
    );
    std::fs::write(path, body)
}

/// Run `serve` to completion against `config`, returning its exit success
/// and stderr. For configurations and flags `serve` must refuse outright.
fn run_serve_to_exit(
    config: &str,
    extra_args: &[&str],
) -> Result<(bool, String), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");
    let token_path = dir.path().join("mcp-token");
    std::fs::write(&config_path, config)?;
    std::fs::write(&token_path, format!("{TOKEN}\n"))?;

    let mut command = support::binary();
    let output = command
        .args(["serve", "--port", "0", "--token-file"])
        .arg(&token_path)
        .args(extra_args)
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env_remove("XDG_CACHE_HOME")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()?;

    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

fn spawn_stderr_drain(stderr: std::process::ChildStderr) -> StderrDrain {
    let (tx, rx) = mpsc::channel();
    let buf = Arc::new(Mutex::new(String::new()));
    let buf_thread = Arc::clone(&buf);
    thread::spawn(move || {
        let reader = std::io::BufReader::new(stderr);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if let Ok(mut held) = buf_thread.lock() {
                held.push_str(&line);
                held.push('\n');
            }
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    StderrDrain { rx, buf }
}

fn wait_for_listen_url(drain: &StderrDrain) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        match drain.rx.recv_timeout(STDERR_LINE_DEADLINE) {
            Ok(line) => {
                if let Some(url) = line
                    .split_whitespace()
                    .find_map(|tok| tok.strip_prefix("url="))
                {
                    return Ok(url.trim_matches('"').to_owned());
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let snap = drain.buf.lock().map(|s| s.clone()).unwrap_or_default();
                return Err(format!("timed out waiting for listen url; stderr:\n{snap}").into());
            }
            Err(RecvTimeoutError::Disconnected) => {
                let snap = drain.buf.lock().map(|s| s.clone()).unwrap_or_default();
                return Err(format!("server exited before listening; stderr:\n{snap}").into());
            }
        }
    }
}

fn parse_sse_or_json(body: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // Stateful streamable HTTP prefixes a priming SSE event whose `data:` is
    // empty; the JSON-RPC payload is a later `data: {...}` line.
    for line in body.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
            return Ok(value);
        }
    }
    serde_json::from_str(body)
        .map_err(|err| format!("no JSON-RPC in MCP HTTP body ({err}); raw={body:?}").into())
}

fn call_text(reply: &serde_json::Value) -> String {
    reply["result"]["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|block| block["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn handshake(daemon: &HttpDaemon) -> Result<String, Box<dyn std::error::Error>> {
    let (session, reply) = daemon.rpc(
        None,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "hippius-mem-test", "version": "0" }
            }
        }),
    )?;
    assert!(
        reply["result"]["serverInfo"]["name"].is_string(),
        "initialize must return serverInfo: {reply}"
    );
    let session = session.ok_or("initialize must return mcp-session-id")?;
    let _ = daemon.rpc(
        Some(&session),
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );
    Ok(session)
}

#[test]
fn the_binary_remembers_recalls_and_gets_over_http() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let session = handshake(&daemon)?;

    let (_, remembered) = daemon.rpc(
        Some(&session),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "remember",
                "arguments": {
                    "note_type": "gotcha",
                    "repo": "global",
                    "summary": "quokka-http eviction storm",
                    "body": "pin the group instance id"
                }
            }
        }),
    )?;
    let stored: serde_json::Value = serde_json::from_str(&call_text(&remembered))?;
    let id = stored["id"].as_str().ok_or("remember must return an id")?;

    let (_, found) = daemon.rpc(
        Some(&session),
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "recall", "arguments": { "text": "quokka-http" } }
        }),
    )?;
    let found_text = call_text(&found);
    assert!(
        found_text.contains("quokka-http"),
        "HTTP recall must surface the stored summary, got {found_text}"
    );

    let (_, got) = daemon.rpc(
        Some(&session),
        &json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": { "name": "get", "arguments": { "id": id } }
        }),
    )?;
    let got_text = call_text(&got);
    assert!(
        got_text.contains("pin the group instance id"),
        "HTTP get must return the stored body, got {got_text}"
    );
    Ok(())
}

/// The shared daemon refuses a `remember` that omits `repo`, as the CLI does.
/// It used to write the note team-global, into the pool every repository's
/// recall and brief read, while the docs said an omitted `repo` means the
/// repository the server was launched in.
#[test]
fn the_daemon_refuses_a_remember_without_repo() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let session = handshake(&daemon)?;
    let (_, reply) = daemon.rpc(
        Some(&session),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "remember",
                "arguments": {
                    "note_type": "gotcha",
                    "summary": "lynx-http unscoped note",
                    "body": "body"
                }
            }
        }),
    )?;
    assert_eq!(reply["result"]["isError"].as_bool(), Some(true), "{reply}");
    assert!(call_text(&reply).contains("invalid repo"), "{reply}");
    Ok(())
}

#[test]
fn two_http_sessions_share_one_process_and_see_each_others_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let a = handshake(&daemon)?;
    let b = handshake(&daemon)?;
    assert_ne!(a, b, "stateful HTTP must mint a session per client");

    let (_, remembered) = daemon.rpc(
        Some(&a),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "remember",
                "arguments": {
                    "note_type": "decision",
                    "repo": "global",
                    "summary": "shared-daemon session B can recall A's note",
                    "body": "one ONNX load"
                }
            }
        }),
    )?;
    if remembered["result"]["isError"].as_bool() == Some(true) {
        return Err(format!("remember failed: {remembered}").into());
    }

    let (_, found) = daemon.rpc(
        Some(&b),
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "recall",
                "arguments": { "text": "shared-daemon session B" }
            }
        }),
    )?;
    let found_text = call_text(&found);
    assert!(
        found_text.contains("shared-daemon"),
        "session B must see session A's write in the shared process, got {found_text}"
    );
    Ok(())
}

#[test]
fn http_mcp_rejects_a_missing_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(&daemon.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .body("{}")
        .send()?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "MCP data plane must require the bearer token"
    );

    let health = client.get(daemon.url.replace("/mcp", "/health")).send()?;
    assert!(
        health.status().is_success(),
        "/health must stay unauthenticated so doctor/LaunchAgent can probe it"
    );
    Ok(())
}

/// One shared process cannot route per repository. With two team profiles it
/// must refuse rather than hand every client whichever profile it guessed —
/// that would read and write one team's notes with another team's bucket/key.
#[test]
fn serve_refuses_a_multi_profile_config() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let config = format!(
        "team = \"trial\"\n\
         team_key_hex = \"{TEAM_KEY_HEX}\"\n\
         author_seed_hex = \"{AUTHOR_SEED_HEX}\"\n\
         storage = \"local\"\n\
         local_root = \"{root}\"\n\
         semantic_embeddings = false\n\
         \n\
         [[teams]]\n\
         name = \"other\"\n\
         orgs = [\"github.com/other-org\"]\n\
         team_key_hex = \"{TEAM_KEY_HEX}\"\n\
         author_seed_hex = \"{AUTHOR_SEED_HEX}\"\n\
         storage = \"local\"\n\
         local_root = \"{root}\"\n",
        root = dir.path().join("vault").display()
    );

    let (success, stderr) = run_serve_to_exit(&config, &[])?;

    assert!(!success, "serve must not come up: {stderr}");
    assert!(
        stderr.contains("2 team profiles"),
        "the refusal must name the reason: {stderr}"
    );
    Ok(())
}

/// Arguments are parsed before the store boots, so a typo fails without ever
/// reading the config (here: a config that would not even load).
#[test]
fn serve_rejects_an_unknown_flag_before_booting() -> Result<(), Box<dyn std::error::Error>> {
    let (success, stderr) = run_serve_to_exit("this is not toml = = =", &["--prot", "1"])?;

    assert!(!success);
    assert!(
        stderr.contains("unknown serve argument"),
        "the flag error must win over the config error: {stderr}"
    );
    Ok(())
}

/// A git checkout named `name` under `parent` whose `origin` is the `widget`
/// repository, which is what makes `widget` its repository scope.
fn widget_checkout(
    parent: &std::path::Path,
    name: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let checkout = parent.join(name);
    std::fs::create_dir(&checkout)?;
    for args in [
        &["init", "-q"][..],
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widget.git",
        ][..],
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(&checkout)
            .args(args)
            .status()?;
        assert!(status.success(), "git {args:?} failed");
    }
    Ok(checkout)
}

/// Run `hippius-mem path-notes` for `file` in `checkout` against `daemon`.
fn path_notes_stdout(
    daemon: &HttpDaemon,
    checkout: &std::path::Path,
    file: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let port = daemon
        .url
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.split('/').next())
        .ok_or("daemon url has no port")?;
    let output = support::binary()
        .args(["path-notes", "--port", port, "--repo-root"])
        .arg(checkout)
        .arg("--file")
        .arg(checkout.join(file))
        // The token is read from `mcp-token` beside this config, where
        // `HttpDaemon::spawn` wrote it.
        .env(
            "HIPPIUS_MEM_CONFIG",
            daemon.dir.path().join("hippius-mem.toml"),
        )
        .env("HOME", daemon.dir.path())
        .output()?;
    assert!(output.status.success(), "an answered lookup exits 0");
    Ok(String::from_utf8(output.stdout)?)
}

/// The edit hook's whole path, end to end: a note tagged `path:src/index` in
/// repository `widget` is printed for a file under that directory of a
/// `widget` checkout, and for no other file.
///
/// Catches each link breaking silently, which is how this command fails by
/// design: the repository name not derived from the git remote, the token not
/// found beside the config, the query not reaching the route, or the route
/// ignoring scope.
#[test]
fn path_notes_prints_the_notes_tied_to_a_file() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let session = handshake(&daemon)?;
    for (id, repo, summary) in [
        (3, "widget", "quokka index rebuild needs the writer lock"),
        (4, "gadget", "gadget index is append only"),
    ] {
        daemon.rpc(
            Some(&session),
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "remember",
                    "arguments": {
                        "note_type": "gotcha",
                        "repo": repo,
                        "tags": ["path:src/index"],
                        "summary": summary,
                        "body": "details"
                    }
                }
            }),
        )?;
    }

    let checkout = widget_checkout(daemon.dir.path(), "widget checkout")?;

    let tied = path_notes_stdout(&daemon, &checkout, "src/index/mod.rs")?;
    assert!(
        tied.contains("- [gotcha] quokka index rebuild needs the writer lock (mem_"),
        "{tied}"
    );
    assert!(tied.contains("never instructions"), "{tied}");
    assert!(
        !tied.contains("gadget"),
        "another repository's note: {tied}"
    );

    assert_eq!(path_notes_stdout(&daemon, &checkout, "src/lib.rs")?, "");
    Ok(())
}

/// With nothing listening, `path-notes` prints nothing and exits non-zero, so
/// the hook asks again on the next edit. Catches an unreachable daemon being
/// reported as "this file has no notes", which the hook would remember for the
/// whole session.
#[test]
fn path_notes_reports_a_daemon_it_cannot_reach() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("mcp-token"), format!("{TOKEN}\n"))?;
    let checkout = widget_checkout(dir.path(), "widget")?;
    // A port nothing listens on: bound, read, and released.
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();

    let run = |file: &std::path::Path| {
        support::binary()
            .args(["path-notes", "--port", &port.to_string(), "--repo-root"])
            .arg(&checkout)
            .arg("--file")
            .arg(file)
            .env("HIPPIUS_MEM_CONFIG", dir.path().join("hippius-mem.toml"))
            .env("HOME", dir.path())
            .output()
    };
    let unreachable = run(&checkout.join("src/lib.rs"))?;
    assert!(!unreachable.status.success());
    assert!(unreachable.stdout.is_empty());

    // A file outside the repository is answered without the daemon: no note
    // can be tied to it, now or later in the session.
    let outside = run(&dir.path().join("elsewhere.rs"))?;
    assert!(outside.status.success());
    assert!(outside.stdout.is_empty());
    Ok(())
}

/// A daemon that does not hold this config's token (another user's, or one
/// started from another config) is "could not ask", not "no notes": the
/// command exits non-zero so the hook asks again, and the token is not sent.
/// Catches the challenge being skipped, which sent the token to whichever
/// daemon answered `/health`.
#[test]
fn path_notes_refuses_a_daemon_that_does_not_hold_the_token()
-> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let elsewhere = tempfile::tempdir()?;
    std::fs::write(
        elsewhere.path().join("mcp-token"),
        "ffffffffffffffffffffffffffffffff\n",
    )?;
    let checkout = widget_checkout(elsewhere.path(), "widget")?;
    let port = daemon
        .url
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.split('/').next())
        .ok_or("daemon url has no port")?;

    let output = support::binary()
        .args(["path-notes", "--port", port, "--repo-root"])
        .arg(&checkout)
        .arg("--file")
        .arg(checkout.join("src/lib.rs"))
        .env(
            "HIPPIUS_MEM_CONFIG",
            elsewhere.path().join("hippius-mem.toml"),
        )
        .env("HOME", elsewhere.path())
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not prove it holds this user's daemon token"),
        "{stderr}"
    );
    Ok(())
}

/// The bearer token is not sent to a listener that is not this daemon. With
/// the daemon down another local service can hold its port, and the edit hook
/// runs this command on every first edit of a file.
#[test]
fn path_notes_does_not_send_the_token_to_a_foreign_listener()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read as _, Write as _};

    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("mcp-token"), format!("{TOKEN}\n"))?;
    let checkout = widget_checkout(dir.path(), "widget")?;

    // A service that answers every request `200 ok` and records what it read.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let seen = Arc::new(Mutex::new(String::new()));
    let recorder = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buf = [0_u8; 2048];
            let read = stream.read(&mut buf).unwrap_or(0);
            if let Ok(mut seen) = recorder.lock() {
                seen.push_str(&String::from_utf8_lossy(&buf[..read]));
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });

    let output = support::binary()
        .args(["path-notes", "--port", &port.to_string(), "--repo-root"])
        .arg(&checkout)
        .arg("--file")
        .arg(checkout.join("src/lib.rs"))
        .env("HIPPIUS_MEM_CONFIG", dir.path().join("hippius-mem.toml"))
        .env("HOME", dir.path())
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let seen = seen.lock().map_err(|_| "recorder poisoned")?.clone();
    assert!(
        seen.contains("GET /token-proof?nonce="),
        "the listener was never challenged: {seen}"
    );
    assert!(
        !seen.contains(TOKEN),
        "the token reached a foreign listener"
    );
    Ok(())
}

/// A second `serve` whose port is taken exits 0 only when the daemon there
/// proves it holds the same token, and fails otherwise. It used to exit 0 for
/// any daemon that answered `/health`, so on a shared host this user's service
/// stopped while its clients sent their token to another user's daemon.
#[test]
fn serve_on_a_taken_port_exits_0_only_for_a_daemon_with_its_token()
-> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let port = daemon
        .url
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.split('/').next())
        .ok_or("daemon url has no port")?
        .to_owned();
    let config_path = daemon.dir.path().join("hippius-mem.toml");
    let other_token = daemon.dir.path().join("other-token");
    std::fs::write(&other_token, "ffffffffffffffffffffffffffffffff\n")?;

    let second_serve = |token_path: &std::path::Path| {
        support::binary()
            .args(["serve", "--port", &port, "--token-file"])
            .arg(token_path)
            .current_dir(daemon.dir.path())
            .env("HOME", daemon.dir.path())
            .env("XDG_DATA_HOME", daemon.dir.path().join("data"))
            .env("HIPPIUS_MEM_CONFIG", &config_path)
            .env_remove("XDG_CACHE_HOME")
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .output()
    };

    let same = second_serve(&daemon.dir.path().join("mcp-token"))?;
    assert!(
        same.status.success(),
        "{}",
        String::from_utf8_lossy(&same.stderr)
    );
    let other = second_serve(&other_token)?;
    let stderr = String::from_utf8_lossy(&other.stderr);
    assert!(!other.status.success(), "{stderr}");
    assert!(
        stderr.contains("does not prove it holds this user's token"),
        "{stderr}"
    );
    Ok(())
}

/// A `serve` started while the previous daemon is still releasing the port
/// waits for it and takes the port. Catches a serve that probes the occupant
/// at once: the dying occupant proves no token, so that serve fails, and the
/// user service it runs under starts no daemon on a restart.
#[test]
fn serve_takes_a_port_its_previous_occupant_releases() -> Result<(), Box<dyn std::error::Error>> {
    let occupant = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = occupant.local_addr()?.port();
    // Held past `serve`'s first bind and released inside its retry window
    // (eight binds 150 ms apart, about 1 s). A binary slower than 600 ms to
    // its first bind finds the port free and passes without retrying.
    let releaser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(600));
        drop(occupant);
    });

    let daemon = HttpDaemon::spawn_on_port(port)?;
    releaser
        .join()
        .map_err(|_| "the releasing thread panicked")?;
    assert_eq!(daemon.url, format!("http://127.0.0.1:{port}/mcp"));
    Ok(())
}

/// A port `serve` may not bind at all fails at once with the bind error, not
/// after the retries meant for a port another process is releasing, and not
/// as "held by a process that does not prove it holds this user's token".
/// Skipped where this user may bind port 1 (root, or a lowered
/// `ip_unprivileged_port_start`).
#[test]
fn serve_reports_a_port_it_may_not_bind() -> Result<(), Box<dyn std::error::Error>> {
    match std::net::TcpListener::bind("127.0.0.1:1") {
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {}
        _ => return Ok(()),
    }
    let dir = tempfile::tempdir()?;
    let token_path = dir.path().join("mcp-token");
    std::fs::write(&token_path, format!("{TOKEN}\n"))?;

    let output = support::binary()
        .args(["serve", "--port", "1", "--token-file"])
        .arg(&token_path)
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("HIPPIUS_MEM_CONFIG", dir.path().join("hippius-mem.toml"))
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("failed to bind loopback MCP port 1") && !stderr.contains("does not prove"),
        "{stderr}"
    );
    Ok(())
}

/// Summaries are team data: the route needs the bearer token, as `/mcp` does.
#[test]
fn path_notes_route_rejects_a_missing_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let url = daemon
        .url
        .replace("/mcp", "/path-notes?repo=widget&path=src");
    let response = reqwest::blocking::Client::new().get(url).send()?;
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

/// `serve` anchors the ops it buffered below the batch threshold when it gets
/// SIGTERM, the signal a supervisor stops it with, and then exits. Its buffer
/// lived only in memory, so the daemon's last writes were never anchored.
#[cfg(unix)]
#[test]
fn serve_anchors_its_last_writes_on_sigterm() -> Result<(), Box<dyn std::error::Error>> {
    let mut daemon = HttpDaemon::spawn()?;
    let session = handshake(&daemon)?;
    let (_, remembered) = daemon.rpc(
        Some(&session),
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "remember",
                "arguments": {
                    "note_type": "gotcha",
                    "repo": "global",
                    "summary": "heron-http anchors at stop",
                    "body": "body"
                }
            }
        }),
    )?;
    assert_ne!(
        remembered["result"]["isError"].as_bool(),
        Some(true),
        "{remembered}"
    );

    let pid = daemon.child.0.id().to_string();
    let killed = Command::new("kill").args(["-TERM", &pid]).status()?;
    assert!(killed.success(), "kill -TERM failed");
    let status = daemon.child.0.wait()?;
    assert!(status.success(), "serve exits cleanly on SIGTERM: {status}");

    let anchors = daemon
        .dir
        .path()
        .join("vault")
        .join("trial")
        .join("_anchors");
    let mut records = 0;
    for entry in std::fs::read_dir(&anchors).into_iter().flatten().flatten() {
        records += std::fs::read_dir(entry.path()).map_or(0, Iterator::count);
    }
    assert_eq!(records, 1, "one batch record under {}", anchors.display());
    Ok(())
}

/// The real daemon answers the token challenge `install` sends with the proof
/// for its own token, unauthenticated, so a client can check whose daemon holds
/// the shared port without sending its token.
#[test]
fn the_daemon_answers_the_token_challenge_with_its_own_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let url = daemon.url.replace("/mcp", "/token-proof?nonce=n0nce");
    let body = reqwest::blocking::Client::new().get(url).send()?.text()?;
    assert_eq!(body, hippius_mem_core::token_proof(&daemon.token, "n0nce"));
    assert_ne!(
        body,
        hippius_mem_core::token_proof("another-token", "n0nce")
    );
    Ok(())
}

/// Run `hippius-mem <args>` against `daemon`, from a directory with no git
/// remote, so `--repo` is exactly what the test passes.
fn cli(
    daemon: &HttpDaemon,
    args: &[&str],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let port = daemon
        .url
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.split('/').next())
        .ok_or("daemon url has no port")?;
    Ok(support::binary()
        .args(args)
        .args(["--port", port])
        .current_dir(daemon.dir.path())
        .env(
            "HIPPIUS_MEM_CONFIG",
            daemon.dir.path().join("hippius-mem.toml"),
        )
        .env("HOME", daemon.dir.path())
        .stdin(Stdio::null())
        .output()?)
}

fn cli_json(
    daemon: &HttpDaemon,
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let output = cli(daemon, args)?;
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// The memory tools from a command line, end to end through the daemon: a
/// note written with `remember` is found by `recall`, opened by `get`, and its
/// history read through the generic `call`.
///
/// Catches each command sending arguments the tool does not parse, the route
/// not reaching the tool, and a result printed as anything but the tool's
/// JSON.
#[test]
fn the_cli_remembers_recalls_and_gets_through_the_daemon() -> Result<(), Box<dyn std::error::Error>>
{
    let daemon = HttpDaemon::spawn()?;

    let stored = cli_json(
        &daemon,
        &[
            "remember",
            "--type",
            "gotcha",
            "--summary",
            "quokka-cli eviction storm",
            "--body",
            "pin the group instance id",
            "--repo",
            "widget",
            "--tag",
            "path:src",
        ],
    )?;
    assert_eq!(stored["repo"], "widget");
    let id = stored["id"].as_str().ok_or("remember must return an id")?;

    let found = cli_json(
        &daemon,
        &["recall", "quokka-cli", "storm", "--repo", "widget"],
    )?;
    assert_eq!(found["pointers"][0]["id"], id, "{found}");
    let elsewhere = cli_json(&daemon, &["recall", "quokka-cli", "--repo", "gadget"])?;
    assert_eq!(elsewhere["returned"], 0, "{elsewhere}");

    let note = cli_json(&daemon, &["get", id])?;
    assert_eq!(note["body"], "pin the group instance id");
    assert_eq!(note["tags"], json!(["path:src"]));

    let arguments = json!({ "id": id }).to_string();
    let history = cli_json(&daemon, &["call", "history", &arguments])?;
    assert_eq!(history["entries"][0]["kind"], "Remember", "{history}");
    Ok(())
}

/// A failure is an exit status and the tool's own message, never a JSON
/// document on stdout that a script would take for a result.
#[test]
fn the_cli_reports_a_failed_or_unknown_tool() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;

    let unknown = cli(&daemon, &["call", "nope"])?;
    assert!(!unknown.status.success());
    assert!(unknown.stdout.is_empty());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown tool `nope`"));

    let bad_id = cli(&daemon, &["get", "not-an-id"])?;
    assert!(!bad_id.status.success());
    assert!(bad_id.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&bad_id.stderr).contains("invalid id"),
        "{}",
        String::from_utf8_lossy(&bad_id.stderr)
    );
    Ok(())
}

/// A note's history, saved from the daemon, verifies offline, and stops
/// verifying when one op hash in the file is changed.
///
/// The file is the real `history` output, so this also catches the tool's
/// result and `verify-history`'s reader drifting apart. Sixteen writes reach
/// the default anchor threshold, which gives the first note's op a proof.
#[test]
fn a_saved_history_verifies_offline_until_it_is_tampered_with()
-> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let mut first = None;
    for i in 0..16 {
        let summary = format!("zebra{i} quokka{i} ibis{i} note");
        let stored = cli_json(
            &daemon,
            &[
                "remember",
                "--type",
                "reference",
                "--summary",
                &summary,
                "--repo",
                "global",
                "--body",
                "b",
                "--force",
            ],
        )?;
        first.get_or_insert(stored["id"].as_str().ok_or("no id")?.to_owned());
    }
    let id = first.ok_or("no note was written")?;
    let arguments = json!({ "id": id }).to_string();
    let history = cli(&daemon, &["call", "history", &arguments])?;
    assert!(history.status.success());
    let saved = daemon.dir.path().join("history.json");
    std::fs::write(&saved, &history.stdout)?;

    let verify = |path: &std::path::Path| {
        support::binary()
            .arg("verify-history")
            .arg(path)
            // No config and an empty home: the check reads only its input.
            .env_remove("HIPPIUS_MEM_CONFIG")
            .env("HOME", daemon.dir.path().join("nowhere"))
            .output()
    };
    let intact = verify(&saved)?;
    let report = String::from_utf8_lossy(&intact.stdout);
    assert!(intact.status.success(), "{report}");
    assert!(
        report.contains("1 proofs valid, 0 ops pending, 0 proofs invalid"),
        "{report}"
    );
    assert!(report.contains("recorded locally"), "{report}");

    let mut document: serde_json::Value = serde_json::from_slice(&history.stdout)?;
    let op_hash = document["entries"][0]["op_hash"]
        .as_str()
        .ok_or("no op_hash")?;
    let flipped = if op_hash.starts_with('0') { "1" } else { "0" };
    document["entries"][0]["op_hash"] = json!(format!("{flipped}{}", &op_hash[1..]));
    let tampered = daemon.dir.path().join("tampered.json");
    std::fs::write(&tampered, document.to_string())?;
    let rejected = verify(&tampered)?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stdout).contains("INVALID"));
    Ok(())
}

/// Run `hippius-mem <args>` against `daemon` from `cwd`, with `stdin` piped in.
fn cli_with_stdin(
    daemon: &HttpDaemon,
    cwd: &std::path::Path,
    args: &[&str],
    stdin: &str,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    use std::io::Write as _;

    let port = daemon
        .url
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.split('/').next())
        .ok_or("daemon url has no port")?;
    let mut child = support::binary()
        .args(args)
        .args(["--port", port])
        .current_dir(cwd)
        .env(
            "HIPPIUS_MEM_CONFIG",
            daemon.dir.path().join("hippius-mem.toml"),
        )
        .env("HOME", daemon.dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("child stdin was not piped")?
        .write_all(stdin.as_bytes())?;
    Ok(child.wait_with_output()?)
}

/// `remember` reads its body from stdin and takes its scope from the
/// checkout it runs in; `call <tool> -` reads its JSON from stdin. Outside a
/// repository `remember` refuses to guess a scope, and an empty stdin is not
/// stored as an empty note.
///
/// Catches the two defaults a script relies on going wrong silently: a note
/// written team-wide because of where a shell was, and an empty body stored
/// because stdin was `/dev/null`.
#[test]
fn the_cli_takes_the_body_from_stdin_and_the_scope_from_the_checkout()
-> Result<(), Box<dyn std::error::Error>> {
    let daemon = HttpDaemon::spawn()?;
    let checkout = widget_checkout(daemon.dir.path(), "widget")?;
    let remember = [
        "remember",
        "--type",
        "gotcha",
        "--summary",
        "quokka-stdin note",
    ];

    let stored = cli_with_stdin(&daemon, &checkout, &remember, "body from a pipe\n")?;
    assert!(
        stored.status.success(),
        "{}",
        String::from_utf8_lossy(&stored.stderr)
    );
    let stored: serde_json::Value = serde_json::from_slice(&stored.stdout)?;
    assert_eq!(stored["repo"], "widget");
    let id = stored["id"].as_str().ok_or("no id")?;

    let arguments = json!({ "id": id }).to_string();
    let got = cli_with_stdin(&daemon, &checkout, &["call", "get", "-"], &arguments)?;
    let got: serde_json::Value = serde_json::from_slice(&got.stdout)?;
    assert_eq!(got["body"], "body from a pipe\n");

    // `--body -` is stdin too, as `call <tool> -` is: it must not store a dash.
    let dashed = cli_with_stdin(
        &daemon,
        &checkout,
        &[
            "remember",
            "--type",
            "gotcha",
            "--summary",
            "zebra-dash note",
            "--body",
            "-",
        ],
        "body through a dash",
    )?;
    let dashed: serde_json::Value = serde_json::from_slice(&dashed.stdout)?;
    let arguments = json!({ "id": dashed["id"] }).to_string();
    let got = cli_with_stdin(&daemon, &checkout, &["call", "get", "-"], &arguments)?;
    let got: serde_json::Value = serde_json::from_slice(&got.stdout)?;
    assert_eq!(got["body"], "body through a dash");

    let outside = cli_with_stdin(&daemon, daemon.dir.path(), &remember, "body\n")?;
    assert!(!outside.status.success());
    assert!(String::from_utf8_lossy(&outside.stderr).contains("pass --repo"));

    let empty = cli_with_stdin(&daemon, &checkout, &remember, "")?;
    assert!(!empty.status.success());
    assert!(String::from_utf8_lossy(&empty.stderr).contains("empty"));
    Ok(())
}

/// With no daemon the commands fail and say why; they do not fall back to
/// building a store of their own.
#[test]
fn the_cli_says_so_when_there_is_no_daemon() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("mcp-token"), format!("{TOKEN}\n"))?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let output = support::binary()
        .args(["recall", "anything", "--port", &port.to_string()])
        .current_dir(dir.path())
        .env("HIPPIUS_MEM_CONFIG", dir.path().join("hippius-mem.toml"))
        .env("HOME", dir.path())
        .stdin(Stdio::null())
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no hippius-mem daemon"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
