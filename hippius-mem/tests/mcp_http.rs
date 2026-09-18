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
    _dir: tempfile::TempDir,
    _child: ChildGuard,
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
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("hippius-mem.toml");
        let vault_root = dir.path().join("vault");
        let token_path = dir.path().join("mcp-token");
        std::fs::create_dir_all(&vault_root)?;
        seed_trial_config(&config_path, &vault_root)?;
        std::fs::write(&token_path, format!("{TOKEN}\n"))?;

        let mut command = Command::new(env!("CARGO_BIN_EXE_hippius-mem"));
        for (name, _) in std::env::vars_os() {
            if name
                .to_str()
                .is_some_and(|name| name.starts_with("HIPPIUS_MEM_"))
            {
                command.env_remove(name);
            }
        }
        command
            .args(["serve", "--port", "0", "--token-file"])
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
            _dir: dir,
            _child: child,
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

    let mut command = Command::new(env!("CARGO_BIN_EXE_hippius-mem"));
    for (name, _) in std::env::vars_os() {
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("HIPPIUS_MEM_"))
        {
            command.env_remove(name);
        }
    }
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
