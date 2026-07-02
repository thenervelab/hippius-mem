//! MCP-registration and `.gitignore` provisioning.
//!
//! Writes the `hippius-mem` server entry into a Claude Code MCP config —
//! project-scope `.mcp.json` or user-scope `~/.claude.json` — preserving every
//! other server, and appends the per-machine hook-cache dir to `.gitignore`.
//!
//! Secrets never enter these files: the repo entry relies on the server's default
//! `./hippius-mem.toml` (a gitignored, per-machine file), and the global entry
//! points `HIPPIUS_MEM_CONFIG` at an absolute path — a location, never a key.

use std::path::Path;

use anyhow::Context;
use serde_json::{Value, json};

/// The server key under `mcpServers`. Stable: teammates' configs and this
/// installer must agree on it for a re-run to update rather than duplicate.
const SERVER_NAME: &str = "hippius-mem";

/// The bare binary name written as the repo `.mcp.json` command.
///
/// Deliberately NOT the absolute `current_exe()` path: `.mcp.json` is committed
/// and shared, so each teammate must resolve the server through their own `PATH`
/// (after `cargo install` puts it on `~/.cargo/bin`). An absolute path would
/// encode one machine's layout and fail for everyone else. The global entry, by
/// contrast, IS per-machine and uses the resolved absolute path.
const SERVER_BINARY: &str = "hippius-mem";

/// Register the server in project-scope `<repo>/.mcp.json`.
///
/// The command is the bare [`SERVER_BINARY`] name (PATH-resolved per teammate),
/// and no `env` is written: Claude Code launches a project MCP server with the
/// project root as cwd, and the server already defaults `HIPPIUS_MEM_CONFIG` to
/// `./hippius-mem.toml`. Both choices keep the committed `.mcp.json` free of any
/// machine-specific path.
///
/// # Errors
///
/// Returns an error if the existing file is not valid JSON or cannot be written.
pub(crate) fn register_mcp_repo(repo: &Path) -> anyhow::Result<()> {
    let path = repo.join(".mcp.json");
    let mut config = load_json(&path)?;
    upsert_server(&mut config, json!({ "command": SERVER_BINARY, "args": [] }))?;
    write_json(&path, &config)
}

/// Register the server in user-scope `~/.claude.json`.
///
/// MCP servers live in `~/.claude.json`, NOT `~/.claude/settings.json` (Claude
/// Code's loader ignores `mcpServers` there). The global entry pins
/// `HIPPIUS_MEM_CONFIG` to an absolute path because a user-scope server has no
/// predictable cwd to resolve the default relative config against.
///
/// # Errors
///
/// Returns an error if the existing file is not valid JSON or cannot be written.
pub(crate) fn register_mcp_global(home: &Path, command: &str) -> anyhow::Result<()> {
    let path = home.join(".claude.json");
    let config_path = home.join(".config/hippius-mem/hippius-mem.toml");
    let entry = json!({
        "command": command,
        "args": [],
        "env": { "HIPPIUS_MEM_CONFIG": config_path.to_string_lossy() },
    });
    let mut config = load_json(&path)?;
    upsert_server(&mut config, entry)?;
    write_json(&path, &config)
}

/// Insert/replace `mcpServers.hippius-mem`, leaving all other servers untouched.
fn upsert_server(config: &mut Value, entry: Value) -> anyhow::Result<()> {
    let root = config
        .as_object_mut()
        .context("MCP config root is not a JSON object")?;
    let servers = root.entry("mcpServers").or_insert_with(|| json!({}));
    let servers = servers
        .as_object_mut()
        .context("`mcpServers` is not a JSON object")?;
    servers.insert(SERVER_NAME.to_string(), entry);
    Ok(())
}

/// Append `entry` (e.g. `.hippius-mem/`) to `<repo>/.gitignore` if not already
/// listed, creating the file when absent.
///
/// # Errors
///
/// Returns an error if `.gitignore` cannot be read or written.
pub(crate) fn ensure_gitignore_entry(repo: &Path, entry: &str) -> anyhow::Result<()> {
    let path = repo.join(".gitignore");
    let content = match std::fs::read_to_string(&path) {
        Ok(existing) => existing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {} failed", path.display())),
    };
    if content.lines().any(|line| line.trim() == entry) {
        return Ok(());
    }
    let mut updated = content;
    // Ensure the appended entry lands on its own line even if the file did not
    // end with a newline.
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(entry);
    updated.push('\n');
    std::fs::write(&path, updated).with_context(|| format!("writing {} failed", path.display()))
}

/// The absolute path of the running binary, for the MCP `command` field.
///
/// Falls back to the bare name (resolved via `PATH` by the client) if the
/// platform cannot report `current_exe` — better a name than a hard failure
/// during provisioning.
pub(crate) fn resolved_binary_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "hippius-mem".to_string())
}

/// Read and parse a JSON config, treating absent-or-empty as `{}`.
fn load_json(path: &Path) -> anyhow::Result<Value> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(json!({})),
        Ok(s) => serde_json::from_str(&s)
            .with_context(|| format!("{} is not valid JSON", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e).with_context(|| format!("reading {} failed", path.display())),
    }
}

/// Pretty-print `config` back to `path` with a trailing newline.
fn write_json(path: &Path, config: &Value) -> anyhow::Result<()> {
    let body = serde_json::to_string_pretty(config).context("serializing MCP config failed")?;
    std::fs::write(path, format!("{body}\n"))
        .with_context(|| format!("writing {} failed", path.display()))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning filesystem/JSON steps"
    )]

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::{SERVER_NAME, ensure_gitignore_entry, register_mcp_repo};

    fn mcp(dir: &TempDir) -> Value {
        let raw = std::fs::read_to_string(dir.path().join(".mcp.json")).expect(".mcp.json exists");
        serde_json::from_str(&raw).expect("valid JSON")
    }

    #[test]
    fn writes_bare_command_and_no_secret() {
        let tmp = TempDir::new().expect("tempdir");
        register_mcp_repo(tmp.path()).expect("register");
        let config = mcp(&tmp);
        let command = config["mcpServers"][SERVER_NAME]["command"]
            .as_str()
            .expect("command must be a string");
        // The committed .mcp.json must carry the bare, PATH-resolved name — never
        // an absolute path, which would encode one machine's layout and break for
        // every teammate who checks out the repo.
        assert_eq!(command, "hippius-mem");
        assert!(
            !command.starts_with('/'),
            "repo command must not be an absolute path: {command}"
        );
        // Repo scope carries no env block at all — nothing machine-specific.
        assert!(
            config["mcpServers"][SERVER_NAME].get("env").is_none(),
            "repo entry must omit env"
        );
        // No secret-shaped keys anywhere in the file.
        let serialized = config.to_string();
        assert!(
            !serialized.contains("team_key"),
            "no secret must be written: {serialized}"
        );
        assert!(
            !serialized.contains("secret"),
            "no secret must be written: {serialized}"
        );
    }

    #[test]
    fn preserves_other_servers() {
        let tmp = TempDir::new().expect("tempdir");
        let seed = json!({ "mcpServers": { "illu": { "command": "illu-rs", "args": ["serve"] } } });
        std::fs::write(
            tmp.path().join(".mcp.json"),
            serde_json::to_string_pretty(&seed).expect("seed json"),
        )
        .expect("seed");
        register_mcp_repo(tmp.path()).expect("register");
        let config = mcp(&tmp);
        assert_eq!(
            config["mcpServers"]["illu"]["command"], "illu-rs",
            "sibling server dropped"
        );
        assert_eq!(config["mcpServers"][SERVER_NAME]["command"], "hippius-mem");
    }

    #[test]
    fn register_is_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        register_mcp_repo(tmp.path()).expect("first");
        register_mcp_repo(tmp.path()).expect("second");
        let config = mcp(&tmp);
        let servers = config["mcpServers"].as_object().expect("object");
        assert_eq!(
            servers.len(),
            1,
            "re-run must not multiply the server entry"
        );
    }

    #[test]
    fn gitignore_appends_once_and_is_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join(".gitignore"), "/target\n").expect("seed");
        ensure_gitignore_entry(tmp.path(), ".hippius-mem/").expect("first");
        ensure_gitignore_entry(tmp.path(), ".hippius-mem/").expect("second");
        let body = std::fs::read_to_string(tmp.path().join(".gitignore")).expect("read");
        assert_eq!(
            body.matches(".hippius-mem/").count(),
            1,
            "entry must appear once: {body}"
        );
        assert!(
            body.contains("/target"),
            "existing entries must survive: {body}"
        );
    }

    #[test]
    fn gitignore_created_when_absent() {
        let tmp = TempDir::new().expect("tempdir");
        ensure_gitignore_entry(tmp.path(), ".hippius-mem/").expect("create");
        let body = std::fs::read_to_string(tmp.path().join(".gitignore")).expect("read");
        assert_eq!(body, ".hippius-mem/\n");
    }
}
