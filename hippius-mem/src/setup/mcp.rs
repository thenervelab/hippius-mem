//! MCP-registration and `.gitignore` provisioning.
//!
//! Writes the `hippius-mem` server entry into a Claude Code MCP config —
//! project-scope `.mcp.json` or user-scope `~/.claude.json` — preserving every
//! other server, and appends the per-machine hook-cache dir to `.gitignore`.
//!
//! Secrets never enter these files: both scopes point `HIPPIUS_MEM_CONFIG` at an
//! absolute config path — a location, never a key. Both entries are per-machine
//! (the repo `.mcp.json` is gitignored by `init`), so each carries the running
//! binary's absolute path rather than a shared, portable name that would depend
//! on every teammate's `PATH`.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::{Value, json};

/// The server key under `mcpServers`. Stable: teammates' configs and this
/// installer must agree on it for a re-run to update rather than duplicate.
const SERVER_NAME: &str = "hippius-mem";

/// Register the server in project-scope `<repo>/.mcp.json`.
///
/// Writes the absolute installed `command` (the running binary's path) plus an
/// absolute `HIPPIUS_MEM_CONFIG` env when `config_path` is `Some`, mirroring the
/// global entry. `.mcp.json` is PER-MACHINE and gitignored (see
/// `super::MCP_JSON_IGNORE`), never committed — an absolute path here is correct
/// precisely because the file is not shared. A prior design wrote the bare name to
/// a *committed* `.mcp.json`; that shifted the fragility onto every teammate's
/// `PATH` (and a stale committed absolute path from an older binary is what
/// shadowed the good global entry and failed to spawn). `self_heal_on_serve`
/// re-writes this file to the current `current_exe()` on every boot, so a
/// reinstalled or moved binary self-corrects rather than leaving a dead path.
///
/// `config_path` is `None` only when `$HOME` cannot be resolved; the entry then
/// omits `env` and the server falls back to its cwd-relative `./hippius-mem.toml`
/// default (Claude Code launches a project server with the repo root as cwd).
///
/// # Errors
///
/// Returns an error if the existing file is not valid JSON or cannot be written.
pub(crate) fn register_mcp_repo(
    repo: &Path,
    command: &str,
    config_path: Option<&Path>,
) -> anyhow::Result<()> {
    let path = repo.join(".mcp.json");
    let entry = match config_path {
        Some(cfg) => json!({
            "command": command,
            "args": [],
            "env": { "HIPPIUS_MEM_CONFIG": cfg.to_string_lossy() },
        }),
        None => json!({ "command": command, "args": [] }),
    };
    let mut config = load_json(&path)?;
    upsert_server(&mut config, entry)?;
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
    let config_path = resolved_global_config_path()
        .unwrap_or_else(|| home.join(".config/hippius-mem/hippius-mem.toml"));
    let entry = json!({
        "command": command,
        "args": [],
        "env": { "HIPPIUS_MEM_CONFIG": config_path.to_string_lossy() },
    });
    let mut config = load_json(&path)?;
    upsert_server(&mut config, entry)?;
    write_json(&path, &config)
}

/// The user-global config file path, honoring `XDG_CONFIG_HOME` then `$HOME`.
///
/// Mirrors the installer's `${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem/
/// hippius-mem.toml` (`scripts/install.sh`) and `dashboard::global_config_path`, so
/// all three agree on where the config lives — hardcoding `~/.config` here made
/// `HIPPIUS_MEM_CONFIG` point at a nonexistent file whenever `XDG_CONFIG_HOME` was
/// set. Pure so the precedence is unit-testable; an empty value is treated as unset
/// to match the shell `:-` fallback. `None` when neither var yields a base dir.
pub(crate) fn global_config_path(
    xdg_config_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    let base = xdg_config_home
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        })?;
    Some(base.join("hippius-mem").join("hippius-mem.toml"))
}

/// [`global_config_path`] resolved from the current environment, or `None` if
/// neither `XDG_CONFIG_HOME` nor `$HOME` is set.
pub(crate) fn resolved_global_config_path() -> Option<PathBuf> {
    global_config_path(
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
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

    use std::ffi::OsStr;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::{SERVER_NAME, ensure_gitignore_entry, global_config_path, register_mcp_repo};

    fn mcp(dir: &TempDir) -> Value {
        let raw = std::fs::read_to_string(dir.path().join(".mcp.json")).expect(".mcp.json exists");
        serde_json::from_str(&raw).expect("valid JSON")
    }

    #[test]
    fn writes_absolute_command_and_config_env() {
        let tmp = TempDir::new().expect("tempdir");
        let cfg = tmp.path().join("cfg/hippius-mem.toml");
        register_mcp_repo(tmp.path(), "/opt/bin/hippius-mem", Some(&cfg)).expect("register");
        let config = mcp(&tmp);
        let entry = &config["mcpServers"][SERVER_NAME];
        // The per-machine (gitignored) .mcp.json carries the absolute installed
        // path — robust against the client's PATH not including ~/.cargo/bin — and
        // pins the config location, mirroring the global entry.
        assert_eq!(
            entry["command"], "/opt/bin/hippius-mem",
            "repo command must be the absolute installed path"
        );
        assert_eq!(
            entry["env"]["HIPPIUS_MEM_CONFIG"],
            cfg.to_string_lossy().as_ref(),
            "repo entry must pin the absolute config path"
        );
        // Only a config *location* is written — never a secret VALUE. Both
        // secret-shaped substrings are asserted because the entry now carries an
        // `env` block: a future change that leaked a key into it must trip a test.
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
    fn global_config_path_honors_xdg_then_home() {
        // XDG_CONFIG_HOME wins when set and non-empty.
        assert_eq!(
            global_config_path(Some(OsStr::new("/xdg")), Some(OsStr::new("/home/u"))),
            Some("/xdg/hippius-mem/hippius-mem.toml".into())
        );
        // Falls back to $HOME/.config when XDG is unset or empty (the shell `:-`).
        assert_eq!(
            global_config_path(None, Some(OsStr::new("/home/u"))),
            Some("/home/u/.config/hippius-mem/hippius-mem.toml".into())
        );
        assert_eq!(
            global_config_path(Some(OsStr::new("")), Some(OsStr::new("/home/u"))),
            Some("/home/u/.config/hippius-mem/hippius-mem.toml".into())
        );
        // Neither set -> no path (caller falls back).
        assert_eq!(global_config_path(None, None), None);
    }

    #[test]
    fn omits_env_when_no_config_path() {
        let tmp = TempDir::new().expect("tempdir");
        // config_path == None models a box where $HOME cannot be resolved: the
        // command is still written, but env is omitted so the server falls back to
        // its cwd-relative ./hippius-mem.toml default.
        register_mcp_repo(tmp.path(), "/opt/bin/hippius-mem", None).expect("register");
        let config = mcp(&tmp);
        assert_eq!(
            config["mcpServers"][SERVER_NAME]["command"],
            "/opt/bin/hippius-mem"
        );
        assert!(
            config["mcpServers"][SERVER_NAME].get("env").is_none(),
            "no config path -> no env block"
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
        register_mcp_repo(tmp.path(), "/opt/bin/hippius-mem", None).expect("register");
        let config = mcp(&tmp);
        assert_eq!(
            config["mcpServers"]["illu"]["command"], "illu-rs",
            "sibling server dropped"
        );
        assert_eq!(
            config["mcpServers"][SERVER_NAME]["command"],
            "/opt/bin/hippius-mem"
        );
    }

    #[test]
    fn register_is_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        register_mcp_repo(tmp.path(), "/opt/bin/hippius-mem", None).expect("first");
        register_mcp_repo(tmp.path(), "/opt/bin/hippius-mem", None).expect("second");
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
