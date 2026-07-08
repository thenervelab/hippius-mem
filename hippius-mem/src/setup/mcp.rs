//! MCP-registration and `.gitignore` provisioning.
//!
//! hippius-mem registers its MCP server ONLY in user-scope `~/.claude.json` (see
//! [`register_mcp_global`]); it does NOT write a project-scope `<repo>/.mcp.json`
//! entry. A project entry would be per-machine (gitignored — no cross-teammate
//! value) yet would OVERRIDE the good user-scope entry: a stale one shadows it and
//! fails to spawn (the ENOENT / config-not-found `-32000` failures). So `init`
//! instead REMOVES any hippius-mem entry a prior version left in a repo's
//! `.mcp.json` (see [`deregister_mcp_repo`]), preserving other servers, and the one
//! global entry serves every repo — routing to the right team by the launch repo's
//! git remote against the `[[teams]]` in the global config.
//!
//! Secrets never enter these files: the global entry points `HIPPIUS_MEM_CONFIG`
//! at an absolute config path — a location, never a key.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::{Value, json};

/// The server key under `mcpServers`. Stable: teammates' configs and this
/// installer must agree on it for a re-run to update rather than duplicate.
const SERVER_NAME: &str = "hippius-mem";

/// Remove any `hippius-mem` server entry from project-scope `<repo>/.mcp.json`,
/// leaving every other server untouched.
///
/// hippius-mem registers only in user-scope `~/.claude.json`; a project entry would
/// merely shadow it, and a stale one is the `-32000`/ENOENT failure. This cleans up
/// entries a prior version wrote. Guarantees:
///
/// - It NEVER creates `.mcp.json` (a missing file is a no-op).
/// - When our entry is ABSENT it does not rewrite the file at all — a repo that
///   commits `.mcp.json` for other servers sees no diff. (When our entry IS present,
///   removing it is a deliberate change; the surviving servers are re-serialized, so
///   their key order / indentation may normalize — that is the intended cleanup, not
///   a spurious diff.)
/// - It tolerates a malformed `.mcp.json` (a repo's file for another server with a
///   syntax error): it is left untouched rather than erroring, so this cleanup step
///   cannot fail an `init`/uninstall on a file that is not ours.
/// - If removing our entry leaves `{"mcpServers": {}}` and nothing else, the now
///   purposeless file is deleted rather than left as an empty artifact.
///
/// # Errors
///
/// Returns an error only on a genuine I/O fault reading, writing, or removing the
/// file (not on a missing or malformed one).
pub(crate) fn deregister_mcp_repo(repo: &Path) -> anyhow::Result<()> {
    let path = repo.join(".mcp.json");
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {} failed", path.display())),
    };
    let Ok(mut config) = serde_json::from_str::<Value>(&content) else {
        tracing::debug!(
            path = %path.display(),
            "deregister: .mcp.json is not valid JSON; leaving it untouched"
        );
        return Ok(());
    };
    let removed = config
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .is_some_and(|servers| servers.remove(SERVER_NAME).is_some());
    if !removed {
        return Ok(());
    }
    // Removing our entry may have emptied the file; delete a now-purposeless
    // `{"mcpServers": {}}` rather than leave an artifact, else rewrite the remainder.
    if is_empty_config(&config) {
        return std::fs::remove_file(&path)
            .with_context(|| format!("removing {} failed", path.display()));
    }
    write_json(&path, &config)
}

/// Whether `config` is exactly `{"mcpServers": {}}` — nothing of value remains after
/// removing our entry.
fn is_empty_config(config: &Value) -> bool {
    config.as_object().is_some_and(|root| {
        root.len() == 1
            && root
                .get("mcpServers")
                .and_then(Value::as_object)
                .is_some_and(serde_json::Map::is_empty)
    })
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

/// Remove every full-line occurrence of `entry` from `<repo>/.gitignore`.
///
/// The inverse of [`ensure_gitignore_entry`], to undo a line an earlier version
/// added (`.mcp.json`) once hippius-mem no longer manages that path. A missing file
/// or absent line is a no-op, and only a whole-line match is removed, so unrelated
/// patterns survive. The file's trailing-newline state is preserved.
///
/// # Errors
///
/// Returns an error if `.gitignore` cannot be read or written.
pub(crate) fn remove_gitignore_entry(repo: &Path, entry: &str) -> anyhow::Result<()> {
    let path = repo.join(".gitignore");
    let content = match std::fs::read_to_string(&path) {
        Ok(existing) => existing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {} failed", path.display())),
    };
    if !content.lines().any(|line| line.trim() == entry) {
        return Ok(());
    }
    let kept: Vec<&str> = content
        .lines()
        .filter(|line| line.trim() != entry)
        .collect();
    let mut updated = kept.join("\n");
    // `lines()` drops the line terminator; restore a trailing newline if the source
    // had one, so removing an entry does not strip the file's final newline.
    if content.ends_with('\n') && !updated.is_empty() {
        updated.push('\n');
    }
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

    use super::{
        SERVER_NAME, deregister_mcp_repo, ensure_gitignore_entry, global_config_path,
        remove_gitignore_entry,
    };

    fn mcp(dir: &TempDir) -> Value {
        let raw = std::fs::read_to_string(dir.path().join(".mcp.json")).expect(".mcp.json exists");
        serde_json::from_str(&raw).expect("valid JSON")
    }

    #[test]
    fn deregister_removes_our_entry_preserving_others() {
        let tmp = TempDir::new().expect("tempdir");
        // A .mcp.json carrying our (stale) entry alongside another server.
        let seed = json!({ "mcpServers": {
            "hippius-mem": { "command": "hippius-mem", "args": [] },
            "illu": { "command": "illu-rs", "args": ["serve"] },
        }});
        std::fs::write(
            tmp.path().join(".mcp.json"),
            serde_json::to_string_pretty(&seed).expect("seed json"),
        )
        .expect("seed");
        deregister_mcp_repo(tmp.path()).expect("deregister");
        let config = mcp(&tmp);
        assert!(
            config["mcpServers"].get(SERVER_NAME).is_none(),
            "our entry must be removed so the global registration is not shadowed: {config}"
        );
        assert_eq!(
            config["mcpServers"]["illu"]["command"], "illu-rs",
            "a sibling server must survive"
        );
    }

    #[test]
    fn deregister_deletes_file_when_our_entry_was_the_only_server() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join(".mcp.json");
        // The common upgrade case: a prior version wrote a .mcp.json holding ONLY our
        // entry. Removing it must delete the file, not leave `{"mcpServers": {}}`.
        let seed = json!({ "mcpServers": { "hippius-mem": { "command": "x", "args": [] } } });
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&seed).expect("seed json"),
        )
        .expect("seed");
        deregister_mcp_repo(tmp.path()).expect("deregister");
        assert!(
            !path.exists(),
            "an emptied .mcp.json must be deleted, not left as an artifact"
        );
    }

    #[test]
    fn deregister_tolerates_a_malformed_foreign_file() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join(".mcp.json");
        // A repo's committed .mcp.json for another server with a syntax error must not
        // fail the cleanup (and must be left byte-identical).
        let junk = "{ \"mcpServers\": { \"illu\": }, trailing";
        std::fs::write(&path, junk).expect("seed");
        deregister_mcp_repo(tmp.path()).expect("must not error on malformed JSON");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            junk,
            "a malformed file must be left untouched"
        );
    }

    #[test]
    fn remove_gitignore_entry_strips_only_the_matching_line() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join(".gitignore");
        std::fs::write(&path, "/target\n.mcp.json\n.hippius-mem/\n").expect("seed");
        remove_gitignore_entry(tmp.path(), ".mcp.json").expect("remove");
        let body = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            body, "/target\n.hippius-mem/\n",
            "only the .mcp.json line must go, others preserved with trailing newline: {body:?}"
        );
        // Idempotent + no-op when the line (or file) is absent.
        remove_gitignore_entry(tmp.path(), ".mcp.json").expect("second");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "/target\n.hippius-mem/\n"
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
    fn deregister_never_creates_the_file() {
        let tmp = TempDir::new().expect("tempdir");
        // No .mcp.json -> no-op, and the file is NOT created: hippius-mem registers
        // only in ~/.claude.json, so a fresh repo must gain no project entry.
        deregister_mcp_repo(tmp.path()).expect("deregister");
        assert!(
            !tmp.path().join(".mcp.json").exists(),
            "deregister must not create .mcp.json"
        );
    }

    #[test]
    fn deregister_leaves_a_foreign_file_byte_identical() {
        let tmp = TempDir::new().expect("tempdir");
        // A .mcp.json with only OTHER servers must be untouched (no spurious diff for
        // a repo that legitimately commits .mcp.json for another server), and the
        // second call is idempotent.
        let seed = "{\n  \"mcpServers\": {\n    \"illu\": {\n      \"command\": \"illu-rs\"\n    }\n  }\n}\n";
        let path = tmp.path().join(".mcp.json");
        std::fs::write(&path, seed).expect("seed");
        deregister_mcp_repo(tmp.path()).expect("first");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            seed,
            "a file without our entry must be left byte-identical"
        );
        deregister_mcp_repo(tmp.path()).expect("second");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), seed);
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
