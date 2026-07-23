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
    // Atomic + symlink-safe (CWE-59/377): a co-resident process could plant a
    // symlink at `.gitignore` to redirect this write onto another operator file.
    super::atomic::atomic_write(&path, updated.as_bytes())
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
    super::atomic::atomic_write(&path, updated.as_bytes())
}

/// The absolute path of the running binary, for the MCP `command` field.
///
/// Falls back to the bare name (resolved via `PATH` by the client) if the
/// platform cannot report `current_exe` — better a name than a hard failure
/// during provisioning. [`register_mcp_global`] pins whatever path this returns
/// into `~/.claude.json` for EVERY repo, so a path that looks ephemeral (a
/// `cargo build` output dir, the OS temp dir) gets a warning, not a hard
/// failure: `cargo run`-during-dev must keep working, but the operator should
/// know a later `cargo clean` will break every repo's MCP spawn with no
/// self-heal (`-32000`/ENOENT — finding [21]).
pub(crate) fn resolved_binary_path() -> String {
    let Some(path) = std::env::current_exe().ok() else {
        return "hippius-mem".to_string();
    };
    if is_ephemeral_install_path(&path, &std::env::temp_dir()) {
        tracing::warn!(
            path = %path.display(),
            "hippius-mem's binary path looks ephemeral (under a `target/` build \
             directory or the OS temp dir); registering it in ~/.claude.json means a \
             later `cargo clean` or temp-dir cleanup will delete it, breaking every \
             repo's MCP spawn (-32000/ENOENT) with nothing pointing back here — \
             install to a stable location (e.g. `cargo install --path .` or \
             /usr/local/bin) before running init/install"
        );
    }
    path.to_str()
        .map_or_else(|| "hippius-mem".to_string(), String::from)
}

/// Whether `path` looks like an ephemeral build/temp location: under a
/// `target/` path component (a `cargo build` output directory `cargo clean`
/// wipes) or inside `temp_dir` (the OS scratch directory, cleared on reboot or
/// by OS housekeeping on some platforms).
///
/// Pure and `temp_dir`-parameterized (rather than calling [`std::env::temp_dir`]
/// internally) so the heuristic is unit-testable without touching the real
/// environment. A heuristic, not a proof: a legitimately stable install could
/// coincidentally live under a directory named `target`, and a symlinked
/// `current_exe` this does not resolve could evade the temp-dir check — false
/// negatives here just mean a missed warning, never a hard failure, so erring
/// toward simplicity is the right tradeoff for a diagnostic.
fn is_ephemeral_install_path(path: &Path, temp_dir: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "target") || path.starts_with(temp_dir)
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

/// Pretty-print `config` back to `path` with a trailing newline, atomically and
/// with the destination's permissions preserved.
///
/// Delegates to [`super::atomic::atomic_write`] rather than a hand-rolled
/// `std::fs::write` to a predictable `<name>.tmp.<pid>` sibling, which got two
/// things wrong on this exact file. (1) Mode: `~/.claude.json` is created `0600`
/// by Claude Code and holds OAuth account data, but `std::fs::write` created its
/// temp at the umask default (`0644`) and the rename carried that onto the
/// destination — silently widening the secret-bearing file to group/other-
/// readable on EVERY `install`/`init`. `atomic_write` preserves an existing
/// regular file's mode (via `symlink_metadata`, so `0600` stays `0600`) and keeps
/// tempfile's owner-only `0600` for a fresh file. (2) Symlink: the predictable
/// temp name was plantable, and `deregister_mcp_repo` runs this in the repo root;
/// `atomic_write`'s temp is uniquely named (O_EXCL) and it renames OVER — never
/// through — a symlink at `path` (CWE-59/CWE-377). The crash-safety the previous
/// impl provided is retained: `path` is only ever named by the final rename, and
/// the temp is fsynced first, so a crash leaves the disposable temp, never a torn
/// `path`.
///
/// # Errors
///
/// Returns an error if serialization, the temp-file write/fsync, or the rename
/// fails (see [`super::atomic::atomic_write`]).
fn write_json(path: &Path, config: &Value) -> anyhow::Result<()> {
    let body = serde_json::to_string_pretty(config).context("serializing MCP config failed")?;
    super::atomic::atomic_write(path, format!("{body}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning filesystem/JSON steps"
    )]

    use std::ffi::OsStr;
    use std::path::Path;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::{
        SERVER_NAME, deregister_mcp_repo, ensure_gitignore_entry, global_config_path,
        is_ephemeral_install_path, remove_gitignore_entry, write_json,
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

    #[test]
    fn write_json_round_trips_and_leaves_no_stray_temp_file() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join(".claude.json");
        let config = json!({ "mcpServers": { "hippius-mem": { "command": "hippius-mem" } } });
        write_json(&path, &config).expect("write_json succeeds");
        let read_back: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read"))
            .expect("valid json");
        assert_eq!(read_back, config);
        // The temp file must be consumed by `rename`, not left behind: the
        // directory holds exactly the target, no `.tmp.<pid>` litter.
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("read dir")
            .map(|e| e.expect("dir entry").file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from(".claude.json")],
            "no stray temp file must remain after a successful write: {entries:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_json_leaves_the_original_untouched_when_the_write_fails() {
        use std::os::unix::fs::PermissionsExt;
        // write_json is atomic: `path` is only ever named by the final rename, so a
        // failure to create/write the temp leaves the original byte-identical
        // (never the whole-file truncation a bare `std::fs::write(path, ...)` risks
        // — for `~/.claude.json` that is every OTHER MCP server's registration).
        // Force the failure by making the parent directory unwritable so the temp
        // file cannot be created.
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("cfg");
        std::fs::create_dir(&dir).expect("cfg dir");
        let path = dir.join(".claude.json");
        let original = json!({ "mcpServers": { "other": { "command": "other-server" } } });
        let original_body = serde_json::to_string_pretty(&original).expect("seed json");
        std::fs::write(&path, &original_body).expect("seed original");

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500))
            .expect("make dir read-only");
        let new_config = json!({ "mcpServers": { "hippius-mem": { "command": "x" } } });
        let result = write_json(&path, &new_config);
        // Restore write access so the original reads back and TempDir can clean up.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("restore dir perms");

        assert!(
            result.is_err(),
            "write_json must fail when its temp file cannot be created"
        );
        let survived = std::fs::read_to_string(&path).expect("original still readable");
        assert_eq!(
            survived, original_body,
            "the original file must be byte-identical after a failed write"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_json_preserves_the_destinations_0600_mode() {
        use std::os::unix::fs::PermissionsExt;
        // Regression: `~/.claude.json` is created 0600 and holds OAuth data.
        // write_json must NOT widen it — the old bare `std::fs::write` created its
        // temp at the umask default (0644) and the rename carried that onto the
        // destination on every install/init.
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join(".claude.json");
        std::fs::write(&path, "{}\n").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600");

        let config = json!({ "mcpServers": { "hippius-mem": { "command": "hippius-mem" } } });
        write_json(&path, &config).expect("write_json succeeds");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "write_json must preserve the destination's 0600 mode, not widen it to 0644"
        );
    }

    #[test]
    fn ephemeral_install_path_detection() {
        let temp_dir = Path::new("/tmp");
        assert!(
            is_ephemeral_install_path(Path::new("/repo/target/release/hippius-mem"), temp_dir),
            "a target/ build output dir must be flagged"
        );
        assert!(
            is_ephemeral_install_path(Path::new("/tmp/x/hippius-mem"), temp_dir),
            "a path under the OS temp dir must be flagged"
        );
        assert!(
            !is_ephemeral_install_path(Path::new("/usr/local/bin/hippius-mem"), temp_dir),
            "a stable install location must not be flagged"
        );
        assert!(
            !is_ephemeral_install_path(Path::new("/home/u/.cargo/bin/hippius-mem"), temp_dir),
            "cargo install's bin dir must not be flagged"
        );
    }
}
