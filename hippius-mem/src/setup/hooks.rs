//! The hook half of provisioning: write the three `hippius-mem-*.sh` hook scripts
//! into `.claude/hooks/` and merge their entries into `.claude/settings.json`.
//!
//! Ported from illu-rs `src/agents/hook_install.rs`, generalized over hook EVENT
//! (illu's hooks are all `PreToolUse`; hippius-mem spans `PreToolUse`,
//! `PostToolUse`, and `Stop`). The script bodies are embedded from the canonical
//! `.claude/hooks/*.sh` files, so those files stay the single source of truth and
//! the binary writes them verbatim into a target repo.

use std::path::Path;

use anyhow::Context;
use serde_json::{Value, json};

/// Which Claude Code hook event a [`HookSpec`] registers under. The `&str` is the
/// exact object key Claude Code reads from `settings.json.hooks`.
#[derive(Debug, Clone, Copy)]
enum HookEvent {
    PreToolUse,
    PostToolUse,
    Stop,
}

impl HookEvent {
    /// The `settings.json` key for this event.
    fn key(self) -> &'static str {
        match self {
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
            HookEvent::Stop => "Stop",
        }
    }
}

/// One hippius-mem hook: where its script lives, which event/matcher registers it,
/// and the script bytes embedded at build time.
///
/// `matcher` is `None` for `Stop` (which has no tool matcher); `Some(pattern)` for
/// the tool-scoped `PreToolUse`/`PostToolUse` hooks. `command_path` is repo-
/// relative so the committed `settings.json` is machine-portable.
struct HookSpec {
    event: HookEvent,
    matcher: Option<&'static str>,
    command_path: &'static str,
    script_body: &'static str,
}

/// The three hooks that enforce recall-before-mutate and remember-after-learn.
///
/// Bodies are `include_str!`'d from `<repo>/.claude/hooks/` (three levels up from
/// this file) so the shipped binary carries the exact scripts this repo runs.
const HOOKS: &[HookSpec] = &[
    HookSpec {
        event: HookEvent::PreToolUse,
        matcher: Some("Edit|Write|MultiEdit"),
        command_path: ".claude/hooks/hippius-mem-recall-preflight.sh",
        script_body: include_str!("../../../.claude/hooks/hippius-mem-recall-preflight.sh"),
    },
    HookSpec {
        event: HookEvent::PostToolUse,
        matcher: Some("mcp__hippius-mem__recall"),
        command_path: ".claude/hooks/hippius-mem-recall-token.sh",
        script_body: include_str!("../../../.claude/hooks/hippius-mem-recall-token.sh"),
    },
    HookSpec {
        event: HookEvent::Stop,
        matcher: None,
        command_path: ".claude/hooks/hippius-mem-remember-nudge.sh",
        script_body: include_str!("../../../.claude/hooks/hippius-mem-remember-nudge.sh"),
    },
];

/// Write the three hook scripts into `<repo>/.claude/hooks/`, each owner-executable.
///
/// # Errors
///
/// Returns an error if a hook directory cannot be created or a script cannot be
/// written.
pub(crate) fn install_hook_scripts(repo: &Path) -> anyhow::Result<()> {
    for spec in HOOKS {
        let path = repo.join(spec.command_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {} failed", parent.display()))?;
        }
        std::fs::write(&path, spec.script_body)
            .with_context(|| format!("writing {} failed", path.display()))?;
        set_executable(&path)?;
    }
    Ok(())
}

/// Merge all three hook entries into `<repo>/.claude/settings.json`, creating the
/// file when absent and preserving every unrelated entry (e.g. illu's own hooks).
///
/// # Errors
///
/// Returns an error if the settings directory cannot be created, the existing
/// file is not valid JSON, or the merged file cannot be written.
pub(crate) fn register_hooks_in_settings(repo: &Path) -> anyhow::Result<()> {
    let path = repo.join(".claude/settings.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {} failed", parent.display()))?;
    }
    let mut settings = load_settings(&path)?;
    for spec in HOOKS {
        register_one(&mut settings, spec)?;
    }
    write_settings(&path, &settings)
}

/// Remove the three hook scripts and their `settings.json` entries. Used by
/// `init --uninstall`; a missing script or settings file is a no-op.
///
/// # Errors
///
/// Returns an error if a present script cannot be removed, or the settings file
/// cannot be parsed or rewritten.
pub(crate) fn unregister_hooks(repo: &Path) -> anyhow::Result<()> {
    for spec in HOOKS {
        let path = repo.join(spec.command_path);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {} failed", path.display())),
        }
    }
    let path = repo.join(".claude/settings.json");
    if !path.exists() {
        return Ok(());
    }
    let mut settings = load_settings(&path)?;
    for spec in HOOKS {
        if let Some(events) = settings
            .get_mut("hooks")
            .and_then(|h| h.get_mut(spec.event.key()))
            .and_then(Value::as_array_mut)
        {
            sweep_command(events, spec.command_path);
        }
    }
    write_settings(&path, &settings)
}

/// Read and parse `settings.json`, treating absent-or-empty as `{}`.
fn load_settings(path: &Path) -> anyhow::Result<Value> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(json!({})),
        Ok(s) => serde_json::from_str(&s)
            .with_context(|| format!("{} is not valid JSON", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e).with_context(|| format!("reading {} failed", path.display())),
    }
}

/// Pretty-print `settings` back to `path` with a trailing newline.
fn write_settings(path: &Path, settings: &Value) -> anyhow::Result<()> {
    let body =
        serde_json::to_string_pretty(settings).context("serializing settings.json failed")?;
    std::fs::write(path, format!("{body}\n"))
        .with_context(|| format!("writing {} failed", path.display()))
}

/// Merge one hook spec into `settings`, replacing any prior entry for the same
/// command so a re-run is idempotent and a moved path leaves no stale reference.
fn register_one(settings: &mut Value, spec: &HookSpec) -> anyhow::Result<()> {
    let events = ensure_events(settings, spec.event)?;
    sweep_command(events, spec.command_path);

    let entry = json!({ "type": "command", "command": spec.command_path });
    if let Some(group) = events.iter_mut().find(|g| group_matches(g, spec.matcher)) {
        if let Some(inner) = group.get_mut("hooks").and_then(Value::as_array_mut) {
            inner.push(entry);
        }
        return Ok(());
    }
    events.push(new_group(spec.matcher, entry));
    Ok(())
}

/// Ensure `settings.hooks.<event>` is an array and return a mutable handle to it.
fn ensure_events(settings: &mut Value, event: HookEvent) -> anyhow::Result<&mut Vec<Value>> {
    let root = settings
        .as_object_mut()
        .context("settings.json root is not a JSON object")?;
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    let hooks = hooks
        .as_object_mut()
        .context("settings.json `hooks` is not a JSON object")?;
    let events = hooks.entry(event.key()).or_insert_with(|| json!([]));
    events
        .as_array_mut()
        .context("settings.json hook-event value is not a JSON array")
}

/// Drop every entry for `command_path` from all groups, then discard any group
/// left with an empty `hooks` array (avoids `{matcher, hooks: []}` litter).
fn sweep_command(events: &mut Vec<Value>, command_path: &str) {
    for group in events.iter_mut() {
        if let Some(inner) = group.get_mut("hooks").and_then(Value::as_array_mut) {
            inner.retain(|e| e.get("command").and_then(Value::as_str) != Some(command_path));
        }
    }
    events.retain(|g| {
        g.get("hooks")
            .and_then(Value::as_array)
            .is_none_or(|a| !a.is_empty())
    });
}

/// Whether `group`'s `matcher` field equals `matcher` (both absent counts as a
/// match — that is how the `Stop` groups, which carry no matcher, are found).
fn group_matches(group: &Value, matcher: Option<&str>) -> bool {
    group.get("matcher").and_then(Value::as_str) == matcher
}

/// Build a fresh matcher-group holding `entry`, omitting `matcher` when `None`.
fn new_group(matcher: Option<&str>, entry: Value) -> Value {
    let mut group = serde_json::Map::new();
    if let Some(pattern) = matcher {
        group.insert("matcher".to_string(), json!(pattern));
    }
    // `Value::Array(vec![entry])` moves `entry`; `json!([entry])` would only
    // borrow it, leaving the by-value parameter needlessly un-consumed.
    group.insert("hooks".to_string(), Value::Array(vec![entry]));
    Value::Object(group)
}

/// Set the owner-executable bit on Unix so Claude Code can run the hook.
#[cfg(unix)]
fn set_executable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {} failed", path.display()))?
        .permissions();
    // 0o755: rwx for owner, rx for group/other — the standard mode for a shell
    // hook Claude Code execs.
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("chmod {} failed", path.display()))
}

/// No-op on non-Unix: Windows hook execution is out of scope.
#[cfg(not(unix))]
fn set_executable(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning filesystem/JSON steps"
    )]

    use std::path::Path;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::{HOOKS, install_hook_scripts, register_hooks_in_settings, unregister_hooks};

    fn settings(dir: &Path) -> Value {
        let raw = std::fs::read_to_string(dir.join(".claude/settings.json"))
            .expect("settings.json must exist");
        serde_json::from_str(&raw).expect("settings.json must be valid JSON")
    }

    /// Count entries across all groups of an event whose command == `command`.
    fn count(settings: &Value, event: &str, command: &str) -> usize {
        settings["hooks"][event]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|g| g.get("hooks").and_then(Value::as_array))
            .flatten()
            .filter(|e| e.get("command").and_then(Value::as_str) == Some(command))
            .count()
    }

    #[test]
    fn registers_all_three_events_when_settings_absent() {
        let tmp = TempDir::new().expect("tempdir");
        register_hooks_in_settings(tmp.path()).expect("register");
        let s = settings(tmp.path());
        assert_eq!(count(&s, "PreToolUse", HOOKS[0].command_path), 1);
        assert_eq!(count(&s, "PostToolUse", HOOKS[1].command_path), 1);
        assert_eq!(count(&s, "Stop", HOOKS[2].command_path), 1);
    }

    #[test]
    fn is_idempotent_across_reruns() {
        let tmp = TempDir::new().expect("tempdir");
        register_hooks_in_settings(tmp.path()).expect("first");
        register_hooks_in_settings(tmp.path()).expect("second");
        let s = settings(tmp.path());
        // Exactly one entry per hook — no duplication on re-run.
        for spec in HOOKS {
            assert_eq!(
                count(&s, spec.event.key(), spec.command_path),
                1,
                "{}",
                spec.command_path
            );
        }
    }

    #[test]
    fn preserves_a_sibling_bash_gate_group() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".claude")).expect("mkdir");
        // Seed an illu-style Bash gate group that must survive our merge.
        let seed = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [
                    { "type": "command", "command": ".claude/hooks/illu-quality-gate.sh" }
                ]}
            ]}
        });
        std::fs::write(
            tmp.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&seed).expect("seed json"),
        )
        .expect("seed write");

        register_hooks_in_settings(tmp.path()).expect("register");
        let s = settings(tmp.path());
        assert_eq!(
            count(&s, "PreToolUse", ".claude/hooks/illu-quality-gate.sh"),
            1,
            "illu gate lost"
        );
        assert_eq!(
            count(&s, "PreToolUse", HOOKS[0].command_path),
            1,
            "our hook missing"
        );
    }

    #[test]
    fn co_hosts_in_an_existing_edit_write_matcher_group() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".claude")).expect("mkdir");
        // An existing Edit|Write|MultiEdit group (illu-preflight) — our recall
        // preflight shares its matcher and must join it, not spawn a rival group.
        let seed = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Edit|Write|MultiEdit", "hooks": [
                    { "type": "command", "command": ".claude/hooks/illu-preflight.sh" }
                ]}
            ]}
        });
        std::fs::write(
            tmp.path().join(".claude/settings.json"),
            serde_json::to_string_pretty(&seed).expect("seed json"),
        )
        .expect("seed write");

        register_hooks_in_settings(tmp.path()).expect("register");
        let s = settings(tmp.path());
        let groups = s["hooks"]["PreToolUse"]
            .as_array()
            .expect("array")
            .iter()
            .filter(|g| g.get("matcher").and_then(Value::as_str) == Some("Edit|Write|MultiEdit"))
            .count();
        assert_eq!(
            groups, 1,
            "must co-host in one Edit|Write group, not two: {s}"
        );
    }

    #[test]
    fn malformed_settings_surfaces_an_error() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".claude")).expect("mkdir");
        std::fs::write(tmp.path().join(".claude/settings.json"), "{ not json").expect("seed");
        let err = register_hooks_in_settings(tmp.path()).expect_err("must reject malformed JSON");
        assert!(
            err.to_string().contains("not valid JSON"),
            "context should name it: {err}"
        );
    }

    #[test]
    fn unregister_removes_entries_and_scripts() {
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("install scripts");
        register_hooks_in_settings(tmp.path()).expect("register");
        unregister_hooks(tmp.path()).expect("unregister");
        let s = settings(tmp.path());
        for spec in HOOKS {
            assert_eq!(
                count(&s, spec.event.key(), spec.command_path),
                0,
                "{}",
                spec.command_path
            );
            assert!(
                !tmp.path().join(spec.command_path).exists(),
                "script left behind"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn scripts_are_written_executable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("install");
        for spec in HOOKS {
            let mode = std::fs::metadata(tmp.path().join(spec.command_path))
                .expect("stat")
                .permissions()
                .mode();
            assert_ne!(
                mode & 0o100,
                0,
                "owner-executable bit must be set on {}",
                spec.command_path
            );
        }
    }
}
