//! The hook half of provisioning: write the five `hippius-mem-*.sh` hook scripts
//! into `.claude/hooks/` and merge their entries into `.claude/settings.json`.
//!
//! Generalized over hook EVENT: hippius-mem spans `PreToolUse`, `PostToolUse`,
//! `Stop`, and `SessionStart`. The script bodies are embedded from the canonical
//! `.claude/hooks/*.sh` files, so those files stay the single source of truth and
//! the binary writes them verbatim into a target repo.
//!
//! Grok resolves a hook `command` relative to the settings JSON file
//! (`.claude/settings.json`), so `.claude/hooks/foo.sh` becomes
//! `<repo>/.claude/.claude/hooks/foo.sh`. Claude Code resolves the same string
//! from the repo root. One relative command cannot satisfy both joins unless it
//! is absolute (not portable). Install therefore also plants a Unix symlink
//! `.claude/.claude/hooks` → `../hooks` so Grok's doubled path lands on the
//! real scripts without changing Claude's command strings.

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
    SessionStart,
}

impl HookEvent {
    /// The `settings.json` key for this event.
    fn key(self) -> &'static str {
        match self {
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
            HookEvent::Stop => "Stop",
            HookEvent::SessionStart => "SessionStart",
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

/// The five hooks that enforce recall-before-mutate and remember-after-learn, and
/// nudge a one-time seeding of a repo's pre-existing memory.
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
    // SessionStart, matcher-less: fires on every session source (startup/resume/
    // clear/compact) and self-suppresses once the repo's `seeded` marker exists.
    // SessionStart hooks cannot block, which is fine — this one only injects the
    // seed-checkpoint directive as context.
    HookSpec {
        event: HookEvent::SessionStart,
        matcher: None,
        command_path: ".claude/hooks/hippius-mem-seed-nudge.sh",
        script_body: include_str!("../../../.claude/hooks/hippius-mem-seed-nudge.sh"),
    },
    // SessionStart, matcher-less: injects a tiered digest of the team's live
    // memory (`hippius-mem brief`) so a session starts with ambient knowledge
    // instead of only pull-recall. Best-effort — it injects nothing on any
    // failure and never blocks (SessionStart hooks cannot).
    HookSpec {
        event: HookEvent::SessionStart,
        matcher: None,
        command_path: ".claude/hooks/hippius-mem-session-brief.sh",
        script_body: include_str!("../../../.claude/hooks/hippius-mem-session-brief.sh"),
    },
];

/// Write the five hook scripts into `<repo>/.claude/hooks/`, each owner-executable,
/// and plant the Grok doubled-path shim (see module docs).
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
        // Atomic + symlink-safe (CWE-59/377), like the sibling config writes -- and
        // the highest-value target of the three, since a followed symlink here would
        // then be chmod +x'd. The executable bit is set on the temp BEFORE the
        // rename, so the hook is atomically the right file at the right mode with no
        // post-rename chmod a swapped symlink could redirect.
        super::atomic::atomic_write_executable(&path, spec.script_body.as_bytes())?;
    }
    install_grok_hook_path_shim(repo)
}

/// Merge all five hook entries into `<repo>/.claude/settings.json`, creating the
/// file when absent and preserving every unrelated entry (e.g. another tool's
/// own hooks).
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

/// Remove the five hook scripts and their `settings.json` entries. Used by
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
    remove_grok_hook_path_shim(repo)?;
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

/// Grok-compat path: `.claude/settings.json` + command `.claude/hooks/foo.sh`
/// resolves to `<repo>/.claude/.claude/hooks/foo.sh`. See module docs.
#[cfg(unix)]
const GROK_HOOK_SHIM_DIR: &str = ".claude/.claude";
#[cfg(unix)]
const GROK_HOOK_SHIM: &str = ".claude/.claude/hooks";
#[cfg(unix)]
const GROK_HOOK_SHIM_TARGET: &str = "../hooks";

/// Plant `.claude/.claude/hooks` → `../hooks`. Idempotent; leaves a real
/// file or directory at that path alone so init never clobbers unexpected
/// content.
#[cfg(unix)]
fn install_grok_hook_path_shim(repo: &Path) -> anyhow::Result<()> {
    let shim_dir = repo.join(GROK_HOOK_SHIM_DIR);
    std::fs::create_dir_all(&shim_dir)
        .with_context(|| format!("creating {} failed", shim_dir.display()))?;
    let shim = repo.join(GROK_HOOK_SHIM);
    match std::fs::symlink_metadata(&shim) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = std::fs::read_link(&shim)
                .with_context(|| format!("reading {} failed", shim.display()))?;
            if target == Path::new(GROK_HOOK_SHIM_TARGET) {
                return Ok(());
            }
            std::fs::remove_file(&shim)
                .with_context(|| format!("replacing {} failed", shim.display()))?;
        }
        // A real directory may hold user content; leave it. A regular file is
        // the git `core.symlinks=false` / ZIP placeholder (`../hooks` bytes)
        // and can never be a valid hooks dir — replace it.
        Ok(meta) if meta.file_type().is_dir() => return Ok(()),
        Ok(_) => {
            std::fs::remove_file(&shim)
                .with_context(|| format!("replacing {} failed", shim.display()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("stat {} failed", shim.display()));
        }
    }
    std::os::unix::fs::symlink(GROK_HOOK_SHIM_TARGET, &shim).with_context(|| {
        format!(
            "creating {} -> {GROK_HOOK_SHIM_TARGET} failed",
            shim.display()
        )
    })
}

#[cfg(not(unix))]
fn install_grok_hook_path_shim(_repo: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Remove the Grok doubled-path shim when it is our `../hooks` symlink.
/// A foreign symlink or a real directory is left alone.
#[cfg(unix)]
fn remove_grok_hook_path_shim(repo: &Path) -> anyhow::Result<()> {
    let shim = repo.join(GROK_HOOK_SHIM);
    match std::fs::symlink_metadata(&shim) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = std::fs::read_link(&shim)
                .with_context(|| format!("reading {} failed", shim.display()))?;
            if target == Path::new(GROK_HOOK_SHIM_TARGET) {
                std::fs::remove_file(&shim)
                    .with_context(|| format!("removing {} failed", shim.display()))?;
            }
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("stat {} failed", shim.display()));
        }
    }
    // Best-effort: drop the wrapper dir if we emptied it.
    let _ = std::fs::remove_dir(repo.join(GROK_HOOK_SHIM_DIR));
    Ok(())
}

#[cfg(not(unix))]
fn remove_grok_hook_path_shim(_repo: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Snapshot of a repo's on-disk hook wiring, taken by boot-time self-heal
/// (`super::provision_on_serve`) to decide whether hook-install evidence
/// exists and whether that wiring has drifted.
///
/// The two counts are kept separate rather than collapsed into booleans
/// because the DECISION needs both directions: scripts-without-registration
/// and registration-without-scripts are each evidence of a prior install that
/// drifted, while zero of both is a repo that never opted into hooks (e.g.
/// `init --no-hooks`) and must be left alone.
pub(crate) struct HookWiringStatus {
    /// How many of the [`HOOKS`] script files exist under `.claude/hooks/`.
    installed_scripts: usize,
    /// How many of the [`HOOKS`] command paths are registered in
    /// `.claude/settings.json`. Zero when the file is absent or malformed —
    /// a broken file can prove nothing either way.
    registered_commands: usize,
    /// Whether the Grok doubled-path shim is in a state `install_hook_scripts`
    /// would leave untouched (our symlink, or a real directory it refuses to
    /// clobber). Always `true` off Unix, where the shim does not exist.
    shim_healthy: bool,
}

impl HookWiringStatus {
    /// Whether ANY evidence of a prior hook install exists.
    ///
    /// This is the consent line for boot-time repair: a repo provisioned with
    /// `--no-hooks` has blocks but no traces, and forcing hooks onto it would
    /// override a deliberate standing choice. The shim is deliberately NOT
    /// evidence on its own — it never exists without the scripts that `init`
    /// plants alongside it, and a stray symlink is not consent.
    pub(crate) fn has_traces(&self) -> bool {
        self.installed_scripts > 0 || self.registered_commands > 0
    }

    /// Whether the wiring is exactly what a full install leaves behind, so a
    /// boot finding this state has nothing to repair.
    ///
    /// Anything short of complete — a missing script, a missing registration,
    /// a shim `install_hook_scripts` would change — is drift, and (given
    /// [`has_traces`](Self::has_traces)) worth repairing. The completeness
    /// check must agree with what install actually produces, or every boot
    /// would attempt a "repair" that never converges.
    pub(crate) fn is_complete(&self) -> bool {
        self.installed_scripts == HOOKS.len()
            && self.registered_commands == HOOKS.len()
            && self.shim_healthy
    }
}

/// Probe `repo`'s hook wiring without writing anything. Best-effort and
/// infallible: an unreadable settings file or hooks directory reads as "not
/// there", which errs toward `has_traces() == false` — the do-nothing answer.
pub(crate) fn probe_hook_wiring(repo: &Path) -> HookWiringStatus {
    let installed_scripts = HOOKS
        .iter()
        .filter(|spec| repo.join(spec.command_path).is_file())
        .count();
    // A malformed settings.json counts as zero registrations, not as an error:
    // it can prove nothing either way, and with no scripts present it must not
    // read as install evidence (a foreign broken file is not consent). With
    // scripts present the repo has traces regardless, and the repair path will
    // surface the parse error where it can be acted on.
    let registered_commands = match load_settings(&repo.join(".claude/settings.json")) {
        Ok(settings) => HOOKS
            .iter()
            .filter(|spec| command_registered(&settings, spec))
            .count(),
        Err(err) => {
            tracing::debug!(
                error = %err,
                "hook probe: settings.json unreadable; counting no registrations"
            );
            0
        }
    };
    HookWiringStatus {
        installed_scripts,
        registered_commands,
        shim_healthy: grok_hook_shim_healthy(repo),
    }
}

/// Whether `settings` registers `spec`'s command under its event, in any
/// matcher group — the read-side mirror of [`register_one`]'s merge.
fn command_registered(settings: &Value, spec: &HookSpec) -> bool {
    settings
        .get("hooks")
        .and_then(|hooks| hooks.get(spec.event.key()))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|group| group.get("hooks").and_then(Value::as_array))
        .flatten()
        .any(|entry| entry.get("command").and_then(Value::as_str) == Some(spec.command_path))
}

/// Whether the Grok doubled-path shim is in a state
/// [`install_grok_hook_path_shim`] would leave untouched. The dispositions
/// MUST mirror that function's exactly: anything install would change (a
/// missing shim, a wrong-target symlink, the `core.symlinks=false`
/// regular-file placeholder) reads as drift so a repair converges in one
/// pass, and anything install leaves alone (our symlink, a user's real
/// directory) reads as healthy so boot never attempts a repair that cannot
/// converge.
#[cfg(unix)]
fn grok_hook_shim_healthy(repo: &Path) -> bool {
    let shim = repo.join(GROK_HOOK_SHIM);
    match std::fs::symlink_metadata(&shim) {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::read_link(&shim).is_ok_and(|target| target == Path::new(GROK_HOOK_SHIM_TARGET))
        }
        Ok(meta) if meta.file_type().is_dir() => true,
        // Everything else is a state install would act on: a regular-file
        // placeholder, a missing shim (the common drift), or an unreadable
        // path — the probe reports drift for all of them.
        Ok(_) | Err(_) => false,
    }
}

#[cfg(not(unix))]
fn grok_hook_shim_healthy(_repo: &Path) -> bool {
    true
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

/// Pretty-print `settings` back to `path` with a trailing newline, atomically.
///
/// Routed through [`super::atomic::atomic_write`] so a symlink planted at
/// `.claude/settings.json` cannot redirect the merged-hooks write (CWE-59/377).
fn write_settings(path: &Path, settings: &Value) -> anyhow::Result<()> {
    let body =
        serde_json::to_string_pretty(settings).context("serializing settings.json failed")?;
    super::atomic::atomic_write(path, format!("{body}\n").as_bytes())
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

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning filesystem/JSON steps"
    )]

    use std::path::Path;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::{
        HOOKS, install_hook_scripts, probe_hook_wiring, register_hooks_in_settings,
        unregister_hooks,
    };

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
    fn registers_session_start_seed_nudge() {
        let tmp = TempDir::new().expect("tempdir");
        register_hooks_in_settings(tmp.path()).expect("register");
        let s = settings(tmp.path());
        // The seed nudge is the SessionStart hook (HOOKS[3]).
        assert_eq!(count(&s, "SessionStart", HOOKS[3].command_path), 1);
        let group = s["hooks"]["SessionStart"]
            .as_array()
            .expect("SessionStart array")
            .first()
            .expect("one group");
        // Matcher-less so it fires on every session source; self-suppression is the
        // hook's job, not a matcher's.
        assert!(
            group.get("matcher").is_none(),
            "SessionStart seed nudge must be matcher-less: {group}"
        );
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
        // Seed another tool's Bash gate group that must survive our merge.
        let seed = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash", "hooks": [
                    { "type": "command", "command": ".claude/hooks/other-gate.sh" }
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
            count(&s, "PreToolUse", ".claude/hooks/other-gate.sh"),
            1,
            "sibling gate lost"
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
        // An existing Edit|Write|MultiEdit group (another tool's preflight) — our
        // recall preflight shares its matcher and must join it, not spawn a rival group.
        let seed = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Edit|Write|MultiEdit", "hooks": [
                    { "type": "command", "command": ".claude/hooks/other-preflight.sh" }
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
        #[cfg(unix)]
        assert!(
            !tmp.path().join(super::GROK_HOOK_SHIM).exists(),
            "Grok path shim left behind"
        );
    }

    #[test]
    fn probe_reports_no_traces_on_a_bare_repo() {
        let tmp = TempDir::new().expect("tempdir");
        let status = probe_hook_wiring(tmp.path());
        assert!(
            !status.has_traces(),
            "a repo with no scripts and no registrations has no hook-install evidence"
        );
    }

    #[test]
    fn probe_reports_complete_after_a_full_install() {
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("install");
        register_hooks_in_settings(tmp.path()).expect("register");
        let status = probe_hook_wiring(tmp.path());
        assert!(status.has_traces(), "a full install leaves traces");
        assert!(
            status.is_complete(),
            "a full install must probe complete, or boot self-heal would rewrite \
             the wiring on every start"
        );
    }

    #[test]
    fn probe_flags_a_missing_script_as_drift() {
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("install");
        register_hooks_in_settings(tmp.path()).expect("register");
        std::fs::remove_file(tmp.path().join(HOOKS[0].command_path)).expect("drop one script");
        let status = probe_hook_wiring(tmp.path());
        assert!(status.has_traces(), "registrations remain as evidence");
        assert!(
            !status.is_complete(),
            "a registered hook whose script is gone is drift"
        );
    }

    #[test]
    fn probe_flags_missing_registration_as_drift() {
        // Scripts without registration (settings.json deleted or never merged):
        // the scripts are the evidence, the missing registration is the drift.
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("install");
        let status = probe_hook_wiring(tmp.path());
        assert!(status.has_traces(), "scripts alone are evidence");
        assert!(
            !status.is_complete(),
            "installed scripts with no settings.json registration is drift"
        );

        // The mirror image: registration without scripts.
        let tmp = TempDir::new().expect("tempdir");
        register_hooks_in_settings(tmp.path()).expect("register");
        let status = probe_hook_wiring(tmp.path());
        assert!(status.has_traces(), "registrations alone are evidence");
        assert!(
            !status.is_complete(),
            "registered hooks with no script files is drift"
        );
    }

    #[test]
    fn probe_treats_malformed_settings_as_unregistered() {
        // Malformed settings.json cannot prove anything either way: with scripts
        // present it reads as drift (repair will surface the parse error); with
        // no scripts it must NOT read as evidence, or a foreign broken
        // settings.json would invite hooks into a repo that never had them.
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".claude")).expect("mkdir");
        std::fs::write(tmp.path().join(".claude/settings.json"), "{ not json").expect("seed");
        let status = probe_hook_wiring(tmp.path());
        assert!(
            !status.has_traces(),
            "malformed settings with no scripts must not count as evidence"
        );

        install_hook_scripts(tmp.path()).expect("install");
        let status = probe_hook_wiring(tmp.path());
        assert!(status.has_traces() && !status.is_complete());
    }

    #[cfg(unix)]
    #[test]
    fn probe_flags_shim_drift_but_accepts_a_real_directory() {
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("install");
        register_hooks_in_settings(tmp.path()).expect("register");
        let shim = tmp.path().join(super::GROK_HOOK_SHIM);

        // Missing shim while hooks exist: the drift `init` would repair.
        std::fs::remove_file(&shim).expect("drop shim");
        assert!(
            !probe_hook_wiring(tmp.path()).is_complete(),
            "a missing Grok shim while hooks exist is drift"
        );

        // A regular-file placeholder (git core.symlinks=false checkout):
        // `install_hook_scripts` replaces it, so it counts as drift too.
        std::fs::write(&shim, "../hooks").expect("placeholder");
        assert!(
            !probe_hook_wiring(tmp.path()).is_complete(),
            "a regular-file shim placeholder is drift"
        );

        // A real directory is deliberately left alone by install, so it must
        // count as healthy — otherwise boot would attempt a repair that can
        // never converge, warning forever.
        std::fs::remove_file(&shim).expect("drop placeholder");
        std::fs::create_dir_all(&shim).expect("real dir");
        assert!(
            probe_hook_wiring(tmp.path()).is_complete(),
            "a real directory at the shim path must not read as drift"
        );
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

    #[cfg(unix)]
    #[test]
    fn grok_path_shim_resolves_doubled_claude_command() {
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("install");
        let shim = tmp.path().join(super::GROK_HOOK_SHIM);
        let meta = std::fs::symlink_metadata(&shim).expect("shim exists");
        assert!(
            meta.file_type().is_symlink(),
            "must be a symlink, not a copy"
        );
        assert_eq!(
            std::fs::read_link(&shim).expect("readlink"),
            Path::new(super::GROK_HOOK_SHIM_TARGET)
        );
        let via_shim = shim.join("hippius-mem-recall-preflight.sh");
        let via_real = tmp.path().join(HOOKS[0].command_path);
        assert!(
            via_shim.exists(),
            "Grok doubled path must find the preflight script"
        );
        assert_eq!(
            std::fs::canonicalize(&via_shim).expect("canon shim"),
            std::fs::canonicalize(&via_real).expect("canon real")
        );
    }

    #[cfg(unix)]
    #[test]
    fn grok_path_shim_is_idempotent_and_repairs_a_wrong_symlink() {
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("first");
        install_hook_scripts(tmp.path()).expect("second");
        let shim = tmp.path().join(super::GROK_HOOK_SHIM);
        assert_eq!(
            std::fs::read_link(&shim).expect("readlink after re-run"),
            Path::new(super::GROK_HOOK_SHIM_TARGET)
        );

        std::fs::remove_file(&shim).expect("drop shim");
        std::os::unix::fs::symlink("/tmp", &shim).expect("wrong target");
        install_hook_scripts(tmp.path()).expect("repair");
        assert_eq!(
            std::fs::read_link(&shim).expect("readlink after repair"),
            Path::new(super::GROK_HOOK_SHIM_TARGET)
        );
    }

    #[cfg(unix)]
    #[test]
    fn grok_path_shim_replaces_a_regular_file() {
        let tmp = TempDir::new().expect("tempdir");
        let shim = tmp.path().join(super::GROK_HOOK_SHIM);
        std::fs::create_dir_all(shim.parent().expect("parent")).expect("mkdir");
        std::fs::write(&shim, "../hooks").expect("git symlink placeholder");
        install_hook_scripts(tmp.path()).expect("install");
        let meta = std::fs::symlink_metadata(&shim).expect("shim exists");
        assert!(
            meta.file_type().is_symlink(),
            "a regular file at the shim path must be replaced"
        );
        assert_eq!(
            std::fs::read_link(&shim).expect("readlink"),
            Path::new(super::GROK_HOOK_SHIM_TARGET)
        );
    }

    #[cfg(unix)]
    #[test]
    fn grok_path_shim_leaves_a_real_directory_alone() {
        let tmp = TempDir::new().expect("tempdir");
        let shim = tmp.path().join(super::GROK_HOOK_SHIM);
        std::fs::create_dir_all(&shim).expect("mkdir");
        std::fs::write(shim.join("keep"), "user").expect("write");
        install_hook_scripts(tmp.path()).expect("install");
        assert!(
            shim.join("keep").exists(),
            "init must not clobber unexpected content at the shim path"
        );
        assert!(
            !std::fs::symlink_metadata(&shim)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "must leave the real directory in place"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unregister_leaves_a_foreign_shim_alone() {
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("install");
        let shim = tmp.path().join(super::GROK_HOOK_SHIM);
        std::fs::remove_file(&shim).expect("drop our shim");
        std::os::unix::fs::symlink("/tmp", &shim).expect("foreign symlink");
        unregister_hooks(tmp.path()).expect("unregister");
        assert_eq!(
            std::fs::read_link(&shim).expect("foreign shim must remain"),
            Path::new("/tmp")
        );
    }

    /// If the preflight is invoked the way Grok will (via the doubled path),
    /// `pwd -P` must still treat the temp repo — not `.claude/` — as the root,
    /// otherwise an in-repo Edit would pass through as "outside the tree".
    #[cfg(unix)]
    #[test]
    fn grok_doubled_path_preflight_still_scopes_to_repo_root() {
        assert!(
            std::process::Command::new("jq")
                .arg("--version")
                .output()
                .is_ok(),
            "jq is required for grok_doubled_path_preflight_still_scopes_to_repo_root"
        );
        let tmp = TempDir::new().expect("tempdir");
        install_hook_scripts(tmp.path()).expect("install");
        let target = tmp.path().join("src/lib.rs");
        std::fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        std::fs::write(&target, "fn x() {}\n").expect("write");
        // macOS: TempDir is often `/var/...` while `pwd -P` is `/private/var/...`.
        let file_abs = std::fs::canonicalize(&target).expect("canon target");
        let repo_abs = std::fs::canonicalize(tmp.path()).expect("canon repo");

        // The gate fail-opens (degraded pass, no "block") when hippius-mem is
        // neither on PATH nor MCP-registered — correct for a collaborator who
        // never installed it, but this test's subject is PATH-SCOPING under the
        // Grok shim, which only shows in the block decision. Put a stub binary on
        // PATH so the gate is active regardless of whether the machine running
        // the tests (CI in particular) has hippius-mem installed.
        let stub_bin = tmp.path().join("stub-bin");
        std::fs::create_dir_all(&stub_bin).expect("mkdir stub-bin");
        let stub = stub_bin.join("hippius-mem");
        std::fs::write(&stub, "#!/bin/sh\nexit 0\n").expect("write stub");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
                .expect("chmod stub");
        }
        let path_with_stub = format!(
            "{}:{}",
            stub_bin.to_string_lossy(),
            std::env::var("PATH").unwrap_or_default()
        );

        let script = tmp
            .path()
            .join(super::GROK_HOOK_SHIM)
            .join("hippius-mem-recall-preflight.sh");
        let payload = json!({
            "tool_name": "Edit",
            "tool_input": { "file_path": file_abs.to_string_lossy() },
            "cwd": repo_abs.to_string_lossy(),
            "session_id": "shim-scope-test"
        });
        let output = std::process::Command::new(&script)
            .env_remove("HIPPIUS_MEM_HOOKS_BYPASS")
            .env("PATH", &path_with_stub)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .take()
                    .expect("stdin")
                    .write_all(payload.to_string().as_bytes())?;
                child.wait_with_output()
            })
            .expect("run preflight via shim");
        assert!(
            output.status.success(),
            "preflight must exit 0 (fail-open or block): {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let body: Value = serde_json::from_str(&stdout).expect("preflight must emit JSON");
        assert_eq!(
            body.get("decision").and_then(Value::as_str),
            Some("block"),
            "in-repo Edit via the Grok path must still be gated, not pass-through: {stdout}"
        );
    }
}
