//! Hermes memory-provider install (not MCP).
//!
//! `install --agent hermes` copies the stdlib plugin into
//! `$HERMES_HOME/plugins/hippius-mem/`, writes a sidecar JSON pinning the
//! binary and `HIPPIUS_MEM_CONFIG`, sets `memory.provider: hippius-mem`, and
//! strips any leftover `mcp_servers.hippius-mem` entry from v0.1.0.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use super::agents;
use super::atomic::atomic_write;
use super::mcp::McpLaunch;

const PROVIDER: &str = "hippius-mem";
const PLUGIN_DIR: &str = "plugins/hippius-mem";
const SIDECAR: &str = "hippius-mem.json";
const CONFIG_YAML: &str = "config.yaml";
/// 0.2.0's copied yaml omitted this; doctor must not treat that copy as wired.
const REQUIRED_PLUGIN_HOOK: &str = "system_prompt_block";

const PLUGIN_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../integrations/hermes/hippius_mem/__init__.py"
));
const PLUGIN_CLIENT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../integrations/hermes/hippius_mem/mcp_client.py"
));
const PLUGIN_YAML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../integrations/hermes/hippius_mem/plugin.yaml"
));
const PLUGIN_README: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../integrations/hermes/hippius_mem/README.md"
));

const PLUGIN_FILES: &[(&str, &str)] = &[
    ("__init__.py", PLUGIN_INIT),
    ("mcp_client.py", PLUGIN_CLIENT),
    ("plugin.yaml", PLUGIN_YAML),
    ("README.md", PLUGIN_README),
];

/// Hermes-specific `install` flags.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct HermesOpts {
    /// `--hermes-home <path>`.
    pub(crate) home: Option<PathBuf>,
    /// `--hermes-profile <name>`.
    pub(crate) profile: Option<String>,
    /// `--hermes-all-profiles`.
    pub(crate) all_profiles: bool,
}

impl HermesOpts {
    /// True when the operator named a Hermes target (`--hermes-home`,
    /// `--hermes-profile`, or `--hermes-all-profiles`).
    pub(crate) fn requested(&self) -> bool {
        self.home.is_some() || self.profile.is_some() || self.all_profiles
    }
}

/// Whether Hermes should be in the `--all-detected` set.
///
/// `--hermes-home` counts even if the directory does not exist yet (`install`
/// creates it). `hermes_home_env` is injected so tests do not read process
/// `HERMES_HOME`.
pub(super) fn is_detected(
    user_home: &Path,
    opts: &HermesOpts,
    hermes_home_env: Option<&std::ffi::OsStr>,
) -> bool {
    opts.requested()
        || hermes_home_env.is_some_and(|path| Path::new(path).is_dir())
        || user_home.join(".hermes").is_dir()
}

/// Install the memory-provider plugin into each resolved Hermes home.
///
/// # Errors
///
/// Returns an error on a conflicting profile flag, a missing named profile,
/// a flow-style `memory:` mapping, or an existing `memory.provider` that is
/// not `hippius-mem` / `builtin` / empty.
pub(crate) fn install(
    user_home: &Path,
    launch: &McpLaunch,
    opts: &HermesOpts,
) -> anyhow::Result<()> {
    install_with(user_home, launch, opts, std::env::var_os("HERMES_HOME"))
}

/// [`install`] with an injected `HERMES_HOME` so tests cannot touch a real profile.
pub(crate) fn install_with(
    user_home: &Path,
    launch: &McpLaunch,
    opts: &HermesOpts,
    hermes_home_env: Option<std::ffi::OsString>,
) -> anyhow::Result<()> {
    for root in resolve_roots(user_home, opts, hermes_home_env)? {
        install_into(&root, launch)?;
    }
    Ok(())
}

/// Reverse [`install`]: plugin dir, sidecar, `memory.provider` if we set it,
/// leftover MCP entry.
///
/// # Errors
///
/// Returns an error only on a genuine I/O fault writing a well-formed file.
pub(crate) fn uninstall(user_home: &Path, opts: &HermesOpts) -> anyhow::Result<()> {
    uninstall_with(user_home, opts, std::env::var_os("HERMES_HOME"))
}

/// [`uninstall`] with an injected `HERMES_HOME` so tests cannot touch a real profile.
pub(crate) fn uninstall_with(
    user_home: &Path,
    opts: &HermesOpts,
    hermes_home_env: Option<std::ffi::OsString>,
) -> anyhow::Result<()> {
    let Ok(roots) = resolve_roots(user_home, opts, hermes_home_env) else {
        return Ok(());
    };
    for root in roots {
        uninstall_from(&root)?;
    }
    Ok(())
}

fn resolve_roots(
    user_home: &Path,
    opts: &HermesOpts,
    hermes_home_env: Option<std::ffi::OsString>,
) -> anyhow::Result<Vec<PathBuf>> {
    if opts.profile.is_some() && opts.all_profiles {
        bail!("--hermes-profile and --hermes-all-profiles cannot be combined");
    }
    let default_root = opts
        .home
        .clone()
        .or_else(|| hermes_home_env.map(PathBuf::from))
        .unwrap_or_else(|| user_home.join(".hermes"));

    if let Some(name) = &opts.profile {
        let dir = profile_dir(&default_root, name);
        if !dir.is_dir() {
            bail!(
                "Hermes profile `{name}` does not exist at {} — create it first, or omit --hermes-profile",
                dir.display()
            );
        }
        return Ok(vec![dir]);
    }
    if opts.all_profiles {
        let mut roots = vec![default_root.clone()];
        let profiles = default_root.join("profiles");
        if let Ok(entries) = std::fs::read_dir(&profiles) {
            for entry in entries {
                let path = entry
                    .with_context(|| format!("reading {} failed", profiles.display()))?
                    .path();
                if path.is_dir() && path.join(CONFIG_YAML).is_file() {
                    roots.push(path);
                }
            }
        }
        return Ok(roots);
    }
    Ok(vec![default_root])
}

fn profile_dir(default_root: &Path, name: &str) -> PathBuf {
    match default_root.parent() {
        Some(profiles)
            if profiles
                .file_name()
                .is_some_and(|parent| parent == "profiles") =>
        {
            profiles.join(name)
        }
        _ => default_root.join("profiles").join(name),
    }
}

fn install_into(root: &Path, launch: &McpLaunch) -> anyhow::Result<()> {
    let plugin_dir = root.join(PLUGIN_DIR);
    std::fs::create_dir_all(&plugin_dir)
        .with_context(|| format!("creating {} failed", plugin_dir.display()))?;
    for (name, body) in PLUGIN_FILES {
        atomic_write(&plugin_dir.join(name), body.as_bytes())?;
    }

    let sidecar = serde_json::json!({
        "binary": launch.command,
        "config_path": launch.config_path,
    });
    let sidecar_body = serde_json::to_vec_pretty(&sidecar).context("serializing Hermes sidecar")?;
    atomic_write(&root.join(SIDECAR), &sidecar_body)?;

    let config_path = root.join(CONFIG_YAML);
    let existing = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(e).with_context(|| format!("reading {} failed", config_path.display()));
        }
    };
    let without_mcp = match agents::remove_yaml_server(&existing) {
        Ok(text) => text,
        Err(_) => existing.clone(),
    };
    let updated = upsert_memory_provider(&without_mcp, PROVIDER)
        .with_context(|| format!("updating {} failed", config_path.display()))?;
    atomic_write(&config_path, updated.as_bytes())?;
    Ok(())
}

fn uninstall_from(root: &Path) -> anyhow::Result<()> {
    let plugin_dir = root.join(PLUGIN_DIR);
    if plugin_dir.is_dir() {
        std::fs::remove_dir_all(&plugin_dir)
            .with_context(|| format!("removing {} failed", plugin_dir.display()))?;
    }
    let sidecar = root.join(SIDECAR);
    match std::fs::remove_file(&sidecar) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing {} failed", sidecar.display())),
    }
    let config_path = root.join(CONFIG_YAML);
    let existing = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).with_context(|| format!("reading {} failed", config_path.display()));
        }
    };
    let without_mcp = match agents::remove_yaml_server(&existing) {
        Ok(text) => text,
        Err(_) => existing.clone(),
    };
    let updated = match clear_memory_provider(&without_mcp, PROVIDER) {
        Ok(text) => text,
        Err(_) => without_mcp,
    };
    if updated != existing {
        atomic_write(&config_path, updated.as_bytes())?;
    }
    Ok(())
}

fn upsert_memory_provider(text: &str, provider: &str) -> anyhow::Result<String> {
    if agents::yaml_has_flow_key(text, "memory") {
        bail!(
            "Hermes config uses a flow-style `memory:` mapping; set memory.provider \
             to `{provider}` by hand (or rewrite that key as a block mapping) rather \
             than letting install clobber it"
        );
    }
    if let Some(current) = memory_provider_value(text)
        && !current.is_empty()
        && current != provider
        && current != "builtin"
    {
        bail!(
            "Hermes memory.provider is already `{current}`; hippius-mem will not \
             replace another provider. Switch with `hermes config set memory.provider {provider}` \
             (or clear that key) and re-run install"
        );
    }
    let block = format!("  provider: {provider}\n");
    if text.trim().is_empty() {
        return Ok(format!("memory:\n{block}"));
    }
    let Some(memory_line) = agents::find_top_level_key(text, "memory") else {
        let mut out = text.to_owned();
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("memory:\n");
        out.push_str(&block);
        return Ok(out);
    };
    let section_end = agents::next_top_level_after(text, memory_line);
    if let Some(entry_line) = agents::find_indented_key(text, memory_line, section_end, "provider")
    {
        let entry_end = agents::next_indent_leq(text, entry_line, section_end, 2);
        return Ok(agents::replace_span(text, entry_line, entry_end, &block));
    }
    let insert_at = agents::after_line(text, memory_line);
    let mut out = String::new();
    out.push_str(&text[..insert_at]);
    out.push_str(&block);
    out.push_str(&text[insert_at..]);
    Ok(out)
}

fn clear_memory_provider(text: &str, provider: &str) -> anyhow::Result<String> {
    if agents::yaml_has_flow_key(text, "memory") {
        bail!("flow-style memory");
    }
    let Some(current) = memory_provider_value(text) else {
        return Ok(text.to_owned());
    };
    if current != provider {
        return Ok(text.to_owned());
    }
    let Some(memory_line) = agents::find_top_level_key(text, "memory") else {
        return Ok(text.to_owned());
    };
    let section_end = agents::next_top_level_after(text, memory_line);
    let Some(entry_line) = agents::find_indented_key(text, memory_line, section_end, "provider")
    else {
        return Ok(text.to_owned());
    };
    let entry_end = agents::next_indent_leq(text, entry_line, section_end, 2);
    Ok(agents::replace_span(text, entry_line, entry_end, ""))
}

/// How Hermes is wired on this machine, if at all.
///
/// [`doctor`](crate::doctor) uses this so `doctor --offline` can fail a
/// first-landing that never ran `install --agent hermes`, instead of reporting
/// a green bundle while the agent still has no `recall` / `remember` / `get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HermesWiring {
    /// No `~/.hermes` and no directory `HERMES_HOME`. Doctor skips.
    Absent,
    /// Plugin, sidecar (binary + config path), and `memory.provider: hippius-mem`.
    Wired,
    /// Hermes is present but `memory.provider` names a different backend.
    /// Doctor warns and does not fail — install refuses to clobber it.
    OtherProvider(String),
    /// Hermes is present and should be hippius-mem, but pieces are missing.
    Incomplete {
        /// Stable, operator-facing reasons (`plugin missing`, …).
        reasons: Vec<String>,
    },
}

/// Inspect the Hermes home this process would use (`HERMES_HOME` if it is a
/// directory, else `user_home/.hermes`).
///
/// `hermes_home_env` is injected so tests never read process `HERMES_HOME`
/// (that env would rewrite a real profile — see the recorded gotcha).
pub(crate) fn wiring_status(
    user_home: &Path,
    hermes_home_env: Option<&std::ffi::OsStr>,
) -> HermesWiring {
    let opts = HermesOpts::default();
    if !is_detected(user_home, &opts, hermes_home_env) {
        return HermesWiring::Absent;
    }
    let root = match hermes_home_env {
        Some(path) if Path::new(path).is_dir() => PathBuf::from(path),
        _ => user_home.join(".hermes"),
    };
    inspect_root(&root)
}

fn inspect_root(root: &Path) -> HermesWiring {
    let config_text = std::fs::read_to_string(root.join(CONFIG_YAML)).unwrap_or_default();
    if let Some(current) = memory_provider_value(&config_text)
        && !current.is_empty()
        && current != PROVIDER
        && current != "builtin"
    {
        return HermesWiring::OtherProvider(current);
    }

    let mut reasons = Vec::new();
    inspect_plugin(&root.join(PLUGIN_DIR).join("plugin.yaml"), &mut reasons);
    inspect_sidecar(&root.join(SIDECAR), &mut reasons);
    match memory_provider_value(&config_text).as_deref() {
        Some(PROVIDER) => {}
        _ => reasons.push("memory.provider is not hippius-mem".to_owned()),
    }

    if reasons.is_empty() {
        HermesWiring::Wired
    } else {
        HermesWiring::Incomplete { reasons }
    }
}

fn inspect_plugin(path: &Path, reasons: &mut Vec<String>) {
    match std::fs::read_to_string(path) {
        Ok(text) if plugin_declares_hook(&text, REQUIRED_PLUGIN_HOOK) => {}
        Ok(_) => reasons.push("plugin missing system_prompt_block hook".to_owned()),
        Err(_) if !path.is_file() => reasons.push("plugin missing".to_owned()),
        Err(_) => reasons.push("plugin unreadable".to_owned()),
    }
}

fn plugin_declares_hook(text: &str, hook: &str) -> bool {
    text.lines().any(|line| {
        line.trim()
            .strip_prefix('-')
            .map(str::trim)
            .is_some_and(|item| item == hook)
    })
}

fn inspect_sidecar(path: &Path, reasons: &mut Vec<String>) {
    if !path.is_file() {
        reasons.push("sidecar missing".to_owned());
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        reasons.push("sidecar unreadable".to_owned());
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        reasons.push("sidecar unreadable".to_owned());
        return;
    };
    match value.get("binary").and_then(serde_json::Value::as_str) {
        Some(bin) if Path::new(bin).is_file() => {}
        _ => reasons.push("sidecar binary not found".to_owned()),
    }
    match value.get("config_path").and_then(serde_json::Value::as_str) {
        Some(cfg) if Path::new(cfg).is_file() => {}
        _ => reasons.push("sidecar config_path not found".to_owned()),
    }
}

fn memory_provider_value(text: &str) -> Option<String> {
    let memory_line = agents::find_top_level_key(text, "memory")?;
    let section_end = agents::next_top_level_after(text, memory_line);
    let entry_line = agents::find_indented_key(text, memory_line, section_end, "provider")?;
    let line = text[entry_line..].lines().next()?;
    let value = line.trim_start().strip_prefix("provider:")?.trim();
    Some(unquote(value))
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        if (bytes[0] == b'"' && bytes[trimmed.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[trimmed.len() - 1] == b'\'')
        {
            return trimmed[1..trimmed.len() - 1].to_owned();
        }
    }
    trimmed.to_owned()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success of Result-returning adapter steps"
    )]

    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::{
        HermesOpts, HermesWiring, install_with, uninstall_with, upsert_memory_provider,
        wiring_status,
    };
    use crate::setup::mcp::McpLaunch;

    fn launch() -> McpLaunch {
        McpLaunch {
            command: "/opt/hippius-mem".to_owned(),
            config_path: PathBuf::from("/cfg/hippius-mem.toml"),
        }
    }

    #[test]
    fn install_writes_plugin_sidecar_and_memory_provider() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".hermes")).expect("dir");
        std::fs::write(
            home.path().join(".hermes/config.yaml"),
            "model: gpt\nmcp_servers:\n  docs:\n    url: \"https://example\"\n  hippius-mem:\n    command: old\n",
        )
        .expect("seed");
        install_with(home.path(), &launch(), &HermesOpts::default(), None).expect("install");
        let plugin = home.path().join(".hermes/plugins/hippius-mem/plugin.yaml");
        assert!(plugin.is_file(), "plugin.yaml must be copied");
        let yaml = std::fs::read_to_string(plugin).expect("read plugin");
        assert!(yaml.contains("name: hippius-mem"));
        let sidecar: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.path().join(".hermes/hippius-mem.json"))
                .expect("sidecar"),
        )
        .expect("json");
        assert_eq!(sidecar["binary"], "/opt/hippius-mem");
        assert_eq!(sidecar["config_path"], "/cfg/hippius-mem.toml");
        let config =
            std::fs::read_to_string(home.path().join(".hermes/config.yaml")).expect("config");
        assert!(config.contains("model: gpt"));
        assert!(config.contains("  docs:"));
        assert!(config.contains("  provider: hippius-mem"));
        assert!(
            !config.contains("  hippius-mem:"),
            "stale MCP entry must be stripped: {config}"
        );
        install_with(home.path(), &launch(), &HermesOpts::default(), None).expect("re-install");
        let after =
            std::fs::read_to_string(home.path().join(".hermes/config.yaml")).expect("config");
        assert_eq!(
            after.matches("  provider: hippius-mem").count(),
            1,
            "exactly one provider line: {after}"
        );
        uninstall_with(home.path(), &HermesOpts::default(), None).expect("uninstall");
        assert!(!home.path().join(".hermes/plugins/hippius-mem").exists());
        assert!(!home.path().join(".hermes/hippius-mem.json").exists());
        let cleaned =
            std::fs::read_to_string(home.path().join(".hermes/config.yaml")).expect("config");
        assert!(!cleaned.contains("provider: hippius-mem"));
        assert!(cleaned.contains("model: gpt"));
        assert!(cleaned.contains("  docs:"));
    }

    #[test]
    fn hermes_home_flag_beats_dot_hermes() {
        let home = TempDir::new().expect("tempdir");
        let fleet = home.path().join("fleet/ops");
        std::fs::create_dir_all(&fleet).expect("fleet");
        let opts = HermesOpts {
            home: Some(fleet.clone()),
            ..HermesOpts::default()
        };
        install_with(home.path(), &launch(), &opts, None).expect("install");
        assert!(fleet.join("plugins/hippius-mem/plugin.yaml").is_file());
        assert!(!home.path().join(".hermes/config.yaml").exists());
    }

    #[test]
    fn injected_hermes_home_env_beats_dot_hermes() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".hermes")).expect("dir");
        let fleet = home.path().join("fleet/ops");
        std::fs::create_dir_all(&fleet).expect("fleet");
        install_with(
            home.path(),
            &launch(),
            &HermesOpts::default(),
            Some(fleet.clone().into_os_string()),
        )
        .expect("install");
        assert!(fleet.join("plugins/hippius-mem/plugin.yaml").is_file());
        assert!(!home.path().join(".hermes/plugins/hippius-mem").exists());
    }

    #[test]
    fn hermes_profile_wires_only_that_profile() {
        let home = TempDir::new().expect("tempdir");
        let ops = home.path().join(".hermes/profiles/ops");
        std::fs::create_dir_all(&ops).expect("ops");
        std::fs::write(ops.join("config.yaml"), "model: ops\n").expect("seed");
        std::fs::create_dir_all(home.path().join(".hermes/profiles/chat")).expect("chat");
        std::fs::write(
            home.path().join(".hermes/profiles/chat/config.yaml"),
            "model: chat\n",
        )
        .expect("chat seed");
        let profile_opts = HermesOpts {
            profile: Some("ops".into()),
            ..HermesOpts::default()
        };
        install_with(home.path(), &launch(), &profile_opts, None).expect("install");
        assert!(ops.join("plugins/hippius-mem/plugin.yaml").is_file());
        assert!(
            !home
                .path()
                .join(".hermes/profiles/chat/plugins/hippius-mem")
                .exists()
        );
        assert!(!home.path().join(".hermes/plugins/hippius-mem").exists());
    }

    #[test]
    fn all_profiles_wires_default_and_each_existing_config() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".hermes")).expect("hermes");
        let ops = home.path().join(".hermes/profiles/ops");
        std::fs::create_dir_all(&ops).expect("ops");
        std::fs::write(ops.join("config.yaml"), "model: ops\n").expect("seed");
        let all_opts = HermesOpts {
            all_profiles: true,
            ..HermesOpts::default()
        };
        install_with(home.path(), &launch(), &all_opts, None).expect("install");
        assert!(
            home.path()
                .join(".hermes/plugins/hippius-mem/plugin.yaml")
                .is_file()
        );
        assert!(ops.join("plugins/hippius-mem/plugin.yaml").is_file());
    }

    #[test]
    fn refuses_to_replace_another_memory_provider() {
        let err = upsert_memory_provider("memory:\n  provider: honcho\n", "hippius-mem")
            .expect_err("honcho");
        assert!(format!("{err:#}").contains("honcho"), "unexpected: {err:#}");
    }

    #[test]
    fn refuses_flow_style_memory() {
        let err = upsert_memory_provider("memory: { provider: honcho }\n", "hippius-mem")
            .expect_err("flow");
        assert!(
            format!("{err:#}").contains("flow-style"),
            "unexpected: {err:#}"
        );
    }

    #[test]
    fn wiring_status_is_absent_without_hermes_home() {
        let home = TempDir::new().expect("tempdir");
        assert_eq!(wiring_status(home.path(), None), HermesWiring::Absent);
    }

    #[test]
    fn wiring_status_is_incomplete_when_dot_hermes_exists_unwired() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".hermes")).expect("dir");
        let status = wiring_status(home.path(), None);
        assert!(
            matches!(
                &status,
                HermesWiring::Incomplete { reasons }
                    if reasons.iter().any(|reason| reason.contains("plugin missing"))
            ),
            "unwired ~/.hermes must name the missing plugin, got {status:?}"
        );
    }

    #[test]
    fn wiring_status_is_wired_after_install() {
        let home = TempDir::new().expect("tempdir");
        let binary = home.path().join("hippius-mem");
        let config = home.path().join("hippius-mem.toml");
        std::fs::write(&binary, b"fake").expect("binary");
        std::fs::write(&config, b"bucket = \"b\"\n").expect("config");
        std::fs::create_dir(home.path().join(".hermes")).expect("dir");
        let launch = McpLaunch {
            command: binary.to_string_lossy().into_owned(),
            config_path: config,
        };
        install_with(home.path(), &launch, &HermesOpts::default(), None).expect("install");
        assert_eq!(
            wiring_status(home.path(), None),
            HermesWiring::Wired,
            "install --agent hermes must satisfy doctor"
        );
    }

    #[test]
    fn wiring_status_is_incomplete_when_plugin_omits_system_prompt_block() {
        let home = TempDir::new().expect("tempdir");
        let binary = home.path().join("hippius-mem");
        let config = home.path().join("hippius-mem.toml");
        std::fs::write(&binary, b"fake").expect("binary");
        std::fs::write(&config, b"bucket = \"b\"\n").expect("config");
        std::fs::create_dir(home.path().join(".hermes")).expect("dir");
        let launch = McpLaunch {
            command: binary.to_string_lossy().into_owned(),
            config_path: config,
        };
        install_with(home.path(), &launch, &HermesOpts::default(), None).expect("install");
        std::fs::write(
            home.path().join(".hermes/plugins/hippius-mem/plugin.yaml"),
            "name: hippius-mem\nhooks:\n  - prefetch\n  - sync_turn\n",
        )
        .expect("stale yaml");
        let status = wiring_status(home.path(), None);
        assert!(
            matches!(
                &status,
                HermesWiring::Incomplete { reasons }
                    if reasons.iter().any(|reason| reason.contains("system_prompt_block"))
            ),
            "a 0.2.0 plugin.yaml must not count as wired: {status:?}"
        );
    }

    #[test]
    fn wiring_status_warns_on_another_provider() {
        let home = TempDir::new().expect("tempdir");
        let hermes = home.path().join(".hermes");
        std::fs::create_dir(&hermes).expect("dir");
        std::fs::write(hermes.join("config.yaml"), "memory:\n  provider: honcho\n").expect("yaml");
        assert_eq!(
            wiring_status(home.path(), None),
            HermesWiring::OtherProvider("honcho".into())
        );
    }

    #[test]
    fn wiring_status_injected_env_beats_dot_hermes() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".hermes")).expect("dir");
        let fleet = home.path().join("fleet");
        std::fs::create_dir(&fleet).expect("fleet");
        let status = wiring_status(home.path(), Some(fleet.as_os_str()));
        assert!(
            matches!(status, HermesWiring::Incomplete { .. }),
            "HERMES_HOME dir must be the inspected root, got {status:?}"
        );
    }

    #[test]
    fn for_agents_goal_wires_the_client_not_mcp() {
        let playbook = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../FOR-AGENTS.md"));
        assert!(
            playbook.contains("The agent the human is using is wired"),
            "Goal 3 must say the client is wired, not that MCP is registered"
        );
        assert!(
            !playbook.contains("The MCP server is registered for the agent the human is using"),
            "the MCP-centric Goal 3 is what sent a Hermes agent to paste JSON"
        );
        let agents = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../AGENTS.md"));
        assert!(
            agents.contains("wires the client"),
            "the AGENTS.md opener must not say the playbook wires MCP"
        );
    }

    #[test]
    fn profile_and_all_profiles_conflict() {
        let home = TempDir::new().expect("tempdir");
        let opts = HermesOpts {
            profile: Some("ops".into()),
            all_profiles: true,
            ..HermesOpts::default()
        };
        let err = install_with(home.path(), &launch(), &opts, None).expect_err("conflict");
        assert!(
            format!("{err:#}").contains("cannot be combined"),
            "unexpected: {err:#}"
        );
    }
}
