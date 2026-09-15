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
    for root in resolve_roots(user_home, opts, std::env::var_os("HERMES_HOME"))? {
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
    let Ok(roots) = resolve_roots(user_home, opts, std::env::var_os("HERMES_HOME")) else {
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

    use super::{HermesOpts, install, uninstall, upsert_memory_provider};
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
        install(home.path(), &launch(), &HermesOpts::default()).expect("install");
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
        install(home.path(), &launch(), &HermesOpts::default()).expect("re-install");
        let after =
            std::fs::read_to_string(home.path().join(".hermes/config.yaml")).expect("config");
        assert_eq!(
            after.matches("  provider: hippius-mem").count(),
            1,
            "exactly one provider line: {after}"
        );
        uninstall(home.path(), &HermesOpts::default()).expect("uninstall");
        assert!(!home.path().join(".hermes/plugins/hippius-mem").exists());
        assert!(!home.path().join(".hermes/hippius-mem.json").exists());
        let cleaned =
            std::fs::read_to_string(home.path().join(".hermes/config.yaml")).expect("config");
        assert!(!cleaned.contains("provider: hippius-mem"));
        assert!(cleaned.contains("model: gpt"));
        assert!(cleaned.contains("  docs:"));
    }

    #[test]
    fn hermes_home_env_beats_dot_hermes() {
        let home = TempDir::new().expect("tempdir");
        let fleet = home.path().join("fleet/ops");
        std::fs::create_dir_all(&fleet).expect("fleet");
        let opts = HermesOpts {
            home: Some(fleet.clone()),
            ..HermesOpts::default()
        };
        install(home.path(), &launch(), &opts).expect("install");
        assert!(fleet.join("plugins/hippius-mem/plugin.yaml").is_file());
        assert!(!home.path().join(".hermes/config.yaml").exists());
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
        install(home.path(), &launch(), &profile_opts).expect("install");
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
        install(home.path(), &launch(), &all_opts).expect("install");
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
    fn profile_and_all_profiles_conflict() {
        let home = TempDir::new().expect("tempdir");
        let opts = HermesOpts {
            profile: Some("ops".into()),
            all_profiles: true,
            ..HermesOpts::default()
        };
        let err = install(home.path(), &launch(), &opts).expect_err("conflict");
        assert!(
            format!("{err:#}").contains("cannot be combined"),
            "unexpected: {err:#}"
        );
    }
}
