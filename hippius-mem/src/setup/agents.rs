//! Per-agent MCP registration adapters.
//!
//! `install` requires `--agent` or `--all-detected` (a TTY prompt is offered
//! for a bare `install`). `--all-detected` is Claude plus every adapter whose
//! product directory already exists under `$HOME`. Detection is directory
//! presence, never PATH — a missing `~/.codex` is not created. Hermes honours
//! `HERMES_HOME` and is a memory-provider plugin, not an MCP registration.
//! Unrelated keys in those files are preserved; a malformed file is refused
//! (or, on uninstall, left untouched) rather than rewritten.

use std::path::Path;

use anyhow::{Context, bail};
use serde_json::{Value, json};

use super::mcp::{
    McpLaunch, SERVER_NAME, TomlHttpAuth, register_json_mcp_servers, register_mcp_global,
    unregister_json_mcp_servers,
};

/// Clients `install` can register the stdio server with.
///
/// Grok Bot is deliberately absent: it runs on a cloud VM and cannot spawn a
/// local stdio binary. `OpenClaw` is the personal-assistant gateway, not a
/// coding TUI; it still gets an MCP entry because it is a local stdio client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentId {
    Claude,
    Grok,
    Codex,
    Gemini,
    Hermes,
    OpenClaw,
}

impl AgentId {
    /// Every adapter `install --agent` / `--all-detected` can name.
    pub(crate) const ALL: [Self; 6] = [
        Self::Claude,
        Self::Grok,
        Self::Codex,
        Self::Gemini,
        Self::Hermes,
        Self::OpenClaw,
    ];

    /// Parse a CLI token (`grok`, `codex`, …). Unknown names are `None`.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "claude" => Some(Self::Claude),
            "grok" => Some(Self::Grok),
            "codex" => Some(Self::Codex),
            "gemini" => Some(Self::Gemini),
            "hermes" => Some(Self::Hermes),
            "openclaw" => Some(Self::OpenClaw),
            _ => None,
        }
    }

    /// The CLI token for this adapter.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Grok => "grok",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Hermes => "hermes",
            Self::OpenClaw => "openclaw",
        }
    }

    /// Whether this product's config directory already exists under `home`.
    ///
    /// Detection is directory-presence, never PATH: creating `~/.codex` on a
    /// machine that has never run Codex is not ours to do. Claude is always
    /// treated as present — `install` has always created `~/.claude`.
    pub(crate) fn is_present(self, home: &Path) -> bool {
        match self {
            Self::Claude => true,
            Self::Grok => home.join(".grok").is_dir(),
            Self::Codex => home.join(".codex").is_dir(),
            Self::Gemini => home.join(".gemini").is_dir(),
            Self::Hermes => home.join(".hermes").is_dir(),
            Self::OpenClaw => home.join(".openclaw").is_dir(),
        }
    }

    /// Whether this client speaks streamable HTTP MCP and should share the
    /// loopback daemon when `install` prepared one. Gemini and `OpenClaw` stay
    /// on stdio (their HTTP MCP support is not the installer's contract);
    /// Hermes is a memory-provider plugin, not MCP.
    pub(crate) fn prefers_http(self) -> bool {
        matches!(self, Self::Claude | Self::Grok | Self::Codex)
    }

    /// Whether this client's config currently points hippius-mem at a URL
    /// (the shared daemon) rather than a stdio `command`.
    ///
    /// Read-only and forgiving: a missing or malformed file is simply "not
    /// wired", because the caller only asks so it can decide whether the
    /// daemon still has a client.
    #[cfg(any(test, feature = "http-mcp"))]
    pub(crate) fn is_http_wired(self, home: &Path) -> bool {
        match self {
            Self::Claude => json_entry_has_url(&home.join(".claude.json")),
            Self::Grok => toml_entry_has_url(&home.join(".grok/config.toml")),
            Self::Codex => toml_entry_has_url(&home.join(".codex/config.toml")),
            Self::Gemini | Self::Hermes | Self::OpenClaw => false,
        }
    }

    /// Upsert this client's MCP entry. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the client's config file is malformed or cannot
    /// be written.
    pub(crate) fn register(self, home: &Path, launch: &McpLaunch) -> anyhow::Result<()> {
        match self {
            Self::Claude => register_mcp_global(home, launch),
            Self::Grok => upsert_toml_mcp(
                home.join(".grok/config.toml").as_path(),
                launch,
                self.prefers_http(),
                TomlHttpAuth::Headers,
            ),
            Self::Codex => upsert_toml_mcp(
                home.join(".codex/config.toml").as_path(),
                launch,
                self.prefers_http(),
                TomlHttpAuth::HttpHeaders,
            ),
            Self::Gemini => register_json_mcp_servers(
                home.join(".gemini/settings.json").as_path(),
                launch,
                false,
            ),
            Self::Hermes => {
                super::hermes::install(home, launch, &super::hermes::HermesOpts::default())
            }
            Self::OpenClaw => {
                upsert_openclaw_json(home.join(".openclaw/openclaw.json").as_path(), launch)
            }
        }
    }

    /// Remove this client's hippius-mem MCP entry if the file exists.
    ///
    /// A missing or malformed file is a no-op so uninstall cannot fail on a
    /// file we do not own.
    ///
    /// # Errors
    ///
    /// Returns an error only on a genuine I/O fault writing a well-formed file.
    pub(crate) fn unregister(self, home: &Path) -> anyhow::Result<()> {
        match self {
            Self::Claude => super::mcp::deregister_mcp_global(home),
            Self::Grok => remove_toml_mcp(home.join(".grok/config.toml").as_path()),
            Self::Codex => remove_toml_mcp(home.join(".codex/config.toml").as_path()),
            Self::Gemini => unregister_json_mcp_servers(&home.join(".gemini/settings.json")),
            Self::Hermes => super::hermes::uninstall(home, &super::hermes::HermesOpts::default()),
            Self::OpenClaw => remove_openclaw_json(home.join(".openclaw/openclaw.json").as_path()),
        }
    }
}

/// How `install` chooses which adapters to run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum AgentSelect {
    /// Explicit `--agent` list, in the order the user named them.
    Explicit(Vec<AgentId>),
    /// Claude plus every adapter whose product directory already exists.
    /// Opt-in via `--all-detected` (no longer the silent default).
    AllDetected,
    /// Bare `install`: prompt on a TTY, otherwise refuse until `--agent` or
    /// `--all-detected` is passed. The default.
    #[default]
    Required,
}

impl AgentSelect {
    /// Resolve the adapter list against `home`.
    ///
    /// `hermes_home_env` is injected so tests do not read process `HERMES_HOME`.
    pub(crate) fn resolve(
        &self,
        home: &Path,
        hermes: &super::hermes::HermesOpts,
        hermes_home_env: Option<&std::ffi::OsStr>,
    ) -> Vec<AgentId> {
        match self {
            Self::Explicit(ids) => ids.clone(),
            Self::AllDetected | Self::Required => {
                let mut ids = Vec::with_capacity(AgentId::ALL.len());
                for id in AgentId::ALL {
                    let present = match id {
                        AgentId::Hermes => {
                            super::hermes::is_detected(home, hermes, hermes_home_env)
                        }
                        other => other.is_present(home),
                    };
                    if present {
                        ids.push(id);
                    }
                }
                ids
            }
        }
    }
}

/// Parse a comma-separated `--agent` value, appending onto `into`.
///
/// # Errors
///
/// Returns an error naming the unknown token and the accepted set.
pub(crate) fn parse_agent_list(raw: &str, into: &mut Vec<AgentId>) -> anyhow::Result<()> {
    for token in raw.split(',') {
        let name = token.trim();
        if name.is_empty() {
            continue;
        }
        let Some(id) = AgentId::parse(name) else {
            bail!(
                "unknown agent `{name}`; expected one of: claude, grok, codex, gemini, hermes, openclaw"
            );
        };
        if !into.contains(&id) {
            into.push(id);
        }
    }
    if into.is_empty() {
        bail!("--agent requires at least one name (claude, grok, codex, gemini, hermes, openclaw)");
    }
    Ok(())
}

/// Every adapter whose config still points at the shared daemon's URL.
#[cfg(any(test, feature = "http-mcp"))]
pub(crate) fn http_wired_agents(home: &Path) -> Vec<AgentId> {
    [AgentId::Claude, AgentId::Grok, AgentId::Codex]
        .into_iter()
        .filter(|agent| agent.is_http_wired(home))
        .collect()
}

#[cfg(any(test, feature = "http-mcp"))]
fn json_entry_has_url(path: &Path) -> bool {
    let Ok(config) = super::mcp::load_json(path) else {
        return false;
    };
    config
        .get("mcpServers")
        .and_then(|servers| servers.get(SERVER_NAME))
        .and_then(|entry| entry.get("url"))
        .is_some()
}

#[cfg(any(test, feature = "http-mcp"))]
fn toml_entry_has_url(path: &Path) -> bool {
    let Ok(root) = load_toml_table(path) else {
        return false;
    };
    root.get("mcp_servers")
        .and_then(|servers| servers.get(SERVER_NAME))
        .and_then(|entry| entry.get("url"))
        .is_some()
}

/// Upsert `[mcp_servers.hippius-mem]` in a Grok/Codex `config.toml`.
fn upsert_toml_mcp(
    path: &Path,
    launch: &McpLaunch,
    prefer_http: bool,
    auth: TomlHttpAuth,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {} failed", parent.display()))?;
    }
    let mut root = load_toml_table(path)?;
    let servers = toml_table_entry(&mut root, "mcp_servers")?;
    servers.insert(SERVER_NAME.to_owned(), launch.toml_entry(prefer_http, auth));
    if launch.writes_token(prefer_http) {
        return write_toml_private(path, &root);
    }
    write_toml(path, &root)
}

fn remove_toml_mcp(path: &Path) -> anyhow::Result<()> {
    let mut root = match load_toml_table(path) {
        Ok(table) => table,
        Err(e) if path_missing_or_malformed(path, &e) => return Ok(()),
        Err(e) => return Err(e),
    };
    let Some(servers) = root
        .get_mut("mcp_servers")
        .and_then(toml::Value::as_table_mut)
    else {
        return Ok(());
    };
    if servers.remove(SERVER_NAME).is_none() {
        return Ok(());
    }
    if servers.is_empty() {
        root.remove("mcp_servers");
    }
    write_toml(path, &root)
}

fn load_toml_table(path: &Path) -> anyhow::Result<toml::Table> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(toml::Table::new()),
        Ok(s) => s
            .parse()
            .with_context(|| format!("{} is not valid TOML", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(toml::Table::new()),
        Err(e) => Err(e).with_context(|| format!("reading {} failed", path.display())),
    }
}

fn toml_table_entry<'a>(
    root: &'a mut toml::Table,
    key: &str,
) -> anyhow::Result<&'a mut toml::Table> {
    if !root.contains_key(key) {
        root.insert(key.to_owned(), toml::Value::Table(toml::Table::new()));
    }
    root.get_mut(key)
        .and_then(toml::Value::as_table_mut)
        .with_context(|| format!("`{key}` is not a TOML table"))
}

fn write_toml(path: &Path, root: &toml::Table) -> anyhow::Result<()> {
    let body = toml::to_string(root).context("serializing MCP TOML failed")?;
    super::atomic::atomic_write(path, format!("{body}\n").as_bytes())
}

/// [`write_toml`], forced owner-only because the table embeds the daemon's
/// bearer token (see [`McpLaunch::writes_token`]).
fn write_toml_private(path: &Path, root: &toml::Table) -> anyhow::Result<()> {
    let body = toml::to_string(root).context("serializing MCP TOML failed")?;
    super::atomic::atomic_write_private(path, format!("{body}\n").as_bytes())
}

fn path_missing_or_malformed(path: &Path, err: &anyhow::Error) -> bool {
    if !path.exists() {
        return true;
    }
    let msg = format!("{err:#}");
    msg.contains("is not valid TOML") || msg.contains("is not valid JSON")
}

/// Upsert `OpenClaw`'s nested `mcp.servers.hippius-mem` object.
fn upsert_openclaw_json(path: &Path, launch: &McpLaunch) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {} failed", parent.display()))?;
    }
    let mut config = super::mcp::load_json(path)?;
    let root = config
        .as_object_mut()
        .context("OpenClaw config root is not a JSON object")?;
    let mcp = root.entry("mcp").or_insert_with(|| json!({}));
    let mcp = mcp.as_object_mut().context("`mcp` is not a JSON object")?;
    let servers = mcp.entry("servers").or_insert_with(|| json!({}));
    let servers = servers
        .as_object_mut()
        .context("`mcp.servers` is not a JSON object")?;
    servers.insert(SERVER_NAME.to_owned(), launch.json_entry(false));
    super::mcp::write_json(path, &config)
}

fn remove_openclaw_json(path: &Path) -> anyhow::Result<()> {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {} failed", path.display())),
    };
    let Ok(mut config) = serde_json::from_str::<Value>(&content) else {
        tracing::debug!(
            path = %path.display(),
            "unregister: OpenClaw JSON is not valid JSON; leaving it untouched"
        );
        return Ok(());
    };
    let removed = config
        .get_mut("mcp")
        .and_then(Value::as_object_mut)
        .and_then(|mcp| mcp.get_mut("servers"))
        .and_then(Value::as_object_mut)
        .is_some_and(|servers| servers.remove(SERVER_NAME).is_some());
    if !removed {
        return Ok(());
    }
    super::mcp::write_json(path, &config)
}

#[cfg(test)]
fn hermes_server_block(launch: &McpLaunch) -> String {
    format!(
        "  hippius-mem:\n    command: {}\n    args: []\n    env:\n      HIPPIUS_MEM_CONFIG: {}\n",
        yaml_quote(&launch.command),
        yaml_quote(&launch.config_path.to_string_lossy()),
    )
}

#[cfg(test)]
fn yaml_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Insert or replace the `hippius-mem` entry under a block-style `mcp_servers:`.
#[cfg(test)]
fn upsert_yaml_server(text: &str, server_block: &str) -> anyhow::Result<String> {
    if yaml_has_flow_mcp_servers(text) {
        bail!(
            "Hermes config uses a flow-style `mcp_servers:` mapping; add hippius-mem by hand \
             (or rewrite that key as a block mapping) rather than letting install clobber it"
        );
    }
    if text.trim().is_empty() {
        return Ok(format!("mcp_servers:\n{server_block}"));
    }
    let Some(servers_line) = find_top_level_key(text, "mcp_servers") else {
        let mut out = text.to_owned();
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("mcp_servers:\n");
        out.push_str(server_block);
        return Ok(out);
    };
    let section_end = next_top_level_after(text, servers_line);
    if let Some(entry_line) = find_indented_key(text, servers_line, section_end, "hippius-mem") {
        let entry_end = next_indent_leq(text, entry_line, section_end, 2);
        return Ok(replace_span(text, entry_line, entry_end, server_block));
    }
    let insert_at = after_line(text, servers_line);
    let mut out = String::new();
    out.push_str(&text[..insert_at]);
    out.push_str(server_block);
    out.push_str(&text[insert_at..section_end]);
    out.push_str(&text[section_end..]);
    Ok(out)
}

pub(super) fn remove_yaml_server(text: &str) -> anyhow::Result<String> {
    if yaml_has_flow_mcp_servers(text) {
        bail!("flow-style mcp_servers");
    }
    let Some(servers_line) = find_top_level_key(text, "mcp_servers") else {
        return Ok(text.to_owned());
    };
    let section_end = next_top_level_after(text, servers_line);
    let Some(entry_line) = find_indented_key(text, servers_line, section_end, "hippius-mem") else {
        return Ok(text.to_owned());
    };
    let entry_end = next_indent_leq(text, entry_line, section_end, 2);
    Ok(replace_span(text, entry_line, entry_end, ""))
}

fn yaml_has_flow_mcp_servers(text: &str) -> bool {
    yaml_has_flow_key(text, "mcp_servers")
}

/// True when `key:` is a flow mapping (`key: { ... }`) at any indent.
pub(super) fn yaml_has_flow_key(text: &str, key: &str) -> bool {
    let prefix = format!("{key}:");
    text.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with(&prefix) && trimmed[prefix.len()..].trim_start().starts_with('{')
    })
}

pub(super) fn find_top_level_key(text: &str, key: &str) -> Option<usize> {
    let prefix = format!("{key}:");
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_end_matches(['\n', '\r']).starts_with(&prefix)
            && !line.starts_with(' ')
            && !line.starts_with('\t')
        {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

pub(super) fn find_indented_key(text: &str, from: usize, to: usize, key: &str) -> Option<usize> {
    let needle = format!("  {key}:");
    let mut offset = from;
    for line in text[from..to].split_inclusive('\n') {
        if offset != from && line.starts_with(&needle) {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

pub(super) fn next_top_level_after(text: &str, from: usize) -> usize {
    let mut offset = from;
    let mut first = true;
    for line in text[from..].split_inclusive('\n') {
        if !first {
            let body = line.trim_end_matches(['\n', '\r']);
            if !body.is_empty()
                && !body.starts_with(' ')
                && !body.starts_with('\t')
                && !body.starts_with('#')
                && body.contains(':')
            {
                return offset;
            }
        }
        first = false;
        offset += line.len();
    }
    text.len()
}

pub(super) fn next_indent_leq(text: &str, from: usize, to: usize, indent: usize) -> usize {
    let mut offset = from;
    let mut first = true;
    for line in text[from..to].split_inclusive('\n') {
        if !first {
            let body = line.trim_end_matches(['\n', '\r']);
            if !body.is_empty() && !body.starts_with('#') {
                let leading = body.chars().take_while(|c| *c == ' ').count();
                if leading <= indent && body.contains(':') {
                    return offset;
                }
            }
        }
        first = false;
        offset += line.len();
    }
    to
}

pub(super) fn after_line(text: &str, line_start: usize) -> usize {
    text[line_start..]
        .find('\n')
        .map_or(text.len(), |i| line_start + i + 1)
}

pub(super) fn replace_span(text: &str, start: usize, end: usize, replacement: &str) -> String {
    let mut out = String::with_capacity(text.len() - (end - start) + replacement.len());
    out.push_str(&text[..start]);
    out.push_str(replacement);
    out.push_str(&text[end..]);
    out
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
        AgentId, AgentSelect, hermes_server_block, parse_agent_list, remove_yaml_server,
        upsert_yaml_server,
    };
    use crate::setup::hermes::{HermesOpts, install_with, uninstall_with};
    use crate::setup::mcp::McpLaunch;

    fn launch() -> McpLaunch {
        McpLaunch {
            command: "/opt/hippius-mem".to_owned(),
            config_path: PathBuf::from("/cfg/hippius-mem.toml"),
            http: None,
        }
    }

    fn http_launch() -> McpLaunch {
        use crate::setup::mcp::{DEFAULT_HTTP_PORT, McpHttp, http_listen_url};

        McpLaunch {
            command: "/opt/hippius-mem".to_owned(),
            config_path: PathBuf::from("/cfg/hippius-mem.toml"),
            http: Some(McpHttp {
                url: http_listen_url(DEFAULT_HTTP_PORT),
                token: "tok".to_owned(),
            }),
        }
    }

    #[test]
    fn parses_known_agent_names_and_rejects_unknown() {
        assert_eq!(AgentId::parse("grok"), Some(AgentId::Grok));
        assert_eq!(AgentId::parse("openclaw"), Some(AgentId::OpenClaw));
        assert_eq!(AgentId::parse("grok-bot"), None);
        assert_eq!(AgentId::parse("claude"), Some(AgentId::Claude));
    }

    #[test]
    fn parse_agent_list_dedups_and_accepts_commas() {
        let mut ids = Vec::new();
        parse_agent_list("grok,codex", &mut ids).expect("parse");
        parse_agent_list("grok", &mut ids).expect("dedup");
        assert_eq!(ids, vec![AgentId::Grok, AgentId::Codex]);
    }

    #[test]
    fn parse_agent_list_rejects_empty_and_unknown() {
        let mut ids = Vec::new();
        assert!(parse_agent_list("", &mut ids).is_err());
        assert!(parse_agent_list("cursor", &mut ids).is_err());
    }

    #[test]
    fn default_select_is_required_not_silent_all_detected() {
        assert_eq!(AgentSelect::default(), AgentSelect::Required);
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".grok")).expect("grok dir");
        assert_eq!(
            AgentSelect::AllDetected.resolve(home.path(), &HermesOpts::default(), None),
            vec![AgentId::Claude, AgentId::Grok]
        );
    }

    #[test]
    fn all_detected_includes_claude_and_existing_dirs() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".grok")).expect("grok dir");
        std::fs::create_dir(home.path().join(".hermes")).expect("hermes dir");
        assert_eq!(
            AgentSelect::AllDetected.resolve(home.path(), &HermesOpts::default(), None),
            vec![AgentId::Claude, AgentId::Grok, AgentId::Hermes]
        );
    }

    #[test]
    fn all_detected_includes_hermes_when_hermes_home_flag_is_set() {
        let home = TempDir::new().expect("tempdir");
        let opts = HermesOpts {
            home: Some(home.path().join("fleet/ops")),
            ..HermesOpts::default()
        };
        assert_eq!(
            AgentSelect::AllDetected.resolve(home.path(), &opts, None),
            vec![AgentId::Claude, AgentId::Hermes]
        );
    }

    #[test]
    fn grok_toml_upsert_is_idempotent_and_preserves_siblings() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".grok")).expect("dir");
        std::fs::write(
            home.path().join(".grok/config.toml"),
            "[cli]\nauto_update = false\n\n[mcp_servers.other]\ncommand = \"x\"\n",
        )
        .expect("seed");
        AgentId::Grok
            .register(home.path(), &launch())
            .expect("register");
        AgentId::Grok
            .register(home.path(), &launch())
            .expect("re-register");
        let body = std::fs::read_to_string(home.path().join(".grok/config.toml")).expect("read");
        let table: toml::Table = body.parse().expect("toml");
        assert_eq!(
            table["cli"]["auto_update"].as_bool(),
            Some(false),
            "unrelated keys must survive: {body}"
        );
        assert_eq!(table["mcp_servers"]["other"]["command"].as_str(), Some("x"));
        assert_eq!(
            table["mcp_servers"]["hippius-mem"]["command"].as_str(),
            Some("/opt/hippius-mem")
        );
        assert_eq!(
            table["mcp_servers"]["hippius-mem"]["env"]["HIPPIUS_MEM_CONFIG"].as_str(),
            Some("/cfg/hippius-mem.toml")
        );
    }

    #[test]
    fn grok_http_launch_writes_url_and_gemini_stays_stdio() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".grok")).expect("grok");
        AgentId::Grok
            .register(home.path(), &http_launch())
            .expect("grok");
        AgentId::Gemini
            .register(home.path(), &http_launch())
            .expect("gemini");
        let grok: toml::Table = std::fs::read_to_string(home.path().join(".grok/config.toml"))
            .expect("read")
            .parse()
            .expect("toml");
        assert!(
            grok["mcp_servers"]["hippius-mem"]
                .get("url")
                .and_then(toml::Value::as_str)
                .is_some_and(|url| url.ends_with("/mcp")),
            "Grok must point at the loopback daemon: {grok:?}"
        );
        assert!(
            grok["mcp_servers"]["hippius-mem"].get("command").is_none(),
            "an HTTP Grok entry must not spawn a child: {grok:?}"
        );
        assert_eq!(
            grok["mcp_servers"]["hippius-mem"]["headers"]["Authorization"].as_str(),
            Some("Bearer tok"),
            "Grok reads `headers`, not Codex's `http_headers`: {grok:?}"
        );
        assert!(
            grok["mcp_servers"]["hippius-mem"]
                .get("http_headers")
                .is_none(),
            "Grok must not emit Codex's key: {grok:?}"
        );
        let gemini: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.path().join(".gemini/settings.json")).expect("read"),
        )
        .expect("json");
        assert_eq!(
            gemini["mcpServers"]["hippius-mem"]["command"], "/opt/hippius-mem",
            "Gemini stays on stdio: {gemini}"
        );
    }

    #[test]
    fn http_wired_agents_names_only_clients_pointed_at_the_url() {
        use super::http_wired_agents;

        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".grok")).expect("grok");
        std::fs::create_dir(home.path().join(".codex")).expect("codex");
        assert!(
            http_wired_agents(home.path()).is_empty(),
            "missing configs are not wired"
        );

        AgentId::Claude
            .register(home.path(), &http_launch())
            .expect("claude");
        AgentId::Grok
            .register(home.path(), &http_launch())
            .expect("grok");
        AgentId::Codex
            .register(home.path(), &launch())
            .expect("codex stdio");
        assert_eq!(
            http_wired_agents(home.path()),
            [AgentId::Claude, AgentId::Grok],
            "a stdio `command` entry does not need the daemon"
        );

        // Uninstalling one HTTP client must leave the other counted, so
        // `install --uninstall --agent grok` keeps the daemon up for Claude.
        AgentId::Grok.unregister(home.path()).expect("unregister");
        assert_eq!(http_wired_agents(home.path()), [AgentId::Claude]);
    }

    #[cfg(unix)]
    #[test]
    fn a_token_bearing_client_config_is_tightened_to_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = TempDir::new().expect("tempdir");
        let dir = home.path().join(".codex");
        std::fs::create_dir(&dir).expect("codex");
        let path = dir.join("config.toml");
        std::fs::write(&path, "model = \"gpt\"\n").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        // A stdio entry holds no secret: the operator's mode is preserved.
        AgentId::Codex
            .register(home.path(), &launch())
            .expect("stdio");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);

        // The HTTP entry embeds the bearer token the 0600 `mcp-token` guards.
        AgentId::Codex
            .register(home.path(), &http_launch())
            .expect("http");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a world-readable config would leak the token");
    }

    #[test]
    fn codex_http_launch_writes_http_headers_not_headers() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".codex")).expect("codex");
        AgentId::Codex
            .register(home.path(), &http_launch())
            .expect("codex");
        let codex: toml::Table = std::fs::read_to_string(home.path().join(".codex/config.toml"))
            .expect("read")
            .parse()
            .expect("toml");
        let server = &codex["mcp_servers"]["hippius-mem"];
        assert!(
            server
                .get("url")
                .and_then(toml::Value::as_str)
                .is_some_and(|url| url.ends_with("/mcp")),
            "Codex must point at the loopback daemon: {codex:?}"
        );
        assert_eq!(
            server["http_headers"]["Authorization"].as_str(),
            Some("Bearer tok"),
            "Codex streamable HTTP reads `http_headers`, not `headers`: {codex:?}"
        );
        assert!(
            server.get("headers").is_none(),
            "a `headers` table is ignored by Codex and 401s the daemon: {codex:?}"
        );
        assert!(server.get("command").is_none());
    }

    #[test]
    fn grok_toml_unregister_removes_only_our_server() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".grok")).expect("dir");
        AgentId::Grok
            .register(home.path(), &launch())
            .expect("register");
        AgentId::Grok.unregister(home.path()).expect("unregister");
        let body = std::fs::read_to_string(home.path().join(".grok/config.toml")).expect("read");
        let table: toml::Table = body.parse().expect("toml");
        assert!(
            table.get("mcp_servers").is_none(),
            "empty mcp_servers table should be dropped: {body}"
        );
    }

    #[test]
    fn malformed_toml_is_refused_on_register() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".codex")).expect("dir");
        std::fs::write(home.path().join(".codex/config.toml"), "[[[not toml").expect("seed");
        let err = AgentId::Codex
            .register(home.path(), &launch())
            .expect_err("must refuse");
        assert!(
            format!("{err:#}").contains("not valid TOML"),
            "unexpected error: {err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join(".codex/config.toml")).expect("read"),
            "[[[not toml"
        );
    }

    #[test]
    fn gemini_json_upsert_uses_mcp_servers() {
        let home = TempDir::new().expect("tempdir");
        AgentId::Gemini
            .register(home.path(), &launch())
            .expect("register");
        let raw = std::fs::read_to_string(home.path().join(".gemini/settings.json")).expect("read");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(
            value["mcpServers"]["hippius-mem"]["command"],
            "/opt/hippius-mem"
        );
    }

    #[test]
    fn openclaw_json_nests_under_mcp_servers() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".openclaw")).expect("dir");
        std::fs::write(
            home.path().join(".openclaw/openclaw.json"),
            "{\n  \"gateway\": { \"port\": 18789 }\n}\n",
        )
        .expect("seed");
        AgentId::OpenClaw
            .register(home.path(), &launch())
            .expect("register");
        let raw =
            std::fs::read_to_string(home.path().join(".openclaw/openclaw.json")).expect("read");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["gateway"]["port"], 18789, "sibling keys survive");
        assert_eq!(
            value["mcp"]["servers"]["hippius-mem"]["env"]["HIPPIUS_MEM_CONFIG"],
            "/cfg/hippius-mem.toml"
        );
        AgentId::OpenClaw
            .unregister(home.path())
            .expect("unregister");
        let after =
            std::fs::read_to_string(home.path().join(".openclaw/openclaw.json")).expect("read");
        let value: serde_json::Value = serde_json::from_str(&after).expect("json");
        assert!(
            value["mcp"]["servers"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
                || value["mcp"]["servers"].get("hippius-mem").is_none()
        );
        assert_eq!(value["gateway"]["port"], 18789);
    }

    #[test]
    fn yaml_upsert_creates_and_replaces_and_preserves_siblings() {
        let block = hermes_server_block(&launch());
        let created = upsert_yaml_server("", &block).expect("create");
        assert!(created.starts_with("mcp_servers:\n  hippius-mem:"));
        assert!(created.contains("/opt/hippius-mem"));

        let seeded = "personality: terse\nmcp_servers:\n  github:\n    command: \"npx\"\n";
        let updated = upsert_yaml_server(seeded, &block).expect("insert");
        assert!(updated.contains("personality: terse"));
        assert!(updated.contains("  github:\n    command: \"npx\""));
        assert!(updated.contains("  hippius-mem:"));

        let replaced = upsert_yaml_server(&updated, &block).expect("replace");
        assert_eq!(
            replaced.matches("  hippius-mem:").count(),
            1,
            "exactly one hippius-mem entry: {replaced}"
        );

        let removed = remove_yaml_server(&replaced).expect("remove");
        assert!(
            !removed.contains("hippius-mem:"),
            "entry must be gone: {removed}"
        );
        assert!(removed.contains("  github:"));
    }

    #[test]
    fn yaml_refuses_flow_style_mcp_servers() {
        let err = upsert_yaml_server(
            "mcp_servers: { github: { command: x } }\n",
            "  hippius-mem:\n",
        )
        .expect_err("flow");
        assert!(
            format!("{err:#}").contains("flow-style"),
            "unexpected: {err:#}"
        );
    }

    #[test]
    fn hermes_adapter_round_trips_on_disk() {
        let home = TempDir::new().expect("tempdir");
        std::fs::create_dir(home.path().join(".hermes")).expect("dir");
        std::fs::write(
            home.path().join(".hermes/config.yaml"),
            "model: gpt\nmcp_servers:\n  docs:\n    url: \"https://example\"\n",
        )
        .expect("seed");
        install_with(home.path(), &launch(), &HermesOpts::default(), None).expect("register");
        install_with(home.path(), &launch(), &HermesOpts::default(), None).expect("re-register");
        let body = std::fs::read_to_string(home.path().join(".hermes/config.yaml")).expect("read");
        assert!(body.contains("model: gpt"));
        assert!(body.contains("  docs:"));
        assert!(body.contains("  provider: hippius-mem"));
        assert!(
            !body.contains("  hippius-mem:"),
            "must not register an MCP server: {body}"
        );
        assert!(
            home.path()
                .join(".hermes/plugins/hippius-mem/plugin.yaml")
                .is_file()
        );
        uninstall_with(home.path(), &HermesOpts::default(), None).expect("unregister");
        let after = std::fs::read_to_string(home.path().join(".hermes/config.yaml")).expect("read");
        assert!(!after.contains("provider: hippius-mem"));
        assert!(after.contains("model: gpt"));
        assert!(
            !home.path().join(".hermes/plugins/hippius-mem").exists(),
            "plugin dir must be removed"
        );
    }
}
