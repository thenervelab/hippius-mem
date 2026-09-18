//! User-level service that keeps `hippius-mem serve` running.
//!
//! Claude / Grok / Codex are registered against a loopback streamable-HTTP
//! MCP URL. That URL is only useful if one long-lived process is listening,
//! so `install` writes a per-user service (a macOS Launch Agent, systemd
//! user unit on Linux) and best-effort starts it. Uninstall reverses both.
//! Windows has no service writer in this phase: `install` still writes the
//! HTTP MCP entry and tells the operator to run `hippius-mem serve`.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::Context;

use super::mcp::{DEFAULT_HTTP_PORT, McpLaunch, health_response_is_ours};

/// Label / unit name. Stable so a re-install updates rather than duplicates.
const SERVICE_NAME: &str = "ai.hippius.mem";

const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const HEALTH_WAIT: Duration = Duration::from_secs(8);
const HEALTH_POLL: Duration = Duration::from_millis(100);

/// Write the user service and start it. Returns `Ok` only when `/health`
/// answers on the default loopback port, so `install` can refuse to rewrite
/// working stdio MCP entries onto a dead URL.
///
/// # Errors
///
/// Returns an error if the unit file cannot be written, the service command
/// fails, or the daemon never becomes healthy.
pub(crate) fn install_and_start(home: &Path, launch: &McpLaunch) -> anyhow::Result<()> {
    write_unit(home, launch)?;

    let started = start(home);
    if started.is_err() {
        // A unit that cannot come up must not stay behind: launchd / systemd
        // would respawn it at every login (and on every non-zero exit) for a
        // URL no client was pointed at.
        let _ = uninstall(home);
    }
    started
}

/// Stop the user service if it is loaded and remove the unit file.
///
/// # Errors
///
/// Returns an error only if a present unit file cannot be removed.
pub(crate) fn uninstall(home: &Path) -> anyhow::Result<()> {
    let _ = stop(home);
    let path = unit_path(home);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("removing {} failed", path.display())),
    }
}

fn write_unit(home: &Path, launch: &McpLaunch) -> anyhow::Result<()> {
    let path = unit_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {} failed", parent.display()))?;
    }
    let body = unit_body(home, launch);
    super::atomic::atomic_write(&path, body.as_bytes())
}

fn unit_path(home: &Path) -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/LaunchAgents")
            .join(format!("{SERVICE_NAME}.plist"))
    } else {
        home.join(".config/systemd/user")
            .join(format!("{SERVICE_NAME}.service"))
    }
}

fn unit_body(home: &Path, launch: &McpLaunch) -> String {
    let log_dir = launch
        .config_path
        .parent()
        .map_or_else(|| home.join(".config/hippius-mem"), Path::to_path_buf);
    let err_log = log_dir.join("serve.err.log");
    let out_log = log_dir.join("serve.out.log");
    if cfg!(target_os = "macos") {
        macos_plist(
            &launch.command,
            &launch.config_path.to_string_lossy(),
            &out_log.to_string_lossy(),
            &err_log.to_string_lossy(),
        )
    } else {
        systemd_unit(
            &launch.command,
            &launch.config_path.to_string_lossy(),
            &err_log.to_string_lossy(),
        )
    }
}

fn macos_plist(command: &str, config_path: &str, out_log: &str, err_log: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{SERVICE_NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>serve</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HIPPIUS_MEM_CONFIG</key>
    <string>{}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>{}</string>
  <key>StandardErrorPath</key>
  <string>{}</string>
</dict>
</plist>
"#,
        xml_escape(command),
        xml_escape(config_path),
        xml_escape(out_log),
        xml_escape(err_log),
    )
}

fn systemd_unit(command: &str, config_path: &str, err_log: &str) -> String {
    format!(
        "[Unit]\n\
         Description=Hippius Memory MCP daemon\n\
         \n\
         [Service]\n\
         ExecStart={command} serve\n\
         Environment={environment}\n\
         Restart=on-failure\n\
         StandardOutput=null\n\
         StandardError=append:{err_log}\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        command = systemd_quote(command, SystemdField::ExecStart),
        environment = systemd_quote(
            &format!("HIPPIUS_MEM_CONFIG={config_path}"),
            SystemdField::Environment
        ),
        err_log = err_log.replace('%', "%%"),
    )
}

/// Which unit-file setting a value is quoted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemdField {
    /// `ExecStart=`: `$` additionally starts environment expansion.
    ExecStart,
    /// `Environment=`: no `$` expansion.
    Environment,
}

/// Double-quote `value` for a systemd unit so a path with a space (a home
/// directory like `/home/Jane Doe`) stays ONE word instead of splitting the
/// binary path from its tail. `%` is a specifier everywhere in a unit file.
fn systemd_quote(value: &str, field: SystemdField) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match (ch, field) {
            ('\\', _) => quoted.push_str("\\\\"),
            ('"', _) => quoted.push_str("\\\""),
            ('%', _) => quoted.push_str("%%"),
            ('$', SystemdField::ExecStart) => quoted.push_str("$$"),
            (other, _) => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn start(home: &Path) -> anyhow::Result<()> {
    if cfg!(target_os = "macos") {
        let path = unit_path(home);
        let uid = user_id()?;
        let domain = format!("gui/{uid}");
        let label = format!("{domain}/{SERVICE_NAME}");
        // bootout is best-effort: a first install has nothing loaded.
        let _ = quiet(Command::new("launchctl").args(["bootout", &label])).status();
        // Wait for a SIGTERM'd occupant to drop /health so the new job does
        // not see AddrInUse, exit 0, then leave the port empty.
        let _ = wait_for_health(DEFAULT_HTTP_PORT, false, HEALTH_WAIT);
        let status = Command::new("launchctl")
            .args(["bootstrap", &domain, &path.to_string_lossy()])
            .status()
            .context("launchctl bootstrap failed to start")?;
        if !status.success() {
            anyhow::bail!("launchctl bootstrap exited {status}");
        }
    } else if cfg!(target_os = "linux") {
        let unit = format!("{SERVICE_NAME}.service");
        let reload = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .context("systemctl --user daemon-reload failed")?;
        if !reload.success() {
            anyhow::bail!("systemctl --user daemon-reload exited {reload}");
        }
        let enable = Command::new("systemctl")
            .args(["--user", "enable", "--now", &unit])
            .status()
            .context("systemctl --user enable failed to start")?;
        if !enable.success() {
            anyhow::bail!("systemctl --user enable exited {enable}");
        }
        // `enable --now` is a no-op when the unit is already running; restart
        // picks up the binary `install` just wrote.
        let restart = Command::new("systemctl")
            .args(["--user", "restart", &unit])
            .status()
            .context("systemctl --user restart failed")?;
        if !restart.success() {
            anyhow::bail!("systemctl --user restart exited {restart}");
        }
    } else {
        anyhow::bail!("no user-service writer on this OS; run `hippius-mem serve`");
    }
    if !wait_for_health(DEFAULT_HTTP_PORT, true, HEALTH_WAIT) {
        anyhow::bail!(
            "hippius-mem serve did not become healthy on 127.0.0.1:{DEFAULT_HTTP_PORT} \
             within {}s",
            HEALTH_WAIT.as_secs()
        );
    }
    Ok(())
}

/// Poll `/health` until it matches `want_ok` or `budget` elapses.
fn wait_for_health(port: u16, want_ok: bool, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if loopback_health_ok(port) == want_ok {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(HEALTH_POLL);
    }
}

/// Unauthenticated GET `/health` on the default loopback MCP port.
fn loopback_health_ok(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, HEALTH_PROBE_TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(HEALTH_PROBE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HEALTH_PROBE_TIMEOUT));
    let req =
        format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    health_response_is_ours(&buf)
}

fn stop(home: &Path) -> anyhow::Result<()> {
    if cfg!(target_os = "macos") {
        let uid = user_id()?;
        let label = format!("gui/{uid}/{SERVICE_NAME}");
        let _ = quiet(Command::new("launchctl").args(["bootout", &label])).status();
        let _ = home;
        Ok(())
    } else if cfg!(target_os = "linux") {
        let _ = quiet(Command::new("systemctl").args([
            "--user",
            "disable",
            "--now",
            &format!("{SERVICE_NAME}.service"),
        ]))
        .status();
        Ok(())
    } else {
        Ok(())
    }
}

/// Silence a best-effort service command. `install` now retires the daemon
/// whenever no client uses it, so stopping a service that was never loaded is
/// routine, and launchctl's "Boot-out failed: 3: No such process" on the
/// operator's terminal would read as an install failure.
fn quiet(command: &mut Command) -> &mut Command {
    command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
}

fn user_id() -> anyhow::Result<u32> {
    // `$UID` is not POSIX-guaranteed (bash sets it; dash does not), so `id -u`
    // is the portable userspace answer without pulling libc / unsafe.
    if let Ok(uid) = std::env::var("UID")
        && let Ok(parsed) = uid.parse()
    {
        return Ok(parsed);
    }
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("running `id -u` to resolve the launchctl domain")?;
    if !output.status.success() {
        anyhow::bail!("`id -u` exited {}", output.status);
    }
    let stdout = String::from_utf8(output.stdout).context("`id -u` stdout was not UTF-8")?;
    stdout
        .trim()
        .parse()
        .with_context(|| format!("`id -u` printed {stdout:?}, not a uid"))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert on fixtures where construction cannot fail"
    )]

    use std::path::PathBuf;

    use super::{
        SERVICE_NAME, SystemdField, loopback_health_ok, macos_plist, systemd_quote, systemd_unit,
        unit_path, xml_escape,
    };
    use crate::setup::mcp::HEALTH_BODY;
    use crate::setup::mcp::McpLaunch;

    #[test]
    fn macos_plist_runs_serve_with_config_and_does_not_restart_on_success() {
        let body = macos_plist(
            "/opt/hippius-mem",
            "/cfg/hippius-mem.toml",
            "/cfg/serve.out.log",
            "/cfg/serve.err.log",
        );
        assert!(body.contains("<string>serve</string>"));
        assert!(body.contains("/opt/hippius-mem"));
        assert!(body.contains("HIPPIUS_MEM_CONFIG"));
        assert!(body.contains("/cfg/hippius-mem.toml"));
        assert!(
            body.contains("SuccessfulExit"),
            "KeepAlive must not respawn an exit-0 already-running serve: {body}"
        );
        assert!(body.contains(SERVICE_NAME));
    }

    #[test]
    fn systemd_unit_restarts_on_failure_only() {
        let body = systemd_unit(
            "/opt/hippius-mem",
            "/cfg/hippius-mem.toml",
            "/cfg/serve.err.log",
        );
        assert!(body.contains("ExecStart=\"/opt/hippius-mem\" serve"));
        assert!(body.contains("Restart=on-failure"));
        assert!(body.contains("Environment=\"HIPPIUS_MEM_CONFIG=/cfg/hippius-mem.toml\""));
    }

    #[test]
    fn systemd_unit_keeps_a_spaced_binary_path_one_word() {
        let body = systemd_unit(
            "/home/Jane Doe/.local/bin/hippius-mem",
            "/home/Jane Doe/.config/hippius-mem/hippius-mem.toml",
            "/home/Jane Doe/.config/hippius-mem/serve.err.log",
        );

        assert!(
            body.contains("ExecStart=\"/home/Jane Doe/.local/bin/hippius-mem\" serve"),
            "an unquoted path would exec `/home/Jane`: {body}"
        );
    }

    #[test]
    fn systemd_quote_escapes_specifiers_and_expansion() {
        assert_eq!(
            systemd_quote("a\"b\\c%d$e", SystemdField::ExecStart),
            "\"a\\\"b\\\\c%%d$$e\""
        );
        assert_eq!(systemd_quote("K=$v", SystemdField::Environment), "\"K=$v\"");
    }

    #[test]
    fn xml_escape_covers_the_three_markup_chars() {
        assert_eq!(xml_escape("a&b<c>\"d"), "a&amp;b&lt;c&gt;&quot;d");
    }

    #[test]
    fn unit_path_is_under_the_user_home() {
        let home = PathBuf::from("/home/u");
        let path = unit_path(&home);
        assert!(
            path.starts_with(&home),
            "unit must be a user-level file, got {}",
            path.display()
        );
        assert!(
            path.to_string_lossy().contains(SERVICE_NAME),
            "unit filename must be stable: {}",
            path.display()
        );
        let _ = McpLaunch {
            command: "x".into(),
            config_path: PathBuf::from("/cfg/hippius-mem.toml"),
            http: None,
        };
    }

    #[test]
    fn loopback_health_ok_is_false_when_nothing_listens() {
        assert!(
            !loopback_health_ok(1),
            "port 1 is not a hippius-mem health endpoint"
        );
    }

    #[test]
    fn loopback_health_ok_accepts_the_daemon_health_body() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{HEALTH_BODY}",
                    HEALTH_BODY.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        assert!(
            loopback_health_ok(port),
            "the daemon's own health body must count as our daemon"
        );
        let _ = handle.join();
    }
}
