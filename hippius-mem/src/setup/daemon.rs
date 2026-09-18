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

use super::mcp::{DEFAULT_HTTP_PORT, McpLaunch};

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
    start(home)
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
         Environment=HIPPIUS_MEM_CONFIG={config_path}\n\
         Restart=on-failure\n\
         StandardOutput=null\n\
         StandardError=append:{err_log}\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
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
        let _ = Command::new("launchctl").args(["bootout", &label]).status();
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
    String::from_utf8_lossy(&buf).contains("\r\n\r\nok")
}

fn stop(home: &Path) -> anyhow::Result<()> {
    if cfg!(target_os = "macos") {
        let uid = user_id()?;
        let label = format!("gui/{uid}/{SERVICE_NAME}");
        let _ = Command::new("launchctl").args(["bootout", &label]).status();
        let _ = home;
        Ok(())
    } else if cfg!(target_os = "linux") {
        let _ = Command::new("systemctl")
            .args([
                "--user",
                "disable",
                "--now",
                &format!("{SERVICE_NAME}.service"),
            ])
            .status();
        Ok(())
    } else {
        Ok(())
    }
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
        SERVICE_NAME, loopback_health_ok, macos_plist, systemd_unit, unit_path, xml_escape,
    };
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
        assert!(body.contains("ExecStart=/opt/hippius-mem serve"));
        assert!(body.contains("Restart=on-failure"));
        assert!(body.contains("HIPPIUS_MEM_CONFIG=/cfg/hippius-mem.toml"));
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
    fn loopback_health_ok_accepts_the_ok_body() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
        });
        assert!(
            loopback_health_ok(port),
            "a 200 body of `ok` must count as our daemon"
        );
        let _ = handle.join();
    }
}
