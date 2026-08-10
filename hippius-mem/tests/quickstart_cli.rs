//! quickstart writes a zero-decision local trial profile and refuses to
//! touch an existing config.
//!
//! Modeled on `tests/join_bundle_cli.rs`: the real binary, the real
//! filesystem, `HIPPIUS_MEM_CONFIG` pinned at a temp path so the write target
//! is isolated, and `HOME` pinned at the same tempdir so `--no-wire`'s
//! skipped Claude Code wiring has nothing outside the sandbox to touch even
//! if a future change forgets to honor the flag. `XDG_DATA_HOME` (and
//! `XDG_CACHE_HOME`, which the trial vault must NOT use — finding #4: a
//! cache-cleaner must never be able to delete the only copy of a trial
//! user's notes) are always removed so the trial vault's `local_trial_root`
//! derivation is deterministic (falls back to `HOME/.local/share`) and never
//! leaks a probe write into a real machine's data directory. Storage-related
//! `HIPPIUS_MEM_*` overrides are removed too, so an operator's own shell
//! cannot spuriously trip finding #11's conflicting-env-var refusal.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

/// Run `hippius-mem quickstart --no-wire` against an isolated `HOME` and
/// `HIPPIUS_MEM_CONFIG`, returning the process output.
fn run_quickstart(
    config_path: &std::path::Path,
    home: &std::path::Path,
) -> anyhow::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["quickstart", "--no-wire"])
        .env("HIPPIUS_MEM_CONFIG", config_path)
        .env("HOME", home)
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("HIPPIUS_MEM_STORAGE")
        .env_remove("HIPPIUS_MEM_BUCKET")
        .env_remove("HIPPIUS_MEM_ACCESS_KEY_ID")
        .env_remove("HIPPIUS_MEM_SECRET")
        .output()
        .map_err(anyhow::Error::from)
}

#[test]
fn quickstart_writes_a_local_trial_profile() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("config.toml");

    let output = run_quickstart(&config_path, dir.path())?;
    assert!(
        output.status.success(),
        "quickstart failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The written file is the product: owner-only, and every field a
    // storage = "local" trial profile needs is present and well-formed.
    let mode = std::fs::metadata(&config_path)?.permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "config must be owner-only: {mode:o}");

    let written = std::fs::read_to_string(&config_path)?;
    let parsed: toml::Value = toml::from_str(&written)?;
    assert_eq!(
        parsed.get("storage").and_then(toml::Value::as_str),
        Some("local"),
        "a fresh trial must bind the local backend: {written}"
    );

    // Finding #5: the RESOLVED vault directory must be pinned into
    // `local_root`, so `upgrade`/`serve` resolve to this exact path later
    // regardless of what XDG_DATA_HOME/HOME are set to when they run — no
    // `--team` was passed, so the default team "trial" derives
    // `<HOME>/.local/share/hippius-mem/local/trial` (the XDG *data* base,
    // not *cache* — finding #4).
    let vault_root = dir.path().join(".local/share/hippius-mem/local/trial");
    assert_eq!(
        parsed.get("local_root").and_then(toml::Value::as_str),
        Some(vault_root.to_string_lossy().as_ref()),
        "local_root must be persisted as the resolved vault directory: {written}"
    );

    let team_key_hex = parsed
        .get("team_key_hex")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("team_key_hex missing: {written}"))?;
    assert_eq!(
        team_key_hex.len(),
        64,
        "team_key_hex must be 32 bytes as hex"
    );
    assert!(team_key_hex.bytes().all(|b| b.is_ascii_hexdigit()));

    let author_seed_hex = parsed
        .get("author_seed_hex")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("author_seed_hex missing: {written}"))?;
    assert_eq!(
        author_seed_hex.len(),
        64,
        "author_seed_hex must be 32 bytes as hex"
    );
    assert!(author_seed_hex.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(
        team_key_hex, author_seed_hex,
        "team key and author seed must be independent CSPRNG draws"
    );

    for field in ["bucket", "access_key_id", "secret"] {
        let value = parsed
            .get(field)
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        assert!(
            value.is_empty(),
            "{field} must be empty for a local trial: {value:?}"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hippius-mem upgrade"),
        "next steps must point at the upgrade path: {stdout}"
    );

    // "Trial vault ready at {root}" names the same vault directory checked
    // above via `local_root` — never the config file path, which is a
    // different location entirely.
    assert!(
        stdout.contains(&format!("Trial vault ready at {}", vault_root.display())),
        "next steps must name the trial vault directory {}: {stdout}",
        vault_root.display()
    );
    assert!(
        !stdout.contains(&config_path.display().to_string()),
        "the vault-ready line must not print the config file path: {stdout}"
    );

    Ok(())
}

#[test]
fn quickstart_succeeds_with_no_env_preconfigured() -> anyhow::Result<()> {
    // The critical first-run scenario: a brand-new user with NOTHING
    // pre-configured — no HIPPIUS_MEM_CONFIG, an isolated XDG_CONFIG_HOME (so
    // the write target is the XDG global default under this tempdir, never
    // the real machine's), and a cwd holding no local hippius-mem.toml.
    // quickstart must still succeed end to end: the doctor probe
    // (probe_fresh_trial -> doctor::run_for_config) must examine the exact
    // config quickstart just wrote, not silently fall back to
    // Config::default() via Config::from_env_and_file's cwd-relative
    // default, which this scenario would never find.
    let home = tempfile::tempdir()?;
    let xdg_config_home = home.path().join("xdg-config");
    let cwd = tempfile::tempdir()?;

    let output = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["quickstart", "--no-wire"])
        .env_remove("HIPPIUS_MEM_CONFIG")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("HIPPIUS_MEM_STORAGE")
        .env_remove("HIPPIUS_MEM_BUCKET")
        .env_remove("HIPPIUS_MEM_ACCESS_KEY_ID")
        .env_remove("HIPPIUS_MEM_SECRET")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .current_dir(cwd.path())
        .output()?;

    assert!(
        output.status.success(),
        "quickstart must succeed on a first run with nothing pre-configured: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The config must land at the XDG global default resolve_target_path
    // falls back to when HIPPIUS_MEM_CONFIG is unset — the same location
    // setup::install's MCP registration will point HIPPIUS_MEM_CONFIG at.
    let config_path = xdg_config_home.join("hippius-mem/hippius-mem.toml");
    assert!(
        config_path.is_file(),
        "the config must land at the XDG global default: {}",
        config_path.display()
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Trial vault ready at"),
        "the full flow, including the doctor probe, must have completed: {stdout}"
    );

    Ok(())
}

#[test]
fn quickstart_refuses_an_existing_config() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("config.toml");
    let existing = "this is not even a config, quickstart must not care why\n";
    std::fs::write(&config_path, existing)?;

    let output = run_quickstart(&config_path, dir.path())?;
    assert!(
        !output.status.success(),
        "quickstart must refuse to touch an existing config"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("doctor"),
        "the refusal must point the operator at doctor: {stderr}"
    );

    assert_eq!(
        std::fs::read_to_string(&config_path)?,
        existing,
        "an existing config must be left byte-identical"
    );

    Ok(())
}

/// Run `hippius-mem <args>` against the same isolated `HOME`/`HIPPIUS_MEM_CONFIG`
/// as [`run_quickstart`], with no mnemonic set — a team-lifecycle command must
/// refuse a local trial profile before it ever asks for one.
fn run_team_command(
    config_path: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
) -> anyhow::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(args)
        .env("HIPPIUS_MEM_CONFIG", config_path)
        .env("HOME", home)
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .map_err(anyhow::Error::from)
}

/// Assert `output` is the pointed local-trial refusal — non-zero exit, and a
/// message naming both why (team mode needs a bucket) and the fix
/// (`hippius-mem upgrade`) — rather than some other, unrelated failure (a
/// missing mnemonic, a missing `--bucket` flag, or silent success).
fn assert_refuses_local_profile(output: &std::process::Output, command: &str) {
    assert!(
        !output.status.success(),
        "`{command}` must refuse on a local trial profile"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("team mode needs a Hippius bucket"),
        "`{command}` refusal must name why: {stderr}"
    );
    assert!(
        stderr.contains("hippius-mem upgrade"),
        "`{command}` refusal must point at the upgrade path: {stderr}"
    );
}

#[test]
fn team_commands_refuse_a_local_profile() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("config.toml");

    let quickstart = run_quickstart(&config_path, dir.path())?;
    assert!(
        quickstart.status.success(),
        "quickstart must succeed to set up the fixture: {}",
        String::from_utf8_lossy(&quickstart.stderr)
    );

    // `invite` is gated behind the `console` feature (see `main`'s
    // feature-gated dispatch): without it the binary refuses it with an
    // unrelated "requires --features console" message before ever reaching
    // profile resolution, so only exercise it when this test binary itself
    // was built with the feature — the same features the
    // `CARGO_BIN_EXE_hippius-mem` binary under test was built with.
    // `mint-token` is deliberately NOT in this list (finding #10): it mints
    // the S3 sub-token `upgrade --access-key-id` needs, so it must remain
    // usable against a local trial profile — see
    // `mint_token_reaches_arg_parsing_on_a_local_profile` below.
    let mut commands = vec!["join", "provision"];
    if cfg!(feature = "console") {
        commands.push("invite");
    }

    for command in commands {
        let output = run_team_command(&config_path, dir.path(), &[command])?;
        assert_refuses_local_profile(&output, command);
    }

    Ok(())
}

/// Finding #10: `mint-token` must NOT refuse on a local trial profile — it is
/// the command that mints the credentials `hippius-mem upgrade
/// --access-key-id` requires, so gating it behind `require_s3` dead-ends the
/// exact funnel it is supposed to unblock. Bare `mint-token` (no `--bucket`)
/// against a local-profile config must fail at ARGUMENT PARSING ("requires
/// --bucket"), not at profile resolution ("team mode needs a Hippius
/// bucket") — proving it got past the removed gate.
#[test]
fn mint_token_reaches_arg_parsing_on_a_local_profile() -> anyhow::Result<()> {
    if !cfg!(feature = "console") {
        // mint-token is entirely uncompiled without --features console; see
        // the comment on `team_commands_refuse_a_local_profile` above.
        return Ok(());
    }

    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("config.toml");

    let quickstart = run_quickstart(&config_path, dir.path())?;
    assert!(
        quickstart.status.success(),
        "quickstart must succeed to set up the fixture: {}",
        String::from_utf8_lossy(&quickstart.stderr)
    );

    let output = run_team_command(&config_path, dir.path(), &["mint-token"])?;
    assert!(
        !output.status.success(),
        "mint-token with no --bucket must still fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires --bucket"),
        "mint-token must reach argument parsing, not the local-profile refusal: {stderr}"
    );
    assert!(
        !stderr.contains("team mode needs a Hippius bucket"),
        "mint-token must not be gated by require_s3 on a local trial profile: {stderr}"
    );

    Ok(())
}
