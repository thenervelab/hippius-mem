//! quickstart writes a zero-decision local trial profile and refuses to
//! touch an existing config.
//!
//! Modeled on `tests/join_bundle_cli.rs`: the real binary, the real
//! filesystem, `HIPPIUS_MEM_CONFIG` pinned at a temp path so the write target
//! is isolated, and `HOME` pinned at the same tempdir so `--no-wire`'s
//! skipped Claude Code wiring has nothing outside the sandbox to touch even
//! if a future change forgets to honor the flag.

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
