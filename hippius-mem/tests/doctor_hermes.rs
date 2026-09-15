//! `doctor --offline` must fail a Hermes first-landing that never ran
//! `install --agent hermes`, and stay quiet when Hermes is absent.
//!
//! Isolated `HOME` / `HIPPIUS_MEM_CONFIG` / `HERMES_HOME` so a developer
//! profile cannot leak into the assertion (the recorded `HERMES_HOME` gotcha).

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use std::process::Command;

/// 64 hex chars decoding to 32 bytes — valid team-key/seed material.
fn hex64(byte: &str) -> String {
    byte.repeat(32)
}

fn offline_toml() -> String {
    format!(
        "bucket = \"b\"\naccess_key_id = \"AK\"\nsecret = \"s\"\n\
         team = \"t\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n",
        key = hex64("ab"),
        seed = hex64("cd"),
    )
}

fn run_doctor_offline(home: &std::path::Path) -> anyhow::Result<std::process::Output> {
    let config_path = home.join("hippius-mem.toml");
    std::fs::write(&config_path, offline_toml())?;
    Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["doctor", "--offline"])
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", home)
        .env("RUST_LOG", "info")
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .output()
        .map_err(anyhow::Error::from)
}

#[test]
fn doctor_offline_passes_when_hermes_is_absent() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let output = run_doctor_offline(dir.path())?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "absent Hermes must not fail doctor: {stderr}"
    );
    assert!(
        !stderr.contains("hermes:"),
        "absent Hermes must stay silent: {stderr}"
    );
    Ok(())
}

#[test]
fn doctor_offline_fails_when_hermes_is_present_but_unwired() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::create_dir(dir.path().join(".hermes"))?;
    let output = run_doctor_offline(dir.path())?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "unwired ~/.hermes must fail doctor --offline: {stderr}"
    );
    assert!(
        stderr.contains("install --agent hermes"),
        "the operator must be told the fix: {stderr}"
    );
    Ok(())
}

#[test]
fn doctor_offline_passes_when_hermes_is_wired() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let binary = dir.path().join("hippius-mem-bin");
    std::fs::write(&binary, b"fake")?;
    let hermes = dir.path().join(".hermes");
    std::fs::create_dir(&hermes)?;
    std::fs::create_dir_all(hermes.join("plugins/hippius-mem"))?;
    std::fs::write(
        hermes.join("plugins/hippius-mem/plugin.yaml"),
        "name: hippius-mem\nhooks:\n  - prefetch\n  - system_prompt_block\n",
    )?;
    std::fs::write(
        hermes.join("config.yaml"),
        "memory:\n  provider: hippius-mem\n",
    )?;
    let config_path = dir.path().join("hippius-mem.toml");
    std::fs::write(&config_path, offline_toml())?;
    let sidecar = serde_json::json!({
        "binary": binary.to_string_lossy(),
        "config_path": config_path.to_string_lossy(),
    });
    std::fs::write(
        hermes.join("hippius-mem.json"),
        serde_json::to_vec_pretty(&sidecar)?,
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["doctor", "--offline"])
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", dir.path())
        .env("RUST_LOG", "info")
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a wired Hermes home must pass doctor --offline: {stderr}"
    );
    assert!(
        stderr.contains("hermes: memory provider wired"),
        "the operator must see that Hermes is wired: {stderr}"
    );
    Ok(())
}

#[test]
fn doctor_offline_fails_when_plugin_omits_system_prompt_block() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let binary = dir.path().join("hippius-mem-bin");
    std::fs::write(&binary, b"fake")?;
    let hermes = dir.path().join(".hermes");
    std::fs::create_dir(&hermes)?;
    std::fs::create_dir_all(hermes.join("plugins/hippius-mem"))?;
    std::fs::write(
        hermes.join("plugins/hippius-mem/plugin.yaml"),
        "name: hippius-mem\nhooks:\n  - prefetch\n  - sync_turn\n",
    )?;
    std::fs::write(
        hermes.join("config.yaml"),
        "memory:\n  provider: hippius-mem\n",
    )?;
    let config_path = dir.path().join("hippius-mem.toml");
    std::fs::write(&config_path, offline_toml())?;
    let sidecar = serde_json::json!({
        "binary": binary.to_string_lossy(),
        "config_path": config_path.to_string_lossy(),
    });
    std::fs::write(
        hermes.join("hippius-mem.json"),
        serde_json::to_vec_pretty(&sidecar)?,
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["doctor", "--offline"])
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", dir.path())
        .env("RUST_LOG", "info")
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a 0.2.0 plugin.yaml must fail doctor --offline: {stderr}"
    );
    assert!(
        stderr.contains("system_prompt_block") && stderr.contains("install --agent hermes"),
        "the operator must be told to re-install the plugin: {stderr}"
    );
    Ok(())
}
