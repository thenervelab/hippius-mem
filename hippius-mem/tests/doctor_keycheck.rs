//! `doctor` compares the configured team key with the team's published key
//! check, run as the binary against a local trial vault.
//!
//! Isolated `HOME`, config and state directory, and every ambient
//! `HIPPIUS_MEM_*` stripped, so a developer profile cannot leak into the
//! assertions.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes"
)]

mod support;

use std::path::Path;
use std::process::Output;

const NO_CHECK: &str = "has no usable team-key check for epoch 0";
const MATCHES: &str = "the configured team key matches the team's published key check";

/// Run the binary with `args` over the local vault under `home`, configured
/// with the team key `key_byte` repeated.
fn hippius_mem(home: &Path, key_byte: &str, args: &[&str]) -> anyhow::Result<Output> {
    let config_path = home.join("hippius-mem.toml");
    std::fs::write(
        &config_path,
        format!(
            "team = \"trial\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n\
             storage = \"local\"\nlocal_root = \"{root}\"\nsemantic_embeddings = false\n",
            key = key_byte.repeat(32),
            seed = "cd".repeat(32),
            root = home.join("vault").display(),
        ),
    )?;
    Ok(support::binary()
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HIPPIUS_MEM_STATE_DIR", home.join("state"))
        .env("HIPPIUS_MEM_CACHE_DIR", "off")
        .env("RUST_LOG", "info")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME")
        .output()?)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// With no check published, `doctor` passes but warns that it cannot tell
/// whether the key is the team's, and never reports a match.
#[test]
fn doctor_warns_when_no_key_check_is_published() -> anyhow::Result<()> {
    let home = tempfile::tempdir()?;

    let doctor = hippius_mem(home.path(), "ab", &["doctor"])?;

    let err = stderr(&doctor);
    assert!(doctor.status.success(), "{err}");
    assert!(err.contains(NO_CHECK), "{err}");
    assert!(!err.contains(MATCHES), "{err}");
    Ok(())
}

/// After the key's check is published, `doctor` reports the match and drops
/// the warning; with another key it fails, naming the check's object key.
#[test]
fn doctor_reports_a_published_key_check_match_and_fails_a_mismatch() -> anyhow::Result<()> {
    let home = tempfile::tempdir()?;
    let publish = hippius_mem(home.path(), "ab", &["admin", "keycheck", "publish"])?;
    assert!(publish.status.success(), "{}", stderr(&publish));

    let doctor = hippius_mem(home.path(), "ab", &["doctor"])?;

    let err = stderr(&doctor);
    assert!(doctor.status.success(), "{err}");
    assert!(err.contains(MATCHES), "{err}");
    assert!(!err.contains(NO_CHECK), "{err}");

    let other_key = hippius_mem(home.path(), "ef", &["doctor"])?;

    let err = stderr(&other_key);
    assert!(!other_key.status.success(), "{err}");
    assert!(
        err.contains("is not team trial's key")
            && err.contains(&format!("trial/_keycheck/{:020}", 0)),
        "{err}"
    );
    assert!(!err.contains(MATCHES), "{err}");
    Ok(())
}
