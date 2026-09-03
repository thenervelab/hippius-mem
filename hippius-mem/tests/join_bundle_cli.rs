//! End-to-end CLI tests for `hippius-mem join --bundle -`: the real binary,
//! the real stdin path, and the real filesystem — the exact surface a joiner
//! touches. Offline by design: with no `HIPPIUS_MEM_MNEMONIC` the command
//! writes and validates the config without any network operation.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]
#![expect(
    clippy::expect_used,
    reason = "tests assert on hand-built fixtures where construction cannot fail"
)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

/// 64 hex chars decoding to 32 bytes — valid team-key material.
fn hex64(byte: &str) -> String {
    byte.repeat(32)
}

/// A minimal always-present-fields bundle, exactly the shape `invite` emits
/// (header comments omitted — they are `#` comments and parse away).
fn bundle_text() -> String {
    format!(
        "bucket = \"team-bucket\"\nteam = \"acme\"\nteam_key_hex = \"{key}\"\n\
         access_key_id = \"AKIAJOIN\"\nsecret = \"shown-once\"\n",
        key = hex64("ab"),
    )
}

#[test]
fn stdin_bundle_writes_a_fresh_0600_config() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["join", "--bundle", "-"])
        // Pin the write target and keep the flow offline (no member-key publish).
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(bundle_text().as_bytes())?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "join --bundle - failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The written file is the product: owner-only, parseable, seed generated
    // locally (the bundle carried none), and the secret never echoed back.
    let mode = std::fs::metadata(&config_path)?.permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "config must be owner-only: {mode:o}");
    let written = std::fs::read_to_string(&config_path)?;
    assert!(written.contains("team = \"acme\""));
    let seed_line = written
        .lines()
        .find_map(|line| line.strip_prefix("author_seed_hex = \""))
        .expect("a generated author_seed_hex line");
    let seed = seed_line.trim_end_matches('"');
    assert_eq!(seed.len(), 64, "seed must be 32 CSPRNG bytes as hex");
    assert!(seed.bytes().all(|b| b.is_ascii_hexdigit()));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("DELETE"),
        "must tell the joiner to delete the bundle"
    );
    assert!(
        !stdout.contains("shown-once") && !stdout.contains(&hex64("ab")),
        "secrets must never be echoed back"
    );
    Ok(())
}

#[test]
fn parse_failure_stderr_never_echoes_the_secret() -> anyhow::Result<()> {
    // The confirmed spec-review repro: an unterminated `secret = "...` string
    // made toml's span rendering print the raw secret line to stderr. The
    // sanitized error must fail WITHOUT the sentinel anywhere in the output.
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["join", "--bundle", "-"])
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(b"bucket = \"b\"\nteam = \"t\"\nsecret = \"SUPERSECRETVALUE123\n")?;
    let output = child.wait_with_output()?;
    assert!(!output.status.success(), "a malformed bundle must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stderr.contains("SUPERSECRETVALUE123") && !stdout.contains("SUPERSECRETVALUE123"),
        "the secret must never be echoed back: {stderr}"
    );
    assert!(!config_path.exists(), "no half-config may be left behind");
    Ok(())
}

#[test]
fn malformed_bundle_fails_naming_the_missing_field() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["join", "--bundle", "-"])
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(b"team = \"acme\"\n")?;
    let output = child.wait_with_output()?;
    assert!(!output.status.success(), "a field-less bundle must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bucket"),
        "the error must name the first missing field: {stderr}"
    );
    assert!(!config_path.exists(), "no half-config may be left behind");
    Ok(())
}
