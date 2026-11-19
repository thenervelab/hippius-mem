//! `doctor` warns when a repo's installed hook scripts are not the ones the
//! binary carries, which is the state a binary upgrade leaves a provisioned
//! repo in until `init` runs there again.
//!
//! Isolated `HOME` / `HIPPIUS_MEM_CONFIG` so a developer profile cannot leak
//! into the assertions.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use std::path::Path;
use std::process::{Command, Output};

const PREFLIGHT: &str = ".claude/hooks/hippius-mem-recall-preflight.sh";
const TOKEN: &str = ".claude/hooks/hippius-mem-recall-token.sh";

/// Run the binary with `args` in `repo`, with `HOME` and the config under `home`.
fn hippius_mem(home: &Path, repo: &Path, args: &[&str]) -> anyhow::Result<Output> {
    let config_path = home.join("hippius-mem.toml");
    let hex64 = |byte: &str| byte.repeat(32);
    std::fs::write(
        &config_path,
        format!(
            "bucket = \"b\"\naccess_key_id = \"AK\"\nsecret = \"s\"\n\
             team = \"t\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n",
            key = hex64("ab"),
            seed = hex64("cd"),
        ),
    )?;
    Ok(Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(args)
        .current_dir(repo)
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", home)
        .env("RUST_LOG", "info")
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .output()?)
}

/// A git repo under `home` that `init` has provisioned with the binary's hooks.
fn provisioned_repo(home: &Path) -> anyhow::Result<std::path::PathBuf> {
    let repo = home.join("repo");
    std::fs::create_dir(&repo)?;
    let git = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .output()?;
    assert!(git.status.success(), "git init failed: {git:?}");
    let init = hippius_mem(home, &repo, &["init"])?;
    assert!(init.status.success(), "init failed: {init:?}");
    Ok(repo)
}

/// The `hooks:` warning `doctor --offline` printed in `repo`, if any.
fn doctor_hooks_warning(home: &Path, repo: &Path) -> anyhow::Result<Option<String>> {
    let output = hippius_mem(home, repo, &["doctor", "--offline"])?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "hook drift must never fail doctor: {stderr}"
    );
    Ok(stderr
        .lines()
        .find(|line| line.contains("hooks:"))
        .map(str::to_owned))
}

#[test]
fn doctor_is_silent_about_hooks_right_after_init() -> anyhow::Result<()> {
    let home = tempfile::tempdir()?;
    let repo = provisioned_repo(home.path())?;
    let warning = doctor_hooks_warning(home.path(), &repo)?;
    assert_eq!(warning, None, "freshly installed hooks match the binary");
    Ok(())
}

#[test]
fn doctor_names_a_changed_hook_and_init_clears_the_warning() -> anyhow::Result<()> {
    let home = tempfile::tempdir()?;
    let repo = provisioned_repo(home.path())?;
    // What a repo provisioned by an older release looks like to a newer binary:
    // one script with other bytes. A removed script is a choice, not drift.
    std::fs::write(repo.join(PREFLIGHT), "#!/usr/bin/env bash\nexit 0\n")?;
    std::fs::remove_file(repo.join(TOKEN))?;

    let warning = doctor_hooks_warning(home.path(), &repo)?
        .ok_or_else(|| anyhow::anyhow!("a changed hook script must be reported"))?;
    assert!(warning.contains(PREFLIGHT), "names the script: {warning}");
    assert!(
        !warning.contains(TOKEN),
        "skips a removed script: {warning}"
    );
    assert!(
        warning.contains("hippius-mem init"),
        "names the fix: {warning}"
    );

    let init = hippius_mem(home.path(), &repo, &["init"])?;
    assert!(init.status.success(), "init failed: {init:?}");
    let warning = doctor_hooks_warning(home.path(), &repo)?;
    assert_eq!(warning, None, "the fix the warning names must clear it");
    Ok(())
}
