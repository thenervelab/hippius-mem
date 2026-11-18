//! `report` renders the converged-data digest with the honesty label.
//!
//! Modeled on `tests/upgrade_cli.rs`: `quickstart` writes a local trial
//! profile, then a `MemoryStore` is reconstructed directly over the SAME
//! `FsBlobStore` root (this integration-test binary has no access to the
//! `hippius-mem` binary crate's private `Config`/`TeamProfile`, only
//! `hippius-mem-core`'s public API and the compiled `hippius-mem` binary
//! itself) to seed notes, remembers, edits, links, forgets, and
//! recall+get reinforcements — then the real `report` subcommand is run
//! against the identical config and its stdout is asserted against those
//! seeded numbers.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use std::collections::BTreeSet;
use std::process::Command;
use std::sync::Arc;

use anyhow::Context as _;
use hippius_mem_core::{
    BlobStore, FsBlobStore, HashEmbedder, InMemoryIndex, MemoryStore, NetworkPrefix, NoopAnchor,
    NoteId, NoteType, OpLogStore, RecallInput, RememberInput, RepoScope, SecretKey, Signer,
    Sr25519Signer,
};

/// Decode a 64-hex-char field into its 32 raw bytes.
fn hex32(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hippius_mem_core::hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", bytes.len()))
}

/// The trial identity `quickstart` wrote, parsed from the config it just
/// produced. Mirrors `upgrade_cli.rs`'s `TrialIdentity`.
struct TrialIdentity {
    team: String,
    team_key_hex: String,
    author_seed_hex: String,
}

/// Run `quickstart --no-wire` for real, then parse the team identity back out
/// of the config it wrote.
fn quickstart_trial_identity(
    config_path: &std::path::Path,
    home: &std::path::Path,
) -> anyhow::Result<TrialIdentity> {
    let quickstart = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["quickstart", "--no-wire"])
        .env("HIPPIUS_MEM_CONFIG", config_path)
        .env("HOME", home)
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()?;
    anyhow::ensure!(
        quickstart.status.success(),
        "quickstart failed: {}",
        String::from_utf8_lossy(&quickstart.stderr)
    );

    let written = std::fs::read_to_string(config_path)?;
    let parsed: toml::Value = toml::from_str(&written)?;
    let field = |name: &str| -> anyhow::Result<String> {
        Ok(parsed
            .get(name)
            .and_then(toml::Value::as_str)
            .with_context(|| format!("{name} missing from the written config"))?
            .to_owned())
    };
    Ok(TrialIdentity {
        team: field("team")?,
        team_key_hex: field("team_key_hex")?,
        author_seed_hex: field("author_seed_hex")?,
    })
}

/// Build a `MemoryStore` directly over `blob`, signing with `author_seed_hex`
/// and encrypting under `team_key_hex` — the same primitives
/// `TeamProfile::build_store` wires. Mirrors `upgrade_cli.rs::build_live_store`.
fn build_live_store(
    blob: Arc<dyn BlobStore>,
    team: &str,
    team_key_hex: &str,
    author_seed_hex: &str,
) -> anyhow::Result<MemoryStore> {
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let oplog = OpLogStore::new(blob.clone());
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
        &hex32(author_seed_hex)?,
        NetworkPrefix::HIPPIUS,
    )?);
    let team_key = SecretKey::from_bytes(hex32(team_key_hex)?);

    Ok(MemoryStore::new(
        blob,
        index,
        oplog,
        Arc::new(NoopAnchor),
        signer,
        std::collections::BTreeMap::from([(0_u64, team_key)]),
        0,
        team.to_owned(),
        16,
    ))
}

fn remember_input(summary: &str) -> RememberInput {
    RememberInput {
        force: true,
        note_type: NoteType::Convention,
        repo: RepoScope::Global,
        tags: BTreeSet::new(),
        summary: summary.to_owned(),
        body: format!("body of {summary}"),
    }
}

fn recall_for(text: &str) -> RecallInput {
    RecallInput {
        text: text.to_owned(),
        repo: RepoScope::Global,
        k: 10,
        token_budget: None,
    }
}

/// Seed a local trial vault with a known, hand-countable activity/reuse
/// pattern: 4 remembers (`added == 4`), 1 edit, 1 link, 1 forget, and two
/// notes each reinforced (via recall+get) by this machine's own author —
/// `reuse.len() == 2`, each `distinct_reinforcers == 1`, `reuse_total == 2`
/// (no cap truncation: the renderer's own unit tests cover the "top 20 of N"
/// cap note).
async fn seed_known_activity(store: &MemoryStore) -> anyhow::Result<(NoteId, NoteId)> {
    let reused_a = store
        .remember(remember_input("postmortem template teammates keep reusing"))
        .await?;
    let reused_b = store
        .remember(remember_input("release checklist for the gateway service"))
        .await?;
    let edited = store
        .remember(remember_input("a note that will be edited and linked"))
        .await?;
    let forgotten = store
        .remember(remember_input("a note that will be forgotten"))
        .await?;

    store
        .edit(edited, remember_input("revised: edited and linked"))
        .await?;
    store.link(edited, reused_a).await?;
    store.forget(forgotten).await?;

    store.recall(recall_for("postmortem"))?;
    store.get(reused_a).await?;
    store.recall(recall_for("checklist"))?;
    store.get(reused_b).await?;

    Ok((reused_a, reused_b))
}

/// Run `hippius-mem report <extra>` against the given config/home.
fn run_report(
    config_path: &std::path::Path,
    home: &std::path::Path,
    extra: &[&str],
) -> anyhow::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .arg("report")
        .args(extra)
        .env("HIPPIUS_MEM_CONFIG", config_path)
        .env("HOME", home)
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .map_err(anyhow::Error::from)
}

/// `hippius-mem brief`, the command the session-start hook runs, prints the
/// vault's team-wide rules. It lives in this file because it needs the same
/// seeded trial vault. Run outside any git repository, so the scope is
/// team-wide notes, which is what every seeded note is.
///
/// Catches the command printing nothing: every failure path in `brief` exits 0
/// with empty output by design, so only a check of the output can tell a
/// working brief from a broken one.
#[tokio::test]
async fn brief_prints_the_vaults_team_wide_rules() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");
    let identity = quickstart_trial_identity(&config_path, dir.path())?;
    let vault_root = dir
        .path()
        .join(".local/share/hippius-mem/local")
        .join(&identity.team);
    let blob: Arc<dyn BlobStore> = Arc::new(FsBlobStore::new(vault_root));
    let store = build_live_store(
        blob,
        &identity.team,
        &identity.team_key_hex,
        &identity.author_seed_hex,
    )?;
    seed_known_activity(&store).await?;

    let output = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .arg("brief")
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", dir.path())
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .current_dir(dir.path())
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("## Conventions & decisions"), "{stdout}");
    assert!(
        stdout.contains("- [convention] (global) release checklist for the gateway service"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("a note that will be forgotten"),
        "a tombstoned note was briefed: {stdout}"
    );
    Ok(())
}

/// `brief`, run inside a repository, covers that repository's notes and not
/// another's. The bug this catches: the command ignoring the launch repo, which
/// briefs team-wide notes only (or, before scoping, every repository's).
#[tokio::test]
async fn brief_covers_the_launch_repository_and_no_other() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");
    let identity = quickstart_trial_identity(&config_path, dir.path())?;
    let vault_root = dir
        .path()
        .join(".local/share/hippius-mem/local")
        .join(&identity.team);
    let blob: Arc<dyn BlobStore> = Arc::new(FsBlobStore::new(vault_root));
    let store = build_live_store(
        blob,
        &identity.team,
        &identity.team_key_hex,
        &identity.author_seed_hex,
    )?;
    for (repo, summary) in [
        ("widget", "widget releases go out on Tuesdays"),
        ("gadget", "gadget migrations need a dry run"),
    ] {
        let input = RememberInput {
            repo: RepoScope::Repo(repo.to_owned()),
            ..remember_input(summary)
        };
        store.remember(input).await?;
    }

    let checkout = dir.path().join("widget");
    std::fs::create_dir(&checkout)?;
    for args in [
        &["init", "-q"][..],
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widget.git",
        ][..],
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(&checkout)
            .args(args)
            .status()?;
        assert!(status.success(), "git {args:?} failed");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .arg("brief")
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", dir.path())
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .current_dir(&checkout)
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("(widget) widget releases go out on Tuesdays"),
        "{stdout}"
    );
    assert!(!stdout.contains("gadget"), "{stdout}");
    Ok(())
}

/// `garden` on a real vault: a superseded note that is still live is listed
/// with its replacement, two near-identical summaries are a pair, and the
/// scope table counts them. Catches the command surveying something other
/// than the converged index (a forgotten note must not appear).
#[tokio::test]
async fn garden_lists_a_replaced_note_and_a_duplicate_pair() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");
    let identity = quickstart_trial_identity(&config_path, dir.path())?;
    let vault_root = dir
        .path()
        .join(".local/share/hippius-mem/local")
        .join(&identity.team);
    let blob: Arc<dyn BlobStore> = Arc::new(FsBlobStore::new(vault_root));
    let store = build_live_store(
        blob,
        &identity.team,
        &identity.team_key_hex,
        &identity.author_seed_hex,
    )?;
    let old = store
        .remember(remember_input("gateway retries are capped at three"))
        .await?;
    let new = store
        .remember(remember_input(
            "gateway retry cap moved to five in the March release",
        ))
        .await?;
    store
        .relate(new, old, hippius_mem_core::LinkRel::Supersedes)
        .await?;
    store
        .remember(remember_input(
            "uploader chunk size is eight megabytes per part",
        ))
        .await?;
    store
        .remember(remember_input(
            "uploader chunk size is eight megabytes per part now",
        ))
        .await?;
    let forgotten = store
        .remember(remember_input("a note that will be forgotten"))
        .await?;
    store.forget(forgotten).await?;

    let output = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .arg("garden")
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HOME", dir.path())
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .current_dir(dir.path())
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("4 live notes."), "{stdout}");
    assert!(stdout.contains("- global: 4"), "{stdout}");
    assert!(stdout.contains("## Replaced and still live: 1"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "- `{old}` (global) gateway retries are capped at three, replaced by `{new}`"
        )),
        "{stdout}"
    );
    assert!(stdout.contains("## Likely duplicates: 1"), "{stdout}");
    assert!(!stdout.contains("will be forgotten"), "{stdout}");

    let run = |flag: &str| {
        Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
            .args(["garden", flag])
            .env("HIPPIUS_MEM_CONFIG", &config_path)
            .env("HOME", dir.path())
            .env_remove("HERMES_HOME")
            .env_remove("HIPPIUS_MEM_MNEMONIC")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_DATA_HOME")
            .current_dir(dir.path())
            .output()
    };
    let json: serde_json::Value = serde_json::from_slice(&run("--json")?.stdout)?;
    assert_eq!(json["notes"], 4);
    assert_eq!(json["replaced"][0]["by"], new.to_string());
    assert!(
        !run("--jsn")?.status.success(),
        "an unknown flag must be refused"
    );
    Ok(())
}

#[tokio::test]
async fn report_renders_markdown_leading_with_reuse() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");

    let identity = quickstart_trial_identity(&config_path, dir.path())?;
    // The XDG *data* base (finding #4), not *cache* — matches
    // `quickstart_trial_identity`'s isolated HOME with XDG_DATA_HOME removed.
    let vault_root = dir
        .path()
        .join(".local/share/hippius-mem/local")
        .join(&identity.team);
    let blob: Arc<dyn BlobStore> = Arc::new(FsBlobStore::new(vault_root));
    let store = build_live_store(
        blob,
        &identity.team,
        &identity.team_key_hex,
        &identity.author_seed_hex,
    )?;
    seed_known_activity(&store).await?;

    let output = run_report(&config_path, dir.path(), &[])?;
    assert!(
        output.status.success(),
        "report failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    let reuse_at = stdout.find("Reused");
    let activity_at = stdout.find("Activity");
    let machine_at = stdout.find("This machine");
    assert!(
        reuse_at.is_some(),
        "stdout must have a reuse section header: {stdout}"
    );
    assert!(
        activity_at.is_some(),
        "stdout must have an activity section header: {stdout}"
    );
    assert!(
        machine_at.is_some(),
        "stdout must have a This machine section: {stdout}"
    );
    assert!(
        reuse_at < activity_at,
        "reuse must lead, before activity: {stdout}"
    );
    assert!(
        activity_at < machine_at,
        "activity must come before the This machine section: {stdout}"
    );

    assert!(
        stdout.contains("saved"),
        "reuse entries must use the 'saved' phrasing: {stdout}"
    );
    assert!(
        stdout.contains("this machine only"),
        "the local section must carry the literal 'this machine only' label: {stdout}"
    );

    // Hand-countable numbers from `seed_known_activity`.
    assert!(
        stdout.contains("| Added | 4 |"),
        "4 remembers were seeded: {stdout}"
    );
    assert!(
        stdout.contains("| Edited | 1 |"),
        "1 edit was seeded: {stdout}"
    );
    assert!(
        stdout.contains("| Linked | 1 |"),
        "1 link was seeded: {stdout}"
    );
    assert!(
        stdout.contains("| Tombstoned | 1 |"),
        "1 forget was seeded: {stdout}"
    );
    assert!(
        stdout.contains("saved 1 teammate"),
        "both reinforced notes were saved by exactly 1 distinct teammate: {stdout}"
    );

    // Only 2 notes were reinforced — reuse_total (2) equals reuse.len() (2),
    // so no cap truncation note should appear.
    assert!(
        !stdout.contains("top 20"),
        "no cap note is expected when nothing was truncated: {stdout}"
    );

    Ok(())
}

/// Regression test for the finding-#6 fix-batch ripple: `resolve_and_build_store`
/// (`hippius-mem/src/main.rs`) grew a vault-lock acquisition for `serve`, and the
/// mechanical ripple into `report`/`brief`/`gc`/`import` made those one-shot
/// commands bind (and thereby hold) that SAME exclusive lock — so running
/// `report` while a Claude Code session (`hippius-mem serve`) was bound to the
/// same local trial vault started failing with "already holds", even though
/// nothing before that fix batch prevented it. `report` is a transient read
/// against a concurrent multi-writer op-log (ops are distinct, lamport-ordered
/// objects), so it must succeed regardless of a live serve session — only
/// `serve` (and a migrating `upgrade`) should hold the vault locks.
///
/// Simulates a live writer `serve` by acquiring the vault's advisory locks
/// directly (the same non-blocking `flock`s `TeamProfile::try_lock_vault_writer`
/// / `try_lock_vault_liveness_shared` take: exclusive on `{vault_root}/.lock`,
/// shared on `{vault_root}/.live.lock`) in THIS test process, then running the
/// real `report` subcommand as a separate child process against the same vault.
#[tokio::test]
async fn report_succeeds_while_the_vault_lock_is_held_by_another_process() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");

    let identity = quickstart_trial_identity(&config_path, dir.path())?;
    let vault_root = dir
        .path()
        .join(".local/share/hippius-mem/local")
        .join(&identity.team);

    // Simulate a live writer `serve` process already bound to this vault:
    // hold the SAME advisory lock files a serve session holds — the write
    // role exclusively, the liveness lock shared — in `lock_file` /
    // `liveness_file` until the explicit `drop`s below (after `report` has
    // already run against the still-held locks).
    let lock_path = vault_root.join(".lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)?;
    lock_file.try_lock()?;
    let liveness_path = vault_root.join(".live.lock");
    let liveness_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&liveness_path)?;
    liveness_file.try_lock_shared()?;

    let output = run_report(&config_path, dir.path(), &[])?;
    assert!(
        output.status.success(),
        "report must succeed against a local vault even while another process \
         holds its advisory locks (a live serve session must not block a \
         transient one-shot read): {}",
        String::from_utf8_lossy(&output.stderr)
    );

    drop(lock_file);
    drop(liveness_file);
    Ok(())
}

#[test]
fn report_supports_since() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("hippius-mem.toml");
    quickstart_trial_identity(&config_path, dir.path())?;

    // A well-formed `--since` parses and the report still runs to completion,
    // with the window header naming the parsed span.
    let ok = run_report(&config_path, dir.path(), &["--since", "30d"])?;
    assert!(
        ok.status.success(),
        "report --since 30d failed: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let stdout = String::from_utf8_lossy(&ok.stdout);
    assert!(
        stdout.contains("30 days"),
        "the parsed --since span must be named in the window header: {stdout}"
    );

    // A bogus value fails fast (before any config/store is even touched) and
    // names the accepted forms.
    let bad_dir = tempfile::tempdir()?;
    let bad_config = bad_dir.path().join("hippius-mem.toml");
    let bogus = Command::new(env!("CARGO_BIN_EXE_hippius-mem"))
        .args(["report", "--since", "bogus"])
        .env("HIPPIUS_MEM_CONFIG", &bad_config)
        .env("HOME", bad_dir.path())
        .env_remove("HERMES_HOME")
        .env_remove("HIPPIUS_MEM_MNEMONIC")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()?;
    assert!(
        !bogus.status.success(),
        "a bogus --since value must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&bogus.stderr);
    assert!(
        stderr.contains("bogus"),
        "the refusal must echo the bad value: {stderr}"
    );
    assert!(
        stderr.contains("7d") && stderr.contains("Nd") && stderr.contains("Nw"),
        "the refusal must name the accepted forms (7d default, Nd, Nw): {stderr}"
    );

    Ok(())
}
