//! Commands run as the binary on a machine whose team rotated past the epoch
//! it holds a key for, over a local trial vault whose rotation the test writes
//! through the core API (`join` and `rotate` need a team bucket), as is the
//! write that the core refuses on a mismatched key check.
//!
//! Isolated `HOME`, config and state directory, and every ambient
//! `HIPPIUS_MEM_*` stripped (the mnemonic included), so this machine holds
//! only the configured epoch-0 key unless a test sets the mnemonic.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes"
)]

mod support;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use anyhow::Context as _;
use hippius_mem_core::{
    BlobStore, FsBlobStore, HashEmbedder, InMemoryIndex, MemError, MemberKey, MemoryStore,
    NetworkPrefix, NoopAnchor, NoteType, OpLogStore, RememberInput, RepoScope, SecretKey, Signer,
    Sr25519Signer, TeamManifest, derive_identity, key_check_key, provision_team_key,
    publish_manifest, signer_from_mnemonic,
};

const PHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

/// Publish a manifest and a founder-signed wrap of a new key at epoch 1 to a
/// member that is not this machine, in the local vault under `home`.
fn rotate_vault_to_epoch_1(home: &Path) -> anyhow::Result<()> {
    let blob = FsBlobStore::new(home.join("vault"));
    let founder = Sr25519Signer::from_seed_with_prefix(&[5_u8; 32], NetworkPrefix::HIPPIUS)?;
    let identity = derive_identity(PHRASE, NetworkPrefix::HIPPIUS)?;
    let member = MemberKey::create_signed(
        &signer_from_mnemonic(PHRASE, NetworkPrefix::HIPPIUS)?,
        &identity,
    );
    let manifest = TeamManifest::create_signed(
        &founder,
        "trial".to_owned(),
        BTreeSet::from([member.ss58.clone()]),
        0,
    );
    tokio::runtime::Runtime::new()?.block_on(async {
        publish_manifest(&blob, &manifest).await?;
        let new_key = SecretKey::from_bytes([9_u8; 32]);
        provision_team_key(&blob, "trial", &new_key, 1, &[member], None, &founder).await?;
        anyhow::Ok(())
    })
}

/// Run the binary with `args` over the local vault under `home`.
fn hippius_mem(home: &Path, args: &[&str]) -> anyhow::Result<Output> {
    Ok(command(home, args)?.output()?)
}

/// The binary with `args`, configured for the local vault under `home`.
fn command(home: &Path, args: &[&str]) -> anyhow::Result<Command> {
    let config_path = home.join("hippius-mem.toml");
    std::fs::write(
        &config_path,
        format!(
            "team = \"trial\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n\
             storage = \"local\"\nlocal_root = \"{root}\"\nsemantic_embeddings = false\n",
            key = "ab".repeat(32),
            seed = "cd".repeat(32),
            root = home.join("vault").display(),
        ),
    )?;
    let mut command = support::binary();
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("HIPPIUS_MEM_CONFIG", &config_path)
        .env("HIPPIUS_MEM_STATE_DIR", home.join("state"))
        .env("HIPPIUS_MEM_CACHE_DIR", "off")
        .env("RUST_LOG", "info")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME");
    Ok(command)
}

/// `brief` warns that the team rotated past the epoch this process holds, so
/// a member sees why newer notes are missing and writes are refused.
#[test]
fn brief_warns_that_the_team_rotated_past_this_machine() -> anyhow::Result<()> {
    let home = tempfile::tempdir()?;
    rotate_vault_to_epoch_1(home.path())?;

    let brief = hippius_mem(home.path(), &["brief"])?;

    let err = String::from_utf8_lossy(&brief.stderr);
    assert!(
        err.contains("team trial rotated its key to epoch 1"),
        "{err}"
    );
    Ok(())
}

/// `doctor` fails on a team rotated past epoch 0 when this machine cannot
/// load the newest epoch's key (here: no mnemonic is set).
#[test]
fn doctor_fails_when_the_team_rotated_past_this_machine() -> anyhow::Result<()> {
    let home = tempfile::tempdir()?;
    rotate_vault_to_epoch_1(home.path())?;

    let doctor = hippius_mem(home.path(), &["doctor"])?;

    let err = String::from_utf8_lossy(&doctor.stderr);
    assert!(!doctor.status.success(), "{err}");
    assert!(
        err.contains("rotated to epoch 1") && err.contains("HIPPIUS_MEM_MNEMONIC"),
        "{err}"
    );
    Ok(())
}

/// The author seed `command` configures, so the wrap below is addressed to
/// this machine.
const MACHINE_SEED: [u8; 32] = [0xcd; 32];

/// The epoch-1 key the founder wraps for this machine.
const EPOCH_1_KEY: [u8; 32] = [9; 32];

/// Rotate the vault under `home` to epoch 1 with a wrap addressed to this
/// machine (author `MACHINE_SEED`, opened with `PHRASE`).
fn rotate_vault_to_epoch_1_for_this_machine(home: &Path) -> anyhow::Result<()> {
    let blob = FsBlobStore::new(home.join("vault"));
    let founder = Sr25519Signer::from_seed_with_prefix(&[5_u8; 32], NetworkPrefix::HIPPIUS)?;
    let machine = Sr25519Signer::from_seed_with_prefix(&MACHINE_SEED, NetworkPrefix::HIPPIUS)?;
    let member =
        MemberKey::create_signed(&machine, &derive_identity(PHRASE, NetworkPrefix::HIPPIUS)?);
    let manifest = TeamManifest::create_signed(
        &founder,
        "trial".to_owned(),
        BTreeSet::from([member.ss58.clone()]),
        0,
    );
    tokio::runtime::Runtime::new()?.block_on(async {
        publish_manifest(&blob, &manifest).await?;
        let new_key = SecretKey::from_bytes(EPOCH_1_KEY);
        provision_team_key(&blob, "trial", &new_key, 1, &[member], None, &founder).await?;
        anyhow::Ok(())
    })
}

/// A remember through a store holding the epoch-1 key this machine opens.
fn remember_at_epoch_1(home: &Path) -> anyhow::Result<Result<(), MemError>> {
    let blob: Arc<dyn BlobStore> = Arc::new(FsBlobStore::new(home.join("vault")));
    let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
        &MACHINE_SEED,
        NetworkPrefix::HIPPIUS,
    )?);
    let store = MemoryStore::new(
        Arc::clone(&blob),
        Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
        OpLogStore::new(blob),
        Arc::new(NoopAnchor),
        signer,
        std::collections::BTreeMap::from([(1_u64, SecretKey::from_bytes(EPOCH_1_KEY))]),
        1,
        "trial".to_owned(),
        16,
    );
    let input = RememberInput {
        force: false,
        note_type: NoteType::Gotcha,
        repo: RepoScope::Global,
        tags: BTreeSet::new(),
        summary: "heron-cache keeps stale leases".to_owned(),
        body: "renew before the epoch ends".to_owned(),
    };
    Ok(tokio::runtime::Runtime::new()?.block_on(async { store.remember(input).await.map(drop) }))
}

/// `doctor` fails when the key this machine opens for the rotated epoch is not
/// the one the team's key check for that epoch names, as the write path does,
/// and points at a new wrap or a rotation rather than this machine's config.
/// With no check at that epoch, the same machine passes.
#[test]
fn doctor_fails_when_the_rotated_epochs_key_check_differs() -> anyhow::Result<()> {
    let home = tempfile::tempdir()?;
    rotate_vault_to_epoch_1_for_this_machine(home.path())?;
    let doctor = || -> anyhow::Result<Output> {
        Ok(command(home.path(), &["doctor"])?
            .env("HIPPIUS_MEM_MNEMONIC", PHRASE)
            .output()?)
    };

    let clean = doctor()?;
    let err = String::from_utf8_lossy(&clean.stderr);
    assert!(clean.status.success(), "{err}");

    // Another key's check at epoch 1.
    let check = key_check_key("trial", 1);
    let planted = format!(
        "{{\"version\":1,\"team\":\"trial\",\"epoch\":1,\"check\":\"{}\"}}",
        "00".repeat(32)
    );
    let path = home.path().join("vault").join(&check);
    std::fs::create_dir_all(path.parent().context("check key has a parent")?)?;
    std::fs::write(&path, planted)?;

    let write = remember_at_epoch_1(home.path())?;
    assert!(
        matches!(write, Err(MemError::TeamKeyMismatch { epoch: 1, .. })),
        "{write:?}"
    );

    let mismatch = doctor()?;
    let err = String::from_utf8_lossy(&mismatch.stderr);
    assert!(!mismatch.status.success(), "{err}");
    assert!(
        err.contains("epoch 1") && err.contains(&check) && err.contains("hippius-mem rotate"),
        "{err}"
    );
    assert!(!err.contains("team_key_hex"), "{err}");
    Ok(())
}
