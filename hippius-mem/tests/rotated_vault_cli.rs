//! Commands run as the binary on a machine whose team rotated past the epoch
//! it holds a key for, over a local trial vault whose rotation the test writes
//! through the core API (`join` and `rotate` need a team bucket).
//!
//! Isolated `HOME`, config and state directory, and every ambient
//! `HIPPIUS_MEM_*` stripped (the mnemonic included), so this machine holds
//! only the configured epoch-0 key.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes"
)]

mod support;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Output;

use hippius_mem_core::{
    FsBlobStore, MemberKey, NetworkPrefix, SecretKey, Sr25519Signer, TeamManifest, derive_identity,
    provision_team_key, publish_manifest, signer_from_mnemonic,
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
