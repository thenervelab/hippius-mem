//! Team-admin subcommands: thin wrappers over the core library's membership and
//! epoch-key flows, so the documented "team management" is operable from the
//! binary rather than library-only.
//!
//! Each subcommand builds the same S3-backed [`MemoryStore`] the server uses
//! (from `hippius-mem.toml` / `HIPPIUS_MEM_*`), then calls one core method.
//! Secrets never reach stdout/stderr: only non-secret coordinates are logged.

use std::collections::BTreeSet;

use anyhow::{Context, bail};
use hippius_mem_core::{Identity, MemError, MemoryStore, NetworkPrefix, Ss58, derive_identity};

use crate::config::Config;

/// SS58 network prefix for Hippius / generic Substrate identities (Bittensor),
/// matching [`crate::config`]'s author derivation so a bootstrapped identity's
/// address lines up with the member the team-key wraps are addressed to.
/// `pub(crate)` so `join --bundle` derives the same address shape.
pub(crate) const HIPPIUS_SS58_PREFIX: NetworkPrefix = NetworkPrefix::HIPPIUS;

/// Run `publish-membership --members <ss58,ss58,...>`.
///
/// Publishes a founder-signed membership manifest for the configured team. Once
/// published, every member's `sync` converges only listed members' ops — this is
/// the command that activates membership enforcement end to end.
///
/// # Errors
///
/// Returns an error if `--members` is missing or holds no valid SS58 address,
/// the configuration cannot be loaded/validated, or
/// [`MemoryStore::publish_membership`] fails (e.g. this signer is not the team
/// founder).
pub(crate) async fn publish_membership(args: &[String]) -> anyhow::Result<()> {
    let members = parse_publish_membership_args(args)?;
    let count = members.len();
    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    let store = cfg.build_store().await?;
    store.publish_membership(members).await?;
    tracing::info!(
        members = count,
        team = %cfg.team,
        "published team membership manifest"
    );
    Ok(())
}

/// Run `provision`: as the founder, wrap the current-epoch team key to every
/// published member key the founder-signed manifest authorizes.
///
/// This is the read-side complement of `publish-membership`: membership gates who
/// may WRITE (converge ops); provisioning gates who may READ (decrypt notes).
/// Run it after `publish-membership` and after members have `join`ed. The founder
/// pin from config is threaded through so a bucket writer's planted key is not
/// wrapped the team key.
///
/// # Errors
///
/// Returns an error if the configuration cannot be loaded, or
/// [`MemoryStore::provision_members`] fails (e.g. this store's key-ring lacks the
/// current epoch's key because it is not the founder).
pub(crate) async fn provision(args: &[String]) -> anyhow::Result<()> {
    reject_args("provision", args)?;
    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    let store = cfg.build_store().await?;
    let considered = store.provision_members().await?;
    tracing::info!(
        member_keys = considered,
        team = %cfg.team,
        "provisioned the team key to authorized published member keys"
    );
    Ok(())
}

/// Run `join`: as a member, publish this identity's signed member key so the
/// founder's `provision` can wrap the team key to it, then load any epoch keys
/// already provisioned to this member.
///
/// With `--bundle <path|->` the command instead consumes a founder-emitted
/// invite bundle first — writing this machine's config from it — and only
/// then performs the same publish, gated on a mnemonic being present (see
/// [`crate::join_bundle`]). The bare form below is unchanged and still
/// requires `HIPPIUS_MEM_MNEMONIC` (the member's own identity, whose x25519
/// key the founder wraps to). A join is the prerequisite for being
/// provisioned.
///
/// # Errors
///
/// Returns an error if the arguments are malformed, the bundle flow fails
/// (see [`crate::join_bundle::run`]), or — on the bare form —
/// `HIPPIUS_MEM_MNEMONIC` is unset or does not derive an identity, the
/// configuration cannot be loaded, or [`MemoryStore::join_as_member`] fails.
pub(crate) async fn join(args: &[String]) -> anyhow::Result<()> {
    if let Some(opts) = crate::join_bundle::Options::parse(args)? {
        return crate::join_bundle::run(opts).await;
    }
    let mnemonic = std::env::var("HIPPIUS_MEM_MNEMONIC")
        .context("`join` requires HIPPIUS_MEM_MNEMONIC (the joining member's identity)")?;
    let identity = derive_identity(&mnemonic, HIPPIUS_SS58_PREFIX)
        .context("deriving the member identity from HIPPIUS_MEM_MNEMONIC failed")?;
    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    let store = cfg.build_store().await?;
    store.join_as_member(&identity).await?;
    // Pick up any epoch keys the founder already provisioned to this member.
    bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    tracing::info!(
        team = %cfg.team,
        member = %identity.ss58.as_str(),
        "published member key; the founder can now `provision` the team key to it"
    );
    Ok(())
}

/// Run `rotate [--members <ss58,...>]`: as the founder, rotate the team key to
/// a fresh epoch wrapped to the remaining members only, and advance the write
/// epoch — then tell the operator exactly what every member must change.
///
/// With `--members`, the shrunk membership manifest is published FIRST, so the
/// rotation's wrap gate already excludes the removed members. Without it, the
/// rotation runs against the manifest as published (mirroring `provision`'s
/// authorization exactly, including the open-team fallback when no manifest and
/// no founder pin exist).
///
/// The mnemonic-gated epoch bootstrap runs BEFORE the rotation for two reasons:
/// the new epoch must clear every epoch this founder can see (a stale local
/// ring must not re-mint an existing epoch), and this entry point reads/writes
/// full team memory, so skipping the bootstrap would silently pin it to the
/// founding epoch (the recorded `bootstrap_epochs` gotcha).
///
/// Scope: like `provision` and `join`, this operates on the PRIMARY (flat,
/// top-level) profile only — `[[teams]]` profiles are not routed here, so
/// rotate a secondary team from a config whose primary IS that team.
///
/// Open-team caveat: on a team with no `founder_ss58` pin and no published
/// manifest, whoever runs `rotate --members` first publishes the genesis
/// manifest and thereby CLAIMS founderhood — the pre-existing trust-on-genesis
/// model, not something rotation adds. Pinning `founder_ss58` on every
/// member's config is the mitigation.
///
/// # Errors
///
/// Returns an error if the arguments are malformed, the configuration cannot be
/// loaded, publishing the manifest fails (e.g. this signer is not the founder),
/// or [`MemoryStore::rotate_key`] refuses (not the founder, no trusted manifest
/// under a pin, or nothing to rotate — see the typed `MemError` variants).
pub(crate) async fn rotate(args: &[String]) -> anyhow::Result<()> {
    use std::io::Write;

    let members = parse_rotate_args(args)?;
    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    let store = cfg.build_store().await?;
    if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
        bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    } else {
        tracing::warn!(
            "HIPPIUS_MEM_MNEMONIC is unset: rotating with only the configured key-ring; \
             the new epoch is floored by max_epoch, not by the epochs in the bucket"
        );
    }
    let published_members = members.is_some();
    if let Some(members) = members {
        let count = members.len();
        store.publish_membership(members).await?;
        tracing::info!(
            members = count,
            team = %cfg.team,
            "published team membership manifest before rotating"
        );
    }
    let outcome = store.rotate_key(cfg.max_epoch).await.map_err(|err| {
        // `--members` then NothingToRotate leaves a half-applied command: the
        // shrunk manifest IS published (removed members' ops already filtered)
        // while the key is NOT rotated. Name that state and the way out, so
        // the operator does not read the refusal as "nothing happened".
        if published_members && matches!(err, MemError::NothingToRotate { .. }) {
            anyhow::Error::new(err).context(
                "the shrunk membership WAS already published (removed members' ops are \
                 filtered), but the key is NOT yet rotated — have the remaining members \
                 `join`, then re-run `rotate` (without --members) to finish",
            )
        } else {
            anyhow::Error::new(err)
        }
    })?;

    // Operator-facing output goes to the stdout handle directly (the workspace
    // denies the `print!` family); write failures are ignored like `members`'.
    // The ACTION REQUIRED block is the point of the command: a rotation nobody's
    // config follows silently hides every post-rotation note from the team.
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "rotated team `{}` to epoch {}",
        cfg.team, outcome.new_epoch
    );
    let _ = writeln!(
        out,
        "wrapped the new epoch key to {} member(s):",
        outcome.wrapped.len()
    );
    for member in &outcome.wrapped {
        let _ = writeln!(out, "  {}", member.as_str());
    }
    let _ = writeln!(
        out,
        "\n==================== ACTION REQUIRED ====================\n\
         Every member must now update their machine:\n\
         \n\
           1. Set max_epoch = {epoch} in hippius-mem.toml\n\
              (or export HIPPIUS_MEM_MAX_EPOCH={epoch}).\n\
           2. Restart the MCP server — and any running `dashboard`, which\n\
              caches stores per vault — so each bootstraps the new epoch key.\n\
         \n\
         A stale max_epoch fails SILENTLY: startup only bootstraps epochs\n\
         0..=max_epoch, so notes sealed under epoch {epoch} simply never\n\
         appear on that machine — no error is raised.\n\
         ==========================================================",
        epoch = outcome.new_epoch
    );
    Ok(())
}

/// Run `members`: print the founder-signed membership of the configured team to
/// stdout, one SS58 address per line (or a note that the team is open).
///
/// # Errors
///
/// Returns an error if the configuration cannot be loaded or
/// [`MemoryStore::members`] fails.
pub(crate) async fn members(args: &[String]) -> anyhow::Result<()> {
    use std::io::Write;

    reject_args("members", args)?;
    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    let store = cfg.build_store().await?;
    let members = store.members().await?;
    // Write to the stdout handle directly: this is operator-facing output, but the
    // workspace denies the `print!` family; `writeln!` on the handle is allowed.
    let mut out = std::io::stdout();
    if members.is_empty() {
        let _ = writeln!(out, "(no membership manifest published — the team is open)");
    } else {
        for member in &members {
            let _ = writeln!(out, "{}", member.as_str());
        }
    }
    Ok(())
}

/// Best-effort: load every team-key epoch this member can unwrap into the store's
/// key-ring, so a member provisioned after a rotation can read newer-epoch notes —
/// and advance the write epoch to the newest key the ring then holds.
///
/// The advancement is what makes a rotation effective end to end: the core
/// bootstrap deliberately only READS keys (its documented contract), and a store
/// is always built at the founding epoch, so without this step every entry point
/// would keep sealing new notes under epoch 0 — a key a removed member still
/// holds. The ring's max is by construction an epoch this member can decrypt, so
/// sealing under it is always safe for the writer; teammates see those notes once
/// their own `max_epoch` catches up (the loud instruction `rotate` prints).
///
/// Non-fatal by contract: a fresh bucket, an un-provisioned epoch, or a derivation
/// failure is logged and skipped — the server still serves with its configured
/// key-ring. Called at startup only when `HIPPIUS_MEM_MNEMONIC` is set (the team
/// identity whose x25519 secret unwraps the [`WrappedKey`](hippius_mem_core::WrappedKey)s).
pub(crate) async fn bootstrap_epochs(store: &MemoryStore, mnemonic: &str, max_epoch: u64) {
    let identity: Identity = match derive_identity(mnemonic, HIPPIUS_SS58_PREFIX) {
        Ok(identity) => identity,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "could not derive identity from HIPPIUS_MEM_MNEMONIC; skipping epoch-key bootstrap"
            );
            return;
        }
    };
    // Inclusive 0..=max_epoch: there is no on-bucket epoch discovery, so the
    // operator names the highest rotated epoch via `max_epoch` and we try each.
    let epochs: Vec<u64> = (0..=max_epoch).collect();
    match store.bootstrap_epoch_keys(&identity, &epochs).await {
        Ok(added) => {
            // Seal future writes under the newest epoch this member holds. Only
            // ever advances (never rolls back): a member who could not unwrap
            // the newest epoch keeps writing under their newest readable one.
            if let Some(top) = store.highest_epoch()
                && top > store.current_epoch()
            {
                store.set_current_epoch(top);
                tracing::info!(
                    epoch = top,
                    "advanced the write epoch to the newest ring key"
                );
            }
            tracing::info!(
                added,
                max_epoch,
                "bootstrapped accessible epoch keys from the bucket"
            );
        }
        Err(err) => tracing::warn!(
            error = %err,
            "epoch-key bootstrap failed; serving with the configured key-ring"
        ),
    }
}

/// Refuse stray arguments on a no-argument subcommand.
///
/// A typo or a flag meant for another command (`provision --members ...`,
/// `members --help`) must fail loudly BEFORE the real store/S3 operation runs,
/// not be silently discarded — the same loud-failure rule
/// [`parse_publish_membership_args`] and the dashboard's `parse_args` follow.
fn reject_args(subcommand: &str, args: &[String]) -> anyhow::Result<()> {
    if let Some(first) = args.first() {
        bail!("`{subcommand}` takes no arguments (got `{first}`)");
    }
    Ok(())
}

/// Parse `publish-membership`'s arguments into the validated member set.
fn parse_publish_membership_args(args: &[String]) -> anyhow::Result<BTreeSet<Ss58>> {
    let mut members_csv = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--members" => members_csv = Some(next_value(&mut iter, "--members")?),
            other => bail!(
                "unknown publish-membership argument `{other}`; usage: \
                 publish-membership --members <ss58,ss58,...>"
            ),
        }
    }
    let csv = members_csv.context("publish-membership requires --members <ss58,ss58,...>")?;
    parse_members(&csv)
}

/// Parse `rotate`'s arguments: an OPTIONAL `--members` list.
///
/// `Some(set)` means "publish this membership first, then rotate"; `None` means
/// "rotate for the manifest as already published". The distinction is the whole
/// flag: an empty `--members` is rejected (it would publish a founder-only
/// manifest by accident), while omitting the flag entirely is the common case.
fn parse_rotate_args(args: &[String]) -> anyhow::Result<Option<BTreeSet<Ss58>>> {
    let mut members_csv = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--members" => members_csv = Some(next_value(&mut iter, "--members")?),
            other => bail!(
                "unknown rotate argument `{other}`; usage: rotate [--members <ss58,ss58,...>]"
            ),
        }
    }
    members_csv.map(|csv| parse_members(&csv)).transpose()
}

/// Parse a comma-separated list of SS58 addresses into a validated, deduplicated
/// member set (empty entries are skipped; at least one address is required).
fn parse_members(csv: &str) -> anyhow::Result<BTreeSet<Ss58>> {
    let mut members = BTreeSet::new();
    for raw in csv.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let member = Ss58::new(trimmed)
            .with_context(|| format!("invalid SS58 member address {trimmed:?}"))?;
        members.insert(member);
    }
    if members.is_empty() {
        bail!("--members needs at least one SS58 member address");
    }
    Ok(members)
}

/// Take the next argument as a flag value, or error naming the flag.
fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> anyhow::Result<String> {
    iter.next()
        .map(ToOwned::to_owned)
        .with_context(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use std::sync::Arc;

    use hippius_mem_core::{
        BlobStore, HashEmbedder, InMemoryIndex, MemberKey, MemoryBlobStore, MemoryStore,
        NoopAnchor, OpLogStore, SecretKey, Signer, derive_identity, provision_team_key,
        publish_member_key, signer_from_mnemonic,
    };

    use super::{
        HIPPIUS_SS58_PREFIX, bootstrap_epochs, parse_members, parse_publish_membership_args,
        parse_rotate_args, reject_args,
    };

    // Two real, structurally-valid SS58 addresses (the canonical //Alice and the
    // dev-phrase account) so `Ss58::new`'s length/base58 gate accepts them.
    const ALICE: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    const DEV: &str = "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV";

    #[test]
    fn parses_a_member_csv() -> anyhow::Result<()> {
        let members = parse_members(&format!("{ALICE},{DEV}"))?;
        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|m| m.as_str() == ALICE));
        assert!(members.iter().any(|m| m.as_str() == DEV));
        Ok(())
    }

    #[test]
    fn skips_blanks_and_dedups() -> anyhow::Result<()> {
        // Trailing comma, whitespace, and a duplicate all collapse away.
        let members = parse_members(&format!(" {ALICE} , {ALICE} ,"))?;
        assert_eq!(members.len(), 1, "duplicates and blanks are dropped");
        Ok(())
    }

    #[test]
    fn rejects_empty_member_list() {
        assert!(parse_members("").is_err(), "no members is an error");
        assert!(parse_members(" , ").is_err(), "only blanks is an error");
    }

    #[test]
    fn rejects_a_non_ss58_member() {
        assert!(
            parse_members("not-an-ss58-address").is_err(),
            "a malformed address must be rejected"
        );
    }

    #[test]
    fn dispatch_parses_members_flag() -> anyhow::Result<()> {
        let args = vec!["--members".to_owned(), format!("{ALICE},{DEV}")];
        let members = parse_publish_membership_args(&args)?;
        assert_eq!(members.len(), 2);
        Ok(())
    }

    #[test]
    fn dispatch_requires_members_flag() {
        assert!(
            parse_publish_membership_args(&[]).is_err(),
            "missing --members is an error"
        );
    }

    #[test]
    fn dispatch_rejects_unknown_flag() {
        let args = vec!["--bogus".to_owned(), "x".to_owned()];
        assert!(
            parse_publish_membership_args(&args).is_err(),
            "an unknown flag is rejected"
        );
    }

    #[test]
    fn rotate_args_default_to_the_published_manifest() -> anyhow::Result<()> {
        // No `--members` is the common case: rotate for the manifest as-is.
        assert!(parse_rotate_args(&[])?.is_none());
        Ok(())
    }

    #[test]
    fn rotate_args_parse_an_explicit_member_list() -> anyhow::Result<()> {
        let args = vec!["--members".to_owned(), format!("{ALICE},{DEV}")];
        let members = parse_rotate_args(&args)?
            .ok_or_else(|| anyhow::anyhow!("--members must yield a member set"))?;
        assert_eq!(members.len(), 2);
        Ok(())
    }

    #[test]
    fn rotate_args_reject_junk() {
        // A bare value for --members is required, an unknown flag refused, and
        // an empty list refused (it would silently shrink membership to just
        // the founder) — each BEFORE any store/S3 operation runs.
        assert!(parse_rotate_args(&["--members".to_owned()]).is_err());
        assert!(parse_rotate_args(&["--bogus".to_owned()]).is_err());
        assert!(parse_rotate_args(&["--members".to_owned(), " , ".to_owned()]).is_err());
    }

    // A standard BIP-39 English test vector (Trezor); its seed is public, so it
    // is safe to pin as an interoperability fixture.
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon about";
    /// Team namespace for the bootstrap tests below.
    const TEAM: &str = "rotation-test";

    /// One machine's store over `bucket`, holding ONLY the epoch-0 key — the
    /// exact shape `Config::build_store` produces before any bootstrap.
    fn epoch0_store(bucket: &Arc<MemoryBlobStore>) -> anyhow::Result<MemoryStore> {
        let blob: Arc<dyn BlobStore> = bucket.clone();
        let signer: Arc<dyn Signer> =
            Arc::new(signer_from_mnemonic(MNEMONIC, HIPPIUS_SS58_PREFIX)?);
        Ok(MemoryStore::new(
            blob.clone(),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(blob),
            Arc::new(NoopAnchor),
            signer,
            std::collections::BTreeMap::from([(0_u64, SecretKey::from_bytes([1u8; 32]))]),
            0,
            TEAM.to_owned(),
            16,
        ))
    }

    #[tokio::test]
    async fn bootstrap_advances_the_write_epoch_to_the_newest_unwrapped_key() -> anyhow::Result<()>
    {
        // A member provisioned through a rotation (epochs 0 and 1 wrapped to
        // them) must come out of the bootstrap WRITING under epoch 1, not just
        // reading it — otherwise post-rotation notes stay sealed under the old
        // key a removed member still holds.
        let bucket = Arc::new(MemoryBlobStore::default());
        let identity = derive_identity(MNEMONIC, HIPPIUS_SS58_PREFIX)?;
        let signer = signer_from_mnemonic(MNEMONIC, HIPPIUS_SS58_PREFIX)?;
        let member_key = MemberKey::create_signed(&signer, &identity);
        publish_member_key(bucket.as_ref(), TEAM, &member_key).await?;
        provision_team_key(
            bucket.as_ref(),
            TEAM,
            &SecretKey::from_bytes([1u8; 32]),
            0,
            std::slice::from_ref(&member_key),
            None,
        )
        .await?;
        provision_team_key(
            bucket.as_ref(),
            TEAM,
            &SecretKey::from_bytes([2u8; 32]),
            1,
            std::slice::from_ref(&member_key),
            None,
        )
        .await?;

        let store = epoch0_store(&bucket)?;
        bootstrap_epochs(&store, MNEMONIC, 1).await;
        assert_eq!(
            store.current_epoch(),
            1,
            "the write epoch follows the newest bootstrapped key"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_keeps_the_write_epoch_when_nothing_newer_unwraps() -> anyhow::Result<()> {
        // A fresh bucket (no wraps at all) must leave the configured founding
        // epoch alone — the advancement is strictly monotonic and evidence-based.
        let bucket = Arc::new(MemoryBlobStore::default());
        let store = epoch0_store(&bucket)?;
        bootstrap_epochs(&store, MNEMONIC, 3).await;
        assert_eq!(
            store.current_epoch(),
            0,
            "no unwrappable newer epoch means no advancement"
        );
        Ok(())
    }

    #[test]
    fn no_arg_subcommands_reject_stray_arguments() -> anyhow::Result<()> {
        // `provision --members X` (confused with publish-membership) or
        // `members --help` must fail loudly BEFORE the store/S3 operation runs.
        let stray = vec!["--members".to_owned(), "x".to_owned()];
        let Err(err) = reject_args("provision", &stray) else {
            anyhow::bail!("stray arguments must be rejected");
        };
        assert!(
            err.to_string().contains("provision") && err.to_string().contains("--members"),
            "the error names the subcommand and the stray argument: {err}"
        );
        assert!(reject_args("members", &[]).is_ok(), "no args is fine");
        Ok(())
    }
}
