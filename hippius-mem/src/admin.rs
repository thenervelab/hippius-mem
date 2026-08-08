//! Team-admin subcommands: thin wrappers over the core library's membership and
//! epoch-key flows, so the documented "team management" is operable from the
//! binary rather than library-only.
//!
//! Each subcommand builds the same S3-backed [`MemoryStore`] the server uses
//! (from `hippius-mem.toml` / `HIPPIUS_MEM_*`), then calls one core method.
//! Secrets never reach stdout/stderr: only non-secret coordinates are logged.

use std::collections::BTreeSet;
use std::io::IsTerminal as _;

use anyhow::{Context, bail, ensure};
use hippius_mem_core::{
    Identity, MemError, MemoryStore, NetworkPrefix, Signer, Sr25519Signer, Ss58, TeamManifest,
    derive_identity,
};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::join_bundle::generate_seed_hex;

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

/// Run `provision [--no-recovery]`: as the founder, wrap the current-epoch
/// team key to every published member key the founder-signed manifest
/// authorizes, then — by default — name a fresh recovery key on the team
/// manifest.
///
/// The team-key wrap is the read-side complement of `publish-membership`:
/// membership gates who may WRITE (converge ops); provisioning gates who may
/// READ (decrypt notes). Run it after `publish-membership` and after members
/// have `join`ed. The founder pin from config is threaded through so a bucket
/// writer's planted key is not wrapped the team key.
///
/// Naming a recovery key is `provision`'s default: it is the escape hatch
/// `recover` uses if the founder key is ever lost, and an operator should not
/// have to remember a separate step to get one. `--no-recovery` opts out of
/// generating one on this run.
///
/// # Errors
///
/// Returns an error if the arguments are malformed, the configuration cannot
/// be loaded, the resolved profile is a local trial vault (see
/// [`crate::config::require_s3`] — team mode needs a Hippius bucket; run
/// `hippius-mem upgrade` first), [`MemoryStore::provision_members`] fails
/// (e.g. this store's key-ring lacks the current epoch's key because it is
/// not the founder), or — when recovery-key generation runs — minting the
/// seed or [`MemoryStore::publish_recovery_key`] fails for a reason OTHER
/// than "no manifest published yet" (see [`generate_and_print_recovery_key`]).
pub(crate) async fn provision(args: &[String]) -> anyhow::Result<()> {
    let generate_recovery = parse_provision_args(args)?;

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    crate::config::require_s3(&cfg.primary_profile(), "provision")?;

    let store = cfg.build_store().await?;

    // Load this founder's full epoch key-ring BEFORE wrapping the team key to
    // members. `build_store` starts at epoch 0, but on a team that has rotated,
    // `provision_members` must wrap the CURRENT epoch key — otherwise a member
    // provisioned after a rotation receives only the founding-epoch key and would
    // then WRITE under epoch 0, the key a removed member still holds. This is the
    // recorded `bootstrap_epochs` gotcha (a new entry point that builds a store
    // and touches team memory must bootstrap or it silently pins the founding
    // epoch); mirrors the server warmup and `rotate`. Best-effort + mnemonic-
    // gated: the founder always has HIPPIUS_MEM_MNEMONIC set, and an un-rotated
    // team or missing mnemonic degrades to the prior epoch-0 behavior, never a
    // hard failure.
    if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
        bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    }

    let considered = store.provision_members().await?;
    tracing::info!(
        member_keys = considered,
        team = %cfg.team,
        "provisioned the team key to authorized published member keys"
    );

    if generate_recovery {
        generate_and_print_recovery_key(&store, &cfg.team).await?;
    }

    Ok(())
}

/// Parse `provision`'s arguments: the sole optional flag `--no-recovery`.
///
/// Returns whether recovery-key generation should run (`true` unless
/// `--no-recovery` was given). No other argument is accepted — a typo or a
/// flag meant for another command must fail loudly before any store/S3
/// operation runs, the same discipline [`reject_args`] follows for the
/// truly argument-less subcommands.
fn parse_provision_args(args: &[String]) -> anyhow::Result<bool> {
    match args {
        [] => Ok(true),
        [flag] if flag == "--no-recovery" => Ok(false),
        [other, ..] => {
            bail!("unknown provision argument `{other}`; usage: provision [--no-recovery]")
        }
    }
}

/// `provision`'s default step: mint a fresh recovery keypair and name it on
/// the live manifest via [`MemoryStore::publish_recovery_key`], then print the
/// seed to the operator EXACTLY ONCE.
///
/// A team with no membership manifest published yet cannot have a recovery
/// key named on it (there is nothing to attach it to), so THAT case is a
/// warning, not a hard failure — the team-key wrap `provision` already
/// performed stays a success. Any OTHER failure (storage, an unauthorized
/// signer) IS surfaced: naming a recovery key is a security-relevant act, and
/// a silently swallowed failure here would leave the operator believing the
/// escape hatch exists when it does not.
///
/// Every run (with no prior `--no-recovery`) mints and publishes a BRAND NEW
/// recovery key, retiring whichever one was live before — `publish_recovery_key`
/// hands back that previous key (if any) at no extra cost, and this prints a
/// loud REPLACES warning when it is `Some`, so a re-run does not silently
/// orphan a seed an operator has stored offline.
///
/// # Errors
///
/// Returns an error if minting the seed fails, [`MemoryStore::publish_recovery_key`]
/// fails for any reason other than "no manifest published yet", or the seed
/// could not be displayed after it was already published (see
/// [`print_recovery_seed`] — this is surfaced, never swallowed, because by
/// that point the key is live and an operator who never saw it needs to know).
async fn generate_and_print_recovery_key(store: &MemoryStore, team: &str) -> anyhow::Result<()> {
    let seed_hex = generate_seed_hex()?;
    let signer = sr25519_signer_from_hex_seed(&seed_hex)?;
    let recovery_key = signer.verifying_key();

    match store.publish_recovery_key(recovery_key).await {
        Ok((_manifest, previous_recovery_key)) => {
            print_recovery_seed(
                &mut std::io::stdout(),
                &seed_hex,
                previous_recovery_key.is_some(),
            )
            .context(
                "a recovery key WAS published to the team manifest, but it could not be \
                 displayed (writing to stdout failed) -- the operator never saw the seed; run \
                 `hippius-mem provision` again to mint and display a fresh replacement",
            )?;
            tracing::info!(team = %team, "named a fresh recovery key on the team manifest");
            Ok(())
        }
        Err(MemError::ManifestUnavailable { .. }) => {
            tracing::warn!(
                team = %team,
                "no membership manifest published yet; skipped recovery-key generation — run \
                 `publish-membership`, then re-run `provision` to name a recovery key"
            );
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

/// Print the freshly generated recovery seed EXACTLY ONCE, with the loud
/// full-power-credential warning every recovery seed printout carries (see
/// [`print_recovery_outcome`] for `recover`'s sibling banner), and — when
/// `replaces_existing` is set — a loud warning FIRST that this overwrites a
/// previously named recovery key. Never written to config or disk — this is
/// the only place this seed reaches an output stream.
///
/// Takes `out: &mut dyn Write` (production callers pass `std::io::stdout()`)
/// rather than opening the stdout handle itself, so tests can capture the
/// rendered banner into a `Vec<u8>` and assert on its exact content.
///
/// # Errors
///
/// Returns an error if the write fails (e.g. a closed pipe/EPIPE on the real
/// stdout handle). This is called AFTER the manifest is already published
/// (see [`generate_and_print_recovery_key`]), so the caller must treat a
/// write failure here as a genuine failure, not swallow it — the key is live
/// either way, but the operator may never have seen the seed.
fn print_recovery_seed(
    out: &mut dyn std::io::Write,
    seed_hex: &str,
    replaces_existing: bool,
) -> anyhow::Result<()> {
    if replaces_existing {
        writeln!(
            out,
            "\nWARNING: this REPLACES the previous recovery seed -- the earlier one no \
             longer works.",
        )?;
    }
    writeln!(
        out,
        "\n===================== RECOVERY SEED =======================\n\
         {seed_hex}\n\
         \n\
         Write this down and store it OFFLINE. It is shown exactly once and\n\
         is never written to this machine's config or disk.\n\
         \n\
         WARNING: this seed is a FULL-POWER credential. Anyone holding it,\n\
         together with write access to this team's bucket, can take over\n\
         the team AT ANY TIME -- not only after a founder-key loss. Protect\n\
         it like the founder key itself (cold storage, separate custody).\n\
         \n\
         If the founder key is ever lost, recover the team with:\n\
         \x20 hippius-mem recover\n\
         =============================================================",
    )?;
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
/// (see [`crate::join_bundle::run`]), or — on the bare form — the
/// configuration cannot be loaded, the resolved profile is a local trial
/// vault (see [`crate::config::require_s3`]), `HIPPIUS_MEM_MNEMONIC` is
/// unset or does not derive an identity, or [`MemoryStore::join_as_member`]
/// fails.
pub(crate) async fn join(args: &[String]) -> anyhow::Result<()> {
    if let Some(opts) = crate::join_bundle::Options::parse(args)? {
        return crate::join_bundle::run(opts).await;
    }

    // Profile resolution happens BEFORE the mnemonic check: a local trial
    // profile is refused outright, so an operator without a bucket yet is
    // not asked to produce a mnemonic for a command that could never
    // succeed.
    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    crate::config::require_s3(&cfg.primary_profile(), "join")?;

    let mnemonic = std::env::var("HIPPIUS_MEM_MNEMONIC")
        .context("`join` requires HIPPIUS_MEM_MNEMONIC (the joining member's identity)")?;
    let identity = derive_identity(&mnemonic, HIPPIUS_SS58_PREFIX)
        .context("deriving the member identity from HIPPIUS_MEM_MNEMONIC failed")?;
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
    let members = parse_rotate_args(args)?;
    let (cfg, store) = load_rotation_store().await?;
    publish_and_rotate(&cfg, &store, members, RotationStrictness::Strict).await
}

/// Run `remove <ss58>`: as the founder, fuse the removable parts of the
/// three-step member-removal runbook into one command — publish the roster
/// WITHOUT the target, rotate the team key to a fresh epoch wrapped to the
/// remaining members, and print the one step that stays manual (revoking the
/// removed member's S3 sub-token at the gateway).
///
/// The publish+rotate half IS [`rotate`]'s `--members` path
/// ([`publish_and_rotate`]), with the member list computed from the published
/// manifest instead of typed by hand.
///
/// # Resumability
///
/// Every step is safe to re-run with the exact same `<ss58>` argument, which
/// is what recovers from the recorded `rotate --members` non-atomicity gotcha
/// (`publish_membership` can land while `rotate_key` then refuses, typically
/// [`MemError::NothingToRotate`] because no remaining member has `join`ed
/// yet):
///
/// - If the target is still in the live roster, the shrunk membership is
///   published (as on a fresh run). If it is already absent — a prior
///   partial run already published this exact shrink, or the address was
///   never a member; [`plan_removal`] cannot and need not tell those apart —
///   nothing is (re-)published, and a "resuming" line is printed instead.
/// - Either way, the rotation step still runs. `Ok` and
///   [`MemError::NothingToRotate`] both leave this command exiting
///   successfully: the security-relevant half (membership no longer
///   converging the target's ops) is done regardless, and a rotation that
///   could not happen yet (no remaining member has `join`ed) is now durably
///   caught on every later run by `hippius-mem doctor`'s "removed member
///   still holds the current epoch key" check — not only by this command's
///   exit code.
/// - The manual revoke reminder — the one step no CLI reaches — prints on
///   every run, success or not, resumed or not: the membership shrink alone
///   already means the removed member should no longer hold a sub-token,
///   independent of whether rotation itself has completed yet.
///
/// # Errors
///
/// Returns an error if the argument is missing/malformed, the configuration
/// cannot be loaded, the removal is refused (open team, or target is the
/// founder — see [`RemoveRefusal`]), or the publish/rotate path fails for a
/// reason OTHER than the tolerated `NothingToRotate` above (e.g. this signer
/// is not the founder, or a storage failure).
pub(crate) async fn remove(args: &[String]) -> anyhow::Result<()> {
    use std::io::Write;

    let target = parse_remove_args(args)?;
    let (cfg, store) = load_rotation_store().await?;
    let manifest = store.membership_manifest().await?;
    let step = plan_removal(manifest, &target)?;

    let members_to_publish = match step {
        RemovalStep::Publish(remaining) => Some(remaining),
        RemovalStep::AlreadyExcluded => {
            let mut out = std::io::stdout();
            let _ = writeln!(
                out,
                "membership already excludes {target} (resuming)",
                target = target.as_str()
            );
            None
        }
    };

    // The revoke reminder must survive BOTH arms. On a genuine failure the
    // operator is reading stderr and will finish via plain `rotate` (the
    // half-applied recovery), which never mentions the sub-token — so the
    // reminder rides the error chain itself rather than a stdout banner
    // around an error. `Tolerant`: `NothingToRotate` is not a genuine failure
    // here (see the doc comment above), so it falls through to the manual-step
    // banner below like any other success.
    if let Err(err) = publish_and_rotate(
        &cfg,
        &store,
        members_to_publish,
        RotationStrictness::Tolerant,
    )
    .await
    {
        return Err(err.context(pending_revoke_reminder(&target)));
    }

    // The one step no CLI can reach: the removed member's S3 sub-token is
    // gateway-side state. Until it is revoked they can still read AND write the
    // bucket directly — the rotation only seals FUTURE notes away from them.
    // Only sub-token MINTING has a documented API (POST
    // /api/objectstore/sub-tokens/); no revoke endpoint is documented, so this
    // deliberately points at the console UI rather than inventing a path.
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "\n================== ONE MANUAL STEP LEFT ==================\n\
         Revoke the removed member's S3 sub-token in the hippius-console\n\
         (S3 -> Sub Tokens):\n\
         \n\
           {target}\n\
         \n\
         Until that sub-token is revoked, the removed member can still\n\
         read and write the team bucket DIRECTLY — the rotation above\n\
         only keeps notes sealed under the new epoch away from them.\n\
         \n\
         If you onboarded them with `hippius-mem invite --name <label>`,\n\
         their sub-token carries that label in the console's list\n\
         (tokens minted without --name are labeled `hippius-mem-invite`).\n\
         ==========================================================",
        target = target.as_str()
    );
    Ok(())
}

/// The reminder `remove` attaches to its failure path: even when the
/// publish+rotate half stops short (the documented recoverable half-applied
/// state), the security-critical manual step has NOT gone away. Without this,
/// the operator finishes via plain `rotate` — which never mentions sub-tokens —
/// and the revoke is silently lost.
fn pending_revoke_reminder(target: &Ss58) -> String {
    format!(
        "member removal did not complete, but the manual step still applies: revoke \
         {target}'s S3 sub-token in the hippius-console (S3 -> Sub Tokens) once the \
         rotation completes — until revoked, they can still read and write the team \
         bucket directly",
        target = target.as_str()
    )
}

/// Why `remove <ss58>` refused before touching any bucket state.
///
/// A typed enum (the [`crate::config::ConfigError`] shape: `thiserror`,
/// `#[non_exhaustive]`, one actionable message per variant) so each refusal is
/// a testable state whose message names the operator's next command, not a
/// formatted string assembled at the call site.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum RemoveRefusal {
    /// No membership manifest exists — an open team has no roster to remove from.
    #[error(
        "the team is open (no membership manifest published), so there is no roster to \
         remove from; publish one first: hippius-mem publish-membership --members <ss58,...>"
    )]
    OpenTeam,

    /// The target is the manifest's founder.
    #[error(
        "{founder} is the team founder — the founder cannot remove themselves; that is \
         team dissolution (retire the team / bucket), not member removal"
    )]
    TargetIsFounder {
        /// The founder address the operator asked to remove.
        founder: String,
    },
}

/// What `remove <target>`'s manifest step must do.
///
/// There used to be a third, refusal outcome here — "the target is not in
/// the published roster" — but it is INDISTINGUISHABLE, from the manifest
/// alone, from "a prior partial `remove` already published this exact
/// shrink and this run is resuming it": both look like "target absent from
/// the live roster". `remove` must be safe to re-run with the exact same
/// argument (the recovery path for the recorded `rotate --members`
/// non-atomicity gotcha), so both now resolve to [`RemovalStep::AlreadyExcluded`]
/// rather than a refusal — the cost is that a genuine operator typo of a
/// never-a-member address is no longer distinguished from a resume, and
/// simply becomes a harmless no-op publish (the rotation step may still run;
/// see [`remove`]'s docs).
#[derive(Debug, PartialEq, Eq)]
enum RemovalStep {
    /// Publish this member set (the live roster minus the target).
    Publish(BTreeSet<Ss58>),
    /// The target is already absent from the live roster; nothing to
    /// publish. The rotation step still runs (see [`remove`]), so a prior
    /// run that shrank membership but never finished rotating can complete.
    AlreadyExcluded,
}

/// Decide what `remove <target>` may do: a [`RemovalStep`], or a typed
/// refusal.
///
/// Pure by design — all bucket I/O happens before (manifest load) and after
/// (publish+rotate) — so every refusal path is unit-testable without S3. The
/// founder check runs FIRST: the founder is by construction always in the
/// roster, and "you cannot remove the founder" is the more precise refusal.
fn plan_removal(
    manifest: Option<TeamManifest>,
    target: &Ss58,
) -> Result<RemovalStep, RemoveRefusal> {
    let Some(manifest) = manifest else {
        return Err(RemoveRefusal::OpenTeam);
    };

    if manifest.founder == *target {
        return Err(RemoveRefusal::TargetIsFounder {
            founder: target.as_str().to_owned(),
        });
    }

    let mut members = manifest.members;
    if !members.remove(target) {
        return Ok(RemovalStep::AlreadyExcluded);
    }

    Ok(RemovalStep::Publish(members))
}

/// Shared preamble of the rotation-driving commands (`rotate`, `remove`): load
/// the primary-profile config, build its store, and run the mnemonic-gated
/// epoch bootstrap.
///
/// The bootstrap runs BEFORE any rotation for two reasons: the new epoch must
/// clear every epoch this founder can see (a stale local ring must not re-mint
/// an existing epoch), and these entry points read/write full team memory, so
/// skipping it would silently pin them to the founding epoch (the recorded
/// `bootstrap_epochs` gotcha).
async fn load_rotation_store() -> anyhow::Result<(Config, MemoryStore)> {
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

    Ok((cfg, store))
}

/// Whether [`publish_and_rotate`]'s rotation half must treat
/// [`MemError::NothingToRotate`] as a command failure, or as an ordinary
/// not-yet-ready state to report and move past.
///
/// `rotate` ([`Strict`](Self::Strict)) keeps refusing: an operator who
/// explicitly asked for a rotation right now must be told when it did not
/// happen. `remove` ([`Tolerant`](Self::Tolerant)) does not: its own job —
/// shrinking membership, which already stops the target's future ops from
/// converging — is complete regardless, and the still-open read exposure
/// through the un-rotated epoch key is now durably caught by `hippius-mem
/// doctor`'s "removed member still holds the current epoch key" check on
/// every later run, not only by this one command's exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RotationStrictness {
    /// Surface `NothingToRotate` as a command failure.
    Strict,
    /// Report `NothingToRotate` and return success.
    Tolerant,
}

/// Publish `members` (when given) and rotate the team key — the shared tail of
/// `rotate` and `remove`, moved verbatim out of `rotate` so both commands drive
/// one code path.
///
/// The manifest is published FIRST so the rotation's wrap gate already excludes
/// anyone removed. The two halves are NOT atomic; when the manifest landed but
/// the rotation refused (typically `NothingToRotate` because no remaining
/// member has `join`ed), `strictness` decides what happens next: under
/// [`RotationStrictness::Strict`] the error names that half-applied state and
/// the way out, so the operator does not read the refusal as "nothing
/// happened"; under [`RotationStrictness::Tolerant`] it is reported to stdout
/// and treated as a successful (if incomplete) run — see
/// [`RotationStrictness`]'s docs for why that is safe.
async fn publish_and_rotate(
    cfg: &Config,
    store: &MemoryStore,
    members: Option<BTreeSet<Ss58>>,
    strictness: RotationStrictness,
) -> anyhow::Result<()> {
    use std::io::Write;

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

    let outcome = match store.rotate_key(cfg.max_epoch).await {
        Ok(outcome) => outcome,
        Err(MemError::NothingToRotate { .. }) if strictness == RotationStrictness::Tolerant => {
            let mut out = std::io::stdout();
            let _ = writeln!(
                out,
                "membership is published, but the key is NOT yet rotated (no remaining \
                 member has `join`ed yet) -- have them join, then run `hippius-mem rotate` \
                 (or `remove` again) to finish"
            );
            return Ok(());
        }
        Err(err) => {
            // `--members` then NothingToRotate leaves a half-applied command: the
            // shrunk manifest IS published (removed members' ops already filtered)
            // while the key is NOT rotated. Name that state and the way out, so
            // the operator does not read the refusal as "nothing happened".
            return Err(
                if published_members && matches!(err, MemError::NothingToRotate { .. }) {
                    anyhow::Error::new(err).context(
                        "the shrunk membership WAS already published (removed members' ops \
                         are filtered), but the key is NOT yet rotated — have the remaining \
                         members `join`, then re-run `rotate` (without --members) to finish",
                    )
                } else {
                    anyhow::Error::new(err)
                },
            );
        }
    };

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

/// Run `recover`: consume the team's recovery seed to become the new founder
/// when the original founder key is lost.
///
/// The seed is read from the terminal or stdin only — NEVER argv (see
/// [`reject_recover_args`]). It is checked against the live manifest's
/// published recovery key (an [`hippius_mem_core::MemError::Unauthorized`]
/// error names a mismatch), then a fresh manifest is published — signed by
/// the recovery identity, who becomes the new founder — at the next version,
/// carrying membership forward and naming a fresh recovery key so the escape
/// hatch never closes after one use. The fresh seed is printed exactly once,
/// alongside a loud instruction to re-pin `founder_ss58` on every machine.
///
/// # Errors
///
/// Returns an error if arguments were given, the configuration cannot be
/// loaded, the resolved profile is a local trial vault (see
/// [`crate::config::require_s3`]), the seed cannot be read or is malformed,
/// minting the fresh seed fails, or [`MemoryStore::recover_founder`] fails
/// (no manifest published yet, or the seed does not match the published
/// recovery key).
pub(crate) async fn recover(args: &[String]) -> anyhow::Result<()> {
    reject_recover_args(args)?;

    let cfg = Config::from_env_and_file().context(
        "failed to load configuration; set HIPPIUS_MEM_* env vars or create hippius-mem.toml",
    )?;
    crate::config::require_s3(&cfg.primary_profile(), "recover")?;

    let store = cfg.build_store().await?;

    let seed_hex = read_recovery_seed()?;
    let recovery_signer = sr25519_signer_from_hex_seed(&seed_hex)?;
    drop(seed_hex);

    let fresh_seed_hex = generate_seed_hex()?;
    let fresh_signer = sr25519_signer_from_hex_seed(&fresh_seed_hex)?;
    let fresh_recovery_key = fresh_signer.verifying_key();

    let manifest = store
        .recover_founder(&recovery_signer, fresh_recovery_key)
        .await
        .context(
            "recovery failed -- the seed you entered may not match this team's published \
             recovery key, or no membership manifest has been published for this team",
        )?;

    print_recovery_outcome(&mut std::io::stdout(), &manifest, &fresh_seed_hex).context(
        "the team WAS recovered (a fresh manifest naming the new founder is already \
         published), but the outcome could not be displayed (writing to stdout failed) -- \
         nobody has seen the new founder address or the fresh recovery seed. The seed you just \
         entered is now the FOUNDER's signing key: set it as author_seed_hex (or \
         HIPPIUS_MEM_AUTHOR_SEED_HEX) on a machine, then run `hippius-mem provision` from that \
         machine to mint and display a fresh replacement recovery key. That same seed also \
         still needs to become founder_ss58 on every machine, or membership administration \
         stays frozen -- re-running `recover` will NOT work: the seed you just consumed is no \
         longer the trusted recovery key",
    )?;
    tracing::info!(
        team = %cfg.team,
        new_founder = %manifest.founder.as_str(),
        "recovered the team founder through the recovery key"
    );
    Ok(())
}

/// Refuse EVERY argument to `recover`, with a pointed message when the
/// argument looks like an attempt to pass the recovery seed on argv
/// (`--seed`, `--recovery-seed`) — the recovery seed is exactly as sensitive
/// as an S3 secret and must never be visible in `ps` to every user on this
/// machine; mirrors `upgrade`'s `--secret` rejection.
fn reject_recover_args(args: &[String]) -> anyhow::Result<()> {
    let Some(first) = args.first() else {
        return Ok(());
    };
    if first == "--seed" || first == "--recovery-seed" {
        bail!(
            "the recovery seed must never be passed via {first}: it would be visible in argv \
             (`ps`) to every user on this machine; `recover` prompts for it on the terminal, \
             or reads one line from stdin when piped"
        );
    }
    bail!(
        "`recover` takes no arguments (got `{first}`); the recovery seed is read from the \
         terminal or stdin, never argv"
    );
}

/// Read the recovery seed: prompted with input hidden on a real terminal, or
/// one line from stdin when piped — NEVER from argv (see
/// [`reject_recover_args`]). Mirrors `upgrade::read_secret`'s tty/stdin
/// discipline: a recovery seed is exactly as sensitive as an S3 secret — in
/// fact more so, since it is a full-power team-takeover credential.
///
/// # Errors
///
/// Returns an error if the terminal/stdin read fails, or the input is empty.
fn read_recovery_seed() -> anyhow::Result<Zeroizing<String>> {
    let seed = if std::io::stdin().is_terminal() {
        Zeroizing::new(
            rpassword::prompt_password("Recovery seed: ")
                .context("reading the recovery seed from the terminal failed")?,
        )
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading the recovery seed from stdin failed")?;
        Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_owned())
    };

    ensure!(
        !seed.is_empty(),
        "no recovery seed was provided (empty terminal/stdin input)"
    );
    Ok(seed)
}

/// Decode `seed_hex` (64 lowercase hex chars, [`generate_seed_hex`]'s format)
/// into an [`Sr25519Signer`] under the Hippius SS58 prefix.
///
/// Shared by `provision` (the fresh recovery keypair it mints) and `recover`
/// (both the operator-typed CONSUMED seed and the fresh one it mints), so the
/// two commands can never disagree on how a recovery seed maps to a keypair.
/// The hex source is never echoed in an error: a malformed seed is refused
/// with a fixed detail, mirroring `upgrade`'s secret-handling discipline of
/// never leaking secret material into an error chain.
///
/// # Errors
///
/// Returns an error if `seed_hex` is not valid hex, does not decode to
/// exactly 32 bytes, or schnorrkel rejects the seed.
fn sr25519_signer_from_hex_seed(seed_hex: &str) -> anyhow::Result<Sr25519Signer> {
    let bytes = Zeroizing::new(
        hex::decode(seed_hex.trim())
            .map_err(|_| anyhow::anyhow!("the recovery seed is not valid hex"))?,
    );
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("the recovery seed must decode to exactly 32 bytes"))?,
    );
    Sr25519Signer::from_seed_with_prefix(&seed, HIPPIUS_SS58_PREFIX)
        .map_err(|err| anyhow::anyhow!("the recovery seed was rejected: {err}"))
}

/// Print `recover`'s outcome: the new founder address, the fresh recovery
/// seed (once), the full-power-credential warning, and — LOUDLY — the two
/// steps that actually unfreeze membership administration.
///
/// Setting `founder_ss58` alone does NOT unfreeze administration:
/// [`MemoryStore::publish_membership`] requires `self.author == manifest.founder`
/// (`store/mod.rs`), and the new founder IS the recovery keypair the operator
/// just consumed — nothing on disk derives that identity until the operator
/// sets it as `author_seed_hex` somewhere. Until BOTH steps are done —
/// re-pinning `founder_ss58` AND setting `author_seed_hex` to the just-entered
/// seed on the administering machine — `publish-membership`/`rotate`/`remove`
/// stay FROZEN for both the old founder (their key no longer signs the live
/// manifest) and the new one (a stale pin refuses even the correct signer
/// outright, before the manifest is even loaded). Both are fail-closed by
/// design, not a bug, but easy to miss right after a recovery — hence the
/// banner spells out the working end state, not just the symptom.
///
/// Takes `out: &mut dyn Write` for the same reason [`print_recovery_seed`]
/// does: production callers pass `std::io::stdout()`, and tests capture the
/// rendered banner into a `Vec<u8>` to assert on its exact content.
///
/// # Errors
///
/// Returns an error if the write fails — see [`print_recovery_seed`]'s doc
/// for why this must be surfaced, never swallowed: by the time this runs,
/// the recovery manifest is ALREADY published.
fn print_recovery_outcome(
    out: &mut dyn std::io::Write,
    manifest: &TeamManifest,
    fresh_seed_hex: &str,
) -> anyhow::Result<()> {
    writeln!(
        out,
        "\n===================== TEAM RECOVERED =======================\n\
         New founder: {founder}\n\
         \n\
         NEW RECOVERY SEED (write this down, store it OFFLINE, it is shown\n\
         exactly once and is never written to this machine's config or disk):\n\
         \n\
         {seed}\n\
         \n\
         WARNING: this seed is a FULL-POWER credential. Anyone holding it,\n\
         together with write access to this team's bucket, can take over\n\
         the team AT ANY TIME -- not only after a founder-key loss. Protect\n\
         it like the founder key itself (cold storage, separate custody).\n\
         \n\
         ==================== ACTION REQUIRED ========================\n\
         Two steps, BOTH required, before membership administration works\n\
         again:\n\
         \n\
         1. Keep the RECOVERY SEED YOU JUST ENTERED for this recovery --\n\
            it is now the FOUNDER's signing key, not a spent credential.\n\
            Set it as author_seed_hex (or HIPPIUS_MEM_AUTHOR_SEED_HEX) on\n\
            whichever machine will administer this team going forward.\n\
         2. Update founder_ss58 to {founder} (and HIPPIUS_MEM_FOUNDER_SS58,\n\
            wherever it is set) on EVERY teammate's machine, including\n\
            this one.\n\
         \n\
         Until BOTH are done, publish-membership / rotate / remove stay\n\
         FROZEN, fail-closed by design: they require this machine's own\n\
         signing identity to match the manifest's founder, AND a\n\
         founder_ss58 pin that already agrees -- a stale pin or the wrong\n\
         signing key refuses everyone. The bucket itself already governs\n\
         correctly; only this LOCAL state (the pin, and which key each\n\
         machine signs with) lags behind it.\n\
         ==============================================================",
        founder = manifest.founder.as_str(),
        seed = fresh_seed_hex,
    )?;
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

/// Best-effort: warn (loudly, at WARN level) when `store`'s bucket has
/// published a wrapped-key epoch newer than `configured_max_epoch`.
///
/// This is the warning-side counterpart to [`bootstrap_epochs`]: that function
/// only tries epochs `0..=max_epoch` because it has no way to see what the
/// bucket actually holds, so a `max_epoch` an operator forgets to raise after
/// a teammate's `rotate` silently hides every note sealed under the new epoch
/// — the recorded, twice-recurred `bootstrap_epochs` gotcha. Calling this
/// after every store build closes that: it needs no identity (unlike
/// `bootstrap_epochs`, it only lists the `_keys/` prefix), so it runs
/// unconditionally, not gated on `HIPPIUS_MEM_MNEMONIC`.
///
/// Never raises `max_epoch` itself — the pin is security-relevant (it bounds
/// how many epoch keys startup tries to fetch), so only the operator decides
/// to widen it. A fetch failure (offline, missing permissions) is silent: this
/// check exists to add a hint on top of whatever already runs, never to become
/// a new failure mode of its own.
pub(crate) async fn warn_if_max_epoch_stale(store: &MemoryStore, configured_max_epoch: u64) {
    let Ok(published) = store.highest_published_epoch().await else {
        return;
    };
    if published > configured_max_epoch {
        tracing::warn!(
            configured = configured_max_epoch,
            published,
            "this machine's max_epoch hides rotated notes: raise max_epoch to {published} \
             in the [[teams]] profile or new-epoch notes stay invisible"
        );
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

/// Parse `remove`'s arguments: exactly one positional SS58 address.
///
/// No flags: the member list is computed from the published manifest, so the
/// only operator input is WHO leaves. Extra arguments are refused loudly (the
/// same pre-store loud-failure rule as [`reject_args`]) — a second address here
/// most likely means the operator wanted `rotate --members`.
fn parse_remove_args(args: &[String]) -> anyhow::Result<Ss58> {
    match args {
        [target] => {
            Ss58::new(target).with_context(|| format!("invalid SS58 member address {target:?}"))
        }
        [] => bail!("remove requires the member's SS58 address; usage: remove <ss58>"),
        [_, extra, ..] => bail!(
            "remove takes exactly one SS58 address (got extra `{extra}`); usage: remove <ss58> \
             — to set an explicit member list, use rotate --members <ss58,...>"
        ),
    }
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
    #![expect(
        clippy::expect_used,
        reason = "tests assert success/failure of Result-returning outcomes directly"
    )]

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hippius_mem_core::{
        BlobStore, HashEmbedder, InMemoryIndex, MemError, MemberKey, MemoryBlobStore, MemoryStore,
        NoopAnchor, OpLogStore, SecretKey, Signer, Sr25519Signer, Ss58, TeamManifest,
        derive_identity, provision_team_key, publish_member_key, signer_from_mnemonic,
    };

    use super::{
        HIPPIUS_SS58_PREFIX, RemovalStep, RemoveRefusal, RotationStrictness, bootstrap_epochs,
        parse_members, parse_provision_args, parse_publish_membership_args, parse_remove_args,
        parse_rotate_args, pending_revoke_reminder, plan_removal, print_recovery_outcome,
        print_recovery_seed, publish_and_rotate, reject_args, reject_recover_args,
        sr25519_signer_from_hex_seed,
    };
    use crate::config::Config;

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
    fn remove_args_accept_exactly_one_ss58() -> anyhow::Result<()> {
        let target = parse_remove_args(&[ALICE.to_owned()])?;
        assert_eq!(target.as_str(), ALICE);
        Ok(())
    }

    #[test]
    fn remove_args_reject_missing_extra_and_malformed() -> anyhow::Result<()> {
        // Each refusal fires BEFORE any store/S3 operation runs, and the
        // extra-argument message redirects to `rotate --members` (the command
        // an operator passing a list most likely wanted).
        assert!(parse_remove_args(&[]).is_err(), "no address is an error");
        let Err(err) = parse_remove_args(&[ALICE.to_owned(), DEV.to_owned()]) else {
            anyhow::bail!("two addresses must be rejected");
        };
        assert!(
            err.to_string().contains("rotate --members"),
            "the extra-argument refusal points at rotate --members: {err}"
        );
        assert!(
            parse_remove_args(&["not-an-ss58".to_owned()]).is_err(),
            "a malformed address must be rejected"
        );
        Ok(())
    }

    /// Publish `extra_members` (the founder is inserted automatically by the
    /// manifest signing) through the PUBLIC ingestion path and hand back the
    /// manifest exactly as `remove` loads it.
    async fn published_manifest(
        extra_members: &[&str],
    ) -> anyhow::Result<Option<hippius_mem_core::TeamManifest>> {
        let bucket = Arc::new(MemoryBlobStore::default());
        let store = epoch0_store(&bucket)?;
        let members = extra_members
            .iter()
            .map(|raw| Ss58::new(*raw).map_err(anyhow::Error::from))
            .collect::<anyhow::Result<BTreeSet<Ss58>>>()?;
        store.publish_membership(members).await?;
        Ok(store.membership_manifest().await?)
    }

    #[tokio::test]
    async fn remove_plan_refuses_an_open_team() -> anyhow::Result<()> {
        // No manifest ever published: nothing to remove from, and the refusal
        // must point at publish-membership, not fail obscurely downstream.
        let bucket = Arc::new(MemoryBlobStore::default());
        let store = epoch0_store(&bucket)?;
        let manifest = store.membership_manifest().await?;
        let Err(err) = plan_removal(manifest, &Ss58::new(ALICE)?) else {
            anyhow::bail!("an open team must refuse removal");
        };
        assert!(matches!(err, RemoveRefusal::OpenTeam));
        assert!(
            err.to_string().contains("publish-membership"),
            "the refusal names the command that creates a roster: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn remove_skips_republish_when_member_already_gone() -> anyhow::Result<()> {
        // Roster is {founder, DEV}; ALICE is absent from it. This is exactly
        // the shape a re-run-after-partial-failure leaves behind (a prior
        // `remove ALICE` already published the shrink but never finished
        // rotating), and `plan_removal` cannot tell that apart from "ALICE
        // was never a member" -- so BOTH resolve to the same idempotent
        // Skip, never a refusal, so `remove` stays safe to re-run.
        let manifest = published_manifest(&[DEV]).await?;
        let step = plan_removal(manifest, &Ss58::new(ALICE)?).map_err(|refusal| {
            anyhow::anyhow!("an absent target must not be refused: {refusal}")
        })?;
        assert_eq!(
            step,
            RemovalStep::AlreadyExcluded,
            "an already-absent target must produce a Skip, not a republish"
        );
        Ok(())
    }

    #[tokio::test]
    async fn remove_plan_refuses_founder_self_removal() -> anyhow::Result<()> {
        let manifest = published_manifest(&[ALICE]).await?;
        let founder = derive_identity(MNEMONIC, HIPPIUS_SS58_PREFIX)?.ss58;
        let Err(err) = plan_removal(manifest, &founder) else {
            anyhow::bail!("the founder must not be removable");
        };
        assert!(matches!(err, RemoveRefusal::TargetIsFounder { .. }));
        assert!(
            err.to_string().contains("dissolution"),
            "the refusal explains why self-removal is out of scope: {err}"
        );
        Ok(())
    }

    #[test]
    fn remove_failure_context_keeps_the_revoke_reminder() -> anyhow::Result<()> {
        // The half-applied path (manifest published, rotation refused) exits
        // through an error chain; the revoke reminder must lead that chain —
        // the operator finishing via plain `rotate` would otherwise never
        // hear about the sub-token again — while the underlying cause stays
        // visible below it.
        let target = Ss58::new(ALICE)?;
        let err = anyhow::anyhow!("nothing to rotate").context(pending_revoke_reminder(&target));
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(ALICE) && rendered.contains("Sub Tokens"),
            "the reminder names the target and where to revoke: {rendered}"
        );
        assert!(
            rendered.contains("nothing to rotate"),
            "the underlying rotation failure stays in the chain: {rendered}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn remove_plan_shrinks_the_roster_to_exactly_the_rest() -> anyhow::Result<()> {
        // The set handed to the publish+rotate path is EXACTLY roster minus the
        // target — nothing dropped, nothing invented, founder retained.
        let manifest = published_manifest(&[ALICE, DEV]).await?;
        let founder = derive_identity(MNEMONIC, HIPPIUS_SS58_PREFIX)?.ss58;
        let step = plan_removal(manifest, &Ss58::new(DEV)?)
            .map_err(|refusal| anyhow::anyhow!("unexpected refusal: {refusal}"))?;
        assert_eq!(
            step,
            RemovalStep::Publish(BTreeSet::from([founder, Ss58::new(ALICE)?]))
        );
        Ok(())
    }

    /// A minimal [`Config`] fixture naming this test module's `TEAM`/`MNEMONIC`
    /// fixtures, for tests that call `publish_and_rotate` directly (it needs
    /// `cfg.team` for logging and `cfg.max_epoch` as the rotation floor).
    fn rotation_test_config() -> Config {
        Config {
            team: TEAM.to_owned(),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn remove_treats_nothing_to_rotate_as_done() -> anyhow::Result<()> {
        // No remaining member has published a MemberKey (nobody `join`ed),
        // so once the shrunk manifest is published, `rotate_key` can wrap the
        // new epoch to NOBODY and returns `NothingToRotate` -- the exact
        // half-applied gotcha state. In `Tolerant` mode (the path `remove`
        // drives) that must still complete the command successfully instead
        // of leaving the recorded gotcha state: membership shrunk, key
        // un-rotated, command failed.
        let bucket = Arc::new(MemoryBlobStore::default());
        let store = epoch0_store(&bucket)?;
        let cfg = rotation_test_config();

        // Seed an initial manifest with DEV as a member, so there is
        // something for the shrink below to actually remove.
        store
            .publish_membership(BTreeSet::from([Ss58::new(DEV)?]))
            .await?;

        let founder = derive_identity(MNEMONIC, HIPPIUS_SS58_PREFIX)?.ss58;
        let remaining = BTreeSet::from([founder]);

        publish_and_rotate(&cfg, &store, Some(remaining), RotationStrictness::Tolerant)
            .await
            .expect(
                "NothingToRotate after a successful republish must be treated as done in \
                 Tolerant mode, not surfaced as a command failure",
            );

        // The membership shrink DID land, even though rotation did not.
        let live = store
            .membership_manifest()
            .await?
            .ok_or_else(|| anyhow::anyhow!("a manifest must have been published"))?;
        assert!(
            !live.members.contains(&Ss58::new(DEV)?),
            "the shrunk membership must still be published even though rotation was skipped"
        );
        Ok(())
    }

    #[tokio::test]
    async fn publish_and_rotate_strict_still_fails_on_nothing_to_rotate() -> anyhow::Result<()> {
        // `rotate` (the direct command, not via `remove`) must keep the
        // ORIGINAL strict behavior: NothingToRotate is a genuine command
        // failure the operator must see and act on.
        let bucket = Arc::new(MemoryBlobStore::default());
        let store = epoch0_store(&bucket)?;
        let cfg = rotation_test_config();
        let founder = derive_identity(MNEMONIC, HIPPIUS_SS58_PREFIX)?.ss58;
        let remaining = BTreeSet::from([founder]);

        let err = publish_and_rotate(&cfg, &store, Some(remaining), RotationStrictness::Strict)
            .await
            .expect_err("NothingToRotate must still fail the direct rotate path");
        assert!(
            err.chain().any(|cause| matches!(
                cause.downcast_ref::<MemError>(),
                Some(MemError::NothingToRotate { .. })
            )),
            "the underlying NothingToRotate cause must stay in the error chain: {err}"
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

    #[test]
    fn provision_args_default_to_generating_a_recovery_key() -> anyhow::Result<()> {
        assert!(
            parse_provision_args(&[])?,
            "bare `provision` generates a recovery key by default"
        );
        Ok(())
    }

    #[test]
    fn provision_args_no_recovery_opts_out() -> anyhow::Result<()> {
        let args = vec!["--no-recovery".to_owned()];
        assert!(
            !parse_provision_args(&args)?,
            "--no-recovery must opt out of recovery-key generation"
        );
        Ok(())
    }

    #[test]
    fn provision_args_reject_unknown_flags() -> anyhow::Result<()> {
        let args = vec!["--bogus".to_owned()];
        let Err(err) = parse_provision_args(&args) else {
            anyhow::bail!("an unknown flag must be rejected");
        };
        assert!(
            err.to_string().contains("--bogus"),
            "the refusal names the offending flag: {err}"
        );
        Ok(())
    }

    #[test]
    fn recover_rejects_any_argument() -> anyhow::Result<()> {
        // A bare stray argument is refused generically...
        let stray = vec!["--bogus".to_owned()];
        let Err(err) = reject_recover_args(&stray) else {
            anyhow::bail!("a stray argument must be rejected");
        };
        assert!(
            err.to_string().to_lowercase().contains("argv"),
            "the generic refusal still explains the seed is never on argv: {err}"
        );

        // ...and a seed-shaped flag gets the POINTED refusal, mirroring
        // `upgrade`'s `--secret` rejection.
        for flag in ["--seed", "--recovery-seed"] {
            let args = vec![flag.to_owned(), "deadbeef".to_owned()];
            let Err(err) = reject_recover_args(&args) else {
                anyhow::bail!("a seed-shaped flag must be rejected with a pointed error");
            };
            let rendered = err.to_string();
            assert!(
                rendered.to_lowercase().contains("argv") && rendered.contains(flag),
                "the pointed refusal names the flag and argv: {rendered}"
            );
        }

        assert!(
            reject_recover_args(&[]).is_ok(),
            "no arguments is the only accepted form"
        );
        Ok(())
    }

    #[test]
    fn hex_seed_round_trips_to_the_same_signer() -> anyhow::Result<()> {
        let seed_hex = "11".repeat(32);
        let a = sr25519_signer_from_hex_seed(&seed_hex)?;
        let b = sr25519_signer_from_hex_seed(&seed_hex)?;
        assert_eq!(
            a.author_ss58(),
            b.author_ss58(),
            "the same hex seed must always derive the same identity"
        );
        Ok(())
    }

    #[test]
    fn hex_seed_rejects_malformed_input() {
        assert!(
            sr25519_signer_from_hex_seed("not-hex").is_err(),
            "non-hex input must be rejected"
        );
        assert!(
            sr25519_signer_from_hex_seed("ab").is_err(),
            "a seed shorter than 32 bytes must be rejected"
        );
        assert!(
            sr25519_signer_from_hex_seed(&"ab".repeat(33)).is_err(),
            "a seed longer than 32 bytes must be rejected"
        );
    }

    #[test]
    fn recovery_seed_banner_warns_when_it_replaces_an_existing_key() -> anyhow::Result<()> {
        // I1: `provision` re-runs silently mint a new recovery key every
        // time; the operator must be told the seed they have stored offline
        // just stopped working.
        let mut buf = Vec::new();
        print_recovery_seed(&mut buf, "deadbeef", true)?;
        let rendered = String::from_utf8(buf)?;
        assert!(
            rendered.contains("REPLACES") && rendered.contains("no longer works"),
            "a re-run must warn that it replaces the previous seed: {rendered}"
        );
        Ok(())
    }

    #[test]
    fn recovery_seed_banner_first_run_has_no_replaces_warning() -> anyhow::Result<()> {
        let mut buf = Vec::new();
        print_recovery_seed(&mut buf, "deadbeef", false)?;
        let rendered = String::from_utf8(buf)?;
        assert!(
            !rendered.contains("REPLACES"),
            "naming a FIRST recovery key must not claim to replace one: {rendered}"
        );
        Ok(())
    }

    #[test]
    fn recovery_seed_banner_never_omits_the_full_power_warning() -> anyhow::Result<()> {
        // Carry-forward mandate #2: every printout of a recovery seed states
        // the full-power-credential warning, regardless of `replaces_existing`.
        for replaces in [false, true] {
            let mut buf = Vec::new();
            print_recovery_seed(&mut buf, "deadbeef", replaces)?;
            let rendered = String::from_utf8(buf)?;
            assert!(
                rendered.contains("FULL-POWER") && rendered.contains("AT ANY TIME"),
                "replaces={replaces}: the full-power warning must always print: {rendered}"
            );
        }
        Ok(())
    }

    /// A throwaway, structurally-valid [`TeamManifest`] fixture for banner
    /// content tests — its signature/members are irrelevant, only the
    /// `founder` field the banner interpolates matters.
    fn fixture_manifest() -> anyhow::Result<TeamManifest> {
        let signer = Sr25519Signer::from_seed_with_prefix(&[1_u8; 32], HIPPIUS_SS58_PREFIX)?;
        Ok(TeamManifest::create_signed(
            &signer,
            "team".to_owned(),
            BTreeSet::from([signer.author_ss58()]),
            3,
        ))
    }

    #[test]
    fn recovery_outcome_banner_instructs_setting_author_seed_hex() -> anyhow::Result<()> {
        // I2: re-pinning founder_ss58 alone does not unfreeze administration —
        // the banner must also tell the operator to set the just-entered seed
        // as author_seed_hex (the actual founder signing identity) somewhere.
        let manifest = fixture_manifest()?;
        let mut buf = Vec::new();
        print_recovery_outcome(&mut buf, &manifest, "deadbeef")?;
        let rendered = String::from_utf8(buf)?;
        assert!(
            rendered.contains("author_seed_hex")
                && rendered.contains("HIPPIUS_MEM_AUTHOR_SEED_HEX"),
            "the banner must instruct setting author_seed_hex: {rendered}"
        );
        assert!(
            rendered.contains("founder_ss58") && rendered.contains("HIPPIUS_MEM_FOUNDER_SS58"),
            "the banner must still instruct the founder_ss58 re-pin: {rendered}"
        );
        assert!(
            rendered.contains(manifest.founder.as_str()),
            "the banner must name the new founder address: {rendered}"
        );
        assert!(
            rendered.contains("deadbeef"),
            "the banner must show the fresh recovery seed: {rendered}"
        );
        Ok(())
    }
}
