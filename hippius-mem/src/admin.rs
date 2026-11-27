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
    CreateOnly, DropClass, Identity, Joined, KeyCheckPublished, KeyShares, MemError, MemoryStore,
    NetworkPrefix, PublishKeyCheck, QuarantinedAuthorDetail, Signer, Sr25519Signer, Ss58,
    TeamManifest, derive_identity,
};
use zeroize::Zeroizing;

use crate::config::{Config, TeamProfile};
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

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (_profile, store) = routed_store(&cfg).await?;
    store.publish_membership(members).await?;

    tracing::info!(
        members = count,
        team = %store.team(),
        "published team membership manifest"
    );

    Ok(())
}

/// Run `provision [--no-recovery]`: as the founder, by default name a fresh
/// recovery key on the team manifest, then wrap every epoch key this machine
/// holds to every published member key the founder-signed manifest
/// authorizes.
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

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (profile, store) = routed_store(&cfg).await?;
    crate::config::require_s3(&profile, "provision")?;

    // Load this founder's full epoch key-ring BEFORE wrapping the team key to
    // members. `build_store` starts at epoch 0, and `provision_members` wraps
    // only the epochs the ring holds: without the rotated ones a member
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
        adopt_shared_epoch_keys(&store, &mnemonic).await?;
    }

    // The new recovery key is named BEFORE the wrap pass. The pass keeps every
    // wrap a reader accepts, and readers accept a wrap the CURRENT recovery key
    // signed; naming a new one retires that key, so a wrap it signed and the pass
    // kept would be refused by every reader afterwards, the founder included, and
    // its epoch lost. Named first, those wraps are no longer accepted during the
    // pass, which replaces them with founder-signed ones. The epoch bootstrap
    // above already opened this founder's own such wraps while they were still
    // accepted. A wrap the retired key signed at an epoch this founder does not
    // hold cannot be replaced, and stays refused.
    if generate_recovery {
        generate_and_print_recovery_key(&store, store.team()).await?;
    }

    let provisioned = store.provision_members().await?;
    tracing::info!(
        written = provisioned.written.len(),
        kept = provisioned.kept,
        team = %store.team(),
        "provisioned the team key to authorized published member keys (kept every wrap a \
         reader already accepts)"
    );

    // The founder holds the team's keys by construction, so this is a place a
    // team-key check can be published without trusting anyone's judgment. Best
    // effort, like `rotate`'s: the members are provisioned already.
    publish_founder_key_checks(&store).await;

    Ok(())
}

/// Load the keys of epochs this founder holds no wrap of from the key shares
/// members published (`admin share-epoch-keys`), and say so on stdout, so the
/// `provision_members` that follows wraps them to the founder and to every
/// member. Writes nothing itself.
///
/// # Errors
///
/// A mnemonic that does not derive an identity, or a failed share listing.
async fn adopt_shared_epoch_keys(store: &MemoryStore, mnemonic: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let identity = derive_identity(mnemonic, HIPPIUS_SS58_PREFIX)
        .context("deriving the identity from HIPPIUS_MEM_MNEMONIC failed")?;
    let adopted = store
        .adopt_shared_epoch_keys(&identity)
        .await
        .context("reading the members' key shares failed")?;
    for epoch in adopted {
        let _ = writeln!(
            std::io::stdout(),
            "loaded the key of epoch {epoch} from a member's key share, checked against the \
             founder-signed wrap it opens; this run wraps it to the founder and every member"
        );
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
/// warning, not a hard failure — the team-key wrap `provision` performs next
/// still runs. Any OTHER failure (storage, an unauthorized
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
        Err(err @ MemError::Unauthorized(_)) => Err(anyhow::Error::new(err).context(
            "only the founder names a recovery key; the recovery key's holder runs \
             `hippius-mem provision --no-recovery`",
        )),
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
    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (profile, _launch_repo) = crate::resolve_profile(&cfg)?;
    crate::config::require_s3(&profile, "join")?;

    let mnemonic = std::env::var("HIPPIUS_MEM_MNEMONIC")
        .context("`join` requires HIPPIUS_MEM_MNEMONIC (the joining member's identity)")?;
    let identity = derive_identity(&mnemonic, HIPPIUS_SS58_PREFIX)
        .context("deriving the member identity from HIPPIUS_MEM_MNEMONIC failed")?;
    let store = profile.build_store(&cfg).await?;
    store.join_as_member(&identity).await?;
    // Pick up any epoch keys the founder already provisioned to this member.
    bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    // The member key, and so the founder's wrap, is under the author address,
    // not the mnemonic's (`join_as_member`).
    let member = profile.signer()?.author_ss58();
    tracing::info!(
        team = %profile.name,
        member = %member.as_str(),
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
/// Scope: like every team command, this operates on the profile the current
/// directory's git remote routes to (see [`routed_store`]), so a `[[teams]]`
/// team is rotated from a checkout of one of its repositories.
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
    let (cfg, store, founder) = load_rotation_store("rotate").await?;
    // `rotate`'s whole point is rotating: always attempt it. The
    // should-we-bother guard `remove` uses (see `removal_requires_rotation`)
    // is meaningless here — there is no single removal target to check
    // against.
    publish_and_rotate(&cfg, &store, &founder, members, true).await
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
/// Every step is safe to re-run with the exact same `<ss58>` argument:
///
/// - If the target is still in the live roster, the shrunk membership is
///   published (as on a fresh run). If it is already absent — a prior
///   partial run already published this exact shrink, or the address was
///   never a member; [`plan_removal`] cannot and need not tell those apart —
///   nothing is (re-)published, and a "resuming" line is printed instead.
/// - Rotation runs EXACTLY when THIS invocation's republish actually shrank
///   the roster (see [`removal_requires_rotation`]) — never based on
///   `_keys/` wrap membership, which a member who joined by invite bundle
///   (holding `team_key_hex` directly) never appears in. A completed-removal
///   re-run (or a never-a-member target) does NOT rotate: nothing changed, and
///   rotating again would mint a new epoch for no security benefit. A
///   half-done run (the shrink published, then the rotation failed) also reads
///   as already excluded on a re-run; its error says to finish with
///   `hippius-mem rotate`.
/// - The rotation always has a recipient: the founder, whose member key
///   [`publish_and_rotate`] publishes first when it has none, so it no longer waits for a
///   remaining member to `join`.
/// - The manual revoke reminder — the one step no CLI reaches — prints on
///   every run, success or not, resumed or not, rotated or not: the
///   membership shrink alone already means the removed member should no
///   longer hold a sub-token.
///
/// # Errors
///
/// Returns an error if the argument is missing/malformed, `HIPPIUS_MEM_MNEMONIC`
/// is unset, the configuration cannot be loaded or routes to a local trial
/// vault, the removal is refused (open team, or target is the founder — see
/// [`RemoveRefusal`]), or the
/// publish/rotate path fails (e.g. this signer is not the founder, or a
/// storage failure).
pub(crate) async fn remove(args: &[String]) -> anyhow::Result<()> {
    use std::io::Write;

    let target = parse_remove_args(args)?;
    let (cfg, store, founder) = load_rotation_store("remove").await?;
    let manifest = store.membership_manifest().await?;
    let step = plan_removal(manifest, &target)?;

    // Decide whether rotating would accomplish anything for THIS target
    // BEFORE `step` is consumed by the match below — the membership publish
    // that follows always still happens regardless of this decision; only
    // the (potentially unnecessary) rotation is gated on it. See
    // `removal_requires_rotation`'s doc for why "did this invocation shrink
    // the roster" replaced the old `_keys/`-recipients-based proxy.
    let should_rotate = removal_requires_rotation(&step);

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

    if !should_rotate {
        let mut out = std::io::stdout();
        let _ = writeln!(
            out,
            "{target} is already off the roster; skipping rotation (nothing to fix by \
             rotating)",
            target = target.as_str()
        );
    }

    // The revoke reminder must survive BOTH arms. On a failure the operator is
    // reading stderr and will finish via plain `rotate` (the half-applied
    // recovery), which never mentions the sub-token — so the reminder rides
    // the error chain itself rather than a stdout banner around an error.
    let published = publish_and_rotate(&cfg, &store, &founder, members_to_publish, should_rotate);
    if let Err(err) = published.await {
        return Err(err.context(pending_revoke_reminder(&target)));
    }

    // The one step no CLI can reach: the removed member's S3 sub-token is
    // gateway-side state. Until it is revoked they can still read AND write the
    // bucket directly — the rotation only seals FUTURE notes away from them.
    // Only sub-token MINTING has a documented API (POST
    // /api/objectstore/sub-tokens/); no revoke endpoint is documented, so this
    // deliberately points at the console UI rather than inventing a path.
    let _ = writeln!(
        std::io::stdout(),
        "{}",
        manual_step_banner(&target, should_rotate)
    );
    Ok(())
}

/// The banner `remove` ends with: the sub-token revoke no CLI can do, and what
/// the removed member can still do until then. `rotated` says whether this run
/// rotated the key; a run that did not (the target was already off the roster)
/// must not claim a rotation, and names the command that rotates.
fn manual_step_banner(target: &Ss58, rotated: bool) -> String {
    let exposure = if rotated {
        "read and write the team bucket DIRECTLY — the rotation above\n\
         only keeps notes sealed under the new epoch away from them."
    } else {
        "read and write the team bucket DIRECTLY. This run did not rotate\n\
         the key: if no rotation followed their removal, they also still\n\
         decrypt every new note; run `hippius-mem rotate`."
    };
    format!(
        "\n================== ONE MANUAL STEP LEFT ==================\n\
         Revoke the removed member's S3 sub-token in the hippius-console\n\
         (S3 -> Sub Tokens):\n\
         \n\
           {target}\n\
         \n\
         Until that sub-token is revoked, the removed member can still\n\
         {exposure}\n\
         \n\
         If you onboarded them with `hippius-mem invite --name <label>`,\n\
         their sub-token carries that label in the console's list\n\
         (tokens minted without --name are labeled `hippius-mem-invite`).\n\
         ==========================================================",
        target = target.as_str()
    )
}

/// Whether removing a member should rotate the team key: exactly when THIS
/// invocation's [`plan_removal`] actually shrank the roster, i.e. `step` is
/// [`RemovalStep::Publish`].
///
/// # Why "did this invocation shrink the roster", not "does `_keys/` still
/// hold a wrap for them"
///
/// An earlier version of this gate asked whether `target` still held a wrap
/// of the CURRENT epoch's key (`_keys/` recipients at the highest published
/// epoch) — reasoning that a member who holds no such wrap has nothing left
/// to revoke by rotating. That proxy has a hole: `join --bundle` hands a
/// member `team_key_hex` DIRECTLY (see `crate::join_bundle`), so a
/// bundle-provisioned member never appears in ANY `_keys/` wrap, at any
/// epoch, ever. Removing them under the old gate read "absent from
/// `_keys/`" as "already excluded" and skipped rotation entirely — leaving
/// their epoch-0 key able to decrypt every future note forever, exactly the
/// exposure `remove` exists to close.
///
/// "Did the republish in THIS invocation actually remove someone from the
/// roster" has no such hole: it does not care how (or whether) the target
/// ever received a key, only whether they were just now removed from who
/// is authorized to hold one. A genuine removal (`RemovalStep::Publish`)
/// always rotates. An already-excluded target
/// (`RemovalStep::AlreadyExcluded` — a completed-removal re-run, or a
/// never-a-member typo; [`plan_removal`] cannot and need not tell those
/// apart) does not rotate: nothing changed in this invocation, so rotating
/// again would mint a gratuitous new epoch and force every remaining
/// member to restart, for no security benefit — Task 12's
/// churn-avoidance, preserved.
///
/// One residual: a HALF-DONE resume — a prior run published the shrunk roster
/// but the rotation then failed — also presents as `AlreadyExcluded` and is
/// NOT retried by re-running `remove` with the same target. That run's error
/// names `hippius-mem rotate`, which finishes it.
fn removal_requires_rotation(step: &RemovalStep) -> bool {
    matches!(step, RemovalStep::Publish(_))
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
/// simply becomes a fully harmless no-op: no publish, and — since
/// [`removal_requires_rotation`] gates on this exact step — no rotation
/// either.
#[derive(Debug, PartialEq, Eq)]
enum RemovalStep {
    /// Publish this member set (the live roster minus the target).
    Publish(BTreeSet<Ss58>),
    /// The target is already absent from the live roster; nothing to
    /// publish, and — since this invocation changed nothing — no rotation
    /// either (see [`removal_requires_rotation`]).
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

/// The team profile the current directory's git remote routes to, and its
/// store. Every team command picks its team this way, as `doctor` and the MCP
/// server do, so on a config with `[[teams]]` profiles an operator runs it from
/// a checkout of that team's repository.
///
/// # Errors
///
/// When the repository routes to no profile (memory is disabled here), or the
/// store cannot be built.
async fn routed_store(cfg: &Config) -> anyhow::Result<(TeamProfile, MemoryStore)> {
    let (profile, _launch_repo) = crate::resolve_profile(cfg)?;
    let store = profile.build_store(cfg).await?;
    Ok((profile, store))
}

/// Shared preamble of the rotation-driving commands (`rotate`, `remove`): load
/// the config, build the routed profile's store, refuse a local trial vault
/// (`command` names the refused command), derive the founder identity from `HIPPIUS_MEM_MNEMONIC`, and run the epoch
/// bootstrap. Writes nothing.
///
/// `HIPPIUS_MEM_MNEMONIC` is required: the founder loads a rotated epoch's key
/// only from a wrap addressed to its member key, opened with that mnemonic, so
/// a rotation without it mints an epoch this founder cannot read once the
/// command exits, and nobody else may wrap it to the founder again.
///
/// The bootstrap runs BEFORE any rotation for two reasons: the new epoch must
/// clear every epoch this founder can see (a stale local ring must not re-mint
/// an existing epoch), and these entry points read/write full team memory, so
/// skipping it would silently pin them to the founding epoch (the recorded
/// `bootstrap_epochs` gotcha). The founder's member key is published later, by
/// [`publish_and_rotate`], only once the command is going to rotate.
async fn load_rotation_store(command: &str) -> anyhow::Result<(Config, MemoryStore, Identity)> {
    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (profile, store) = routed_store(&cfg).await?;
    crate::config::require_s3(&profile, command)?;

    let mnemonic = std::env::var("HIPPIUS_MEM_MNEMONIC").context(
        "`rotate` and `remove` require HIPPIUS_MEM_MNEMONIC (the founder's mnemonic): the \
         founder reads a rotated epoch only with it, so rotating without it would mint an epoch \
         this founder cannot read once the command exits",
    )?;
    let identity = derive_identity(&mnemonic, HIPPIUS_SS58_PREFIX)
        .context("deriving the founder identity from HIPPIUS_MEM_MNEMONIC failed")?;
    bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;

    Ok((cfg, store, identity))
}

/// Publish `members` (when given) and rotate the team key — the shared tail of
/// `rotate` and `remove`, moved verbatim out of `rotate` so both commands drive
/// one code path.
///
/// The manifest is published FIRST so the rotation's wrap gate already excludes
/// anyone removed. The two halves are NOT atomic; when the manifest landed but
/// the rotation then failed, the error names that half-applied state and the
/// way out, so the operator does not read the failure as "nothing happened".
///
/// `should_rotate = false` publishes `members` (if any) exactly as above, but
/// returns `Ok(())` immediately afterward WITHOUT calling `rotate_key` at
/// all — the membership shrink is never conditional, only the (possibly
/// pointless) rotation is. `rotate` (the direct command) always passes
/// `true`; `remove` computes it via [`removal_requires_rotation`] and prints
/// its own explanation before calling this function, so no message is
/// printed here for that case.
async fn publish_and_rotate(
    cfg: &Config,
    store: &MemoryStore,
    founder: &Identity,
    members: Option<BTreeSet<Ss58>>,
    should_rotate: bool,
) -> anyhow::Result<()> {
    use std::io::Write;

    // Before the membership publish, so a refusal here (not the founder, or a
    // member key made with another mnemonic) leaves nothing half-applied.
    if should_rotate && store.publish_rotating_founder_key(founder).await? == Joined::Now {
        let _ = writeln!(
            std::io::stdout(),
            "published this machine's member key (what `hippius-mem join` does), so the new \
             epoch is wrapped to it too"
        );
    }

    let published_members = members.is_some();
    if let Some(members) = members {
        let count = members.len();
        store.publish_membership(members).await?;
        tracing::info!(
            members = count,
            team = %store.team(),
            "published team membership manifest before rotating"
        );
    }

    if !should_rotate {
        return Ok(());
    }

    let outcome = match store.rotate_key(cfg.max_epoch).await {
        Ok(outcome) => outcome,
        // A rotation that fails after the membership publish leaves a
        // half-applied command: the shrunk manifest IS published (removed
        // members' ops already filtered) while the key is NOT rotated. Name
        // that state and the way out.
        Err(err) if published_members => {
            return Err(anyhow::Error::new(err).context(
                "the new membership WAS already published (removed members' ops are filtered), \
                 but the key is NOT yet rotated; fix the cause below, then run `hippius-mem \
                 rotate` (without --members) to finish (a `remove` re-run does not retry it)",
            ));
        }
        Err(err) => return Err(err.into()),
    };

    // Operator-facing output goes to the stdout handle directly (the workspace
    // denies the `print!` family); write failures are ignored like `members`'.
    // The ACTION REQUIRED block is the point of the command: until a member's
    // server restarts with its mnemonic, it refuses writes and shows none of the
    // post-rotation notes.
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "rotated team `{}` to epoch {}",
        store.team(),
        outcome.new_epoch
    );
    let _ = writeln!(
        out,
        "wrapped the new epoch key to {} member(s):",
        outcome.wrapped.len()
    );
    for member in &outcome.wrapped {
        let _ = writeln!(out, "  {}", member.as_str());
    }
    match outcome.key_check {
        Ok(KeyCheckPublished::Published { .. } | KeyCheckPublished::AlreadyPublished) => {}
        Ok(KeyCheckPublished::Refused) => tracing::warn!(
            "a key check for the new epoch already exists and is not this key's; run \
             `hippius-mem admin keycheck publish --replace` from this machine"
        ),
        Ok(KeyCheckPublished::KeyFailsOnNotes) => tracing::warn!(
            "no team-key check was published for the new epoch: this machine's new key \
             opens fewer than half of that epoch's oldest notes it tried; run \
             `hippius-mem doctor`, or `hippius-mem admin keycheck publish` from a machine \
             whose key opens those notes"
        ),
        Err(err) => tracing::warn!(
            error = %err,
            "could not publish the new epoch's team-key check; run `hippius-mem admin \
             keycheck publish` from this machine"
        ),
    }
    let _ = writeln!(
        out,
        "\n==================== ACTION REQUIRED ====================\n\
         Every member must now restart the MCP server, and any running\n\
         `dashboard` (it caches stores per vault), with HIPPIUS_MEM_MNEMONIC\n\
         set, so each loads the epoch {epoch} key. A process without it,\n\
         such as the `serve` daemon, cannot load the key: it refuses every\n\
         write and does not show notes sealed under epoch {epoch}.\n\
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

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (profile, store) = routed_store(&cfg).await?;
    crate::config::require_s3(&profile, "recover")?;

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
        team = %store.team(),
        new_founder = %manifest.founder.as_str(),
        "recovered the team founder through the recovery key"
    );
    Ok(())
}

/// Refuse EVERY argument to `recover`, with a pointed message when the
/// argument looks like an attempt to pass the recovery seed on argv
/// (`--seed`, `--recovery-seed`, or either with a `=value` suffix) — the
/// recovery seed is exactly as sensitive as an S3 secret and must never be
/// visible in `ps` to every user on this machine; mirrors `upgrade`'s
/// `--secret` rejection.
///
/// Neither refusal message ever echoes anything past the flag NAME. This
/// matters most for `--seed=<value>`/`--recovery-seed=<value>`: comparing
/// (and, on the generic fallback, printing) only the part before `=`
/// ensures a full-power recovery seed passed in that form is never leaked
/// into stderr, a log, or a terminal scrollback — even the generic
/// unknown-argument path, which previously echoed the whole argument
/// verbatim because it only recognized the exact `--seed`/`--recovery-seed`
/// forms.
fn reject_recover_args(args: &[String]) -> anyhow::Result<()> {
    let Some(first) = args.first() else {
        return Ok(());
    };

    // Strip a `=value` suffix BEFORE comparing or echoing: `split('=')`
    // always yields at least one element, so `flag_name` is `first` itself
    // when there is no `=`.
    let flag_name = first.split('=').next().unwrap_or(first.as_str());

    if flag_name == "--seed" || flag_name == "--recovery-seed" {
        bail!(
            "the recovery seed must never be passed via {flag_name}: it would be visible in \
             argv (`ps`) to every user on this machine; `recover` prompts for it on the \
             terminal, or reads one line from stdin when piped"
        );
    }
    bail!(
        "`recover` takes no arguments (got `{flag_name}`); the recovery seed is read from the \
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
        hippius_mem_core::hex::decode(seed_hex.trim())
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
    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (_profile, store) = routed_store(&cfg).await?;
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
/// their own servers restart with their mnemonic (the instruction `rotate` prints).
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
    // Every epoch with a wrap addressed to this member, so a rotation reaches
    // this machine without anyone raising `max_epoch` first. Listed, not
    // walked as a range: rotations step over epochs another object holds, and
    // a planted wrap at a huge epoch then costs one GET instead of a walk.
    // `max_epoch` is the range tried when the listing fails.
    let epochs = match store.wrapped_epochs().await {
        Ok(epochs) => epochs,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "could not list this member's wrapped keys; trying epochs up to max_epoch"
            );
            (0..=max_epoch).collect()
        }
    };
    match store.bootstrap_epoch_keys(&identity, &epochs).await {
        Ok(added) => {
            // Seal future writes under the newest epoch this member holds. Only
            // ever advances (never rolls back). A member who could not unwrap
            // the newest epoch has its writes refused (`EpochSuperseded`).
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
                tried = epochs.len(),
                "bootstrapped accessible epoch keys from the bucket"
            );
        }
        Err(err) => tracing::warn!(
            error = %err,
            "epoch-key bootstrap failed; serving with the configured key-ring"
        ),
    }
}

/// Best-effort: warn when the team's founder provisioned an epoch newer than
/// the one `store` seals under, so this process neither reads the notes
/// sealed under it nor writes (its writes are refused with
/// [`MemError::EpochSuperseded`]).
///
/// Needs no identity, only the `_keys/` listing (and a wrap GET when it names a
/// newer epoch), so it runs whether or not `HIPPIUS_MEM_MNEMONIC` is set: that
/// is the case it exists for, the `serve` daemon. A lookup failure is silent:
/// the write path reports its own.
pub(crate) async fn warn_if_epoch_superseded(store: &MemoryStore) {
    let sealing = store.current_epoch();
    if let Ok(Some(newest)) = store.newest_provisioned_epoch(sealing).await {
        let team = store.team();
        tracing::warn!(
            sealing,
            newest,
            "team {team} rotated its key to epoch {newest}, and this process holds keys only up \
             to epoch {sealing}: notes sealed under the newer key stay unreadable here and writes \
             are refused; set HIPPIUS_MEM_MNEMONIC to this member's mnemonic and restart (the \
             `serve` daemon cannot load rotated keys)"
        );
    }
}

/// Usage line shared by every `admin quarantine` refusal.
const QUARANTINE_USAGE: &str = "usage: admin quarantine [--remove <object-key> [--yes]]";

/// Usage line for the `admin` namespace router, naming every subcommand.
const ADMIN_USAGE: &str = "usage: admin quarantine [--remove <object-key> [--yes]] | admin \
     resign-anchors | admin keycheck publish [--replace] | admin share-epoch-keys";

/// Run `admin <subcommand>`: the operator-maintenance namespace — `quarantine`
/// (persistent op-log quarantine inspection and safety-railed remediation) and
/// `resign-anchors` (re-sign this author's own legacy unsigned anchor records
/// so the strict-mode readiness gauge can reach 0). A namespace rather than
/// more bare top-level verbs, so maintenance tooling stays visibly separated
/// from the everyday membership flow.
pub(crate) async fn admin(args: &[String]) -> anyhow::Result<()> {
    match args.split_first() {
        Some((sub, rest)) => match sub.as_str() {
            "quarantine" => quarantine(rest).await,
            "resign-anchors" => resign_anchors(rest).await,
            "keycheck" => keycheck(rest).await,
            "share-epoch-keys" => share_epoch_keys(rest).await,
            other => bail!("unknown admin subcommand `{other}`; {ADMIN_USAGE}"),
        },
        None => bail!("admin requires a subcommand; {ADMIN_USAGE}"),
    }
}

/// Run `admin share-epoch-keys`: as a member, give the founder what it needs
/// to load every epoch key it holds no wrap of (see
/// [`MemoryStore::share_epoch_keys`]), then tell the operator the founder's next
/// step.
///
/// The repair for an epoch minted by a founder that had no member key yet.
/// The founder opens its own founder-signed wrap with what this sends, so it
/// trusts no member for the key itself.
///
/// # Errors
///
/// Stray arguments, `HIPPIUS_MEM_MNEMONIC` unset or invalid, a store that
/// cannot be built, a team without a manifest, a founder without a member key,
/// an epoch the founder lacks whose wrap here could not be shared, or a failed
/// read or write.
async fn share_epoch_keys(args: &[String]) -> anyhow::Result<()> {
    use std::io::Write;

    reject_args("admin share-epoch-keys", args)?;
    let mnemonic = std::env::var("HIPPIUS_MEM_MNEMONIC").context(
        "`admin share-epoch-keys` requires HIPPIUS_MEM_MNEMONIC (this member's mnemonic), which \
         opens this member's wraps",
    )?;
    let identity = derive_identity(&mnemonic, HIPPIUS_SS58_PREFIX)
        .context("deriving the member identity from HIPPIUS_MEM_MNEMONIC failed")?;
    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (_profile, store) = routed_store(&cfg).await?;

    let KeyShares { shared, skipped } = store.share_epoch_keys(&identity).await?;
    let list = |epochs: &[u64]| {
        epochs
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    if !shared.is_empty() {
        let _ = writeln!(
            std::io::stdout(),
            "shared the key of epoch {} with the founder; the founder now runs \
             `hippius-mem provision` with HIPPIUS_MEM_MNEMONIC set, which loads and wraps it",
            list(&shared)
        );
    }
    if !skipped.is_empty() {
        bail!(
            "could not share epoch {}: this machine's wrap of it is not one the founder or the \
             recovery key signed, or does not open with HIPPIUS_MEM_MNEMONIC (the warnings \
             above say which). When every member's wrap of an epoch was replaced by one no \
             reader accepts (a member's `provision` before 0.8.1 did that), no member can \
             share it and the epoch cannot be recovered; see docs/TEAMS.md, \"Repair an epoch \
             the founder cannot read\"",
            list(&skipped)
        );
    }
    if shared.is_empty() {
        let _ = writeln!(
            std::io::stdout(),
            "the founder already holds a wrap of every epoch this machine holds; nothing to share"
        );
    }
    Ok(())
}

/// Run `admin keycheck publish [--replace]`: publish this machine's team-key
/// check for every epoch it holds a key for (the configured key, plus the
/// rotated epochs `HIPPIUS_MEM_MNEMONIC` unwraps).
///
/// For a team that predates the check, run once from the founder's machine:
/// on an epoch with no notes the probe below cannot tell a wrong key, so a
/// member with a mistyped key would publish a check that refuses the rest of
/// the team. Without
/// `--replace` an existing check is never overwritten, so a wrong one is
/// reported and the command fails. `--replace` overwrites it: the recovery
/// for a wrong or unusable check, and a decision that this machine's key IS
/// the team's, since every client with another key is refused afterwards.
/// Either way, an epoch whose oldest notes this machine's key mostly fails to
/// open is not published, and the command fails; an epoch with no notes is
/// published.
///
/// # Errors
///
/// A usage error, a store that cannot be built, a failed read or write, an
/// epoch whose published check is another key's (without `--replace`), or an
/// epoch whose notes this machine's key does not open.
async fn keycheck(args: &[String]) -> anyhow::Result<()> {
    let mode = parse_keycheck_args(args)?;

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (_profile, store) = routed_store(&cfg).await?;
    if let Ok(mnemonic) = std::env::var("HIPPIUS_MEM_MNEMONIC") {
        bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    }

    let unpublished = publish_key_checks(&store, mode).await?;
    let problems = keycheck_problems(&unpublished);
    if !problems.is_empty() {
        bail!("{}", problems.join("; "));
    }
    Ok(())
}

/// Parse `admin keycheck`'s arguments: `publish`, optionally `--replace`.
///
/// # Errors
///
/// A usage error for anything else, before any configuration is read.
fn parse_keycheck_args(args: &[String]) -> anyhow::Result<PublishKeyCheck> {
    match args {
        [verb] if verb == "publish" => Ok(PublishKeyCheck::IfAbsent),
        [verb, flag] if verb == "publish" && flag == "--replace" => Ok(PublishKeyCheck::Replace),
        _ => bail!("usage: admin keycheck publish [--replace]"),
    }
}

/// The epochs [`publish_key_checks`] published nothing for, by reason.
#[derive(Debug, Default)]
pub(crate) struct Unpublished {
    /// The team's check is another key's, or cannot be read.
    pub(crate) other_check: Vec<u64>,
    /// This machine's key fails to open most of the epoch's oldest notes.
    pub(crate) key_fails_on_notes: Vec<u64>,
}

/// Publish this store's key check for every epoch it holds a key for, logging
/// each outcome, and return the epochs it published nothing for.
///
/// # Errors
///
/// Whatever [`MemoryStore::publish_team_key_check`] reports.
pub(crate) async fn publish_key_checks(
    store: &MemoryStore,
    mode: PublishKeyCheck,
) -> anyhow::Result<Unpublished> {
    let mut unpublished = Unpublished::default();
    for epoch in store.held_epochs() {
        match store
            .publish_team_key_check(epoch, mode)
            .await
            .with_context(|| format!("publishing the team-key check for epoch {epoch} failed"))?
        {
            KeyCheckPublished::Published {
                create_only: Some(CreateOnly::Enforced),
            } => tracing::info!(epoch, "published the team-key check"),
            KeyCheckPublished::Published { create_only: None } => {
                tracing::info!(epoch, "replaced the team-key check with this key's");
            }
            KeyCheckPublished::Published {
                create_only: Some(CreateOnly::NotEnforced),
            } => tracing::warn!(
                epoch,
                "published the team-key check, but the storage gateway does not enforce \
                 create-only writes, so a publisher with another key at the same moment could \
                 have overwritten it or been overwritten; run `hippius-mem doctor` from both \
                 machines to confirm"
            ),
            KeyCheckPublished::AlreadyPublished => {
                tracing::info!(epoch, "the team-key check is already this key's");
            }
            KeyCheckPublished::Refused => unpublished.other_check.push(epoch),
            KeyCheckPublished::KeyFailsOnNotes => unpublished.key_fails_on_notes.push(epoch),
        }
    }
    Ok(unpublished)
}

/// Publish the team-key check of every epoch `store` holds a key for where
/// none exists, from a machine that holds the team's keys by construction (the
/// founder's `provision`, or `upgrade` of the vault's only user). A check that
/// disagrees is reported, never replaced. Best effort: every failure is a
/// warning naming `admin keycheck publish`.
pub(crate) async fn publish_founder_key_checks(store: &MemoryStore) {
    match publish_key_checks(store, PublishKeyCheck::IfAbsent).await {
        Ok(unpublished) => {
            for (epochs, message) in provision_unpublished_warnings(&unpublished) {
                tracing::warn!(epochs = ?epochs, "{message}");
            }
        }
        Err(err) => tracing::warn!(
            error = %format!("{err:#}"),
            "could not publish the team-key check; run `hippius-mem admin keycheck publish`"
        ),
    }
}

/// Warning lines `provision` emits for epochs it published no check for.
/// Extracted so a unit test can pin the empty/non-empty conditions without
/// loading a configured store.
fn provision_unpublished_warnings(unpublished: &Unpublished) -> Vec<(Vec<u64>, String)> {
    let mut warnings = Vec::new();
    if !unpublished.other_check.is_empty() {
        warnings.push((
            unpublished.other_check.clone(),
            String::from(
                "the team's published key check for these epochs is not this founder's key; \
                 if this machine's key is the team's, run `hippius-mem admin keycheck \
                 publish --replace`",
            ),
        ));
    }
    if !unpublished.key_fails_on_notes.is_empty() {
        warnings.push((
            unpublished.key_fails_on_notes.clone(),
            String::from(
                "no team-key check was published for these epochs: this founder's key opens \
                 fewer than half of their oldest notes it tried; run `hippius-mem doctor`",
            ),
        ));
    }
    warnings
}

/// Error messages `admin keycheck publish` returns for epochs it published
/// nothing for. Extracted so a unit test can pin the empty/non-empty conditions
/// without loading a configured store.
fn keycheck_problems(unpublished: &Unpublished) -> Vec<String> {
    let mut problems = Vec::new();
    if !unpublished.key_fails_on_notes.is_empty() {
        problems.push(format!(
            "this machine's team key opens fewer than half of the oldest notes of epoch(s) {:?} \
             it tried, so it is probably not the team's key, and publishing it would refuse the \
             clients whose key those notes were sealed under; nothing was published for them. \
             Fix team_key_hex (or HIPPIUS_MEM_TEAM_KEY_HEX, which overrides it when set) and run \
             `hippius-mem doctor`, or publish from a machine whose key opens the team's notes. \
             If this machine's key is the team's and those notes were sealed under another key, \
             the founder's `hippius-mem rotate` moves the team to a new epoch, whose check is \
             published",
            unpublished.key_fails_on_notes
        ));
    }
    if !unpublished.other_check.is_empty() {
        problems.push(format!(
            "the team's published key check for epoch(s) {:?} is another key's (or cannot be \
             read), so it was left alone; if this machine's key is the team's, rerun with \
             --replace, and otherwise fix team_key_hex",
            unpublished.other_check
        ));
    }
    problems
}

/// Run `admin resign-anchors`: re-sign THIS author's own legacy (unsigned)
/// anchor records in place, so `reconcile`'s `unsigned_anchor_records`
/// readiness gauge can actually reach 0 and `require_signed_anchors` becomes
/// safely enableable for a team with pre-signing history.
///
/// Thin wrapper over [`MemoryStore::resign_anchor_records`], which holds the
/// whole semantics: only this author's records are touched (each member runs
/// this themselves — only they hold the attesting signer), a record is
/// rewritten at its SAME key as a byte-superset (the legacy layout plus the
/// `sig` field), tampered records are skipped-and-warned rather than
/// laundered, and every resigned record is verified to read back validly
/// signed before the run reports success.
///
/// Output is counts only, via `tracing` like the rest of this module —
/// nothing secret crosses stdout/stderr. Like `quarantine`, this deliberately
/// skips [`bootstrap_epochs`]: nothing here decrypts a note, so no mnemonic
/// or epoch key is needed.
async fn resign_anchors(args: &[String]) -> anyhow::Result<()> {
    reject_args("admin resign-anchors", args)?;

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (_profile, store) = routed_store(&cfg).await?;
    let report = store.resign_anchor_records().await?;

    tracing::info!(
        resigned = report.resigned,
        already_signed = report.already_signed,
        invalid_skipped = report.invalid_skipped,
        other_author = report.other_author,
        team = %store.team(),
        "re-signed this author's legacy anchor records (every resigned record verified \
         to read back validly signed)"
    );
    if report.invalid_skipped > 0 {
        tracing::warn!(
            invalid_skipped = report.invalid_skipped,
            "some of this author's records carry signatures that do NOT verify — that is \
             tamper, and re-signing would launder it, so they were left untouched; \
             investigate the bucket before enabling require_signed_anchors"
        );
    }
    if report.other_author > 0 {
        tracing::info!(
            other_author = report.other_author,
            "records by other authors were skipped: each member runs `admin resign-anchors` \
             themselves (only they hold their signer); watch `reconcile`'s \
             unsigned_anchor_records reach 0 before enabling require_signed_anchors"
        );
    }
    Ok(())
}

/// Parsed `admin quarantine` arguments.
#[derive(Debug)]
struct QuarantineArgs {
    /// The op object key to delete, or `None` for a bare inspection.
    remove: Option<String>,
    /// Whether the delete is confirmed; without it `--remove` is a dry-run.
    yes: bool,
}

/// Parse `admin quarantine`'s arguments: an optional `--remove <object-key>`
/// plus an optional `--yes` confirming it.
///
/// `--yes` without `--remove` is refused — it confirms nothing, and silently
/// accepting it would train operators to type `--yes` reflexively. Every
/// refusal fires BEFORE any store/S3 operation runs, the same loud-failure
/// rule the other parsers in this module follow.
fn parse_quarantine_args(args: &[String]) -> anyhow::Result<QuarantineArgs> {
    let mut remove = None;
    let mut yes = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--remove" => remove = Some(next_value(&mut iter, "--remove")?),
            "--yes" => yes = true,
            other => bail!("unknown quarantine argument `{other}`; {QUARANTINE_USAGE}"),
        }
    }
    if yes && remove.is_none() {
        bail!("--yes only confirms --remove <object-key>; {QUARANTINE_USAGE}");
    }
    Ok(QuarantineArgs { remove, yes })
}

/// Run `admin quarantine`: inspect a persistent op-log quarantine, or —
/// with `--remove <object-key> --yes` — delete exactly one fork-losing op
/// object behind the core's safety rails.
///
/// Everything printed is SIGNED PLAINTEXT op metadata (authors, object keys,
/// lamports, op ids, hashes) — ops never carry note content, so the report
/// crosses no privacy boundary; output goes through `tracing` like the rest
/// of this module. Like `gc`, this deliberately skips
/// [`bootstrap_epochs`]: nothing here decrypts a note, so no mnemonic or
/// epoch key is needed for a complete view.
async fn quarantine(args: &[String]) -> anyhow::Result<()> {
    let parsed = parse_quarantine_args(args)?;

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;
    let (_profile, store) = routed_store(&cfg).await?;

    match parsed.remove {
        None => inspect_and_report(&store).await,
        Some(object_key) => remove_with_plan(&store, &object_key, parsed.yes).await,
    }
}

/// The bare `admin quarantine` inspection: print the classified report, or
/// "no quarantine" when every author's chain is whole.
async fn inspect_and_report(store: &MemoryStore) -> anyhow::Result<()> {
    let details = store.inspect_quarantine().await?;
    if details.is_empty() {
        tracing::info!("no quarantine: every author's op-log chain is whole");
        return Ok(());
    }
    for detail in &details {
        report_author(detail);
    }
    tracing::info!(
        "next step: `admin quarantine --remove <object-key> --yes` deletes ONE removable \
         (fork-losing, leaf) object; gap-classified drops are honest writes whose \
         predecessor is missing and are never removable — restore the missing object, \
         or wait if the listing is merely lagging. A fork loser can be another \
         same-identity machine's un-synced honest writes; the removal plan warns \
         about that (and about permanence) before --yes"
    );
    Ok(())
}

/// Print one quarantined author's classified report: what survives, then
/// every dropped op with enough coordinates to name exactly one bucket
/// object.
fn report_author(detail: &QuarantinedAuthorDetail) {
    if let Some(tip) = &detail.surviving_tip {
        tracing::info!(
            author = %detail.author.as_str(),
            classification = %detail.classification,
            surviving_ops = detail.surviving_ops,
            tip_object_key = %tip.object_key,
            tip_lamport = tip.lamport,
            tip_op_id = %tip.op_id,
            tip_op_hash = %tip.op_hash.to_hex(),
            "quarantined author — the surviving chain keeps this tip"
        );
    } else {
        tracing::warn!(
            author = %detail.author.as_str(),
            classification = %detail.classification,
            "quarantined author with NO surviving genesis-rooted ops (the chain root \
             itself is absent from the listing)"
        );
    }
    for dropped in &detail.dropped {
        tracing::info!(
            author = %detail.author.as_str(),
            object_key = %dropped.object_key,
            lamport = dropped.lamport,
            op_id = %dropped.op_id,
            op_hash = %dropped.op_hash.to_hex(),
            prev_op_hash = %dropped.prev_op_hash.to_hex(),
            class = %dropped.class,
            removable = dropped.class == DropClass::ForkLoser && !dropped.has_listed_children,
            "dropped op"
        );
    }
}

/// Plan-output warning for a gap-classified drop: the core rails WILL refuse
/// its removal, and the plan says so instead of reading as an endorsement.
const GAP_DROP_WARNING: &str = "this drop is gap-classified: removal WILL refuse — it is an honest signed \
     write whose predecessor object is missing, and deleting it destroys real \
     data without healing the gap";

/// Plan-output warning for a fork loser that still has listed successors: the
/// leaf-first rail WILL refuse it until the branch below it is removed.
const NON_LEAF_WARNING: &str = "this fork loser still has listed successors: removal WILL refuse — delete \
     the branch leaf-first (the dropped ops marked removable)";

/// Plan-output warning printed for EVERY fork loser, before `--yes` is acted
/// on. Honesty the classification cannot provide mechanically: "fork loser"
/// only proves the branch lost convergence over THIS listing — it cannot say
/// who wrote it. Two machines writing under one identity is routine
/// (MCP registration is user-global), and an un-synced machine's genuine
/// writes lose the branch selection exactly like a planted fork.
const FORK_LOSER_PERMANENCE_WARNING: &str = "before --yes: a fork-losing branch can be UN-SYNCED HONEST WRITES from \
     another machine writing under this same identity — no read of the bucket \
     can tell that apart from a planted fork. Confirm every machine using this \
     identity has synced (or the lost writes were re-issued) before deleting; \
     deletion is permanent (the op object now, and eventually the note \
     ciphertext it names, once gc finds that blob unreferenced)";

/// The honesty warnings the removal plan prints for one dropped op — pure, so
/// a unit test pins the plan's warning selection without a store or a tracing
/// capture.
///
/// Every fork loser carries [`FORK_LOSER_PERMANENCE_WARNING`], leaf or not:
/// a non-leaf is refused THIS run, but the operator dismantling the branch
/// leaf-first is on their way to deleting it, so the permanence warning must
/// not wait for the final step.
fn plan_warnings(class: DropClass, has_listed_children: bool) -> Vec<&'static str> {
    match class {
        DropClass::GapOrphan => vec![GAP_DROP_WARNING],
        DropClass::ForkLoser if has_listed_children => {
            vec![NON_LEAF_WARNING, FORK_LOSER_PERMANENCE_WARNING]
        }
        DropClass::ForkLoser => vec![FORK_LOSER_PERMANENCE_WARNING],
    }
}

/// The `--remove` flow: print exactly what would be removed and what
/// survives, then — only with `--yes` — delete it through the core rails and
/// report whether the author's chain is whole again.
///
/// Without `--yes` this is a clearly-labeled dry-run: the plan prints and
/// nothing is touched. The plan lookup here is presentation only; the
/// authoritative decision is [`MemoryStore::remove_quarantined_op`]'s own
/// double-read (so even a stale plan can never cause a wrong delete — the
/// core path re-fetches and re-verifies the candidate on each of its own
/// reads regardless of what this plan read cached).
async fn remove_with_plan(store: &MemoryStore, object_key: &str, yes: bool) -> anyhow::Result<()> {
    let details = store.inspect_quarantine().await?;
    let planned = details.iter().find_map(|detail| {
        detail
            .dropped
            .iter()
            .find(|dropped| dropped.object_key == object_key)
            .map(|dropped| (detail, dropped))
    });
    let Some((detail, dropped)) = planned else {
        bail!(
            "{object_key} is not among the dropped ops of the current verified read — \
             nothing was deleted. Run `admin quarantine` (no flags) to list the \
             removable objects"
        );
    };

    tracing::info!(
        author = %detail.author.as_str(),
        object_key = %dropped.object_key,
        lamport = dropped.lamport,
        op_id = %dropped.op_id,
        op_hash = %dropped.op_hash.to_hex(),
        prev_op_hash = %dropped.prev_op_hash.to_hex(),
        class = %dropped.class,
        "removal plan: this op object would be deleted"
    );
    report_author(detail);
    // An honest plan warns when the core rails are going to refuse, and warns
    // about permanence/provenance before a delete the rails will allow —
    // instead of letting the dry-run read as an endorsement. The selection
    // lives in `plan_warnings` so a test pins it.
    for warning in plan_warnings(dropped.class, dropped.has_listed_children) {
        tracing::warn!("{warning}");
    }

    if !yes {
        tracing::info!(
            "DRY-RUN: nothing was deleted; re-run with --yes to remove the object above"
        );
        return Ok(());
    }

    let removal = store.remove_quarantined_op(object_key).await?;
    if removal.author_chain_whole {
        tracing::info!(
            author = %removal.author.as_str(),
            object_key = %removal.removed.object_key,
            "removed the op object; the author's chain now reads WHOLE"
        );
    } else {
        tracing::warn!(
            author = %removal.author.as_str(),
            object_key = %removal.removed.object_key,
            remaining_dropped_ops = removal.remaining_dropped_ops,
            "removed the op object, but the author is still quarantined — run \
             `admin quarantine` again and remove the next leaf"
        );
    }
    Ok(())
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

/// Take the next argument as `flag`'s value, or error naming the flag.
///
/// A value starting with `--` is refused rather than consumed: no legitimate
/// value here ever looks like a flag (op-log object keys start with the team
/// prefix, member lists with an SS58 address), while a flag in value position
/// means the operator omitted the value. Before this check,
/// `admin quarantine --remove --yes` parsed as a dry-run against the literal
/// object key `--yes` — silently dropping BOTH the key and the confirmation.
fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> anyhow::Result<String> {
    let value = iter
        .next()
        .with_context(|| format!("{flag} requires a value"))?;
    if value.starts_with("--") {
        bail!("{flag} requires a value, but found the flag `{value}` instead");
    }
    Ok(value.clone())
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
        BlobStore, DropClass, HashEmbedder, InMemoryIndex, MemError, MemberKey, MemoryBlobStore,
        MemoryStore, NoopAnchor, OpLogStore, PublishKeyCheck, SecretKey, Signer, Sr25519Signer,
        Ss58, TeamManifest, derive_identity, provision_team_key, publish_member_key,
        signer_from_mnemonic,
    };

    use super::{
        HIPPIUS_SS58_PREFIX, RemovalStep, RemoveRefusal, Unpublished, admin, bootstrap_epochs,
        keycheck_problems, parse_keycheck_args, parse_members, parse_provision_args,
        parse_publish_membership_args, parse_quarantine_args, parse_remove_args, parse_rotate_args,
        pending_revoke_reminder, plan_removal, plan_warnings, print_recovery_outcome,
        print_recovery_seed, provision_unpublished_warnings, publish_and_rotate,
        publish_key_checks, reject_args, reject_recover_args, removal_requires_rotation,
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

    // ---- `admin quarantine` arg parsing / routing ----

    #[test]
    fn quarantine_args_default_to_inspection() -> anyhow::Result<()> {
        let parsed = parse_quarantine_args(&[])?;
        assert!(parsed.remove.is_none(), "bare = inspect, nothing to remove");
        assert!(!parsed.yes);
        Ok(())
    }

    #[test]
    fn quarantine_args_parse_remove_with_yes() -> anyhow::Result<()> {
        let args = vec![
            "--remove".to_owned(),
            "team/_oplog/some-op-object".to_owned(),
            "--yes".to_owned(),
        ];
        let parsed = parse_quarantine_args(&args)?;
        assert_eq!(parsed.remove.as_deref(), Some("team/_oplog/some-op-object"));
        assert!(parsed.yes);
        Ok(())
    }

    #[test]
    fn quarantine_args_without_yes_stay_a_dry_run() -> anyhow::Result<()> {
        let args = vec![
            "--remove".to_owned(),
            "team/_oplog/some-op-object".to_owned(),
        ];
        let parsed = parse_quarantine_args(&args)?;
        assert_eq!(parsed.remove.as_deref(), Some("team/_oplog/some-op-object"));
        assert!(
            !parsed.yes,
            "--remove without --yes must parse as a dry-run"
        );
        Ok(())
    }

    #[test]
    fn quarantine_args_reject_junk() {
        // Each refusal fires BEFORE any store/S3 operation runs (the same
        // loud-failure rule every parser here follows): --yes without
        // --remove confirms nothing, --remove needs a value, and an unknown
        // flag is most likely a typo of a destructive command.
        assert!(parse_quarantine_args(&["--yes".to_owned()]).is_err());
        assert!(parse_quarantine_args(&["--remove".to_owned()]).is_err());
        assert!(parse_quarantine_args(&["--bogus".to_owned()]).is_err());
    }

    #[test]
    fn quarantine_remove_does_not_swallow_a_flag_as_its_value() {
        // `admin quarantine --remove --yes` once parsed as a DRY-RUN against
        // the literal object key "--yes": the confirmation flag silently
        // became the key and the confirmation itself vanished. A value
        // starting with `--` can never be a real op-log object key (those
        // start with the team prefix), so it must refuse, naming the flag
        // that is missing its value.
        let err = parse_quarantine_args(&["--remove".to_owned(), "--yes".to_owned()])
            .expect_err("--remove must not swallow --yes as its object key");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--remove"),
            "the refusal must name the flag missing its value: {msg}"
        );
    }

    #[test]
    fn members_flags_do_not_swallow_a_flag_as_their_value() {
        // The same trap at every other `next_value` call site: a
        // `--`-prefixed token in value position is a flag, never data.
        let err = parse_rotate_args(&["--members".to_owned(), "--yes".to_owned()])
            .expect_err("rotate --members must not swallow a flag as its value");
        assert!(
            format!("{err:#}").contains("--members"),
            "the refusal must name the flag missing its value: {err:#}"
        );
        let err = parse_publish_membership_args(&["--members".to_owned(), "--members".to_owned()])
            .expect_err("publish-membership --members must not swallow a flag as its value");
        assert!(
            format!("{err:#}").contains("--members"),
            "the refusal must name the flag missing its value: {err:#}"
        );
    }

    #[test]
    fn removal_plan_warns_a_fork_loser_may_be_an_unsynced_machines_writes() {
        // The plan output's honesty floor (printed before --yes is acted on):
        // a "fork loser" is only provably excluded from convergence over THIS
        // listing — it may be un-synced honest writes from another machine
        // under the same identity, the double-read cannot tell the two apart,
        // and deletion is permanent. The operator must see that BEFORE
        // confirming.
        let warnings = plan_warnings(DropClass::ForkLoser, false).join("\n");
        assert!(
            warnings.contains("another machine"),
            "the plan must warn the branch may be another machine's writes: {warnings}"
        );
        assert!(
            warnings.contains("synced"),
            "the plan must tell the operator to confirm the other machine synced: {warnings}"
        );
        assert!(
            warnings.contains("permanent"),
            "the plan must state that deletion is permanent: {warnings}"
        );
    }

    #[test]
    fn removal_plan_still_warns_refused_classes_and_keeps_permanence_on_non_leaves() {
        let gap = plan_warnings(DropClass::GapOrphan, false).join("\n");
        assert!(
            gap.contains("gap-classified"),
            "a gap drop's plan must predict the refusal: {gap}"
        );
        let non_leaf = plan_warnings(DropClass::ForkLoser, true).join("\n");
        assert!(
            non_leaf.contains("leaf-first"),
            "a non-leaf fork loser's plan must predict the leaf-first refusal: {non_leaf}"
        );
        assert!(
            non_leaf.contains("permanent"),
            "the permanence warning covers every fork loser — the operator dismantling \
             the branch leaf-first will reach this one: {non_leaf}"
        );
    }

    #[tokio::test]
    async fn admin_rejects_unknown_and_missing_subcommands() {
        // Both refusals fire before any config/store work, so they are safe to
        // exercise directly.
        let err = admin(&[])
            .await
            .expect_err("admin without a subcommand must refuse");
        assert!(
            err.to_string().contains("quarantine") && err.to_string().contains("resign-anchors"),
            "the refusal names every available subcommand: {err}"
        );
        let err = admin(&["bogus".to_owned()])
            .await
            .expect_err("an unknown admin subcommand must refuse");
        assert!(
            err.to_string().contains("bogus"),
            "the refusal names the offender: {err}"
        );
    }

    #[tokio::test]
    async fn keycheck_accepts_only_publish_with_an_optional_replace() {
        for args in [&[][..], &["publish", "--force"][..], &["show"][..]] {
            let mut argv = vec!["keycheck".to_owned()];
            argv.extend(args.iter().map(|arg| (*arg).to_owned()));
            let err = admin(&argv)
                .await
                .expect_err("a malformed keycheck invocation must refuse");
            assert!(
                err.to_string()
                    .contains("admin keycheck publish [--replace]"),
                "the refusal shows the usage: {err}"
            );
        }
    }

    #[tokio::test]
    async fn resign_anchors_rejects_stray_arguments() {
        // `admin resign-anchors` takes no arguments; a typo or a flag meant
        // for another command must fail loudly BEFORE any store/S3 operation
        // runs — the same rule every parser in this module follows.
        let err = admin(&["resign-anchors".to_owned(), "--bogus".to_owned()])
            .await
            .expect_err("a stray resign-anchors argument must refuse");
        assert!(
            err.to_string().contains("--bogus"),
            "the refusal names the offender: {err}"
        );
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

    #[test]
    fn keycheck_parses_publish_and_replace() -> anyhow::Result<()> {
        let args = |list: &[&str]| list.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            parse_keycheck_args(&args(&["publish"]))?,
            hippius_mem_core::PublishKeyCheck::IfAbsent
        );
        assert_eq!(
            parse_keycheck_args(&args(&["publish", "--replace"]))?,
            hippius_mem_core::PublishKeyCheck::Replace
        );
        assert!(parse_keycheck_args(&args(&["replace", "--publish"])).is_err());
        Ok(())
    }

    #[test]
    fn keycheck_problems_follow_each_unpublished_reason() {
        let none = Unpublished {
            other_check: vec![],
            key_fails_on_notes: vec![],
        };
        assert!(keycheck_problems(&none).is_empty());
        assert!(provision_unpublished_warnings(&none).is_empty());

        let failed = Unpublished {
            other_check: vec![],
            key_fails_on_notes: vec![0],
        };
        let problems = keycheck_problems(&failed);
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].contains("opens fewer than half"),
            "{problems:?}"
        );
        let warnings = provision_unpublished_warnings(&failed);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].0, [0]);
        assert!(warnings[0].1.contains("opens fewer than half"));

        let other = Unpublished {
            other_check: vec![1],
            key_fails_on_notes: vec![],
        };
        let problems = keycheck_problems(&other);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("is another key's"), "{problems:?}");
        let warnings = provision_unpublished_warnings(&other);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].0, [1]);
        assert!(warnings[0].1.contains("not this founder's key"));

        let both = Unpublished {
            other_check: vec![2],
            key_fails_on_notes: vec![0],
        };
        assert_eq!(keycheck_problems(&both).len(), 2);
        assert_eq!(provision_unpublished_warnings(&both).len(), 2);
    }

    /// `publish_key_checks` sorts each epoch it published nothing for by
    /// reason: another key's check (without `--replace`), or a key that does
    /// not open the epoch's notes (with it, too).
    #[tokio::test]
    async fn publish_key_checks_reports_the_epochs_it_left_unpublished() -> anyhow::Result<()> {
        let bucket = Arc::new(MemoryBlobStore::default());
        let first = epoch0_store(&bucket)?;
        let published = publish_key_checks(&first, PublishKeyCheck::IfAbsent).await?;
        assert!(published.other_check.is_empty() && published.key_fails_on_notes.is_empty());
        first
            .remember(hippius_mem_core::RememberInput {
                note_type: hippius_mem_core::NoteType::Decision,
                repo: hippius_mem_core::RepoScope::Global,
                tags: BTreeSet::new(),
                summary: "a note the first key opens".to_owned(),
                body: "body".to_owned(),
                force: true,
            })
            .await?;

        let blob: Arc<dyn BlobStore> = bucket.clone();
        let other_key = MemoryStore::new(
            blob.clone(),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(blob),
            Arc::new(NoopAnchor),
            Arc::new(signer_from_mnemonic(MNEMONIC, HIPPIUS_SS58_PREFIX)?),
            std::collections::BTreeMap::from([(0_u64, SecretKey::from_bytes([2u8; 32]))]),
            0,
            TEAM.to_owned(),
            16,
        );
        let if_absent = publish_key_checks(&other_key, PublishKeyCheck::IfAbsent).await?;
        assert_eq!(if_absent.other_check, [0]);
        assert!(if_absent.key_fails_on_notes.is_empty());

        let replace = publish_key_checks(&other_key, PublishKeyCheck::Replace).await?;
        assert!(replace.other_check.is_empty());
        assert_eq!(replace.key_fails_on_notes, [0]);
        Ok(())
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
            &signer,
        )
        .await?;
        provision_team_key(
            bucket.as_ref(),
            TEAM,
            &SecretKey::from_bytes([2u8; 32]),
            1,
            std::slice::from_ref(&member_key),
            None,
            &signer,
        )
        .await?;

        let store = epoch0_store(&bucket)?;
        // `max_epoch` 0: the fallback range stops at epoch 0, so epoch 1 comes
        // only from the listing of this member's wraps.
        bootstrap_epochs(&store, MNEMONIC, 0).await;
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

    /// A bucket that refuses every wrap write, so a rotation fails after the
    /// membership publish.
    struct RefusesWraps(MemoryBlobStore);

    #[async_trait::async_trait]
    impl BlobStore for RefusesWraps {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.0.put(key, bytes).await
        }

        async fn put_if_absent(
            &self,
            key: &str,
            bytes: Vec<u8>,
        ) -> Result<hippius_mem_core::CreateOutcome, MemError> {
            if key.starts_with(&format!("{TEAM}/_keys/")) {
                return Err(MemError::Storage("wrap writes are refused here".to_owned()));
            }
            self.0.put_if_absent(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.0.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.0.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.0.delete(key).await
        }
    }

    /// A rotation that fails after the membership publish says the membership
    /// landed and how to finish, and keeps the cause in the chain.
    #[tokio::test]
    async fn a_rotation_failing_after_the_publish_names_the_half_applied_state()
    -> anyhow::Result<()> {
        let blob: Arc<dyn BlobStore> = Arc::new(RefusesWraps(MemoryBlobStore::default()));
        let store = MemoryStore::new(
            Arc::clone(&blob),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(Arc::clone(&blob)),
            Arc::new(NoopAnchor),
            Arc::new(signer_from_mnemonic(MNEMONIC, HIPPIUS_SS58_PREFIX)?),
            std::collections::BTreeMap::from([(0_u64, SecretKey::from_bytes([1u8; 32]))]),
            0,
            TEAM.to_owned(),
            16,
        );
        let cfg = rotation_test_config();
        store
            .publish_membership(BTreeSet::from([Ss58::new(DEV)?]))
            .await?;
        let founder = derive_identity(MNEMONIC, HIPPIUS_SS58_PREFIX)?;
        let roster = Some(BTreeSet::from([founder.ss58.clone()]));

        let err = publish_and_rotate(&cfg, &store, &founder, roster, true)
            .await
            .expect_err("the wrap writes are refused");
        assert!(
            format!("{err:#}").contains("membership WAS already published"),
            "{err:#}"
        );
        assert!(
            err.chain().any(|cause| matches!(
                cause.downcast_ref::<MemError>(),
                Some(MemError::Storage(_))
            )),
            "{err:#}"
        );
        assert!(
            blob.list(&format!("{TEAM}/_keys/")).await?.is_empty(),
            "no wrap is written"
        );
        Ok(())
    }

    #[tokio::test]
    async fn publish_and_rotate_skips_rotation_when_should_rotate_is_false() -> anyhow::Result<()> {
        // I2 fix: a completed-removal re-run (or a bogus never-a-member
        // target) must not mint a gratuitous new epoch just because `remove`
        // was invoked again -- `should_rotate = false` must publish (when
        // asked) but never call `rotate_key`, so the write epoch is
        // untouched.
        let bucket = Arc::new(MemoryBlobStore::default());
        let store = epoch0_store(&bucket)?;
        let cfg = rotation_test_config();
        let founder = derive_identity(MNEMONIC, HIPPIUS_SS58_PREFIX)?;
        let roster = Some(BTreeSet::from([founder.ss58.clone()]));

        publish_and_rotate(&cfg, &store, &founder, roster, false).await?;

        assert_eq!(
            store.current_epoch(),
            0,
            "should_rotate = false must never advance the write epoch"
        );
        Ok(())
    }

    #[test]
    fn removal_requires_rotation_is_true_for_a_real_removal() {
        let step = RemovalStep::Publish(BTreeSet::new());
        assert!(
            removal_requires_rotation(&step),
            "a real removal (the roster shrank in this invocation) must always rotate"
        );
    }

    #[test]
    fn removal_requires_rotation_is_false_when_already_excluded() {
        assert!(
            !removal_requires_rotation(&RemovalStep::AlreadyExcluded),
            "nothing changed in this invocation, so no rotation is needed"
        );
    }

    #[tokio::test]
    async fn remove_rotates_a_bundle_provisioned_target_never_wrapped_in_keys() -> anyhow::Result<()>
    {
        // Task 3 (security) regression: `join --bundle` hands a member
        // `team_key_hex` directly (see `join_bundle`), so a
        // bundle-provisioned member NEVER appears in any `_keys/` wrap. The
        // old gate (`target_still_holds_current_epoch_key`, now removed)
        // read that absence as "already excluded" and skipped rotation
        // entirely, leaving such a member able to decrypt every future note
        // with their epoch-0 key forever. The fixed gate
        // (`removal_requires_rotation`) instead asks whether THIS
        // invocation's republish actually shrank the roster -- which it
        // did here -- independent of `_keys/`.
        let bucket = Arc::new(MemoryBlobStore::default());
        let store = epoch0_store(&bucket)?;
        let cfg = rotation_test_config();

        // The founder publishes a MemberKey so `rotate_key` has someone to
        // wrap the new epoch to; the target never does -- a
        // bundle-provisioned member already holds the team key and need
        // not `join`.
        let founder_signer = signer_from_mnemonic(MNEMONIC, HIPPIUS_SS58_PREFIX)?;
        let founder_identity = derive_identity(MNEMONIC, HIPPIUS_SS58_PREFIX)?;
        let founder_key = MemberKey::create_signed(&founder_signer, &founder_identity);
        publish_member_key(bucket.as_ref(), TEAM, &founder_key).await?;

        let target = Ss58::new(DEV)?;
        store
            .publish_membership(BTreeSet::from([target.clone()]))
            .await?;
        let manifest = store.membership_manifest().await?;

        let step = plan_removal(manifest, &target)
            .map_err(|refusal| anyhow::anyhow!("unexpected refusal: {refusal}"))?;
        assert!(
            matches!(step, RemovalStep::Publish(_)),
            "the target was in the roster; expected a Publish step"
        );
        let should_rotate = removal_requires_rotation(&step);
        assert!(
            should_rotate,
            "a real removal must always rotate, independent of _keys/ membership"
        );

        let RemovalStep::Publish(remaining) = step else {
            anyhow::bail!("expected a Publish step");
        };
        publish_and_rotate(
            &cfg,
            &store,
            &founder_identity,
            Some(remaining),
            should_rotate,
        )
        .await?;

        assert_eq!(
            store.current_epoch(),
            1,
            "removing a bundle-provisioned member (never in _keys/) must still rotate the epoch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn remove_does_not_rotate_when_the_target_is_already_off_the_roster() -> anyhow::Result<()>
    {
        // Task 12 idempotency, preserved by the fix: re-running `remove
        // <ss58>` after a PRIOR run already published the shrink AND
        // rotated (or the address was never a member) must not mint a
        // gratuitous new epoch just because the operator ran the command
        // again.
        let bucket = Arc::new(MemoryBlobStore::default());
        let store = epoch0_store(&bucket)?;
        let cfg = rotation_test_config();

        let target = Ss58::new(DEV)?;
        // The roster already excludes the target -- exactly the shape a
        // completed prior removal leaves behind.
        store.publish_membership(BTreeSet::new()).await?;
        let manifest = store.membership_manifest().await?;

        let step = plan_removal(manifest, &target)
            .map_err(|refusal| anyhow::anyhow!("unexpected refusal: {refusal}"))?;
        assert_eq!(step, RemovalStep::AlreadyExcluded);
        let should_rotate = removal_requires_rotation(&step);
        assert!(!should_rotate, "an already-excluded target must not rotate");

        let founder = derive_identity(MNEMONIC, HIPPIUS_SS58_PREFIX)?;
        publish_and_rotate(&cfg, &store, &founder, None, should_rotate).await?;

        assert_eq!(
            store.current_epoch(),
            0,
            "re-running remove after full completion must not rotate the epoch"
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
    fn recover_rejects_the_seed_equals_form_without_echoing_the_value() -> anyhow::Result<()> {
        // Finding #9b: `--seed=<value>` (as opposed to the exact `--seed`
        // form) used to fall through to the generic unknown-argument
        // refusal, which echoed the WHOLE argument -- including the
        // full-power recovery seed -- into stderr. It must instead hit the
        // same pointed refusal as bare `--seed`, and the seed value itself
        // must never appear in the rendered error.
        let seed_value = "deadbeef".repeat(8); // 64 hex chars, a plausible seed shape
        for flag in ["--seed", "--recovery-seed"] {
            let args = vec![format!("{flag}={seed_value}")];
            let Err(err) = reject_recover_args(&args) else {
                anyhow::bail!("{flag}=<value> must be rejected");
            };
            let rendered = err.to_string();
            assert!(
                rendered.to_lowercase().contains("argv") && rendered.contains(flag),
                "the pointed refusal still names the flag and argv: {rendered}"
            );
            assert!(
                !rendered.contains(&seed_value),
                "the seed value must never be echoed into the error text: {rendered}"
            );
        }
        Ok(())
    }

    #[test]
    fn recover_generic_refusal_strips_the_value_from_an_equals_form() -> anyhow::Result<()> {
        // A non-seed-shaped `--flag=value` still must not echo the value:
        // the generic refusal path must name only the flag, never anything
        // after `=`.
        let args = vec!["--bogus=super-secret-looking-value".to_owned()];
        let Err(err) = reject_recover_args(&args) else {
            anyhow::bail!("an unknown flag must be rejected");
        };
        let rendered = err.to_string();
        assert!(rendered.contains("--bogus"), "names the flag: {rendered}");
        assert!(
            !rendered.contains("super-secret-looking-value"),
            "the value after `=` must not be echoed: {rendered}"
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
