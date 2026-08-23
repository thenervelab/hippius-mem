//! The `hippius-mem doctor` subcommand: validate a memory-key bundle.
//!
//! Loads the same [`Config`] the server boots from and reports the non-secret
//! coordinates (bucket, `access_key_id`, author SS58), so an operator can confirm
//! a bundle is well-formed before starting the server. Secrets (`secret`,
//! `team_key_hex`, `author_seed_hex`) are never logged.

use std::sync::Arc;

use anyhow::{Context, bail, ensure};
use hippius_mem_core::{
    BlobStore, HeadRegression, HeadWatermarks, OpLogStore, QuarantinedAuthor, SecretKey, Signer,
    Ss58, SuppressedTail, find_suppressed_tails, highest_published_epoch, load_manifest, open,
    read_heads, read_wrapped_key, seal, wrapped_key_recipients,
};

use crate::config::{Config, TeamProfile};
use crate::resolver::{self, GitRemoteReader, RemoteReader, Resolution};

/// Fixed, non-secret plaintext the live probe seals and reads back.
///
/// A constant sentinel — never key material — so it is safe to name in an
/// assertion message and safe to round-trip through a real gateway.
const PROBE_PLAINTEXT: &[u8] = b"hippius-mem doctor encryption-boundary probe";

/// Object key the probe writes its sealed sentinel under.
///
/// The leading `_doctor/` segment is disjoint from every real key by shape, not
/// just by convention: note keys are `{team}/{repo}/{mem_id}/ver_{ulid}` (four
/// segments) and op-log keys are `{team}/_oplog/...`, so even a team literally
/// named `_doctor` cannot mint this exact two-segment key. The probe therefore
/// cannot read or clobber a real note or op.
const PROBE_KEY: &str = "_doctor/encryption-boundary-probe";

/// Non-secret outcome of a successful encryption-boundary probe.
///
/// Carries only the sealed byte count — a size, never any key, ciphertext, or
/// plaintext — so it is safe to log. The type deliberately holds no secret so a
/// secret cannot reach a log line even by mistake.
#[derive(Debug, Clone, Copy)]
struct ProbeReport {
    /// Ciphertext bytes written to the gateway (nonce + sealed body + tag).
    bytes_written: usize,
}

/// Run the `doctor` subcommand over the args following `doctor`.
///
/// Loads the config via [`Config::from_env_and_file`] (`HIPPIUS_MEM_CONFIG`,
/// else the cwd-relative default) and delegates to [`run_for_config`]. Callers
/// that already hold a validated [`Config`] — because they just built or wrote
/// it themselves, so re-resolving it from the environment/cwd could pick up a
/// DIFFERENT file — should call [`run_for_config`] directly instead (see
/// `quickstart::probe_fresh_trial`, which must probe the exact bytes it just
/// wrote, not whatever `Config::from_env_and_file` separately resolves).
///
/// # Errors
///
/// Returns an error if an unknown argument is passed, the configuration is
/// missing or malformed, the launch repo routes to no team profile (memory
/// disabled here), or the author identity cannot be derived from
/// `author_seed_hex`.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let opts = Options::parse(args)?;

    let cfg = Config::from_env_and_file().context(crate::config::CONFIG_LOAD_HELP)?;

    run_for_config(&cfg, opts.offline).await
}

/// Run the doctor checks against an already-resolved `cfg`, skipping
/// [`Config::from_env_and_file`]'s own env/cwd resolution entirely.
///
/// The profile diagnosed is resolved from the LAUNCH repo's git remote exactly
/// as [`crate::resolver::resolve`] does for the server ([`crate::main`]'s
/// `resolve_and_build_store`) — not the flat/primary profile — so a `[[teams]]`
/// profile whose bucket doesn't match its sub-token's scope is the one probed
/// when standing in that repo, instead of doctor silently checking a different,
/// healthy profile while the real one 403s at runtime (finding [13]). With
/// `offline = true` the check stops after the offline validation; otherwise it
/// runs the live gateway/local-disk probe.
///
/// # Errors
///
/// Returns an error if the launch repo routes to no team profile (memory
/// disabled here), the author identity cannot be derived from
/// `author_seed_hex`, or (unless `offline`) the live probe fails.
pub(crate) async fn run_for_config(cfg: &Config, offline: bool) -> anyhow::Result<()> {
    let profile = resolve_bound_profile(cfg)?;

    // Deriving the signer proves `author_seed_hex` yields a usable sr25519
    // identity and hands us the SS58 to report. The SS58 is bound to the seed by
    // construction (see `Sr25519Signer`), so it is safe, non-secret output.
    let signer = profile
        .signer()
        .context("deriving the author identity from author_seed_hex failed")?;
    let author = signer.author_ss58();

    // `offline_report_lines` is handed only public coordinates — never `&cfg` or
    // `&profile` — so a secret field cannot reach the report even by mistake. The
    // profile name is the first line, so the operator sees WHICH profile this run
    // diagnosed before the coordinates that name resolved to.
    for line in offline_report_lines(
        &profile.name,
        &profile.bucket,
        &profile.access_key_id,
        author.as_str(),
    ) {
        tracing::info!("{line}");
    }

    if offline {
        tracing::info!("offline check passed; skipping live gateway probe");
        return Ok(());
    }

    probe_live(cfg, &profile).await
}

/// Resolve the team profile bound for the current working directory's git
/// remote — the SAME routing [`crate::main`]'s `resolve_and_build_store` uses to
/// pick which profile the server binds, so `doctor` diagnoses exactly the
/// profile the server would.
///
/// Thin: reads the one live seam (the cwd's git remote) and hands off to
/// [`resolve_profile_for_remote`], which carries all the testable logic. Kept
/// separate so a test can drive the routing decision with an explicit `remote`
/// instead of depending on the test runner's own git checkout.
///
/// # Errors
///
/// Returns an error if the repo routes to no team profile (memory disabled for
/// this repo, per [`crate::resolver::DisabledReason`]).
fn resolve_bound_profile(cfg: &Config) -> anyhow::Result<TeamProfile> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let remote = GitRemoteReader.origin_url(&cwd);
    resolve_profile_for_remote(cfg, remote.as_deref())
}

/// Resolve the team profile bound for `remote` (a git `origin` URL, or `None`
/// for no/unreadable remote), the remote-independent half of
/// [`resolve_bound_profile`].
///
/// Returns an owned, cloned [`TeamProfile`] rather than a borrow of
/// [`Config::all_profiles`]'s local `Vec`: that `Vec` is rebuilt fresh on every
/// call and dropped at the end of this function, so a borrow from it cannot
/// outlive the function. `doctor` is a one-shot CLI command resolving exactly
/// one profile, so one small clone (a handful of `String` fields) is simpler
/// and cheaper than restructuring the caller around the borrow's lifetime.
///
/// # Errors
///
/// Returns an error if `remote` routes to no team profile (memory disabled for
/// this repo, per [`crate::resolver::DisabledReason`]).
fn resolve_profile_for_remote(cfg: &Config, remote: Option<&str>) -> anyhow::Result<TeamProfile> {
    let profiles = cfg.all_profiles();
    match resolver::resolve(&profiles, remote) {
        Resolution::Bound(profile) => Ok(profile.clone()),
        Resolution::Disabled(reason) => {
            bail!("team memory is disabled for this repository: {reason}")
        }
    }
}

/// Parsed `doctor` arguments.
struct Options {
    /// Run only the offline bundle validation, skipping the live gateway probe.
    offline: bool,
}

impl Options {
    /// Parse `[--offline]`.
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let mut offline = false;
        for arg in args {
            match arg.as_str() {
                "--offline" => offline = true,
                other => bail!("unknown doctor argument `{other}`; usage: doctor [--offline]"),
            }
        }
        Ok(Self { offline })
    }
}

/// Build the non-secret lines of the doctor report.
///
/// Takes only the four public coordinates — never `&Config`/`&TeamProfile` — so a
/// secret (`secret`, `team_key_hex`, `author_seed_hex`) is structurally
/// impossible to include in the report this produces. `profile_name` is first so
/// the report always names which profile it diagnosed (finding [13]).
fn offline_report_lines(
    profile_name: &str,
    bucket: &str,
    access_key_id: &str,
    author_ss58: &str,
) -> Vec<String> {
    vec![
        format!("profile: {profile_name}"),
        format!("bucket: {bucket}"),
        format!("access_key_id: {access_key_id}"),
        format!("author_ss58: {author_ss58}"),
    ]
}

/// Run the live encryption-boundary probe against the configured backend.
///
/// Builds the same [`SecretKey`] and blob store the server boots from FOR THE
/// RESOLVED PROFILE — `profile`'s bucket/credentials (or, for a local trial
/// profile, its trial-vault root), not the flat/primary config — then
/// delegates to [`probe_encryption_boundary`]. The blob store itself comes
/// from [`TeamProfile::build_blob_store`], the SAME construction
/// [`TeamProfile::build_store`] uses, rather than a doctor-local copy of that
/// match: `probe_live` used to hand-roll its own, and had twice drifted from
/// it — see [`TeamProfile::build_blob_store`]'s doc for both. Sharing the one
/// function is what makes "probes the exact store the server would bind" true
/// rather than aspirational. On success it logs a non-secret line carrying
/// only the sealed byte count. Also checks (best-effort) whether this
/// machine's configured `max_epoch` is stale against what the bucket has
/// actually published — see [`stale_max_epoch_line`].
///
/// # Errors
///
/// Returns an error if the team key cannot be derived, the local trial root
/// cannot be resolved (a local trial profile with no `local_root` and no
/// `XDG_CACHE_HOME`/`HOME`), or the seal/put/get/open round-trip in
/// [`probe_encryption_boundary`] fails.
async fn probe_live(cfg: &Config, profile: &TeamProfile) -> anyhow::Result<()> {
    let key = profile
        .team_key()
        .context("deriving the team key from team_key_hex failed")?;
    let blob: Arc<dyn BlobStore> = profile
        .build_blob_store(cfg, &key)
        .context("building the blob store for the resolved profile failed")?;

    // A stale `max_epoch` is checked ahead of the encryption probe, and
    // independently of its outcome: it needs no team key, only the bucket
    // listing, so it should still be reported even when the probe below fails.
    if let Some(line) = stale_max_epoch_line(blob.as_ref(), &profile.name, cfg.max_epoch).await {
        tracing::warn!("{line}");
    }

    // Same reasoning as the stale-`max_epoch` check above: no team key
    // needed, only manifest/bucket reads, so it runs and reports
    // independently of the encryption probe's outcome below.
    let founder = profile.founder().ok().flatten();
    for line in
        removed_member_still_holds_key_lines(blob.as_ref(), &profile.name, founder.as_ref()).await
    {
        tracing::warn!("{line}");
    }

    // Same best-effort placement and reasoning again: this check never
    // decrypts a wrap (no team key needed), only checks its provisioner
    // signature and, against the live manifest, its authorization -- so it
    // runs and reports independently of the encryption probe's outcome below.
    for line in
        unsigned_or_unauthorized_wrapped_key_lines(blob.as_ref(), &profile.name, founder.as_ref())
            .await
    {
        tracing::warn!("{line}");
    }

    // Same best-effort placement and reasoning again: the op-log read needs no
    // team key, so a broken author chain and a truncated tail are reported whether
    // or not the encryption probe below succeeds.
    // The SAME marks the server advances (one file per team, resolved identically),
    // so a `doctor` run both reports a rolled-back head and keeps the machine's
    // memory of the honest heads current. `None` means no state directory resolved;
    // the head-regression check is then inert, which `build_store` warns about on
    // the serve path.
    let watermarks = profile.head_watermarks();
    for line in
        op_log_integrity_lines(Arc::clone(&blob), &profile.name, watermarks.as_deref()).await
    {
        tracing::warn!("{line}");
    }

    let report = probe_encryption_boundary(blob.as_ref(), &key).await?;

    tracing::info!(
        bytes_written = report.bytes_written,
        "live encryption-boundary probe passed: the probe object was stored as ciphertext and round-tripped"
    );
    Ok(())
}

/// The stale-`max_epoch` report line for `team`, or `None` when nothing is
/// stale.
///
/// Compares `configured_max_epoch` (this machine's bootstrap ceiling) against
/// [`highest_published_epoch`]'s live read of the bucket's `_keys/` prefix: a
/// stale `max_epoch` silently hides every note sealed under a rotated epoch
/// past it (the recorded `bootstrap_epochs` gotcha's warning-side
/// counterpart), so a doctor run is exactly where an operator should learn
/// this before it bites.
///
/// Best-effort: a fetch failure (offline gateway, missing permissions) returns
/// `None` silently rather than surfacing — this check exists to add a hint on
/// top of the load-bearing live probe, never to become a new doctor failure
/// mode of its own.
async fn stale_max_epoch_line(
    blob: &dyn BlobStore,
    team: &str,
    configured_max_epoch: u64,
) -> Option<String> {
    let published = highest_published_epoch(blob, team).await.ok()?;
    if published <= configured_max_epoch {
        return None;
    }
    Some(format!(
        "WARN: max_epoch is stale (configured {configured_max_epoch}, bucket published epoch \
         {published}): raise max_epoch to {published} at the TOP LEVEL of hippius-mem.toml -- \
         it is a top-level setting, never a per-team profile field -- or new-epoch notes stay \
         invisible"
    ))
}

/// The "removed member still holds the current epoch key" report lines for
/// `team`: every SS58 the CURRENT epoch's team key is wrapped to (per
/// [`wrapped_key_recipients`] at [`highest_published_epoch`]) that the live
/// membership manifest (per [`load_manifest`]) no longer lists.
///
/// This is the read-side detector for the recorded `rotate --members`
/// non-atomicity gotcha: `publish_membership` can land while `rotate_key`
/// then refuses (typically `MemError::NothingToRotate` because no remaining
/// member has `join`ed yet), leaving a removed member's wrap for the CURRENT
/// epoch on the bucket even though the manifest no longer lists them —
/// `hippius-mem remove` is now resumable and reports this itself on the run
/// that hits it (see `crate::admin::remove`), but a machine that never
/// re-ran `remove`/`rotate` to finish would otherwise carry a silently
/// half-done removal forever. Running this on every `doctor` invocation
/// catches it independent of whether that original run's output was ever
/// seen.
///
/// Best-effort, mirroring [`stale_max_epoch_line`]: an open team (no
/// manifest published — nothing to compare a wrap against) or any read
/// failure yields no lines rather than becoming a new doctor failure mode.
///
/// # Known blind spot: invite-bundle-provisioned members
///
/// This check can only see who holds a `_keys/` wrap — but `join --bundle`
/// hands a member `team_key_hex` DIRECTLY (see `crate::join_bundle`), so a
/// bundle-provisioned member never appears in ANY `_keys/` wrap, at any
/// epoch. Removing such a member is therefore invisible to this check by
/// construction: there is nothing in `_keys/` to compare against the live
/// manifest for them.
///
/// This is NOT the primary guard against that exposure. `hippius-mem
/// remove` (`crate::admin::remove`) now ALWAYS rotates the team key when it
/// actually removes someone from the live roster — see
/// `crate::admin::removal_requires_rotation`, which gates on "did this
/// invocation shrink the roster", never on `_keys/` membership — so a real
/// removal already closes the exposure before this check ever runs,
/// bundle-provisioned or not. This check's remaining, genuinely useful role
/// is the residual half-done-removal case: a prior run published the
/// shrunk roster but `rotate_key` then refused (no remaining member had
/// `join`ed yet) — a state that IS visible in `_keys/`, because rotation
/// simply never happened.
async fn removed_member_still_holds_key_lines(
    blob: &dyn BlobStore,
    team: &str,
    founder: Option<&Ss58>,
) -> Vec<String> {
    let Ok(Some(manifest)) = load_manifest(blob, team, founder).await else {
        return Vec::new();
    };
    // A listing failure here must NOT fall back to epoch 0: epoch 0's
    // recipients are almost certainly stale (superseded by real rotations),
    // so comparing them against the live manifest would flag long-since-
    // removed members as a false "still holds the current epoch key"
    // warning on an otherwise healthy team hitting a storage hiccup. Mirrors
    // `stale_max_epoch_line`'s short-circuit exactly.
    let Ok(epoch) = highest_published_epoch(blob, team).await else {
        return Vec::new();
    };
    let Ok(recipients) = wrapped_key_recipients(blob, team, epoch).await else {
        return Vec::new();
    };

    recipients
        .into_iter()
        .filter(|ss58| !manifest.members.contains(ss58))
        .map(|ss58| {
            format!(
                "WARN: removed member {ss58} still holds the current epoch key; run: \
                 hippius-mem rotate (then revoke their sub-token in the console)",
                ss58 = ss58.as_str(),
            )
        })
        .collect()
}

/// The "wrap fails signature verification, or was sealed by an unauthorized
/// provisioner" report lines for `team`: every `WrappedKey` published at the
/// CURRENT (highest published) epoch that either fails `WrappedKey::verify`
/// or whose `WrappedKey::provisioner` the live manifest does not authorize.
///
/// This is the PROACTIVE, doctor-side counterpart of the authorization gate
/// `fetch_team_key` enforces on the READ path: that gate only fires the
/// moment a member actually tries to bootstrap the team key from a bad wrap
/// planted on the bucket. This check surfaces the same bad wrap on a routine
/// `doctor` run, before any member hits it, naming exactly the recipient
/// whose wrap an operator must clear with a rotation.
///
/// # One source of truth, not a copy
///
/// Both the object-key format and the authorization rule are read through
/// the SAME shared primitives `fetch_team_key` itself uses, rather than a
/// doctor-local copy of either: [`hippius_mem_core::read_wrapped_key`] (which
/// internally applies the one `hippius_mem_core::wrapped_key_key` format
/// function every writer and reader in `teamkey.rs` already goes through) for
/// the raw record, and `TeamManifest::authorizes_provisioner` for the
/// founder-or-recovery-key rule. A copied rule or a copied key-format literal
/// is exactly the silent-drift hazard this check exists to catch in OTHER
/// people's wraps; it must not carry that hazard itself.
///
/// Reuses [`wrapped_key_recipients`] to enumerate the epoch's recipients —
/// the same read [`removed_member_still_holds_key_lines`] uses — then fetches
/// each recipient's raw record via `read_wrapped_key`, because this check
/// needs the signed record itself, not merely who holds one.
///
/// # Verify before authorize
///
/// A wrap that fails `WrappedKey::verify` is reported for that alone; its
/// `provisioner` field is not yet trustworthy evidence of anything once the
/// signature over it does not check out, so the authorization comparison
/// below is skipped for it rather than compounding an unverified claim with
/// a second one.
///
/// # Open team
///
/// Mirrors `fetch_team_key`'s and [`removed_member_still_holds_key_lines`]'s
/// own fallback: when no trusted manifest is published yet, every wrap that
/// verifies is accepted — an unpinned, not-yet-founded team is open by
/// design — so only a wrap failing `WrappedKey::verify` is reported.
///
/// Best-effort, mirroring [`stale_max_epoch_line`] and
/// [`removed_member_still_holds_key_lines`]: a listing/fetch failure at any
/// stage (the epoch lookup, the recipient listing, an individual wrap fetch
/// or decode, or the manifest load) is swallowed for that item rather than
/// becoming a new doctor failure mode — a bad wrap this run could not even
/// read is a missed detection, the lesser fault, never a false accusation.
async fn unsigned_or_unauthorized_wrapped_key_lines(
    blob: &dyn BlobStore,
    team: &str,
    founder: Option<&Ss58>,
) -> Vec<String> {
    let Ok(epoch) = highest_published_epoch(blob, team).await else {
        return Vec::new();
    };
    let Ok(recipients) = wrapped_key_recipients(blob, team, epoch).await else {
        return Vec::new();
    };

    // A manifest read failure is treated exactly like "no manifest published
    // yet": the authorization half below is then skipped for every wrap,
    // never itself becoming a failure of this check. Mirrors `probe_live`'s
    // own `founder` handling just above this check's call site.
    let manifest = load_manifest(blob, team, founder).await.ok().flatten();

    let mut lines = Vec::new();
    for ss58 in recipients {
        let Ok(wrapped) = read_wrapped_key(blob, team, epoch, ss58.as_str()).await else {
            continue;
        };

        if !wrapped.verify() {
            lines.push(format!(
                "WARN: wrap for team {team:?} epoch {epoch} recipient {:?} fails its \
                 provisioner signature check (garbage or forged signature); run: \
                 hippius-mem rotate",
                ss58.as_str(),
            ));
            continue;
        }

        let Some(manifest) = &manifest else {
            continue;
        };
        if !manifest.authorizes_provisioner(&wrapped.provisioner) {
            lines.push(format!(
                "WARN: wrap for team {team:?} epoch {epoch} recipient {:?} was sealed by a \
                 provisioner the current manifest does not authorize (neither its founder \
                 nor its named recovery key); run: hippius-mem rotate",
                ss58.as_str(),
            ));
        }
    }
    lines
}

/// The op-log integrity report lines for `team`: one per author whose ops a
/// verified read had to quarantine, one per author whose own signed head pointer
/// names a tip the visible log does not contain, and one per author whose served
/// head has fallen below the highest head this machine already verified.
///
/// All three facts are otherwise invisible to an operator. The read path keeps
/// only each author's longest genesis-rooted chain and drops the rest with a
/// `tracing::warn!` deep inside the op-log module; a truncated tail and a lowered
/// head produce no log line at all. This surfaces all three where an operator is
/// already looking, alongside the `reconcile` MCP tool's `quarantined_authors`,
/// `suppressed_tails` and `head_regressions` (the same three comparisons, over the
/// same `OpLogStore::read_all_reporting_quarantine` read and the same
/// `read_heads`).
///
/// The three are reported from ONE op-log read on purpose: that read is the
/// dominant cost of a `doctor` run (see below), so the head-pointer check reuses
/// the ops it already has via `find_suppressed_tails` rather than paying for a
/// second pass. The head listing it adds is one small object per author.
///
/// # Read the HEADS first — the order is load-bearing
///
/// See the comment on the two reads below. Reading the ops first turns an ordinary
/// concurrent teammate write into a WARN accusing that teammate of a suppressed
/// tail. [`hippius_mem_core::reconcile`] takes the same two reads in the same
/// order for the same reason; keep the two in step.
///
/// Best-effort, mirroring [`stale_max_epoch_line`] and
/// [`removed_member_still_holds_key_lines`]: any read failure yields no lines
/// rather than becoming a new doctor failure mode. A failed HEAD read costs
/// EVERYTHING that rests on the heads — the tail check, the head-regression check,
/// AND the mark advance `watermarks.observe` performs — because all three sit
/// inside the one `if let Ok(heads)` block below; only the quarantine lines
/// survive it. So one unreadable head object cannot silence the whole section, but
/// it does silence two thirds of it, and it also means this run teaches the
/// machine nothing about the heads it should have remembered. Note that the
/// systemic-outage guard makes a majority fetch failure an error here, so a
/// whole-bucket outage is silent in THIS check — the live probe below is what
/// fails on it.
///
/// # Cost
///
/// Unlike its two siblings — a keys-only listing and a manifest read — this GETs
/// and crypto-verifies EVERY op object the team has ever written, because a chain
/// break is only visible once the whole log is linked up. The op-log is
/// append-only, so that cost grows monotonically with the team's history and is
/// the dominant cost of a `doctor` run on a long-lived team. It is bounded only by
/// `OPLOG_FETCH_CONCURRENCY`'s in-flight cap, not by any window or page limit.
async fn op_log_integrity_lines(
    blob: Arc<dyn BlobStore>,
    team: &str,
    watermarks: Option<&HeadWatermarks>,
) -> Vec<String> {
    // HEADS FIRST, THEN OPS. This order is load-bearing; do not swap it.
    //
    // These are two unsynchronised reads of a live bucket, so whichever runs
    // SECOND sees the fresher view, and the tail check reports "a head names a tip
    // the ops do not contain".
    //
    // Heads first: a teammate's write landing between the reads puts its op in the
    // LATER ops read while its head was absent from the earlier one. The head set
    // is then a subset of what the ops justify, which the check cannot report —
    // benign, and silent by construction.
    //
    // Ops first: that same write lands its head in the LATER heads read while its
    // op is missing from the earlier ops read. That is head-ahead-of-log, which is
    // exactly the evidence condition, so doctor prints a WARN naming an honest
    // teammate as having a suppressed tail. A false `SuppressedTail` is an
    // ACCUSATION against a named identity, and the window is the whole verified
    // op-log read — this function's dominant cost — so on an active team it is
    // likely, not exotic. A missed detection would be the lesser fault; this order
    // is chosen because it can only ever err toward silence.
    //
    // `reconcile` (`audit/reconcile.rs`) takes the same two reads in this same
    // order, with the same reasoning recorded there. Keep them in step.
    //
    // The `Result` is held rather than `?`-ed so an unreadable heads prefix still
    // leaves the quarantine lines below reported. It costs everything else the
    // heads feed: the tail check, the head-regression check, and the mark advance.
    let heads = read_heads(&blob, team).await;

    let oplog = OpLogStore::new(Arc::clone(&blob));
    let Ok((ops, quarantined)) = oplog.read_all_reporting_quarantine(team).await else {
        return Vec::new();
    };

    let mut lines = quarantine_lines(&quarantined);
    if let Ok(heads) = heads {
        lines.extend(suppressed_tail_lines(&find_suppressed_tails(&heads, &ops)));
        // The head-regression check compares those same verified heads against this
        // machine's local marks, and ADVANCES them — so a `doctor` run is also how a
        // machine that never calls `reconcile` keeps its memory of the honest heads
        // current. `None` marks make it inert, not wrong: the lines are simply absent.
        if let Some(watermarks) = watermarks {
            lines.extend(head_regression_lines(&watermarks.observe(&heads)));
        }
    }
    lines
}

/// Render [`op_log_integrity_lines`]' quarantine findings, split out so the
/// wording is unit-testable without a bucket.
///
/// The wording carries the honest limit with the finding: this evidence names a
/// break, never its cause. A hostile fork, a mid-chain object the bucket dropped,
/// one this read merely failed to fetch or did not see listed, this author's own
/// cancelled-but-durable append, and two honest writers under ONE identity on
/// different MACHINES (routine here — MCP registration is user-global, so concurrent
/// agent sessions share an author key; two processes on one machine are now
/// serialized by the cross-process writer lock) are
/// indistinguishable at author granularity;
/// the two fetch/listing causes clear themselves on a later read, and a
/// cancelled-but-durable append now usually does too (the writer best-effort
/// reclaims the orphaned op object right after the failed append) — but that
/// reclaim can itself fail, leaving the orphan exactly as durable as before.
fn quarantine_lines(quarantined: &[QuarantinedAuthor]) -> Vec<String> {
    quarantined
        .iter()
        .map(|entry| {
            format!(
                "WARN: author {author} lost {dropped} op(s) to a broken op-log chain, so their \
                 history is incomplete in every read on this machine -- this reports the BREAK, \
                 not its cause: a forked or suppressed op, an object the bucket dropped for \
                 good, one this read merely failed to fetch or did not see listed, this \
                 author's own cancelled-but-durable append, and TWO HONEST WRITERS UNDER ONE \
                 IDENTITY ON DIFFERENT MACHINES all look identical here. That last one is \
                 routine, not exotic: MCP registration is user-global, so concurrent agent \
                 sessions share this author key. Two of them on ONE machine are now \
                 serialized by the cross-process writer lock, so if this is a single-machine \
                 setup that cause is closed unless no state directory resolves -- the \
                 lost ops are gone from convergence for good and must be re-issued. Re-run \
                 doctor: the fetch/listing causes clear themselves, and a cancelled-but-durable \
                 append usually does too (the writer best-effort reclaims it right after the \
                 failed append) -- but that reclaim can itself fail, and a hostile fork, a real \
                 deletion or a same-identity race never clears on its own. Then call the \
                 `reconcile` MCP tool for the anchored-suppression evidence, which this check \
                 does not cover",
                author = entry.author.as_str(),
                dropped = entry.dropped_ops,
            )
        })
        .collect()
}

/// Render [`op_log_integrity_lines`]' truncated-tail findings, split out so the
/// wording is unit-testable without a bucket.
///
/// The wording carries the honest limit with the finding, exactly as
/// [`quarantine_lines`] does. What is proved here is narrower and stronger than
/// the quarantine case: the author SIGNED the tip being named, so nobody but that
/// author could have made the claim. What is not proved is that the bucket
/// suppressed it — the op may simply not have been fetched or listed on this read,
/// or it may have been quarantined by a chain break, in which case a quarantine
/// line for the same author appears above. That pair must NOT be read as "a fork":
/// a bucket dropping one mid-chain object quarantines the whole post-gap run
/// including the tail, so while that author's head survives and is current it
/// produces the pair, while a fork produces it when the planted branch wins the
/// tiebreak or when a fork is combined with tail truncation. Nor does the pair say
/// the tip is merely quarantined and still in the bucket — it may equally have been
/// dropped or left unfetched. All the pair proves is that this author's chain broke
/// and their signed tip is not in the surviving set.
///
/// The line must not overclaim in the other direction either: this check catches
/// a truncated tail only while the author's head object survives and is current.
/// THREE residuals leave it silent, and the third is the one an operator is most
/// likely to reason past. A bucket that drops the head too, or serves an older
/// validly-signed one, is silent HERE — [`head_regression_lines`] is what reports
/// those, and only on a machine that had already verified the higher head. The
/// third needs no bucket action at all: the head publish is best-effort, so a
/// publish that merely FAILED leaves the previous tip named, and a lagging head is
/// healthy by construction — and because this machine's mark advances only on a
/// successful publish, `head_regression_lines` is silent on it too. Clean here AND
/// clean there is therefore NOT proof that no tail was truncated, on any machine.
fn suppressed_tail_lines(suppressed: &[SuppressedTail]) -> Vec<String> {
    suppressed
        .iter()
        .map(|entry| {
            let visible = match entry.visible_lamport {
                Some(lamport) => format!("the newest op visible for them is lamport {lamport}"),
                None => "not one op of theirs is visible at all".to_owned(),
            };
            format!(
                "WARN: author {author} signed a head naming op {tip} at lamport {claimed}, but \
                 that op is not in this machine's view -- {visible}. The author's SIGNATURE over \
                 that tip is what makes this evidence: nobody else could have made the claim. It \
                 does NOT prove suppression -- the op may merely have failed to fetch or not been \
                 listed on this read (which clears itself on a re-run), or it may have been \
                 quarantined by a chain break, in which case a broken-chain line above names the \
                 same author. Do NOT read that pair as a fork: a bucket dropping one mid-chain \
                 object quarantines everything after the gap including the tail, so while this \
                 author's head survives and is current it produces the pair, whereas a fork \
                 produces it when the planted branch wins or is combined with tail truncation. \
                 Nor does the pair mean the tip is merely quarantined and still in the bucket -- \
                 it may equally have been dropped or left unfetched. All it proves is that the \
                 chain broke and the signed tip is not in the surviving set, so it is a reason \
                 to look harder, not to stand down. Re-run doctor, then \
                 call the `reconcile` MCP tool. Note the reverse is not proof either: this check \
                 is silent in THREE cases -- the bucket also dropped the head object, it served \
                 an older validly-signed one, or this author's best-effort head publish simply \
                 FAILED and left the previous tip named. A head-moved-BACKWARD line reports the \
                 first two, and only on a machine that had already verified the higher head; the \
                 third is silent there too, because the served head never moved and this \
                 machine's mark only ever advances on a publish that succeeded",
                author = entry.author.as_str(),
                tip = entry.claimed_tip.to_hex(),
                claimed = entry.claimed_lamport,
            )
        })
        .collect()
}

/// Render [`op_log_integrity_lines`]' head-regression findings, split out so the
/// wording is unit-testable without a bucket.
///
/// This is the one finding in the section whose evidence is not entirely the
/// bucket's: it says the bucket serves less than this machine has already
/// verified. The wording therefore has two honest limits to carry rather than one.
///
/// It must not overclaim. A regression proves the SERVED head is below what this
/// machine verified, and nothing stronger. In particular it does NOT prove the
/// bucket withdrew anything: only the key-holder can SIGN a head, but the
/// key-holder can also publish a LOWER one, and two ordinary cases do — two
/// writers under one identity on DIFFERENT machines racing their head PUTs (the
/// PUT has no compare-and-swap, and MCP registration is user-global, so concurrent
/// sessions share an identity; two processes on ONE machine are now ordered by the
/// cross-process writer lock, which is held across the head PUT), and a restarted
/// process
/// re-seeding from a short view, which publishes a brand-new head below the mark
/// rather than restoring an old one. A third ordinary case publishes no lower head
/// at all: the heads prefix is re-read by LIST, the gateways are only eventually
/// consistent, and this machine's mark is recorded the moment its own PUT
/// succeeds — so a `remember` followed immediately by a `doctor` can report a
/// regression against this machine's OWN identity, with no concurrency involved,
/// that self-clears on the next read.
///
/// "Ordinary" must not be rendered as "harmless". The first case is a race between
/// two processes that can equally mint two ops against one `prev_op_hash` and
/// self-fork the author's chain — reported by [`quarantine_lines`] above, and
/// permanent: the losing branch's ops are dropped from convergence for good. A head
/// regression clears itself; that does not.
///
/// Nor does a regression prove any op was suppressed — the ops may all still be
/// readable, which is what the suppressed-tail line above answers separately. Two
/// further benign causes present identically: a team re-created from scratch under
/// the same name and identity, and the same team name pointed at a restored backup,
/// a staging mirror or a different endpoint, since the mark file is keyed on the
/// team name alone. The line names the state file so an operator can act on all of
/// those.
///
/// It must not underclaim either: silence here is not proof no head moved. This
/// check can only fire for an author this machine has ALREADY verified a head for,
/// so a fresh machine, a new teammate and a cleared state directory are all blind
/// by construction — which is why the line does not appear at all rather than
/// appearing as an all-clear. And it does not cover the third residual
/// [`suppressed_tail_lines`] documents at all: a head publish that merely failed
/// leaves the previous tip named without the served head ever moving backward, and
/// this machine's mark advances only on a publish that succeeded, so there is
/// nothing here to regress against.
fn head_regression_lines(regressions: &[HeadRegression]) -> Vec<String> {
    regressions
        .iter()
        .map(|entry| {
            let served = match (entry.served_lamport, entry.served_tip) {
                (Some(lamport), Some(tip)) => format!(
                    "it now serves a head at lamport {lamport} naming op {tip}",
                    tip = tip.to_hex()
                ),
                // Both fields are populated or absent together, so the remaining
                // combinations describe the same fact: no verifiable head came back.
                (None, _) | (_, None) => {
                    "it now serves no verifiable head for them at all (the object was not listed \
                     -- deleted, never written, or a listing that has not caught up -- or it was \
                     listed and then failed to decode, verify or sit at its own key path, in \
                     which case an earlier warn names it; a head that was never listed is silent \
                     in the log)"
                        .to_owned()
                }
            };
            format!(
                "WARN: this machine had already verified a signed head for author {author} at \
                 lamport {remembered} naming op {remembered_tip}, but the served head is now \
                 LOWER -- {served}. Only the key-holder can SIGN a head, so the bucket did not \
                 fabricate the higher one. It does NOT follow that the bucket withdrew it: the \
                 key-holder can also publish a LOWER head, and two ordinary cases do. (1) TWO \
                 PROCESSES UNDER ONE IDENTITY: the writer lock serializes head writes within one \
                 process only and the head PUT has no compare-and-swap, while MCP registration \
                 is user-global, so concurrent agent sessions share this identity -- if one \
                 process's head PUT lands after another's higher one, the served head goes \
                 backward with every op present. It clears on the next write above the higher \
                 lamport -- but do NOT read that as concurrent sessions being harmless: the same \
                 two processes can also mint two ops against ONE prev_op_hash and self-fork this \
                 author's chain, which a broken-chain line above reports and which does NOT \
                 clear, the losing branch's ops being gone from convergence for good. (2) A \
                 RESTARTED PROCESS RE-SEEDING FROM A SHORT VIEW: it mints a lower \
                 lamport and publishes a BRAND NEW head below the mark, so there is no \
                 rolled-back object to find -- and if the view was short because of a \
                 truncation, this line is a true detection naming the wrong artifact. (3) \
                 ORDINARY READ-LAG AGAINST THIS MACHINE'S OWN IDENTITY, with no concurrency at \
                 all: the mark is recorded as soon as this machine's own head PUT succeeds, the \
                 heads prefix is re-read by LIST, and the gateways are only eventually \
                 consistent, so a write followed immediately by this check can find no head \
                 listed for us while the one we just published is durable in the bucket. That \
                 one self-clears on the next read. A hostile \
                 bucket dropping or rolling back the head produces the same evidence, and that \
                 is the step it must take to hide a truncated tail from the head-pointer check. \
                 It does NOT by itself prove any op was suppressed: check the truncated-tail \
                 line above and call the `reconcile` MCP tool. Other BENIGN causes look \
                 identical -- a team re-created from scratch under the same name and identity \
                 restarts at a lower lamport, and the state file is keyed on the TEAM NAME \
                 alone, so the same name pointed at a restored backup, a staging mirror or a \
                 different endpoint does too; for any of those, delete this team's \
                 head-watermarks.json state file. Note the reverse is not proof either: this \
                 check is silent for any author this machine has not already verified a head \
                 for, and silent as well when a best-effort head publish merely FAILED -- that \
                 leaves the previous tip named without the served head ever moving backward, so \
                 there is nothing here to regress against",
                author = entry.author.as_str(),
                remembered = entry.remembered_lamport,
                remembered_tip = entry.remembered_tip.to_hex(),
            )
        })
        .collect()
}

/// Prove the encryption boundary holds end-to-end against `blob`: seal a known
/// plaintext, store it, read it back, and confirm the gateway only ever saw
/// ciphertext that round-trips to the original.
///
/// `blob` is injected (rather than built inside) so this is a deterministic I/O
/// seam: tests drive it against an in-memory store and against fault-injecting
/// fakes with no live gateway. The probe binds [`PROBE_KEY`] as AAD on both
/// `seal` and `open`, mirroring `MemoryStore::remember`: authenticating the key
/// the bytes live under turns a relocated or swapped ciphertext into an
/// authentication failure rather than a silent content swap.
///
/// Every error and log path here is secret-free by construction — none
/// interpolate `key`, the ciphertext, or the fetched bytes. The only literal
/// bytes named anywhere are the fixed, non-secret [`PROBE_PLAINTEXT`] sentinel.
///
/// # Errors
///
/// Returns an error if sealing fails, the store rejects the write or read, the
/// gateway hands back the plaintext verbatim (the encryption boundary is
/// broken), or the fetched ciphertext does not decrypt back to
/// [`PROBE_PLAINTEXT`].
async fn probe_encryption_boundary(
    blob: &dyn BlobStore,
    key: &SecretKey,
) -> anyhow::Result<ProbeReport> {
    let ciphertext = seal(key, PROBE_PLAINTEXT, PROBE_KEY.as_bytes())
        .context("sealing the probe plaintext failed")?;

    // Defensive guard against a future `seal` regression that forgets to
    // encrypt: the real `seal` always prepends a 24-byte nonce and appends a
    // 16-byte tag, so this can never fire today. The load-bearing boundary
    // check is `fetched != PROBE_PLAINTEXT` below, since `blob` (not `seal`) is
    // the injected, untrusted seam.
    ensure!(
        ciphertext.as_slice() != PROBE_PLAINTEXT,
        "seal returned the plaintext unchanged: the encryption layer is a no-op"
    );

    blob.put(PROBE_KEY, ciphertext.clone())
        .await
        .context("storing the probe ciphertext failed")?;

    // Read back first, then delete unconditionally: the probe must never leave
    // its object behind, even when a check below fails and returns early. Delete
    // is idempotent and best-effort, so its failure must not fail the probe — but
    // a genuine transport/permission fault leaves the sentinel object behind, so
    // log it (MemError is secret-free) to aid diagnosis.
    let fetched = blob.get(PROBE_KEY).await;
    if let Err(err) = blob.delete(PROBE_KEY).await {
        tracing::debug!(%err, "probe cleanup delete failed; sentinel object may remain");
    }
    let fetched = fetched.context("fetching the probe ciphertext back failed")?;

    ensure!(
        fetched.as_slice() != PROBE_PLAINTEXT,
        "the gateway returned plaintext — only ciphertext must ever be stored"
    );

    let opened = open(key, &fetched, PROBE_KEY.as_bytes())
        .context("decrypting the probe ciphertext failed")?;
    ensure!(
        opened.as_slice() == PROBE_PLAINTEXT,
        "decrypted probe bytes did not round-trip to the known plaintext"
    );

    Ok(ProbeReport {
        bytes_written: ciphertext.len(),
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert success/failure of Result-returning probe steps"
    )]
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
    )]

    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use hippius_mem_core::{
        BlobStore, HashEmbedder, HeadPointer, HeadRegression, HeadWatermarks, InMemoryIndex,
        MemError, MemberKey, MemoryBlobStore, MemoryStore, NetworkPrefix, NoopAnchor, NoteType, Op,
        OpContent, OpKind, OpLogStore, QuarantinedAuthor, RememberInput, RepoScope, SecretKey,
        Signature, Signer, Sr25519Signer, Ss58, SuppressedTail, TeamManifest, VerifyingKey,
        WrappedKey, content_hash, derive_identity, provision_team_key, publish_manifest,
        read_heads, seal, signer_from_mnemonic, wrapped_key_key,
    };

    use super::{
        PROBE_KEY, PROBE_PLAINTEXT, head_regression_lines, offline_report_lines,
        op_log_integrity_lines, probe_encryption_boundary, probe_live, quarantine_lines,
        removed_member_still_holds_key_lines, resolve_profile_for_remote, stale_max_epoch_line,
        suppressed_tail_lines, unsigned_or_unauthorized_wrapped_key_lines,
    };
    use crate::config::{Config, StorageBackend};

    /// A [`BlobStore`] that hides ONE object key from `get` and `list`, forwarding
    /// everything else to an inner [`MemoryBlobStore`].
    ///
    /// The `BlobStore` trait's `delete` is not enough to model this: a test must
    /// SEED a complete bucket (so the anchor records and the head pointer are the
    /// ones a real write produced) and only then make one object invisible, which
    /// is exactly what a bucket suppressing a tail op does.
    struct HidingBlobStore {
        inner: Arc<MemoryBlobStore>,
        hidden: String,
    }

    #[async_trait::async_trait]
    impl BlobStore for HidingBlobStore {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            if key == self.hidden {
                return Err(MemError::NotFound { id: key.to_owned() });
            }
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            let keys = self.inner.list(prefix).await?;
            Ok(keys.into_iter().filter(|key| *key != self.hidden).collect())
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// A [`BlobStore`] that lets a teammate's write land in the bucket at exactly
    /// the boundary BETWEEN `op_log_integrity_lines`' two reads.
    ///
    /// The heads read and the op-log read are one `list` call each, so "after the
    /// first `list` returns, before the second begins" is a deterministic seam — no
    /// threads, no sleeps, no timing. `pending` holds the complete teammate write
    /// (its op object and its head object); the first `list` serves the pre-write
    /// bucket and then materialises both, so the SECOND read sees them.
    ///
    /// That is the whole test: which of the two reads runs second decides whether a
    /// concurrent write looks like a truncated tail. Heads-then-ops puts the new op
    /// in the later read and its head is simply absent — silent. Ops-then-heads puts
    /// the new head in the later read while its op is missing from the earlier one —
    /// head-ahead-of-log, a false accusation against an honest teammate.
    struct WriteBetweenReadsStore {
        inner: Arc<MemoryBlobStore>,
        /// `(key, bytes)` pairs written into `inner` once the first `list` returns.
        pending: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    }

    #[async_trait::async_trait]
    impl BlobStore for WriteBetweenReadsStore {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            // Serve the pre-write view for THIS listing...
            let keys = self.inner.list(prefix).await?;
            // ...then land the teammate's write, so only a LATER listing sees it.
            // Drained under the guard and applied after it is dropped, so the lock
            // never spans the `put` await.
            let landing = {
                let mut pending = self
                    .pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                std::mem::take(&mut *pending)
            };
            for (key, bytes) in landing {
                self.inner.put(&key, bytes).await?;
            }
            Ok(keys)
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// A [`BlobStore`] fake whose `get` returns whatever bytes the test seeded,
    /// independent of what was `put`. It models a gateway that violated the
    /// encryption boundary — returning plaintext or corrupted ciphertext — which
    /// a faithful store would never do, so only an injected fake can exercise
    /// those failure paths.
    struct CannedGetStore {
        /// Bytes every `get` hands back, regardless of key.
        canned: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl BlobStore for CannedGetStore {
        async fn put(&self, _key: &str, _bytes: Vec<u8>) -> Result<(), MemError> {
            Ok(())
        }

        async fn get(&self, _key: &str) -> Result<Vec<u8>, MemError> {
            Ok(self.canned.clone())
        }

        async fn list(&self, _prefix: &str) -> Result<Vec<String>, MemError> {
            Ok(Vec::new())
        }

        async fn delete(&self, _key: &str) -> Result<(), MemError> {
            Ok(())
        }
    }

    /// The doctor-surface test for the broken-chain check: the seeded-bucket
    /// wrapper, not just the renderer.
    ///
    /// What only this test covers is the wiring that stands between a real fork
    /// and the operator: constructing the [`OpLogStore`] over the doctor's own
    /// blob handle, passing the right `team`, and the best-effort `let Ok(..)
    /// else` arm. A silent failure in any of those restores the exact bug this
    /// check exists to fix — doctor reporting healthy while the evidence sits in
    /// the bucket — and the renderer test cannot see it.
    #[tokio::test]
    async fn a_forked_chain_in_the_bucket_reaches_the_doctor_report()
    -> Result<(), Box<dyn std::error::Error>> {
        const TEAM: &str = "clientx";
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let signer = Sr25519Signer::from_seed_with_prefix(&[9u8; 32], NetworkPrefix::HIPPIUS)?;
        let author = signer.author_ss58();
        let store_signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &[9u8; 32],
            NetworkPrefix::HIPPIUS,
        )?);
        let store = MemoryStore::new(
            Arc::clone(&blob),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(Arc::clone(&blob)),
            Arc::new(NoopAnchor),
            store_signer,
            BTreeMap::from([(0_u64, SecretKey::from_bytes([7u8; 32]))]),
            0,
            TEAM.to_owned(),
            1,
        );
        store
            .remember(RememberInput {
                note_type: NoteType::Decision,
                repo: RepoScope::Global,
                tags: BTreeSet::new(),
                summary: "the honest write".to_owned(),
                body: "body of the honest write".to_owned(),
                force: true,
            })
            .await?;

        // An intact log must stay quiet, so the assertions below cannot be
        // satisfied by a check that always warns.
        assert!(
            op_log_integrity_lines(Arc::clone(&blob), TEAM, None)
                .await
                .is_empty(),
            "an unforked op-log must add no lines to the doctor report"
        );

        // Fork the author's chain root: a second op sharing the first's
        // `prev_op_hash` (GENESIS_PREV). Both branches are height-1 leaves, so the
        // tie resolves on the LOWER `(lamport, op_id, hash)` — the sibling's
        // Lamport is deliberately higher, so the SIBLING is what gets quarantined
        // and the honest op survives.
        let oplog = OpLogStore::new(Arc::clone(&blob));
        let ops = oplog.read_all(TEAM).await?;
        let root = ops.first().ok_or("the remember must have written one op")?;
        let sibling = Op::create_signed(
            &signer,
            OpContent {
                op_id: root.op_id,
                lamport: root.lamport.saturating_add(1),
                key_epoch: root.key_epoch,
                kind: OpKind::Remember,
                note_id: root.note_id,
                object_key: format!("{TEAM}/global/{}/ver_forked-sibling", root.note_id),
                cid: content_hash(b"the forked sibling's ciphertext"),
                prev_op_hash: root.prev_op_hash,
            },
        );
        oplog.append(TEAM, &sibling).await?;

        let lines = op_log_integrity_lines(Arc::clone(&blob), TEAM, None).await;

        assert_eq!(
            lines.len(),
            1,
            "one line for the one forked author: {lines:?}"
        );
        assert!(
            lines[0].contains(author.as_str()),
            "the line must name the author whose chain broke: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("lost 1 op(s)"),
            "the line must carry the exact count the read dropped: {}",
            lines[0]
        );

        // The `team` argument is really threaded through to the op-log prefix: the
        // same bucket, asked about a team that never wrote, has nothing to report.
        assert!(
            op_log_integrity_lines(Arc::clone(&blob), "a-team-that-never-wrote", None)
                .await
                .is_empty(),
            "the check must read the team it was asked about, not the whole bucket"
        );
        Ok(())
    }

    #[test]
    fn quarantined_authors_produce_one_named_line_each() {
        let first = Ss58::new("5CthWdw5iYzoh92cwLUCKb7G2dZMtW45XMUFQ5bMyv1QFjtA")
            .expect("a valid SS58 fixture");
        let second = Ss58::new("5GCNV7KK1Y62v1WNsV4rdvn81SeeXX1z24YYfvuoX2wsW6S1")
            .expect("a valid SS58 fixture");
        let lines = quarantine_lines(&[
            QuarantinedAuthor {
                author: first.clone(),
                dropped_ops: 3,
            },
            QuarantinedAuthor {
                author: second.clone(),
                dropped_ops: 1,
            },
        ]);

        assert_eq!(lines.len(), 2, "one line per affected author: {lines:?}");
        assert!(
            lines[0].contains(first.as_str()) && lines[0].contains("lost 3 op(s)"),
            "the line must name the author and the exact count: {}",
            lines[0]
        );
        assert!(
            lines[1].contains(second.as_str()) && lines[1].contains("lost 1 op(s)"),
            "counts must not be shared between authors: {}",
            lines[1]
        );
        // The honest limit travels with the finding: an operator reading only this
        // line must not conclude an attack from it.
        assert!(
            lines[0].contains("not its cause"),
            "the line must say it does not identify a cause: {}",
            lines[0]
        );
        // The cause list must include the one an operator is most likely to have
        // caused themselves and least likely to guess: two concurrent agent
        // sessions, which this product's user-global MCP registration produces
        // under a single author key. Omitting it from a list that claims to
        // enumerate the causes is how an operator concludes "bucket" and stops.
        //
        // Now scoped to DIFFERENT MACHINES, because the cross-process writer lock
        // closed the same-machine half. Asserting the narrowed wording rather than
        // a loose substring is deliberate: if that lock is ever removed or wired
        // out, the cause widens again and this line has to widen with it, so the
        // assertion should fail rather than keep passing on stale prose. This test
        // has already caught exactly that once, in the commit that narrowed it.
        assert!(
            lines[0].contains("TWO HONEST WRITERS UNDER ONE IDENTITY ON DIFFERENT MACHINES"),
            "the cause list must name the same-identity write race, scoped to the case the \
             writer lock does not close: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("must be re-issued"),
            "and must say those ops are gone for good rather than self-clearing, since \
             that is what distinguishes it from a head regression: {}",
            lines[0]
        );
    }

    #[test]
    fn an_intact_op_log_produces_no_quarantine_lines() {
        assert!(
            quarantine_lines(&[]).is_empty(),
            "a healthy log must add no noise to the doctor report"
        );
        assert!(
            suppressed_tail_lines(&[]).is_empty(),
            "an untruncated log must add no noise to the doctor report"
        );
    }

    #[test]
    fn suppressed_tails_produce_one_named_line_each() {
        let author = Ss58::new("5CthWdw5iYzoh92cwLUCKb7G2dZMtW45XMUFQ5bMyv1QFjtA")
            .expect("a valid SS58 fixture");
        let tip = content_hash(b"the tip the author signed");
        let lines = suppressed_tail_lines(&[
            SuppressedTail {
                author: author.clone(),
                author_key: VerifyingKey::new([0xDD; 32]),
                claimed_tip: tip,
                claimed_lamport: 11,
                visible_lamport: Some(9),
            },
            SuppressedTail {
                author: author.clone(),
                author_key: VerifyingKey::new([0xEE; 32]),
                claimed_tip: tip,
                claimed_lamport: 4,
                visible_lamport: None,
            },
        ]);

        assert_eq!(lines.len(), 2, "one line per affected author: {lines:?}");
        // An operator must be able to act on the line alone: who claimed it, which
        // op is gone, and how far the visible log lags.
        assert!(
            lines[0].contains(author.as_str())
                && lines[0].contains(&tip.to_hex())
                && lines[0].contains("lamport 11"),
            "the line must name the author, the claimed tip, and its lamport: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("newest op visible for them is lamport 9"),
            "a partially-visible author's line must report how far the log lags: {}",
            lines[0]
        );
        // The whole-author case reads differently from a truncated tail, so an
        // operator is not told there is a "newest visible op" when there is none.
        assert!(
            lines[1].contains("not one op of theirs is visible at all"),
            "an author with no visible ops must be described as such: {}",
            lines[1]
        );
        // Both honest limits travel with the finding: it is not proof of
        // suppression, and a clean run is not proof of no suppression.
        assert!(
            lines[0].contains("does NOT prove suppression"),
            "the line must not overclaim what it detected: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("silent in THREE cases")
                && lines[0].contains("the bucket also dropped the head object")
                && lines[0].contains("best-effort head publish simply FAILED"),
            "the line must state ALL THREE residuals this check cannot see, including the \
             failed-publish one that head_regressions does not cover either: {}",
            lines[0]
        );
    }

    /// A teammate's write landing between the two reads must NOT be reported as a
    /// suppressed tail.
    ///
    /// This pins the read ORDER inside `op_log_integrity_lines`. Whichever of the
    /// heads read and the op-log read runs second sees the fresher bucket, and the
    /// tail check reports "a head names a tip the ops do not contain" — so reading
    /// the ops first puts a concurrent write's head in the later read while its op
    /// is missing from the earlier one, which is exactly the evidence condition. The
    /// output is not a missed detection but a WARN accusing a named, honest teammate
    /// of suppressing their own tail, over a window as wide as the whole verified
    /// op-log read.
    ///
    /// The teammate is a SECOND author whose chain is one genesis-rooted op, so
    /// their arrival cannot break anyone's chain and the only line it could produce
    /// is the false tail accusation. Swapping the two reads in
    /// `op_log_integrity_lines` fails this test with that author named.
    #[tokio::test]
    async fn a_write_landing_between_the_two_reads_is_not_reported_as_a_truncated_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        const TEAM: &str = "clientx";
        let inner = Arc::new(MemoryBlobStore::default());
        let blob: Arc<dyn BlobStore> = inner.clone();

        // An existing author with one settled write, so the bucket is not empty and
        // the op-log read has something to link up.
        let settled: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &[9u8; 32],
            NetworkPrefix::HIPPIUS,
        )?);
        let store = MemoryStore::new(
            Arc::clone(&blob),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(Arc::clone(&blob)),
            Arc::new(NoopAnchor),
            Arc::clone(&settled),
            BTreeMap::from([(0_u64, SecretKey::from_bytes([7u8; 32]))]),
            0,
            TEAM.to_owned(),
            1,
        );
        store
            .remember(RememberInput {
                note_type: NoteType::Decision,
                repo: RepoScope::Global,
                tags: BTreeSet::new(),
                summary: "the settled write".to_owned(),
                body: "body of the settled write".to_owned(),
                force: true,
            })
            .await?;

        // The teammate's write, pre-built but NOT yet in the bucket: one
        // genesis-rooted op plus the head naming it, exactly what a real write
        // publishes.
        let teammate = Sr25519Signer::from_seed_with_prefix(&[21u8; 32], NetworkPrefix::HIPPIUS)?;
        // `op_id`/`note_id` are borrowed from the settled op rather than minted here
        // (this crate does not depend on `ulid`). Sharing them is harmless: the
        // op-log key is namespaced by author key, so the two objects cannot collide,
        // and a second author writing about the same note is ordinary convergence.
        let settled_ops = OpLogStore::new(Arc::clone(&blob)).read_all(TEAM).await?;
        let settled_op = settled_ops
            .first()
            .ok_or("the settled write appended one op")?;
        let note_id = settled_op.note_id;
        let op = Op::create_signed(
            &teammate,
            OpContent {
                op_id: settled_op.op_id,
                lamport: 1,
                key_epoch: 0,
                kind: OpKind::Remember,
                note_id,
                object_key: format!("{TEAM}/global/{note_id}/ver_teammate"),
                cid: content_hash(b"the teammate's ciphertext"),
                prev_op_hash: hippius_mem_core::GENESIS_PREV,
            },
        );
        let head = HeadPointer::create_signed(&teammate, TEAM, op.lamport, op.hash());
        let pending = vec![
            (
                format!(
                    "{TEAM}/_oplog/{:020}_{}_{}",
                    op.lamport,
                    op.op_id,
                    op.author_key.to_hex()
                ),
                serde_json::to_vec(&op)?,
            ),
            (
                format!("{TEAM}/_heads/{}", op.author_key.to_hex()),
                serde_json::to_vec(&head)?,
            ),
        ];

        let racing: Arc<dyn BlobStore> = Arc::new(WriteBetweenReadsStore {
            inner: Arc::clone(&inner),
            pending: std::sync::Mutex::new(pending),
        });

        let lines = op_log_integrity_lines(Arc::clone(&racing), TEAM, None).await;

        assert!(
            lines.is_empty(),
            "a teammate's write landing between the two reads must produce no line at all; \
             reading the ops BEFORE the heads makes it look like a truncated tail: {lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains(teammate.author_ss58().as_str())),
            "the honest teammate must never be named: {lines:?}"
        );

        // Positive control: once BOTH objects are settled in the bucket, the same
        // check over the same data is still silent. Without this, the assertion
        // above would also pass if the teammate's write simply never landed.
        assert!(
            op_log_integrity_lines(Arc::clone(&blob), TEAM, None)
                .await
                .is_empty(),
            "with the teammate's op and head both settled, the log is healthy"
        );
        let settled_heads = hippius_mem_core::read_heads(&blob, TEAM).await?;
        assert_eq!(
            settled_heads.len(),
            2,
            "the teammate's write really did land in the bucket, so the silence above \
             is about ordering, not about an absent write"
        );
        Ok(())
    }

    #[test]
    fn head_regressions_produce_one_named_line_each() {
        let author = Ss58::new("5CthWdw5iYzoh92cwLUCKb7G2dZMtW45XMUFQ5bMyv1QFjtA")
            .expect("a valid SS58 fixture");
        let remembered = content_hash(b"the head this machine already verified");
        let served = content_hash(b"the head the bucket serves now");
        let lines = head_regression_lines(&[
            HeadRegression {
                author: author.clone(),
                author_key: VerifyingKey::new([0xDD; 32]),
                remembered_lamport: 11,
                remembered_tip: remembered,
                served_lamport: Some(4),
                served_tip: Some(served),
            },
            HeadRegression {
                author: author.clone(),
                author_key: VerifyingKey::new([0xEE; 32]),
                remembered_lamport: 7,
                remembered_tip: remembered,
                served_lamport: None,
                served_tip: None,
            },
        ]);

        assert_eq!(lines.len(), 2, "one line per affected author: {lines:?}");
        // A rolled-back head: the line must name who, what this machine remembered,
        // and what the bucket serves instead — enough to act on without the report.
        assert!(
            lines[0].contains(author.as_str())
                && lines[0].contains(&remembered.to_hex())
                && lines[0].contains("lamport 11")
                && lines[0].contains(&served.to_hex())
                && lines[0].contains("lamport 4"),
            "the rollback line must name the author, both tips and both lamports: {}",
            lines[0]
        );
        // A withdrawn head has no served value at all, and the line must say so
        // rather than printing a misleading zero.
        assert!(
            lines[1].contains("no verifiable head"),
            "the dropped-head line must say no head came back, not invent one: {}",
            lines[1]
        );
        // Both honest limits travel with the finding: the benign re-created-team
        // cause with its remedy, and the silence a machine with no marks produces.
        for line in &lines {
            assert!(
                line.contains("head-watermarks.json"),
                "the line must name the state file so the benign cause is actionable: {line}"
            );
            assert!(
                line.contains("not already verified a head for"),
                "the line must say silence is not an all-clear: {line}"
            );
            assert!(
                line.contains("does NOT by itself prove any op was suppressed"),
                "the line must not overclaim a lowered head as a suppressed op: {line}"
            );
            // The M1 correction, pinned: the line must NOT assert that the bucket
            // withdrew the claim. The key-holder can publish a lower head too, and
            // two ordinary cases do — a line that skips this accuses the operator's
            // own identity with no qualification.
            assert!(
                line.contains("does NOT follow that the bucket withdrew it"),
                "the line must not claim a backward head proves a bucket withdrawal: {line}"
            );
            assert!(
                line.contains("TWO PROCESSES UNDER ONE IDENTITY"),
                "the line must name the same-identity head-PUT race: {line}"
            );
            assert!(
                line.contains("RESTARTED PROCESS RE-SEEDING"),
                "the line must name the re-seeded-from-a-short-view case, where the served \
                 head is brand new rather than withdrawn: {line}"
            );
            assert!(
                line.contains("keyed on the TEAM NAME"),
                "the line must name the shared-team-name cause beside the re-created-team \
                 one, since both have the same remedy: {line}"
            );
            // The third ordinary cause: no lower head is published at all, the
            // regression is against this machine's OWN identity, and no second
            // process is involved. An enumeration written as a closed set that omits
            // it sends an operator hunting for a concurrency bug that is not there.
            assert!(
                line.contains("ORDINARY READ-LAG AGAINST THIS MACHINE'S OWN IDENTITY"),
                "the line must name the eventually-consistent listing cause: {line}"
            );
            // "Routine" must never render as "harmless": the same two processes can
            // self-fork the chain, which is permanent, unlike this evidence.
            assert!(
                line.contains("self-fork this author's chain"),
                "the line must carry the self-fork counterweight beside the clears-itself \
                 promise, or 'routine' reads as 'harmless': {line}"
            );
            assert!(
                line.contains("best-effort head publish merely FAILED"),
                "the line must state that it does not cover the third suppressed-tail \
                 residual either: {line}"
            );
        }
    }

    /// The doctor-surface test for the head-regression check: the seeded-bucket
    /// wrapper and the shared marks file, not just the renderer.
    ///
    /// What only this test covers is that `doctor` passes marks at all. Passing
    /// `None` there would leave the whole feature dead on this surface while every
    /// unit test above still passed, and the report would read exactly as it does
    /// on a healthy team.
    #[tokio::test]
    async fn a_rolled_back_head_in_the_bucket_reaches_the_doctor_report()
    -> Result<(), Box<dyn std::error::Error>> {
        const TEAM: &str = "clientx";
        let dir = tempfile::tempdir()?;
        let marks = HeadWatermarks::load(dir.path().join("state").join("head-watermarks.json"));
        let inner = Arc::new(MemoryBlobStore::default());
        let blob: Arc<dyn BlobStore> = inner.clone();
        let store_signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &[9u8; 32],
            NetworkPrefix::HIPPIUS,
        )?);
        let author = store_signer.author_ss58();
        let store = MemoryStore::new(
            Arc::clone(&blob),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(Arc::clone(&blob)),
            Arc::new(NoopAnchor),
            store_signer,
            BTreeMap::from([(0_u64, SecretKey::from_bytes([7u8; 32]))]),
            0,
            TEAM.to_owned(),
            1,
        );
        let remember = |summary: &str| RememberInput {
            note_type: NoteType::Decision,
            repo: RepoScope::Global,
            tags: BTreeSet::new(),
            summary: summary.to_owned(),
            body: format!("body of {summary}"),
            force: true,
        };
        store.remember(remember("the first write")).await?;
        let stale_head = read_heads(&blob, TEAM)
            .await?
            .last()
            .cloned()
            .ok_or("the first write must publish a head")?;
        store.remember(remember("the second write")).await?;

        // THE RETURNING-MACHINE PREMISE: a healthy doctor run, which is what leaves
        // the mark at the higher head. It must also stay quiet, so the assertion
        // below cannot be satisfied by a check that always warns.
        assert!(
            op_log_integrity_lines(Arc::clone(&blob), TEAM, Some(&marks))
                .await
                .is_empty(),
            "a healthy run must add no lines, and is what records the honest head"
        );

        // The bucket rolls the head object back to the first write's. Nothing else
        // changes: every op is still present, so the truncated-tail check has
        // nothing to say and only the regression can produce a line.
        let current_tip = OpLogStore::new(Arc::clone(&blob))
            .read_all(TEAM)
            .await?
            .last()
            .ok_or("expected two ops")?
            .hash();
        hippius_mem_core::publish_head(&blob, TEAM, &stale_head).await?;

        let lines = op_log_integrity_lines(Arc::clone(&blob), TEAM, Some(&marks)).await;

        assert_eq!(
            lines.len(),
            1,
            "one line for the one rolled-back head: {lines:?}"
        );
        assert!(
            lines[0].contains(author.as_str())
                && lines[0].contains(&current_tip.to_hex())
                && lines[0].contains(&stale_head.tip_hash.to_hex()),
            "the line must name the author, the head this machine remembered, and the \
             one the bucket serves instead: {}",
            lines[0]
        );
        Ok(())
    }

    /// The doctor-surface test for the truncated-tail check: the seeded-bucket
    /// wrapper, not just the renderer.
    ///
    /// What only this test covers is the wiring between a real truncation and the
    /// operator — reading the heads over the doctor's own blob handle, passing the
    /// right `team`, and comparing against the ops the SAME read produced. A
    /// silent failure in any of those reproduces the bug this check exists to fix:
    /// doctor reporting healthy while the evidence sits in the bucket.
    #[tokio::test]
    async fn a_truncated_tail_in_the_bucket_reaches_the_doctor_report()
    -> Result<(), Box<dyn std::error::Error>> {
        const TEAM: &str = "clientx";
        let inner = Arc::new(MemoryBlobStore::default());
        let blob: Arc<dyn BlobStore> = inner.clone();
        let store_signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            &[9u8; 32],
            NetworkPrefix::HIPPIUS,
        )?);
        let author = store_signer.author_ss58();
        let store = MemoryStore::new(
            Arc::clone(&blob),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(Arc::clone(&blob)),
            Arc::new(NoopAnchor),
            store_signer,
            BTreeMap::from([(0_u64, SecretKey::from_bytes([7u8; 32]))]),
            0,
            TEAM.to_owned(),
            1,
        );
        for summary in ["the first write", "the second write"] {
            store
                .remember(RememberInput {
                    note_type: NoteType::Decision,
                    repo: RepoScope::Global,
                    tags: BTreeSet::new(),
                    summary: summary.to_owned(),
                    body: format!("body of {summary}"),
                    force: true,
                })
                .await?;
        }

        // An intact log must stay quiet, so the assertions below cannot be
        // satisfied by a check that always warns.
        assert!(
            op_log_integrity_lines(Arc::clone(&blob), TEAM, None)
                .await
                .is_empty(),
            "an untruncated op-log must add no lines to the doctor report"
        );

        // Hide the tail op object: the bucket serves the head, which still names it.
        let oplog = OpLogStore::new(Arc::clone(&blob));
        let ops = oplog.read_all(TEAM).await?;
        let tail = ops.last().ok_or("expected two ops")?;
        let tail_key = format!(
            "{TEAM}/_oplog/{:020}_{}_{}",
            tail.lamport,
            tail.op_id,
            tail.author_key.to_hex()
        );
        let truncating: Arc<dyn BlobStore> = Arc::new(HidingBlobStore {
            inner: Arc::clone(&inner),
            hidden: tail_key,
        });

        let lines = op_log_integrity_lines(Arc::clone(&truncating), TEAM, None).await;

        assert_eq!(
            lines.len(),
            1,
            "one line for the one truncated tail: {lines:?}"
        );
        assert!(
            lines[0].contains(author.as_str()) && lines[0].contains(&tail.hash().to_hex()),
            "the line must name the author and the tip they signed: {}",
            lines[0]
        );

        // The `team` argument is really threaded through to the heads prefix: the
        // same bucket, asked about a team that never wrote, has nothing to report.
        assert!(
            op_log_integrity_lines(Arc::clone(&truncating), "a-team-that-never-wrote", None)
                .await
                .is_empty(),
            "the check must read the team it was asked about, not the whole bucket"
        );
        Ok(())
    }

    #[test]
    fn report_contains_the_four_non_secret_coordinates() {
        let lines = offline_report_lines(
            "clientx",
            "team-bucket",
            "AKIAEXAMPLE",
            "5GExampleSs58Address",
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("profile: clientx"),
            "report must name the diagnosed profile: {joined}"
        );
        assert!(
            joined.contains("team-bucket"),
            "report must name the bucket: {joined}"
        );
        assert!(
            joined.contains("AKIAEXAMPLE"),
            "report must name the access_key_id: {joined}"
        );
        assert!(
            joined.contains("5GExampleSs58Address"),
            "report must name the author SS58: {joined}"
        );
    }

    /// A minimal valid multi-profile config: primary is the catch-all
    /// (`ourovoros`), plus one org-routed `clientx` profile with a DIFFERENT
    /// bucket. Mirrors `config.rs`'s `valid_toml`/`team_block` fixtures.
    fn multi_profile_toml() -> String {
        "bucket = \"primary-bucket\"\n\
         access_key_id = \"AKID\"\n\
         secret = \"s3-sub-token-secret\"\n\
         team = \"ourovoros\"\n\
         team_key_hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n\
         author_seed_hex = \"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\"\n\
         \n\
         [[teams]]\n\
         name = \"clientx\"\n\
         orgs = [\"github.com/clientx\"]\n\
         bucket = \"clientx-bucket\"\n\
         access_key_id = \"AK-clientx\"\n\
         secret = \"s3-sub-token-secret\"\n\
         team_key_hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n\
         author_seed_hex = \"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\"\n"
            .to_owned()
    }

    #[test]
    fn resolve_profile_for_remote_routes_by_remote_not_the_primary() {
        // The bug this fixes: doctor used to always validate/probe the flat
        // PRIMARY profile (`cfg.signer()`/`cfg.bucket` etc.), never a `[[teams]]`
        // profile, so a repo routed to `clientx` would have its `clientx-bucket`
        // never checked even though that is the bucket the server actually binds
        // there (finding [13]).
        let cfg = Config::from_toml_str(&multi_profile_toml()).expect("valid multi-profile config");
        let profile = resolve_profile_for_remote(&cfg, Some("git@github.com:clientx/app.git"))
            .expect("clientx repo routes to a bound profile");
        assert_eq!(profile.name, "clientx");
        assert_eq!(
            profile.bucket, "clientx-bucket",
            "doctor must probe the CLIENTX bucket for a clientx repo, not the primary's"
        );
    }

    #[test]
    fn resolve_profile_for_remote_falls_back_to_the_catch_all() {
        // A repo whose remote matches no `orgs` still routes to the primary
        // (the effective catch-all here), exactly as the server would.
        let cfg = Config::from_toml_str(&multi_profile_toml()).expect("valid multi-profile config");
        let profile = resolve_profile_for_remote(&cfg, Some("git@github.com:someoneelse/x.git"))
            .expect("unmatched repo falls back to the catch-all");
        assert_eq!(profile.name, "ourovoros");
        assert_eq!(profile.bucket, "primary-bucket");
    }

    #[test]
    fn resolve_profile_for_remote_errors_when_memory_is_disabled() {
        // A single org-scoped profile with no catch-all: an unmatched remote must
        // surface an error naming the disabled reason, not silently fall back to
        // validating an unrelated profile.
        let toml = "bucket = \"b\"\n\
             access_key_id = \"AK\"\n\
             secret = \"s\"\n\
             team = \"ourovoros\"\n\
             team_key_hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n\
             author_seed_hex = \"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\"\n\
             orgs = [\"github.com/ourovoros\"]\n";
        let cfg = Config::from_toml_str(toml).expect("valid config");
        let err = resolve_profile_for_remote(&cfg, Some("git@github.com:someoneelse/x.git"))
            .expect_err("an unmatched repo with no catch-all must be disabled, not routed");
        assert!(
            err.to_string().contains("disabled"),
            "error must name the disabled reason: {err}"
        );
    }

    #[tokio::test]
    async fn probe_round_trips_over_clean_store() {
        let blob = MemoryBlobStore::default();
        let key = SecretKey::from_bytes([7u8; 32]);

        let report = probe_encryption_boundary(&blob, &key)
            .await
            .expect("probe must succeed over a faithful store");

        assert!(
            report.bytes_written > 0,
            "probe must report the sealed byte count"
        );
        // The probe deletes its object regardless of outcome, so a clean store is
        // empty again afterwards: a follow-up `get` must miss.
        let leftover = blob.get(PROBE_KEY).await;
        assert!(
            matches!(leftover, Err(MemError::NotFound { .. })),
            "probe must clean up its object, got {leftover:?}"
        );
    }

    #[tokio::test]
    async fn probe_rejects_a_store_that_returns_plaintext() {
        let blob = CannedGetStore {
            canned: PROBE_PLAINTEXT.to_vec(),
        };
        let key = SecretKey::from_bytes([7u8; 32]);

        let err = probe_encryption_boundary(&blob, &key)
            .await
            .expect_err("a gateway returning plaintext must fail the probe");

        // Assert it failed at the plaintext-leak check specifically, not merely
        // that some error occurred (e.g. a spurious decrypt failure would also
        // be an error but would mean the test is not exercising this boundary).
        assert!(
            err.to_string().contains("returned plaintext"),
            "expected the plaintext-leak failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn probe_rejects_a_store_that_corrupts_ciphertext() {
        let key = SecretKey::from_bytes([7u8; 32]);
        // Seal a valid blob, then flip a tag byte so `open`'s authentication
        // fails — the corruption path, distinct from the plaintext-leak path.
        let mut corrupted = seal(&key, PROBE_PLAINTEXT, PROBE_KEY.as_bytes())
            .expect("sealing the fixed probe plaintext is infallible here");
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xFF;
        let blob = CannedGetStore { canned: corrupted };

        let err = probe_encryption_boundary(&blob, &key)
            .await
            .expect_err("corrupted ciphertext must fail the round-trip");

        // Assert it failed at the `open` (decrypt) step specifically: the
        // corrupted bytes pass the `fetched != PROBE_PLAINTEXT` check but must
        // fail authentication, so the error must come from decrypting.
        assert!(
            err.to_string().contains("decrypting"),
            "expected the decrypt failure, got: {err}"
        );
    }

    /// A `storage = "local"` profile's live probe must bind an `FsBlobStore`
    /// over its trial root, never the `S3BlobStore` an S3 profile uses — the
    /// bug this pins: `probe_live` used to build an `S3BlobStore`
    /// unconditionally, so a fresh trial vault's doctor probe (no bucket, no
    /// credentials) failed against the real gateway instead of succeeding
    /// against local disk.
    #[tokio::test]
    async fn probe_live_uses_fs_blob_store_for_a_local_profile() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = Config {
            team: "trial".to_owned(),
            team_key_hex: "ab".repeat(32),
            author_seed_hex: "cd".repeat(32),
            storage: StorageBackend::Local,
            local_root: Some(dir.path().to_path_buf()),
            ..Config::default()
        };
        let profile = cfg.primary_profile();

        probe_live(&cfg, &profile).await?;

        // The probe cleans up after itself; the trial root gains only the
        // `_doctor/` directory the probe created, no leftover object.
        assert!(
            !dir.path().join(PROBE_KEY).exists(),
            "the probe object must not remain on disk"
        );
        Ok(())
    }

    /// `probe_live`'s S3 blob store must carry the SAME local encrypted cache
    /// [`crate::config::TeamProfile::build_store`] wraps every S3 profile in by
    /// default — the divergence this pins, once the hand-rolled S3-vs-local
    /// bug above was fixed: `probe_live` kept a doctor-local copy of the
    /// storage-backend match instead of calling
    /// [`crate::config::TeamProfile::build_blob_store`], so it built a BARE
    /// `S3BlobStore` and never applied the `CachingBlobStore` wrap. That made
    /// `probe_live`'s own doc claim — "probes the exact store the server
    /// would bind" — false for the common case (caching is on by default), and
    /// left it out of step with `reconcile`'s three comparisons
    /// (`op_log_integrity_lines`'s own doc says it mirrors those exactly),
    /// which DO run over the cached store. `probe_live` now calls
    /// `build_blob_store` directly, so this test on that one shared function
    /// pins `probe_live`'s actual construction, not a copy of it.
    ///
    /// No live gateway is needed: `CachingBlobStore::new` creates its cache
    /// directory synchronously at construction, before any network call, and
    /// `S3BlobStore::new` dials nothing either — so this pins the wrap from
    /// construction alone.
    #[test]
    fn probe_lives_s3_blob_store_carries_the_shared_local_cache() {
        const TEAM: &str = "doctor-build-blob-store-cache-pin";
        let Some(cache_dir) = crate::config::blob_cache_dir(TEAM) else {
            // No resolvable HOME/XDG_CACHE_HOME in this environment: caching is
            // disabled everywhere (build_blob_store's S3 branch falls back to
            // the bare S3BlobStore too, per its own `None => s3` arm), so
            // there is nothing on disk for this test to observe.
            return;
        };
        let _ = std::fs::remove_dir_all(&cache_dir);

        let cfg = Config {
            team: TEAM.to_owned(),
            team_key_hex: "ab".repeat(32),
            author_seed_hex: "cd".repeat(32),
            storage: StorageBackend::S3,
            bucket: "bucket".to_owned(),
            access_key_id: "access-key".to_owned(),
            secret: "secret".to_owned(),
            ..Config::default()
        };
        let profile = cfg.primary_profile();
        let key = profile
            .team_key()
            .expect("a well-formed team_key_hex decodes");

        let _blob = profile
            .build_blob_store(&cfg, &key)
            .expect("construction must not touch the network");

        assert!(
            cache_dir.is_dir(),
            "an S3 profile's blob store must be wrapped in a CachingBlobStore, whose \
             constructor creates this directory; the old hand-rolled probe_live factory \
             built a bare S3BlobStore and never created it: {}",
            cache_dir.display()
        );

        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    /// The doctor-surface test for the stale-`max_epoch` warning: a store
    /// holding an epoch-1 wrapped key against a configured `max_epoch = 0`
    /// must produce a report line telling the operator to raise it to 1.
    #[tokio::test]
    async fn stale_max_epoch_line_warns_when_the_bucket_holds_a_newer_epoch() -> Result<(), MemError>
    {
        const TEAM: &str = "clientx";
        const PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

        let blob = MemoryBlobStore::default();

        // Publish a wrapped key at epoch 1 via the real teamkey publish path
        // (`provision_team_key`), exactly how a rotation populates the bucket.
        let signer = signer_from_mnemonic(PHRASE, NetworkPrefix::HIPPIUS)?;
        let identity = derive_identity(PHRASE, NetworkPrefix::HIPPIUS)?;
        let member = MemberKey::create_signed(&signer, &identity);
        let team_key = SecretKey::from_bytes([1u8; 32]);
        provision_team_key(&blob, TEAM, &team_key, 1, &[member], None, &signer).await?;

        // Configured max_epoch = 0 never bootstraps the epoch-1 rotation: the
        // report must warn, naming the exact fix.
        let line = stale_max_epoch_line(&blob, TEAM, 0)
            .await
            .expect("a published epoch newer than max_epoch must produce a warning line");
        assert!(
            line.contains("raise max_epoch to 1"),
            "report line must name the actionable fix: {line}"
        );
        // Finding #15: max_epoch is a TOP-LEVEL Config field; TeamProfile
        // carries `#[serde(deny_unknown_fields)]`, so a message pointing at
        // "[[teams]]" would send the operator to add max_epoch there and
        // break parsing for every subsequent command.
        assert!(
            line.to_lowercase().contains("top level"),
            "report line must point at the top level of the config: {line}"
        );
        assert!(
            !line.contains("[[teams]]"),
            "report line must not point at a [[teams]] profile: {line}"
        );

        // A max_epoch that already covers the published epoch is not stale.
        assert!(
            stale_max_epoch_line(&blob, TEAM, 1).await.is_none(),
            "max_epoch at or above the highest published epoch must not warn"
        );
        Ok(())
    }

    /// The doctor-surface test for the "removed member still holds the
    /// current epoch key" check: a member wrapped the CURRENT epoch's team
    /// key whom the live manifest no longer lists must produce a warning
    /// naming them and the fix — the read-side symptom of the recorded
    /// `rotate --members` non-atomicity gotcha (publish lands, rotation
    /// refuses, and nobody ever finishes the rotation).
    #[tokio::test]
    async fn removed_member_still_holds_key_lines_warns_and_names_the_fix() -> Result<(), MemError>
    {
        const TEAM: &str = "clientx";
        const FOUNDER_PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        const REMOVED_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                       abandon abandon abandon abandon about";

        let blob = MemoryBlobStore::default();
        let founder_signer = signer_from_mnemonic(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;

        // v0: the roster includes the member who will be removed, so
        // provisioning them the epoch-0 key is authorized.
        let removed_identity = derive_identity(REMOVED_PHRASE, NetworkPrefix::HIPPIUS)?;
        let removed_signer = signer_from_mnemonic(REMOVED_PHRASE, NetworkPrefix::HIPPIUS)?;
        let removed_key = MemberKey::create_signed(&removed_signer, &removed_identity);
        let manifest_v0 = TeamManifest::create_signed(
            &founder_signer,
            TEAM.to_owned(),
            BTreeSet::from([removed_identity.ss58.clone()]),
            0,
        );
        publish_manifest(&blob, &manifest_v0).await?;

        let team_key = SecretKey::from_bytes([3u8; 32]);
        provision_team_key(
            &blob,
            TEAM,
            &team_key,
            0,
            &[removed_key],
            None,
            &founder_signer,
        )
        .await?;

        // v1: the founder publishes a shrunk roster (the `remove` half that
        // landed) -- but the epoch-0 key was never rotated to a fresh epoch,
        // so the wrap above is still on the bucket at the CURRENT (highest
        // published) epoch.
        let manifest_v1 =
            TeamManifest::create_signed(&founder_signer, TEAM.to_owned(), BTreeSet::new(), 1);
        publish_manifest(&blob, &manifest_v1).await?;

        let lines = removed_member_still_holds_key_lines(&blob, TEAM, None).await;
        assert_eq!(
            lines.len(),
            1,
            "exactly the one stale wrap must be flagged: {lines:?}"
        );
        assert!(
            lines[0].contains(removed_identity.ss58.as_str())
                && lines[0].contains("run: hippius-mem rotate"),
            "the line names the stale member and the fix: {}",
            lines[0]
        );
        Ok(())
    }

    /// Documents the check's known blind spot (see
    /// `removed_member_still_holds_key_lines`'s doc comment): a
    /// bundle-provisioned member (`join --bundle` hands `team_key_hex`
    /// directly and never wraps `_keys/` for that member) who is removed
    /// from the manifest is NOT flagged, because this check can only see
    /// `_keys/` recipients. This is acceptable because it is no longer the
    /// primary guard: `hippius-mem remove` now always rotates on a real
    /// removal regardless of `_keys/` (Task 3's fix), so this check's role
    /// is the half-done-removal backstop, not the bundle-member exposure.
    #[tokio::test]
    async fn removed_member_still_holds_key_lines_cannot_see_a_bundle_provisioned_member()
    -> Result<(), MemError> {
        const TEAM: &str = "clientx";
        const FOUNDER_PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        const BUNDLE_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                      abandon abandon abandon abandon about";

        let blob = MemoryBlobStore::default();
        let founder_signer = signer_from_mnemonic(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;
        let founder_identity = derive_identity(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;
        let founder_key = MemberKey::create_signed(&founder_signer, &founder_identity);
        let bundle_identity = derive_identity(BUNDLE_PHRASE, NetworkPrefix::HIPPIUS)?;

        // v0: the roster includes both the founder and the bundle-provisioned
        // member. Only the founder is ever wrapped at `_keys/` -- the bundle
        // member holds `team_key_hex` directly (join --bundle) and so never
        // appears there, at any epoch.
        let manifest_v0 = TeamManifest::create_signed(
            &founder_signer,
            TEAM.to_owned(),
            BTreeSet::from([bundle_identity.ss58.clone()]),
            0,
        );
        publish_manifest(&blob, &manifest_v0).await?;
        provision_team_key(
            &blob,
            TEAM,
            &SecretKey::from_bytes([4u8; 32]),
            0,
            &[founder_key],
            None,
            &founder_signer,
        )
        .await?;

        // v1: the bundle-provisioned member is removed from the roster -- a
        // REAL removal that (via the Task 3 fix) always rotates in
        // `admin::remove`. This check, however, only ever sees `_keys/`,
        // and the bundle member was never in it.
        let manifest_v1 =
            TeamManifest::create_signed(&founder_signer, TEAM.to_owned(), BTreeSet::new(), 1);
        publish_manifest(&blob, &manifest_v1).await?;

        let lines = removed_member_still_holds_key_lines(&blob, TEAM, None).await;
        assert!(
            lines.is_empty(),
            "a bundle-provisioned member is invisible to this _keys/-only check by \
             construction -- `remove`'s always-rotate-on-removal is the primary guard \
             against their stale key, not this doctor check: {lines:?}"
        );
        Ok(())
    }

    /// An open team (no manifest published yet) has no roster to compare a
    /// wrap against, so the check must stay silent rather than flag every
    /// wrap as "removed" -- it never applies before a manifest exists.
    #[tokio::test]
    async fn removed_member_still_holds_key_lines_is_silent_on_an_open_team() -> Result<(), MemError>
    {
        let blob = MemoryBlobStore::default();
        assert!(
            removed_member_still_holds_key_lines(&blob, "clientx", None)
                .await
                .is_empty(),
            "an open team (no manifest) must never be flagged"
        );
        Ok(())
    }

    /// A [`BlobStore`] wrapper whose `list` fails for exactly the TOP-LEVEL
    /// `_keys/` prefix — what `highest_published_epoch` reads — while a
    /// per-epoch `_keys/{epoch}/` listing (what `wrapped_key_recipients`
    /// reads) and everything else delegate untouched. Deliberately does NOT
    /// fail every `_keys/`-containing prefix: that would make
    /// `wrapped_key_recipients` fail too, which would ALSO yield an empty
    /// result via the function's second short-circuit regardless of whether
    /// the first one (I1's fix) is present — masking the exact bug this
    /// pins. Failing only the top-level listing isolates the one behavior
    /// under test: does a failed EPOCH lookup fall back to a hardcoded `0`?
    struct FailingTopLevelKeysListStore {
        inner: MemoryBlobStore,
        /// The exact prefix `highest_published_epoch` lists (`{team}/_keys/`);
        /// only this one fails.
        failing_prefix: String,
    }

    #[async_trait::async_trait]
    impl BlobStore for FailingTopLevelKeysListStore {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            if prefix == self.failing_prefix {
                return Err(MemError::Storage("simulated listing failure".to_owned()));
            }
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// I1 regression: a listing failure on the EPOCH lookup must not fall
    /// back to comparing the manifest against epoch 0's recipients. This is
    /// the precise reason that fallback is dangerous, not merely a
    /// hypothetical: epoch 0 here holds a genuinely STALE member — one a
    /// REAL prior rotation already excluded from epoch 1, the true current
    /// epoch, which matches the live manifest exactly (a healthy team). If
    /// the epoch lookup's failure were papered over with `0`, this stale,
    /// properly-rotated-away member would be wrongly flagged as still
    /// holding the CURRENT epoch key.
    #[tokio::test]
    async fn removed_member_still_holds_key_lines_is_silent_on_an_epoch_lookup_failure()
    -> Result<(), MemError> {
        const TEAM: &str = "clientx";
        const FOUNDER_PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        const STALE_PHRASE: &str = "letter advice cage absurd amount doctor acoustic avoid \
                                     letter advice cage above";

        let blob = FailingTopLevelKeysListStore {
            inner: MemoryBlobStore::default(),
            failing_prefix: format!("{TEAM}/_keys/"),
        };
        let founder_signer = signer_from_mnemonic(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;
        let founder_identity = derive_identity(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;
        let founder_key = MemberKey::create_signed(&founder_signer, &founder_identity);
        let stale_signer = signer_from_mnemonic(STALE_PHRASE, NetworkPrefix::HIPPIUS)?;
        let stale_identity = derive_identity(STALE_PHRASE, NetworkPrefix::HIPPIUS)?;
        let stale_key = MemberKey::create_signed(&stale_signer, &stale_identity);

        // Epoch 0 (stale history): both wrapped. Epoch 1 (the TRUE current
        // epoch, after a real prior rotation): the founder only.
        provision_team_key(
            &blob,
            TEAM,
            &SecretKey::from_bytes([1u8; 32]),
            0,
            &[founder_key.clone(), stale_key],
            None,
            &founder_signer,
        )
        .await?;
        provision_team_key(
            &blob,
            TEAM,
            &SecretKey::from_bytes([2u8; 32]),
            1,
            std::slice::from_ref(&founder_key),
            None,
            &founder_signer,
        )
        .await?;

        // The live manifest matches epoch 1 exactly: a healthy team with
        // nothing to flag, IF the epoch lookup succeeds.
        let manifest =
            TeamManifest::create_signed(&founder_signer, TEAM.to_owned(), BTreeSet::new(), 0);
        publish_manifest(&blob, &manifest).await?;

        assert!(
            removed_member_still_holds_key_lines(&blob, TEAM, None)
                .await
                .is_empty(),
            "an epoch-lookup failure must yield no lines -- falling back to epoch 0 would \
             wrongly flag the STALE (properly-rotated-away) member as still holding the \
             CURRENT epoch's key"
        );
        Ok(())
    }

    /// The doctor-surface test for Task 4: a wrap that fails
    /// [`super::WrappedKey::verify`] (a garbage/forged signature, planted
    /// directly at its `_keys/` leaf, never produced by `wrap_team_key`) AND a
    /// wrap that verifies but was provisioned by an identity the manifest does
    /// not authorize (neither its founder nor its recovery key) must BOTH be
    /// named in the report, each with the `hippius-mem rotate` remediation --
    /// while a healthy, founder-provisioned, manifest-listed member's wrap is
    /// never named.
    #[tokio::test]
    async fn unsigned_or_unauthorized_wrapped_key_lines_flags_a_bad_signature_and_an_unauthorized_provisioner()
    -> Result<(), MemError> {
        const TEAM: &str = "clientx";
        const FOUNDER_PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        const GOOD_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                    abandon abandon abandon abandon about";
        const VICTIM_PHRASE: &str =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        const FORGED_PHRASE: &str = "letter advice cage absurd amount doctor acoustic avoid \
                                      letter advice cage above";

        let blob = MemoryBlobStore::default();
        let founder_signer = signer_from_mnemonic(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;

        let good_identity = derive_identity(GOOD_PHRASE, NetworkPrefix::HIPPIUS)?;
        let good_signer = signer_from_mnemonic(GOOD_PHRASE, NetworkPrefix::HIPPIUS)?;
        let good_key = MemberKey::create_signed(&good_signer, &good_identity);

        let victim_identity = derive_identity(VICTIM_PHRASE, NetworkPrefix::HIPPIUS)?;
        let victim_signer = signer_from_mnemonic(VICTIM_PHRASE, NetworkPrefix::HIPPIUS)?;
        let victim_key = MemberKey::create_signed(&victim_signer, &victim_identity);

        // Named in the manifest, but never publishes a MemberKey: this test
        // plants a raw, garbage-signature WrappedKey directly at its `_keys/`
        // leaf, so no MemberKey (or `wrap_team_key` call) is needed for it.
        let forged_identity = derive_identity(FORGED_PHRASE, NetworkPrefix::HIPPIUS)?;

        let manifest = TeamManifest::create_signed(
            &founder_signer,
            TEAM.to_owned(),
            BTreeSet::from([
                good_identity.ss58.clone(),
                victim_identity.ss58.clone(),
                forged_identity.ss58.clone(),
            ]),
            0,
        );
        publish_manifest(&blob, &manifest).await?;

        // The healthy wrap: founder-provisioned, verifies, authorized. Must
        // never appear in the report.
        provision_team_key(
            &blob,
            TEAM,
            &SecretKey::from_bytes([1u8; 32]),
            0,
            &[good_key],
            None,
            &founder_signer,
        )
        .await?;

        // An attacker who is neither the founder nor a recovery key
        // provisions a REAL, correctly-signed wrap for a legitimate manifest
        // member: it verifies, but is not authorized. Mirrors
        // `hippius_mem_core::identity::teamkey`'s own
        // `fetch_rejects_a_wrap_from_an_unauthorized_provisioner` test.
        let attacker_signer =
            Sr25519Signer::from_seed_with_prefix(&[42u8; 32], NetworkPrefix::HIPPIUS)?;
        provision_team_key(
            &blob,
            TEAM,
            &SecretKey::from_bytes([2u8; 32]),
            0,
            &[victim_key],
            None,
            &attacker_signer,
        )
        .await?;

        // A raw, garbage-signature wrap planted directly at its `_keys/`
        // leaf -- no legitimate provisioner ever produced this record.
        let forged = WrappedKey {
            epoch: 0,
            ephemeral_public: [7u8; 32],
            ciphertext: vec![1, 2, 3, 4],
            provisioner: founder_signer.verifying_key(),
            sig: Signature::new([0xAB; 64]),
        };
        blob.put(
            &wrapped_key_key(TEAM, 0, forged_identity.ss58.as_str()),
            serde_json::to_vec(&forged).expect("WrappedKey serializes"),
        )
        .await?;

        let lines = unsigned_or_unauthorized_wrapped_key_lines(&blob, TEAM, None).await;

        assert_eq!(
            lines.len(),
            2,
            "exactly the two bad wraps must be flagged: {lines:?}"
        );
        let forged_line = lines
            .iter()
            .find(|line| line.contains(forged_identity.ss58.as_str()))
            .expect("the garbage-signature wrap must be named");
        assert!(
            forged_line.contains("signature") && forged_line.contains("run: hippius-mem rotate"),
            "the line must name the signature failure and the fix: {forged_line}"
        );
        let unauthorized_line = lines
            .iter()
            .find(|line| line.contains(victim_identity.ss58.as_str()))
            .expect("the unauthorized-provisioner wrap must be named");
        assert!(
            unauthorized_line.contains("does not authorize")
                && unauthorized_line.contains("run: hippius-mem rotate"),
            "the line must name the authorization failure and the fix: {unauthorized_line}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains(good_identity.ss58.as_str())),
            "the healthy, authorized wrap must never be named: {lines:?}"
        );
        Ok(())
    }

    /// A wrap provisioned by the manifest's TRUSTED RECOVERY key (never its
    /// founder) must be silent, not flagged -- this is the guard against
    /// regressing `recover`: once a founder key is lost and a recovery key
    /// takes over, wraps IT provisions must stay unflagged, mirroring
    /// `hippius_mem_core::identity::teamkey`'s own
    /// `fetch_accepts_a_wrap_from_the_recovery_key` test.
    #[tokio::test]
    async fn unsigned_or_unauthorized_wrapped_key_lines_is_silent_on_a_recovery_key_wrap()
    -> Result<(), MemError> {
        const TEAM: &str = "clientx";
        const FOUNDER_PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        const RECOVERY_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                        abandon abandon abandon abandon about";
        const MEMBER_PHRASE: &str =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";

        let blob = MemoryBlobStore::default();
        let founder_signer = signer_from_mnemonic(FOUNDER_PHRASE, NetworkPrefix::HIPPIUS)?;
        let recovery_signer = signer_from_mnemonic(RECOVERY_PHRASE, NetworkPrefix::HIPPIUS)?;
        let member_identity = derive_identity(MEMBER_PHRASE, NetworkPrefix::HIPPIUS)?;
        let member_signer = signer_from_mnemonic(MEMBER_PHRASE, NetworkPrefix::HIPPIUS)?;
        let member_key = MemberKey::create_signed(&member_signer, &member_identity);

        let manifest = TeamManifest::create_signed_with_recovery(
            &founder_signer,
            TEAM.to_owned(),
            BTreeSet::from([member_identity.ss58.clone()]),
            0,
            Some(recovery_signer.verifying_key()),
        );
        publish_manifest(&blob, &manifest).await?;

        // Provisioned by the RECOVERY key, not the founder.
        provision_team_key(
            &blob,
            TEAM,
            &SecretKey::from_bytes([9u8; 32]),
            0,
            &[member_key],
            None,
            &recovery_signer,
        )
        .await?;

        assert!(
            unsigned_or_unauthorized_wrapped_key_lines(&blob, TEAM, None)
                .await
                .is_empty(),
            "a wrap provisioned by the manifest's trusted recovery key must never be flagged"
        );
        Ok(())
    }

    /// An open team (no manifest published yet) has no roster to authorize a
    /// provisioner against, so a wrap from an arbitrary signer must stay
    /// silent -- but a wrap whose signature does not even verify must still
    /// be flagged, since `WrappedKey::verify` needs no manifest at all.
    #[tokio::test]
    async fn unsigned_or_unauthorized_wrapped_key_lines_open_team_only_checks_signatures()
    -> Result<(), MemError> {
        const TEAM: &str = "clientx";
        const PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
        const FORGED_PHRASE: &str =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";

        let blob = MemoryBlobStore::default();
        let signer = signer_from_mnemonic(PHRASE, NetworkPrefix::HIPPIUS)?;
        let identity = derive_identity(PHRASE, NetworkPrefix::HIPPIUS)?;
        let member_key = MemberKey::create_signed(&signer, &identity);

        // No manifest published: an arbitrary signer's wrap is accepted (an
        // open team), so long as it verifies.
        provision_team_key(
            &blob,
            TEAM,
            &SecretKey::from_bytes([3u8; 32]),
            0,
            &[member_key],
            None,
            &signer,
        )
        .await?;

        let forged_identity = derive_identity(FORGED_PHRASE, NetworkPrefix::HIPPIUS)?;
        let forged = WrappedKey {
            epoch: 0,
            ephemeral_public: [1u8; 32],
            ciphertext: vec![9, 9, 9],
            provisioner: signer.verifying_key(),
            sig: Signature::new([0xCD; 64]),
        };
        blob.put(
            &wrapped_key_key(TEAM, 0, forged_identity.ss58.as_str()),
            serde_json::to_vec(&forged).expect("WrappedKey serializes"),
        )
        .await?;

        let lines = unsigned_or_unauthorized_wrapped_key_lines(&blob, TEAM, None).await;
        assert_eq!(
            lines.len(),
            1,
            "only the garbage-signature wrap is flagged on an open team: {lines:?}"
        );
        assert!(
            lines[0].contains(forged_identity.ss58.as_str()),
            "the line must name the forged wrap: {}",
            lines[0]
        );
        Ok(())
    }

    /// A [`BlobStore`] wrapper whose `get` fails for exactly one object key,
    /// while `list` and everything else delegate untouched -- models a bucket
    /// that LISTS an object (so its recipient is enumerated) but then fails to
    /// SERVE it, distinct from [`HidingBlobStore`] (which also hides the key
    /// from `list`, so it is never even enumerated).
    struct FailingGetStore {
        inner: MemoryBlobStore,
        /// The one object key whose `get` fails; every other key is served
        /// from `inner` untouched.
        failing_key: String,
    }

    #[async_trait::async_trait]
    impl BlobStore for FailingGetStore {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
            self.inner.put(key, bytes).await
        }

        async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
            if key == self.failing_key {
                return Err(MemError::Storage("simulated wrap fetch failure".to_owned()));
            }
            self.inner.get(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
            self.inner.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), MemError> {
            self.inner.delete(key).await
        }
    }

    /// A wrap this run could list (so its recipient is enumerated) but then
    /// failed to FETCH must be silent, not flagged -- a read failure is a
    /// missed detection, the lesser fault, never a false accusation. Mirrors
    /// the best-effort reasoning `stale_max_epoch_line` and
    /// `removed_member_still_holds_key_lines` already rely on for their own
    /// listing failures.
    #[tokio::test]
    async fn unsigned_or_unauthorized_wrapped_key_lines_is_silent_on_a_wrap_fetch_failure()
    -> Result<(), MemError> {
        const TEAM: &str = "clientx";
        const PHRASE: &str =
            "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

        let signer = signer_from_mnemonic(PHRASE, NetworkPrefix::HIPPIUS)?;
        let identity = derive_identity(PHRASE, NetworkPrefix::HIPPIUS)?;
        let member_key = MemberKey::create_signed(&signer, &identity);

        let inner = MemoryBlobStore::default();
        provision_team_key(
            &inner,
            TEAM,
            &SecretKey::from_bytes([5u8; 32]),
            0,
            &[member_key],
            None,
            &signer,
        )
        .await?;

        let failing_key = wrapped_key_key(TEAM, 0, identity.ss58.as_str());
        let blob = FailingGetStore { inner, failing_key };

        assert!(
            unsigned_or_unauthorized_wrapped_key_lines(&blob, TEAM, None)
                .await
                .is_empty(),
            "a wrap this run could not fetch must not be flagged"
        );
        Ok(())
    }
}
