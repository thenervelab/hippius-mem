//! The `join --bundle` flow: consume a founder-emitted invite bundle and turn
//! it into a working local config in one command.
//!
//! The bundle (`crate::bundle::InviteBundle`) is pure TOML, so this module
//! needs zero marker-stripping: `toml::from_str` on the exact text the founder
//! copied. From the parsed fields it writes the joiner's config — a fresh
//! primary profile on a machine with no config, or an appended `[[teams]]`
//! profile on a machine that already has one — then runs the same member-key
//! publish the bare `join` performs (when a mnemonic is present).
//!
//! Three input sources: `--bundle <path>` (a file), `--bundle -` (stdin to
//! EOF), and `--bundle` with no value — the onboarding path for a joiner who
//! was just sent the bundle in chat: on a terminal it prompts and reads the
//! PASTED text ([`read_bundle_no_value`]), on piped stdin it behaves exactly
//! like `-`.
//!
//! Secret hygiene: the bundle text and every rendered config fragment hold a
//! live S3 secret and the team key, so they are wrapped in
//! [`zeroize::Zeroizing`] and never logged; config files end up 0600 on both
//! paths (created 0600 fresh, pinned to 0600 after an append); and TOML parse
//! errors surface only toml's span-free message, because the span rendering
//! quotes the offending source line — which here IS the secret. For the
//! config documents that sanitization is structural (`ConfigError::Toml`
//! captures a span-free, value-scrubbed payload at conversion — see
//! `crate::config::TomlParseError`); [`parse_bundle`] applies the same
//! discipline locally for the bundle, which never becomes a `ConfigError`.
//! `author_seed_hex` is ALWAYS generated here via the OS CSPRNG — never
//! prompted for, never taken from the bundle (an amended bundle carrying one
//! still parses, per the leniency contract, but its seed is ignored: the seed
//! is this machine's unique signing identity and must not be shared).

use std::io::{IsTerminal as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use hippius_mem_core::derive_identity;
use zeroize::Zeroizing;

// The shared SS58 prefix keeps the published member identity aligned with the
// address the founder's `provision` wraps the team key to.
use crate::admin::HIPPIUS_SS58_PREFIX;
use crate::bundle::InviteBundle;
use crate::config::Config;
use crate::resolver::{GitRemoteReader, RemoteReader};

/// Parsed `join` arguments when `--bundle` is present.
#[derive(Debug)]
pub(crate) struct Options {
    /// Where the bundle text comes from.
    source: BundleSource,
    /// `--orgs` routing patterns for the appended `[[teams]]` profile (or the
    /// fresh primary). Empty when the flag was omitted.
    orgs: Vec<String>,
}

/// Where `--bundle` reads the invite text from.
#[derive(Debug)]
enum BundleSource {
    /// `--bundle -`: read stdin to EOF (e.g. `pbpaste | hippius-mem join --bundle -`).
    Stdin,
    /// `--bundle <path>`: read the file at `path`.
    File(PathBuf),
    /// `--bundle` with no value: on a terminal, prompt and read the pasted
    /// bundle interactively; on piped stdin, behave exactly like `-`. The
    /// TTY check happens at READ time (`std::io::IsTerminal`), not parse
    /// time, so `Options::parse` stays a pure argv function.
    Interactive,
}

impl Options {
    /// Parse `join`'s arguments: `Ok(None)` for the bare legacy `join`,
    /// `Ok(Some(_))` when `--bundle` selects this flow.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown flag, a missing `--orgs` value,
    /// `--orgs` without `--bundle`, or an empty `--orgs` list — each BEFORE
    /// any file or network operation runs, matching the CLI's loud-failure
    /// rule. `--bundle` itself takes an OPTIONAL value: none selects the
    /// interactive paste source.
    pub(crate) fn parse(args: &[String]) -> anyhow::Result<Option<Self>> {
        if args.is_empty() {
            return Ok(None);
        }
        let mut source = None;
        let mut orgs = Vec::new();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--bundle" => {
                    // The value is optional: a following `--flag` (or nothing
                    // at all) means "no value", selecting the interactive
                    // paste source. `-` and file paths never start with `--`
                    // (a genuinely `--`-prefixed filename still works as
                    // `./--name`), so existing invocations parse unchanged.
                    let value = match iter.peek() {
                        Some(next) if !next.starts_with("--") => iter.next(),
                        Some(_) | None => None,
                    };
                    source = Some(match value.map(String::as_str) {
                        None => BundleSource::Interactive,
                        Some("-") => BundleSource::Stdin,
                        Some(path) => BundleSource::File(PathBuf::from(path)),
                    });
                }
                "--orgs" => {
                    let csv = iter
                        .next()
                        .context("--orgs requires a value (comma-separated host/org patterns)")?;
                    orgs = csv
                        .split(',')
                        .map(str::trim)
                        .filter(|pattern| !pattern.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                    if orgs.is_empty() {
                        bail!(
                            "--orgs needs at least one non-empty pattern (e.g. --orgs github.com/acme)"
                        );
                    }
                }
                other => bail!(
                    "unknown join argument `{other}`; usage: join [--bundle [<path|->] [--orgs <host/org,...>]]"
                ),
            }
        }
        let Some(source) = source else {
            bail!("`join` takes no arguments except `--bundle [<path|->] [--orgs <host/org,...>]`");
        };
        Ok(Some(Self { source, orgs }))
    }
}

/// How the bundle landed in the config file — drives the next-steps output.
#[derive(Debug, Clone, Copy)]
pub(crate) enum WriteOutcome {
    /// No config existed: the bundle became the primary (flat) profile.
    FreshPrimary,
    /// A config existed: the bundle was appended as a `[[teams]]` profile.
    AppendedProfile,
}

/// Run `join --bundle`: parse the bundle, write the config, then perform the
/// same member-key publish the bare `join` does (when a mnemonic is present).
///
/// # Errors
///
/// Returns an error if the bundle cannot be read or parsed (the parse error
/// names the missing field), no config path can be resolved, the write is
/// refused (conflicting profile name, top-level key conflict, missing
/// `--orgs` on append, or a config the append would invalidate), or — with
/// `HIPPIUS_MEM_MNEMONIC` set — the member-key publish fails. A publish
/// failure happens AFTER the config write; the error says so, and re-running
/// the bare `join` retries only the publish.
pub(crate) async fn run(opts: Options) -> anyhow::Result<()> {
    let text = read_bundle_text(&opts.source)?;
    let bundle = parse_bundle(&text)?;
    drop(text); // zeroized: the raw bundle carries the live secret
    let seed_hex = generate_seed_hex()?;
    let path = resolve_target_path()?;
    let outcome = write_config(&path, &bundle, &seed_hex, &opts.orgs)?;

    // Round-trip proof, from the bytes on disk: the file `Config` will load at
    // the next server start must validate offline NOW, not at that later boot.
    // (`doctor`'s live probe is still the recommended follow-up — see the
    // next-steps output.)
    let written = Zeroizing::new(std::fs::read_to_string(&path).with_context(|| {
        format!(
            "re-reading the just-written config at {} failed",
            path.display()
        )
    })?);
    let cfg = Config::from_toml_str(&written).with_context(|| {
        format!(
            "the just-written config at {} failed validation",
            path.display()
        )
    })?;
    drop(written);

    // The DELETE-the-bundle warning is printed BEFORE the fallible publish
    // below: the bundle text is a live shown-once secret whether or not the
    // member-key publish succeeds, so the warning must reach the user either way.
    print_written(&path, &bundle, outcome);
    let published = publish_member_key(&cfg, &bundle.team).await?;
    print_next_steps(&bundle, published);
    // Only public coordinates reach the log — never the secret or team key.
    tracing::info!(
        team = %bundle.team,
        access_key_id = %bundle.access_key_id,
        config = %path.display(),
        "joined via invite bundle"
    );
    Ok(())
}

/// Read the bundle text from the selected source, zeroized on drop.
fn read_bundle_text(source: &BundleSource) -> anyhow::Result<Zeroizing<String>> {
    let text = match source {
        BundleSource::Stdin => std::io::read_to_string(std::io::stdin())
            .context("reading the invite bundle from stdin failed")?,
        BundleSource::File(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading the invite bundle at {} failed", path.display()))?,
        BundleSource::Interactive => {
            // The TTY probe lives at this production edge — not inside the
            // seam — so tests drive both semantics without a terminal. The
            // prompt goes to stderr: stdout is protocol/product space.
            let stdin = std::io::stdin();
            let is_tty = stdin.is_terminal();
            return read_bundle_no_value(stdin.lock(), is_tty, &mut std::io::stderr());
        }
    };
    Ok(Zeroizing::new(text))
}

/// Bracketed-paste begin marker (`ESC[200~`) a terminal in paste mode wraps
/// around pasted text. This flow never enables that mode, but stripping the
/// markers is trivial and keeps a paste relayed through such a wrapper
/// parseable; a legitimate bundle can never contain a raw ESC byte (toml
/// escapes it), so unconditional stripping cannot corrupt one.
const PASTE_BEGIN: &str = "\u{1b}[200~";
/// Bracketed-paste end marker (`ESC[201~`). See [`PASTE_BEGIN`].
const PASTE_END: &str = "\u{1b}[201~";

/// Read the bundle when `--bundle` was given NO value: the paste flow.
///
/// `is_tty` selects the semantics — injected (rather than probed here, see
/// [`read_bundle_text`]) so tests can drive both without a real terminal:
///
/// - **terminal**: write a short prompt to `prompt` (stderr in production —
///   stdout stays protocol-clean) and accumulate lines, stopping the moment
///   the accumulated text parses as a complete [`InviteBundle`]. The
///   canonical bundle ends with the `secret` field, so that moment IS the
///   paste's last line. A blank-line terminator would be wrong — TOML
///   legitimately contains blank lines — and demanding Ctrl-D alone would
///   make the happy path fiddlier. EOF (Ctrl-D) stays the explicit finish:
///   the accumulated text is returned as-is and the CALLER's
///   [`parse_bundle`] owns the diagnosis, because an error rendered here
///   would risk echoing the pasted secret (`parse_bundle`'s span-free,
///   value-scrubbed discipline is the one safe renderer).
/// - **piped stdin**: exactly `--bundle -` — read to EOF, no prompt, no
///   early stop (an amended trailing `author_seed_hex` line, allowed by the
///   leniency contract, must survive into the text).
///
/// # Errors
///
/// Returns an error only when reading or prompting itself fails;
/// unparseable text is NOT an error here (see above).
fn read_bundle_no_value(
    mut reader: impl std::io::BufRead,
    is_tty: bool,
    prompt: &mut impl std::io::Write,
) -> anyhow::Result<Zeroizing<String>> {
    if !is_tty {
        let mut text = Zeroizing::new(String::new());
        reader
            .read_to_string(&mut text)
            .context("reading the invite bundle from stdin failed")?;
        return Ok(text);
    }

    writeln!(
        prompt,
        "Paste the invite bundle from your founder now (the whole block \
         `hippius-mem invite` printed, comment lines included)."
    )
    .and_then(|()| {
        writeln!(
            prompt,
            "Input finishes on its own once the bundle is complete; Ctrl-D also finishes it."
        )
    })
    .context("writing the paste prompt failed")?;

    // Reserve once: a bundle is a few hundred bytes, and every String
    // reallocation would strand an un-zeroized copy of the secret-bearing
    // text (`Zeroizing` scrubs only the final buffer it owns at drop).
    let mut text = Zeroizing::new(String::with_capacity(4096));
    let mut line = Zeroizing::new(String::with_capacity(256));
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .context("reading the pasted invite bundle failed")?;
        if read == 0 {
            // Ctrl-D on an empty line: the explicit finish.
            return Ok(text);
        }
        push_stripped(&mut text, &line);
        // The completion check. The parse RESULT is deliberately discarded,
        // never rendered: a mid-paste parse error embeds document values —
        // here, potentially the live secret.
        if toml::from_str::<InviteBundle>(&text).is_ok() {
            return Ok(text);
        }
    }
}

/// Append `line` to `text`, dropping bracketed-paste markers (see
/// [`PASTE_BEGIN`]). Each replacement buffer is wrapped in [`Zeroizing`]
/// immediately — the line may hold the live secret.
fn push_stripped(text: &mut String, line: &str) {
    if line.contains(PASTE_BEGIN) || line.contains(PASTE_END) {
        let without_begin = Zeroizing::new(line.replace(PASTE_BEGIN, ""));
        let without_end = Zeroizing::new(without_begin.replace(PASTE_END, ""));
        text.push_str(&without_end);
    } else {
        text.push_str(line);
    }
}

/// Parse the bundle text. The serde error already names a missing field
/// ("missing field bucket"); the context anchors it to the bundle.
///
/// Only the scrubbed `toml::de::Error::message()` travels — never the error
/// itself. toml's span rendering (its `Display`) quotes the offending SOURCE
/// LINE, and this input carries a live secret: a malformed `secret = "...`
/// line would be echoed verbatim to stderr. Nor is `message()` alone enough:
/// a wrong-typed field (`max_epoch = "SECRET"`) embeds the document VALUE in
/// the message itself, so the same value scrub `ConfigError::Toml` applies at
/// conversion is applied here too. What survives is the diagnosis only
/// ("invalid string", "missing field `bucket`", "value has the wrong type,
/// expected a nonzero u64").
fn parse_bundle(text: &str) -> anyhow::Result<InviteBundle> {
    toml::from_str(text).map_err(|err: toml::de::Error| {
        anyhow::anyhow!("{}", crate::config::scrub_value_payload(err.message())).context(
            "parsing the invite bundle failed — paste the exact block `hippius-mem invite` \
             printed (every non-field line is a `#` comment, so the whole block is valid TOML)",
        )
    })
}

/// Generate 32 CSPRNG bytes as hex — this machine's `author_seed_hex`, or
/// (via [`crate::quickstart`]) a freshly minted `team_key_hex` for a solo
/// trial vault that has no founder to mint the team key elsewhere.
///
/// The seed is the machine's unique op-log signing identity: it is never
/// prompted for and never accepted from the bundle, matching the installer's
/// `gen_seed` and the never-downgrade rule the dashboard token follows — no
/// seed is safer than a guessable one. `pub(crate)`: `quickstart` reuses the
/// exact same CSPRNG mechanism for its `team_key_hex`.
pub(crate) fn generate_seed_hex() -> anyhow::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|err| anyhow::anyhow!("OS CSPRNG unavailable for author_seed_hex: {err}"))?;

    Ok(Zeroizing::new(hex::encode(&bytes[..])))
}

/// The config file `--bundle` writes: `HIPPIUS_MEM_CONFIG` when set (matching
/// how the binary itself resolves config), else the installer's global
/// `${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem/hippius-mem.toml`.
///
/// An empty env value counts as unset, matching the shell `:-` fallback the
/// installer uses (`scripts/install.sh`). `pub(crate)`: `quickstart` resolves
/// its trial config to the exact same location, so the file it writes is the
/// one `setup::install`'s global MCP registration (and any later `join
/// --bundle`) will also find.
pub(crate) fn resolve_target_path() -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("HIPPIUS_MEM_CONFIG")
        && !path.trim().is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    crate::setup::mcp::resolved_global_config_path().context(
        "cannot resolve a config path: set HIPPIUS_MEM_CONFIG, or set HOME/XDG_CONFIG_HOME",
    )
}

/// Serialization shape of the fresh primary-profile config. Borrowing `&str`
/// avoids a second owned copy of each secret; `toml`/serde escaping (not
/// string templating) is what keeps a metacharacter-bearing secret from
/// corrupting the file — the same rule `InviteBundle` itself follows.
#[derive(serde::Serialize)]
struct PrimaryDoc<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    s3_endpoint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_epoch: Option<std::num::NonZeroU64>,
    team: &'a str,
    bucket: &'a str,
    access_key_id: &'a str,
    secret: &'a str,
    team_key_hex: &'a str,
    author_seed_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    founder_ss58: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    orgs: &'a [String],
}

/// Serialization shape of one appended `[[teams]]` profile. `s3_endpoint` and
/// `max_epoch` are deliberately absent: they are TOP-LEVEL config keys
/// (`TeamProfile` is `deny_unknown_fields` without them), so a bundle carrying
/// them is reconciled against the existing top level instead — see
/// [`append_profile`].
#[derive(serde::Serialize)]
struct ProfileDoc<'a> {
    name: &'a str,
    orgs: &'a [String],
    bucket: &'a str,
    access_key_id: &'a str,
    secret: &'a str,
    team_key_hex: &'a str,
    author_seed_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    founder_ss58: Option<&'a str>,
}

/// Wrapper whose single field serializes as the `[[teams]]` array-of-tables
/// header, so the appended block is produced by the same serde escaping path
/// as everything else.
#[derive(serde::Serialize)]
struct AppendDoc<'a> {
    teams: [ProfileDoc<'a>; 1],
}

/// Write the bundle into the config at `path`: a fresh 0600 primary-profile
/// file when none exists, else an appended `[[teams]]` profile.
///
/// The fresh-vs-append decision is `create_new` on the filesystem itself —
/// not a separate `exists()` probe — so two racing invocations cannot both
/// take the fresh path. In BOTH branches the candidate document is validated
/// with [`Config::from_toml_str`] before any byte lands on disk.
///
/// # Errors
///
/// See [`run`]; additionally any I/O failure creating the parent directory or
/// writing the file.
pub(crate) fn write_config(
    path: &Path,
    bundle: &InviteBundle,
    seed_hex: &str,
    orgs: &[String],
) -> anyhow::Result<WriteOutcome> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("creating the config directory {} failed", parent.display())
        })?;
    }
    let body = render_fresh_config(bundle, seed_hex, orgs)?;
    // Validate BEFORE creating the file: a refusal must leave no half-config.
    Config::from_toml_str(&body).context(
        "the invite bundle does not form a valid config (is a field empty, or the team key not 64 hex chars?)",
    )?;
    // 0600 at create time via `mode` (umask can only clear further bits, so the
    // file is never group/world readable even transiently), then pinned to
    // exactly 0600 after the write — the installer's umask-077-then-chmod
    // discipline, in Rust.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(body.as_bytes())
                .with_context(|| format!("writing the config at {} failed", path.display()))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("setting 0600 on {} failed", path.display()))?;
            Ok(WriteOutcome::FreshPrimary)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            append_profile(path, bundle, seed_hex, orgs)
        }
        Err(err) => {
            Err(err).with_context(|| format!("creating the config at {} failed", path.display()))
        }
    }
}

/// Render the fresh primary-profile config: a warning header (comments only,
/// like the installer's) plus the serde-escaped fields.
fn render_fresh_config(
    bundle: &InviteBundle,
    seed_hex: &str,
    orgs: &[String],
) -> anyhow::Result<Zeroizing<String>> {
    let doc = PrimaryDoc {
        s3_endpoint: bundle.s3_endpoint.as_deref(),
        max_epoch: bundle.max_epoch,
        team: &bundle.team,
        bucket: &bundle.bucket,
        access_key_id: &bundle.access_key_id,
        secret: &bundle.secret,
        team_key_hex: &bundle.team_key_hex,
        author_seed_hex: seed_hex,
        founder_ss58: bundle.founder_ss58.as_deref(),
        orgs,
    };

    let fields =
        Zeroizing::new(toml::to_string(&doc).context("serializing the joiner config as TOML")?);

    Ok(Zeroizing::new(format!(
        "# hippius-mem per-user config. Holds secrets — never commit. Mode 0600.\n\
         # Written by `hippius-mem join --bundle`.\n\
         {}",
        fields.as_str()
    )))
}

/// Append the bundle as a `[[teams]]` profile to the existing config at
/// `path`, refusing every conflict rather than silently overwriting:
///
/// - a profile (primary or `[[teams]]`) already named `bundle.team`;
/// - an `s3_endpoint` differing from the existing top level (a shared
///   TOP-LEVEL key — one file cannot speak to two gateways);
/// - a bundle `max_epoch` above the existing top level (also TOP-LEVEL; a
///   silent drop would hide every post-rotation note — the documented rotate
///   gotcha);
/// - no `--orgs` (an org-less `[[teams]]` profile is a second catch-all,
///   which `Config::validate` rejects at the next launch).
///
/// The full candidate document is validated before the block is appended, so
/// a refused append leaves the existing file byte-identical. A successful
/// append then pins the file to exactly 0600 — a pre-existing looser mode is
/// tightened, not preserved, because the file now provably holds a live
/// secret.
fn append_profile(
    path: &Path,
    bundle: &InviteBundle,
    seed_hex: &str,
    orgs: &[String],
) -> anyhow::Result<WriteOutcome> {
    let existing_text =
        Zeroizing::new(std::fs::read_to_string(path).with_context(|| {
            format!("reading the existing config at {} failed", path.display())
        })?);
    let existing = Config::from_toml_str(&existing_text).with_context(|| {
        format!(
            "the existing config at {} failed to load; fix it before `join --bundle` can append",
            path.display()
        )
    })?;

    if existing.team == bundle.team || existing.teams.iter().any(|p| p.name == bundle.team) {
        bail!(
            "a profile named `{team}` already exists in {path} — refusing to overwrite it; \
             if you meant to replace its credentials, edit the file by hand (it is 0600) or \
             remove the old profile first",
            team = bundle.team,
            path = path.display()
        );
    }

    let default_endpoint = Config::default().s3_endpoint;
    let bundle_endpoint = bundle.s3_endpoint.as_deref().unwrap_or(&default_endpoint);
    if existing.s3_endpoint != bundle_endpoint {
        bail!(
            "this bundle's gateway is `{bundle_endpoint}` but {path} sets s3_endpoint = \
             `{existing_endpoint}`; s3_endpoint is a shared TOP-LEVEL key, so one config file \
             cannot hold teams on two gateways — use a separate config \
             (HIPPIUS_MEM_CONFIG=<other file> hippius-mem join --bundle ...)",
            existing_endpoint = existing.s3_endpoint,
            path = path.display()
        );
    }
    if let Some(epoch) = bundle.max_epoch
        && existing.max_epoch < epoch.get()
    {
        bail!(
            "this team has rotated to epoch {epoch}, but {path} sets max_epoch = {existing_epoch}; \
             max_epoch is a shared TOP-LEVEL key — raise `max_epoch = {epoch}` at the top of the \
             file (before any [[teams]] table), then re-run; a stale max_epoch silently hides \
             every note sealed after the rotation",
            existing_epoch = existing.max_epoch,
            path = path.display()
        );
    }
    if orgs.is_empty() {
        let suggestion = derived_org_suggestion().map_or_else(String::new, |org| {
            format!(", e.g. --orgs {org} (this repo's origin)")
        });
        bail!(
            "appending a [[teams]] profile needs `--orgs <host/org,...>` so repos can route to \
             it (an org-less profile would be a second catch-all, which config validation \
             rejects) — re-run with --orgs{suggestion}"
        );
    }

    let doc = AppendDoc {
        teams: [ProfileDoc {
            name: &bundle.team,
            orgs,
            bucket: &bundle.bucket,
            access_key_id: &bundle.access_key_id,
            secret: &bundle.secret,
            team_key_hex: &bundle.team_key_hex,
            author_seed_hex: seed_hex,
            founder_ss58: bundle.founder_ss58.as_deref(),
        }],
    };
    let block =
        Zeroizing::new(toml::to_string(&doc).context("serializing the [[teams]] profile as TOML")?);
    // Validate the exact document the file will hold; only then touch disk.
    let candidate = Zeroizing::new(format!("{}\n{}", existing_text.as_str(), block.as_str()));
    Config::from_toml_str(&candidate).with_context(|| {
        format!(
            "appending team `{}` would make {} invalid; nothing was written",
            bundle.team,
            path.display()
        )
    })?;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("opening {} for append failed", path.display()))?;
    file.write_all(format!("\n{}", block.as_str()).as_bytes())
        .with_context(|| format!("appending the profile to {} failed", path.display()))?;
    // The file now PROVABLY holds a live secret (we just appended one), so pin
    // it to 0600 regardless of the mode it had before — preserving a looser
    // pre-existing mode would be preserving a leak, not a feature.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting 0600 on {} failed", path.display()))?;
    Ok(WriteOutcome::AppendedProfile)
}

/// Best-effort `--orgs` suggestion from the current repo's `origin` remote,
/// so the missing-orgs refusal is actionable without leaving the terminal.
fn derived_org_suggestion() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let url = GitRemoteReader.origin_url(&cwd)?;
    let coord = crate::resolver::normalize_remote(&url)?;
    Some(format!("{}/{}", coord.host, coord.org))
}

/// Publish this machine's member key for the joined team, exactly as the bare
/// `join` does — gated on `HIPPIUS_MEM_MNEMONIC` because `--bundle` must work
/// for the common joiner who has none (the bundled `team_key_hex` already
/// grants read/write). Returns whether a key was published.
///
/// # Errors
///
/// Returns an error if the mnemonic derives no identity, the joined profile's
/// store cannot be built, or the publish itself fails. The config is already
/// written at this point; the caller's error context says so.
async fn publish_member_key(cfg: &Config, team: &str) -> anyhow::Result<bool> {
    let mnemonic = match std::env::var("HIPPIUS_MEM_MNEMONIC") {
        Ok(mnemonic) if !mnemonic.trim().is_empty() => mnemonic,
        _ => {
            tracing::info!(
                "HIPPIUS_MEM_MNEMONIC is not set; skipped publishing a member key — only needed \
                 for wrapped-key provisioning (set it and run `hippius-mem join` to publish later)"
            );
            return Ok(false);
        }
    };
    let identity = derive_identity(&mnemonic, HIPPIUS_SS58_PREFIX)
        .context("deriving the member identity from HIPPIUS_MEM_MNEMONIC failed")?;
    // `all_profiles` covers both outcomes: the fresh primary and the appended
    // `[[teams]]` profile — the bare `join` is primary-only, but here the
    // joined team may be either.
    let profile = cfg
        .all_profiles()
        .into_iter()
        .find(|profile| profile.name == team)
        .with_context(|| format!("the just-written config holds no profile named `{team}`"))?;
    let store = profile.build_store(cfg).await?;
    store.join_as_member(&identity).await.context(
        "the config was written, but publishing the member key failed — re-run `hippius-mem join` \
         (without --bundle) to retry the publish alone",
    )?;
    // Pick up any epoch keys the founder already provisioned to this member.
    crate::admin::bootstrap_epochs(&store, &mnemonic, cfg.max_epoch).await;
    tracing::info!(
        team = %team,
        member = %identity.ss58.as_str(),
        "published member key; the founder can now `provision` the team key to it"
    );
    Ok(true)
}

/// Print the config-written line and the DELETE-the-bundle warning.
///
/// Called BEFORE the fallible member-key publish, deliberately: the bundle
/// text is a live shown-once secret whether or not the publish succeeds, so
/// this warning must reach the user on the failure path too. Advisory output
/// (the config write already succeeded), so write failures are ignored like
/// `rotate`'s — unlike `invite`, whose stdout IS the shown-once product.
fn print_written(path: &Path, bundle: &InviteBundle, outcome: WriteOutcome) {
    let mut out = std::io::stdout();
    let what = match outcome {
        WriteOutcome::FreshPrimary => "wrote the primary profile to",
        WriteOutcome::AppendedProfile => "appended a [[teams]] profile to",
    };
    let _ = writeln!(
        out,
        "joined team `{team}`: {what} {path} (0600 — holds live secrets, never commit it)",
        team = bundle.team,
        path = path.display()
    );
    let _ = writeln!(
        out,
        "\nThe invite bundle text contains a live secret shown once — DELETE it now."
    );
}

/// Print the numbered next steps, after the member-key publish resolved
/// (`published` selects the rotated-team instruction variant). Same advisory
/// output rules as [`print_written`].
fn print_next_steps(bundle: &InviteBundle, published: bool) {
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "\nNext steps:\n\
         1. Reconnect Claude Code with /mcp (or start a new session) so the\n\
            server picks up the new profile.\n\
         2. Verify the setup: hippius-mem doctor   (--offline to skip the gateway probe)"
    );
    if bundle.max_epoch.is_some() {
        if published {
            let _ = writeln!(
                out,
                "3. This team has ROTATED its key: your member key is published — ask the\n\
                    founder to run `hippius-mem provision` so the newer epoch keys reach you."
            );
        } else {
            let _ = writeln!(
                out,
                "3. This team has ROTATED its key: to receive wrapped epoch keys, set\n\
                    HIPPIUS_MEM_MNEMONIC and run `hippius-mem join`, then ask the founder\n\
                    to run `hippius-mem provision`."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
    )]
    #![expect(
        clippy::expect_used,
        reason = "tests assert on hand-built fixtures where construction cannot fail"
    )]

    use std::io::Read as _;
    use std::num::NonZeroU64;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::{BundleSource, Options, parse_bundle, read_bundle_no_value, write_config};
    use crate::bundle::InviteBundle;
    use crate::config::Config;

    /// 64 hex chars decoding to 32 bytes — valid key/seed material.
    fn hex64(byte: &str) -> String {
        byte.repeat(32)
    }

    fn sample_bundle(team: &str) -> InviteBundle {
        InviteBundle {
            s3_endpoint: None,
            bucket: "team-bucket".to_owned(),
            team: team.to_owned(),
            founder_ss58: None,
            max_epoch: None,
            team_key_hex: hex64("ab"),
            access_key_id: "AKIAJOIN".to_owned(),
            secret: "shown-once".to_owned(),
        }
    }

    /// A valid pre-existing primary-profile config, as the installer writes it.
    fn existing_primary(dir: &Path) -> anyhow::Result<std::path::PathBuf> {
        let path = dir.join("hippius-mem.toml");
        std::fs::write(
            &path,
            format!(
                "team = \"primary\"\nbucket = \"b1\"\naccess_key_id = \"AK1\"\n\
                 secret = \"s1\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n",
                key = hex64("11"),
                seed = hex64("22"),
            ),
        )?;
        Ok(path)
    }

    #[test]
    fn fresh_bundle_becomes_a_valid_primary_config() -> anyhow::Result<()> {
        // The whole point of --bundle: bundle fields → primary profile the
        // next `Config` load validates, with the seed generated locally (the
        // bundle has no seed to take). The nested path also proves the parent
        // directory is created, as a fresh XDG target needs.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("nested").join("hippius-mem.toml");
        let seed = hex64("cd");
        write_config(&path, &sample_bundle("acme"), &seed, &[])?;
        let cfg = Config::from_toml_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(cfg.team, "acme");
        assert_eq!(cfg.bucket, "team-bucket");
        assert_eq!(cfg.access_key_id, "AKIAJOIN");
        assert_eq!(cfg.secret, "shown-once");
        assert_eq!(cfg.team_key_hex, hex64("ab"));
        assert_eq!(cfg.author_seed_hex, seed);
        Ok(())
    }

    #[test]
    fn fresh_config_carries_the_conditional_top_level_keys() -> anyhow::Result<()> {
        // s3_endpoint / max_epoch / founder_ss58 must land as TOP-LEVEL keys
        // (the bundle header's contract), and a NonZeroU64 epoch survives.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hippius-mem.toml");
        let mut bundle = sample_bundle("acme");
        bundle.s3_endpoint = Some("https://gw.example".to_owned());
        bundle.max_epoch = NonZeroU64::new(3);
        bundle.founder_ss58 = Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_owned());
        write_config(&path, &bundle, &hex64("cd"), &[])?;
        let cfg = Config::from_toml_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(cfg.s3_endpoint, "https://gw.example");
        assert_eq!(cfg.max_epoch, 3);
        assert_eq!(
            cfg.founder_ss58.as_deref(),
            Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
        );
        Ok(())
    }

    #[test]
    fn written_config_is_owner_only_0600() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hippius-mem.toml");
        write_config(&path, &sample_bundle("acme"), &hex64("cd"), &[])?;
        let mode = std::fs::metadata(&path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "config must be owner-only: {mode:o}");
        Ok(())
    }

    #[test]
    fn amended_bundle_parses_and_its_seed_is_ignored() -> anyhow::Result<()> {
        // End-to-end leniency contract: the header tells the joiner to amend
        // the bundle text with author_seed_hex; --bundle must accept that
        // amended file AND still use a locally generated seed — the seed in
        // the text travelled, so it must never become this machine's identity.
        let travelled_seed = hex64("ee");
        let text = format!(
            "{}author_seed_hex = \"{travelled_seed}\"\n",
            toml::to_string(&sample_bundle("acme"))?
        );
        let bundle = parse_bundle(&text)?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hippius-mem.toml");
        let local_seed = hex64("cd");
        write_config(&path, &bundle, &local_seed, &[])?;
        let cfg = Config::from_toml_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(cfg.author_seed_hex, local_seed);
        assert_ne!(cfg.author_seed_hex, travelled_seed);
        Ok(())
    }

    #[test]
    fn malformed_bundle_error_names_the_missing_field() {
        let err = parse_bundle("team = \"acme\"\n").expect_err("a bucket-less bundle must fail");
        assert!(
            format!("{err:#}").contains("bucket"),
            "the error must name the missing field: {err:#}"
        );
    }

    #[test]
    fn parse_error_never_echoes_the_secret_line() {
        // Confirmed leak (spec review): toml's span rendering quotes the
        // offending SOURCE LINE, so an unterminated `secret = "...` string
        // echoed the live secret to stderr. Only the span-free message may
        // survive, in EVERY rendering anyhow offers ({:#} alternate and the
        // {:?} chain main() prints).
        let text = "bucket = \"b\"\nteam = \"t\"\nsecret = \"SENTINELSECRET123\n";
        let err = parse_bundle(text).expect_err("an unterminated string must fail");
        for rendering in [format!("{err:#}"), format!("{err:?}")] {
            assert!(
                !rendering.contains("SENTINELSECRET123"),
                "the secret must never be echoed: {rendering}"
            );
        }
    }

    #[test]
    fn wrong_typed_bundle_field_error_never_echoes_the_value() {
        // The span-free message is not value-free: serde type errors embed the
        // document value (`invalid type: string "…", expected a nonzero u64`),
        // so a secret pasted into a wrong-typed bundle field (max_epoch is the
        // one typed field) must be scrubbed exactly like ConfigError::Toml's.
        let text = "bucket = \"b\"\nteam = \"t\"\nteam_key_hex = \"aa\"\n\
                    access_key_id = \"k\"\nsecret = \"s\"\n\
                    max_epoch = \"BUNDLETYPESENTINEL\"\n";
        let err = parse_bundle(text).expect_err("a wrong-typed field must fail");
        for rendering in [format!("{err:#}"), format!("{err:?}")] {
            assert!(
                !rendering.contains("BUNDLETYPESENTINEL"),
                "the mistyped value must never be echoed: {rendering}"
            );
        }
    }

    #[test]
    fn broken_existing_config_error_never_echoes_its_secrets() -> anyhow::Result<()> {
        // The append path parses the EXISTING config, which also holds live
        // secrets — a malformed secret line there must be sanitized exactly
        // like the bundle's.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hippius-mem.toml");
        std::fs::write(&path, "team = \"t\"\nsecret = \"EXISTINGSENTINEL456\n")?;
        let err = write_config(
            &path,
            &sample_bundle("acme"),
            &hex64("cd"),
            &["github.com/acme".to_owned()],
        )
        .expect_err("a broken existing config must refuse the append");
        for rendering in [format!("{err:#}"), format!("{err:?}")] {
            assert!(
                !rendering.contains("EXISTINGSENTINEL456"),
                "the existing config's secret must never be echoed: {rendering}"
            );
        }
        Ok(())
    }

    #[test]
    fn append_tightens_a_loose_mode_to_0600() -> anyhow::Result<()> {
        // A pre-existing 0644 config gains a live secret on append, so the
        // mode is pinned to 0600 — tightened, not preserved.
        let dir = tempfile::tempdir()?;
        let path = existing_primary(dir.path())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        write_config(
            &path,
            &sample_bundle("acme"),
            &hex64("cd"),
            &["github.com/acme".to_owned()],
        )?;
        let mode = std::fs::metadata(&path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "append must end owner-only: {mode:o}");
        Ok(())
    }

    #[test]
    fn append_adds_an_org_routed_profile() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = existing_primary(dir.path())?;
        let orgs = vec!["github.com/acme".to_owned()];
        write_config(&path, &sample_bundle("acme"), &hex64("cd"), &orgs)?;
        let cfg = Config::from_toml_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(cfg.team, "primary", "the primary profile is untouched");
        assert_eq!(cfg.teams.len(), 1);
        assert_eq!(cfg.teams[0].name, "acme");
        assert_eq!(cfg.teams[0].orgs, orgs);
        assert_eq!(cfg.teams[0].author_seed_hex, hex64("cd"));
        Ok(())
    }

    #[test]
    fn conflicting_profile_name_is_refused_without_modifying_the_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = existing_primary(dir.path())?;
        let before = std::fs::read_to_string(&path)?;
        let err = write_config(
            &path,
            &sample_bundle("primary"),
            &hex64("cd"),
            &["github.com/acme".to_owned()],
        )
        .expect_err("a duplicate profile name must be refused");
        assert!(
            format!("{err:#}").contains("primary"),
            "names the profile: {err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&path)?,
            before,
            "file must be untouched"
        );
        Ok(())
    }

    #[test]
    fn append_without_orgs_is_refused() -> anyhow::Result<()> {
        // An org-less [[teams]] profile is a second catch-all — refused here
        // with guidance rather than discovered as a validation error at the
        // next server launch.
        let dir = tempfile::tempdir()?;
        let path = existing_primary(dir.path())?;
        let before = std::fs::read_to_string(&path)?;
        let err = write_config(&path, &sample_bundle("acme"), &hex64("cd"), &[])
            .expect_err("append without orgs must be refused");
        assert!(
            format!("{err:#}").contains("--orgs"),
            "points at the flag: {err:#}"
        );
        assert_eq!(std::fs::read_to_string(&path)?, before);
        Ok(())
    }

    #[test]
    fn append_with_mismatched_endpoint_is_refused() -> anyhow::Result<()> {
        // s3_endpoint is a shared TOP-LEVEL key: a bundle for another gateway
        // cannot be represented in this file, so it is refused with guidance.
        let dir = tempfile::tempdir()?;
        let path = existing_primary(dir.path())?;
        let mut bundle = sample_bundle("acme");
        bundle.s3_endpoint = Some("https://other-gateway.example".to_owned());
        let err = write_config(
            &path,
            &bundle,
            &hex64("cd"),
            &["github.com/acme".to_owned()],
        )
        .expect_err("a different gateway must be refused");
        assert!(
            format!("{err:#}").contains("s3_endpoint"),
            "names the conflicting key: {err:#}"
        );
        Ok(())
    }

    #[test]
    fn append_with_stale_max_epoch_is_refused_with_guidance() -> anyhow::Result<()> {
        // The rotate gotcha: silently dropping max_epoch would hide every
        // post-rotation note. The refusal names the exact top-level edit.
        let dir = tempfile::tempdir()?;
        let path = existing_primary(dir.path())?;
        let mut bundle = sample_bundle("acme");
        bundle.max_epoch = NonZeroU64::new(2);
        let err = write_config(
            &path,
            &bundle,
            &hex64("cd"),
            &["github.com/acme".to_owned()],
        )
        .expect_err("a stale top-level max_epoch must be refused");
        assert!(
            format!("{err:#}").contains("max_epoch = 2"),
            "names the exact edit: {err:#}"
        );
        Ok(())
    }

    #[test]
    fn append_with_covering_max_epoch_is_accepted() -> anyhow::Result<()> {
        // An existing max_epoch at or above the bundle's already bootstraps
        // the rotated epochs — no conflict.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hippius-mem.toml");
        std::fs::write(
            &path,
            format!(
                "max_epoch = 5\nteam = \"primary\"\nbucket = \"b1\"\naccess_key_id = \"AK1\"\n\
                 secret = \"s1\"\nteam_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n",
                key = hex64("11"),
                seed = hex64("22"),
            ),
        )?;
        let mut bundle = sample_bundle("acme");
        bundle.max_epoch = NonZeroU64::new(2);
        write_config(
            &path,
            &bundle,
            &hex64("cd"),
            &["github.com/acme".to_owned()],
        )?;
        let cfg = Config::from_toml_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(cfg.max_epoch, 5);
        assert_eq!(cfg.teams[0].name, "acme");
        Ok(())
    }

    #[test]
    fn duplicate_org_pattern_is_refused_by_candidate_validation() -> anyhow::Result<()> {
        // The candidate document is validated before any byte is appended, so
        // a routing conflict (here: an org the primary already owns) refuses
        // cleanly instead of corrupting the config for the next launch.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("hippius-mem.toml");
        std::fs::write(
            &path,
            format!(
                "team = \"primary\"\norgs = [\"github.com/acme\"]\ncatch_all = true\n\
                 bucket = \"b1\"\naccess_key_id = \"AK1\"\nsecret = \"s1\"\n\
                 team_key_hex = \"{key}\"\nauthor_seed_hex = \"{seed}\"\n",
                key = hex64("11"),
                seed = hex64("22"),
            ),
        )?;
        let before = std::fs::read_to_string(&path)?;
        let err = write_config(
            &path,
            &sample_bundle("acme"),
            &hex64("cd"),
            &["github.com/acme".to_owned()],
        )
        .expect_err("a duplicate org pattern must be refused");
        assert!(
            format!("{err:#}").contains("nothing was written"),
            "says the file is untouched: {err:#}"
        );
        assert_eq!(std::fs::read_to_string(&path)?, before);
        Ok(())
    }

    /// The bundle text as a joiner would paste it, WITH a blank line between
    /// fields: pure TOML tolerates it, so the paste flow must too — a
    /// blank-line terminator would truncate this very text.
    fn pasted_bundle_text() -> String {
        format!(
            "bucket = \"team-bucket\"\nteam = \"acme\"\n\nteam_key_hex = \"{key}\"\n\
             access_key_id = \"AKIAJOIN\"\nsecret = \"shown-once\"\n",
            key = hex64("ab"),
        )
    }

    /// A reader that errors on first use. Chained after the pasted text it
    /// proves the paste loop stopped at bundle completion instead of reading
    /// on toward EOF.
    struct FailingTail;

    impl std::io::Read for FailingTail {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("read past the completed bundle"))
        }
    }

    impl std::io::BufRead for FailingTail {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            Err(std::io::Error::other("read past the completed bundle"))
        }

        fn consume(&mut self, _amt: usize) {}
    }

    #[test]
    fn pasted_bundle_with_a_blank_line_stops_at_completion_without_eof() -> anyhow::Result<()> {
        // The termination rule: stop the moment the accumulated text parses
        // as a complete bundle — proven here by chaining a reader that ERRORS
        // if the loop reads even one byte past the bundle's last line. The
        // blank line inside the text is what rules out the naive blank-line
        // terminator.
        let reader = std::io::Cursor::new(pasted_bundle_text()).chain(FailingTail);
        let mut prompt = Vec::new();
        let text = read_bundle_no_value(reader, true, &mut prompt)?;
        let bundle = parse_bundle(&text)?;
        assert_eq!(bundle.team, "acme");
        assert_eq!(bundle.secret, "shown-once");
        let prompt = String::from_utf8(prompt)?;
        assert!(
            prompt.contains("Paste"),
            "the TTY flow must prompt: {prompt}"
        );
        assert!(
            prompt.contains("Ctrl-D"),
            "the prompt must name the manual finish: {prompt}"
        );
        Ok(())
    }

    #[test]
    fn pasted_bundle_without_trailing_newline_still_completes() -> anyhow::Result<()> {
        // Ctrl-D on a non-empty final line delivers it WITHOUT a newline
        // (read_line returns it with n > 0); completion must still fire.
        let text = pasted_bundle_text();
        let reader = std::io::Cursor::new(text.trim_end().to_owned());
        let mut prompt = Vec::new();
        let text = read_bundle_no_value(reader, true, &mut prompt)?;
        assert_eq!(parse_bundle(&text)?.secret, "shown-once");
        Ok(())
    }

    #[test]
    fn pasted_bundle_cut_short_fails_at_eof_naming_the_missing_field() {
        // EOF (Ctrl-D) is the explicit finish: whatever accumulated goes to
        // parse_bundle, whose span-free diagnosis names what is missing.
        let reader = std::io::Cursor::new("bucket = \"b\"\nteam = \"acme\"\n".to_owned());
        let mut prompt = Vec::new();
        let text = read_bundle_no_value(reader, true, &mut prompt)
            .expect("EOF returns the accumulated text for diagnosis");
        let err = parse_bundle(&text).expect_err("an incomplete bundle must fail");
        assert!(
            format!("{err:#}").contains("team_key_hex"),
            "the error must name the missing field: {err:#}"
        );
    }

    #[test]
    fn pasted_garbage_at_eof_fails_span_free_without_echoing_input() {
        // EOF with text that never parses: the failure must go through
        // parse_bundle's span-free discipline — the pasted line IS the
        // secret, so no rendering may echo it.
        let reader = std::io::Cursor::new("secret = \"PASTEDSENTINEL789\n".to_owned());
        let mut prompt = Vec::new();
        let text = read_bundle_no_value(reader, true, &mut prompt)
            .expect("EOF returns the accumulated text for diagnosis");
        let err = parse_bundle(&text).expect_err("garbage must fail to parse");
        for rendering in [format!("{err:#}"), format!("{err:?}")] {
            assert!(
                !rendering.contains("PASTEDSENTINEL789"),
                "the pasted secret must never be echoed: {rendering}"
            );
        }
    }

    #[test]
    fn non_tty_no_value_reads_stdin_to_eof_like_dash() -> anyhow::Result<()> {
        // `join --bundle` on piped stdin must behave EXACTLY like
        // `--bundle -`: read to EOF with no prompt and no early stop — an
        // amended line after the bundle's last field (the leniency contract)
        // must survive into the returned text.
        let full = format!(
            "{}author_seed_hex = \"{}\"\n",
            pasted_bundle_text(),
            hex64("ee")
        );
        let reader = std::io::Cursor::new(full.clone());
        let mut prompt = Vec::new();
        let text = read_bundle_no_value(reader, false, &mut prompt)?;
        assert_eq!(
            text.as_str(),
            full,
            "piped input is read to EOF, never stopped early"
        );
        assert!(prompt.is_empty(), "no prompt on piped stdin");
        Ok(())
    }

    #[test]
    fn bracketed_paste_markers_are_stripped_from_pasted_lines() -> anyhow::Result<()> {
        // Terminals in bracketed-paste mode wrap a paste in ESC[200~ /
        // ESC[201~. This flow never enables that mode, but stripping the
        // markers is trivial and keeps a paste relayed through such a
        // wrapper parseable.
        let wrapped = format!(
            "\u{1b}[200~{}\u{1b}[201~\n",
            pasted_bundle_text().trim_end()
        );
        let reader = std::io::Cursor::new(wrapped);
        let mut prompt = Vec::new();
        let text = read_bundle_no_value(reader, true, &mut prompt)?;
        assert_eq!(parse_bundle(&text)?.secret, "shown-once");
        Ok(())
    }

    #[test]
    fn bare_join_still_parses_as_the_legacy_flow() -> anyhow::Result<()> {
        assert!(Options::parse(&[])?.is_none());
        Ok(())
    }

    #[test]
    fn bundle_flag_selects_stdin_or_a_file() -> anyhow::Result<()> {
        let stdin = Options::parse(&["--bundle".to_owned(), "-".to_owned()])?
            .expect("--bundle selects the bundle flow");
        assert!(matches!(stdin.source, BundleSource::Stdin));
        let file = Options::parse(&["--bundle".to_owned(), "invite.toml".to_owned()])?
            .expect("--bundle selects the bundle flow");
        match file.source {
            BundleSource::File(path) => assert_eq!(path, Path::new("invite.toml")),
            BundleSource::Stdin => anyhow::bail!("a path must not parse as stdin"),
            BundleSource::Interactive => anyhow::bail!("a path must not parse as interactive"),
        }
        Ok(())
    }

    #[test]
    fn bundle_flag_without_value_selects_the_interactive_source() -> anyhow::Result<()> {
        // The onboarding gap this closes: a joiner who was just sent the
        // bundle in chat runs `join --bundle` and simply pastes. No value —
        // either at the end of the args or before another flag — selects the
        // interactive source; `-` and paths keep their exact old meaning
        // (covered by `bundle_flag_selects_stdin_or_a_file`).
        let bare = Options::parse(&["--bundle".to_owned()])?
            .expect("--bundle alone selects the bundle flow");
        assert!(matches!(bare.source, BundleSource::Interactive));
        let before_flag = Options::parse(&[
            "--bundle".to_owned(),
            "--orgs".to_owned(),
            "github.com/acme".to_owned(),
        ])?
        .expect("--bundle before --orgs selects the bundle flow");
        assert!(matches!(before_flag.source, BundleSource::Interactive));
        assert_eq!(before_flag.orgs, ["github.com/acme"]);
        Ok(())
    }

    #[test]
    fn orgs_flag_splits_and_trims_the_csv() -> anyhow::Result<()> {
        let opts = Options::parse(&[
            "--bundle".to_owned(),
            "-".to_owned(),
            "--orgs".to_owned(),
            " github.com/acme , github.com/acme-labs ,".to_owned(),
        ])?
        .expect("--bundle selects the bundle flow");
        assert_eq!(opts.orgs, ["github.com/acme", "github.com/acme-labs"]);
        Ok(())
    }

    #[test]
    fn join_args_reject_junk_and_orphaned_flags() {
        // Loud failure BEFORE any file or network operation, matching the
        // other subcommands' arg discipline. (A bare `--bundle` is no longer
        // junk — it selects the interactive paste source, pinned by
        // `bundle_flag_without_value_selects_the_interactive_source`.)
        assert!(
            Options::parse(&["--bogus".to_owned()]).is_err(),
            "unknown flag"
        );
        assert!(
            Options::parse(&["--orgs".to_owned(), "github.com/acme".to_owned()]).is_err(),
            "--orgs without --bundle"
        );
        assert!(
            Options::parse(&[
                "--bundle".to_owned(),
                "-".to_owned(),
                "--orgs".to_owned(),
                " , ".to_owned()
            ])
            .is_err(),
            "empty orgs list"
        );
    }
}
