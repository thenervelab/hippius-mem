//! A member removal, end to end through the real binary against a live
//! S3-compatible endpoint: three machines `join`, the founder publishes the
//! roster and runs `remove`, and a remaining member's MCP server is then asked
//! to write.
//!
//! Every process is configured only through the file `HIPPIUS_MEM_CONFIG`
//! names, as the installed daemon is, plus `HIPPIUS_MEM_MNEMONIC` where a
//! command needs an identity. Endpoint coordinates follow the environment
//! contract of `tests/gc_s3.rs`. `#[ignore]`d; run with `--ignored`.

#![expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests use `?` for setup but still assert on outcomes; the assertions are the test"
)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use hippius_mem_core::{
    BlobStore, NetworkPrefix, OpLogStore, S3BlobStore, SecretKey, Signer as _, Sr25519Signer, Ss58,
    load_member_keys, rotate_team_key,
};
use serde_json::{Value, json};

/// The team namespace this test owns, cleared before and after the run.
const TEAM: &str = "rw-rotation-live";

/// The team namespace the bundle-join test owns, apart from [`TEAM`] so the
/// two tests can run at once.
const JOIN_TEAM: &str = "rw-join-bundle-live";

/// The team key every machine starts with (epoch 0).
const TEAM_KEY_HEX: &str = "24acd7ca317cb31b657364ac6aa260e1a3ed469a2c296973ad21d5b42e0b1835";

/// How long one MCP reply may take: the server's first sync and the first
/// write each talk to the gateway. Arbitrary headroom.
const REPLY_DEADLINE: Duration = Duration::from_secs(120);

/// One machine: its own home directory, config file, author seed and
/// mnemonic.
struct Machine {
    home: tempfile::TempDir,
    seed: [u8; 32],
    mnemonic: &'static str,
}

impl Machine {
    fn new(seed_byte: u8, mnemonic: &'static str) -> anyhow::Result<Self> {
        Ok(Self {
            home: tempfile::tempdir()?,
            seed: [seed_byte; 32],
            mnemonic,
        })
    }

    fn address(&self) -> anyhow::Result<String> {
        let signer = Sr25519Signer::from_seed_with_prefix(&self.seed, NetworkPrefix::HIPPIUS)?;
        Ok(signer.author_ss58().as_str().to_owned())
    }

    fn config_path(&self) -> PathBuf {
        self.home.path().join("hippius-mem.toml")
    }

    fn write_config(&self, live: &Live, team: &str, founder: &str) -> anyhow::Result<()> {
        let toml = format!(
            "s3_endpoint = \"{endpoint}\"\ns3_region = \"{region}\"\nbucket = \"{bucket}\"\n\
             access_key_id = \"{access}\"\nsecret = \"{secret}\"\nteam = \"{team}\"\n\
             team_key_hex = \"{TEAM_KEY_HEX}\"\nauthor_seed_hex = \"{seed}\"\n\
             founder_ss58 = \"{founder}\"\nsemantic_embeddings = false\n",
            endpoint = live.endpoint,
            region = live.region,
            bucket = live.bucket,
            access = live.access_key_id,
            secret = live.secret,
            seed = hippius_mem_core::hex::encode(self.seed),
        );
        std::fs::write(self.config_path(), toml)?;
        Ok(())
    }

    /// The binary, with no inherited `HIPPIUS_MEM_*` or XDG setting, `HOME`
    /// in this machine's directory and its config named by
    /// `HIPPIUS_MEM_CONFIG`.
    fn command(&self, mnemonic: Mnemonic) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hippius-mem"));
        for (name, _) in std::env::vars_os() {
            if name
                .to_str()
                .is_some_and(|name| name.starts_with("HIPPIUS_MEM_") || name.starts_with("XDG_"))
            {
                command.env_remove(name);
            }
        }
        command
            .current_dir(self.home.path())
            .env("HOME", self.home.path())
            .env("HIPPIUS_MEM_CONFIG", self.config_path())
            .env("RUST_LOG", "info");
        // The test endpoint is plain-HTTP loopback, which the binary refuses
        // unless told otherwise.
        if std::env::var_os("HIPPIUS_MEM_ALLOW_INSECURE_ENDPOINT").is_some() {
            command.env("HIPPIUS_MEM_ALLOW_INSECURE_ENDPOINT", "1");
        }
        if mnemonic == Mnemonic::Set {
            command.env("HIPPIUS_MEM_MNEMONIC", self.mnemonic);
        }
        command
    }

    /// Run one CLI command with this machine's mnemonic and fail on a
    /// non-zero exit, naming the command and its stderr.
    fn run(&self, args: &[&str]) -> anyhow::Result<String> {
        let output = self.command(Mnemonic::Set).args(args).output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.status.success() {
            bail!(
                "`hippius-mem {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(stdout)
    }
}

/// Whether a spawned process gets the machine's mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mnemonic {
    Set,
    Unset,
}

/// The live endpoint, from the same variables as the other live suites.
struct Live {
    endpoint: String,
    bucket: String,
    access_key_id: String,
    secret: String,
    region: String,
}

impl Live {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            endpoint: std::env::var("HIPPIUS_MEM_TEST_S3_ENDPOINT")
                .context("set HIPPIUS_MEM_TEST_S3_ENDPOINT to the throwaway S3 endpoint")?,
            bucket: std::env::var("HIPPIUS_MEM_TEST_BUCKET").context(
                "set HIPPIUS_MEM_TEST_BUCKET to a bucket that already exists on the endpoint",
            )?,
            access_key_id: std::env::var("HIPPIUS_MEM_TEST_ACCESS_KEY_ID")
                .unwrap_or_else(|_| "test".to_owned()),
            secret: std::env::var("HIPPIUS_MEM_TEST_SECRET")
                .unwrap_or_else(|_| "testtest1".to_owned()),
            region: std::env::var("HIPPIUS_MEM_TEST_S3_REGION")
                .unwrap_or_else(|_| "us-east-1".to_owned()),
        })
    }

    fn raw_bucket(&self) -> S3BlobStore {
        S3BlobStore::new(
            self.endpoint.clone(),
            self.bucket.clone(),
            self.access_key_id.clone(),
            self.secret.clone(),
            self.region.clone(),
        )
    }
}

/// Every object under `prefix`, with its bytes.
async fn objects_under(
    bucket: &dyn BlobStore,
    prefix: &str,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut objects = Vec::new();
    for key in bucket.list(prefix).await? {
        let bytes = bucket.get(&key).await?;
        objects.push((key, bytes));
    }
    Ok(objects)
}

async fn clear_team(bucket: &dyn BlobStore, team: &str) {
    for key in bucket
        .list(&format!("{team}/"))
        .await
        .unwrap_or_else(|_| Vec::new())
    {
        let _ = bucket.delete(&key).await;
    }
}

/// A running stdio MCP server, killed on drop.
struct Server {
    child: Child,
    stdin: std::process::ChildStdin,
    lines: mpsc::Receiver<String>,
    next_id: u64,
}

impl Server {
    fn spawn(machine: &Machine, mnemonic: Mnemonic) -> anyhow::Result<Self> {
        let mut child = machine
            .command(mnemonic)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().context("stdin is piped")?;
        let stdout = child.stdout.take().context("stdout is piped")?;
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut server = Self {
            child,
            stdin,
            lines,
            next_id: 1,
        };
        server.request(
            "initialize",
            &json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "rotation-live-test", "version": "0" }
            }),
        )?;
        server.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;
        Ok(server)
    }

    fn send(&mut self, message: &Value) -> anyhow::Result<()> {
        writeln!(self.stdin, "{message}")?;
        self.stdin.flush()?;
        Ok(())
    }

    fn request(&mut self, method: &str, params: &Value) -> anyhow::Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))?;
        loop {
            let line = self
                .lines
                .recv_timeout(REPLY_DEADLINE)
                .with_context(|| format!("no reply to {method} within {REPLY_DEADLINE:?}"))?;
            let reply: Value = serde_json::from_str(&line)?;
            if reply["id"] == id {
                return Ok(reply);
            }
        }
    }

    /// Call `remember` and return the tool result (`isError` and text).
    fn remember(&mut self, summary: &str) -> anyhow::Result<(bool, String)> {
        self.call(
            "remember",
            &json!({
                "note_type": "decision",
                "summary": summary,
                "body": "written after the removal",
                "repo": "global",
            }),
        )
    }

    /// Call `remember`, require it to succeed, and return the new note's id.
    fn remember_id(&mut self, summary: &str) -> anyhow::Result<String> {
        let (refused, text) = self.remember(summary)?;
        if refused {
            bail!("remember was refused: {text}");
        }
        let answer: Value = serde_json::from_str(&text)?;
        answer["id"]
            .as_str()
            .map(str::to_owned)
            .with_context(|| format!("remember answer has no id: {text}"))
    }

    /// Call the tool `name` and return the tool result (`isError` and text).
    fn call(&mut self, name: &str, arguments: &Value) -> anyhow::Result<(bool, String)> {
        let reply = self.request(
            "tools/call",
            &json!({ "name": name, "arguments": arguments }),
        )?;
        let result = &reply["result"];
        let text = result["content"][0]["text"]
            .as_str()
            .with_context(|| format!("{name} reply has no text: {reply}"))?
            .to_owned();
        Ok((result["isError"].as_bool() == Some(true), text))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The key epoch of each of `author`'s ops on the bucket, in Lamport order.
async fn key_epochs_of(bucket: S3BlobStore, author: &str) -> anyhow::Result<Vec<u64>> {
    key_epochs_of_team(bucket, TEAM, author).await
}

/// [`key_epochs_of`] for `team`.
async fn key_epochs_of_team(
    bucket: S3BlobStore,
    team: &str,
    author: &str,
) -> anyhow::Result<Vec<u64>> {
    let blob: std::sync::Arc<dyn BlobStore> = std::sync::Arc::new(bucket);
    let ops = OpLogStore::new(blob).read_all(team).await?;
    let mut ops: Vec<_> = ops
        .iter()
        .filter(|op| op.author.as_str() == author)
        .map(|op| (op.lamport, op.key_epoch))
        .collect();
    ops.sort_unstable();
    Ok(ops.into_iter().map(|(_, epoch)| epoch).collect())
}

/// After the founder removes C, a remaining member's server that cannot load
/// the new key (no mnemonic, as the `serve` daemon runs) refuses to write
/// instead of sealing under the key C still holds, and the same member's
/// server with its mnemonic loads the rotated key without anyone editing
/// `max_epoch`, and writes under it.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn after_a_removal_a_member_server_seals_only_under_the_new_key() -> anyhow::Result<()> {
    let live = Live::from_env()?;
    clear_team(&live.raw_bucket(), TEAM).await;

    let founder = Machine::new(
        31,
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    )?;
    let member = Machine::new(
        32,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )?;
    let removed = Machine::new(
        33,
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    )?;
    let founder_address = founder.address()?;
    for machine in [&founder, &member, &removed] {
        machine.write_config(&live, TEAM, &founder_address)?;
    }

    for machine in [&founder, &member, &removed] {
        machine.run(&["join"])?;
    }
    let roster = [founder.address()?, member.address()?, removed.address()?].join(",");
    founder.run(&["publish-membership", "--members", &roster])?;
    founder.run(&["provision", "--no-recovery"])?;

    let mut daemon_like = Server::spawn(&member, Mnemonic::Unset)?;
    let (refused, text) = daemon_like.remember("written before the removal")?;
    assert!(!refused, "a write before any rotation succeeds: {text}");
    drop(daemon_like);

    let removal = founder.run(&["remove", &removed.address()?])?;
    assert!(
        removal.contains("rotated team"),
        "remove rotates the key: {removal}"
    );

    let mut daemon_like = Server::spawn(&member, Mnemonic::Unset)?;
    let (refused, text) = daemon_like.remember("sealed under the key the removed member holds")?;
    assert!(
        refused && text.contains("rotated its key to epoch 1"),
        "a server without the new key must refuse the write: {text}"
    );
    drop(daemon_like);

    // The same member's CLI says so before any write: `doctor` fails, and a
    // command that reads the team (`brief`) warns.
    let doctor = member.command(Mnemonic::Unset).arg("doctor").output()?;
    let doctor_err = String::from_utf8_lossy(&doctor.stderr);
    assert!(
        !doctor.status.success()
            && doctor_err.contains("rotated to epoch 1, and HIPPIUS_MEM_MNEMONIC is not set"),
        "doctor must fail for a machine that cannot open the newest epoch: {doctor_err}"
    );
    let brief = member.command(Mnemonic::Unset).arg("brief").output()?;
    let brief_err = String::from_utf8_lossy(&brief.stderr);
    assert!(
        brief.status.success() && brief_err.contains("rotated its key to epoch 1"),
        "brief must warn that this process holds no key for epoch 1: {brief_err}"
    );
    assert_eq!(
        key_epochs_of(live.raw_bucket(), &member.address()?).await?,
        [0],
        "nothing was written after the removal"
    );

    let mut with_mnemonic = Server::spawn(&member, Mnemonic::Set)?;
    let sealed_at_1 = with_mnemonic.remember_id("sealed under the rotated key")?;
    drop(with_mnemonic);
    assert_eq!(
        key_epochs_of(live.raw_bucket(), &member.address()?).await?,
        [0, 1],
        "the member's write after the removal is sealed under the rotated key"
    );

    // A process without the epoch-1 key says the note exists and why it
    // cannot open it, instead of "not found".
    let mut daemon_like = Server::spawn(&member, Mnemonic::Unset)?;
    let (failed, text) = daemon_like.call("get", &json!({ "id": sealed_at_1 }))?;
    assert!(
        failed && text.contains("no team key for epoch 1"),
        "get names the missing epoch: {text}"
    );
    for (tool, arguments) in [
        ("refresh", json!({})),
        (
            "recall",
            json!({ "text": "sealed under the rotated key", "repo": "global" }),
        ),
    ] {
        let (failed, text) = daemon_like.call(tool, &arguments)?;
        assert!(
            !failed && text.contains("keyless_notes") && text.contains("epoch 1"),
            "{tool} warns that notes are left out: {text}"
        );
    }
    drop(daemon_like);

    clear_team(&live.raw_bucket(), TEAM).await;
    Ok(())
}

/// `join --bundle` with `HIPPIUS_MEM_MNEMONIC` set publishes this machine's
/// member key, so the founder's next `provision` can wrap a rotated key to it,
/// and its next steps say so. Catches a join that skips the publish.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn joining_by_bundle_with_a_mnemonic_publishes_the_member_key() -> anyhow::Result<()> {
    let live = Live::from_env()?;
    clear_team(&live.raw_bucket(), JOIN_TEAM).await;

    let joiner = Machine::new(
        34,
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    )?;
    let bundle_path = joiner.home.path().join("invite.toml");
    std::fs::write(
        &bundle_path,
        format!(
            "s3_endpoint = \"{endpoint}\"\nbucket = \"{bucket}\"\nteam = \"{JOIN_TEAM}\"\n\
             max_epoch = 1\nteam_key_hex = \"{TEAM_KEY_HEX}\"\naccess_key_id = \"{access}\"\n\
             secret = \"{secret}\"\n",
            endpoint = live.endpoint,
            bucket = live.bucket,
            access = live.access_key_id,
            secret = live.secret,
        ),
    )?;
    let stdout = joiner.run(&["join", "--bundle", &bundle_path.to_string_lossy()])?;
    assert!(
        stdout.contains("your member key is published"),
        "the next steps name the published key: {stdout}"
    );

    let member_keys = live
        .raw_bucket()
        .list(&format!("{JOIN_TEAM}/_memberkeys/"))
        .await?;
    assert_eq!(member_keys.len(), 1, "one member key: {member_keys:?}");

    clear_team(&live.raw_bucket(), JOIN_TEAM).await;
    Ok(())
}

/// The team namespace the member-provision test owns.
const PROVISION_TEAM: &str = "rw-provision-live";

/// After a rotation, a member's `provision` (with or without a recovery key)
/// fails before it writes: every wrap and the manifest stay byte for byte, and
/// the founder still reads its epoch-1 note from a fresh session. A member's
/// `provision` used to replace the founder's wraps with ones only it signed,
/// which no reader accepts, so the epoch-1 notes became unreadable to everyone.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn a_members_provision_changes_no_wrap_and_the_founder_keeps_reading() -> anyhow::Result<()> {
    let live = Live::from_env()?;
    let bucket = live.raw_bucket();
    clear_team(&bucket, PROVISION_TEAM).await;

    let founder = Machine::new(
        41,
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    )?;
    let member = Machine::new(
        42,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )?;
    let founder_address = founder.address()?;
    for machine in [&founder, &member] {
        machine.write_config(&live, PROVISION_TEAM, &founder_address)?;
        machine.run(&["join"])?;
    }
    founder.run(&["publish-membership", "--members", &member.address()?])?;
    founder.run(&["provision", "--no-recovery"])?;
    founder.run(&["rotate"])?;
    let mut session = Server::spawn(&founder, Mnemonic::Set)?;
    let id = session.remember_id("sealed under epoch one by the founder")?;
    drop(session);

    let keys = format!("{PROVISION_TEAM}/_keys/");
    let manifests = format!("{PROVISION_TEAM}/_manifest/");
    let wraps_before = objects_under(&bucket, &keys).await?;
    let manifests_before = objects_under(&bucket, &manifests).await?;
    for args in [&["provision", "--no-recovery"][..], &["provision"][..]] {
        let output = member.command(Mnemonic::Set).args(args).output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains("only the team founder"),
            "a member's `{}` must be refused: {stderr}",
            args.join(" ")
        );
    }
    assert_eq!(objects_under(&bucket, &keys).await?, wraps_before);
    assert_eq!(objects_under(&bucket, &manifests).await?, manifests_before);

    let mut session = Server::spawn(&founder, Mnemonic::Set)?;
    let (failed, text) = session.call("get", &json!({ "id": id }))?;
    assert!(
        !failed && text.contains("written after the removal"),
        "the founder reads its epoch-1 note: {text}"
    );
    drop(session);

    clear_team(&bucket, PROVISION_TEAM).await;
    Ok(())
}

/// The team namespace the late-member test owns.
const LATE_TEAM: &str = "rw-late-member-live";

/// A member who joins after two rotations is first told by `doctor` which
/// epochs it cannot read, and after the founder's `provision` reads the notes
/// of every epoch. `provision` used to wrap only the current epoch, and
/// `doctor` passed while the epoch-1 notes stayed unreadable.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn a_member_who_joins_after_two_rotations_reads_every_epoch() -> anyhow::Result<()> {
    let live = Live::from_env()?;
    let bucket = live.raw_bucket();
    clear_team(&bucket, LATE_TEAM).await;

    let founder = Machine::new(
        51,
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    )?;
    let member = Machine::new(
        52,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )?;
    let late = Machine::new(
        53,
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    )?;
    let founder_address = founder.address()?;
    for machine in [&founder, &member, &late] {
        machine.write_config(&live, LATE_TEAM, &founder_address)?;
    }
    founder.run(&["join"])?;
    member.run(&["join"])?;
    founder.run(&["publish-membership", "--members", &member.address()?])?;
    founder.run(&["provision", "--no-recovery"])?;
    let mut ids = Vec::new();
    for summary in ["sealed under epoch one", "sealed under epoch two"] {
        founder.run(&["rotate"])?;
        let mut session = Server::spawn(&member, Mnemonic::Set)?;
        ids.push(session.remember_id(summary)?);
    }

    late.run(&["join"])?;
    let roster = [member.address()?, late.address()?].join(",");
    founder.run(&["publish-membership", "--members", &roster])?;
    let doctor = late.command(Mnemonic::Set).arg("doctor").output()?;
    let doctor_err = String::from_utf8_lossy(&doctor.stderr);
    assert!(
        doctor_err.contains("1 note(s) are sealed under epoch 1, which this machine"),
        "doctor names the epoch the late member cannot read: {doctor_err}"
    );

    founder.run(&["provision", "--no-recovery"])?;
    let mut session = Server::spawn(&late, Mnemonic::Set)?;
    for id in &ids {
        let (failed, text) = session.call("get", &json!({ "id": id }))?;
        assert!(!failed, "the late member reads {id}: {text}");
    }
    drop(session);
    let doctor = late.command(Mnemonic::Set).arg("doctor").output()?;
    let doctor_err = String::from_utf8_lossy(&doctor.stderr);
    assert!(
        doctor.status.success() && !doctor_err.contains("holds no key for"),
        "doctor passes once every epoch is wrapped: {doctor_err}"
    );

    clear_team(&bucket, LATE_TEAM).await;
    Ok(())
}

/// The team namespace the never-joined-founder test owns.
const FOUNDER_TEAM: &str = "rw-founder-live";

/// A founder that follows the runbook without `join` and runs `rotate` still
/// reads the epoch it minted: `rotate` publishes the founder's member key
/// first and says so, the new epoch is wrapped to the founder, and its fresh
/// session reads a member's note sealed under it. Without the mnemonic,
/// `rotate` is refused before it writes anything. The founder used to be left
/// out of the new epoch, with only a stderr warning, and could never read it.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn a_founder_who_never_joined_reads_the_epoch_its_rotate_mints() -> anyhow::Result<()> {
    let live = Live::from_env()?;
    let bucket = live.raw_bucket();
    clear_team(&bucket, FOUNDER_TEAM).await;

    let founder = Machine::new(
        61,
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    )?;
    let member = Machine::new(
        62,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )?;
    let founder_address = founder.address()?;
    for machine in [&founder, &member] {
        machine.write_config(&live, FOUNDER_TEAM, &founder_address)?;
    }
    member.run(&["join"])?;
    founder.run(&["publish-membership", "--members", &member.address()?])?;
    founder.run(&["provision", "--no-recovery"])?;

    let keys = format!("{FOUNDER_TEAM}/_keys/");
    let before = objects_under(&bucket, &keys).await?;
    let unset = founder.command(Mnemonic::Unset).arg("rotate").output()?;
    let unset_err = String::from_utf8_lossy(&unset.stderr);
    assert!(
        !unset.status.success() && unset_err.contains("require HIPPIUS_MEM_MNEMONIC"),
        "rotate without the mnemonic is refused: {unset_err}"
    );
    assert_eq!(
        objects_under(&bucket, &keys).await?,
        before,
        "nothing written"
    );

    let rotation = founder.run(&["rotate"])?;
    assert!(
        rotation.contains("published this machine's member key")
            && rotation.contains(&format!("  {founder_address}")),
        "rotate says it published the founder's key and wraps the founder: {rotation}"
    );
    let mut session = Server::spawn(&member, Mnemonic::Set)?;
    let id = session.remember_id("sealed under epoch one by a member")?;
    drop(session);

    let mut session = Server::spawn(&founder, Mnemonic::Set)?;
    let (failed, text) = session.call("get", &json!({ "id": id }))?;
    assert!(
        !failed,
        "the founder reads the member's epoch-1 note: {text}"
    );
    drop(session);
    let doctor = founder.command(Mnemonic::Set).arg("doctor").output()?;
    assert!(
        doctor.status.success(),
        "doctor passes for the founder: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );

    clear_team(&bucket, FOUNDER_TEAM).await;
    Ok(())
}

/// The team namespace the stranded-epoch repair test owns.
const STRANDED_TEAM: &str = "rw-stranded-live";

/// An epoch an older release minted without the founder (wrapped by the
/// founder to the member only) is repaired: `doctor` names the repair, the
/// member's `admin share-epoch-keys` sends the founder the opening of its own
/// founder-signed wrap, and the founder's `provision` loads the key from that
/// wrap and wraps it to the founder, whose fresh session then reads the
/// member's note. Before, no command could give the founder that epoch.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn a_founder_stranded_by_an_older_rotation_recovers_the_epoch() -> anyhow::Result<()> {
    let live = Live::from_env()?;
    let bucket = live.raw_bucket();
    clear_team(&bucket, STRANDED_TEAM).await;

    let founder = Machine::new(
        71,
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    )?;
    let member = Machine::new(
        72,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )?;
    let founder_address = founder.address()?;
    for machine in [&founder, &member] {
        machine.write_config(&live, STRANDED_TEAM, &founder_address)?;
    }
    member.run(&["join"])?;
    founder.run(&["publish-membership", "--members", &member.address()?])?;
    founder.run(&["provision", "--no-recovery"])?;

    // What an older `rotate` by a founder that never joined left behind.
    let founder_signer =
        Sr25519Signer::from_seed_with_prefix(&founder.seed, NetworkPrefix::HIPPIUS)?;
    let member_keys = load_member_keys(&bucket, STRANDED_TEAM).await?;
    let founder_pin = Ss58::new(&founder_address)?;
    let wrapped = rotate_team_key(
        &bucket,
        STRANDED_TEAM,
        &SecretKey::from_bytes([91_u8; 32]),
        1,
        &member_keys,
        Some(&founder_pin),
        &founder_signer,
    )
    .await?;
    assert_eq!(wrapped.len(), 1, "epoch 1 reaches the member only");
    let mut session = Server::spawn(&member, Mnemonic::Set)?;
    let id = session.remember_id("sealed under the stranded epoch")?;
    drop(session);

    founder.run(&["join"])?;
    let doctor = founder.command(Mnemonic::Set).arg("doctor").output()?;
    let doctor_err = String::from_utf8_lossy(&doctor.stderr);
    assert!(
        !doctor.status.success() && doctor_err.contains("admin share-epoch-keys"),
        "doctor names the repair: {doctor_err}"
    );

    let shared = member.run(&["admin", "share-epoch-keys"])?;
    assert!(
        shared.contains("shared the key of epoch 0, 1 with"),
        "{shared}"
    );
    let provision = founder.run(&["provision", "--no-recovery"])?;
    assert!(
        provision.contains("loaded the key of epoch 1"),
        "provision loads the shared epoch: {provision}"
    );

    let mut session = Server::spawn(&founder, Mnemonic::Set)?;
    let (failed, text) = session.call("get", &json!({ "id": id }))?;
    assert!(
        !failed,
        "the founder reads the stranded epoch's note: {text}"
    );
    drop(session);
    let doctor = founder.command(Mnemonic::Set).arg("doctor").output()?;
    assert!(
        doctor.status.success(),
        "doctor passes once the founder holds the epoch: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );

    clear_team(&bucket, STRANDED_TEAM).await;
    Ok(())
}

/// The team namespace the live-session removal test owns.
const SESSION_TEAM: &str = "rw-live-session-live";

/// A member's session that wrote a moment before the founder removed someone
/// is refused its next write, after `refresh` and without one, instead of
/// sealing it under the key the removed member holds. The session used to
/// keep sealing under the old key for a minute after its last write.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn a_session_that_just_wrote_is_refused_after_a_removal() -> anyhow::Result<()> {
    let live = Live::from_env()?;
    let bucket = live.raw_bucket();
    clear_team(&bucket, SESSION_TEAM).await;

    let founder = Machine::new(
        81,
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    )?;
    let member = Machine::new(
        82,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )?;
    let removed = Machine::new(
        83,
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    )?;
    let founder_address = founder.address()?;
    for machine in [&founder, &member, &removed] {
        machine.write_config(&live, SESSION_TEAM, &founder_address)?;
        machine.run(&["join"])?;
    }
    let roster = [member.address()?, removed.address()?].join(",");
    founder.run(&["publish-membership", "--members", &roster])?;
    founder.run(&["provision", "--no-recovery"])?;

    let mut session = Server::spawn(&member, Mnemonic::Set)?;
    session.remember_id("written before the removal")?;
    founder.run(&["remove", &removed.address()?])?;

    let (refused, text) = session.remember("written right after the removal")?;
    assert!(
        refused && text.contains("rotated its key to epoch 1"),
        "the session refuses at once: {text}"
    );
    let (failed, text) = session.call("refresh", &json!({}))?;
    assert!(!failed, "{text}");
    let (refused, text) = session.remember("written after a refresh")?;
    assert!(
        refused && text.contains("rotated its key to epoch 1"),
        "the session refuses after a refresh: {text}"
    );
    drop(session);
    assert_eq!(
        key_epochs_of_team(live.raw_bucket(), SESSION_TEAM, &member.address()?).await?,
        [0],
        "nothing was sealed after the removal"
    );

    clear_team(&bucket, SESSION_TEAM).await;
    Ok(())
}

/// The team namespace the never-rotated removal test owns.
const UNROTATED_TEAM: &str = "rw-unrotated-live";

/// A roster that shrank while the team stayed at epoch 0 (what `remove` left
/// when it could not rotate before 0.8.1) is flagged by `doctor`, a `remove`
/// re-run says it did not rotate instead of pointing at "the rotation above",
/// and `rotate` clears the warning. `doctor` used to pass such a team.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn a_removal_that_never_rotated_is_flagged_until_a_rotation() -> anyhow::Result<()> {
    let live = Live::from_env()?;
    let bucket = live.raw_bucket();
    clear_team(&bucket, UNROTATED_TEAM).await;

    let founder = Machine::new(
        91,
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    )?;
    let kept = Machine::new(
        92,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )?;
    let removed = Machine::new(
        93,
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    )?;
    let founder_address = founder.address()?;
    founder.write_config(&live, UNROTATED_TEAM, &founder_address)?;
    let removed_address = removed.address()?;
    let both = [kept.address()?, removed_address.clone()].join(",");
    founder.run(&["publish-membership", "--members", &both])?;
    founder.run(&["publish-membership", "--members", &kept.address()?])?;

    let doctor = founder.command(Mnemonic::Set).arg("doctor").output()?;
    let doctor_err = String::from_utf8_lossy(&doctor.stderr);
    assert!(
        doctor_err.contains(&format!(
            "{removed_address} was removed from the roster, but the team key was never rotated"
        )),
        "doctor flags the unrotated removal: {doctor_err}"
    );

    let removal = founder.run(&["remove", &removed_address])?;
    assert!(
        removal.contains("already excludes")
            && removal.contains("This run did not rotate")
            && !removal.contains("the rotation above"),
        "the banner does not claim a rotation: {removal}"
    );

    founder.run(&["rotate"])?;
    let doctor = founder.command(Mnemonic::Set).arg("doctor").output()?;
    let doctor_err = String::from_utf8_lossy(&doctor.stderr);
    assert!(
        !doctor_err.contains("was removed from the roster"),
        "a rotation clears the warning: {doctor_err}"
    );

    clear_team(&bucket, UNROTATED_TEAM).await;
    Ok(())
}

/// The primary profile's namespace in the routing test.
const ROUTING_PRIMARY: &str = "rw-routing-primary-live";

/// The `[[teams]]` profile's namespace in the routing test.
const ROUTING_TEAM: &str = "rw-routing-team-live";

/// A team command run from a checkout whose remote routes to a `[[teams]]`
/// profile acts on that profile, as `doctor` and the server do. Team commands
/// used to act on the primary profile wherever they ran, so a founder of an
/// org-routed team published its roster into the personal namespace.
#[tokio::test]
#[ignore = "needs a live S3-compatible endpoint (the MinIO CI job, or a local MinIO)"]
async fn a_team_command_acts_on_the_profile_the_remote_routes_to() -> anyhow::Result<()> {
    let live = Live::from_env()?;
    let bucket = live.raw_bucket();
    for team in [ROUTING_PRIMARY, ROUTING_TEAM] {
        clear_team(&bucket, team).await;
    }

    let founder = Machine::new(
        95,
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    )?;
    // Both profiles share the bucket, credentials, key and seed; only the
    // namespace tells them apart.
    let profile = format!(
        "bucket = \"{bucket}\"\naccess_key_id = \"{access}\"\nsecret = \"{secret}\"\n\
         team_key_hex = \"{TEAM_KEY_HEX}\"\nauthor_seed_hex = \"{seed}\"\n\
         founder_ss58 = \"{founder}\"\n",
        bucket = live.bucket,
        access = live.access_key_id,
        secret = live.secret,
        seed = hippius_mem_core::hex::encode(founder.seed),
        founder = founder.address()?,
    );
    std::fs::write(
        founder.config_path(),
        format!(
            "s3_endpoint = \"{endpoint}\"\ns3_region = \"{region}\"\nsemantic_embeddings = false\n\
             team = \"{ROUTING_PRIMARY}\"\n{primary}\n[[teams]]\nname = \"{ROUTING_TEAM}\"\n\
             orgs = [\"github.com/acme\"]\n{routed}",
            endpoint = live.endpoint,
            region = live.region,
            primary = profile,
            routed = profile,
        ),
    )?;
    let checkout = founder.home.path().join("app");
    std::fs::create_dir_all(&checkout)?;
    for args in [
        &["init", "-q"][..],
        &["remote", "add", "origin", "git@github.com:acme/app.git"][..],
    ] {
        let status = Command::new("git")
            .args(args)
            .current_dir(&checkout)
            .status()?;
        assert!(status.success(), "git {}", args.join(" "));
    }

    let output = founder
        .command(Mnemonic::Set)
        .current_dir(&checkout)
        .args(["publish-membership", "--members", &founder.address()?])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        bucket
            .list(&format!("{ROUTING_TEAM}/_manifest/"))
            .await?
            .len(),
        1,
        "the routed profile's roster is published"
    );
    assert!(
        bucket
            .list(&format!("{ROUTING_PRIMARY}/_manifest/"))
            .await?
            .is_empty(),
        "the primary profile is untouched"
    );

    for team in [ROUTING_PRIMARY, ROUTING_TEAM] {
        clear_team(&bucket, team).await;
    }
    Ok(())
}
