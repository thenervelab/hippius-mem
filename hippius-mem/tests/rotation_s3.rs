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
    BlobStore, NetworkPrefix, OpLogStore, S3BlobStore, Signer as _, Sr25519Signer,
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

    fn write_config(&self, live: &Live, founder: &str) -> anyhow::Result<()> {
        let toml = format!(
            "s3_endpoint = \"{endpoint}\"\ns3_region = \"{region}\"\nbucket = \"{bucket}\"\n\
             access_key_id = \"{access}\"\nsecret = \"{secret}\"\nteam = \"{TEAM}\"\n\
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
        let reply = self.request(
            "tools/call",
            &json!({
                "name": "remember",
                "arguments": {
                    "note_type": "decision",
                    "summary": summary,
                    "body": "written after the removal",
                    "repo": "global",
                }
            }),
        )?;
        let result = &reply["result"];
        let text = result["content"][0]["text"]
            .as_str()
            .with_context(|| format!("remember reply has no text: {reply}"))?
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
    let blob: std::sync::Arc<dyn BlobStore> = std::sync::Arc::new(bucket);
    let ops = OpLogStore::new(blob).read_all(TEAM).await?;
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
        machine.write_config(&live, &founder_address)?;
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

    assert_eq!(
        key_epochs_of(live.raw_bucket(), &member.address()?).await?,
        [0],
        "nothing was written after the removal"
    );

    let mut with_mnemonic = Server::spawn(&member, Mnemonic::Set)?;
    let (refused, text) = with_mnemonic.remember("sealed under the rotated key")?;
    assert!(!refused, "a server with the mnemonic loads epoch 1: {text}");
    drop(with_mnemonic);
    assert_eq!(
        key_epochs_of(live.raw_bucket(), &member.address()?).await?,
        [0, 1],
        "the member's write after the removal is sealed under the rotated key"
    );

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
