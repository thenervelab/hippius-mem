//! `hippius-mem call`, `recall`, `get` and `remember`: the memory tools from a
//! command line.
//!
//! Each sends one request to the loopback daemon (`hippius-mem serve`), which
//! runs the same tool an agent's MCP call runs, and prints the JSON result.
//!
//! They go through the daemon and never build a store of their own. A second
//! process writing under the same identity while the daemon runs can fork that
//! author's op chain on an S3 vault (only the local trial vault takes a lock),
//! and a store built per command would also pay a model load and an op-log
//! sync each time. So with no daemon these commands fail and say so.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::time::Duration;

use anyhow::Context as _;
use serde_json::{Value, json};

use crate::daemon_client::{self, Request, percent_encode};
use crate::resolver::{self, GitRemoteReader, RemoteReader as _};
use crate::setup::mcp::DEFAULT_HTTP_PORT;

/// Longest wait on one socket read. A daemon that has just started holds a
/// read until its first sync ends (the server's `WARMUP_READ_WAIT`, 90 s), and
/// a write then talks to the gateway; arbitrary headroom over that.
const READ_TIMEOUT: Duration = Duration::from_secs(150);

const USAGE: &str = "\
usage:
  hippius-mem call <tool> [<json-arguments> | -]   any memory tool; `-` reads the JSON from stdin
  hippius-mem recall [--repo <name>] [--k <n>] [--] <text>
  hippius-mem get <mem_id>
  hippius-mem remember --type <note_type> --summary <text> --repo <name> [--body <text>]
                       [--tag <tag>]... [--force]
                       (the body is read from stdin when --body is omitted or `-`)
all take [--port <n>] [--token-file <path>] (the token file `serve --token-file` was given).
`--repo` defaults to the repository of the current directory;
pass `--repo global` for team-wide. `remember` outside a repository needs `--repo`.";

/// Command-line arguments split into flags and positional words.
#[derive(Debug, Default)]
struct Parsed {
    /// `--flag value` pairs, in order (a flag may repeat).
    values: Vec<(String, String)>,
    /// `--flag` switches that take no value.
    switches: Vec<String>,
    /// Everything else, and everything after a bare `--`.
    words: Vec<String>,
}

impl Parsed {
    /// The last value given for `flag`.
    fn value(&self, flag: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(name, _)| name == flag)
            .map(|(_, value)| value.as_str())
    }

    /// Every value given for `flag`.
    fn all(&self, flag: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(name, _)| name == flag)
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

/// Split `args` for a command that takes the flags `value_flags` (each
/// followed by a value) and `switch_flags`.
///
/// One parser for every command, so they agree: a flag's value is taken as it
/// is, even when it starts with `--`; any other argument starting with `--`
/// is an error, not text; and a bare `--` ends the flags, for text that does
/// start with `--`.
fn parse(args: &[String], value_flags: &[&str], switch_flags: &[&str]) -> anyhow::Result<Parsed> {
    let mut parsed = Parsed::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            parsed.words.extend(iter.cloned());
            break;
        }
        if value_flags.contains(&arg.as_str()) {
            let value = iter
                .next()
                .with_context(|| format!("{arg} requires a value\n{USAGE}"))?;
            parsed.values.push((arg.clone(), value.clone()));
        } else if switch_flags.contains(&arg.as_str()) {
            parsed.switches.push(arg.clone());
        } else if arg.starts_with("--") {
            anyhow::bail!("unknown argument `{arg}`\n{USAGE}");
        } else {
            parsed.words.push(arg.clone());
        }
    }
    Ok(parsed)
}

/// Where the daemon listens and the file holding its token.
#[derive(Debug)]
struct Daemon {
    port: u16,
    token_file: std::path::PathBuf,
}

/// The tool to call, its JSON arguments, and the daemon to ask, for `command`.
fn request(command: &str, args: &[String]) -> anyhow::Result<(String, Value, Daemon)> {
    let (tool, arguments, parsed) = match command {
        "call" => {
            let parsed = parse(args, &["--port", "--token-file"], &[])?;
            let (tool, arguments) = call_arguments(&parsed.words)?;
            (tool, arguments, parsed)
        }
        "recall" => {
            let parsed = parse(args, &["--port", "--token-file", "--repo", "--k"], &[])?;
            ("recall".to_owned(), recall_arguments(&parsed)?, parsed)
        }
        "get" => {
            let parsed = parse(args, &["--port", "--token-file"], &[])?;
            let [id] = parsed.words.as_slice() else {
                anyhow::bail!("{USAGE}");
            };
            ("get".to_owned(), json!({ "id": id }), parsed)
        }
        "remember" => {
            let parsed = parse(
                args,
                &[
                    "--port",
                    "--token-file",
                    "--type",
                    "--summary",
                    "--body",
                    "--repo",
                    "--tag",
                ],
                &["--force"],
            )?;
            ("remember".to_owned(), remember_arguments(&parsed)?, parsed)
        }
        _ => anyhow::bail!("{USAGE}"),
    };
    let port = match parsed.value("--port") {
        Some(value) => value
            .parse()
            .with_context(|| format!("invalid --port value `{value}`"))?,
        None => DEFAULT_HTTP_PORT,
    };
    let token_file = daemon_client::token_path(parsed.value("--token-file"));
    Ok((tool, arguments, Daemon { port, token_file }))
}

/// Run one of the four commands; `command` is the subcommand name.
///
/// # Errors
///
/// Returns an error for malformed arguments, when the daemon cannot be
/// reached, and when the tool itself fails (with the tool's message).
pub(crate) fn run(command: &str, args: &[String]) -> anyhow::Result<()> {
    let (tool, arguments, Daemon { port, token_file }) = request(command, args)?;
    let token = daemon_client::token(&token_file)?;
    let target = format!("/call/{}", percent_encode(&tool));
    let body = arguments.to_string();
    let (status, answer) = daemon_client::send(
        &Request {
            port,
            target: &target,
            body: Some(&body),
            read_timeout: READ_TIMEOUT,
        },
        &token,
    )
    .with_context(|| format!("{tool}: the request to the daemon failed"))?;
    anyhow::ensure!(
        status == 200,
        "{tool}: the daemon answered {status}: {}",
        answer.trim()
    );

    let value: Value = serde_json::from_str(&answer).context("the daemon's answer is not JSON")?;
    let mut text = serde_json::to_string_pretty(&value)?;
    text.push('\n');
    // A failed write is an error: a script reading the result must not take a
    // truncated or missing document for success.
    std::io::stdout().write_all(text.as_bytes())?;
    Ok(())
}

/// Everything on stdin, for `what`. Refused when stdin is a terminal: the
/// command would sit waiting for input nobody knows to type.
fn read_stdin(what: &str) -> anyhow::Result<String> {
    let mut stdin = std::io::stdin();
    anyhow::ensure!(
        !stdin.is_terminal(),
        "{what} is read from stdin, and stdin is a terminal; pipe it in or pass it as an argument"
    );
    let mut text = String::new();
    stdin.read_to_string(&mut text)?;
    Ok(text)
}

/// `call <tool> [<json> | -]`.
fn call_arguments(words: &[String]) -> anyhow::Result<(String, Value)> {
    let (tool, json) = match words {
        [tool] => (tool, None),
        [tool, json] => (tool, Some(json.as_str())),
        _ => anyhow::bail!("{USAGE}"),
    };
    let arguments = match json {
        None => json!({}),
        Some("-") => serde_json::from_str(&read_stdin("the JSON")?).context("stdin is not JSON")?,
        Some(text) => serde_json::from_str(text).context("the arguments are not JSON")?,
    };
    Ok((tool.clone(), arguments))
}

/// The repository of the current directory, from its `origin` remote. The
/// daemon serves every repository and cannot know which one a command line
/// is in.
fn launch_repo() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let remote = GitRemoteReader.origin_url(&cwd)?;
    Some(resolver::normalize_remote(&remote)?.repo)
}

/// `recall [--repo <name>] [--k <n>] <text>`. Outside a repository and
/// without `--repo`, the daemon searches team-wide notes only.
fn recall_arguments(parsed: &Parsed) -> anyhow::Result<Value> {
    anyhow::ensure!(!parsed.words.is_empty(), "{USAGE}");
    let k = match parsed.value("--k") {
        Some(value) => Some(
            value
                .parse::<usize>()
                .with_context(|| format!("invalid --k value `{value}`"))?,
        ),
        None => None,
    };
    let repo = parsed
        .value("--repo")
        .map(str::to_owned)
        .or_else(launch_repo);
    Ok(json!({ "text": parsed.words.join(" "), "repo": repo, "k": k }))
}

/// `remember --type <t> --summary <s> [--body <b>] [--repo <r>] [--tag <t>]... [--force]`.
///
/// Outside a repository `--repo` is required. Falling back to team-wide there
/// would put a note in the pool every repository reads because of where a
/// shell happened to be.
fn remember_arguments(parsed: &Parsed) -> anyhow::Result<Value> {
    anyhow::ensure!(
        parsed.words.is_empty(),
        "unexpected `{}`\n{USAGE}",
        parsed.words.join(" ")
    );
    let (Some(note_type), Some(summary)) = (parsed.value("--type"), parsed.value("--summary"))
    else {
        anyhow::bail!("{USAGE}");
    };
    let repo = parsed
        .value("--repo")
        .map(str::to_owned)
        .or_else(launch_repo)
        .context(
            "this directory is not a repository with an `origin` remote; pass --repo <name>, \
             or --repo global for a team-wide note",
        )?;
    let body = if let Some(body) = parsed.value("--body").filter(|&body| body != "-") {
        body.to_owned()
    } else {
        let body = read_stdin("the note body")?;
        anyhow::ensure!(
            !body.trim().is_empty(),
            "the note body on stdin is empty; pass --body \"\" to store an empty body"
        );
        body
    };
    Ok(json!({
        "note_type": note_type,
        "summary": summary,
        "body": body,
        "repo": repo,
        "tags": parsed.all("--tag"),
        "force": parsed.switches.iter().any(|switch| switch == "--force"),
    }))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|&arg| arg.to_owned()).collect()
    }

    /// A flag's value is taken as written, an unknown flag is an error and not
    /// search text, and `--` ends the flags. The bugs this catches: `--port`
    /// stripped out of a query's text, a mistyped `--rpo widget` searched for
    /// as words, and `--body "--port"` read as a flag.
    #[test]
    fn flags_values_and_text_are_told_apart() -> anyhow::Result<()> {
        let (tool, arguments, port) = request(
            "recall",
            &strings(&[
                "writer", "--port", "9", "lock", "--repo", "widget", "--k", "3",
            ]),
        )?;
        assert_eq!((tool.as_str(), port.port), ("recall", 9));
        assert_eq!(
            arguments,
            json!({ "text": "writer lock", "repo": "widget", "k": 3 })
        );

        assert!(request("recall", &strings(&["foo", "--rpo", "widget"])).is_err());

        let (_, dashed, _) = request(
            "recall",
            &strings(&["--repo", "widget", "--", "what", "does", "--port", "do"]),
        )?;
        assert_eq!(dashed["text"], "what does --port do");

        let (_, stored, port) = request(
            "remember",
            &strings(&[
                "--type",
                "gotcha",
                "--summary",
                "s",
                "--body",
                "--port",
                "--repo",
                "global",
            ]),
        )?;
        assert_eq!(stored["body"], "--port");
        assert_eq!(port.port, DEFAULT_HTTP_PORT);
        Ok(())
    }

    #[test]
    fn remember_needs_a_type_and_a_summary() {
        let no_type = ["--summary", "s", "--body", "b", "--repo", "global"];
        let no_summary = ["--type", "gotcha", "--body", "b", "--repo", "global"];
        assert!(request("remember", &strings(&no_type)).is_err());
        assert!(request("remember", &strings(&no_summary)).is_err());
    }

    #[test]
    fn remember_collects_every_tag() -> anyhow::Result<()> {
        let (_, arguments, _) = request(
            "remember",
            &strings(&[
                "--type",
                "gotcha",
                "--summary",
                "s",
                "--body",
                "b",
                "--repo",
                "global",
                "--tag",
                "path:src",
                "--tag",
                "db",
                "--force",
            ]),
        )?;
        assert_eq!(
            arguments,
            json!({
                "note_type": "gotcha", "summary": "s", "body": "b", "repo": "global",
                "tags": ["path:src", "db"], "force": true,
            })
        );
        Ok(())
    }
}
