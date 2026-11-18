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

use std::io::{Read as _, Write as _};
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
  hippius-mem recall <text> [--repo <name>] [--k <n>]
  hippius-mem get <mem_id>
  hippius-mem remember --type <note_type> --summary <text> [--body <text>]
                       [--repo <name>] [--tag <tag>]... [--force]
                       (the body is read from stdin when --body is omitted)
all take [--port <n>]. `--repo` defaults to the repository of the current directory;
pass `--repo global` for team-wide.";

/// Run one of the four commands; `command` is the subcommand name.
///
/// # Errors
///
/// Returns an error for malformed arguments, when the daemon cannot be
/// reached, and when the tool itself fails (with the tool's message).
#[expect(
    clippy::unused_async,
    reason = "shares the one-shot subcommands' `async fn run` signature"
)]
pub(crate) async fn run(command: &str, args: &[String]) -> anyhow::Result<()> {
    let (port, args) = take_port(args)?;
    let (tool, arguments) = match command {
        "call" => call_arguments(&args)?,
        "recall" => ("recall".to_owned(), recall_arguments(&args)?),
        "get" => ("get".to_owned(), get_arguments(&args)?),
        "remember" => ("remember".to_owned(), remember_arguments(&args)?),
        _ => anyhow::bail!("{USAGE}"),
    };

    let token = daemon_client::token()?;
    let target = format!("/call/{}", percent_encode(&tool));
    let body = arguments.to_string();
    // The request blocks this thread. Nothing else runs in a one-shot
    // command, so there is no task to starve.
    let (status, answer) = daemon_client::send(
        &Request {
            port,
            target: &target,
            body: Some(&body),
            read_timeout: READ_TIMEOUT,
        },
        &token,
    )?;
    anyhow::ensure!(status == 200, "{tool}: {}", answer.trim());

    let value: Value = serde_json::from_str(&answer).context("the daemon's answer is not JSON")?;
    let mut text = serde_json::to_string_pretty(&value)?;
    text.push('\n');
    let _ = std::io::stdout().write_all(text.as_bytes());
    Ok(())
}

/// Split `--port <n>` out of `args`.
fn take_port(args: &[String]) -> anyhow::Result<(u16, Vec<String>)> {
    let mut port = DEFAULT_HTTP_PORT;
    let mut rest = Vec::with_capacity(args.len());
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--port" {
            let value = iter.next().context("--port requires a value")?;
            port = value
                .parse()
                .with_context(|| format!("invalid --port value `{value}`"))?;
        } else {
            rest.push(arg.clone());
        }
    }
    Ok((port, rest))
}

/// `call <tool> [<json> | -]`.
fn call_arguments(args: &[String]) -> anyhow::Result<(String, Value)> {
    let (tool, json) = match args {
        [tool] => (tool, None),
        [tool, json] => (tool, Some(json.as_str())),
        _ => anyhow::bail!("{USAGE}"),
    };
    let arguments = match json {
        None => json!({}),
        Some("-") => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            serde_json::from_str(&text).context("stdin is not JSON")?
        }
        Some(text) => serde_json::from_str(text).context("the arguments are not JSON")?,
    };
    Ok((tool.clone(), arguments))
}

/// The value after `flag`, or an error naming the flag.
fn flag_value<'a>(
    flag: &str,
    iter: &mut impl Iterator<Item = &'a String>,
) -> anyhow::Result<&'a String> {
    iter.next()
        .with_context(|| format!("{flag} requires a value"))
}

/// `repo` as given, or the repository of the current directory, or `None`
/// (the daemon then scopes to team-global). The daemon serves every
/// repository and cannot know which one a command line is in.
fn repo_or_launch(repo: Option<String>) -> Option<String> {
    repo.or_else(|| {
        let cwd = std::env::current_dir().ok()?;
        let remote = GitRemoteReader.origin_url(&cwd)?;
        Some(resolver::normalize_remote(&remote)?.repo)
    })
}

/// `recall <text> [--repo <name>] [--k <n>]`.
fn recall_arguments(args: &[String]) -> anyhow::Result<Value> {
    let mut words = Vec::new();
    let mut repo = None;
    let mut k = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--repo" => repo = Some(flag_value("--repo", &mut iter)?.clone()),
            "--k" => {
                let value = flag_value("--k", &mut iter)?;
                k = Some(
                    value
                        .parse::<usize>()
                        .with_context(|| format!("invalid --k value `{value}`"))?,
                );
            }
            word => words.push(word),
        }
    }
    anyhow::ensure!(!words.is_empty(), "{USAGE}");
    Ok(json!({ "text": words.join(" "), "repo": repo_or_launch(repo), "k": k }))
}

/// `get <mem_id>`.
fn get_arguments(args: &[String]) -> anyhow::Result<Value> {
    match args {
        [id] => Ok(json!({ "id": id })),
        _ => anyhow::bail!("{USAGE}"),
    }
}

/// `remember --type <t> --summary <s> [--body <b>] [--repo <r>] [--tag <t>]... [--force]`.
fn remember_arguments(args: &[String]) -> anyhow::Result<Value> {
    let mut note_type = None;
    let mut summary = None;
    let mut body = None;
    let mut repo = None;
    let mut tags = Vec::new();
    let mut force = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--type" => note_type = Some(flag_value("--type", &mut iter)?.clone()),
            "--summary" => summary = Some(flag_value("--summary", &mut iter)?.clone()),
            "--body" => body = Some(flag_value("--body", &mut iter)?.clone()),
            "--repo" => repo = Some(flag_value("--repo", &mut iter)?.clone()),
            "--tag" => tags.push(flag_value("--tag", &mut iter)?.clone()),
            "--force" => force = true,
            other => anyhow::bail!("unknown argument `{other}`\n{USAGE}"),
        }
    }
    let (Some(note_type), Some(summary)) = (note_type, summary) else {
        anyhow::bail!("{USAGE}");
    };
    let body = if let Some(body) = body {
        body
    } else {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        text
    };
    Ok(json!({
        "note_type": note_type,
        "summary": summary,
        "body": body,
        "repo": repo_or_launch(repo),
        "tags": tags,
        "force": force,
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

    /// Catches `--port` leaking into a recall's text, and a flag given after
    /// the text being read as part of it.
    #[test]
    fn recall_takes_its_text_from_every_word_that_is_not_a_flag() -> anyhow::Result<()> {
        let (port, rest) = take_port(&strings(&[
            "writer", "--port", "9", "lock", "--repo", "widget", "--k", "3",
        ]))?;
        assert_eq!(port, 9);
        assert_eq!(
            recall_arguments(&rest)?,
            json!({ "text": "writer lock", "repo": "widget", "k": 3 })
        );
        Ok(())
    }

    #[test]
    fn remember_needs_a_type_and_a_summary() {
        assert!(remember_arguments(&strings(&["--summary", "s", "--body", "b"])).is_err());
        assert!(remember_arguments(&strings(&["--type", "gotcha", "--body", "b"])).is_err());
    }

    #[test]
    fn remember_collects_every_tag() -> anyhow::Result<()> {
        let arguments = remember_arguments(&strings(&[
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
        ]))?;
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
