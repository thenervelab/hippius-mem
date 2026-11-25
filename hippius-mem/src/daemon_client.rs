//! A minimal HTTP client for this machine's own loopback daemon
//! (`hippius-mem serve`).
//!
//! Hand-written over `std::net` on purpose. The two callers (`path-notes` and
//! the `call` family) each send one small request to `127.0.0.1` and read one
//! fixed-length answer, and an HTTP client crate would add a TLS stack and a
//! second async runtime to every build for that.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::Context as _;

use crate::http_mcp::default_token_path_from_env;
use crate::setup::mcp::{response_proves_token, token_proof_request};

/// Longest wait for the daemon to accept the connection. Loopback connects in
/// well under a millisecond or is refused at once; arbitrary headroom.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);

/// The daemon's bearer token: the file beside the config `serve` loads.
///
/// # Errors
///
/// Returns an error if the file cannot be read, which is what a machine
/// without the daemon looks like.
pub(crate) fn token() -> anyhow::Result<String> {
    let path = default_token_path_from_env();
    let token = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "no daemon token at {}; `hippius-mem install` sets up the daemon",
            path.display()
        )
    })?;
    Ok(token.trim().to_owned())
}

/// Longest wait on a read of the `/token-proof` answer: one keyed hash.
/// Arbitrary headroom.
const PROOF_TIMEOUT: Duration = Duration::from_millis(500);

/// One request to the daemon.
pub(crate) struct Request<'a> {
    /// The daemon's loopback port.
    pub(crate) port: u16,
    /// Path and query, already percent-encoded.
    pub(crate) target: &'a str,
    /// A JSON body makes the request a `POST`; `None` makes it a `GET`.
    pub(crate) body: Option<&'a str>,
    /// Longest wait on any one socket read. Not a bound on the whole
    /// exchange: a daemon that trickles bytes can take longer.
    pub(crate) read_timeout: Duration,
}

/// Send `request` with the bearer `token` and return the status code and body.
///
/// The token is sent only after the listener answers a fresh `/token-proof`
/// challenge with the proof of `token`. With the daemon down, another local
/// process (another user's daemon on a shared host, or any program) may hold
/// its port, and an edit hook runs this on every first edit of a file: without
/// the check that process would be handed the token. The MCP clients that
/// `install` configures do not make this check.
///
/// # Errors
///
/// Returns an error if the daemon cannot be reached, the listener does not
/// prove it holds `token`, it does not answer within the timeouts, or it answers something
/// that is not an HTTP response.
pub(crate) fn send(request: &Request<'_>, token: &str) -> anyhow::Result<(u16, String)> {
    let Request {
        port,
        target,
        body,
        read_timeout,
    } = *request;
    let nonce = hippius_mem_core::Ulid::new().to_string();
    let proof = exchange(port, &token_proof_request(port, &nonce), PROOF_TIMEOUT)?;
    anyhow::ensure!(
        response_proves_token(proof.as_bytes(), token, &nonce),
        "port {port} is held by a process that does not prove it holds this user's daemon \
         token (another user's daemon, an older hippius-mem serve, or not hippius-mem); not \
         sending it the token"
    );

    let method = if body.is_some() { "POST" } else { "GET" };
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Authorization: Bearer {token}\r\nConnection: close\r\n"
    );
    if let Some(body) = body {
        // Writing to a `String` cannot fail.
        let _ = write!(
            request,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
    }
    request.push_str("\r\n");
    request.push_str(body.unwrap_or_default());
    let response = exchange(port, &request, read_timeout)?;
    // `Connection: close` and a fixed-length body: the daemon does not chunk
    // these answers, so the body is everything after the header block.
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("the daemon's answer is not an HTTP response")?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .context("the daemon's answer has no status line")?;
    Ok((status, body.to_owned()))
}

/// Open a connection to the loopback `port`, write `request`, and read the
/// whole answer (the requests all say `Connection: close`).
fn exchange(port: u16, request: &str, read_timeout: Duration) -> anyhow::Result<String> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).with_context(|| {
        format!("no hippius-mem daemon on {addr}; start it with `hippius-mem serve`")
    })?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(read_timeout))?;
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        // The daemon runs a tool call in its own task, so one it had started
        // is not cancelled by this side giving up.
        .context(
            "the hippius-mem daemon did not answer in time; a call it had started still runs \
             to completion",
        )?;
    String::from_utf8(response).context("the daemon's answer is not UTF-8")
}

/// Percent-encode everything outside RFC 3986's unreserved set.
pub(crate) fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            // Writing to a `String` cannot fail.
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path with a space, `&` or `#` must reach the daemon as one value.
    #[test]
    fn reserved_bytes_are_percent_encoded() {
        assert_eq!(percent_encode("a b&c#d/é.rs"), "a%20b%26c%23d%2F%C3%A9.rs");
        assert_eq!(percent_encode("Az09-._~"), "Az09-._~");
    }
}
