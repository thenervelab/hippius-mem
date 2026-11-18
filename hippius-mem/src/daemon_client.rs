//! A minimal HTTP client for this machine's own loopback daemon
//! (`hippius-mem serve`).
//!
//! Hand-written over `std::net` on purpose. Its caller (`path-notes`) sends
//! one small `GET` to `127.0.0.1` and reads one fixed-length answer, and an
//! HTTP client crate would add a TLS stack and a second async runtime to
//! every build for that.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::Context as _;

use crate::http_mcp::default_token_path_from_env;
use crate::setup::mcp::health_response_is_ours;

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

/// Longest wait on a read of the `/health` answer: a constant string from
/// memory. Arbitrary headroom.
const HEALTH_TIMEOUT: Duration = Duration::from_millis(500);

/// `GET target` (path and query, already percent-encoded) from the daemon on
/// `port` with the bearer `token`, and return the status code and body.
/// `read_timeout` bounds each socket read, not the whole exchange.
///
/// The token is sent only after the listener answers `/health` as this daemon
/// does. With the daemon down, some other local service may hold its port, and
/// an edit hook runs this on every first edit of a file: without the check
/// that service would be handed the token. The check stops an accidental
/// occupant, not a hostile one, which can answer `/health` the same way; the
/// MCP clients configured by `install` have the same exposure.
///
/// # Errors
///
/// Returns an error if the daemon cannot be reached, the listener is not this
/// daemon, it does not answer within the timeouts, or it answers something
/// that is not an HTTP response.
pub(crate) fn get(
    port: u16,
    target: &str,
    read_timeout: Duration,
    token: &str,
) -> anyhow::Result<(u16, String)> {
    let health = exchange(
        port,
        &format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
        HEALTH_TIMEOUT,
    )?;
    anyhow::ensure!(
        health_response_is_ours(health.as_bytes()),
        "port {port} is held by something that is not the hippius-mem daemon; \
         not sending it the token"
    );

    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Authorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
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
        .context("the hippius-mem daemon did not answer in time")?;
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
