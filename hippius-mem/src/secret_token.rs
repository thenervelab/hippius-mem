//! Loopback bearer-token primitives shared by the dashboard and the HTTP MCP
//! daemon.
//!
//! Both surfaces gate a loopback listener on a random token. One copy of the
//! minting and the constant-time comparison means a hardening fix cannot land
//! on one surface and miss the other.

/// 16 OS-CSPRNG bytes as 32 lowercase hex characters.
///
/// Hex is inherently non-empty and URL-safe, so the dashboard can compare the
/// raw, un-percent-decoded `?t=` value.
///
/// # Errors
///
/// Returns an error if the OS CSPRNG is unavailable (`getrandom::fill` fails).
/// The failure is never downgraded to a weaker source: no token is safer than
/// a guessable one.
pub(crate) fn generate() -> anyhow::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|err| anyhow::anyhow!("OS CSPRNG unavailable for a loopback token: {err}"))?;
    Ok(hippius_mem_core::hex::encode(bytes))
}

/// Constant-time equality for equal-length secrets.
///
/// A length mismatch returns `false` immediately (the tokens are fixed 32-hex;
/// a length leak is not useful). Equal-length compares XOR every byte so a
/// prefix match does not return early.
pub(crate) fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut acc = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        acc |= a ^ b;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests assert on fixtures where construction cannot fail"
    )]

    use super::{constant_time_eq, generate};

    #[test]
    fn generate_is_thirty_two_lowercase_hex_and_unique() {
        let a = generate().unwrap();
        let b = generate().unwrap();

        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_ne!(a, b);
    }

    #[test]
    fn constant_time_eq_rejects_prefix_and_length_mismatch() {
        assert!(constant_time_eq("abcd", "abcd"));
        assert!(!constant_time_eq("abcd", "abce"));
        assert!(!constant_time_eq("abcd", "abc"));
        assert!(!constant_time_eq("abcd", "abcde"));
    }
}
