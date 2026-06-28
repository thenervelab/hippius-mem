//! api.hippius.com sub-token minting: turn one BIP-39 mnemonic into an S3
//! sub-token (`access_key_id` + `secret`) scoped to a team bucket.
//!
//! # Why this exists
//!
//! Every dev needs an S3 sub-token to read/write the team's memory blobs. Those
//! are minted from the Hippius backend (`api.hippius.com`; the `hippius-console`
//! repo is its web frontend) via a three-step EIP-191 challenge/response:
//!
//! 1. `POST /api/auth/mnemonic/` `{address, substrate_address}` → `{challenge,
//!    message}`.
//! 2. EIP-191 personal-sign the returned `message` with the account's **ETH**
//!    key, then `POST /api/auth/verify/` → a session bearer `token`.
//! 3. `POST /api/objectstore/sub-tokens/` (auth `Token <bearer>`) → the
//!    `{accessKeyId, secret}` pair.
//!
//! The wire shapes below mirror `hippius-console`'s `auth-service.ts`,
//! `WalletAuthContext.tsx`, `useApiTokens.ts`, and `config.ts` exactly (verified
//! by cross-repo inspection, 2026-06). The HTTP/crypto machinery is gated behind
//! the `console` cargo feature so the default build never pulls reqwest/alloy;
//! only the plain serde wire types and [`S3Creds`] compile unconditionally so the
//! wire contract is pinned by CI tests even without the feature.
//!
//! # Secret handling
//!
//! The S3 `secret` is the one piece of returned material that grants write
//! access. It lives only inside [`S3Creds`] (whose [`Debug`] redacts it) and is
//! never interpolated into a log line, a `tracing` event, or a [`MemError`]
//! string — see [`ConsoleClient::mint_sub_token`] and its `post_json` helper.

use serde::{Deserialize, Serialize};

/// The default Hippius backend the sub-token API lives behind.
///
/// Mirrors `hippius-console`'s `API_CONFIG.baseUrl` default (`config.ts`).
pub const DEFAULT_CONSOLE_BASE_URL: &str = "https://api.hippius.com";

/// SS58 network prefix for Hippius / generic Substrate identities (prefix 42),
/// matching the `@polkadot/keyring` default the console signs in with.
#[cfg(feature = "console")]
const HIPPIUS_SS58_PREFIX: crate::domain::NetworkPrefix = crate::domain::NetworkPrefix::HIPPIUS;

/// Challenge endpoint (`API_CONFIG.auth.mnemonic`).
#[cfg(feature = "console")]
const AUTH_MNEMONIC_PATH: &str = "/api/auth/mnemonic/";
/// Verify endpoint (`API_CONFIG.auth.verify`).
#[cfg(feature = "console")]
const AUTH_VERIFY_PATH: &str = "/api/auth/verify/";
/// Sub-token mint endpoint (`useApiTokens.ts` create mutation).
#[cfg(feature = "console")]
const SUB_TOKENS_PATH: &str = "/api/objectstore/sub-tokens/";
/// `scope_type` wire value for a sub-token scoped to exactly one bucket.
///
/// `resolveScopeType` in `useApiTokens.ts` maps a one-bucket list to
/// `single_bucket`; we always scope to a single team bucket.
#[cfg(feature = "console")]
const SINGLE_BUCKET_SCOPE: &str = "single_bucket";

/// Body of `POST /api/auth/mnemonic/`.
///
/// `substrate_address` is the SS58 form; `address` is the EIP-55 ETH form. Field
/// names match `auth-service.ts`'s `requestChallenge` request body exactly.
///
/// This and the sibling wire types are public — they are the documented
/// api.hippius.com contract, and being public keeps them alive (no dead-code
/// warning) when the `console` feature, the only in-crate consumer, is off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MnemonicChallengeReq {
    /// EIP-55 checksummed ETH address.
    pub address: String,
    /// SS58 substrate address.
    pub substrate_address: String,
}

/// Response of `POST /api/auth/mnemonic/`.
///
/// `message` is the human-readable text that gets EIP-191 signed (the console
/// signs `message`, not the bare `challenge`); `challenge` is echoed back in the
/// verify step. Matches `ChallengeResponse` in `auth-service.ts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResp {
    /// Opaque challenge token, echoed back when verifying.
    pub challenge: String,
    /// The exact text the client must EIP-191 sign.
    pub message: String,
}

/// The `session_data` sub-object the console sends inside the verify body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionData {
    /// The challenge being answered.
    pub challenge: String,
    /// The ETH address that requested the challenge.
    pub address: String,
}

/// Body of `POST /api/auth/verify/`.
///
/// Mirrors `auth-service.ts`'s `verifySignature` request: a `0x`-prefixed
/// signature, the two addresses, the echoed challenge, an optional referral
/// code (always `null` here), and the duplicated `session_data`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReq {
    /// `0x`-prefixed 65-byte EIP-191 signature over [`ChallengeResp::message`].
    pub signature: String,
    /// EIP-55 checksummed ETH address.
    pub address: String,
    /// SS58 substrate address.
    pub substrate_address: String,
    /// The challenge being answered.
    pub challenge: String,
    /// Referral code — `None` (serialized as JSON `null`) for sub-token minting.
    pub referral_code: Option<String>,
    /// Duplicated challenge/address the console includes as `session_data`.
    pub session_data: SessionData,
}

/// Response of `POST /api/auth/verify/`.
///
/// Only `token` (the session bearer) is consumed; the real response also carries
/// `user_id`, `username`, `substrate_address`, and `is_new`, which serde ignores
/// as unknown fields. Kept minimal so there are no dead fields to lint. [`Debug`]
/// redacts the bearer token by hand so it cannot reach a log line.
#[derive(Clone, Deserialize)]
pub struct VerifyResp {
    /// Session bearer token used to authorize the sub-token mint.
    pub token: String,
}

impl core::fmt::Debug for VerifyResp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The bearer token authorizes minting; keep it out of logs/panics.
        f.debug_struct("VerifyResp")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Body of `POST /api/objectstore/sub-tokens/`.
///
/// Mirrors the create payload in `useApiTokens.ts`. `not_before`/`expires_at`
/// are `None` here: a `null`/absent `not_before` means "active immediately" and
/// a `null` `expires_at` means "never expires", which avoids a date/time
/// dependency. Evidence that the backend tolerates an absent `not_before`: the
/// `hippius-s3` smoke client (`tests/smoke/hippius_api_client.py`) omits it
/// entirely and succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubTokenReq {
    /// Human-facing label for the sub-token.
    pub name: String,
    /// `single_bucket` — see [`SINGLE_BUCKET_SCOPE`].
    pub scope_type: String,
    /// The buckets the sub-token may touch (exactly one, the team bucket).
    pub bucket_names: Vec<String>,
    /// Granted actions, e.g. `["read", "write"]`.
    pub actions: Vec<String>,
    /// Object-key prefixes the sub-token is restricted to (empty = no restriction).
    pub allowed_prefixes: Vec<String>,
    /// Source-IP allowlist (empty = any).
    pub ip_allowlist: Vec<String>,
    /// Activation time; `None` (JSON `null`) means active immediately.
    pub not_before: Option<String>,
    /// Expiry time; `None` (JSON `null`) means never expires.
    pub expires_at: Option<String>,
}

/// Response of `POST /api/objectstore/sub-tokens/`.
///
/// The create endpoint returns `camelCase` (`accessKeyId`); the list endpoint
/// returns `snake_case` (`access_key_id`). The `alias` accepts both, matching the
/// smoke client's `body.get("accessKeyId") or body["access_key_id"]` fallback.
/// [`Debug`] redacts the secret by hand so it cannot reach a log line.
#[derive(Clone, Deserialize)]
pub struct SubTokenResp {
    /// The sub-token's access key id.
    #[serde(rename = "accessKeyId", alias = "access_key_id")]
    pub access_key_id: String,
    /// The sub-token's secret — write-granting material, never logged.
    pub secret: String,
}

impl core::fmt::Debug for SubTokenResp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Mirror `S3Creds`: the secret never reaches a log or panic message.
        f.debug_struct("SubTokenResp")
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// A minted S3 sub-token: the `access_key_id` plus its `secret`.
///
/// The `secret` grants write access to the team bucket. [`Debug`] is implemented
/// by hand to redact it so it cannot reach a log line or panic message; callers
/// that must persist it should write it to a `0600` file, never stdout.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Creds {
    /// Public sub-token id, safe to display.
    pub access_key_id: String,
    /// Secret half of the sub-token. Redacted in [`Debug`]; never log it.
    pub secret: String,
}

impl core::fmt::Debug for S3Creds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Hand-written so the secret never reaches a log or panic message;
        // deriving Debug would print it in full.
        f.debug_struct("S3Creds")
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "console")]
use alloy_signer::Signer;
#[cfg(feature = "console")]
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};

#[cfg(feature = "console")]
use crate::error::MemError;
#[cfg(feature = "console")]
use crate::identity::derive_identity;

/// Derive the ETH signer (and, via it, the EIP-55 address) for a mnemonic.
///
/// Completes the ETH-key derivation deferred from Task 21. Uses the standard
/// Ethereum BIP-44 path `m/44'/60'/0'/0/0` (account index 0) — the same default
/// as viem's `mnemonicToAccount`, which the console signs in with, so the
/// derived address matches the console's.
///
/// # Errors
///
/// Returns [`MemError::Identity`] if the mnemonic is not a valid BIP-39 phrase
/// or the key cannot be derived. The mnemonic is never included in the error.
#[cfg(feature = "console")]
pub fn eth_signer_from_mnemonic(mnemonic: &str) -> Result<PrivateKeySigner, MemError> {
    MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .index(0)
        .map_err(|_| MemError::Identity("invalid mnemonic for ETH key derivation".to_owned()))?
        .build()
        .map_err(|_| MemError::Identity("could not derive ETH key from mnemonic".to_owned()))
}

/// A client for the api.hippius.com sub-token minting flow.
///
/// Holds the backend base URL and a reusable async [`reqwest::Client`]. Cheap to
/// clone (the inner client is reference-counted); all methods take `&self`.
#[cfg(feature = "console")]
#[derive(Debug, Clone)]
pub struct ConsoleClient {
    /// Backend base URL, with any trailing `/` trimmed so path joins are clean.
    base_url: String,
    /// Shared async HTTP client (connection pool is reference-counted inside).
    http: reqwest::Client,
}

#[cfg(feature = "console")]
impl ConsoleClient {
    /// Build a client targeting `base_url` (e.g. [`DEFAULT_CONSOLE_BASE_URL`]).
    ///
    /// A trailing `/` on `base_url` is trimmed so it joins cleanly with the
    /// leading-slash endpoint paths. A non-HTTPS, non-loopback `base_url` is
    /// warned about (see below) but accepted, so the constructor stays infallible.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        // This URL carries the session bearer token and the minted S3 secret; a
        // plaintext http:// endpoint exposes both to a network MITM. Production
        // must be https. We warn rather than reject so local loopback mocks and
        // dev over http keep working without forcing a fallible constructor.
        let is_https = base_url
            .split_once("://")
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"));
        if !is_https && !is_loopback_base_url(&base_url) {
            tracing::warn!(
                base_url = %base_url,
                "ConsoleClient targets a non-HTTPS, non-loopback URL; the bearer token and minted S3 secret would traverse the network in cleartext"
            );
        }
        Self {
            base_url,
            http: reqwest::Client::new(),
        }
    }

    /// Mint an S3 sub-token scoped to `bucket` with read+write, named `name`.
    ///
    /// Runs the full three-step flow: challenge → EIP-191 sign with the ETH key
    /// → verify → mint. The two addresses are derived from `mnemonic` exactly as
    /// the console does (ETH key at `m/44'/60'/0'/0/0`; SS58 at prefix 42).
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Identity`] if the mnemonic cannot be turned into the
    /// ETH/SS58 identities or the challenge cannot be signed, [`MemError::Storage`]
    /// for any HTTP/transport failure or non-2xx response, and
    /// [`MemError::Malformed`] if a 2xx response body does not decode. Neither the
    /// mnemonic nor the returned secret is ever placed in an error.
    pub async fn mint_sub_token(
        &self,
        mnemonic: &str,
        bucket: &str,
        name: &str,
    ) -> Result<S3Creds, MemError> {
        // Both addresses come from the one mnemonic, the way the console derives
        // them: the ETH account (EIP-55) signs; the SS58 account labels the user.
        let signer = eth_signer_from_mnemonic(mnemonic)?;
        let address = signer.address().to_checksum(None);
        let substrate_address = derive_identity(mnemonic, HIPPIUS_SS58_PREFIX)?
            .ss58
            .as_str()
            .to_owned();

        // 1) Ask for a challenge.
        let challenge: ChallengeResp = self
            .post_json(
                AUTH_MNEMONIC_PATH,
                &MnemonicChallengeReq {
                    address: address.clone(),
                    substrate_address: substrate_address.clone(),
                },
                None,
                "challenge",
            )
            .await?;

        // 2) EIP-191 personal-sign the message. `sign_message` applies the
        // `\x19Ethereum Signed Message:\n<len>` prefix; `as_bytes()` yields
        // `r ‖ s ‖ v` with `v` in 27/28 form — byte-identical to viem's
        // `signMessage`, which the backend recovers against.
        let signature = signer
            .sign_message(challenge.message.as_bytes())
            .await
            .map_err(|_| MemError::Identity("could not sign the auth challenge".to_owned()))?;
        let signature = format!("0x{}", hex::encode(signature.as_bytes()));

        // 3) Verify the signature, receiving a session bearer token.
        let verified: VerifyResp = self
            .post_json(
                AUTH_VERIFY_PATH,
                &VerifyReq {
                    signature,
                    address: address.clone(),
                    substrate_address,
                    challenge: challenge.challenge.clone(),
                    referral_code: None,
                    session_data: SessionData {
                        challenge: challenge.challenge,
                        address,
                    },
                },
                None,
                "verify",
            )
            .await?;

        // 4) Mint a sub-token scoped to the one bucket with read+write.
        let minted: SubTokenResp = self
            .post_json(
                SUB_TOKENS_PATH,
                &SubTokenReq {
                    name: name.to_owned(),
                    scope_type: SINGLE_BUCKET_SCOPE.to_owned(),
                    bucket_names: vec![bucket.to_owned()],
                    actions: vec!["read".to_owned(), "write".to_owned()],
                    allowed_prefixes: Vec::new(),
                    ip_allowlist: Vec::new(),
                    not_before: None,
                    expires_at: None,
                },
                Some(&verified.token),
                "mint sub-token",
            )
            .await?;

        Ok(S3Creds {
            access_key_id: minted.access_key_id,
            secret: minted.secret,
        })
    }

    /// POST `body` as JSON to `path`, optionally with a `Token <bearer>` header,
    /// and deserialize the 2xx response into `R`.
    ///
    /// `step` names the stage for error messages. The success body is
    /// deserialized straight into `R` and never formatted into a string, so the
    /// secret-bearing sub-token response cannot leak into a log or error: a
    /// decode failure is reported WITHOUT the body for that reason. Only the
    /// non-2xx error body — which never carries a secret — is surfaced verbatim.
    async fn post_json<B, R>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
        step: &str,
    ) -> Result<R, MemError>
    where
        B: Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{path}", self.base_url);
        let mut request = self.http.post(&url).json(body);
        if let Some(token) = bearer {
            // Django REST Framework's `TokenAuthentication` scheme is `Token
            // <key>` (NOT `Bearer`), matching `useApiTokens.ts`.
            request = request.header(reqwest::header::AUTHORIZATION, format!("Token {token}"));
        }
        let response = request
            .send()
            .await
            .map_err(|err| MemError::Storage(format!("console {step} request failed: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(MemError::Storage(format!(
                "console {step} returned HTTP {}: {body}",
                status.as_u16()
            )));
        }
        // A 2xx whose body will not decode is a malformed response (the backend
        // worked; the bytes are wrong) — `Malformed`, not `Storage` (a transport
        // fault). The body is still omitted: the sub-token response carries the
        // S3 secret, which must never reach an error string.
        response.json::<R>().await.map_err(|_| {
            MemError::Malformed(format!("console {step} returned a malformed response"))
        })
    }
}

/// Whether `base_url`'s host is exactly a loopback address, where plain `http`
/// is acceptable (local mock servers, dev). Anything else over `http` trips the
/// [`ConsoleClient::new`] cleartext warning.
///
/// The host must END at a port (`:`), a path (`/`), or string end, so a spoof
/// like `http://localhost.evil.com` or `http://127.0.0.1@evil.com` does NOT
/// suppress the warning (a bare `starts_with` would). This is a best-effort
/// advisory check, not a parsed-URL authority, since `url` is not a dependency;
/// the real defense is using `https` in production.
#[cfg(feature = "console")]
fn is_loopback_base_url(base_url: &str) -> bool {
    // Split scheme://authority case-insensitively, matching the https check, and
    // accept only a plain `http` scheme (loopback never needs https).
    let Some((scheme, rest)) = base_url.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    // The authority ends at the first `/` (path) if present.
    let authority = rest.split('/').next().unwrap_or(rest);
    // Strip an optional `:port`, but reject userinfo (`@`) — `127.0.0.1@evil` is
    // NOT a loopback host. `[::1]` keeps its brackets before the port split.
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_prefix("[::1]") {
        Some(after) => return after.is_empty() || after.starts_with(':'),
        None => authority.split(':').next().unwrap_or(authority),
    };
    host.eq_ignore_ascii_case("127.0.0.1") || host.eq_ignore_ascii_case("localhost")
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests parse hand-built JSON fixtures whose shape cannot fail"
    )]

    use super::*;

    #[test]
    fn challenge_resp_deserializes_real_shape() {
        let raw = r#"{"challenge":"abc123","message":"Sign in to Hippius: abc123"}"#;
        let resp: ChallengeResp = serde_json::from_str(raw).expect("challenge parses");
        assert_eq!(resp.challenge, "abc123");
        assert_eq!(resp.message, "Sign in to Hippius: abc123");
    }

    #[test]
    fn verify_resp_deserializes_real_shape() {
        // The real verify response carries extra fields; serde must ignore them
        // and still extract the bearer token.
        let raw = r#"{
            "token":"sess-tok-xyz",
            "user_id":42,
            "username":"ouro",
            "substrate_address":"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "is_new":false
        }"#;
        let resp: VerifyResp = serde_json::from_str(raw).expect("verify parses");
        assert_eq!(resp.token, "sess-tok-xyz");
    }

    #[test]
    fn sub_token_resp_extracts_creds_camel_case() {
        // The CREATE endpoint returns camelCase plus extra fields.
        let raw = r#"{
            "id":"tok-1",
            "name":"hippius-mem",
            "accessKeyId":"AKIAEXAMPLE",
            "secret":"s3cr3t-value",
            "createdAt":"2026-06-26T00:00:00Z"
        }"#;
        let resp: SubTokenResp = serde_json::from_str(raw).expect("sub-token parses");
        assert_eq!(resp.access_key_id, "AKIAEXAMPLE");
        assert_eq!(resp.secret, "s3cr3t-value");
    }

    #[test]
    fn sub_token_resp_accepts_snake_case_alias() {
        // The LIST endpoint (and any snake_case variant) must still parse.
        let raw = r#"{"access_key_id":"AKIASNAKE","secret":"snake-secret"}"#;
        let resp: SubTokenResp = serde_json::from_str(raw).expect("snake-case parses");
        assert_eq!(resp.access_key_id, "AKIASNAKE");
        assert_eq!(resp.secret, "snake-secret");
    }

    #[test]
    fn sub_token_req_serializes_expected_fields() {
        let req = SubTokenReq {
            name: "hippius-mem".to_owned(),
            scope_type: "single_bucket".to_owned(),
            bucket_names: vec!["team-bucket".to_owned()],
            actions: vec!["read".to_owned(), "write".to_owned()],
            allowed_prefixes: Vec::new(),
            ip_allowlist: Vec::new(),
            not_before: None,
            expires_at: None,
        };
        let value: serde_json::Value = serde_json::to_value(&req).expect("serializes");
        assert_eq!(value["name"], "hippius-mem");
        assert_eq!(value["scope_type"], "single_bucket");
        assert_eq!(value["bucket_names"][0], "team-bucket");
        assert_eq!(value["actions"], serde_json::json!(["read", "write"]));
        assert_eq!(value["allowed_prefixes"], serde_json::json!([]));
        assert_eq!(value["ip_allowlist"], serde_json::json!([]));
        // `None` must serialize to explicit JSON null, matching the console's
        // `expires_at: expires_at ?? null`.
        assert!(value["not_before"].is_null());
        assert!(value["expires_at"].is_null());
    }

    #[test]
    fn challenge_req_serializes_substrate_address_field() {
        let req = MnemonicChallengeReq {
            address: "0xabc".to_owned(),
            substrate_address: "5Grw".to_owned(),
        };
        let value: serde_json::Value = serde_json::to_value(&req).expect("serializes");
        assert_eq!(value["address"], "0xabc");
        assert_eq!(value["substrate_address"], "5Grw");
    }

    #[test]
    fn s3creds_debug_redacts_secret() {
        let creds = S3Creds {
            access_key_id: "AKIAEXAMPLE".to_owned(),
            secret: "top-secret-value".to_owned(),
        };
        let shown = format!("{creds:?}");
        assert!(
            !shown.contains("top-secret-value"),
            "Debug leaked the secret: {shown}"
        );
        assert!(shown.contains("AKIAEXAMPLE"), "access key id should show");
        assert!(
            shown.contains("redacted"),
            "secret should be marked redacted"
        );
    }
}

#[cfg(all(test, feature = "console"))]
mod console_tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert on fixtures and a local mock where setup cannot fail"
    )]

    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The standard hardhat/anvil test mnemonic. Its keys are public, so it is
    /// safe to pin as an interoperability fixture.
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
    /// Account 0 (`m/44'/60'/0'/0/0`) of [`TEST_MNEMONIC`], EIP-55 checksummed.
    const TEST_ETH_ADDR0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn loopback_detection_rejects_spoofed_hosts() {
        // Genuine loopback over http is allowed (no cleartext warning).
        assert!(super::is_loopback_base_url("http://127.0.0.1:8080"));
        assert!(super::is_loopback_base_url("http://localhost"));
        assert!(super::is_loopback_base_url("http://localhost:3000/api"));
        assert!(super::is_loopback_base_url("http://[::1]:9999"));
        // Spoofs that a bare prefix-match would wrongly accept must be rejected.
        assert!(!super::is_loopback_base_url("http://localhost.evil.com"));
        assert!(!super::is_loopback_base_url("http://127.0.0.1.evil.com"));
        assert!(!super::is_loopback_base_url("http://127.0.0.1@evil.com"));
        assert!(!super::is_loopback_base_url("https://api.hippius.com"));
    }

    #[test]
    fn eth_signer_from_mnemonic_known_vector() {
        let signer = eth_signer_from_mnemonic(TEST_MNEMONIC).expect("derives");
        assert_eq!(signer.address().to_checksum(None), TEST_ETH_ADDR0);
    }

    #[test]
    fn eth_signer_from_mnemonic_is_deterministic() {
        let a = eth_signer_from_mnemonic(TEST_MNEMONIC).expect("derives");
        let b = eth_signer_from_mnemonic(TEST_MNEMONIC).expect("derives");
        assert_eq!(a.address(), b.address());
    }

    #[test]
    fn eth_signer_from_mnemonic_rejects_garbage() {
        assert!(eth_signer_from_mnemonic("not a real mnemonic at all").is_err());
    }

    #[tokio::test]
    async fn eip191_signature_recovers_offline() {
        // identity-3: pin alloy's EIP-191 recovery-id byte layout (r||s||v with v
        // in 27/28 form) WITHOUT a network round-trip, so an upstream alloy change
        // that altered it is caught by CI rather than by a failed live mint. The
        // live test only asserts the backend accepts the signature; this asserts
        // the bytes themselves recover to the known signer.
        let signer = eth_signer_from_mnemonic(TEST_MNEMONIC).expect("derives");
        let message = b"hippius-memory offline recovery probe";
        let signature = signer.sign_message(message).await.expect("signs");

        // The signature recovers to the signer's own address — proving the byte
        // layout the backend's recovery relies on.
        let recovered = signature
            .recover_address_from_msg(message)
            .expect("recovers the signer");
        assert_eq!(recovered.to_checksum(None), TEST_ETH_ADDR0);

        // The v byte (index 64 of r ‖ s ‖ v) is in Ethereum's 27/28 form.
        let bytes = signature.as_bytes();
        assert_eq!(bytes.len(), 65, "r||s||v is 65 bytes");
        assert!(
            bytes[64] == 27 || bytes[64] == 28,
            "v must be 27 or 28, got {}",
            bytes[64]
        );
    }

    #[tokio::test]
    async fn mint_sub_token_happy_path() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(AUTH_MNEMONIC_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "chal-123",
                "message": "Sign in to Hippius: chal-123",
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(AUTH_VERIFY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "sess-token",
                "user_id": 1,
                "username": "ouro",
                "substrate_address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
                "is_new": false,
            })))
            .mount(&server)
            .await;

        // This mock only matches when the `Token <bearer>` header from the verify
        // step is present, so a passing test proves the bearer propagated.
        Mock::given(method("POST"))
            .and(path(SUB_TOKENS_PATH))
            .and(header("authorization", "Token sess-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tok-1",
                "name": "my-token",
                "accessKeyId": "AKIA_FROM_MOCK",
                "secret": "secret-from-mock",
                "createdAt": "2026-06-26T00:00:00Z",
            })))
            .mount(&server)
            .await;

        let client = ConsoleClient::new(server.uri());
        let creds = client
            .mint_sub_token(TEST_MNEMONIC, "team-bucket", "my-token")
            .await
            .expect("mint succeeds");

        assert_eq!(creds.access_key_id, "AKIA_FROM_MOCK");
        assert_eq!(creds.secret, "secret-from-mock");

        // Prove the EIP-191 signature was generated and sent: the verify request
        // body must carry a `0x`-prefixed 65-byte signature (132 chars).
        let requests = server.received_requests().await.expect("requests recorded");
        let verify = requests
            .iter()
            .find(|r| r.url.path() == AUTH_VERIFY_PATH)
            .expect("verify request sent");
        let body: serde_json::Value =
            serde_json::from_slice(&verify.body).expect("verify body is json");
        let signature = body["signature"].as_str().expect("signature present");
        assert!(signature.starts_with("0x"), "signature must be 0x-prefixed");
        assert_eq!(
            signature.len(),
            2 + 130,
            "65-byte sig is 0x + 130 hex chars"
        );
    }

    #[tokio::test]
    async fn mint_sub_token_maps_http_error_to_storage() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_MNEMONIC_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_string("upstream boom"))
            .mount(&server)
            .await;

        let client = ConsoleClient::new(server.uri());
        let err = client
            .mint_sub_token(TEST_MNEMONIC, "team-bucket", "my-token")
            .await
            .expect_err("a 500 must surface as an error");
        assert!(
            matches!(err, MemError::Storage(_)),
            "expected Storage, got {err:?}"
        );
        // The mnemonic must never appear in the error string.
        assert!(!err.to_string().contains("junk"), "mnemonic leaked: {err}");
    }

    #[tokio::test]
    async fn mint_sub_token_maps_malformed_2xx_to_malformed() {
        // L1 regression: a 2xx whose body does not decode is a Malformed response
        // (the backend answered; the bytes are wrong), distinct from the Storage a
        // transport failure or non-2xx status yields.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(AUTH_MNEMONIC_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string("{ not the expected shape"))
            .mount(&server)
            .await;

        let client = ConsoleClient::new(server.uri());
        let err = client
            .mint_sub_token(TEST_MNEMONIC, "team-bucket", "my-token")
            .await
            .expect_err("a malformed 2xx body must error");
        assert!(
            matches!(err, MemError::Malformed(_)),
            "expected Malformed, got {err:?}"
        );
    }

    /// Live end-to-end mint against the real backend. `#[ignore]`d: it needs a
    /// real mnemonic, a real bucket, and network. Run explicitly with, e.g.:
    ///
    /// ```text
    /// HIPPIUS_MEM_MNEMONIC="word word ..." HIPPIUS_MEM_TEST_BUCKET="my-bucket" \
    ///   cargo test -p hippius-mem-core --features console -- --ignored live_
    /// ```
    #[tokio::test]
    #[ignore = "live: needs HIPPIUS_MEM_MNEMONIC, HIPPIUS_MEM_TEST_BUCKET, and network"]
    async fn live_mint_sub_token_against_real_backend() {
        let mnemonic = std::env::var("HIPPIUS_MEM_MNEMONIC").expect("set HIPPIUS_MEM_MNEMONIC");
        let bucket = std::env::var("HIPPIUS_MEM_TEST_BUCKET").expect("set HIPPIUS_MEM_TEST_BUCKET");
        let base = std::env::var("HIPPIUS_MEM_CONSOLE_URL")
            .unwrap_or_else(|_| DEFAULT_CONSOLE_BASE_URL.to_owned());

        let client = ConsoleClient::new(base);
        let creds = client
            .mint_sub_token(&mnemonic, &bucket, "hippius-mem-live-test")
            .await
            .expect("real mint succeeds");
        // Never print the secret; just assert both halves came back non-empty.
        assert!(!creds.access_key_id.is_empty(), "access_key_id returned");
        assert!(!creds.secret.is_empty(), "secret returned");
    }
}
