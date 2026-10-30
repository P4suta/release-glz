//! What a GitHub Actions OIDC token's validity window, run numbers, and URLs allow.
//!
//! The adapter verifies the token's signature and parses its claims and URLs, and these functions decide what the parsed values allow.

/// Seconds that a token's issue time and the start of its validity may lie ahead of the verifier's clock.
pub const CLOCK_SKEW_SECONDS: i64 = 30;

/// The host that serves the issuer's discovery document and key set.
pub const OIDC_ISSUER_HOST: &[u8] = b"token.actions.githubusercontent.com";

/// The zone whose hosts serve runners their tokens.
pub const RUNNER_TOKEN_ZONE: &[u8] = b"actions.githubusercontent.com";

/// The base of the decimal digits that a run attempt is written in.
const DECIMAL_BASE: u64 = 10;

/// The times that a token states, in Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct TokenTimes {
    /// When the issuer minted the token.
    pub issued_at: i64,
    /// The earliest time the token is valid, when it names one.
    pub not_before: Option<i64>,
    /// The time from which the token is no longer valid.
    pub expires_at: i64,
}

/// Why a token isn't valid now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowRefusal {
    /// The token expired at or before now.
    Expired,
    /// The issuer minted the token later than now and the clock skew allow.
    IssuedInFuture,
    /// The token becomes valid later than now and the clock skew allow.
    NotYetValid,
}

/// Whether a token with `times` is valid at `now`, or the first check it fails.
///
/// The token has to expire after `now`, and neither its issue time nor the start of its validity may lie more than [`CLOCK_SKEW_SECONDS`] after `now`.
pub fn token_window(times: TokenTimes, now: i64) -> Result<(), WindowRefusal> {
    if expired(times.expires_at, now) {
        return Err(WindowRefusal::Expired);
    }
    let latest = latest_start(now);
    if times.issued_at > latest {
        return Err(WindowRefusal::IssuedInFuture);
    }
    if times
        .not_before
        .is_some_and(|not_before| not_before > latest)
    {
        return Err(WindowRefusal::NotYetValid);
    }
    Ok(())
}

fn expired(expires_at: i64, now: i64) -> bool {
    #[cfg(feature = "negative-control-token-expiry")]
    if let Some(expired) = negative_control_token_expiry(expires_at, now) {
        return expired;
    }
    expires_at <= now
}

/// The latest issue time or start of validity that a token may state at `now`, which stays at the largest time instead of wrapping.
fn latest_start(now: i64) -> i64 {
    #[cfg(feature = "negative-control-token-skew-wrap")]
    if let Some(latest) = negative_control_token_skew_wrap(now) {
        return latest;
    }
    now.saturating_add(CLOCK_SKEW_SECONDS)
}

/// Whether `text` is a run ID: one or more ASCII digits.
pub fn is_run_id(text: &[u8]) -> bool {
    !text.is_empty() && text.iter().all(u8::is_ascii_digit)
}

/// The attempt number that `text` names, when it is one or more ASCII digits for a positive number that fits in 64 bits.
pub fn run_attempt(text: &[u8]) -> Option<u64> {
    #[cfg(feature = "negative-control-signed-attempt")]
    if let Some(attempt) = negative_control_signed_attempt(text) {
        return attempt;
    }
    positive_decimal(text)
}

fn positive_decimal(text: &[u8]) -> Option<u64> {
    if !is_run_id(text) {
        return None;
    }
    let mut value: u64 = 0;
    for &byte in text {
        value = value
            .checked_mul(DECIMAL_BASE)?
            .checked_add(u64::from(byte - b'0'))?;
    }
    (value > 0).then_some(value)
}

/// Which GitHub OIDC URL an adapter checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum OidcUrlKind {
    /// The issuer's discovery document.
    Discovery,
    /// The issuer's key set.
    Jwks,
    /// The runner's token request.
    RunnerToken,
}

/// Why a URL can't serve as a GitHub OIDC URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginRefusal {
    /// The URL uses another scheme than HTTPS.
    NotHttps,
    /// The URL's host isn't GitHub's host for its kind.
    UntrustedHost,
}

/// Whether a URL of `kind` with `scheme` and `host` names GitHub's own origin, or why not.
///
/// `loopback` tells whether the host is a loopback IP address, which a test may use over plain HTTP when `allow_http_loopback` is set.
pub fn oidc_origin(
    kind: OidcUrlKind,
    scheme: &[u8],
    host: &[u8],
    loopback: bool,
    allow_http_loopback: bool,
) -> Result<(), OriginRefusal> {
    if allow_http_loopback && loopback && scheme == b"http" {
        return Ok(());
    }
    if scheme != b"https" {
        return Err(OriginRefusal::NotHttps);
    }
    let trusted = match kind {
        OidcUrlKind::Discovery | OidcUrlKind::Jwks => host.eq_ignore_ascii_case(OIDC_ISSUER_HOST),
        OidcUrlKind::RunnerToken => {
            host.eq_ignore_ascii_case(RUNNER_TOKEN_ZONE) || in_zone(host, RUNNER_TOKEN_ZONE)
        }
    };
    if !trusted {
        return Err(OriginRefusal::UntrustedHost);
    }
    Ok(())
}

/// Whether `host` names a host inside `zone`: a label and a dot come before `zone`, in any letter case.
fn in_zone(host: &[u8], zone: &[u8]) -> bool {
    #[cfg(feature = "negative-control-zone-without-dot")]
    if let Some(inside) = negative_control_zone_without_dot(host, zone) {
        return inside;
    }
    let Some(start) = host.len().checked_sub(zone.len()) else {
        return false;
    };
    let (labels, tail) = host.split_at(start);
    labels.last() == Some(&b'.') && tail.eq_ignore_ascii_case(zone)
}

/// Accepts a token at the second it expires.
#[cfg(feature = "negative-control-token-expiry")]
fn negative_control_token_expiry(expires_at: i64, now: i64) -> Option<bool> {
    Some(expires_at < now)
}

/// Adds the clock skew with wrapping, so a clock near the largest time refuses every token.
#[cfg(feature = "negative-control-token-skew-wrap")]
fn negative_control_token_skew_wrap(now: i64) -> Option<i64> {
    Some(now.wrapping_add(CLOCK_SKEW_SECONDS))
}

/// Reads a leading `+` as part of the number, as `u64::from_str` does.
#[cfg(feature = "negative-control-signed-attempt")]
fn negative_control_signed_attempt(text: &[u8]) -> Option<Option<u64>> {
    text.strip_prefix(b"+").map(positive_decimal)
}

/// Accepts any host that ends with the zone, even when no dot separates the two.
#[cfg(feature = "negative-control-zone-without-dot")]
fn negative_control_zone_without_dot(host: &[u8], zone: &[u8]) -> Option<bool> {
    let start = host.len().checked_sub(zone.len())?;
    Some(start > 0 && host[start..].eq_ignore_ascii_case(zone))
}

#[cfg(kani)]
mod proofs {
    use super::{
        OidcUrlKind, OriginRefusal, TokenTimes, WindowRefusal, is_run_id, oidc_origin, run_attempt,
        token_window,
    };

    /// A token is valid exactly while it hasn't expired and neither its issue time nor the start of its validity lies more than thirty seconds after now, and a refusal names the first check that fails.
    ///
    /// Every time a token can state and every time the verifier can read, compared in 128-bit arithmetic that can't overflow.
    #[kani::proof]
    fn a_token_is_valid_exactly_while_its_window_holds_now() {
        let times: TokenTimes = kani::any();
        let now: i64 = kani::any();
        let latest = i128::from(now) + 30;
        let expected = if i128::from(times.expires_at) <= i128::from(now) {
            Err(WindowRefusal::Expired)
        } else if i128::from(times.issued_at) > latest {
            Err(WindowRefusal::IssuedInFuture)
        } else if times
            .not_before
            .is_some_and(|not_before| i128::from(not_before) > latest)
        {
            Err(WindowRefusal::NotYetValid)
        } else {
            Ok(())
        };
        let decided = token_window(times, now);
        kani::assert(
            decided == expected,
            "a token must be valid exactly while its window holds now",
        );
        kani::cover!(decided == Ok(()) && times.issued_at > now && now > i64::MAX - 30);
        kani::cover!(decided == Err(WindowRefusal::NotYetValid));
    }

    /// A run attempt is exactly a positive decimal number in ASCII digits that fits in 64 bits, and a run ID is exactly one or more ASCII digits.
    ///
    /// Every text of at most three bytes, and the 20-digit texts on both sides of 2^64.
    #[kani::proof]
    #[kani::unwind(22)]
    fn run_numbers_are_exactly_decimal_digits() {
        let bytes: [u8; 3] = kani::any();
        let length: usize = kani::any_where(|length| *length <= bytes.len());
        let text = &bytes[..length];
        let digits = length > 0 && text.iter().all(u8::is_ascii_digit);
        let mut value: u64 = 0;
        if digits {
            for &byte in text {
                value = value * 10 + u64::from(byte - b'0');
            }
        }
        let expected = (digits && value > 0).then_some(value);
        kani::assert(
            run_attempt(text) == expected
                && is_run_id(text) == digits
                && run_attempt(b"18446744073709551615") == Some(u64::MAX)
                && run_attempt(b"18446744073709551616").is_none(),
            "a run number must be decimal digits",
        );
        kani::cover!(length == 3 && expected.is_some());
        kani::cover!(digits && expected.is_none());
    }

    /// Whether `host` spells `name` in any letter case.
    fn spells(host: &[u8], name: &[u8]) -> bool {
        if host.len() != name.len() {
            return false;
        }
        let mut same = true;
        let mut index = 0;
        while index < name.len() {
            same &= host[index].to_ascii_lowercase() == name[index];
            index += 1;
        }
        same
    }

    /// Whether `host` ends with a dot and a spelling of `zone`.
    fn under(host: &[u8], zone: &[u8]) -> bool {
        host.len() > zone.len()
            && host[host.len() - zone.len() - 1] == b'.'
            && spells(&host[host.len() - zone.len()..], zone)
    }

    /// A URL serves as a GitHub OIDC URL exactly when it uses HTTPS and names GitHub's host for its kind, or when a test allows a loopback address over plain HTTP.
    ///
    /// The issuer's URLs name `token.actions.githubusercontent.com`, and a runner's token URL names `actions.githubusercontent.com` or a host inside it, in any letter case.
    /// Every kind and loopback setting, the schemes `https`, `http`, `HTTPS`, and `ftp`, and every host of 0, 28 to 31, or 34 to 36 bytes.
    /// Those lengths reach each boundary: the decision reads only the last 30 bytes of a longer host, and no shorter host matches.
    #[kani::proof]
    #[kani::unwind(37)]
    fn an_oidc_url_trusts_no_host_but_githubs_own() {
        let kind: OidcUrlKind = kani::any();
        let schemes: [&[u8]; 4] = [b"https", b"http", b"HTTPS", b"ftp"];
        let scheme = schemes[kani::any_where(|index: &usize| *index < schemes.len())];
        let loopback: bool = kani::any();
        let allow_http_loopback: bool = kani::any();
        let decided = |host: &[u8]| oidc_origin(kind, scheme, host, loopback, allow_http_loopback);
        let agrees = |host: &[u8]| {
            let githubs = match kind {
                OidcUrlKind::Discovery | OidcUrlKind::Jwks => {
                    spells(host, b"token.actions.githubusercontent.com")
                }
                OidcUrlKind::RunnerToken => {
                    spells(host, b"actions.githubusercontent.com")
                        || under(host, b"actions.githubusercontent.com")
                }
            };
            let expected = if allow_http_loopback && loopback && scheme == b"http" {
                Ok(())
            } else if scheme != b"https" {
                Err(OriginRefusal::NotHttps)
            } else if !githubs {
                Err(OriginRefusal::UntrustedHost)
            } else {
                Ok(())
            };
            decided(host) == expected
        };
        let empty: [u8; 0] = [];
        let short: [u8; 28] = kani::any();
        let zone: [u8; 29] = kani::any();
        let dotted: [u8; 30] = kani::any();
        let inside: [u8; 31] = kani::any();
        let near: [u8; 34] = kani::any();
        let issuer: [u8; 35] = kani::any();
        let long: [u8; 36] = kani::any();
        kani::assert(
            agrees(&empty)
                && agrees(&short)
                && agrees(&zone)
                && agrees(&dotted)
                && agrees(&inside)
                && agrees(&near)
                && agrees(&issuer)
                && agrees(&long),
            "an OIDC URL must name GitHub's own host for its kind",
        );
        kani::cover!(decided(&inside) == Ok(()) && kind == OidcUrlKind::RunnerToken && !loopback);
        kani::cover!(decided(&issuer) == Ok(()) && kind == OidcUrlKind::Jwks);
    }
}
