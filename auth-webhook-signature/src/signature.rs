// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SIGNATURES THEMSELVES, as pure functions: what each variant signs, and the constant-time
//! check of a presented signature against it. No ABI, no settings, no I/O. `standard-webhooks` is
//! the contract SDK's wiped HMAC-SHA256, its tag compared with `busbar_contract::constant_time_eq`;
//! `twilio` uses the SDK's wiped HMAC-SHA1 with an opaque credential, fed the signed string in
//! parts, and compares the tag with `busbar_contract::constant_time_eq`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use busbar_contract::abi::sdk::cred::Cred;
use busbar_contract::abi::sdk::hmac::{hmac_sha1, sha256};
use zeroize::Zeroizing;

/// `origin` (`scheme://authority`) with its scheme's default port added when it has none, or
/// removed when it is that default: the other form of the URL Twilio's reference validators accept.
/// The defaults are `https`/`wss` 443 and `http`/`ws` 80. `None` = no default port for the scheme.
#[must_use]
pub(crate) fn origin_with_default_port_toggled(origin: &str) -> Option<String> {
    let (scheme, authority) = origin.split_once("://")?;
    let default = match scheme.to_ascii_lowercase().as_str() {
        "https" | "wss" => "443",
        "http" | "ws" => "80",
        _ => return None,
    };

    let host_at = authority.rfind('@').map_or(0, |at| at + 1);
    let host = &authority[host_at..];
    match host.rfind(':') {
        Some(colon)
            if !host[colon + 1..].is_empty()
                && host[colon + 1..].bytes().all(|b| b.is_ascii_digit()) =>
        {
            (&host[colon + 1..] == default)
                .then(|| format!("{scheme}://{}{}", &authority[..host_at], &host[..colon]))
        }
        _ => Some(format!("{origin}:{default}")),
    }
}

/// The parameters in the order a `twilio` signature signs them, as Twilio's reference validators
/// build it: the DISTINCT names sorted, and under each name its DISTINCT values sorted (a repeated
/// identical `name=value` pair is signed once).
fn twilio_pairs(params: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
    let mut pairs: Vec<(&[u8], &[u8])> = params
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    pairs.sort_unstable();
    pairs.dedup();
    pairs
}

fn twilio_parts<'a>(url: &'a [u8], params: &'a [(Vec<u8>, Vec<u8>)]) -> Vec<&'a [u8]> {
    let pairs = twilio_pairs(params);
    let mut parts = Vec::with_capacity(1 + pairs.len() * 2);
    parts.push(url);
    for (name, value) in pairs {
        parts.push(name);
        parts.push(value);
    }
    parts
}

/// Judge both accepted URL spellings with one decode and one parameter ordering. Both MACs are
/// compared when an alternate exists, regardless of which one matches.
pub(crate) fn twilio_verify_either_cred(
    key: &Cred,
    url: &[u8],
    alternate: Option<&[u8]>,
    params: &[(Vec<u8>, Vec<u8>)],
    presented: &[u8],
) -> bool {
    let Some(tag) = twilio_tag(presented) else {
        return false;
    };
    twilio_tag_matches(key, &tag, twilio_parts(url, params), alternate)
}

/// The presented `twilio` tag, base64-decoded; `None` = not base64 (so not the signature).
fn twilio_tag(presented: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    STANDARD
        .decode(presented.trim_ascii())
        .ok()
        .map(Zeroizing::new)
}

/// Whether `tag` is the HMAC-SHA1 of `parts` under `key`, or of `parts` with its first part (the
/// URL) replaced by `alternate`. Both MACs are compared when an alternate exists.
fn twilio_tag_matches<'a>(
    key: &Cred,
    tag: &[u8],
    mut parts: Vec<&'a [u8]>,
    alternate: Option<&'a [u8]>,
) -> bool {
    let expected = hmac_sha1(key, &parts);
    let mut matched = busbar_contract::constant_time_eq(&expected[..], tag);
    if let Some(alternate) = alternate {
        parts[0] = alternate;
        let expected = hmac_sha1(key, &parts);
        matched |= busbar_contract::constant_time_eq(&expected[..], tag);
    }
    matched
}

/// The most non-empty `name=value` pairs a `twilio` form body may carry: far above the few dozen
/// parameters a Twilio voice, messaging or status callback carries. A body with more is refused
/// before its pairs are indexed, so a hostile body of many tiny pairs costs about one copy of
/// itself to judge, never a per-pair index of it.
pub const MAX_FORM_PAIRS: usize = 1024;

/// Why a `twilio` form body was refused before its signature could be judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormRefusal {
    /// Not a form body: a malformed escape (`%` not followed by two hex digits).
    Malformed,
    /// More than [`MAX_FORM_PAIRS`] non-empty pairs.
    TooManyPairs,
}

/// [`twilio_verify_either_cred`] over a form `body`'s parameters, with the pair order of
/// [`twilio_pairs`] over the percent-decoded (`+` is a space) pairs, but without owned buffers per pair: the body's
/// pairs are counted first, and one over [`MAX_FORM_PAIRS`] is refused before anything is
/// allocated; under the cap the judgment costs one borrowed slice per pair and one decoded copy of
/// the parameters. `Err` = refused before the signature is judged (a malformed escape: `%` not
/// followed by two hex digits, or too many pairs).
pub(crate) fn twilio_form_verify_either_cred(
    key: &Cred,
    url: &[u8],
    alternate: Option<&[u8]>,
    body: &[u8],
    presented: &[u8],
) -> Result<bool, FormRefusal> {
    let non_empty = |pair: &&[u8]| !pair.is_empty();
    let count = body
        .split(|b| *b == b'&')
        .filter(non_empty)
        .take(MAX_FORM_PAIRS + 1)
        .count();
    if count > MAX_FORM_PAIRS {
        return Err(FormRefusal::TooManyPairs);
    }
    let mut pairs: Vec<&[u8]> = Vec::with_capacity(count);
    for pair in body.split(|b| *b == b'&').filter(non_empty) {
        let (name, value) = form_pair(pair);
        if !form_bytes(name)
            .chain(form_bytes(value))
            .all(|b| b.is_some())
        {
            return Err(FormRefusal::Malformed);
        }
        pairs.push(pair);
    }
    let Some(tag) = twilio_tag(presented) else {
        return Ok(false);
    };
    pairs.sort_unstable_by(|a, b| form_pair_cmp(a, b));
    pairs.dedup_by(|a, b| form_pair_cmp(a, b).is_eq());
    let mut signed = Vec::with_capacity(body.len());
    for pair in pairs {
        let (name, value) = form_pair(pair);
        signed.extend(form_bytes(name).flatten());
        signed.extend(form_bytes(value).flatten());
    }
    Ok(twilio_tag_matches(
        key,
        &tag,
        vec![url, &signed[..]],
        alternate,
    ))
}

/// One form pair's raw name and value: split at the first `=`; no `=` = an empty value.
fn form_pair(pair: &[u8]) -> (&[u8], &[u8]) {
    match pair.iter().position(|b| *b == b'=') {
        Some(at) => (&pair[..at], &pair[at + 1..]),
        None => (pair, &b""[..]),
    }
}

/// Two raw form pairs in the order [`twilio_pairs`] sorts their decoded forms: by name, then value.
/// Read lazily, so a comparison costs the pairs' common decoded prefix, as comparing the decoded
/// pairs does, not a scan of each whole name for its `=`.
fn form_pair_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    form_pair_key(a).cmp(form_pair_key(b))
}

/// One raw (already validated) form pair as the sequence its decoded `(name, value)` sorts by:
/// each decoded name byte as `1 + byte`, then `0` for the end of the name (whether or not the pair
/// has an `=`), then each decoded value byte as `1 + byte`. Two keys compare as the two decoded
/// `(name, value)` tuples do.
fn form_pair_key(pair: &[u8]) -> impl Iterator<Item = u16> + '_ {
    let mut i = 0;
    let mut in_name = true;
    std::iter::from_fn(move || {
        if in_name && pair.get(i).is_none_or(|b| *b == b'=') {
            in_name = false;
            i += 1;
            return Some(0);
        }
        let b = *pair.get(i)?;
        i += 1;
        let byte = match b {
            b'+' => b' ',
            b'%' => {
                let byte = hex_byte(pair.get(i..i + 2)?)?;
                i += 2;
                byte
            }
            b => b,
        };
        Some(1 + u16::from(byte))
    })
}

/// The byte a `%XY` escape's two hex digits name; `None` = not two hex digits.
fn hex_byte(hex: &[u8]) -> Option<u8> {
    let hi = char::from(hex[0]).to_digit(16)?;
    let lo = char::from(hex[1]).to_digit(16)?;
    u8::try_from(hi * 16 + lo).ok()
}

/// One form component decoded a byte at a time (`+` is a space, `%XY` one byte); a `None` item is
/// a malformed escape, and nothing follows it.
fn form_bytes(s: &[u8]) -> impl Iterator<Item = Option<u8>> + '_ {
    let mut i = 0;
    std::iter::from_fn(move || {
        let b = *s.get(i)?;
        i += 1;
        if b != b'%' {
            return Some(Some(if b == b'+' { b' ' } else { b }));
        }
        let escape = s.get(i..i + 2).and_then(hex_byte);
        i = if escape.is_some() { i + 2 } else { s.len() };
        Some(escape)
    })
}

/// The value of query parameter `name` in `query` (raw, not decoded); `None` = absent.
#[must_use]
pub fn query_param<'q>(query: &'q [u8], name: &[u8]) -> Option<&'q [u8]> {
    query.split(|b| *b == b'&').find_map(|pair| {
        let at = pair.iter().position(|b| *b == b'=')?;
        (&pair[..at] == name).then_some(&pair[at + 1..])
    })
}

/// Whether `expected_hex` (from `bodySHA256`) is the SHA-256 of `body`, hex (either case). Not a
/// secret comparison: the digest of the body is public, and what authenticates it is the signature
/// over the URL that carries it.
#[must_use]
pub fn body_sha256_matches(body: &[u8], expected_hex: &[u8]) -> bool {
    let digest = sha256(&[body]);
    let hex = |n: u8| b"0123456789abcdef"[usize::from(n)];
    expected_hex.len() == 64
        && digest
            .iter()
            .flat_map(|b| [hex(b >> 4), hex(b & 0xf)])
            .zip(expected_hex)
            .all(|(want, got)| want == got.to_ascii_lowercase())
}

/// The signing key of a Standard Webhooks secret: base64, with an optional `whsec_` prefix; surrounding
/// ASCII whitespace is trimmed first, then the prefix stripped.
/// `None` = not base64, or empty. The key is decoded into a buffer sized once and wiped on drop
/// (auth material is zeroised).
#[must_use]
pub(crate) fn standard_webhooks_key(secret: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let secret = secret.trim_ascii();
    let b64 = secret.strip_prefix(b"whsec_").unwrap_or(secret);
    let mut key = Zeroizing::new(Vec::with_capacity(b64.len() / 4 * 3 + 3));
    STANDARD
        .decode_vec(b64, &mut key)
        .ok()
        .map(|()| key)
        .filter(|k| !k.is_empty())
}

fn standard_webhooks_signed(id: &[u8], timestamp: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(id.len() + timestamp.len() + body.len() + 2);
    out.extend_from_slice(id);
    out.push(b'.');
    out.extend_from_slice(timestamp);
    out.push(b'.');
    out.extend_from_slice(body);
    out
}

/// The expected HMAC-SHA256 tag of one message under `key` (the decoded secret), in a buffer that is
/// wiped on drop: the contract SDK's wiped HMAC, not `ring::hmac::Key`, whose key schedule is freed
/// unwiped.
pub(crate) fn standard_webhooks_expected(
    key: &[u8],
    id: &[u8],
    timestamp: &[u8],
    body: &[u8],
) -> Zeroizing<[u8; 32]> {
    let signed = Zeroizing::new(standard_webhooks_signed(id, timestamp, body));
    busbar_contract::abi::sdk::hmac::hmac_sha256(key, &signed)
}

/// Why a Standard Webhooks message did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardWebhooksRefusal {
    /// `webhook-timestamp` is not a decimal count of seconds.
    BadTimestamp,
    /// The timestamp is further than the tolerance from now (either direction).
    Stale,
    /// No `v1` entry of `webhook-signature` matches.
    BadSignature,
}

/// Verify one Standard Webhooks message: `signatures` is the `webhook-signature` header (a
/// space-separated list of `version,base64` entries; only `v1` is judged), `now` the wall clock in
/// seconds, `tolerance_secs` the allowed skew either way.
///
/// `Ok` carries the timestamp, in seconds.
///
/// # Errors
/// The timestamp is malformed or outside the tolerance, or no `v1` entry matches.
pub fn standard_webhooks_verify(
    key: &[u8],
    id: &[u8],
    timestamp: &[u8],
    body: &[u8],
    signatures: &[u8],
    now: u64,
    tolerance_secs: u64,
) -> Result<u64, StandardWebhooksRefusal> {
    let ts: u64 = std::str::from_utf8(timestamp.trim_ascii())
        .ok()
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse().ok())
        .ok_or(StandardWebhooksRefusal::BadTimestamp)?;
    if now.abs_diff(ts) > tolerance_secs {
        return Err(StandardWebhooksRefusal::Stale);
    }

    let expected = standard_webhooks_expected(key, id, timestamp.trim_ascii(), body);
    let matched = signatures
        .trim_ascii()
        .split(|b| *b == b' ')
        .filter_map(|entry| entry.strip_prefix(b"v1,"))
        .filter_map(|b64| STANDARD.decode(b64).ok().map(Zeroizing::new))
        .any(|tag| busbar_contract::constant_time_eq(&tag[..], &expected[..]));
    if matched {
        Ok(ts)
    } else {
        Err(StandardWebhooksRefusal::BadSignature)
    }
}

#[cfg(test)]
#[path = "tests/signature_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/signing.rs"]
pub(crate) mod signing;
