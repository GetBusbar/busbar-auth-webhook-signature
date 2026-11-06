//! Test-only signers for the in-crate tests: an independent `ring` Twilio signer and the expected
//! tags under the retained keys, and the plain (owned, decoded) reference forms of the Twilio signed
//! string and form decoding the production path is checked against. The service itself only verifies.

use super::*;
use ring::hmac;

fn twilio_key(secret: &[u8]) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret)
}

/// The `twilio` signature of `url` and `params` under `secret`, base64 as Twilio presents it.
#[must_use]
pub(crate) fn twilio_sign(secret: &[u8], url: &[u8], params: &[(Vec<u8>, Vec<u8>)]) -> String {
    let tag = hmac::sign(&twilio_key(secret), &twilio_signed_string(url, params));
    STANDARD.encode(tag.as_ref())
}

/// The expected tag under the retained opaque key. The metadata vector only borrows the URL and
/// sorted/deduplicated parameters; the signed body and the secret are never assembled or copied.
pub(crate) fn twilio_expected(
    key: &Cred,
    url: &[u8],
    params: &[(Vec<u8>, Vec<u8>)],
) -> Zeroizing<[u8; 20]> {
    hmac_sha1(key, &twilio_parts(url, params))
}

/// The `v1,<base64>` signature of one message, for the in-crate tests.
pub(crate) fn standard_webhooks_sign(
    key: &[u8],
    id: &[u8],
    timestamp: &[u8],
    body: &[u8],
) -> String {
    format!(
        "v1,{}",
        STANDARD.encode(&standard_webhooks_expected(key, id, timestamp, body)[..])
    )
}

/// The reference construction the production path must agree with.
///
/// The string a `twilio` signature is computed over: `url`, then each parameter's name and value,
/// as Twilio's reference validators build it — the DISTINCT names sorted, and under each name its
/// DISTINCT values sorted (a repeated identical `name=value` pair is signed once).
#[must_use]
pub(crate) fn twilio_signed_string(url: &[u8], params: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = url.to_vec();
    for (name, value) in twilio_pairs(params) {
        out.extend_from_slice(name);
        out.extend_from_slice(value);
    }
    out
}

/// Whether `presented` (the header value, base64) is the `twilio` signature of `url` and `params`
/// under `secret`. A value that is not base64 is simply not the signature.
#[must_use]
pub(crate) fn twilio_verify(
    secret: &[u8],
    url: &[u8],
    params: &[(Vec<u8>, Vec<u8>)],
    presented: &[u8],
) -> bool {
    let secret = Cred::captured(Zeroizing::new(secret.to_vec()));
    twilio_verify_cred(&secret, url, params, presented)
}

/// [`twilio_verify`] under an already-captured credential, with no alternate URL.
pub(crate) fn twilio_verify_cred(
    key: &Cred,
    url: &[u8],
    params: &[(Vec<u8>, Vec<u8>)],
    presented: &[u8],
) -> bool {
    twilio_verify_either_cred(key, url, None, params, presented)
}

/// An `application/x-www-form-urlencoded` body as Twilio signs it: each `name=value` pair
/// percent-decoded (`+` is a space). `None` = not a form body (a malformed escape).
#[must_use]
pub(crate) fn form_params(body: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    body.split(|b| *b == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = form_pair(pair);
            Some((form_decode(name)?, form_decode(value)?))
        })
        .collect()
}

fn form_decode(s: &[u8]) -> Option<Vec<u8>> {
    form_bytes(s).collect()
}
