//! Test-only signers for the in-crate tests: an independent `ring` Twilio signer and the expected
//! tags under the retained keys. The service itself only verifies.

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
