// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The logic's own tests: the digest against its published vectors, the Twilio judgement, and the
//! settings refusals. The door itself is driven through the real loader by the plugin crate's
//! conformance test.

use super::sha1::{hmac_sha1, sha1};
use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const TOKEN: &[u8] = b"twilio-auth-token";
const URL: &str = "wss://node.example/twilio/stream";
const URL_SIGNATURE: &str = "iFnGrIvJGD8PELA0CVNYXLpX35Q=";

#[test]
fn sha1_matches_fips_180_vectors_across_the_padding_boundaries() {
    assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(
        hex(&sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex(&sha1(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    // 55, 56 and 64 bytes straddle where the length no longer fits the last block.
    assert_eq!(
        hex(&sha1(&[b'a'; 55])),
        "c1c8bbdc22796e28c0e15163d20899b65621d65a"
    );
    assert_eq!(
        hex(&sha1(&[b'a'; 56])),
        "c2db330f6083854c99d4b5bfb6e8f29f201be699"
    );
    assert_eq!(
        hex(&sha1(&[b'a'; 64])),
        "0098ba824b5c16427bd7a1122a5a442a25ec644d"
    );
    assert_eq!(
        hex(&sha1(&[b'a'; 1000])),
        "291e9a6c66994949b57ba5e650361e98fc36b1ba"
    );
}

#[test]
fn hmac_sha1_matches_rfc_2202() {
    assert_eq!(
        hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    assert_eq!(
        hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
    // A key longer than the block is hashed first.
    assert_eq!(
        hex(&hmac_sha1(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "aa4ae5e15272d00e95705637ce8a3b55ed402112"
    );
}

#[test]
fn the_signature_is_the_base64_hmac_of_the_url() {
    assert_eq!(twilio_signature(TOKEN, URL), URL_SIGNATURE);
}

#[test]
fn a_matching_signature_identifies_twilio() {
    let v = authenticate_twilio(TOKEN, URL, Some(URL_SIGNATURE.as_bytes()));
    let Verdict::Identity(id) = v else {
        panic!("a matching signature must identify, got {v:?}");
    };
    assert_eq!(id.subject, TWILIO_SUBJECT);
    assert_eq!(id.provider.as_deref(), Some(MODULE_NAME));
}

#[test]
fn a_missing_signature_abstains() {
    assert_eq!(authenticate_twilio(TOKEN, URL, None), Verdict::Pass);
}

#[test]
fn every_other_signature_is_rejected() {
    for presented in [
        &b"nF7kkLMbw+DImmWmIYWZPW8sGfY="[..], // another URL's
        b"",
        b"iFnGrIvJGD8PELA0CVNYXLpX35Q", // truncated
        b"\xff\xfe",                    // not text
    ] {
        assert_eq!(
            authenticate_twilio(TOKEN, URL, Some(presented)),
            Verdict::Reject
        );
    }
    // The right signature under the wrong token.
    assert_eq!(
        authenticate_twilio(b"rotated", URL, Some(URL_SIGNATURE.as_bytes())),
        Verdict::Reject
    );
}

#[test]
fn open_refuses_what_is_not_its_settings() {
    let token: &[u8] = b"t";
    for settings in [
        &b"not json"[..],
        b"[]",
        b"\"s\"",
        br#"{"scheme":7}"#,
        br#"{"host":[]}"#,
    ] {
        assert_eq!(
            WebhookSignature::open(settings, &[token]).unwrap_err(),
            BAD_SETTINGS
        );
    }
    for secrets in [&[][..], &[&b""[..]]] {
        assert_eq!(
            WebhookSignature::open(b"{}", secrets).unwrap_err(),
            NO_TOKEN
        );
    }
    assert!(WebhookSignature::open(br#"{"scheme":"https","host":"h.example"}"#, &[token]).is_ok());
    let shown = format!("{:?}", WebhookSignature::open(b"{}", &[b"sekrit"]).unwrap());
    assert!(
        !shown.contains("sekrit"),
        "the token must never print: {shown}"
    );
}
