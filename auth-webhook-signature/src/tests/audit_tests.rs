// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regressions for the settings decode refusals and the Twilio form POST over the alternate
//! (default-port toggled) URL.

use super::*;

const TOKEN: &[u8] = b"twilio-auth-token";

/// A settings document that is a JSON array is not the object the schema describes: serde's derived
/// struct would otherwise decode it positionally.
#[test]
fn red_settings_as_a_json_array_are_refused_as_not_an_object() {
    for settings in [
        &br#"["twilio","wss://edge.example.com"]"#[..],
        br#" ["standard-webhooks"]"#,
    ] {
        let shown = String::from_utf8_lossy(settings);
        assert_eq!(
            Settings::parse(settings),
            Err("settings: must be a JSON object"),
            "{shown}"
        );
        assert!(
            <WebhookSignature as VerifyPlugin>::validate(settings).is_err(),
            "{shown}"
        );
        assert!(
            WebhookSignature::new(settings, &[TOKEN]).is_err(),
            "{shown}"
        );
    }
    assert_eq!(
        Settings::parse(b"[not json"),
        Err("settings: not well-formed JSON")
    );
}

/// A number too large for any JSON number representation is well-formed JSON; the refusal says the
/// number is out of range rather than calling the document malformed.
#[test]
fn red_a_number_out_of_range_is_not_called_malformed_json() {
    assert_eq!(
        Settings::parse(br#"{"variant":"standard-webhooks","tolerance_secs":1e400}"#),
        Err("settings: a number is out of range")
    );
}

/// A signed Twilio form POST whose sender signed the URL with the scheme's default port verifies
/// against an origin configured without it, as a GET does (and the reverse).
#[test]
fn a_form_post_signed_over_the_default_port_toggled_url_verifies() {
    let params = vec![
        (b"CallSid".to_vec(), b"CA1".to_vec()),
        (b"From".to_vec(), b"+1 234".to_vec()),
    ];
    let body: &[u8] = b"From=%2B1+234&CallSid=CA1";
    for (configured, signed) in [
        ("https://edge.example.com", "https://edge.example.com:443"),
        ("https://edge.example.com:443", "https://edge.example.com"),
    ] {
        let settings = format!(r#"{{"variant":"twilio","origin":"{configured}"}}"#);
        let plugin = WebhookSignature::new(settings.as_bytes(), &[TOKEN]).expect("opens");
        let sig = signature::signing::twilio_sign(
            TOKEN,
            format!("{signed}/hook?a=1").as_bytes(),
            &params,
        );
        let lookup = |name: &str| {
            name.eq_ignore_ascii_case(TWILIO_SIGNATURE_HEADER)
                .then_some(sig.as_bytes())
        };
        let verdict = plugin.judge(&Request {
            method: b"POST",
            path: b"/hook",
            query: Some(b"a=1"),
            body: Some(body),
            now: 0,
            headers: &lookup,
        });
        assert!(
            matches!(verdict, Verdict::Identity(_)),
            "{configured} vs {signed}: {verdict:?}"
        );
    }
}
