// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed schema and the real lifecycle validator agree on representative settings.

#[path = "../../testing/settings/integer_token.rs"]
mod settings_profile;

use super::*;
use serde_json::{json, Value};

fn check(cases: &[(Value, bool)]) {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).expect("schema JSON");
    let validator = settings_profile::validator(&schema).expect("valid settings schema");
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    for (settings, accepted) in cases {
        let bytes = serde_json::to_vec(settings).expect("settings JSON");
        assert_eq!(
            validator.is_valid(settings),
            *accepted,
            "schema: {settings}"
        );
        assert_eq!(
            <WebhookSignature as VerifyPlugin>::validate(&bytes).is_ok(),
            *accepted,
            "lifecycle: {settings}"
        );
    }
}

#[test]
fn settings_schema_matches_webhook_lifecycle() {
    check(&[
        (json!({"variant":"standard-webhooks"}), true),
        (
            json!({"variant":"standard-webhooks","origin":null,"tolerance_secs":null,"subject":null}),
            true,
        ),
        (
            json!({"variant":"standard-webhooks","tolerance_secs":0,"subject":" "}),
            true,
        ),
        (
            json!({"variant":"standard-webhooks","tolerance_secs":-1}),
            false,
        ),
        (
            json!({"variant":"standard-webhooks","origin":"https://edge.example"}),
            false,
        ),
        (
            json!({"variant":"twilio","origin":"wss://edge.example"}),
            true,
        ),
        (
            json!({"variant":"twilio","origin":"https://[::1]:443","tolerance_secs":null}),
            true,
        ),
        (json!({"variant":"twilio","origin":"1://host:999999"}), true),
        (
            json!({"variant":"twilio","origin":"https://host","tolerance_secs":0}),
            false,
        ),
        (json!({"variant":"twilio"}), false),
        (json!({"variant":"twilio","origin":null}), false),
        (json!({"variant":"standard-webhooks","subject":""}), false),
        (
            json!({"variant":"standard-webhooks","signing_secret":"secret"}),
            false,
        ),
        (json!({"variant":"unknown"}), false),
        (json!({}), false),
        (json!([]), false),
    ]);
    for (origin, accepted) in [
        ("https://host/", false),
        ("https://host?query", false),
        ("https://host#fragment", false),
        ("https://host:", false),
        ("https://host:abc", false),
        ("https://[]", false),
        ("https://[::1]extra", false),
        ("https://host\n", false),
        ("https://host[a", true),
        ("https://userinfo@host", true),
    ] {
        check(&[(json!({"variant":"twilio","origin":origin}), accepted)]);
    }
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    assert_eq!(
        schema["allOf"][0]["else"]["properties"]["tolerance_secs"]["default"],
        DEFAULT_TOLERANCE_SECS
    );
    for (branch, variant) in [("then", "twilio"), ("else", "standard-webhooks")] {
        let settings = if variant == "twilio" {
            json!({"variant":variant,"origin":"https://edge.example"})
        } else {
            json!({"variant":variant})
        };
        let parsed = Settings::parse(&serde_json::to_vec(&settings).unwrap()).unwrap();
        assert_eq!(
            schema["allOf"][0][branch]["properties"]["subject"]["default"],
            parsed.subject()
        );
    }
}

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [(
        r#"/properties/tolerance_secs"#,
        r#"{"variant":"standard-webhooks","tolerance_secs":TOKEN}"#,
        "1",
        "unsigned",
    )] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                <WebhookSignature as VerifyPlugin>::validate(text.as_bytes()).is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                <WebhookSignature as VerifyPlugin>::validate(text.as_bytes()).is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}
