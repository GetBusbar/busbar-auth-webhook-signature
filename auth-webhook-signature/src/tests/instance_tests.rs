//! Configured instances judging requests: a Twilio Media Streams upgrade, a Twilio signed POST, and
//! a Standard Webhooks delivery — the verdicts and the REDs.

use super::*;

/// A request over a plain header list.
fn judge(
    plugin: &WebhookSignature,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: Option<&[u8]>,
    now: u64,
    headers: &[(&str, &[u8])],
) -> Verdict {
    let lookup = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };
    plugin.judge(&Request {
        method: method.as_bytes(),
        path: path.as_bytes(),
        query: query.map(str::as_bytes),
        body,
        now,
        headers: &lookup,
    })
}

/// A reject naming its reason word, as the host receives it.
fn rejected(why: &'static str) -> Verdict {
    Verdict::reject(why)
}

fn identity(subject: &str) -> Verdict {
    Verdict::Identity(VerifiedIdentity {
        subject: subject.into(),
        provider: Some("webhook-signature".into()),
        ..VerifiedIdentity::default()
    })
}

const TOKEN: &[u8] = b"twilio-auth-token";
const TWILIO: &[u8] = br#"{"variant":"twilio","origin":"wss://edge.example.com"}"#;
const PATH: &str = "/twilio/inbound";
const QUERY: &str = "tenant=acme";

fn twilio() -> WebhookSignature {
    WebhookSignature::new(TWILIO, &[TOKEN]).expect("settings are this plugin's")
}

/// What Twilio presents for the upgrade to `wss://edge.example.com/twilio/inbound?tenant=acme`.
fn upgrade_signature() -> String {
    signature::signing::twilio_sign(
        TOKEN,
        b"wss://edge.example.com/twilio/inbound?tenant=acme",
        &[],
    )
}

fn upgrade(path: &str, query: Option<&str>, sig: Option<&[u8]>) -> Verdict {
    let headers: Vec<(&str, &[u8])> = sig.map(|s| ("X-Twilio-Signature", s)).into_iter().collect();
    judge(&twilio(), "GET", path, query, None, 0, &headers)
}

#[test]
fn a_valid_twilio_signature_over_the_requested_url_identifies_the_sender() {
    let sig = upgrade_signature();
    assert_eq!(
        upgrade(PATH, Some(QUERY), Some(sig.as_bytes())),
        identity("webhook-signature:twilio")
    );
    let bare =
        signature::signing::twilio_sign(TOKEN, b"wss://edge.example.com/twilio/inbound", &[]);
    assert_eq!(
        upgrade(PATH, None, Some(bare.as_bytes())),
        identity("webhook-signature:twilio")
    );
}

#[test]
fn red_a_bad_twilio_signature_is_rejected() {
    let other_token = signature::signing::twilio_sign(
        b"not-the-token",
        b"wss://edge.example.com/twilio/inbound?tenant=acme",
        &[],
    );
    for bad in [
        other_token.as_bytes(),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        b"%%%",
        b"",
    ] {
        assert_eq!(
            upgrade(PATH, Some(QUERY), Some(bad)),
            rejected("twilio-mismatch"),
            "{bad:?}"
        );
    }
}

#[test]
fn red_a_missing_twilio_signature_header_never_identifies() {
    assert_eq!(upgrade(PATH, Some(QUERY), None), Verdict::Pass);
}

#[test]
fn red_a_twilio_signature_replayed_on_another_url_is_rejected() {
    let sig = upgrade_signature();
    for (path, query) in [
        ("/twilio/other", Some(QUERY)),
        (PATH, Some("tenant=evil")),
        (PATH, None),
    ] {
        assert_eq!(
            upgrade(path, query, Some(sig.as_bytes())),
            rejected("twilio-mismatch"),
            "{path} {query:?}"
        );
    }
    let elsewhere = WebhookSignature::new(
        br#"{"variant":"twilio","origin":"wss://other.example.com"}"#,
        &[TOKEN],
    )
    .expect("settings");
    let headers: &[(&str, &[u8])] = &[("x-twilio-signature", sig.as_bytes())];
    assert_eq!(
        judge(&elsewhere, "GET", PATH, Some(QUERY), None, 0, headers),
        rejected("twilio-mismatch")
    );
}

/// Twilio's published example, arriving as the signed form POST it describes.
#[test]
fn twilios_published_vector_verifies_as_a_signed_form_post() {
    let plugin = WebhookSignature::new(
        br#"{"variant":"twilio","origin":"https://mycompany.com"}"#,
        &[b"12345"],
    )
    .expect("settings");
    let body: &[u8] = b"CallSid=CA1234567890ABCDE&Caller=%2B12349013030&Digits=1234&From=%2B12349013030&To=%2B18005551212";
    let headers: &[(&str, &[u8])] = &[("X-Twilio-Signature", b"0/KCTR6DLpKmkAf8muzZqo1nDgQ=")];
    let post = |body: Option<&[u8]>, query: &str| {
        judge(&plugin, "POST", "/myapp.php", Some(query), body, 0, headers)
    };
    assert_eq!(
        post(Some(body), "foo=1&bar=2"),
        identity("webhook-signature:twilio")
    );

    let tampered: &[u8] = b"CallSid=CA1234567890ABCDE&Caller=%2B12349013030&Digits=9999&From=%2B12349013030&To=%2B18005551212";
    assert_eq!(
        post(Some(tampered), "foo=1&bar=2"),
        rejected("twilio-mismatch")
    );
    assert_eq!(post(Some(body), "foo=1&bar=3"), rejected("twilio-mismatch"));
    assert_eq!(post(None, "foo=1&bar=2"), rejected("no-body"));
}

#[test]
fn a_twilio_json_post_is_bound_by_its_body_sha256() {
    let body: &[u8] = br#"{"property": "value", "boolean": true}"#;
    let query = "bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620";
    let url = format!("wss://edge.example.com/twilio/status?{query}");
    let sig = signature::signing::twilio_sign(TOKEN, url.as_bytes(), &[]);
    let headers: &[(&str, &[u8])] = &[("x-twilio-signature", sig.as_bytes())];
    let post = |body: &[u8]| {
        judge(
            &twilio(),
            "POST",
            "/twilio/status",
            Some(query),
            Some(body),
            0,
            headers,
        )
    };
    assert_eq!(post(body), identity("webhook-signature:twilio"));

    assert_eq!(
        post(br#"{"property": "other"}"#),
        rejected("body-digest-mismatch")
    );
}

/// The bodySHA256 branch binds the body by its digest AND checks the signature over the URL: a
/// correct digest under a signature from another token, or a garbage one, is refused.
#[test]
fn red_a_twilio_json_post_with_a_bad_signature_is_rejected_though_its_digest_matches() {
    let body: &[u8] = br#"{"property": "value", "boolean": true}"#;
    let query = "bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620";
    let url = format!("wss://edge.example.com/twilio/status?{query}");
    let other_token = signature::signing::twilio_sign(b"not-the-token", url.as_bytes(), &[]);
    for bad in [other_token.as_bytes(), b"AAAAAAAAAAAAAAAAAAAAAAAAAAA="] {
        let headers: &[(&str, &[u8])] = &[("x-twilio-signature", bad)];
        assert_eq!(
            judge(
                &twilio(),
                "POST",
                "/twilio/status",
                Some(query),
                Some(body),
                0,
                headers
            ),
            rejected("twilio-mismatch"),
            "{bad:?}"
        );
    }
}

const SW: &[u8] = br#"{"variant":"standard-webhooks"}"#;
const SW_SECRET: &[u8] = b"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const SW_ID: &[u8] = b"msg_p5jXN8AQM9LWM0D4loKWxJek";
const SW_TS: &[u8] = b"1614265330";
const SW_NOW: u64 = 1_614_265_330;
const SW_BODY: &[u8] = br#"{"test": 2432232314}"#;
const SW_SIG: &[u8] = b"v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

fn standard() -> WebhookSignature {
    WebhookSignature::new(SW, &[SW_SECRET]).expect("settings are this plugin's")
}

fn delivery(headers: &[(&str, &[u8])], body: Option<&[u8]>, now: u64) -> Verdict {
    judge(
        &standard(),
        "POST",
        "/v1/webhooks/inbound",
        None,
        body,
        now,
        headers,
    )
}

const ALL: &[(&str, &[u8])] = &[
    ("webhook-id", SW_ID),
    ("webhook-timestamp", SW_TS),
    ("webhook-signature", SW_SIG),
];

#[test]
fn the_standard_webhooks_published_vector_identifies_the_sender() {
    let Verdict::Identity(id) = delivery(ALL, Some(SW_BODY), SW_NOW) else {
        panic!("the published vector verifies");
    };
    assert_eq!(id.subject, "webhook-signature:standard-webhooks");
    assert_eq!(id.provider.as_deref(), Some("webhook-signature"));
}

/// The replay key the kernel claims: the message id, for the rest of the window in which its
/// timestamp is acceptable. A later delivery of the same message gets a shorter claim, and one at
/// the window's edge a one-second claim; after the window the message is stale anyway.
#[test]
fn a_verified_delivery_asks_the_kernel_to_admit_its_webhook_id_once_for_the_window() {
    let replay = |now: u64| match delivery(ALL, Some(SW_BODY), now) {
        Verdict::Identity(id) => id.replay.map(|r| (r.key, r.ttl_secs)),
        other => panic!("{other:?}"),
    };
    let key = "standard-webhooks/msg_p5jXN8AQM9LWM0D4loKWxJek".to_string();
    assert_eq!(replay(SW_NOW), Some((key.clone(), 301)));
    assert_eq!(replay(SW_NOW - 300), Some((key.clone(), 601)));
    assert_eq!(replay(SW_NOW + 300), Some((key, 1)));
}

/// Two distinct non-UTF-8 `webhook-id`s are two distinct messages: each gets its own replay key,
/// so the second genuine message is not refused as a replay of the first.
#[test]
fn distinct_non_utf8_webhook_ids_get_distinct_replay_keys() {
    let key_bytes = signature::standard_webhooks_key(SW_SECRET).unwrap();
    let replay_key = |id: &[u8]| {
        let sig = signature::signing::standard_webhooks_sign(&key_bytes, id, SW_TS, SW_BODY);
        let headers: &[(&str, &[u8])] = &[
            ("webhook-id", id),
            ("webhook-timestamp", SW_TS),
            ("webhook-signature", sig.as_bytes()),
        ];
        match delivery(headers, Some(SW_BODY), SW_NOW) {
            Verdict::Identity(i) => i.replay.expect("a replay claim").key,
            other => panic!("{other:?}"),
        }
    };
    let ff = replay_key(b"evt-\xff");
    let fe = replay_key(b"evt-\xfe");
    assert_ne!(ff, fe);
    assert_eq!(ff, "standard-webhooks-raw/6576742dff");
}

/// A tolerance near `u64::MAX` at `now == 0` saturates the replay window instead of overflowing it.
#[test]
fn a_huge_tolerance_saturates_the_replay_ttl() {
    let wide = WebhookSignature::new(
        br#"{"variant":"standard-webhooks","tolerance_secs":18446744073709551615}"#,
        &[SW_SECRET],
    )
    .expect("settings");
    let Verdict::Identity(id) = judge(&wide, "POST", "/x", None, Some(SW_BODY), 0, ALL) else {
        panic!("the published vector verifies");
    };
    assert_eq!(id.replay.map(|r| r.ttl_secs), Some(u64::MAX));
}

/// Under a configured tolerance the replay claim lasts to the end of THAT window, not the default one.
#[test]
fn the_replay_ttl_follows_the_configured_tolerance() {
    let wide = WebhookSignature::new(
        br#"{"variant":"standard-webhooks","tolerance_secs":600}"#,
        &[SW_SECRET],
    )
    .expect("settings");
    let Verdict::Identity(id) = judge(&wide, "POST", "/x", None, Some(SW_BODY), SW_NOW + 301, ALL)
    else {
        panic!("inside the widened window");
    };
    assert_eq!(
        id.replay.map(|r| (r.key, r.ttl_secs)),
        Some((
            "standard-webhooks/msg_p5jXN8AQM9LWM0D4loKWxJek".to_string(),
            300
        ))
    );
}

/// A Twilio signature has no nonce or timestamp to key a replay claim on: none is asked.
#[test]
fn a_verified_twilio_request_asks_no_replay_claim() {
    let sig = upgrade_signature();
    assert!(matches!(
        upgrade(PATH, Some(QUERY), Some(sig.as_bytes())),
        Verdict::Identity(VerifiedIdentity { replay: None, .. })
    ));
}

#[test]
fn red_a_bad_standard_webhooks_signature_is_rejected() {
    let wrong: &[(&str, &[u8])] = &[
        ("webhook-id", SW_ID),
        ("webhook-timestamp", SW_TS),
        (
            "webhook-signature",
            b"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
        ),
    ];
    assert_eq!(
        delivery(wrong, Some(SW_BODY), SW_NOW),
        rejected("bad-signature")
    );
    assert_eq!(
        delivery(ALL, Some(br#"{"test": 1}"#), SW_NOW),
        rejected("bad-signature"),
        "another body"
    );
    assert_eq!(
        delivery(ALL, None, SW_NOW),
        rejected("no-body"),
        "no body lent"
    );
}

#[test]
fn red_a_stale_standard_webhooks_timestamp_is_rejected() {
    assert_eq!(
        delivery(ALL, Some(SW_BODY), SW_NOW + 301),
        rejected("stale")
    );
    assert_eq!(
        delivery(ALL, Some(SW_BODY), SW_NOW - 301),
        rejected("stale")
    );

    let wide = WebhookSignature::new(
        br#"{"variant":"standard-webhooks","tolerance_secs":600}"#,
        &[SW_SECRET],
    )
    .expect("settings");
    assert!(matches!(
        judge(&wide, "POST", "/x", None, Some(SW_BODY), SW_NOW + 301, ALL),
        Verdict::Identity(_)
    ));
}

#[test]
fn red_a_missing_standard_webhooks_header_never_identifies() {
    assert_eq!(delivery(&[], Some(SW_BODY), SW_NOW), Verdict::Pass);

    for skip in 0..ALL.len() {
        let partial: Vec<(&str, &[u8])> = ALL
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip)
            .map(|(_, h)| *h)
            .collect();
        assert_eq!(
            delivery(&partial, Some(SW_BODY), SW_NOW),
            rejected("partial-headers"),
            "{skip}"
        );
    }
}

/// Only the one declared `signing_secret` slot may be supplied by the host.
#[test]
fn the_signing_secret_requires_one_resolved_slot() {
    assert_eq!(SECRET_REFS.len(), 1);
    assert_eq!(SECRET_REF, "signing_secret");
    assert!(WebhookSignature::new(TWILIO, &[TOKEN]).is_ok());
    for secrets in [&[TOKEN, &b""[..]][..], &[&b""[..], TOKEN][..]] {
        assert_eq!(
            WebhookSignature::new(TWILIO, secrets).unwrap_err(),
            "secrets: expected exactly one `signing_secret`"
        );
    }
}

#[test]
fn the_settings_and_the_secret_are_checked_at_open() {
    assert!(WebhookSignature::new(TWILIO, &[]).is_err(), "no secret");
    assert!(
        WebhookSignature::new(TWILIO, &[b""]).is_err(),
        "empty secret"
    );
    assert!(
        WebhookSignature::new(TWILIO, &[TOKEN, TOKEN]).is_err(),
        "two secrets"
    );
    assert!(
        WebhookSignature::new(TWILIO, &[b"", b"", TOKEN]).is_err(),
        "three secrets"
    );
    assert!(
        WebhookSignature::new(TWILIO, &[TOKEN, b"", b""]).is_err(),
        "three secrets, first set"
    );
    assert!(
        WebhookSignature::new(SW, &[b"whsec_%%%"]).is_err(),
        "not base64"
    );
    for bad in [
        &br#"{"variant":"stripe"}"#[..],
        br#"{"variant":"twilio"}"#,
        br#"{"variant":"twilio","origin":"edge.example.com"}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com/"}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com?x=1"}"#,
        br#"{"variant":"twilio","origin":"wss://"}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com","tolerance_secs":1}"#,
        br#"{"variant":"standard-webhooks","origin":"https://x"}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com","subject":""}"#,
        br#"{"variant":"twilio","origin":"wss://edge.example.com","extra":1}"#,
        b"not json",
    ] {
        assert!(
            WebhookSignature::new(bad, &[TOKEN]).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    let named = WebhookSignature::new(
        br#"{"variant":"twilio","origin":"wss://edge.example.com:8443","subject":"acme-phone"}"#,
        &[TOKEN],
    )
    .expect("a port and a subject are fine");
    let sig =
        signature::signing::twilio_sign(TOKEN, b"wss://edge.example.com:8443/twilio/inbound", &[]);
    let headers: &[(&str, &[u8])] = &[("x-twilio-signature", sig.as_bytes())];
    assert_eq!(
        judge(&named, "GET", PATH, None, None, 0, headers),
        identity("acme-phone")
    );
}

#[test]
fn the_signing_secret_is_never_formatted() {
    let shown = format!("{:?} {:?}", twilio(), standard());
    assert!(!shown.contains("twilio-auth-token"), "{shown}");
    assert!(!shown.contains("MfKQ9r8G"), "{shown}");

    let list = |b: &[u8]| {
        let s = format!("{b:?}");
        s[1..s.len() - 1].to_string()
    };
    assert!(!shown.contains(&list(TOKEN)), "{shown}");
    assert!(
        !shown.contains(&list(&signature::standard_webhooks_key(SW_SECRET).unwrap())),
        "{shown}"
    );
}

/// The retained Twilio key is opaque, and the decoded Standard Webhooks key keeps its wiping
/// holder. The existing request vectors drive both variants through these retained keys.
#[test]
fn the_signing_key_is_held_opaque_or_wiped_on_drop() {
    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let twilio = WebhookSignature::new(TWILIO, &[TOKEN]).expect("opens");
    let current = twilio.current();
    match &current.key {
        SigningKey::Twilio(key) => {
            let _: &Cred = key;
            assert_eq!(key.len(), TOKEN.len());
        }
        SigningKey::StandardWebhooks(_) => panic!("a Twilio token must stay opaque"),
    }
    let sw = WebhookSignature::new(SW, &[SW_SECRET]).expect("opens");
    let current = sw.current();
    match &current.key {
        SigningKey::StandardWebhooks(key) => {
            let _: &zeroize::Zeroizing<Vec<u8>> = key;
            wipes(key);
            assert_eq!(
                key,
                &signature::standard_webhooks_key(SW_SECRET).expect("decodes")
            );
        }
        SigningKey::Twilio(_) => panic!("a Standard Webhooks secret must be decoded"),
    }
}

/// The declared carriers (the open answer's EXT_CARRIERS) are the instance's own variant's lines
/// only, the same lines `verify` strips: a `twilio` instance never names a Standard Webhooks line.
#[test]
fn red_each_instance_declares_only_its_own_variants_carriers() {
    assert_eq!(
        VerifyPlugin::carriers(&twilio()),
        Some(vec!["x-twilio-signature".to_string()])
    );
    assert_eq!(
        VerifyPlugin::carriers(&standard()),
        Some(vec![
            "webhook-id".to_string(),
            "webhook-timestamp".to_string(),
            "webhook-signature".to_string(),
        ])
    );
}

#[test]
fn the_compiled_in_entry_is_the_door_the_dropped_in_image_exports() {
    assert!(std::ptr::eq(
        compiled_in::door::door as *const (),
        door as *const ()
    ));
}

/// Judge `delivery` under a log capture; the rendered records.
fn logged(headers: &[(&str, &[u8])], body: Option<&[u8]>, now: u64) -> (Verdict, String) {
    let cap = RefusalLog::default();
    let verdict =
        tracing::subscriber::with_default(cap.subscriber(), || delivery(headers, body, now));
    (verdict, cap.messages().join("\n"))
}

/// Every reject reason, as the one log shape says it (`reason` = a short word), and never a
/// credential: not the signature presented, the signing secret, the body or the message id. The
/// verdict names the same word ([`Verdict::RejectBecause`]), so the host's log says why too.
#[test]
fn red_every_reject_is_logged_with_its_short_reason_and_no_credential() {
    let bad_ts: &[(&str, &[u8])] = &[
        ("webhook-id", SW_ID),
        ("webhook-timestamp", b"soon"),
        ("webhook-signature", SW_SIG),
    ];
    let wrong_sig: &[u8] = b"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=";
    let wrong: &[(&str, &[u8])] = &[
        ("webhook-id", SW_ID),
        ("webhook-timestamp", SW_TS),
        ("webhook-signature", wrong_sig),
    ];
    let tw_sig = upgrade_signature();
    let tw_bad: &[(&str, &[u8])] = &[("x-twilio-signature", b"AAAA")];
    let tw_good: &[(&str, &[u8])] = &[("x-twilio-signature", tw_sig.as_bytes())];
    let tw = |method, query, body: Option<&[u8]>, headers: &[(&str, &[u8])]| {
        let cap = RefusalLog::default();
        let verdict = tracing::subscriber::with_default(cap.subscriber(), || {
            judge(&twilio(), method, PATH, query, body, 0, headers)
        });
        (verdict, cap.messages().join("\n"))
    };
    let digest_bad =
        Some("bodySHA256=0000000000000000000000000000000000000000000000000000000000000000");
    let too_many = "a&".repeat(signature::MAX_FORM_PAIRS + 1);
    let cases: Vec<(&'static str, (Verdict, String))> = vec![
        ("stale", logged(ALL, Some(SW_BODY), SW_NOW + 301)),
        ("bad-timestamp", logged(bad_ts, Some(SW_BODY), SW_NOW)),
        ("bad-signature", logged(wrong, Some(SW_BODY), SW_NOW)),
        ("partial-headers", logged(&ALL[..2], Some(SW_BODY), SW_NOW)),
        ("no-body", logged(ALL, None, SW_NOW)),
        ("twilio-mismatch", tw("GET", Some(QUERY), None, tw_bad)),
        (
            "get-with-body",
            tw("GET", Some(QUERY), Some(b"smuggled"), tw_good),
        ),
        ("no-body", tw("POST", Some(QUERY), None, tw_good)),
        (
            "body-digest-mismatch",
            tw("POST", digest_bad, Some(b"{}"), tw_good),
        ),
        ("bad-form-body", tw("POST", None, Some(b"a=%zz"), tw_good)),
        (
            "too-many-form-pairs",
            tw("POST", None, Some(too_many.as_bytes()), tw_good),
        ),
    ];
    for (reason, (verdict, log)) in &cases {
        assert_eq!(*verdict, rejected(reason), "{reason}");
        assert!(log.contains(reason), "{reason}: {log:?}");
        assert!(
            log.contains("module=\"webhook-signature\""),
            "{reason}: {log:?}"
        );
        for secret in [
            "g0hM9SsE",
            "MfKQ9r8G",
            "2432232314",
            "msg_p5jX",
            "Ceo5qEr0",
            "twilio-auth-token",
            tw_sig.as_str(),
            "smuggled",
        ] {
            assert!(!log.contains(secret), "{reason}: {secret} leaked: {log:?}");
        }
    }
}

#[test]
fn red_a_twilio_post_with_no_body_is_logged_once() {
    let cap = RefusalLog::default();
    let sig = upgrade_signature();
    let verdict = tracing::subscriber::with_default(cap.subscriber(), || {
        judge(
            &twilio(),
            "POST",
            PATH,
            Some(QUERY),
            None,
            0,
            &[("x-twilio-signature", sig.as_bytes())],
        )
    });
    assert_eq!(verdict, rejected("no-body"));
    assert_eq!(cap.count("request rejected"), 1, "{:?}", cap.messages());
    assert!(cap.contains("no-body"), "{:?}", cap.messages());
}

#[test]
fn refusal_logs_attribute_the_variant_and_escape_the_configured_subject() {
    let settings = serde_json::json!({
        "variant": "twilio",
        "origin": "wss://edge.example.com",
        "subject": "receiver-one\nforged-line"
    })
    .to_string();
    let plugin = WebhookSignature::new(settings.as_bytes(), &[TOKEN]).unwrap();
    let cap = RefusalLog::default();
    let verdict = tracing::subscriber::with_default(cap.subscriber(), || {
        judge(
            &plugin,
            "GET",
            PATH,
            Some(QUERY),
            None,
            0,
            &[("x-twilio-signature", b"invalid-signature-canary")],
        )
    });
    assert_eq!(verdict, rejected("twilio-mismatch"));
    let log = cap.messages().join("\n");
    assert!(log.contains("variant=\"twilio\""), "{log}");
    assert!(log.contains("receiver-one\\nforged-line"), "{log}");
    assert!(!log.contains("receiver-one\nforged-line"), "{log}");
    assert!(!log.contains("invalid-signature-canary"), "{log}");
    assert!(!log.contains("twilio-auth-token"), "{log}");

    let cap = RefusalLog::default();
    tracing::subscriber::with_default(cap.subscriber(), || {
        assert!(VerifyPlugin::reload(&plugin, settings.as_bytes(), &[b""]).is_err());
    });
    let log = cap.messages().join("\n");
    assert!(log.contains("variant=\"twilio\""), "{log}");
    assert!(log.contains("receiver-one\\nforged-line"), "{log}");
    assert!(!log.contains("receiver-one\nforged-line"), "{log}");
    assert!(!log.contains("twilio-auth-token"), "{log}");
}

/// Settings, secrets, and the line `open` refuses them with.
type Refused<'a> = (&'a [u8], &'a [&'a [u8]], &'a str);

#[test]
fn red_settings_and_secret_refusals_name_what_is_wrong() {
    let cases: &[Refused] = &[
        (b"not json", &[TOKEN], "settings: not well-formed JSON"),
        (b"[]", &[TOKEN], "settings: must be a JSON object"),
        (b"{}", &[TOKEN], "settings.variant: required, `twilio` or `standard-webhooks`"),
        (
            br#"{"variant":"stripe"}"#,
            &[TOKEN],
            "settings.variant: must be `twilio` or `standard-webhooks`",
        ),
        (
            br#"{"variant":"twilio","origin":"wss://edge.example.com","extra":1}"#,
            &[TOKEN],
            "settings: an unknown key is set; the keys are `variant`, `origin`, `tolerance_secs` and `subject`",
        ),
        (
            br#"{"variant":"standard-webhooks","tolerance_secs":"300"}"#,
            &[SW_SECRET],
            "settings: a value has the wrong type",
        ),
        (
            br#"{"variant":"standard-webhooks","variant":"twilio"}"#,
            &[SW_SECRET],
            "settings: a key is set twice",
        ),
        (
            br#"{"variant":"standard-webhooks","tolerance_secs":-1}"#,
            &[SW_SECRET],
            "settings.tolerance_secs: out of range, a count of seconds from 0",
        ),
        (
            br#"{"variant":"twilio"}"#,
            &[TOKEN],
            "settings.origin: required for `twilio`",
        ),
        (
            br#"{"variant":"twilio","origin":"wss://edge.example.com/"}"#,
            &[TOKEN],
            "settings.origin: must be scheme://authority, with no path, query or fragment",
        ),
        (
            br#"{"variant":"twilio","origin":"wss://edge.example.com","tolerance_secs":1}"#,
            &[TOKEN],
            "settings.tolerance_secs: a `standard-webhooks` setting",
        ),
        (
            br#"{"variant":"standard-webhooks","origin":"https://x"}"#,
            &[SW_SECRET],
            "settings.origin: a `twilio` setting",
        ),
        (
            br#"{"variant":"twilio","origin":"wss://edge.example.com","subject":""}"#,
            &[TOKEN],
            "settings.subject: must not be empty",
        ),
        (TWILIO, &[b""], "secrets: `signing_secret` is not set"),
        (TWILIO, &[b"\xff\xfe"], "secrets: `signing_secret` is not UTF-8"),
        (
            SW,
            &[b"whsec_%%%"],
            "secrets: `signing_secret` is not a standard-webhooks secret (base64, optionally `whsec_`-prefixed)",
        ),
    ];
    for (settings, secrets, want) in cases {
        let Err(got) = WebhookSignature::new(settings, secrets) else {
            panic!("{} opens", String::from_utf8_lossy(settings));
        };
        assert_eq!(got, *want, "{}", String::from_utf8_lossy(settings));
    }
}

#[test]
fn red_a_refused_refresh_is_logged_at_warn_and_the_held_pair_keeps_judging() {
    let p = twilio();
    for (settings, secrets, why) in [
        (
            &br#"{"variant":"stripe"}"#[..],
            &[TOKEN][..],
            "settings.variant: must be `twilio` or `standard-webhooks`",
        ),
        (
            TWILIO,
            &[&b""[..]][..],
            "secrets: `signing_secret` is not set",
        ),
    ] {
        let cap = RefusalLog::default();
        let reloaded = tracing::subscriber::with_default(cap.subscriber(), || {
            VerifyPlugin::reload(&p, settings, secrets)
        });
        assert!(reloaded.is_err(), "invalid refresh must report failure");
        assert_eq!(cap.count("refresh refused"), 1, "{:?}", cap.messages());
        assert!(cap.contains(why), "{:?}", cap.messages());
        assert!(
            cap.contains("module=\"webhook-signature\""),
            "{:?}",
            cap.messages()
        );
        assert!(!cap.contains("twilio-auth-token"), "{:?}", cap.messages());
    }
    let sig = upgrade_signature();
    assert_eq!(
        judge(
            &p,
            "GET",
            PATH,
            Some(QUERY),
            None,
            0,
            &[("x-twilio-signature", sig.as_bytes())],
        ),
        identity("webhook-signature:twilio")
    );
}

#[test]
fn a_requests_debug_keeps_header_values_and_the_body_out() {
    let lookup = |_: &str| Some(&b"SECRET-HEADER-VALUE"[..]);
    let r = Request {
        method: b"POST",
        path: b"/hook",
        query: Some(b"q=1"),
        body: Some(b"SECRET-BODY"),
        now: 7,
        headers: &lookup,
    };
    let shown = format!("{r:?} {r:#?}");
    assert!(shown.contains("POST") && shown.contains("/hook"), "{shown}");
    assert!(!shown.contains("SECRET"), "{shown}");
}

#[test]
fn red_f1_a_twilio_get_or_head_with_a_body_is_rejected() {
    let sig = upgrade_signature();
    let headers: &[(&str, &[u8])] = &[("x-twilio-signature", sig.as_bytes())];
    for method in ["GET", "HEAD"] {
        assert_eq!(
            judge(
                &twilio(),
                method,
                PATH,
                Some(QUERY),
                Some(b"smuggled"),
                0,
                headers
            ),
            rejected("get-with-body"),
            "{method} with a body"
        );
        for body in [None, Some(&b""[..])] {
            assert_eq!(
                judge(&twilio(), method, PATH, Some(QUERY), body, 0, headers),
                identity("webhook-signature:twilio"),
                "{method} with {body:?}"
            );
        }
    }
}

#[test]
fn red_f2_the_secret_is_trimmed_first_for_both_variants() {
    let sig = upgrade_signature();
    let twilio_headers: &[(&str, &[u8])] = &[("x-twilio-signature", sig.as_bytes())];
    for padded in [&b"twilio-auth-token\n"[..], b" \ttwilio-auth-token\r\n"] {
        let p = WebhookSignature::new(TWILIO, &[padded]).expect("opens");
        assert_eq!(
            judge(&p, "GET", PATH, Some(QUERY), None, 0, twilio_headers),
            identity("webhook-signature:twilio"),
            "{padded:?}"
        );
    }
    for padded in [
        &b"  whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw\n"[..],
        b"\nMfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw \n",
        b"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw\n",
    ] {
        let p = WebhookSignature::new(SW, &[padded]).expect("opens");
        let Verdict::Identity(id) = judge(&p, "POST", "/", None, Some(SW_BODY), SW_NOW, ALL) else {
            panic!("{padded:?} does not verify");
        };
        assert_eq!(id.subject, "webhook-signature:standard-webhooks");
    }
    for blank in [&b" \n\t"[..], b"\r\n"] {
        assert_eq!(
            WebhookSignature::new(TWILIO, &[blank]).err(),
            Some("secrets: `signing_secret` is not set")
        );
        assert_eq!(
            WebhookSignature::new(SW, &[blank]).err(),
            Some("secrets: `signing_secret` is not set")
        );
    }
}

#[test]
fn red_f3_the_twilio_url_is_also_tried_with_the_default_port_added_or_removed() {
    let at = |origin: &str, signed: &str| {
        let settings = format!(r#"{{"variant":"twilio","origin":"{origin}"}}"#);
        let p = WebhookSignature::new(settings.as_bytes(), &[TOKEN]).expect("opens");
        let sig = signature::signing::twilio_sign(TOKEN, format!("{signed}{PATH}").as_bytes(), &[]);
        judge(
            &p,
            "GET",
            PATH,
            None,
            None,
            0,
            &[("x-twilio-signature", sig.as_bytes())],
        )
    };
    let ok = identity("webhook-signature:twilio");

    assert_eq!(at("https://h.example", "https://h.example"), ok);

    assert_eq!(at("https://h.example", "https://h.example:443"), ok);
    assert_eq!(at("https://h.example:443", "https://h.example"), ok);
    assert_eq!(at("http://h.example", "http://h.example:80"), ok);
    assert_eq!(at("http://h.example:80", "http://h.example"), ok);
    assert_eq!(at("wss://h.example", "wss://h.example:443"), ok);
    assert_eq!(at("https://u@h.example", "https://u@h.example:443"), ok);
    assert_eq!(at("https://[::1]", "https://[::1]:443"), ok);
    assert_eq!(at("https://[::1]:443", "https://[::1]"), ok);

    assert_eq!(
        at("https://h.example", "https://h.example:80"),
        rejected("twilio-mismatch")
    );
    assert_eq!(
        at("http://h.example", "http://h.example:443"),
        rejected("twilio-mismatch")
    );
    assert_eq!(
        at("https://h.example:8443", "https://h.example"),
        rejected("twilio-mismatch")
    );
    assert_eq!(
        at("https://h.example:8443", "https://h.example:443"),
        rejected("twilio-mismatch")
    );
    assert_eq!(
        at("https://h.example", "https://other.example"),
        rejected("twilio-mismatch")
    );
}

#[test]
fn twilio_origin_ports_are_validated_without_changing_signed_authorities() {
    for origin in [
        "https://host:",
        "wss://host:abc",
        "https://[::1]:",
        "wss://[::1]:abc",
    ] {
        let settings = serde_json::json!({"variant": "twilio", "origin": origin}).to_string();
        assert!(
            WebhookSignature::new(settings.as_bytes(), &[TOKEN]).is_err(),
            "{origin}"
        );
    }
    for origin in [
        "https://host",
        "https://host:443",
        "ws://host:80",
        "wss://host:443",
        "wss://host:8443",
        "https://[::1]",
        "wss://[2001:db8::1]:443",
    ] {
        let settings = serde_json::json!({"variant": "twilio", "origin": origin}).to_string();
        let plugin = WebhookSignature::new(settings.as_bytes(), &[TOKEN]).expect("valid authority");
        let url = format!("{origin}{PATH}");
        let signature = signature::signing::twilio_sign(TOKEN, url.as_bytes(), &[]);
        assert_eq!(
            judge(
                &plugin,
                "GET",
                PATH,
                None,
                None,
                0,
                &[("x-twilio-signature", signature.as_bytes())]
            ),
            identity("webhook-signature:twilio"),
            "{origin}"
        );
    }
}

#[test]
fn signed_requests_accept_surrounding_signature_and_timestamp_whitespace() {
    let twilio_signature = format!(" \t{}\t ", upgrade_signature());
    assert_eq!(
        upgrade(PATH, Some(QUERY), Some(twilio_signature.as_bytes())),
        identity("webhook-signature:twilio")
    );

    let standard_signature = format!(" \t{}\t ", std::str::from_utf8(SW_SIG).unwrap());
    let headers: &[(&str, &[u8])] = &[
        ("webhook-id", SW_ID),
        ("webhook-timestamp", b" \t1614265330\t "),
        ("webhook-signature", standard_signature.as_bytes()),
    ];
    let Verdict::Identity(id) = delivery(headers, Some(SW_BODY), SW_NOW) else {
        panic!("the published signature verifies with surrounding header whitespace");
    };
    assert_eq!(id.subject, "webhook-signature:standard-webhooks");
    assert_eq!(
        id.replay
            .expect("a verified delivery retains its replay claim")
            .ttl_secs,
        301
    );
    assert_eq!(
        delivery(headers, Some(b"tampered"), SW_NOW),
        rejected("bad-signature")
    );
    assert_eq!(
        delivery(headers, Some(SW_BODY), SW_NOW + 301),
        rejected("stale")
    );
}

#[test]
fn mixed_case_origin_schemes_keep_their_signed_default_port_alternate() {
    for (origin, alternate) in [
        ("HTTPS://host", "HTTPS://host:443"),
        ("HtTp://user@host:80", "HtTp://user@host"),
        ("WsS://[::1]", "WsS://[::1]:443"),
        ("wSs://[2001:db8::1]:443", "wSs://[2001:db8::1]"),
    ] {
        let settings = serde_json::json!({"variant":"twilio", "origin":origin}).to_string();
        let plugin = WebhookSignature::new(settings.as_bytes(), &[TOKEN]).expect("valid origin");
        let signed_url = format!("{alternate}{PATH}?{QUERY}");
        let signature = signature::signing::twilio_sign(TOKEN, signed_url.as_bytes(), &[]);
        assert_eq!(
            judge(
                &plugin,
                "GET",
                PATH,
                Some(QUERY),
                None,
                0,
                &[("x-twilio-signature", signature.as_bytes())]
            ),
            identity("webhook-signature:twilio"),
            "{origin} -> {alternate}"
        );
        assert_eq!(
            judge(
                &plugin,
                "GET",
                "/other-route",
                Some(QUERY),
                None,
                0,
                &[("x-twilio-signature", signature.as_bytes())]
            ),
            rejected("twilio-mismatch")
        );
    }
}

// This test-local writer records this plugin's refusal events, including their fields.
#[derive(Clone, Default)]
struct RefusalLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for RefusalLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl RefusalLog {
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .finish()
    }
    fn messages(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    fn contains(&self, text: &str) -> bool {
        self.messages().iter().any(|line| line.contains(text))
    }
    fn count(&self, text: &str) -> usize {
        self.messages()
            .iter()
            .filter(|line| line.contains(text))
            .count()
    }
}
