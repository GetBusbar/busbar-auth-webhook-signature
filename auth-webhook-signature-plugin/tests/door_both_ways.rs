// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PLUGIN TESTS ITSELF, BOTH WAYS**: this crate's `door` (the `DoorFn` a compiled-in row
//! holds) through [`load_linked`], and its dropped-in image (this crate's cdylib,
//! the one exported `busbar_plugin_door`) through [`load_dropped`] — the loader's ONE path, every
//! answer judged by the auth kind's own `check_identify`.

use busbar_contract::abi::mechanism::call::RawOutcome;
use std::ffi::c_void;
use std::mem::zeroed;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use busbar_auth_webhook_signature::signature::twilio_signed_string;
use busbar_contract::abi::auth::{
    slot, IdentifyOut, IdentityBuf, NamedValue, RequestFacts, StripName, VerifyIn,
    DECISION_CONTINUE, DECISION_STOP, POINT_HEAD_BODY, SPAN_ABSENT, STRIP_FIELD, VERDICT_IDENTITY,
    VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, RefreshIn, TickIn, TickOut, ValidateIn,
};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Diagnostic, DispatchConfig,
    Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
};

const TOKEN: &str = "twilio-auth-token";
const SETTINGS: &str = r#"{"variant":"twilio","origin":"wss://edge.example.com"}"#;
const PATH: &str = "/twilio/inbound";
const QUERY: &str = "tenant=acme";
const SIGNED_URL: &str = "wss://edge.example.com/twilio/inbound?tenant=acme";

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &str) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &[u8], fmt: u32, flags: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

#[derive(Default)]
struct Folds(Mutex<Vec<String>>);

impl EnvelopeSink for Folds {
    fn metric(&self, m: Metric<'_>) {
        let mut records = self.0.lock().unwrap();
        records.push(format!("metric {}", m.family));
        records.extend(
            m.labels
                .iter()
                .map(|label| String::from_utf8_lossy(label).into_owned()),
        );
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.0
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(d.name).into_owned());
        self.0
            .lock()
            .unwrap()
            .push(format!("diag {} {}", d.id, String::from_utf8_lossy(d.text)));
    }
    fn dropped(&self, why: Dropped) {
        panic!("privacy capture dropped an envelope: {why:?}");
    }
}

fn bind(folds: &Arc<Folds>, d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("conformance"),
        max_inflight_cap: 64,
        sink: folds.clone(),
        dispatcher: d.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    }
}

/// The compiled-in row `door` states: its Statement rendering and the door.
fn row(door: DoorFn) -> LinkedRow {
    LinkedRow::of(door).expect("the door states its Statement")
}

fn linked(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    load_linked::<Auth>(&row(busbar_auth_webhook_signature::door), bind(folds, d))
        .expect("the linked door loads")
}

/// The dropped-in image `cargo test` builds: this crate's cdylib (busbar's suite finds it beside
/// the test binary, uplifted or hashed under `deps/`). A missing artifact is a failure, never a
/// skip.
fn dropped(folds: &Arc<Folds>, d: &Dispatcher) -> Plugin<Auth> {
    let path = built_plugin_image();
    let stated =
        rendering_of(busbar_auth_webhook_signature::door).expect("the door renders its Statement");
    load_dropped::<Auth>(&path, &stated, bind(folds, d)).expect("the dropped door loads")
}

fn open(p: &Plugin<Auth>, settings: &str, secret: &str) -> Outcome {
    let secrets = [blob(secret.as_bytes(), BLOB_OCTETS, BLOB_SECRET)];
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    o.input.settings = blob(settings.as_bytes(), BLOB_JSON, 0);
    o.input.secrets = secrets.as_ptr();
    o.input.secrets_len = secrets.len();
    let answer = one_header_crossing(p, || private_answer(p.call(life::OPEN, &mut o)));
    answer.outcome
}

/// `refresh` to `generation` with `settings` and the re-resolved `secret`, as a reload carries them.
fn refresh(p: &Plugin<Auth>, settings: &str, secret: &str, generation: u64) -> Outcome {
    refresh_answer(p, settings, secret, generation).outcome
}
fn refresh_answer(
    p: &Plugin<Auth>,
    settings: &str,
    secret: &str,
    generation: u64,
) -> busbar_plugin_loader::dispatch::Called {
    let secrets = [blob(secret.as_bytes(), BLOB_OCTETS, BLOB_SECRET)];
    let mut f: Frame<RefreshIn, OutHead> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out = out_head();
    f.input.generation = generation;
    f.input.settings = blob(settings.as_bytes(), BLOB_JSON, 0);
    f.input.secrets = secrets.as_ptr();
    f.input.secrets_len = secrets.len();
    one_header_crossing(p, || private_answer(p.call(life::REFRESH, &mut f)))
}

/// One `verify` at `HeadBody`: `outcome verdict subject`, as the loader judged it. The host lends
/// `body` (none = no body lent, which a body-signed request is refused for).
#[allow(clippy::too_many_arguments)]
fn verify_req(
    p: &Plugin<Auth>,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: Option<&[u8]>,
    now: u64,
    headers: &[(&str, &str)],
) -> String {
    verify_answer(p, method, path, query, body, now, headers).0
}

/// [`verify_req`]'s line, and the decision and the strip names (lower-case) the answer carried.
#[allow(clippy::too_many_arguments)]
fn verify_answer(
    p: &Plugin<Auth>,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: Option<&[u8]>,
    now: u64,
    headers: &[(&str, &str)],
) -> (String, u32, Vec<String>) {
    let mut buf = vec![0u8; 256];
    let mut groups = vec![Span { offset: 0, len: 0 }; 4];
    let mut strips = vec![
        StripName {
            name: Span { offset: 0, len: 0 },
            place: 0,
            _reserved: 0,
        };
        8
    ];
    let lines: Vec<NamedValue> = headers
        .iter()
        .map(|(n, v)| NamedValue {
            name: s(n),
            value: blob(v.as_bytes(), BLOB_OCTETS, BLOB_SECRET),
        })
        .collect();
    let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.credential = z();
    f.input.lines = lines.as_ptr();
    f.input.lines_len = lines.len();
    f.input.point = POINT_HEAD_BODY;
    f.input.body = body.map_or(z(), |b| blob(b, BLOB_OCTETS, 0));
    f.input.strip = strips.as_mut_ptr();
    f.input.strip_cap = strips.len() as u32;
    f.input.request = RequestFacts {
        method: s(method),
        authority: s("edge.example.com"),
        canonical_path: s(path),
        query: query.map_or(
            AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            s,
        ),
        timestamp: now,
    };
    f.input.out_buf = IdentityBuf {
        buf: buf.as_mut_ptr(),
        buf_cap: buf.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let c = private_answer(p.call(slot::VERIFY, &mut f));
    assert_private_text(&buf);
    let verdict = match f.out.verdict {
        VERDICT_IDENTITY => "identity",
        VERDICT_REJECT => "reject",
        VERDICT_PASS => "pass",
        _ => "?",
    };
    let subject = f.out.identity.subject;
    let subject = if c.outcome == Outcome::Ready
        && f.out.verdict == VERDICT_IDENTITY
        && subject.offset != SPAN_ABSENT
    {
        String::from_utf8_lossy(
            &buf[subject.offset as usize..(subject.offset + subject.len) as usize],
        )
        .into_owned()
    } else {
        String::new()
    };
    let replay = f.out.identity.replay_key;
    let replay = if c.outcome == Outcome::Ready
        && f.out.verdict == VERDICT_IDENTITY
        && replay.offset != SPAN_ABSENT
    {
        format!(
            " replay={}/{}s",
            String::from_utf8_lossy(
                &buf[replay.offset as usize..(replay.offset + replay.len) as usize]
            ),
            f.out.identity.replay_ttl_secs
        )
    } else {
        String::new()
    };
    let named = if c.outcome == Outcome::Ready {
        strips[..f.out.strip_len as usize]
            .iter()
            .map(|n| {
                assert_eq!(n.place, STRIP_FIELD, "a signature header is a field line");
                String::from_utf8_lossy(
                    &buf[n.name.offset as usize..(n.name.offset + n.name.len) as usize],
                )
                .to_ascii_lowercase()
            })
            .collect()
    } else {
        Vec::new()
    };
    (
        format!("{:?} {verdict} {subject}{replay}", c.outcome)
            .trim_end()
            .to_string(),
        f.out.decision,
        named,
    )
}

/// A Twilio Media Streams upgrade (a GET) with `signature` in `X-Twilio-Signature`, or none.
fn verify(p: &Plugin<Auth>, path: &str, query: Option<&str>, signature: Option<&str>) -> String {
    let headers: Vec<(&str, &str)> = signature
        .map(|v| ("X-Twilio-Signature", v))
        .into_iter()
        .collect();
    verify_req(p, "GET", path, query, None, 0, &headers)
}

/// A Twilio signature of `url` and `params` under `secret`, as a sender computes it.
fn twilio_sign(secret: &[u8], url: &[u8], params: &[(Vec<u8>, Vec<u8>)]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = ring::hmac::sign(&key, &twilio_signed_string(url, params));
    base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
}

/// THE TWILIO SCRIPT, one line per call.
fn script(p: &Plugin<Auth>) -> Vec<String> {
    let valid = twilio_sign(TOKEN.as_bytes(), SIGNED_URL.as_bytes(), &[]);
    let wrong_key = twilio_sign(b"not-the-token", SIGNED_URL.as_bytes(), &[]);
    let form = b"CallSid=CA1&Digits=12";
    let params = vec![
        (b"CallSid".to_vec(), b"CA1".to_vec()),
        (b"Digits".to_vec(), b"12".to_vec()),
    ];
    let post_sig = twilio_sign(
        TOKEN.as_bytes(),
        b"wss://edge.example.com/twilio/status",
        &params,
    );
    let post = |body: Option<&[u8]>| {
        verify_req(
            p,
            "POST",
            "/twilio/status",
            None,
            body,
            0,
            &[("X-Twilio-Signature", &post_sig)],
        )
    };
    vec![
        format!("open {:?}", open(p, SETTINGS, TOKEN)),
        format!("valid {}", verify(p, PATH, Some(QUERY), Some(&valid))),
        format!(
            "bad-signature {}",
            verify(p, PATH, Some(QUERY), Some(&wrong_key))
        ),
        format!("garbage {}", verify(p, PATH, Some(QUERY), Some("%%%"))),
        format!("missing-header {}", verify(p, PATH, Some(QUERY), None)),
        format!(
            "replayed-path {}",
            verify(p, "/twilio/other", Some(QUERY), Some(&valid))
        ),
        format!(
            "replayed-query {}",
            verify(p, PATH, Some("tenant=evil"), Some(&valid))
        ),
        format!("replayed-no-query {}", verify(p, PATH, None, Some(&valid))),
        format!("signed-post {}", post(Some(form))),
        format!(
            "signed-post-tampered {}",
            post(Some(b"CallSid=CA1&Digits=99"))
        ),
        format!("signed-post-no-body {}", post(None)),
    ]
}

const EXPECTED: &[&str] = &[
    "open Ready",
    "valid Ready identity webhook-signature:twilio",
    "bad-signature Ready reject",
    "garbage Ready reject",
    "missing-header Ready pass",
    "replayed-path Ready reject",
    "replayed-query Ready reject",
    "replayed-no-query Ready reject",
    "signed-post Ready identity webhook-signature:twilio",
    "signed-post-tampered Ready reject",
    "signed-post-no-body Ready reject",
];

/// Exercises the Standard Webhooks published vector and invalid-signature cases.
fn standard_script(p: &Plugin<Auth>) -> Vec<String> {
    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const TS: &str = "1614265330";
    const NOW: u64 = 1_614_265_330;
    const BODY: &[u8] = br#"{"test": 2432232314}"#;
    const SIG: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
    let all = [
        ("webhook-id", ID),
        ("webhook-timestamp", TS),
        ("webhook-signature", SIG),
    ];
    let deliver = |headers: &[(&str, &str)], body: Option<&[u8]>, now: u64| {
        verify_req(p, "POST", "/v1/webhooks/inbound", None, body, now, headers)
    };
    vec![
        format!(
            "open {:?}",
            open(p, r#"{"variant":"standard-webhooks"}"#, SECRET)
        ),
        format!("valid {}", deliver(&all, Some(BODY), NOW)),
        format!(
            "bad-signature {}",
            deliver(
                &[
                    ("webhook-id", ID),
                    ("webhook-timestamp", TS),
                    (
                        "webhook-signature",
                        "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc="
                    ),
                ],
                Some(BODY),
                NOW
            )
        ),
        format!("stale {}", deliver(&all, Some(BODY), NOW + 301)),
        format!("missing-headers {}", deliver(&[], Some(BODY), NOW)),
        format!("missing-signature {}", deliver(&all[..2], Some(BODY), NOW)),
        format!("no-body-lent {}", deliver(&all, None, NOW)),
    ]
}

const STANDARD_EXPECTED: &[&str] = &[
    "open Ready",
    "valid Ready identity webhook-signature:standard-webhooks \
     replay=standard-webhooks/msg_p5jXN8AQM9LWM0D4loKWxJek/301s",
    "bad-signature Ready reject",
    "stale Ready reject",
    "missing-headers Ready pass",
    "missing-signature Ready reject",
    "no-body-lent Ready reject",
];

#[test]
fn compiled_in_and_dropped_in_verify_every_variant_identically() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let linked_t = script(&linked(&folds, &d));
    assert_eq!(linked_t, EXPECTED, "the linked door");
    let linked_s = standard_script(&linked(&folds, &d));
    assert_eq!(
        linked_s, STANDARD_EXPECTED,
        "the linked door, standard-webhooks"
    );
    let folds = Arc::new(Folds::default());
    let p = dropped(&folds, &d);
    {
        assert_eq!(script(&p), linked_t, "the dropped door");
        let p = dropped(&folds, &d);
        assert_eq!(
            standard_script(&p),
            linked_s,
            "the dropped door, standard-webhooks"
        );
        println!(
            "PROOF auth-webhook-signature: linked and dropped answered {} calls identically",
            linked_t.len() + linked_s.len()
        );
    }
}

#[test]
fn red_open_without_a_signing_secret_or_with_foreign_settings_fails() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    assert_eq!(open(&linked(&folds, &d), SETTINGS, ""), Outcome::Failed);
    assert_eq!(
        open(
            &linked(&folds, &d),
            r#"{"variant":"stripe","origin":"wss://x"}"#,
            TOKEN
        ),
        Outcome::Failed
    );
}

#[test]
fn every_verdict_names_the_signature_lines_and_a_decision() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let p = linked(&folds, &d);
    assert_eq!(open(&p, SETTINGS, TOKEN), Outcome::Ready);
    let valid = twilio_sign(TOKEN.as_bytes(), SIGNED_URL.as_bytes(), &[]);

    let names = ["x-twilio-signature"];
    for (sig, verdict, decision) in [
        (Some(valid.as_str()), "identity", DECISION_CONTINUE),
        (Some("%%%"), "reject", DECISION_STOP),
        (None, "pass", DECISION_CONTINUE),
    ] {
        let headers: Vec<(&str, &str)> =
            sig.map(|v| ("X-Twilio-Signature", v)).into_iter().collect();
        let (line, got, stripped) = verify_answer(&p, "GET", PATH, Some(QUERY), None, 0, &headers);
        assert!(line.starts_with(&format!("Ready {verdict}")), "{line}");
        assert_eq!(got, decision, "{line}");
        assert_eq!(stripped, names, "{line}");
    }
}

#[test]
fn a_standard_webhooks_instance_strips_only_its_own_lines() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    const BODY: &[u8] = br#"{"test": 2432232314}"#;
    const SIG: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
    const NOW: u64 = 1_614_265_330;
    for p in [linked(&folds, &d), dropped(&folds, &d)] {
        assert_eq!(
            open(
                &p,
                r#"{"variant":"standard-webhooks"}"#,
                "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
            ),
            Outcome::Ready
        );
        for (signature, now, verdict, decision) in [
            (Some(SIG), NOW, "identity", DECISION_CONTINUE),
            (Some("v1,%%%"), NOW, "reject", DECISION_STOP),
            (Some(SIG), NOW + 301, "reject", DECISION_STOP),
            (None, NOW, "pass", DECISION_CONTINUE),
        ] {
            let headers = signature
                .map(|signature| {
                    vec![
                        ("webhook-id", "msg_p5jXN8AQM9LWM0D4loKWxJek"),
                        ("webhook-timestamp", "1614265330"),
                        ("webhook-signature", signature),
                    ]
                })
                .unwrap_or_default();
            let (line, got, stripped) =
                verify_answer(&p, "POST", "/", None, Some(BODY), now, &headers);
            assert!(line.starts_with(&format!("Ready {verdict}")), "{line}");
            assert_eq!(got, decision, "{line}");
            assert_eq!(
                stripped,
                ["webhook-id", "webhook-timestamp", "webhook-signature"],
                "{line}"
            );
        }
    }
}

/// THE ROTATION SCRIPT (CREDENTIAL-LOCKDOWN P1.5): a `refresh` carrying a ROTATED signing secret is
/// picked up on the same instance, without a re-open: a signature under the new secret identifies
/// and one under the old secret is refused. A refresh with the unchanged secret (the admin cache
/// flush) changes nothing; a refresh whose secret or settings would not open keeps what the
/// instance holds and answers FAILED to the host.
fn rotation_script(p: &Plugin<Auth>) -> Vec<String> {
    const NEW: &str = "the-rotated-twilio-auth-token";
    let old_sig = twilio_sign(TOKEN.as_bytes(), SIGNED_URL.as_bytes(), &[]);
    let new_sig = twilio_sign(NEW.as_bytes(), SIGNED_URL.as_bytes(), &[]);
    let both = |label: &str| {
        [
            format!(
                "old {label}{}",
                verify(p, PATH, Some(QUERY), Some(&old_sig))
            ),
            format!(
                "new {label}{}",
                verify(p, PATH, Some(QUERY), Some(&new_sig))
            ),
        ]
    };
    let mut out = vec![format!("open {:?}", open(p, SETTINGS, TOKEN))];
    out.extend(both(""));
    out.push(format!("flush {:?}", refresh(p, SETTINGS, TOKEN, 2)));
    out.extend(both("after flush "));
    out.push(format!("rotate {:?}", refresh(p, SETTINGS, NEW, 3)));
    out.extend(both("after rotate "));
    out.push(format!("empty-secret {:?}", refresh(p, SETTINGS, "", 4)));
    out.extend(both("after empty-secret "));
    out.push(format!(
        "foreign-settings {:?}",
        refresh(p, r#"{"variant":"stripe"}"#, TOKEN, 5)
    ));
    out.extend(both("after foreign-settings "));
    out
}

const ROTATION_EXPECTED: &[&str] = &[
    "open Ready",
    "old Ready identity webhook-signature:twilio",
    "new Ready reject",
    "flush Ready",
    "old after flush Ready identity webhook-signature:twilio",
    "new after flush Ready reject",
    "rotate Ready",
    "old after rotate Ready reject",
    "new after rotate Ready identity webhook-signature:twilio",
    "empty-secret Failed",
    "old after empty-secret Ready reject",
    "new after empty-secret Ready identity webhook-signature:twilio",
    "foreign-settings Failed",
    "old after foreign-settings Ready reject",
    "new after foreign-settings Ready identity webhook-signature:twilio",
];

#[test]
fn refresh_picks_up_a_rotated_signing_secret_without_a_reopen() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    assert_eq!(
        rotation_script(&linked(&folds, &d)),
        ROTATION_EXPECTED,
        "the linked door"
    );
    let p = dropped(&folds, &d);
    assert_eq!(rotation_script(&p), ROTATION_EXPECTED, "the dropped door");
}

#[test]
fn an_invalid_signing_secret_refuses_refresh_and_keeps_the_previous_signature() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let signature = twilio_sign(TOKEN.as_bytes(), SIGNED_URL.as_bytes(), &[]);
    for p in [linked(&folds, &d), dropped(&folds, &d)] {
        assert_eq!(open(&p, SETTINGS, TOKEN), Outcome::Ready);
        assert_eq!(refresh(&p, SETTINGS, "", 2), Outcome::Failed);
        let answer = verify(&p, PATH, Some(QUERY), Some(&signature));
        assert_eq!(answer, "Ready identity webhook-signature:twilio");
        assert_eq!(refresh(&p, SETTINGS, TOKEN, 3), Outcome::Ready);
        assert_eq!(verify(&p, PATH, Some(QUERY), Some(&signature)), answer);
    }
}

/// The SDK owns a SHORT answer until the host recalls or abandons it. A reload and a later
/// timestamp cannot change the identity, replay window, or strips already judged for this call.
#[test]
fn a_short_standard_webhook_keeps_its_judgment_across_rotation_and_elapsed_time() {
    use busbar_auth_webhook_signature::{
        DEFAULT_TOLERANCE_SECS, WEBHOOK_ID_HEADER, WEBHOOK_SIGNATURE_HEADER,
        WEBHOOK_TIMESTAMP_HEADER,
    };

    const SETTINGS: &str = r#"{"variant":"standard-webhooks"}"#;
    const ROTATED_SETTINGS: &str =
        r#"{"variant":"standard-webhooks","subject":"rotated-webhook-subject"}"#;
    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const ROTATED_SECRET: &str = "whsec_cm90YXRlZC1zdGFuZGFyZC13ZWJob29rLWtleQ==";
    const ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const TIMESTAMP: &str = "1614265330";
    const NOW: u64 = 1_614_265_330;
    const BODY: &[u8] = br#"{"test": 2432232314}"#;
    const SIGNATURE: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
    const SUBJECT: &str = "webhook-signature:standard-webhooks";
    const REPLAY_KEY: &str = "standard-webhooks/msg_p5jXN8AQM9LWM0D4loKWxJek";
    const REFRESH_GENERATION: u64 = 2;
    const RESTORE_GENERATION: u64 = 3;

    let headers = [
        (WEBHOOK_ID_HEADER, ID),
        (WEBHOOK_TIMESTAMP_HEADER, TIMESTAMP),
        (WEBHOOK_SIGNATURE_HEADER, SIGNATURE),
    ];
    let lines: Vec<NamedValue> = headers
        .iter()
        .map(|(name, value)| NamedValue {
            name: s(name),
            value: blob(value.as_bytes(), BLOB_OCTETS, BLOB_SECRET),
        })
        .collect();
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    for p in [linked(&folds, &d), dropped(&folds, &d)] {
        assert_eq!(open(&p, SETTINGS, SECRET), Outcome::Ready);
        let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
        f.input.head = in_head();
        f.out.head = out_head();
        f.input.lines = lines.as_ptr();
        f.input.lines_len = lines.len();
        f.input.point = POINT_HEAD_BODY;
        f.input.body = blob(BODY, BLOB_OCTETS, 0);
        f.input.request = RequestFacts {
            method: s("POST"),
            authority: s("edge.example.com"),
            canonical_path: s(PATH),
            query: z(),
            timestamp: NOW,
        };
        let short = private_answer(p.call(slot::VERIFY, &mut f));
        assert_ne!(f.out.head.lease, 0, "the SHORT answer retains its judgment");
        assert_eq!(short.outcome, Outcome::Failed);
        let recall = short
            .recall
            .expect("the valid identity needs output buffers");
        assert_eq!(f.out.needed_groups, 0);
        assert_eq!(f.out.needed_strip as usize, headers.len());
        let mut bytes = vec![0; f.out.needed_bytes as usize];
        let mut strips = vec![z::<StripName>(); f.out.needed_strip as usize];
        f.input.out_buf = IdentityBuf {
            buf: bytes.as_mut_ptr(),
            buf_cap: bytes.len(),
            ..z()
        };
        f.input.strip = strips.as_mut_ptr();
        f.input.strip_cap = strips.len() as u32;
        f.input.request.timestamp = NOW + DEFAULT_TOLERANCE_SECS + 1;
        f.out = z();
        f.out.head = out_head();
        assert_eq!(
            refresh(&p, ROTATED_SETTINGS, ROTATED_SECRET, REFRESH_GENERATION),
            Outcome::Ready
        );
        let recalled = private_answer(p.recall(recall, slot::VERIFY, &mut f));
        assert_private_text(&bytes);
        assert_eq!(recalled.outcome, Outcome::Ready);
        assert!(recalled.recall.is_none());
        assert_eq!(f.out.verdict, VERDICT_IDENTITY);
        assert_eq!(f.out.decision, DECISION_CONTINUE);
        let text =
            |span: Span| &bytes[span.offset as usize..span.offset as usize + span.len as usize];
        assert_eq!(text(f.out.identity.subject), SUBJECT.as_bytes());
        assert_eq!(text(f.out.identity.replay_key), REPLAY_KEY.as_bytes());
        assert_eq!(f.out.identity.replay_ttl_secs, DEFAULT_TOLERANCE_SECS + 1);
        assert_eq!(f.out.strip_len as usize, headers.len());
        for (strip, (name, _)) in strips.iter().zip(headers) {
            assert_eq!(strip.place, STRIP_FIELD);
            assert_eq!(text(strip.name), name.as_bytes());
        }
        assert_eq!(
            verify_req(&p, "POST", PATH, None, Some(BODY), NOW, &headers),
            "Ready reject",
            "a new judgment uses the rotated key"
        );
        assert_eq!(
            refresh(&p, SETTINGS, SECRET, RESTORE_GENERATION),
            Outcome::Ready
        );
        assert_eq!(
            verify_req(&p, "POST", PATH, None, Some(BODY), NOW, &headers),
            format!(
                "Ready identity {SUBJECT} replay={REPLAY_KEY}/{}s",
                DEFAULT_TOLERANCE_SECS + 1
            ),
            "restoring the original key still verifies at the original time"
        );
        assert_eq!(
            verify_req(
                &p,
                "POST",
                PATH,
                None,
                Some(BODY),
                f.input.request.timestamp,
                &headers,
            ),
            "Ready reject",
            "a new judgment sees the expired timestamp even under the original key"
        );
    }
}

fn built_plugin_image() -> std::path::PathBuf {
    let image = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let test_binary = std::env::current_exe().expect("test binary path");
            test_binary
                .parent()
                .and_then(std::path::Path::parent)
                .expect("target profile directory")
                .join(format!(
                    "{}busbar_auth_webhook_signature_plugin{}",
                    std::env::consts::DLL_PREFIX,
                    std::env::consts::DLL_SUFFIX
                ))
        });
    assert!(
        image.is_absolute(),
        "the actual dropped-in plugin image must have an absolute path: {}",
        image.display()
    );
    assert!(
        image.is_file(),
        "build the actual dropped-in plugin before running this test: {}",
        image.display()
    );
    image
}

#[test]
fn validate_refuses_malformed_settings_before_secrets_are_resolved() {
    let cases: &[(&[u8], &str)] = &[
        (b"{", "settings: not well-formed JSON"),
        (b"[]", "settings: must be a JSON object"),
        (b"{}", "settings.variant: required, `twilio` or `standard-webhooks`"),
        (
            br#"{"variant":"webhook-validation-private-canary"}"#,
            "settings.variant: must be `twilio` or `standard-webhooks`",
        ),
        (br#"{"variant":"twilio"}"#, "settings.origin: required for `twilio`"),
        (
            br#"{"variant":"twilio","origin":"wss://edge.example/private-path"}"#,
            "settings.origin: must be scheme://authority, with no path, query or fragment",
        ),
        (
            br#"{"variant":"twilio","origin":"wss://edge.example","tolerance_secs":10}"#,
            "settings.tolerance_secs: a `standard-webhooks` setting",
        ),
        (
            br#"{"variant":"standard-webhooks","origin":"https://edge.example"}"#,
            "settings.origin: a `twilio` setting",
        ),
        (
            br#"{"variant":"standard-webhooks","subject":""}"#,
            "settings.subject: must not be empty",
        ),
        (
            br#"{"variant":"standard-webhooks","tolerance_secs":-1}"#,
            "settings.tolerance_secs: out of range, a count of seconds from 0",
        ),
        (
            br#"{"variant":"standard-webhooks","webhook-validation-private-canary":"misplaced-signing-secret"}"#,
            "settings: an unknown key is set; the keys are `variant`, `origin`, `tolerance_secs` and `subject`",
        ),
    ];
    for leg in [false, true] {
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        let folds = Arc::new(Folds::default());
        let plugin = if leg {
            dropped(&folds, &dispatcher)
        } else {
            linked(&folds, &dispatcher)
        };
        for &(settings, expected) in cases {
            let validated = validate_settings(&plugin, settings);
            assert_eq!(validated.outcome, Outcome::Failed, "{leg:?}: {validated:?}");
            let text = String::from_utf8(validated.error.expect("a settings refusal says why"))
                .expect("the refusal is text");
            assert_eq!(text, expected, "{leg:?}");
            assert!(!text.contains("webhook-validation-private-canary"));
            assert!(!text.contains("misplaced-signing-secret"));
            assert!(!text.contains("private-path"));
            assert_eq!(open_resolved(&plugin, settings).outcome, Outcome::Failed);
        }
    }
}

#[test]
fn both_variants_validate_without_a_secret_and_open_after_secret_resolution() {
    let cases: &[(&[u8], &[u8])] = &[
        (
            br#"{"variant":"twilio","origin":"wss://edge.example"}"#,
            br#"{"variant":"twilio","origin":"wss://edge.example","signing_secret":" webhook-validation-secret \n"}"#,
        ),
        (
            br#"{"variant":"standard-webhooks","tolerance_secs":0}"#,
            br#"{"variant":"standard-webhooks","tolerance_secs":0,"signing_secret":"whsec_d2ViaG9vay12YWxpZGF0aW9uLXNlY3JldA=="}"#,
        ),
    ];
    for leg in [false, true] {
        for &(settings, resolved) in cases {
            let dispatcher = Dispatcher::new(DispatchConfig::default());
            let folds = Arc::new(Folds::default());
            let plugin = if leg {
                dropped(&folds, &dispatcher)
            } else {
                linked(&folds, &dispatcher)
            };
            assert_eq!(validate_settings(&plugin, settings).outcome, Outcome::Ready);

            assert_eq!(open_resolved(&plugin, settings).outcome, Outcome::Failed);
            assert_eq!(validate_settings(&plugin, resolved).outcome, Outcome::Ready);
            assert_eq!(open_resolved(&plugin, resolved).outcome, Outcome::Ready);
            assert_eq!(close(&plugin).outcome, Outcome::Ready);
        }
    }
}

fn split_settings(settings: &[u8]) -> (Vec<u8>, String) {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(settings) else {
        return (settings.to_vec(), String::new());
    };
    let secret = value
        .as_object_mut()
        .and_then(|o| {
            o.remove("signing_secret")
                .or_else(|| o.remove("signing-secret"))
        })
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    (serde_json::to_vec(&value).unwrap(), secret)
}
fn validate_settings(p: &Plugin<Auth>, settings: &[u8]) -> busbar_plugin_loader::dispatch::Called {
    let (settings, _) = split_settings(settings);
    let mut error = [0u8; 512];
    let mut f: Frame<ValidateIn, OutHead> = Frame::new(z(), out_head());
    f.input.head = in_head();
    f.input.settings = blob(&settings, BLOB_JSON, 0);
    f.input.err_buf = error.as_mut_ptr();
    f.input.err_cap = error.len();
    one_header_crossing(p, || private_answer(p.call(life::VALIDATE, &mut f)))
}
fn open_resolved(p: &Plugin<Auth>, settings: &[u8]) -> busbar_plugin_loader::dispatch::Called {
    let (settings, secret) = split_settings(settings);
    let secrets = [blob(secret.as_bytes(), BLOB_OCTETS, BLOB_SECRET)];
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.generation = 1;
    f.input.settings = blob(&settings, BLOB_JSON, 0);
    if !secret.is_empty() {
        f.input.secrets = secrets.as_ptr();
        f.input.secrets_len = 1;
    }
    one_header_crossing(p, || private_answer(p.call(life::OPEN, &mut f)))
}
fn close(p: &Plugin<Auth>) -> busbar_plugin_loader::dispatch::Called {
    let mut f = Frame::<InHead, OutHead>::new(in_head(), out_head());
    one_header_crossing(p, || private_answer(p.call(life::CLOSE, &mut f)))
}

#[test]
fn a_changed_statement_is_refused_linked_and_dropped() {
    use busbar_plugin_loader::dispatch::LoadError;
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let honest = rendering_of(busbar_auth_webhook_signature::door).unwrap();
    let statement = rendering_of(another_version_door).unwrap();
    busbar_contract::abi::mechanism::rendering::read(&honest)
        .expect("the honest Statement is a valid rendering");
    busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the different-version Statement is a valid rendering");
    assert_ne!(statement, honest);
    let row = LinkedRow {
        statement: statement.clone(),
        door: busbar_plugin_loader::dispatch::load::raw(busbar_auth_webhook_signature::door),
    };
    assert_eq!(
        load_linked::<Auth>(&row, bind(&folds, &d)).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Auth>(&built_plugin_image(), &statement, bind(&folds, &d)).err(),
        Some(LoadError::StatementMismatch)
    );
}

#[test]
fn the_door_refuses_every_other_kind_linked_and_dropped() {
    use busbar_plugin_loader::dispatch::kinds::{
        export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
        transport::Transport,
    };
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let row = row(busbar_auth_webhook_signature::door);
    let path = built_plugin_image();
    assert_eq!(
        load_linked::<Export>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Export
        })
    );
    assert_eq!(
        load_dropped::<Export>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Export
        })
    );
    assert_eq!(
        load_linked::<Hook>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Hook
        })
    );
    assert_eq!(
        load_dropped::<Hook>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Hook
        })
    );
    assert_eq!(
        load_linked::<Plane>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Plane
        })
    );
    assert_eq!(
        load_dropped::<Plane>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Plane
        })
    );
    assert_eq!(
        load_linked::<Secret>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Secret
        })
    );
    assert_eq!(
        load_dropped::<Secret>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Secret
        })
    );
    assert_eq!(
        load_linked::<Store>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Store
        })
    );
    assert_eq!(
        load_dropped::<Store>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Store
        })
    );
    assert_eq!(
        load_linked::<Transport>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Transport
        })
    );
    assert_eq!(
        load_dropped::<Transport>(&path, &row.statement, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Transport
        })
    );
}

#[test]
fn conformance_honors_the_requested_release_profile() {
    assert!(!(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()));
}

extern "C" fn wrong_abi_door<const UP: bool>() -> &'static Door {
    let real = busbar_auth_webhook_signature::door();
    let abi = if UP {
        real.kind_abi() + 1
    } else {
        real.kind_abi().wrapping_sub(1)
    };
    // SAFETY: preserve every pointer and its lifetime, changing only the refused ABI number.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            kind_abi: abi,
            ..real.parts()
        })
    }))
}

#[test]
fn another_kind_abi_is_refused() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    for door in [wrong_abi_door::<true> as DoorFn, wrong_abi_door::<false>] {
        let host = busbar_auth_webhook_signature::door().kind_abi();
        let abi = door().kind_abi();
        let want = busbar_plugin_loader::dispatch::LoadError::KindAbi {
            kind: busbar_contract::abi::mechanism::KindCode::Auth,
            door: abi,
            host,
        };
        assert_eq!(rendering_of(door).err(), Some(want.clone()));
        let refused = LinkedRow::of(door)
            .and_then(|r| load_linked::<Auth>(&r, bind(&folds, &d)))
            .err()
            .unwrap();
        assert_eq!(refused, want);
        assert!(refused.to_string().contains("rebuild"));
        let mut statement = rendering_of(busbar_auth_webhook_signature::door).unwrap();
        let at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        statement[at..at + 4].copy_from_slice(&door().kind_abi().to_le_bytes());
        assert_eq!(
            load_dropped::<Auth>(&built_plugin_image(), &statement, bind(&folds, &d)).err(),
            Some(busbar_plugin_loader::dispatch::LoadError::ManifestKindAbi { stated: abi, host })
        );
    }
}

// The checked-in vectors are product inputs, exercised directly rather than interpreted by a kit.
#[derive(Debug, PartialEq, Eq)]
struct VectorAnswer {
    verdict: String,
    error: Option<Vec<u8>>,
    needed_bytes: u64,
    needed_groups: u32,
    needed_strip: u32,
    decision: u32,
    identity: String,
    groups: Vec<(u32, u32)>,
    strips: Vec<(u32, u32, u32)>,
    bytes: Vec<u8>,
}
fn vector_verify(
    p: &Plugin<Auth>,
    d: &Dispatcher,
    case: &serde_json::Value,
    submitted: bool,
    short: bool,
) -> VectorAnswer {
    let lines: Vec<NamedValue> = case["carriers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| NamedValue {
            name: s(name),
            value: blob(value.as_str().unwrap().as_bytes(), BLOB_OCTETS, BLOB_SECRET),
        })
        .collect();
    let mut bytes = vec![0u8; 2048];
    let mut groups = vec![z::<Span>(); 8];
    let mut strips = vec![z::<StripName>(); 8];
    let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.credential = case["credential"]
        .as_str()
        .map_or(z(), |v| blob(v.as_bytes(), BLOB_OCTETS, BLOB_SECRET));
    f.input.lines = lines.as_ptr();
    f.input.lines_len = lines.len();
    f.input.point = POINT_HEAD_BODY;
    f.input.body = case["body"]
        .as_str()
        .map_or(z(), |v| blob(v.as_bytes(), BLOB_OCTETS, 0));
    f.input.request = RequestFacts {
        method: s(case["method"].as_str().unwrap_or("GET")),
        authority: s("conformance.invalid"),
        canonical_path: s(case["path"].as_str().unwrap_or("/")),
        query: case["query"].as_str().map_or(z(), s),
        timestamp: case["timestamp"].as_u64().unwrap_or(0),
    };
    f.input.out_buf = IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    f.input.strip = strips.as_mut_ptr();
    f.input.strip_cap = strips.len() as u32;
    if short {
        f.input.out_buf = z();
        f.input.strip = std::ptr::null_mut();
        f.input.strip_cap = 0;
    }
    let before = p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed);
    let answer_error;
    let mut short_needs = None;
    let resumes = p.inner.resumes.load(std::sync::atomic::Ordering::Relaxed);
    let outcome = if submitted {
        let ticket = d.mint(0).expect("a free ticket");
        // All pointed-to storage remains alive and unmodified until wait_done returns the frame.
        let done = d
            .submit_watched(
                p,
                ticket,
                slot::VERIFY,
                f,
                busbar_contract::abi::mechanism::call::DeadlineClass::Call,
                busbar_plugin_loader::dispatch::now_ns() + 10_000_000_000,
                Arc::new(()),
                std::time::Duration::ZERO,
            )
            .wait_done();
        d.recycle(ticket);
        assert_private_text(done.error.as_deref().unwrap_or_default());
        answer_error = done.error.clone();
        assert_eq!(done.lease, 0);
        f = done.frame.expect("synchronous auth returns its frame");
        done.outcome
    } else {
        let c = private_answer(p.call(slot::VERIFY, &mut f));
        if short {
            assert_eq!(c.outcome, Outcome::Failed);
            assert_ne!(
                f.out.head.lease, 0,
                "the original vectors default to retained SHORT storage"
            );
            let token = c.recall.expect("SHORT retains the original judgment");
            assert!(f.out.needed_bytes > 0);
            assert_eq!(f.out.needed_groups, 0, "webhook identities carry no groups");
            let strip_count = if case["carriers"].get("x-twilio-signature").is_some() {
                1
            } else {
                3
            };
            assert_eq!(f.out.needed_strip, strip_count);
            short_needs = Some((f.out.needed_bytes, f.out.needed_groups, f.out.needed_strip));
            f.input.out_buf = IdentityBuf {
                buf: bytes.as_mut_ptr(),
                buf_cap: bytes.len(),
                groups: groups.as_mut_ptr(),
                groups_cap: groups.len() as u32,
                _reserved: 0,
            };
            f.input.strip = strips.as_mut_ptr();
            f.input.strip_cap = strips.len() as u32;
            f.out = z();
            f.out.head = out_head();
            let recalled = private_answer(p.recall(token, slot::VERIFY, &mut f));
            assert!(recalled.recall.is_none());
            assert_eq!(recalled.lease, 0);
            answer_error = recalled.error.clone();
            recalled.outcome
        } else {
            assert_eq!(c.lease, 0);
            answer_error = c.error.clone();
            c.outcome
        }
    };
    let expected_crossings = if short { 3 } else { 1 };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while short
        && p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before
            < expected_crossings
        && std::time::Instant::now() < deadline
    {
        std::thread::yield_now();
    }
    assert_eq!(
        p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before,
        expected_crossings
    );
    assert_eq!(
        p.inner.resumes.load(std::sync::atomic::Ordering::Relaxed),
        resumes
    );
    assert_eq!(outcome, Outcome::Ready);
    let subject = f.out.identity.subject;
    assert_private_text(&bytes);
    let result = match f.out.verdict {
        VERDICT_IDENTITY => format!(
            "identity:{}",
            std::str::from_utf8(
                &bytes[subject.offset as usize..(subject.offset + subject.len) as usize]
            )
            .unwrap()
        ),
        VERDICT_REJECT => "reject".into(),
        VERDICT_PASS => "pass".into(),
        other => panic!("unknown verdict {other}"),
    };
    assert_eq!(result, case["verdict"].as_str().unwrap());
    let identity = &f.out.identity;
    let written_groups = &groups[..identity.groups_len as usize];
    let written_strips = &strips[..f.out.strip_len as usize];
    if let Some((needed_bytes, needed_groups, needed_strip)) = short_needs {
        assert_eq!(identity.groups_len, needed_groups);
        assert_eq!(f.out.strip_len, needed_strip);
        let identity_spans = [
            identity.subject,
            identity.key_id,
            identity.key_name,
            identity.user,
            identity.provider,
            identity.name,
            identity.claims,
            identity.replay_key,
            identity.credential,
        ];
        let written_end = identity_spans
            .iter()
            .copied()
            .chain(written_groups.iter().copied())
            .chain(written_strips.iter().map(|strip| strip.name))
            .filter(|span| span.offset != SPAN_ABSENT)
            .map(|span| u64::from(span.offset) + u64::from(span.len))
            .max()
            .unwrap_or(0);
        assert_eq!(
            needed_bytes, written_end,
            "SHORT names exactly the required serialized bytes"
        );
    }
    VectorAnswer {
        verdict: result,
        error: answer_error,
        needed_bytes: f.out.needed_bytes,
        needed_groups: f.out.needed_groups,
        needed_strip: f.out.needed_strip,
        decision: f.out.decision,
        identity: format!("{identity:?}"),
        groups: written_groups
            .iter()
            .map(|span| (span.offset, span.len))
            .collect(),
        strips: written_strips
            .iter()
            .map(|strip| (strip.place, strip.name.offset, strip.name.len))
            .collect(),
        bytes,
    }
}
#[test]
fn published_twilio_and_standard_vectors_cross_both_doors_on_the_spot_and_submitted() {
    for inputs in [
        include_str!("conformance.json"),
        include_str!("conformance_standard_webhooks.json"),
    ] {
        let input: serde_json::Value = serde_json::from_str(inputs).unwrap();
        let settings = input["settings"].as_str().unwrap().as_bytes();
        let auth = &input["auth"];
        let d = Dispatcher::new(DispatchConfig::default());
        let folds = Arc::new(Folds::default());
        let mut transcripts = Vec::new();
        let mut rotated_transcripts = Vec::new();
        let mut facts_transcripts = Vec::new();
        let mut tick_transcripts = Vec::new();
        let mut lifecycle_transcripts = Vec::new();
        for (is_dropped, p) in [(false, linked(&folds, &d)), (true, dropped(&folds, &d))] {
            let mut lifecycle = Vec::new();
            assert_eq!(p.kind(), busbar_contract::abi::mechanism::KindCode::Auth);
            assert_eq!(p.name(), "busbar-auth-webhook-signature");
            assert_eq!(p.max_inflight(), 64);
            let linked_rendering = rendering_of(busbar_auth_webhook_signature::door).unwrap();
            assert_eq!(
                busbar_plugin_loader::dispatch::rendering_of_library(&built_plugin_image())
                    .unwrap()
                    .unwrap(),
                linked_rendering
            );
            // SAFETY: the actual door owns a complete immutable Statement and AuthTail.
            let stated = unsafe {
                busbar_auth_webhook_signature::door()
                    .parts()
                    .statement
                    .read_unaligned()
            };
            let tail = unsafe {
                stated
                    .kind_tail
                    .cast::<busbar_contract::abi::auth::AuthTail>()
                    .read_unaligned()
            };
            assert_eq!(tail.caps, busbar_contract::abi::auth::CAP_INBOUND);
            assert_eq!(tail.facts, 0);
            assert_eq!(tail.login_kind, 0);
            assert_eq!(tail.inbound_points, POINT_HEAD_BODY);
            let words =
                unsafe { std::slice::from_raw_parts(stated.mark_words, stated.mark_words_len) };
            let carriers: Vec<_> = words
                .iter()
                .filter(|word| {
                    word.class == busbar_contract::abi::mechanism::door::MARK_WORD_CARRIER
                })
                .map(|word| {
                    String::from_utf8_lossy(unsafe {
                        std::slice::from_raw_parts(word.word.ptr, word.word.len)
                    })
                    .into_owned()
                })
                .collect();
            assert_eq!(
                carriers,
                [
                    "x-twilio-signature",
                    "webhook-id",
                    "webhook-timestamp",
                    "webhook-signature"
                ]
            );
            facts_transcripts.push(format!(
                "{:?} {} max_inflight={} caps={} facts={} login_kind={} carriers={carriers:?}",
                p.kind(),
                p.name(),
                p.max_inflight(),
                tail.caps,
                tail.facts,
                tail.login_kind
            ));
            let mut unopened: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
            unopened.input.head = in_head();
            unopened.out.head = out_head();
            let before = p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed);
            assert_ne!(
                private_answer(p.call(slot::VERIFY, &mut unopened)).outcome,
                Outcome::Ready
            );
            assert_eq!(
                p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed),
                before
            );
            let before = p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                lifecycle_answer("validate", &validate_settings(&p, settings), &mut lifecycle),
                Outcome::Ready
            );
            assert_eq!(
                p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before,
                1
            );
            assert_eq!(
                lifecycle_answer("open", &open_resolved(&p, settings), &mut lifecycle),
                Outcome::Ready
            );
            assert_eq!(
                p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before,
                2
            );
            let ready_crossings = u64::from(p.has_ready());
            p.ready(&d, std::time::Duration::from_secs(5)).unwrap();
            assert_eq!(
                p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before,
                2 + ready_crossings
            );
            assert_undeclared_slots(&p);
            assert_eq!(
                p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before,
                7 + ready_crossings
            );
            let mut transcript = Vec::new();
            for case in auth["cases"].as_array().unwrap() {
                let now = vector_verify(&p, &d, case, false, false);
                assert_eq!(vector_verify(&p, &d, case, true, false), now);
                for secret in auth["never_echoed"].as_array().unwrap() {
                    let secret = secret.as_str().unwrap();
                    assert!(!now.verdict.contains(secret));
                    for text in [
                        now.bytes.as_slice(),
                        now.error.as_deref().unwrap_or_default(),
                    ] {
                        assert!(
                            !text.windows(secret.len()).any(|w| w == secret.as_bytes()),
                            "an ABI answer echoes a never_echoed secret"
                        );
                    }
                }
                transcript.push(now);
            }
            for (index, case) in auth["cases"].as_array().unwrap().iter().enumerate() {
                if case["verdict"].as_str().unwrap().starts_with("identity:") {
                    assert_eq!(
                        vector_verify(&p, &d, case, false, true),
                        transcript[index],
                        "full retained SHORT answer equals the original identity"
                    );
                }
            }
            let rotated = if is_dropped {
                dropped(&folds, &d)
            } else {
                linked(&folds, &d)
            };
            let before = rotated
                .inner
                .crossings
                .load(std::sync::atomic::Ordering::Relaxed);
            let resumes = rotated
                .inner
                .resumes
                .load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                lifecycle_answer(
                    "open rotated",
                    &open_resolved(
                        &rotated,
                        auth["rotated_settings"].as_str().unwrap().as_bytes()
                    ),
                    &mut lifecycle
                ),
                Outcome::Ready
            );
            assert_eq!(
                rotated
                    .inner
                    .crossings
                    .load(std::sync::atomic::Ordering::Relaxed)
                    - before,
                1
            );
            let before_ready = rotated
                .inner
                .crossings
                .load(std::sync::atomic::Ordering::Relaxed);
            rotated
                .ready(&d, std::time::Duration::from_secs(5))
                .unwrap();
            assert_eq!(
                rotated
                    .inner
                    .crossings
                    .load(std::sync::atomic::Ordering::Relaxed)
                    - before_ready,
                u64::from(rotated.has_ready())
            );
            let mut rotated_answers = Vec::new();
            for case in auth["cases"].as_array().unwrap() {
                if case["verdict"].as_str().unwrap().starts_with("identity:") {
                    let mut rotated_case = case.clone();
                    rotated_case["verdict"] = serde_json::Value::String("reject".into());
                    let answer = vector_verify(&rotated, &d, &rotated_case, false, false);
                    assert_eq!(answer.verdict, "reject");
                    assert_eq!(
                        vector_verify(&rotated, &d, &rotated_case, true, false),
                        answer
                    );
                    rotated_answers.push(answer);
                }
            }
            let before_close = rotated
                .inner
                .crossings
                .load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                lifecycle_answer("close rotated", &close(&rotated), &mut lifecycle),
                Outcome::Ready
            );
            assert_eq!(
                rotated
                    .inner
                    .crossings
                    .load(std::sync::atomic::Ordering::Relaxed)
                    - before_close,
                1
            );
            assert_eq!(
                rotated
                    .inner
                    .resumes
                    .load(std::sync::atomic::Ordering::Relaxed),
                resumes
            );
            rotated_transcripts.push(rotated_answers);
            let (settings_bytes, secret) = split_settings(settings);
            let before_refresh = p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                lifecycle_answer(
                    "refresh",
                    &refresh_answer(
                        &p,
                        std::str::from_utf8(&settings_bytes).unwrap(),
                        &secret,
                        2
                    ),
                    &mut lifecycle
                ),
                Outcome::Ready
            );
            assert_eq!(
                p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before_refresh,
                1
            );
            assert_eq!(
                vector_verify(&p, &d, &auth["cases"][0], false, false),
                transcript[0]
            );
            let mut tick: Frame<TickIn, TickOut> = Frame::new(z(), z());
            tick.input.head = in_head();
            tick.input.now_ns = 1_000;
            tick.out.head = out_head();
            let answer = one_header_crossing(&p, || private_answer(p.call(life::TICK, &mut tick)));
            tick_transcripts.push((
                answer.outcome,
                answer.error,
                answer.lease != 0,
                tick.out.next_tick_ns,
            ));
            let before_close = p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                lifecycle_answer("close", &close(&p), &mut lifecycle),
                Outcome::Ready
            );
            assert_eq!(
                p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before_close,
                1
            );
            let before = p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed);
            assert_ne!(
                private_answer(p.call(slot::VERIFY, &mut unopened)).outcome,
                Outcome::Ready
            );
            assert_eq!(
                p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed),
                before
            );
            transcripts.push(transcript);
            for (bad_index, settings) in auth["bad_settings"].as_array().unwrap().iter().enumerate()
            {
                let p = if is_dropped {
                    dropped(&folds, &d)
                } else {
                    linked(&folds, &d)
                };
                let before = p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed);
                let resumes = p.inner.resumes.load(std::sync::atomic::Ordering::Relaxed);
                let validated = validate_settings(&p, settings.as_str().unwrap().as_bytes());
                // Secret syntax belongs to OPEN; settings-only VALIDATE accepts this case.
                let secret_only =
                    inputs == include_str!("conformance_standard_webhooks.json") && bad_index == 2;
                assert_eq!(
                    validated.outcome,
                    if secret_only {
                        Outcome::Ready
                    } else {
                        Outcome::Failed
                    }
                );
                lifecycle_answer(
                    &format!("validate bad #{bad_index}"),
                    &validated,
                    &mut lifecycle,
                );
                assert!(validated.recall.is_none());
                if secret_only {
                    assert!(validated.error.is_none());
                } else {
                    assert!(validated
                        .error
                        .as_ref()
                        .is_some_and(|text| !text.is_empty()));
                }
                assert_eq!(
                    p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before,
                    1
                );
                assert_eq!(
                    p.inner.resumes.load(std::sync::atomic::Ordering::Relaxed),
                    resumes
                );
                let refused = open_resolved(&p, settings.as_str().unwrap().as_bytes());
                assert_eq!(
                    p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before,
                    2
                );
                assert_eq!(
                    p.inner.resumes.load(std::sync::atomic::Ordering::Relaxed),
                    resumes
                );
                assert!(refused.recall.is_none());
                assert_eq!(refused.outcome, Outcome::Failed);
                assert!(refused.error.as_ref().is_some_and(|text| !text.is_empty()));
                assert_eq!(refused.lease, 0);
                lifecycle_answer(&format!("open bad #{bad_index}"), &refused, &mut lifecycle);
            }
            lifecycle_transcripts.push(lifecycle);
        }
        assert_eq!(transcripts[0], transcripts[1]);
        assert_eq!(rotated_transcripts[0], rotated_transcripts[1]);
        assert_eq!(facts_transcripts[0], facts_transcripts[1]);
        assert_eq!(tick_transcripts[0], tick_transcripts[1]);
        assert_eq!(lifecycle_transcripts[0], lifecycle_transcripts[1]);
        for secret in auth["never_echoed"].as_array().unwrap() {
            for event in folds.0.lock().unwrap().iter() {
                assert!(!event.contains(secret.as_str().unwrap()));
            }
        }
    }
}

fn assert_undeclared_slots(p: &Plugin<Auth>) {
    use busbar_contract::abi::auth::*;
    let mut begin: Frame<BeginLoginIn, BeginLoginOut> = Frame::new(z(), z());
    begin.input.head = in_head();
    begin.out.head = out_head();
    assert_eq!(
        one_header_crossing(p, || private_answer(p.call(slot::BEGIN_LOGIN, &mut begin))).outcome,
        Outcome::Refused
    );
    let mut complete: Frame<CompleteLoginIn, IdentifyOut> = Frame::new(z(), z());
    complete.input.head = in_head();
    complete.out.head = out_head();
    assert_eq!(
        one_header_crossing(p, || private_answer(
            p.call(slot::COMPLETE_LOGIN, &mut complete)
        ))
        .outcome,
        Outcome::Refused
    );
    let mut open: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(z(), z());
    open.input.head = in_head();
    open.out.head = out_head();
    assert_eq!(
        one_header_crossing(p, || private_answer(p.call(slot::OPEN_OUTBOUND, &mut open))).outcome,
        Outcome::Refused
    );
    let mut ready: Frame<OutboundReadyIn, OutboundReadyOut> = Frame::new(z(), z());
    ready.input.head = in_head();
    ready.out.head = out_head();
    assert_eq!(
        one_header_crossing(p, || private_answer(
            p.call(slot::OUTBOUND_READY, &mut ready)
        ))
        .outcome,
        Outcome::Refused
    );
    let mut fields: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
    fields.input.head = in_head();
    fields.out.head = out_head();
    assert_eq!(
        one_header_crossing(p, || private_answer(p.call(slot::FIELDS, &mut fields))).outcome,
        Outcome::Refused
    );
}
extern "C" fn wrong_layout_door<const ZERO: bool>() -> &'static Door {
    let real = busbar_auth_webhook_signature::door();
    // SAFETY: only the fingerprint changes; the real static product pointers remain valid.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            layout: if ZERO { 0 } else { real.parts().layout ^ 1 },
            ..real.parts()
        })
    }))
}
#[test]
fn another_kind_layout_is_refused() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    for door in [
        wrong_layout_door::<true> as DoorFn,
        wrong_layout_door::<false>,
    ] {
        let refused = rendering_of(door).unwrap_err();
        assert!(matches!(
            refused,
            busbar_plugin_loader::dispatch::LoadError::KindLayout { .. }
        ));
        assert!(refused.to_string().contains("rebuild"));
        let row = LinkedRow {
            statement: rendering_of(busbar_auth_webhook_signature::door).unwrap(),
            door: busbar_plugin_loader::dispatch::load::raw(door),
        };
        assert_eq!(
            load_linked::<Auth>(&row, bind(&folds, &d)).err(),
            Some(refused.clone())
        );
        assert_eq!(LinkedRow::of(door).err(), Some(refused));
    }
}
#[test]
fn declared_needs_match_the_real_statement() {
    let bytes = rendering_of(busbar_auth_webhook_signature::door).unwrap();
    assert!(busbar_contract::abi::mechanism::rendering::read(&bytes)
        .unwrap()
        .needs
        .is_empty());
    assert!(!include_str!("../../auth-webhook-signature/declares.json").contains("\"needs\""));
}

static READY_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
unsafe extern "C" fn failing_ready(
    _: *mut c_void,
    _: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    READY_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let failed = RawOutcome::of(Outcome::Failed);
    // SAFETY: READY receives the host's live OutHead.
    unsafe {
        let head = &mut *out.cast::<busbar_contract::abi::mechanism::call::OutHead>();
        head.outcome = failed;
        head.error = s("webhook readiness witness refused");
    }
    failed
}
extern "C" fn failing_ready_door() -> &'static Door {
    // SAFETY: retain this product's static data and substitute one call-convention callback.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            ready: Some(failing_ready),
            ..busbar_auth_webhook_signature::door().parts()
        })
    }))
}
#[test]
fn a_failing_ready_is_refused_once() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let p = load_linked::<Auth>(&row(failing_ready_door), bind(&folds, &d)).unwrap();
    assert_eq!(open(&p, SETTINGS, TOKEN), Outcome::Ready);
    let refused = p.ready(&d, std::time::Duration::from_secs(5)).unwrap_err();
    assert!(
        refused
            == format!(
                "plugin '{}' ready failed: webhook readiness witness refused",
                p.name()
            ),
        "{refused}"
    );
    assert_eq!(READY_CALLS.load(std::sync::atomic::Ordering::SeqCst), 1);
}

extern "C" fn another_version_door() -> &'static Door {
    let real = busbar_auth_webhook_signature::door();
    // SAFETY: real's Statement points at immutable static product data; copy it and change only version.
    let mut statement = unsafe { *real.statement() };
    statement.version = s("0.0.0-wrong-version");
    let statement = Box::leak(Box::new(statement));
    // SAFETY: the replacement Statement and all original door pointers remain static.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            statement: std::ptr::from_ref(statement),
            ..real.parts()
        })
    }))
}
#[test]
fn a_restated_version_does_not_match_the_honest_row() {
    let d = Dispatcher::new(DispatchConfig::default());
    let folds = Arc::new(Folds::default());
    let row = LinkedRow {
        statement: rendering_of(busbar_auth_webhook_signature::door).unwrap(),
        door: busbar_plugin_loader::dispatch::load::raw(another_version_door),
    };
    assert_eq!(
        load_linked::<Auth>(&row, bind(&folds, &d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::StatementMismatch)
    );
}

// Each header operation is synchronous: exactly one entry, with no resumed invocation.
fn one_header_crossing<T>(p: &Plugin<Auth>, call: impl FnOnce() -> T) -> T {
    use std::sync::atomic::Ordering;
    let before = p.inner.crossings.load(Ordering::Relaxed);
    let resumes = p.inner.resumes.load(Ordering::Relaxed);
    let result = call();
    assert_eq!(p.inner.crossings.load(Ordering::Relaxed) - before, 1);
    assert_eq!(p.inner.resumes.load(Ordering::Relaxed) - resumes, 0);
    result
}

// Every signing secret these tests configure: the vector files' never_echoed strings, and the
// script secrets. `twilio-auth-token` is a substring of the conformance token and of the rotated
// token `the-rotated-twilio-auth-token`, so it covers all three.
fn assert_private_text(answer: &[u8]) {
    for secret in [
        "twilio-auth-token",
        "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
        "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
        "cm90YXRlZC1zdGFuZGFyZC13ZWJob29rLWtleQ",
        "rotated-standard-webhook-key",
    ] {
        assert!(
            !answer
                .windows(secret.len())
                .any(|bytes| bytes == secret.as_bytes()),
            "an ABI answer echoes a configured signing secret"
        );
    }
}
fn private_answer(
    called: busbar_plugin_loader::dispatch::Called,
) -> busbar_plugin_loader::dispatch::Called {
    assert_private_text(called.error.as_deref().unwrap_or_default());
    called
}

fn lifecycle_answer(
    label: &str,
    answer: &busbar_plugin_loader::dispatch::Called,
    transcript: &mut Vec<(String, Outcome, Option<Vec<u8>>, bool)>,
) -> Outcome {
    transcript.push((
        label.to_owned(),
        answer.outcome,
        answer.error.clone(),
        answer.lease != 0,
    ));
    answer.outcome
}
