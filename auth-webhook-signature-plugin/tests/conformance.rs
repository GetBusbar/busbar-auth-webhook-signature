// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE WEBHOOK-SIGNATURE DOOR, BOTH WAYS IN, ONE TRANSCRIPT**: the plugin's linked + dropped-in
//! conformance on the auth kind's memory ABI (THE DESIGN §11.4), run against the busbar rev this
//! repo pins (`.busbar-ref`).
//!
//! The plugin is held two ways at once: LINKED (the logic crate's `door::door`, its row's Statement
//! rendered by `LinkedRow::of` and admitted by the loader's `load_linked`) and DROPPED IN (this
//! crate's built cdylib, `dlopen`ed by `load_dropped`, which resolves `busbar_plugin_door` and
//! admits it only when its Statement renders byte for byte as the linked row's). Each is bound to a
//! real dispatcher and driven over the same script through the auth table: `open` over settings
//! that are not its own and over a missing token, then `verify` over the Twilio cases (a good
//! signature, none, a signature of another URL, a query, the header in another case, a configured
//! public host and scheme). The two transcripts must agree, and every verdict must equal what
//! `authenticate_twilio` answers for the same URL.
//!
//! THE RED ARMS, same file: the door opened over a ROTATED token judges differently (the equality is
//! not vacuous in the verdicts); the door asked for as another kind is refused; a stated rendering
//! one byte off the door's is refused. A missing cdylib PANICS: this test IS the dropped-in door's
//! proof, and never skips.

use std::mem::zeroed;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use busbar_auth_webhook_signature::{
    authenticate_twilio, door, MODULE_NAME, TWILIO_SIGNATURE_HEADER,
};
use busbar_contract::abi::auth::{
    slot, IdentifyOut, IdentityBuf, NamedValue, VerifyIn, SPAN_ABSENT, VERDICT_IDENTITY,
    VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Span, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as lc, OpenIn, OpenOut};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, Called, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, Plugin,
};

/// The Twilio auth token the plugin is opened with, and a rotated one.
const TOKEN: &[u8] = b"twilio-auth-token";
const ROTATED: &[u8] = b"a-rotated-token";

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file =
        busbar_plugin_loader::plugin_library_filename("busbar_auth_webhook_signature_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| {
            panic!("the busbar-auth-webhook-signature-plugin cdylib ({file}) is not built")
        })
}

fn row() -> LinkedRow {
    LinkedRow::of(door::door).expect("the door states itself")
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("twilio"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

fn abi(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// A call's answer as the transcript spells it: outcome and error text.
fn spelled(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} {text}", c.outcome)
}

fn open(p: &Plugin<Auth>, settings: &str, secrets: &[&[u8]]) -> String {
    let secrets: Vec<Blob> = secrets
        .iter()
        .map(|s| Blob {
            ptr: s.as_ptr(),
            len: s.len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        })
        .collect();
    let mut reason = vec![0_u8; 1024];
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    i.secrets = secrets.as_ptr();
    i.secrets_len = secrets.len();
    i.generation = 1;
    i.err_buf = reason.as_mut_ptr();
    i.err_cap = reason.len();
    let mut o: OpenOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    spelled(&p.call(lc::OPEN, &mut f))
}

/// One request as the host hands it to `verify`: the carrier fields, the authority, the path and
/// the query.
struct Request<'a> {
    carriers: &'a [(&'a str, &'a str)],
    authority: &'a str,
    path: &'a str,
    query: Option<&'a str>,
}

/// One `verify`: the verdict, and the subject when it identified.
fn verify(p: &Plugin<Auth>, r: &Request<'_>) -> String {
    let carriers: Vec<NamedValue> = r
        .carriers
        .iter()
        .map(|(k, v)| NamedValue {
            name: abi(k),
            value: Blob {
                ptr: v.as_ptr(),
                len: v.len(),
                fmt: BLOB_OCTETS,
                flags: BLOB_SECRET,
            },
        })
        .collect();
    let mut bytes = vec![0_u8; 4096];
    let mut groups: Vec<Span> = vec![z(); 16];
    let mut i: VerifyIn = z();
    i.head = in_head();
    i.carrier = carriers.as_ptr();
    i.carrier_len = carriers.len();
    i.request.method = abi("GET");
    i.request.authority = abi(r.authority);
    i.request.canonical_path = abi(r.path);
    if let Some(q) = r.query {
        i.request.query = abi(q);
    }
    i.out_buf = IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let mut o: IdentifyOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    let c = p.call(slot::VERIFY, &mut f);
    let subject = &f.out.identity.subject;
    let who = if f.out.verdict == VERDICT_IDENTITY && subject.offset != SPAN_ABSENT {
        let at = subject.offset as usize;
        String::from_utf8_lossy(&bytes[at..at + subject.len as usize]).into_owned()
    } else {
        String::new()
    };
    format!("{} verdict={} subject={who}", spelled(&c), f.out.verdict)
}

/// The verdict `authenticate_twilio` gives for the same URL, spelled as the transcript spells it.
fn expected(token: &[u8], url: &str, presented: Option<&str>) -> String {
    let (verdict, subject) = match authenticate_twilio(token, url, presented.map(str::as_bytes)) {
        busbar_contract::abi::sdk::auth_door::Verdict::Identity(id) => {
            (VERDICT_IDENTITY, id.subject)
        }
        busbar_contract::abi::sdk::auth_door::Verdict::Reject => (VERDICT_REJECT, String::new()),
        busbar_contract::abi::sdk::auth_door::Verdict::Pass => (VERDICT_PASS, String::new()),
    };
    format!("Ready  verdict={verdict} subject={subject}")
}

const URL: &str = "wss://node.example/twilio/stream";
const URL_QUERY: &str = "wss://node.example/twilio/stream?call=1";
const URL_PUBLIC: &str = "wss://public.example/twilio/stream";
const URL_HTTPS: &str = "https://node.example/twilio/stream";

fn sig(token: &[u8], url: &str) -> String {
    busbar_auth_webhook_signature::twilio_signature(token, url)
}

/// Each case: the carriers, the authority/path/query, the settings the plugin is opened over, the
/// token it is opened over, and the verdict `authenticate_twilio` must give.
struct Case {
    settings: &'static str,
    token: &'static [u8],
    header: Option<(&'static str, String)>,
    query: Option<&'static str>,
    want_url: &'static str,
}

fn cases() -> Vec<Case> {
    let h = TWILIO_SIGNATURE_HEADER;
    vec![
        // A good signature, none, another URL's, a query, the header in another case.
        Case {
            settings: r#"{"auth_token":"ref"}"#,
            token: TOKEN,
            header: Some((h, sig(TOKEN, URL))),
            query: None,
            want_url: URL,
        },
        Case {
            settings: r#"{"auth_token":"ref"}"#,
            token: TOKEN,
            header: None,
            query: None,
            want_url: URL,
        },
        Case {
            settings: r#"{"auth_token":"ref"}"#,
            token: TOKEN,
            header: Some((h, sig(TOKEN, URL_QUERY))),
            query: None,
            want_url: URL,
        },
        Case {
            settings: r#"{"auth_token":"ref"}"#,
            token: TOKEN,
            header: Some((h, sig(TOKEN, URL_QUERY))),
            query: Some("call=1"),
            want_url: URL_QUERY,
        },
        Case {
            settings: r#"{"auth_token":"ref"}"#,
            token: TOKEN,
            header: Some(("X-Twilio-Signature", sig(TOKEN, URL))),
            query: None,
            want_url: URL,
        },
        // A configured public host, a configured scheme.
        Case {
            settings: r#"{"auth_token":"ref","host":"public.example"}"#,
            token: TOKEN,
            header: Some((h, sig(TOKEN, URL_PUBLIC))),
            query: None,
            want_url: URL_PUBLIC,
        },
        Case {
            settings: r#"{"auth_token":"ref","host":"public.example"}"#,
            token: TOKEN,
            header: Some((h, sig(TOKEN, URL))),
            query: None,
            want_url: URL_PUBLIC,
        },
        Case {
            settings: r#"{"auth_token":"ref","scheme":"https"}"#,
            token: TOKEN,
            header: Some((h, sig(TOKEN, URL_HTTPS))),
            query: None,
            want_url: URL_HTTPS,
        },
        // A rotated token: the old token's signature is refused.
        Case {
            settings: r#"{"auth_token":"ref"}"#,
            token: ROTATED,
            header: Some((h, sig(TOKEN, URL))),
            query: None,
            want_url: URL,
        },
    ]
}

/// What one door does, as one comparable transcript: its name, its refusals at `open`, and every
/// case's verdict, each on a freshly opened instance.
fn transcript(load: &dyn Fn() -> Plugin<Auth>) -> Vec<String> {
    let mut out = vec![format!("name={}", load().name())];
    out.push(open(&load(), "not json", &[TOKEN]));
    out.push(open(&load(), "[]", &[TOKEN]));
    out.push(open(&load(), r#"{"scheme":7}"#, &[TOKEN]));
    out.push(open(&load(), r#"{"auth_token":"ref"}"#, &[]));
    out.push(open(&load(), r#"{"auth_token":"ref"}"#, &[b""]));
    for c in cases() {
        let p = load();
        let opened = open(&p, c.settings, &[c.token]);
        let carriers: Vec<(&str, &str)> = c.header.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let request = Request {
            carriers: &carriers,
            authority: "node.example",
            path: "/twilio/stream",
            query: c.query,
        };
        out.push(format!("{opened} | {}", verify(&p, &request)));
    }
    out
}

/// The plugin admits and answers as ONE plugin through either way in, every verdict is the logic's,
/// and the RED arms show the comparison is not vacuous.
#[test]
fn the_linked_and_the_dropped_in_webhook_signature_door_are_one_plugin() {
    let d = Dispatcher::new(DispatchConfig {
        workers: 2,
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    });
    let stated = row().statement;
    let linked =
        || -> Plugin<Auth> { load_linked(&row(), bind(&d)).expect("the linked door loads") };
    let dropped = || -> Plugin<Auth> {
        load_dropped(&cdylib(), &stated, bind(&d)).expect("the dropped-in door loads")
    };

    let a = transcript(&linked);
    let b = transcript(&dropped);
    assert_eq!(a, b, "the two doors are not one plugin");

    // Not a vacuous pass: the plugin refused what is not its own and judged every case as the
    // logic does.
    let text = a.join("\n");
    assert_eq!(a[0], format!("name={MODULE_NAME}"), "{text}");
    for line in &a[1..=5] {
        assert!(line.starts_with("Failed webhook-signature"), "{text}");
    }
    for (line, case) in a[6..].iter().zip(cases()) {
        let header = case.header.as_ref().map(|(_, v)| v.as_str());
        let want = expected(case.token, case.want_url, header);
        assert_eq!(line, &format!("Ready  | {want}"), "{text}");
    }
    for verdict in [VERDICT_IDENTITY, VERDICT_REJECT, VERDICT_PASS] {
        assert!(
            text.contains(&format!("verdict={verdict}")),
            "no verdict {verdict}: {text}"
        );
    }

    // RED ARM 1: the door opened over a ROTATED token judges the same signature differently.
    let good = &cases()[0];
    let rotated = &cases()[8];
    assert_eq!(
        good.header.as_ref().map(|h| &h.1),
        rotated.header.as_ref().map(|h| &h.1)
    );
    assert_ne!(
        a[6], a[14],
        "a door judging another token must not compare equal"
    );

    // RED ARM 2: the door asked for as another kind is refused, through either way in.
    assert!(load_linked::<Secret>(&row(), bind(&d)).is_err());
    assert!(load_dropped::<Secret>(&cdylib(), &stated, bind(&d)).is_err());

    // RED ARM 3: a stated rendering one byte off the door's is refused before any slot is called.
    let mut other = stated.clone();
    *other.last_mut().expect("a rendering has bytes") ^= 1;
    match load_dropped::<Auth>(&cdylib(), &other, bind(&d)) {
        Ok(_) => panic!("a Statement that is not the door's must be refused"),
        Err(e) => assert!(!e.to_string().is_empty()),
    }
}
