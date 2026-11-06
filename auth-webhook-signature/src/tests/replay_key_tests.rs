//! The Standard Webhooks replay key against the Standard Webhooks spec: a sender's retry keeps its
//! `webhook-id` but carries a fresh `webhook-timestamp` and signature, so it is a new attempt and
//! must be admitted; a byte-identical copy of an admitted attempt inside the window is a replay and
//! must be refused. The kernel's claim (`<provider>/<key>` held for `ttl_secs`) is modelled here by
//! [`Claims`], as `busbar-kernel`'s `replay_claimed` makes it.

use super::*;

const SW: &[u8] = br#"{"variant":"standard-webhooks"}"#;
const SW_SECRET: &[u8] = b"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const SW_BODY: &[u8] = br#"{"test": 2432232314}"#;
const T0: u64 = 1_614_265_330;

/// The kernel's replay store: a claim on `<provider>/<key>` that stands until `now + ttl_secs`.
#[derive(Default)]
struct Claims(std::collections::HashMap<String, u64>);

impl Claims {
    /// Whether the kernel admits `replay` at `now` (wins its claim), as `replay_claimed` decides.
    fn win(&mut self, provider: &str, replay: &Replay, now: u64) -> bool {
        let token = format!("{provider}/{}", replay.key);
        match self.0.get(&token) {
            Some(&expires_at) if now < expires_at => false,
            _ => {
                self.0.insert(token, now.saturating_add(replay.ttl_secs));
                true
            }
        }
    }
}

fn standard() -> WebhookSignature {
    WebhookSignature::new(SW, &[SW_SECRET]).expect("settings are this plugin's")
}

/// One signed attempt as its sender presents it: `id`, `ts` and a signature over both and the body.
struct Attempt {
    id: Vec<u8>,
    ts: Vec<u8>,
    sig: String,
}

fn attempt(id: &[u8], ts: u64) -> Attempt {
    let key = signature::standard_webhooks_key(SW_SECRET).expect("a standard-webhooks secret");
    let ts = ts.to_string().into_bytes();
    let sig = signature::signing::standard_webhooks_sign(&key, id, &ts, SW_BODY);
    Attempt {
        id: id.to_vec(),
        ts,
        sig,
    }
}

/// The replay claim a verified `attempt`, received at `now`, asks the kernel for.
fn claim_of(plugin: &WebhookSignature, a: &Attempt, now: u64) -> Box<Replay> {
    let headers: [(&str, &[u8]); 3] = [
        (WEBHOOK_ID_HEADER, &a.id),
        (WEBHOOK_TIMESTAMP_HEADER, &a.ts),
        (WEBHOOK_SIGNATURE_HEADER, a.sig.as_bytes()),
    ];
    let lookup = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };
    let verdict = plugin.judge(&Request {
        method: b"POST",
        path: b"/v1/webhooks/inbound",
        query: None,
        body: Some(SW_BODY),
        now,
        headers: &lookup,
    });
    match verdict {
        Verdict::Identity(id) => id.replay.expect("a verified delivery asks a replay claim"),
        other => panic!("the attempt verifies: {other:?}"),
    }
}

/// The sender's retry inside the tolerance window keeps the id but re-stamps and re-signs the
/// attempt (spec: "Every time an attempt is retried the timestamp of the attempt is updated"): it
/// is a new attempt and the kernel admits it.
#[test]
fn a_retry_with_a_new_timestamp_inside_the_window_is_admitted() {
    let plugin = standard();
    let mut kernel = Claims::default();

    let first = attempt(b"msg_retry", T0);
    assert!(kernel.win("hooks", &claim_of(&plugin, &first, T0), T0));

    let retry = attempt(b"msg_retry", T0 + 30);
    assert!(
        kernel.win("hooks", &claim_of(&plugin, &retry, T0 + 30), T0 + 30),
        "a retry with a fresh timestamp is a new attempt, not a replay"
    );
}

/// A byte-identical copy of an admitted attempt is a replay: refused anywhere inside the window,
/// including its last acceptable second, and stale after it.
#[test]
fn an_exact_replay_inside_the_window_is_refused() {
    let plugin = standard();
    let mut kernel = Claims::default();

    let first = attempt(b"msg_once", T0);
    assert!(kernel.win("hooks", &claim_of(&plugin, &first, T0), T0));
    for now in [T0, T0 + 1, T0 + 150, T0 + DEFAULT_TOLERANCE_SECS] {
        assert!(
            !kernel.win("hooks", &claim_of(&plugin, &first, now), now),
            "replay at {now} is refused"
        );
    }
}

/// A replay of the RETRY is refused too, and the retry's own claim does not free the first
/// attempt's: each attempt is admitted once.
#[test]
fn each_attempt_of_one_message_is_admitted_exactly_once() {
    let plugin = standard();
    let mut kernel = Claims::default();
    let first = attempt(b"msg_twice", T0);
    let retry = attempt(b"msg_twice", T0 + 60);

    assert!(kernel.win("hooks", &claim_of(&plugin, &first, T0), T0));
    assert!(kernel.win("hooks", &claim_of(&plugin, &retry, T0 + 60), T0 + 60));
    assert!(!kernel.win("hooks", &claim_of(&plugin, &retry, T0 + 61), T0 + 61));
    assert!(!kernel.win("hooks", &claim_of(&plugin, &first, T0 + 62), T0 + 62));
}

/// The claim on an attempt stands for exactly the rest of the window in which ITS timestamp is
/// acceptable (`ts + tolerance - now`, plus a second), from whichever edge it arrives at.
#[test]
fn the_claim_lasts_to_the_end_of_the_attempts_own_window() {
    let plugin = standard();
    let a = attempt(b"msg_ttl", T0);
    assert_eq!(claim_of(&plugin, &a, T0).ttl_secs, 301);
    assert_eq!(claim_of(&plugin, &a, T0 - 300).ttl_secs, 601);
    assert_eq!(claim_of(&plugin, &a, T0 + 300).ttl_secs, 1);
}

/// The key names the id and the attempt's timestamp; the timestamp leads (it is digits only, so the
/// first `/` after it ends it) and an id holding `/` or digits cannot make two attempts one key.
#[test]
fn the_key_is_the_timestamp_and_the_id_unambiguously() {
    let plugin = standard();
    let key = |id: &[u8], ts: u64| claim_of(&plugin, &attempt(id, ts), ts).key;

    assert_eq!(key(b"msg_1", T0), format!("standard-webhooks/{T0}/msg_1"));
    assert_ne!(key(b"msg_1", T0), key(b"msg_1", T0 + 1));
    assert_ne!(key(b"1/x", T0), key(b"x", T0 + 1));
    assert_ne!(key(b"x/1", T0), key(b"x/", T0));
    assert_eq!(
        key(b"evt-\xff", T0),
        format!("standard-webhooks-raw/{T0}/6576742dff")
    );
    assert_ne!(key(b"evt-\xff", T0), key(b"evt-\xff", T0 + 1));
}
