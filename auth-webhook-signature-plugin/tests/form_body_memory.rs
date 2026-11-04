// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bounded work on a hostile `twilio` form body: an unauthenticated POST carrying any
//! `X-Twilio-Signature` and a body of many tiny pairs (`a&a&a&...`, up to the host's body cap) is
//! parsed before the signature can be judged. Judging it must cost about one copy of the body at
//! most, not a per-pair index of it: a body over the pair cap is refused before anything is
//! allocated for its pairs. Its own test binary: the counting allocator below sees every
//! allocation the judgment makes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use busbar_auth_webhook_signature::signature::MAX_FORM_PAIRS;
use busbar_auth_webhook_signature::{Request, WebhookSignature};
use busbar_contract::abi::sdk::auth_door::Verdict;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is forwarded to `System` unchanged; the counters only observe sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which is `System`'s.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(live, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System.alloc` with this `layout` (above).
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// libtest runs a binary's tests on parallel threads; the counters are process-wide, so each
/// measurement holds this lock from building its body to dropping it, and no other test's body is
/// allocated or freed while it measures.
static MEASURING: Mutex<()> = Mutex::new(());

/// The peak bytes, above what was live before, that judging an unauthenticated twilio POST of
/// `pair` repeated `times` times allocates, and that body's length, given the reject reason the
/// judgment must name.
fn peak_judging(pair: &[u8], times: usize, reason: &'static str) -> (usize, usize) {
    let _measuring = MEASURING.lock().unwrap_or_else(PoisonError::into_inner);
    let body = pair.repeat(times);
    let plugin = WebhookSignature::new(
        br#"{"variant":"twilio","origin":"https://hooks.example.com"}"#,
        &[b"twilio-auth-token".as_slice()],
    )
    .expect("opens");
    let lookup = |name: &str| {
        name.eq_ignore_ascii_case("x-twilio-signature")
            .then_some(&b"AAAAAAAAAAAAAAAAAAAAAAAAAAA="[..])
    };
    let request = Request {
        method: b"POST",
        path: b"/twilio/status",
        query: None,
        body: Some(&body[..]),
        now: 0,
        headers: &lookup,
    };

    let before = LIVE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let verdict = plugin.judge(&request);
    let extra = PEAK.load(Ordering::SeqCst) - before;
    assert_eq!(verdict, Verdict::reject(reason));
    (extra, body.len())
}

/// Many tiny pairs (`a&a&...`) are refused for their count before any per-pair index is built:
/// judging them allocates less than one copy of the body. Before the cap, the index of borrowed
/// pairs alone was eight times the body.
#[test]
fn red_a_hostile_twilio_form_body_is_judged_in_a_small_multiple_of_its_size() {
    let (extra, len) = peak_judging(b"a&", 512 * 1024, "too-many-form-pairs");
    assert!(
        extra < len,
        "judging a {len} byte form body allocated {extra} bytes at peak"
    );
}

/// A body of exactly the most pairs a form may carry, each with a long value, is judged (and its
/// unauthenticated signature refused) within about one decoded copy of the body plus the
/// fixed-size pair index.
#[test]
fn a_form_body_at_the_pair_cap_is_judged_in_about_one_copy_of_itself() {
    let pair: Vec<u8> = [&b"name="[..], &[b'v'; 1024][..], &b"&"[..]].concat();
    let (extra, len) = peak_judging(&pair, MAX_FORM_PAIRS, "twilio-mismatch");
    assert!(
        extra < len + len / 4,
        "judging a {len} byte form body at the pair cap allocated {extra} bytes at peak"
    );
}

/// Empty pairs (`&&&...`) are skipped, so they reserve nothing: room is made for the pairs a body
/// has, not one per `&`.
#[test]
fn red_a_body_of_only_separators_reserves_no_room_per_separator() {
    let (extra, len) = peak_judging(b"&", 1024 * 1024, "twilio-mismatch");
    assert!(
        extra < 4 * len,
        "judging a {len} byte body of empty pairs allocated {extra} bytes at peak"
    );
}
