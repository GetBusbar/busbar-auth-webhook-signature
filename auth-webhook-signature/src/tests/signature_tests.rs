//! Checks both variants against published vectors and invalid-signature cases.

use super::signing::{
    form_params, standard_webhooks_sign, twilio_expected, twilio_sign, twilio_signed_string,
    twilio_verify, twilio_verify_cred,
};
use super::*;

fn owned(params: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    params
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

/// Twilio's published request-validation example (its docs and every official helper library's
/// tests): auth token `12345`, this URL, these POST parameters.
const TOKEN: &[u8] = b"12345";
const URL: &[u8] = b"https://mycompany.com/myapp.php?foo=1&bar=2";
const PARAMS: &[(&str, &str)] = &[
    ("CallSid", "CA1234567890ABCDE"),
    ("Caller", "+12349013030"),
    ("Digits", "1234"),
    ("From", "+12349013030"),
    ("To", "+18005551212"),
];
/// The signature Twilio publishes for it.
const PUBLISHED: &[u8] = b"0/KCTR6DLpKmkAf8muzZqo1nDgQ=";

#[test]
fn twilios_published_test_vector_signs_and_verifies() {
    assert_eq!(
        twilio_sign(TOKEN, URL, &owned(PARAMS)).as_bytes(),
        PUBLISHED
    );
    assert!(twilio_verify(TOKEN, URL, &owned(PARAMS), PUBLISHED));
}

/// The adopted opaque-key path agrees with the independent ring test signer, including keys
/// longer than SHA-1's block and message lengths spanning its padding boundaries. The published
/// Twilio vector above remains the independent wire-format receipt.
#[test]
fn the_opaque_twilio_key_matches_the_reference_signer_across_digest_boundaries() {
    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let params = owned(&[("Z", "last"), ("A", "z"), ("A", "b"), ("A", "b")]);
    for key_len in [1, 63, 64, 65, 80, 128] {
        let secret = vec![b'k'; key_len];
        let key = Cred::captured(Zeroizing::new(secret.clone()));
        for url_len in [0, 55, 56, 63, 64, 65, 127, 128, 129] {
            let url = vec![b'u'; url_len];
            let expected = twilio_expected(&key, &url, &params);
            wipes(&expected);
            let reference = twilio_sign(&secret, &url, &params);
            assert_eq!(STANDARD.encode(&expected[..]), reference);
            assert!(twilio_verify_cred(
                &key,
                &url,
                &params,
                reference.as_bytes()
            ));
            assert!(!twilio_verify_cred(&key, &url, &params, b"AAAA"));
        }
    }
}

#[test]
fn both_twilio_url_spellings_share_the_same_ordered_parameters_and_refuse_other_messages() {
    let key = Cred::captured(Zeroizing::new(TOKEN.to_vec()));
    let params = owned(&[("Z", "last"), ("A", "z"), ("A", "b"), ("A", "b")]);
    let alternate = b"https://mycompany.com:443/myapp.php?foo=1&bar=2";
    for url in [URL, alternate.as_slice()] {
        let signature = twilio_sign(TOKEN, url, &params);
        assert!(twilio_verify_either_cred(
            &key,
            URL,
            Some(alternate),
            &params,
            signature.as_bytes(),
        ));
        let changed = owned(&[("A", "b"), ("A", "different"), ("Z", "last")]);
        assert!(!twilio_verify_either_cred(
            &key,
            URL,
            Some(alternate),
            &changed,
            signature.as_bytes(),
        ));
    }
    let other = twilio_sign(TOKEN, b"https://other.example/", &params);
    assert!(!twilio_verify_either_cred(
        &key,
        URL,
        Some(alternate),
        &params,
        other.as_bytes(),
    ));
    assert!(!twilio_verify_either_cred(
        &key,
        URL,
        Some(alternate),
        &params,
        b"not base64!",
    ));
    assert!(twilio_verify_either_cred(
        &key,
        URL,
        None,
        &owned(PARAMS),
        PUBLISHED,
    ));
}

#[test]
fn the_published_vector_verifies_from_its_form_body_in_any_order() {
    let body = b"To=%2B18005551212&From=%2B12349013030&Digits=1234&Caller=%2B12349013030&CallSid=CA1234567890ABCDE";
    let params = form_params(body).expect("a form body");
    assert!(twilio_verify(TOKEN, URL, &params, PUBLISHED));
}

/// A repeated identical pair is signed once, and a name's distinct values are signed sorted — the
/// reference validators' `sorted(set(names))`, then `sorted(set(values))` under each.
#[test]
fn a_repeated_pair_is_signed_once_and_a_names_values_sorted() {
    let once = owned(&[("Digits", "1"), ("To", "+1")]);
    let twice = owned(&[("Digits", "1"), ("To", "+1"), ("Digits", "1")]);
    assert_eq!(
        twilio_signed_string(URL, &once),
        twilio_signed_string(URL, &twice)
    );
    let multi = owned(&[("A", "z"), ("A", "b"), ("A", "b")]);
    assert_eq!(
        twilio_signed_string(b"u", &multi),
        b"uAbAz".to_vec(),
        "distinct values, sorted"
    );
}

#[test]
fn a_form_body_decodes_plus_and_percent_escapes() {
    assert_eq!(
        form_params(b"a=x+y&b=%41%2b&c&=v").expect("form"),
        owned(&[("a", "x y"), ("b", "A+"), ("c", ""), ("", "v")])
    );
    assert_eq!(form_params(b"").expect("empty form"), Vec::new());
    assert_eq!(form_params(b"a=%4"), None, "a truncated escape");
    assert_eq!(form_params(b"a=%zz"), None, "a non-hex escape");
}

#[test]
fn a_json_body_is_bound_by_the_body_sha256_its_url_carries() {
    let body = br#"{"property": "value", "boolean": true}"#;
    let hash = b"0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620";
    assert!(body_sha256_matches(body, hash));
    assert!(body_sha256_matches(body, &hash.to_ascii_uppercase()));
    assert!(!body_sha256_matches(br#"{"property": "other"}"#, hash));
    assert!(!body_sha256_matches(body, &hash[..63]));
    let mut longer = hash.to_vec();
    longer.push(b'0');
    assert!(!body_sha256_matches(body, &longer));
    assert_eq!(
        query_param(b"x=1&bodySHA256=abc&y=2", b"bodySHA256"),
        Some(&b"abc"[..])
    );
    assert_eq!(query_param(b"x=1", b"bodySHA256"), None);
}

#[test]
fn the_standard_signature_list_ignores_only_its_surrounding_ascii_whitespace() {
    let padded = format!(" \t{}\t ", std::str::from_utf8(SW_PUBLISHED).unwrap());
    assert_eq!(
        standard_webhooks_verify(
            &sw_key(),
            SW_ID,
            SW_TS,
            SW_BODY,
            padded.as_bytes(),
            SW_NOW,
            FIVE_MIN,
        ),
        Ok(SW_NOW)
    );
    assert_eq!(
        standard_webhooks_verify(
            &sw_key(),
            SW_ID,
            SW_TS,
            b"tampered",
            padded.as_bytes(),
            SW_NOW,
            FIVE_MIN,
        ),
        Err(StandardWebhooksRefusal::BadSignature)
    );

    for invalid in [b" \tv2,%%%\t ".as_slice(), b" \tv1,%%%\t "] {
        assert_eq!(
            standard_webhooks_verify(&sw_key(), SW_ID, SW_TS, SW_BODY, invalid, SW_NOW, FIVE_MIN,),
            Err(StandardWebhooksRefusal::BadSignature)
        );
    }
}

#[test]
fn red_a_bad_twilio_signature_is_refused() {
    let params = owned(PARAMS);

    assert!(!twilio_verify(
        TOKEN,
        URL,
        &params,
        b"1/KCTR6DLpKmkAf8muzZqo1nDgQ="
    ));

    assert!(!twilio_verify(b"54321", URL, &params, PUBLISHED));

    assert!(!twilio_verify(TOKEN, URL, &params, b"not base64!"));
    assert!(!twilio_verify(TOKEN, URL, &params, b""));
}

#[test]
fn red_a_twilio_signature_replayed_on_another_url_is_refused() {
    let params = owned(PARAMS);
    for other in [
        &b"https://mycompany.com/other.php?foo=1&bar=2"[..],
        b"https://mycompany.com/myapp.php?foo=1&bar=3",
        b"wss://mycompany.com/myapp.php?foo=1&bar=2",
        b"https://evil.example/myapp.php?foo=1&bar=2",
    ] {
        assert!(
            !twilio_verify(TOKEN, other, &params, PUBLISHED),
            "{other:?}"
        );
    }

    let mut tampered = params.clone();
    tampered[2].1 = b"9999".to_vec();
    assert!(!twilio_verify(TOKEN, URL, &tampered, PUBLISHED));
    assert!(!twilio_verify(TOKEN, URL, &params[1..], PUBLISHED));
}

/// The Standard Webhooks specification's published test vector (its reference libraries' tests).
const SW_SECRET: &[u8] = b"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const SW_ID: &[u8] = b"msg_p5jXN8AQM9LWM0D4loKWxJek";
const SW_TS: &[u8] = b"1614265330";
const SW_NOW: u64 = 1_614_265_330;
const SW_BODY: &[u8] = br#"{"test": 2432232314}"#;
const SW_PUBLISHED: &[u8] = b"v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
const FIVE_MIN: u64 = 300;

fn sw_key() -> Zeroizing<Vec<u8>> {
    standard_webhooks_key(SW_SECRET).expect("a whsec_ secret")
}

#[test]
fn the_standard_webhooks_published_vector_signs_and_verifies() {
    assert_eq!(
        standard_webhooks_sign(&sw_key(), SW_ID, SW_TS, SW_BODY).as_bytes(),
        SW_PUBLISHED
    );
    assert_eq!(
        standard_webhooks_verify(
            &sw_key(),
            SW_ID,
            SW_TS,
            SW_BODY,
            SW_PUBLISHED,
            SW_NOW,
            FIVE_MIN
        ),
        Ok(SW_NOW)
    );

    assert_eq!(
        standard_webhooks_key(&SW_SECRET[6..]).expect("bare base64"),
        sw_key()
    );
}

#[test]
fn any_one_v1_entry_of_the_signature_list_may_match() {
    let list = [
        &b"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= "[..],
        b"v2,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE= ",
        SW_PUBLISHED,
    ]
    .concat();
    assert_eq!(
        standard_webhooks_verify(&sw_key(), SW_ID, SW_TS, SW_BODY, &list, SW_NOW, FIVE_MIN),
        Ok(SW_NOW)
    );

    assert_eq!(
        standard_webhooks_verify(
            &sw_key(),
            SW_ID,
            SW_TS,
            SW_BODY,
            b"v2,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
            SW_NOW,
            FIVE_MIN
        ),
        Err(StandardWebhooksRefusal::BadSignature)
    );
}

#[test]
fn red_a_bad_standard_webhooks_signature_is_refused() {
    let bad = |sig: &[u8], id: &[u8], body: &[u8]| {
        standard_webhooks_verify(&sw_key(), id, SW_TS, body, sig, SW_NOW, FIVE_MIN)
    };
    let refused = Err(StandardWebhooksRefusal::BadSignature);
    assert_eq!(
        bad(
            b"v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=",
            SW_ID,
            SW_BODY
        ),
        refused
    );
    assert_eq!(
        bad(SW_PUBLISHED, b"msg_other", SW_BODY),
        refused,
        "another id"
    );
    assert_eq!(
        bad(SW_PUBLISHED, SW_ID, br#"{"test": 1}"#),
        refused,
        "another body"
    );
    assert_eq!(bad(b"", SW_ID, SW_BODY), refused, "no entries");
    assert_eq!(bad(b"v1,%%%", SW_ID, SW_BODY), refused, "not base64");
    let other_key = standard_webhooks_key(b"whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").expect("key");
    assert_eq!(
        standard_webhooks_verify(
            &other_key,
            SW_ID,
            SW_TS,
            SW_BODY,
            SW_PUBLISHED,
            SW_NOW,
            FIVE_MIN
        ),
        refused
    );
}

#[test]
fn red_a_stale_or_future_timestamp_is_refused_even_with_a_valid_signature() {
    let at = |now: u64| {
        standard_webhooks_verify(
            &sw_key(),
            SW_ID,
            SW_TS,
            SW_BODY,
            SW_PUBLISHED,
            now,
            FIVE_MIN,
        )
    };
    assert_eq!(at(SW_NOW + FIVE_MIN), Ok(SW_NOW), "at the edge");
    assert_eq!(at(SW_NOW - FIVE_MIN), Ok(SW_NOW), "at the other edge");
    assert_eq!(
        at(SW_NOW + FIVE_MIN + 1),
        Err(StandardWebhooksRefusal::Stale)
    );
    assert_eq!(
        at(SW_NOW - FIVE_MIN - 1),
        Err(StandardWebhooksRefusal::Stale)
    );
    for ts in [
        &b"not-a-number"[..],
        b"",
        b"-1",
        b"1614265330.5",
        b"+1614265330",
        b"99999999999999999999",
    ] {
        assert_eq!(
            standard_webhooks_verify(
                &sw_key(),
                SW_ID,
                ts,
                SW_BODY,
                SW_PUBLISHED,
                SW_NOW,
                FIVE_MIN
            ),
            Err(StandardWebhooksRefusal::BadTimestamp),
            "{ts:?}"
        );
    }
}

#[test]
fn a_secret_that_is_not_base64_has_no_key() {
    assert_eq!(standard_webhooks_key(b"whsec_%%%"), None);
    assert_eq!(standard_webhooks_key(b"whsec_"), None);
}

#[test]
fn a_valid_v1_entry_after_junk_entries_still_verifies() {
    let valid_b64 = &SW_PUBLISHED[3..];
    let wrong = format!("v1,{}", STANDARD.encode([7u8; 32]));
    let v2 = [&b"v2,"[..], valid_b64].concat();
    let list = [
        &b" v1,"[..],
        b"v1,AAAA",
        wrong.as_bytes(),
        &v2,
        b"v1,!!!not-base64",
        SW_PUBLISHED,
    ]
    .join(&b' ');
    assert_eq!(
        standard_webhooks_verify(&sw_key(), SW_ID, SW_TS, SW_BODY, &list, SW_NOW, FIVE_MIN),
        Ok(SW_NOW)
    );
}

#[test]
fn red_only_junk_entries_are_refused() {
    let wrong = format!("v1,{}", STANDARD.encode([7u8; 32]));
    let v2 = [&b"v2,"[..], &SW_PUBLISHED[3..]].concat();
    let list = [&b" v1,"[..], b"v1,AAAA", wrong.as_bytes(), &v2, b"v1,"].join(&b' ');
    assert_eq!(
        standard_webhooks_verify(&sw_key(), SW_ID, SW_TS, SW_BODY, &list, SW_NOW, FIVE_MIN),
        Err(StandardWebhooksRefusal::BadSignature)
    );
}

#[test]
fn red_the_valid_tag_with_one_byte_flipped_is_refused() {
    let mut tag = STANDARD.decode(&SW_PUBLISHED[3..]).expect("base64");
    tag[31] ^= 1;
    let list = format!("v1,{}", STANDARD.encode(&tag));
    assert_eq!(
        standard_webhooks_verify(
            &sw_key(),
            SW_ID,
            SW_TS,
            SW_BODY,
            list.as_bytes(),
            SW_NOW,
            FIVE_MIN
        ),
        Err(StandardWebhooksRefusal::BadSignature)
    );
}

/// The expected tag is held in a buffer that wipes on drop (ring's `Tag` does not).
#[test]
fn the_expected_standard_webhooks_tag_is_wiped_on_drop() {
    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let tag = standard_webhooks_expected(&sw_key(), SW_ID, SW_TS, SW_BODY);
    wipes(&tag);
    assert_eq!(STANDARD.encode(&tag[..]).as_bytes(), &SW_PUBLISHED[3..]);
}

/// The production form path (borrowed pairs, decoded once into one buffer) signs exactly what
/// `form_params` + `twilio_signed_string` sign: the same pair order, dedup and decoding, the same
/// default-port alternate, and the same refusal of a body that is not a form body.
#[test]
fn the_borrowed_form_path_judges_exactly_as_the_owned_parameters() {
    let key = Cred::captured(Zeroizing::new(TOKEN.to_vec()));
    let alternate = b"https://mycompany.com:443/myapp.php?foo=1&bar=2";
    let bodies: &[&[u8]] = &[
        b"",
        b"&&&",
        b"To=%2B18005551212&From=%2B12349013030&Digits=1234&Caller=%2B12349013030&CallSid=CA1234567890ABCDE",
        b"a=b&ab=&a=b&a",
        b"ab&a=b&a%3Db=c",
        b"x=%41&x=A&x=a+b&x=a%20b&x=%c3%a9",
        b"Z=last&A=z&A=b&A=b&=v&n=",
        b"b=2&a=10&a=9&a=1",
        b"k=%ff%00&k=%FF",
    ];
    for body in bodies {
        let params = form_params(body).expect("a form body");
        for url in [URL, alternate.as_slice()] {
            let signature = twilio_sign(TOKEN, url, &params);
            assert_eq!(
                twilio_form_verify_either_cred(
                    &key,
                    URL,
                    Some(alternate),
                    body,
                    signature.as_bytes()
                ),
                Ok(true),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let other = twilio_sign(TOKEN, URL, &owned(&[("extra", "pair")]));
        for presented in [
            other.as_bytes(),
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            b"not base64!",
        ] {
            assert_eq!(
                twilio_form_verify_either_cred(&key, URL, Some(alternate), body, presented),
                Ok(twilio_verify_either_cred(
                    &key,
                    URL,
                    Some(alternate),
                    &params,
                    presented
                )),
            );
        }
    }
    assert_eq!(
        twilio_form_verify_either_cred(
            &key,
            URL,
            None,
            b"To=%2B18005551212&From=%2B12349013030&Digits=1234&Caller=%2B12349013030&CallSid=CA1234567890ABCDE",
            PUBLISHED
        ),
        Ok(true)
    );
    for bad in [
        &b"a=%"[..],
        b"a=%4",
        b"a=%zz&b=1",
        b"ok=1&%g0=x",
        b"n=v&m=%2",
    ] {
        assert_eq!(form_params(bad), None);
        assert_eq!(
            twilio_form_verify_either_cred(&key, URL, None, bad, PUBLISHED),
            Err(FormRefusal::Malformed)
        );
    }
}

/// The lazy pair comparison orders and equates raw pairs exactly as their decoded `(name, value)`
/// tuples do, including a pair without `=` against the same name with an empty value, an encoded
/// `=` (`%3D`) inside a name, and a name that is a prefix of another.
#[test]
fn the_lazy_pair_order_is_the_decoded_tuple_order() {
    let raw: &[&[u8]] = &[
        b"a", b"a=", b"a=b", b"ab", b"ab=", b"a%3D=b", b"a=%3Db", b"a%3Db", b"=", b"=x", b"+=+",
        b"%20=%20", b"%ff=%00", b"%FF", b"a+b=c", b"a%20b=c", b"a=b=c", b"a==", b"b", b"%41=1",
    ];
    for a in raw {
        for b in raw {
            let da = form_params(a).expect("a form pair");
            let db = form_params(b).expect("a form pair");
            assert_eq!(
                form_pair_cmp(a, b),
                da[0].cmp(&db[0]),
                "{} vs {}",
                String::from_utf8_lossy(a),
                String::from_utf8_lossy(b)
            );
        }
    }
    let key = Cred::captured(Zeroizing::new(TOKEN.to_vec()));
    for body in [
        &b"a&a=&b"[..],
        b"a=&a&a=x",
        b"%3D=1&=%3D1&=&",
        b"a%3D=b&a=%3Db&a%3Db",
        b"+=+&%20=%20&%20=+",
    ] {
        let params = form_params(body).expect("a form body");
        let signature = twilio_sign(TOKEN, URL, &params);
        assert_eq!(
            twilio_form_verify_either_cred(&key, URL, None, body, signature.as_bytes()),
            Ok(true),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

/// Bounded work on a hostile form body: comparing a huge pair against a small one stops at their
/// first decoded difference, as comparing the decoded pairs does. Scanning the whole huge name for
/// its `=` on every comparison makes a sort that picks it as a pivot cost (pairs x its length).
///
/// A read of a slice cannot be counted from outside, so this is timed, with a margin of three
/// orders of magnitude each way: 8000 comparisons that each scan an 8 MiB name read 64 GiB (many
/// seconds even optimised, minutes in a debug build), while 8000 lazy comparisons that stop at the
/// first byte take about a millisecond in a debug build. `black_box` keeps an optimised build
/// from hoisting the pure comparison out of the loop.
#[test]
fn red_a_pair_comparison_does_not_scan_a_huge_name() {
    use std::hint::black_box;
    let huge = b"x".repeat(8 << 20);
    let started = std::time::Instant::now();
    for _ in 0..4000 {
        assert_eq!(
            form_pair_cmp(black_box(&huge[..]), black_box(&b"a=1"[..])),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            form_pair_cmp(black_box(&b"a=1"[..]), black_box(&huge[..])),
            std::cmp::Ordering::Less
        );
    }
    let took = started.elapsed();
    assert!(
        took < std::time::Duration::from_secs(2),
        "8000 comparisons against an 8 MiB name took {took:?}"
    );
}

/// A form body may carry at most [`MAX_FORM_PAIRS`] non-empty pairs. One at the cap, genuinely
/// signed, verifies exactly as before (empty pairs between them do not count); one pair more is
/// refused before its signature is judged, even when it is genuinely signed.
#[test]
fn red_a_twilio_form_body_over_the_pair_cap_is_refused_and_one_at_it_verifies() {
    let key = Cred::captured(Zeroizing::new(TOKEN.to_vec()));
    let body = |pairs: usize| {
        (0..pairs)
            .map(|i| format!("p{i}=v{i}"))
            .collect::<Vec<_>>()
            .join("&&")
    };
    let at_cap = body(MAX_FORM_PAIRS);
    let params = form_params(at_cap.as_bytes()).expect("a form body");
    assert_eq!(params.len(), MAX_FORM_PAIRS);
    let signature = twilio_sign(TOKEN, URL, &params);
    assert_eq!(
        twilio_form_verify_either_cred(&key, URL, None, at_cap.as_bytes(), signature.as_bytes()),
        Ok(true)
    );

    let over = body(MAX_FORM_PAIRS + 1);
    let signature = twilio_sign(
        TOKEN,
        URL,
        &form_params(over.as_bytes()).expect("a form body"),
    );
    assert_eq!(
        twilio_form_verify_either_cred(&key, URL, None, over.as_bytes(), signature.as_bytes()),
        Err(FormRefusal::TooManyPairs)
    );
    assert_eq!(
        twilio_form_verify_either_cred(&key, URL, None, "a&".repeat(1 << 16).as_bytes(), PUBLISHED),
        Err(FormRefusal::TooManyPairs)
    );
}
