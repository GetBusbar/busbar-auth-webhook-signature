// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `webhook-signature` auth for busbar: its logic and its door.
//!
//! An inbound `kind: auth` plugin on the auth kind's memory ABI (THE DESIGN §11.4, §11.6): one
//! `verify` call per request, judged on the spot, no I/O, no cache. [`door::door`] is the
//! plugin's `plugin_door!` door, built by the SDK's `auth_verify_door!` over [`WebhookSignature`]. A
//! build that links this crate registers it as the `webhook-signature` row; the sibling
//! `busbar-auth-webhook-signature-plugin` cdylib exports the SAME door as `busbar_plugin_door`.
//! This crate exports no symbol.
//!
//! ## What it verifies
//!
//! The Twilio variant: `X-Twilio-Signature` is `base64(HMAC-SHA1(auth_token, url))`, where `url` is
//! the full URL Twilio was configured with (the Media Streams WebSocket upgrade, a GET with no form
//! parameters, is signed over the URL alone). The scheme the operator's Twilio account holds
//! (`wss` by default) and, behind a proxy, the public host are settings; the path and query are the
//! request's, raw as received.
//!
//! * the header absent: [`Verdict::Pass`] (not this plugin's credential; the kernel refuses a
//!   request every inbound plugin abstained on, so a missing signature is 401 end to end);
//! * present and equal (constant time): an identity, subject `twilio`;
//! * present and anything else: [`Verdict::Reject`].
//!
//! Twilio carries no replay rule (1.5.5 had none: Twilio sends no nonce), so the identity names no
//! replay key.
//!
//! ## What it does not, at this busbar pin
//!
//! `verify` hands a plugin the SHA-256 of a request body, never the body. A Twilio form POST is
//! signed over the sorted form parameters and a Standard Webhooks signature is an HMAC over
//! `id.timestamp.body`; neither can be recomputed from a hash, so both fail closed here (a form POST
//! with parameters is rejected, never admitted unchecked), and the identity carries no
//! `replay_key` for a Standard Webhooks `webhook-id`. Both land with the body and replay fields of
//! the auth ABI.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod sha1;

use busbar_contract::abi::auth::AuthTail;
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_tail, Verdict, VerifiedIdentity, VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::media::base64_encode;
use busbar_contract::redacted::constant_time_eq;

/// The module name: the auth chain entry this plugin answers.
pub const MODULE_NAME: &str = "webhook-signature";

/// The carrier Twilio signs with (lower-case).
pub const TWILIO_SIGNATURE_HEADER: &str = "x-twilio-signature";

/// The principal a verified Twilio request identifies as.
pub const TWILIO_SUBJECT: &str = "twilio";

/// The settings key whose value is the Twilio auth token's secret reference; the kernel resolves it
/// into `OpenIn.secrets[0]`.
pub const AUTH_TOKEN_KEY: &str = "auth_token";

/// Refused at `open`: the settings are not a JSON object of this plugin's keys.
pub const BAD_SETTINGS: &str =
    "webhook-signature settings must be a JSON object {auth_token, scheme?, host?}";

/// Refused at `open`: no auth token was resolved.
pub const NO_TOKEN: &str =
    "webhook-signature needs `auth_token`: a secret reference to the Twilio auth token";

/// The URL scheme Twilio signs a Media Streams upgrade under when settings do not say.
const DEFAULT_SCHEME: &str = "wss";

/// The `X-Twilio-Signature` of `url` under `token`: `base64(HMAC-SHA1(token, url))`.
#[must_use]
pub fn twilio_signature(token: &[u8], url: &str) -> String {
    base64_encode(&sha1::hmac_sha1(token, url.as_bytes()))
}

/// Judge one presented signature (`None` = no header) against the URL it should have signed.
#[must_use]
pub fn authenticate_twilio(token: &[u8], url: &str, presented: Option<&[u8]>) -> Verdict {
    let Some(presented) = presented else {
        return Verdict::Pass;
    };
    let Ok(presented) = std::str::from_utf8(presented) else {
        return Verdict::Reject;
    };
    if constant_time_eq(presented.trim(), &twilio_signature(token, url)) {
        Verdict::Identity(VerifiedIdentity {
            subject: TWILIO_SUBJECT.to_string(),
            provider: Some(MODULE_NAME.to_string()),
            ..VerifiedIdentity::default()
        })
    } else {
        Verdict::Reject
    }
}

/// THE PLUGIN: the Twilio auth token and the URL shape its signatures cover.
pub struct WebhookSignature {
    token: Vec<u8>,
    scheme: String,
    host: Option<String>,
}

impl std::fmt::Debug for WebhookSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSignature").finish_non_exhaustive()
    }
}

impl WebhookSignature {
    /// The URL a request's signature covers: scheme, the configured or received host, and the path
    /// and query raw as received.
    fn url(&self, request: &VerifyView<'_>) -> Option<String> {
        let authority = match &self.host {
            Some(h) => h.as_str(),
            None => std::str::from_utf8(request.authority()).ok()?,
        };
        let path = std::str::from_utf8(request.path()).ok()?;
        let mut url = format!("{}://{authority}{path}", self.scheme);
        if let Some(q) = request.query() {
            url.push('?');
            url.push_str(std::str::from_utf8(q).ok()?);
        }
        Some(url)
    }
}

impl VerifyPlugin for WebhookSignature {
    fn open(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, &'static str> {
        let serde_json::Value::Object(s) =
            serde_json::from_slice(settings).map_err(|_| BAD_SETTINGS)?
        else {
            return Err(BAD_SETTINGS);
        };
        let text = |key: &str| match s.get(key) {
            None => Ok(None),
            Some(serde_json::Value::String(v)) => Ok(Some(v.clone())),
            Some(_) => Err(BAD_SETTINGS),
        };
        let token = secrets.first().filter(|t| !t.is_empty()).ok_or(NO_TOKEN)?;
        Ok(Self {
            token: token.to_vec(),
            scheme: text("scheme")?.unwrap_or_else(|| DEFAULT_SCHEME.to_string()),
            host: text("host")?,
        })
    }

    fn verify(&self, request: &VerifyView<'_>) -> Verdict {
        let presented = request.carrier(TWILIO_SIGNATURE_HEADER);
        if presented.is_none() {
            return Verdict::Pass;
        }
        match self.url(request) {
            Some(url) => authenticate_twilio(&self.token, &url, presented),
            None => Verdict::Reject,
        }
    }
}

/// The settings keys that hold secret references.
const SECRET_REFS: &[AbiStr] = &[abi_str(AUTH_TOKEN_KEY)];

/// The credential line `verify` reads, the Statement's carrier word mark.
const CARRIERS: &[MarkWord] = &[carrier(TWILIO_SIGNATURE_HEADER)];

/// The auth tail: inbound only, judged on the spot, nothing cached (the verdict is a function of
/// the URL and the token, and a rotated token must take effect at once).
const TAIL: &AuthTail = &verify_tail(0);

/// What the plugin states: its name, version, the concurrency it serves, its one secret and its
/// one carrier.
pub const STATEMENT: Statement = with_tail(
    Statement {
        secret_refs: SECRET_REFS.as_ptr(),
        secret_refs_len: SECRET_REFS.len(),
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement(MODULE_NAME, env!("CARGO_PKG_VERSION"), 64)
    },
    TAIL,
);

/// THE DOOR: `door::door`, the plugin's `DoorFn`. A build that links this crate registers it as the
/// `webhook-signature` row; `busbar-auth-webhook-signature-plugin` exports it as
/// `busbar_plugin_door`.
pub mod door {
    busbar_contract::auth_verify_door!(super::WebhookSignature, super::STATEMENT);
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
