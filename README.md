<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-webhook-signature

First-party signed kind:auth plugin cdylib: the webhook-signature auth module, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `webhook-signature` | `busbar-auth-webhook-signature-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-webhook-signature/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-webhook-signature/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-webhook-signature` is a `kind: auth` busbar plugin. A webhook sender that holds no busbar
credential signs each request with a secret it shares with the receiver; this plugin checks that
signature on the auth kind's inbound `verify`, so the request's handler never sees the secret. A
claim names it under the `webhook-signature` scheme alternative.

## Config

Configured under the `webhook-signature` module name. Settings are one JSON object:

| key | variant | meaning |
|---|---|---|
| `variant` | both, required | `twilio` or `standard-webhooks` |
| `origin` | `twilio`, required | the scheme and authority the sender requested, exactly as configured at the sender (e.g. `wss://edge.example.com`); no path, query or fragment. The signed URL is this plus the received path and query. A signature over the same URL with the scheme's default port added or removed (`:443` for `https`/`wss`, `:80` for `http`/`ws`) also verifies. |
| `tolerance_secs` | `standard-webhooks` | allowed distance between `webhook-timestamp` and now, either direction (default 300) |
| `subject` | both, optional | the identity a verified request is attributed to (default `webhook-signature:<variant>`) |

Variants:

* `twilio`: HMAC-SHA1 over the URL plus the sorted POST form parameters (a JSON POST binds its body
  through `bodySHA256`), in `X-Twilio-Signature`. A GET or HEAD (a Media Streams upgrade) signs the URL
  alone, so one that carries a body is rejected.
* `standard-webhooks`: the Standard Webhooks specification, HMAC-SHA256 over `id.timestamp.body`, in
  `webhook-id`, `webhook-timestamp` and `webhook-signature`.

### Secret

The signing secret (for `twilio` the account auth token, for `standard-webhooks` the base64 `whsec_`
secret) arrives through the secret kind as the Statement's `signing_secret` reference; the former name
`signing-secret` is still accepted, but set only one. Surrounding ASCII whitespace is trimmed first
(then `whsec_` is stripped); a secret empty after that is refused at open and refresh. It is never
logged or echoed.

### Verdicts

* none of the variant's headers present: pass (not this plugin's credential; a claim whose only
  alternative is this one is then refused);
* a signature that verifies (and, for `standard-webhooks`, a timestamp inside the tolerance): identity
  (the `subject`);
* anything else, including a partial header set, or a signed request whose body the host did not lend:
  reject. The client sees one opaque reject; the plugin log says why at info with
  `module = "webhook-signature"` and a short `reason` word (`stale`, `bad-timestamp`, `bad-signature`,
  `partial-headers`, `no-body`, `twilio-mismatch`, `body-digest-mismatch`, `bad-form-body`,
  `get-with-body`), never a signature, secret or body.

An instance names and strips only its own variant's header lines.

### Replay

A verified `standard-webhooks` identity carries a replay key (`standard-webhooks/<webhook-id>`) with
the rest of the tolerance window as its TTL; the kernel refuses the same webhook id again inside the
window. A `twilio` identity carries none: its signature has no nonce or timestamp to key on.

## Build

```bash
cargo build --release -p busbar-auth-webhook-signature-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
