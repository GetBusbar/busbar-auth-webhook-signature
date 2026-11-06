<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-webhook-signature

First-party signed kind:auth plugin cdylib: the webhook-signature auth module, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `webhook-signature` | `busbar-auth-webhook-signature-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

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

The default subject is shared by instances of the same variant. Set an explicit, distinct subject
when deliveries from different configured receivers must be attributed to different identities.

Variants:

* `twilio`: HMAC-SHA1 over the URL plus the sorted POST form parameters (a JSON POST binds its body
  through `bodySHA256`), in `X-Twilio-Signature`. A GET or HEAD (a Media Streams upgrade) signs the URL
  alone, so one that carries a body is rejected. A form body may carry at most 1024 non-empty
  `name=value` pairs, far above what Twilio sends; one with more is rejected before its signature is
  judged, so an unauthenticated body costs about one copy of itself to judge.
* `standard-webhooks`: the Standard Webhooks specification, HMAC-SHA256 over `id.timestamp.body`, in
  `webhook-id`, `webhook-timestamp` and `webhook-signature`.

### Secret

The signing secret (for `twilio` the account auth token, for `standard-webhooks` the base64 `whsec_`
secret) arrives through the secret kind as the Statement's `signing_secret` reference. Surrounding ASCII
whitespace is trimmed first (then `whsec_` is stripped); a secret empty after that is refused at open and refresh. A refused
refresh reports failure and leaves the last accepted pair of settings and secret intact. It is
never logged or echoed.

### Verdicts

* none of the variant's headers present: pass (not this plugin's credential; a claim whose only
  alternative is this one is then refused);
* a signature that verifies (and, for `standard-webhooks`, a timestamp inside the tolerance): identity
  (the `subject`);
* anything else, including a partial header set, or a request whose signature covers a body (every
  `standard-webhooks` delivery, every `twilio` request other than GET or HEAD) that the host did not
  lend: reject. The client sees one opaque reject. The reject names a short `reason` word (`stale`,
  `bad-timestamp`, `bad-signature`, `partial-headers`, `no-body`, `twilio-mismatch`,
  `body-digest-mismatch`, `bad-form-body`, `too-many-form-pairs`, `get-with-body`), which the host
  writes to the operator's logs; the plugin log also records it at info with
  `module = "webhook-signature"`, the variant and the escaped configured subject. Neither ever
  carries a signature, secret or body.

An instance names and strips only its own variant's header lines.

### Replay

A verified `standard-webhooks` identity carries a replay key naming the attempt: its
`webhook-timestamp` and its `webhook-id`, `standard-webhooks/<webhook-timestamp>/<webhook-id>` (the
timestamp as its decimal value; a webhook-id that is not UTF-8 is keyed
`standard-webhooks-raw/<webhook-timestamp>/<lower-case hex>`, so distinct byte ids cannot collapse
into one key through lossy text conversion). Its TTL is the rest of the tolerance window in which
that timestamp is acceptable, plus one second. The kernel refuses the same key again inside the
window, so a byte-identical replay of an admitted request is refused, and after the window it is
stale anyway. The key is not the webhook-id alone: per the Standard Webhooks spec a sender's retry
keeps the webhook-id but carries a new `webhook-timestamp` and a new signature, so a legitimate
retry inside the tolerance window is a new attempt and is accepted. A receiver that must process
each event once deduplicates on the webhook-id itself, as the spec's idempotency guidance says. A
`twilio` identity carries none: its signature has no nonce or timestamp to key on.

The kernel stores each claim under the configured provider name (the `identity-providers:` key,
`<provider>/<key>`), so two differently configured instances never share a claim; one provider
named in both the data-plane and admin chains, or on several nodes sharing one store, is one sender
and one secret and shares its claims on purpose.

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
