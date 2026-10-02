<!-- fleet:header:begin (rendered by `busbar-release plugin sync` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-webhook-signature

First-party signed kind:auth plugin cdylib: the webhook-signature auth module, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `webhook-signature` | `busbar-auth-webhook-signature-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-webhook-signature/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-webhook-signature/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-webhook-signature` is a `kind: auth` busbar plugin.

## Config

Configured under the `webhook-signature` module name.

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
