// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN** (busbar TODO ABI-b4; OWNER 2026-10-03:
//! plugins test themselves against busbar). busbar's suite, at the commit this repo pins
//! (`.busbar-ref`), drives the `webhook-signature` door two ways through the one loader: LINKED (the
//! logic crate's `door`) and DROPPED IN (this crate's built cdylib), over the auth kind's inbound
//! script with the inputs in `conformance.json` (the `twilio` variant over the suite's fixed request,
//! `GET https://conformance.invalid/`, its signature pre-computed under the test signing secret);
//! every step's crossings exactly at the script's pin, the two folds equal, and the suite's RED
//! arms kept. `plugin-ci.yml` runs it under `--release`.

busbar_plugin_loader::conformance_suite! {
    door: busbar_auth_webhook_signature::door,
    cdylib: "busbar_auth_webhook_signature_plugin",
    inputs: include_str!("conformance.json"),
}
