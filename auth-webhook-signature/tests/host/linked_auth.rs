// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_info_auth_modules_are_the_inbound_rows_only() {
    link();
    let linked = busbar_kernel::preflight::linked_auth_names();
    assert!(
        linked.len() > 1,
        "the default build links an outbound-only auth row beside the operator credential's: {linked:?}"
    );
    assert_eq!(
        busbar_core_admin::v1::service::auth_modules_compiled_in(),
        vec![
            "keys",
            config::operator_provider(),
            "busbar-auth-webhook-signature"
        ],
        "only inbound auth-chain modules are listed, 1.5.5's two first and the default build's \
         webhook-signature row after them (linked rows: {linked:?})"
    );
}
