// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

fn main() {
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = root.join("src/host_tests/linked_auth.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    let generated = format!(
        "#[doc(hidden)]\n#[macro_export]\nmacro_rules! __busbar_context_tests {{\n    (linked_auth, $name:literal) => {{\n        #[path = {source:?}]\n        mod owner_linked_auth;\n    }};\n}}\n"
    );
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("host_test_macros.rs"), generated).unwrap();
}
