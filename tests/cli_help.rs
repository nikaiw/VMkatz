//! Black-box check of the CLI surface through `--help`.
#![cfg(feature = "sam")]

use std::process::Command;

#[test]
fn help_lists_registry_flags() {
    let out = Command::new(env!("CARGO_BIN_EXE_vmkatz"))
        .arg("--help")
        .output()
        .expect("run vmkatz --help");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("--no-mem-registry"), "{help}");
    assert!(help.contains("--registry-carve"), "{help}");
}
