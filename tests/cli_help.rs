//! Black-box check of the CLI surface through `--help`.

use std::process::Command;

#[test]
#[cfg(feature = "sam")]
fn help_lists_registry_flags() -> std::io::Result<()> {
    let out = Command::new(env!("CARGO_BIN_EXE_vmkatz"))
        .arg("--help")
        .output()?;
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("--no-mem-registry"), "{help}");
    assert!(help.contains("--registry-carve"), "{help}");
    Ok(())
}

#[test]
fn no_arguments_still_displays_help() -> std::io::Result<()> {
    let out = Command::new(env!("CARGO_BIN_EXE_vmkatz")).output()?;
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Usage:"));
    Ok(())
}

#[test]
fn options_without_an_input_do_not_report_success() -> std::io::Result<()> {
    let out = Command::new(env!("CARGO_BIN_EXE_vmkatz"))
        .arg("--verbose")
        .output()?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("No input file provided"));
    Ok(())
}

#[test]
#[cfg(feature = "disk")]
fn ls_and_cp_require_an_input_image() -> std::io::Result<()> {
    // The legacy --ls syntax now consumes the image name as its PATH argument.
    // Detect the missing image instead of returning a successful help screen.
    for args in [vec!["--ls", "image.vmdk"], vec!["--cp", "\\file", "output"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_vmkatz"))
            .args(args)
            .output()?;
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("No input file provided"));
    }
    Ok(())
}

#[test]
#[cfg(feature = "ntds.dit")]
fn all_reports_a_missing_disk_as_failure() -> std::io::Result<()> {
    let missing = std::env::temp_dir()
        .join(format!("vmkatz-missing-all-{}", std::process::id()))
        .join("missing.vmdk");
    let out = Command::new(env!("CARGO_BIN_EXE_vmkatz"))
        .arg(missing)
        .arg("--all")
        .output()?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Failed to open disk image"));
    Ok(())
}

#[test]
#[cfg(feature = "vmfs")]
fn explicit_vmfs_device_does_not_require_a_positional_image() -> std::io::Result<()> {
    let missing = std::env::temp_dir()
        .join(format!("vmkatz-missing-device-{}", std::process::id()))
        .join("device");
    let out = Command::new(env!("CARGO_BIN_EXE_vmkatz"))
        .arg("--vmfs-device")
        .arg(missing)
        .args(["--vmdk", "vm/disk-flat.vmdk", "--ls", "\\"])
        .output()?;
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(error.contains("VMFS open failed"), "{error}");
    assert!(!error.contains("No input file provided"), "{error}");
    Ok(())
}
