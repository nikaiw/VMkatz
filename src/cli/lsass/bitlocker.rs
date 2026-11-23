//! BitLocker FVEK discovery and CLI export.

#[cfg(feature = "sam")]
use std::path::Path;

use vmkatz::memory::PhysicalMemory;

#[cfg(feature = "sam")]
use super::snapshot::{SnapshotFormat, detect_snapshot_format};
use crate::cli::args::{Args, get_colors};
use crate::cli::output::export_bitlocker_fvek;

/// Extract `BitLocker` FVEK keys from physical memory, display results, and
/// optionally export as dislocker-compatible `.fvek` files.
pub(super) fn extract_and_output_bitlocker<L: PhysicalMemory>(
    layer: &L,
    args: &Args,
) -> Vec<vmkatz::lsass::bitlocker::BitLockerKey> {
    let t_bl = std::time::Instant::now();
    let keys = vmkatz::lsass::bitlocker::extract_bitlocker_keys(layer);
    if keys.is_empty() {
        log::debug!("BitLocker: no FVEK candidates found ({:?})", t_bl.elapsed());
        return keys;
    }
    eprintln!(
        "[+] BitLocker: {} FVEK candidate(s) found ({:?})",
        keys.len(),
        t_bl.elapsed()
    );

    let c = get_colors(args);

    println!(
        "\n{}[+] BitLocker FVEK ({} candidate(s)):{}\n",
        c.green,
        keys.len(),
        c.reset
    );

    for (i, key) in keys.iter().enumerate() {
        println!("  {}Candidate #{}{}", c.bold, i + 1, c.reset);
        println!("    Cipher  : {}{}{}", c.yellow, key.cipher, c.reset);
        println!(
            "    FVEK    : {}{}{}",
            c.yellow,
            hex::encode(&key.fvek),
            c.reset
        );
        if !key.tweak.is_empty() {
            println!(
                "    Tweak   : {}{}{}",
                c.yellow,
                hex::encode(&key.tweak),
                c.reset
            );
        }
        println!("    Pool tag: {} @ 0x{:x}", key.pool_tag, key.phys_addr);
        println!("    Method  : 0x{:04x} ({})", key.method, key.key_bits());
        println!("    Dislocker: dislocker-fuse -K fvek_{i}.bin -- /dev/sdX /mnt");
        println!();
    }

    if let Some(dir) = &args.bitlocker_fvek {
        export_bitlocker_fvek(&keys, dir);
    }

    keys
}

/// Scan a snapshot for BitLocker FVEK candidates without extracting LSASS credentials.
#[cfg(feature = "sam")]
pub fn extract_bitlocker_keys_from_snapshot(
    path: &Path,
) -> Vec<vmkatz::lsass::bitlocker::BitLockerKey> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let format = detect_snapshot_format(path, ext, false);

    macro_rules! try_layer {
        ($make_layer:expr_2021) => {
            match $make_layer {
                Ok(layer) => {
                    return vmkatz::lsass::bitlocker::extract_bitlocker_keys(&layer);
                }
                Err(e) => {
                    log::info!(
                        "BitLocker key extraction: failed to open {}: {}",
                        path.display(),
                        e
                    );
                    return Vec::new();
                }
            }
        };
    }

    match format {
        #[cfg(feature = "vbox")]
        SnapshotFormat::VBox => try_layer!(vmkatz::vbox::VBoxLayer::open(path)),
        #[cfg(feature = "qemu")]
        SnapshotFormat::QemuElf => try_layer!(vmkatz::qemu::QemuElfLayer::open(path)),
        #[cfg(feature = "qemu")]
        SnapshotFormat::QemuSavevm => try_layer!(vmkatz::qemu::QemuSavevmLayer::open(path)),
        #[cfg(feature = "hyperv")]
        SnapshotFormat::HypervBin => try_layer!(vmkatz::hyperv::HypervLayer::open(path)),
        #[cfg(feature = "hyperv")]
        SnapshotFormat::HypervVmrs => try_layer!(vmkatz::hyperv::VmrsLayer::open(path)),
        #[cfg(feature = "vmware")]
        SnapshotFormat::Vmware => try_layer!(vmkatz::vmware::VmwareLayer::open(path)),
        _ => Vec::new(),
    }
}
