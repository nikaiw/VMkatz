//! List and copy files within selected NTFS partitions.

use std::path::Path;

/// Format a byte count with binary units (B/KiB/MiB/GiB/TiB).
fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let units = ["KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < units.len() {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", units[i])
}

/// One listing line: `<DIR>` marker or right-aligned size, then the name.
fn format_entry(e: &vmkatz::fs::DirEntry) -> String {
    match e.kind {
        vmkatz::fs::EntryKind::Dir => format!("{:>10}  {}", "<DIR>", e.name),
        vmkatz::fs::EntryKind::File { size } => format!("{:>10}  {}", human_size(size), e.name),
    }
}

/// List `path` on each selected NTFS partition of `reader`.
pub fn run_ls<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    path: &str,
    partition: Option<u64>,
) -> anyhow::Result<()> {
    use vmkatz::fs::{ListOutcome, list_path};
    use vmkatz::fs::{find_ntfs_partitions, is_bitlocker_partition, select_partition};

    let offsets = select_partition(find_ntfs_partitions(reader)?, partition)?;
    for off in offsets {
        if is_bitlocker_partition(reader, off) {
            println!("[partition @ {off:#x}, BitLocker] skipped: encrypted volume");
            continue;
        }
        let outcome = match list_path(reader, off, path) {
            Ok(o) => o,
            Err(e) => {
                println!("[partition @ {off:#x}] listing failed: {e}");
                continue;
            }
        };
        match outcome {
            ListOutcome::Listed { entries, degraded } => {
                let note = if degraded { " (degraded: MFTMirr)" } else { "" };
                println!("[partition @ {off:#x}, NTFS]{note}");
                if entries.is_empty() {
                    println!("(empty)");
                }
                for e in &entries {
                    println!("{}", format_entry(e));
                }
            }
            ListOutcome::PathNotFound => {
                println!("[partition @ {off:#x}, NTFS]");
                println!("path not found: {path}");
            }
            ListOutcome::PathUnresolvableDegraded => {
                println!("[partition @ {off:#x}, NTFS] (degraded: MFTMirr)");
                println!(
                    "path cannot be resolved: NTFS index unusable and fallback scan could not locate it: {path}"
                );
            }
        }
    }
    Ok(())
}

/// Copy an NTFS file to a new local destination without overwriting existing files.
pub fn run_cp<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    src: &str,
    dst: &str,
    partition: Option<u64>,
) -> anyhow::Result<()> {
    use vmkatz::fs::{
        PartitionReader, copy_file_to_path, find_entry, find_ntfs_partitions,
        is_bitlocker_partition, navigate_to_dir, select_partition,
    };

    let src_norm = src.replace('/', "\\");
    let (parent, name) = src_norm.rsplit_once('\\').ok_or_else(|| {
        anyhow::anyhow!("--cp SRC must be an absolute guest path, e.g. \\Windows\\NTDS\\ntds.dit")
    })?;

    let offsets = select_partition(find_ntfs_partitions(reader)?, partition)?;
    for off in offsets {
        if is_bitlocker_partition(reader, off) {
            continue;
        }
        let mut pr = PartitionReader::new(reader, off);
        let Ok(ntfs) = ntfs::Ntfs::new(&mut pr) else {
            continue;
        };
        let Ok(root) = ntfs.root_directory(&mut pr) else {
            continue;
        };
        let dir = match navigate_to_dir(&ntfs, &root, &mut pr, parent) {
            Ok(d) => d,
            Err(e) => {
                log::info!("cp: navigate '{parent}' failed @ {off:#x}: {e}");
                continue;
            }
        };
        let file = match find_entry(&ntfs, &dir, &mut pr, name) {
            Ok(f) => f,
            Err(e) => {
                log::info!("cp: '{name}' not found @ {off:#x}: {e}");
                continue;
            }
        };
        let copied = copy_file_to_path(&file, &mut pr, Path::new(dst))
            .map_err(|e| anyhow::anyhow!("--cp: cannot copy to {dst}: {e}"))?;
        eprintln!("[+] cp: wrote {copied} bytes from '{src}' (partition {off:#x}) to {dst}");
        return Ok(());
    }
    anyhow::bail!("--cp: '{src}' not found on any NTFS partition")
}

#[cfg(test)]
mod tests {
    use super::{format_entry, human_size};
    use vmkatz::fs::{DirEntry, EntryKind};

    #[test]
    fn human_size_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(4096), "4.0 KiB");
        assert_eq!(human_size(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }

    #[test]
    fn format_entry_dir_vs_file() {
        let d = format_entry(&DirEntry {
            name: "Windows".into(),
            kind: EntryKind::Dir,
        });
        assert!(d.contains("<DIR>") && d.contains("Windows"));
        let f = format_entry(&DirEntry {
            name: "a.txt".into(),
            kind: EntryKind::File { size: 4096 },
        });
        assert!(f.contains("4.0 KiB") && f.contains("a.txt") && !f.contains("<DIR>"));
    }

    #[test]
    fn run_ls_lists_root_when_fixture_present() {
        let p = std::path::Path::new("/tmp/test.qcow2");
        if !p.exists() {
            eprintln!("SKIP run_ls_lists_root_when_fixture_present: /tmp/test.qcow2 absent");
            return;
        }
        let mut disk = vmkatz::disk::open_disk(p).unwrap();
        super::run_ls(&mut disk, "", None).unwrap();
    }
}
