// Quick helper: extract a single file (or list a directory) from an NTFS partition
// inside any vmkatz-supported disk image. For finding chrome's elevation_service.exe.
//
// Usage:
//   cargo run --release --features chrome --bin extract_file <disk> ls <path>
//   cargo run --release --features chrome --bin extract_file <disk> get <path> <out>

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: extract_file <disk> ls|get <path> [out]");
        std::process::exit(1);
    }
    let disk_path = PathBuf::from(&args[1]);
    let cmd = &args[2];
    let path = &args[3];

    let mut disk = vmkatz::disk::open_disk(&disk_path)?;
    let partitions = vmkatz::sam::find_ntfs_partitions(&mut disk).unwrap_or_default();
    if partitions.is_empty() {
        anyhow::bail!("no NTFS partitions found");
    }

    for &part_offset in &partitions {
        if vmkatz::sam::is_bitlocker_partition(&mut disk, part_offset) {
            continue;
        }
        let mut part_reader = vmkatz::sam::PartitionReader::new(&mut disk, part_offset);
        let ntfs = match ntfs::Ntfs::new(&mut part_reader) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let root = ntfs.root_directory(&mut part_reader)?;
        if cmd == "get" {
            let (parent, name) = match path.rsplit_once('\\') {
                Some((p, n)) => (p, n),
                None => {
                    eprintln!("get: path needs a parent dir");
                    continue;
                }
            };
            let parent_dir = match vmkatz::sam::navigate_to_dir(&ntfs, &root, &mut part_reader, parent) {
                Ok(d) => d,
                Err(e) => { eprintln!("navigate {} fail at part 0x{:x}: {}", parent, part_offset, e); continue; }
            };
            let file = match vmkatz::sam::find_entry(&ntfs, &parent_dir, &mut part_reader, name) {
                Ok(f) => f,
                Err(e) => { eprintln!("find {} fail: {}", name, e); continue; }
            };
            let data = vmkatz::sam::read_file_data(&file, &mut part_reader)?;
            let out = &args[4];
            std::fs::write(out, &data)?;
            eprintln!("wrote {} bytes to {}", data.len(), out);
            return Ok(());
        }
        let dir = match vmkatz::sam::navigate_to_dir(&ntfs, &root, &mut part_reader, path) {
            Ok(d) => d,
            Err(e) => { eprintln!("navigate fail at part 0x{:x}: {}", part_offset, e); continue; }
        };
        if cmd == "ls" {
            let entries = vmkatz::sam::list_directory(&ntfs, &dir, &mut part_reader)?;
            for (name, is_dir) in entries {
                println!("{}\t{}", if is_dir { "DIR " } else { "FILE" }, name);
            }
            return Ok(());
        }
    }
    anyhow::bail!("path not found on any NTFS partition")
}
