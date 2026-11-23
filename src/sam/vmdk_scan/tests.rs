use super::*;

fn hbin(name: &str, size: usize) -> Vec<u8> {
    let mut data = vec![0; size];
    data[..4].copy_from_slice(b"hbin");
    data[8..12].copy_from_slice(&(size as u32).to_le_bytes());
    data[0x20..0x24].copy_from_slice(&(-256i32).to_le_bytes());
    data[0x24..0x26].copy_from_slice(b"nk");
    data[0x26..0x28].copy_from_slice(&0x20u16.to_le_bytes());
    data[0x6C..0x6E].copy_from_slice(&(name.len() as u16).to_le_bytes());
    data[0x70..0x70 + name.len()].copy_from_slice(name.as_bytes());
    data
}

fn registry_file(name: &str, size: usize) -> Vec<u8> {
    let mut data = vec![0; CLUSTER_SIZE];
    data[..4].copy_from_slice(b"regf");
    data[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
    data[0x28..0x2C].copy_from_slice(&((size - CLUSTER_SIZE) as u32).to_le_bytes());
    let path = format!("CONFIG\\{name}");
    data[0x30..0x30 + path.len()].copy_from_slice(path.as_bytes());
    data.extend(hbin(name, size - CLUSTER_SIZE));
    data
}

fn recover_image(
    tag: &str,
    data: &[u8],
    capacity: Option<u64>,
) -> Result<(super::super::HiveFiles, Option<[u8; 16]>)> {
    let dir = std::env::temp_dir().join(format!("vmkatz-grains-{}-{tag}", std::process::id()));
    std::fs::create_dir(&dir)?;
    std::fs::write(dir.join("flat.vmdk"), data)?;
    let descriptor = dir.join("disk.vmdk");
    std::fs::write(
        &descriptor,
        format!(
            "RW {} FLAT \"flat.vmdk\" 0\n",
            capacity.unwrap_or(data.len() as u64) / 512
        ),
    )?;
    let mut disk = VmdkDisk::open(&descriptor)?;
    let result = scan_vmdk_grains_for_hives(&mut disk);
    drop(disk);
    std::fs::remove_dir_all(dir)?;
    result
}

#[test]
fn complete_files_keep_priority_and_stop_after_sam_and_system() {
    let sam = registry_file("SAM", 0x2000);
    let system = registry_file("SYSTEM", MIN_SYSTEM_HIVE_SIZE as usize);
    let security = registry_file("SECURITY", 0x2000);
    for security_first in [true, false] {
        let mut image = sam.clone();
        if security_first {
            image.extend_from_slice(&security);
        }
        image.extend_from_slice(&system);
        if !security_first {
            image.extend_from_slice(&security);
        }
        let ((actual_sam, actual_system, actual_security), key) =
            recover_image("complete", &image, None).unwrap();
        assert_eq!(actual_sam, sam);
        assert_eq!(actual_system, system);
        assert_eq!(
            actual_security.as_deref(),
            security_first.then_some(security.as_slice())
        );
        assert!(key.is_none());
    }
}

#[test]
fn contiguous_hbins_recover_without_registry_headers() {
    let sam = hbin("SAM", CLUSTER_SIZE);
    let system = hbin("SYSTEM", MIN_SYSTEM_HIVE_SIZE as usize - CLUSTER_SIZE);
    let security = hbin("SECURITY", CLUSTER_SIZE);
    let image = [sam.as_slice(), system.as_slice(), security.as_slice()].concat();
    let ((actual_sam, actual_system, actual_security), key) =
        recover_image("contiguous", &image, None).unwrap();
    assert_eq!(&actual_sam[CLUSTER_SIZE..], sam);
    assert_eq!(&actual_system[CLUSTER_SIZE..], system);
    assert_eq!(&actual_security.unwrap()[CLUSTER_SIZE..], security);
    assert!(key.is_none());
}

#[test]
fn small_system_survives_failed_fragmented_recovery() {
    let sam = hbin("SAM", CLUSTER_SIZE);
    let system = hbin("SYSTEM", CLUSTER_SIZE);
    let image = [sam.as_slice(), system.as_slice()].concat();
    let ((actual_sam, actual_system, security), key) =
        recover_image("small-fallback", &image, None).unwrap();
    assert_eq!(&actual_sam[CLUSTER_SIZE..], sam);
    assert_eq!(&actual_system[CLUSTER_SIZE..], system);
    assert!(security.is_none());
    assert!(key.is_none());
}

#[test]
fn fragmented_system_replaces_the_small_contiguous_fallback() {
    let mut image = hbin("SAM", CLUSTER_SIZE);
    let system_root = hbin("SYSTEM", CLUSTER_SIZE);
    image.extend_from_slice(&system_root);
    image.extend_from_slice(&[0; CLUSTER_SIZE]); // Break the contiguous chain.
    let block_size = 1024 * 1024;
    for index in 0..4 {
        let mut block = vec![0xA0 + index as u8; block_size];
        block[..4].copy_from_slice(b"hbin");
        block[4..8].copy_from_slice(&((CLUSTER_SIZE + index * block_size) as u32).to_le_bytes());
        block[8..12].copy_from_slice(&(block_size as u32).to_le_bytes());
        image.extend_from_slice(&block);
    }
    let ((_, system, _), key) = recover_image("fragmented", &image, None).unwrap();
    assert_eq!(system.len(), CLUSTER_SIZE + 8 * 1024 * 1024);
    assert_eq!(&system[CLUSTER_SIZE..2 * CLUSTER_SIZE], system_root);
    assert_eq!(
        &system[2 * CLUSTER_SIZE..2 * CLUSTER_SIZE + 4 * block_size],
        &image[3 * CLUSTER_SIZE..]
    );
    assert!(
        system[2 * CLUSTER_SIZE + 4 * block_size..]
            .iter()
            .all(|&b| b == 0)
    );
    assert!(key.is_none());
}

#[test]
fn eight_tib_capacity_is_rejected_before_recovery() {
    let result = recover_image("large", &[0; CLUSTER_SIZE], Some(8u64 << 40));
    assert!(
        matches!(result, Err(VmkatzError::RecoveryLimit(message)) if message.contains("above 1 GiB"))
    );
}

#[test]
fn scattered_blocks_are_bounded_by_their_declared_total_size() {
    let mut block = vec![0; CLUSTER_SIZE];
    block[..4].copy_from_slice(b"hbin");
    block[4..8].copy_from_slice(&0x1000u32.to_le_bytes()); // Not a root candidate.
    block[8..12].copy_from_slice(&0x100000u32.to_le_bytes());
    let image = block.repeat(65); // Small fixture advertising more than 64 MiB of blocks.
    assert!(matches!(
        recover_image("block-limit", &image, None),
        Err(VmkatzError::RecoveryLimit(
            "scattered hive blocks exceed 64 MiB"
        ))
    ));
}

#[test]
fn missing_hives_keep_their_diagnostic() {
    let result = recover_image("missing", &[0; CLUSTER_SIZE], None);
    assert!(matches!(result, Err(VmkatzError::DecryptionError(message))
        if message == "VMDK grain scan: SAM not found, SYSTEM not found"));
}

#[test]
fn candidate_limit_stops_before_adding_more_records() {
    let mut candidates = HiveCandidates {
        hbins: vec![(0, 0, 0x1000); MAX_CANDIDATES],
        ..HiveCandidates::default()
    };
    assert!(matches!(
        candidates.scan_grain(0, &hbin("SAM", CLUSTER_SIZE)),
        Err(VmkatzError::RecoveryLimit(
            "VMDK scan exceeds 65536 candidates"
        ))
    ));
    assert_eq!(candidates.hbins.len(), MAX_CANDIDATES);
    assert_eq!(candidates.roots.len(), 0);
}
