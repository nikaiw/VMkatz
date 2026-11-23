use crate::error::VmkatzError;
use crate::fs::EntryKind;
use crate::fs::recovery::ScanBudget;

use super::data::read_from_data_runs;
use super::mft::{MftBootstrap, ScanTarget, for_each_accessible_record, scan_for_targets};
use super::records::{DataRun, NtfsParams};
use super::{list_path_degraded, try_mftmirr_fallback, try_mftmirr_fallback_ntds};

#[test]
fn huge_run_reads_only_logical_file_and_preserves_sparse_holes() {
    let runs = [DataRun {
        vcn_start: 1,
        vcn_length: 1 << 34,
        lcn_start: 0,
    }];
    let mut reader = std::io::Cursor::new(vec![0xAB; 512]);
    let data = read_from_data_runs(&mut reader, &runs, 1024, 512, 0).unwrap();
    assert_eq!(&data[..512], &[0; 512]);
    assert_eq!(&data[512..], &[0xAB; 512]);
    assert_eq!(reader.position(), 512);
}

#[test]
fn oversized_recovered_file_is_rejected_before_io() {
    let mut reader = std::io::Cursor::new(Vec::<u8>::new());
    assert!(matches!(
        read_from_data_runs(&mut reader, &[], 8 << 40, 512, 0),
        Err(VmkatzError::RecoveryLimit(_))
    ));
    assert_eq!(reader.position(), 0);
}

#[test]
fn huge_mft_scan_stops_even_when_every_read_fails() {
    let bootstrap = MftBootstrap {
        params: NtfsParams {
            cluster_size: 4096,
            record_size: 1024,
            mft_position: 0,
            mftmirr_position: 0,
        },
        mft_runs: vec![],
        accessible_segments: vec![(0, 0, (8u64 << 40) / 1024)],
    };
    let mut reader = std::io::Cursor::new(Vec::<u8>::new());
    let mut budget = ScanBudget::new();
    assert!(matches!(
        for_each_accessible_record(&mut reader, &bootstrap, &mut budget, |_, _| false),
        Err(VmkatzError::RecoveryLimit(_))
    ));
    assert!(reader.position() <= 64 * 1024 * 1024);
}

#[test]
fn mft_retry_shares_the_first_pass_budget() {
    let bootstrap = MftBootstrap {
        params: NtfsParams {
            cluster_size: 4096,
            record_size: 1024,
            mft_position: 0,
            mftmirr_position: 0,
        },
        mft_runs: vec![],
        accessible_segments: vec![(0, 0, 32769)],
    };
    let mut reader = std::io::Cursor::new(Vec::<u8>::new());
    let wanted = [ScanTarget::Sam];
    assert!(matches!(
        scan_for_targets(&mut reader, &bootstrap, 0, &wanted, &wanted),
        Err(VmkatzError::RecoveryLimit(_))
    ));
}

pub const PART_OFF: u64 = 0x1000;
const CLUSTER: u64 = 512;

// MFT record numbers
const REC_MFT: u32 = 0;
const REC_DECOY_SYSTEM: u32 = 3;
const REC_DECOY_NTDSDIT: u32 = 4;
const REC_WINDOWS: u32 = 5;
const REC_SYSTEM32: u32 = 6;
const REC_CONFIG: u32 = 7;
const REC_NTDS: u32 = 8;
const REC_SYSTEM: u32 = 9;
const REC_NTDSDIT: u32 = 10;
const REC_SAM: u32 = 11;
const REC_SECURITY: u32 = 12;

// Cluster assignments (all clusters, 512 B each)
const CL_MFTMIRR: u64 = 2; // 4 records = 8 clusters
const CL_MFT: u64 = 16; // 16 records = 32 clusters
const CL_REGF_SYSTEM: u64 = 60;
const CL_ESE: u64 = 80;
const CL_REGF_SAM: u64 = 100;
const CL_REGF_SECURITY: u64 = 120;
const CL_DECOY: u64 = 140;

const REC_ROOT_DIR: u32 = 13;
const REC_ROOT_FILE: u32 = 14;
const ROOT_FILE_SIZE: u64 = 0x1234_5678;

const FILE_SIZE: u64 = 0x2000; // every file's $DATA size

/// Build a resident $FILE_NAME attribute (type 0x30).
fn file_name_attr(name: &str, parent: u64, size: u64) -> Vec<u8> {
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    let value_len = 0x42 + name_utf16.len() * 2;
    let value_offset = 0x18usize;
    let mut attr = vec![0u8; value_offset + value_len];
    attr[0..4].copy_from_slice(&0x30u32.to_le_bytes());
    let len = attr.len() as u32;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr[0x0A..0x0C].copy_from_slice(&(value_offset as u16).to_le_bytes());
    attr[0x10..0x14].copy_from_slice(&(value_len as u32).to_le_bytes());
    attr[0x14..0x16].copy_from_slice(&(value_offset as u16).to_le_bytes());
    let value = &mut attr[value_offset..];
    value[0..8].copy_from_slice(&parent.to_le_bytes());
    value[0x30..0x38].copy_from_slice(&size.to_le_bytes());
    value[0x40] = name_utf16.len() as u8;
    value[0x41] = 0; // Win32 namespace
    for (i, ch) in name_utf16.iter().enumerate() {
        value[0x42 + i * 2..0x44 + i * 2].copy_from_slice(&ch.to_le_bytes());
    }
    attr
}

/// Build a non-resident $DATA attribute (type 0x80) with one data run.
fn data_attr(lcn: u64, n_clusters: u64, real_size: u64) -> Vec<u8> {
    let runs_offset = 0x48usize;
    // Run header 0x21: length field 1 byte, offset field 2 bytes
    let mut runs = vec![0x21u8];
    runs.push(n_clusters as u8);
    runs.extend_from_slice(&lcn.to_le_bytes()[..2]);

    let mut attr = vec![0u8; runs_offset + runs.len()];
    attr[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    let len = attr.len() as u32;
    attr[4..8].copy_from_slice(&len.to_le_bytes());
    attr[8] = 1; // non-resident
    attr[0x18..0x20].copy_from_slice(&(n_clusters - 1).to_le_bytes()); // last VCN
    attr[0x20..0x22].copy_from_slice(&(runs_offset as u16).to_le_bytes());
    attr[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
    attr[runs_offset..].copy_from_slice(&runs);
    attr
}

/// Assemble a 1024-byte FILE record with a valid fixup array.
fn make_record(is_dir: bool, attrs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut rec = vec![0u8; 1024];
    rec[0..4].copy_from_slice(b"FILE");
    rec[4..6].copy_from_slice(&0x30u16.to_le_bytes()); // fixup array offset
    rec[6..8].copy_from_slice(&3u16.to_le_bytes()); // signature + 2 sector ends
    rec[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes()); // first attribute
    rec[0x16..0x18].copy_from_slice(&(if is_dir { 3u16 } else { 1u16 }).to_le_bytes()); // in-use (+dir)
    rec[0x18..0x1C].copy_from_slice(&1024u32.to_le_bytes()); // used size
    rec[0x1C..0x20].copy_from_slice(&1024u32.to_le_bytes()); // allocated size

    // Fixup array: on-disk sector ends carry the signature, the array holds
    // the replacements (mirroring what fixup_file_record expects).
    rec[0x30..0x32].copy_from_slice(&0x1122u16.to_le_bytes());
    rec[0x32..0x34].copy_from_slice(&0x3344u16.to_le_bytes());
    rec[0x34..0x36].copy_from_slice(&0x5566u16.to_le_bytes());
    rec[510..512].copy_from_slice(&0x1122u16.to_le_bytes());
    rec[1022..1024].copy_from_slice(&0x1122u16.to_le_bytes());

    let mut pos = 0x38;
    for attr in attrs {
        rec[pos..pos + attr.len()].copy_from_slice(&attr);
        pos += attr.len();
    }
    rec[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    rec
}

/// Write a "regf" header at a cluster.
fn put_regf(image: &mut [u8], cluster: u64) {
    let off = (PART_OFF + cluster * CLUSTER) as usize;
    image[off..off + 4].copy_from_slice(b"regf");
}

/// Place an MFT record at its number within the MFT extent.
fn put_mft(image: &mut [u8], rec: u32, r: &[u8]) {
    let off = (PART_OFF + CL_MFT * CLUSTER + u64::from(rec) * 1024) as usize;
    image[off..off + 1024].copy_from_slice(r);
}

/// Build a synthetic NTFS volume. `ntds_parent`/`system_parent` set the
/// parent MFT references of ntds.dit/SYSTEM (use record numbers beyond the
/// MFT extent to make the parent chain unverifiable).
pub fn build_volume(ntds_parent: u64, system_parent: u64, hives: bool, decoys: bool) -> Vec<u8> {
    let mut image = vec![0u8; 0x14000];

    // Boot sector
    let boot = PART_OFF as usize;
    image[boot + 3..boot + 11].copy_from_slice(b"NTFS    ");
    image[boot + 0x0B..boot + 0x0D].copy_from_slice(&512u16.to_le_bytes());
    image[boot + 0x0D] = 1; // sectors per cluster
    image[boot + 0x30..boot + 0x38].copy_from_slice(&CL_MFT.to_le_bytes());
    image[boot + 0x38..boot + 0x40].copy_from_slice(&CL_MFTMIRR.to_le_bytes());
    image[boot + 0x40] = 0xF6; // -10 → record size 2^10

    // File contents
    put_regf(&mut image, CL_REGF_SYSTEM);
    put_regf(&mut image, CL_REGF_SAM);
    put_regf(&mut image, CL_REGF_SECURITY);
    let off = (PART_OFF + CL_ESE * CLUSTER) as usize;
    image[off + 4..off + 8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);

    // Place an MFT record at its number within the MFT extent

    // Record 0 ($MFT): $DATA covering the 16-record MFT extent; mirrored
    // into $MFTMirr, which is how the fallback bootstraps MFT access.
    let mft_record = make_record(false, vec![data_attr(CL_MFT, 32, 16 * 1024)]);
    put_mft(&mut image, REC_MFT, &mft_record);
    let mirr = (PART_OFF + CL_MFTMIRR * CLUSTER) as usize;
    image[mirr..mirr + 1024].copy_from_slice(&mft_record);

    // Directory records (parents)
    put_mft(
        &mut image,
        REC_WINDOWS,
        &make_record(true, vec![file_name_attr("Windows", 5, 0)]),
    );
    put_mft(
        &mut image,
        REC_SYSTEM32,
        &make_record(
            true,
            vec![file_name_attr("System32", u64::from(REC_WINDOWS), 0)],
        ),
    );
    put_mft(
        &mut image,
        REC_CONFIG,
        &make_record(
            true,
            vec![file_name_attr("config", u64::from(REC_SYSTEM32), 0)],
        ),
    );
    put_mft(
        &mut image,
        REC_NTDS,
        &make_record(
            true,
            vec![file_name_attr("NTDS", u64::from(REC_WINDOWS), 0)],
        ),
    );

    // Registry hives and ntds.dit
    put_mft(
        &mut image,
        REC_SYSTEM,
        &make_record(
            false,
            vec![
                file_name_attr("SYSTEM", system_parent, 0),
                data_attr(CL_REGF_SYSTEM, FILE_SIZE / CLUSTER, FILE_SIZE),
            ],
        ),
    );
    put_mft(
        &mut image,
        REC_NTDSDIT,
        &make_record(
            false,
            vec![
                file_name_attr("ntds.dit", ntds_parent, 0),
                data_attr(CL_ESE, FILE_SIZE / CLUSTER, FILE_SIZE),
            ],
        ),
    );
    if hives {
        put_mft(
            &mut image,
            REC_SAM,
            &make_record(
                false,
                vec![
                    file_name_attr("SAM", u64::from(REC_CONFIG), 0),
                    data_attr(CL_REGF_SAM, FILE_SIZE / CLUSTER, FILE_SIZE),
                ],
            ),
        );
        put_mft(
            &mut image,
            REC_SECURITY,
            &make_record(
                false,
                vec![
                    file_name_attr("SECURITY", u64::from(REC_CONFIG), 0),
                    data_attr(CL_REGF_SECURITY, FILE_SIZE / CLUSTER, FILE_SIZE),
                ],
            ),
        );
    }

    // Root children (parent = record 5): one directory, one file with a known size
    put_mft(
        &mut image,
        REC_ROOT_DIR,
        &make_record(true, vec![file_name_attr("Users", 5, 0)]),
    );
    put_mft(
        &mut image,
        REC_ROOT_FILE,
        &make_record(
            false,
            vec![file_name_attr("pagefile.sys", 5, ROOT_FILE_SIZE)],
        ),
    );

    if decoys {
        // Same names but a wrong parent chain — pass 1 must reject them.
        put_mft(
            &mut image,
            REC_DECOY_SYSTEM,
            &make_record(
                false,
                vec![
                    file_name_attr("SYSTEM", u64::from(REC_SYSTEM32), 0),
                    data_attr(CL_REGF_SYSTEM, FILE_SIZE / CLUSTER, FILE_SIZE),
                ],
            ),
        );
        put_mft(
            &mut image,
            REC_DECOY_NTDSDIT,
            &make_record(
                false,
                vec![
                    file_name_attr("ntds.dit", u64::from(REC_CONFIG), 0),
                    data_attr(CL_DECOY, FILE_SIZE / CLUSTER, FILE_SIZE),
                ],
            ),
        );
    }

    image
}

#[test]
fn mftmirr_fallback_finds_hives_and_ntds_with_verified_parents() {
    let image = build_volume(u64::from(REC_NTDS), u64::from(REC_CONFIG), true, true);
    let mut reader = std::io::Cursor::new(image);

    let (ntds, system) = try_mftmirr_fallback_ntds(&mut reader, PART_OFF).unwrap();
    assert_eq!(ntds.len(), FILE_SIZE as usize);
    assert_eq!(ntds[4..8], [0xEF, 0xCD, 0xAB, 0x89]); // ESE magic
    assert_eq!(&system[0..4], b"regf");

    let (sam, sys, security) = try_mftmirr_fallback(&mut reader, PART_OFF).unwrap();
    assert_eq!(&sam[0..4], b"regf");
    assert_eq!(&sys[0..4], b"regf");
    let security = security.expect("SECURITY hive not found");
    assert_eq!(&security[0..4], b"regf");
}

#[test]
fn mftmirr_fallback_ntds_accepts_content_validated_records_without_parents() {
    // Parent records 998/999 are beyond the MFT extent — pass 1 cannot
    // verify the chain, so pass 2 must validate the content signatures.
    let image = build_volume(999, 998, false, false);
    let mut reader = std::io::Cursor::new(image);

    let (ntds, system) = try_mftmirr_fallback_ntds(&mut reader, PART_OFF).unwrap();
    assert_eq!(ntds[4..8], [0xEF, 0xCD, 0xAB, 0x89]);
    assert_eq!(&system[0..4], b"regf");
}

#[test]
fn mftmirr_fallback_reports_missing_sam() {
    let image = build_volume(u64::from(REC_NTDS), u64::from(REC_CONFIG), false, false);
    let mut reader = std::io::Cursor::new(image);

    let err = try_mftmirr_fallback(&mut reader, PART_OFF).unwrap_err();
    assert!(err.to_string().contains("SAM hive not found"));
}

#[test]
fn degraded_lists_root_children() {
    let image = build_volume(u64::from(REC_NTDS), u64::from(REC_CONFIG), true, false);
    let mut reader = std::io::Cursor::new(image);

    let entries = list_path_degraded(&mut reader, PART_OFF, "")
        .unwrap()
        .expect("root should resolve");
    let find = |n: &str| entries.iter().find(|e| e.name == n).expect(n);
    assert_eq!(find("Users").kind, EntryKind::Dir);
    assert_eq!(
        find("pagefile.sys").kind,
        EntryKind::File {
            size: ROOT_FILE_SIZE
        }
    );
    // Harness record 5 doubles as "Windows", so System32/NTDS also have
    // parent 5; the self-referencing record 5 itself must not be listed.
    assert_eq!(entries.len(), 4);
    assert!(entries.iter().all(|e| e.name != "Windows"));
    assert_eq!(entries[3].name, "pagefile.sys"); // files after dirs
}

#[test]
fn degraded_deep_path_unresolvable() {
    let image = build_volume(u64::from(REC_NTDS), u64::from(REC_CONFIG), true, false);
    let mut reader = std::io::Cursor::new(image);

    let res = list_path_degraded(&mut reader, PART_OFF, "Users\\Missing\\Deeper").unwrap();
    assert!(res.is_none());
    let res = list_path_degraded(&mut reader, PART_OFF, "/NoSuchDir").unwrap();
    assert!(res.is_none());
}
