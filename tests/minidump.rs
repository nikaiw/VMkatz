use std::path::Path;
use vmkatz::memory::VirtualMemory;
use vmkatz::minidump::Minidump;

/// Synthetic minidump: header + 1 `SystemInfoStream` + 1 `Memory64ListStream` with 1 region.
fn make_test_minidump() -> Vec<u8> {
    let mut data = Vec::new();

    // Header (32 bytes)
    data.extend_from_slice(&0x504D_444Du32.to_le_bytes()); // Signature "MDMP"
    data.extend_from_slice(&0x0000_A793u32.to_le_bytes()); // Version
    data.extend_from_slice(&2u32.to_le_bytes()); // NumberOfStreams
    data.extend_from_slice(&32u32.to_le_bytes()); // StreamDirectoryRva
    data.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
    data.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    data.extend_from_slice(&2u64.to_le_bytes()); // Flags

    // Stream directory (2 entries × 12 bytes = 24 bytes, starts at offset 32)
    let sysinfo_rva = 32 + 24; // 56
    let sysinfo_size = 56u32;
    data.extend_from_slice(&7u32.to_le_bytes()); // STREAM_TYPE_SYSTEM_INFO
    data.extend_from_slice(&sysinfo_size.to_le_bytes());
    data.extend_from_slice(&(sysinfo_rva as u32).to_le_bytes());

    let mem64_rva = sysinfo_rva + sysinfo_size as usize; // 112
    let mem64_size = 16 + 16; // header(16) + 1 descriptor(16) = 32
    data.extend_from_slice(&9u32.to_le_bytes()); // STREAM_TYPE_MEMORY64_LIST
    data.extend_from_slice(&(mem64_size as u32).to_le_bytes());
    data.extend_from_slice(&(mem64_rva as u32).to_le_bytes());

    // SystemInfoStream (56 bytes at offset 56)
    data.extend_from_slice(&9u16.to_le_bytes()); // ProcessorArchitecture = AMD64
    data.extend_from_slice(&0u16.to_le_bytes()); // ProcessorLevel
    data.extend_from_slice(&0u16.to_le_bytes()); // ProcessorRevision
    data.extend_from_slice(&[1u8]); // NumberOfProcessors
    data.extend_from_slice(&[1u8]); // ProductType
    data.extend_from_slice(&10u32.to_le_bytes()); // MajorVersion
    data.extend_from_slice(&0u32.to_le_bytes()); // MinorVersion
    data.extend_from_slice(&19045u32.to_le_bytes()); // BuildNumber
    data.extend_from_slice(&2u32.to_le_bytes()); // PlatformId
    data.extend_from_slice(&0u32.to_le_bytes()); // CSDVersionRva
    data.extend_from_slice(&0u16.to_le_bytes()); // SuiteMask
    data.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    data.extend_from_slice(&[0u8; 24]); // CPU_INFORMATION

    // Memory64ListStream at offset 112
    let memory_data_start = mem64_rva + mem64_size; // 144
    data.extend_from_slice(&1u64.to_le_bytes()); // NumberOfMemoryRanges
    data.extend_from_slice(&(memory_data_start as u64).to_le_bytes()); // BaseRva

    data.extend_from_slice(&0x1000u64.to_le_bytes()); // StartOfMemoryRange
    data.extend_from_slice(&8u64.to_le_bytes()); // DataSize

    // Memory data: 8 bytes at offset 144
    data.extend_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());

    data
}

#[test]
fn parse_synthetic_minidump() {
    let data = make_test_minidump();
    let mdmp = Minidump::parse(data).expect("parse failed");

    assert_eq!(mdmp.build_number, 19045);
    assert_eq!(mdmp.major_version, 10);
    assert_eq!(mdmp.minor_version, 0);
    assert_eq!(mdmp.modules.len(), 0);

    // Read back the memory region
    let val = mdmp.read_virt_u64(0x1000).expect("read failed");
    assert_eq!(val, 0xDEAD_BEEF_CAFE_BABE);
}

#[test]
fn read_outside_region_fails() {
    let data = make_test_minidump();
    let mdmp = Minidump::parse(data).expect("parse failed");

    // Address outside any region should fail
    assert!(mdmp.read_virt_u64(0x2000).is_err());
}

#[test]
fn parse_real_minidump() {
    let path = Path::new("lsass.dmp");
    if !path.exists() {
        return;
    }

    let mdmp = Minidump::open(path).expect("failed to parse lsass.dmp");

    assert!(mdmp.build_number > 0, "build number should be > 0");
    assert!(!mdmp.modules.is_empty(), "should have modules");
    assert!(
        mdmp.modules.iter().any(|m| !m.full_name.is_empty()),
        "at least some modules should have names"
    );

    let has_lsasrv = mdmp.modules.iter().any(|m| m.base_name == "lsasrv.dll");
    assert!(has_lsasrv, "lsasrv.dll should be in module list");

    let lsasrv = mdmp
        .modules
        .iter()
        .find(|m| m.base_name == "lsasrv.dll")
        .unwrap();
    let mz = mdmp
        .read_virt_u16(lsasrv.base)
        .expect("should read MZ header");
    assert_eq!(mz, 0x5A4D, "lsasrv.dll should start with MZ");
}

/// End-to-end credential extraction from lsass.dmp.
/// Validates that vmkatz extracts the same NT hash as pypykatz.
#[test]
fn extract_credentials_from_real_minidump() {
    let path = Path::new("lsass.dmp");
    if !path.exists() {
        return;
    }

    let mdmp = Minidump::open(path).expect("failed to parse lsass.dmp");
    let region_ranges = mdmp.region_ranges();
    let credentials = vmkatz::lsass::finder::extract_credentials_from_minidump(
        &mdmp,
        &mdmp.modules,
        mdmp.build_number,
        &region_ranges,
        mdmp.arch,
    )
    .expect("credential extraction should succeed");

    // Should find at least one credential with MSV data
    let msv_creds: Vec<_> = credentials.iter().filter(|c| c.msv.is_some()).collect();
    assert!(
        !msv_creds.is_empty(),
        "should extract at least one MSV credential from lsass.dmp"
    );

    // Validate known-good NT hash for user@SECLAB (Win10 19045)
    let expected_nt = "bbf7d1528afa8b0fdd40a5b2531bbb6d";
    let expected_sha1 = "abdcba254aec226bb7762f709753084d3985b7d3";

    let found_nt = msv_creds.iter().any(|c| {
        if let Some(msv) = &c.msv {
            hex::encode(msv.nt_hash) == expected_nt
        } else {
            false
        }
    });
    assert!(found_nt, "should find NT hash {expected_nt} (user@SECLAB)");

    let found_sha1 = msv_creds.iter().any(|c| {
        if let Some(msv) = &c.msv {
            hex::encode(msv.sha1_hash) == expected_sha1
        } else {
            false
        }
    });
    assert!(
        found_sha1,
        "should find SHA1 hash {expected_sha1} (matches pypykatz)"
    );

    // Verify the user's session metadata
    let user_cred = credentials
        .iter()
        .find(|c| c.username == "user" && c.domain == "SECLAB" && c.msv.is_some());
    assert!(
        user_cred.is_some(),
        "should find user@SECLAB session with MSV data"
    );
}
