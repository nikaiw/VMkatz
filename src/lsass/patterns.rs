use crate::error::{GovmemError, Result};
use crate::memory::VirtualMemory;

// lsasrv.dll IV / key patterns for Windows 10 x64

/// Pattern to find the IV (InitializationVector) in lsasrv.dll.
/// Multiple patterns for different builds.
pub static LSASRV_KEY_PATTERNS: &[&[u8]] = &[
    // Win10 1607+ / Win11 (most common)
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8D, 0x45, 0xE0, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8D,
        0x15,
    ],
    // Win10 1507/1511
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8D, 0x15,
    ],
    // Win8.1 / Server 2012 R2
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8D, 0x15,
    ],
    // Win7 / Server 2008 R2 (LsaInitializeProtectedMemory)
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8D, 0x45, 0xE0, 0x44, 0x8B, 0x4D, 0xD8,
    ],
    // Win8 / Server 2012
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8D, 0x45, 0xE0, 0x44, 0x8B, 0x4D,
    ],
];

/// Pattern to find LogonSessionList in msv1_0.dll.
/// Multiple patterns for Windows 7 through Windows 11.
pub static MSV_LOGON_SESSION_PATTERNS: &[&[u8]] = &[
    // Win10 1607+ (build 14393)
    &[
        0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC0, 0x74,
    ],
    // Win10 1903+ (build 18362)
    &[
        0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC9, 0x74,
    ],
    // Win10 2004+ variant
    &[
        0x33, 0xFF, 0x45, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC0, 0x74,
    ],
    // Win10 19041+ / Win11: alternate sequence
    &[
        0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC9, 0x0F, 0x84,
    ],
    // Win10 19045 / Win11 22H2
    &[
        0x33, 0xFF, 0x45, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC9, 0x74,
    ],
    // Win7 SP1 / Server 2008 R2: xor esi,esi; mov [r15],ebp; mov r14,rbx; test eax,eax
    &[
        0x33, 0xF6, 0x45, 0x89, 0x2F, 0x4C, 0x8B, 0xF3, 0x85, 0xC0, 0x74,
    ],
    // Win8 / Server 2012
    &[
        0x33, 0xF6, 0x45, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC0, 0x74,
    ],
    // Win8.1 / Server 2012 R2
    &[
        0x33, 0xF6, 0x45, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC9, 0x74,
    ],
    // Shorter fallback: xor edi,edi; mov [r15],edi
    &[0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3],
    // Win7/8 shorter fallback: xor esi,esi; mov [r15],ebp/esi
    &[0x33, 0xF6, 0x45, 0x89, 0x2F, 0x4C, 0x8B, 0xF3],
];

/// Pattern to find l_LogSessList in wdigest.dll.
/// These patterns appear in SpAcceptCredentials near the list reference.
/// Win7 through Win11 — CMP instructions use same encoding across versions.
pub static WDIGEST_LOGON_SESSION_PATTERNS: &[&[u8]] = &[
    // Win10 1607+ / Win11: CMP RBX,RCX; JE (short)
    &[0x48, 0x3B, 0xD9, 0x74],
    // Win10 older / Win8+: CMP RCX,RBX; JE (short)
    &[0x48, 0x3B, 0xCB, 0x74],
    // Win10 1809+: CMP RBX,RCX; JE (near)
    &[0x48, 0x3B, 0xD9, 0x0F, 0x84],
    // CMP RCX,RBX; JE (near)
    &[0x48, 0x3B, 0xCB, 0x0F, 0x84],
    // Win7: CMP RDI,RBX; JE (short) — SpAcceptCredentials variant
    &[0x48, 0x3B, 0xFB, 0x74],
    // Win7: CMP RBX,RDI; JE (short)
    &[0x48, 0x3B, 0xDF, 0x74],
];

/// Pattern to find KerbGlobalLogonSessionTable in kerberos.dll.
pub static KERBEROS_LOGON_SESSION_PATTERNS: &[&[u8]] = &[
    // Win10 1607+
    &[0x48, 0x8B, 0x18, 0x48, 0x8D, 0x0D],
    // Older
    &[0x48, 0x8B, 0x1F, 0x48, 0x8D, 0x0D],
];

/// Pattern to find TSGlobalCredTable in tspkg.dll.
pub static TSPKG_LOGON_SESSION_PATTERNS: &[&[u8]] = &[&[0x48, 0x83, 0xEC, 0x20, 0x48, 0x8D, 0x0D]];

/// Pattern to find g_MasterKeyCacheList in lsasrv.dll (DPAPI).
pub static DPAPI_MASTER_KEY_PATTERNS: &[&[u8]] = &[
    // Win10 1607+
    &[
        0x4C, 0x89, 0x1F, 0x48, 0x89, 0x47, 0x08, 0x49, 0x8B, 0x43, 0x08, 0x48, 0x89, 0x07,
    ],
    // Win10 older
    &[
        0x4C, 0x89, 0x1F, 0x48, 0x89, 0x47, 0x08, 0x49, 0x8B, 0x06, 0x48, 0x89, 0x07,
    ],
];

/// Pattern to find SspCredentialList in msv1_0.dll (SSP).
pub static SSP_CREDENTIAL_PATTERNS: &[&[u8]] = &[
    // Win10 1607+
    &[0x48, 0x83, 0xEC, 0x20, 0x48, 0x8D, 0x0D],
    // Alternate
    &[0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8D, 0x0D],
];

/// Pattern to find LiveGlobalLogonSessionList in livessp.dll.
pub static LIVESSP_LOGON_SESSION_PATTERNS: &[&[u8]] = &[
    &[
        0x33, 0xF6, 0x45, 0x89, 0x2F, 0x4C, 0x8B, 0xF3, 0x85, 0xC0, 0x74,
    ],
    &[
        0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC0, 0x74,
    ],
];

/// Pattern to find cloudap cache in cloudap.dll.
pub static CLOUDAP_CACHE_PATTERNS: &[&[u8]] = &[&[0x44, 0x8B, 0x01, 0x44, 0x39, 0x42, 0x18, 0x75]];

/// Scan a memory region for any of the given byte patterns.
/// Returns the virtual address where the pattern starts.
pub fn find_pattern(
    vmem: &impl VirtualMemory,
    base: u64,
    size: u32,
    patterns: &[&[u8]],
    name: &str,
) -> Result<(u64, usize)> {
    // Read the section into a local buffer for faster scanning
    let data = vmem.read_virt_bytes(base, size as usize)?;

    for (pat_idx, pattern) in patterns.iter().enumerate() {
        if let Some(offset) = find_bytes(&data, pattern) {
            let addr = base + offset as u64;
            log::info!(
                "Found pattern '{}' (variant {}) at 0x{:x} (base+0x{:x})",
                name,
                pat_idx,
                addr,
                offset
            );
            return Ok((addr, pat_idx));
        }
    }

    Err(GovmemError::PatternNotFound(name.to_string()))
}

/// Find a byte pattern in a buffer. Returns the offset of the first match.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Resolve a RIP-relative address from a code location.
/// At `code_addr + disp_offset`, reads a 4-byte signed displacement.
/// Target = code_addr + disp_offset + 4 + displacement.
pub fn resolve_rip_relative(
    vmem: &impl VirtualMemory,
    code_addr: u64,
    disp_offset: i64,
) -> Result<u64> {
    let disp_addr = (code_addr as i64 + disp_offset) as u64;
    let displacement = vmem.read_virt_u32(disp_addr)? as i32;
    let target = (disp_addr as i64 + 4 + displacement as i64) as u64;
    log::debug!(
        "RIP-relative: code=0x{:x} disp_offset={} disp_addr=0x{:x} disp={} target=0x{:x}",
        code_addr,
        disp_offset,
        disp_addr,
        displacement,
        target
    );
    Ok(target)
}

/// Find a LIST_ENTRY global by scanning for LEA instructions near a code pattern.
///
/// Scans 0x100 bytes starting from `pattern_addr - 0x30` for `48/4C 8D modrm`
/// LEA instructions, resolves RIP-relative targets, and validates as LIST_ENTRY.
pub fn find_list_via_lea(vmem: &impl VirtualMemory, pattern_addr: u64, label: &str) -> Result<u64> {
    let search_start = pattern_addr.saturating_sub(0x30);
    let data = vmem.read_virt_bytes(search_start, 0x100)?;

    for i in 0..data.len().saturating_sub(7) {
        let is_lea = (data[i] == 0x48 || data[i] == 0x4C)
            && data[i + 1] == 0x8D
            && matches!(data[i + 2], 0x05 | 0x0D | 0x15 | 0x35 | 0x3D);
        if is_lea {
            let target = resolve_rip_relative(vmem, search_start + i as u64, 3)?;
            if let Ok(flink) = vmem.read_virt_u64(target) {
                if flink == target || (flink > 0x10000 && (flink >> 48) == 0) {
                    return Ok(target);
                }
            }
        }
    }

    Err(GovmemError::PatternNotFound(format!("LEA for {}", label)))
}

pub fn is_heap_ptr(addr: u64) -> bool {
    addr > 0x10000 && (addr >> 48) == 0
}
