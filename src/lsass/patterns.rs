use crate::error::{Result, VmkatzError};
use crate::memory::VirtualMemory;

// lsasrv.dll IV / key patterns for Windows 10 x64
//
// These patterns locate LsaInitializeProtectedMemory in lsasrv.dll .text.
// From the pattern match, RIP-relative LEA instructions resolve:
//   - InitializationVector (IV, 16 bytes) at KEY_OFFSET_SETS[i].0
//   - h3DesKey handle pointer at KEY_OFFSET_SETS[i].1
//   - hAesKey handle pointer at KEY_OFFSET_SETS[i].2

/// Pattern to find the IV (InitializationVector) in lsasrv.dll.
/// Multiple patterns for different builds.
pub static LSASRV_KEY_PATTERNS: &[&[u8]] = &[
    // Win10 1607+ / Win11 (most common)
    // and [rsp+30h],0; lea rax,[rbp-20h]; mov r9d,[rbp-28h]; lea rdx,[rip+disp32]
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8D, 0x45, 0xE0, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8D,
        0x15,
    ],
    // Win10 1507/1511
    // and [rsp+30h],0; mov r9d,[rbp-28h]; lea rdx,[rip+disp32]
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8D, 0x15,
    ],
    // Win8.1 / Server 2012 R2 (same encoding as 1507)
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8D, 0x15,
    ],
    // Win7 / Server 2008 R2
    // and [rsp+30h],0; lea rax,[rbp-20h]; mov r9d,[rbp-28h]
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8D, 0x45, 0xE0, 0x44, 0x8B, 0x4D, 0xD8,
    ],
    // Win8 / Server 2012
    // and [rsp+30h],0; lea rax,[rbp-20h]; mov r9d,[rbp-...]
    &[
        0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8D, 0x45, 0xE0, 0x44, 0x8B, 0x4D,
    ],
];

/// Pattern to find LogonSessionList in msv1_0.dll.
/// Located in NlpUserLogon near the hash table initialization code.
/// After match, two LEA [rip+disp32] instructions resolve the list base and bucket count.
pub static MSV_LOGON_SESSION_PATTERNS: &[&[u8]] = &[
    // Win10 1607+: xor edi,edi; mov [r15],edi; mov r14,rbx; test r8d,r8d; je short
    &[
        0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC0, 0x74,
    ],
    // Win10 1903+: xor edi,edi; mov [r15],edi; mov r14,rbx; test r9d,r9d; je short
    &[
        0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC9, 0x74,
    ],
    // Win10 2004+: xor edi,edi; mov [r15],esi; mov r14,rbx; test r8d,r8d; je short
    &[
        0x33, 0xFF, 0x45, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC0, 0x74,
    ],
    // Win10 19041+/Win11: ...test r9d,r9d; je near (0F 84 = JE rel32)
    &[
        0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC9, 0x0F, 0x84,
    ],
    // Win10 19045/Win11 22H2: ...mov [r15],esi; test r9d,r9d; je short
    &[
        0x33, 0xFF, 0x45, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC9, 0x74,
    ],
    // Win7 SP1: xor esi,esi; mov [r15],ebp; mov r14,rbx; test eax,eax; je short
    &[
        0x33, 0xF6, 0x45, 0x89, 0x2F, 0x4C, 0x8B, 0xF3, 0x85, 0xC0, 0x74,
    ],
    // Win8: xor esi,esi; mov [r15],esi; mov r14,rbx; test r8d,r8d; je short
    &[
        0x33, 0xF6, 0x45, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC0, 0x74,
    ],
    // Win8.1: xor esi,esi; mov [r15],esi; mov r14,rbx; test r9d,r9d; je short
    &[
        0x33, 0xF6, 0x45, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC9, 0x74,
    ],
    // Win11 24H2+: mov [r12],r14d; mov edi,ebx; test r8d,r8d; jcc near
    &[0x45, 0x89, 0x34, 0x24, 0x8B, 0xFB, 0x45, 0x85, 0xC0, 0x0F],
    // Shorter fallback: xor edi,edi; mov [r15],edi; mov r14,rbx
    &[0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3],
    // Win7/8 shorter fallback: xor esi,esi; mov [r15],ebp; mov r14,rbx
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
/// Located near RTL_AVL_TABLE lookup. The LEA [rip+disp32] resolves the table address.
pub static KERBEROS_LOGON_SESSION_PATTERNS: &[&[u8]] = &[
    // Win10 1607+: mov rbx,[rax]; lea rcx,[rip+disp32]
    &[0x48, 0x8B, 0x18, 0x48, 0x8D, 0x0D],
    // Older: mov rbx,[rdi]; lea rcx,[rip+disp32]
    &[0x48, 0x8B, 0x1F, 0x48, 0x8D, 0x0D],
];

/// Pattern to find TSGlobalCredTable in tspkg.dll.
/// sub rsp,20h; lea rcx,[rip+disp32] — function prologue + table reference.
pub static TSPKG_LOGON_SESSION_PATTERNS: &[&[u8]] = &[&[0x48, 0x83, 0xEC, 0x20, 0x48, 0x8D, 0x0D]];

/// Pattern to find g_MasterKeyCacheList in lsasrv.dll (DPAPI).
/// Located in linked list insertion code (InsertHeadList equivalent).
pub static DPAPI_MASTER_KEY_PATTERNS: &[&[u8]] = &[
    // Win10 1607+: mov [rdi],r11; mov [rdi+8],rax; mov rax,[r11+8]; mov [rdi],rax
    &[
        0x4C, 0x89, 0x1F, 0x48, 0x89, 0x47, 0x08, 0x49, 0x8B, 0x43, 0x08, 0x48, 0x89, 0x07,
    ],
    // Win10 older: mov [rdi],r11; mov [rdi+8],rax; mov rax,[r14]; mov [rdi],rax
    &[
        0x4C, 0x89, 0x1F, 0x48, 0x89, 0x47, 0x08, 0x49, 0x8B, 0x06, 0x48, 0x89, 0x07,
    ],
];

/// Pattern to find SspCredentialList in msv1_0.dll (SSP).
pub static SSP_CREDENTIAL_PATTERNS: &[&[u8]] = &[
    // sub rsp,20h; lea rcx,[rip+disp32]
    &[0x48, 0x83, 0xEC, 0x20, 0x48, 0x8D, 0x0D],
    // sub rsp,20h; lea r9,[rip+disp32]
    &[0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8D, 0x0D],
];

/// Pattern to find LiveGlobalLogonSessionList in livessp.dll.
/// Same instruction pattern family as MSV LogonSessionList (hash table init).
pub static LIVESSP_LOGON_SESSION_PATTERNS: &[&[u8]] = &[
    // xor esi,esi; mov [r15],ebp; mov r14,rbx; test eax,eax; je short
    &[
        0x33, 0xF6, 0x45, 0x89, 0x2F, 0x4C, 0x8B, 0xF3, 0x85, 0xC0, 0x74,
    ],
    // xor edi,edi; mov [r15],esi; mov r14,rbx; test r8d,r8d; je short
    &[
        0x33, 0xFF, 0x41, 0x89, 0x37, 0x4C, 0x8B, 0xF3, 0x45, 0x85, 0xC0, 0x74,
    ],
];

/// Pattern to find cloudap cache in cloudap.dll.
/// Multiple patterns for different LUID offsets across Windows versions:
///   - Win10 1903-2004: LUID at struct+0x18, cmp [rdx+0x18],r8d (REX encoding)
///   - Win10 1511-1809: LUID at struct+0x18, cmp [rcx+0x18],edx (non-REX)
///   - Win11 22H2+: LUID at struct+0x1C
///   - Win11 24H2+: LUID at struct+0x1C, different register encoding
pub static CLOUDAP_CACHE_PATTERNS: &[&[u8]] = &[
    // Win10 1903-2004: mov r8d,[rcx]; cmp [rdx+0x18],r8d; jne short
    &[0x44, 0x8B, 0x01, 0x44, 0x39, 0x42, 0x18, 0x75],
    // Win10 1511-1809: cmp [rcx+0x18],edx; jne short +8; mov eax,[rdi+4]
    &[0x39, 0x51, 0x18, 0x75, 0x08, 0x8B, 0x47, 0x04],
    // Win10 1511-1809 variant: cmp [rcx+0x18],edx; jne short +8; mov eax,[rbx+4]
    &[0x39, 0x51, 0x18, 0x75, 0x08, 0x8B, 0x43, 0x04],
    // Win11 22H2: cmp [rdx+0x1C],r8d; jne short; mov eax,[rcx+4]
    &[0x44, 0x39, 0x42, 0x1C, 0x75, 0x0D, 0x8B, 0x41],
    // Win11 24H2: mov edx,[r8]; cmp [rax+0x1C],edx; je short
    &[0x41, 0x8B, 0x10, 0x39, 0x50, 0x1C, 0x74, 0x05],
    // Win11 21H2: mov ecx,[rsi]; cmp [rdx+0x1C],ecx; jne short
    &[0x8B, 0x0E, 0x39, 0x4A, 0x1C, 0x75, 0x0C, 0x8B, 0x46, 0x04],
    // Win10 1507: cmp [rcx+0x14],edx; jne short +8; mov eax,[rdi+4]
    &[0x39, 0x51, 0x14, 0x75, 0x08, 0x8B, 0x47, 0x04],
];

/// Scan a memory region for any of the given byte patterns.
/// Returns the virtual address where the pattern starts.
pub fn find_pattern(
    vmem: &dyn VirtualMemory,
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
                "Found pattern '{name}' (variant {pat_idx}) at 0x{addr:x} (base+0x{offset:x})"
            );
            return Ok((addr, pat_idx));
        }
    }

    Err(VmkatzError::PatternNotFound(name.to_string()))
}

/// Find a byte pattern in a buffer. Returns the offset of the first match.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    memchr::memmem::find(haystack, needle)
}

/// Resolve a RIP-relative address from a code location.
/// At `code_addr + disp_offset`, reads a 4-byte signed displacement.
/// Target = code_addr + disp_offset + 4 + displacement.
pub fn resolve_rip_relative(
    vmem: &dyn VirtualMemory,
    code_addr: u64,
    disp_offset: i64,
) -> Result<u64> {
    let disp_addr = (code_addr as i64 + disp_offset) as u64;
    let displacement = vmem.read_virt_u32(disp_addr)? as i32;
    let target = (disp_addr as i64 + 4 + i64::from(displacement)) as u64;
    log::debug!(
        "RIP-relative: code=0x{code_addr:x} disp_offset={disp_offset} disp_addr=0x{disp_addr:x} disp={displacement} target=0x{target:x}"
    );
    Ok(target)
}

/// Find a LIST_ENTRY global by scanning for LEA instructions near a code pattern.
///
/// Scans 0x100 bytes starting from `pattern_addr - 0x30` for `48/4C 8D modrm`
/// LEA instructions, resolves RIP-relative targets, and validates as LIST_ENTRY.
pub fn find_list_via_lea(vmem: &dyn VirtualMemory, pattern_addr: u64, label: &str) -> Result<u64> {
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

    Err(VmkatzError::PatternNotFound(format!("LEA for {label}")))
}

pub const fn is_heap_ptr(addr: u64) -> bool {
    addr > 0x10000 && (addr >> 48) == 0
}

// -- Win10 x86 patterns --

/// Patterns to find the key initialization in lsasrv.dll on Win10 x86.
/// These use x86 instructions (no REX prefix, absolute addressing).
pub static LSASRV_KEY_PATTERNS_X86: &[&[u8]] = &[
    // Win10 x86 v1: AND dword [ebp-4],0; LEA eax,[ebp-10h]
    &[0x83, 0x65, 0xFC, 0x00, 0x8D, 0x45, 0xF0],
    // Win10 x86 v2: AND dword [esp+20h],0
    &[0x83, 0x64, 0x24, 0x20, 0x00],
];

/// Patterns to find LogonSessionList in msv1_0.dll on Win10 x86.
/// Currently unused: MSV x86 uses .data fallback scanning instead of .text patterns.
#[expect(
    dead_code,
    reason = "signatures x86 conservées, réservées à un futur chemin lsass 32 bits"
)]
pub static MSV_LOGON_SESSION_PATTERNS_X86: &[&[u8]] = &[
    // Win10 x86: XOR EAX,EAX; MOV [ESI],EAX; MOV [ESI+4],EAX (most common, 11/12 builds)
    &[0x33, 0xC0, 0x89, 0x06, 0x89, 0x46, 0x04],
    // Win10 x86: XOR EAX,EAX; MOV [ESI],EAX; MOV [EBP-4],EDI (Win10 17763+)
    &[0x33, 0xC0, 0x89, 0x06, 0x89, 0x7D, 0xFC],
    // Win10 x86: XOR EAX,EAX; MOV [EDI],EAX (Win11 WoW64)
    &[0x33, 0xC0, 0x89, 0x07],
    // Older register variants:
    // XOR EDI,EDI; MOV [ESI],EDI; TEST EAX,EAX; JZ short
    &[0x33, 0xFF, 0x89, 0x3E, 0x85, 0xC0, 0x74],
    // XOR EDI,EDI; MOV [ESI],EDI; TEST EAX,EAX; JE near
    &[0x33, 0xFF, 0x89, 0x3E, 0x85, 0xC0, 0x0F, 0x84],
    // XOR ESI,ESI; MOV [EDI],ESI
    &[0x33, 0xF6, 0x89, 0x37, 0x85, 0xC0, 0x74],
];

/// Patterns to find l_LogSessList in wdigest.dll on Win10 x86.
pub static WDIGEST_LOGON_SESSION_PATTERNS_X86: &[&[u8]] = &[
    // Win10 x86: CMP ECX,EBX; JE
    &[0x3B, 0xCB, 0x74],
    // CMP EBX,ECX; JE
    &[0x3B, 0xD9, 0x74],
    // CMP ECX,EBX; JE near
    &[0x3B, 0xCB, 0x0F, 0x84],
    // CMP EBX,ECX; JE near
    &[0x3B, 0xD9, 0x0F, 0x84],
];

/// Patterns to find KerbGlobalLogonSessionTable in kerberos.dll on Win10 x86.
pub static KERBEROS_LOGON_SESSION_PATTERNS_X86: &[&[u8]] = &[
    // Win10 x86: MOV reg,[reg]; LEA/PUSH abs32
    &[0x8B, 0x38, 0x8D],
    &[0x8B, 0x18, 0x8D],
    // MOV EBX,[EAX]; PUSH abs32
    &[0x8B, 0x18, 0x68],
    &[0x8B, 0x38, 0x68],
    // Win11 21H2 (22000) / Win11 22H2 (22621) x86: ADD dword [ESI+8],-1; PUSH &table
    // Compiler emits refcount decrement immediately before passing table ptr to RtlLookup*
    &[0x83, 0x46, 0x08, 0xFF, 0x68],
    // Win11 21H2/22H2 x86 alternate: TEST ESI,ESI; JE short +0x30; PUSH &table
    // ESI = credential ptr null-check gate before table lookup
    &[0x85, 0xF6, 0x74, 0x30, 0x68],
];

/// Patterns to find TSGlobalCredTable in tspkg.dll on Win10 x86.
pub static TSPKG_LOGON_SESSION_PATTERNS_X86: &[&[u8]] = &[
    // Win10 x86: XOR EBX,EBX; PUSH 1; PUSH abs32 (11/12 builds)
    &[0x33, 0xDB, 0x6A, 0x01, 0x68],
    // Win10 x86: MOV EDI,ECX; XOR EBX,EBX; PUSH 1; PUSH abs32 (longer, more specific)
    &[0x8B, 0xF9, 0x33, 0xDB, 0x6A, 0x01, 0x68],
    // Win10 x86 26100+: LEA EAX,[EBP-6Ch]; PUSH 1; PUSH abs32
    &[0x8D, 0x45, 0x94, 0x6A, 0x01, 0x68],
];

/// Patterns to find SspCredentialList in msv1_0.dll on Win10 x86.
pub static SSP_CREDENTIAL_PATTERNS_X86: &[&[u8]] =
    &[&[0x83, 0xEC, 0x10, 0x68], &[0x83, 0xEC, 0x0C, 0x68]];

/// Patterns to find g_MasterKeyCacheList in lsasrv.dll on Win10 x86 (DPAPI).
pub static DPAPI_MASTER_KEY_PATTERNS_X86: &[&[u8]] = &[
    // Win10 x86: MOV [EDI],ESI; MOV [EDI+4],EAX; MOV EAX,[ESI+4]; MOV [EDI],EAX
    &[0x89, 0x37, 0x89, 0x47, 0x04, 0x8B, 0x46, 0x04, 0x89, 0x07],
    &[0x89, 0x1F, 0x89, 0x47, 0x04, 0x8B, 0x43, 0x04, 0x89, 0x07],
];

/// Find a LIST_ENTRY global by scanning for MOV/LEA/PUSH with absolute addresses in x86 code.
/// Check if an x86 instruction at `data[i]` uses a 4-byte absolute address operand.
/// Matches: PUSH imm32 (0x68), MOV EAX,[abs32] (0xA1), MOV [abs32],EAX (0xA3),
/// LEA/MOV reg,[abs32] (0x8D/0x8B with ModRM mod=00, rm=101).
#[inline]
const fn is_x86_abs_address_insn(data: &[u8], i: usize) -> bool {
    match data[i] {
        0x68 | 0xA1 | 0xA3 => true,
        0x8D | 0x8B => i + 1 < data.len() && (data[i + 1] & 0xC7) == 0x05,
        _ => false,
    }
}

pub fn find_list_via_abs(
    vmem: &dyn VirtualMemory,
    pattern_addr: u64,
    dll_base: u64,
    data_base: u64,
    data_end: u64,
    label: &str,
) -> Result<u64> {
    let search_start = pattern_addr.saturating_sub(0x30);
    let data = vmem.read_virt_bytes(search_start, 0x100)?;

    for i in 0..data.len().saturating_sub(5) {
        // Look for instructions with 4-byte absolute addresses:
        // LEA reg,[abs32]: 8D 05/0D/15/1D/25/2D/35/3D [abs32]
        // MOV reg,[abs32]: 8B 05/0D/15/1D/25/2D/35/3D [abs32] (with specific ModRM)
        // PUSH abs32: 68 [abs32]
        let is_abs_ref = match data[i] {
            0x8D => {
                // LEA reg,[abs32] — ModRM byte with mod=00, rm=101 (disp32)
                let modrm = data[i + 1];
                (modrm & 0xC7) == 0x05
            }
            // PUSH imm32, MOV EAX,[abs32], MOV [abs32],EAX
            0x68 | 0xA1 | 0xA3 => true,
            _ => false,
        };

        if !is_abs_ref {
            continue;
        }

        let abs_off = if data[i] == 0x68 || data[i] == 0xA1 || data[i] == 0xA3 {
            i + 1
        } else {
            i + 2
        };
        if abs_off + 4 > data.len() {
            continue;
        }

        let target = u64::from(u32::from_le_bytes([
            data[abs_off],
            data[abs_off + 1],
            data[abs_off + 2],
            data[abs_off + 3],
        ]));

        // Must point into .data section
        if target < data_base || target >= data_end {
            continue;
        }

        // Validate as LIST_ENTRY: flink should be valid or self-referencing
        if let Ok(flink) = vmem.read_virt_u32(target) {
            let flink = u64::from(flink);
            if flink == target || (flink > 0x10000 && flink < 0x8000_0000) {
                log::info!(
                    "Found x86 {} via abs at 0x{:x} → 0x{:x}",
                    label,
                    search_start + i as u64,
                    target
                );
                return Ok(target);
            }
        }
    }

    // Second pass: wider scan for any abs32 reference to .data
    let search_start2 = pattern_addr.saturating_sub(0x80);
    let data2 = vmem.read_virt_bytes(search_start2, 0x200)?;
    for i in 0..data2.len().saturating_sub(5) {
        if !is_x86_abs_address_insn(&data2, i) {
            continue;
        }
        let abs_off = if data2[i] == 0x68 || data2[i] == 0xA1 || data2[i] == 0xA3 {
            i + 1
        } else {
            i + 2
        };
        if abs_off + 4 > data2.len() {
            continue;
        }
        let target = u64::from(u32::from_le_bytes([
            data2[abs_off],
            data2[abs_off + 1],
            data2[abs_off + 2],
            data2[abs_off + 3],
        ]));
        if target < data_base || target >= data_end || target < dll_base {
            continue;
        }
        if let Ok(flink) = vmem.read_virt_u32(target) {
            let flink = u64::from(flink);
            if flink == target || (flink > 0x10000 && flink < 0x8000_0000) {
                log::info!(
                    "Found x86 {} via wider abs scan at 0x{:x} → 0x{:x}",
                    label,
                    search_start2 + i as u64,
                    target
                );
                return Ok(target);
            }
        }
    }

    Err(VmkatzError::PatternNotFound(format!("abs for {label}")))
}

// -- Pre-Vista (WinXP / Win2003) patterns --

/// Patterns to find LsaInitializeProtectedMemory in lsasrv.dll for pre-Vista x86.
/// These locate g_pDESXKey, g_Feedback, and g_pRandomKey references.
pub static PREVISTA_KEY_PATTERNS: &[&[u8]] = &[
    // WinXP SP3 x86: ADD EAX, 0x90; PUSH 0x18; PUSH EAX; CALL ...
    &[0x05, 0x90, 0x00, 0x00, 0x00, 0x6A, 0x18, 0x50, 0xE8],
    // Win2003 SP2 x86
    &[0x05, 0x90, 0x00, 0x00, 0x00, 0x6A, 0x18, 0x50],
];

/// Pre-Vista key offset sets relative to pattern start.
/// Each: (desx_key_disp, feedback_disp, random_key_disp) — absolute address offsets in x86 code.
/// These are the byte offsets within the code where the absolute addresses are stored.
pub const PREVISTA_KEY_OFFSET_SETS: &[(i64, i64, i64)] = &[
    // WinXP SP3: g_pDESXKey at pattern-0x22, g_Feedback at pattern+0x3E, g_pRandomKey at pattern+0x57
    (-0x22, 0x3E, 0x57),
    // Win2003 SP2
    (-0x1E, 0x3A, 0x53),
];

/// Patterns to find LogonSessionList in msv1_0.dll for pre-Vista x86.
pub static PREVISTA_MSV_LOGON_SESSION_PATTERNS: &[&[u8]] = &[
    // WinXP SP3 msv1_0.dll: MOV EAX,[EBP+8]; MOV EAX,[EAX+10]; MOV [EBP+??],EAX
    &[0x8B, 0x45, 0x08, 0x8B, 0x40, 0x10, 0x89, 0x45],
    // Win2003 SP2 msv1_0.dll
    &[0x8B, 0x45, 0x08, 0x89, 0x45, 0xFC],
];

/// Resolve an absolute address from x86 code.
/// At `code_addr + disp_offset`, reads a 4-byte absolute address (not RIP-relative).
pub fn resolve_absolute_address(
    vmem: &dyn VirtualMemory,
    code_addr: u64,
    disp_offset: i64,
) -> Result<u64> {
    let addr = (code_addr as i64 + disp_offset) as u64;
    let abs_addr = u64::from(vmem.read_virt_u32(addr)?);
    log::debug!(
        "Absolute address: code=0x{code_addr:x} offset={disp_offset} read_addr=0x{addr:x} target=0x{abs_addr:x}"
    );
    Ok(abs_addr)
}
