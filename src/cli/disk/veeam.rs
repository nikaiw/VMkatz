//! Veeam backup listing, file reconstruction and disk extraction commands.

use std::path::Path;

use anyhow::Context;

#[cfg(feature = "ntds.dit")]
use crate::cli::args::Colors;
use crate::cli::args::{Args, get_colors};
#[cfg(feature = "ntds.dit")]
use crate::cli::credentials::emit_disk_extras;
#[cfg(feature = "ntds.dit")]
use crate::cli::output::{
    print_disk_secrets, print_ntds_brief, print_ntds_csv, print_ntds_hashcat, print_ntds_ntlm,
    print_ntds_text,
};

use super::extract_and_print_reader;
#[cfg(feature = "ntds.dit")]
use super::read_ntds_stream;

/// Run the credential pipeline over every disk image in a Veeam backup.
/// Images are read on demand — nothing is written to a temp file.
pub fn run_veeam(input_path: &Path, args: &Args) -> anyhow::Result<()> {
    use vmkatz::disk::DiskImage;

    let password = args.veeam_password.as_deref();

    if args.veeam_list {
        return run_veeam_list(input_path, password, args);
    }
    if let Some(name) = &args.veeam_extract {
        return run_veeam_extract(
            input_path,
            name,
            args.veeam_output.as_deref(),
            password,
            args,
        );
    }

    // Without a password, encrypted backups can only yield a Hashcat target.
    if password.is_none()
        && vmkatz::veeam::inspect_encryption(input_path).is_ok_and(|e| e.encrypted)
    {
        return emit_veeam_hashcat(input_path);
    }

    let disks = vmkatz::veeam::list_disk_images(input_path, password)
        .context("failed to enumerate Veeam disk images")?;
    if disks.is_empty() {
        anyhow::bail!(
            "No supported Windows disk images found in Veeam backup {} (a Linux-only or agent-based backup may contain no Windows disks)",
            input_path.display()
        );
    }

    let c = get_colors(args);
    eprintln!(
        "[+] Veeam backup: {} disk image(s) in {}",
        disks.len(),
        input_path.display()
    );

    let mut found_anything = false;
    for entry in &disks {
        let size_note = entry
            .size
            .map(|s| format!(" ({})", veeam_human_size(s)))
            .unwrap_or_default();
        eprintln!(
            "\n{}=== disk image: {}{}{}",
            c.green, entry.name, size_note, c.reset
        );

        let mut disk = match vmkatz::veeam::VbkDisk::open(input_path, &entry.path, password) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[!] cannot open {}: {e}", entry.name);
                continue;
            }
        };
        log::info!("[veeam] {} = {} bytes", entry.name, disk.disk_size());

        #[cfg(feature = "ntds.dit")]
        if args.ntds || args.all {
            match extract_ntds_from_reader(&mut disk, args, c) {
                Ok(found) => found_anything |= found,
                Err(error) if args.all => {
                    eprintln!("[!] NTDS extraction skipped on {}: {error}", entry.name);
                    match extract_and_print_reader(&mut disk, args, c, &[], false) {
                        Ok(found) => found_anything |= found,
                        Err(fallback_error) => {
                            eprintln!("[!] extraction failed on {}: {fallback_error}", entry.name);
                        }
                    }
                }
                Err(error) => {
                    eprintln!("[!] NTDS extraction failed on {}: {error}", entry.name);
                }
            }
            continue;
        }

        match extract_and_print_reader(&mut disk, args, c, &[], false) {
            Ok(found) => found_anything |= found,
            Err(e) => eprintln!("[!] extraction failed on {}: {e}", entry.name),
        }
    }

    if !found_anything {
        anyhow::bail!("No SAM hashes or DPAPI master keys found in Veeam backup");
    }
    Ok(())
}

/// Print the encrypted backup's wrapped keyset as a Hashcat target
/// (`$vbk$*salt*iterations*verifier`, mode 31200) for offline cracking.
fn emit_veeam_hashcat(input_path: &Path) -> anyhow::Result<()> {
    let hashes = vmkatz::veeam::hashcat_hashes(input_path).with_context(|| {
        format!(
            "{} is encrypted but no Hashcat target could be built",
            input_path.display()
        )
    })?;
    eprintln!(
        "[+] Encrypted Veeam backup — {} Hashcat target(s), mode {}:",
        hashes.len(),
        vmkatz::veeam::HASHCAT_VEEAM_VBK_MODE
    );
    for h in &hashes {
        println!("{h}");
    }
    eprintln!(
        "[*] Crack with: hashcat -m {} <hash> <wordlist>, then re-run with --veeam-password",
        vmkatz::veeam::HASHCAT_VEEAM_VBK_MODE
    );
    Ok(())
}

/// Human-readable byte size (binary units), matching vbktool's list output.
fn veeam_human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// `--veeam-list`: print the backup catalogue (directories and stored files).
fn run_veeam_list(input_path: &Path, password: Option<&str>, args: &Args) -> anyhow::Result<()> {
    use vmkatz::veeam::StoredItemKind;
    let catalog = vmkatz::veeam::list_items_with_password(input_path, password)
        .context("failed to read Veeam catalogue")?;
    let c = get_colors(args);
    let (mut files, mut dirs, mut total) = (0u64, 0u64, 0u64);
    for item in &catalog.items {
        match item.kind {
            StoredItemKind::Directory => {
                dirs += 1;
                eprintln!("\n{}{}/{}", c.cyan, item.name, c.reset);
            }
            StoredItemKind::File => {
                files += 1;
                let sz = item.size.unwrap_or(0);
                total += sz;
                println!("  {:>11}  {}", veeam_human_size(sz), item.name);
            }
        }
    }
    eprintln!(
        "\n{files} file(s) · {dirs} director(ies) · {} total",
        veeam_human_size(total)
    );
    Ok(())
}

/// `--veeam-extract`: reconstruct one stored file to disk (never overwrites).
fn run_veeam_extract(
    input_path: &Path,
    name: &str,
    output: Option<&str>,
    password: Option<&str>,
    args: &Args,
) -> anyhow::Result<()> {
    // Default destination: the item's basename (after any catalogue path) in cwd.
    let default_name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let dest = Path::new(output.unwrap_or(default_name));
    let report =
        vmkatz::veeam::extract_item_to_path_with_password(input_path, name, dest, password)
            .with_context(|| format!("failed to extract {name:?}"))?;
    let c = get_colors(args);
    eprintln!(
        "{}[+] Extracted {} → {}{}",
        c.green,
        report.name,
        dest.display(),
        c.reset
    );
    eprintln!(
        "    {} · {} blocks ({} sparse, {} compressed)",
        veeam_human_size(report.bytes_written),
        report.block_count,
        report.sparse_blocks,
        report.compressed_blocks
    );
    Ok(())
}

/// Extract NTDS hashes and optional disk secrets; return whether any were found.
#[cfg(feature = "ntds.dit")]
fn extract_ntds_from_reader<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    args: &Args,
    c: &Colors,
) -> anyhow::Result<bool> {
    use std::io::SeekFrom;

    let secrets = if args.credman || args.all {
        reader.seek(SeekFrom::Start(0))?;
        vmkatz::sam::extract_secrets_from_reader_scoped(reader, args.partition).ok()
    } else {
        None
    };
    if args.all {
        if let Some(s) = &secrets {
            print_disk_secrets(s, args);
        }
    }

    reader.seek(SeekFrom::Start(0))?;
    let artifacts =
        read_ntds_stream(reader, args, &[]).context("NTDS artifact extraction failed")?;
    let (ctx, hashes) = artifacts.output.context("NTDS hash extraction failed")?;

    eprintln!("\n{}[+] NTDS Artifacts:{}", c.green, c.reset);
    eprintln!("  Partition offset : 0x{:x}", artifacts.partition_offset);
    eprintln!("  ntds.dit size    : {} bytes", ctx.ntds_size);
    eprintln!("  Hashes extracted : {}", hashes.len());

    match args.format.as_str() {
        "csv" => print_ntds_csv(&hashes, args.ntds_domain_prefix.as_deref()),
        "hashcat" => print_ntds_hashcat(&hashes, args.ntds_domain_prefix.as_deref()),
        "ntlm" => print_ntds_ntlm(&hashes, args.ntds_domain_prefix.as_deref()),
        "brief" => print_ntds_brief(&hashes, args.ntds_domain_prefix.as_deref()),
        _ => print_ntds_text(&hashes, c, args.ntds_domain_prefix.as_deref()),
    }

    let ntds_by_name: Vec<_> = hashes
        .iter()
        .filter(|h| !h.is_history)
        .map(|h| (h.username.clone(), h.nt_hash))
        .collect();
    let found_anything =
        emit_disk_extras(reader, args, c, secrets.as_ref(), &ntds_by_name) || !hashes.is_empty();

    Ok(found_anything)
}
