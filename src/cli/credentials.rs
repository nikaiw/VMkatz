//! Optional disk consumers, shared by local images, VMFS and Veeam.

use super::args::{Args, Colors};
use vmkatz::secrets::DiskSecrets;

/// Run only the consumers selected at build time. Registry records are optional:
/// explicit credentials can seed DPAPI consumers in a build without SAM.
/// Callers pass a mutable borrow to keep ownership of their open reader.
#[cfg(feature = "dpapi")]
pub(super) fn emit_disk_extras<R: std::io::Read + std::io::Seek>(
    mut reader: R,
    args: &Args,
    c: &Colors,
    secrets: Option<&DiskSecrets>,
    ntds_by_name: &[(String, [u8; 16])],
) -> bool {
    let found = emit_dpapi(&mut reader, args, c, secrets, ntds_by_name);
    #[cfg(feature = "chrome")]
    let found = emit_chrome(&mut reader, args, secrets) || found;
    found
}

/// No optional disk consumer is compiled without DPAPI (Chrome depends on it).
#[cfg(not(feature = "dpapi"))]
pub(super) fn emit_disk_extras<R: std::io::Read + std::io::Seek>(
    _reader: R,
    _args: &Args,
    _c: &Colors,
    _secrets: Option<&DiskSecrets>,
    _ntds_by_name: &[(String, [u8; 16])],
) -> bool {
    false
}

#[cfg(feature = "dpapi")]
#[cfg_attr(
    not(feature = "credman"),
    allow(
        unused_variables,
        reason = "registry records and prior credentials are used only by CredMan"
    )
)]
fn emit_dpapi<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    args: &Args,
    c: &Colors,
    secrets: Option<&DiskSecrets>,
    ntds_by_name: &[(String, [u8; 16])],
) -> bool {
    use super::output::{
        dedup_dpapi_hashes, print_dpapi_masterkey_csv, print_dpapi_masterkey_hashcat,
        print_dpapi_masterkey_text,
    };

    let hashes = vmkatz::dpapi::disk::extract_dpapi_masterkeys_from_reader(reader, args.partition);
    // Display only the selected keys; CredMan still needs every candidate.
    let display_hashes = dedup_dpapi_hashes(&hashes, args.all);
    let found = !display_hashes.is_empty();
    if found {
        match args.format.as_str() {
            "csv" => print_dpapi_masterkey_csv(&display_hashes),
            "hashcat" => print_dpapi_masterkey_hashcat(&display_hashes),
            _ => print_dpapi_masterkey_text(&display_hashes, c),
        }
    }
    #[cfg(feature = "credman")]
    if args.credman || args.all {
        return super::credman::emit_credman(reader, args, c, secrets, &hashes, ntds_by_name)
            || found;
    }
    found
}

#[cfg(feature = "chrome")]
fn emit_chrome<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    args: &Args,
    secrets: Option<&DiskSecrets>,
) -> bool {
    if !(args.chrome || args.all) {
        return false;
    }
    let empty = DiskSecrets::default();
    let nt_hashes = super::args::parse_chrome_nthashes(&args.chrome_nthash);
    match vmkatz::chrome::runner::run_reader(
        reader,
        secrets.unwrap_or(&empty),
        &args.chrome_password,
        &nt_hashes,
    ) {
        Ok(summary) => {
            let output = vmkatz::chrome::runner::render_summary(&summary, args.chrome_json);
            if !output.trim().is_empty() {
                println!("{output}");
            }
            !summary.profiles.is_empty() || !summary.findings.is_empty()
        }
        Err(error) => {
            log::warn!("chrome extraction failed: {error}");
            false
        }
    }
}
