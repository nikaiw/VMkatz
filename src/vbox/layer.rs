use std::cell::RefCell;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Result, VmkatzError};
use crate::memory::{
    PhysicalMemory,
    page_index::{PageIndex, PageLocation},
};

#[path = "ssm.rs"]
mod ssm;
use ssm::SsmStream;
#[cfg(test)]
use ssm::lzf_decompress;

const PAGE_SIZE: usize = 4096;

// PGM page record types
const PGM_RAM_ZERO: u8 = 0x00;
const PGM_RAM_RAW: u8 = 0x01;
const PGM_MMIO2_RAW: u8 = 0x02;
const PGM_MMIO2_ZERO: u8 = 0x03;
const PGM_ROM_VIRGIN: u8 = 0x04;
const PGM_ROM_SHW_RAW: u8 = 0x05;
const PGM_ROM_SHW_ZERO: u8 = 0x06;
const PGM_ROM_PROT: u8 = 0x07;
const PGM_RAM_BALLOONED: u8 = 0x08;
const PGM_END: u8 = 0xFF;

const PGM_ADDR_FLAG: u8 = 0x80;

/// VirtualBox saved-state RAM, read from SSM records on demand.
pub struct VBoxLayer {
    stream: RefCell<SsmStream<fs::File>>,
    pages: PageIndex,
    phys_end: u64,
}

impl VBoxLayer {
    /// Open a VirtualBox .sav file and extract all RAM pages.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        let file_size = crate::utils::file_size(&mut file)?;
        log::info!(
            "VBox .sav file: {} bytes ({} MB)",
            file_size,
            file_size / (1024 * 1024)
        );

        let mut reader = io::BufReader::new(file);

        // Parse file header (64 bytes)
        let mut header = [0u8; 64];
        reader.read_exact(&mut header)?;

        let magic = &header[0..32];
        if !magic.starts_with(b"\x7fVirtualBox SavedState V2.0\n") {
            return Err(VmkatzError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Not a VirtualBox .sav file (bad magic)",
            )));
        }

        let cb_gc_phys = header[45];
        log::info!("VBox header: cbGCPhys={cb_gc_phys}");

        // Find the "pgm" unit by scanning for unit headers
        let (pgm_data_offset, pgm_version) = Self::find_pgm_unit(&mut reader, file_size)?;
        log::info!(
            "PGM unit data starts at file offset 0x{pgm_data_offset:x}, version {pgm_version}"
        );

        // Seek to PGM data and create SSM stream
        reader.seek(SeekFrom::Start(pgm_data_offset))?;
        let mut stream = SsmStream::new(reader.into_inner(), pgm_data_offset, file_size)?;

        let ram_size = Self::read_pgm_config(&mut stream, pgm_version)?;
        Self::read_ram_pages(stream, ram_size)
    }

    /// Read RAM configuration and consume the ROM/MMIO2 range declarations.
    fn read_pgm_config<R: Read + Seek>(stream: &mut SsmStream<R>, pgm_version: u32) -> Result<u64> {
        // Skip PGM struct fields — size depends on saved state version
        //    Version 14 (VBox 7.x):  78 bytes (fMappingsFixed + GCPtrMappingFixed +
        //                             cbMappingFixed + cBalloonedPages + per-CPU fields)
        //    Version 12-13 (VBox 5.x-6.x): 74 bytes (no cBalloonedPages)
        //    Version 11 (pre-balloon): 70 bytes
        //    Version <= 10: no cbRamHole/cbRam config follows
        let pgm_struct_size = match pgm_version {
            14.. => 78,
            12..=13 => 74,
            11 => 70,
            _ => {
                return Err(VmkatzError::Io(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "Unsupported PGM saved state version {pgm_version} (need >= 11, VBox 4.1+)"
                    ),
                )));
            }
        };
        stream.skip(pgm_struct_size)?;

        // Read RAM config (present in version >= 11)
        let cb_ram_hole = stream.read_u32_le()?;
        let cb_ram = stream.read_u64_le()?;
        log::info!(
            "PGM config: cbRamHole=0x{:x} ({} MB), cbRam=0x{:x} ({} MB)",
            cb_ram_hole,
            cb_ram_hole / (1024 * 1024),
            cb_ram,
            cb_ram / (1024 * 1024)
        );

        // Skip ROM range declarations
        let mut rom_count = 0u32;
        loop {
            let id = stream.read_u8()?;
            if id == 0xFF {
                break;
            }
            let _dev = stream.read_strz()?;
            let _inst = stream.read_u32_le()?;
            let _reg = stream.read_u8()?;
            let desc = stream.read_strz()?;
            let gcphys = stream.read_u64_le()?;
            let cb = stream.read_u64_le()?;
            rom_count += 1;
            log::debug!(
                "ROM range {rom_count}: id={id} desc='{desc}' gcphys=0x{gcphys:x} size=0x{cb:x}"
            );
        }
        log::info!("Skipped {rom_count} ROM range declarations");

        // Skip MMIO2 range declarations
        let mut mmio2_count = 0u32;
        loop {
            let id = stream.read_u8()?;
            if id == 0xFF {
                break;
            }
            let _dev = stream.read_strz()?;
            let _inst = stream.read_u32_le()?;
            let _reg = stream.read_u8()?;
            let desc = stream.read_strz()?;
            let cb = stream.read_u64_le()?;
            mmio2_count += 1;
            log::debug!("MMIO2 range {mmio2_count}: id={id} desc='{desc}' size=0x{cb:x}");
        }
        log::info!("Skipped {mmio2_count} MMIO2 range declarations");

        Ok(cb_ram)
    }

    /// Index RAM records, retaining raw pages and marking zero/ballooned pages.
    fn read_ram_pages(mut stream: SsmStream<fs::File>, ram_size: u64) -> Result<Self> {
        let mut pages = PageIndex::default();
        let mut gpa: u64 = 0;
        let mut raw_count = 0u64;
        let mut zero_count = 0u64;
        let mut rom_pages = 0u64;
        let mut mmio2_pages = 0u64;

        loop {
            let type_byte = stream.read_u8()?;
            if type_byte == PGM_END {
                break;
            }

            let has_addr = type_byte & PGM_ADDR_FLAG != 0;
            let base_type = type_byte & 0x7F;

            match base_type {
                PGM_RAM_ZERO | PGM_RAM_BALLOONED => {
                    if has_addr {
                        gpa = stream.read_u64_le()?;
                    }
                    pages.insert(gpa, None)?;
                    gpa += PAGE_SIZE as u64;
                    zero_count += 1;
                }
                PGM_RAM_RAW => {
                    if has_addr {
                        gpa = stream.read_u64_le()?;
                    }
                    pages.insert(gpa, Some(stream.position()))?;
                    stream.skip(PAGE_SIZE)?;
                    gpa += PAGE_SIZE as u64;
                    raw_count += 1;
                }
                PGM_MMIO2_RAW => {
                    if has_addr {
                        stream.read_u8()?; // range_id
                        stream.read_u32_le()?; // page_index
                    }
                    stream.skip(PAGE_SIZE)?;
                    mmio2_pages += 1;
                }
                PGM_MMIO2_ZERO => {
                    if has_addr {
                        stream.read_u8()?;
                        stream.read_u32_le()?;
                    }
                    mmio2_pages += 1;
                }
                PGM_ROM_VIRGIN | PGM_ROM_SHW_RAW => {
                    if has_addr {
                        stream.read_u8()?;
                        stream.read_u32_le()?;
                    }
                    stream.read_u8()?; // protection
                    stream.skip(PAGE_SIZE)?;
                    rom_pages += 1;
                }
                PGM_ROM_SHW_ZERO | PGM_ROM_PROT => {
                    if has_addr {
                        stream.read_u8()?;
                        stream.read_u32_le()?;
                    }
                    stream.read_u8()?; // protection
                    rom_pages += 1;
                }
                _ => {
                    return Err(VmkatzError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unknown PGM page type: 0x{base_type:02x}"),
                    )));
                }
            }
        }

        log::info!(
            "VBox RAM: {} raw pages ({} MB), {} zero pages, {} ROM pages, {} MMIO2 pages",
            raw_count,
            (raw_count * PAGE_SIZE as u64) / (1024 * 1024),
            zero_count,
            rom_pages,
            mmio2_pages,
        );
        let phys_end = pages.phys_end().unwrap_or(ram_size);

        log::info!(
            "Physical address space end: 0x{:x} ({} MB)",
            phys_end,
            phys_end / (1024 * 1024)
        );

        Ok(Self {
            stream: RefCell::new(stream),
            pages,
            phys_end,
        })
    }

    /// Scan the file for the "pgm" unit header and return the data offset.
    /// Returns (data_offset, pgm_version).
    fn find_pgm_unit<R: Read + Seek>(reader: &mut R, file_size: u64) -> Result<(u64, u32)> {
        let unit_magic = b"\nUnit\n\x00\x00";

        // Start scanning from offset 64 (after file header)
        reader.seek(SeekFrom::Start(64))?;

        let mut scan_buf = vec![0u8; 64 * 1024];
        let mut file_pos: u64 = 64;

        loop {
            if file_pos >= file_size {
                return Err(VmkatzError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "PGM unit not found in .sav file",
                )));
            }

            let to_read = (file_size - file_pos).min(scan_buf.len() as u64) as usize;
            reader.read_exact(&mut scan_buf[..to_read])?;

            // Scan for unit magic
            for i in 0..to_read.saturating_sub(unit_magic.len()) {
                if &scan_buf[i..i + unit_magic.len()] == unit_magic {
                    // Found a unit header at file_pos + i
                    let unit_offset = file_pos + i as u64;

                    // Read the rest of the unit header
                    reader.seek(SeekFrom::Start(unit_offset + 8))?;
                    let mut hdr = [0u8; 36]; // bytes 8..44
                    reader.read_exact(&mut hdr)?;

                    let cb_name = u32::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35]]) as usize;
                    if cb_name > 256 {
                        continue; // invalid
                    }

                    let mut name_buf = vec![0u8; cb_name];
                    reader.read_exact(&mut name_buf)?;

                    // Strip null terminator
                    let name = String::from_utf8_lossy(
                        &name_buf[..name_buf.iter().position(|&b| b == 0).unwrap_or(cb_name)],
                    );

                    if name == "pgm" {
                        // u32Version is at unit header offset 24 → hdr[16..20]
                        let pgm_version = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
                        let data_offset = unit_offset + 8 + 36 + cb_name as u64;
                        log::info!(
                            "Found pgm unit at offset 0x{unit_offset:x}, data at 0x{data_offset:x}, version {pgm_version}"
                        );
                        return Ok((data_offset, pgm_version));
                    }

                    // Seek back to continue scanning
                    reader.seek(SeekFrom::Start(
                        file_pos + i as u64 + unit_magic.len() as u64,
                    ))?;
                }
            }

            // Overlap by unit_magic.len() to avoid missing matches at boundaries
            let advance = to_read.saturating_sub(unit_magic.len());
            if advance == 0 {
                break;
            }
            file_pos += advance as u64;
            reader.seek(SeekFrom::Start(file_pos))?;
        }

        Err(VmkatzError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "PGM unit not found in .sav file",
        )))
    }

    /// Number of mapped RAM pages.
    pub fn page_count(&self) -> usize {
        usize::try_from(self.pages.page_count()).unwrap_or(usize::MAX)
    }
}

impl PhysicalMemory for VBoxLayer {
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<()> {
        // Handle reads that span page boundaries
        let mut remaining = buf.len();
        let mut buf_pos = 0;
        let mut cur_addr = phys_addr;

        while remaining > 0 {
            let cur_page = cur_addr & !(PAGE_SIZE as u64 - 1);
            let cur_offset = (cur_addr & (PAGE_SIZE as u64 - 1)) as usize;
            let avail = PAGE_SIZE - cur_offset;
            let to_copy = remaining.min(avail);

            match self.pages.get(cur_page) {
                Some(PageLocation::Zero) => buf[buf_pos..buf_pos + to_copy].fill(0),
                Some(PageLocation::File(offset)) => {
                    let mut stream = self.stream.borrow_mut();
                    stream.seek_logical(offset + cur_offset as u64)?;
                    stream.read_exact(&mut buf[buf_pos..buf_pos + to_copy])?;
                }
                None => return Err(VmkatzError::UnmappablePhysical(cur_addr)),
            }

            buf_pos += to_copy;
            remaining -= to_copy;
            cur_addr = cur_addr
                .checked_add(to_copy as u64)
                .ok_or(VmkatzError::UnmappablePhysical(cur_addr))?;
        }

        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.phys_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete saved state, with ROM/MMIO2 declarations before the pages.
    fn open_fixture(version: u32, pages: &[u8], tag: &str) -> Result<VBoxLayer> {
        let preamble_size = match version {
            14.. => 78,
            12..=13 => 74,
            _ => 70,
        };
        let mut pgm = vec![0; preamble_size];
        pgm.extend_from_slice(&0u32.to_le_bytes()); // RAM hole
        pgm.extend_from_slice(&0x8000u64.to_le_bytes()); // Configured RAM size
        // ROM ranges carry a physical address; MMIO2 declarations do not.
        for address in [Some(0xA0000u64), None] {
            pgm.push(1); // Range ID
            pgm.extend_from_slice(&0u32.to_le_bytes()); // Empty device name
            pgm.extend_from_slice(&0u32.to_le_bytes()); // Instance
            pgm.push(0); // Register
            pgm.extend_from_slice(&0u32.to_le_bytes()); // Empty description
            if let Some(address) = address {
                pgm.extend_from_slice(&address.to_le_bytes());
            }
            pgm.extend_from_slice(&4096u64.to_le_bytes());
            pgm.push(0xFF); // End of range declarations
        }
        pgm.extend_from_slice(pages);

        let mut file = vec![0; 64];
        let magic = b"\x7fVirtualBox SavedState V2.0\n";
        file[..magic.len()].copy_from_slice(magic);
        file[45] = 8;
        file.extend_from_slice(b"\nUnit\n\x00\x00");
        let mut unit = [0; 36];
        unit[16..20].copy_from_slice(&version.to_le_bytes());
        unit[32..36].copy_from_slice(&4u32.to_le_bytes());
        file.extend_from_slice(&unit);
        file.extend_from_slice(b"pgm\0");
        // Small RAW records exercise reads spanning SSM record boundaries.
        for chunk in pgm.chunks(127) {
            file.extend_from_slice(&[0x82, chunk.len() as u8]);
            file.extend_from_slice(chunk);
        }
        file.push(0x81); // SSM terminator
        file.extend_from_slice(&[0; 14]);

        let path = std::env::temp_dir().join(format!(
            "vmkatz-vbox-{tag}-{}-{version}.sav",
            std::process::id()
        ));
        fs::write(&path, file)?;
        let result = VBoxLayer::open(&path);
        fs::remove_file(path)?;
        result
    }

    #[test]
    fn saved_state_versions_preserve_ram_layout() {
        let mut pages = vec![PGM_RAM_RAW | PGM_ADDR_FLAG];
        pages.extend_from_slice(&0x1000u64.to_le_bytes());
        pages.extend_from_slice(&[0xA5; PAGE_SIZE]);
        pages.push(PGM_RAM_ZERO); // Next RAM address is implicit.
        for kind in [
            PGM_MMIO2_RAW,
            PGM_MMIO2_ZERO,
            PGM_ROM_VIRGIN,
            PGM_ROM_SHW_RAW,
            PGM_ROM_SHW_ZERO,
            PGM_ROM_PROT,
        ] {
            pages.push(kind | PGM_ADDR_FLAG);
            pages.extend_from_slice(&[1, 0, 0, 0, 0]); // Range ID and page index
            if matches!(
                kind,
                PGM_ROM_VIRGIN | PGM_ROM_SHW_RAW | PGM_ROM_SHW_ZERO | PGM_ROM_PROT
            ) {
                pages.push(0); // ROM protection
            }
            if matches!(kind, PGM_MMIO2_RAW | PGM_ROM_VIRGIN | PGM_ROM_SHW_RAW) {
                pages.extend_from_slice(&[0xCC; PAGE_SIZE]);
            }
        }
        pages.push(PGM_RAM_BALLOONED); // Device records must not advance the RAM GPA.
        pages.push(PGM_RAM_RAW);
        pages.extend_from_slice(&[0x5A; PAGE_SIZE]);
        pages.push(PGM_END);

        for version in [11, 12, 13, 14, 15] {
            let layer = open_fixture(version, &pages, "layout").unwrap();
            assert_eq!(layer.page_count(), 4);
            assert_eq!(layer.phys_size(), 0x5000);
            let mut data = vec![0xFF; 4 * PAGE_SIZE];
            layer.read_phys(0x1000, &mut data).unwrap();
            assert_eq!(&data[..PAGE_SIZE], &[0xA5; PAGE_SIZE]);
            assert!(data[PAGE_SIZE..3 * PAGE_SIZE].iter().all(|&b| b == 0));
            assert_eq!(&data[3 * PAGE_SIZE..], &[0x5A; PAGE_SIZE]);
            assert!(layer.read_phys(0, &mut [0; 1]).is_err());
        }
    }

    #[test]
    fn empty_ram_uses_configured_size() {
        let layer = open_fixture(14, &[PGM_END], "empty").unwrap();
        assert_eq!(layer.page_count(), 0);
        assert_eq!(layer.phys_size(), 0x8000);
    }

    #[test]
    fn invalid_saved_states_return_errors() {
        for (version, pages, expected) in [
            (10, &[PGM_END][..], io::ErrorKind::Unsupported),
            (14, &[0x7E][..], io::ErrorKind::InvalidData),
            (14, &[PGM_RAM_RAW, 0xA5][..], io::ErrorKind::UnexpectedEof),
        ] {
            let result = open_fixture(version, pages, "invalid");
            assert!(matches!(result, Err(VmkatzError::Io(ref e)) if e.kind() == expected));
        }
    }

    #[test]
    fn lzf_literal_run() {
        // ctrl=1 => 2 literal bytes "AB"
        let out = lzf_decompress(&[0x01, b'A', b'B'], 2).unwrap();
        assert_eq!(out, b"AB");
    }

    #[test]
    fn lzf_rle_overlap_offset1() {
        // "A" then back-ref offset=1 length=4 => replicate last byte (RLE).
        // ctrl=0x40 (len (2>>0)+2=4), off byte 0x00 => offset=1.
        let out = lzf_decompress(&[0x00, b'A', 0x40, 0x00], 5).unwrap();
        assert_eq!(out, b"AAAAA");
    }

    #[test]
    fn lzf_pattern_overlap_offset2() {
        // "AB" then back-ref offset=2 length=4 => period-2 repeat "ABABAB".
        // A naive slice copy would read stale bytes; sequential copy must not.
        let out = lzf_decompress(&[0x01, b'A', b'B', 0x40, 0x01], 6).unwrap();
        assert_eq!(out, b"ABABAB");
    }

    #[test]
    fn lzf_nonoverlap_backref() {
        // "ABCD" then back-ref offset=4 length=4 => copy first 4 bytes.
        let out = lzf_decompress(&[0x03, b'A', b'B', b'C', b'D', 0x40, 0x03], 8).unwrap();
        assert_eq!(out, b"ABCDABCD");
    }
}
