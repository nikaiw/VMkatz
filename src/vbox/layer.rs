use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{VmkatzError, Result};
use crate::memory::PhysicalMemory;

const PAGE_SIZE: usize = 4096;

// SSM record types
const SSM_REC_TERM: u8 = 1;
const SSM_REC_RAW: u8 = 2;
const SSM_REC_LZF: u8 = 3;
const SSM_REC_ZERO: u8 = 4;

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

/// VirtualBox .sav memory layer: provides physical memory access from saved state files.
///
/// Decompresses the PGM unit from the SSM record stream and builds a GPA→page map.
/// RAM pages are stored in a flat buffer; zero pages are served from a static zero page.
pub struct VBoxLayer {
    /// Flat buffer containing all RAM_RAW page data, concatenated.
    page_data: Vec<u8>,
    /// Map from GPA (page-aligned) to index into page_data (in units of PAGE_SIZE),
    /// or u32::MAX for zero pages.
    page_map: HashMap<u64, u32>,
    /// Highest guest physical address + PAGE_SIZE (end of address space).
    phys_end: u64,
}

/// SSM record stream reader: handles the record layer (RAW, LZF, ZERO, TERM).
/// Presents a flat byte stream from which PGM data can be read sequentially.
struct SsmStream<R: Read + Seek> {
    reader: R,
    /// Buffered decompressed data from current/previous records.
    buf: Vec<u8>,
    /// Current read position within buf.
    pos: usize,
    /// Whether we've hit the TERM record.
    done: bool,
}

impl<R: Read + Seek> SsmStream<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            pos: 0,
            done: false,
        }
    }

    /// Ensure at least `n` bytes are available in the buffer ahead of `pos`.
    fn fill(&mut self, n: usize) -> io::Result<()> {
        while self.buf.len() - self.pos < n && !self.done {
            self.read_record()?;
        }
        if self.buf.len() - self.pos < n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SSM stream ended prematurely",
            ));
        }
        Ok(())
    }

    /// Read one SSM record and append its decompressed payload to buf.
    fn read_record(&mut self) -> io::Result<()> {
        // Compact buffer: discard consumed data
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }

        let mut hdr = [0u8; 1];
        self.reader.read_exact(&mut hdr)?;
        let hdr_byte = hdr[0];

        // Validate: bit 7 must be set
        if hdr_byte & 0xE0 != 0x80 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid SSM record header: 0x{:02x}", hdr_byte),
            ));
        }

        let rec_type = hdr_byte & 0x0F;

        match rec_type {
            SSM_REC_TERM => {
                // Skip the 14-byte terminator payload
                let mut term = [0u8; 14];
                self.reader.read_exact(&mut term)?;
                self.done = true;
            }
            SSM_REC_RAW => {
                let size = self.read_varlen_size()? as usize;
                let start = self.buf.len();
                self.buf.resize(start + size, 0);
                self.reader.read_exact(&mut self.buf[start..start + size])?;
            }
            SSM_REC_LZF => {
                let size = self.read_varlen_size()? as usize;
                if size < 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LZF record with zero size",
                    ));
                }
                // First byte: uncompressed size in 1KB units
                let mut uncomp_units = [0u8; 1];
                self.reader.read_exact(&mut uncomp_units)?;
                let uncomp_size = uncomp_units[0] as usize * 1024;
                let comp_size = size - 1;
                let mut compressed = vec![0u8; comp_size];
                self.reader.read_exact(&mut compressed)?;
                let decompressed = lzf_decompress(&compressed, uncomp_size)?;
                self.buf.extend_from_slice(&decompressed);
            }
            SSM_REC_ZERO => {
                let _size = self.read_varlen_size()?;
                // 1 byte: zero-fill count in 1KB units
                let mut zero_units = [0u8; 1];
                self.reader.read_exact(&mut zero_units)?;
                let zero_size = zero_units[0] as usize * 1024;
                let start = self.buf.len();
                self.buf.resize(start + zero_size, 0);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unknown SSM record type: {}", rec_type),
                ));
            }
        }

        Ok(())
    }

    /// Read VBox's variable-length size encoding.
    fn read_varlen_size(&mut self) -> io::Result<u32> {
        let mut b = [0u8; 1];
        self.reader.read_exact(&mut b)?;
        let b0 = b[0];

        if b0 < 0x80 {
            // 1 byte: 0-127
            return Ok(b0 as u32);
        }

        if b0 < 0xC0 {
            // 0x80-0xBF: 2-byte (VBox relaxed UTF-8)
            self.reader.read_exact(&mut b)?;
            let b1 = b[0];
            return Ok((((b0 & 0x3F) as u32) << 6) | (b1 & 0x3F) as u32);
        }

        if b0 < 0xE0 {
            // 0xC0-0xDF: 2-byte standard UTF-8
            self.reader.read_exact(&mut b)?;
            let b1 = b[0];
            return Ok((((b0 & 0x1F) as u32) << 6) | (b1 & 0x3F) as u32);
        }

        if b0 < 0xF0 {
            // 0xE0-0xEF: 3-byte
            let mut b2 = [0u8; 2];
            self.reader.read_exact(&mut b2)?;
            return Ok((((b0 & 0x0F) as u32) << 12)
                | (((b2[0] & 0x3F) as u32) << 6)
                | (b2[1] & 0x3F) as u32);
        }

        // 0xF0-0xF7: 4-byte
        let mut b3 = [0u8; 3];
        self.reader.read_exact(&mut b3)?;
        Ok((((b0 & 0x07) as u32) << 18)
            | (((b3[0] & 0x3F) as u32) << 12)
            | (((b3[1] & 0x3F) as u32) << 6)
            | (b3[2] & 0x3F) as u32)
    }

    /// Read exactly `n` bytes from the logical stream.
    fn read_bytes(&mut self, n: usize) -> io::Result<Vec<u8>> {
        self.fill(n)?;
        let data = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(data)
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        self.fill(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u32_le(&mut self) -> io::Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64_le(&mut self) -> io::Result<u64> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Skip `n` bytes in the logical stream.
    fn skip(&mut self, n: usize) -> io::Result<()> {
        self.fill(n)?;
        self.pos += n;
        Ok(())
    }

    /// Read a VBox strz: u32 length, then that many bytes (no null terminator).
    fn read_strz(&mut self) -> io::Result<String> {
        let len = self.read_u32_le()? as usize;
        if len == 0 {
            return Ok(String::new());
        }
        let data = self.read_bytes(len)?;
        Ok(String::from_utf8_lossy(&data).to_string())
    }
}

/// LZF decompression (liblzf algorithm).
fn lzf_decompress(data: &[u8], expected_len: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; expected_len];
    let mut ip = 0usize;
    let mut op = 0usize;

    while ip < data.len() {
        let ctrl = data[ip] as usize;
        ip += 1;

        if ctrl < 32 {
            // Literal run: ctrl + 1 bytes
            let length = ctrl + 1;
            if ip + length > data.len() || op + length > expected_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LZF literal overrun",
                ));
            }
            out[op..op + length].copy_from_slice(&data[ip..ip + length]);
            ip += length;
            op += length;
        } else {
            // Back-reference
            let mut length = (ctrl >> 5) + 2;
            if length == 9 {
                // Extended length
                if ip >= data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LZF extended length overrun",
                    ));
                }
                length += data[ip] as usize;
                ip += 1;
            }
            if ip >= data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LZF offset overrun",
                ));
            }
            let offset = ((ctrl & 0x1F) << 8) + data[ip] as usize + 1;
            ip += 1;

            if op < offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LZF back-reference before start",
                ));
            }
            let mut ref_pos = op - offset;
            if op + length > expected_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LZF output overrun",
                ));
            }
            // Copy byte-by-byte (overlapping allowed)
            for _ in 0..length {
                out[op] = out[ref_pos];
                op += 1;
                ref_pos += 1;
            }
        }
    }

    out.truncate(op);
    Ok(out)
}

impl VBoxLayer {
    /// Open a VirtualBox .sav file and extract all RAM pages.
    pub fn open(path: &Path) -> Result<Self> {
        let file = fs::File::open(path)?;
        let file_size = file.metadata()?.len();
        log::info!(
            "VBox .sav file: {} bytes ({} MB)",
            file_size,
            file_size / (1024 * 1024)
        );

        let mut reader = io::BufReader::new(file);

        // 1. Parse file header (64 bytes)
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
        log::info!("VBox header: cbGCPhys={}", cb_gc_phys);

        // 2. Find the "pgm" unit by scanning for unit headers
        let (pgm_data_offset, pgm_version) = Self::find_pgm_unit(&mut reader, file_size)?;
        log::info!(
            "PGM unit data starts at file offset 0x{:x}, version {}",
            pgm_data_offset,
            pgm_version
        );

        // 3. Seek to PGM data and create SSM stream
        reader.seek(SeekFrom::Start(pgm_data_offset))?;
        let mut stream = SsmStream::new(reader);

        // 4. Skip PGM struct fields — size depends on saved state version
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
                    format!("Unsupported PGM saved state version {} (need >= 11, VBox 4.1+)", pgm_version),
                )));
            }
        };
        stream.skip(pgm_struct_size)?;

        // 5. Read RAM config (present in version >= 11)
        let cb_ram_hole = stream.read_u32_le()?;
        let cb_ram = stream.read_u64_le()?;
        log::info!(
            "PGM config: cbRamHole=0x{:x} ({} MB), cbRam=0x{:x} ({} MB)",
            cb_ram_hole,
            cb_ram_hole / (1024 * 1024),
            cb_ram,
            cb_ram / (1024 * 1024)
        );

        // 6. Skip ROM range declarations
        let mut rom_count = 0u32;
        loop {
            let id = stream.read_u8()?;
            if id == 0xFF {
                break;
            }
            let _dev = stream.read_strz()?;
            let _inst = stream.read_u32_le()?;
            let _reg = stream.read_u8()?;
            let _desc = stream.read_strz()?;
            let _gcphys = stream.read_u64_le()?;
            let _cb = stream.read_u64_le()?;
            rom_count += 1;
            log::debug!(
                "ROM range {}: id={} desc='{}' gcphys=0x{:x} size=0x{:x}",
                rom_count,
                id,
                _desc,
                _gcphys,
                _cb
            );
        }
        log::info!("Skipped {} ROM range declarations", rom_count);

        // 7. Skip MMIO2 range declarations
        let mut mmio2_count = 0u32;
        loop {
            let id = stream.read_u8()?;
            if id == 0xFF {
                break;
            }
            let _dev = stream.read_strz()?;
            let _inst = stream.read_u32_le()?;
            let _reg = stream.read_u8()?;
            let _desc = stream.read_strz()?;
            let _cb = stream.read_u64_le()?;
            mmio2_count += 1;
            log::debug!(
                "MMIO2 range {}: id={} desc='{}' size=0x{:x}",
                mmio2_count,
                id,
                _desc,
                _cb
            );
        }
        log::info!("Skipped {} MMIO2 range declarations", mmio2_count);

        // 8. Process page records - collect RAM pages
        let mut page_data: Vec<u8> = Vec::new();
        let mut page_map: HashMap<u64, u32> = HashMap::new();
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
                PGM_RAM_ZERO => {
                    if has_addr {
                        gpa = stream.read_u64_le()?;
                    }
                    page_map.insert(gpa, u32::MAX);
                    gpa += PAGE_SIZE as u64;
                    zero_count += 1;
                }
                PGM_RAM_RAW => {
                    if has_addr {
                        gpa = stream.read_u64_le()?;
                    }
                    let page_idx = (page_data.len() / PAGE_SIZE) as u32;
                    let data = stream.read_bytes(PAGE_SIZE)?;
                    page_data.extend_from_slice(&data);
                    page_map.insert(gpa, page_idx);
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
                PGM_ROM_VIRGIN => {
                    if has_addr {
                        stream.read_u8()?;
                        stream.read_u32_le()?;
                    }
                    stream.read_u8()?; // protection
                    stream.skip(PAGE_SIZE)?;
                    rom_pages += 1;
                }
                PGM_ROM_SHW_RAW => {
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
                PGM_RAM_BALLOONED => {
                    if has_addr {
                        gpa = stream.read_u64_le()?;
                    }
                    page_map.insert(gpa, u32::MAX);
                    gpa += PAGE_SIZE as u64;
                    zero_count += 1;
                }
                _ => {
                    return Err(VmkatzError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unknown PGM page type: 0x{:02x}", base_type),
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
        log::info!(
            "Page data buffer: {} MB, page_map entries: {}",
            page_data.len() / (1024 * 1024),
            page_map.len(),
        );

        // Compute the highest GPA to determine the physical address space size
        let phys_end = page_map
            .keys()
            .max()
            .map(|&max_gpa| max_gpa + PAGE_SIZE as u64)
            .unwrap_or(cb_ram);

        log::info!(
            "Physical address space end: 0x{:x} ({} MB)",
            phys_end,
            phys_end / (1024 * 1024)
        );

        Ok(Self {
            page_data,
            page_map,
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

            let to_read = scan_buf.len().min((file_size - file_pos) as usize);
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
                            "Found pgm unit at offset 0x{:x}, data at 0x{:x}, version {}",
                            unit_offset,
                            data_offset,
                            pgm_version
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
        self.page_map.len()
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

            match self.page_map.get(&cur_page) {
                Some(&idx) if idx == u32::MAX => {
                    // Zero page
                    buf[buf_pos..buf_pos + to_copy].fill(0);
                }
                Some(&idx) => {
                    let data_start = idx as usize * PAGE_SIZE + cur_offset;
                    let data_end = data_start + to_copy;
                    if data_end > self.page_data.len() {
                        return Err(VmkatzError::UnmappablePhysical(cur_addr));
                    }
                    buf[buf_pos..buf_pos + to_copy]
                        .copy_from_slice(&self.page_data[data_start..data_end]);
                }
                None => {
                    return Err(VmkatzError::UnmappablePhysical(cur_addr));
                }
            }

            buf_pos += to_copy;
            remaining -= to_copy;
            cur_addr += to_copy as u64;
        }

        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.phys_end
    }
}
