use std::io::{Read, Seek, SeekFrom};

pub const HUGE_FILE: u64 = 8 << 40;
const CLUSTER: u64 = 4096;

pub struct Disk {
    regions: Vec<(u64, Vec<u8>)>,
    pos: u64,
    len: u64,
    pub bytes_read: usize,
}

impl Read for Disk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = buf.len().min(self.len.saturating_sub(self.pos) as usize);
        let buf = &mut buf[..count];
        self.bytes_read += count;
        assert!(
            self.bytes_read <= 512 * 1024,
            "unexpected whole-file read or recovery scan"
        );
        assert!(buf.len() <= 65536, "unbounded NTFS read");
        buf.fill(0);
        let end = self.pos + buf.len() as u64;
        for (start, bytes) in &self.regions {
            let from = self.pos.max(*start);
            let to = end.min(start + bytes.len() as u64);
            if from < to {
                buf[(from - self.pos) as usize..(to - self.pos) as usize]
                    .copy_from_slice(&bytes[(from - start) as usize..(to - start) as usize]);
            }
        }
        self.pos = end;
        Ok(buf.len())
    }
}

impl Seek for Disk {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
        }
        .ok_or_else(|| std::io::Error::other("invalid test seek"))?;
        Ok(self.pos)
    }
}

fn put16(buf: &mut [u8], at: usize, value: u16) {
    buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(buf: &mut [u8], at: usize, value: u32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(buf: &mut [u8], at: usize, value: u64) {
    buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn record(attribute: &[u8], directory: bool) -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..4].copy_from_slice(b"FILE");
    put16(&mut bytes, 4, 48);
    put16(&mut bytes, 6, 3);
    put16(&mut bytes, 20, 56);
    put16(&mut bytes, 22, if directory { 3 } else { 1 });
    put32(&mut bytes, 24, (56 + attribute.len() + 8) as u32);
    put32(&mut bytes, 28, 1024);
    bytes[56..56 + attribute.len()].copy_from_slice(attribute);
    put32(&mut bytes, 56 + attribute.len(), u32::MAX);
    for at in [48, 510, 1022] {
        put16(&mut bytes, at, 0xABCD);
    }
    bytes
}

fn resident(kind: u32, name: &str, data: &[u8]) -> Vec<u8> {
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let value_offset = (24 + name.len()).next_multiple_of(8);
    let mut bytes = vec![0; (value_offset + data.len()).next_multiple_of(8)];
    let len = bytes.len() as u32;
    put32(&mut bytes, 0, kind);
    put32(&mut bytes, 4, len);
    bytes[9] = (name.len() / 2) as u8;
    put16(&mut bytes, 10, 24);
    put32(&mut bytes, 16, data.len() as u32);
    put16(&mut bytes, 20, value_offset as u16);
    bytes[24..24 + name.len()].copy_from_slice(&name);
    bytes[value_offset..value_offset + data.len()].copy_from_slice(data);
    bytes
}

fn nonresident(len: u64, runs: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; (64 + runs.len()).next_multiple_of(8)];
    let size = bytes.len() as u32;
    put32(&mut bytes, 0, 0x80);
    put32(&mut bytes, 4, size);
    bytes[8] = 1;
    put64(&mut bytes, 24, len.div_ceil(CLUSTER) - 1);
    put16(&mut bytes, 32, 64);
    put64(&mut bytes, 40, len);
    put64(&mut bytes, 48, len);
    put64(&mut bytes, 56, len);
    bytes[64..64 + runs.len()].copy_from_slice(runs);
    bytes
}

fn directory(entries: &[(&str, u64)]) -> Vec<u8> {
    let mut data = vec![0; 32];
    put32(&mut data, 0, 0x30);
    put32(&mut data, 4, 1);
    put32(&mut data, 8, 4096);
    data[12] = 1;
    put32(&mut data, 16, 16);
    for (name, record) in entries {
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut entry = vec![0; (16 + 66 + name.len()).next_multiple_of(8)];
        let len = entry.len() as u16;
        put64(&mut entry, 0, *record);
        put16(&mut entry, 8, len);
        put16(&mut entry, 10, (66 + name.len()) as u16);
        entry[16 + 64] = (name.len() / 2) as u8;
        entry[16 + 65] = 1;
        entry[16 + 66..16 + 66 + name.len()].copy_from_slice(&name);
        data.extend(entry);
    }
    let mut end = [0; 16];
    put16(&mut end, 8, 16);
    put16(&mut end, 12, 2);
    data.extend(end);
    let len = data.len() as u32 - 16;
    put32(&mut data, 20, len);
    put32(&mut data, 24, len);
    record(&resident(0x90, "$I30", &data), true)
}

fn catalog_record(kind: u16, id: u32, value: u32, name: &str) -> Vec<u8> {
    let mut row = vec![0; 42];
    row[0] = 9;
    row[1] = 128;
    put16(&mut row, 2, 40);
    put32(&mut row, 4, 42);
    put16(&mut row, 8, kind);
    put32(&mut row, 10, id);
    put32(&mut row, 14, value);
    put32(&mut row, 18, 4);
    put16(&mut row, 31, 4);
    put16(&mut row, 40, name.len() as u16);
    row.extend_from_slice(name.as_bytes());
    row
}

pub fn leaf(rows: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0; CLUSTER as usize];
    put16(&mut bytes, 0x22, (rows.len() + 1) as u16);
    put32(&mut bytes, 0x24, 3);
    let mut offset = 0;
    for (i, row) in rows.iter().enumerate() {
        let len = row.len() + 2;
        bytes[40 + offset + 2..40 + offset + len].copy_from_slice(row);
        put32(
            &mut bytes,
            CLUSTER as usize - (i + 2) * 4,
            ((offset as u32) << 16) | len as u32,
        );
        offset += len;
    }
    bytes
}

pub fn disk(large_system: bool) -> Disk {
    let mut boot = vec![0; 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    put16(&mut boot, 11, 512);
    boot[13] = 8;
    put64(&mut boot, 40, 2048);
    put64(&mut boot, 48, 1);
    boot[64] = 246;
    boot[68] = 244;
    put16(&mut boot, 510, 0xAA55);
    let mut regions = vec![
        (0, boot),
        (
            CLUSTER,
            record(&nonresident(32768, &[0x11, 8, 1, 0]), false),
        ),
    ];
    for (number, entries) in [
        (5, vec![("Windows", 10)]),
        (10, vec![("NTDS", 11), ("System32", 13)]),
        (11, vec![("ntds.dit", 12)]),
        (13, vec![("config", 14)]),
        (14, vec![("SAM", 16), ("SECURITY", 17), ("SYSTEM", 15)]),
    ] {
        regions.push((CLUSTER + number * 1024, directory(&entries)));
    }
    let mut runs = vec![0x11, 32, 64, 0x04];
    runs.extend_from_slice(&((HUGE_FILE / CLUSTER - 33) as u32).to_le_bytes());
    runs.extend_from_slice(&[0x11, 1, 64, 0]);
    regions.push((
        CLUSTER + 12 * 1024,
        record(&nonresident(HUGE_FILE, &runs), false),
    ));
    for number in [15, 16, 17] {
        let attr = if number == 15 && large_system {
            nonresident(128 * 1024 * 1024, &[0x02, 0, 128, 0])
        } else {
            resident(0x80, "", b"fixture")
        };
        regions.push((CLUSTER + number * 1024, record(&attr, false)));
    }
    let mut header = vec![0; 4096];
    header[4..8].copy_from_slice(&[0xEF, 0xCD, 0xAB, 0x89]);
    put32(&mut header, 0xEC, 4096);
    regions.push((64 * CLUSTER, header));
    let last_page = (HUGE_FILE / CLUSTER - 2) as u32;
    regions.push((
        64 * CLUSTER + 5 * CLUSTER,
        leaf(&[
            catalog_record(1, 42, last_page, "datatable"),
            catalog_record(2, 1, 4, "value"),
        ]),
    ));
    regions.push((
        128 * CLUSTER,
        leaf(&[vec![1, 127, 8, 0, 0x78, 0x56, 0x34, 0x12]]),
    ));
    Disk {
        regions,
        pos: 0,
        len: 1024 * 1024,
        bytes_read: 0,
    }
}

#[cfg(feature = "ntds.dit")]
pub fn write_workstation(
    path: &std::path::Path,
    hives: [Vec<(u64, Vec<u8>)>; 3],
    hive_len: u64,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut disk = disk(false);
    for (number, regions) in [15, 16, 17].into_iter().zip(hives) {
        disk.replace_hive(number, hive_len, regions);
    }
    disk.regions
        .push((CLUSTER + 10 * 1024, directory(&[("System32", 13)])));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.set_len(disk.len)?;
    for (offset, bytes) in disk.regions {
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&bytes)?;
    }
    Ok(())
}

#[cfg(feature = "sam")]
impl Disk {
    pub fn replace_hive(&mut self, number: u64, len: u64, regions: Vec<(u64, Vec<u8>)>) {
        let base = number * len + 1024 * 1024;
        self.len = self.len.max(base + len);
        if let Some((_, boot)) = self.regions.iter_mut().find(|(at, _)| *at == 0) {
            put64(boot, 40, self.len / 512);
        }
        let mut runs = vec![0x44];
        runs.extend_from_slice(&(len.div_ceil(CLUSTER) as u32).to_le_bytes());
        runs.extend_from_slice(&((base / CLUSTER) as u32).to_le_bytes());
        runs.push(0);
        let at = CLUSTER + number * 1024;
        self.regions.retain(|(offset, _)| *offset != at);
        self.regions
            .push((at, record(&nonresident(len, &runs), false)));
        self.regions.extend(
            regions
                .into_iter()
                .map(|(offset, bytes)| (base + offset, bytes)),
        );
    }
}
