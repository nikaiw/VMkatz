use std::io::{Read, Seek, SeekFrom};

pub const HIVE_LEN: u64 = 2 << 30;
const CELL_BASE: u32 = 256 * 1024 * 1024;

pub struct LargeHive {
    pub regions: Vec<(u64, Vec<u8>)>,
    position: u64,
    pub bytes_read: usize,
}

impl Read for LargeHive {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = output
            .len()
            .min(HIVE_LEN.saturating_sub(self.position) as usize);
        assert!(count <= 65536, "whole-hive allocation/read");
        self.bytes_read += count;
        assert!(self.bytes_read <= 512 * 1024, "unexpected hive scan");
        output[..count].fill(0);
        for (offset, bytes) in &self.regions {
            let start = self.position.max(*offset);
            let end = (self.position + count as u64).min(offset + bytes.len() as u64);
            if start < end {
                output[(start - self.position) as usize..(end - self.position) as usize]
                    .copy_from_slice(&bytes[(start - offset) as usize..(end - offset) as usize]);
            }
        }
        self.position += count as u64;
        Ok(count)
    }
}
impl Seek for LargeHive {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.position = match position {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => HIVE_LEN.checked_add_signed(delta),
        }
        .ok_or_else(|| std::io::Error::other("invalid fixture seek"))?;
        Ok(self.position)
    }
}

struct Builder {
    cells: Vec<u8>,
}
impl Builder {
    fn cell(&mut self, data: &[u8]) -> u32 {
        let offset = CELL_BASE + self.cells.len() as u32;
        let size = (data.len() + 4).next_multiple_of(8);
        self.cells
            .extend_from_slice(&(-(size as i32)).to_le_bytes());
        self.cells.extend_from_slice(data);
        self.cells
            .resize(self.cells.len() + size - 4 - data.len(), 0);
        offset
    }
    fn key(
        &mut self,
        name: &str,
        children: &[u32],
        values: &[(&str, &[u8])],
        class: Option<&str>,
    ) -> u32 {
        let mut nk = vec![0; 0x4C];
        nk[..2].copy_from_slice(b"nk");
        put32(&mut nk, 0x14, children.len() as u32);
        let mut list = b"li".to_vec();
        list.extend_from_slice(&(children.len() as u16).to_le_bytes());
        for child in children {
            list.extend_from_slice(&child.to_le_bytes());
        }
        put32(&mut nk, 0x1C, self.cell(&list));
        let mut list = Vec::new();
        for (name, data) in values {
            let mut vk = vec![0; 0x14];
            vk[..2].copy_from_slice(b"vk");
            vk[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            put32(&mut vk, 4, data.len() as u32);
            put32(&mut vk, 8, self.cell(data));
            vk.extend_from_slice(name.as_bytes());
            list.extend_from_slice(&self.cell(&vk).to_le_bytes());
        }
        put32(&mut nk, 0x24, values.len() as u32);
        put32(&mut nk, 0x28, self.cell(&list));
        if let Some(class) = class {
            let bytes: Vec<u8> = class.encode_utf16().flat_map(u16::to_le_bytes).collect();
            put32(&mut nk, 0x30, self.cell(&bytes));
            nk[0x4A..0x4C].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        }
        nk[0x48..0x4A].copy_from_slice(&(name.len() as u16).to_le_bytes());
        nk.extend_from_slice(name.as_bytes());
        self.cell(&nk)
    }
    fn finish(self, root: u32) -> LargeHive {
        let mut header = vec![0; 4096];
        header[..4].copy_from_slice(b"regf");
        put32(&mut header, 0x24, root);
        put32(&mut header, 0x28, HIVE_LEN as u32 - 4096);
        LargeHive {
            regions: vec![(0, header), (4096 + u64::from(CELL_BASE), self.cells)],
            position: 0,
            bytes_read: 0,
        }
    }
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn system() -> LargeHive {
    let mut b = Builder { cells: Vec::new() };
    let mut children = Vec::new();
    for (name, class) in [
        ("JD", "00010203"),
        ("Skew1", "04050607"),
        ("GBG", "08090a0b"),
        ("Data", "0c0d0e0f"),
    ] {
        children.push(b.key(name, &[], &[], Some(class)));
    }
    let lsa = b.key("Lsa", &children, &[], None);
    let control = b.key("Control", &[lsa], &[], None);
    let cs = b.key("ControlSet001", &[control], &[], None);
    let root = b.key("SYSTEM", &[cs], &[], None);
    b.finish(root)
}

pub fn sam() -> LargeHive {
    let mut b = Builder { cells: Vec::new() };
    let mut user_v = vec![0; 0xCC];
    let user_name: Vec<u8> = "fixture-user"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    put32(&mut user_v, 0x10, user_name.len() as u32);
    user_v.extend_from_slice(&user_name);
    let user = b.key("000001F4", &[], &[("V", &user_v)], None);
    let users = b.key("Users", &[user], &[], None);
    let mut f = [0; 0xA0];
    f[0] = 2;
    let account = b.key("Account", &[users], &[("F", &f)], None);
    let domains = b.key("Domains", &[account], &[], None);
    let sam = b.key("SAM", &[domains], &[], None);
    let root = b.key("SAM", &[sam], &[], None);
    b.finish(root)
}

pub fn security() -> LargeHive {
    let mut b = Builder { cells: Vec::new() };
    let encrypted = b.key("PolSecretEncryptionKey", &[], &[("", &[0; 0x4C])], None);
    let policy = b.key("Policy", &[encrypted], &[], None);
    let root = b.key("SECURITY", &[policy], &[], None);
    b.finish(root)
}
