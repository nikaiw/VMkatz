use crate::error::{Result, VmkatzError};

const HEADER_SIZE: usize = 12;
const GROUP_SIZE: usize = 80;
pub const PAGE_SIZE: usize = 0x1000;

const VALID_MAGICS: [u32; 4] = [0xbed2bed0, 0xbad1bad1, 0xbed2bed2, 0xbed3bed3];

#[derive(Debug)]
pub struct VmsnHeader {
    pub magic: u32,
    pub group_count: u32,
}

#[derive(Debug)]
pub struct VmsnGroup {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

impl VmsnHeader {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(VmkatzError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "VMSN header too short",
            )));
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if !VALID_MAGICS.contains(&magic) {
            return Err(VmkatzError::InvalidMagic(magic));
        }
        let _reserved = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let group_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        Ok(Self { magic, group_count })
    }
}

impl VmsnGroup {
    fn parse(data: &[u8]) -> Self {
        let name_bytes = &data[..64];
        let name = name_bytes
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect::<Vec<u8>>();
        let name = String::from_utf8_lossy(&name).to_string();
        let offset = u64::from_le_bytes([
            data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71],
        ]);
        let size = u64::from_le_bytes([
            data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
        ]);
        Self { name, offset, size }
    }
}

/// Parse all groups from a VMSN file.
pub fn parse_vmsn(data: &[u8]) -> Result<(VmsnHeader, Vec<VmsnGroup>)> {
    let header = VmsnHeader::parse(data)?;
    // Cap allocation to prevent OOM from forged group_count
    let max_groups = (data.len() - HEADER_SIZE) / GROUP_SIZE;
    let group_count = usize::try_from(header.group_count)
        .unwrap_or(usize::MAX)
        .min(max_groups);
    let mut groups = Vec::with_capacity(group_count);
    for i in 0..group_count {
        let start = HEADER_SIZE + i * GROUP_SIZE;
        let end = start + GROUP_SIZE;
        if end > data.len() {
            break;
        }
        groups.push(VmsnGroup::parse(&data[start..end]));
    }
    Ok((header, groups))
}
