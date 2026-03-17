use crate::error::{VmkatzError, Result};

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
        let magic = crate::utils::read_u32_le(data, 0).unwrap_or(0);
        if !VALID_MAGICS.contains(&magic) {
            return Err(VmkatzError::InvalidMagic(magic));
        }
        let _reserved = crate::utils::read_u32_le(data, 4).unwrap_or(0);
        let group_count = crate::utils::read_u32_le(data, 8).unwrap_or(0);
        Ok(Self {
            magic,
            group_count,
        })
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
        let offset = crate::utils::read_u64_le(data, 64).unwrap_or(0);
        let size = crate::utils::read_u64_le(data, 72).unwrap_or(0);
        Self { name, offset, size }
    }
}

/// Parse all groups from a VMSN file.
pub fn parse_vmsn(data: &[u8]) -> Result<(VmsnHeader, Vec<VmsnGroup>)> {
    let header = VmsnHeader::parse(data)?;
    // Cap allocation to prevent OOM from forged group_count
    let max_groups = (data.len() - HEADER_SIZE) / GROUP_SIZE;
    let mut groups = Vec::with_capacity((header.group_count as usize).min(max_groups));
    for i in 0..header.group_count as usize {
        let start = HEADER_SIZE + i * GROUP_SIZE;
        let end = start + GROUP_SIZE;
        if end > data.len() {
            break;
        }
        groups.push(VmsnGroup::parse(&data[start..end]));
    }
    Ok((header, groups))
}
