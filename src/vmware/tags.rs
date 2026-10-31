use crate::error::Result;

#[derive(Debug, Clone)]
pub struct Tag {
    pub name: String,
    pub indices: Vec<u32>,
    pub data_offset: u64,
    pub data_size: u64,
}

/// Parse tags from a VMware memory group.
///
/// Tag format:
///   byte 0: flags - `bits[7:6]` = index_count (0-3), `bits[5:0]` = inline_data_len
///   byte 1: name_len
///   bytes 2..2+name_len: name (ASCII)
///   next index_count*4 bytes: indices (u32 LE each)
///   if inline_data_len < 62: data_size = inline_data_len
///   if inline_data_len == 62 or 63: next 8 bytes = data_size (u64 LE)
///   next data_size bytes: data payload
///
/// Terminates when flags == 0 && name_len == 0.
pub fn parse_tags(data: &[u8], base_offset: u64) -> Result<Vec<Tag>> {
    let mut tags = Vec::new();
    let mut pos: usize = 0;

    loop {
        if pos.checked_add(2).is_none_or(|end| end > data.len()) {
            break;
        }
        let flags = data[pos];
        let name_len = data[pos + 1] as usize;
        if flags == 0 && name_len == 0 {
            break;
        }
        pos += 2;

        if pos.checked_add(name_len).is_none_or(|end| end > data.len()) {
            break;
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        pos += name_len;

        let index_count = ((flags >> 6) & 3) as usize;
        let Some(index_bytes) = index_count.checked_mul(4) else {
            break;
        };
        if pos
            .checked_add(index_bytes)
            .is_none_or(|end| end > data.len())
        {
            break; // Not enough data for all indices — stop parsing
        }
        let mut indices = Vec::with_capacity(index_count);
        for _ in 0..index_count {
            indices.push(u32::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]));
            pos += 4;
        }

        let inline_len = u64::from(flags & 0x3F);
        let data_size = if inline_len >= 62 {
            if pos + 8 > data.len() {
                break;
            }
            let Some(size) = crate::utils::read_u64_le(data, pos) else {
                break;
            };
            pos += 8;
            size
        } else {
            inline_len
        };

        let Ok(pos_u64) = u64::try_from(pos) else {
            break;
        };
        let Some(data_offset) = base_offset.checked_add(pos_u64) else {
            break;
        };
        tags.push(Tag {
            name,
            indices,
            data_offset,
            data_size,
        });

        // Guard against overflow: data_size must fit in remaining buffer
        let remaining = data.len() - pos;
        let Ok(data_size_usize) = usize::try_from(data_size) else {
            break;
        };
        if data_size_usize > remaining {
            break;
        }
        pos += data_size_usize;
    }

    Ok(tags)
}

/// Find a tag by name and optional indices.
pub fn find_tag<'a>(tags: &'a [Tag], name: &str, indices: &[u32]) -> Option<&'a Tag> {
    tags.iter().find(|t| t.name == name && t.indices == indices)
}
