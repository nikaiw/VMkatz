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
///   byte 0: flags - bits[7:6] = index_count (0-3), bits[5:0] = inline_data_len
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
        if pos + 2 > data.len() {
            break;
        }
        let flags = data[pos];
        let name_len = data[pos + 1] as usize;
        if flags == 0 && name_len == 0 {
            break;
        }
        pos += 2;

        if pos + name_len > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        pos += name_len;

        let index_count = ((flags >> 6) & 3) as usize;
        let mut indices = Vec::with_capacity(index_count);
        for _ in 0..index_count {
            if pos + 4 > data.len() {
                break;
            }
            indices.push(crate::utils::read_u32_le(data, pos).unwrap_or(0));
            pos += 4;
        }

        let inline_len = (flags & 0x3F) as u64;
        let data_size = if inline_len >= 62 {
            if pos + 8 > data.len() {
                break;
            }
            let size = crate::utils::read_u64_le(data, pos).unwrap_or(0);
            pos += 8;
            size
        } else {
            inline_len
        };

        let data_offset = base_offset + pos as u64;
        tags.push(Tag {
            name,
            indices,
            data_offset,
            data_size,
        });

        // Guard against overflow: data_size must fit in remaining buffer
        if data_size > (data.len() - pos) as u64 {
            break;
        }
        pos += data_size as usize;
    }

    Ok(tags)
}

/// Find a tag by name and optional indices.
pub fn find_tag<'a>(tags: &'a [Tag], name: &str, indices: &[u32]) -> Option<&'a Tag> {
    tags.iter().find(|t| t.name == name && t.indices == indices)
}
