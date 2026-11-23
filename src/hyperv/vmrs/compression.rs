//! XPRESS decoding and VmCompressUnpack RAM block framing.

use super::RAM_BLOCK_SIZE;
use crate::utils::u32_le;

/// Plain XPRESS (LZ77) decompression — `RtlDecompressBufferEx` with
/// `COMPRESSION_FORMAT_XPRESS` (3), per [MS-XCA] §2.4. This is what Hyper-V's
/// `VmCompressUnpack` uses for each saved-state RAM page (NOT LZNT1). Writes
/// decompressed bytes into `out` and returns the count written.
fn xpress_decompress(input: &[u8], out: &mut [u8]) -> usize {
    let mut in_pos = 0usize;
    let mut out_pos = 0usize;
    let mut flags: u32 = 0;
    let mut flag_count = 0u32;
    let mut last_len_halfbyte = 0usize;

    loop {
        if flag_count == 0 {
            if in_pos + 4 > input.len() {
                break;
            }
            flags = u32_le(input, in_pos);
            in_pos += 4;
            flag_count = 32;
        }
        let is_match = flags & 0x8000_0000 != 0;
        flags <<= 1;
        flag_count -= 1;

        if !is_match {
            if in_pos >= input.len() || out_pos >= out.len() {
                break;
            }
            out[out_pos] = input[in_pos];
            in_pos += 1;
            out_pos += 1;
            continue;
        }

        // Match: 16-bit (length:3, offset:13)
        if in_pos + 2 > input.len() {
            break;
        }
        let match_bytes = u16::from_le_bytes([input[in_pos], input[in_pos + 1]]) as usize;
        in_pos += 2;
        let match_offset = (match_bytes >> 3) + 1;
        let mut match_length = match_bytes & 7;
        if match_length == 7 {
            if last_len_halfbyte == 0 {
                if in_pos >= input.len() {
                    break;
                }
                match_length = (input[in_pos] & 0xf) as usize;
                last_len_halfbyte = in_pos;
                in_pos += 1;
            } else {
                match_length = (input[last_len_halfbyte] >> 4) as usize;
                last_len_halfbyte = 0;
            }
            if match_length == 15 {
                if in_pos >= input.len() {
                    break;
                }
                match_length = input[in_pos] as usize;
                in_pos += 1;
                if match_length == 255 {
                    if in_pos + 2 > input.len() {
                        break;
                    }
                    match_length = u16::from_le_bytes([input[in_pos], input[in_pos + 1]]) as usize;
                    in_pos += 2;
                    let Some(length) = match_length.checked_sub(15 + 7) else {
                        break;
                    };
                    match_length = length;
                }
                match_length += 15;
            }
            match_length += 7;
        }
        match_length += 3;

        if match_offset > out_pos {
            break; // invalid back-reference
        }
        for _ in 0..match_length {
            if out_pos >= out.len() {
                break;
            }
            out[out_pos] = out[out_pos - match_offset];
            out_pos += 1;
        }
    }
    out_pos
}

/// Decompress a VmCompressUnpack-encoded buffer into a 1MB block.
///
/// Format: sequence of tagged pages:
/// - 0xFFFFFFFF: end marker
/// - 0xFFFFFFFE: fill 1 page (4KB) with 8-byte repeating pattern
/// - 0xFFFFFFFD: fill N pages with pattern (pattern followed by count)
/// - 0xFFFFFFFC: variable page size
/// - other: compressed_size — if page size, raw copy; else XPRESS decompress
pub(super) fn vm_compress_unpack(data: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; RAM_BLOCK_SIZE];
    let mut out_offset = 0usize;
    let mut in_offset = 0usize;
    let mut short_decode = false; // an XPRESS page produced fewer bytes than its page size

    while in_offset + 4 <= data.len() && out_offset < RAM_BLOCK_SIZE {
        let tag = u32_le(data, in_offset);
        in_offset += 4;

        match tag {
            0xFFFFFFFF => {
                // End marker
                break;
            }
            0xFFFFFFFE => {
                // Fill 1 page with 8-byte pattern
                if in_offset + 8 > data.len() {
                    break;
                }
                let pattern = &data[in_offset..in_offset + 8];
                in_offset += 8;
                let page_end = (out_offset + 4096).min(RAM_BLOCK_SIZE);
                while out_offset + 8 <= page_end {
                    output[out_offset..out_offset + 8].copy_from_slice(pattern);
                    out_offset += 8;
                }
                // Handle remainder
                while out_offset < page_end {
                    output[out_offset] = pattern[(out_offset - (page_end - 4096)) % 8];
                    out_offset += 1;
                }
            }
            0xFFFFFFFD => {
                // Fill N pages with an 8-byte pattern. Layout per VmCompressUnpack:
                // [pattern: u64][count: u32] (pattern FIRST, then count).
                if in_offset + 12 > data.len() {
                    break;
                }
                let pattern = data[in_offset..in_offset + 8].to_vec();
                let count = u32_le(data, in_offset + 8) as usize;
                in_offset += 12;
                for _ in 0..count {
                    let page_end = (out_offset + 4096).min(RAM_BLOCK_SIZE);
                    if out_offset >= page_end {
                        break;
                    }
                    let mut k = 0;
                    while out_offset < page_end {
                        output[out_offset] = pattern[k % 8];
                        out_offset += 1;
                        k += 1;
                    }
                }
            }
            0xFFFFFFFC => {
                // Variable-size page. Layout per VmCompressUnpack:
                // [uncompressed_size: u32 (<=0xfff)][compressed_size: u32][data].
                // Output advances by uncompressed_size (NOT a full 4096 page).
                if in_offset + 8 > data.len() {
                    break;
                }
                let uncomp = u32_le(data, in_offset) as usize;
                let comp = u32_le(data, in_offset + 4) as usize;
                in_offset += 8;
                let Some(input_end) = in_offset.checked_add(comp) else {
                    break;
                };
                let Some(output_end) = out_offset.checked_add(uncomp) else {
                    break;
                };
                if uncomp == 0
                    || uncomp > 4096
                    || output_end > RAM_BLOCK_SIZE
                    || comp > uncomp
                    || input_end > data.len()
                {
                    break;
                }
                let end = output_end;
                if comp == uncomp {
                    let n = end - out_offset;
                    output[out_offset..end].copy_from_slice(&data[in_offset..in_offset + n]);
                } else {
                    let n = xpress_decompress(
                        &data[in_offset..in_offset + comp],
                        &mut output[out_offset..end],
                    );
                    short_decode |= n < end - out_offset;
                }
                out_offset += uncomp;
                in_offset += comp;
            }
            compressed_size => {
                let compressed_size = compressed_size as usize;
                if compressed_size == 4096 {
                    // Uncompressed page — raw copy
                    if in_offset + 4096 > data.len() {
                        break;
                    }
                    let copy_len = 4096.min(RAM_BLOCK_SIZE - out_offset);
                    output[out_offset..out_offset + copy_len]
                        .copy_from_slice(&data[in_offset..in_offset + copy_len]);
                    out_offset += 4096;
                    in_offset += 4096;
                } else if compressed_size > 0 && compressed_size < 4096 {
                    // XPRESS compressed page (RtlDecompressBufferEx format 3)
                    if in_offset + compressed_size > data.len() {
                        break;
                    }
                    let end = (out_offset + 4096).min(RAM_BLOCK_SIZE);
                    let n = xpress_decompress(
                        &data[in_offset..in_offset + compressed_size],
                        &mut output[out_offset..end],
                    );
                    short_decode |= n < end - out_offset;
                    out_offset += 4096;
                    in_offset += compressed_size;
                } else {
                    // Invalid tag
                    log::warn!(
                        "VMRS: Invalid compression tag {:#x} at offset {}",
                        tag,
                        in_offset - 4
                    );
                    break;
                }
            }
        }
    }

    // Warn when a short XPRESS decode leaves a zero-filled tail.
    if short_decode {
        log::warn!("VMRS: XPRESS page under-decompressed in a RAM block — data may be incomplete");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::xpress_decompress;

    // Plain XPRESS (MS-XCA §2.4): "AB" then a match (offset 2, length 3) => "ABABA".
    // flags=0x20000000 (bit29 set = 3rd symbol is a match); match u16 = (off-1<<3)|(len-3).
    #[test]
    fn xpress_match_basic() {
        let input = [0x00, 0x00, 0x00, 0x20, b'A', b'B', 0x08, 0x00];
        let mut out = [0u8; 5];
        let n = xpress_decompress(&input, &mut out);
        assert_eq!(&out[..n], b"ABABA", "got {:?}", &out[..n]);
    }

    // All-literal: flags=0 => 4 literal bytes.
    #[test]
    fn xpress_literals() {
        let input = [0x00, 0x00, 0x00, 0x00, b'W', b'X', b'Y', b'Z'];
        let mut out = [0u8; 4];
        let n = xpress_decompress(&input, &mut out);
        assert_eq!(&out[..n], b"WXYZ");
    }

    // RLE via offset-1 match: "A" then match(off1,len4) => "AAAAA".
    #[test]
    fn xpress_rle() {
        // match u16 = ((1-1)<<3)|(4-3) = 1
        let input = [0x00, 0x00, 0x00, 0x40, b'A', 0x01, 0x00];
        let mut out = [0u8; 5];
        let n = xpress_decompress(&input, &mut out);
        assert_eq!(&out[..n], b"AAAAA", "got {:?}", &out[..n]);
    }
}
