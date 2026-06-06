use crate::error::{Result, VmkatzError as Error};

#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Int(i64),
    Real(f64),
    /// Raw bytes from a TEXT-affinity column. SQLite does not enforce UTF-8 on
    /// TEXT columns; Chromium stores v10/v20-prefixed binary cookie ciphertext
    /// in a "TEXT" column here. UTF-8 conversion is lazy via `as_text`.
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

/// Decode a SQLite "huffman" varint (1-9 bytes, big-endian, 7 bits per byte except the
/// 9th which contributes all 8). Returns (value, bytes_consumed).
pub fn read_varint(bytes: &[u8]) -> Result<(i64, usize)> {
    let mut acc: u64 = 0;
    for i in 0..8 {
        if i >= bytes.len() {
            return Err(Error::Parse("varint truncated".into()));
        }
        let b = bytes[i];
        acc = (acc << 7) | ((b & 0x7F) as u64);
        if b & 0x80 == 0 {
            return Ok((acc as i64, i + 1));
        }
    }
    if bytes.len() < 9 {
        return Err(Error::Parse("varint 9-byte truncated".into()));
    }
    acc = (acc << 8) | (bytes[8] as u64);
    Ok((acc as i64, 9))
}

/// Decode the cell payload of one table B-tree leaf row.
/// `payload` is the in-cell payload (overflow pages NOT spliced — caller handles overflow).
pub fn decode_record(payload: &[u8]) -> Result<Vec<Value>> {
    let (hdr_size_signed, hdr_off) = read_varint(payload)?;
    if hdr_size_signed < 0 {
        return Err(Error::Parse("record header size negative".into()));
    }
    let hdr_size = hdr_size_signed as usize;
    if hdr_size > payload.len() {
        return Err(Error::Parse("record header > payload".into()));
    }
    let mut types: Vec<i64> = Vec::new();
    let mut cur = hdr_off;
    while cur < hdr_size {
        let (t, n) = read_varint(&payload[cur..])?;
        types.push(t);
        cur += n;
    }
    let mut body = hdr_size;
    let mut out = Vec::with_capacity(types.len());
    for t in types {
        let (v, sz) = decode_value(t, &payload[body..])?;
        out.push(v);
        body += sz;
    }
    Ok(out)
}

fn decode_value(serial_type: i64, b: &[u8]) -> Result<(Value, usize)> {
    fn need(b: &[u8], n: usize) -> Result<()> {
        if b.len() < n {
            return Err(Error::Parse("record value truncated".into()));
        }
        Ok(())
    }
    Ok(match serial_type {
        0 => (Value::Null, 0),
        1 => {
            need(b, 1)?;
            (Value::Int(b[0] as i8 as i64), 1)
        }
        2 => {
            need(b, 2)?;
            (Value::Int(i16::from_be_bytes([b[0], b[1]]) as i64), 2)
        }
        3 => {
            need(b, 3)?;
            // 24-bit big-endian, sign-extended via arithmetic shift.
            let v = ((b[0] as i64) << 56) >> 40 | ((b[1] as i64) << 8) | (b[2] as i64);
            (Value::Int(v), 3)
        }
        4 => {
            need(b, 4)?;
            (Value::Int(i32::from_be_bytes(b[..4].try_into().unwrap()) as i64), 4)
        }
        5 => {
            need(b, 6)?;
            let mut bytes = [0u8; 8];
            bytes[2..].copy_from_slice(&b[..6]);
            let raw = i64::from_be_bytes(bytes);
            // Sign-extend from 48-bit if bit 47 is set.
            let signed = if raw & 0x0000_8000_0000_0000 != 0 {
                raw | 0xFFFF_0000_0000_0000_u64 as i64
            } else {
                raw
            };
            (Value::Int(signed), 6)
        }
        6 => {
            need(b, 8)?;
            (Value::Int(i64::from_be_bytes(b[..8].try_into().unwrap())), 8)
        }
        7 => {
            need(b, 8)?;
            (Value::Real(f64::from_be_bytes(b[..8].try_into().unwrap())), 8)
        }
        8 => (Value::Int(0), 0),
        9 => (Value::Int(1), 0),
        10 | 11 => return Err(Error::Parse("reserved serial type".into())),
        t if t >= 12 && t % 2 == 0 => {
            let n = ((t - 12) / 2) as usize;
            need(b, n)?;
            (Value::Blob(b[..n].to_vec()), n)
        }
        t if t >= 13 && t % 2 == 1 => {
            let n = ((t - 13) / 2) as usize;
            need(b, n)?;
            (Value::Text(b[..n].to_vec()), n)
        }
        _ => return Err(Error::Parse(format!("bad serial type {}", serial_type))),
    })
}

impl Value {
    /// UTF-8 decode of a TEXT column. Returns None if bytes aren't valid UTF-8 (Chromium
    /// stores binary ciphertext in some TEXT columns — use `text_bytes`/`as_bytes` then).
    pub fn as_text(&self) -> Option<&str> {
        if let Value::Text(b) = self { std::str::from_utf8(b).ok() } else { None }
    }
    pub fn as_blob(&self) -> Option<&[u8]> {
        if let Value::Blob(b) = self { Some(b) } else { None }
    }
    /// Raw bytes for either a TEXT or BLOB column. Useful when a TEXT column
    /// holds binary data (e.g. Chromium cookies).
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Text(b) | Value::Blob(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        if let Value::Int(i) = self { Some(*i) } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_one_byte() {
        assert_eq!(read_varint(&[0x05]).unwrap(), (5, 1));
    }
    #[test]
    fn varint_two_byte() {
        // 0x81 0x00 = 128
        assert_eq!(read_varint(&[0x81, 0x00]).unwrap(), (128, 2));
    }
    #[test]
    fn decode_record_text_int_blob() {
        // header_size = 4, serial types: 23 (text len 5) + 1 (int8) + 14 (blob len 1)
        // i.e. text "hello", int 7, blob 0xAA
        let mut payload = vec![0x04, 23, 1, 14];
        payload.extend_from_slice(b"hello");
        payload.push(0x07);
        payload.push(0xAA);
        let r = decode_record(&payload).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].as_text(), Some("hello"));
        assert_eq!(r[1].as_int(), Some(7));
        assert_eq!(r[2].as_blob(), Some(&[0xAAu8][..]));
    }

    #[test]
    fn decode_record_rejects_truncated_value() {
        // Header claims a 5-byte text value (serial type 23 = 13+5*2),
        // but the body has only 3 bytes. Must error, not panic.
        let payload = vec![0x02u8, 23, b'h', b'i', b'!'];
        let r = decode_record(&payload);
        assert!(r.is_err(), "expected error on truncated text value");
    }

    #[test]
    fn decode_record_rejects_negative_header_size() {
        // Varint encoding of a value whose top bit-after-shifts is 1 would yield
        // a "negative" i64 when interpreted signed. Use the 9-byte varint form:
        // bytes 0..8 are 0xFF, byte 8 = 0xFF -> result is 0xFFFF_FFFF_FFFF_FFFFu64 as i64 = -1.
        let payload = vec![0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let r = decode_record(&payload);
        assert!(r.is_err(), "expected error on negative header size");
    }
}
