use crate::error::{Result, VmkatzError as Error};

#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
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
    Ok(match serial_type {
        0 => (Value::Null, 0),
        1 => (Value::Int(b[0] as i8 as i64), 1),
        2 => (Value::Int(i16::from_be_bytes([b[0], b[1]]) as i64), 2),
        3 => {
            let v = ((b[0] as i64) << 56) >> 40 | ((b[1] as i64) << 8) | (b[2] as i64);
            // Sign-extend 24-bit
            let signed = if v & 0x0080_0000 != 0 { v | (!0xFF_FFFFi64) } else { v };
            (Value::Int(signed), 3)
        }
        4 => (Value::Int(i32::from_be_bytes(b[..4].try_into().unwrap()) as i64), 4),
        5 => {
            let mut bytes = [0u8; 8];
            bytes[2..].copy_from_slice(&b[..6]);
            let raw = i64::from_be_bytes(bytes);
            // Sign-extend from 48-bit
            let signed = if raw & 0x0000_8000_0000_0000 != 0 {
                raw | (0xFFFFu64 << 48) as i64
            } else {
                raw
            };
            (Value::Int(signed), 6)
        }
        6 => (Value::Int(i64::from_be_bytes(b[..8].try_into().unwrap())), 8),
        7 => (Value::Real(f64::from_be_bytes(b[..8].try_into().unwrap())), 8),
        8 => (Value::Int(0), 0),
        9 => (Value::Int(1), 0),
        10 | 11 => return Err(Error::Parse("reserved serial type".into())),
        t if t >= 12 && t % 2 == 0 => {
            let n = ((t - 12) / 2) as usize;
            (Value::Blob(b[..n].to_vec()), n)
        }
        t if t >= 13 && t % 2 == 1 => {
            let n = ((t - 13) / 2) as usize;
            let s = String::from_utf8_lossy(&b[..n]).into_owned();
            (Value::Text(s), n)
        }
        _ => return Err(Error::Parse(format!("bad serial type {}", serial_type))),
    })
}

impl Value {
    pub fn as_text(&self) -> Option<&str> {
        if let Value::Text(s) = self { Some(s) } else { None }
    }
    pub fn as_blob(&self) -> Option<&[u8]> {
        if let Value::Blob(b) = self { Some(b) } else { None }
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
}
