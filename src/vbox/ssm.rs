//! Seekable SSM stream with bounded decompression and sparse checkpoints.

use std::collections::VecDeque;
use std::io::{self, BufReader, Read, Seek, SeekFrom};

const CHECKPOINT_INTERVAL: u64 = 8 * 1024 * 1024;
const MAX_CHECKPOINTS: usize = 65_536;
const CACHE_RECORDS: usize = 16;

#[derive(Clone, Copy)]
struct Checkpoint {
    logical: u64,
    file: u64,
}

#[derive(Clone, Copy)]
struct Record {
    kind: u8,
    start: u64,
    end: u64,
    payload: u64,
    stored_end: u64,
}

pub(super) struct SsmStream<R: Read + Seek> {
    reader: BufReader<R>,
    file_size: u64,
    pos: u64,
    next_file: u64,
    record: Option<Record>,
    checkpoints: Vec<Checkpoint>,
    interval: u64,
    cache: VecDeque<(u64, Vec<u8>)>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl<R: Read + Seek> SsmStream<R> {
    pub(super) fn new(reader: R, start: u64, file_size: u64) -> io::Result<Self> {
        let mut reader = BufReader::with_capacity(64 * 1024, reader);
        reader.seek(SeekFrom::Start(start))?;
        Ok(Self {
            reader,
            file_size,
            pos: 0,
            next_file: start,
            record: None,
            checkpoints: vec![Checkpoint {
                logical: 0,
                file: start,
            }],
            interval: CHECKPOINT_INTERVAL,
            cache: VecDeque::new(),
        })
    }

    pub(super) const fn position(&self) -> u64 {
        self.pos
    }

    fn seek_file(&mut self, offset: u64) -> io::Result<()> {
        let delta = i128::from(offset) - i128::from(self.reader.stream_position()?);
        if let Ok(delta) = i64::try_from(delta) {
            self.reader.seek_relative(delta)
        } else {
            self.reader.seek(SeekFrom::Start(offset)).map(|_| ())
        }
    }

    fn add_checkpoint(&mut self, file: u64) -> io::Result<()> {
        let Some(last) = self.checkpoints.last() else {
            return Ok(());
        };
        if self.pos.saturating_sub(last.logical) < self.interval {
            return Ok(());
        }
        if self.checkpoints.len() == MAX_CHECKPOINTS {
            let mut index = 0usize;
            self.checkpoints.retain(|_| {
                let keep = index.is_multiple_of(2);
                index += 1;
                keep
            });
            self.interval = self.interval.saturating_mul(2);
        }
        self.checkpoints.try_reserve(1).map_err(io::Error::other)?;
        self.checkpoints.push(Checkpoint {
            logical: self.pos,
            file,
        });
        Ok(())
    }

    fn ensure_record(&mut self) -> io::Result<Record> {
        loop {
            if let Some(record) = self.record {
                if self.pos < record.end {
                    return Ok(record);
                }
                self.next_file = record.stored_end;
            }
            let file = self.next_file;
            self.seek_file(file)?;
            let mut byte = [0];
            self.reader.read_exact(&mut byte)?;
            if byte[0] & 0xE0 != 0x80 {
                return Err(invalid("Invalid SSM record header"));
            }
            let kind = byte[0] & 0x0F;
            if kind == 1 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "End of SSM stream",
                ));
            }
            let size = u64::from(self.read_varlen_size()?);
            let (len, stored_len) = match kind {
                2 => (size, size),
                3 => {
                    if size == 0 {
                        return Err(invalid("LZF record with zero size"));
                    }
                    self.reader.read_exact(&mut byte)?;
                    (u64::from(byte[0]) * 1024, size - 1)
                }
                4 => {
                    if size != 1 {
                        return Err(invalid("Invalid SSM zero record size"));
                    }
                    self.reader.read_exact(&mut byte)?;
                    (u64::from(byte[0]) * 1024, 0)
                }
                _ => return Err(invalid("Unknown SSM record type")),
            };
            let payload = self.reader.stream_position()?;
            let stored_end = payload
                .checked_add(stored_len)
                .filter(|&end| end <= self.file_size)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "Truncated SSM record")
                })?;
            let end = self
                .pos
                .checked_add(len)
                .ok_or_else(|| invalid("SSM logical offset overflow"))?;
            self.add_checkpoint(file)?;
            self.record = Some(Record {
                kind,
                start: self.pos,
                end,
                payload,
                stored_end,
            });
        }
    }

    pub(super) fn seek_logical(&mut self, target: u64) -> io::Result<()> {
        if self
            .record
            .is_some_and(|r| r.start <= target && target < r.end)
        {
            self.pos = target;
            return Ok(());
        }
        let index = self
            .checkpoints
            .partition_point(|c| c.logical <= target)
            .saturating_sub(1);
        let checkpoint = self.checkpoints[index];
        if target < self.pos || checkpoint.logical > self.pos {
            self.pos = checkpoint.logical;
            self.next_file = checkpoint.file;
            self.record = None;
        }
        self.skip_bytes(target - self.pos)
    }

    pub(super) fn read_exact(&mut self, mut output: &mut [u8]) -> io::Result<()> {
        while !output.is_empty() {
            let record = self.ensure_record()?;
            let within = usize::try_from(self.pos - record.start).map_err(io::Error::other)?;
            let count = output
                .len()
                .min(usize::try_from(record.end - self.pos).map_err(io::Error::other)?);
            match record.kind {
                2 => {
                    self.seek_file(record.payload + within as u64)?;
                    self.reader.read_exact(&mut output[..count])?;
                }
                3 => {
                    if !self
                        .cache
                        .iter()
                        .any(|(offset, _)| *offset == record.payload)
                    {
                        if self.cache.len() == CACHE_RECORDS {
                            self.cache.pop_front();
                        }
                        self.seek_file(record.payload)?;
                        let size = usize::try_from(record.stored_end - record.payload)
                            .map_err(io::Error::other)?;
                        let mut compressed = crate::utils::zeroed_buffer(size)?;
                        self.reader.read_exact(&mut compressed)?;
                        let expected =
                            usize::try_from(record.end - record.start).map_err(io::Error::other)?;
                        let data = lzf_decompress(&compressed, expected)?;
                        if data.len() != expected {
                            return Err(invalid("Truncated LZF output"));
                        }
                        self.cache.push_back((record.payload, data));
                    }
                    let data = self
                        .cache
                        .iter()
                        .find(|(offset, _)| *offset == record.payload)
                        .ok_or_else(|| invalid("SSM cache entry missing"))?;
                    output[..count].copy_from_slice(&data.1[within..within + count]);
                }
                4 => output[..count].fill(0),
                _ => return Err(invalid("Unknown SSM record type")),
            }
            self.pos += count as u64;
            output = &mut output[count..];
        }
        Ok(())
    }

    fn skip_bytes(&mut self, mut count: u64) -> io::Result<()> {
        while count != 0 {
            let record = self.ensure_record()?;
            let step = count.min(record.end - self.pos);
            self.pos += step;
            count -= step;
        }
        Ok(())
    }

    pub(super) fn skip(&mut self, count: usize) -> io::Result<()> {
        self.skip_bytes(count as u64)
    }

    pub(super) fn read_u8(&mut self) -> io::Result<u8> {
        let mut bytes = [0];
        self.read_exact(&mut bytes)?;
        Ok(bytes[0])
    }
    pub(super) fn read_u32_le(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    pub(super) fn read_u64_le(&mut self) -> io::Result<u64> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    pub(super) fn read_strz(&mut self) -> io::Result<String> {
        let len = self.read_u32_le()? as usize;
        if len > 1024 * 1024 {
            return Err(invalid("SSM string exceeds 1 MiB"));
        }
        let mut data = crate::utils::zeroed_buffer(len)?;
        self.read_exact(&mut data)?;
        Ok(String::from_utf8_lossy(&data).into_owned())
    }
    /// Read VBox's variable-length size encoding.
    fn read_varlen_size(&mut self) -> io::Result<u32> {
        let mut b = [0u8; 1];
        self.reader.read_exact(&mut b)?;
        let b0 = b[0];

        if b0 < 0x80 {
            // 1 byte: 0-127
            return Ok(u32::from(b0));
        }

        if b0 < 0xC0 {
            // 0x80-0xBF: 2-byte (VBox relaxed UTF-8)
            self.reader.read_exact(&mut b)?;
            let b1 = b[0];
            return Ok((u32::from(b0 & 0x3F) << 6) | u32::from(b1 & 0x3F));
        }

        if b0 < 0xE0 {
            // 0xC0-0xDF: 2-byte standard UTF-8
            self.reader.read_exact(&mut b)?;
            let b1 = b[0];
            return Ok((u32::from(b0 & 0x1F) << 6) | u32::from(b1 & 0x3F));
        }

        if b0 < 0xF0 {
            // 0xE0-0xEF: 3-byte
            let mut b2 = [0u8; 2];
            self.reader.read_exact(&mut b2)?;
            return Ok((u32::from(b0 & 0x0F) << 12)
                | (u32::from(b2[0] & 0x3F) << 6)
                | u32::from(b2[1] & 0x3F));
        }

        // 0xF0-0xF7: 4-byte
        let mut b3 = [0u8; 3];
        self.reader.read_exact(&mut b3)?;
        Ok((u32::from(b0 & 0x07) << 18)
            | (u32::from(b3[0] & 0x3F) << 12)
            | (u32::from(b3[1] & 0x3F) << 6)
            | u32::from(b3[2] & 0x3F))
    }
}

/// LZF decompression (liblzf algorithm).
pub(super) fn lzf_decompress(data: &[u8], expected_len: usize) -> io::Result<Vec<u8>> {
    let mut out = crate::utils::zeroed_buffer(expected_len)?;
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
            let ref_pos = op - offset;
            if op + length > expected_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "LZF output overrun",
                ));
            }
            // Copy byte-by-byte (overlapping back-reference: reads may hit
            // bytes written earlier in this same loop, so it stays sequential).
            for i in 0..length {
                out[op + i] = out[ref_pos + i];
            }
            op += length;
        }
    }

    out.truncate(op);
    Ok(out)
}

#[cfg(test)]
#[path = "ssm/tests.rs"]
mod tests;
