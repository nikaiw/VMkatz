//! Normalized block properties shared by parsers and reconstruction.

use serde::Serialize;

/// Compression applied to a stored block.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// Stored bytes are the reconstructed bytes.
    None,
    /// Legacy Veeam run-length encoding.
    Rle,
    /// Legacy zlib encoding.
    Zlib,
    /// Standard LZ4 block encoding.
    Lz4,
    /// Zstandard encoding.
    Zstd,
    /// Modern Veeam-framed LZ4 block encoding.
    VeeamLz4,
    /// Identifier recognized as a compression field but not understood by this build.
    Unsupported(u16),
}

impl Compression {
    /// Decode a modern physical-record compression identifier.
    ///
    /// Windows Agent server-managed fulls set the upper byte of this `u16` to the in-band
    /// per-block digest-engine hint (`0x00` = MD5, `0x01` = BLAKE3-128; for example
    /// `0x0107` is a BLAKE3-framed LZ4 block). This is independent of the storage-header
    /// `DigestType` string, which those writers keep at `md5` even when every block is
    /// BLAKE3-128. The algorithm selector is always in the low byte, so the upper byte is
    /// ignored when normalizing the identifier and is consumed separately for digest
    /// dispatch.
    ///
    /// The low-byte selector reproduces the empirical mapping observed across every
    /// fixture the tool ships: `0` and `255` = uncompressed, `1` = RLE, `2`/`3` = zlib,
    /// `4` = LZ4, `5`/`8`/`9` = zstd (writer levels 3 and 9 collapse into the same
    /// decoder because zstd frames self-describe), and `7` = LZ4 with the 12-byte magic
    /// `0xF800000F` + CRC32C + `SourceSize` prelude that `dissect.archive` names
    /// `Lz4BlockHeader`. `io::block::CDataBlock::GetCompressionImpl` in Extract.exe
    /// (`sub_1403A9B70`) uses a partially-overlapping scheme (`2` = RLE, `3`/`4` =
    /// zlib high/low, `7` = LZ4, `8`/`9` = zstd), but Veeam's older writers — including
    /// the `test13` and `test9` fixtures — emit the older scheme this table matches, so
    /// the two are kept aligned by keeping `2`/`3` as zlib and `4` as raw LZ4.
    pub const fn from_modern(identifier: u16) -> Self {
        match identifier & 0xFF {
            0 | 255 => Self::None,
            1 => Self::Rle,
            2 | 3 => Self::Zlib,
            4 => Self::Lz4,
            5 | 8 | 9 => Self::Zstd,
            7 => Self::VeeamLz4,
            _ => Self::Unsupported(identifier),
        }
    }

    /// Return the serialized identifier when it is not supported.
    pub const fn unsupported_identifier(self) -> Option<u16> {
        match self {
            Self::Unsupported(identifier) => Some(identifier),
            Self::None | Self::Rle | Self::Zlib | Self::Lz4 | Self::Zstd | Self::VeeamLz4 => None,
        }
    }

    /// Whether decoding requires a decompression algorithm.
    pub const fn is_compressed(self) -> bool {
        match self {
            Self::None => false,
            Self::Rle
            | Self::Zlib
            | Self::Lz4
            | Self::Zstd
            | Self::VeeamLz4
            | Self::Unsupported(_) => true,
        }
    }
}

/// Expected digest of reconstructed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Digest {
    /// The format records no digest for this range.
    None,
    /// MD5 content digest.
    Md5([u8; 16]),
    /// SHA-256 content digest.
    Sha256([u8; 32]),
    /// BLAKE3 digest truncated to 128 bits.
    Blake3_128([u8; 16]),
}

impl Digest {
    /// Convert a legacy all-zero MD5 field to `None`.
    pub fn from_optional_md5(bytes: [u8; 16]) -> Self {
        if bytes == [0; 16] {
            Self::None
        } else {
            Self::Md5(bytes)
        }
    }

    /// Return the 16-byte digest value for the engines that use one, or `None` for an
    /// absent digest or a 32-byte SHA-256. Used to cross-check a record's stored digest
    /// bytes against the digest of the physical block it references.
    #[must_use]
    pub const fn short_bytes(&self) -> Option<[u8; 16]> {
        match self {
            Self::Md5(bytes) | Self::Blake3_128(bytes) => Some(*bytes),
            Self::None | Self::Sha256(_) => None,
        }
    }

    /// Build a 16-byte digest tagged with the engine indicated by `digest_type`.
    ///
    /// Mirrors the dispatch used by `CDigestCalcImpl` (Extract.exe): a zero engine ID
    /// selects MD5 and a one selects BLAKE3 truncated to 128 bits. Server-managed
    /// agent-format physical records carry the engine ID in the high byte of their
    /// compression `u16`; modern logical records carry it in the high nibble of the
    /// state byte. An all-zero field maps to `None` regardless of the engine ID because
    /// that is how the writer suppresses per-block verification.
    ///
    /// Any other engine ID returns `None` too. Extract.exe throws
    /// `CDigestCalcImpl(): unsupported digest type` on the same condition, and the caller
    /// treats `None` as "no verifiable digest" — so an unknown engine ID makes the block
    /// unmatchable rather than being silently mis-tagged as MD5.
    pub fn from_engine(bytes: [u8; 16], digest_type: u8) -> Self {
        if bytes == [0; 16] {
            return Self::None;
        }
        match digest_type {
            0 => Self::Md5(bytes),
            1 => Self::Blake3_128(bytes),
            _ => Self::None,
        }
    }
}

/// Source of a logical range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReference {
    /// Implicit zero-filled range. Mirrors `dissect.archive`'s
    /// `BlockLocationType::Sparse` (`= 1`) and server-managed agent state byte with
    /// `kind_nibble == 1`.
    Zero,
    /// Global physical block index in the current storage. Mirrors
    /// `dissect.archive`'s `BlockLocationType::Normal` (`= 0`) and server-managed agent
    /// state byte with `kind_nibble == 0`.
    Local(u64),
    /// Block identifier that must be resolved in a parent restore point.
    Parent(u64),
    /// Block identifier that must be resolved through a deduplication index — the
    /// `BlockInBlob` and `BlockInBlobReserved` variants in `dissect.archive`. Not
    /// currently reachable from the parser; kept for future work.
    Deduplicated(u64),
    /// Object stored outside the current backup file — the `Archived` variant in
    /// `dissect.archive` (compressed payload encoded inside `BlockId`). Not currently
    /// reachable from the parser; kept for future work.
    External([u8; 16]),
}

/// Writer flag byte at `FibBlockDescriptorV7.Flags` (offset 29 of the 46-byte logical
/// record).
///
/// `vbktool` currently ignores it; the type is provided so downstream tooling can treat
/// the byte semantically instead of a raw integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockFlags {
    /// No flags set.
    None,
    /// Writer marked the block as pending an update at commit time.
    Updated,
    /// Writer was in the middle of committing when the snapshot slot was serialised.
    CommitInProgress,
    /// Unknown flag bits. Preserved verbatim so callers can decide how to react.
    Unknown(u8),
}

impl BlockFlags {
    /// Interpret a raw `Flags` byte per `dissect.archive`'s `BlockFlags` enum.
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Self::None,
            0x01 => Self::Updated,
            0x02 => Self::CommitInProgress,
            other => Self::Unknown(other),
        }
    }
}
