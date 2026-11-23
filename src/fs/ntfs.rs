use std::io::{Read, Seek, Write};

use ntfs::structured_values::NtfsFileNamespace;

use crate::error::{Result, VmkatzError};

mod stream;
pub(crate) use stream::ResilientReader;

/// Maximum size of a single buffered NTFS file read.
pub const MAX_BUFFERED_BYTES: usize = 128 * 1024 * 1024;

pub trait ReadSeek: Read + Seek {}
impl<R: Read + Seek> ReadSeek for R {}

/// Wraps a Read+Seek with a partition offset.
pub struct PartitionReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> PartitionReader<'a, R> {
    pub const fn new(inner: &'a mut R, offset: u64) -> Self {
        Self { inner, offset }
    }
}

impl<R: Read + Seek> Read for PartitionReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for PartitionReader<'_, R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::io::{Error, ErrorKind, SeekFrom};
        let invalid = || {
            Error::new(
                ErrorKind::InvalidInput,
                "seek outside partition address space",
            )
        };
        let target = match pos {
            SeekFrom::Start(offset) => self.offset.checked_add(offset),
            SeekFrom::Current(delta) => self.inner.stream_position()?.checked_add_signed(delta),
            SeekFrom::End(delta) => {
                // Probing the disk length must not move the cursor if validation fails.
                let original = self.inner.stream_position()?;
                let end = self.inner.seek(SeekFrom::End(0))?;
                self.inner.seek(SeekFrom::Start(original))?;
                end.checked_add_signed(delta)
            }
        }
        .ok_or_else(invalid)?;
        target.checked_sub(self.offset).ok_or_else(invalid)?;
        self.inner
            .seek(SeekFrom::Start(target))?
            .checked_sub(self.offset)
            .ok_or_else(invalid)
    }
}

/// Find a directory entry by name (case-insensitive).
pub fn find_entry<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    dir: &ntfs::NtfsFile<'n>,
    reader: &mut R,
    name: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    let index = dir.directory_index(reader).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!(
            "Directory index error for '{name}': {e}"
        ))
    })?;
    let mut iter = index.entries();
    while let Some(entry) = iter.next(reader) {
        let entry = entry.map_err(|e| {
            crate::error::VmkatzError::DecryptionError(format!("Dir entry error: {e}"))
        })?;
        // key() returns Option<Result<NtfsFileName>>
        let key = match entry.key() {
            Some(Ok(k)) => k,
            Some(Err(e)) => {
                log::warn!("Index key error: {e}");
                continue;
            }
            None => continue, // Last entry sentinel, no key
        };
        if key.name().to_string_lossy().eq_ignore_ascii_case(name) {
            let file = entry.to_file(ntfs, reader).map_err(|e| {
                crate::error::VmkatzError::DecryptionError(format!("Failed to open '{name}': {e}"))
            })?;
            return Ok(file);
        }
    }
    Err(crate::error::VmkatzError::NtfsEntryNotFound(
        name.to_string(),
    ))
}

/// Read a small unnamed $DATA stream, capped at 128 MiB.
/// Large consumers should use [`with_file_data`] and read only needed ranges.
pub fn read_file_data<R: Read + Seek>(file: &ntfs::NtfsFile, reader: &mut R) -> Result<Vec<u8>> {
    read_file_data_bounded(file, reader, MAX_BUFFERED_BYTES)
}

/// Reject oversize metadata before allocating. `limit` may tighten the 128 MiB ceiling.
pub fn read_file_data_bounded<R: Read + Seek>(
    file: &ntfs::NtfsFile,
    reader: &mut R,
    limit: usize,
) -> Result<Vec<u8>> {
    with_file_data(file, reader, |stream, len| {
        let limit = limit.min(MAX_BUFFERED_BYTES);
        if len > limit as u64 {
            return Err(VmkatzError::AllocTooLarge {
                what: "NTFS buffered file",
                requested: usize::try_from(len).unwrap_or(usize::MAX),
                limit,
            });
        }
        let mut data = crate::utils::zeroed_buffer(len as usize)?;
        ResilientReader::new(stream, len).read_exact(&mut data)?;
        Ok(data)
    })
}

/// Give a consumer a seekable $DATA stream without loading it into memory.
/// The NTFS reader preserves resident, fragmented and sparse attribute handling.
pub fn with_file_data<R: Read + Seek, T>(
    file: &ntfs::NtfsFile,
    reader: &mut R,
    consume: impl FnOnce(&mut dyn ReadSeek, u64) -> Result<T>,
) -> Result<T> {
    let item = file
        .data(reader, "")
        .ok_or_else(|| VmkatzError::DecryptionError("No $DATA attribute".into()))?
        .map_err(|e| VmkatzError::DecryptionError(format!("$DATA error: {e}")))?;
    let attribute = item
        .to_attribute()
        .map_err(|e| VmkatzError::DecryptionError(format!("to_attribute error: {e}")))?;
    let value = attribute
        .value(reader)
        .map_err(|e| VmkatzError::DecryptionError(format!("Attribute value error: {e}")))?;
    let len = value.len();
    consume(&mut value.attach(reader), len)
}

/// Copy the unnamed NTFS $DATA stream to a new host file with bounded memory.
///
/// Unlike registry recovery, this propagates read errors and premature EOF.
/// Existing paths (including symlinks) are refused; partial outputs created by
/// this call are removed on a copy or flush error.
pub fn copy_file_to_path<R: Read + Seek>(
    file: &ntfs::NtfsFile,
    reader: &mut R,
    destination: &std::path::Path,
) -> Result<u64> {
    let item = file
        .data(reader, "")
        .ok_or_else(|| crate::error::VmkatzError::DecryptionError("No $DATA attribute".into()))?
        .map_err(|e| crate::error::VmkatzError::DecryptionError(format!("$DATA error: {e}")))?;
    let attr = item.to_attribute().map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("to_attribute error: {e}"))
    })?;
    let value = attr.value(reader).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("Attribute value error: {e}"))
    })?;
    let len = value.len();
    copy_to_new_file(&mut value.attach(reader), len, destination)?;
    Ok(len)
}

fn copy_to_new_file<R: Read>(
    reader: &mut R,
    len: u64,
    path: &std::path::Path,
) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let result = copy_exact(reader, &mut file, len).and_then(|()| file.flush());
    if result.is_err() {
        drop(file);
        if let Err(error) = std::fs::remove_file(path) {
            log::warn!("Cannot remove incomplete copy {}: {error}", path.display());
        }
    }
    result
}

fn copy_exact<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    while remaining != 0 {
        let count = crate::disk::read_len(remaining, buf.len());
        reader.read_exact(&mut buf[..count])?;
        writer.write_all(&buf[..count])?;
        remaining -= count as u64;
    }
    Ok(())
}

/// Kind of a directory entry; a directory carries no size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File { size: u64 },
}

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: EntryKind,
}

/// Shared listing policy: drop `.`/`..`, drop `$`-prefixed metafiles unless
/// `show_metafiles`, dedup case-insensitively (first wins), sort directories
/// first then by case-insensitive name.
pub fn finalize(raw: Vec<DirEntry>, show_metafiles: bool) -> Vec<DirEntry> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<DirEntry> = raw
        .into_iter()
        .filter(|e| e.name != "." && e.name != "..")
        .filter(|e| show_metafiles || !e.name.starts_with('$'))
        .filter(|e| seen.insert(e.name.to_lowercase()))
        .collect();
    out.sort_by_key(|e| {
        (
            matches!(e.kind, EntryKind::File { .. }),
            e.name.to_lowercase(),
        )
    });
    out
}

/// Iterate a healthy directory index, skipping DOS 8.3 short names.
/// Filtering, dedup and ordering are left to `finalize`.
pub(crate) fn list_index<'n, R: Read + Seek>(
    _ntfs: &'n ntfs::Ntfs,
    dir: &ntfs::NtfsFile<'n>,
    reader: &mut R,
) -> Result<Vec<DirEntry>> {
    let index = dir.directory_index(reader).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("Directory index error: {e}"))
    })?;
    let mut entries = Vec::new();
    let mut iter = index.entries();
    while let Some(entry) = iter.next(reader) {
        let Ok(entry) = entry else { continue };
        let Some(Ok(key)) = entry.key() else { continue };
        if key.namespace() == NtfsFileNamespace::Dos {
            continue;
        }
        let kind = if key.is_directory() {
            EntryKind::Dir
        } else {
            EntryKind::File {
                size: key.data_size(),
            }
        };
        entries.push(DirEntry {
            name: key.name().to_string_lossy().clone(),
            kind,
        });
    }
    Ok(entries)
}

/// List all file/directory names in a directory.
pub fn list_directory<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    dir: &ntfs::NtfsFile<'n>,
    reader: &mut R,
) -> Result<Vec<(String, bool)>> {
    let entries = finalize(list_index(ntfs, dir, reader)?, false);
    Ok(entries
        .into_iter()
        .map(|e| (e.name, matches!(e.kind, EntryKind::Dir)))
        .collect())
}

/// Navigate to a directory by path components.
pub fn navigate_to_dir<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    root: &ntfs::NtfsFile<'n>,
    reader: &mut R,
    path: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    let components: Vec<&str> = path.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    let mut current = root.clone();
    for &component in &components {
        current = find_entry(ntfs, &current, reader, component)?;
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_recovery_seek_zeroes_the_chunk_without_reading_stale_data() {
        struct BadSeek {
            inner: std::io::Cursor<Vec<u8>>,
            failed: bool,
        }
        impl Read for BadSeek {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                assert!(!self.failed, "read attempted after failed seek");
                if buf.len() > 4096 {
                    return Err(std::io::Error::other("injected bulk read failure"));
                }
                self.inner.read(buf)
            }
        }
        impl Seek for BadSeek {
            fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
                self.failed = pos == std::io::SeekFrom::Start(4096);
                if self.failed {
                    return Err(std::io::Error::other("injected seek failure"));
                }
                self.inner.seek(pos)
            }
        }
        let input = [vec![0x11; 4096], vec![0x22; 4096], vec![0x33; 4096]].concat();
        let mut reader = BadSeek {
            inner: std::io::Cursor::new(input),
            failed: false,
        };
        let mut output = vec![0xFF; 3 * 4096];
        ResilientReader::new(&mut reader, output.len() as u64)
            .read_exact(&mut output)
            .unwrap();
        assert_eq!(&output[..4096], &[0x11; 4096]);
        assert_eq!(&output[4096..8192], &[0; 4096]);
        assert_eq!(&output[8192..], &[0x33; 4096]);
    }

    #[test]
    fn copy_streams_more_than_two_gib_with_a_bounded_buffer() {
        struct ZeroSource {
            remaining: u64,
            max_request: usize,
        }
        impl Read for ZeroSource {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.max_request = self.max_request.max(buf.len());
                let n = self.remaining.min(buf.len() as u64) as usize;
                // The copy buffer starts at zero and this mock only produces zeroes.
                self.remaining -= n as u64;
                Ok(n)
            }
        }
        let size = (2u64 << 30) + 17;
        let mut reader = ZeroSource {
            remaining: size,
            max_request: 0,
        };
        copy_exact(&mut reader, &mut std::io::sink(), size).unwrap();
        assert_eq!(reader.remaining, 0);
        assert!(reader.max_request <= 64 * 1024);
    }

    #[test]
    fn copy_checks_length_and_propagates_writer_errors() {
        struct BadWriter;
        impl Write for BadWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut output = Vec::new();
        copy_exact(&mut &b"abcdef"[..], &mut output, 3).unwrap();
        assert_eq!(output, b"abc");
        assert_eq!(
            copy_exact(&mut &b"ab"[..], &mut output, 3)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            copy_exact(&mut &b"abc"[..], &mut BadWriter, 3)
                .unwrap_err()
                .to_string(),
            "disk full"
        );
    }

    #[test]
    fn copy_preserves_existing_paths_and_removes_incomplete_outputs() {
        let dir = std::env::temp_dir().join(format!(
            "vmkatz-copy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let dst = dir.join("destination");
        std::fs::write(&dst, b"original").unwrap();
        let mut reader = std::io::Cursor::new(b"replacement");
        assert_eq!(
            copy_to_new_file(&mut reader, 11, &dst).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(reader.position(), 0);
        assert_eq!(std::fs::read(&dst).unwrap(), b"original");
        #[cfg(unix)]
        {
            let link = dir.join("link");
            std::os::unix::fs::symlink(&dst, &link).unwrap();
            assert_eq!(
                copy_to_new_file(&mut reader, 11, &link).unwrap_err().kind(),
                std::io::ErrorKind::AlreadyExists
            );
            assert_eq!(std::fs::read(&dst).unwrap(), b"original");
        }
        let partial = dir.join("partial");
        assert_eq!(
            copy_to_new_file(
                &mut std::io::Cursor::new(vec![0; 65536 + 3]),
                65536 + 4,
                &partial
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert!(!partial.exists());
        copy_to_new_file(&mut &b"data"[..], 4, &partial).unwrap();
        assert_eq!(std::fs::read(&partial).unwrap(), b"data");
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn d(n: &str) -> DirEntry {
        DirEntry {
            name: n.into(),
            kind: EntryKind::Dir,
        }
    }
    fn f(n: &str, size: u64) -> DirEntry {
        DirEntry {
            name: n.into(),
            kind: EntryKind::File { size },
        }
    }
    fn names(v: &[DirEntry]) -> Vec<&str> {
        v.iter().map(|e| e.name.as_str()).collect()
    }

    #[test]
    fn finalize_sorts_dirs_first_then_alpha() {
        let out = finalize(
            vec![f("b.txt", 1), d("Zeta"), f("A.txt", 2), d("alpha")],
            false,
        );
        assert_eq!(names(&out), ["alpha", "Zeta", "A.txt", "b.txt"]);
    }

    #[test]
    fn finalize_drops_dot_entries() {
        let out = finalize(vec![d("."), d(".."), f("x", 0)], false);
        assert_eq!(names(&out), ["x"]);
    }

    #[test]
    fn finalize_metafile_policy() {
        let raw = || vec![f("$MFT", 10), f("a", 1)];
        assert_eq!(names(&finalize(raw(), false)), ["a"]);
        assert_eq!(names(&finalize(raw(), true)), ["$MFT", "a"]);
    }

    #[test]
    fn finalize_dedups_case_insensitively() {
        let out = finalize(vec![d("Windows"), d("WINDOWS")], false);
        assert_eq!(names(&out), ["Windows"]);
    }
}
