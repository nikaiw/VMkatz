use std::io::{Read, Seek};

use ntfs::NtfsReadSeek;
use ntfs::structured_values::NtfsFileNamespace;

use crate::error::Result;

/// Wraps a Read+Seek with a partition offset.
pub struct PartitionReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> PartitionReader<'a, R> {
    pub const fn new(inner: &'a mut R, offset: u64) -> Self {
        Self { inner, offset }
    }

    /// Access the underlying reader (for fallback paths that manage offsets themselves).
    #[cfg(feature = "sam")]
    pub(crate) const fn inner_mut(&mut self) -> &mut R {
        self.inner
    }
}

impl<R: Read + Seek> Read for PartitionReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for PartitionReader<'_, R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Start(offset) => {
                let actual = self
                    .inner
                    .seek(std::io::SeekFrom::Start(self.offset + offset))?;
                Ok(actual - self.offset)
            }
            std::io::SeekFrom::Current(delta) => {
                let actual = self.inner.seek(std::io::SeekFrom::Current(delta))?;
                Ok(actual.saturating_sub(self.offset))
            }
            std::io::SeekFrom::End(delta) => {
                let actual = self.inner.seek(std::io::SeekFrom::End(delta))?;
                Ok(actual.saturating_sub(self.offset))
            }
        }
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
    Err(crate::error::VmkatzError::DiskFormatError(format!(
        "NTFS entry '{name}' not found"
    )))
}

/// Read file data ($DATA attribute) into a `Vec<u8>`.
/// Uses resilient reads — on I/O errors, zero-fills the failing chunk and continues.
/// This allows extraction from live/in-use block devices.
pub fn read_file_data<R: Read + Seek>(file: &ntfs::NtfsFile, reader: &mut R) -> Result<Vec<u8>> {
    // Attribute length comes from untrusted NTFS metadata; cap it so a bogus
    // size cannot drive a multi-GB allocation (real hives are well under this).
    const MAX_ATTR_LEN: u64 = 2 << 30; // 2 GiB
    const CHUNK: usize = 4096;

    let data_item = file
        .data(reader, "")
        .ok_or_else(|| {
            crate::error::VmkatzError::DecryptionError("No $DATA attribute".to_string())
        })?
        .map_err(|e| crate::error::VmkatzError::DecryptionError(format!("$DATA error: {e}")))?;
    let data_attr = data_item.to_attribute().map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("to_attribute error: {e}"))
    })?;
    let mut data_value = data_attr.value(reader).map_err(|e| {
        crate::error::VmkatzError::DecryptionError(format!("Attribute value error: {e}"))
    })?;
    let len = data_value.len();
    if len > MAX_ATTR_LEN {
        return Err(crate::error::VmkatzError::DecryptionError(format!(
            "NTFS attribute too large: {len} bytes"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    // Try exact read first; on error, use chunked resilient read
    match data_value.read_exact(reader, &mut buf) {
        Ok(()) => Ok(buf),
        Err(e) => {
            log::debug!("Exact read failed ({e}), retrying with resilient chunked I/O");
            // Reset and try chunked reads with zero-fill on errors
            let mut data_value = data_attr.value(reader).map_err(|e2| {
                crate::error::VmkatzError::DecryptionError(format!("Attribute value error: {e2}"))
            })?;
            let mut offset = 0usize;
            let mut zeroed = 0usize; // bytes we could not read
            while offset < buf.len() {
                let end = (offset + CHUNK).min(buf.len());
                // Seek to the correct position before each chunk to avoid cursor desync
                // after a failed read_exact (which leaves the cursor in an undefined state)
                let _ = data_value.seek(reader, std::io::SeekFrom::Start(offset as u64));
                if data_value
                    .read_exact(reader, &mut buf[offset..end])
                    .is_err()
                {
                    // Zero-fill this chunk and skip
                    buf[offset..end].fill(0);
                    zeroed += end - offset;
                }
                offset = end;
            }
            // Signal how much is missing: a silently-zeroed hive (SAM/NTDS/Chrome)
            // would otherwise look complete and yield wrong or absent secrets.
            if zeroed > 0 {
                log::warn!(
                    "NTFS resilient read: {zeroed}/{} bytes unreadable and zero-filled — file is incomplete",
                    buf.len()
                );
            }
            Ok(buf)
        }
    }
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
fn list_index<'n, R: Read + Seek>(
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
