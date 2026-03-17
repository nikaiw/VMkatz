//! Minimal ESE (Extensible Storage Engine) / JET Blue database parser.
//!
//! Parses NTDS.dit files to extract AD account hashes natively,
//! without shelling out to impacket-secretsdump.
//!
//! Only implements the subset needed for NTDS.dit credential extraction:
//! - Database header + page size detection
//! - B+ tree page traversal (branch + leaf pages)
//! - Catalog (MSysObjects) parsing for table/column metadata
//! - Tagged/fixed/variable column value extraction
//! - Long value (separated record) resolution

use crate::error::{VmkatzError, Result};
use std::collections::HashMap;

/// ESE database backed by a byte slice.
pub struct EseDb<'a> {
    data: &'a [u8],
    page_size: usize,
    /// Catalog: table_name -> EseTable
    tables: HashMap<String, EseTable>,
}

/// Column metadata from the catalog.
#[derive(Debug, Clone)]
pub struct EseColumn {
    pub id: u32,
    pub name: String,
    #[allow(dead_code)] // stored for debugging, not read at runtime
    pub col_type: u32,
    pub offset: u16,
    pub size: u16,
    pub is_fixed: bool,
    pub is_variable: bool,
    pub is_tagged: bool,
}

/// Table metadata from the catalog.
#[derive(Debug, Clone)]
struct EseTable {
    _obj_id: u32,
    /// FDP page number for the data B+ tree
    data_pgno: u32,
    /// Long value FDP page (for separated records)
    lv_pgno: u32,
    columns: Vec<EseColumn>,
}


// ESE page flags (from JET_bitXxx / esent.h)
const PAGE_FLAG_ROOT: u32 = 0x01;
const PAGE_FLAG_LEAF: u32 = 0x02;
const PAGE_FLAG_SPACE_TREE: u32 = 0x08;
const PAGE_FLAG_INDEX: u32 = 0x20;
const PAGE_FLAG_NEW_CHECKSUM: u32 = 0x2000;

// ESE column types (used in fixed_size_for_type)
const JET_COLTYPBIT: u32 = 1;
const JET_COLTYP_UNSIGNED_BYTE: u32 = 2;
const JET_COLTYP_SHORT: u32 = 3;
const JET_COLTYP_LONG: u32 = 4;
const JET_COLTYP_CURRENCY: u32 = 5;
const JET_COLTYP_IEEE_SINGLE: u32 = 6;
const JET_COLTYP_IEEE_DOUBLE: u32 = 7;
const JET_COLTYP_DATE_TIME: u32 = 8;
const JET_COLTYP_UNSIGNED_LONG: u32 = 14;
const JET_COLTYP_LONG_LONG: u32 = 15;
const JET_COLTYP_UNSIGNED_SHORT: u32 = 17;

/// Fixed-size for each column type (0 = variable length).
fn fixed_size_for_type(col_type: u32) -> usize {
    match col_type {
        JET_COLTYPBIT | JET_COLTYP_UNSIGNED_BYTE => 1,
        JET_COLTYP_SHORT | JET_COLTYP_UNSIGNED_SHORT => 2,
        JET_COLTYP_LONG | JET_COLTYP_UNSIGNED_LONG | JET_COLTYP_IEEE_SINGLE => 4,
        JET_COLTYP_CURRENCY | JET_COLTYP_IEEE_DOUBLE | JET_COLTYP_DATE_TIME
        | JET_COLTYP_LONG_LONG => 8,
        _ => 0, // variable/tagged
    }
}

impl<'a> EseDb<'a> {
    /// Open an ESE database from raw bytes.
    pub fn open(data: &'a [u8]) -> Result<Self> {
        // Validate ESE magic at offset 4
        if data.len() < 0x1000 {
            return Err(ese_err("Database too small"));
        }
        if data[4..8] != [0xEF, 0xCD, 0xAB, 0x89] {
            return Err(ese_err("Invalid ESE magic"));
        }

        // Page size: offset 0xEC in the header (u32)
        let page_size = u32_le(data, 0xEC) as usize;
        if page_size == 0 || !page_size.is_power_of_two() || !(4096..=32768).contains(&page_size)
        {
            // Fallback: try common page sizes
            let ps = if data.len() >= 2 * 8192 { 8192 } else { 4096 };
            log::info!(
                "ESE: page_size field = {}, using fallback {}",
                page_size,
                ps
            );
            return Self::init(data, ps);
        }

        Self::init(data, page_size)
    }

    fn init(data: &'a [u8], page_size: usize) -> Result<EseDb<'a>> {
        log::info!(
            "ESE: {} bytes, page_size={}, {} pages",
            data.len(),
            page_size,
            data.len() / page_size
        );

        let mut db = EseDb {
            data,
            page_size,
            tables: HashMap::new(),
        };

        // Parse catalog at page 4 (MSysObjects)
        db.parse_catalog()?;

        Ok(db)
    }

    /// Get page data by logical page number.
    ///
    /// ESE files start with 2 header pages (header + shadow copy).
    /// Logical page N is at file offset (N + 1) * page_size.
    fn page_data(&self, pgno: u32) -> Option<&'a [u8]> {
        if pgno == 0 {
            return None;
        }
        let offset = (pgno as usize + 1) * self.page_size;
        if offset + self.page_size > self.data.len() {
            return None;
        }
        Some(&self.data[offset..offset + self.page_size])
    }

    /// Read page header fields. Returns (page_flags, next_page).
    ///
    /// ESE page header is 40 bytes for both 4KB and 8KB pages.
    /// Layout from offset 0x10 is identical for both formats:
    ///   +0x10: pgnoPrev(4) +0x14: pgnoNext(4) +0x18: objidFDP(4)
    ///   +0x1C: cbFree(2)   +0x1E: cbUncommittedFree(2)
    ///   +0x20: ibMicFree(2) +0x22: itagMicFree(2) +0x24: fPageFlags(4)
    fn page_header(&self, page: &[u8]) -> (u32, u32) {
        let flags = u32_le(page, 0x24);
        let next = u32_le(page, 0x14);
        (flags, next)
    }

    /// Get header size and tag count from a page.
    ///
    /// Large pages (>=16KB) use an 80-byte header (40 base PGHDR + 40 extended PGHDR2)
    /// and encode the tag count in the low 12 bits of itagMicFree (upper 4 bits are reserved).
    /// Small pages (<=8KB) use a 40-byte header and the full itagMicFree as tag count.
    fn page_tags(&self, page: &[u8]) -> (usize, usize) {
        let raw = u16_le(page, 0x22) as usize;
        if self.page_size > 8192 {
            (80, raw & 0xFFF)
        } else {
            (40, raw)
        }
    }

    /// Read tag entry N. Tags are stored at the end of the page, growing backwards.
    ///
    /// ESE TAG struct: cb_(u16) | ib_(u16)
    ///   cb_ (low 16 bits) = size; ib_ (high 16 bits) = offset
    ///
    /// Small pages (≤8K): 13-bit values, flags from ib_ >> 13
    /// Large pages (>8K): 15-bit values, flags from tag data
    ///
    /// Returns (offset_in_data_area, size, flags).
    fn read_tag(&self, page: &[u8], tag_idx: usize, page_flags: u32) -> (usize, usize, u8) {
        let Some(tag_bytes) = (tag_idx + 1).checked_mul(4) else { return (0, 0, 0) };
        if tag_bytes > self.page_size { return (0, 0, 0); }
        let tag_pos = self.page_size - tag_bytes;
        if tag_pos + 4 > page.len() {
            return (0, 0, 0);
        }

        let raw = u32_le(page, tag_pos);

        if self.page_size <= 8192 {
            // Small pages: cb_ & 0x1FFF = size, ib_ & 0x1FFF = offset, flags = ib_ >> 13
            let size = (raw & 0x1FFF) as usize;
            let offset = ((raw >> 16) & 0x1FFF) as usize;
            let flags = ((raw >> 29) & 0x07) as u8;
            (offset, size, flags)
        } else if page_flags & PAGE_FLAG_NEW_CHECKSUM != 0 {
            // Large pages with new checksum: cb_ & 0x7FFF, ib_ & 0x7FFF
            let size = (raw & 0x7FFF) as usize;
            let offset = ((raw >> 16) & 0x7FFF) as usize;
            // Flags are in the tag data, not the entry
            (offset, size, 0)
        } else {
            // Old format: cb_(16) | ib_(16), no masking
            let size = (raw & 0xFFFF) as usize;
            let offset = ((raw >> 16) & 0xFFFF) as usize;
            (offset, size, 0)
        }
    }

    /// Get raw tag data. Tag offsets are relative to the data area (after header).
    /// Returns (tag_data, tag_flags).
    fn tag_data_with_flags(
        &self,
        page: &'a [u8],
        tag_idx: usize,
        page_flags: u32,
    ) -> Option<(&'a [u8], u8)> {
        let (hdr_size, num_tags) = self.page_tags(page);
        if tag_idx >= num_tags {
            return None;
        }
        let (offset, size, mut flags) = self.read_tag(page, tag_idx, page_flags);
        if size == 0 && tag_idx != 0 {
            return None;
        }
        let abs_offset = hdr_size + offset;
        if abs_offset + size > page.len() {
            return None;
        }
        let data = &page[abs_offset..abs_offset + size];

        // Large pages: flags are in the tag data (second byte, bits 5-7)
        if self.page_size > 8192 && data.len() >= 2 {
            flags = data[1] >> 5;
        }

        Some((data, flags))
    }

    /// Get raw tag data (convenience wrapper).
    fn tag_data(&self, page: &'a [u8], tag_idx: usize, page_flags: u32) -> Option<&'a [u8]> {
        self.tag_data_with_flags(page, tag_idx, page_flags)
            .map(|(d, _)| d)
    }

    /// Strip the key prefix/suffix from a leaf tag entry, returning only record data.
    ///
    /// Leaf tag format:
    ///   If TAG_FLAG.Compressed (0x04): prefix_size(u16 & 0x1FFF) + suffix_size(u16) + suffix + data
    ///   Otherwise: suffix_size(u16 & 0x1FFF) + suffix + data
    fn strip_leaf_key<'b>(&self, tag_data: &'b [u8], tag_flags: u8) -> &'b [u8] {
        let mut off = 0;
        let compressed = tag_flags & 0x04 != 0;

        if compressed {
            // prefix_size: 2 bytes
            if tag_data.len() < 2 {
                return &[];
            }
            off += 2;
        }

        // suffix_size: 2 bytes
        if off + 2 > tag_data.len() {
            return &[];
        }
        let suffix_size = (u16_le(tag_data, off) & 0x1FFF) as usize;
        off += 2 + suffix_size;

        if off > tag_data.len() {
            return &[];
        }
        &tag_data[off..]
    }

    /// Extract the key bytes from a leaf tag entry.
    ///
    /// Returns (prefix_size, key_suffix_bytes).
    fn extract_leaf_key<'b>(
        &self,
        tag_data: &'b [u8],
        tag_flags: u8,
    ) -> (usize, &'b [u8]) {
        let mut off = 0;
        let compressed = tag_flags & 0x04 != 0;

        let prefix_size = if compressed && tag_data.len() >= 2 {
            let ps = (u16_le(tag_data, 0) & 0x1FFF) as usize;
            off += 2;
            ps
        } else {
            0
        };

        if off + 2 > tag_data.len() {
            return (0, &[]);
        }
        let suffix_size = (u16_le(tag_data, off) & 0x1FFF) as usize;
        off += 2;

        let suffix_end = (off + suffix_size).min(tag_data.len());
        (prefix_size, &tag_data[off..suffix_end])
    }

    /// Traverse a B+ tree starting at the given root page, collecting all leaf records.
    /// Calls `callback` for each leaf record data (with key bytes stripped).
    fn traverse_btree<F>(&self, root_pgno: u32, mut callback: F) -> Result<()>
    where
        F: FnMut(&'a [u8]),
    {
        let mut stack = vec![root_pgno];
        let mut visited = std::collections::HashSet::new();

        while let Some(pgno) = stack.pop() {
            if pgno == 0 || !visited.insert(pgno) {
                continue;
            }

            let page = match self.page_data(pgno) {
                Some(p) => p,
                None => continue,
            };

            let (flags, _next_page) = self.page_header(page);
            let (_hdr_size, num_tags) = self.page_tags(page);

            // Skip empty or space tree pages
            if flags & PAGE_FLAG_SPACE_TREE != 0 || flags & PAGE_FLAG_INDEX != 0 {
                continue;
            }

            log::debug!(
                "ESE traverse: page {} flags=0x{:x} tags={}",
                pgno, flags, num_tags
            );

            if flags & PAGE_FLAG_LEAF != 0 {
                // Leaf page: tag 0 is page key prefix (skip), tags 1+ are records
                for i in 1..num_tags {
                    if let Some((tag_data, tag_flags)) =
                        self.tag_data_with_flags(page, i, flags)
                    {
                        let record = self.strip_leaf_key(tag_data, tag_flags);
                        if !record.is_empty() {
                            callback(record);
                        }
                    }
                }
            } else {
                // Branch/FDP page: any non-leaf is treated as branch.
                // Tag 0 is page key prefix or root header (skip).
                // Tags 1+ contain key + child_page_pointer.
                for i in 1..num_tags {
                    if let Some((tag_data, tag_flags)) =
                        self.tag_data_with_flags(page, i, flags)
                    {
                        let record = self.strip_leaf_key(tag_data, tag_flags);
                        if record.len() >= 4 {
                            let child = u32_le(record, 0);
                            stack.push(child);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Traverse a B+ tree, calling `callback` with (key, record_data) for each leaf record.
    /// Used for long value resolution where the key is needed.
    fn traverse_btree_kv<F>(&self, root_pgno: u32, mut callback: F) -> Result<()>
    where
        F: FnMut(Vec<u8>, &'a [u8]),
    {
        let mut stack = vec![root_pgno];
        let mut visited = std::collections::HashSet::new();

        while let Some(pgno) = stack.pop() {
            if pgno == 0 || !visited.insert(pgno) {
                continue;
            }

            let page = match self.page_data(pgno) {
                Some(p) => p,
                None => continue,
            };

            let (flags, _) = self.page_header(page);
            let (_, num_tags) = self.page_tags(page);

            if flags & PAGE_FLAG_SPACE_TREE != 0 || flags & PAGE_FLAG_INDEX != 0 {
                continue;
            }

            if flags & PAGE_FLAG_LEAF != 0 {
                // Get page key prefix from tag 0 (for key reconstruction)
                let page_key_prefix = if flags & PAGE_FLAG_ROOT == 0 {
                    // Non-root page: tag 0 is the raw key prefix
                    self.tag_data(page, 0, flags).unwrap_or(&[])
                } else {
                    // Root page: tag 0 has root header, no usable prefix
                    &[]
                };

                for i in 1..num_tags {
                    if let Some((tag_data, tag_flags)) =
                        self.tag_data_with_flags(page, i, flags)
                    {
                        let (prefix_size, key_suffix) =
                            self.extract_leaf_key(tag_data, tag_flags);
                        let record = self.strip_leaf_key(tag_data, tag_flags);

                        // Reconstruct full key
                        let mut key =
                            Vec::with_capacity(prefix_size + key_suffix.len());
                        let prefix_end = prefix_size.min(page_key_prefix.len());
                        key.extend_from_slice(&page_key_prefix[..prefix_end]);
                        if prefix_end < prefix_size {
                            key.resize(prefix_size, 0);
                        }
                        key.extend_from_slice(key_suffix);

                        if !record.is_empty() {
                            callback(key, record);
                        }
                    }
                }
            } else {
                // Branch/FDP: follow child pointers (skip tag 0)
                for i in 1..num_tags {
                    if let Some((tag_data, tag_flags)) =
                        self.tag_data_with_flags(page, i, flags)
                    {
                        let record = self.strip_leaf_key(tag_data, tag_flags);
                        if record.len() >= 4 {
                            let child = u32_le(record, 0);
                            stack.push(child);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse the catalog (MSysObjects, page 4) to discover tables and columns.
    fn parse_catalog(&mut self) -> Result<()> {
        // The catalog is a B+ tree rooted at page 4
        let mut records: Vec<Vec<u8>> = Vec::new();

        self.traverse_btree(4, |data| {
            records.push(data.to_vec());
        })?;

        log::info!("ESE catalog: {} raw records", records.len());

        // Catalog record layout (MSysObjects):
        //   Bytes 0-3:   preamble: lastFixedId(1) + lastVarId(1) + varDataOffset(2)
        //   Bytes 4-7:   ObjidTable (u32)      - column 1
        //   Bytes 8-9:   Type (u16)            - column 2 (1=table, 2=column, 3=index, 4=LV)
        //   Bytes 10-13: Id (u32)              - column 3
        //   Bytes 14-17: ColtypOrPgnoFDP (u32) - column 4
        //   Bytes 18-21: SpaceUsage (u32)      - column 5
        //   Bytes 22-25: Flags (u32)           - column 6
        //   Bytes 26-29: PagesOrLocale (u32)   - column 7
        //
        //   After fixed cols: variable column offset table (2 bytes each)
        //   Variable column 128 = Name (first variable column)

        let mut table_map: HashMap<u32, (String, u32)> = HashMap::new(); // obj_id -> (name, data_pgno)
        let mut lv_map: HashMap<u32, u32> = HashMap::new(); // obj_id -> lv_pgno
        let mut col_map: HashMap<u32, Vec<EseColumn>> = HashMap::new(); // obj_id -> columns

        for (rec_idx, rec) in records.iter().enumerate() {
            log::debug!(
                "ESE catalog rec[{}]: len={} hex={}",
                rec_idx,
                rec.len(),
                hex::encode(&rec[..rec.len().min(64)])
            );

            if rec.len() < 30 {
                continue;
            }

            // Preamble
            let last_fixed_id = rec[0] as u16;
            let last_var_id = rec[1] as u16;
            let var_data_off = u16_le(rec, 2) as usize;

            log::debug!(
                "ESE catalog rec[{}]: last_fixed_id={} last_var_id={} var_data_off={}",
                rec_idx, last_fixed_id, last_var_id, var_data_off
            );

            if last_fixed_id < 7 || var_data_off < 4 {
                log::debug!("ESE catalog rec[{}]: skipped (last_fixed_id < 7 or var_data_off < 4)", rec_idx);
                continue;
            }

            let obj_id_table = u32_le(rec, 4);
            let rec_type = u16_le(rec, 8);
            let id = u32_le(rec, 10);
            let coltyp_or_pgno = u32_le(rec, 14);
            let space_usage = u32_le(rec, 18);
            let _flags = u32_le(rec, 22);
            let _pages_or_locale = u32_le(rec, 26);

            // Extract name from variable column 128 (first variable column)
            let name = self.extract_catalog_name(rec, var_data_off, last_var_id);

            match rec_type {
                1 => {
                    // Table
                    table_map.insert(obj_id_table, (name.clone(), coltyp_or_pgno));
                    log::debug!(
                        "ESE catalog: table '{}' obj_id={} pgno={}",
                        name,
                        obj_id_table,
                        coltyp_or_pgno
                    );
                }
                2 => {
                    // Column
                    let col_type = coltyp_or_pgno;
                    let col_offset = (space_usage & 0xFFFF) as u16;
                    let col_size = ((space_usage >> 16) & 0xFFFF) as u16;

                    let fsize = fixed_size_for_type(col_type);
                    let is_fixed = id <= 127 && fsize > 0;
                    let is_variable = (128..=255).contains(&id);
                    let is_tagged = id >= 256;

                    let col = EseColumn {
                        id,
                        name: name.clone(),
                        col_type,
                        offset: col_offset,
                        size: if is_fixed { fsize as u16 } else { col_size },
                        is_fixed,
                        is_variable,
                        is_tagged,
                    };

                    col_map.entry(obj_id_table).or_default().push(col);
                }
                4 => {
                    // Long Value tree
                    lv_map.insert(obj_id_table, coltyp_or_pgno);
                    log::debug!(
                        "ESE catalog: LV for obj_id={} pgno={}",
                        obj_id_table,
                        coltyp_or_pgno
                    );
                }
                _ => {} // Index (3) and others - skip
            }
        }

        // Build table map
        for (obj_id, (name, data_pgno)) in &table_map {
            let columns = col_map.remove(obj_id).unwrap_or_default();
            let lv_pgno = lv_map.get(obj_id).copied().unwrap_or(0);

            log::debug!(
                "ESE table '{}': obj_id={} data_pgno={} lv_pgno={} columns={}",
                name,
                obj_id,
                data_pgno,
                lv_pgno,
                columns.len()
            );

            self.tables.insert(
                name.clone(),
                EseTable {
                    _obj_id: *obj_id,
                    data_pgno: *data_pgno,
                    lv_pgno,
                    columns,
                },
            );
        }

        log::info!("ESE: {} tables parsed", self.tables.len());
        Ok(())
    }

    /// Extract name string from catalog record's variable columns.
    fn extract_catalog_name(&self, rec: &[u8], var_data_off: usize, last_var_id: u16) -> String {
        // Variable columns start after fixed data at var_data_off
        // First: offset array (2 bytes per variable column present)
        // Variable column IDs start at 128
        if last_var_id < 128 || var_data_off >= rec.len() {
            return String::new();
        }

        let num_var = (last_var_id - 128 + 1) as usize;
        let offsets_start = var_data_off;
        let offsets_end = offsets_start + num_var * 2;
        if offsets_end > rec.len() {
            return String::new();
        }

        // First variable column (128 = Name) data offset
        let first_off = u16_le(rec, offsets_start);
        // The actual data starts after the offset array
        let data_start = offsets_end;
        // First column data is from data_start to data_start + first_off
        // Wait - the offset values are relative to the start of variable data area
        // Actually: each offset tells you where the NEXT column's data starts
        // Column 128 data: from offsets_end to offsets_end + offset[0]
        // But offset[0] could be an absolute offset from var_data_off...

        // ESE variable column encoding:
        // The offset array stores the END offset of each variable column's data,
        // relative to the start of the variable data area (after the offset array).
        // Column 128 data: [0 .. offset[0]]
        // Column 129 data: [offset[0] .. offset[1]]
        // etc.

        let end_off = (first_off & 0x7FFF) as usize;  // Bit 15 is "null" flag
        if first_off & 0x8000 != 0 {
            return String::new(); // Column is null
        }

        if data_start + end_off > rec.len() {
            return String::new();
        }

        let name_bytes = &rec[data_start..data_start + end_off];
        // Try ASCII first (most catalog names are ASCII)
        if let Ok(s) = std::str::from_utf8(name_bytes) {
            s.trim_end_matches('\0').to_string()
        } else {
            // UTF-16LE fallback
            crate::utils::utf16le_decode(name_bytes)
        }
    }

    /// List available table names.
    pub fn table_names(&self) -> Vec<&str> {
        self.tables.keys().map(|s| s.as_str()).collect()
    }

    /// Get columns for a table.
    pub fn columns(&self, table: &str) -> Option<&[EseColumn]> {
        self.tables.get(table).map(|t| t.columns.as_slice())
    }

    /// Iterate all rows in a table, calling `callback` for each row.
    /// The callback receives a closure that can read column values by column name.
    pub fn for_each_row<F>(&self, table: &str, mut callback: F) -> Result<()>
    where
        F: FnMut(&dyn Fn(&str) -> Option<Vec<u8>>),
    {
        let tbl = self
            .tables
            .get(table)
            .ok_or_else(|| ese_err(&format!("Table '{}' not found", table)))?;

        let columns = &tbl.columns;
        let lv_pgno = tbl.lv_pgno;

        // Collect all leaf records from the data B+ tree
        let mut records: Vec<&'a [u8]> = Vec::new();
        self.traverse_btree(tbl.data_pgno, |data| {
            records.push(data);
        })?;

        log::info!(
            "ESE table '{}': {} leaf records, {} columns",
            table,
            records.len(),
            columns.len()
        );

        // Build column name -> index map
        let col_by_name: HashMap<&str, &EseColumn> =
            columns.iter().map(|c| (c.name.as_str(), c)).collect();

        for rec_data in &records {
            if rec_data.len() < 4 {
                continue;
            }

            let reader = |col_name: &str| -> Option<Vec<u8>> {
                let col = col_by_name.get(col_name)?;
                self.read_column_value(rec_data, columns, col, lv_pgno)
            };

            callback(&reader);
        }

        Ok(())
    }

    /// Read a column value from a record.
    fn read_column_value(
        &self,
        rec: &[u8],
        _columns: &[EseColumn],
        col: &EseColumn,
        lv_pgno: u32,
    ) -> Option<Vec<u8>> {
        if rec.len() < 4 {
            return None;
        }

        let last_fixed_id = rec[0] as u32;
        let last_var_id = rec[1] as u32;
        let var_data_off = u16_le(rec, 2) as usize;

        if col.is_fixed {
            self.read_fixed_column(rec, col, last_fixed_id, var_data_off)
        } else if col.is_variable {
            self.read_variable_column(rec, col, last_var_id, var_data_off, lv_pgno)
        } else if col.is_tagged {
            self.read_tagged_column(rec, col, var_data_off, last_var_id, lv_pgno)
        } else {
            None
        }
    }

    /// Read a fixed column value.
    fn read_fixed_column(
        &self,
        rec: &[u8],
        col: &EseColumn,
        last_fixed_id: u32,
        _var_data_off: usize,
    ) -> Option<Vec<u8>> {
        if col.id > last_fixed_id {
            return None; // Column not present in this record
        }

        // Fixed columns are stored starting at offset 4 (after the 4-byte preamble)
        // Each column's offset within the fixed data area is stored in col.offset,
        // but that's the offset within the table definition, not the record.
        // We need to compute the actual offset based on columns present.
        //
        // Actually, col.offset from the catalog is the fixed offset in the record
        // (relative to byte 4, the start of fixed data).
        let rec_offset = col.offset as usize;
        let size = col.size as usize;

        if rec_offset + size > rec.len() {
            return None;
        }

        Some(rec[rec_offset..rec_offset + size].to_vec())
    }

    /// Read a variable column value.
    fn read_variable_column(
        &self,
        rec: &[u8],
        col: &EseColumn,
        last_var_id: u32,
        var_data_off: usize,
        lv_pgno: u32,
    ) -> Option<Vec<u8>> {
        if col.id > last_var_id || col.id < 128 || last_var_id < 128 {
            return None;
        }

        let var_idx = (col.id - 128) as usize;
        let num_var = (last_var_id - 128 + 1) as usize;

        if var_data_off + num_var * 2 > rec.len() {
            return None;
        }

        // Read offset table
        let offsets_start = var_data_off;
        let data_start = offsets_start + num_var * 2;

        let end_raw = u16_le(rec, offsets_start + var_idx * 2);
        if end_raw & 0x8000 != 0 {
            return None; // NULL column
        }
        let end = (end_raw & 0x7FFF) as usize;

        let start = if var_idx == 0 {
            0
        } else {
            let prev_raw = u16_le(rec, offsets_start + (var_idx - 1) * 2);
            (prev_raw & 0x7FFF) as usize
        };

        if start >= end {
            return None;
        }

        let abs_start = data_start + start;
        let abs_end = data_start + end;
        if abs_end > rec.len() {
            return None;
        }

        let data = &rec[abs_start..abs_end];
        self.maybe_resolve_lv(data, lv_pgno)
    }

    /// Read a tagged column value.
    ///
    /// Tagged column format: array of TAGFLD entries (column_id: u16, offset_flags: u16)
    /// followed by column data. Each TAGFLD is 4 bytes (one DWORD).
    ///
    /// For small pages (<=8KB):
    ///   offset = offset_flags & 0x1FFF (13-bit),
    ///   has_extended_info = offset_flags & 0x4000 (per-entry!),
    ///   is_null = offset_flags & 0x2000.
    /// For large pages (>8KB):
    ///   offset = offset_flags & 0x7FFF (15-bit),
    ///   has_extended_info = always true.
    ///
    /// When has_extended_info: first byte of data is a flags byte (TAGFLD_HEADER):
    ///   0x01 = LongValue type, 0x02 = Compressed, 0x04 = Separated (LV ref),
    ///   0x08 = MultiValues, 0x20 = Null
    fn read_tagged_column(
        &self,
        rec: &[u8],
        col: &EseColumn,
        var_data_off: usize,
        last_var_id: u32,
        lv_pgno: u32,
    ) -> Option<Vec<u8>> {
        // Tagged columns come after variable columns
        let num_var = if last_var_id >= 128 {
            (last_var_id - 128 + 1) as usize
        } else {
            0
        };

        let var_offsets_end = var_data_off + num_var * 2;

        // Find the end of variable data
        let var_data_end = if num_var > 0 && var_offsets_end <= rec.len() {
            let last_off_raw = u16_le(rec, var_data_off + (num_var - 1) * 2);
            let last_off = (last_off_raw & 0x7FFF) as usize;
            var_offsets_end + last_off
        } else {
            var_offsets_end
        };

        let tagged_start = var_data_end;
        if tagged_start >= rec.len() {
            return None;
        }

        let tagged_data = &rec[tagged_start..];
        if tagged_data.len() < 4 {
            return None;
        }

        let small_pages = self.page_size <= 8192;

        // First TAGFLD: its offset field tells us the directory size in bytes
        let first_raw = u32_le(tagged_data, 0);
        let first_offset_bits = ((first_raw >> 16) & 0xFFFF) as u16;
        let dir_bytes = if small_pages {
            (first_offset_bits & 0x1FFF) as usize
        } else {
            (first_offset_bits & 0x7FFF) as usize
        };

        if dir_bytes == 0 || dir_bytes > tagged_data.len() || dir_bytes % 4 != 0 {
            return None;
        }

        let num_entries = dir_bytes / 4;

        // Find our column in the directory
        for i in 0..num_entries {
            let entry_off = i * 4;
            if entry_off + 4 > tagged_data.len() {
                break;
            }

            let entry_raw = u32_le(tagged_data, entry_off);
            let tag_col_id = (entry_raw & 0xFFFF) as u16;
            let offset_bits = ((entry_raw >> 16) & 0xFFFF) as u16;

            if tag_col_id != col.id as u16 {
                continue;
            }

            // Null check (small pages: bit 0x2000)
            if small_pages && offset_bits & 0x2000 != 0 {
                return None;
            }

            // Per-entry extended info flag
            let has_extended_info = if small_pages {
                offset_bits & 0x4000 != 0
            } else {
                true
            };

            // Actual data offset within tagged_data
            let data_offset = if small_pages {
                (offset_bits & 0x1FFF) as usize
            } else {
                (offset_bits & 0x7FFF) as usize
            };

            // End of this column's data: next entry's offset or end of tagged_data
            let data_end = if i + 1 < num_entries {
                let next_raw = u32_le(tagged_data, (i + 1) * 4);
                let next_bits = ((next_raw >> 16) & 0xFFFF) as u16;
                if small_pages {
                    (next_bits & 0x1FFF) as usize
                } else {
                    (next_bits & 0x7FFF) as usize
                }
            } else {
                tagged_data.len()
            };

            if data_offset >= data_end || data_end > tagged_data.len() {
                return None;
            }

            let mut data = &tagged_data[data_offset..data_end];

            // When has_extended_info, first byte is TAGFLD_HEADER flags
            if has_extended_info && !data.is_empty() {
                let flags = data[0];
                data = &data[1..]; // Skip flags byte

                // Null check for large pages
                if !small_pages && flags & 0x20 != 0 {
                    return None;
                }

                // Separated: data is a long value reference (LID)
                if flags & 0x04 != 0 && data.len() >= 4 {
                    return self.resolve_long_value(lv_pgno, data);
                }
            }

            if data.is_empty() {
                return None;
            }
            return Some(data.to_vec());
        }

        None
    }

    /// Check if data is a long value reference and resolve it.
    fn maybe_resolve_lv(&self, data: &[u8], _lv_pgno: u32) -> Option<Vec<u8>> {
        // Long values in variable columns are indicated by the column type being
        // JET_coltypLongBinary or JET_coltypLongText, and the data being a key.
        // However, we can't easily tell from just the data - return as-is for now.
        // The tagged column handler does explicit LV resolution.
        Some(data.to_vec())
    }

    /// Resolve a long value from the LV tree.
    fn resolve_long_value(&self, lv_pgno: u32, lv_key: &[u8]) -> Option<Vec<u8>> {
        if lv_pgno == 0 || lv_key.len() < 4 {
            return None;
        }

        // LV reference from tagged column: LID stored as little-endian u32
        let lid = u32::from_le_bytes(lv_key[..4].try_into().ok()?);

        let mut chunks: Vec<(u32, Vec<u8>)> = Vec::new();

        // LV B+ tree keys: LID(4 BE) + segment_offset(4 BE)
        self.traverse_btree_kv(lv_pgno, |key, data| {
            if let Some(rec_lid) = key
                .get(..4)
                .and_then(|s| <[u8; 4]>::try_from(s).ok())
                .map(u32::from_be_bytes)
            {
                if rec_lid == lid {
                    let seg_offset = key
                        .get(4..8)
                        .and_then(|s| <[u8; 4]>::try_from(s).ok())
                        .map(u32::from_be_bytes)
                        .unwrap_or(0);
                    chunks.push((seg_offset, data.to_vec()));
                }
            }
        })
        .ok()?;

        if chunks.is_empty() {
            return None;
        }

        chunks.sort_by_key(|(off, _)| *off);
        let mut result = Vec::new();
        for (_, chunk) in chunks {
            result.extend_from_slice(&chunk);
        }

        Some(result)
    }
}

fn ese_err(msg: &str) -> VmkatzError {
    VmkatzError::DecryptionError(format!("ESE: {}", msg))
}

fn u16_le(data: &[u8], off: usize) -> u16 {
    data.get(off..off + 2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(u16::from_le_bytes)
        .unwrap_or(0)
}

fn u32_le(data: &[u8], off: usize) -> u32 {
    data.get(off..off + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}
