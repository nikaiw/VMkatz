use super::page::Pager;
use super::record::{decode_record, read_varint, Value};
use crate::error::{Result, VmkatzError as Error};

const PAGE_INTERIOR_INDEX: u8 = 0x02;
const PAGE_INTERIOR_TABLE: u8 = 0x05;
const PAGE_LEAF_INDEX: u8 = 0x0A;
const PAGE_LEAF_TABLE: u8 = 0x0D;

// Bound the recursion depth to defend against cyclic / corrupted trees.
// Real SQLite B-trees are very shallow; 32 is far beyond any plausible depth.
const MAX_BTREE_DEPTH: u32 = 32;

/// Iterate every row in a table B-tree rooted at `root_page_no`.
/// `cb` receives (rowid, decoded columns).
pub fn walk_table<F: FnMut(i64, Vec<Value>) -> Result<()>>(
    pager: &Pager<'_>,
    root_page_no: u32,
    mut cb: F,
) -> Result<()> {
    walk_inner(pager, root_page_no, &mut cb, 0)
}

fn walk_inner<F: FnMut(i64, Vec<Value>) -> Result<()>>(
    pager: &Pager<'_>,
    page_no: u32,
    cb: &mut F,
    depth: u32,
) -> Result<()> {
    if depth > MAX_BTREE_DEPTH {
        return Err(Error::Parse("btree depth exceeded".into()));
    }
    let page = pager.page(page_no)?;
    // Skip the 100-byte file header that lives only on page 1.
    let header_off = if page_no == 1 { 100 } else { 0 };
    if page.len() < header_off + 12 {
        return Err(Error::Parse("btree page header truncated".into()));
    }
    let h = &page[header_off..];
    let kind = h[0];
    let cell_count = u16::from_be_bytes([h[3], h[4]]) as usize;

    match kind {
        PAGE_LEAF_TABLE => {
            // 8-byte leaf header; cell pointer array follows immediately.
            let cell_ptr_off = header_off
                .checked_add(8)
                .ok_or_else(|| Error::Parse("cell ptr offset overflow".into()))?;
            let cell_ptr_end = cell_ptr_off
                .checked_add(cell_count.checked_mul(2).ok_or_else(|| {
                    Error::Parse("cell pointer array size overflow".into())
                })?)
                .ok_or_else(|| Error::Parse("cell pointer array end overflow".into()))?;
            if cell_ptr_end > page.len() {
                return Err(Error::Parse("cell pointer array beyond page".into()));
            }
            for i in 0..cell_count {
                let p = cell_ptr_off + i * 2;
                let cell_off = u16::from_be_bytes([page[p], page[p + 1]]) as usize;
                decode_leaf_table_cell(pager, page, cell_off, cb)?;
            }
        }
        PAGE_INTERIOR_TABLE => {
            // 12-byte interior header; final 4 bytes are the right-most child pointer.
            let cell_ptr_off = header_off
                .checked_add(12)
                .ok_or_else(|| Error::Parse("cell ptr offset overflow".into()))?;
            let cell_ptr_end = cell_ptr_off
                .checked_add(cell_count.checked_mul(2).ok_or_else(|| {
                    Error::Parse("cell pointer array size overflow".into())
                })?)
                .ok_or_else(|| Error::Parse("cell pointer array end overflow".into()))?;
            if cell_ptr_end > page.len() {
                return Err(Error::Parse("cell pointer array beyond page".into()));
            }
            for i in 0..cell_count {
                let p = cell_ptr_off + i * 2;
                let cell_off = u16::from_be_bytes([page[p], page[p + 1]]) as usize;
                if cell_off
                    .checked_add(4)
                    .map(|e| e > page.len())
                    .unwrap_or(true)
                {
                    return Err(Error::Parse("interior cell out of range".into()));
                }
                let child =
                    u32::from_be_bytes(page[cell_off..cell_off + 4].try_into().unwrap());
                // The varint rowid that follows is unused for table walks.
                walk_inner(pager, child, cb, depth + 1)?;
            }
            let rightmost = u32::from_be_bytes(h[8..12].try_into().unwrap());
            if rightmost != 0 {
                walk_inner(pager, rightmost, cb, depth + 1)?;
            }
        }
        PAGE_LEAF_INDEX | PAGE_INTERIOR_INDEX => {
            // Index B-trees aren't needed for the chrome use case.
            return Err(Error::Parse("unexpected index page in table walk".into()));
        }
        _ => return Err(Error::Parse(format!("unknown btree page kind {}", kind))),
    }
    Ok(())
}

fn decode_leaf_table_cell<F: FnMut(i64, Vec<Value>) -> Result<()>>(
    pager: &Pager<'_>,
    page: &[u8],
    cell_off: usize,
    cb: &mut F,
) -> Result<()> {
    if cell_off >= page.len() {
        return Err(Error::Parse("leaf cell offset out of range".into()));
    }
    let (payload_size, n1) = read_varint(&page[cell_off..])?;
    let after_size = cell_off
        .checked_add(n1)
        .ok_or_else(|| Error::Parse("cell offset overflow".into()))?;
    if after_size >= page.len() {
        return Err(Error::Parse("leaf cell rowid truncated".into()));
    }
    let (rowid, n2) = read_varint(&page[after_size..])?;
    let payload_off = after_size
        .checked_add(n2)
        .ok_or_else(|| Error::Parse("payload offset overflow".into()))?;

    if payload_size < 0 {
        return Err(Error::Parse("negative payload size".into()));
    }
    let payload_size_us = payload_size as usize;

    // Reserved space at the end of each page (DbHeader stores it as 0 today;
    // hard-code 0 here, but compute defensively in case that changes).
    let usable = pager.header.page_size as usize;
    if usable < 480 {
        // Per SQLite spec the minimum legal page size is 512, so usable - 12
        // is always >= 500. Guard against zero / underflow here regardless.
        return Err(Error::Parse("usable page size too small".into()));
    }
    let max_local = usable - 35;
    // i64 arithmetic protects against underflow if the spec's tuning constants
    // ever produce a negative intermediate.
    let min_local_i = ((usable as i64 - 12) * 32 / 255) - 23;
    if min_local_i < 0 {
        return Err(Error::Parse("min_local underflow".into()));
    }
    let min_local = min_local_i as usize;

    let payload_buf: Vec<u8>;
    let payload: &[u8] = if payload_size_us <= max_local {
        // Fully local: no overflow chain.
        let end = payload_off
            .checked_add(payload_size_us)
            .ok_or_else(|| Error::Parse("payload end overflow".into()))?;
        if end > page.len() {
            return Err(Error::Parse("local payload truncated".into()));
        }
        &page[payload_off..end]
    } else {
        // Mixed local + overflow chain (SQLite spec §1.6.4).
        if usable <= 4 {
            return Err(Error::Parse("usable too small for overflow".into()));
        }
        let mut local = min_local + ((payload_size_us - min_local) % (usable - 4));
        if local > max_local {
            local = min_local;
        }
        let local_end = payload_off
            .checked_add(local)
            .ok_or_else(|| Error::Parse("local end overflow".into()))?;
        let next_ptr_end = local_end
            .checked_add(4)
            .ok_or_else(|| Error::Parse("overflow ptr end overflow".into()))?;
        if next_ptr_end > page.len() {
            return Err(Error::Parse("overflow ptr truncated".into()));
        }
        let mut buf = Vec::with_capacity(payload_size_us);
        buf.extend_from_slice(&page[payload_off..local_end]);

        let mut next =
            u32::from_be_bytes(page[local_end..next_ptr_end].try_into().unwrap());
        let mut remaining = payload_size_us - local;
        // Cap the number of overflow hops to defend against cyclic chains.
        let max_hops = pager.header.page_count as usize + 1;
        let mut hops: usize = 0;
        while next != 0 && remaining > 0 {
            hops += 1;
            if hops > max_hops {
                return Err(Error::Parse("overflow chain too long (cycle?)".into()));
            }
            let op = pager.page(next)?;
            if op.len() < 4 {
                return Err(Error::Parse("overflow page truncated".into()));
            }
            let nxt = u32::from_be_bytes(op[..4].try_into().unwrap());
            let take = remaining.min(usable - 4);
            let end = 4usize
                .checked_add(take)
                .ok_or_else(|| Error::Parse("overflow take overflow".into()))?;
            if end > op.len() {
                return Err(Error::Parse("overflow page payload short".into()));
            }
            buf.extend_from_slice(&op[4..end]);
            remaining -= take;
            next = nxt;
        }
        if remaining > 0 {
            return Err(Error::Parse("overflow chain ended early".into()));
        }
        payload_buf = buf;
        &payload_buf
    };

    let values = decode_record(payload)?;
    cb(rowid, values)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanity: bounds-check failure path doesn't panic.
    #[test]
    fn rejects_truncated_btree_page_header() {
        // Build a one-page "database" too small to hold the 12-byte interior
        // header at offset 100. walk_inner should err, not panic.
        let mut bytes = vec![0u8; 4096];
        // sqlite header magic + page_size = 4096
        bytes[..16].copy_from_slice(b"SQLite format 3\x00");
        bytes[16] = 0x10;
        bytes[17] = 0x00;
        // page_count = 1
        bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
        // text encoding = 1 (utf8)
        bytes[56..60].copy_from_slice(&1u32.to_be_bytes());
        // page kind byte at offset 100 = interior table (0x05).
        bytes[100] = PAGE_INTERIOR_TABLE;
        // Truncate the page buffer to exactly 100 + 5 bytes so the 12-byte
        // header read fails the bounds check.
        bytes.truncate(105);
        // Pager::open requires >= 100 bytes; we're below page_size, so emulate
        // by adjusting page_size to 100 to make pager.page(1) succeed.
        let mut header_bytes = bytes.clone();
        header_bytes[16] = 0x00;
        header_bytes[17] = 0x64; // 100
        let pager = Pager::open(&header_bytes).unwrap();
        let r = walk_table(&pager, 1, |_, _| Ok(()));
        assert!(r.is_err(), "expected error on truncated header");
    }
}
