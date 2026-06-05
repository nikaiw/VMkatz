use super::page::Pager;
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct MasterEntry {
    pub kind: String,      // "table" | "index" | ...
    pub name: String,
    pub tbl_name: String,
    pub rootpage: i64,
    pub sql: String,
}

impl<'a> Pager<'a> {
    /// Walks page 1 as the sqlite_master table B-tree leaf, returns table entries.
    /// (Small DBs keep sqlite_master entirely in page 1's leaf. For now we error if
    /// sqlite_master spans an interior node — extended in Task 4.)
    pub fn list_tables(&self) -> Result<Vec<MasterEntry>> {
        // Implemented in Task 3 once the record decoder exists; the full walk lives in
        // src/chrome/sqlite/btree.rs (Task 4).
        Ok(Vec::new())
    }
}
