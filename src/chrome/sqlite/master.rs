use super::btree::walk_table;
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
    /// Walk sqlite_master (root page 1) and return every `table` entry.
    pub fn list_tables(&self) -> Result<Vec<MasterEntry>> {
        let mut out = Vec::new();
        walk_table(self, 1, |_rowid, cols| {
            // sqlite_master columns: type, name, tbl_name, rootpage, sql
            if cols.len() < 5 {
                return Ok(());
            }
            let kind = cols[0].as_text().unwrap_or("").to_string();
            let name = cols[1].as_text().unwrap_or("").to_string();
            let tbl_name = cols[2].as_text().unwrap_or("").to_string();
            let rootpage = cols[3].as_int().unwrap_or(0);
            let sql = cols[4].as_text().unwrap_or("").to_string();
            if kind == "table" {
                out.push(MasterEntry {
                    kind,
                    name,
                    tbl_name,
                    rootpage,
                    sql,
                });
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Look up a table by name and return its root page number, if any.
    pub fn root_of(&self, table: &str) -> Result<Option<u32>> {
        let tables = self.list_tables()?;
        Ok(tables
            .iter()
            .find(|t| t.name == table)
            .map(|t| t.rootpage as u32))
    }
}
