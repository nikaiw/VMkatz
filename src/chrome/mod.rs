//! Chrome / Chromium / Firefox secrets extraction.
//!
//! See `docs/plans/2026-06-05-chrome-module-design.md` for full spec.

pub mod abe;
pub mod blob;
pub mod disk;
pub mod dpapi_decrypt;
pub mod heuristic;
pub mod local_state;
pub mod memory;
pub mod profile;
pub mod signatures;
pub mod sqlite;
pub mod types;
pub mod util;

pub use types::{
    AutofillEntry, AutofillKind, Browser, BrowserProfile, ChromeFindings, ChromeSource, Cookie,
    SavedPassword,
};

/// Top-level entrypoint. Wired into CLI in a later task.
pub fn run_placeholder() -> ChromeFindings {
    ChromeFindings::default()
}
