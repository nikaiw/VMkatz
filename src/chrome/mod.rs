//! Chrome / Chromium / Firefox secrets extraction.
//!
//! See `docs/plans/2026-06-05-chrome-module-design.md` for full spec.

pub mod abe;
pub mod abe_keys;
pub mod blob;
pub mod disk;
pub mod dpapi_decrypt;
pub mod heuristic;
pub mod hybrid;
pub mod local_state;
pub mod memory;
pub mod output;
pub mod profile;
pub mod runner;
pub mod signatures;
pub mod sqlite;
pub mod types;
pub mod util;

pub mod firefox;

pub use types::{
    AutofillEntry, AutofillKind, Browser, BrowserProfile, ChromeFindings, ChromeSource, Cookie,
    SavedPassword,
};

/// Top-level entrypoint. Wired into CLI in a later task.
pub fn run_placeholder() -> ChromeFindings {
    ChromeFindings::default()
}
