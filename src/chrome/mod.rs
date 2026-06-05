//! Chrome / Chromium / Firefox secrets extraction.
//!
//! See `docs/plans/2026-06-05-chrome-module-design.md` for full spec.

pub mod dpapi_decrypt;
pub mod local_state;
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
