//! Browser-secret extraction from Chromium-family browsers and Firefox.
//!
//! Gated by the `chrome` Cargo feature and the `--chrome` runtime flag.
//! Three decrypt paths share the same SQLite + DPAPI primitives:
//!
//! - **Disk-only** ([`runner::run_disk_with_passwords`]): walk
//!   `Users\*\AppData\…` over NTFS, decrypt every masterkey file with the
//!   user's plaintext password (LSA-recovered or `--chrome-password`), pair
//!   them with `DPAPI_SYSTEM` to unlock SYSTEM-context MKs, then decrypt
//!   each `Login Data` / `Cookies` / `Web Data` row.
//! - **Hybrid mem+disk** ([`runner::run_reader_with_keyring`]): same disk
//!   pipeline plus a memory-extracted keyring from LSASS's DPAPI cache. A
//!   [`hybrid::ComposedResolver`] consults memory first and falls back to
//!   disk. v20 ABE specifically needs this path on most Chrome ≥127 installs
//!   because the inner DPAPI layers reference SYSTEM-context user MKs that
//!   the elevation service produces and only LSASS retains.
//! - **VMFS reader** ([`runner::run_reader`]): used by the ESXi VMFS-6 raw
//!   reader so SAM extraction and chrome discovery share one disk handle.
//!
//! ## Module layout
//!
//! - [`runner`] — CLI orchestration + the public `run_*` entrypoints.
//! - [`profile`] — NTFS-walking discovery of browser profiles and artifact
//!   paths.
//! - [`disk`] — per-profile SQLite decrypt orchestration; the
//!   [`disk::MasterkeyResolver`] trait is what the hybrid keyring implements.
//! - [`local_state`] — parses Chrome's `Local State` JSON for the v10
//!   `encrypted_key` and the v20 `app_bound_encrypted_key`.
//! - [`dpapi_decrypt`] — minimal DPAPI blob parser + AES-256-CBC /
//!   HMAC-SHA512 primitive.
//! - [`abe`] — Chrome v20 App-Bound Encryption (two DPAPI layers wrapping a
//!   flag-keyed AES-256-GCM envelope).
//! - [`abe_keys`] — auto-extract the per-flag static keys from the install's
//!   `elevation_service.exe` PE; ships a Chrome 135 fallback.
//! - [`blob`] — small shape helpers shared by v10 / v20.
//! - [`hybrid`] — `HybridKeyring` + `ComposedResolver` (mem → disk fallback).
//! - [`heuristic`] — candidate-validation heuristics (SQLite shape,
//!   key-byte sanity).
//! - [`memory`] — memory-side pattern / key-ring helpers (called by the
//!   lsass extractor).
//! - [`sqlite`] — minimal embedded SQLite reader; avoids a `rusqlite`
//!   dependency.
//! - [`output`] — pretty + JSON renderers.
//! - [`types`] — `Browser`, `Cookie`, `SavedPassword`, `AutofillEntry`,
//!   `ChromeFindings`.
//! - [`firefox`] — Firefox profile discovery (NSS plaintext decrypt is a
//!   scaffold).
//!
//! See [`docs/plans/2026-06-05-chrome-module-design.md`](../../docs/plans/2026-06-05-chrome-module-design.md)
//! for the original design spec.

pub mod abe;
pub mod abe_keys;
pub mod blob;
pub mod cookie_monster;
pub mod disk;
pub mod dpapi_decrypt;
pub mod heuristic;
pub mod hybrid;
pub mod local_state;
pub mod memory;
pub mod output;
pub mod process_scan;
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
