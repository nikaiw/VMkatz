//! Command-line entry points and their supporting modules.
//!
//! `dispatch` selects the input pipeline. `args` parses options and classifies
//! raw files; `dir`, `disk`, and `lsass` execute the selected pipeline. Shared
//! formatting lives in `output`, with optional disk consumers in `credentials`.

pub mod args;
#[cfg(feature = "disk")]
mod credentials;
#[cfg(feature = "credman")]
mod credman;
pub mod dir;
#[cfg(feature = "disk")]
pub mod disk;
mod dispatch;
pub mod lsass;
pub mod output;

pub(crate) use args::Args;
pub(crate) use dispatch::run;
