#[cfg(not(any(
    feature = "vmware",
    feature = "vbox",
    feature = "qemu",
    feature = "hyperv",
    feature = "disk"
)))]
compile_error!(
    "At least one backend must be enabled: --features vmware, vbox, qemu, hyperv, and/or disk"
);

pub mod cli;

use anyhow::Context as _;
use clap::Parser;

use cli::Args;

/// Minimal logger without an additional dependency.
struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "[{:<5} {}] {}",
                record.level(),
                record.target(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

fn main() -> anyhow::Result<()> {
    // Memory scans need more stack than ESXi's 512 KiB shell limit.
    const STACK_SIZE: usize = 8 * 1024 * 1024;
    let builder = std::thread::Builder::new().stack_size(STACK_SIZE);
    let handler = builder
        .spawn(vmkatz_main)
        .context("failed to spawn main thread")?;
    handler
        .join()
        .map_err(|_| anyhow::anyhow!("main thread panicked"))?
}

fn vmkatz_main() -> anyhow::Result<()> {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) if e.kind() == clap::error::ErrorKind::MissingRequiredArgument => {
            Args::parse_from(["vmkatz", "--help"]);
            std::process::exit(0)
        }
        Err(e) => e.exit(),
    };
    let log_level = match args.verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        _ => log::LevelFilter::Debug,
    };
    if let Err(e) = log::set_logger(&SimpleLogger) {
        eprintln!("[!] cannot install logger: {e}");
    }
    log::set_max_level(log_level);

    eprintln!("[*] vmkatz v{}", env!("CARGO_PKG_VERSION"));

    cli::run(&args)
}
