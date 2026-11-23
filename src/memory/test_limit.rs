//! Run memory regressions in a child so allocation failures cannot kill the test runner.

use std::io;

pub fn child(name: &str) -> io::Result<bool> {
    if std::env::var_os("VMKATZ_SNAPSHOT_TEST_CHILD").is_none() {
        use std::os::unix::process::CommandExt as _;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command
            .args(["--exact", name, "--nocapture"])
            .env("VMKATZ_SNAPSHOT_TEST_CHILD", "1");
        // SAFETY: this hook only calls setrlimit and reads errno.
        unsafe {
            command.pre_exec(restrict_memory);
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "{name}: {}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        return Ok(true);
    }
    Ok(false)
}

fn restrict_memory() -> io::Result<()> {
    for (resource, bytes) in [(libc::RLIMIT_AS, 64 * 1024 * 1024), (libc::RLIMIT_CORE, 0)] {
        let limit = libc::rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        // SAFETY: limit has the expected layout and lives throughout the call.
        if unsafe { libc::setrlimit(resource, &raw const limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
