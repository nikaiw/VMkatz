pub mod reader;
pub use reader::{PhysicalMemory, VirtualMemory};

#[cfg(any(feature = "vbox", feature = "qemu"))]
pub(crate) mod page_index;

#[cfg(all(test, any(feature = "vbox", feature = "qemu", feature = "hyperv")))]
pub(crate) mod test_limit;
