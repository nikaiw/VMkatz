use std::cell::Cell;

use vmkatz::error::{Result, VmkatzError};
use vmkatz::memory::PhysicalMemory;
use vmkatz::paging::ept::find_ept_candidates;

#[test]
fn ept_scan_makes_progress_over_a_four_gib_address_space() {
    struct UnreadableMemory {
        next: Cell<u64>,
    }
    impl PhysicalMemory for UnreadableMemory {
        fn phys_size(&self) -> u64 {
            1 << 32
        }

        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            // A cast before clamping used to produce a zero-byte read on 32-bit
            // hosts, leaving the scan stuck forever at address zero.
            assert_ne!(buf.len(), 0);
            assert_eq!(addr, self.next.get());
            assert!(buf.len() <= 1024 * 1024);
            self.next.set(addr + buf.len() as u64);
            Err(VmkatzError::UnmappablePhysical(addr))
        }
    }
    let mem = UnreadableMemory { next: Cell::new(0) };
    assert!(find_ept_candidates(&mem).is_err());
    assert_eq!(mem.next.get(), mem.phys_size());
}

#[test]
fn ept_scan_ignores_an_incomplete_final_page() {
    struct PartialPage;
    impl PhysicalMemory for PartialPage {
        fn phys_size(&self) -> u64 {
            4096 + 8
        }

        fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            // Only the scan read is legitimate. Following the apparent PML4
            // entry in the truncated final page would trigger another read.
            assert_eq!(addr, 0);
            assert_eq!(buf.len(), 4096 + 8);
            buf.fill(0);
            buf[4096..].copy_from_slice(&0x1007u64.to_le_bytes());
            Ok(())
        }
    }
    assert!(find_ept_candidates(&PartialPage).is_err());
}
