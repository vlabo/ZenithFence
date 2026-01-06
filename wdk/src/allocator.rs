extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};

use alloc::alloc::handle_alloc_error;
use windows_sys::Wdk::System::SystemServices::{ExAllocatePool2, ExFreePoolWithTag};

// For reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/pool_flags
#[allow(dead_code)]
#[repr(u64)]
enum PoolType {
    RequiredStartUseQuota = 0x0000000000000001,
    Uninitialized = 0x0000000000000002, // Don't zero-initialize allocation
    Session = 0x0000000000000004,       // Use session specific pool
    CacheAligned = 0x0000000000000008,  // Cache aligned allocation
    RaiseOnFailure = 0x0000000000000020, // Raise exception on failure
    NonPaged = 0x0000000000000040,      // Non paged pool NX
    NonPagedExecute = 0x0000000000000080, // Non paged pool executable
    Paged = 0x0000000000000100,         // Paged pool
    RequiredEnd = 0x0000000080000000,
    OptionalStart = 0x0000000100000000,
    OptionalEnd = 0x8000000000000000,
}

pub struct WindowsAllocator {}

unsafe impl Sync for WindowsAllocator {}

pub(crate) const POOL_TAG: u32 = u32::from_ne_bytes(*b"znfc");

unsafe impl GlobalAlloc for WindowsAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pool = ExAllocatePool2(PoolType::NonPaged as u64, layout.size(), POOL_TAG);
        if pool.is_null() {
            handle_alloc_error(layout);
        }

        pool as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        ExFreePoolWithTag(ptr as _, POOL_TAG);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        return self.alloc(layout);
    }
}
