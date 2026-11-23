extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};

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

/// Pool allocations are 16-byte aligned on 64-bit Windows.
const POOL_ALIGNMENT: usize = 16;
/// Cache-aligned pool allocations start on a processor cache line.
const CACHE_LINE_ALIGNMENT: usize = 64;

unsafe impl GlobalAlloc for WindowsAllocator {
    /// Returns null when the pool is exhausted, as `GlobalAlloc` requires: the caller decides what
    /// a failed allocation means (`Box::new` still treats it as fatal, `try_reserve` does not).
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let flags = if layout.align() <= POOL_ALIGNMENT {
            PoolType::NonPaged as u64
        } else if layout.align() <= CACHE_LINE_ALIGNMENT {
            PoolType::NonPaged as u64 | PoolType::CacheAligned as u64
        } else {
            // The pool has no way to honour a larger alignment.
            return core::ptr::null_mut();
        };

        ExAllocatePool2(flags, layout.size(), POOL_TAG) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        ExFreePoolWithTag(ptr as _, POOL_TAG);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // ExAllocatePool2 zeroes the memory unless asked not to (POOL_FLAG_UNINITIALIZED).
        return self.alloc(layout);
    }
}
