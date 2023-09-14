extern crate alloc;

use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
};

use alloc::alloc::handle_alloc_error;
// use winapi::{shared::ntdef::PHYSICAL_ADDRESS, um::winnt::RtlZeroMemory};

pub type PoolType = i32;

pub const PAGED_POOL: PoolType = 1;
pub const NON_PAGED_POOL: PoolType = 0;
pub const NON_PAGED_POOL_EXECUTE: PoolType = 0;
pub const NON_PAGED_POOL_MUST_SUCCEED: PoolType = 2;
pub const DONT_USE_THIS_TYPE: PoolType = 3;
pub const NON_PAGED_POOL_CACHE_ALIGNED: PoolType = 4;
pub const PAGED_POOL_CACHE_ALIGNED: PoolType = 5;
pub const NON_PAGED_POOL_CACHE_ALIGNED_MUST_S: PoolType = 6;
pub const MAX_POOL_TYPE: PoolType = 7;
pub const NON_PAGED_POOL_BASE: PoolType = 0;
pub const NON_PAGED_POOL_BASE_MUST_SUCCEED: PoolType = 2;
pub const NON_PAGED_POOL_BASE_CACHE_ALIGNED: PoolType = 4;
pub const NON_PAGED_POOL_BASE_CACHE_ALIGNED_MUST_S: PoolType = 6;
pub const NON_PAGED_POOL_SESSION: PoolType = 32;
pub const PAGED_POOL_SESSION: PoolType = 33;
pub const NON_PAGED_POOL_MUST_SUCCEED_SESSION: PoolType = 34;
pub const DONT_USE_THIS_TYPE_SESSION: PoolType = 35;
pub const NON_PAGED_POOL_CACHE_ALIGNED_SESSION: PoolType = 36;
pub const PAGED_POOL_CACHE_ALIGNED_SESSION: PoolType = 37;
pub const NON_PAGED_POOL_CACHE_ALIGNED_MUST_SSESSION: PoolType = 38;
pub const NON_PAGED_POOL_NX: PoolType = 512;
pub const NON_PAGED_POOL_NX_CACHE_ALIGNED: PoolType = 516;
pub const NON_PAGED_POOL_SESSION_NX: PoolType = 544;

pub const MM_ANY_NODE_OK: u32 = 0x80000000;
pub type NodeRequirement = u32;

#[repr(i32)]
pub enum MemoryCachingType {
    MmNonCached = 0,
    MmCached = 1,
    MmWriteCombined = 2,
    MmHardwareCoherentCached = 3,
    MmNonCachedUnordered = 4,
    MmUSWCCached = 5,
    MmMaximumCacheType = 6,
    MmNotMapped = -1,
}

#[link(name = "ntoskrnl")]
extern "system" {
    // fn ExAllocatePool(pool_type: PoolType, number_of_bytes: usize) -> *mut u64;
    fn ExAllocatePoolWithTag(pool_type: PoolType, number_of_bytes: usize, tag: u32) -> *mut u64;
    // fn ExFreePool(pool: u64);
    fn ExFreePoolWithTag(pool: u64, tag: u32);
    // fn MmAllocateContiguousMemorySpecifyCacheNode(
    //     NumberOfBytes: usize,
    //     LowestAcceptableAddress: PHYSICAL_ADDRESS,
    //     HighestAcceptableAddress: PHYSICAL_ADDRESS,
    //     BoundaryAddressMultiple: PHYSICAL_ADDRESS,
    //     CacheType: MemoryCachingType,
    //     PreferredNode: NodeRequirement,
    // ) -> *mut u64;
    pub fn MmFreeContiguousMemory(BaseAddress: *mut u64);

    fn RtlZeroMemory(Destination: *mut c_void, Length: usize);
}

pub struct WindowsAllocator {}

unsafe impl Sync for WindowsAllocator {}

const POOL_TAG: u32 = u32::from_ne_bytes(*b"PMrs");

unsafe impl GlobalAlloc for WindowsAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pool = ExAllocatePoolWithTag(NON_PAGED_POOL, layout.size(), POOL_TAG);
        if pool.is_null() {
            handle_alloc_error(layout);
        }

        pool as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        ExFreePoolWithTag(ptr as u64, POOL_TAG);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pool = self.alloc(layout);
        RtlZeroMemory(pool as _, layout.size());
        pool
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller must ensure that the `new_size` does not overflow.
        // `layout.align()` comes from a `Layout` and is thus guaranteed to be valid.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: the caller must ensure that `new_layout` is greater than zero.
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            // SAFETY: the previously allocated block cannot overlap the newly allocated block.
            // The safety contract for `dealloc` must be upheld by the caller.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    ptr,
                    new_ptr,
                    core::cmp::min(layout.size(), new_size),
                );
                self.dealloc(ptr, layout);
            }
        }
        new_ptr
    }
}
