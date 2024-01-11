extern crate alloc;

use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
};

use alloc::alloc::handle_alloc_error;

#[repr(i32)]
enum PoolType {
    NonPaged = 0,
    // Paged = 1,
}

#[link(name = "NtosKrnl")]
extern "system" {
    fn ExAllocatePoolWithTag(pool_type: PoolType, number_of_bytes: usize, tag: u32) -> *mut u64;
    fn ExFreePoolWithTag(pool: u64, tag: u32);
    fn RtlZeroMemory(Destination: *mut c_void, Length: usize);
}

pub struct WindowsAllocator {}

unsafe impl Sync for WindowsAllocator {}

pub(crate) const POOL_TAG: u32 = u32::from_ne_bytes(*b"PMrs");

unsafe impl GlobalAlloc for WindowsAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pool = ExAllocatePoolWithTag(PoolType::NonPaged, layout.size(), POOL_TAG);
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
