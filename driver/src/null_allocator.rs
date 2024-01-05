use core::{alloc::Layout, ptr::NonNull};

use allocator_api2::alloc::Allocator;

pub struct NullAllocator {}
unsafe impl Sync for NullAllocator {}

unsafe impl Allocator for NullAllocator {
    fn allocate(
        &self,
        _layout: Layout,
    ) -> Result<NonNull<[u8]>, allocator_api2::alloc::AllocError> {
        panic!("Empty allocator should not be used for allocation");
    }

    unsafe fn deallocate(&self, _ptr: core::ptr::NonNull<u8>, _layout: Layout) {
        // Do nothing
    }
}
