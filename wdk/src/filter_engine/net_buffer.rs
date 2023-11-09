use core::mem::MaybeUninit;

use alloc::string::{String, ToString};
use windows_sys::Wdk::System::SystemServices::{
    IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool,
};

use crate::{
    allocator::POOL_TAG,
    ffi::{
        FwpsAllocateNetBufferAndNetBufferList0, FwpsFreeNetBufferList0,
        NdisAdvanceNetBufferDataStart, NdisAllocateNetBufferListPool, NdisFreeNetBufferListPool,
        NdisGetDataBuffer, NdisRetreatNetBufferDataStart, NDIS_HANDLE, NDIS_OBJECT_TYPE_DEFAULT,
        NET_BUFFER_LIST, NET_BUFFER_LIST_POOL_PARAMETERS,
        NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
    },
    utils::check_ntstatus,
};

pub struct NBLIterator(*mut NET_BUFFER_LIST);

impl NBLIterator {
    pub fn new(nbl: *mut NET_BUFFER_LIST) -> Self {
        Self(nbl)
    }
}

impl Iterator for NBLIterator {
    type Item = *mut NET_BUFFER_LIST;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if let Some(nbl) = self.0.as_mut() {
                self.0 = nbl.Header.next as _;
                return Some(nbl);
            }
            None
        }
    }
}

/// Returns a buffer with the whole packet, or the size of the packet on error.
pub fn read_first_packet<'a>(
    nbl: *mut NET_BUFFER_LIST,
) -> Result<(&'a [u8], Option<alloc::vec::Vec<u8>>), ()> {
    unsafe {
        let Some(nbl) = nbl.as_ref() else {
            return Err(());
        };
        let nb = nbl.Header.first_net_buffer;
        if let Some(nb) = nb.as_ref() {
            let data_length = nb.stDataLength as u32;
            if data_length == 0 {
                return Err(());
            }

            // Try to return reference to the data.
            let ptr = NdisGetDataBuffer(nb, data_length, core::ptr::null_mut(), 1, 0);
            if !ptr.is_null() {
                let slice = alloc::slice::from_raw_parts(ptr, data_length as usize);
                return Ok((slice, None));
            }

            // Cant return reference. Allocate buffer.
            let mut vec = alloc::vec![0; data_length as usize];
            let ptr = NdisGetDataBuffer(nb, data_length, vec.as_mut_ptr(), 1, 0);
            if !ptr.is_null() {
                let slice = alloc::slice::from_raw_parts(ptr, data_length as usize);
                return Ok((slice, Some(vec)));
            }
        }
    }
    return Err(());
}

pub struct NetworkAllocator {
    pool_handle: NDIS_HANDLE,
}

impl NetworkAllocator {
    pub fn new() -> Self {
        unsafe {
            let mut params: NET_BUFFER_LIST_POOL_PARAMETERS = MaybeUninit::zeroed().assume_init();
            params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
            params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
            params.Header.Size = core::mem::size_of::<NET_BUFFER_LIST_POOL_PARAMETERS>() as u16;
            params.fAllocateNetBuffer = true;
            params.PoolTag = POOL_TAG;
            params.DataSize = 0;

            let pool_handle = NdisAllocateNetBufferListPool(core::ptr::null_mut(), &params);
            Self { pool_handle }
        }
    }

    pub fn wrap_packet_in_nbl(&self, packet_data: &[u8]) -> Result<*mut NET_BUFFER_LIST, String> {
        if self.pool_handle.is_null() {
            return Err("allocator not initialized".to_string());
        }
        unsafe {
            let mdl = IoAllocateMdl(
                packet_data.as_ptr() as _,
                packet_data.len() as u32,
                0,
                0,
                core::ptr::null_mut(),
            );
            if mdl.is_null() {
                return Err("failed to allocate mdl".to_string());
            }
            MmBuildMdlForNonPagedPool(mdl);
            let mut nbl = core::ptr::null_mut();
            let status = FwpsAllocateNetBufferAndNetBufferList0(
                self.pool_handle,
                0,
                0,
                mdl,
                0,
                packet_data.len() as u64,
                &mut nbl,
            );
            if let Err(err) = check_ntstatus(status) {
                IoFreeMdl(mdl);
                return Err(err);
            }
            return Ok(nbl);
        }
    }

    pub fn free_net_buffer(nbl: *mut NET_BUFFER_LIST) {
        NBLIterator::new(nbl).for_each(|nbl| unsafe {
            if let Some(nbl) = nbl.as_mut() {
                if let Some(nb) = nbl.Header.first_net_buffer.as_mut() {
                    IoFreeMdl(nb.MdlChain);
                }
                FwpsFreeNetBufferList0(nbl);
            }
        });
    }

    pub fn retreat_net_buffer(nbl: *mut NET_BUFFER_LIST, size: u32) {
        unsafe {
            if let Some(nbl) = nbl.as_mut() {
                if let Some(nb) = nbl.Header.first_net_buffer.as_mut() {
                    NdisRetreatNetBufferDataStart(nb as _, size, 0, core::ptr::null_mut());
                }
            }
        }
    }
    pub fn advance_net_buffer(nbl: *mut NET_BUFFER_LIST, size: u32) {
        unsafe {
            if let Some(nbl) = nbl.as_mut() {
                if let Some(nb) = nbl.Header.first_net_buffer.as_mut() {
                    NdisAdvanceNetBufferDataStart(nb as _, size, false, core::ptr::null_mut());
                }
            }
        }
    }
}

impl Drop for NetworkAllocator {
    fn drop(&mut self) {
        unsafe {
            NdisFreeNetBufferListPool(self.pool_handle);
        }
    }
}
