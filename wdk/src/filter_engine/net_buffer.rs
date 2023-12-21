use alloc::{
    string::{String, ToString},
    vec::Vec,
};
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
pub fn read_packet<'a>(nbl: *mut NET_BUFFER_LIST, buffer: &'a mut Vec<u8>) -> Result<(), ()> {
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

            // Allocate space in buffer, if buffer is too small.
            if buffer.len() < data_length as usize {
                buffer.resize(data_length as usize, 0);
            }
            let ptr = NdisGetDataBuffer(nb, data_length, buffer.as_mut_ptr(), 1, 0);
            if !ptr.is_null() {
                return Ok(());
            }
        }
    }
    return Err(());
}

pub fn read_packet_partial<'a>(nbl: *mut NET_BUFFER_LIST, buffer: &'a mut [u8]) -> Result<(), ()> {
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

            if buffer.len() > data_length as usize {
                return Err(());
            }

            let ptr = NdisGetDataBuffer(nb, buffer.len() as u32, buffer.as_mut_ptr(), 1, 0);
            if !ptr.is_null() {
                return Ok(());
            }
        }
    }
    return Err(());
}

pub struct RetreatGuard {
    size: u32,
    nbl: *mut NET_BUFFER_LIST,
}

impl Drop for RetreatGuard {
    fn drop(&mut self) {
        NetworkAllocator::advance_net_buffer(self.nbl, self.size);
    }
}

pub struct NetworkAllocator {
    pool_handle: NDIS_HANDLE,
}

impl NetworkAllocator {
    pub fn new() -> Self {
        unsafe {
            let mut params: NET_BUFFER_LIST_POOL_PARAMETERS = core::mem::zeroed();
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

    pub fn retreat_net_buffer(
        nbl: *mut NET_BUFFER_LIST,
        size: u32,
        auto_advance: bool,
    ) -> Option<RetreatGuard> {
        unsafe {
            if let Some(nbl) = nbl.as_mut() {
                if let Some(nb) = nbl.Header.first_net_buffer.as_mut() {
                    NdisRetreatNetBufferDataStart(nb as _, size, 0, core::ptr::null_mut());
                    if auto_advance {
                        return Some(RetreatGuard { size, nbl });
                    }
                }
            }
        }

        return None;
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
