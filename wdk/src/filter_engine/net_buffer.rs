use core::{ffi::c_void, mem::MaybeUninit};

use alloc::string::{String, ToString};
use windows_sys::{
    Wdk::{
        Foundation::MDL,
        System::SystemServices::{IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool},
    },
    Win32::Foundation::{HANDLE, NTSTATUS},
};

use crate::{allocator::POOL_TAG, utils::check_ntstatus};

const NDIS_OBJECT_TYPE_DEFAULT: u8 = 0x80; // used when object type is implicit in the API call
const NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1: u8 = 1;

#[repr(C)]
struct NBListHeader {
    next: *mut NET_BUFFER_LIST,
    first_net_buffer: *mut NET_BUFFER,
}

/// This is internal struct should never be allocated from the driver. Use provieded functions by microsoft.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub struct NET_BUFFER_LIST {
    Header: NBListHeader,
    Context: *mut c_void,
    ParentNetBufferList: *mut NET_BUFFER_LIST,
    NdisPoolHandle: NDIS_HANDLE,
    NdisReserved: [*mut c_void; 2],
    ProtocolReserved: [*mut c_void; 4],
    MiniportReserved: [*mut c_void; 2],
    Scratch: *mut c_void,
    SourceHandle: NDIS_HANDLE,
    NblFlags: u32,
    ChildRefCount: i32,
    Flags: u32,
    Status: NDIS_STATUS,
    NetBufferListInfo: [*mut c_void; 20], // Extra data at the end of the struct. The size of the array is not fixed.
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub struct NET_BUFFER {
    Next: *mut NET_BUFFER,
    CurrentMdl: *mut MDL,
    CurrentMdlOffset: u32,
    stDataLength: u64, // Use as u32 value. Check the original struct. TODO: Handle this in a better way.
    MdlChain: *mut MDL,
    DataOffset: u32,
    ChecksumBias: u16,
    Reserved: u16,
    NdisPoolHandle: NDIS_HANDLE,
    NdisReserved: [*mut c_void; 2],
    ProtocolReserved: [*mut c_void; 6],
    MiniportReserved: [*mut c_void; 4],
    DataPhysicalAddress: u64,
    SharedMemoryInfo: *mut c_void,
}

#[allow(non_camel_case_types)]
pub type NDIS_HANDLE = *mut c_void;

#[allow(non_camel_case_types)]
pub type NDIS_STATUS = i32;

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
struct NDIS_OBJECT_HEADER {
    Type: u8,
    Revision: u8,
    Size: u16,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
struct NET_BUFFER_LIST_POOL_PARAMETERS {
    Header: NDIS_OBJECT_HEADER,
    ProtocolId: u8,
    fAllocateNetBuffer: bool,
    ContextSize: u16,
    PoolTag: u32,
    DataSize: u32,
    Flags: u32,
}

#[allow(dead_code)]
extern "C" {
    pub(super) fn FwpsInjectionHandleDestroy0(injectionHandle: HANDLE) -> NTSTATUS;

    pub(super) fn FwpsReferenceNetBufferList0(
        netBufferList: *mut NET_BUFFER_LIST,
        intendToModify: bool,
    );
    pub(super) fn FwpsDereferenceNetBufferList0(
        netBufferList: *mut NET_BUFFER_LIST,
        dispatchLevel: bool,
    );

    pub(super) fn NdisGetDataBuffer(
        NetBuffer: *const NET_BUFFER,
        BytesNeeded: u32,
        Storage: *mut u8,
        AlignMultiple: u32,
        AlignOffset: u32,
    ) -> *mut u8;

    /// Call the NdisAllocateCloneNetBufferList function to create a new clone NET_BUFFER_LIST structure.
    pub(super) fn NdisAllocateCloneNetBufferList(
        OriginalNetBufferList: *mut NET_BUFFER_LIST,
        NetBufferListPoolHandle: NDIS_HANDLE,
        NetBufferPoolHandle: NDIS_HANDLE,
        AllocateCloneFlag: u32,
    ) -> *mut NET_BUFFER_LIST;

    pub(super) fn NdisFreeCloneNetBufferList(
        CloneNetBufferList: *mut NET_BUFFER_LIST,
        FreeCloneFlags: u32,
    );

    fn FwpsAllocateNetBufferAndNetBufferList0(
        poolHandle: NDIS_HANDLE,
        contextSize: u16,
        contextBackFill: u16,
        mdlChain: *mut MDL,
        dataOffset: u32,
        dataLength: u64,
        netBufferList: *mut *mut NET_BUFFER_LIST,
    ) -> NTSTATUS;

    fn FwpsFreeNetBufferList0(netBufferList: *mut NET_BUFFER_LIST);

    fn NdisAllocateNetBufferListPool(
        NdisHandle: NDIS_HANDLE,
        Parameters: *const NET_BUFFER_LIST_POOL_PARAMETERS,
    ) -> NDIS_HANDLE;

    fn NdisFreeNetBufferListPool(PoolHandle: NDIS_HANDLE);
}

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

            // Try to return referenc to the data.
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
}

impl Drop for NetworkAllocator {
    fn drop(&mut self) {
        unsafe {
            NdisFreeNetBufferListPool(self.pool_handle);
        }
    }
}
