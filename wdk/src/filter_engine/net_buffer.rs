use core::ffi::c_void;

use windows_sys::{
    Wdk::Foundation::MDL,
    Win32::Foundation::{HANDLE, NTSTATUS},
};

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
