use core::{
    alloc::Layout,
    ffi::c_void,
    mem::{ManuallyDrop, MaybeUninit},
    ptr::NonNull,
};

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
        NET_BUFFER, NET_BUFFER_LIST, NET_BUFFER_LIST_POOL_PARAMETERS,
        NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
    },
    utils::check_ntstatus,
};

/// A single NET_BUFFER inside a NET_BUFFER_LIST.
///
/// A list can carry a chain of net buffers, and each one is an independent
/// packet with its own data offset, length and MDL chain. Everything that acts
/// on packet bytes -- retreating the data start, reading headers, cloning --
/// is therefore per net buffer; doing it at the list level only ever touches
/// the head of the chain and silently ignores the rest.
pub struct NetBuffer {
    nb: *mut NET_BUFFER,
    advance_on_drop: Option<u32>,
}

impl NetBuffer {
    pub fn new(nb: *mut NET_BUFFER) -> NetBuffer {
        NetBuffer {
            nb,
            advance_on_drop: None,
        }
    }

    pub fn get_data_length(&self) -> u32 {
        unsafe {
            match self.nb.as_ref() {
                Some(nb) => nb.nbSize.DataLength,
                None => 0,
            }
        }
    }

    /// Reads `buffer.len()` bytes from the current data start of the net buffer.
    ///
    /// Fails if the net buffer holds fewer bytes than requested.
    pub fn read_bytes(&self, buffer: &mut [u8]) -> Result<(), ()> {
        unsafe {
            let Some(nb) = self.nb.as_ref() else {
                return Err(());
            };
            let data_length = nb.nbSize.DataLength;
            if data_length == 0 {
                return Err(());
            }

            if buffer.len() > data_length as usize {
                return Err(());
            }

            // Two options: returns a pointer to the raw packet buffer if the
            // requested range is contiguous, or copies into the supplied buffer.
            let mut ptr = NdisGetDataBuffer(nb, buffer.len() as u32, core::ptr::null_mut(), 1, 0);
            if !ptr.is_null() {
                buffer.copy_from_slice(core::slice::from_raw_parts(ptr, buffer.len()));
                return Ok(());
            }

            ptr = NdisGetDataBuffer(nb, buffer.len() as u32, buffer.as_mut_ptr(), 1, 0);
            if !ptr.is_null() {
                return Ok(());
            }
        }
        return Err(());
    }

    /// Copies this net buffer into a new, standalone NET_BUFFER_LIST holding a
    /// single net buffer.
    ///
    /// Each net buffer of a chain is cloned into its own list rather than into a
    /// chain of its own, because that is what the injection path takes: one
    /// packet per injected list.
    pub fn clone_as_nbl(&self, net_allocator: &NetworkAllocator) -> Result<NetBufferList, String> {
        self.clone_as_nbl_with_prefix(net_allocator, 0)
    }

    /// Like `clone_as_nbl`, with `prefix_len` bytes (a multiple of `PACKET_BUFFER_ALIGN`) in front
    /// of the copy, in the same allocation, for what has to live as long as the packet
    /// (`NetBufferList::prefix_mut`).
    pub(crate) fn clone_as_nbl_with_prefix(
        &self,
        net_allocator: &NetworkAllocator,
        prefix_len: usize,
    ) -> Result<NetBufferList, String> {
        unsafe {
            let Some(nb) = self.nb.as_ref() else {
                return Err("net buffer is null".to_string());
            };
            copy_net_buffer(nb, net_allocator, prefix_len)
        }
    }

    /// Retreats the data start of the net buffer, exposing bytes that precede it.
    ///
    /// With `auto_advance` the retreat is undone when the value is dropped.
    /// Returns an error if the retreat failed, in which case the data offset is
    /// unchanged and reads would still return data from the old offset.
    pub fn retreat(&mut self, size: u32, auto_advance: bool) -> Result<(), String> {
        unsafe {
            let Some(nb) = self.nb.as_mut() else {
                return Err("net buffer is null".to_string());
            };

            let status = NdisRetreatNetBufferDataStart(nb as _, size, 0, core::ptr::null_mut());
            check_ntstatus(status)?;

            if auto_advance {
                self.advance_on_drop = Some(size);
            }

            Ok(())
        }
    }

    /// Advances the data start of the net buffer, undoing a retreat.
    pub fn advance(&self, size: u32) {
        unsafe {
            if let Some(nb) = self.nb.as_mut() {
                NdisAdvanceNetBufferDataStart(nb as _, size, false, core::ptr::null_mut());
            }
        }
    }
}

impl Drop for NetBuffer {
    fn drop(&mut self) {
        if let Some(advance_amount) = self.advance_on_drop {
            self.advance(advance_amount);
        }
    }
}

pub struct NetBufferIter(*mut NET_BUFFER);

impl NetBufferIter {
    pub fn new(nb: *mut NET_BUFFER) -> Self {
        Self(nb)
    }
}

impl Iterator for NetBufferIter {
    type Item = NetBuffer;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if let Some(nb) = self.0.as_mut() {
                self.0 = nb.Next;
                return Some(NetBuffer {
                    nb,
                    advance_on_drop: None,
                });
            }
            None
        }
    }
}

/// Alignment of a packet copy. A prefix is a multiple of it, so what is kept in one (control data:
/// WSACMSGHDR has 8-byte fields) and the packet bytes after it are aligned too.
pub(crate) const PACKET_BUFFER_ALIGN: usize = 16;

/// A packet copy owned by a `NetBufferList`: one allocation holding a prefix of `prefix_len`
/// bytes, then the `len` packet bytes the list's MDL describes.
struct PacketBuffer {
    block: NonNull<u8>,
    prefix_len: usize,
    len: usize,
}

impl PacketBuffer {
    /// Zeroed room for a prefix of `prefix_len` bytes (a multiple of `PACKET_BUFFER_ALIGN`) and a
    /// packet of `len` bytes.
    fn new(prefix_len: usize, len: usize) -> Result<Self, String> {
        let layout = prefix_len
            .checked_add(len)
            .and_then(|size| Layout::from_size_align(size, PACKET_BUFFER_ALIGN).ok());
        let layout = match layout {
            Some(layout) if layout.size() > 0 && prefix_len.is_multiple_of(PACKET_BUFFER_ALIGN) => {
                layout
            }
            _ => return Err("invalid packet copy size".to_string()),
        };

        let block = unsafe { alloc::alloc::alloc_zeroed(layout) };
        match NonNull::new(block) {
            Some(block) => Ok(Self {
                block,
                prefix_len,
                len,
            }),
            None => Err("failed to allocate packet copy".to_string()),
        }
    }

    fn data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.block.as_ptr().add(self.prefix_len), self.len) }
    }

    fn data_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(self.block.as_ptr().add(self.prefix_len), self.len)
        }
    }

    fn prefix_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.block.as_ptr(), self.prefix_len) }
    }

    /// Gives up the allocation without freeing it; `from_raw` takes it back.
    fn into_raw(self) -> *mut u8 {
        ManuallyDrop::new(self).block.as_ptr()
    }

    /// # Safety
    /// `block`, `prefix_len` and `len` must be those of a buffer `into_raw` gave up.
    unsafe fn from_raw(block: *mut u8, prefix_len: usize, len: usize) -> Self {
        Self {
            block: NonNull::new_unchecked(block),
            prefix_len,
            len,
        }
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        unsafe {
            // The layout `new` allocated with, and checked.
            let layout =
                Layout::from_size_align_unchecked(self.prefix_len + self.len, PACKET_BUFFER_ALIGN);
            alloc::alloc::dealloc(self.block.as_ptr(), layout);
        }
    }
}

/// Copies the data of `nb` into a new, standalone NET_BUFFER_LIST, with `prefix_len` bytes in
/// front of the copy (see `PacketBuffer`).
unsafe fn copy_net_buffer(
    nb: &NET_BUFFER,
    net_allocator: &NetworkAllocator,
    prefix_len: usize,
) -> Result<NetBufferList, String> {
    let data_length = nb.nbSize.DataLength;
    if data_length == 0 {
        return Err("can't clone empty packet".to_string());
    }

    let mut buffer = PacketBuffer::new(prefix_len, data_length as usize)?;
    let data = buffer.data_mut();
    let buffer_ptr = data.as_mut_ptr();

    // Two options: returns a pointer to the raw packet buffer if the data is contiguous, or copies
    // it into the supplied buffer and returns a pointer to that.
    let ptr = NdisGetDataBuffer(nb, data_length, buffer_ptr, 1, 0);
    if ptr.is_null() {
        return Err("failed to copy packet buffer".to_string());
    }

    // If the pointers differ the data is not in the correct place.
    if ptr != buffer_ptr {
        data.copy_from_slice(core::slice::from_raw_parts(ptr, data_length as usize));
    }

    let new_nbl = net_allocator.wrap_packet_in_nbl(buffer.data())?;

    Ok(NetBufferList {
        nbl: new_nbl,
        data: Some(buffer),
    })
}

pub struct NetBufferList {
    pub(crate) nbl: *mut NET_BUFFER_LIST,
    /// The packet copy the list's MDL describes, for a list built by `clone`/`clone_as_nbl`.
    /// `None` for a list this does not own.
    data: Option<PacketBuffer>,
}

impl NetBufferList {
    pub fn new(nbl: *mut NET_BUFFER_LIST) -> NetBufferList {
        NetBufferList { nbl, data: None }
    }

    pub fn iter(&self) -> NetBufferListIter {
        NetBufferListIter(self.nbl)
    }

    /// Iterates over every net buffer in this list.
    pub fn iter_net_buffers(&self) -> NetBufferIter {
        unsafe {
            match self.nbl.as_ref() {
                Some(nbl) => NetBufferIter(nbl.Header.first_net_buffer),
                None => NetBufferIter(core::ptr::null_mut()),
            }
        }
    }

    /// Clones the first net buffer of the list.
    ///
    /// Only valid where the list is known to hold a single net buffer. Use
    /// [`NetBufferList::iter_net_buffers`] with [`NetBuffer::clone_as_nbl`] to
    /// clone a chain without dropping everything past the head.
    pub fn clone(&self, net_allocator: &NetworkAllocator) -> Result<NetBufferList, String> {
        unsafe {
            let Some(nbl) = self.nbl.as_ref() else {
                return Err("net buffer list is null".to_string());
            };

            let nb = nbl.Header.first_net_buffer;
            if let Some(nb) = nb.as_ref() {
                copy_net_buffer(nb, net_allocator, 0)
            } else {
                return Err("net buffer is null".to_string());
            }
        }
    }

    pub fn get_data_mut(&mut self) -> Option<&mut [u8]> {
        self.data.as_mut().map(PacketBuffer::data_mut)
    }

    pub fn get_data(&self) -> Option<&[u8]> {
        self.data.as_ref().map(PacketBuffer::data)
    }

    /// The bytes in front of the packet copy (`NetBuffer::clone_as_nbl_with_prefix`).
    pub(crate) fn prefix_mut(&mut self) -> Option<&mut [u8]> {
        self.data.as_mut().map(PacketBuffer::prefix_mut)
    }

    pub(crate) fn prefix_len(&self) -> usize {
        self.data.as_ref().map_or(0, |data| data.prefix_len)
    }

    /// Hands the list over to an asynchronous injection, without allocating a context for it.
    /// Returns the NET_BUFFER_LIST to inject and the completion context: the start of the packet
    /// copy's allocation (its prefix), or null for a list this does not own. The completion
    /// routine gives both back to `from_injected`.
    pub(crate) fn into_injected(self) -> (*mut NET_BUFFER_LIST, *mut c_void) {
        // Nothing is freed here: from now on the injection owns the list.
        let mut this = ManuallyDrop::new(self);
        let context = match this.data.take() {
            Some(data) => data.into_raw() as *mut c_void,
            None => core::ptr::null_mut(),
        };
        (this.nbl, context)
    }

    /// Takes back a list handed over with `into_injected`, once its injection completed or failed
    /// to start. `prefix_len` is the list's `prefix_len()` from before. Dropping the result frees
    /// the list, its MDL and the packet copy.
    ///
    /// The length of the packet is read from the MDL, which `wrap_packet_in_nbl` built over all
    /// of it. Returns `None`, leaking the list, if the MDL does not start right after the prefix:
    /// freeing with a wrong layout would corrupt the pool.
    ///
    /// # Safety
    /// `nbl` and `context` must be a pair `into_injected` returned, and nothing may use the list
    /// anymore.
    pub(crate) unsafe fn from_injected(
        nbl: *mut NET_BUFFER_LIST,
        context: *mut c_void,
        prefix_len: usize,
    ) -> Option<NetBufferList> {
        if context.is_null() {
            return Some(NetBufferList { nbl, data: None });
        }

        let mdl = nbl
            .as_ref()
            .and_then(|nbl| nbl.Header.first_net_buffer.as_ref())
            .and_then(|nb| nb.MdlChain.as_ref());
        let Some(mdl) = mdl else {
            crate::err!("injected packet has no MDL, leaking it");
            return None;
        };
        // MmGetMdlVirtualAddress
        let start = (mdl.StartVa as usize).wrapping_add(mdl.ByteOffset as usize);
        if start != (context as usize).wrapping_add(prefix_len) {
            crate::err!("injected packet MDL does not match its buffer, leaking it");
            return None;
        }

        let data = PacketBuffer::from_raw(context as *mut u8, prefix_len, mdl.ByteCount as usize);
        Some(NetBufferList {
            nbl,
            data: Some(data),
        })
    }

    pub fn get_data_length(&self) -> u64 {
        unsafe {
            if let Some(nbl) = self.nbl.as_ref() {
                let mut nb = nbl.Header.first_net_buffer;
                let mut data_length: u64 = 0;
                while !nb.is_null() {
                    let mut next = core::ptr::null_mut();
                    if let Some(nb) = nb.as_ref() {
                        data_length += nb.nbSize.DataLength as u64;
                        next = nb.Next;
                    }
                    nb = next;
                }

                data_length
            } else {
                0
            }
        }
    }

}

impl Drop for NetBufferList {
    fn drop(&mut self) {
        if self.data.is_some() {
            NetworkAllocator::free_net_buffer(self.nbl);
        }
    }
}

pub struct NetBufferListIter(*mut NET_BUFFER_LIST);

impl NetBufferListIter {
    pub fn new(nbl: *mut NET_BUFFER_LIST) -> Self {
        Self(nbl)
    }
}

impl Iterator for NetBufferListIter {
    type Item = NetBufferList;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if let Some(nbl) = self.0.as_mut() {
                self.0 = nbl.Header.next as _;
                return Some(NetBufferList { nbl, data: None });
            }
            None
        }
    }
}

pub fn read_packet_partial<'a>(nbl: *mut NET_BUFFER_LIST, buffer: &'a mut [u8]) -> Result<(), ()> {
    unsafe {
        let Some(nbl) = nbl.as_ref() else {
            return Err(());
        };
        let nb = nbl.Header.first_net_buffer;
        if let Some(nb) = nb.as_ref() {
            let data_length = nb.nbSize.DataLength;
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
            // Create MDL struct that will hold the buffer.
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

            // Build mdl with packet_data buffer.
            MmBuildMdlForNonPagedPool(mdl);

            // Initialize NBL structure.
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

    /// Frees a net buffer list allocated by `wrap_packet_in_nbl`, and its MDL. Only this one list:
    /// whatever its `Next` points to is not ours to free.
    pub(crate) fn free_net_buffer(nbl: *mut NET_BUFFER_LIST) {
        unsafe {
            if let Some(nbl) = nbl.as_mut() {
                if let Some(nb) = nbl.Header.first_net_buffer.as_mut() {
                    IoFreeMdl(nb.MdlChain);
                }
                FwpsFreeNetBufferList0(nbl);
            }
        }
    }

    /// Retreats the data start of the first net buffer.
    ///
    /// Returns an error if the retreat failed; the returned guard is `None` when
    /// the retreat succeeded but `auto_advance` was not requested.
    pub fn retreat_net_buffer(
        nbl: *mut NET_BUFFER_LIST,
        size: u32,
        auto_advance: bool,
    ) -> Result<Option<RetreatGuard>, String> {
        unsafe {
            let Some(nbl_ref) = nbl.as_mut() else {
                return Err("net buffer list is null".to_string());
            };
            let Some(nb) = nbl_ref.Header.first_net_buffer.as_mut() else {
                return Err("net buffer is null".to_string());
            };

            let status = NdisRetreatNetBufferDataStart(nb as _, size, 0, core::ptr::null_mut());
            check_ntstatus(status)?;

            if auto_advance {
                return Ok(Some(RetreatGuard { size, nbl }));
            }
        }

        return Ok(None);
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
            if !self.pool_handle.is_null() {
                NdisFreeNetBufferListPool(self.pool_handle);
            }
        }
    }
}
