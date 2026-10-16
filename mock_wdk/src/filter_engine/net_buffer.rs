use core::ffi::c_void;

/// Host stand-in for the kernel `NET_BUFFER_LIST`. Owns the packet bytes plus a
/// `data_offset` cursor that models where the current data view starts (the
/// kernel moves this with retreat/advance). `next` chains buffers so the driver
/// can iterate, exactly like the real NBL chain.
#[allow(non_camel_case_types)]
pub struct NET_BUFFER_LIST {
    pub data: Vec<u8>,
    pub data_offset: usize,
    pub next: *mut NET_BUFFER_LIST,
    /// Mock of the FWPS per-NBL injection state: `Some(ipv6)` marks the packet
    /// as injected by the driver through the network handle of that family.
    /// The kernel tracks this per injection handle; the family here models the
    /// v4-vs-v6 handle split (see `Injector::was_network_packet_injected_by_self`).
    pub injected_by_self: Option<bool>,
}

impl NET_BUFFER_LIST {
    /// Allocate a single NBL node on the heap. The caller owns the `Box` and is
    /// responsible for keeping it alive while any `NetBufferList` view of it
    /// exists. For inbound packets, set `data_offset` to the size of the headers
    /// the kernel has already advanced past (so `retreat` brings it back).
    pub fn new_box(data: Vec<u8>, data_offset: usize) -> Box<NET_BUFFER_LIST> {
        Box::new(NET_BUFFER_LIST {
            data,
            data_offset,
            next: core::ptr::null_mut(),
            injected_by_self: None,
        })
    }

    /// Like [`new_box`](Self::new_box), but carrying the injected-by-self mark
    /// for the given family — a packet re-entering the stack after the driver
    /// injected it through the v4 (`ipv6 = false`) or v6 network handle.
    pub fn new_box_injected(data: Vec<u8>, data_offset: usize, ipv6: bool) -> Box<NET_BUFFER_LIST> {
        let mut nbl = Self::new_box(data, data_offset);
        nbl.injected_by_self = Some(ipv6);
        nbl
    }
}

/// Host mock of `wdk::filter_engine::net_buffer::NetBuffer`.
///
/// The real list carries a chain of NET_BUFFERs; the mock models every
/// `NET_BUFFER_LIST` node as holding exactly one net buffer, so a `NetBuffer`
/// views the node's bytes and its `data_offset` cursor directly (retreat and
/// advance move that cursor, like `NdisRetreat/AdvanceNetBufferDataStart`).
/// [`NetBuffer::owned_from_bytes`] builds a standalone one for tests.
pub struct NetBuffer {
    nb: *mut NET_BUFFER_LIST,
    data: Option<Vec<u8>>,
    advance_on_drop: Option<u32>,
}

impl NetBuffer {
    pub fn new(nb: *mut NET_BUFFER_LIST) -> NetBuffer {
        NetBuffer {
            nb,
            data: None,
            advance_on_drop: None,
        }
    }

    /// Test helper: a net buffer over `bytes`, not backed by any list.
    pub fn owned_from_bytes(bytes: Vec<u8>) -> NetBuffer {
        NetBuffer {
            nb: core::ptr::null_mut(),
            data: Some(bytes),
            advance_on_drop: None,
        }
    }

    fn view(&self) -> &[u8] {
        if let Some(d) = &self.data {
            return d;
        }
        unsafe {
            match self.nb.as_ref() {
                Some(nb) => &nb.data[core::cmp::min(nb.data_offset, nb.data.len())..],
                None => &[],
            }
        }
    }

    pub fn get_data_length(&self) -> u32 {
        self.view().len() as u32
    }

    /// Reads `buffer.len()` bytes from the current data start. Fails if the net
    /// buffer is empty or holds fewer bytes than requested.
    pub fn read_bytes(&self, buffer: &mut [u8]) -> Result<(), ()> {
        let view = self.view();
        if view.is_empty() || buffer.len() > view.len() {
            return Err(());
        }
        buffer.copy_from_slice(&view[..buffer.len()]);
        Ok(())
    }

    /// Copies this net buffer into a new, owned single-buffer list.
    pub fn clone_as_nbl(&self, _net_allocator: &NetworkAllocator) -> Result<NetBufferList, String> {
        if self.data.is_none() && self.nb.is_null() {
            return Err("net buffer is null".to_string());
        }
        let view = self.view();
        if view.is_empty() {
            return Err("can't clone empty packet".to_string());
        }
        Ok(NetBufferList::owned_from_bytes(view.to_vec()))
    }

    /// Retreats the data start by `size`. Like the real call (which passes no
    /// allocation routine), it fails when there are not `size` bytes in front
    /// of the current offset, leaving the offset unchanged.
    pub fn retreat(&mut self, size: u32, auto_advance: bool) -> Result<(), String> {
        unsafe {
            let Some(nb) = self.nb.as_mut() else {
                return Err("net buffer is null".to_string());
            };
            if size as usize > nb.data_offset {
                return Err("NDIS_STATUS_RESOURCES".to_string());
            }
            nb.data_offset -= size as usize;
        }
        if auto_advance {
            self.advance_on_drop = Some(size);
        }
        Ok(())
    }

    /// Advances the data start by `size`, undoing a retreat.
    pub fn advance(&self, size: u32) {
        unsafe {
            if let Some(nb) = self.nb.as_mut() {
                nb.data_offset = core::cmp::min(nb.data_offset + size as usize, nb.data.len());
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

/// Host mock of `NetBufferIter`. Yields the single net buffer of a mock list.
pub struct NetBufferIter(*mut NET_BUFFER_LIST);

impl NetBufferIter {
    pub fn new(nb: *mut NET_BUFFER_LIST) -> Self {
        Self(nb)
    }
}

impl Iterator for NetBufferIter {
    type Item = NetBuffer;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_null() {
            return None;
        }
        let current = self.0;
        // One net buffer per mock list node.
        self.0 = core::ptr::null_mut();
        Some(NetBuffer::new(current))
    }
}

/// Host mock of `wdk::filter_engine::net_buffer::NetBufferList`.
///
/// Two modes, mirroring the real type:
/// * *borrowed* -- `nbl` points at an externally owned `NET_BUFFER_LIST`
///   (from a callout's layer data or the iterator). `get_data*` return `None`.
/// * *owned*    -- produced by `clone()`; `data` holds a copy and `get_data*`
///   return `Some`. This is the only mode `packet_util::redirect` mutates.
pub struct NetBufferList {
    pub(crate) nbl: *mut NET_BUFFER_LIST,
    data: Option<Vec<u8>>,
}

impl NetBufferList {
    pub fn new(nbl: *mut NET_BUFFER_LIST) -> NetBufferList {
        NetBufferList {
            nbl,
            data: None,
        }
    }

    /// Test helper: build an *owned* NBL directly from bytes (so `get_data` /
    /// `get_data_mut` return `Some`). Useful for exercising redirect/checksum.
    pub fn owned_from_bytes(bytes: Vec<u8>) -> NetBufferList {
        NetBufferList {
            nbl: core::ptr::null_mut(),
            data: Some(bytes),
        }
    }

    pub fn iter(&self) -> NetBufferListIter {
        NetBufferListIter(self.nbl)
    }

    /// Iterates over every net buffer in this list (one, in the mock).
    pub fn iter_net_buffers(&self) -> NetBufferIter {
        NetBufferIter(self.nbl)
    }

    fn view_len(&self) -> usize {
        if let Some(d) = &self.data {
            return d.len();
        }
        unsafe {
            if let Some(nbl) = self.nbl.as_ref() {
                return nbl.data.len().saturating_sub(nbl.data_offset);
            }
        }
        0
    }

    pub fn read_bytes(&self, buffer: &mut [u8]) -> Result<(), ()> {
        let len = self.view_len();
        if len == 0 {
            return Err(());
        }
        if buffer.len() > len {
            return Err(());
        }
        if let Some(d) = &self.data {
            buffer.copy_from_slice(&d[..buffer.len()]);
            return Ok(());
        }
        unsafe {
            let Some(nbl) = self.nbl.as_ref() else {
                return Err(());
            };
            let start = nbl.data_offset;
            buffer.copy_from_slice(&nbl.data[start..start + buffer.len()]);
        }
        Ok(())
    }

    pub fn clone(&self, _net_allocator: &NetworkAllocator) -> Result<NetBufferList, String> {
        let copy = if let Some(d) = &self.data {
            d.clone()
        } else {
            unsafe {
                let Some(nbl) = self.nbl.as_ref() else {
                    return Err("net buffer list is null".to_string());
                };
                let start = nbl.data_offset;
                if nbl.data.len().saturating_sub(start) == 0 {
                    return Err("can't clone empty packet".to_string());
                }
                nbl.data[start..].to_vec()
            }
        };
        Ok(NetBufferList {
            nbl: core::ptr::null_mut(),
            data: Some(copy),
        })
    }

    pub fn get_data_mut(&mut self) -> Option<&mut [u8]> {
        self.data.as_deref_mut()
    }

    pub fn get_data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    pub fn get_data_length(&self) -> u64 {
        if let Some(d) = &self.data {
            return d.len() as u64;
        }
        let mut total: u64 = 0;
        let mut nb = self.nbl;
        unsafe {
            while let Some(n) = nb.as_ref() {
                total += n.data.len().saturating_sub(n.data_offset) as u64;
                nb = n.next;
            }
        }
        total
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
                let current = self.0;
                self.0 = nbl.next;
                return Some(NetBufferList {
                    nbl: current,
                    data: None,
                        });
            }
            None
        }
    }
}

/// Host mock of `NetworkAllocator`. No pool to manage; all methods are no-ops.
pub struct NetworkAllocator;

impl NetworkAllocator {
    pub fn new() -> Self {
        NetworkAllocator
    }

    pub fn free_net_buffer(_nbl: *mut NET_BUFFER_LIST) {}
}

impl Default for NetworkAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// Keep the c_void import meaningful: a couple of driver call sites cast the
// layer-data pointer through `*mut c_void`. Provide a tiny helper used by tests
// so the import is not dead.
pub fn as_layer_data(nbl: *mut NET_BUFFER_LIST) -> *mut c_void {
    nbl as *mut c_void
}
