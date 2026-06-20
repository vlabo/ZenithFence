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
        })
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
    advance_on_drop: Option<u32>,
}

impl NetBufferList {
    pub fn new(nbl: *mut NET_BUFFER_LIST) -> NetBufferList {
        NetBufferList {
            nbl,
            data: None,
            advance_on_drop: None,
        }
    }

    /// Test helper: build an *owned* NBL directly from bytes (so `get_data` /
    /// `get_data_mut` return `Some`). Useful for exercising redirect/checksum.
    pub fn owned_from_bytes(bytes: Vec<u8>) -> NetBufferList {
        NetBufferList {
            nbl: core::ptr::null_mut(),
            data: Some(bytes),
            advance_on_drop: None,
        }
    }

    pub fn iter(&self) -> NetBufferListIter {
        NetBufferListIter(self.nbl)
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
            advance_on_drop: None,
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

    /// Move the data view start back by `size` (exposes more leading bytes).
    pub fn retreat(&mut self, size: u32, auto_advance: bool) {
        unsafe {
            if let Some(nbl) = self.nbl.as_mut() {
                nbl.data_offset = nbl.data_offset.saturating_sub(size as usize);
                if auto_advance {
                    self.advance_on_drop = Some(size);
                }
            }
        }
    }

    /// Move the data view start forward by `size`.
    pub fn advance(&self, size: u32) {
        unsafe {
            if let Some(nbl) = self.nbl.as_mut() {
                nbl.data_offset =
                    core::cmp::min(nbl.data_offset + size as usize, nbl.data.len());
            }
        }
    }
}

impl Drop for NetBufferList {
    fn drop(&mut self) {
        if let Some(advance_amount) = self.advance_on_drop {
            self.advance(advance_amount);
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
                let current = self.0;
                self.0 = nbl.next;
                return Some(NetBufferList {
                    nbl: current,
                    data: None,
                    advance_on_drop: None,
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
