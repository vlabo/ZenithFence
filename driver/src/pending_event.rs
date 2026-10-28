use alloc::vec::Vec;
use wdk::{irp_helpers::ReadRequest, rw_spin_lock::Mutex};

/// The part of an event that did not fit in the last read: the serialized event and how much of it
/// was already sent. The next read sends the rest first, so user space receives every event whole
/// and in order.
///
/// That holds for one reader at a time. Concurrent reads are memory safe (each method is a single
/// critical section) but two threads reading one byte stream each get pieces of it, as with any
/// stream.
pub struct PendingEvent(Mutex<Option<(Vec<u8>, usize)>>);

impl PendingEvent {
    pub const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// Writes as much of the pending event as fits into `read_request`, and forgets it once all of
    /// it is sent. Returns whether there was a pending event.
    pub fn send(&self, read_request: &mut ReadRequest) -> bool {
        let mut pending = self.0.write_lock();
        let Some((bytes, sent)) = pending.as_mut() else {
            return false;
        };
        *sent += read_request.write(&bytes[*sent..]);
        if *sent == bytes.len() {
            *pending = None;
        }
        return true;
    }

    /// Keeps the event `bytes`, of which the first `sent` were already sent, for the next read.
    pub fn stash(&self, bytes: Vec<u8>, sent: usize) {
        *self.0.write_lock() = Some((bytes, sent));
    }
}
