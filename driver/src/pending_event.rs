use wdk::rw_spin_lock::Mutex;

use crate::event::Event;

/// The event that did not fit in the last read, and how many of its serialized bytes were already
/// sent. The next read sends the rest first, so user space receives every event whole and in
/// order. The event is kept as it is, not serialized: the rest is serialized again from it.
///
/// That holds for one reader at a time. Concurrent reads are memory safe (each method is a single
/// critical section) but two threads reading one byte stream each get pieces of it, as with any
/// stream.
pub struct PendingEvent(Mutex<Option<(Event, usize)>>);

impl PendingEvent {
    pub const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// Takes the pending event, with the number of its bytes already sent.
    pub fn take(&self) -> Option<(Event, usize)> {
        self.0.write_lock().take()
    }

    /// Keeps `event`, of which the first `sent` bytes were already sent, for the next read.
    pub fn stash(&self, event: Event, sent: usize) {
        *self.0.write_lock() = Some((event, sent));
    }
}
