use core::{
    cell::UnsafeCell,
    fmt::Display,
    mem::MaybeUninit,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use alloc::{boxed::Box, collections::VecDeque, string::String};
use windows_sys::{
    Wdk::{
        Foundation::KEVENT,
        System::SystemServices::{Executive, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject},
    },
    Win32::System::Kernel::SynchronizationEvent,
};

use crate::{consts::KERNEL_MODE, rw_spin_lock::Mutex};

/// How long a blocking pop waits before checking again whether the queue was run down, in
/// 100-nanosecond units (negative: relative to now). One second.
const WAIT_RECHECK_INTERVAL: i64 = -10_000_000;

#[derive(Debug)]
pub enum Status {
    Uninitialized,
    Timeout,
    UserAPC,
    Abandoned,
    /// The queue holds its maximum number of entries; the pushed entry was dropped.
    Full,
}

impl Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Status::Uninitialized => write!(f, "Uninitialized"),
            Status::Timeout => write!(f, "Timeout"),
            Status::UserAPC => write!(f, "UserAPC"),
            Status::Abandoned => write!(f, "Abandoned"),
            Status::Full => write!(f, "Full"),
        }
    }
}

/// A queue of up to `max_len` entries, with a blocking pop for the reader.
///
/// The room for all `max_len` entries is reserved when the queue is created, and the queue never
/// holds more, so pushing and popping never allocate: pushes run in the callouts, at up to
/// DISPATCH_LEVEL, on every packet sent to user space.
pub struct IOQueue<T> {
    entries: Mutex<VecDeque<T>>,
    /// Signaled when an entry is pushed into the empty queue, and on rundown. Auto-reset, so it
    /// wakes one waiting reader at a time. The address of the value must not change.
    not_empty: Pin<Box<UnsafeCell<KEVENT>>>,
    initialized: AtomicBool,
    /// The number of entries, kept next to the queue so it can be checked without the lock.
    len: AtomicUsize,
    max_len: usize,
    /// Entries refused because the queue was full.
    dropped: AtomicUsize,
}

// Entries move from the pushing thread to the popping one.
unsafe impl<T: Send> Sync for IOQueue<T> {}

impl<T> IOQueue<T> {
    /// A queue that holds up to `max_len` entries, all of them allocated now. Fails if the pool
    /// has no room for them. Make sure `rundown` is called on exit, if `drop()` is not called for
    /// the queue.
    pub fn new(max_len: usize) -> Result<Self, String> {
        let mut entries = VecDeque::new();
        if entries.try_reserve_exact(max_len).is_err() {
            return Err(alloc::format!(
                "failed to allocate an event queue of {} entries",
                max_len
            ));
        }

        let not_empty = Box::pin(UnsafeCell::new(unsafe {
            MaybeUninit::zeroed().assume_init()
        }));
        unsafe { KeInitializeEvent(not_empty.get(), SynchronizationEvent, 0) };

        Ok(Self {
            entries: Mutex::new(entries),
            not_empty,
            initialized: AtomicBool::new(true),
            len: AtomicUsize::new(0),
            max_len,
            dropped: AtomicUsize::new(0),
        })
    }

    /// Pushes new entry of any type. Fails with `Full`, dropping the entry, when the queue already
    /// holds `max_len` entries: nothing is reading it, and it must not grow without bound.
    pub fn push(&self, entry: T) -> Result<(), Status> {
        let was_empty = {
            let mut entries = self.entries.write_lock();
            if !self.initialized.load(Ordering::SeqCst) {
                return Err(Status::Uninitialized);
            }
            // Checked under the lock, so the reserved room is never exceeded: past it, the deque
            // would reallocate.
            if entries.len() >= self.max_len {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Err(Status::Full);
            }
            entries.push_back(entry);
            self.len.store(entries.len(), Ordering::SeqCst);
            entries.len() == 1
        };

        // A reader only waits on an empty queue, so only the first entry has to wake it.
        if was_empty {
            self.signal();
        }
        Ok(())
    }

    fn signal(&self) {
        unsafe { KeSetEvent(self.not_empty.get(), 0, 0) };
    }

    /// Takes the oldest entry. Also returns whether more are left.
    fn take(&self) -> Result<(T, bool), Status> {
        let mut entries = self.entries.write_lock();
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(Status::Uninitialized);
        }
        let Some(entry) = entries.pop_front() else {
            return Err(Status::Timeout);
        };
        self.len.store(entries.len(), Ordering::SeqCst);
        Ok((entry, !entries.is_empty()))
    }

    /// Returns element or a status. Waits until element is pushed or the queue is interrupted.
    /// PASSIVE_LEVEL only.
    pub fn wait_and_pop(&self) -> Result<T, Status> {
        // Wait in bounded steps rather than forever. A reader that started waiting just as
        // `rundown` ran sees the queue is gone at the next check at the latest.
        loop {
            match self.take() {
                Ok((entry, more_left)) => {
                    // The event only wakes one reader per push into the empty queue. Pass it on,
                    // so another waiting reader gets the entries left.
                    if more_left {
                        self.signal();
                    }
                    return Ok(entry);
                }
                Err(Status::Timeout) => {}
                Err(err) => return Err(err),
            }

            // Not alertable. Signaled or timed out, the queue is checked again either way.
            unsafe {
                KeWaitForSingleObject(
                    self.not_empty.get() as *const _,
                    Executive,
                    KERNEL_MODE,
                    0,
                    &WAIT_RECHECK_INTERVAL,
                )
            };
        }
    }

    /// Returns element or a status. Does not wait.
    pub fn pop(&self) -> Result<T, Status> {
        self.take().map(|(entry, _)| entry)
    }

    /// Whether the queue holds `max_len` entries, so a push would fail.
    pub fn is_full(&self) -> bool {
        self.len.load(Ordering::SeqCst) >= self.max_len
    }

    /// The number of entries waiting to be popped.
    pub fn queued_count(&self) -> usize {
        self.len.load(Ordering::SeqCst)
    }

    /// The number of entries `push` refused because the queue was full.
    pub fn dropped_count(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Drops all entries and stops the queue: pushes and pops fail from now on, and a waiting
    /// reader returns `Uninitialized`. The room reserved for the entries is kept until the queue
    /// is dropped.
    pub fn rundown(&self) {
        {
            let mut entries = self.entries.write_lock();
            if !self.initialized.swap(false, Ordering::SeqCst) {
                return;
            }
            entries.clear();
            self.len.store(0, Ordering::SeqCst);
        }
        self.signal();
    }
}

impl<T> Drop for IOQueue<T> {
    fn drop(&mut self) {
        self.rundown();
    }
}
