use core::{
    cell::UnsafeCell,
    ffi::c_void,
    fmt::Display,
    marker::PhantomData,
    mem::MaybeUninit,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use crate::dbg;
use alloc::boxed::Box;
use windows_sys::{
    Wdk::Foundation::KQUEUE,
    Win32::{
        Foundation::{STATUS_ABANDONED, STATUS_TIMEOUT, STATUS_USER_APC},
        System::Kernel::LIST_ENTRY,
    },
};

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

#[repr(i8)]
pub enum KprocessorMode {
    KernelMode = 0,
    UserMode = 1,
}

#[link(name = "NtosKrnl", kind = "static")]
extern "C" {
    /*
    KeInitializeQueue
        [out] Queue
        Pointer to a KQUEUE structure for which the caller must provide resident storage in nonpaged pool. This structure is defined as follows:

        [in] Count
        The maximum number of threads for which the waits on the queue object can be satisfied concurrently. If this parameter is not supplied, the number of processors in the machine is used.
    */
    fn KeInitializeQueue(queue: *mut KQUEUE, count: u64);
    /*
    KeInsertQueue returns the previous signal state of the given Queue. If it was set to zero (that is, not signaled) before KeInsertQueue was called, KeInsertQueue returns zero, meaning that no entries were queued. If it was nonzero (signaled), KeInsertQueue returns the number of entries that were queued before KeInsertQueue was called.
    */
    fn KeInsertQueue(queue: *mut KQUEUE, list_entry: *mut c_void) -> i32;
    /*
    KeRemoveQueue returns one of the following:
        A pointer to a dequeued entry from the given queue object, if one is available
        STATUS_TIMEOUT, if the given Timeout interval expired before an entry became available
        STATUS_USER_APC, if a user-mode APC was delivered in the context of the calling thread
        STATUS_ABANDONED, if the queue has been run down
    */
    fn KeRemoveQueue(
        queue: *mut KQUEUE,
        waitmode: KprocessorMode,
        timeout: *const i64,
    ) -> *mut LIST_ENTRY;

    // If the queue is empty, KeRundownQueue returns NULL; otherwise, it returns the address of the first entry in the queue.
    fn KeRundownQueue(queue: *mut KQUEUE) -> *mut LIST_ENTRY;
}

#[repr(C)]
struct Entry<T> {
    list: LIST_ENTRY, // Internal use
    entry: T,
}

pub struct IOQueue<T> {
    // The address of the value should not change.
    kernel_queue: Pin<Box<UnsafeCell<KQUEUE>>>,
    initialized: AtomicBool,
    /// Entries pushed and not popped yet, counting the ones being pushed right now.
    len: AtomicUsize,
    max_len: usize,
    /// Entries refused because the queue was full.
    dropped: AtomicUsize,
    _type: PhantomData<T>, // 0 size variable. Required for the generic to work properly. Compiler limitation.
}

unsafe impl<T> Sync for IOQueue<T> {}

impl<T> IOQueue<T> {
    /// A queue that holds up to `max_len` entries. Make sure `rundown` is called on exit, if
    /// `drop()` is not called for queue.
    pub fn new(max_len: usize) -> Self {
        unsafe {
            let kernel_queue = Box::pin(UnsafeCell::new(MaybeUninit::zeroed().assume_init()));
            KeInitializeQueue(kernel_queue.get(), 1);

            Self {
                kernel_queue,
                initialized: AtomicBool::new(true),
                len: AtomicUsize::new(0),
                max_len,
                dropped: AtomicUsize::new(0),
                _type: PhantomData,
            }
        }
    }

    /// Pushes new entry of any type. Fails with `Full`, dropping the entry, when the queue already
    /// holds `max_len` entries: nothing is reading it, and it must not grow without bound.
    pub fn push(&self, entry: T) -> Result<(), Status> {
        // Take a slot first, so concurrent pushes can never overshoot the limit together.
        if self.len.fetch_add(1, Ordering::SeqCst) >= self.max_len {
            self.len.fetch_sub(1, Ordering::SeqCst);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Err(Status::Full);
        }

        let kqueue = self.kernel_queue.get();
        // Allocate entry.
        let list_entry = Box::new(Entry {
            list: LIST_ENTRY {
                Flink: core::ptr::null_mut(),
                Blink: core::ptr::null_mut(),
            },
            entry,
        });
        let raw_ptr = Box::into_raw(list_entry);

        // Check if initialized.
        let result = if self.initialized.load(Ordering::SeqCst) {
            unsafe { KeInsertQueue(kqueue, raw_ptr as *mut c_void) }
        } else {
            -1
        };
        // There is no documentation that rundown queue will return error. This is here just for good measures.
        // It is unlikely to happen and not critical.
        if result >= 0 {
            return Ok(());
        }

        _ = unsafe { Box::from_raw(raw_ptr) };
        self.len.fetch_sub(1, Ordering::SeqCst);
        return Err(Status::Uninitialized);
    }

    /// Returns an Element or a status.
    fn pop_internal(&self, timeout: *const i64) -> Result<T, Status> {
        unsafe {
            let kqueue = self.kernel_queue.get();
            // Check if initialized.
            if self.initialized.load(Ordering::SeqCst) {
                // Pop and check the return value. It is either a pointer to the entry or one of a
                // few small status codes. Compare the whole value: a kernel pointer is never that
                // small, but its low 32 bits alone can equal one of the codes.
                let list_entry =
                    KeRemoveQueue(kqueue, KprocessorMode::KernelMode, timeout) as *mut Entry<T>;
                match list_entry as usize {
                    status if status == STATUS_TIMEOUT as usize => return Err(Status::Timeout),
                    status if status == STATUS_USER_APC as usize => return Err(Status::UserAPC),
                    status if status == STATUS_ABANDONED as usize => {
                        return Err(Status::Abandoned)
                    }
                    _ => {
                        // The return value is a pointer.
                        let list_entry = Box::from_raw(list_entry);
                        self.len.fetch_sub(1, Ordering::SeqCst);
                        let entry = list_entry.entry;
                        return Ok(entry);
                    }
                }
            }
        }

        Err(Status::Uninitialized)
    }

    /// Returns element or a status. Waits until element is pushed or the queue is interrupted.
    pub fn wait_and_pop(&self) -> Result<T, Status> {
        // Wait in bounded steps rather than forever. A reader that passed the initialized check
        // just as `rundown` ran would otherwise wait on a queue nothing is ever pushed to again; it
        // now sees the queue is gone at the next check (`pop_internal` returns Uninitialized).
        loop {
            match self.pop_internal(&WAIT_RECHECK_INTERVAL) {
                Err(Status::Timeout) => continue,
                result => return result,
            }
        }
    }

    /// Returns element or a status. Does not wait.
    pub fn pop(&self) -> Result<T, Status> {
        let timeout: i64 = 0;
        self.pop_internal(&timeout)
    }

    /// Returns element or a status. Waits the specified timeout.
    pub fn pop_timeout(&self, timeout: i64) -> Result<T, Status> {
        let timeout_ptr: i64 = timeout * -10000;
        self.pop_internal(&timeout_ptr)
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

    /// Removes all elements and frees all the memory. The object can't be used after this function is called.
    pub fn rundown(&self) {
        unsafe {
            let kqueue = self.kernel_queue.get();
            if kqueue.is_null() {
                return;
            }

            // Check if initialized.
            if self.initialized.swap(false, Ordering::SeqCst) {
                // Remove and free all elements from the queue.
                Self::free_entries(KeRundownQueue(kqueue));
            }
        }
    }

    /// Frees the entries `KeRundownQueue` returned. `list_entries` is the first entry of the
    /// circular list it handed back, or null when the queue was empty.
    unsafe fn free_entries(list_entries: *mut LIST_ENTRY) {
        if list_entries.is_null() {
            return;
        }
        let mut entry = list_entries;
        while !core::ptr::eq((*entry).Flink, list_entries) {
            let next = (*entry).Flink;
            dbg!("discarding entry");
            let _ = Box::from_raw(entry as *mut Entry<T>);
            entry = next;
        }
        dbg!("discarding last entry");
        let _ = Box::from_raw(entry as *mut Entry<T>);
    }
}

impl<T> Drop for IOQueue<T> {
    fn drop(&mut self) {
        // Reinitialize queue.
        self.rundown();
        unsafe {
            let ptr = self.kernel_queue.get();
            if !ptr.is_null() {
                // A push that passed the initialized check just before `rundown` can still have
                // inserted its entry afterwards. Nothing pushes anymore by the time the queue is
                // dropped, so take whatever is left once more.
                Self::free_entries(KeRundownQueue(ptr));
                *ptr = MaybeUninit::zeroed().assume_init();
            }
        }
    }
}
