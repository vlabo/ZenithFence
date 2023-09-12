use core::{cell::UnsafeCell, marker::PhantomData};

use ntstatus::ntstatus::NtStatus;
// use anyhow::Result;
use winapi::{
    km::wdm::KPROCESSOR_MODE,
    shared::ntdef::{LIST_ENTRY, PVOID},
};

use crate::{allocator, log};

#[derive(Debug, onlyerror::Error)]
pub enum Status {
    #[error("unitialized")]
    Uninitialized,
    #[error("timeout")]
    Timeout,
    #[error("user apc")]
    UserAPC,
    #[error("abandened")]
    Abandened,
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
    fn KeInitializeQueue(queue: *mut KQueue, count: u64);
    /*
    KeInsertQueue returns the previous signal state of the given Queue. If it was set to zero (that is, not signaled) before KeInsertQueue was called, KeInsertQueue returns zero, meaning that no entries were queued. If it was nonzero (signaled), KeInsertQueue returns the number of entries that were queued before KeInsertQueue was called.
    */
    fn KeInsertQueue(queue: *mut KQueue, list_entry: PVOID) -> i64;
    /*
    KeRemoveQueue returns one of the following:
        A pointer to a dequeued entry from the given queue object, if one is available
        STATUS_TIMEOUT, if the given Timeout interval expired before an entry became available
        STATUS_USER_APC, if a user-mode APC was delivered in the context of the calling thread
        STATUS_ABANDONED, if the queue has been run down
    */
    fn KeRemoveQueue(
        queue: *mut KQueue,
        mode: KPROCESSOR_MODE,
        timeout: *const i64,
    ) -> *mut LIST_ENTRY;

    // If the queue is empty, KeRundownQueue returns NULL; otherwise, it returns the address of the first entry in the queue.
    fn KeRundownQueue(queue: *mut KQueue) -> *mut LIST_ENTRY;
}

// TODO: replace with original struct when it becomes avaliable.
#[repr(C)]
struct KQueue {
    data: [u8; 64],    // Size of C KQueue struct.
    initialized: bool, // not used by C.
}

#[repr(C)]
struct Entry<T>
where
    T: Copy,
{
    list: LIST_ENTRY, // Internal use
    entry: T,
}

pub struct IOQueue<T: Copy> {
    kernel_queue: UnsafeCell<KQueue>,
    _type: PhantomData<T>, // 0 size variable. Requierd for the generic to work properly. Compiler limitation.
}

unsafe impl<T: Copy> Sync for IOQueue<T> {}

impl<T: Copy> IOQueue<T> {
    pub const fn default() -> Self {
        Self {
            kernel_queue: UnsafeCell::new(KQueue {
                data: [0; 64],
                initialized: false,
            }),
            _type: PhantomData,
        }
    }

    /// Returns new queue object.
    /// Make sure `rundown` is called on the end of the progrem, if `drop()` is not called for the object.
    pub fn init(&self) {
        unsafe {
            let kqueue = self.kernel_queue.get();
            KeInitializeQueue(kqueue, 1);
            (*kqueue).initialized = true;
        }
    }

    /// Pushes new entry of any type.
    pub fn push(&self, entry: T) -> Result<(), Status> {
        unsafe {
            let kqueue = self.kernel_queue.get();
            // Check if initialized.
            if (*kqueue).initialized {
                // Allocate entry and push to queue.
                let list_entry: *mut Entry<T> = allocator::manual_alloc_t();
                (*list_entry).entry = entry;
                KeInsertQueue(kqueue, list_entry as PVOID);

                return Ok(());
            }
        }

        return Err(Status::Uninitialized);
    }

    /// Returns an Element or a status.
    fn pop_internal(&self, timeout: *const i64) -> Result<T, Status> {
        unsafe {
            let kqueue = self.kernel_queue.get();
            // Check if initialized.
            if (*kqueue).initialized {
                // Pop and check the return value.
                let list_entry =
                    KeRemoveQueue(kqueue, KPROCESSOR_MODE::KernelMode, timeout) as *mut Entry<T>;
                let error_code = NtStatus::from_u32(list_entry as u32);
                match error_code {
                    Some(NtStatus::STATUS_TIMEOUT) => return Err(Status::Timeout),
                    Some(NtStatus::STATUS_USER_APC) => return Err(Status::UserAPC),
                    Some(NtStatus::STATUS_ABANDONED) => return Err(Status::Abandened),
                    _ => {
                        // The return value is a pointer.
                        let entry = (*list_entry).entry;
                        allocator::manual_free(list_entry as *mut u8);
                        return Ok(entry);
                    }
                }
            }
        }

        return Err(Status::Uninitialized);
    }

    /// Returns element or a status. Waits until element is pushed or the queue is interupted.
    pub fn wait_and_pop(&self) -> Result<T, Status> {
        // No timout.
        return self.pop_internal(core::ptr::null());
    }

    /// Returns element or a status. Does not wait.
    pub fn pop(&self) -> Result<T, Status> {
        let timeout: i64 = 0;
        return self.pop_internal(&timeout);
    }

    /// Returns element or a status. Does not wait.
    pub fn pop_timeout(&self, timeout: i64) -> Result<T, Status> {
        let timeout_ptr: i64 = timeout * -10000;
        return self.pop_internal(&timeout_ptr);
    }

    /// Removes all elements and frees all the memory. The object can't be used after this function is called.
    pub fn rundown(&self) {
        unsafe {
            let kqueue = self.kernel_queue.get();
            // Check if initialized.
            if (*kqueue).initialized {
                // Remove and free all elements from the queue.
                let list_entries: *mut LIST_ENTRY = KeRundownQueue(kqueue);
                if !list_entries.is_null() {
                    let mut entry = list_entries;
                    while !core::ptr::eq((*entry).Flink, list_entries) {
                        let next = (*entry).Flink;
                        log!("discarding entry");
                        allocator::manual_free(entry);
                        entry = next;
                    }
                    log!("discarding last entry");
                    allocator::manual_free(entry);
                }
            }
        }
    }

    pub fn deinit(&self) {
        self.rundown();
        unsafe {
            let ptr = self.kernel_queue.get();
            *ptr = KQueue {
                data: [0; 64],
                initialized: false,
            };
        }
    }
}

impl<T: Copy> Drop for IOQueue<T> {
    fn drop(&mut self) {
        // Deinitialize queue.
        self.rundown();
        self.deinit();
    }
}
