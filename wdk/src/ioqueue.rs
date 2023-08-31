use winapi::{
    km::wdm::KPROCESSOR_MODE,
    shared::ntdef::{LIST_ENTRY, PVOID},
};

use crate::{allocator, interface, log};

#[derive(Debug)]
pub enum Status {
    Uninitialized,
    Timeout,
    UserAPC,
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
    fn KeInitializeQueue(queue: PVOID, count: u64);
    /*
    KeInsertQueue returns the previous signal state of the given Queue. If it was set to zero (that is, not signaled) before KeInsertQueue was called, KeInsertQueue returns zero, meaning that no entries were queued. If it was nonzero (signaled), KeInsertQueue returns the number of entries that were queued before KeInsertQueue was called.
    */
    fn KeInsertQueue(queue: PVOID, list_entry: PVOID) -> i64;
    /*
    KeRemoveQueue returns one of the following:
        A pointer to a dequeued entry from the given queue object, if one is available
        STATUS_TIMEOUT, if the given Timeout interval expired before an entry became available
        STATUS_USER_APC, if a user-mode APC was delivered in the context of the calling thread
        STATUS_ABANDONED, if the queue has been run down
    */
    fn KeRemoveQueue(queue: PVOID, mode: KPROCESSOR_MODE, timeout: *const i64) -> *mut LIST_ENTRY;
    // If the queue is empty, KeRundownQueue returns NULL; otherwise, it returns the address of the first entry in the queue.
    fn KeRundownQueue(queue: PVOID) -> *mut LIST_ENTRY;
}

pub struct Entry<T>
where
    T: Copy,
{
    _list: LIST_ENTRY, // Internal use
    entry: T,
}

pub struct IOQueue {
    pub kernel_queue: PVOID,
}

unsafe impl Sync for IOQueue {}

impl IOQueue {
    /// Returns new queue object.
    /// Make sure `rundown` is called on the end of the progrem, if `drop()` is not called for the object.
    pub fn new() -> IOQueue {
        unsafe {
            // Temporary fix until there is a rust KQueue struct.
            // TODO: Replace the manual alloc with the KQueue struct when avaliable.
            let queue = IOQueue {
                kernel_queue: allocator::manual_alloc(interface::c_get_size_of_queue_struct())
                    as PVOID,
            };
            KeInitializeQueue(queue.kernel_queue, 2);
            return queue;
        }
    }

    /// Pushes new entry of any type.
    pub fn push<T: Copy>(&self, entry: T) {
        // Check if initialized.
        if self.kernel_queue.is_null() {
            return;
        }
        unsafe {
            // Allocate entry and push to queue.
            let list_entry: *mut Entry<T> = allocator::manual_alloc_t();
            (*list_entry).entry = entry;
            KeInsertQueue(self.kernel_queue, list_entry as PVOID);
        }
    }

    /// Returns an Element or a status.
    /// If you pop an element of type that is not expected is undefined beheviour.
    pub fn pop_timeout<T: Copy>(&self, timeout: *const i64) -> Result<T, Status> {
        // Check if initialized.
        if self.kernel_queue.is_null() {
            return Err(Status::Uninitialized);
        }
        unsafe {
            // Pop and check the return value.
            let list_entry = KeRemoveQueue(self.kernel_queue, KPROCESSOR_MODE::KernelMode, timeout)
                as *mut Entry<T>;
            let error_code = list_entry as u64;
            match error_code {
                0x00000102 => return Err(Status::Timeout),
                0x000000C0 => return Err(Status::UserAPC),
                0x00000080 => return Err(Status::Abandened),
                _ => {
                    // The return value is a pointer.
                    let entry = (*list_entry).entry;
                    allocator::manual_free(list_entry as *mut u8);
                    return Ok(entry);
                }
            }
        }
    }

    /// Returns element or a status. Waits until element is pushed or the queue is interupted.
    pub fn wait_and_pop<T: Copy>(&self) -> Result<T, Status> {
        // No timout.
        return self.pop_timeout(core::ptr::null());
    }

    /// Returns element or a status. Does not wait.
    pub fn pop<T: Copy>(&self) -> Result<T, Status> {
        let timeout: i64 = 0;
        return self.pop_timeout(&timeout);
    }

    /// Removes all elements and frees all the memory. The object can't be used after this function is called.
    pub fn rundown(&mut self) {
        // Check if initialized.
        if self.kernel_queue.is_null() {
            return;
        }

        unsafe {
            // Remove and free all elements from the queue.
            let list_entries: *mut LIST_ENTRY = KeRundownQueue(self.kernel_queue);
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

            // Free queue memory.
            allocator::manual_free(self.kernel_queue);
            self.kernel_queue = core::ptr::null_mut();
        }
    }
}

impl Drop for IOQueue {
    fn drop(&mut self) {
        // Deinitialize queue.
        self.rundown();
    }
}
