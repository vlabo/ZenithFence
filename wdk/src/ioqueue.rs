use winapi::{
    km::wdm::KPROCESSOR_MODE,
    shared::ntdef::{LIST_ENTRY, PVOID},
};

use crate::{allocator, interface, log};

#[derive(Debug)]
pub enum Status {
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
    pub fn new() -> IOQueue {
        unsafe {
            let queue = IOQueue {
                kernel_queue: allocator::manual_alloc(interface::c_get_size_of_queue_struct())
                    as PVOID,
            };
            KeInitializeQueue(queue.kernel_queue, 2);
            return queue;
        }
    }

    pub fn push<T: Copy>(&self, entry: T) {
        unsafe {
            let list_entry: *mut Entry<T> = allocator::manual_alloc_t();
            (*list_entry).entry = entry;
            KeInsertQueue(self.kernel_queue, list_entry as PVOID);
        }
    }

    pub fn pop<T: Copy>(&self) -> Result<T, Status> {
        unsafe {
            // let mut timeout: i64 = 0;
            let list_entry = KeRemoveQueue(
                self.kernel_queue,
                KPROCESSOR_MODE::KernelMode,
                core::ptr::null_mut(),
            ) as *mut Entry<T>;
            let error_code = list_entry as u64;
            match error_code {
                0x00000102 => return Err(Status::Timeout),
                0x000000C0 => return Err(Status::UserAPC),
                0x00000080 => return Err(Status::Abandened),
                _ => {
                    let entry = (*list_entry).entry;
                    allocator::manual_free(list_entry as *mut u8);
                    return Ok(entry);
                }
            }
        }
    }

    pub fn rundown(&mut self) {
        unsafe {
            let list_entries: *mut LIST_ENTRY = KeRundownQueue(self.kernel_queue);
            if list_entries.is_null() {
                return;
            }
            let mut entry = list_entries;
            while !core::ptr::eq((*entry).Flink, list_entries) {
                let next = (*entry).Flink;
                log!("discarding entry");
                allocator::manual_free(entry);
                entry = next;
            }
            log!("discarding last entry");
            allocator::manual_free(entry);

            allocator::manual_free(self.kernel_queue);
            self.kernel_queue = core::ptr::null_mut();
        }
    }
}

impl Drop for IOQueue {
    fn drop(&mut self) {
        if !self.kernel_queue.is_null() {
            self.rundown();
        }
    }
}
