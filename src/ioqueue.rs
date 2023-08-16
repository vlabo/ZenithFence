use core::{mem, ptr};

use alloc::boxed::Box;
use windows_sys::{
    Wdk::{
        Foundation::{DISPATCHER_HEADER, DISPATCHER_HEADER_0, DISPATCHER_HEADER_0_0, KQUEUE},
        Storage::FileSystem::{KeInitializeQueue, KeInsertQueue, KeRemoveQueue, KeRundownQueue},
    },
    Win32::System::Kernel::LIST_ENTRY,
};

use crate::wdk;

enum Mode {
    KernelMode,
    UserMode,
    MaximumMode,
}

enum Status {
    Timeout,
    UserAPC,
    Abandened,
}

struct Entry<T>
where
    T: Copy,
{
    list: LIST_ENTRY,
    entry: T,
}

struct IOQueue {
    kernel_queue: KQUEUE,
}

impl IOQueue {
    pub fn new() -> Box<IOQueue> {
        let mut queue = Box::new(IOQueue {
            kernel_queue: KQUEUE {
                Header: DISPATCHER_HEADER {
                    Anonymous: DISPATCHER_HEADER_0 {
                        Anonymous1: DISPATCHER_HEADER_0_0 { Lock: 0 },
                    },
                    SignalState: 0,
                    WaitListHead: windows_sys::Win32::System::Kernel::LIST_ENTRY {
                        Flink: ptr::null_mut(),
                        Blink: ptr::null_mut(),
                    },
                },
                EntryListHead: windows_sys::Win32::System::Kernel::LIST_ENTRY {
                    Flink: ptr::null_mut(),
                    Blink: ptr::null_mut(),
                },
                CurrentCount: 0,
                MaximumCount: 0,
                ThreadListHead: windows_sys::Win32::System::Kernel::LIST_ENTRY {
                    Flink: ptr::null_mut(),
                    Blink: ptr::null_mut(),
                },
            },
        });

        unsafe {
            let raw = Box::into_raw(queue);
            KeInitializeQueue(raw as *mut KQUEUE, 1);
            queue = Box::from_raw(raw);
        }

        return queue;
    }

    fn push<T: Copy>(&mut self, entry: T) {
        unsafe {
            let list_entry: *mut Entry<T> = wdk::malloc(mem::size_of::<Entry<T>>());
            (*list_entry).entry = entry;
            KeInsertQueue(&mut self.kernel_queue, list_entry as *mut LIST_ENTRY);
        }
    }

    pub fn pop<T: Copy>(&mut self) -> Result<T, Status> {
        unsafe {
            let mut timeout: i64 = 10000;
            let list_entry =
                KeRemoveQueue(&mut self.kernel_queue, Mode::KernelMode as i8, &mut timeout)
                    as *mut Entry<T>;
            let error_code = list_entry as u64;
            match error_code {
                0x00000102 => return Err(Status::Timeout),
                0x000000C0 => return Err(Status::UserAPC),
                0x00000080 => return Err(Status::Abandened),
                _ => {
                    let entry = (*list_entry).entry;
                    wdk::free(list_entry);
                    return Ok(entry);
                }
            }
        }
    }

    pub fn rundown(&mut self) {
        unsafe {
            let list_entries = KeRundownQueue(&mut self.kernel_queue);
            while !core::ptr::eq((*list_entries).Flink, list_entries) {
                let timeout: i64 = 10;
                let entry = KeRemoveQueue(&mut self.kernel_queue, Mode::KernelMode as i8, &timeout);
                wdk::free(entry);
            }
        }
    }
}
