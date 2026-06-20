use core::fmt::Display;
use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Debug)]
pub enum Status {
    Uninitialized,
    Timeout,
    UserAPC,
    Abandoned,
}

impl Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Status::Uninitialized => write!(f, "Uninitialized"),
            Status::Timeout => write!(f, "Timeout"),
            Status::UserAPC => write!(f, "UserAPC"),
            Status::Abandoned => write!(f, "Abandoned"),
        }
    }
}

/// Host mock of the kernel `IOQueue`. Backed by an in-memory `VecDeque`.
/// `wait_and_pop` does NOT block when empty (that would hang a fuzzer); it
/// returns `Err(Status::Abandoned)`, which drives `device.read` to a clean
/// end-of-file just like a rundown queue would.
pub struct IOQueue<T> {
    queue: Mutex<VecDeque<T>>,
}

unsafe impl<T> Sync for IOQueue<T> {}

impl<T> IOQueue<T> {
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
        }
    }

    pub fn push(&self, entry: T) -> Result<(), Status> {
        if let Ok(mut q) = self.queue.lock() {
            q.push_back(entry);
            Ok(())
        } else {
            Err(Status::Uninitialized)
        }
    }

    pub fn pop(&self) -> Result<T, Status> {
        match self.queue.lock() {
            Ok(mut q) => q.pop_front().ok_or(Status::Timeout),
            Err(_) => Err(Status::Uninitialized),
        }
    }

    pub fn wait_and_pop(&self) -> Result<T, Status> {
        match self.queue.lock() {
            Ok(mut q) => q.pop_front().ok_or(Status::Abandoned),
            Err(_) => Err(Status::Uninitialized),
        }
    }

    pub fn pop_timeout(&self, _timeout: i64) -> Result<T, Status> {
        self.pop()
    }

    pub fn rundown(&self) {
        if let Ok(mut q) = self.queue.lock() {
            q.clear();
        }
    }
}
