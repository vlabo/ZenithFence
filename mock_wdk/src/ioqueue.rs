use core::fmt::Display;
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

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

/// Host mock of the kernel `IOQueue`, backed by a `VecDeque` guarded by a
/// `Mutex` + `Condvar`.
///
/// It has two modes, chosen at construction, because the host harness has two
/// very different needs:
///
/// * **non-blocking** (`new`) — `wait_and_pop` returns `Timeout` immediately when
///   the queue is empty. The synchronous fuzz targets drain the event queue on
///   the same thread that drives the callouts, so a blocking read there would
///   simply hang the fuzzer. This matches the real `pop()` (zero timeout).
/// * **blocking** (`new_blocking`) — `wait_and_pop` blocks until an entry is
///   pushed or the queue is run down, mirroring the kernel `KeRemoveQueue` with a
///   NULL timeout. The full-driver simulation uses this so a user-space reader
///   thread blocks on `Device::read` exactly like the real driver, and `rundown`
///   (shutdown / unload) wakes it with `Abandoned`, which `Device::read` turns
///   into a clean end-of-file.
pub struct IOQueue<T> {
    inner: Mutex<Inner<T>>,
    cond: Condvar,
    blocking: bool,
}

struct Inner<T> {
    queue: VecDeque<T>,
    // Becomes `false` after `rundown`: the queue is permanently closed and any
    // blocked or future `wait_and_pop` returns `Abandoned`.
    live: bool,
}

unsafe impl<T> Sync for IOQueue<T> {}

// Backstop poll interval for the blocking wait. The `Condvar` notification is the
// primary wakeup; re-checking the predicate every interval is defence-in-depth so
// a missed notification can never wedge a reader forever.
const BLOCKING_POLL: Duration = Duration::from_millis(50);

impl<T> IOQueue<T> {
    /// Non-blocking queue (see type docs). The default for fuzz targets.
    pub fn new() -> Self {
        Self::with_blocking(false)
    }

    /// Blocking queue (see type docs). Used by the full-driver simulation so the
    /// user-space reader thread blocks on `Device::read` like the real driver.
    pub fn new_blocking() -> Self {
        Self::with_blocking(true)
    }

    fn with_blocking(blocking: bool) -> Self {
        Self {
            inner: Mutex::new(Inner {
                queue: VecDeque::new(),
                live: true,
            }),
            cond: Condvar::new(),
            blocking,
        }
    }

    pub fn push(&self, entry: T) -> Result<(), Status> {
        // Recover from poison: a worker panicking while holding the lock leaves
        // the `VecDeque` structurally valid, and wedging the whole queue would
        // mask the original failure.
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if !inner.live {
            return Err(Status::Uninitialized);
        }
        inner.queue.push_back(entry);
        drop(inner);
        self.cond.notify_one();
        Ok(())
    }

    /// Non-blocking pop. Returns `Timeout` when empty (mirrors the real `pop()`
    /// with a zero timeout).
    pub fn pop(&self) -> Result<T, Status> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.queue.pop_front().ok_or(Status::Timeout)
    }

    pub fn wait_and_pop(&self) -> Result<T, Status> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if !self.blocking {
            return inner.queue.pop_front().ok_or(Status::Timeout);
        }
        loop {
            if let Some(value) = inner.queue.pop_front() {
                return Ok(value);
            }
            if !inner.live {
                return Err(Status::Abandoned);
            }
            let (guard, _) = self
                .cond
                .wait_timeout(inner, BLOCKING_POLL)
                .unwrap_or_else(|p| p.into_inner());
            inner = guard;
        }
    }

    /// Blocks up to `timeout` milliseconds for an entry. Returns `Timeout` if the
    /// deadline passes with the queue still empty, or `Abandoned` after rundown.
    pub fn pop_timeout(&self, timeout: i64) -> Result<T, Status> {
        let dur = if timeout <= 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(timeout as u64)
        };
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(value) = inner.queue.pop_front() {
            return Ok(value);
        }
        if !inner.live {
            return Err(Status::Abandoned);
        }
        let (mut guard, res) = self
            .cond
            .wait_timeout(inner, dur)
            .unwrap_or_else(|p| p.into_inner());
        if let Some(value) = guard.queue.pop_front() {
            Ok(value)
        } else if !guard.live {
            Err(Status::Abandoned)
        } else {
            let _ = res;
            Err(Status::Timeout)
        }
    }

    /// Closes the queue: drops all pending entries and wakes every blocked
    /// waiter with `Abandoned`. The queue must not be used afterwards (mirrors
    /// `KeRundownQueue`).
    pub fn rundown(&self) {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            inner.live = false;
            inner.queue.clear();
        }
        self.cond.notify_all();
    }
}

impl<T> Default for IOQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn non_blocking_empty_returns_timeout() {
        let q: IOQueue<u32> = IOQueue::new();
        assert!(matches!(q.wait_and_pop(), Err(Status::Timeout)));
        assert!(matches!(q.pop(), Err(Status::Timeout)));
    }

    #[test]
    fn push_then_pop_fifo() {
        let q: IOQueue<u32> = IOQueue::new();
        q.push(1).unwrap();
        q.push(2).unwrap();
        assert!(matches!(q.wait_and_pop(), Ok(1)));
        assert!(matches!(q.pop(), Ok(2)));
        assert!(matches!(q.pop(), Err(Status::Timeout)));
    }

    // A blocking waiter must wake when another thread pushes.
    #[test]
    fn blocking_wait_wakes_on_push() {
        let q: Arc<IOQueue<u32>> = Arc::new(IOQueue::new_blocking());
        let reader = {
            let q = q.clone();
            thread::spawn(move || q.wait_and_pop())
        };
        // Give the reader time to park on the condvar, then push.
        thread::sleep(Duration::from_millis(20));
        q.push(42).unwrap();
        assert!(matches!(reader.join().unwrap(), Ok(42)));
    }

    // A blocking waiter must wake with `Abandoned` when the queue is run down,
    // which is how the simulation releases the reader thread on shutdown.
    #[test]
    fn blocking_wait_wakes_on_rundown() {
        let q: Arc<IOQueue<u32>> = Arc::new(IOQueue::new_blocking());
        let reader = {
            let q = q.clone();
            thread::spawn(move || q.wait_and_pop())
        };
        thread::sleep(Duration::from_millis(20));
        q.rundown();
        assert!(matches!(reader.join().unwrap(), Err(Status::Abandoned)));
    }

    #[test]
    fn push_after_rundown_fails() {
        let q: IOQueue<u32> = IOQueue::new_blocking();
        q.rundown();
        assert!(matches!(q.push(1), Err(Status::Uninitialized)));
        assert!(matches!(q.wait_and_pop(), Err(Status::Abandoned)));
    }
}
