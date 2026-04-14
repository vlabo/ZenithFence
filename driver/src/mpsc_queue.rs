/// Lock-free MPSC (Multiple Producer, Single Consumer) FIFO queue.
///
/// Uses the Vyukov swap-based algorithm:
/// - **Push** (any number of concurrent producer threads): one atomic `swap`
///   on `tail` to claim a slot, then one `store` to stitch the chain. No CAS
///   loops, no retries.
/// - **Peek / Pop** (single consumer thread only): load `head.next`; if
///   non-null, the element is ready to read or remove.
///
/// # Sentinel node
/// A dummy sentinel node is allocated at construction and always lives at
/// `head`. Its `data` is null and it is never handed to the caller. Its sole
/// job is to be a stable target for a producer's `prev.next.store` — this
/// eliminates the use-after-free that would otherwise occur when a producer
/// captures `prev` pointing to the last real node while the consumer is
/// simultaneously freeing that same node.
///
/// # Transient emptiness during push
/// Between a producer's `tail.swap` and the following `prev.next.store` there
/// is a brief window where `peek`/`pop` may return null even though a push is
/// in flight. The consumer should treat null as "nothing available right now"
/// and retry — this matches the typical kernel DPC / worker-thread pattern.
///
/// # Ownership of `T`
/// The queue stores raw `*mut T` pointers and never dereferences or frees
/// `*T`. Lifetime of the pointed-to data is entirely the caller's
/// responsibility.
///
/// # Thread-safety contract
/// - `push` — safe to call from any number of concurrent threads.
/// - `peek`, `pop`, `is_empty` — must only be called from a **single**
///   consumer thread. They are not safe to call concurrently with each other
///   or with themselves.
use alloc::boxed::Box;
use core::{
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

// ── Node ─────────────────────────────────────────────────────────────────────

struct Node<T> {
    /// Raw pointer to the caller-owned element.
    /// Null on the sentinel node; non-null (though possibly a null payload) on
    /// every real node.
    data: *mut T,
    /// Link to the next node closer to the front of the queue.
    /// Written exactly once by the producer that owns the previous tail slot,
    /// then never modified again.
    next: AtomicPtr<Node<T>>,
}

// ── MpscQueue ────────────────────────────────────────────────────────────────

/// Lock-free MPSC FIFO queue storing raw `*mut T` pointers.
// IMPORTANT: Caller must empty the Queue before drop. If not done there will be memory leak.
pub struct MpscQueue<T> {
    /// Always points to the sentinel node. Only the consumer advances this
    /// pointer (via `store`). Producers never read or write `head`.
    head: AtomicPtr<Node<T>>,
    /// Always points to the last node in the chain (sentinel when empty).
    /// Producers advance this with a single atomic `swap`; the consumer never
    /// touches it.
    tail: AtomicPtr<Node<T>>,
}

unsafe impl<T: Send> Send for MpscQueue<T> {}
unsafe impl<T: Send> Sync for MpscQueue<T> {}

impl<T> MpscQueue<T> {
    /// Creates an empty queue.
    ///
    /// Allocates the sentinel node. Both `head` and `tail` start pointing to
    /// it; `tail` moves forward on every push while `head` moves forward on
    /// every pop.
    pub fn new() -> Self {
        let sentinel = Box::into_raw(Box::new(Node::<T> {
            data: ptr::null_mut(),
            next: AtomicPtr::new(ptr::null_mut()),
        }));
        Self {
            head: AtomicPtr::new(sentinel),
            tail: AtomicPtr::new(sentinel),
        }
    }

    /// Appends `ptr` to the back of the queue.
    ///
    /// Uses a single atomic `swap` — no CAS loop, no retries.
    ///
    /// `prev` returned by the swap is always a valid node (at minimum the
    /// sentinel) so the `prev.is_null()` branch that would be needed in a
    /// sentinel-free design does not exist here.
    ///
    /// Safe to call from any number of concurrent threads.
    pub fn push(&self, ptr: *mut T) {
        // Create a node.
        let node = Box::into_raw(Box::new(Node {
            data: ptr,
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        // Atomically claim our slot. `prev` is exclusively ours from this point.
        let prev = self.tail.swap(node, Ordering::SeqCst);

        // Stitch the chain: link prev → node.
        // `prev` is always a valid heap node — at minimum the sentinel —
        // and its `next` field is exclusively ours to write at this point.
        unsafe { (*prev).next.store(node, Ordering::SeqCst) };
    }

    /// Returns the `*mut T` at the front of the queue without removing it.
    ///
    /// Returns `null` if the queue is empty or if a push is mid-flight (see
    /// module-level note on transient emptiness).
    pub fn peek(&self) -> Option<&T> {
        // `head` is the sentinel; the first real element is `head.next`.
        let head = self.head.load(Ordering::SeqCst);
        // head is always a valid sentinel node.
        let next = unsafe { (*head).next.load(Ordering::SeqCst) };

        if next.is_null() {
            // queue is empty
            return None;
        }

        // return the data
        unsafe { (*next).data.as_ref() }
    }

    /// Removes and returns the `*mut T` at the front of the queue.
    /// Returns `null` if the queue is empty or transiently appears so.
    pub fn pop(&self) -> *mut T {
        // Load (not swap) the current sentinel — `head` must remain stable
        // while we inspect it so that producers writing to `prev.next` never
        // race against a freed node.
        let head = self.head.load(Ordering::SeqCst);
        // head is always a valid sentinel node.
        let next = unsafe { (*head).next.load(Ordering::SeqCst) };

        if next.is_null() {
            return ptr::null_mut();
        }

        // Read the payload before promoting `next` to sentinel (after which
        // its `data` field is logically the sentinel's null).
        let ptr = unsafe { (*next).data };

        let new_sentinel = next;
        unsafe {
            // Clear the data for the sentinel.
            (*new_sentinel).data = ptr::null_mut();
        }

        // Advance head: `next` becomes the new sentinel.
        // Store (not swap) — only the consumer ever writes `head`.
        // Release pairs with any future Acquire load of `head` by the consumer.
        self.head.store(new_sentinel, Ordering::SeqCst);

        // Reclaim the old sentinel. Its data was null.
        unsafe { drop(Box::from_raw(head)) };

        ptr
    }

    /// Returns `true` if no elements are currently visible to the consumer.
    /// May return `true` spuriously during a push (see module-level note).
    pub fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::SeqCst);
        // head is always a valid sentinel node.
        unsafe { (*head).next.load(Ordering::SeqCst).is_null() }
    }

    /// Returns the approximate number of elements visible to the consumer.
    /// May under-count by items that are mid-push (see module-level note on
    /// transient emptiness). Must only be called from the single consumer thread.
    pub fn count(&self) -> usize {
        let mut n = 0usize;
        let head = self.head.load(Ordering::SeqCst);
        // head is the sentinel; walk from head.next.
        let mut cur = unsafe { (*head).next.load(Ordering::SeqCst) };
        while !cur.is_null() {
            n += 1;
            cur = unsafe { (*cur).next.load(Ordering::SeqCst) };
        }
        n
    }
}

impl<T> Drop for MpscQueue<T> {
    fn drop(&mut self) {
        // The queue does not own the `*mut T` payloads stored in nodes, so it
        // cannot free them. The caller is responsible for popping all entries
        // before dropping the queue. Any remaining nodes (and their payloads)
        // will be leaked if the queue is dropped while non-empty.
        //
        // Only the sentinel node is guaranteed to be present and is freed here.
        let sentinel = *self.head.get_mut();
        // `head` always points to the sentinel, which was allocated via
        // `Box::into_raw` in `new` (or promoted from a data node in `pop`).
        unsafe { drop(Box::from_raw(sentinel)) };
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::MpscQueue;
    use core::ptr;

    #[test]
    fn empty_queue_returns_null() {
        let q: MpscQueue<u32> = MpscQueue::new();
        assert!(q.is_empty());
        assert!(q.peek().is_none());
        assert!(q.pop().is_null());
    }

    #[test]
    fn single_push_peek_pop() {
        let mut val: u32 = 42;
        let q: MpscQueue<u32> = MpscQueue::new();
        q.push(&mut val);
        assert!(!q.is_empty());
        assert_eq!(q.peek(), Some(&val));
        assert_eq!(q.pop(), &mut val as *mut u32);
        assert!(q.is_empty());
    }

    #[test]
    fn fifo_order() {
        let (mut a, mut b, mut c) = (1u32, 2u32, 3u32);
        let q: MpscQueue<u32> = MpscQueue::new();
        q.push(&mut a);
        q.push(&mut b);
        q.push(&mut c);
        assert_eq!(q.pop(), &mut a as *mut u32);
        assert_eq!(q.pop(), &mut b as *mut u32);
        assert_eq!(q.pop(), &mut c as *mut u32);
        assert!(q.pop().is_null());
    }

    #[test]
    fn peek_does_not_remove() {
        let mut val: u32 = 99;
        let q: MpscQueue<u32> = MpscQueue::new();
        q.push(&mut val);
        assert_eq!(q.peek(), Some(&val));
        assert_eq!(q.peek(), Some(&val));
        assert_eq!(q.pop(), &mut val as *mut u32);
        assert!(q.peek().is_none());
    }

    #[test]
    fn drop_empty_queue_after_draining() {
        // Correct usage: caller pops everything before dropping.
        let (mut a, mut b) = (1u32, 2u32);
        let q: MpscQueue<u32> = MpscQueue::new();
        q.push(&mut a);
        q.push(&mut b);
        assert!(!q.pop().is_null());
        assert!(!q.pop().is_null());
        assert!(q.is_empty());
        drop(q); // only the sentinel remains — freed cleanly
    }

    #[test]
    fn interleaved_push_pop() {
        let (mut a, mut b, mut c) = (10u32, 20u32, 30u32);
        let q: MpscQueue<u32> = MpscQueue::new();
        q.push(&mut a);
        assert_eq!(q.pop(), &mut a as *mut u32);
        q.push(&mut b);
        q.push(&mut c);
        assert_eq!(q.peek(), Some(&b));
        assert_eq!(q.pop(), &mut b as *mut u32);
        assert_eq!(q.pop(), &mut c as *mut u32);
        assert!(q.is_empty());
    }

    #[test]
    fn null_pointer_can_be_pushed() {
        let q: MpscQueue<u32> = MpscQueue::new();
        q.push(ptr::null_mut());
        // The queue is not empty — a node exists — but the stored payload is null.
        // Callers that push null must use `is_empty()` to distinguish this from
        // a genuinely empty queue; the return value of `pop` alone is ambiguous.
        assert!(!q.is_empty());
        assert!(q.pop().is_null());
        assert!(q.is_empty());
    }
}
