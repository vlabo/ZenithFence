//! The queue of connections waiting for a filter reset.
//!
//! A connection that is classified with `FWP_CONDITION_FLAG_IS_REAUTHORIZE` has no completion
//! handle, so it cannot be pended. It is deferred by capturing the packet and blocking it, and it
//! stays held by the filter that blocked it until all resettable filters are re-registered
//! (`FilterEngine::reset_all_filters`), which makes WFP reauthorize it against the fresh filters.
//!
//! That reset opens a WFP write transaction and only one transaction can be open on the filter
//! engine session at a time, so the resets cannot all run when they are asked for. This queue holds
//! them until they can. It only stores and hands back entries; when the reset is attempted, how long
//! to wait and what to do with a batch that could not be released are decisions of `Device` (see
//! `reset_filters_and_inject`).
//!
//! One thread at a time works the queue. That thread is said to hold the *drain claim*, taken with
//! [`FilterResetQueue::push_and_claim`] and given back by
//! [`FilterResetQueue::take_all_or_release`]. Both the entries and the claim are guarded by the same
//! lock, which keeps two guarantees:
//!  - Two threads can never both hold the claim, so whatever the holder does with an entry is done
//!    by one thread at a time.
//!  - A non-empty queue always has a holder. The queue only becomes non-empty through
//!    `push_and_claim`, which never returns without leaving a holder behind, and the claim is only
//!    given back while the queue is empty. So nothing is ever left queued with nobody to come back
//!    for it.

use alloc::collections::VecDeque;
use core::mem;
use wdk::filter_engine::packet::TransportPacketList;
use wdk::rw_spin_lock::Mutex;

/// One entry of the queue: a connection held by a filter, and the packet captured with it. `None`
/// carries no packet, only the need for the reset itself (an outbound connect has no packet data
/// yet, and the ClearCache command has no connection of its own).
pub type PendingReset = Option<TransportPacketList>;

struct State {
    /// Entries waiting for a reset, oldest first.
    entries: VecDeque<PendingReset>,
    /// Set while a thread holds the drain claim.
    claimed: bool,
}

pub struct FilterResetQueue {
    state: Mutex<State>,
}

impl FilterResetQueue {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                entries: VecDeque::new(),
                claimed: false,
            }),
        }
    }

    /// Pushes an entry and takes the drain claim for the calling thread. Returns false when another
    /// thread already holds it.
    ///
    /// The entry is queued either way, so it is never lost when the claim is refused.
    pub fn push_and_claim(&self, entry: PendingReset) -> bool {
        let mut state = self.state.write_lock();
        state.entries.push_back(entry);
        if state.claimed {
            return false;
        }
        state.claimed = true;

        return true;
    }

    /// Takes every entry queued so far, or gives the drain claim back when there is none left. Only
    /// the thread holding the claim may call this.
    ///
    /// `None` means the queue was empty and the claim has been given back, so the caller no longer
    /// holds it.
    pub fn take_all_or_release(&self) -> Option<VecDeque<PendingReset>> {
        let mut state = self.state.write_lock();
        if state.entries.is_empty() {
            state.claimed = false;
            return None;
        }

        let mut entries = VecDeque::new();
        mem::swap(&mut state.entries, &mut entries);

        return Some(entries);
    }

    /// Pushes entries back in front of everything queued in the meantime, keeping the order they
    /// were taken in. The caller keeps the drain claim.
    pub fn push_front_all(&self, mut entries: VecDeque<PendingReset>) {
        let mut state = self.state.write_lock();
        while let Some(entry) = entries.pop_back() {
            state.entries.push_front(entry);
        }
    }

    pub fn get_entries_count(&self) -> usize {
        let state = self.state.read_lock();
        return state.entries.len();
    }
}
