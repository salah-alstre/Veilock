//! Auto-lock timing: inactivity and "window in the background" timeouts.
//!
//! The decision logic lives in [`Tracker`], which is pure (time is passed in), so every policy
//! edge case is unit-tested without sleeping. [`spawn`] runs it on a one-second tick and calls a
//! callback when a lock is due; the callback performs the actual lock (credential store, file
//! vaults, UI event).
//!
//! Activity is reported by the frontend (`touch`), because only the UI knows about real user
//! input. A compromised or buggy UI can only *delay* a lock by sending touches; it can never
//! bypass one that Rust has already performed, and Panic Lock does not depend on this module.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How often the monitor evaluates the policy. One second is fine-grained enough for a
/// "lock after N seconds" feature and costs nothing measurable.
const TICK: Duration = Duration::from_secs(1);

/// The subset of settings the monitor cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// `None` = never; `Some(0)` = as soon as the window loses focus; `Some(n)` = n seconds
    /// without user activity.
    pub inactivity_secs: Option<u32>,
    /// Lock after the window has been in the background for this many minutes. `None` = off.
    pub background_minutes: Option<u32>,
}

#[derive(Debug)]
struct State {
    policy: Policy,
    last_activity: Instant,
    background_since: Option<Instant>,
    /// Set once a lock has been requested, so one idle period produces exactly one lock call.
    /// Cleared by any new activity or by the window regaining focus.
    fired: bool,
}

/// Pure auto-lock decision state.
#[derive(Debug)]
pub struct Tracker {
    state: Mutex<State>,
}

impl Tracker {
    pub fn new(policy: Policy, now: Instant) -> Self {
        Self {
            state: Mutex::new(State {
                policy,
                last_activity: now,
                background_since: None,
                fired: false,
            }),
        }
    }

    // A poisoned mutex only means another thread panicked while holding it; the state is plain
    // data with no invariants spanning fields, so continuing is safe and keeps locking alive.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_policy(&self, policy: Policy, now: Instant) {
        let mut s = self.lock();
        s.policy = policy;
        // A changed policy starts a fresh idle period; otherwise lowering the timeout could
        // lock immediately from stale activity, which would feel like a bug to the user.
        s.last_activity = now;
        s.fired = false;
    }

    /// User activity (or a successful unlock).
    pub fn touch(&self, now: Instant) {
        let mut s = self.lock();
        s.last_activity = now;
        s.fired = false;
    }

    /// The window lost focus or was minimised.
    pub fn blurred(&self, now: Instant) {
        let mut s = self.lock();
        if s.background_since.is_none() {
            s.background_since = Some(now);
        }
    }

    /// The window regained focus.
    pub fn focused(&self, now: Instant) {
        let mut s = self.lock();
        s.background_since = None;
        s.last_activity = now;
        s.fired = false;
    }

    /// Returns `true` exactly once per idle period when a lock is due.
    pub fn poll(&self, now: Instant) -> bool {
        let mut s = self.lock();
        if s.fired {
            return false;
        }
        let due = Self::is_due(&s, now);
        if due {
            s.fired = true;
        }
        due
    }

    fn is_due(s: &State, now: Instant) -> bool {
        if let Some(since) = s.background_since {
            if s.policy.inactivity_secs == Some(0) {
                return true;
            }
            if let Some(min) = s.policy.background_minutes {
                if now.saturating_duration_since(since) >= Duration::from_secs(u64::from(min) * 60)
                {
                    return true;
                }
            }
        }
        match s.policy.inactivity_secs {
            Some(secs) if secs > 0 => {
                now.saturating_duration_since(s.last_activity)
                    >= Duration::from_secs(u64::from(secs))
            }
            _ => false,
        }
    }
}

/// A running monitor thread. Dropping it stops the thread.
pub struct Monitor {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

/// Starts the tick thread. `on_lock` is called (on that thread) whenever [`Tracker::poll`]
/// reports a due lock.
pub fn spawn<F>(tracker: Arc<Tracker>, on_lock: F) -> Monitor
where
    F: Fn() + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("veilock-lock-monitor".into())
        .spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                std::thread::sleep(TICK);
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                if tracker.poll(Instant::now()) {
                    on_lock();
                }
            }
        })
        .ok();
    Monitor { stop, handle }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // The thread wakes within one tick; not joining keeps shutdown instant.
        self.handle.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn policy(inactivity: Option<u32>, background: Option<u32>) -> Policy {
        Policy {
            inactivity_secs: inactivity,
            background_minutes: background,
        }
    }

    #[test]
    fn inactivity_locks_after_timeout_once() {
        let t0 = Instant::now();
        let t = Tracker::new(policy(Some(60), None), t0);
        assert!(!t.poll(t0 + secs(59)));
        assert!(t.poll(t0 + secs(60)));
        assert!(!t.poll(t0 + secs(61)), "one lock per idle period");
    }

    #[test]
    fn activity_postpones_the_lock_and_rearms_it() {
        let t0 = Instant::now();
        let t = Tracker::new(policy(Some(60), None), t0);
        t.touch(t0 + secs(50));
        assert!(!t.poll(t0 + secs(100)));
        assert!(t.poll(t0 + secs(110)));
        t.touch(t0 + secs(120));
        assert!(!t.poll(t0 + secs(121)));
        assert!(t.poll(t0 + secs(180)));
    }

    #[test]
    fn never_means_never() {
        let t0 = Instant::now();
        let t = Tracker::new(policy(None, None), t0);
        t.blurred(t0);
        assert!(!t.poll(t0 + secs(86_400 * 30)));
    }

    #[test]
    fn zero_locks_as_soon_as_the_window_is_blurred() {
        let t0 = Instant::now();
        let t = Tracker::new(policy(Some(0), None), t0);
        assert!(!t.poll(t0 + secs(3600)), "focused window never locks at 0");
        t.blurred(t0 + secs(3600));
        assert!(t.poll(t0 + secs(3600)));
    }

    #[test]
    fn background_timeout_counts_from_blur_and_resets_on_focus() {
        let t0 = Instant::now();
        let t = Tracker::new(policy(None, Some(5)), t0);
        t.blurred(t0);
        assert!(!t.poll(t0 + secs(299)));
        assert!(t.poll(t0 + secs(300)));

        let t = Tracker::new(policy(None, Some(5)), t0);
        t.blurred(t0);
        t.focused(t0 + secs(200));
        assert!(!t.poll(t0 + secs(400)));
        t.blurred(t0 + secs(400));
        assert!(!t.poll(t0 + secs(600)));
        assert!(t.poll(t0 + secs(700)));
    }

    #[test]
    fn a_second_blur_does_not_extend_the_background_period() {
        let t0 = Instant::now();
        let t = Tracker::new(policy(None, Some(1)), t0);
        t.blurred(t0);
        t.blurred(t0 + secs(50));
        assert!(t.poll(t0 + secs(60)));
    }

    #[test]
    fn changing_policy_starts_a_fresh_idle_period() {
        let t0 = Instant::now();
        let t = Tracker::new(policy(Some(600), None), t0);
        t.set_policy(policy(Some(60), None), t0 + secs(500));
        assert!(!t.poll(t0 + secs(520)));
        assert!(t.poll(t0 + secs(560)));
    }

    #[test]
    fn clock_going_backwards_never_panics_or_locks() {
        let t0 = Instant::now() + secs(100);
        let t = Tracker::new(policy(Some(60), Some(1)), t0);
        t.blurred(t0);
        assert!(!t.poll(t0 - secs(50)));
    }

    #[test]
    fn spawned_monitor_stops_on_drop() {
        let t = Arc::new(Tracker::new(policy(None, None), Instant::now()));
        let m = spawn(Arc::clone(&t), || {});
        drop(m);
    }
}
