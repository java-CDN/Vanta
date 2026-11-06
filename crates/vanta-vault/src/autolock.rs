//! Auto-lock policy (F06): pure logic, driven by the shell with millisecond timestamps.

/// Something that happened on the PC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEvent {
    /// Keyboard/mouse activity inside Vanta.
    Activity { now_ms: u64 },
    /// Periodic timer tick.
    Tick { now_ms: u64 },
    /// Sleep / Modern Standby entered (PBT_APMSUSPEND or connected-standby notification).
    Suspend,
    /// Windows session locked (WTS_SESSION_LOCK).
    SessionLock,
    /// Laptop lid closed.
    LidClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Idle,
    Suspend,
    SessionLock,
    LidClose,
}

#[derive(Debug, Clone)]
pub struct AutoLock {
    idle_ms: u64,
    last_activity_ms: u64,
    pub lock_on_suspend: bool,
    pub lock_on_session_lock: bool,
    pub lock_on_lid_close: bool,
}

impl AutoLock {
    /// `idle_minutes = 0` disables the idle timer (other triggers still apply).
    pub fn new(idle_minutes: u32, now_ms: u64) -> Self {
        Self {
            idle_ms: idle_minutes as u64 * 60_000,
            last_activity_ms: now_ms,
            lock_on_suspend: true,
            lock_on_session_lock: true,
            lock_on_lid_close: true,
        }
    }

    pub fn idle_minutes(&self) -> u32 {
        (self.idle_ms / 60_000) as u32
    }

    pub fn set_idle_minutes(&mut self, m: u32) {
        self.idle_ms = m as u64 * 60_000;
    }

    /// Feed an event; returns `Some(reason)` when the vault must lock now.
    pub fn on_event(&mut self, ev: LockEvent) -> Option<LockReason> {
        match ev {
            LockEvent::Activity { now_ms } => {
                self.last_activity_ms = self.last_activity_ms.max(now_ms);
                None
            }
            LockEvent::Tick { now_ms } => {
                if self.idle_ms > 0 && now_ms.saturating_sub(self.last_activity_ms) >= self.idle_ms
                {
                    Some(LockReason::Idle)
                } else {
                    None
                }
            }
            LockEvent::Suspend => self.lock_on_suspend.then_some(LockReason::Suspend),
            LockEvent::SessionLock => self.lock_on_session_lock.then_some(LockReason::SessionLock),
            LockEvent::LidClose => self.lock_on_lid_close.then_some(LockReason::LidClose),
        }
    }

    /// Call after a successful unlock.
    pub fn reset(&mut self, now_ms: u64) {
        self.last_activity_ms = now_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_locks_after_timeout() {
        let mut a = AutoLock::new(10, 0);
        assert_eq!(a.on_event(LockEvent::Tick { now_ms: 9 * 60_000 }), None);
        assert_eq!(
            a.on_event(LockEvent::Tick {
                now_ms: 10 * 60_000
            }),
            Some(LockReason::Idle)
        );
    }

    #[test]
    fn activity_postpones() {
        let mut a = AutoLock::new(10, 0);
        a.on_event(LockEvent::Activity { now_ms: 8 * 60_000 });
        assert_eq!(
            a.on_event(LockEvent::Tick {
                now_ms: 15 * 60_000
            }),
            None
        );
        assert_eq!(
            a.on_event(LockEvent::Tick {
                now_ms: 18 * 60_000
            }),
            Some(LockReason::Idle)
        );
    }

    #[test]
    fn zero_disables_idle_only() {
        let mut a = AutoLock::new(0, 0);
        assert_eq!(
            a.on_event(LockEvent::Tick {
                now_ms: u64::MAX / 2
            }),
            None
        );
        assert_eq!(a.on_event(LockEvent::Suspend), Some(LockReason::Suspend));
    }

    #[test]
    fn system_events_lock_by_default() {
        let mut a = AutoLock::new(10, 0);
        assert_eq!(
            a.on_event(LockEvent::SessionLock),
            Some(LockReason::SessionLock)
        );
        assert_eq!(a.on_event(LockEvent::LidClose), Some(LockReason::LidClose));
        a.lock_on_lid_close = false;
        assert_eq!(a.on_event(LockEvent::LidClose), None);
    }

    #[test]
    fn out_of_order_activity_does_not_go_back_in_time() {
        let mut a = AutoLock::new(10, 0);
        a.on_event(LockEvent::Activity { now_ms: 5 * 60_000 });
        a.on_event(LockEvent::Activity { now_ms: 1 });
        assert_eq!(
            a.on_event(LockEvent::Tick {
                now_ms: 14 * 60_000
            }),
            None
        );
    }
}
