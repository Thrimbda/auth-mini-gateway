use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use crate::auth_mini::{IndeterminateClass, RefreshRejected, TemporaryClass};
use crate::db::ObservedVersion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectedReason {
    Remote(RefreshRejected),
    LocalInactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlightOutcome {
    Ready { generation: i64 },
    Rejected { reason: RejectedReason },
    Temporary { class: TemporaryClass },
    Indeterminate { class: IndeterminateClass },
}

#[derive(Clone, Default)]
pub struct FlightCoordinator {
    inner: Arc<CoordinatorInner>,
}

#[derive(Default)]
struct CoordinatorInner {
    registry: Mutex<HashMap<String, Arc<Flight>>>,
    next_id: AtomicU64,
}

struct Flight {
    _id: u64,
    state: Mutex<FlightState>,
    changed: Condvar,
}

struct FlightState {
    accepted_versions: HashSet<ObservedVersion>,
    outcome: Option<Arc<FlightOutcome>>,
    registered_joiners: usize,
}

pub enum Acquire {
    Leader(FlightLeader),
    Joined(FlightWaiter),
    WaitForClose(FlightWaiter),
}

pub struct FlightLeader {
    coordinator: FlightCoordinator,
    session_id: String,
    flight: Arc<Flight>,
    completed: bool,
}

pub struct FlightWaiter {
    flight: Arc<Flight>,
}

impl FlightCoordinator {
    pub fn acquire(&self, session_id: &str, observed: ObservedVersion) -> Acquire {
        let mut registry = lock_unpoison(&self.inner.registry);
        if let Some(flight) = registry.get(session_id).cloned() {
            let mut state = lock_unpoison(&flight.state);
            if state.outcome.is_some() {
                registry.remove(session_id);
            } else if state.accepted_versions.contains(&observed) {
                state.registered_joiners += 1;
                flight.changed.notify_all();
                drop(state);
                return Acquire::Joined(FlightWaiter { flight });
            } else {
                drop(state);
                return Acquire::WaitForClose(FlightWaiter { flight });
            }
        }

        let flight = Arc::new(Flight {
            _id: self.inner.next_id.fetch_add(1, Ordering::Relaxed),
            state: Mutex::new(FlightState {
                accepted_versions: HashSet::from([observed]),
                outcome: None,
                registered_joiners: 0,
            }),
            changed: Condvar::new(),
        });
        registry.insert(session_id.to_string(), Arc::clone(&flight));
        Acquire::Leader(FlightLeader {
            coordinator: self.clone(),
            session_id: session_id.to_string(),
            flight,
            completed: false,
        })
    }

    fn complete(
        &self,
        session_id: &str,
        flight: &Arc<Flight>,
        outcome: FlightOutcome,
    ) -> Arc<FlightOutcome> {
        let mut registry = lock_unpoison(&self.inner.registry);
        let mut state = lock_unpoison(&flight.state);
        if state.outcome.is_none() {
            state.outcome = Some(Arc::new(outcome));
        }
        let shared = Arc::clone(state.outcome.as_ref().expect("flight outcome published"));
        if registry
            .get(session_id)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            registry.remove(session_id);
        }
        flight.changed.notify_all();
        shared
    }

    #[cfg(test)]
    fn active_count(&self) -> usize {
        lock_unpoison(&self.inner.registry).len()
    }

    #[cfg(test)]
    pub(crate) fn wait_for_joiners(&self, session_id: &str, minimum: usize) {
        let flight = lock_unpoison(&self.inner.registry)
            .get(session_id)
            .cloned()
            .expect("active flight");
        let mut state = lock_unpoison(&flight.state);
        while state.registered_joiners < minimum && state.outcome.is_none() {
            state = wait_unpoison(&flight.changed, state);
        }
        assert!(
            state.registered_joiners >= minimum,
            "flight closed too early"
        );
    }
}

impl FlightLeader {
    pub fn add_alias(&mut self, observed: ObservedVersion) {
        let mut state = lock_unpoison(&self.flight.state);
        if state.outcome.is_none() {
            state.accepted_versions.insert(observed);
        }
    }

    pub fn complete(mut self, outcome: FlightOutcome) -> Arc<FlightOutcome> {
        let shared = self
            .coordinator
            .complete(&self.session_id, &self.flight, outcome);
        self.completed = true;
        shared
    }
}

impl Drop for FlightLeader {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.coordinator.complete(
                &self.session_id,
                &self.flight,
                FlightOutcome::Indeterminate {
                    class: IndeterminateClass::LeaderAborted,
                },
            );
        }
    }
}

impl FlightWaiter {
    pub fn wait_outcome(self) -> Arc<FlightOutcome> {
        let mut state = lock_unpoison(&self.flight.state);
        loop {
            if let Some(outcome) = state.outcome.as_ref() {
                return Arc::clone(outcome);
            }
            state = wait_unpoison(&self.flight.changed, state);
        }
    }

    pub fn wait_closed(self) {
        let _ = self.wait_outcome();
    }
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait_unpoison<'a, T>(condvar: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    condvar
        .wait(guard)
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::db::IdentityState;

    use super::*;

    fn version(generation: i64, identity_state: IdentityState) -> ObservedVersion {
        ObservedVersion {
            generation,
            identity_state,
        }
    }

    #[test]
    fn joiners_share_one_temporary_result_and_later_request_is_independent() {
        let coordinator = FlightCoordinator::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(4));
        let leader = match coordinator.acquire("session", version(0, IdentityState::Ready)) {
            Acquire::Leader(leader) => leader,
            _ => panic!("first request must lead"),
        };
        calls.fetch_add(1, Ordering::SeqCst);

        let mut handles = Vec::new();
        for _ in 0..3 {
            let coordinator = coordinator.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let waiter = match coordinator.acquire("session", version(0, IdentityState::Ready))
                {
                    Acquire::Joined(waiter) => waiter,
                    _ => panic!("same version joins"),
                };
                barrier.wait();
                waiter.wait_outcome()
            }));
        }
        barrier.wait();
        let leader_outcome = leader.complete(FlightOutcome::Temporary {
            class: TemporaryClass::Transport,
        });
        for handle in handles {
            let joiner_outcome = handle.join().expect("joiner");
            assert_eq!(
                *joiner_outcome,
                FlightOutcome::Temporary {
                    class: TemporaryClass::Transport
                }
            );
            assert!(Arc::ptr_eq(&leader_outcome, &joiner_outcome));
        }
        assert_eq!(
            *leader_outcome,
            FlightOutcome::Temporary {
                class: TemporaryClass::Transport
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(coordinator.active_count(), 0);
        assert!(matches!(
            coordinator.acquire("session", version(0, IdentityState::Ready)),
            Acquire::Leader(_)
        ));
    }

    #[test]
    fn mismatched_version_waits_and_pending_alias_joins() {
        let coordinator = FlightCoordinator::default();
        let mut leader = match coordinator.acquire("session", version(0, IdentityState::Ready)) {
            Acquire::Leader(leader) => leader,
            _ => panic!("leader"),
        };
        assert!(matches!(
            coordinator.acquire("session", version(2, IdentityState::Ready)),
            Acquire::WaitForClose(_)
        ));
        leader.add_alias(version(1, IdentityState::Pending));
        assert!(matches!(
            coordinator.acquire("session", version(1, IdentityState::Pending)),
            Acquire::Joined(_)
        ));
        leader.complete(FlightOutcome::Ready { generation: 1 });
    }

    #[test]
    fn dropped_leader_wakes_joiners_with_indeterminate() {
        let coordinator = FlightCoordinator::default();
        let leader = match coordinator.acquire("session", version(0, IdentityState::Ready)) {
            Acquire::Leader(leader) => leader,
            _ => panic!("leader"),
        };
        let waiter = match coordinator.acquire("session", version(0, IdentityState::Ready)) {
            Acquire::Joined(waiter) => waiter,
            _ => panic!("joiner"),
        };
        drop(leader);
        assert_eq!(
            *waiter.wait_outcome(),
            FlightOutcome::Indeterminate {
                class: IndeterminateClass::LeaderAborted
            }
        );
        assert_eq!(coordinator.active_count(), 0);
    }

    #[test]
    fn registered_joiner_consumes_each_shared_outcome_class() {
        let outcomes = [
            FlightOutcome::Ready { generation: 1 },
            FlightOutcome::Rejected {
                reason: RejectedReason::Remote(RefreshRejected::Invalidated),
            },
            FlightOutcome::Temporary {
                class: TemporaryClass::RateLimited,
            },
            FlightOutcome::Indeterminate {
                class: IndeterminateClass::ContractDrift,
            },
        ];
        for outcome in outcomes {
            let coordinator = FlightCoordinator::default();
            let leader = match coordinator.acquire("session", version(0, IdentityState::Ready)) {
                Acquire::Leader(leader) => leader,
                _ => panic!("leader"),
            };
            let waiter = match coordinator.acquire("session", version(0, IdentityState::Ready)) {
                Acquire::Joined(waiter) => waiter,
                _ => panic!("joiner"),
            };
            leader.complete(outcome);
            assert_eq!(*waiter.wait_outcome(), outcome);
            assert_eq!(coordinator.active_count(), 0);
        }
    }

    #[test]
    fn different_sessions_can_have_parallel_leaders() {
        let coordinator = FlightCoordinator::default();
        let first = coordinator.acquire("session-a", version(0, IdentityState::Ready));
        let second = coordinator.acquire("session-b", version(0, IdentityState::Ready));
        assert!(matches!(first, Acquire::Leader(_)));
        assert!(matches!(second, Acquire::Leader(_)));
        assert_eq!(coordinator.active_count(), 2);
    }
}
