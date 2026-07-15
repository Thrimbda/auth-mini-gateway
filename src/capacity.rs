use std::sync::Arc;

use tokio::sync::OwnedSemaphorePermit;

/// One private, cloneable ownership token for one accepted downstream socket.
/// Clones share a single semaphore permit and cannot access permit operations.
#[derive(Clone)]
pub(crate) struct DownstreamLease {
    _inner: Arc<DownstreamLeaseInner>,
}

struct DownstreamLeaseInner {
    _permit: OwnedSemaphorePermit,
}

impl DownstreamLease {
    pub(crate) fn new(permit: OwnedSemaphorePermit) -> Self {
        Self {
            _inner: Arc::new(DownstreamLeaseInner { _permit: permit }),
        }
    }

    #[cfg(test)]
    pub(crate) fn strong_count(&self) -> usize {
        Arc::strong_count(&self._inner)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Semaphore;

    use super::DownstreamLease;

    fn assert_send_sync<T: Send + Sync>() {}

    #[tokio::test]
    async fn clones_share_exactly_one_owned_permit() {
        assert_send_sync::<DownstreamLease>();
        let semaphore = Arc::new(Semaphore::new(1));
        let lease = DownstreamLease::new(
            semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("open semaphore"),
        );
        let clone = lease.clone();
        assert_eq!(lease.strong_count(), 2);
        assert_eq!(semaphore.available_permits(), 0);
        drop(lease);
        assert_eq!(semaphore.available_permits(), 0);
        drop(clone);
        assert_eq!(semaphore.available_permits(), 1);
    }
}
