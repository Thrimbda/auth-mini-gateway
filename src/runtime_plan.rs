use crate::config::{Config, MAX_BLOCKING_RESOLVERS};

pub const AUTH_BLOCKING_WORKERS: usize = 64;
pub const AUTH_BLOCKING_ADMISSION: usize = 128;
pub const BLOCKING_RUNTIME_MARGIN: usize = 16;
pub const UPSTREAM_IDLE_POOL_CAPACITY: usize = 8;
const LISTENER_FD_BUDGET: usize = 1;
const ANCILLARY_FD_RESERVE: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimePlan {
    pub auth_workers: usize,
    pub resolver_limit: usize,
    pub blocking_margin: usize,
    pub max_blocking_threads: usize,
}

impl RuntimePlan {
    pub fn from_config(config: &Config) -> Result<Self, RuntimePlanError> {
        Self::new(config.max_blocking_resolvers)
    }

    pub fn new(resolver_limit: usize) -> Result<Self, RuntimePlanError> {
        if !(1..=MAX_BLOCKING_RESOLVERS).contains(&resolver_limit) {
            return Err(RuntimePlanError);
        }
        let max_blocking_threads = AUTH_BLOCKING_WORKERS
            .checked_add(resolver_limit)
            .and_then(|value| value.checked_add(BLOCKING_RUNTIME_MARGIN))
            .ok_or(RuntimePlanError)?;
        Ok(Self {
            auth_workers: AUTH_BLOCKING_WORKERS,
            resolver_limit,
            blocking_margin: BLOCKING_RUNTIME_MARGIN,
            max_blocking_threads,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimePlanError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NofileLimit {
    Infinite,
    Finite(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NofileError {
    BudgetOverflow,
    Unavailable,
    TooLow { required: u64, effective: u64 },
}

pub fn required_nofile(config: &Config) -> Result<u64, NofileError> {
    required_nofile_for(
        config.upstream.is_some(),
        config.max_downstream_connections,
        config.max_active_upstreams,
    )
}

pub fn required_nofile_for(
    proxy_mode: bool,
    max_downstream_connections: usize,
    max_active_upstreams: usize,
) -> Result<u64, NofileError> {
    let required = if proxy_mode {
        max_downstream_connections
            .checked_add(max_active_upstreams)
            .and_then(|value| value.checked_add(UPSTREAM_IDLE_POOL_CAPACITY))
            .and_then(|value| value.checked_add(LISTENER_FD_BUDGET))
            .and_then(|value| value.checked_add(ANCILLARY_FD_RESERVE))
    } else {
        max_downstream_connections
            .checked_add(LISTENER_FD_BUDGET)
            .and_then(|value| value.checked_add(ANCILLARY_FD_RESERVE))
    }
    .ok_or(NofileError::BudgetOverflow)?;
    u64::try_from(required).map_err(|_| NofileError::BudgetOverflow)
}

pub fn validate_nofile(required: u64, effective: NofileLimit) -> Result<(), NofileError> {
    match effective {
        NofileLimit::Infinite => Ok(()),
        NofileLimit::Finite(value) if value >= required => Ok(()),
        NofileLimit::Finite(value) => Err(NofileError::TooLow {
            required,
            effective: value,
        }),
    }
}

#[cfg(unix)]
pub fn effective_soft_nofile() -> Result<NofileLimit, NofileError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` points to writable storage of the exact libc type and
    // `RLIMIT_NOFILE` requires no additional preconditions.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(NofileError::Unavailable);
    }
    if limit.rlim_cur == libc::RLIM_INFINITY {
        return Ok(NofileLimit::Infinite);
    }
    Ok(NofileLimit::Finite(limit.rlim_cur))
}

#[cfg(not(unix))]
pub fn effective_soft_nofile() -> Result<NofileLimit, NofileError> {
    Err(NofileError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_plan_is_exact_and_independent_of_mode_or_upstreams() {
        assert_eq!(
            RuntimePlan::new(8).expect("default").max_blocking_threads,
            88
        );
        assert_eq!(
            RuntimePlan::new(32).expect("maximum").max_blocking_threads,
            112
        );
        assert_eq!(
            RuntimePlan::new(1).expect("minimum").max_blocking_threads,
            81
        );
        assert_eq!(RuntimePlan::new(0), Err(RuntimePlanError));
        assert_eq!(RuntimePlan::new(33), Err(RuntimePlanError));
    }

    #[test]
    fn nofile_boundaries_accept_equality_greater_and_infinity() {
        assert_eq!(
            validate_nofile(905, NofileLimit::Finite(904)),
            Err(NofileError::TooLow {
                required: 905,
                effective: 904
            })
        );
        assert!(validate_nofile(905, NofileLimit::Finite(905)).is_ok());
        assert!(validate_nofile(905, NofileLimit::Finite(4096)).is_ok());
        assert!(validate_nofile(905, NofileLimit::Infinite).is_ok());
    }

    #[test]
    fn nofile_formulas_are_exact_and_checked() {
        assert_eq!(required_nofile_for(true, 256, 128), Ok(905));
        assert_eq!(required_nofile_for(false, 256, 128), Ok(769));
        assert_eq!(
            required_nofile_for(true, usize::MAX, 1),
            Err(NofileError::BudgetOverflow)
        );
        assert_eq!(
            required_nofile_for(false, usize::MAX, 1),
            Err(NofileError::BudgetOverflow)
        );
    }
}
