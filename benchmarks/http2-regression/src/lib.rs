//! Deterministic, production-independent foundation for the HTTP/2 regression proof.

pub mod archive;
pub mod build;
pub mod bundle;
pub mod calibration;
pub mod codec;
pub mod control;
pub mod error;
pub mod fixture;
pub mod json;
pub mod linux;
pub mod load;
pub mod orchestrator;
pub mod process_plan;
pub mod raw;
pub mod rng;
pub mod sampler;
pub mod schedule;
pub mod schema;
pub mod seal;
pub mod session;
pub mod statistics;
pub mod storage;
pub mod topology;

pub use error::{Error, Result, ResultContext};

/// Runs bounded golden checks used by the `self-test` command.
pub fn self_test() -> Result<()> {
    rng::self_test()?;
    schedule::self_test()?;
    codec::self_test()?;
    Ok(())
}
