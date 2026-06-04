//! The target-agnostic bruteforce engine: candidate generation + parallel dispatch.

pub mod candidate;
pub mod runner;

pub use candidate::{CandidateSource, MaskSpec, WordlistSource};
pub use runner::{run, Outcome, RunConfig};
