//! Attack targets.
//!
//! A target is anything a candidate guess can be tested against. Implement
//! [`Target`] and the generic engine will drive it.

pub mod skesk_v6;
pub mod yopass;

/// Something a candidate can be tested against.
///
/// Implementations MUST be cheap to share across threads (`Send + Sync`) because
/// the runner clones an `Arc<dyn Target>` into every worker. A single attempt
/// should be self-contained and side-effect free where possible — for offline
/// cracking this means "derive key from passphrase, try to decrypt, report".
pub trait Target: Send + Sync {
    /// Test one candidate.
    ///
    /// * `Ok(Some(plaintext))` — the candidate is correct; `plaintext` is the
    ///   recovered secret (the runner stops the whole run).
    /// * `Ok(None)` — a valid attempt that simply did not match.
    /// * `Err(_)` — the attempt could not be evaluated (malformed input, I/O,
    ///   etc.). The runner treats this as fatal: a target that errors on every
    ///   candidate is misconfigured, and silently swallowing it would burn the
    ///   whole keyspace for nothing.
    fn try_candidate(&self, candidate: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;

    /// Human-readable name for progress/reporting.
    fn name(&self) -> &str;
}
