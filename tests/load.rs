//! Load / throughput tests for the dispatch engine.
//!
//! These drive the [`run`](bruteforcer::engine::run) hot path over a large
//! candidate stream against a deliberately *cheap* target, so what they exercise
//! is the engine itself — bounded-channel backpressure, per-worker buffer
//! recycling, the batched progress counter, and stop-on-hit — under contention,
//! not any crypto.
//!
//! The keyspace size is controlled by `LOADTEST_CANDIDATES` (see [`candidates`]):
//! it defaults to a large value for a real local stress run, and CI sets it to a
//! small value so the workflow stays fast while still smoke-testing the path end
//! to end. Run just these with:
//!
//! ```sh
//! LOADTEST_CANDIDATES=50000 cargo test --release --test load
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bruteforcer::engine::{run, CandidateSource, MaskSpec, Outcome, RunConfig};
use bruteforcer::target::Target;

/// Number of candidates to push through the engine.
///
/// Reads `LOADTEST_CANDIDATES`; falls back to a large default for an unattended
/// local stress run. CI exports a small value to keep the workflow quick.
fn candidates() -> u64 {
    const DEFAULT: u64 = 5_000_000;
    std::env::var("LOADTEST_CANDIDATES")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT)
}

fn run_cfg() -> RunConfig {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    // Progress bar off: we're measuring dispatch, not rendering, and CI has no TTY.
    RunConfig {
        threads,
        progress: false,
    }
}

/// Emits `total` distinct candidates: the lower-case decimal of each index,
/// written straight into the caller's buffer so the source allocates nothing on
/// the steady-state path (matching how real sources behave).
struct CountingSource {
    next: u64,
    total: u64,
}

impl CountingSource {
    fn new(total: u64) -> Self {
        Self { next: 0, total }
    }
}

impl CandidateSource for CountingSource {
    fn next_candidate(&mut self, buf: &mut Vec<u8>) -> bool {
        if self.next >= self.total {
            return false;
        }
        render_decimal(self.next, buf);
        self.next += 1;
        true
    }

    fn total_hint(&self) -> Option<u64> {
        Some(self.total)
    }
}

/// The decimal byte representation `n` takes from [`CountingSource`]; lets a test
/// plant a winner the source is guaranteed to emit.
fn decimal(n: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    render_decimal(n, &mut buf);
    buf
}

fn render_decimal(mut n: u64, buf: &mut Vec<u8>) {
    buf.clear();
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let start = buf.len();
    while n > 0 {
        buf.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    buf[start..].reverse();
}

/// Counts every attempt and, optionally, declares one candidate the winner.
/// The work per attempt is intentionally trivial so the engine's dispatch
/// overhead — not the target — is what's under load.
struct CountingTarget {
    seen: AtomicUsize,
    win: Option<Vec<u8>>,
}

impl CountingTarget {
    fn new() -> Self {
        Self {
            seen: AtomicUsize::new(0),
            win: None,
        }
    }
    fn wins_on(mut self, candidate: Vec<u8>) -> Self {
        self.win = Some(candidate);
        self
    }
    fn seen(&self) -> usize {
        self.seen.load(Ordering::Relaxed)
    }
}

impl Target for CountingTarget {
    fn try_candidate(&self, candidate: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        self.seen.fetch_add(1, Ordering::Relaxed);
        if self.win.as_deref() == Some(candidate) {
            return Ok(Some(b"PLAINTEXT".to_vec()));
        }
        Ok(None)
    }
    fn name(&self) -> &str {
        "load-counting"
    }
}

/// Drive the full candidate stream with no winner: the engine must visit every
/// candidate exactly once and report exhaustion. Stresses producer→worker
/// backpressure and buffer recycling at volume.
#[test]
fn engine_exhausts_full_keyspace() {
    let n = candidates();
    let target = Arc::new(CountingTarget::new());
    let source: Box<dyn CandidateSource> = Box::new(CountingSource::new(n));

    let outcome = run(Arc::clone(&target) as Arc<dyn Target>, source, run_cfg()).unwrap();

    assert!(
        matches!(outcome, Outcome::Exhausted),
        "no winner ⇒ exhausted"
    );
    assert_eq!(
        target.seen() as u64,
        n,
        "every candidate tried exactly once"
    );
}

/// Plant a winner halfway through the stream and confirm the engine finds it
/// under load. Stop-on-hit means it must not test the whole keyspace.
#[test]
fn engine_finds_planted_needle_under_load() {
    let n = candidates();
    let needle = decimal(n / 2);
    let target = Arc::new(CountingTarget::new().wins_on(needle.clone()));
    let source: Box<dyn CandidateSource> = Box::new(CountingSource::new(n));

    match run(Arc::clone(&target) as Arc<dyn Target>, source, run_cfg()).unwrap() {
        Outcome::Found { candidate, secret } => {
            assert_eq!(candidate, needle, "winning candidate reported back");
            assert_eq!(secret, b"PLAINTEXT");
        }
        Outcome::Exhausted => panic!("planted needle should be found"),
    }
    assert!(
        (target.seen() as u64) <= n,
        "stop-on-hit must not exceed the keyspace"
    );
}

/// Stream `n` candidates out of an astronomically large mask keyspace
/// (10^18 entries) to prove masks stay O(1) memory — if the source materialized
/// the keyspace this would OOM long before finishing. The `Take` adapter bounds
/// the run to `LOADTEST_CANDIDATES`.
#[test]
fn mask_streams_huge_keyspace_in_o1_memory() {
    let n = candidates();
    let mask = MaskSpec::new("0123456789", 1, 18).unwrap();
    let target = Arc::new(CountingTarget::new());
    let source: Box<dyn CandidateSource> = Box::new(Take::new(mask, n));

    let outcome = run(Arc::clone(&target) as Arc<dyn Target>, source, run_cfg()).unwrap();

    assert!(
        matches!(outcome, Outcome::Exhausted),
        "no winner in this slice"
    );
    assert_eq!(
        target.seen() as u64,
        n,
        "exactly the bounded slice was tried"
    );
}

/// Wraps a [`CandidateSource`], yielding at most `limit` candidates. Keeps the
/// huge-mask test bounded by the env-configured size without materializing it.
struct Take {
    inner: Box<dyn CandidateSource>,
    remaining: u64,
}

impl Take {
    fn new(inner: impl CandidateSource + 'static, limit: u64) -> Self {
        Self {
            inner: Box::new(inner),
            remaining: limit,
        }
    }
}

impl CandidateSource for Take {
    fn next_candidate(&mut self, buf: &mut Vec<u8>) -> bool {
        if self.remaining == 0 {
            return false;
        }
        if self.inner.next_candidate(buf) {
            self.remaining -= 1;
            true
        } else {
            false
        }
    }

    fn total_hint(&self) -> Option<u64> {
        Some(self.remaining)
    }
}
