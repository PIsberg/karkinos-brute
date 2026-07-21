//! Parallel dispatch of candidates against a [`Target`], with stop-on-hit.
//!
//! Topology: one producer thread pulls from the [`CandidateSource`] and pushes
//! into a bounded channel; N worker threads pull and test. The bounded channel
//! provides natural backpressure so the producer never races miles ahead and
//! buffers the whole keyspace in memory.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

use crate::engine::candidate::CandidateSource;
use crate::target::Target;

/// Workers accumulate progress locally and flush to the shared counter every
/// `PROGRESS_FLUSH` guesses. This keeps the atomic off the per-guess hot path
/// for cheap targets (where cross-core contention on the counter would otherwise
/// matter) while still advancing the progress bar sub-second for expensive ones
/// like yopass (~70 guesses/s/thread → a flush roughly every second).
const PROGRESS_FLUSH: u64 = 64;

pub struct RunConfig {
    /// Worker thread count. Defaults to available parallelism.
    pub threads: usize,
    /// Show a progress bar / counter on stderr.
    pub progress: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus::get().max(1),
            progress: true,
        }
    }
}

/// Result of a completed run.
pub enum Outcome {
    /// A candidate matched. Carries the winning guess and the recovered secret.
    Found { candidate: Vec<u8>, secret: Vec<u8> },
    /// The keyspace was exhausted with no match.
    Exhausted,
}

/// Drive `source` against `target` in parallel until a hit or exhaustion.
pub fn run(
    target: Arc<dyn Target>,
    mut source: Box<dyn CandidateSource>,
    cfg: RunConfig,
) -> Result<Outcome> {
    let threads = cfg.threads.max(1);
    let total = source.total_hint();

    // Bounded so the producer can't outrun the workers and balloon memory.
    let cap = threads * 256;
    let (tx, rx) = crossbeam_channel::bounded::<Vec<u8>>(cap);
    // Spent candidate buffers flow back here so the producer can refill and
    // resend them instead of allocating a fresh `Vec` per guess. At steady state
    // ~`cap` buffers cycle forever and the hot path performs no heap allocation.
    let (free_tx, free_rx) = crossbeam_channel::bounded::<Vec<u8>>(cap);

    let stop = Arc::new(AtomicBool::new(false));
    let tried = Arc::new(AtomicU64::new(0));
    // Holds the first hit found. Mutex is contended only once (on success).
    let hit: Arc<Mutex<Option<(Vec<u8>, Vec<u8>)>>> = Arc::new(Mutex::new(None));
    // The first fatal worker error, if any.
    let worker_err: Arc<Mutex<Option<anyhow::Error>>> = Arc::new(Mutex::new(None));

    let progress = make_progress(cfg.progress, total);

    let mut workers = Vec::with_capacity(threads);
    for _ in 0..threads {
        let rx = rx.clone();
        let free_tx = free_tx.clone();
        let target = Arc::clone(&target);
        let stop = Arc::clone(&stop);
        let tried = Arc::clone(&tried);
        let hit = Arc::clone(&hit);
        let worker_err = Arc::clone(&worker_err);
        workers.push(thread::spawn(move || {
            // Accumulate progress locally; flush to the shared atomic in batches
            // to keep it off the per-guess hot path (see `PROGRESS_FLUSH`).
            let mut local_tried = 0u64;
            while let Ok(mut candidate) = rx.recv() {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match target.try_candidate(&candidate) {
                    Ok(Some(secret)) => {
                        let mut guard = hit.lock().unwrap();
                        if guard.is_none() {
                            *guard = Some((candidate, secret));
                        }
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    Ok(None) => {
                        local_tried += 1;
                        if local_tried >= PROGRESS_FLUSH {
                            tried.fetch_add(local_tried, Ordering::Relaxed);
                            local_tried = 0;
                        }
                        // Return the buffer for reuse; if the pool is full just
                        // drop it (bounded memory, and this never blocks).
                        candidate.clear();
                        let _ = free_tx.try_send(candidate);
                    }
                    Err(e) => {
                        let mut guard = worker_err.lock().unwrap();
                        if guard.is_none() {
                            *guard = Some(e);
                        }
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
            // Flush whatever this worker counted but hasn't pushed yet.
            if local_tried > 0 {
                tried.fetch_add(local_tried, Ordering::Relaxed);
            }
        }));
    }
    // Only the workers recycle buffers; drop the original sender so `free_rx`
    // tracks the live recyclers.
    drop(free_tx);

    // Producer (this thread): feed candidates until the source is empty or a
    // worker signals stop. Reuse a recycled buffer when one is available,
    // otherwise allocate (only happens while the pipeline first fills). Dropping
    // `tx` afterwards unblocks the workers' recv.
    while !stop.load(Ordering::Relaxed) {
        let mut buf = free_rx
            .try_recv()
            .unwrap_or_else(|_| Vec::with_capacity(64));
        if !source.next_candidate(&mut buf) {
            break; // exhausted
        }
        if tx.send(buf).is_err() {
            break; // all workers gone
        }
    }
    drop(tx);

    // Periodically refresh the progress bar while workers drain the channel.
    if let Some(pb) = &progress {
        while workers.iter().any(|w| !w.is_finished()) {
            pb.set_position(tried.load(Ordering::Relaxed));
            thread::sleep(Duration::from_millis(100));
        }
    }
    for w in workers {
        let _ = w.join();
    }
    if let Some(pb) = &progress {
        pb.set_position(tried.load(Ordering::Relaxed));
        pb.finish_and_clear();
    }

    if let Some(e) = worker_err.lock().unwrap().take() {
        return Err(e);
    }
    if let Some((candidate, secret)) = hit.lock().unwrap().take() {
        return Ok(Outcome::Found { candidate, secret });
    }
    Ok(Outcome::Exhausted)
}

fn make_progress(enabled: bool, total: Option<u64>) -> Option<ProgressBar> {
    if !enabled {
        return None;
    }
    let pb = match total {
        Some(t) => {
            let pb = ProgressBar::new(t);
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner} {pos}/{len} ({percent}%) {per_sec} ETA {eta}",
                )
                .unwrap(),
            );
            pb
        }
        None => {
            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::with_template("{spinner} {pos} tried {per_sec}").unwrap());
            pb
        }
    };
    pb.enable_steady_tick(Duration::from_millis(120));
    Some(pb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::candidate::CandidateSource;
    use std::sync::atomic::AtomicUsize;

    /// In-memory candidate source over a fixed list.
    struct VecSource(std::vec::IntoIter<Vec<u8>>);
    impl CandidateSource for VecSource {
        fn next_candidate(&mut self, buf: &mut Vec<u8>) -> bool {
            match self.0.next() {
                Some(c) => {
                    buf.clear();
                    buf.extend_from_slice(&c);
                    true
                }
                None => false,
            }
        }
    }
    fn source(words: &[&[u8]]) -> Box<dyn CandidateSource> {
        let owned: Vec<Vec<u8>> = words.iter().map(|w| w.to_vec()).collect();
        Box::new(VecSource(owned.into_iter()))
    }

    /// Counts attempts; optionally matches one candidate and/or errors on one.
    struct MockTarget {
        win: Option<Vec<u8>>,
        err_on: Option<Vec<u8>>,
        seen: AtomicUsize,
    }
    impl MockTarget {
        fn new() -> Self {
            Self {
                win: None,
                err_on: None,
                seen: AtomicUsize::new(0),
            }
        }
        fn wins_on(mut self, c: &[u8]) -> Self {
            self.win = Some(c.to_vec());
            self
        }
        fn errors_on(mut self, c: &[u8]) -> Self {
            self.err_on = Some(c.to_vec());
            self
        }
        fn seen(&self) -> usize {
            self.seen.load(Ordering::Relaxed)
        }
    }
    impl Target for MockTarget {
        fn try_candidate(&self, candidate: &[u8]) -> Result<Option<Vec<u8>>> {
            self.seen.fetch_add(1, Ordering::Relaxed);
            if self.err_on.as_deref() == Some(candidate) {
                anyhow::bail!("simulated fatal target error");
            }
            if self.win.as_deref() == Some(candidate) {
                return Ok(Some(b"PLAINTEXT".to_vec()));
            }
            Ok(None)
        }
        fn name(&self) -> &str {
            "mock"
        }
    }

    fn cfg(threads: usize) -> RunConfig {
        RunConfig {
            threads,
            progress: false,
        }
    }

    #[test]
    fn finds_the_matching_candidate() {
        let target = Arc::new(MockTarget::new().wins_on(b"win"));
        let src = source(&[b"a", b"b", b"win", b"c"]);
        match run(Arc::clone(&target) as Arc<dyn Target>, src, cfg(1)).unwrap() {
            Outcome::Found { candidate, secret } => {
                assert_eq!(candidate, b"win");
                assert_eq!(secret, b"PLAINTEXT");
            }
            Outcome::Exhausted => panic!("expected a match"),
        }
    }

    #[test]
    fn exhausts_when_nothing_matches() {
        let target = Arc::new(MockTarget::new());
        let src = source(&[b"a", b"b", b"c"]);
        let outcome = run(Arc::clone(&target) as Arc<dyn Target>, src, cfg(1)).unwrap();
        assert!(matches!(outcome, Outcome::Exhausted));
        assert_eq!(target.seen(), 3, "every candidate should be tried");
    }

    #[test]
    fn stops_immediately_on_first_hit() {
        // Winner first + a single worker: exactly one attempt runs before
        // stop-on-hit halts the run, no matter how many candidates trail it.
        let target = Arc::new(MockTarget::new().wins_on(b"win"));
        let mut words: Vec<&[u8]> = vec![b"win"];
        words.extend(std::iter::repeat_n(b"x" as &[u8], 1000));
        let src = source(&words);
        let outcome = run(Arc::clone(&target) as Arc<dyn Target>, src, cfg(1)).unwrap();
        assert!(matches!(outcome, Outcome::Found { .. }));
        assert_eq!(
            target.seen(),
            1,
            "should stop after the first (winning) attempt"
        );
    }

    #[test]
    fn worker_error_is_fatal() {
        let target = Arc::new(MockTarget::new().errors_on(b"boom"));
        let src = source(&[b"a", b"boom", b"c"]);
        let result = run(Arc::clone(&target) as Arc<dyn Target>, src, cfg(1));
        assert!(result.is_err(), "a target error must abort the whole run");
    }

    #[test]
    fn finds_match_across_many_threads() {
        // Exercises the concurrent path + buffer recycling under contention.
        let target = Arc::new(MockTarget::new().wins_on(b"needle"));
        let mut words: Vec<Vec<u8>> = (0..5000).map(|i| format!("h{i}").into_bytes()).collect();
        words.insert(2500, b"needle".to_vec());
        let src: Box<dyn CandidateSource> = Box::new(VecSource(words.into_iter()));
        match run(Arc::clone(&target) as Arc<dyn Target>, src, cfg(4)).unwrap() {
            Outcome::Found { candidate, .. } => assert_eq!(candidate, b"needle"),
            Outcome::Exhausted => panic!("needle should be found"),
        }
    }
}
