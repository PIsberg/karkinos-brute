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
    let (tx, rx) = crossbeam_channel::bounded::<Vec<u8>>(threads * 256);

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
        let target = Arc::clone(&target);
        let stop = Arc::clone(&stop);
        let tried = Arc::clone(&tried);
        let hit = Arc::clone(&hit);
        let worker_err = Arc::clone(&worker_err);
        workers.push(thread::spawn(move || {
            while let Ok(candidate) = rx.recv() {
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
                        tried.fetch_add(1, Ordering::Relaxed);
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
        }));
    }

    // Producer (this thread): feed candidates until the source is empty or a
    // worker signals stop. Dropping `tx` afterwards unblocks the workers' recv.
    while !stop.load(Ordering::Relaxed) {
        match source.next_candidate() {
            Some(c) => {
                if tx.send(c).is_err() {
                    break; // all workers gone
                }
            }
            None => break,
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
            pb.set_style(
                ProgressStyle::with_template("{spinner} {pos} tried {per_sec}").unwrap(),
            );
            pb
        }
    };
    pb.enable_steady_tick(Duration::from_millis(120));
    Some(pb)
}
