//! GPU backend tests. Compiled only with `--features gpu`, and each test skips
//! (passes) gracefully when no GPU adapter is available (e.g. headless CI), so
//! they never produce false failures where there's nothing to run on.
//!
//!   cargo test --features gpu
#![cfg(feature = "gpu")]

use bruteforcer::engine::candidate::CandidateSource;
use bruteforcer::gpu::{crack_v6, GpuS2k};
use bruteforcer::target::skesk_v6::SkeskV6;

const V6: &str = include_str!("fixtures/yopass_v6_gcm.asc");
const PASS: &[u8] = b"bHwcaWjaiHr96xZ3yZWQmh";

fn skesk() -> SkeskV6 {
    SkeskV6::parse(V6.as_bytes()).expect("v6 fixture parses")
}

/// Build a GPU engine, or return `None` (skip) if there's no usable adapter.
fn gpu_or_skip(s: &SkeskV6, cap: usize) -> Option<GpuS2k> {
    match GpuS2k::new(s, cap) {
        Ok(g) => Some(g),
        Err(e) => {
            eprintln!("skipping GPU test — no usable adapter: {e}");
            None
        }
    }
}

/// The GPU-derived S2K key must match the CPU reference bit-for-bit, over the
/// real full S2K count (~16 MiB), which forces the chunked/watchdog path.
#[test]
fn gpu_s2k_matches_cpu_reference() {
    let s = skesk();
    let Some(gpu) = gpu_or_skip(&s, 64) else {
        return;
    };
    let batch: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"a".to_vec(),
        b"password".to_vec(),
        b"the quick brown fox jumps".to_vec(),
        PASS.to_vec(),
    ];
    let keys = gpu.derive_batch(&batch).expect("GPU derive");
    for (i, c) in batch.iter().enumerate() {
        assert_eq!(
            s.s2k(c),
            keys[i],
            "GPU S2K mismatch for {:?}",
            String::from_utf8_lossy(c)
        );
    }

    // And the known passphrase's GPU-derived key must pass full verification.
    let slot = batch.iter().position(|c| c == PASS).unwrap();
    assert!(
        s.verify_with_s2k(&keys[slot]).is_some(),
        "known passphrase should verify via GPU-derived key"
    );
}

/// A tiny in-memory candidate source for driving `crack_v6`.
struct VecSource(std::vec::IntoIter<Vec<u8>>);
impl CandidateSource for VecSource {
    fn next_candidate(&mut self) -> Option<Vec<u8>> {
        self.0.next()
    }
}

#[test]
fn gpu_crack_finds_known_passphrase() {
    let s = skesk();
    if gpu_or_skip(&s, 8).is_none() {
        return;
    }
    let words = vec![
        b"foo".to_vec(),
        b"bar".to_vec(),
        PASS.to_vec(),
        b"baz".to_vec(),
    ];
    let found = crack_v6(&s, Box::new(VecSource(words.into_iter())), 1024, false)
        .expect("crack_v6 ok");
    assert_eq!(found.as_deref(), Some(PASS));
}

#[test]
fn gpu_crack_exhausts_without_match() {
    let s = skesk();
    if gpu_or_skip(&s, 8).is_none() {
        return;
    }
    let words = vec![b"nope-1".to_vec(), b"nope-2".to_vec(), b"nope-3".to_vec()];
    let found = crack_v6(&s, Box::new(VecSource(words.into_iter())), 1024, false)
        .expect("crack_v6 ok");
    assert!(found.is_none(), "no candidate should match");
}
