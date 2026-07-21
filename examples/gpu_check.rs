//! GPU correctness self-check: GPU-derived S2K keys must match the CPU
//! reference bit-for-bit, and the known passphrase must verify on the GPU path.
//! Usage: cargo run --features gpu --example gpu_check -- <file.asc> <known-pass>

use bruteforcer::gpu::GpuS2k;
use bruteforcer::target::skesk_v6::SkeskV6;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let bytes = std::fs::read(&args[1])?;
    let known = args.get(2).map(|s| s.as_bytes().to_vec());

    let skesk = SkeskV6::parse(&bytes)?;

    // Count sweep: find where the GPU watchdog kills the kernel.
    for shift in [6u32, 16, 20, 22, 23, 24] {
        let mut s = skesk.clone();
        s.count = 1u32 << shift;
        let g = GpuS2k::new(&s, 16)?;
        let probe = vec![b"abc".to_vec(), b"hello world".to_vec()];
        let cpu: Vec<_> = probe.iter().map(|c| s.s2k(c)).collect();
        let gk = g.derive_batch(&probe)?;
        let ok = cpu == gk;
        println!(
            "count=2^{shift} ({} blocks): {}",
            (s.count + 72) / 64,
            if ok { "MATCH" } else { "FAIL (likely TDR)" }
        );
    }

    let gpu = GpuS2k::new(&skesk, 4096)?;
    println!("GPU adapter: {}", gpu.adapter_name());

    // A batch of decoys plus (optionally) the known passphrase at a known slot.
    let mut batch: Vec<Vec<u8>> = vec![
        b"password".to_vec(),
        b"123456".to_vec(),
        b"".to_vec(),
        b"a".to_vec(),
        b"the quick brown fox".to_vec(),
        b"hunter2".to_vec(),
    ];
    let known_slot = known.as_ref().map(|k| {
        batch.push(k.clone());
        batch.len() - 1
    });

    let gpu_keys = gpu.derive_batch(&batch)?;

    let mut mismatches = 0;
    for (i, c) in batch.iter().enumerate() {
        let cpu = skesk.s2k(c);
        if cpu != gpu_keys[i] {
            mismatches += 1;
            println!("  MISMATCH at {i} ({:?})", String::from_utf8_lossy(c));
        }
    }
    println!(
        "checked {} candidates against CPU reference: {}",
        batch.len(),
        if mismatches == 0 {
            "ALL MATCH"
        } else {
            "FAILED"
        }
    );

    if let Some(slot) = known_slot {
        let verified = skesk.verify_with_s2k(&gpu_keys[slot]).is_some();
        println!(
            "known passphrase via GPU-derived key: {}",
            if verified {
                "VERIFIED"
            } else {
                "rejected (BUG)"
            }
        );
    }

    anyhow::ensure!(mismatches == 0, "GPU/CPU mismatch");
    Ok(())
}
