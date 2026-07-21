//! Opt-in GPU backend (`--features gpu`): runs the expensive S2K on the GPU via
//! a wgpu/WGSL compute shader. HKDF + AEAD verification stay on the CPU.
//!
//! The GPU computes, for a batch of candidate passphrases, the 32-byte S2K key
//! (`SHA256` over `count` octets of `salt||pass`). The host then verifies each
//! key with [`SkeskV6::verify_with_s2k`]. Correctness is checked bit-for-bit
//! against the CPU reference (see tests / `--gpu` self-check).

use anyhow::{Context, Result};
use bytemuck::{Pod, Zeroable};
use wgpu::util::DeviceExt;

use crate::target::skesk_v6::SkeskV6;

const MAX_WORDS: usize = 16; // 64-byte max passphrase, matches the shader
const MAX_PW_LEN: usize = MAX_WORDS * 4;
const WG: u32 = 64;

/// SHA-256 round constants (uploaded to the GPU once).
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Per-dispatch work budget in (blocks × candidates). Chunk size is derived as
/// `WORK_BUDGET / capacity` so each dispatch takes roughly the same wall time
/// (~1s) regardless of batch size, staying safely under the GPU watchdog while
/// minimizing the number of blocking syncs.
const WORK_BUDGET: u64 = 400_000_000;

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Params {
    salt0: u32,
    salt1: u32,
    count: u32,
    num_blocks: u32,
    bitlen_hi: u32,
    bitlen_lo: u32,
    n_candidates: u32,
    start_block: u32,
    end_block: u32,
    is_final: u32,
    _p0: u32,
    _p1: u32,
}

/// A configured GPU S2K engine bound to one SKESK's parameters.
pub struct GpuS2k {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bgl: wgpu::BindGroupLayout,
    capacity: usize,
    params: Params,
    params_buf: wgpu::Buffer,
    pw_buf: wgpu::Buffer,
    len_buf: wgpu::Buffer,
    out_buf: wgpu::Buffer,
    k_buf: wgpu::Buffer,
    state_buf: wgpu::Buffer,
    staging: wgpu::Buffer,
    adapter_name: String,
}

impl GpuS2k {
    /// The GPU device/adapter description (for logging).
    pub fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    /// Build the engine for a given SKESK and max batch size.
    pub fn new(skesk: &SkeskV6, capacity: usize) -> Result<Self> {
        let instance = wgpu::Instance::default();
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
            ..Default::default()
        }))
        .context("no GPU adapter found")?;
        let adapter_name = format!(
            "{:?} ({:?})",
            adapter.get_info().name,
            adapter.get_info().backend
        );

        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("s2k-device"),
            required_features: wgpu::Features::empty(),
            required_limits: adapter.limits(),
            ..Default::default()
        }))
        .context("failed to create GPU device")?;

        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("s2k"),
            source: wgpu::ShaderSource::Wgsl(include_str!("s2k.wgsl").into()),
        });

        let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("s2k-bgl"),
            entries: &[
                uniform_entry(0),
                storage_entry(1, true),
                storage_entry(2, true),
                storage_entry(3, false),
                storage_entry(4, true),
                storage_entry(5, false),
            ],
        });
        let pl = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("s2k-pl"),
            bind_group_layouts: &[Some(&bgl)],
            immediate_size: 0,
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("s2k-pipeline"),
            layout: Some(&pl),
            module: &module,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });

        // Precompute SHA-256 padding geometry for this SKESK's count.
        let count = skesk.count;
        let num_blocks = (count + 72) / 64; // ceil((count + 1 + 8)/64)
        let bitlen = (count as u64) * 8;
        let params = Params {
            salt0: be_word(&skesk.salt[0..4]),
            salt1: be_word(&skesk.salt[4..8]),
            count,
            num_blocks,
            bitlen_hi: (bitlen >> 32) as u32,
            bitlen_lo: bitlen as u32,
            n_candidates: 0,
            start_block: 0,
            end_block: 0,
            is_final: 0,
            _p0: 0,
            _p1: 0,
        };

        let params_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("params"),
            contents: bytemuck::bytes_of(&params),
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        });
        let pw_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("pw"),
            size: (capacity * MAX_WORDS * 4) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let len_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("pwlen"),
            size: (capacity * 4) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let out_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("out"),
            size: (capacity * 32) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let k_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("sha256-k"),
            contents: bytemuck::cast_slice(&SHA256_K),
            usage: wgpu::BufferUsages::STORAGE,
        });
        let state_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("state"),
            size: (capacity * 10 * 4) as u64, // h0..7, m, off
            usage: wgpu::BufferUsages::STORAGE,
            mapped_at_creation: false,
        });
        let staging = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("staging"),
            size: (capacity * 32) as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        Ok(Self {
            device,
            queue,
            pipeline,
            bgl,
            capacity,
            params,
            params_buf,
            pw_buf,
            len_buf,
            out_buf,
            k_buf,
            state_buf,
            staging,
            adapter_name,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Derive the 32-byte S2K key for each candidate in the batch.
    ///
    /// Candidates longer than 64 bytes are not representable on the GPU and are
    /// returned as all-zero keys (they will simply fail verification; the caller
    /// can route them to the CPU path).
    pub fn derive_batch(&self, candidates: &[Vec<u8>]) -> Result<Vec<[u8; 32]>> {
        let n = candidates.len();
        anyhow::ensure!(n <= self.capacity, "batch exceeds GPU capacity");

        // Pack passphrases (big-endian words) and lengths.
        let mut pw = vec![0u32; self.capacity * MAX_WORDS];
        let mut lens = vec![0u32; self.capacity];
        for (ci, c) in candidates.iter().enumerate() {
            let len = c.len().min(MAX_PW_LEN);
            lens[ci] = len as u32;
            let base = ci * MAX_WORDS;
            for (j, &byte) in c.iter().enumerate().take(len) {
                let wi = base + (j >> 2);
                pw[wi] |= (byte as u32) << ((3 - (j & 3)) * 8);
            }
        }

        self.queue
            .write_buffer(&self.pw_buf, 0, bytemuck::cast_slice(&pw));
        self.queue
            .write_buffer(&self.len_buf, 0, bytemuck::cast_slice(&lens));

        let bg = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("s2k-bg"),
            layout: &self.bgl,
            entries: &[
                bind(0, &self.params_buf),
                bind(1, &self.pw_buf),
                bind(2, &self.len_buf),
                bind(3, &self.out_buf),
                bind(4, &self.k_buf),
                bind(5, &self.state_buf),
            ],
        });

        // Split the S2K into watchdog-safe chunks, persisting SHA state in
        // `state_buf` between dispatches. Each chunk is its own submission so no
        // single GPU command runs long enough to trip the driver timeout.
        let num_blocks = self.params.num_blocks;
        // Absolute cap keeps a single dispatch short even for tiny batches.
        const MAX_CHUNK: u64 = 32768;
        let chunk_blocks = (WORK_BUDGET / (self.capacity as u64).max(1))
            .min(MAX_CHUNK)
            .min(num_blocks as u64)
            .max(1) as u32;
        let groups = (n as u32).div_ceil(WG);
        let mut start = 0u32;
        while start < num_blocks {
            let end = (start + chunk_blocks).min(num_blocks);
            let mut params = self.params;
            params.n_candidates = n as u32;
            params.start_block = start;
            params.end_block = end;
            params.is_final = (end == num_blocks) as u32;
            self.queue
                .write_buffer(&self.params_buf, 0, bytemuck::bytes_of(&params));

            let mut enc = self
                .device
                .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                    label: Some("s2k-enc"),
                });
            {
                let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor {
                    label: Some("s2k-pass"),
                    timestamp_writes: None,
                });
                pass.set_pipeline(&self.pipeline);
                pass.set_bind_group(0, &bg, &[]);
                pass.dispatch_workgroups(groups, 1, 1);
            }
            // Submit each chunk as its own short dispatch and wait for it: this
            // keeps the GPU responsive to the OS watchdog (continuous GPU
            // activity > ~2s trips TDR even when individual dispatches are
            // short) and lets the persisted state flow chunk-to-chunk.
            self.queue.submit(Some(enc.finish()));
            self.device
                .poll(wgpu::PollType::wait_indefinitely())
                .map_err(|e| anyhow::anyhow!("GPU poll failed: {e:?}"))?;
            start = end;
        }

        let copy_bytes = (n * 32) as u64;
        let mut enc = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("s2k-copy"),
            });
        enc.copy_buffer_to_buffer(&self.out_buf, 0, &self.staging, 0, copy_bytes);
        self.queue.submit(Some(enc.finish()));

        // Read back.
        let slice = self.staging.slice(0..copy_bytes);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| {
            let _ = tx.send(r);
        });
        self.device
            .poll(wgpu::PollType::wait_indefinitely())
            .map_err(|e| anyhow::anyhow!("GPU poll failed: {e:?}"))?;
        rx.recv()
            .context("GPU map channel closed")?
            .context("GPU buffer map failed")?;

        let data = slice
            .get_mapped_range()
            .map_err(|e| anyhow::anyhow!("GPU buffer range map failed: {e:?}"))?;
        let mut out = Vec::with_capacity(n);
        for ci in 0..n {
            let mut key = [0u8; 32];
            for wi in 0..8 {
                let off = ci * 32 + wi * 4;
                let word =
                    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                key[wi * 4..wi * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            out.push(key);
        }
        drop(data);
        self.staging.unmap();
        Ok(out)
    }
}

/// GPU-backed crack of a v6 SKESK: derive S2K keys on the GPU in batches and
/// verify each on the CPU. Returns the winning passphrase, or `None` if the
/// candidate source is exhausted.
pub fn crack_v6(
    skesk: &SkeskV6,
    mut source: Box<dyn crate::engine::candidate::CandidateSource>,
    batch: usize,
    progress: bool,
) -> Result<Option<Vec<u8>>> {
    use std::time::Instant;

    let gpu = GpuS2k::new(skesk, batch)?;
    eprintln!("GPU: {} (batch {})", gpu.adapter_name(), batch);

    let pb = if progress {
        let pb = indicatif::ProgressBar::new_spinner();
        pb.set_style(
            indicatif::ProgressStyle::with_template("{spinner} {pos} tried {per_sec}").unwrap(),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        Some(pb)
    } else {
        None
    };

    let _start = Instant::now();
    // Reuse the inner buffers across batches: `next_candidate` overwrites each in
    // place, so after the first batch this loop performs no per-guess allocation.
    let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(batch);
    loop {
        // Fill a batch from the candidate source, growing the pool only until it
        // reaches `batch` buffers, then refilling those same allocations.
        let mut filled = 0usize;
        while filled < batch {
            if filled == bufs.len() {
                bufs.push(Vec::with_capacity(64));
            }
            if source.next_candidate(&mut bufs[filled]) {
                filled += 1;
            } else {
                break;
            }
        }
        if filled == 0 {
            break; // exhausted
        }
        let active = &bufs[..filled];

        // GPU handles passphrases up to 64 bytes; longer ones go to the CPU.
        let keys = gpu.derive_batch(active)?;
        for (i, cand) in active.iter().enumerate() {
            let hit = if cand.len() > 64 {
                skesk.verify(cand).is_some()
            } else {
                skesk.verify_with_s2k(&keys[i]).is_some()
            };
            if hit {
                if let Some(pb) = &pb {
                    pb.finish_and_clear();
                }
                return Ok(Some(cand.clone()));
            }
        }
        if let Some(pb) = &pb {
            pb.inc(filled as u64);
        }
        if filled < batch {
            break; // source exhausted mid-batch
        }
    }
    if let Some(pb) = &pb {
        pb.finish_and_clear();
    }
    Ok(None)
}

fn be_word(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn uniform_entry(binding: u32) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Uniform,
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}

fn storage_entry(binding: u32, read_only: bool) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Storage { read_only },
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}

fn bind(binding: u32, buf: &wgpu::Buffer) -> wgpu::BindGroupEntry<'_> {
    wgpu::BindGroupEntry {
        binding,
        resource: buf.as_entire_binding(),
    }
}
