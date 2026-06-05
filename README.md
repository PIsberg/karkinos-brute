# karkinos-brute

[![CI](https://github.com/PIsberg/karkinos-brute/actions/workflows/ci.yml/badge.svg)](https://github.com/PIsberg/karkinos-brute/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg)](#)

A small, pluggable bruteforce **framework** in Rust. The engine (candidate
generation + parallel dispatch) is target-agnostic; each attack is a module that
implements one trait. The first bundled module targets
[**yopass**](https://github.com/jhaals/yopass).

> ⚠️ **Authorized use only.** This tool is for security testing you are
> authorized to perform (your own data, your own deployment, a sanctioned
> engagement, or a CTF). Using it against secrets you do not own or are not
> authorized to access is illegal.

## How yopass works (and what's actually attackable)

yopass encrypts secrets **client-side** with OpenPGP **symmetric** encryption
(via OpenPGP.js). The server only stores the armored ciphertext, keyed by a
random id, served at `GET /secret/<id>`.

Current yopass uses the **RFC 9580 "crypto-refresh"** format: a **v6 SKESK**
(passphrase → key via salted+iterated S2K) wrapping a **SEIPD v2 AEAD** body
(observed: **AES-256 + GCM**). This needs **sequoia-openpgp 2.x** with a backend
that implements the AEAD modes — this project uses the pure-Rust backend
(`crypto-rust`). sequoia 1.x and the Windows CNG backend do **not** parse v6
SKESK and will reject real yopass blobs.

> **Public instance note:** `share.yopass.se` (and `yopass.se`) is a static
> frontend; the real API lives at `https://api.yopass.se`. The tool auto-detects
> this; for any other split deployment use `--api-base <url>`.

A secret therefore has two parts:

| Part | Where it lives | Brute-forceable? |
|------|----------------|------------------|
| **UUID** | the URL | No — 122 random bits |
| **auto-generated key** (`#/s/<uuid>/<key>`) | URL fragment only | No — ~130 bits of entropy |
| **custom password** (`#/c/<uuid>`) | chosen by a human, shared out-of-band | **Yes, if weak** — cracked offline |

So the only realistic attack is **offline recovery of a weak custom password**
against a ciphertext you've downloaded. That's what the `yopass` module does.

> ⚠️ **One-time secrets.** yopass secrets are one-time-view by default: fetching
> the ciphertext **consumes (deletes)** it server-side. Fetch once, save the
> blob, then crack the *saved* blob. Never re-fetch in a loop.

## Build

```sh
cargo build --release
```

No system libraries required: OpenPGP uses the pure-Rust backend
(`sequoia-openpgp` 2.x, `crypto-rust`) on all platforms — needed for yopass's
RFC 9580 AEAD format (see `Cargo.toml`).

### Inspecting a blob (diagnostic)

```sh
cargo run --example inspect -- secret.asc [passphrase]
```

Lists the OpenPGP packets and, if a passphrase is given, attempts a decrypt —
handy for confirming the format of a captured ciphertext.

## Usage

### Fetch a secret's ciphertext (consumes one-time secrets!)

```sh
bruteforcer yopass fetch --url 'https://yopass.se/#/c/<uuid>' --out secret.asc
```

### Crack a saved ciphertext with a wordlist

```sh
bruteforcer yopass crack --message secret.asc --wordlist rockyou.txt
```

### Crack with a brute-force mask

```sh
# all digit PINs up to length 6
bruteforcer yopass crack --message secret.asc --charset digits --min 1 --max 6

# custom alphabet
bruteforcer yopass crack --message secret.asc --charset-raw 'abc123!' --max 5
```

Named charsets: `digits`, `lower`, `upper`, `alpha`, `alnum`, `alnum-lower`,
`ascii`.

### Fetch + crack in one step

```sh
bruteforcer yopass crack --url 'https://yopass.se/#/c/<uuid>' --wordlist rockyou.txt
# or
bruteforcer yopass crack --uuid <uuid> --server https://yopass.se --wordlist rockyou.txt
```

If a share URL embeds the key (`#/s/<uuid>/<key>`), there is nothing to brute —
the tool just decrypts directly.

Other flags: `--threads N` (default: CPU count), `--no-progress`, `--out FILE`
(default: stdout). Read a ciphertext from stdin with `--message -`.

> **Always build `--release`.** The S2K key derivation dominates runtime and the
> debug build is several times slower.

### Recommended workflow

1. **Fetch once, crack the saved blob.** One-time secrets are deleted on the
   first fetch, so `fetch --out secret.asc` (or let `crack --url` auto-save its
   `<id>.asc` backup), then crack the file repeatedly with `--message`.
2. **Wordlist before masks.** Humans pick guessable passwords. A
   `crack --wordlist` pass over a common-password list (e.g. SecLists
   `xato-net-10-million-passwords-1000000.txt`, ~15 min here) finds far more
   real passwords per minute than brute-force masks.
3. **Then escalate masks**, cheapest keyspace first — `digits`, then `lower`,
   then `alnum-lower`, widening length last (see the table below for why length
   matters most).

## How long does it take?

yopass derives the key with an **iterated+salted SHA-256 S2K of 16,777,216
iterations** (the OpenPGP.js default), so every single guess is expensive. On
the reference machine below the engine sustained:

```
~1,140 guesses/sec   (release build, 16 threads, AES-256/GCM v6 SKESK)
```

(Measured end-to-end against a real yopass secret: an exhaustive `alnum-lower`
length-≤4 sweep — 1,679,616 candidates — took **1,518 s ≈ 25 min**, matching the
~24.6 min the table predicts.)

**Worst-case time to exhaust an exact-length keyspace at ~1,140 guesses/sec:**

| len | digits (10) | lower (26) | a–z0–9 (36) | a–zA–Z0–9 (62) | ascii-95 |
|----:|------------:|-----------:|------------:|---------------:|---------:|
| 4   | 9 s         | 6.7 min    | 25 min      | 3.6 hrs        | 20 hrs   |
| 5   | 1.5 min     | 2.9 hrs    | 15 hrs      | 9.3 days       | 79 days  |
| 6   | 15 min      | 3.1 days   | 22 days     | 1.6 yrs        | 20 yrs   |
| 7   | 2.4 hrs     | 82 days    | 2.2 yrs     | 98 yrs         | 1,900 yrs|
| 8   | 24 hrs      | 5.8 yrs    | 78 yrs      | 6,100 yrs      | 184,000 yrs |
| 10  | 101 days    | —          | —           | —              | —        |

Notes:
- **Expected** (not worst-case) time to *find* a password is roughly half these.
- Each added character multiplies the cost by the charset size — length matters
  far more than which charset. A random 8+ char password is not brute-forceable
  here; only weak/short/guessable ones are.
- The rate scales ~linearly with cores and inversely with the S2K iteration
  count. If a secret ever uses **Argon2** S2K instead, multiply these times by
  orders of magnitude (Argon2 is memory-hard by design).
- These are pure-mask numbers. A targeted wordlist is almost always faster for
  real passwords.

## GPU backend (opt-in)

The expensive part of cracking is the S2K (each guess hashes ~16 MiB through
SHA-256). The GPU backend offloads that to a wgpu/WGSL compute shader; HKDF and
the AEAD tag check stay on the CPU.

```sh
cargo build --release --features gpu
bruteforcer yopass crack --message secret.asc --wordlist rockyou.txt --gpu
# tune the batch (candidates per dispatch round); bigger = better GPU utilization
bruteforcer yopass crack --message secret.asc --charset digits --max 8 --gpu --gpu-batch 131072
```

Supported only for the modern yopass format (**v6 SKESK / AES-256 / GCM**); for
anything else `--gpu` prints a notice and falls back to the CPU engine. The S2K
is split into watchdog-safe chunks (persisting SHA state across dispatches) so
long iteration counts don't trip the OS GPU timeout (TDR).

How it works:
1. GPU computes `S2K = SHA256(<count> octets of salt||pass)` for a batch.
2. CPU verifies each: `HKDF-SHA256(S2K, info=[0xC3,6,cipher,aead])` → AES-256-GCM
   open of the SKESK's encrypted session key. A wrong key fails the GCM tag.
3. On a hit, the full plaintext is recovered with one normal sequoia decrypt.

**Performance reality check.** A GPU only wins big when its raw SHA-256 throughput
far exceeds the CPU's. Modern CPUs have **SHA-NI** hardware instructions, which
are very fast; GPUs compute SHA in general ALUs. On the reference machine an entry
discrete GPU (Intel Arc A370M) reached **~1,660 guesses/sec** vs the CPU's
**~1,140** — only ~1.5×. On a high-end discrete GPU the margin is far larger.
Benchmark your own hardware before assuming `--gpu` is faster.

## Architecture

```
src/
  engine/
    candidate.rs   CandidateSource trait: WordlistSource, MaskSpec (lazy odometer)
    runner.rs      parallel dispatch, bounded channel, stop-on-hit, progress
  target/
    mod.rs         Target trait — implement this to add an attack
    yopass.rs      URL parsing, fetch, offline OpenPGP decrypt (sequoia, any format)
    skesk_v6.rs    manual v6-SKESK parse + S2K + HKDF + AES-256-GCM verify
  gpu/             (feature = "gpu")
    mod.rs         wgpu host: batched S2K dispatch + CPU verify
    s2k.wgsl       SHA-256 S2K compute shader (chunked, 16-word schedule)
  main.rs          clap CLI
tests/
  vectors.rs       known-answer regression tests (CPU paths)
  gpu.rs           GPU backend tests (feature = "gpu"; auto-skip if no GPU)
  fixtures/        real captured ciphertexts:
                     yopass_v6_gcm.asc  (v6 SKESK/AES-256/GCM; "bHwc…" -> "fasfd")
                     openpgp_v4.asc     (gpg SEIPD+MDC; "hunter2" -> "v4 symmetric secret")
```

Regression coverage: the fixtures are real decrypted ciphertexts.

```sh
cargo test                 # CPU: SkeskV6 parse/verify + YopassTarget end-to-end (v6 & v4)
cargo test --features gpu  # also: GPU S2K == CPU reference (full 16 MiB count) + crack_v6 end-to-end
```

`vectors.rs` checks both the v6 fast path and the general sequoia path recover
the exact known plaintext, and that v4 correctly falls off the fast path.
`gpu.rs` checks the GPU-derived S2K matches the CPU reference bit-for-bit and
that `crack_v6` finds/exhausts correctly; it skips cleanly on machines without a
GPU adapter.

### Adding a new target

Implement `target::Target`:

```rust
pub trait Target: Send + Sync {
    fn try_candidate(&self, candidate: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
    fn name(&self) -> &str;
}
```

Return `Ok(Some(plaintext))` on a hit, `Ok(None)` on a clean miss, `Err` only for
unrecoverable problems (the runner treats `Err` as fatal). Then wire a subcommand
in `main.rs` and reuse `engine::run`.

## Performance notes

Runtime is almost entirely the **S2K key derivation** (≈16 MiB of SHA-256 per
guess). The CPU path's per-guess message re-parse is microseconds by comparison —
not worth optimizing. The real levers are core count, CPU SHA-NI (used
automatically by the pure-Rust backend), and the GPU backend above. None of them
make a single guess cheaper — that cost is fixed by the secret's S2K count, which
is the entire point of S2K.
