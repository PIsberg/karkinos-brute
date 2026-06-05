# karkinos-brute

[![CI](https://github.com/PIsberg/karkinos-brute/actions/workflows/ci.yml/badge.svg)](https://github.com/PIsberg/karkinos-brute/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg)](#)

A small, pluggable bruteforce **framework** in Rust. The engine (candidate
generation + parallel dispatch) is target-agnostic; each attack is a module that
implements one trait — see [**Targets**](#targets) below.

> ⚠️ **Authorized use only.** This tool is for security testing you are
> authorized to perform (your own data, your own deployment, a sanctioned
> engagement, or a CTF). Using it against secrets you do not own or are not
> authorized to access is illegal.

## Build

```sh
cargo build --release
```

Always build `--release` — the key-derivation step dominates runtime and debug is
several times slower. No system libraries are required: OpenPGP uses the pure-Rust
backend (`sequoia-openpgp` 2.x, `crypto-rust`) on all platforms (see `Cargo.toml`).

```sh
cargo build --release --features gpu   # opt-in GPU backend (yopass S2K)
```

## Targets

Each target is documented in its own file:

| Target | What it recovers | Mode | Docs |
|--------|------------------|------|------|
| **yopass** | a weak custom password on a [yopass](https://github.com/jhaals/yopass) OpenPGP secret, with an optional GPU S2K backend | offline | [`docs/yopass.md`](docs/yopass.md) |
| **PrivateBin** | a weak paste password on a [PrivateBin](https://github.com/PrivateBin/PrivateBin) v2 paste, given the URL key | offline | [`docs/privatebin.md`](docs/privatebin.md) |
| **PasswordPusher** | a weak push *passphrase* on a [PasswordPusher](https://github.com/pglombardo/PasswordPusher) server | **online** | [`docs/pwpush.md`](docs/pwpush.md) |
| **OneTimeSecret** | a weak *passphrase* from its stored [OneTimeSecret](https://github.com/onetimesecret/onetimesecret) hash (Argon2id/bcrypt) | offline | [`docs/onetimesecret.md`](docs/onetimesecret.md) |

Quick taste:

```sh
bruteforcer yopass        crack --message secret.asc --wordlist rockyou.txt
bruteforcer privatebin    crack --url "https://privatebin.net/?<id>#<key>" --charset digits --max 6
bruteforcer pwpush        crack --url "http://localhost:5100/p/<token>" --charset digits --max 4
bruteforcer onetimesecret crack --hash '$argon2id$v=19$m=65536,t=2,p=1$...' --wordlist rockyou.txt
```

> **yopass and PrivateBin are offline** — you crack a downloaded blob locally,
> with zero load on anyone's server. **PasswordPusher is an _online_ target**: it
> isn't zero-knowledge, so the only oracle is a live server and each guess is one
> HTTP request (logged server-side). Run it only against an instance you are
> authorized to test — e.g. your own self-hosted one. See [`docs/pwpush.md`](docs/pwpush.md).

**Which is hardest to crack?** See [`docs/security-comparison.md`](docs/security-comparison.md)
— short version: among per-guess cost, **OneTimeSecret wins by a mile** because its
Argon2id passphrase hash is *memory-hard* (64 MiB/guess), defeating the GPU/ASIC
acceleration that makes yopass's and PrivateBin's plain-SHA-256 KDFs cheap.
PrivateBin edges yopass on threat model (its key never reaches the server).
PasswordPusher is a category apart — nothing to crack offline at all (server-side
encryption, passphrase checked online).

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full design. In short:

```
src/
  engine/
    candidate.rs   CandidateSource trait: WordlistSource, MaskSpec (lazy odometer)
    runner.rs      parallel dispatch, bounded channel, stop-on-hit, progress
  target/
    mod.rs         Target trait — implement this to add an attack
    yopass.rs      URL parsing, fetch, offline OpenPGP decrypt (sequoia, any format)
    skesk_v6.rs    manual v6-SKESK parse + S2K + HKDF + AES-256-GCM verify
    privatebin.rs  paste/URL parsing, fetch, PBKDF2 + AES-256-GCM verify, inflate
    pwpush.rs      online passphrase guess: HTTP retrieval oracle, paced + retried
    onetimesecret.rs  offline passphrase recovery from an Argon2id/bcrypt hash
  gpu/             (feature = "gpu")
    mod.rs         wgpu host: batched S2K dispatch + CPU verify
    s2k.wgsl       SHA-256 S2K compute shader (chunked, 16-word schedule)
  main.rs          clap CLI
tests/
  vectors.rs       yopass known-answer regression tests (CPU paths)
  privatebin.rs    PrivateBin known-answer test (offline, static fixture)
  load.rs          engine throughput tests (LOADTEST_CANDIDATES; small in CI)
  gpu.rs           GPU backend tests (feature = "gpu"; auto-skip if no GPU)
  fixtures/        real captured ciphertexts + a node-WebCrypto KAT vector
scripts/           dev-only helpers to (re)generate / create PrivateBin pastes
```

```sh
cargo test                 # CPU paths + offline PrivateBin KAT + engine load tests
cargo test --features gpu  # also: GPU S2K == CPU reference + crack_v6 end-to-end
```

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
