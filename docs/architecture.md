# Architecture

`karkinos-brute` is a small, pluggable **offline brute-force framework** in Rust.
The engine (candidate generation + parallel dispatch) is target-agnostic; each
attack is a module that implements one trait. The only bundled target is
`yopass` — offline recovery of a weak *custom password* on a yopass secret's
OpenPGP ciphertext.

> The crate, binary, and library are named `bruteforcer` even though the repo is
> `karkinos-brute`. CLI examples and `use bruteforcer::...` paths use that name.

This document explains how the pieces fit together. For build/test commands and
operational notes see [`../CLAUDE.md`](../CLAUDE.md) and [`../README.md`](../README.md).

---

## 1. The big picture

The design separates three concerns, so a new attack is *just* a new `Target`
implementation and the engine is reused unchanged:

| Concern | Module | Question it answers |
|---|---|---|
| **Candidate generation** | `engine::candidate` | *Where do guesses come from?* |
| **Dispatch** | `engine::runner` | *How are guesses run (parallel, stop-on-hit)?* |
| **Target** | `target` | *What is a guess tested against?* |

```mermaid
flowchart LR
    CLI["main.rs (clap CLI)"] --> SRC

    subgraph engine["engine (target-agnostic)"]
        SRC["CandidateSource<br/>(WordlistSource / MaskSpec)"]
        RUN["runner::run<br/>producer + N workers"]
        SRC -- "next_candidate(&mut buf)" --> RUN
    end

    subgraph target["target (the attack)"]
        T["Target trait"]
        Y["YopassTarget"]
        T -.implements.- Y
    end

    RUN -- "try_candidate(&bytes)" --> T

    subgraph crypto["yopass crypto paths"]
        SEQ["sequoia-openpgp<br/>(general path)"]
        V6["skesk_v6::SkeskV6<br/>(manual v6 fast path)"]
    end

    Y --> SEQ
    GPU["gpu::crack_v6<br/>(feature = gpu)"] --> V6
    CLI -. "--gpu" .-> GPU
    GPU -- "S2K on GPU,<br/>verify on CPU" --> V6

    RUN --> OUT["Outcome::Found / Exhausted"]
    OUT --> CLI
```

The GPU backend is an alternative dispatch path for one specific ciphertext
format; it bypasses `runner` and drives `skesk_v6` directly (see §6).

---

## 2. Types and traits (class diagram)

```mermaid
classDiagram
    class CandidateSource {
        <<trait>>
        +next_candidate(buf) bool
        +total_hint() Option~u64~
    }
    class WordlistSource {
        -reader BufReader~File~
        +open(path) Result~Self~
    }
    class MaskSpec {
        -charset Vec~u8~
        -min_len usize
        -max_len usize
        -cur_len usize
        -indices Vec~usize~
        +new(charset, min, max) Result~Self~
    }
    CandidateSource <|.. WordlistSource : impl
    CandidateSource <|.. MaskSpec : impl

    class Target {
        <<trait>>
        +try_candidate(candidate) Result~Option~
        +name() str
    }
    class YopassTarget {
        -ciphertext Vec~u8~
        -policy StandardPolicy
        +new(message) Result~Self~
    }
    Target <|.. YopassTarget : impl

    class RunConfig {
        +threads usize
        +progress bool
    }
    class Outcome {
        <<enum>>
        Found
        Exhausted
    }
    class run {
        <<fn>>
        run(target, source, cfg) Result~Outcome~
    }
    run ..> Target : Arc, drives
    run ..> CandidateSource : Box, pulls
    run ..> RunConfig : configured by
    run ..> Outcome : returns

    class SkeskV6 {
        +salt bytes8
        +count u32
        +aad bytes4
        +iv Vec~u8~
        +esk Vec~u8~
        +parse(message) Result~Self~
        +s2k(passphrase) bytes32
        +verify_with_s2k(key) Option
        +verify(passphrase) Option
    }
    class GpuS2k {
        +new(skesk, capacity) Result~Self~
        +derive_batch(candidates) Result
    }
    YopassTarget ..> SkeskV6 : fast path (via skesk_v6)
    GpuS2k ..> SkeskV6 : reproduces S2K oracle
    SecretLocation : +base_url String
    SecretLocation : +uuid String
    SecretLocation : +key Option~String~
    SecretLocation : +from_share_url(url) Result
```

### The two traits, in words

```rust
pub trait CandidateSource: Send {
    // Overwrite `buf` with the next candidate; false at exhaustion.
    fn next_candidate(&mut self, buf: &mut Vec<u8>) -> bool;
    fn total_hint(&self) -> Option<u64> { None }
}

pub trait Target: Send + Sync {
    // Ok(Some(plaintext)) = hit (stops the run)
    // Ok(None)            = clean miss (the common case)
    // Err(_)              = FATAL, aborts the whole run
    fn try_candidate(&self, candidate: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
    fn name(&self) -> &str;
}
```

The `Err`-is-fatal rule matters: a wrong passphrase must be `Ok(None)`, never
`Err`. `Err` is reserved for malformed ciphertext / I/O — a target that errored
per-candidate would otherwise burn the entire keyspace doing nothing.

---

## 3. CPU crack — end-to-end sequence

This is what `bruteforcer yopass crack --message secret.asc --wordlist words.txt`
does. (Fetching, the embedded-key short-circuit, and the GPU branch are covered
in later sections.)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant CLI as main.rs
    participant YT as YopassTarget
    participant Run as runner::run
    participant Prod as Producer thread
    participant Src as CandidateSource
    participant W as Worker threads (N)
    participant Seq as sequoia-openpgp

    User->>CLI: crack --message --wordlist
    CLI->>YT: new(ciphertext)
    YT->>YT: ensure_passphrase_encrypted()
    Note over YT: validates an SKESK exists ONCE,<br/>not per candidate
    CLI->>Run: run(Arc<YopassTarget>, Box<Source>, cfg)

    Run->>W: spawn N workers (share Arc target)
    loop until exhausted or stop
        Prod->>Src: next_candidate(&mut buf)
        Src-->>Prod: true (buf filled) / false (EOF)
        Prod->>W: send buf over bounded channel
        W->>YT: try_candidate(&buf)
        YT->>Seq: DecryptorBuilder + passphrase
        alt passphrase decrypts
            Seq-->>YT: plaintext
            YT-->>W: Ok(Some(plaintext))
            W->>Run: store hit, set stop=true
        else wrong passphrase
            Seq-->>YT: error (tag/MDC fails)
            YT-->>W: Ok(None)
            W->>W: local_tried++, recycle buf
        end
    end
    Run-->>CLI: Outcome::Found{candidate, secret} | Exhausted
    CLI-->>User: print password / "exhausted"
```

---

## 4. The runner concurrency model

`runner::run` is one **producer** thread feeding N **worker** threads through a
*bounded* channel. A second bounded channel recycles spent buffers so the
steady-state hot path performs no heap allocation.

```mermaid
flowchart TB
    Src["CandidateSource"]

    subgraph prod["Producer (calling thread)"]
        P1["try_recv a recycled buffer<br/>(else allocate)"]
        P2["next_candidate(&mut buf)"]
        P3["tx.send(buf)"]
        P1 --> P2 --> P3 --> P1
    end

    Src --> P2
    P3 -- "work channel<br/>bounded(threads*256)" --> WQ(["queue"])

    subgraph workers["N worker threads"]
        direction TB
        W1["recv buf"]
        W2{"try_candidate"}
        W1 --> W2
        W2 -- "Ok(Some)" --> HIT["store hit<br/>stop = true"]
        W2 -- "Ok(None)" --> CNT["local_tried++<br/>(flush every 64)"]
        W2 -- "Err" --> ERR["store error<br/>stop = true"]
        CNT --> REC["clear + recycle buf"]
        REC --> W1
    end

    WQ --> W1
    REC -- "free channel<br/>bounded(threads*256)" --> P1

    HIT --> STOP(["AtomicBool stop"])
    ERR --> STOP
    STOP -. "checked by producer & workers" .-> prod
```

Key properties:

- **Backpressure.** The bounded work channel (`threads * 256`) stops the producer
  from racing ahead and buffering the whole keyspace in memory. Mask keyspaces
  are astronomically large, so they are streamed lazily, never materialized.
- **Stop-on-hit.** The first hit sets an `AtomicBool`; producer and workers both
  observe it and wind down. The winning `(candidate, secret)` is kept under a
  `Mutex` that is contended exactly once (on success).
- **Zero-alloc steady state.** Workers return spent buffers via the free channel;
  the producer refills and resends them. Allocation happens only while the
  pipeline first fills.
- **Batched progress.** Each worker counts locally and flushes to the shared
  atomic every `PROGRESS_FLUSH` (64) guesses — off the hot path for cheap targets,
  yet still sub-second for slow ones like yopass.
- **Errors are fatal.** A worker `Err` is stored and stops the run; `run` returns
  it to the caller.

---

## 5. yopass: obtaining the ciphertext and choosing a path

Before any cracking, `main.rs` resolves *where the ciphertext comes from* and
whether brute force is even needed.

```mermaid
flowchart TD
    Start([crack invoked]) --> HasMsg{"--message given?"}
    HasMsg -- yes --> ReadFile["read file / stdin"]
    HasMsg -- no --> Loc["resolve SecretLocation<br/>from --url or --uuid+--server"]
    Loc --> ApiBase["apply_api_base()<br/>auto-correct yopass.se -> api.yopass.se"]
    ApiBase --> Fetch["GET /secret/uuid<br/>(CONSUMES one-time secret!)"]
    Fetch --> Backup["save &lt;uuid&gt;.asc backup immediately"]
    ReadFile --> Build
    Backup --> Build["YopassTarget::new()"]

    Build --> KeyInUrl{"share URL embedded<br/>a key? (#/s/uuid/key)"}
    KeyInUrl -- yes --> Direct["decrypt directly<br/>(no brute force)"]
    KeyInUrl -- no --> Gpu{"--gpu set AND<br/>v6/AES-256/GCM?"}
    Gpu -- yes --> GpuPath["gpu::crack_v6"]
    Gpu -- "no / unsupported" --> CpuPath["runner::run (CPU engine)"]

    Direct --> Emit([emit secret])
    GpuPath --> Emit
    CpuPath --> Emit
```

> ⚠️ **One-time secrets.** Fetching consumes (deletes) a one-time secret
> server-side, so the fetched blob is saved to `<uuid>.asc` *immediately* — a
> failed crack must never lose the only copy. Re-crack the saved file with
> `--message`.

### Two decryption paths for the same ciphertext

`YopassTarget` (the CPU engine) uses **sequoia-openpgp**, which handles any
OpenPGP symmetric message. `skesk_v6::SkeskV6` is a hand-rolled decode + verify
for *only* the modern yopass format (RFC 9580 **v6 SKESK / AES-256 / GCM**); it
exists because it is the exact oracle the GPU backend reproduces, and it returns
`UnsupportedSkesk` for anything else so callers fall back to sequoia.

```mermaid
flowchart LR
    CT["armored ciphertext"] --> Q{"v6 SKESK /<br/>AES-256 / GCM?"}
    Q -- yes --> Fast["skesk_v6 fast path<br/>(used by --gpu)"]
    Q -- "no (v4, other cipher/AEAD)" --> Gen["sequoia general path"]
    Fast -. "UnsupportedSkesk -> fall back" .-> Gen
```

---

## 6. GPU backend (`--features gpu`)

The expensive part of every guess is the **S2K**: hashing ~16 MiB of
`salt || passphrase` through SHA-256 (16,777,216 octets by default). The GPU
backend offloads *only* that to a WGSL compute shader; HKDF and the AES-GCM tag
check stay on the CPU via `SkeskV6::verify_with_s2k`.

```mermaid
sequenceDiagram
    autonumber
    participant CLI as main.rs
    participant CV as gpu::crack_v6
    participant Src as CandidateSource
    participant G as GpuS2k (host)
    participant SH as s2k.wgsl (device)
    participant V6 as SkeskV6 (CPU verify)

    CLI->>CV: crack_v6(skesk, source, batch)
    CV->>G: GpuS2k::new(skesk, batch)
    loop per batch
        CV->>Src: fill up to `batch` candidates
        CV->>G: derive_batch(candidates)
        G->>SH: dispatch (chunked, watchdog-safe)
        Note over G,SH: persist SHA state {h[8], m, off}<br/>between chunks so no single<br/>dispatch trips the GPU TDR timeout
        SH-->>G: 32-byte S2K key per candidate
        G-->>CV: keys[]
        loop per candidate
            CV->>V6: verify_with_s2k(key)
            V6-->>CV: Some(session key) on hit / None
        end
        alt hit found
            CV-->>CLI: Some(winning passphrase)
        end
    end
    CV-->>CLI: None (exhausted)
```

### Why the S2K is chunked (state machine)

A single candidate's S2K is ~262,144 SHA-256 blocks. Doing that in one dispatch
would trip the OS GPU watchdog (TDR). The shader instead processes a bounded
range of blocks per dispatch and persists the running SHA state between
dispatches; the host issues `ceil(num_blocks / chunk)` dispatches and the final
one writes the digest.

```mermaid
stateDiagram-v2
    [*] --> Init: start_block == 0
    Init: initialize SHA-256 state (h0..h7), m=0, off=0
    Init --> Compute
    Resume: load {h[8], m, off} from state buffer
    [*] --> Resume: start_block > 0
    Resume --> Compute
    Compute: hash blocks [start_block, end_block)
    Compute --> Persist: not final chunk
    Persist: write {h[8], m, off} back to state buffer
    Persist --> [*]
    Compute --> Emit: is_final == 1
    Emit: write 32-byte digest to out buffer
    Emit --> [*]
```

### The verification chain (one candidate)

For each candidate passphrase `p`, both the CPU fast path and the GPU+CPU split
compute the same chain:

```mermaid
flowchart LR
    P["passphrase p"] --> S2K["S2K = SHA256(count octets<br/>of salt‖p)"]
    S2K --> HKDF["kek = HKDF-SHA256(ikm=S2K,<br/>info=aad)[..32]"]
    HKDF --> AEAD["AES-256-GCM open(esk,<br/>nonce=iv, aad)"]
    AEAD -->|tag verifies| Hit["correct passphrase<br/>(session key recovered)"]
    AEAD -->|tag fails| Miss["wrong passphrase"]
```

`aad = [0xC3, version, cipher_algo, aead_algo]`. On the GPU path only the first
box (S2K) runs on the device; HKDF + AEAD run on the host. On a confirmed hit the
full plaintext is recovered with one ordinary sequoia decrypt.

---

## 7. Adding a new target

The engine is reused unchanged — implement `Target` and wire a subcommand:

```mermaid
flowchart LR
    A["impl Target for MyTarget"] --> B["add a clap subcommand in main.rs"]
    B --> C["build a CandidateSource<br/>(reuse WordlistSource / MaskSpec)"]
    C --> D["engine::run(target, source, cfg)"]
```

```rust
pub trait Target: Send + Sync {
    fn try_candidate(&self, candidate: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
    fn name(&self) -> &str;
}
```

Return `Ok(Some(plaintext))` on a hit, `Ok(None)` on a clean miss, and `Err` only
for unrecoverable problems. Candidate generation, parallel dispatch, stop-on-hit,
progress, and buffer recycling all come for free from `engine::run`.

---

## 8. Source map

```
src/
  lib.rs           crate root; re-exports engine + target (+ gpu under feature)
  main.rs          clap CLI: fetch / crack subcommands, path selection
  engine/
    candidate.rs   CandidateSource trait; WordlistSource, MaskSpec (lazy odometer)
    runner.rs      parallel dispatch, bounded channels, stop-on-hit, progress
  target/
    mod.rs         Target trait
    yopass.rs      URL parsing, fetch, sequoia decrypt (general path)
    skesk_v6.rs    manual v6-SKESK parse + S2K + HKDF + AES-256-GCM verify
  gpu/             (feature = "gpu")
    mod.rs         wgpu host: batched S2K dispatch + CPU verify
    s2k.wgsl       SHA-256 S2K compute shader (chunked, watchdog-safe)
tests/
  vectors.rs       known-answer regression tests (CPU paths)
  gpu.rs           GPU backend tests (auto-skip without an adapter)
  fixtures/        real captured ciphertexts (v6/GCM and classic v4)
```
