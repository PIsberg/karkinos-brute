# PasswordPusher target (online)

[PasswordPusher](https://github.com/pglombardo/PasswordPusher) (public instances
[pwpush.com](https://pwpush.com) / [eu.pwpush.com](https://eu.pwpush.com)) shares
secrets behind a hard-to-guess URL, with an **optional passphrase** gating
retrieval. This target recovers a weak passphrase by guessing it.

Source: [`src/target/pwpush.rs`](../src/target/pwpush.rs).

> ⚠️ **This is the framework's only _online_ target, and the only one that is an
> active attack on a live service.** Unlike yopass and PrivateBin you cannot
> crack a downloaded blob offline — see below. Run it **only** against an
> instance you are authorized to test (e.g. your own self-hosted server).

## Why it's online (and not like the other targets)

yopass and PrivateBin are **zero-knowledge**: the secret is encrypted
*client-side*, the password is fed through a KDF (S2K / PBKDF2) into the
decryption key, and the AEAD tag is a local correctness oracle. You download the
ciphertext once and recover the password offline, math-only.

PasswordPusher is **not** zero-knowledge:

- The payload is encrypted **at rest on the server** (Lockbox **AES-256-GCM**)
  under a random 256-bit master key (`PWPUSH_MASTER_KEY`) the server holds — not
  derived from any user password. Nothing there is brute-forceable.
- The optional **passphrase is not a KDF input.** The server does a constant-time
  **string compare** of the stored passphrase against the supplied one on
  retrieval:

  ```ruby
  ActiveSupport::SecurityUtils.secure_compare(@push.passphrase.to_s, params[:passphrase].to_s)
  ```

So there is **no ciphertext whose password we can recover locally** and no
algorithm to extract and run offline — the passphrase isn't cryptographically
bound to anything. The only thing that can say "right / wrong" is a *running
server holding that push*. Hence: one HTTP request per candidate.

See [`docs/security-comparison.md`](security-comparison.md) for how this
server-side-trust model compares to the two zero-knowledge targets.

## Retrieval API (the oracle)

```
GET {base}/p/{token}.json?passphrase=<candidate>
```

| Server response | Meaning | Target result |
|---|---|---|
| **401** `{"error":"That passphrase is incorrect."}` | wrong/missing passphrase | clean **miss** (`Ok(None)`) |
| **200** with a JSON `payload` | passphrase accepted | **hit** — secret recovered |
| **429** | rate limited | back off + retry (honors `Retry-After`) |
| **404 / 410** | push gone/expired | fatal — nothing to crack |

Two operational facts that make this attack *noisy* and *destructive*, unlike the
offline targets:

- **Every wrong guess is logged server-side** as a failed-passphrase event (it
  shows in the push's audit log). An offline crack leaves no trace; this one does.
- **A correct guess counts as a view** and can delete a view-limited push
  (`GET /p/{token}.json` is a normal retrieval). Set a generous `expire_after_views`
  when creating a push you intend to test against.

## Usage

```sh
# Against a server you control, by full push URL:
bruteforcer pwpush crack --url http://localhost:5100/p/<token> --charset digits --max 4 --delay-ms 0

# Or by server + token:
bruteforcer pwpush crack --server http://localhost:5100 --token <token> --wordlist rockyou.txt

# A shared/remote instance you are authorized to test — be polite:
bruteforcer pwpush crack --url https://pwpush.example/p/<token> --charset lower --max 5 --delay-ms 250
```

There is **no default host** — you must name the instance (`--url`, or
`--server` + `--token`). Candidate flags (`--wordlist` / `--charset` /
`--charset-raw`, `--min` / `--max`) work the same as the other targets.

Online-specific flags:

- `--delay-ms <N>` — minimum delay between requests across all workers
  (default **100**). Use **0** for a localhost instance you own; raise it for a
  shared server to avoid tripping rate limits / alarms.
- `--threads <N>` — default **1**. This is an online attack; keep it low. The
  delay paces the *total* request rate regardless of thread count.

On HTTP 429 the target backs off (respecting `Retry-After`) and retries; after
repeated rate-limit/transport failures it aborts rather than silently skipping
candidates.

## Testing (self-hosted, opt-in)

The unit tests in [`src/target/pwpush.rs`](../src/target/pwpush.rs) are fully
**offline** and run under `cargo test`: URL/token parsing, HTTP-status → outcome
classification, and `payload` extraction. They touch no network.

End-to-end verification needs a running server, so it is **manual** and uses your
own instance — never a public one:

```sh
# 1. Run a throwaway PasswordPusher (ephemeral SQLite; gone when the container is removed):
docker run -d --rm -p 5100:5100 --name pwpush pglombardo/pwpush:latest

# 2. Create a passphrase-protected push and print the ready-to-run crack command:
node scripts/pwpush_create.mjs http://localhost:5100 1234 "self-host smoke test"

# 3. Run the crack it prints, e.g.:
cargo run --release -- pwpush crack --url http://localhost:5100/p/<token> \
  --charset digits --max 4 --delay-ms 0

# 4. Tear down:
docker rm -f pwpush
```

[`scripts/pwpush_create.mjs`](../scripts/pwpush_create.mjs) just POSTs to the
instance's create API (Node 18+, no dependencies); it is **not** part of
`cargo test`.
