# dele.to target (offline password recovery)

[dele.to](https://dele.to) ([source](https://github.com/dele-to/dele-to)) is a
self-destructing secret sharer that bills itself as "an alternative to
PasswordPusher, Yopass and Bitwarden Send." This target recovers a weak
**password** (the optional access password on a share) **offline, from its stored
`passwordHash`**.

Source: [`src/target/deleto.rs`](../src/target/deleto.rs).

## The model (and what's actually attackable)

dele.to splits into two very different pieces:

- **The secret value** is **zero-knowledge**: encrypted client-side with
  **AES-256-GCM** under a random 256-bit key carried in the URL **fragment**
  (`#…`), which the browser never sends to the server (`lib/crypto.ts`). So the
  value is **not** offline-recoverable from a stored blob alone — you'd need the
  URL key, and if you have the URL key there's nothing to brute-force. That mode
  is out of scope here, exactly like yopass `#/s/…` and PrivateBin's default
  key-only paste.
- **The optional password** is **not** zero-knowledge. Unlike the AES key it is
  verified **server-side**: dele.to stores a `passwordHash` next to the share and,
  on retrieval, recomputes it and string-compares
  ([`app/actions/share.ts`](https://github.com/dele-to/dele-to/blob/main/app/actions/share.ts)):

  ```js
  function hashPassword(password) {
    const salt = process.env.SALT || "default-salt-change-in-production"
    return Buffer.from(password + salt).toString("base64")
  }
  // …
  if (share.passwordHash !== hashPassword(password)) { /* reject */ }
  ```

That `passwordHash` is a **self-contained, offline-crackable artifact** — exactly
what this framework attacks. Given the stored hash you obtained legitimately
(e.g. dumped from the Redis/file store of an instance you are authorized to test)
and the salt, you recover the password locally — **no live server, no network**.
Recomputing the base64 is the correctness oracle, so a wrong guess is a clean
miss.

> ⚠️ As with OneTimeSecret, you don't get this hash from the share URL — the
> server never exposes it. It comes from a store dump, a post-compromise /
> authorized-engagement artifact. Treat it like any captured hash.

## Why this is the *easiest* target here

dele.to's password storage is the **weakest** of any target in this repo — the
opposite extreme from OneTimeSecret's memory-hard Argon2id. It is **not** a KDF:
no iteration, no work factor, not memory-hard, and the salt is a single
process-wide value that **defaults to the literal string
`"default-salt-change-in-production"`** — most self-hosted instances never change
it. The hash is simply `base64(password ‖ salt)`.

That makes it not just cheap to brute-force but **directly reversible**:

```text
base64_decode(passwordHash)  ==  password ‖ salt
```

so if you know the salt (and the default is public), you strip the salt suffix
and read the password off with no search at all. `deleto::recover_directly` does
exactly that. The [`Target`] impl still drives the normal candidate engine
(recomputing the hash per guess, mirroring the server) so dele.to slots into the
framework like every other target — but the direct shortcut is why it sits at the
bottom of the difficulty scale. See
[`docs/security-comparison.md`](security-comparison.md).

Recovering the secret *value* afterwards still needs the URL fragment key and is
out of scope — this target's output is the recovered **password**.

## Usage

```sh
# Crack a stored passwordHash with a wordlist (default salt assumed):
bruteforcer deleto crack --hash 'MTIzNGRlZmF1bHQtc2FsdC1jaGFuZ2UtaW4tcHJvZHVjdGlvbg==' \
  --wordlist rockyou.txt

# Digit PINs up to length 6:
bruteforcer deleto crack --hash '<base64 passwordHash>' --charset digits --max 6

# An instance that overrode process.env.SALT:
bruteforcer deleto crack --hash '<hash>' --salt 'my-instance-salt' --charset lower --max 5

# Read the hash from a file (or '-' for stdin):
bruteforcer deleto crack --hash-file share.hash --charset alnum --max 4
```

Provide the hash with `--hash` (inline) or `--hash-file` (path, or `-` for
stdin). `--salt` defaults to dele.to's documented fallback
(`default-salt-change-in-production`); pass the instance's real `SALT` if it set
one. The recovered **password** is printed/written via `--out`. Candidate flags
(`--wordlist` / `--charset` / `--charset-raw`, `--min`/`--max`) and `--threads` /
`--no-progress` work the same as the other targets.

If the salt is correct, the construction step validates that the stored hash
actually decodes to bytes ending in that salt — a wrong `--salt` fails fast with a
clear message instead of silently grinding the whole keyspace to misses.

## Findings from a live test (the realistic attack is *online*)

A live share link (`/view/<id>#<key>`) was analysed end-to-end against the public
instance (authorized, throwaway test secret). The result reframes how a dele.to
share is actually attacked **from a link**, and it is *not* the offline hash crack
above:

- **The value is gated behind the password _server-side_.** Although the AES key
  rides in the URL fragment, the ciphertext and IV are never in the page — they
  are returned only by the `getSecureShare` server action, which **refuses to
  return them until the correct password is submitted**. Holding the URL key is
  not enough; you must clear the password gate first.
- **dele.to exposes no REST API** — retrieval is a Next.js **server action**.
  Three exist (their ids are recoverable from the client bundle):
  `createSecureShare`; `getShareMetadata` → title / view counts / `requirePassword`
  (**non-consuming**); and `getSecureShare(id, password)` → `encryptedContent` +
  `iv` (**consumes a view only on success**).
- **Online password guessing is wide open.** A wrong password returns
  `{"success":false,"error":"Incorrect password"}` and — critically — **consumes
  no view, with no rate-limiting, lockout, or CAPTCHA observed**. An attacker
  holding only a leaked link can brute-force the password over HTTP at near-offline
  speed, for free, leaving the secret intact until the moment they succeed. A weak
  password (e.g. `1234`) falls in milliseconds.
- **Decryption is then local.** Once the correct password yields `encryptedContent`
  (base64 of `ciphertext ‖ 16-byte GCM tag`) and `iv` (base64, 12 bytes),
  AES-256-GCM with the URL-fragment key (base64 → 32 bytes) recovers the plaintext;
  the GCM tag verifies, confirming the key.

**Implication.** From a leaked link, dele.to's defence-in-depth collapses to the
password alone — and that password is checked by an *unthrottled, view-free online
oracle*. The in-URL AES key (the zero-knowledge property that protects against a
server/DB compromise) gives **no** protection once the link leaks, because the
link *is* the key. So the realistic attack here is **online**, the same shape as
the [`pwpush`](pwpush.md) target, not the offline hash crack this module
implements.

> Two modes ship for dele.to: **`deleto crack`** is the **offline** path above (a
> *dumped* `passwordHash`), and **`deleto online`** drives the live server-action
> oracle described here — one HTTP request per candidate, then AES-256-GCM-decrypt
> the value with the URL-fragment key. Run `deleto online` only against an instance
> you are authorized to test; use the local Docker instance (below), not the public
> host.

## Usage — online (`deleto online`)

Attack a *live* share: guess the password against `getSecureShare`, then (if the
URL carries the `#key`) decrypt the value.

```sh
# Full share URL (key in the #fragment → password recovered AND value decrypted):
bruteforcer deleto online --url "http://localhost:3000/view/<id>#<base64key>" \
  --charset digits --max 4 --delay-ms 0

# Server + id, no key → recover the password only (no decryption):
bruteforcer deleto online --server http://localhost:3000 --id <id> --wordlist rockyou.txt

# Skip auto-discovery by passing the getSecureShare action id explicitly:
bruteforcer deleto online --url "<url>" --action-id <40-hex> --charset lower --max 5
```

The `getSecureShare` server-action id is **build-specific**; by default the target
**auto-discovers** it from the client bundle (and verifies it with one wrong-password
probe, which burns no view). Pass `--action-id` to skip discovery or if the bundle
layout changes. Online-specific flags mirror [`pwpush`](pwpush.md): `--delay-ms`
(min interval between requests, total across workers — use `0` on localhost) and
`--threads` (default **1**; keep it low). There is **no default host** — name the
instance with `--url` or `--server`. A wrong password is a clean miss; a structural
failure (bad id/URL, non-password error) aborts rather than burning the keyspace.

## Running dele.to locally in Docker

For authorized end-to-end testing, run dele.to yourself instead of touching the
public instance. The upstream repo ships a compose stack:

```sh
git clone https://github.com/dele-to/dele-to && cd dele-to
docker compose up --build        # app on http://localhost:3000
```

The stack is the Next.js app plus `redis:alpine` fronted by an Upstash-compatible
HTTP shim (`hiett/serverless-redis-http`); the app reaches it via
`UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`, already wired in the compose
file.

Two things matter for this target:

- **`SALT` is unset in the compose file**, so a local instance uses dele.to's
  documented default, `"default-salt-change-in-production"` — which is exactly the
  `--salt` default of `bruteforcer deleto crack`. A `passwordHash` dumped from the
  local Redis therefore cracks with no `--salt` flag at all.
- **The stored hash lives in Redis** under the key `share:<id>`. Create a
  password-protected share at <http://localhost:3000/create>, then read its
  `passwordHash` and run the offline crack:

  ```sh
  docker compose exec redis redis-cli --scan --pattern 'share:*'
  docker compose exec redis redis-cli GET 'share:<id>'   # JSON incl. passwordHash
  bruteforcer deleto crack --hash '<passwordHash>' --charset digits --max 6
  ```

To exercise the **online** path against your local instance, create a
password-protected share with the bundled helper and run the crack it prints:

```sh
# Create a real share (encrypts client-side; prints the view URL incl. #key):
node scripts/deleto_create.mjs http://localhost:3000 1234 "deleto self-host smoke test"

# Then run the printed command, e.g.:
cargo run --release -- deleto online \
  --url "http://localhost:3000/view/<id>#<key>" --charset digits --max 4 --delay-ms 0
```

[`scripts/deleto_create.mjs`](../scripts/deleto_create.mjs) does the same
client-side AES-256-GCM encryption as dele.to's browser, then invokes the
`createSecureShare` server action (Node 18+, no dependencies). Like
`pwpush_create.mjs` it is a dev helper and is **not** part of `cargo test`.

## Testing

The unit/integration tests under `cargo test` are fully **offline** and need no
server:

- Unit tests in [`src/target/deleto.rs`](../src/target/deleto.rs):
  - *offline path* — hashing matches the server's `hashPassword` (default and
    custom salt), malformed/wrong-salt rejection at construction, and the
    direct-recovery shortcut.
  - *online path (pure helpers)* — view-URL parsing (with/without `#key`, query
    stripping, bad-key rejection), an AES-256-GCM round-trip in the Web Crypto
    `ciphertext ‖ tag` layout, server-action body building, Flight-response
    parsing, and the action-id scanner / chunk-URL extractor.
- End-to-end in [`tests/deleto.rs`](../tests/deleto.rs): drives the full engine
  pipeline (mask → runner → target) to crack a password under both the default
  and a custom salt, and confirms a password outside the keyspace exhausts
  cleanly rather than erroring.

The offline tests reproduce the server's `base64(password ‖ salt)` to build their
fixtures, so the cracking path is anchored to dele.to's actual scheme — no bespoke
crypto, no fixture download, no Node, no network.

The **online** path needs a running server, so its end-to-end check is **manual**
and uses your own Docker instance (above) via `scripts/deleto_create.mjs` — never
the public host, and **not** part of `cargo test`.
