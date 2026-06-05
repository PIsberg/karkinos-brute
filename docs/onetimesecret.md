# OneTimeSecret target (offline passphrase recovery)

[OneTimeSecret](https://onetimesecret.com)
([source](https://github.com/onetimesecret/onetimesecret)) shares a secret behind
a one-time link, with an **optional passphrase** gating retrieval. This target
recovers a weak passphrase **offline, from its stored hash**.

Source: [`src/target/onetimesecret.rs`](../src/target/onetimesecret.rs).

## The model (and what's actually attackable)

OneTimeSecret is **not** zero-knowledge. Two distinct things matter:

- **The secret value** is encrypted **server-side** (an `encrypted_field` under the
  instance's global secret, with the passphrase mixed into the key). Recovering
  the value needs that server-held global secret + the stored ciphertext + the
  passphrase, so it is **not** offline-recoverable from a hash alone — out of
  scope here.
- **The passphrase** is *not* stored in clear and *not* a plain string compare
  (that was PasswordPusher). OneTimeSecret stores a **password hash** of it and
  verifies on retrieval
  ([`passphrase_hashing.rb`](https://github.com/onetimesecret/onetimesecret/blob/HEAD/lib/onetime/models/features/passphrase_hashing.rb)):

  | Stored as | When | Format |
  |---|---|---|
  | **Argon2id** | current (`passphrase_encryption = '2'`) | `$argon2id$v=19$m=…,t=…,p=…$salt$hash` |
  | **bcrypt** | legacy | `$2a$…` (60 chars) |

That hash is a **self-contained, offline-crackable artifact** — exactly what this
framework attacks. Given a passphrase hash you obtained legitimately (e.g. dumped
from the Redis store of an instance you are authorized to test), you recover the
passphrase locally, like cracking any leaked hash — **no live server, no
network**. Argon2id/bcrypt verification is the correctness oracle, so a wrong
guess is a clean miss.

> ⚠️ Unlike yopass/PrivateBin you don't get this hash from the share URL — the
> server never exposes it. It comes from a database/Redis dump, which is a
> post-compromise / authorized-engagement artifact. Treat it like any captured
> hash.

## Why this is the hardest target here per guess

Current OneTimeSecret uses **Argon2id** with production cost
`{t_cost: 2, m_cost: 16, p_cost: 1}` — the `argon2` gem reads `m_cost` as an
exponent, so that's **2¹⁶ KiB = 64 MiB of memory per guess**, twice over. Argon2id
is **memory-hard** by design, which defeats the GPU/ASIC acceleration that makes
yopass and PrivateBin (plain SHA-256 KDFs) cheap to attack in bulk. So a OneTimeSecret
passphrase hash is by far the most expensive per-guess of any target in this repo —
only genuinely weak/short passphrases are realistically recoverable. (Legacy bcrypt
hashes are also adaptive but not memory-hard.) See
[`docs/security-comparison.md`](security-comparison.md).

The target reads the cost parameters **from the hash string itself**, so it
verifies against whatever cost the instance configured — including very cheap
test-env hashes and very expensive production ones.

## Usage

```sh
# Crack an Argon2id passphrase hash with a wordlist:
bruteforcer onetimesecret crack --hash '$argon2id$v=19$m=65536,t=2,p=1$...$...' \
  --wordlist rockyou.txt

# A legacy bcrypt hash, digit PINs up to length 6:
bruteforcer onetimesecret crack --hash '$2a$12$....' --charset digits --max 6

# Read the hash from a file (or '-' for stdin):
bruteforcer onetimesecret crack --hash-file secret.hash --charset lower --max 5
```

Provide the hash with `--hash` (inline) or `--hash-file` (path, or `-` for
stdin). The recovered **passphrase** is printed/written via `--out`. Candidate
flags (`--wordlist` / `--charset` / `--charset-raw`, `--min`/`--max`) and
`--threads` / `--no-progress` work the same as the other targets.

> **Build `--release`.** With production Argon2id (64 MiB, t=2) each guess is
> expensive; a debug build makes it far worse. Wordlists beat masks here even more
> than usual — at memory-hard cost, brute-forcing anything but a tiny keyspace is
> impractical.

## Testing

The tests are fully **offline** and need no server:

- Unit tests in [`src/target/onetimesecret.rs`](../src/target/onetimesecret.rs):
  scheme detection, malformed-hash rejection, an Argon2id round-trip, and a
  **published OpenBSD bcrypt reference vector** (passphrase `U*U`) — an
  *independent* implementation, so our bcrypt path is anchored to the canonical C
  one, not just our own crate.
- End-to-end in [`tests/onetimesecret.rs`](../tests/onetimesecret.rs): drives the
  full engine pipeline (mask → runner → target) to crack both a bcrypt and an
  Argon2id hash, and confirms a passphrase outside the keyspace exhausts cleanly
  rather than erroring.

Both Argon2id and bcrypt are standard, pure-Rust, reference-tested formats (the
`argon2` and `bcrypt` crates), so there is no bespoke crypto to re-derive — no
fixture download, no Node, no network.
