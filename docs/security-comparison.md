# Which target is hardest to crack? (yopass vs PrivateBin vs PasswordPusher)

A comparison of the three bundled targets *from a crackability standpoint* — how
well each service resists an attacker trying to recover a weak, human-chosen
password/passphrase.

The three split into **two architectures**, and that split matters more than any
KDF detail:

- **yopass and PrivateBin are zero-knowledge** (encrypt client-side; the password
  feeds a KDF into the decryption key). They hide a strong random key somewhere
  and *optionally* layer a human password on top. The attack is **offline**:
  download the blob once, crack the password locally. Below they're compared on
  two axes — cost per guess, and threat model.
- **PasswordPusher is server-side-trust** (encrypts at rest under a server key;
  the passphrase is a server-side string compare). There is **no offline
  artifact** — the attack, if any, is **online**. It's analysed separately at the
  end because the two axes below don't even apply to it.

For the two zero-knowledge targets the question splits into two independent axes:

1. **Cost per guess** — how expensive is one password attempt (the KDF work factor)?
2. **Can the attack be mounted at all** — what does an attacker need to *have*
   before per-guess cost even matters (the threat model / where the key lives)?

**TL;DR.** Among the zero-knowledge pair, **PrivateBin beats yopass**: per-guess
cost is roughly equal (yopass marginally higher), but PrivateBin's 256-bit key
lives only in the URL fragment and never reaches the server, so a leaked
ciphertext is uncrackable *regardless of password strength*, and its default
paste has no crackable password at all. yopass's custom-password mode makes the
password the **sole** secret, so the stored blob alone is offline-crackable
whenever that password is weak. **PasswordPusher is in a different category** —
nothing is offline-crackable at all, which is a real strength against a *thief who
steals data*, but it's purchased by trusting the server (which can read every
secret) and by reducing any passphrase attack to a noisy, logged, rate-limited
*online* one.

## Axis 1 — Cost per guess (KDF work factor)

Both KDFs are SHA-256-based and iterate to a similar total amount of work:

| | yopass (`/c/` custom password) | PrivateBin (password mode) |
|---|---|---|
| KDF | OpenPGP iterated+salted **S2K**, SHA-256 | **PBKDF2-HMAC-SHA256** |
| Work factor (default) | 16,777,216 octets hashed ≈ **262k** SHA-256 blocks/guess | 100,000 iterations ≈ **200k** SHA-256 blocks/guess |
| Measured rate¹ | **~1,140 guesses/sec** | **~1,000 guesses/sec** |
| Memory-hard? | No | No |
| GPU/ASIC-acceleratable? | Yes (a GPU S2K backend ships here) | Yes |

¹ Reference machine, release build, 16 threads. yopass measured against a real
v6 secret; PrivateBin measured by exhausting 100,000 candidates against the
committed test fixture (`cargo`-independent, on the same box).

**Verdict on Axis 1: a near-tie, slight edge to yopass.** Both sit in the same
order of magnitude (~10⁵–10⁶ SHA-256 compressions per guess), so an attacker
cracks them at within ~15 % of the same speed. yopass costs marginally more per
guess. Crucially, **neither is memory-hard** (no Argon2/scrypt), so both are
linearly accelerated by GPUs/ASICs and the per-guess cost is *not* a strong
defense for either — only password entropy is. (If a yopass secret ever used an
Argon2 S2K, that axis would flip hard in yopass's favor.)

Concretely, at ~1,000–1,140 guesses/sec a 6-character lowercase password
(26⁶ ≈ 3.1×10⁸) takes ~3 days to exhaust on this one machine, on *either* service
— and far less in expectation or on better hardware. See the
[yopass timing table](yopass.md#how-long-does-it-take) for the full keyspace grid;
PrivateBin's numbers are within ~15 % of it.

## Axis 2 — Can the attack be mounted at all (threat model)

This is where they diverge, and it's the more important axis.

| | yopass (`/c/` custom password) | PrivateBin (password mode) |
|---|---|---|
| High-entropy key in URL, withheld from the server? | **No** — `/c/` derives the key from the password alone; the UUID is just an id | **Yes** — a 256-bit key in the `#fragment`, never sent to the server |
| Key derivation | `key = S2K(password)` | `key = PBKDF2(url_key ‖ password)` |
| Stolen/leaked **ciphertext alone** crackable (weak pw)? | **Yes** — the blob is all an attacker needs | **No** — the attacker must *also* steal the link |
| Default mode crackable? | The `/c/` password mode is itself the opt-in | **No** — the default paste has no password (key-only, ~256-bit) |

The decisive difference: in PrivateBin the password is **defense-in-depth on top
of a strong key that the server never sees**. An adversary who compromises the
server, dumps the database, or intercepts the stored blob still cannot crack a
weak password, because they're missing the 256-bit fragment key. In yopass's
custom-password mode the password is the **whole** secret — that same adversary
can offline-crack it directly from the stored ciphertext.

> yopass's *other* mode, `/s/<uuid>/<key>`, mirrors PrivateBin's strength: a
> ~130-bit key in the fragment, withheld from the server. But that mode has **no
> password to crack** — so it isn't a target here. The crackable yopass mode is
> specifically `/c/`, which trades the URL key away for a human password.

## PasswordPusher — a different architecture (server-side trust)

PasswordPusher doesn't fit the two axes above because it isn't zero-knowledge.
The browser sends the secret to the server *in the clear* (over TLS); the server
encrypts it **at rest** with AES-256-GCM (via the Lockbox gem) under a random
256-bit master key it holds (`PWPUSH_MASTER_KEY`). The optional passphrase is
**not** a KDF input — the server stores it and does a constant-time string compare
on retrieval (`ActiveSupport::SecurityUtils.secure_compare`).

| | PasswordPusher | yopass / PrivateBin (zero-knowledge) |
|---|---|---|
| Where encryption happens | server, at rest | client, in the browser |
| Key derivation from the human secret? | **No** — random server master key | Yes — S2K / PBKDF2 → AES key |
| Offline-crackable artifact exists? | **No** | Yes (the downloaded blob) |
| Passphrase check | server-side string compare | local AEAD-tag verify |
| Attack on a weak passphrase | **online only** — one HTTP request/guess | offline, math-only |
| Server can read the secret? | **Yes** | No |

What this buys, and what it costs:

- **Strong against a data thief.** An attacker who steals the database (or a
  single stored row) gets ciphertext encrypted under a 256-bit random key, not a
  human password — uncrackable. There is no offline attack on the passphrase at
  all, because the passphrase never touches the ciphertext.
- **Weak against the server, and against online guessing.** The server holds the
  master key and therefore *can decrypt every secret* — you are trusting the
  operator (and their host, backups, and logs), exactly the trust a
  zero-knowledge design removes. And the passphrase, where used, is only as strong
  as an **online** attack makes it: each guess is a logged HTTP request that a
  rate-limiter, alerting, and view limits all push back on.

So for the *crack tool* PasswordPusher is the **least crackable** in the offline
sense (nothing to crack), but that strength is conditional on trusting the server
— a different promise from yopass/PrivateBin, not a strictly stronger one. Our
[`pwpush`](pwpush.md) target therefore can only mount the **online** passphrase
attack, against a server you are authorized to test.

## Overall verdict

**Among the two zero-knowledge targets, PrivateBin has the best security from a
crackable perspective; PasswordPusher sits in a separate category.**

- **Zero-knowledge pair — Axis 1 (per-guess cost): ~tie**, marginal edge to
  yopass (~1,140 vs ~1,000 guesses/sec; neither memory-hard).
- **Zero-knowledge pair — Axis 2 (threat model): PrivateBin wins clearly** — the
  high-entropy key never reaches the server, so a leaked ciphertext is uncrackable
  regardless of password strength, and the default paste exposes no password at
  all. yopass `/c/` makes a weak password the single point of failure against
  anyone holding the blob.
- **PasswordPusher: no offline crack exists**, which is the strongest possible
  answer to "can a leaked blob be cracked?" (no) — but it's bought by trusting the
  server with the plaintext and by reducing any passphrase attack to a noisy,
  rate-limited online one. Strong against thieves, weak against the operator.

### Practical guidance

- **For both, given an attacker who has the link, password entropy is the only
  real defense.** A short or guessable password falls in hours-to-days on one
  machine and faster on a GPU. Use a long random password — or, better, rely on
  the high-entropy URL key and don't add a weak password at all.
- **Prefer key-in-URL modes** (PrivateBin's default, or yopass `/s/`) over
  human-password modes (yopass `/c/`) whenever the sharing channel for the link
  is trustworthy: a 256-/130-bit key is not brute-forceable, a weak password is.
- **Operators** worried about server compromise should note that only PrivateBin
  (and yopass `/s/`) keep the decryption key off the server; yopass `/c/` blobs
  are offline-crackable if exfiltrated.
- **PasswordPusher** is a good fit when you want central control, audit logs, and
  expiry/burn enforcement and you trust the operator — but understand that the
  server can read your secrets. If you instead want "even the operator can't read
  it," choose a zero-knowledge tool. If you use a PasswordPusher passphrase, it
  defends only against *online* guessing, so rely on the unguessable URL token and
  the server's rate-limiting rather than a short passphrase.
