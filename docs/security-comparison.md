# Which target is hardest to crack? (yopass vs PrivateBin vs PasswordPusher vs OneTimeSecret vs dele.to)

A comparison of the five bundled targets *from a crackability standpoint* — how
well each service resists an attacker trying to recover a weak, human-chosen
password/passphrase.

The cleanest way to organize them is **what an offline attacker can crack, and
from what**:

- **yopass and PrivateBin are zero-knowledge** (encrypt client-side; the password
  feeds a KDF into the decryption key). The offline attack uses the **downloaded
  ciphertext**: crack the password locally, no further server contact.
- **OneTimeSecret is server-side-trust for the *value*, but stores the passphrase
  as a real password hash.** The value can't be cracked offline (it's encrypted
  under a server-held global secret), but the passphrase **hash** — Argon2id or
  legacy bcrypt — *is* an offline-crackable artifact, obtained from a database/Redis
  dump rather than the share URL.
- **PasswordPusher is server-side-trust with no crackable hash at all** (encrypts
  at rest under a server key; the passphrase is a plaintext server-side string
  compare). There is **no offline artifact** — the only attack is **online**.
- **dele.to is zero-knowledge for the *value* (key in the URL fragment, like
  PrivateBin), but its optional password is a separate, server-side gate** — and
  the weakest one here, attackable *two* ways. **Offline:** a dumped `passwordHash`
  (a non-KDF `base64(password‖salt)` with a public default salt) is essentially
  **reversible**, not just brute-forceable. **Online:** a live test showed the
  server-side password check is **unthrottled and burns no view on a wrong guess**,
  so a *leaked link alone* lets you brute-force a weak password over HTTP for free,
  then decrypt with the in-URL key — no store dump needed.

So four of the five expose something offline-crackable and are compared on two
axes; PasswordPusher has neither and is analysed separately:

1. **Cost per guess** — how expensive is one attempt (the KDF / hash work factor)?
2. **Can the attack be mounted at all** — what must an attacker *have* before
   per-guess cost even matters (the threat model / where the secret material lives)?

**TL;DR.**
- **Per-guess cost (Axis 1): OneTimeSecret wins by orders of magnitude.** Its
  Argon2id passphrase hash is **memory-hard** (~64 MiB/guess in production),
  defeating the GPU/ASIC acceleration that makes yopass's and PrivateBin's plain
  SHA-256 KDFs cheap. yopass and PrivateBin are a near-tie (yopass marginally
  higher); legacy-bcrypt OneTimeSecret still beats both. **dele.to is dead last:**
  its `base64(password‖salt)` isn't a hash function at all (O(1), no work factor),
  and with the public default salt it's directly reversible rather than searched.
- **Threat model (Axis 2): PrivateBin is strongest among the URL-shareable pair** —
  its 256-bit key never reaches the server, so a leaked ciphertext is uncrackable
  regardless of password, and the default paste has no crackable password at all.
- **PasswordPusher is a category apart**: nothing is offline-crackable, a real
  strength against a data thief, but bought by trusting the server (which can read
  every secret) and reducing any passphrase attack to a noisy, logged,
  rate-limited *online* one.
- **OneTimeSecret's catch:** the thing you crack (the passphrase hash) is only
  obtainable *after* compromising the store — so although it's the hardest per
  guess, the attacker already needed deep access to get the hash in the first place.

## Axis 1 — Cost per guess (KDF / hash work factor)

yopass and PrivateBin use **SHA-256-based** KDFs of similar total work;
OneTimeSecret uses a **memory-hard Argon2id** (or legacy bcrypt) and is in a
different league:

| | yopass (`/c/`) | PrivateBin (pw mode) | OneTimeSecret (passphrase hash) | dele.to (password hash) |
|---|---|---|---|---|
| KDF / hash | OpenPGP **S2K**, SHA-256 | **PBKDF2-HMAC-SHA256** | **Argon2id** (current) / bcrypt (legacy) | **none** — `base64(password‖salt)` |
| Work factor (default) | 16,777,216 octets ≈ **262k** SHA-256 blocks/guess | 100,000 iters ≈ **200k** SHA-256 blocks/guess | **64 MiB memory + t=2**/guess (Argon2id) | **O(1)** — one base64 encode, no iteration |
| Measured rate¹ | **~1,140 g/s** | **~1,000 g/s** | orders of magnitude slower (memory-bound) | effectively **instant** (reversible, see below) |
| Memory-hard? | No | No | **Yes** (Argon2id) / No (bcrypt) | No |
| GPU/ASIC-acceleratable? | Yes (a GPU S2K backend ships here) | Yes | **Largely no** (Argon2id is designed to resist it) | Moot — no search needed |

¹ Reference machine, release build, 16 threads. yopass measured against a real
v6 secret; PrivateBin by exhausting 100,000 candidates against the committed test
fixture. OneTimeSecret isn't given a single rate because it's set by the hash's
own cost parameters (production Argon2id at 64 MiB/guess is dramatically slower and,
crucially, *can't* be sped up much with a GPU).

**Verdict on Axis 1: OneTimeSecret wins decisively; yopass and PrivateBin are a
near-tie behind it.** yopass and PrivateBin sit in the same order of magnitude
(~10⁵–10⁶ SHA-256 compressions/guess, within ~15 % of each other, slight edge to
yopass) and — crucially — **neither is memory-hard**, so both are linearly
accelerated by GPUs/ASICs; only password entropy really defends them. OneTimeSecret's
Argon2id is **memory-hard by design**: the 64 MiB working set throttles parallel
hardware, so per-guess cost is itself a meaningful defense, not just entropy. Even
legacy bcrypt OneTimeSecret (adaptive, though not memory-hard) is slower per guess
than either SHA-256 KDF. **dele.to is the floor:** its `base64(password‖salt)` is
not a password hash at all — no iteration, no work factor — so per-guess cost is
zero defense. Worse, with the public default salt it doesn't even require a search:
`base64_decode(passwordHash)` *is* `password‖salt`, so you strip the salt and read
the password off directly.

Concretely, at ~1,000–1,140 guesses/sec a 6-character lowercase password
(26⁶ ≈ 3.1×10⁸) takes ~3 days to exhaust on this one machine against *yopass or
PrivateBin* — and far less in expectation or on a GPU. Against production-cost
OneTimeSecret Argon2id the same keyspace is effectively out of reach on one
machine, and a GPU barely helps. See the
[yopass timing table](yopass.md#how-long-does-it-take) for the SHA-256 grid;
PrivateBin is within ~15 % of it, OneTimeSecret far above it.

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

## OneTimeSecret — hardest per guess, but the hash is the catch

OneTimeSecret is a **hybrid**: server-side-trust for the secret value, but the
passphrase is a real, offline-crackable password hash.

- **Value:** encrypted **server-side** under the instance global secret (with the
  passphrase mixed in). Like PasswordPusher, a stolen ciphertext row is not
  decryptable without the server's key — and the server *can* read secrets, so you
  trust the operator.
- **Passphrase:** stored as **Argon2id** (current) or **bcrypt** (legacy) and
  verified on retrieval. That hash *is* offline-crackable — but you only get it by
  **dumping the store** (Redis/DB), not from the share URL.

| | OneTimeSecret (passphrase) |
|---|---|
| Per-guess cost (Axis 1) | **Highest of all targets** — Argon2id is memory-hard (~64 MiB/guess), GPU-resistant |
| What the attacker must already have (Axis 2) | the **passphrase hash** — i.e. prior **store compromise** (not just the link) |
| Stolen ciphertext alone crackable? | **No** — value is under the server's global secret |
| Stolen hash crackable (weak passphrase)? | **Yes, but slowly** — memory-hard cost buys real time |

So OneTimeSecret inverts the usual trade-off. On **Axis 1** it's the strongest by a
wide margin: even with the hash in hand, a memory-hard Argon2id makes brute force
genuinely expensive, so per-guess cost — not just entropy — defends a weak
passphrase (within reason). But on **Axis 2** the bar to *start* is high: the hash
only exists server-side, so an attacker needs to have already breached the store.
An attacker who only has the share link has nothing to crack offline at all; one
who has dumped the database faces the hardest hash here. Our
[`onetimesecret`](onetimesecret.md) target operates on that dumped hash.

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

## dele.to — zero-knowledge value, but the weakest password hash here

dele.to is another **hybrid**, but the mirror image of OneTimeSecret. It is
**zero-knowledge for the value** (AES-256-GCM under a random 256-bit key in the
URL `#fragment`, withheld from the server — PrivateBin's strong posture), yet its
optional password is stored as the **weakest hash of any target**.

- **Value:** encrypted client-side; the key lives in the URL fragment and never
  reaches the server. A stolen blob is uncrackable without the link, exactly like
  PrivateBin's default. This part is genuinely strong.
- **Password:** *not* a KDF input and *not* mixed into the AES key. It's a
  **separate server-side check**: `passwordHash = base64(password ‖ salt)`, with
  `salt` defaulting to the literal `"default-salt-change-in-production"`. There is
  no iteration, no work factor, no memory hardness — and base64 is invertible, so
  given the hash and the (usually default) salt the password falls out directly.

| | dele.to (password) |
|---|---|
| Per-guess cost (Axis 1) | **Lowest of all targets** — `base64(password‖salt)`, O(1), reversible |
| Offline path — what you need | the **passwordHash** (a store dump); then decode base64, strip the salt — no real search |
| Online path — what you need | **just the leaked link** (it carries the AES key); then guess the password against the server |
| Stolen ciphertext alone crackable? | **No** — the AES key is in the URL fragment, never on the server |
| Stolen hash crackable (weak password)? | **Yes, trivially** |

So dele.to inverts OneTimeSecret on **Axis 1** — OneTimeSecret has the most
expensive per-guess cost of any target, dele.to the cheapest by far — but a live
test (see [`docs/deleto.md`](deleto.md#findings-from-a-live-test-the-realistic-attack-is-online))
showed **Axis 2 is also weak, and in a way the offline framing understates.** The
value is gated behind the password *server-side*, so even with the in-URL key you
must clear that gate first; but dele.to's password oracle is **online, unthrottled,
and view-free on failure** — a wrong guess returns "Incorrect password", burns no
view, and triggers no rate-limit or lockout. So an attacker with **only a leaked
link** can brute-force a weak password over HTTP at near-offline speed, then
decrypt locally with the key the link already carries. No store dump required.

The upshot: dele.to's zero-knowledge key-in-URL only defends against a server/DB
compromise (the server never sees the key) — it does **nothing** once the link
leaks, because the link *is* the key, and the password meant to backstop that is
both trivially hashed *and* online-guessable for free. Our [`deleto`](deleto.md)
target implements **both** paths: `deleto crack` for the **offline** dumped
`passwordHash`, and `deleto online` for the realistic **online** attack on a live
share (same shape as [`pwpush`](pwpush.md): one request per candidate, then
AES-256-GCM-decrypt the value with the URL-fragment key).

## Overall verdict

**There's no single winner — it depends which question you ask.** Each target is
"strongest" on a different axis:

- **Hardest per guess → OneTimeSecret.** Memory-hard Argon2id (~64 MiB/guess)
  makes even a recovered hash expensive to attack and GPU-resistant — the only
  target where per-guess cost, not just entropy, is a real defense. Caveat: you
  only get that hash by compromising the store first.
- **Hardest to even start an offline attack → PasswordPusher**, then **PrivateBin**.
  PasswordPusher exposes *no* offline-crackable artifact at all (server-side
  encryption, passphrase compared online); PrivateBin exposes a blob but withholds
  the 256-bit key, so a leaked ciphertext is uncrackable regardless of password.
- **Weakest *password hash* → dele.to.** `base64(password‖salt)` is not a hash
  function — O(1), no work factor, and reversible under the public default salt.
  Once the `passwordHash` leaks it offers essentially no resistance. (Its *value*,
  though, is well protected — the AES key is withheld in the URL fragment.)
- **Weakest *value exposure* → yopass `/c/`.** A weak custom password is the
  **sole** secret on the downloaded blob, with a non-memory-hard KDF —
  offline-crackable by anyone who holds the ciphertext (no store dump needed).

Per axis:

- **Axis 1 (per-guess cost): OneTimeSecret ≫ bcrypt-OneTimeSecret > yopass ≳
  PrivateBin ≫ dele.to.** The two SHA-256 KDFs are a near-tie (marginal edge to
  yopass, ~1,140 vs ~1,000 g/s, neither memory-hard); Argon2id is in a different
  league above them, and dele.to's non-KDF base64 is in a different league below.
- **Axis 2 (can the attack be mounted): PasswordPusher (nothing offline) >
  PrivateBin (key withheld) > OneTimeSecret (needs a store dump) > yopass `/c/`
  (the blob is enough) > dele.to (a leaked link is enough).** dele.to looks
  store-dump-gated like OneTimeSecret if you only count the *offline* hash crack,
  but a live test showed its password oracle is **online, unthrottled, and
  view-free on failure** — so a leaked link alone lets you online-guess a weak
  password for free and then decrypt with the in-URL key. That makes it the
  *easiest to mount* of all, not the hardest.
- **The trust trade-off:** OneTimeSecret and PasswordPusher buy their strength by
  letting the **server read your secret**; yopass and PrivateBin don't. "Hardest to
  crack" is not the same as "best" — a zero-knowledge design with a strong key
  (PrivateBin default / yopass `/s/`) keeps the operator out entirely.

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
- **OneTimeSecret** gives the best per-guess protection *if* a passphrase hash
  leaks (memory-hard Argon2id), so a passphrase here survives much more than a
  yopass/PrivateBin password would against the same hardware — but it's still only
  as strong as the passphrase, and the operator can read the value regardless.
  Operators should ensure current Argon2id (not legacy bcrypt) is in use and that
  the global secret and Redis store are well protected, since the passphrase hash
  becomes crackable the moment the store is dumped.
