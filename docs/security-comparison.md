# Which target is harder to crack? (yopass vs PrivateBin)

A comparison of the two bundled targets *from a crackability standpoint* — i.e.
how well each service resists an offline attacker trying to recover a weak,
human-chosen password. Both services hide a strong random key somewhere and (in
the relevant mode) layer a human password on top; the password is the only thing
ever worth brute-forcing. So the question splits into two independent axes:

1. **Cost per guess** — how expensive is one password attempt (the KDF work factor)?
2. **Can the attack be mounted at all** — what does an attacker need to *have*
   before per-guess cost even matters (the threat model / where the key lives)?

**TL;DR — PrivateBin is the stronger of the two.** The per-guess cost is roughly
equal (yopass is marginally higher), but PrivateBin wins decisively on the threat
model: its 256-bit key lives only in the URL fragment and never reaches the
server, so a stolen/leaked ciphertext is uncrackable *regardless of password
strength*, and its default paste has no crackable password at all. yopass's
custom-password mode makes the password the **sole** secret, so the stored blob
alone is offline-crackable whenever that password is weak.

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

## Overall verdict

**PrivateBin has the best security from a crackable perspective.**

- **Axis 1 (per-guess cost): ~tie**, marginal edge to yopass (~1,140 vs ~1,000
  guesses/sec; neither memory-hard).
- **Axis 2 (threat model): PrivateBin wins clearly** — the high-entropy key never
  reaches the server, so a leaked ciphertext is uncrackable regardless of password
  strength, and the default paste exposes no password at all. yopass `/c/` makes a
  weak password the single point of failure against anyone holding the blob.

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
