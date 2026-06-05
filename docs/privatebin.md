# PrivateBin target

[PrivateBin](https://github.com/PrivateBin/PrivateBin) is a zero-knowledge
pastebin: the browser encrypts client-side and the server stores only ciphertext.
A paste is addressed by an **id** (URL query) and decrypted with a random 256-bit
**paste key** that lives in the URL **fragment** (base58):
`https://privatebin.net/?<id>#<base58key>`.

Source: [`src/target/privatebin.rs`](../src/target/privatebin.rs).

## Crypto (format v2)

```
key  = paste_key ‖ utf8(password)              (byte concatenation)
kdf  = PBKDF2-HMAC-SHA256(key, salt, 100_000)  (8-byte salt, 256-bit output)
text = AES-256-GCM-open(ct, kdf, iv, aad)       (16-byte IV, 128-bit tag)
       then raw-DEFLATE inflate if compression = "zlib"
aad  = JSON(adata)                              (the metadata array, verbatim)
```

The `adata` array is both the wire metadata *and* the AEAD additional data, so a
single wrong byte — or a wrong password — fails the GCM tag. That tag check is
the crack oracle, so a wrong password is a clean **miss** (`Ok(None)`), never a
fatal error — exactly the [`Target`](../src/target/mod.rs) contract. Compression
only affects the readability of the recovered plaintext, never the decision.

> PrivateBin's `"zlib"` compression is, despite the name, **raw DEFLATE** (no
> zlib header) — matching `pako.deflateRaw` in the browser.

## What's attackable

With no password the paste key alone (in the link, ~256 bits) decrypts the
paste — nothing to brute-force, just decrypt directly. The pentest-relevant case,
like yopass's custom-password mode, is a paste that *adds* a weak **password** on
top of the link: you hold the URL key and recover the password offline against
the downloaded ciphertext.

> ⚠️ PrivateBin pastes can be **burn-after-reading**: fetching one deletes it
> server-side. Fetch once, save the JSON, crack the saved blob.

## Usage

```sh
# Crack a password-protected paste (the URL carries the key; brute the password):
bruteforcer privatebin crack \
  --url "https://privatebin.net/?<id>#<base58key>" \
  --charset digits --min 1 --max 6

# Or fetch once, then crack the saved blob offline:
bruteforcer privatebin fetch --url "https://privatebin.net/?<id>#<key>" -o paste.json
bruteforcer privatebin crack --message paste.json --key <base58key> --wordlist rockyou.txt

# Self-hosted / sub-path install by id + server:
bruteforcer privatebin crack --id <id> --server https://host/paste/ --key <base58key> \
  --wordlist rockyou.txt
```

The recovered secret is PrivateBin's inner message JSON (`{"paste":"..."}`).
Candidate flags (`--wordlist` / `--charset` / `--charset-raw`, `--min`/`--max`)
and `--threads` / `--no-progress` / `--out` work the same as for yopass.

## Testing

The known-answer test ([`tests/privatebin.rs`](../tests/privatebin.rs)) is fully
**offline**: it `include_str!`s a static fixture
([`tests/fixtures/privatebin_v2_gcm.json`](../tests/fixtures/privatebin_v2_gcm.json))
and never touches the network or runs Node. The fixture is a real PrivateBin v2
paste document plus an `answer` block (base58 key, password, expected plaintext).

It was generated **once** by
[`scripts/privatebin_vector.mjs`](../scripts/privatebin_vector.mjs) using **Node's
WebCrypto** — the same Web Crypto API PrivateBin's browser code uses, but an
implementation independent of this crate. So the test proves our Rust matches
PrivateBin's crypto (including raw-DEFLATE), without re-deriving anything from our
own code. To regenerate it:

```sh
node scripts/privatebin_vector.mjs > tests/fixtures/privatebin_v2_gcm.json
```

[`scripts/privatebin_create.mjs`](../scripts/privatebin_create.mjs) is a separate
helper that creates a *live* paste on a chosen instance for manual end-to-end
testing — it is **not** part of `cargo test`.
