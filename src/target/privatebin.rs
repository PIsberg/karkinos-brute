//! PrivateBin target module.
//!
//! PrivateBin (<https://github.com/PrivateBin/PrivateBin>) is a zero-knowledge
//! pastebin: the browser encrypts the paste *client-side* and the server only
//! ever stores the opaque ciphertext. A paste is addressed by an **id** (in the
//! URL query) and decrypted with a random 256-bit **paste key** that lives only
//! in the **URL fragment** (base58), e.g. `https://host/?<id>#<base58key>`.
//!
//! Crypto (format **v2**, RFC-style, see the project wiki "Encryption format"):
//!   * `paste_passphrase = paste_key_bytes || utf8(password)`  (byte concat)
//!   * `kdf_key = PBKDF2-HMAC-SHA256(paste_passphrase, salt, iterations)`
//!     truncated to `keysize/8` bytes.
//!   * `plaintext = AES-256-GCM-open(ct, key=kdf_key, iv, aad=JSON(adata))`,
//!     then (raw) DEFLATE-inflated when the spec says so.
//!
//! The `adata` array is both the wire metadata *and* the AEAD additional data,
//! so a single wrong byte (or wrong password) fails the GCM tag — which is
//! exactly our correctness oracle, independent of the compression step.
//!
//! **What's attackable.** When there is *no* password the paste key alone (≈256
//! bits, in the link) decrypts it — not brute-forceable, just decrypt directly.
//! The pentest-relevant case, like yopass's custom-password mode, is a paste
//! that *adds* a weak **password** on top of the link: we hold the URL key and
//! recover the password offline against the downloaded ciphertext.
//!
//! ⚠️  PrivateBin pastes can be **burn-after-reading**: fetching one deletes it
//! server-side. Fetch once, save the JSON, crack the saved blob.

use std::io::Read;

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use aes_gcm::Nonce;
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use pbkdf2::pbkdf2_hmac;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

use crate::target::Target;

/// AES-256-GCM with PrivateBin's **16-byte** IV (and the standard 16-byte tag).
/// PrivateBin uses a 128-bit nonce, not the 96-bit GCM fast-path nonce.
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// Where a PrivateBin paste lives, parsed from a share URL or its pieces.
#[derive(Debug, Clone)]
pub struct PasteLocation {
    /// Everything up to (not including) the `?` — e.g. `https://privatebin.net/`
    /// or `https://host/privatebin/` for a sub-path install.
    pub base_url: String,
    /// The paste id (the URL query token).
    pub id: String,
    /// The decoded base58 paste key from the fragment. Always needed to decrypt;
    /// `None` only when built from `--id`/`--message` without a key supplied.
    pub key: Option<Vec<u8>>,
}

impl PasteLocation {
    /// Parse a PrivateBin share URL: `scheme://host[/path]/?<id>#<base58key>`.
    pub fn from_share_url(url: &str) -> Result<Self> {
        let (left, fragment) = url
            .split_once('#')
            .ok_or_else(|| anyhow!("not a PrivateBin share URL (no '#<key>' fragment): {url}"))?;
        let (prefix, query) = left
            .split_once('?')
            .ok_or_else(|| anyhow!("PrivateBin URL has no '?<id>' query: {url}"))?;

        // The id is the first query token (ignore any extra &params the UI adds).
        let id = query.split('&').next().unwrap_or("").trim();
        if id.is_empty() {
            bail!("empty paste id in {url}");
        }
        // The fragment is the base58 key. PrivateBin has historically prefixed it
        // with '-' to flag a format variant; '-' is not in the base58 alphabet, so
        // stripping a single leading one is safe and never corrupts a real key.
        let key_b58 = fragment.trim().trim_start_matches('-');
        let key = decode_paste_key(key_b58)?;

        Ok(Self {
            base_url: prefix.to_string(),
            id: id.to_string(),
            key: Some(key),
        })
    }

    /// Build from an explicit server base + paste id (+ optional base58 key).
    pub fn from_parts(base_url: &str, id: &str, key_b58: Option<&str>) -> Result<Self> {
        let key = match key_b58 {
            Some(k) => Some(decode_paste_key(k.trim().trim_start_matches('-'))?),
            None => None,
        };
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            id: id.to_string(),
            key,
        })
    }

    /// The JSON-API endpoint that returns this paste.
    fn endpoint(&self) -> String {
        format!("{}?{}", self.base_url.trim_end_matches('?'), self.id)
    }
}

/// Decode a base58 paste key (the URL fragment) into raw bytes.
pub fn decode_paste_key(key_b58: &str) -> Result<Vec<u8>> {
    if key_b58.is_empty() {
        bail!("empty paste key in URL fragment");
    }
    let bytes = bs58::decode(key_b58)
        .into_vec()
        .with_context(|| format!("decoding base58 paste key '{key_b58}'"))?;
    // PrivateBin keys are 256-bit; accept that exactly but don't hard-fail other
    // sizes, since the GCM tag check is the real validator.
    if bytes.is_empty() {
        bail!("paste key decoded to zero bytes");
    }
    Ok(bytes)
}

/// Shape of the JSON returned by `GET /?<id>` (a `paste.jsonld` document).
#[derive(Debug, Deserialize)]
struct PasteResponse {
    /// Base64 ciphertext (AES-GCM output: ciphertext || 16-byte tag).
    #[serde(default)]
    ct: String,
    /// Authenticated metadata array; doubles as the AEAD additional data.
    #[serde(default)]
    adata: Value,
    /// 0 = ok. Non-zero (or a `message`) means the server refused / it's gone.
    #[serde(default)]
    status: i64,
    #[serde(default)]
    message: Option<String>,
}

/// Fetch the paste JSON for a location. Returns the raw JSON bytes (suitable for
/// [`PrivatebinTarget::from_paste_json`]) plus whether it looked burn-after-read.
///
/// ⚠️  This can consume burn-after-reading pastes server-side.
pub fn fetch_paste(loc: &PasteLocation) -> Result<(Vec<u8>, bool)> {
    let endpoint = loc.endpoint();
    let resp = ureq::get(&endpoint)
        // Without this header PrivateBin serves the HTML app, not the JSON paste.
        .header("X-Requested-With", "JSONHttpRequest")
        .call()
        .map_err(|e| anyhow::Error::new(e).context(format!("GET {endpoint}")))?;

    let body = resp
        .into_body()
        .read_to_string()
        .context("reading PrivateBin response body")?;
    let parsed: PasteResponse =
        serde_json::from_str(&body).context("decoding PrivateBin paste JSON")?;
    if parsed.status != 0 || parsed.ct.is_empty() {
        bail!(
            "server did not return a paste (status {}{}). For a burn-after-reading \
             link this means it was already viewed or expired.",
            parsed.status,
            parsed.message.map(|m| format!(": {m}")).unwrap_or_default()
        );
    }
    let burn = adata_burn_after_reading(&parsed.adata);
    Ok((body.into_bytes(), burn))
}

/// Read the burn-after-reading flag (adata\[3\]) if present.
fn adata_burn_after_reading(adata: &Value) -> bool {
    adata
        .as_array()
        .and_then(|a| a.get(3))
        .and_then(|v| v.as_i64())
        .map(|v| v != 0)
        .unwrap_or(false)
}

/// An offline PrivateBin cracking target: a parsed paste + the URL key.
///
/// Everything expensive-to-parse is done once in [`Self::from_paste_json`]; the
/// per-candidate hot path is PBKDF2 + one AES-GCM open.
pub struct PrivatebinTarget {
    /// The 256-bit paste key from the URL (the fixed prefix of the KDF input).
    key: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
    /// Derived-key length in bytes (keysize/8 — 32 for AES-256).
    keylen: usize,
    /// Ciphertext concatenated with the 16-byte GCM tag.
    ct: Vec<u8>,
    /// AEAD additional data: the canonical `JSON.stringify(adata)` bytes.
    aad: Vec<u8>,
    /// Compression spec: `"zlib"` (raw DEFLATE) or `"none"`.
    compression: String,
    name: String,
}

impl PrivatebinTarget {
    /// Build from a paste JSON document (as returned by the API or saved to disk)
    /// and the base58-decoded paste key.
    pub fn from_paste_json(paste_json: &[u8], key: Vec<u8>) -> Result<Self> {
        let doc: Value =
            serde_json::from_slice(paste_json).context("parsing PrivateBin paste JSON")?;

        let ct_b64 = doc
            .get("ct")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("paste JSON has no string 'ct' field"))?;
        let ct = B64
            .decode(ct_b64)
            .context("base64-decoding ciphertext 'ct'")?;

        let adata = doc
            .get("adata")
            .ok_or_else(|| anyhow!("paste JSON has no 'adata' field"))?;
        // The AEAD additional data is the *canonical* JSON serialization of adata
        // (compact, no spaces) — byte-for-byte what the browser's JSON.stringify
        // produced. serde_json's compact form matches it.
        let aad = serde_json::to_vec(adata).context("re-serializing adata for AAD")?;

        let spec = adata
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("adata[0] (cipher spec) is missing or not an array"))?;
        if spec.len() < 8 {
            bail!("adata[0] cipher spec has too few fields ({})", spec.len());
        }

        let iv = B64
            .decode(
                spec[0]
                    .as_str()
                    .ok_or_else(|| anyhow!("spec iv not a string"))?,
            )
            .context("base64-decoding IV")?;
        let salt = B64
            .decode(
                spec[1]
                    .as_str()
                    .ok_or_else(|| anyhow!("spec salt not a string"))?,
            )
            .context("base64-decoding salt")?;
        let iterations: u32 = spec[2]
            .as_u64()
            .ok_or_else(|| anyhow!("spec iterations not an integer"))?
            as u32;
        let keysize: usize = spec[3]
            .as_u64()
            .ok_or_else(|| anyhow!("spec keysize not an integer"))?
            as usize;
        let tagbits: u64 = spec[4].as_u64().unwrap_or(0);
        let cipher = spec[5].as_str().unwrap_or("");
        let mode = spec[6].as_str().unwrap_or("");
        let compression = spec[7].as_str().unwrap_or("none").to_string();

        // Validate the one combination we implement. These are structural facts
        // of the blob (true for every candidate), so a mismatch is fatal, not a
        // miss — mirroring the Target contract.
        if cipher != "aes" || mode != "gcm" {
            bail!("unsupported PrivateBin cipher '{cipher}/{mode}' (only aes/gcm)");
        }
        if keysize != 256 {
            bail!("unsupported PrivateBin key size {keysize} (only 256)");
        }
        if tagbits != 128 {
            bail!("unsupported PrivateBin tag size {tagbits} (only 128)");
        }
        if iv.len() != 16 {
            bail!("unexpected PrivateBin IV length {} (expected 16)", iv.len());
        }

        Ok(Self {
            key,
            iv,
            salt,
            iterations,
            keylen: keysize / 8,
            ct,
            aad,
            compression,
            name: "privatebin".to_string(),
        })
    }

    /// Try one password. `Ok(Some(plaintext))` on success (the GCM tag verified),
    /// `Ok(None)` on a clean miss, `Err` only for structural problems.
    fn attempt(&self, password: &[u8]) -> Result<Option<Vec<u8>>> {
        // KDF input = paste_key || password (byte concatenation).
        let mut kdf_input = Vec::with_capacity(self.key.len() + password.len());
        kdf_input.extend_from_slice(&self.key);
        kdf_input.extend_from_slice(password);

        let mut derived = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            &kdf_input,
            &self.salt,
            self.iterations,
            &mut derived[..self.keylen],
        );

        let cipher = Aes256Gcm16::new_from_slice(&derived[..self.keylen])
            .map_err(|_| anyhow!("derived key length invalid"))?;
        let nonce = Nonce::<U16>::try_from(self.iv.as_slice())
            .map_err(|_| anyhow!("IV must be 16 bytes, got {}", self.iv.len()))?;
        match cipher.decrypt(
            &nonce,
            Payload {
                msg: &self.ct,
                aad: &self.aad,
            },
        ) {
            // Tag verified ⇒ correct password. Decompress for the readable secret.
            Ok(plain) => Ok(Some(decompress(&plain, &self.compression))),
            // Tag mismatch ⇒ wrong password. The common case.
            Err(_) => Ok(None),
        }
    }
}

impl Target for PrivatebinTarget {
    fn try_candidate(&self, candidate: &[u8]) -> Result<Option<Vec<u8>>> {
        self.attempt(candidate)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Inflate a recovered plaintext per the paste's compression spec.
///
/// PrivateBin's `"zlib"` is, despite the name, **raw DEFLATE** (no zlib header) —
/// matching `pako.deflateRaw` in the browser. We try raw DEFLATE first, fall back
/// to zlib-wrapped (older/odd encoders), and finally return the bytes unchanged.
/// Because the GCM tag has already proven the password, this step only affects
/// readability of the result, never the crack decision.
fn decompress(data: &[u8], compression: &str) -> Vec<u8> {
    if compression == "none" {
        return data.to_vec();
    }
    let mut out = Vec::new();
    if DeflateDecoder::new(data).read_to_end(&mut out).is_ok() {
        return out;
    }
    out.clear();
    if ZlibDecoder::new(data).read_to_end(&mut out).is_ok() {
        return out;
    }
    data.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_share_url() {
        let loc = PasteLocation::from_share_url(
            "https://privatebin.net/?abc123def#Cvh7cQjy9y4bQFopRJ61BJVRSJLq92wLt85Kdt7eXAF",
        )
        .unwrap();
        assert_eq!(loc.base_url, "https://privatebin.net/");
        assert_eq!(loc.id, "abc123def");
        assert_eq!(loc.key.as_ref().unwrap().len(), 32);
        assert_eq!(loc.endpoint_for_test(), "https://privatebin.net/?abc123def");
    }

    #[test]
    fn parse_subpath_and_strip_dash() {
        let loc = PasteLocation::from_share_url(
            "https://host.example/paste/?deadbeef#-Cvh7cQjy9y4bQFopRJ61BJVRSJLq92wLt85Kdt7eXAF",
        )
        .unwrap();
        assert_eq!(loc.base_url, "https://host.example/paste/");
        assert_eq!(loc.id, "deadbeef");
        assert!(loc.key.is_some());
    }

    #[test]
    fn reject_url_without_fragment() {
        assert!(PasteLocation::from_share_url("https://privatebin.net/?abc123").is_err());
    }

    #[test]
    fn decompress_roundtrip_raw_deflate() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"hello privatebin").unwrap();
        let compressed = enc.finish().unwrap();
        assert_eq!(decompress(&compressed, "zlib"), b"hello privatebin");
    }

    #[test]
    fn decompress_none_is_identity() {
        assert_eq!(decompress(b"plain", "none"), b"plain");
    }

    impl PasteLocation {
        fn endpoint_for_test(&self) -> String {
            self.endpoint()
        }
    }
}
