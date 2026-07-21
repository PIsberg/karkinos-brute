//! Manual decode + verification for an OpenPGP **v6 SKESK** (RFC 9580), the
//! format current yopass produces. This is deliberately independent of sequoia:
//!   * it is the verification oracle the GPU backend reproduces, and
//!   * it exposes the S2K so the GPU can compute the expensive part.
//!
//! Verification chain for a candidate passphrase `p`:
//!   1. `kek_s2k = SHA256( first <count> octets of (salt || p) repeated )`
//!   2. `kek = HKDF-SHA256(ikm = kek_s2k, salt = "", info = aad)` truncated to
//!      the cipher key length.
//!   3. AEAD-open the packet's encrypted session key with `kek`, nonce = IV,
//!      additional data = `aad = [0xC3, version, cipher_algo, aead_algo]`.
//!
//!   A correct passphrase makes the AEAD tag verify; a wrong one fails it.
//!
//! Only the combination current yopass uses is handled here: **AES-256 + GCM**.
//! Anything else returns [`UnsupportedSkesk`] so callers fall back to sequoia.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Result};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use std::io::Read;

/// Cipher / AEAD ids we implement on the fast path.
const CIPHER_AES256: u8 = 9;
const AEAD_GCM: u8 = 3;

/// The combination present in this message isn't on the manual fast path.
#[derive(Debug)]
pub struct UnsupportedSkesk(pub String);
impl std::fmt::Display for UnsupportedSkesk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported SKESK for fast path: {}", self.0)
    }
}
impl std::error::Error for UnsupportedSkesk {}

/// A parsed v6 SKESK with everything needed to test a passphrase.
#[derive(Debug, Clone)]
pub struct SkeskV6 {
    pub salt: [u8; 8],
    /// Decoded S2K octet count (number of octets of `salt||pass` to hash).
    pub count: u32,
    /// AEAD additional data: `[0xC3, 6, cipher, aead]`.
    pub aad: [u8; 4],
    /// AEAD nonce/IV from the packet (12 bytes for GCM).
    pub iv: Vec<u8>,
    /// Encrypted session key followed by the AEAD tag (48 bytes for AES-256/GCM).
    pub esk: Vec<u8>,
}

impl SkeskV6 {
    /// Parse the first SKESK packet out of an armored/binary OpenPGP message.
    ///
    /// Returns `Err(UnsupportedSkesk)` (downcastable) for v4 SKESK, non-AES-256,
    /// or non-GCM messages so the caller can fall back to the sequoia path.
    pub fn parse(message: &[u8]) -> Result<Self> {
        // Dearmor (if needed) and grab the first packet's raw bytes. We re-parse
        // the body ourselves because sequoia 2.x surfaces v6 SKESK as Unknown.
        let body = first_skesk_body(message)?;

        // body = version(1) | param_count(1) | cipher(1) | aead(1) | s2k_len(1)
        //        | s2k(s2k_len) | iv(iv_len) | enc_session_key+tag(rest)
        if body.len() < 5 {
            bail!("SKESK packet too short");
        }
        let version = body[0];
        if version != 6 {
            return Err(UnsupportedSkesk(format!("SKESK version {version} (only v6)")).into());
        }
        let param_count = body[1] as usize;
        let cipher = body[2];
        let aead = body[3];
        let s2k_len = body[4] as usize;

        if cipher != CIPHER_AES256 {
            return Err(UnsupportedSkesk(format!("cipher algo {cipher} (only AES-256=9)")).into());
        }
        if aead != AEAD_GCM {
            return Err(UnsupportedSkesk(format!("AEAD algo {aead} (only GCM=3)")).into());
        }

        let s2k_start = 5;
        let s2k_end = s2k_start + s2k_len;
        if body.len() < s2k_end {
            bail!("SKESK truncated in S2K");
        }
        let s2k = &body[s2k_start..s2k_end];
        // S2K: type(1) | hash(1) | salt(8) | count_byte(1)  (iterated+salted)
        if s2k.len() < 11 || s2k[0] != 3 {
            return Err(UnsupportedSkesk(format!(
                "S2K type {} (only iterated+salted=3)",
                s2k.first().copied().unwrap_or(0)
            ))
            .into());
        }
        if s2k[1] != 8 {
            return Err(UnsupportedSkesk(format!("S2K hash {} (only SHA-256=8)", s2k[1])).into());
        }
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&s2k[2..10]);
        let count = decode_s2k_count(s2k[10]);

        // IV length = param_count - (cipher + aead + s2k_len_octet + s2k bytes).
        let iv_len = param_count
            .checked_sub(1 + 1 + 1 + s2k_len)
            .ok_or_else(|| anyhow::anyhow!("bad SKESK param count"))?;
        let iv_start = s2k_end;
        let iv_end = iv_start + iv_len;
        if body.len() < iv_end {
            bail!("SKESK truncated in IV");
        }
        let iv = body[iv_start..iv_end].to_vec();
        let esk = body[iv_end..].to_vec();

        Ok(Self {
            salt,
            count,
            aad: [0xC3, version, cipher, aead],
            iv,
            esk,
        })
    }

    /// Derive the S2K key for a passphrase: SHA-256 over `count` octets of
    /// `salt || passphrase` repeated. This is the expensive step (16 MiB by
    /// default) and is exactly what the GPU backend reproduces.
    pub fn s2k(&self, passphrase: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        let unit_len = self.salt.len() + passphrase.len();
        let mut fed = 0usize;
        let count = self.count as usize;
        // Build the repeated (salt||pass) stream a unit at a time, truncating the
        // final unit so exactly `count` octets are hashed.
        while fed < count {
            let remaining = count - fed;
            if remaining >= unit_len {
                h.update(self.salt);
                h.update(passphrase);
                fed += unit_len;
            } else if remaining >= self.salt.len() {
                h.update(self.salt);
                h.update(&passphrase[..remaining - self.salt.len()]);
                fed = count;
            } else {
                h.update(&self.salt[..remaining]);
                fed = count;
            }
        }
        h.finalize().into()
    }

    /// Full verification of a passphrase given its already-computed S2K output
    /// (so the GPU path can feed in GPU-derived keys). Returns the recovered
    /// session key on success.
    pub fn verify_with_s2k(&self, s2k_key: &[u8; 32]) -> Option<Vec<u8>> {
        // HKDF-SHA256 expand the S2K output to the AES-256 key length.
        let hk = Hkdf::<Sha256>::new(None, s2k_key);
        let mut kek = [0u8; 32];
        hk.expand(&self.aad, &mut kek).ok()?;

        let cipher = Aes256Gcm::new((&kek).into());
        let nonce = Nonce::try_from(self.iv.as_slice()).ok()?;
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &self.esk,
                    aad: &self.aad,
                },
            )
            .ok()
    }

    /// Convenience: derive + verify in one call (the CPU reference path).
    pub fn verify(&self, passphrase: &[u8]) -> Option<Vec<u8>> {
        self.verify_with_s2k(&self.s2k(passphrase))
    }
}

/// Decode an OpenPGP S2K count byte into the octet count (RFC 4880 §3.7.1.3).
fn decode_s2k_count(c: u8) -> u32 {
    (16u32 + (c as u32 & 15)) << ((c >> 4) as u32 + 6)
}

/// Dearmor if necessary and return the body bytes of the first SKESK packet.
///
/// We deliberately do our own OpenPGP packet framing instead of using sequoia's
/// packet parser, which mishandles v6 SKESK. sequoia is used only to dearmor.
fn first_skesk_body(message: &[u8]) -> Result<Vec<u8>> {
    let binary = dearmor(message)?;
    let mut i = 0usize;
    while i < binary.len() {
        let (tag, body_start, body_len, next) = parse_packet_header(&binary, i)?;
        let end = body_start + body_len;
        if end > binary.len() {
            bail!("packet body runs past end of message");
        }
        if tag == 3 {
            // SKESK
            return Ok(binary[body_start..end].to_vec());
        }
        i = if next > i { next } else { end };
    }
    bail!("no SKESK packet found")
}

/// ASCII-armored? Use sequoia's armor reader. Otherwise treat as binary.
fn dearmor(message: &[u8]) -> Result<Vec<u8>> {
    let head = &message[..message.len().min(64)];
    let looks_armored = head.windows(14).any(|w| w == b"-----BEGIN PGP");
    if !looks_armored {
        return Ok(message.to_vec());
    }
    use sequoia_openpgp::armor::{Reader, ReaderMode};
    let mut r = Reader::from_bytes(message, ReaderMode::Tolerant(None));
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}

/// Parse an OpenPGP packet header at `i`. Returns
/// `(tag, body_start, body_len, next_packet_index)`. Handles new- and old-format
/// headers; partial body lengths are not expected for an SKESK and are rejected.
fn parse_packet_header(buf: &[u8], i: usize) -> Result<(u8, usize, usize, usize)> {
    if i >= buf.len() {
        bail!("packet header past end");
    }
    let o = buf[i];
    if o & 0x80 == 0 {
        bail!("not an OpenPGP packet (bit 7 clear)");
    }
    if o & 0x40 != 0 {
        // New format: tag = low 6 bits, then a length encoding.
        let tag = o & 0x3f;
        let p = i + 1;
        if p >= buf.len() {
            bail!("truncated new-format length");
        }
        let l0 = buf[p];
        let (len, hdr) = if l0 < 192 {
            (l0 as usize, 1)
        } else if l0 < 224 {
            let l1 = *buf
                .get(p + 1)
                .ok_or_else(|| anyhow::anyhow!("truncated length"))?;
            ((((l0 as usize - 192) << 8) + l1 as usize + 192), 2)
        } else if l0 == 255 {
            let b = buf
                .get(p + 1..p + 5)
                .ok_or_else(|| anyhow::anyhow!("truncated 5-octet length"))?;
            (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 5)
        } else {
            bail!("partial body lengths not supported for SKESK");
        };
        let body_start = p + hdr;
        Ok((tag, body_start, len, body_start + len))
    } else {
        // Old format: tag = bits 5..2, length type = low 2 bits.
        let tag = (o & 0x3c) >> 2;
        let lt = o & 0x03;
        let p = i + 1;
        let (len, hdr) = match lt {
            0 => (
                *buf.get(p).ok_or_else(|| anyhow::anyhow!("trunc"))? as usize,
                1,
            ),
            1 => {
                let b = buf.get(p..p + 2).ok_or_else(|| anyhow::anyhow!("trunc"))?;
                (u16::from_be_bytes([b[0], b[1]]) as usize, 2)
            }
            2 => {
                let b = buf.get(p..p + 4).ok_or_else(|| anyhow::anyhow!("trunc"))?;
                (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 4)
            }
            _ => bail!("indeterminate-length old-format packet not supported"),
        };
        let body_start = p + hdr;
        Ok((tag, body_start, len, body_start + len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vector captured from a live yopass v6 secret:
    //   passphrase "bHwcaWjaiHr96xZ3yZWQmh" -> plaintext "fasfd".
    const SALT: [u8; 8] = [0x0d, 0x61, 0x6c, 0x38, 0xca, 0x32, 0x62, 0x4b];
    const IV: &str = "a597e509239678591f721047";
    const ESK: &str = "c88ffff7b19da6eb7d9cb03e6c8b4976c813f2bb39a2cfe7287d094fa5dd207ae47e0ff74220b716f0688b48e3f4e067";

    fn vector() -> SkeskV6 {
        SkeskV6 {
            salt: SALT,
            count: 16_777_216,
            aad: [0xC3, 6, 9, 3],
            iv: hex(IV),
            esk: hex(ESK),
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn s2k_matches_reference() {
        let v = vector();
        let got = v.s2k(b"bHwcaWjaiHr96xZ3yZWQmh");
        assert_eq!(
            hex("44bbcedf1621ae65ab1f89e3ba3f238469323d38c9e92c43967aa97568c79500"),
            got.to_vec()
        );
    }

    #[test]
    fn correct_passphrase_verifies() {
        let v = vector();
        assert!(v.verify(b"bHwcaWjaiHr96xZ3yZWQmh").is_some());
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let v = vector();
        assert!(v.verify(b"wrong-password").is_none());
        assert!(v.verify(b"bHwcaWjaiHr96xZ3yZWQm").is_none()); // off by one char
    }

    #[test]
    fn decode_count_byte() {
        assert_eq!(decode_s2k_count(224), 16_777_216);
    }
}
