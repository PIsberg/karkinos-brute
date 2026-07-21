//! yopass target module.
//!
//! yopass (<https://github.com/jhaals/yopass>) encrypts secrets *client-side*
//! with OpenPGP **symmetric** encryption (AES, key derived from a passphrase via
//! a salted+iterated S2K). The server only ever stores the armored ciphertext,
//! keyed by a random UUIDv4, and serves it back at `GET /secret/{uuid}`.
//!
//! A secret therefore has two parts:
//!   * the **UUID** — needed to fetch the ciphertext, and
//!   * the **passphrase** — needed to decrypt it.
//!
//! When yopass auto-generates the passphrase it is ~130 bits of entropy and
//! lives only in the URL fragment (`#/s/<uuid>/<key>`) — not brute-forceable.
//! This module is for the case that matters in a pentest: a human chose a weak
//! **custom password** (`#/c/<uuid>`), and we recover it *offline* against the
//! downloaded ciphertext.
//!
//! ⚠️  yopass secrets are **one-time-view by default**: fetching the ciphertext
//! from the server consumes (deletes) it. Fetch once, save the blob, crack the
//! saved blob — never re-fetch in a loop.

use std::io::Read;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use sequoia_openpgp::crypto::{Password, SessionKey};
use sequoia_openpgp::packet::{Tag, PKESK, SKESK};
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::{Cert, KeyHandle};

use crate::target::Target;

/// Where a yopass secret lives, parsed from a share URL or its pieces.
#[derive(Debug, Clone)]
pub struct SecretLocation {
    /// API base, e.g. `https://yopass.se`.
    pub base_url: String,
    pub uuid: String,
    /// The in-URL key, present only for `#/s/<uuid>/<key>` links. If set, the
    /// secret needs no brute force — it can be decrypted directly.
    pub key: Option<String>,
}

impl SecretLocation {
    /// Parse a yopass share URL.
    ///
    /// Accepts the two fragment forms used by the frontend:
    ///   * `https://host/#/s/<uuid>/<key>`  (auto-generated key in URL)
    ///   * `https://host/#/c/<uuid>`        (custom password)
    pub fn from_share_url(url: &str) -> Result<Self> {
        let (origin, fragment) = url
            .split_once('#')
            .ok_or_else(|| anyhow!("not a yopass share URL (no '#fragment'): {url}"))?;
        let base_url = origin_of(origin)
            .ok_or_else(|| anyhow!("could not determine scheme://host from {url}"))?;

        // Fragment looks like "/s/<uuid>/<key>" or "/c/<uuid>".
        let parts: Vec<&str> = fragment.trim_start_matches('/').split('/').collect();
        match parts.as_slice() {
            // Generated-key mode: key is embedded in the URL.
            ["s", uuid, key] => Ok(Self {
                base_url,
                uuid: (*uuid).to_string(),
                key: Some((*key).to_string()),
            }),
            // Single-token /s/ (no embedded key) and custom-password /c/ both
            // mean "fetch by id, then we need a passphrase".
            ["s", uuid] | ["c", uuid] => Ok(Self {
                base_url,
                uuid: (*uuid).to_string(),
                key: None,
            }),
            _ => bail!("unrecognised yopass fragment '#{fragment}' (expected /s/<uuid>[/<key>] or /c/<uuid>)"),
        }
    }

    /// Build a location from an explicit server base + UUID (no share URL).
    pub fn from_parts(base_url: &str, uuid: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            uuid: uuid.to_string(),
            key: None,
        }
    }

    fn secret_endpoint(&self) -> String {
        format!("{}/secret/{}", self.base_url.trim_end_matches('/'), self.uuid)
    }
}

/// Shape of the JSON returned by `GET /secret/{uuid}`.
#[derive(Debug, Deserialize)]
struct SecretResponse {
    /// Armored OpenPGP message.
    message: String,
    #[serde(default)]
    one_time: bool,
    #[serde(default)]
    expiration: i64,
}

/// Fetch the armored ciphertext for a secret.
///
/// ⚠️  This consumes one-time secrets server-side. Returns the armored message
/// plus whether the server flagged it one-time (for the warning we print).
pub fn fetch_ciphertext(loc: &SecretLocation) -> Result<(String, bool)> {
    let endpoint = loc.secret_endpoint();
    let resp = match ureq::get(&endpoint).call() {
        Ok(resp) => resp,
        // yopass returns 404 when a secret doesn't exist — almost always because
        // it was a one-time secret that's already been viewed, or it expired.
        Err(ureq::Error::StatusCode(404)) => {
            bail!(
                "secret not found at {endpoint} — for a one-time link this means it \
                 was already viewed once or its TTL expired (the ciphertext is gone)"
            );
        }
        Err(e) => return Err(anyhow::Error::new(e).context(format!("GET {endpoint}"))),
    };
    let body = resp
        .into_body()
        .read_to_string()
        .context("reading yopass /secret response")?;
    let secret: SecretResponse =
        serde_json::from_str(&body).context("decoding yopass /secret response as JSON")?;
    let _ = secret.expiration;
    Ok((secret.message, secret.one_time))
}

/// An offline yopass cracking target: a parsed ciphertext + a reusable policy.
pub struct YopassTarget {
    ciphertext: Vec<u8>,
    policy: StandardPolicy<'static>,
    name: String,
}

impl YopassTarget {
    /// Build from an armored (or binary) OpenPGP message.
    pub fn new(armored_message: impl Into<Vec<u8>>) -> Result<Self> {
        let ciphertext = armored_message.into();
        // Validate structure up front (once) rather than discovering a bad blob
        // on every candidate: the message must contain a symmetric-key (SKESK)
        // packet, i.e. it is passphrase-encrypted.
        ensure_passphrase_encrypted(&ciphertext)
            .context("input does not look like a yopass (symmetric OpenPGP) message")?;
        Ok(Self {
            ciphertext,
            policy: StandardPolicy::new(),
            name: "yopass".to_string(),
        })
    }

    /// Try one passphrase. `Ok(Some(plaintext))` on success, `Ok(None)` on a
    /// clean miss, `Err` only on structural problems with the ciphertext.
    fn attempt(&self, passphrase: &[u8]) -> Result<Option<Vec<u8>>> {
        let password = Password::from(passphrase);
        let helper = Helper { password };
        let decryptor = DecryptorBuilder::from_bytes(&self.ciphertext)
            .context("parsing OpenPGP message")?
            .with_policy(&self.policy, None, helper);

        match decryptor {
            Ok(mut d) => {
                let mut plaintext = Vec::new();
                d.read_to_end(&mut plaintext)
                    .context("reading decrypted stream")?;
                Ok(Some(plaintext))
            }
            // A wrong password is the overwhelmingly common path: the session
            // key fails its integrity check. sequoia surfaces this as an error
            // from `with_policy`, which for our purposes is a clean miss.
            Err(_) => Ok(None),
        }
    }
}

impl Target for YopassTarget {
    fn try_candidate(&self, candidate: &[u8]) -> Result<Option<Vec<u8>>> {
        self.attempt(candidate)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Scan top-level packets for a symmetric-key (SKESK) packet without decrypting.
fn ensure_passphrase_encrypted(ciphertext: &[u8]) -> Result<()> {
    let mut ppr = PacketParser::from_bytes(ciphertext).context("parsing OpenPGP packets")?;
    while let PacketParserResult::Some(pp) = ppr {
        // Gate on the tag, not the `Packet::SKESK` variant: the top-level parser
        // surfaces a v6 SKESK (RFC 9580) as `Packet::Unknown` that still carries
        // the SKESK tag, while the full decryptor parses it correctly.
        if pp.packet.tag() == Tag::SKESK {
            return Ok(());
        }
        // Advance to the next top-level packet (don't descend into the encrypted
        // container — we only need to see the SKESK that precedes it).
        let (_, next) = pp.next().context("reading next OpenPGP packet")?;
        ppr = next;
    }
    bail!("no symmetric-key (SKESK) packet found — not passphrase-encrypted")
}

/// Decryption helper that only knows a passphrase (no certificates).
struct Helper {
    password: Password,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }
    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        // We don't verify signatures; recovering the plaintext is the goal.
        Ok(())
    }
}

impl DecryptionHelper for Helper {
    fn decrypt(
        &mut self,
        _pkesks: &[PKESK],
        skesks: &[SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> sequoia_openpgp::Result<Option<Cert>> {
        if skesks.is_empty() {
            return Err(anyhow!("no symmetric-key packet (not a passphrase-encrypted message)"));
        }
        for skesk in skesks {
            if let Ok((algo, sk)) = skesk.decrypt(&self.password) {
                // `decrypt` returns true iff the session key actually decrypts
                // the body (AEAD/MDC verifies) — that's our correctness oracle.
                if decrypt(algo, &sk) {
                    return Ok(None);
                }
            }
        }
        Err(anyhow!("passphrase did not decrypt any symmetric-key packet"))
    }
}

fn origin_of(url: &str) -> Option<String> {
    // url is everything before '#', e.g. "https://host/path/". Keep scheme://host.
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split('/').next()?;
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_custom_password_url() {
        let loc =
            SecretLocation::from_share_url("https://yopass.se/#/c/2a8e0e1c-1111-2222-3333-444455556666")
                .unwrap();
        assert_eq!(loc.base_url, "https://yopass.se");
        assert_eq!(loc.uuid, "2a8e0e1c-1111-2222-3333-444455556666");
        assert!(loc.key.is_none());
        assert_eq!(
            loc.secret_endpoint(),
            "https://yopass.se/secret/2a8e0e1c-1111-2222-3333-444455556666"
        );
    }

    #[test]
    fn parse_inurl_key() {
        let loc = SecretLocation::from_share_url(
            "https://my.host:8443/#/s/abcd-uuid/SuperSecretKey123",
        )
        .unwrap();
        assert_eq!(loc.base_url, "https://my.host:8443");
        assert_eq!(loc.uuid, "abcd-uuid");
        assert_eq!(loc.key.as_deref(), Some("SuperSecretKey123"));
    }

    #[test]
    fn reject_non_share_url() {
        assert!(SecretLocation::from_share_url("https://yopass.se/about").is_err());
    }
}
