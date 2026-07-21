//! OneTimeSecret target module.
//!
//! OneTimeSecret (<https://onetimesecret.com>,
//! <https://github.com/onetimesecret/onetimesecret>) shares a secret behind a
//! one-time link, with an **optional passphrase** gating retrieval.
//!
//! Like PasswordPusher — and unlike yopass / PrivateBin — OneTimeSecret is **not**
//! zero-knowledge: the secret *value* is encrypted **server-side** (an
//! `encrypted_field` under the instance's global secret, with the passphrase mixed
//! into the key), so the value cannot be recovered offline without that
//! server-held global secret.
//!
//! **But the passphrase itself is a genuine offline-crackable artifact.** OTS does
//! not store the passphrase; it stores a *password hash* of it and verifies on
//! retrieval (`lib/onetime/models/features/passphrase_hashing.rb`):
//!   * **Argon2id** for current secrets (`passphrase_encryption = '2'`,
//!     `$argon2id$…` PHC string) — memory-hard.
//!   * **bcrypt** for legacy secrets (`$2a$…`).
//!
//! So given a passphrase hash exfiltrated from an instance you are authorized to
//! test (e.g. dumped from its Redis store during an engagement), this target
//! recovers the passphrase **offline**, exactly like cracking any leaked hash —
//! no live server, no network. The hash is fully self-contained: Argon2id/bcrypt
//! verification *is* the correctness oracle, so a wrong guess is a clean miss.
//!
//! Recovering the secret *value* afterwards additionally needs the instance global
//! secret and the stored ciphertext, and is out of scope here — this target's
//! output is the recovered **passphrase**.

use anyhow::{anyhow, bail, Result};
use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};

use crate::target::Target;

/// Which password-hash scheme a stored OneTimeSecret passphrase uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `$argon2id$…` (also accepts the `argon2i`/`argon2d` family) — current OTS.
    Argon2,
    /// `$2a$` / `$2b$` / `$2y$` / `$2x$` — legacy OTS.
    Bcrypt,
}

impl Scheme {
    fn label(self) -> &'static str {
        match self {
            Scheme::Argon2 => "argon2id",
            Scheme::Bcrypt => "bcrypt",
        }
    }
}

/// Identify the hash scheme from its modular-crypt prefix.
pub fn detect_scheme(hash: &str) -> Result<Scheme> {
    let h = hash.trim();
    if h.starts_with("$argon2id$") || h.starts_with("$argon2i$") || h.starts_with("$argon2d$") {
        Ok(Scheme::Argon2)
    } else if h.starts_with("$2a$")
        || h.starts_with("$2b$")
        || h.starts_with("$2y$")
        || h.starts_with("$2x$")
    {
        Ok(Scheme::Bcrypt)
    } else {
        bail!(
            "unrecognized passphrase hash format (expected an Argon2 '$argon2id$…' \
             or bcrypt '$2a$…' string)"
        )
    }
}

/// An offline OneTimeSecret **passphrase**-recovery target: a stored passphrase
/// hash that each candidate is verified against.
pub struct OnetimesecretTarget {
    /// The full modular-crypt hash string (Argon2 PHC or bcrypt).
    hash: String,
    scheme: Scheme,
    name: String,
}

impl OnetimesecretTarget {
    /// Build from a stored passphrase hash. Validates the format up front so a
    /// malformed hash fails immediately (structural, not a per-candidate miss).
    pub fn from_hash(hash: &str) -> Result<Self> {
        let hash = hash.trim().to_string();
        let scheme = detect_scheme(&hash)?;
        // Validate parseability now: a hash that can never verify is a
        // configuration error, not a wrong guess.
        match scheme {
            Scheme::Argon2 => {
                let parsed = PasswordHash::new(&hash)
                    .map_err(|e| anyhow!("invalid Argon2 PHC hash: {e}"))?;
                // A PHC string with no salt or no digest can never verify — reject
                // it now rather than silently grinding the whole keyspace to misses.
                if parsed.salt.is_none() || parsed.hash.is_none() {
                    bail!("Argon2 hash is missing its salt or digest");
                }
            }
            Scheme::Bcrypt => {
                // bcrypt hashes are exactly 60 chars: $2x$cc$ + 53 of base64.
                if hash.len() != 60 {
                    bail!("invalid bcrypt hash length {} (expected 60)", hash.len());
                }
            }
        }
        let name = format!("onetimesecret({})", scheme.label());
        Ok(Self { hash, scheme, name })
    }

    /// The detected hash scheme (useful for reporting).
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    fn attempt(&self, candidate: &[u8]) -> Result<Option<Vec<u8>>> {
        let matched = match self.scheme {
            Scheme::Argon2 => {
                // Params (memory/time/lanes) are read from the hash string itself,
                // so verification is parameter-agnostic and matches whatever the
                // OTS instance used.
                let parsed = PasswordHash::new(&self.hash)
                    .map_err(|e| anyhow!("invalid Argon2 PHC hash: {e}"))?;
                Argon2::default()
                    .verify_password(candidate, &parsed)
                    .is_ok()
            }
            Scheme::Bcrypt => {
                // bcrypt's API takes the password as &str; a non-UTF-8 candidate
                // cannot be the passphrase, so it's a clean miss (never fatal).
                match std::str::from_utf8(candidate) {
                    Ok(pw) => bcrypt::verify(pw, &self.hash).unwrap_or(false),
                    Err(_) => false,
                }
            }
        };
        Ok(if matched {
            // The recovered "secret" is the passphrase itself.
            Some(candidate.to_vec())
        } else {
            None
        })
    }
}

impl Target for OnetimesecretTarget {
    fn try_candidate(&self, candidate: &[u8]) -> Result<Option<Vec<u8>>> {
        self.attempt(candidate)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Published OpenBSD bcrypt reference vector (an *independent* implementation):
    // passphrase "U*U" hashes to this under cost 5. Anchors our bcrypt path to the
    // canonical C implementation, not just our own crate.
    const OPENBSD_BCRYPT_HASH: &str =
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    const OPENBSD_BCRYPT_PW: &str = "U*U";

    #[test]
    fn detects_schemes() {
        assert_eq!(detect_scheme(OPENBSD_BCRYPT_HASH).unwrap(), Scheme::Bcrypt);
        assert_eq!(
            detect_scheme("$argon2id$v=19$m=32,t=1,p=1$c2FsdHNhbHQ$aGFzaA").unwrap(),
            Scheme::Argon2
        );
        assert_eq!(detect_scheme("$2b$10$abcdefg").unwrap(), Scheme::Bcrypt);
        assert!(detect_scheme("not-a-hash").is_err());
        assert!(detect_scheme("$5$rounds=1000$sha512crypt").is_err());
    }

    #[test]
    fn rejects_malformed_hash_at_construction() {
        assert!(OnetimesecretTarget::from_hash("plain text").is_err());
        // bcrypt prefix but wrong length:
        assert!(OnetimesecretTarget::from_hash("$2a$05$tooshort").is_err());
        // argon2 prefix but unparseable PHC:
        assert!(OnetimesecretTarget::from_hash("$argon2id$garbage").is_err());
    }

    #[test]
    fn bcrypt_matches_published_vector() {
        let target = OnetimesecretTarget::from_hash(OPENBSD_BCRYPT_HASH).unwrap();
        assert_eq!(target.scheme(), Scheme::Bcrypt);
        assert_eq!(
            target.try_candidate(OPENBSD_BCRYPT_PW.as_bytes()).unwrap(),
            Some(OPENBSD_BCRYPT_PW.as_bytes().to_vec())
        );
        assert!(target.try_candidate(b"wrong").unwrap().is_none());
        // Non-UTF-8 candidate is a clean miss, not an error.
        assert!(target.try_candidate(&[0xff, 0xfe]).unwrap().is_none());
    }

    #[test]
    fn argon2_roundtrip_low_cost() {
        use argon2::password_hash::{PasswordHasher, SaltString};
        // Hash a known passphrase at low cost, then prove the target cracks it.
        let params = argon2::Params::new(32, 1, 1, None).unwrap();
        let a2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let salt = SaltString::from_b64("c2FsdHNhbHRzYWx0").unwrap();
        let hash = a2.hash_password(b"hunter2", &salt).unwrap().to_string();

        let target = OnetimesecretTarget::from_hash(&hash).unwrap();
        assert_eq!(target.scheme(), Scheme::Argon2);
        assert_eq!(
            target.try_candidate(b"hunter2").unwrap(),
            Some(b"hunter2".to_vec())
        );
        assert!(target.try_candidate(b"hunter3").unwrap().is_none());
    }
}
