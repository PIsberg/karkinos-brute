//! End-to-end (offline) tests for the OneTimeSecret passphrase-recovery target,
//! driving the *full engine pipeline* (mask candidate source → runner → target).
//!
//! These need no network and no server: OneTimeSecret hashes the passphrase with
//! Argon2id (current) or bcrypt (legacy), and that hash is a self-contained
//! offline-crackable artifact. We crack:
//!   * a **published OpenBSD bcrypt reference vector** (an independent oracle), and
//!   * an Argon2id hash produced here at low cost (standard PHC format).

use std::sync::Arc;

use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use bruteforcer::engine::candidate::MaskSpec;
use bruteforcer::engine::runner::{run, Outcome, RunConfig};
use bruteforcer::target::onetimesecret::{OnetimesecretTarget, Scheme};
use bruteforcer::target::Target;

// OpenBSD bcrypt test vector: passphrase "U*U" under cost 5.
const OPENBSD_BCRYPT_HASH: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";

fn quiet() -> RunConfig {
    RunConfig {
        threads: 2,
        progress: false,
    }
}

#[test]
fn crack_bcrypt_passphrase_via_engine() {
    let target: Arc<dyn Target> =
        Arc::new(OnetimesecretTarget::from_hash(OPENBSD_BCRYPT_HASH).unwrap());
    // Charset {U,*}, lengths 1..=3 — a tiny keyspace that contains "U*U".
    let source = Box::new(MaskSpec::new("U*", 1, 3).unwrap());

    match run(target, source, quiet()).unwrap() {
        Outcome::Found { candidate, secret } => {
            assert_eq!(candidate, b"U*U");
            // For this target the recovered "secret" *is* the passphrase.
            assert_eq!(secret, b"U*U");
        }
        Outcome::Exhausted => panic!("should have found the bcrypt passphrase"),
    }
}

#[test]
fn crack_argon2id_passphrase_via_engine() {
    // Low-cost Argon2id hash of "42" (params live in the PHC string, so the
    // target verifies against whatever cost the hash encodes).
    let params = Params::new(32, 1, 1, None).unwrap();
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::from_b64("c2FsdHNhbHRzYWx0").unwrap();
    let hash = a2.hash_password(b"42", &salt).unwrap().to_string();

    let target_obj = OnetimesecretTarget::from_hash(&hash).unwrap();
    assert_eq!(target_obj.scheme(), Scheme::Argon2);
    let target: Arc<dyn Target> = Arc::new(target_obj);
    let source = Box::new(MaskSpec::new("0123456789", 1, 2).unwrap());

    match run(target, source, quiet()).unwrap() {
        Outcome::Found { candidate, secret } => {
            assert_eq!(candidate, b"42");
            assert_eq!(secret, b"42");
        }
        Outcome::Exhausted => panic!("should have found the argon2id passphrase"),
    }
}

#[test]
fn exhausts_when_passphrase_outside_keyspace() {
    let target: Arc<dyn Target> =
        Arc::new(OnetimesecretTarget::from_hash(OPENBSD_BCRYPT_HASH).unwrap());
    // Digits only never produces "U*U": the run must exhaust cleanly (every wrong
    // guess is Ok(None)), not error out.
    let source = Box::new(MaskSpec::new("0123456789", 1, 2).unwrap());
    assert!(matches!(
        run(target, source, quiet()).unwrap(),
        Outcome::Exhausted
    ));
}
