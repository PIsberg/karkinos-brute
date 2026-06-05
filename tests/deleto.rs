//! End-to-end (offline) tests for the dele.to password-recovery target, driving
//! the *full engine pipeline* (mask candidate source → runner → target).
//!
//! These need no network and no server: dele.to verifies the optional password
//! server-side against `passwordHash = base64(password ‖ salt)`, and that stored
//! hash is a self-contained offline-crackable artifact. We reproduce the server's
//! `hashPassword` to build the fixture, then crack it through the engine — and
//! confirm a password outside the keyspace exhausts cleanly rather than erroring.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use bruteforcer::engine::candidate::MaskSpec;
use bruteforcer::engine::runner::{run, Outcome, RunConfig};
use bruteforcer::target::deleto::{DeletoTarget, DEFAULT_SALT};
use bruteforcer::target::Target;

/// Reproduce dele.to's `hashPassword`: `base64(password ‖ salt)`.
fn hash_password(password: &[u8], salt: &[u8]) -> String {
    let mut buf = password.to_vec();
    buf.extend_from_slice(salt);
    B64.encode(&buf)
}

fn quiet() -> RunConfig {
    RunConfig { threads: 2, progress: false }
}

#[test]
fn crack_password_via_engine_default_salt() {
    let hash = hash_password(b"42", DEFAULT_SALT.as_bytes());
    let target: Arc<dyn Target> =
        Arc::new(DeletoTarget::new(&hash, DEFAULT_SALT.as_bytes()).unwrap());
    // Digits, lengths 1..=2 — a tiny keyspace that contains "42".
    let source = Box::new(MaskSpec::new("0123456789", 1, 2).unwrap());

    match run(target, source, quiet()).unwrap() {
        Outcome::Found { candidate, secret } => {
            assert_eq!(candidate, b"42");
            // For this target the recovered "secret" *is* the password.
            assert_eq!(secret, b"42");
        }
        Outcome::Exhausted => panic!("should have found the dele.to password"),
    }
}

#[test]
fn crack_password_via_engine_custom_salt() {
    let salt = b"my-instance-salt";
    let hash = hash_password(b"ab", salt);
    let target: Arc<dyn Target> = Arc::new(DeletoTarget::new(&hash, salt).unwrap());
    let source = Box::new(MaskSpec::new("ab", 1, 2).unwrap());

    match run(target, source, quiet()).unwrap() {
        Outcome::Found { candidate, .. } => assert_eq!(candidate, b"ab"),
        Outcome::Exhausted => panic!("should have found the dele.to password"),
    }
}

#[test]
fn exhausts_when_password_outside_keyspace() {
    let hash = hash_password(b"zz", DEFAULT_SALT.as_bytes());
    let target: Arc<dyn Target> =
        Arc::new(DeletoTarget::new(&hash, DEFAULT_SALT.as_bytes()).unwrap());
    // Digits only never produces "zz": the run must exhaust cleanly (every wrong
    // guess is Ok(None)), not error out.
    let source = Box::new(MaskSpec::new("0123456789", 1, 2).unwrap());
    assert!(matches!(run(target, source, quiet()).unwrap(), Outcome::Exhausted));
}
