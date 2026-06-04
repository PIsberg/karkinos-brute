//! Regression tests against real, captured ciphertexts we decrypted.
//!
//! These are known-answer vectors: the exact armored OpenPGP messages plus the
//! passphrase that opens them and the expected plaintext. They guard both the
//! manual v6-SKESK fast path ([`SkeskV6`]) and the general sequoia path
//! ([`YopassTarget`]) against regressions and crypto-library changes.

use bruteforcer::target::skesk_v6::SkeskV6;
use bruteforcer::target::yopass::YopassTarget;
use bruteforcer::target::Target;

/// Real yopass secret (share.yopass.se), captured 2026-06-04.
/// Format: v6 SKESK / AES-256 / GCM, S2K iterated+salted SHA-256 (16,777,216).
/// Passphrase "bHwcaWjaiHr96xZ3yZWQmh" decrypts to "fasfd".
const YOPASS_V6_GCM: &str = include_str!("fixtures/yopass_v6_gcm.asc");
const YOPASS_V6_PASS: &[u8] = b"bHwcaWjaiHr96xZ3yZWQmh";
const YOPASS_V6_PLAIN: &[u8] = b"fasfd";

/// Classic OpenPGP symmetric message (gpg --symmetric, SEIPD v1 + MDC, AES-256).
/// Passphrase "hunter2" decrypts to "v4 symmetric secret".
const OPENPGP_V4: &str = include_str!("fixtures/openpgp_v4.asc");
const OPENPGP_V4_PASS: &[u8] = b"hunter2";
const OPENPGP_V4_PLAIN: &[u8] = b"v4 symmetric secret";

// ---- v6 SKESK / AES-256 / GCM (the modern yopass format) -------------------

#[test]
fn v6_parses() {
    let s = SkeskV6::parse(YOPASS_V6_GCM.as_bytes()).expect("should parse v6 SKESK");
    assert_eq!(s.count, 16_777_216, "S2K octet count");
    assert_eq!(s.iv.len(), 12, "GCM nonce length");
    assert_eq!(s.esk.len(), 48, "32-byte session key + 16-byte tag");
    assert_eq!(s.aad, [0xC3, 6, 9, 3]);
}

#[test]
fn v6_fast_path_verifies_correct_passphrase() {
    let s = SkeskV6::parse(YOPASS_V6_GCM.as_bytes()).unwrap();
    assert!(s.verify(YOPASS_V6_PASS).is_some(), "correct passphrase must verify");
}

#[test]
fn v6_fast_path_rejects_wrong_passphrase() {
    let s = SkeskV6::parse(YOPASS_V6_GCM.as_bytes()).unwrap();
    assert!(s.verify(b"wrong").is_none());
    assert!(s.verify(b"bHwcaWjaiHr96xZ3yZWQm").is_none()); // one char short
    assert!(s.verify(b"").is_none());
}

#[test]
fn v6_sequoia_path_recovers_plaintext() {
    let t = YopassTarget::new(YOPASS_V6_GCM.as_bytes()).unwrap();
    let secret = t
        .try_candidate(YOPASS_V6_PASS)
        .unwrap()
        .expect("correct passphrase must decrypt");
    assert_eq!(secret, YOPASS_V6_PLAIN);
    assert!(t.try_candidate(b"nope").unwrap().is_none());
}

// ---- classic v4 (SEIPD + MDC) — exercises the sequoia fallback -------------

#[test]
fn v4_is_not_on_the_fast_path() {
    // The manual fast path only handles v6/AES-256/GCM; v4 must be rejected so
    // callers fall back to sequoia.
    let err = SkeskV6::parse(OPENPGP_V4.as_bytes()).unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("version")
            || err.downcast_ref::<bruteforcer::target::skesk_v6::UnsupportedSkesk>().is_some(),
        "expected an unsupported-version error, got: {err}"
    );
}

#[test]
fn v4_sequoia_path_recovers_plaintext() {
    let t = YopassTarget::new(OPENPGP_V4.as_bytes()).unwrap();
    let secret = t
        .try_candidate(OPENPGP_V4_PASS)
        .unwrap()
        .expect("correct passphrase must decrypt");
    assert_eq!(secret, OPENPGP_V4_PLAIN);
    assert!(t.try_candidate(b"wrong").unwrap().is_none());
}
