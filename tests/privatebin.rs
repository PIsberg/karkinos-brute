//! Known-answer test for the PrivateBin target.
//!
//! The fixture `fixtures/privatebin_v2_gcm.json` was produced by
//! `scripts/privatebin_vector.mjs` using **Node's WebCrypto** — the same Web
//! Crypto API PrivateBin's browser code uses — so it is an *independent* oracle:
//! if our Rust recovers what node encrypted, the Rust matches PrivateBin's
//! PBKDF2 + AES-256-GCM scheme (and the raw-DEFLATE `"zlib"` compression).
//!
//! The fixture is a real PrivateBin v2 paste document (`status`/`v`/`adata`/`ct`)
//! plus an `answer` block carrying the base58 key, password, and expected
//! plaintext.

use bruteforcer::target::privatebin::{decode_paste_key, PrivatebinTarget};
use bruteforcer::target::Target;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/privatebin_v2_gcm.json");

/// Build a target from the fixture's wire `paste` + base58 key, and return the
/// expected password/plaintext from the `answer` block.
fn target_and_answer() -> (PrivatebinTarget, String, Vec<u8>) {
    let doc: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let key =
        decode_paste_key(doc["answer"]["keyBase58"].as_str().unwrap()).expect("base58 key decodes");
    let paste = serde_json::to_vec(&doc["paste"]).unwrap();
    let target = PrivatebinTarget::from_paste_json(&paste, key).expect("paste parses");
    let password = doc["answer"]["password"].as_str().unwrap().to_string();
    let plaintext = doc["answer"]["plaintext"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    (target, password, plaintext)
}

#[test]
fn correct_password_recovers_plaintext() {
    let (t, password, plaintext) = target_and_answer();
    let secret = t
        .try_candidate(password.as_bytes())
        .expect("decrypt is not fatal")
        .expect("the correct password must verify and decrypt");
    assert_eq!(secret, plaintext, "recovered (decompressed) plaintext");
}

#[test]
fn wrong_password_is_clean_miss() {
    let (t, _password, _plaintext) = target_and_answer();
    // Wrong passwords must be Ok(None) (GCM tag fails), never Err — otherwise the
    // engine would abort the whole run on the first wrong guess.
    assert!(t.try_candidate(b"wrong").unwrap().is_none());
    assert!(t.try_candidate(b"hunter1").unwrap().is_none()); // off by one char
    assert!(t.try_candidate(b"").unwrap().is_none());
}
