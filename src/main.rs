//! `bruteforcer` — a pluggable bruteforce framework.
//!
//! Authorized use only. The bundled yopass module recovers weak *custom
//! passwords* on yopass secrets offline; see `src/target/yopass.rs`.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{ArgGroup, Args, Parser, Subcommand};

use bruteforcer::engine::candidate::{named_charset, CandidateSource, MaskSpec, WordlistSource};
use bruteforcer::engine::runner::{run, Outcome, RunConfig};
use bruteforcer::target::privatebin::{
    decode_paste_key, fetch_paste, PasteLocation, PrivatebinTarget,
};
use bruteforcer::target::onetimesecret::OnetimesecretTarget;
use bruteforcer::target::pwpush::{PushLocation, PwpushTarget};
use bruteforcer::target::yopass::{fetch_ciphertext, SecretLocation, YopassTarget};
use bruteforcer::target::Target;

#[derive(Parser)]
#[command(name = "bruteforcer", version, about = "Pluggable bruteforce framework (authorized use only)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// yopass secret-sharing service.
    Yopass {
        #[command(subcommand)]
        action: YopassAction,
    },
    /// PrivateBin zero-knowledge pastebin.
    Privatebin {
        #[command(subcommand)]
        action: PrivatebinAction,
    },
    /// PasswordPusher (ONLINE passphrase recovery against a server you control).
    Pwpush {
        #[command(subcommand)]
        action: PwpushAction,
    },
    /// OneTimeSecret (offline passphrase recovery from a stored hash).
    Onetimesecret {
        #[command(subcommand)]
        action: OnetimesecretAction,
    },
}

#[derive(Subcommand)]
enum YopassAction {
    /// Download a secret's ciphertext (consumes one-time secrets!).
    Fetch {
        #[command(flatten)]
        source: SecretInput,
        /// Write the armored ciphertext here (default: stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Recover a weak custom password offline.
    Crack {
        #[command(flatten)]
        source: CrackInput,
        #[command(flatten)]
        candidates: CandidateArgs,
        /// Worker threads (default: number of CPUs).
        #[arg(short, long)]
        threads: Option<usize>,
        /// Disable the progress display.
        #[arg(long)]
        no_progress: bool,
        /// Use the GPU backend (requires building with `--features gpu`).
        /// Only v6-SKESK / AES-256 / GCM secrets are supported; falls back to
        /// the CPU engine otherwise.
        #[arg(long)]
        gpu: bool,
        /// GPU batch size (candidates per dispatch round).
        #[arg(long, default_value_t = 16384)]
        gpu_batch: usize,
        /// Write the recovered secret here (default: stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
// Subcommand enums are parsed once at startup; the size gap between the tiny
// `Fetch` and the option-heavy `Crack` doesn't matter here.
#[allow(clippy::large_enum_variant)]
enum PrivatebinAction {
    /// Download a paste's ciphertext JSON (may consume burn-after-reading pastes!).
    Fetch {
        /// Full share URL, e.g. https://privatebin.net/?<id>#<base58key>
        #[arg(long)]
        url: String,
        /// Write the paste JSON here (default: stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Recover a weak paste password offline (the URL key is known).
    Crack {
        #[command(flatten)]
        source: PbCrackInput,
        #[command(flatten)]
        candidates: CandidateArgs,
        /// Worker threads (default: number of CPUs).
        #[arg(short, long)]
        threads: Option<usize>,
        /// Disable the progress display.
        #[arg(long)]
        no_progress: bool,
        /// Write the recovered secret here (default: stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PwpushAction {
    /// Recover a weak push *passphrase* by guessing ONLINE against the server.
    ///
    /// PasswordPusher has no offline-crackable artifact (the passphrase is a
    /// server-side string compare, the payload is encrypted under a server key),
    /// so every candidate is one HTTP request. Authorized targets only.
    Crack {
        #[command(flatten)]
        source: PwCrackInput,
        #[command(flatten)]
        candidates: CandidateArgs,
        /// Worker threads. This is an online attack — keep it low.
        #[arg(short, long, default_value_t = 1)]
        threads: usize,
        /// Minimum delay between requests, in ms (politeness / rate-limit
        /// avoidance). Use 0 for a localhost instance you own.
        #[arg(long, default_value_t = 100)]
        delay_ms: u64,
        /// Disable the progress display.
        #[arg(long)]
        no_progress: bool,
        /// Write the recovered secret here (default: stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum OnetimesecretAction {
    /// Recover a weak passphrase offline from its stored hash (Argon2id/bcrypt).
    ///
    /// OneTimeSecret stores the passphrase as an Argon2id (current) or bcrypt
    /// (legacy) hash. Given that hash — e.g. dumped from an instance you are
    /// authorized to test — this recovers the passphrase locally, no server.
    Crack {
        #[command(flatten)]
        source: OtsCrackInput,
        #[command(flatten)]
        candidates: CandidateArgs,
        /// Worker threads (default: number of CPUs).
        #[arg(short, long)]
        threads: Option<usize>,
        /// Disable the progress display.
        #[arg(long)]
        no_progress: bool,
        /// Write the recovered passphrase here (default: stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

/// Input for cracking a OneTimeSecret passphrase: the stored hash, inline or from
/// a file. There is no network path — the hash is the whole oracle.
#[derive(Args)]
struct OtsCrackInput {
    /// The stored passphrase hash, e.g. '$argon2id$...' or '$2a$...'.
    #[arg(long, group = "otssrc")]
    hash: Option<String>,
    /// Read the hash from this file ('-' for stdin).
    #[arg(long, group = "otssrc")]
    hash_file: Option<String>,
}

/// Input for cracking a PasswordPusher passphrase. There is no saved-blob mode:
/// the only oracle is a live server holding the push.
#[derive(Args)]
struct PwCrackInput {
    /// Full push URL, e.g. https://host/p/<token> (a server you may test).
    #[arg(long, group = "pwsrc")]
    url: Option<String>,
    /// Push token (use with --server).
    #[arg(long, group = "pwsrc", requires = "server")]
    token: Option<String>,
    /// Server base URL (use with --token), e.g. http://localhost:5100
    #[arg(long)]
    server: Option<String>,
}

/// Input for cracking a PrivateBin paste. The decryption key (URL fragment) is
/// always required — we brute-force the *password* layered on top of it.
#[derive(Args)]
struct PbCrackInput {
    /// Full share URL incl. the `#<key>` fragment (fetches the paste).
    #[arg(long, group = "pbsrc")]
    url: Option<String>,
    /// Read a saved paste JSON from this file ('-' for stdin). Needs --key.
    #[arg(long, group = "pbsrc", requires = "key")]
    message: Option<String>,
    /// Paste id (use with --server). Needs --key.
    #[arg(long, group = "pbsrc", requires = "server", requires = "key")]
    id: Option<String>,
    /// Server base URL (use with --id).
    #[arg(long)]
    server: Option<String>,
    /// Base58 paste key from the URL fragment (required for --message/--id).
    #[arg(long)]
    key: Option<String>,
}

/// How to locate a secret on a yopass server (for `fetch`).
#[derive(Args)]
struct SecretInput {
    /// Full share URL, e.g. https://yopass.se/#/c/<uuid>
    #[arg(long)]
    url: Option<String>,
    /// Override the API base, e.g. https://api.yopass.se. Needed when the
    /// frontend and API live on different hosts (the public instance does).
    #[arg(long)]
    api_base: Option<String>,
}

/// Input for cracking: either fetch from a server, or read a saved blob.
#[derive(Args)]
struct CrackInput {
    /// Full share URL (fetches ciphertext; consumes one-time secrets!).
    #[arg(long, group = "src")]
    url: Option<String>,
    /// Secret UUID (use with --server; fetches ciphertext).
    #[arg(long, requires = "server", group = "src")]
    uuid: Option<String>,
    /// Server/API base URL (use with --uuid, or to override a --url origin).
    #[arg(long)]
    server: Option<String>,
    /// Alias for --server: override the API base (e.g. https://api.yopass.se).
    #[arg(long)]
    api_base: Option<String>,
    /// Read a saved armored ciphertext from this file ('-' for stdin).
    #[arg(long, group = "src")]
    message: Option<String>,
}

/// Candidate-generation options. Exactly one *generator* is required
/// (`--wordlist` XOR `--charset` XOR `--charset-raw`); `--min`/`--max` only
/// apply to the mask generators.
#[derive(Args)]
#[command(group = ArgGroup::new("gen").required(false).multiple(false).args(["wordlist", "charset", "charset_raw"]))]
struct CandidateArgs {
    /// Wordlist file, one candidate per line.
    #[arg(long)]
    wordlist: Option<PathBuf>,
    /// Named charset for a brute-force mask: digits|lower|upper|alpha|alnum|alnum-lower|ascii
    #[arg(long)]
    charset: Option<String>,
    /// Literal charset for a brute-force mask (overrides --charset).
    #[arg(long)]
    charset_raw: Option<String>,
    /// Minimum mask length (mask mode).
    #[arg(long, default_value_t = 1)]
    min: usize,
    /// Maximum mask length (mask mode).
    #[arg(long, default_value_t = 8)]
    max: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Yopass { action } => match action {
            YopassAction::Fetch { source, out } => {
                yopass_fetch(source, out)
            }
            YopassAction::Crack {
                source,
                candidates,
                threads,
                no_progress,
                gpu,
                gpu_batch,
                out,
            } => yopass_crack(source, candidates, threads, no_progress, gpu, gpu_batch, out),
        },
        Command::Privatebin { action } => match action {
            PrivatebinAction::Fetch { url, out } => privatebin_fetch(url, out),
            PrivatebinAction::Crack {
                source,
                candidates,
                threads,
                no_progress,
                out,
            } => privatebin_crack(source, candidates, threads, no_progress, out),
        },
        Command::Pwpush { action } => match action {
            PwpushAction::Crack {
                source,
                candidates,
                threads,
                delay_ms,
                no_progress,
                out,
            } => pwpush_crack(source, candidates, threads, delay_ms, no_progress, out),
        },
        Command::Onetimesecret { action } => match action {
            OnetimesecretAction::Crack {
                source,
                candidates,
                threads,
                no_progress,
                out,
            } => onetimesecret_crack(source, candidates, threads, no_progress, out),
        },
    }
}

fn location_from(
    url: Option<String>,
    uuid: Option<String>,
    server: Option<String>,
    api_base: Option<String>,
) -> Result<SecretLocation> {
    let mut loc = if let Some(url) = url {
        SecretLocation::from_share_url(&url)?
    } else if let (Some(uuid), Some(server)) = (uuid, server.clone()) {
        SecretLocation::from_parts(&server, &uuid)
    } else {
        bail!("provide --url, or both --uuid and --server");
    };
    apply_api_base(&mut loc, api_base.or(server));
    Ok(loc)
}

/// Resolve the API base: explicit override wins; otherwise auto-correct the
/// known public-instance split where the frontend (share/www.yopass.se) is a
/// static site and the real API lives at api.yopass.se.
fn apply_api_base(loc: &mut SecretLocation, override_base: Option<String>) {
    if let Some(base) = override_base {
        loc.base_url = base.trim_end_matches('/').to_string();
        return;
    }
    if let Some(host) = loc.base_url.split("://").nth(1) {
        if (host == "yopass.se" || host == "share.yopass.se" || host == "www.yopass.se")
            && loc.base_url != "https://api.yopass.se"
        {
            eprintln!(
                "ℹ️  {} is the static frontend; using API base https://api.yopass.se",
                loc.base_url
            );
            loc.base_url = "https://api.yopass.se".to_string();
        }
    }
}

fn yopass_fetch(source: SecretInput, out: Option<PathBuf>) -> Result<()> {
    let mut loc = match source.url {
        Some(url) => SecretLocation::from_share_url(&url)?,
        None => bail!("`fetch` requires --url (the full share link)"),
    };
    apply_api_base(&mut loc, source.api_base);

    eprintln!(
        "⚠️  Fetching {} — yopass secrets are one-time by default; this may DELETE it server-side.",
        loc.uuid
    );
    let (message, one_time) = fetch_ciphertext(&loc)?;
    if one_time {
        eprintln!("⚠️  Server reported this secret as one-time: it is now consumed. Save this blob!");
    }

    match out {
        Some(path) => {
            fs::write(&path, message.as_bytes())
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!("Saved ciphertext to {}", path.display());
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(message.as_bytes())?;
        }
    }
    Ok(())
}

fn yopass_crack(
    source: CrackInput,
    candidates: CandidateArgs,
    threads: Option<usize>,
    no_progress: bool,
    gpu: bool,
    gpu_batch: usize,
    out: Option<PathBuf>,
) -> Result<()> {
    // 1. Obtain the armored ciphertext (from file/stdin or by fetching).
    let (ciphertext, in_url_key) = obtain_ciphertext(&source)?;

    let target = Arc::new(YopassTarget::new(ciphertext.clone())?);

    // 2. If the share URL embedded the key (#/s/<uuid>/<key>), there is nothing
    //    to brute-force — just decrypt directly.
    if let Some(key) = in_url_key {
        eprintln!("Share URL contained the decryption key; decrypting directly (no brute force).");
        return match target.try_candidate(key.as_bytes())? {
            Some(secret) => emit_secret(&secret, out),
            None => bail!("the key embedded in the URL did not decrypt the secret"),
        };
    }

    // 3. GPU backend (opt-in). Only the v6/AES-256/GCM fast path is supported;
    //    anything else falls back to the CPU engine below.
    if gpu {
        if let Some(result) = try_gpu_crack(&ciphertext, &candidates, gpu_batch, !no_progress)? {
            return match result {
                Some(candidate) => {
                    eprintln!("\n✅ Password found: {}", String::from_utf8_lossy(&candidate));
                    // Recover the plaintext with the proven passphrase (one decrypt).
                    match target.try_candidate(&candidate)? {
                        Some(secret) => emit_secret(&secret, out),
                        None => bail!("internal: verified passphrase failed to decrypt"),
                    }
                }
                None => bail!("keyspace exhausted; no candidate matched"),
            };
        }
        // None => GPU path not applicable; fall through to CPU.
    }

    // 4. Build the candidate source.
    let source_box = build_candidate_source(&candidates)?;

    let cfg = RunConfig {
        threads: threads.unwrap_or_else(|| num_cpus::get().max(1)),
        progress: !no_progress,
    };
    eprintln!(
        "Cracking with {} threads against target '{}'...",
        cfg.threads,
        target.name()
    );

    match run(target, source_box, cfg)? {
        Outcome::Found { candidate, secret } => {
            eprintln!(
                "\n✅ Password found: {}",
                String::from_utf8_lossy(&candidate)
            );
            emit_secret(&secret, out)
        }
        Outcome::Exhausted => {
            bail!("keyspace exhausted; no candidate matched");
        }
    }
}

/// Get the armored ciphertext and any key embedded in a share URL.
fn obtain_ciphertext(source: &CrackInput) -> Result<(Vec<u8>, Option<String>)> {
    if let Some(message) = &source.message {
        let bytes = if message == "-" {
            let mut buf = Vec::new();
            std::io::stdin()
                .lock()
                .read_to_end(&mut buf)
                .context("reading ciphertext from stdin")?;
            buf
        } else {
            fs::read(message).with_context(|| format!("reading {message}"))?
        };
        return Ok((bytes, None));
    }

    let loc = location_from(
        source.url.clone(),
        source.uuid.clone(),
        source.server.clone(),
        source.api_base.clone(),
    )?;
    eprintln!(
        "⚠️  Fetching {} — yopass secrets are one-time by default; this may DELETE it server-side.",
        loc.uuid
    );
    let (message, one_time) = fetch_ciphertext(&loc)?;

    // Persist the fetched blob IMMEDIATELY. The fetch is destructive for
    // one-time secrets; if cracking later fails (or doesn't match), we must not
    // lose the only copy of the ciphertext.
    let backup = format!("{}.asc", sanitize_filename(&loc.uuid));
    if let Err(e) = fs::write(&backup, message.as_bytes()) {
        eprintln!("⚠️  could not save a backup of the fetched ciphertext: {e}");
    } else {
        eprintln!("💾 Saved fetched ciphertext to {backup} (re-crack with `--message {backup}`).");
    }
    if one_time {
        eprintln!("⚠️  Server reported this secret as one-time: it is now consumed.");
    }
    Ok((message.into_bytes(), loc.key))
}

/// Keep a UUID safe to use as a filename (defensive; yopass ids are already tame).
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// Attempt the GPU crack. Returns:
/// * `Ok(None)` — GPU path not applicable (unsupported SKESK, or built without
///   the `gpu` feature); the caller should fall back to the CPU engine.
/// * `Ok(Some(Some(candidate)))` — found.
/// * `Ok(Some(None))` — keyspace exhausted on the GPU path.
#[cfg(feature = "gpu")]
fn try_gpu_crack(
    ciphertext: &[u8],
    candidates: &CandidateArgs,
    batch: usize,
    progress: bool,
) -> Result<Option<Option<Vec<u8>>>> {
    use bruteforcer::target::skesk_v6::SkeskV6;
    let skesk = match SkeskV6::parse(ciphertext) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("GPU path unavailable ({e}); using CPU engine.");
            return Ok(None);
        }
    };
    let source = build_candidate_source(candidates)?;
    let found = bruteforcer::gpu::crack_v6(&skesk, source, batch, progress)?;
    Ok(Some(found))
}

#[cfg(not(feature = "gpu"))]
fn try_gpu_crack(
    _ciphertext: &[u8],
    _candidates: &CandidateArgs,
    _batch: usize,
    _progress: bool,
) -> Result<Option<Option<Vec<u8>>>> {
    eprintln!("⚠️  built without GPU support (rebuild with `--features gpu`); using CPU engine.");
    Ok(None)
}

fn privatebin_fetch(url: String, out: Option<PathBuf>) -> Result<()> {
    let loc = PasteLocation::from_share_url(&url)?;
    eprintln!(
        "⚠️  Fetching paste {} — PrivateBin pastes may be burn-after-reading; this can DELETE it server-side.",
        loc.id
    );
    let (json, burn) = fetch_paste(&loc)?;
    if burn {
        eprintln!("⚠️  This paste is burn-after-reading: it is now consumed. Save this blob!");
    }
    match out {
        Some(path) => {
            fs::write(&path, &json).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("Saved paste JSON to {}", path.display());
        }
        None => std::io::stdout().lock().write_all(&json)?,
    }
    Ok(())
}

fn privatebin_crack(
    source: PbCrackInput,
    candidates: CandidateArgs,
    threads: Option<usize>,
    no_progress: bool,
    out: Option<PathBuf>,
) -> Result<()> {
    // 1. Obtain the paste JSON and the (always-required) URL key.
    let (paste_json, key) = pb_obtain(&source)?;

    let target = Arc::new(PrivatebinTarget::from_paste_json(&paste_json, key)?);

    // 2. Brute-force the password layered on top of the URL key.
    let source_box = build_candidate_source(&candidates)?;
    let cfg = RunConfig {
        threads: threads.unwrap_or_else(|| num_cpus::get().max(1)),
        progress: !no_progress,
    };
    eprintln!(
        "Cracking with {} threads against target '{}'...",
        cfg.threads,
        target.name()
    );

    match run(target, source_box, cfg)? {
        Outcome::Found { candidate, secret } => {
            eprintln!("\n✅ Password found: {}", String::from_utf8_lossy(&candidate));
            emit_secret(&secret, out)
        }
        Outcome::Exhausted => bail!("keyspace exhausted; no candidate matched"),
    }
}

/// Resolve a PrivateBin crack source into (paste JSON bytes, decoded key bytes).
fn pb_obtain(source: &PbCrackInput) -> Result<(Vec<u8>, Vec<u8>)> {
    // Saved blob: needs an explicit --key (enforced by clap `requires`).
    if let Some(message) = &source.message {
        let bytes = if message == "-" {
            let mut buf = Vec::new();
            std::io::stdin()
                .lock()
                .read_to_end(&mut buf)
                .context("reading paste JSON from stdin")?;
            buf
        } else {
            fs::read(message).with_context(|| format!("reading {message}"))?
        };
        let key = decode_paste_key(source.key.as_deref().unwrap())?;
        return Ok((bytes, key));
    }

    // Otherwise we fetch from the server; build a location and persist a backup.
    let loc = if let Some(url) = &source.url {
        PasteLocation::from_share_url(url)?
    } else if let (Some(id), Some(server)) = (&source.id, &source.server) {
        PasteLocation::from_parts(server, id, source.key.as_deref())?
    } else {
        bail!("provide --url, or --message + --key, or --id + --server + --key");
    };
    let key = loc
        .key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no paste key — pass it in the URL fragment or via --key"))?;

    eprintln!(
        "⚠️  Fetching paste {} — PrivateBin pastes may be burn-after-reading; this can DELETE it server-side.",
        loc.id
    );
    let (json, burn) = fetch_paste(&loc)?;
    let backup = format!("{}.json", sanitize_filename(&loc.id));
    if let Err(e) = fs::write(&backup, &json) {
        eprintln!("⚠️  could not save a backup of the fetched paste: {e}");
    } else {
        eprintln!("💾 Saved fetched paste to {backup} (re-crack with `--message {backup} --key <key>`).");
    }
    if burn {
        eprintln!("⚠️  This paste was burn-after-reading: it is now consumed.");
    }
    Ok((json, key))
}

fn pwpush_crack(
    source: PwCrackInput,
    candidates: CandidateArgs,
    threads: usize,
    delay_ms: u64,
    no_progress: bool,
    out: Option<PathBuf>,
) -> Result<()> {
    // Locate the push (full URL, or server + token). No public default host:
    // the user must name the instance they are authorized to test.
    let loc = if let Some(url) = &source.url {
        PushLocation::from_share_url(url)?
    } else if let (Some(token), Some(server)) = (&source.token, &source.server) {
        PushLocation::from_parts(server, token)?
    } else {
        bail!("provide --url, or both --token and --server");
    };

    eprintln!("⚠️  ONLINE ATTACK. PasswordPusher has no offline-crackable artifact, so every");
    eprintln!("    candidate is a live HTTP request to the server. Run this ONLY against an");
    eprintln!("    instance you are authorized to test (e.g. your own self-hosted server).");
    eprintln!("    • Wrong guesses are logged server-side as failed-passphrase events.");
    eprintln!("    • A correct guess COUNTS AS A VIEW and may delete a view-limited push.");
    eprintln!("    Target: {}", loc.endpoint());

    let target = Arc::new(PwpushTarget::new(&loc, Duration::from_millis(delay_ms)));
    let source_box = build_candidate_source(&candidates)?;
    let cfg = RunConfig {
        threads: threads.max(1),
        progress: !no_progress,
    };
    eprintln!(
        "Guessing passphrase with {} thread(s), {} ms min delay between requests...",
        cfg.threads, delay_ms
    );

    match run(target, source_box, cfg)? {
        Outcome::Found { candidate, secret } => {
            eprintln!("\n✅ Passphrase found: {}", String::from_utf8_lossy(&candidate));
            emit_secret(&secret, out)
        }
        Outcome::Exhausted => bail!("keyspace exhausted; no passphrase matched"),
    }
}

fn onetimesecret_crack(
    source: OtsCrackInput,
    candidates: CandidateArgs,
    threads: Option<usize>,
    no_progress: bool,
    out: Option<PathBuf>,
) -> Result<()> {
    // Obtain the stored passphrase hash (inline, file, or stdin).
    let hash = if let Some(h) = &source.hash {
        h.clone()
    } else if let Some(path) = &source.hash_file {
        let raw = if path == "-" {
            let mut buf = String::new();
            std::io::stdin()
                .lock()
                .read_to_string(&mut buf)
                .context("reading hash from stdin")?;
            buf
        } else {
            fs::read_to_string(path).with_context(|| format!("reading {path}"))?
        };
        raw.trim().to_string()
    } else {
        bail!("provide --hash, or --hash-file");
    };

    let target = Arc::new(OnetimesecretTarget::from_hash(&hash)?);
    let source_box = build_candidate_source(&candidates)?;
    let cfg = RunConfig {
        threads: threads.unwrap_or_else(|| num_cpus::get().max(1)),
        progress: !no_progress,
    };
    eprintln!(
        "Cracking with {} threads against target '{}'...",
        cfg.threads,
        target.name()
    );

    match run(target, source_box, cfg)? {
        Outcome::Found { candidate, .. } => {
            eprintln!("\n✅ Passphrase found: {}", String::from_utf8_lossy(&candidate));
            emit_secret(&candidate, out)
        }
        Outcome::Exhausted => bail!("keyspace exhausted; no passphrase matched"),
    }
}

fn build_candidate_source(args: &CandidateArgs) -> Result<Box<dyn CandidateSource>> {
    if let Some(path) = &args.wordlist {
        return Ok(Box::new(WordlistSource::open(path)?));
    }
    let charset = if let Some(raw) = &args.charset_raw {
        raw.clone()
    } else if let Some(name) = &args.charset {
        named_charset(name)
            .ok_or_else(|| anyhow::anyhow!("unknown charset '{name}'"))?
            .to_string()
    } else {
        bail!("provide --wordlist, or --charset/--charset-raw for a mask");
    };
    Ok(Box::new(MaskSpec::new(&charset, args.min, args.max)?))
}

fn emit_secret(secret: &[u8], out: Option<PathBuf>) -> Result<()> {
    match out {
        Some(path) => {
            fs::write(&path, secret).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("Recovered secret written to {}", path.display());
        }
        None => {
            eprintln!("--- recovered secret ---");
            std::io::stdout().lock().write_all(secret)?;
            println!();
        }
    }
    Ok(())
}
