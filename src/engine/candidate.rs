//! Candidate (guess) generation.
//!
//! A [`CandidateSource`] is just an iterator of byte vectors. Keeping it an
//! iterator (rather than materialising a `Vec`) means masks with astronomically
//! large keyspaces stream lazily and use O(1) memory.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

/// A stream of candidate guesses.
///
/// `total_hint` lets the runner render a progress bar/ETA when the size is known
/// up front (masks); it returns `None` for unbounded/unknown sources (stdin).
pub trait CandidateSource: Send {
    /// Overwrite `buf` with the next candidate and return `true`. Return `false`
    /// when the source is exhausted (leaving `buf`'s contents unspecified).
    ///
    /// Filling a caller-owned buffer — rather than returning a fresh `Vec` —
    /// lets the runner recycle one allocation per worker instead of allocating
    /// per guess (see [`crate::engine::runner`]). Implementations MUST clear
    /// `buf` before writing, so a recycled buffer never leaks stale bytes into a
    /// candidate.
    fn next_candidate(&mut self, buf: &mut Vec<u8>) -> bool;
    /// Total number of candidates, if known cheaply and exactly.
    fn total_hint(&self) -> Option<u64> {
        None
    }
}

/// Candidates read one-per-line from a file (classic wordlist / dictionary).
///
/// Trailing `\r`/`\n` are stripped so Windows (CRLF) lists behave like Unix ones.
/// Blank lines are skipped.
pub struct WordlistSource {
    reader: BufReader<File>,
}

impl WordlistSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file =
            File::open(path).with_context(|| format!("opening wordlist {}", path.display()))?;
        Ok(Self {
            reader: BufReader::new(file),
        })
    }
}

impl CandidateSource for WordlistSource {
    fn next_candidate(&mut self, buf: &mut Vec<u8>) -> bool {
        loop {
            buf.clear();
            let n = match self.reader.read_until(b'\n', buf) {
                Ok(n) => n,
                Err(_) => return false,
            };
            if n == 0 {
                return false; // EOF
            }
            while matches!(buf.last(), Some(b'\n' | b'\r')) {
                buf.pop();
            }
            if buf.is_empty() {
                continue; // skip blank lines
            }
            return true;
        }
    }
}

/// A brute-force mask: every combination of `charset` for each length in
/// `min_len..=max_len`.
///
/// This is an odometer. We keep a vector of indices into `charset`; each
/// `next_candidate` increments it like a base-N counter, rolling over to the
/// next length when a given length is exhausted.
pub struct MaskSpec {
    charset: Vec<u8>,
    min_len: usize,
    max_len: usize,
    // Current state.
    cur_len: usize,
    indices: Vec<usize>,
    started: bool,
    exhausted: bool,
}

impl MaskSpec {
    pub fn new(charset: &str, min_len: usize, max_len: usize) -> Result<Self> {
        anyhow::ensure!(!charset.is_empty(), "charset must not be empty");
        anyhow::ensure!(min_len >= 1, "min length must be >= 1");
        anyhow::ensure!(max_len >= min_len, "max length must be >= min length");
        // Dedupe charset bytes while preserving order; duplicates would generate
        // the same candidate many times.
        let mut seen = [false; 256];
        let mut bytes = Vec::new();
        for &b in charset.as_bytes() {
            if !seen[b as usize] {
                seen[b as usize] = true;
                bytes.push(b);
            }
        }
        Ok(Self {
            charset: bytes,
            min_len,
            max_len,
            cur_len: min_len,
            indices: vec![0; min_len],
            started: false,
            exhausted: false,
        })
    }
}

impl CandidateSource for MaskSpec {
    fn next_candidate(&mut self, buf: &mut Vec<u8>) -> bool {
        if self.exhausted {
            return false;
        }
        if !self.started {
            self.started = true;
            self.render(buf);
            return true;
        }
        // Increment the odometer (least-significant position is the last index).
        let base = self.charset.len();
        let mut pos = self.cur_len;
        loop {
            if pos == 0 {
                // Carried past the most-significant digit: this length is done.
                self.cur_len += 1;
                if self.cur_len > self.max_len {
                    self.exhausted = true;
                    return false;
                }
                self.indices = vec![0; self.cur_len];
                self.render(buf);
                return true;
            }
            pos -= 1;
            self.indices[pos] += 1;
            if self.indices[pos] < base {
                break;
            }
            self.indices[pos] = 0; // carry
        }
        self.render(buf);
        true
    }

    fn total_hint(&self) -> Option<u64> {
        let base = self.charset.len() as u128;
        let mut total: u128 = 0;
        for len in self.min_len..=self.max_len {
            total = total.checked_add(base.checked_pow(len as u32)?)?;
            if total > u64::MAX as u128 {
                return None; // too large to be a useful ETA anyway
            }
        }
        Some(total as u64)
    }
}

impl MaskSpec {
    fn render(&self, buf: &mut Vec<u8>) {
        buf.clear();
        buf.extend(self.indices.iter().map(|&i| self.charset[i]));
    }
}

/// Convenience charset aliases usable on the CLI, e.g. `?l?d`-style is overkill
/// for v1, so we expose named sets instead.
pub fn named_charset(name: &str) -> Option<&'static str> {
    Some(match name {
        "digits" => "0123456789",
        "lower" => "abcdefghijklmnopqrstuvwxyz",
        "upper" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "alpha" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "alnum" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "alnum-lower" => "abcdefghijklmnopqrstuvwxyz0123456789",
        "ascii" => {
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(mut s: impl CandidateSource) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = Vec::new();
        while s.next_candidate(&mut buf) {
            out.push(String::from_utf8(buf.clone()).unwrap());
        }
        out
    }

    /// Write `contents` to a uniquely-named temp file and return its path.
    fn temp_wordlist(tag: &str, contents: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "karkinos_brute_wl_{}_{}.txt",
            std::process::id(),
            tag
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn wordlist_strips_crlf_and_skips_blank_lines() {
        // Mixed CRLF/LF endings and blank lines (both kinds) must be normalized.
        let p = temp_wordlist("crlf", b"alpha\r\nbeta\n\n\r\ngamma\n");
        let got = collect(WordlistSource::open(&p).unwrap());
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn wordlist_handles_missing_trailing_newline() {
        let p = temp_wordlist("notrail", b"first\nsecond");
        let got = collect(WordlistSource::open(&p).unwrap());
        let _ = std::fs::remove_file(&p);
        assert_eq!(got, vec!["first", "second"]);
    }

    #[test]
    fn wordlist_empty_file_yields_nothing() {
        let p = temp_wordlist("empty", b"");
        let got = collect(WordlistSource::open(&p).unwrap());
        let _ = std::fs::remove_file(&p);
        assert!(got.is_empty());
    }

    #[test]
    fn mask_single_length() {
        let m = MaskSpec::new("ab", 2, 2).unwrap();
        assert_eq!(m.total_hint(), Some(4));
        assert_eq!(collect(m), vec!["aa", "ab", "ba", "bb"]);
    }

    #[test]
    fn mask_length_range() {
        let m = MaskSpec::new("ab", 1, 2).unwrap();
        assert_eq!(m.total_hint(), Some(6));
        assert_eq!(collect(m), vec!["a", "b", "aa", "ab", "ba", "bb"]);
    }

    #[test]
    fn mask_dedupes_charset() {
        let m = MaskSpec::new("aa", 1, 1).unwrap();
        assert_eq!(collect(m), vec!["a"]);
    }
}
