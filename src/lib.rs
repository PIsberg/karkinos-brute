//! A pluggable bruteforce framework.
//!
//! The design separates three concerns:
//!   * [`engine::candidate`] — *where guesses come from* (wordlists, masks, ...).
//!   * [`engine::runner`]    — *how guesses are dispatched* (parallel, stop-on-hit).
//!   * [`target`]            — *what a guess is tested against* (the [`target::Target`] trait).
//!
//! A new attack is just a new [`target::Target`] implementation; the engine is
//! reused unchanged. The first bundled module is [`target::yopass`].

pub mod engine;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod target;
