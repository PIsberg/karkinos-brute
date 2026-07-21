//! ArchUnit-style architecture tests.
//!
//! Rust has no ArchUnit, so this is the closest equivalent: a test that scans
//! the source tree and asserts the layering rules the crate documents in
//! `src/lib.rs` / `CLAUDE.md`. Like ArchUnit, it checks *dependencies between
//! layers* rather than behavior, and fails the build when a layer reaches
//! somewhere it shouldn't.
//!
//! The two invariants:
//!   1. The **target** layer (what a guess is tested against) must not depend on
//!      the **dispatch** layer (`engine::runner`) or the GPU orchestration — a
//!      `Target` only implements the per-candidate contract; it never knows how
//!      guesses are scheduled.
//!   2. The **engine** layer is target-agnostic: it may use the `Target` *trait*
//!      but must not reference any concrete target module (yopass, privatebin, …).
//!
//! Both are enforced by structure today; this test keeps them that way as new
//! targets are added.

use std::fs;
use std::path::{Path, PathBuf};

/// The concrete target modules the engine must stay ignorant of.
const CONCRETE_TARGETS: &[&str] = &[
    "yopass",
    "privatebin",
    "pwpush",
    "onetimesecret",
    "deleto",
    "skesk_v6",
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Read every `.rs` file directly inside `dir`, returning (filename, source).
/// Comment lines are stripped so a module name merely *mentioned* in prose does
/// not count as a dependency (ArchUnit inspects references, not documentation).
fn rust_files_in(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).expect("read src subdir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let raw = fs::read_to_string(&path).expect("read source file");
        let code: String = raw
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        out.push((name, code));
    }
    out
}

#[test]
fn targets_do_not_depend_on_the_dispatch_layer() {
    let dir = src_dir().join("target");
    let mut violations = Vec::new();
    for (name, code) in rust_files_in(&dir) {
        if name == "mod.rs" {
            continue;
        }
        for forbidden in ["engine::runner", "crate::gpu", "gpu::"] {
            if code.contains(forbidden) {
                violations.push(format!("target/{name} references `{forbidden}`"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "target layer must not depend on the dispatch/GPU layer:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn engine_is_target_agnostic() {
    let dir = src_dir().join("engine");
    let mut violations = Vec::new();
    for (name, code) in rust_files_in(&dir) {
        for target in CONCRETE_TARGETS {
            let needle = format!("target::{target}");
            if code.contains(&needle) {
                violations.push(format!("engine/{name} references `{needle}`"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "engine layer must not depend on any concrete target module:\n  {}",
        violations.join("\n  ")
    );
}
