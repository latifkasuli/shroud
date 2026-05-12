//! Build script: derive the actually-resolved `p3-symmetric` version from the
//! workspace `Cargo.lock` and surface it as `SHROUD_P3_SYM_{MAJOR,MINOR,PATCH}`
//! environment variables.
//!
//! This is the answer to the GHSA-3g92-f9ch-qjcm trust hole: a caller-supplied
//! `P3SymmetricVersion` can lie about the underlying stack; a build-time
//! derivation from the lockfile cannot. `PINNED_P3_SYMMETRIC_VERSION` in
//! `src/lib.rs` is built from these env vars and reflects the real dependency
//! graph at compile time.
//!
//! # Multi-version handling
//!
//! Cargo permits multiple resolved versions of a package across the workspace
//! (e.g., one crate needs `< 0.6` and another needs `>= 0.6`). Silently picking
//! the first lockfile match would mislead the advisory gate.
//!
//! This script collects every `[[package]] name = "p3-symmetric"` entry, then:
//!
//! - if zero entries are present, fails the build (the dep is required);
//! - if all entries resolve to the same version, uses it;
//! - if multiple **distinct** versions are present, fails the build with a
//!   clear error listing them — ambiguity is itself a security signal and
//!   forces investigation rather than guesswork.
//!
//! TODO(production-gate): once `shroud-plonky3` ships as a production bridge,
//! reject the build here if the resolved version is `< 0.6.0` per
//! [GHSA-3g92-f9ch-qjcm]. Currently the runtime check in `lib.rs` surfaces
//! [`BackendDriftError::UnpatchedSymmetric`] instead, so dev work can continue
//! while the pinned `p3-zk-proofs` revision is upgraded.
//!
//! [GHSA-3g92-f9ch-qjcm]: https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // The lockfile lives at the workspace root, two levels up from the crate.
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("shroud-plonky3 build.rs: CARGO_MANIFEST_DIR is always set by cargo");
    let lockfile = PathBuf::from(&manifest_dir).join("../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lockfile.display());

    let contents = fs::read_to_string(&lockfile).unwrap_or_else(|err| {
        panic!(
            "shroud-plonky3 build.rs: failed to read workspace Cargo.lock at {}: {err}",
            lockfile.display()
        )
    });

    let version = resolve_pinned_version(&contents);

    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "shroud-plonky3 build.rs: p3-symmetric version must be X.Y.Z, got {version}"
    );

    println!("cargo:rustc-env=SHROUD_P3_SYM_MAJOR={}", parts[0]);
    println!("cargo:rustc-env=SHROUD_P3_SYM_MINOR={}", parts[1]);
    println!("cargo:rustc-env=SHROUD_P3_SYM_PATCH={}", parts[2]);
}

/// Resolves the single `p3-symmetric` version from the lockfile contents.
///
/// Panics with a clear message if the dep is missing or if the workspace
/// resolves multiple distinct versions of it.
fn resolve_pinned_version(lockfile: &str) -> String {
    let versions = collect_p3_symmetric_versions(lockfile);

    match versions.as_slice() {
        [] => panic!(
            "shroud-plonky3 build.rs: p3-symmetric not found in Cargo.lock; \
             this should not happen given the p3-zk-proofs dependency"
        ),
        _ => {
            // Deduplicate. Multiple identical entries are fine (different
            // [[package]] blocks pointing to the same version); multiple
            // distinct entries are a workspace-level ambiguity that must be
            // resolved by a human, not silently smoothed over here.
            let mut sorted = versions.clone();
            sorted.sort();
            sorted.dedup();
            match sorted.len() {
                1 => sorted.into_iter().next().unwrap(),
                _ => panic!(
                    "shroud-plonky3 build.rs: Cargo.lock resolves multiple distinct p3-symmetric versions ({sorted:?}). \
                     The advisory gate (GHSA-3g92-f9ch-qjcm) cannot pick one silently. \
                     Either deduplicate the workspace (e.g., via cargo update) or extend this build script to trace \
                     the version on the shroud-plonky3 -> p3-zk-proofs path explicitly."
                ),
            }
        }
    }
}

/// Returns the version of every `[[package]] name = "p3-symmetric"` entry in
/// the lockfile, in the order they appear.
fn collect_p3_symmetric_versions(lockfile: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = lockfile.lines();
    while let Some(line) = lines.next() {
        if line.trim() == r#"name = "p3-symmetric""# {
            for next in lines.by_ref() {
                let trimmed = next.trim();
                if let Some(rest) = trimmed.strip_prefix("version = ") {
                    out.push(rest.trim_matches('"').to_string());
                    break;
                }
                if trimmed.starts_with("name = ") {
                    // Reached next package without finding version — malformed entry; bail.
                    break;
                }
            }
        }
    }
    out
}
