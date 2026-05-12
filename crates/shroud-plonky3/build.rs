//! Build script: derive `p3-symmetric` provenance from the workspace
//! `Cargo.lock` and surface it as compile-time environment variables.
//!
//! The advisory gate in `src/lib.rs` consumes these env vars to build
//! `PINNED_P3_SYMMETRIC_PROVENANCE`, a typed record of *where* the resolved
//! `p3-symmetric` crate came from. This closes two trust holes:
//!
//! 1. **Caller-supplied version** (closed in the prior pass) — `cargo:rustc-env`
//!    derivation means no caller can declare a version that doesn't match the
//!    actual lockfile resolution.
//!
//! 2. **Source conflation** (closed in this pass) — pointing `p3-zk-proofs`
//!    at a Plonky3 commit with the `Pad10Sponge` patch does NOT cause Cargo
//!    to use a patched `p3-symmetric`; Cargo still resolves `p3-symmetric`
//!    from `crates.io` unless an explicit `[patch.crates-io]` override
//!    redirects it. Therefore the provenance gate inspects `p3-symmetric`'s
//!    OWN `[[package]]` entry, not any transitively-related git revision.
//!
//! # Emitted env vars
//!
//! - `SHROUD_P3_SYM_MAJOR`, `SHROUD_P3_SYM_MINOR`, `SHROUD_P3_SYM_PATCH`
//!   — version components (existing).
//! - `SHROUD_P3_SYM_SOURCE_KIND_CODE` — `"0"` = registry, `"1"` = git.
//! - `SHROUD_P3_SYM_CHECKSUM` — checksum (registry) or empty (git).
//! - `SHROUD_P3_SYM_GIT_URL` — clean URL (git) or empty (registry).
//! - `SHROUD_P3_SYM_GIT_REV` — full resolved commit hash (git) or empty.
//!
//! # Multi-version handling
//!
//! Same policy as before: zero entries fail the build; multiple entries
//! resolving to identical (version, source, checksum) are fine; multiple
//! distinct resolutions fail the build with a clear ambiguity error.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
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

    let pkg = resolve_pinned_package(&contents);

    let parts: Vec<&str> = pkg.version.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "shroud-plonky3 build.rs: p3-symmetric version must be X.Y.Z, got {}",
        pkg.version
    );

    println!("cargo:rustc-env=SHROUD_P3_SYM_MAJOR={}", parts[0]);
    println!("cargo:rustc-env=SHROUD_P3_SYM_MINOR={}", parts[1]);
    println!("cargo:rustc-env=SHROUD_P3_SYM_PATCH={}", parts[2]);

    let parsed = parse_source(&pkg.source);
    match parsed {
        ParsedSource::Registry => {
            println!("cargo:rustc-env=SHROUD_P3_SYM_SOURCE_KIND_CODE=0");
            println!(
                "cargo:rustc-env=SHROUD_P3_SYM_CHECKSUM={}",
                pkg.checksum.as_deref().unwrap_or("")
            );
            println!("cargo:rustc-env=SHROUD_P3_SYM_GIT_URL=");
            println!("cargo:rustc-env=SHROUD_P3_SYM_GIT_REV=");
        }
        ParsedSource::Git { url, rev } => {
            println!("cargo:rustc-env=SHROUD_P3_SYM_SOURCE_KIND_CODE=1");
            println!("cargo:rustc-env=SHROUD_P3_SYM_CHECKSUM=");
            println!("cargo:rustc-env=SHROUD_P3_SYM_GIT_URL={url}");
            println!("cargo:rustc-env=SHROUD_P3_SYM_GIT_REV={rev}");
        }
    }
}

/// Minimal `[[package]]` projection for the resolved `p3-symmetric` entry.
struct PackageInfo {
    version: String,
    source: String,
    checksum: Option<String>,
}

/// Returns the single resolved `p3-symmetric` package, panicking on absence
/// or workspace-level ambiguity (multiple distinct resolutions).
fn resolve_pinned_package(lockfile: &str) -> PackageInfo {
    let mut packages = collect_p3_symmetric_packages(lockfile);
    if packages.is_empty() {
        panic!(
            "shroud-plonky3 build.rs: p3-symmetric not found in Cargo.lock; \
             this should not happen given the p3-zk-proofs dependency"
        );
    }
    // Dedup identical entries (same version + source + checksum). Multiple
    // distinct resolutions is ambiguous and must be resolved by a human.
    packages.sort_by(|a, b| {
        (a.version.as_str(), a.source.as_str(), a.checksum.as_deref()).cmp(&(
            b.version.as_str(),
            b.source.as_str(),
            b.checksum.as_deref(),
        ))
    });
    packages.dedup_by(|a, b| {
        a.version == b.version && a.source == b.source && a.checksum == b.checksum
    });
    if packages.len() > 1 {
        let descriptions: Vec<String> = packages
            .iter()
            .map(|p| {
                format!(
                    "{{ version: {}, source: {}, checksum: {:?} }}",
                    p.version, p.source, p.checksum
                )
            })
            .collect();
        panic!(
            "shroud-plonky3 build.rs: Cargo.lock resolves multiple distinct p3-symmetric entries ({descriptions:?}). \
             The advisory gate cannot pick one silently. Either deduplicate the workspace (e.g., via cargo update or \
             a [patch.crates-io] override) or extend this build script to trace the entry on the shroud-plonky3 -> \
             p3-zk-proofs path explicitly."
        );
    }
    packages.into_iter().next().unwrap()
}

/// Returns every `[[package]] name = "p3-symmetric"` entry's info, in
/// lockfile order. Each entry must have a `source` field (otherwise the
/// lockfile is malformed for our purposes).
///
/// State: `current` is `Some(_)` iff we're inside a `p3-symmetric` package
/// block. A new `name = "..."` line or a new `[[package]]`/`[section]`
/// header commits the in-progress entry (if any) and resets the tracker.
fn collect_p3_symmetric_packages(lockfile: &str) -> Vec<PackageInfo> {
    let mut out = Vec::new();
    let mut current: Option<PackageInfo> = None;

    for line in lockfile.lines() {
        let trimmed = line.trim();

        // Section / package boundary: commit any in-progress entry.
        if trimmed.starts_with("[[package]]") || trimmed.starts_with('[') {
            if let Some(pkg) = current.take() {
                out.push(pkg);
            }
            continue;
        }

        // Name line: commit previous, start a new entry iff it's p3-symmetric.
        if let Some(rest) = trimmed.strip_prefix("name = ") {
            if let Some(pkg) = current.take() {
                out.push(pkg);
            }
            if rest.trim_matches('"') == "p3-symmetric" {
                current = Some(PackageInfo {
                    version: String::new(),
                    source: String::new(),
                    checksum: None,
                });
            }
            continue;
        }

        // Field line: only meaningful if we're inside a p3-symmetric block.
        let Some(pkg) = current.as_mut() else {
            continue;
        };
        if let Some(rest) = trimmed.strip_prefix("version = ") {
            pkg.version = rest.trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("source = ") {
            pkg.source = rest.trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("checksum = ") {
            pkg.checksum = Some(rest.trim_matches('"').to_string());
        }
    }

    // Commit the trailing entry, if any.
    if let Some(pkg) = current.take() {
        out.push(pkg);
    }

    // Sanity: every collected entry must have a non-empty source.
    for pkg in &out {
        assert!(
            !pkg.source.is_empty(),
            "shroud-plonky3 build.rs: p3-symmetric package in Cargo.lock has no source field; version = {}",
            pkg.version
        );
    }

    out
}

/// Parsed Cargo source descriptor.
enum ParsedSource {
    Registry,
    Git { url: String, rev: String },
}

/// Parses a Cargo.lock `source = "..."` value.
///
/// Registry sources look like `"registry+https://..."`. The registry URL is
/// not surfaced — the checksum (recorded elsewhere in the package block) is
/// the audit hook for registry resolution.
///
/// Git sources look like `"git+URL#FULL_HASH"` or
/// `"git+URL?rev=X#FULL_HASH"` or with `?branch=` / `?tag=` query params.
/// The portion after `#` is the resolved commit hash (Cargo always pins git
/// deps to a specific commit in the lockfile). The portion before the first
/// `?` or `#` is the clean repo URL.
fn parse_source(source: &str) -> ParsedSource {
    if source.starts_with("registry+") {
        ParsedSource::Registry
    } else if let Some(rest) = source.strip_prefix("git+") {
        let (url_and_query, rev) = rest.rsplit_once('#').unwrap_or((rest, ""));
        assert!(
            !rev.is_empty(),
            "shroud-plonky3 build.rs: git p3-symmetric source {source:?} has no resolved commit hash after `#`; \
             Cargo.lock must pin git dependencies to a concrete revision"
        );
        let url = url_and_query
            .split('?')
            .next()
            .unwrap_or(url_and_query)
            .to_string();
        ParsedSource::Git {
            url,
            rev: rev.to_string(),
        }
    } else {
        panic!(
            "shroud-plonky3 build.rs: unknown p3-symmetric source format {source:?}; \
             expected `registry+...` or `git+...`"
        );
    }
}
