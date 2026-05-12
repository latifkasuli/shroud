#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Backend-specific bridge: SHROUD profiles and hash-suite identifiers
//! against the pinned `p3-zk-proofs` backend.
//!
//! This crate is the audit surface for the Plonky3 integration. It pins:
//!
//! - the backend's hiding-PCS constants — [`BACKEND_LOG_BLOWUP`],
//!   [`BACKEND_NUM_RANDOMIZER_COLS`], [`BACKEND_EXTENSION_DEGREE`],
//!   [`BACKEND_NUM_QUERIES`], [`BACKEND_QUERY_POW_BITS`];
//! - the **build-time-derived** `p3-symmetric` version
//!   ([`PINNED_P3_SYMMETRIC_VERSION`]) and the advisory floor
//!   ([`P3SymmetricVersion::MIN_PATCHED`]) from [GHSA-3g92-f9ch-qjcm];
//! - the canonical hash-suite identifier ([`Plonky3HashIdentifier::standard`]),
//!   which embeds the resolved `p3-symmetric` version so transcripts cannot
//!   replay under a different stack.
//!
//! It exists as a separate crate to keep `shroud-reference` backend-neutral
//! while the bridge surface grows.
//!
//! # Trust model — no caller-supplied advisory state
//!
//! Earlier versions of this crate accepted a `P3SymmetricVersion` parameter,
//! which let callers declare a patched version against an unpatched
//! dependency graph. That is the exact failure mode the advisory describes:
//! the auditable artifact must reflect the *actually-resolved* dependency.
//!
//! [`PINNED_P3_SYMMETRIC_VERSION`] is now derived at build time by `build.rs`,
//! which parses the workspace `Cargo.lock`. Public APIs read from the const;
//! there is no caller-supplied path.
//!
//! While the resolved `p3-symmetric` remains `< 0.6`,
//! [`verify_profile_matches_backend`] returns
//! [`BackendDriftError::UnpatchedSymmetric`] for every profile. That is the
//! honest state: the bridge is not safe to use in production until the
//! pinned `p3-zk-proofs` revision is updated to a stack that resolves
//! `p3-symmetric >= 0.6`.
//!
//! [GHSA-3g92-f9ch-qjcm]: https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm

use core::fmt;

pub use p3_zk_proofs::backend::{HidingBackend, HidingConfig};
use shroud_core::{HashIdentifier, HidingTechniqueClaim, TranscriptBindable, TranscriptBinding};
use shroud_reference::ReferenceHidingFriPcsProfile;

pub mod extended_bindings;

pub use extended_bindings::{
    DOMAIN_PLONKY3_AIR_PUBLIC_VALUES, DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS,
    DOMAIN_PLONKY3_FRI_FINAL_POLY, DOMAIN_PLONKY3_FRI_LOG_ARITIES, DOMAIN_PLONKY3_LOG_DEGREE,
    DOMAIN_PLONKY3_LOG_EXT_DEGREE, DOMAIN_PLONKY3_OPENED_VALUES,
    DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT, DOMAIN_PLONKY3_PREPROCESSED_WIDTH,
    DOMAIN_PLONKY3_QUOTIENT_COMMITMENT, DOMAIN_PLONKY3_TRACE_COMMITMENT, Plonky3UniStarkBindings,
};

// ── Pinned backend constants ─────────────────────────────────────────────────

/// Pinned backend constant: `LOG_BLOWUP_HIDING` in `p3-zk-proofs::backend`.
pub const BACKEND_LOG_BLOWUP: usize = 2;

/// Pinned backend constant: `NUM_RANDOMIZER_COLS` in `p3-zk-proofs::backend`.
pub const BACKEND_NUM_RANDOMIZER_COLS: usize = 4;

/// Pinned backend constant: degree of `BinomialExtensionField<BabyBear, 4>`.
pub const BACKEND_EXTENSION_DEGREE: usize = 4;

/// Pinned backend constant: `NUM_QUERIES` in `p3-zk-proofs::backend`.
pub const BACKEND_NUM_QUERIES: usize = 40;

/// Pinned backend constant: `QUERY_POW_BITS` in `p3-zk-proofs::backend`.
pub const BACKEND_QUERY_POW_BITS: usize = 8;

// ── p3-symmetric advisory ────────────────────────────────────────────────────

/// Declared semantic version of `p3-symmetric` resolved by the dependency graph.
///
/// Constructed by [`Self::new`] from build-time inputs. The
/// [`PINNED_P3_SYMMETRIC_VERSION`] constant is the only authoritative source
/// for the bridge — it is built from `cargo:rustc-env` variables emitted by
/// `build.rs`, which parses the workspace `Cargo.lock`. Callers cannot supply
/// their own version to the public verification APIs.
///
/// See [GHSA-3g92-f9ch-qjcm]: `p3-symmetric < 0.6` admits sponge-length
/// collisions when an attacker can vary the number of hashed elements.
/// SHROUD's [`shroud_core::TranscriptBinding`] payloads are length-prefixed
/// throughout, which mitigates the surface, but the bridge MUST reject
/// unpatched stacks as defense in depth.
///
/// [GHSA-3g92-f9ch-qjcm]: https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct P3SymmetricVersion {
    /// Major version component.
    pub major: u64,
    /// Minor version component.
    pub minor: u64,
    /// Patch version component.
    pub patch: u64,
}

impl P3SymmetricVersion {
    /// Minimum patched version per [GHSA-3g92-f9ch-qjcm] (published 2026-04-16).
    ///
    /// [GHSA-3g92-f9ch-qjcm]: https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm
    pub const MIN_PATCHED: Self = Self::new(0, 6, 0);

    /// Constructs a [`P3SymmetricVersion`] from major/minor/patch components.
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns `true` if this version is at least [`Self::MIN_PATCHED`].
    ///
    /// Lexicographic compare over `(major, minor, patch)`. Written manually
    /// (rather than as `*self >= Self::MIN_PATCHED` over a derived `PartialOrd`)
    /// so this stays `const fn` — the const is consumed by the const advisory
    /// gate in [`check_advisory`].
    #[must_use]
    #[allow(clippy::absurd_extreme_comparisons)] // MIN_PATCHED components may be u64::MIN; the form is intentional
    pub const fn is_patched(&self) -> bool {
        if self.major != Self::MIN_PATCHED.major {
            return self.major > Self::MIN_PATCHED.major;
        }
        if self.minor != Self::MIN_PATCHED.minor {
            return self.minor > Self::MIN_PATCHED.minor;
        }
        self.patch >= Self::MIN_PATCHED.patch
    }
}

impl fmt::Display for P3SymmetricVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ── Build-time-derived pinned version ────────────────────────────────────────

/// Const-context parser for ASCII-digit `u64` literals emitted by `build.rs`.
const fn parse_const_u64(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let mut acc: u64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < b'0' || b > b'9' {
            panic!("p3-symmetric version component must contain only ASCII digits");
        }
        acc = acc * 10 + (b - b'0') as u64;
        i += 1;
    }
    acc
}

/// Where the resolved `p3-symmetric` came from. Built from `Cargo.lock` at
/// build time; callers cannot override it.
///
/// The provenance gate ([`check_advisory`]) inspects this OWN provenance of
/// `p3-symmetric`, never `p3-zk-proofs`'s or any other crate's. The Cargo
/// dependency graph can have `p3-zk-proofs` pinned to a patched Plonky3
/// commit yet still resolve `p3-symmetric` from `crates.io` — only a
/// `[patch.crates-io]` redirect changes `p3-symmetric`'s own source. This
/// type makes that distinction structural rather than narrative.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum P3SymmetricProvenance {
    /// Resolved from a Cargo registry (typically `crates.io`).
    Registry {
        /// Declared semver from the lockfile entry.
        version: P3SymmetricVersion,
        /// SHA-256 of the `.crate` artifact, as recorded by Cargo. Empty
        /// string if the lockfile entry lacks a `checksum` line.
        checksum: &'static str,
    },
    /// Resolved from a Git source (e.g. via `[patch.crates-io]` override).
    Git {
        /// Declared semver from the lockfile entry. Note: this can be
        /// anything the upstream `Cargo.toml` sets, including pre-`0.6`
        /// numbers on a patched commit. **Do not infer patch state from
        /// version alone for Git sources** — match `(source_url, rev)`
        /// against [`KNOWN_PATCHED_P3_SYMMETRIC_SOURCES`].
        version: P3SymmetricVersion,
        /// Clean repository URL (everything before `?` or `#`).
        source_url: &'static str,
        /// Full resolved commit hash (Cargo pins git deps to a specific commit).
        rev: &'static str,
    },
}

impl P3SymmetricProvenance {
    /// Declared semver, regardless of source kind.
    #[must_use]
    pub const fn version(&self) -> P3SymmetricVersion {
        match self {
            Self::Registry { version, .. } | Self::Git { version, .. } => *version,
        }
    }
}

impl fmt::Display for P3SymmetricProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry { version, checksum } => {
                write!(f, "registry: version {version}, checksum {checksum:?}")
            }
            Self::Git {
                version,
                source_url,
                rev,
            } => write!(f, "git: version {version}, source {source_url}, rev {rev}"),
        }
    }
}

/// Build-time-derived provenance for the resolved `p3-symmetric` crate.
///
/// This is the only authoritative provenance source used by [`check_advisory`]
/// and [`verify_profile_matches_backend`]. The `build.rs` script parses
/// `Cargo.lock` directly; lockfile changes trigger a build-script re-run
/// so the const updates automatically.
pub const PINNED_P3_SYMMETRIC_PROVENANCE: P3SymmetricProvenance = {
    let version = P3SymmetricVersion::new(
        parse_const_u64(env!("SHROUD_P3_SYM_MAJOR")),
        parse_const_u64(env!("SHROUD_P3_SYM_MINOR")),
        parse_const_u64(env!("SHROUD_P3_SYM_PATCH")),
    );
    let kind = parse_const_u64(env!("SHROUD_P3_SYM_SOURCE_KIND_CODE"));
    if kind == 0 {
        P3SymmetricProvenance::Registry {
            version,
            checksum: env!("SHROUD_P3_SYM_CHECKSUM"),
        }
    } else if kind == 1 {
        P3SymmetricProvenance::Git {
            version,
            source_url: env!("SHROUD_P3_SYM_GIT_URL"),
            rev: env!("SHROUD_P3_SYM_GIT_REV"),
        }
    } else {
        panic!("invalid SHROUD_P3_SYM_SOURCE_KIND_CODE; expected 0 or 1");
    }
};

/// The actually-resolved `p3-symmetric` version, derived from `Cargo.lock` at
/// build time.
///
/// This is a convenience accessor over [`PINNED_P3_SYMMETRIC_PROVENANCE`] for
/// callers that only need the semver and don't care about the source kind.
/// Most advisory-gate logic should consume the full provenance instead, since
/// version alone does not establish patch state for git sources.
pub const PINNED_P3_SYMMETRIC_VERSION: P3SymmetricVersion =
    PINNED_P3_SYMMETRIC_PROVENANCE.version();

/// Allowlist of (repository URL, commit hash) pairs for `p3-symmetric` git
/// sources that have been reviewed and confirmed to contain the
/// [GHSA-3g92-f9ch-qjcm] patch (the `Pad10Sponge` fix or an equivalent that
/// closes sponge-length collision).
///
/// # ⚠️ Adding an entry is security-critical
///
/// Each entry MUST be justified by:
///
/// 1. The upstream commit URL in the PR description, with a one-paragraph
///    review of the diff that closes the advisory.
/// 2. Confirmation that the diff modifies `p3-symmetric` itself (NOT a
///    transitively-related crate like `p3-zk-proofs`).
/// 3. A co-sign from someone other than the bumper.
///
/// See `docs/security-model.md` § 4 for the full audit obligation.
///
/// This list is intentionally empty until the workspace actually patches the
/// dependency graph via `[patch.crates-io]`. The clean path is an upstream
/// `p3-symmetric >= 0.6.0` registry release; the allowlist is the escape
/// hatch for cases where that release has not landed.
///
/// [GHSA-3g92-f9ch-qjcm]: https://github.com/Plonky3/Plonky3/security/advisories/GHSA-3g92-f9ch-qjcm
pub const KNOWN_PATCHED_P3_SYMMETRIC_SOURCES: &[(&str, &str)] = &[];

// ── BackendDriftError + verification ─────────────────────────────────────────

/// First detected mismatch between a `ReferenceHidingFriPcsProfile` and the
/// pinned `p3-zk-proofs` backend, or an advisory violation.
///
/// Each variant carries enough state for a consumer to react programmatically
/// rather than parsing a string. `Display` produces a stable human-readable
/// message; `std::error::Error` is implemented for ergonomics.
///
/// `Copy` is intentionally not derived — [`Self::MissingHidingTechnique`]
/// carries a `HidingTechniqueClaim` which contains owned data
/// (`Composite`'s `Box`, `BackendSpecific`'s `String`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendDriftError {
    /// `log_blowup` does not match [`BACKEND_LOG_BLOWUP`].
    LogBlowup {
        /// Pinned-backend value.
        expected: usize,
        /// Value declared by the profile.
        actual: usize,
    },
    /// `num_random_codewords` does not match [`BACKEND_NUM_RANDOMIZER_COLS`].
    NumRandomizerCols {
        /// Pinned-backend value.
        expected: usize,
        /// Value declared by the profile.
        actual: usize,
    },
    /// `basis.extension_degree` does not match [`BACKEND_EXTENSION_DEGREE`].
    ExtensionDegree {
        /// Pinned-backend value.
        expected: usize,
        /// Value declared by the profile.
        actual: usize,
    },
    /// The resolved `p3-symmetric` does not satisfy the advisory floor.
    ///
    /// Provenance is derived from `Cargo.lock` by `build.rs` — not from the
    /// caller. Failure modes:
    ///
    /// - **Registry, version < 0.6.0** — no patched registry release is
    ///   available; bridge cannot start. Wait for an upstream `>= 0.6.0`
    ///   release, or add a `[patch.crates-io]` redirect to a reviewed git
    ///   source.
    /// - **Git, version < 0.6.0, `(source_url, rev)` not in allowlist** —
    ///   the workspace overrides `p3-symmetric` to a git source, but the
    ///   specific commit has not been audit-reviewed and added to
    ///   [`KNOWN_PATCHED_P3_SYMMETRIC_SOURCES`].
    ///
    /// A caller-supplied "is patched" claim cannot satisfy the gate —
    /// provenance is structural, not declarative.
    UnpatchedSymmetric {
        /// Resolved provenance that failed the gate.
        provenance: P3SymmetricProvenance,
        /// Minimum patched version per the advisory.
        min_patched: P3SymmetricVersion,
    },
    /// The profile declares `input_mmcs_hiding = false`.
    ///
    /// `HidingFriPcs` documents that the input MMCS MUST be hiding. A
    /// non-hiding input MMCS leaks witness rows on query, defeating
    /// polynomial randomization regardless of how the FRI layer is
    /// configured.
    NonHidingInputMmcs,
    /// The profile declares `fri_mmcs_hiding = false`.
    ///
    /// `HidingFriPcs` documents that the FRI query-phase MMCS MUST also be
    /// hiding. A non-hiding FRI MMCS leaks intermediate Reed-Solomon values
    /// on query.
    NonHidingFriMmcs,
    /// The profile's declared [`HidingTechniqueClaim`] does not contain a
    /// technique that the pinned Plonky3 backend stack requires.
    ///
    /// The bridge stack is `Composite(RandomCodewordInterleaving,
    /// QuotientChunkRandomization, RandomRowPadding)`. If any of those three
    /// is absent from the claim tree, the profile cannot be audited against
    /// the backend's hiding semantics.
    MissingHidingTechnique {
        /// The required technique that is absent from the declared claim.
        technique: HidingTechniqueClaim,
    },
}

impl fmt::Display for BackendDriftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LogBlowup { expected, actual } => write!(
                f,
                "log_blowup drifted from backend LOG_BLOWUP_HIDING: expected {expected}, got {actual}"
            ),
            Self::NumRandomizerCols { expected, actual } => write!(
                f,
                "num_random_codewords drifted from backend NUM_RANDOMIZER_COLS: expected {expected}, got {actual}"
            ),
            Self::ExtensionDegree { expected, actual } => write!(
                f,
                "basis extension degree drifted from backend BinomialExtensionField<BabyBear, 4>: expected {expected}, got {actual}"
            ),
            Self::UnpatchedSymmetric {
                provenance,
                min_patched,
            } => write!(
                f,
                "p3-symmetric failed the GHSA-3g92-f9ch-qjcm advisory gate: \
                 resolved {provenance}; advisory floor is version >= {min_patched} OR a \
                 git source matching shroud_plonky3::KNOWN_PATCHED_P3_SYMMETRIC_SOURCES. \
                 The bridge refuses to start until either the registry resolves a patched \
                 release or the workspace adds a [patch.crates-io] redirect pointing \
                 p3-symmetric at a reviewed git commit"
            ),
            Self::NonHidingInputMmcs => write!(
                f,
                "profile declares input_mmcs_hiding = false; HidingFriPcs requires a hiding input MMCS"
            ),
            Self::NonHidingFriMmcs => write!(
                f,
                "profile declares fri_mmcs_hiding = false; HidingFriPcs requires a hiding FRI MMCS"
            ),
            Self::MissingHidingTechnique { technique } => write!(
                f,
                "profile's hiding_technique claim does not contain {technique}; \
                 the pinned Plonky3 stack composes RandomCodewordInterleaving, \
                 QuotientChunkRandomization, and RandomRowPadding"
            ),
        }
    }
}

impl std::error::Error for BackendDriftError {}

/// Returns the three [`HidingTechniqueClaim`] variants that the pinned Plonky3
/// backend stack composes.
///
/// A profile's `hiding_technique` must contain each of these (via
/// `HidingTechniqueClaim::contains`) to pass [`check_profile_drift`].
#[must_use]
pub fn required_plonky3_hiding_techniques() -> [HidingTechniqueClaim; 3] {
    [
        HidingTechniqueClaim::RandomCodewordInterleaving,
        HidingTechniqueClaim::QuotientChunkRandomization,
        HidingTechniqueClaim::RandomRowPadding,
    ]
}

/// Checks the resolved `p3-symmetric` provenance against the advisory.
///
/// Passes iff:
///
/// 1. The source is `Registry` and the declared version is `>= 0.6.0`, OR
/// 2. The source is `Git` AND `(source_url, rev)` matches an entry in
///    [`KNOWN_PATCHED_P3_SYMMETRIC_SOURCES`].
///
/// The Git allowlist path requires that `p3-symmetric` *itself* be
/// redirected to a reviewed git source (typically via `[patch.crates-io]`).
/// A patched `p3-zk-proofs` revision does NOT satisfy the gate unless the
/// dependency graph also redirects `p3-symmetric` — see the
/// [`P3SymmetricProvenance`] doc comment for why version-alone cannot be
/// trusted on git sources.
pub fn check_advisory() -> Result<(), BackendDriftError> {
    verify_provenance(
        PINNED_P3_SYMMETRIC_PROVENANCE,
        KNOWN_PATCHED_P3_SYMMETRIC_SOURCES,
    )
}

/// Pure-function variant of [`check_advisory`] used by both the production
/// gate and the test suite. Returns `Ok` iff the given provenance meets the
/// advisory floor under the given allowlist.
///
/// Exposed (rather than private) so test code can exercise the Git
/// allowlist match path with synthetic provenance — the production
/// allowlist is intentionally empty until a real patched source is
/// reviewed.
pub fn verify_provenance(
    provenance: P3SymmetricProvenance,
    allowlist: &[(&str, &str)],
) -> Result<(), BackendDriftError> {
    match provenance {
        P3SymmetricProvenance::Registry { version, .. } if version.is_patched() => {
            return Ok(());
        }
        P3SymmetricProvenance::Git {
            source_url, rev, ..
        } if allowlist.iter().any(|(u, r)| *u == source_url && *r == rev) => {
            return Ok(());
        }
        _ => {}
    }
    Err(BackendDriftError::UnpatchedSymmetric {
        provenance,
        min_patched: P3SymmetricVersion::MIN_PATCHED,
    })
}

/// Checks every profile field that influences the bridge's hiding semantics
/// against the pinned backend constants.
///
/// Independent of [`check_advisory`], so callers (and tests) can verify the
/// profile-drift checks even on an advisory-failing stack. The combined
/// production check is [`verify_profile_matches_backend`].
///
/// Checked in declaration order; the first detected drift is returned:
/// `log_blowup` → `num_random_codewords` → `basis.extension_degree`
/// → `input_mmcs_hiding` → `fri_mmcs_hiding` → required hiding techniques.
pub fn check_profile_drift(
    profile: &ReferenceHidingFriPcsProfile,
) -> Result<(), BackendDriftError> {
    if profile.log_blowup != BACKEND_LOG_BLOWUP {
        return Err(BackendDriftError::LogBlowup {
            expected: BACKEND_LOG_BLOWUP,
            actual: profile.log_blowup,
        });
    }
    if profile.num_random_codewords != BACKEND_NUM_RANDOMIZER_COLS {
        return Err(BackendDriftError::NumRandomizerCols {
            expected: BACKEND_NUM_RANDOMIZER_COLS,
            actual: profile.num_random_codewords,
        });
    }
    if profile.basis.extension_degree != BACKEND_EXTENSION_DEGREE {
        return Err(BackendDriftError::ExtensionDegree {
            expected: BACKEND_EXTENSION_DEGREE,
            actual: profile.basis.extension_degree,
        });
    }
    if !profile.input_mmcs_hiding {
        return Err(BackendDriftError::NonHidingInputMmcs);
    }
    if !profile.fri_mmcs_hiding {
        return Err(BackendDriftError::NonHidingFriMmcs);
    }
    for technique in required_plonky3_hiding_techniques() {
        if !profile.hiding_technique.contains(&technique) {
            return Err(BackendDriftError::MissingHidingTechnique { technique });
        }
    }
    Ok(())
}

/// Verifies the supplied profile against the pinned backend AND the advisory.
///
/// The advisory check fires first because without a patched `p3-symmetric`,
/// every other check is built on quicksand.
///
/// Production bridge code calls this as the verifier-trust enforcement
/// primitive during setup. The pinned `p3-symmetric` version is derived from
/// `Cargo.lock` at build time — the caller cannot supply it, which closes
/// the trust hole identified in the GHSA-3g92-f9ch-qjcm review pass.
pub fn verify_profile_matches_backend(
    profile: &ReferenceHidingFriPcsProfile,
) -> Result<(), BackendDriftError> {
    check_advisory()?;
    check_profile_drift(profile)?;
    Ok(())
}

/// Asserts that `ReferenceHidingFriPcsProfile::standard()` matches the constants
/// used by [`HidingBackend`] in the pinned `p3-zk-proofs` crate AND that the
/// resolved `p3-symmetric` meets the advisory floor.
///
/// # Panics
///
/// Panics with the drift reason returned by [`verify_profile_matches_backend`]
/// if any field disagrees with the backend constants or the resolved
/// `p3-symmetric` is unpatched. Under the current pinned `p3-zk-proofs`
/// revision (which resolves `p3-symmetric = 0.5.2`) this function panics
/// unconditionally with [`BackendDriftError::UnpatchedSymmetric`]. That is
/// the intended honest signal — the bridge is not production-safe until the
/// pinned revision is updated.
pub fn assert_profile_matches_backend() {
    let profile = ReferenceHidingFriPcsProfile::standard();
    if let Err(drift) = verify_profile_matches_backend(&profile) {
        panic!("{drift}");
    }
}

// ── Plonky3HashIdentifier ────────────────────────────────────────────────────

/// Canonical hash-suite identifier for the pinned Plonky3 backend stack.
///
/// SHROUD's transcript replay rejects proofs derived under a different hash
/// suite via [`shroud_core::HashIdentifier`]. For Plonky3 bridges, a free-form
/// string is too loose — auditors need to know *exactly* which combination of
/// field, extension, hash, sponge, challenger, MMCS, DFT, RNG, and resolved
/// `p3-symmetric` version produced the challenges.
///
/// [`Self::standard`] produces the canonical identifier for the pinned
/// `p3-zk-proofs` backend at commit `d0c9fbc54e2314a90edd6a6ef84055c1179a4754`.
/// The embedded `p3-symmetric` version is [`PINNED_P3_SYMMETRIC_VERSION`] —
/// the actual resolved value, not a caller-supplied one — so changing the
/// underlying dep necessarily changes the rendered identifier and replay
/// rejects across the boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plonky3HashIdentifier {
    field: &'static str,
    extension_degree: usize,
    byte_hash: &'static str,
    sponge: &'static str,
    challenger: &'static str,
    val_mmcs: &'static str,
    challenge_mmcs: &'static str,
    dft: &'static str,
    rng: &'static str,
    log_blowup: usize,
    num_randomizer_cols: usize,
    num_queries: usize,
    query_pow_bits: usize,
    p3_symmetric: P3SymmetricVersion,
}

impl Plonky3HashIdentifier {
    /// Returns the canonical identifier for the pinned `p3-zk-proofs` backend.
    ///
    /// Components correspond exactly to the type aliases in
    /// `p3_zk_proofs::backend` at the pinned commit. The embedded
    /// `p3-symmetric` version is read from [`PINNED_P3_SYMMETRIC_VERSION`].
    /// Updating the pinned revision changes the rendered identifier
    /// automatically through the build-time derivation.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            field: "babybear",
            extension_degree: BACKEND_EXTENSION_DEGREE,
            byte_hash: "keccak256",
            sponge: "pf_sponge_25_17_4",
            challenger: "ser_chal32",
            val_mmcs: "mtree_hiding_mmcs",
            challenge_mmcs: "ext_mmcs",
            dft: "radix2_dit_parallel",
            rng: "hiding_rng",
            log_blowup: BACKEND_LOG_BLOWUP,
            num_randomizer_cols: BACKEND_NUM_RANDOMIZER_COLS,
            num_queries: BACKEND_NUM_QUERIES,
            query_pow_bits: BACKEND_QUERY_POW_BITS,
            p3_symmetric: PINNED_P3_SYMMETRIC_VERSION,
        }
    }

    /// Renders the canonical identifier as a stable, colon-separated string.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "plonky3-zk:v1:{}:ext{}:{}:{}:{}:{}:{}:{}:{}:log_blowup{}:randomizers{}:queries{}:pow{}:p3sym{}",
            self.field,
            self.extension_degree,
            self.byte_hash,
            self.sponge,
            self.challenger,
            self.val_mmcs,
            self.challenge_mmcs,
            self.dft,
            self.rng,
            self.log_blowup,
            self.num_randomizer_cols,
            self.num_queries,
            self.query_pow_bits,
            self.p3_symmetric,
        )
    }

    /// Wraps this identifier in a backend-neutral [`HashIdentifier`].
    #[must_use]
    pub fn to_hash_identifier(&self) -> HashIdentifier {
        HashIdentifier::new(self.render())
    }

    /// Returns the embedded `p3-symmetric` version (= [`PINNED_P3_SYMMETRIC_VERSION`]
    /// for the standard constructor).
    #[must_use]
    pub const fn p3_symmetric(&self) -> P3SymmetricVersion {
        self.p3_symmetric
    }

    /// Test-only: constructs an identifier with an explicit `p3-symmetric`
    /// version, used to verify that the rendered identifier responds to
    /// changes in the embedded version. NOT for production code.
    #[cfg(test)]
    fn with_p3_symmetric_for_test(p3_symmetric: P3SymmetricVersion) -> Self {
        let mut id = Self::standard();
        id.p3_symmetric = p3_symmetric;
        id
    }
}

impl TranscriptBindable for Plonky3HashIdentifier {
    /// Encodes the canonical identifier under `DOMAIN_HASH_ID`, matching the
    /// encoding [`HashIdentifier`] uses.
    fn to_transcript_binding(&self) -> TranscriptBinding {
        self.to_hash_identifier().to_transcript_binding()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::BasisDescriptor;

    // ── PINNED_P3_SYMMETRIC_VERSION + check_advisory ─────────────────────────

    /// This test documents the *current* state of the workspace and forces a
    /// review when the pinned dep is upgraded.
    ///
    /// When the underlying `p3-zk-proofs` revision is bumped to a stack that
    /// resolves `p3-symmetric >= 0.6`, this test will fail. That failure is
    /// the trigger to:
    ///   - flip every `#[should_panic]` test below to a regular assertion;
    ///   - delete this test;
    ///   - update `docs/security-model.md` §4 to remove the "currently
    ///     unpatched" disclaimer.
    #[test]
    fn pinned_state_is_currently_unpatched_per_advisory() {
        assert!(
            !PINNED_P3_SYMMETRIC_VERSION.is_patched(),
            "pinned p3-symmetric is now patched ({PINNED_P3_SYMMETRIC_VERSION}); \
             flip should_panic tests, delete this test, and update the security model doc"
        );
    }

    #[test]
    fn check_advisory_currently_returns_unpatched() {
        let err = check_advisory().expect_err("unpatched stack must fail advisory check");
        match err {
            BackendDriftError::UnpatchedSymmetric {
                provenance,
                min_patched,
            } => {
                assert_eq!(provenance, PINNED_P3_SYMMETRIC_PROVENANCE);
                assert_eq!(min_patched, P3SymmetricVersion::MIN_PATCHED);
            }
            other => panic!("expected UnpatchedSymmetric, got {other:?}"),
        }
    }

    // ── Provenance gate — Registry vs Git, allowlist match ──────────────────

    #[test]
    fn verify_provenance_accepts_patched_registry_version() {
        // Registry source with version >= MIN_PATCHED is the clean path.
        let prov = P3SymmetricProvenance::Registry {
            version: P3SymmetricVersion::new(0, 6, 0),
            checksum: "synthetic-checksum",
        };
        assert!(verify_provenance(prov, &[]).is_ok());
    }

    #[test]
    fn verify_provenance_rejects_unpatched_registry_version() {
        let prov = P3SymmetricProvenance::Registry {
            version: P3SymmetricVersion::new(0, 5, 2),
            checksum: "synthetic-checksum",
        };
        let err = verify_provenance(prov, &[]).expect_err("registry < 0.6 must fail");
        assert!(matches!(err, BackendDriftError::UnpatchedSymmetric { .. }));
    }

    #[test]
    fn verify_provenance_rejects_unpatched_git_when_allowlist_empty() {
        // Even with a git source, version < 0.6 fails when the commit is
        // NOT in the reviewed allowlist. This is the conflation defense:
        // a patched p3-zk-proofs commit cannot bless an unreviewed
        // p3-symmetric git source.
        let prov = P3SymmetricProvenance::Git {
            version: P3SymmetricVersion::new(0, 5, 2),
            source_url: "https://github.com/example/p3-symmetric.git",
            rev: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        };
        let err = verify_provenance(prov, &[]).expect_err("unreviewed git source must fail");
        assert!(matches!(err, BackendDriftError::UnpatchedSymmetric { .. }));
    }

    #[test]
    fn verify_provenance_accepts_unpatched_git_when_in_allowlist() {
        // version < 0.6 BUT the (url, rev) pair is in the reviewed allowlist.
        // This is the escape hatch for [patch.crates-io] redirects pointing
        // at a reviewed git commit that contains the GHSA-3g92-f9ch-qjcm fix.
        let url = "https://github.com/example/p3-symmetric.git";
        let rev = "abcd1234abcd1234abcd1234abcd1234abcd1234";
        let prov = P3SymmetricProvenance::Git {
            version: P3SymmetricVersion::new(0, 5, 99),
            source_url: url,
            rev,
        };
        assert!(verify_provenance(prov, &[(url, rev)]).is_ok());
    }

    #[test]
    fn verify_provenance_rejects_git_with_matching_url_but_wrong_rev() {
        // The allowlist match is on the FULL (url, rev) pair — matching URL
        // alone is insufficient. Different commits on the same repo can have
        // wildly different patch state.
        let url = "https://github.com/example/p3-symmetric.git";
        let prov = P3SymmetricProvenance::Git {
            version: P3SymmetricVersion::new(0, 5, 2),
            source_url: url,
            rev: "1111111111111111111111111111111111111111",
        };
        let allowlist = [(url, "2222222222222222222222222222222222222222")];
        let err =
            verify_provenance(prov, &allowlist).expect_err("matching url but wrong rev must fail");
        assert!(matches!(err, BackendDriftError::UnpatchedSymmetric { .. }));
    }

    #[test]
    fn verify_provenance_rejects_git_with_matching_rev_but_wrong_url() {
        // Symmetric: matching rev on the wrong repo URL is insufficient.
        // A commit hash collision across repos is astronomically unlikely
        // but the gate cannot rely on that — the pair must match together.
        let rev = "abcd1234abcd1234abcd1234abcd1234abcd1234";
        let prov = P3SymmetricProvenance::Git {
            version: P3SymmetricVersion::new(0, 5, 2),
            source_url: "https://github.com/attacker/lookalike.git",
            rev,
        };
        let allowlist = [("https://github.com/example/p3-symmetric.git", rev)];
        let err =
            verify_provenance(prov, &allowlist).expect_err("matching rev but wrong url must fail");
        assert!(matches!(err, BackendDriftError::UnpatchedSymmetric { .. }));
    }

    #[test]
    fn verify_provenance_rejects_patched_git_when_not_allowlisted() {
        // Git source semver is self-declared by the fork. Even version >= 0.6
        // cannot bypass the reviewed (url, rev) allowlist requirement.
        let prov = P3SymmetricProvenance::Git {
            version: P3SymmetricVersion::new(0, 7, 0),
            source_url: "https://github.com/example/p3-symmetric.git",
            rev: "unreviewed-even-though-version-is-patched",
        };
        let err = verify_provenance(prov, &[]).expect_err("unreviewed git source must fail");
        assert!(matches!(err, BackendDriftError::UnpatchedSymmetric { .. }));
    }

    #[test]
    fn verify_provenance_accepts_patched_git_when_allowlisted() {
        let url = "https://github.com/example/p3-symmetric.git";
        let rev = "reviewed-patched-git-revision";
        let prov = P3SymmetricProvenance::Git {
            version: P3SymmetricVersion::new(0, 7, 0),
            source_url: url,
            rev,
        };
        assert!(verify_provenance(prov, &[(url, rev)]).is_ok());
    }

    #[test]
    fn known_patched_sources_allowlist_starts_empty() {
        // Audit hygiene: the production allowlist must be empty until a real
        // patched source is reviewed. CI failure here is the trigger to
        // re-review what was added and why.
        assert!(
            KNOWN_PATCHED_P3_SYMMETRIC_SOURCES.is_empty(),
            "allowlist contains {} entries; each must be audit-justified per docs/security-model.md §4",
            KNOWN_PATCHED_P3_SYMMETRIC_SOURCES.len()
        );
    }

    // ── Provenance accessors and Display ────────────────────────────────────

    #[test]
    fn provenance_version_accessor_returns_inner_version() {
        let reg = P3SymmetricProvenance::Registry {
            version: P3SymmetricVersion::new(0, 5, 2),
            checksum: "x",
        };
        assert_eq!(reg.version(), P3SymmetricVersion::new(0, 5, 2));
        let git = P3SymmetricProvenance::Git {
            version: P3SymmetricVersion::new(0, 7, 0),
            source_url: "u",
            rev: "r",
        };
        assert_eq!(git.version(), P3SymmetricVersion::new(0, 7, 0));
    }

    #[test]
    fn provenance_display_distinguishes_registry_and_git() {
        let reg = P3SymmetricProvenance::Registry {
            version: P3SymmetricVersion::new(0, 5, 2),
            checksum: "synthetic-checksum",
        };
        let git = P3SymmetricProvenance::Git {
            version: P3SymmetricVersion::new(0, 5, 2),
            source_url: "https://example.com/repo.git",
            rev: "deadbeef",
        };
        let reg_msg = reg.to_string();
        let git_msg = git.to_string();
        assert!(reg_msg.contains("registry"));
        assert!(reg_msg.contains("synthetic-checksum"));
        assert!(git_msg.contains("git"));
        assert!(git_msg.contains("https://example.com/repo.git"));
        assert!(git_msg.contains("deadbeef"));
    }

    #[test]
    fn pinned_provenance_version_matches_pinned_version_accessor() {
        // The convenience PINNED_P3_SYMMETRIC_VERSION must always equal
        // PINNED_P3_SYMMETRIC_PROVENANCE.version() — they're two views of
        // the same lockfile entry.
        assert_eq!(
            PINNED_P3_SYMMETRIC_VERSION,
            PINNED_P3_SYMMETRIC_PROVENANCE.version()
        );
    }

    #[test]
    fn verify_profile_matches_backend_currently_blocks_on_advisory() {
        // Even with a perfect profile, the advisory check fires first.
        let profile = ReferenceHidingFriPcsProfile::standard();
        let err = verify_profile_matches_backend(&profile).expect_err("unpatched stack must fail");
        assert!(matches!(err, BackendDriftError::UnpatchedSymmetric { .. }));
    }

    #[test]
    #[should_panic(expected = "GHSA-3g92-f9ch-qjcm")]
    fn assert_profile_matches_backend_panics_under_current_unpatched_state() {
        // This is the canonical bridge-setup invariant. While the stack is
        // unpatched, calling it MUST panic with the advisory reason. When the
        // stack is upgraded, drop the should_panic attribute.
        assert_profile_matches_backend();
    }

    // ── check_profile_drift (independent of advisory) ────────────────────────

    #[test]
    fn check_profile_drift_accepts_standard_profile() {
        // The profile itself is well-formed; advisory state is orthogonal.
        let profile = ReferenceHidingFriPcsProfile::standard();
        assert!(check_profile_drift(&profile).is_ok());
    }

    #[test]
    fn check_profile_drift_rejects_drifted_log_blowup() {
        let mut profile = ReferenceHidingFriPcsProfile::standard();
        profile.log_blowup = BACKEND_LOG_BLOWUP + 1;
        let err = check_profile_drift(&profile).expect_err("drifted log_blowup must be rejected");
        assert_eq!(
            err,
            BackendDriftError::LogBlowup {
                expected: BACKEND_LOG_BLOWUP,
                actual: BACKEND_LOG_BLOWUP + 1,
            }
        );
    }

    #[test]
    fn check_profile_drift_rejects_drifted_randomizer_count() {
        let mut profile = ReferenceHidingFriPcsProfile::standard();
        profile.num_random_codewords = BACKEND_NUM_RANDOMIZER_COLS + 1;
        let err = check_profile_drift(&profile)
            .expect_err("drifted num_random_codewords must be rejected");
        assert_eq!(
            err,
            BackendDriftError::NumRandomizerCols {
                expected: BACKEND_NUM_RANDOMIZER_COLS,
                actual: BACKEND_NUM_RANDOMIZER_COLS + 1,
            }
        );
    }

    #[test]
    fn check_profile_drift_rejects_drifted_extension_degree() {
        let mut profile = ReferenceHidingFriPcsProfile::standard();
        profile.basis = BasisDescriptor::plonky3_binomial(2);
        let err =
            check_profile_drift(&profile).expect_err("drifted extension degree must be rejected");
        assert_eq!(
            err,
            BackendDriftError::ExtensionDegree {
                expected: BACKEND_EXTENSION_DEGREE,
                actual: 2,
            }
        );
    }

    #[test]
    fn check_profile_drift_rejects_non_hiding_input_mmcs() {
        let mut profile = ReferenceHidingFriPcsProfile::standard();
        profile.input_mmcs_hiding = false;
        let err =
            check_profile_drift(&profile).expect_err("non-hiding input MMCS must be rejected");
        assert_eq!(err, BackendDriftError::NonHidingInputMmcs);
    }

    #[test]
    fn check_profile_drift_rejects_non_hiding_fri_mmcs() {
        let mut profile = ReferenceHidingFriPcsProfile::standard();
        profile.fri_mmcs_hiding = false;
        let err = check_profile_drift(&profile).expect_err("non-hiding FRI MMCS must be rejected");
        assert_eq!(err, BackendDriftError::NonHidingFriMmcs);
    }

    #[test]
    fn check_profile_drift_rejects_missing_random_codeword_interleaving() {
        let mut profile = ReferenceHidingFriPcsProfile::standard();
        profile.hiding_technique = HidingTechniqueClaim::Composite(
            Box::new(HidingTechniqueClaim::QuotientChunkRandomization),
            Box::new(HidingTechniqueClaim::RandomRowPadding),
        );
        let err = check_profile_drift(&profile)
            .expect_err("missing RandomCodewordInterleaving must be rejected");
        assert_eq!(
            err,
            BackendDriftError::MissingHidingTechnique {
                technique: HidingTechniqueClaim::RandomCodewordInterleaving,
            }
        );
    }

    #[test]
    fn check_profile_drift_rejects_missing_quotient_chunk_randomization() {
        let mut profile = ReferenceHidingFriPcsProfile::standard();
        profile.hiding_technique = HidingTechniqueClaim::Composite(
            Box::new(HidingTechniqueClaim::RandomCodewordInterleaving),
            Box::new(HidingTechniqueClaim::RandomRowPadding),
        );
        let err = check_profile_drift(&profile)
            .expect_err("missing QuotientChunkRandomization must be rejected");
        assert_eq!(
            err,
            BackendDriftError::MissingHidingTechnique {
                technique: HidingTechniqueClaim::QuotientChunkRandomization,
            }
        );
    }

    #[test]
    fn check_profile_drift_rejects_missing_random_row_padding() {
        let mut profile = ReferenceHidingFriPcsProfile::standard();
        profile.hiding_technique = HidingTechniqueClaim::Composite(
            Box::new(HidingTechniqueClaim::RandomCodewordInterleaving),
            Box::new(HidingTechniqueClaim::QuotientChunkRandomization),
        );
        let err =
            check_profile_drift(&profile).expect_err("missing RandomRowPadding must be rejected");
        assert_eq!(
            err,
            BackendDriftError::MissingHidingTechnique {
                technique: HidingTechniqueClaim::RandomRowPadding,
            }
        );
    }

    // ── Display + advisory message contents ──────────────────────────────────

    #[test]
    fn drift_error_display_includes_expected_and_actual() {
        let err = BackendDriftError::LogBlowup {
            expected: 2,
            actual: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("expected 2"));
        assert!(msg.contains("got 3"));
    }

    #[test]
    fn unpatched_display_cites_advisory_and_provenance() {
        let err = BackendDriftError::UnpatchedSymmetric {
            provenance: P3SymmetricProvenance::Registry {
                version: P3SymmetricVersion::new(0, 5, 9),
                checksum: "synthetic-checksum",
            },
            min_patched: P3SymmetricVersion::MIN_PATCHED,
        };
        let msg = err.to_string();
        assert!(msg.contains("GHSA-3g92-f9ch-qjcm"));
        assert!(msg.contains("0.5.9"));
        assert!(msg.contains("0.6.0"));
        assert!(msg.contains("registry"));
        assert!(msg.contains("synthetic-checksum"));
    }

    #[test]
    fn unpatched_display_for_git_source_includes_url_and_rev() {
        let err = BackendDriftError::UnpatchedSymmetric {
            provenance: P3SymmetricProvenance::Git {
                version: P3SymmetricVersion::new(0, 5, 2),
                source_url: "https://github.com/example/p3-symmetric.git",
                rev: "abcd1234",
            },
            min_patched: P3SymmetricVersion::MIN_PATCHED,
        };
        let msg = err.to_string();
        assert!(msg.contains("git"));
        assert!(msg.contains("https://github.com/example/p3-symmetric.git"));
        assert!(msg.contains("abcd1234"));
        assert!(msg.contains("KNOWN_PATCHED_P3_SYMMETRIC_SOURCES"));
    }

    #[test]
    fn non_hiding_mmcs_display_explains_requirement() {
        let in_msg = BackendDriftError::NonHidingInputMmcs.to_string();
        let fri_msg = BackendDriftError::NonHidingFriMmcs.to_string();
        assert!(in_msg.contains("input_mmcs_hiding"));
        assert!(fri_msg.contains("fri_mmcs_hiding"));
    }

    #[test]
    fn missing_technique_display_names_the_technique() {
        let err = BackendDriftError::MissingHidingTechnique {
            technique: HidingTechniqueClaim::RandomCodewordInterleaving,
        };
        let msg = err.to_string();
        assert!(msg.contains("random codeword interleaving"));
    }

    // ── P3SymmetricVersion ───────────────────────────────────────────────────

    #[test]
    fn min_patched_is_zero_six_zero() {
        assert_eq!(
            P3SymmetricVersion::MIN_PATCHED,
            P3SymmetricVersion::new(0, 6, 0)
        );
    }

    #[test]
    fn is_patched_accepts_exact_floor() {
        assert!(P3SymmetricVersion::new(0, 6, 0).is_patched());
    }

    #[test]
    fn is_patched_accepts_above_floor() {
        assert!(P3SymmetricVersion::new(0, 6, 1).is_patched());
        assert!(P3SymmetricVersion::new(0, 7, 0).is_patched());
        assert!(P3SymmetricVersion::new(1, 0, 0).is_patched());
    }

    #[test]
    fn is_patched_rejects_below_floor() {
        assert!(!P3SymmetricVersion::new(0, 5, 99).is_patched());
        assert!(!P3SymmetricVersion::new(0, 5, 0).is_patched());
        assert!(!P3SymmetricVersion::new(0, 0, 1).is_patched());
    }

    #[test]
    fn version_display_renders_dotted() {
        assert_eq!(P3SymmetricVersion::new(0, 6, 1).to_string(), "0.6.1");
        assert_eq!(P3SymmetricVersion::new(1, 2, 3).to_string(), "1.2.3");
    }

    // ── Plonky3HashIdentifier ────────────────────────────────────────────────

    #[test]
    fn standard_hash_identifier_renders_canonical_form() {
        let id = Plonky3HashIdentifier::standard();
        let rendered = id.render();
        assert!(rendered.starts_with("plonky3-zk:v1:"));
        assert!(rendered.contains(":babybear:"));
        assert!(rendered.contains(":ext4:"));
        assert!(rendered.contains(":keccak256:"));
        assert!(rendered.contains(":pf_sponge_25_17_4:"));
        assert!(rendered.contains(":ser_chal32:"));
        assert!(rendered.contains(":mtree_hiding_mmcs:"));
        assert!(rendered.contains(":ext_mmcs:"));
        assert!(rendered.contains(":radix2_dit_parallel:"));
        assert!(rendered.contains(":hiding_rng:"));
        assert!(rendered.contains(":log_blowup2:"));
        assert!(rendered.contains(":randomizers4:"));
        assert!(rendered.contains(":queries40:"));
        assert!(rendered.contains(":pow8:"));
        // Embedded p3-symmetric MUST be the pinned (build-time-derived) version,
        // never a caller-controlled one.
        let expected_suffix = format!(":p3sym{PINNED_P3_SYMMETRIC_VERSION}");
        assert!(rendered.ends_with(&expected_suffix));
    }

    #[test]
    fn standard_hash_identifier_is_stable() {
        let a = Plonky3HashIdentifier::standard().render();
        let b = Plonky3HashIdentifier::standard().render();
        assert_eq!(a, b);
    }

    #[test]
    fn different_p3_symmetric_versions_produce_different_identifiers() {
        // Use the test-only helper to confirm the embedded version actually
        // propagates into the rendered identifier.
        let a = Plonky3HashIdentifier::standard().render();
        let b =
            Plonky3HashIdentifier::with_p3_symmetric_for_test(P3SymmetricVersion::new(99, 99, 99))
                .render();
        assert_ne!(a, b);
        assert!(b.contains(":p3sym99.99.99"));
    }

    #[test]
    fn standard_identifier_embeds_resolved_version_not_min_patched() {
        // The point of P1 fix: the identifier reflects what is, not what
        // we wish were true. Even though MIN_PATCHED = 0.6.0, the standard
        // identifier embeds the actually-resolved version (currently 0.5.2).
        let rendered = Plonky3HashIdentifier::standard().render();
        let expected_suffix = format!(":p3sym{PINNED_P3_SYMMETRIC_VERSION}");
        assert!(rendered.ends_with(&expected_suffix));
    }

    #[test]
    fn hash_identifier_round_trips_through_to_hash_identifier() {
        let id = Plonky3HashIdentifier::standard();
        let hash_id = id.to_hash_identifier();
        assert_eq!(hash_id.suite(), id.render());
    }

    #[test]
    fn transcript_binding_matches_hash_identifier_binding() {
        let id = Plonky3HashIdentifier::standard();
        let direct = id.to_transcript_binding();
        let via_hash_id = HashIdentifier::new(id.render()).to_transcript_binding();
        assert_eq!(direct, via_hash_id);
    }

    // ── Live backend integration ─────────────────────────────────────────────

    #[test]
    fn pinned_backend_config_builds() {
        let _config = HidingBackend::deterministic_config(42);
    }

    // ── required_plonky3_hiding_techniques ───────────────────────────────────

    #[test]
    fn required_techniques_are_the_three_plonky3_composite_layers() {
        let required = required_plonky3_hiding_techniques();
        assert_eq!(required.len(), 3);
        assert!(required.contains(&HidingTechniqueClaim::RandomCodewordInterleaving));
        assert!(required.contains(&HidingTechniqueClaim::QuotientChunkRandomization));
        assert!(required.contains(&HidingTechniqueClaim::RandomRowPadding));
    }

    #[test]
    fn standard_profile_satisfies_all_required_techniques() {
        let profile = ReferenceHidingFriPcsProfile::standard();
        for technique in required_plonky3_hiding_techniques() {
            assert!(
                profile.hiding_technique.contains(&technique),
                "standard profile must contain {technique}"
            );
        }
    }
}
