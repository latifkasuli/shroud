//! Transcript binding types for SHROUD Fiat-Shamir security.
//!
//! # Background
//!
//! The Fiat-Shamir heuristic replaces an interactive verifier with a hash
//! function. For the transformation to be secure, the challenge hash must bind
//! **every** public parameter that influences the proof: commitments, protocol
//! parameters, domain labels, and the security profile. An omitted input gives
//! an attacker a free variable — replay, context confusion, or proof forgery
//! all follow from incomplete binding.
//!
//! This module provides the backend-neutral surface for declaring and verifying
//! those bindings in SHROUD objects before any challenge is sampled.

use core::fmt;

use crate::SecurityLevel;
use crate::claim::{BasisDescriptor, CoordinateOrder, ReconstructionRule};

/// Domain label for the SHROUD hiding profile (log-blowup, randomizer count, basis).
pub const DOMAIN_PROFILE: &str = "SHROUD_V1_PROFILE";

/// Domain label for the extension-field basis descriptor.
pub const DOMAIN_BASIS: &str = "SHROUD_V1_BASIS";

/// Domain label for the oracle-commitment shape and security level.
pub const DOMAIN_ORACLE_COMMITMENT: &str = "SHROUD_V1_ORACLE_COMMITMENT";

/// Domain label for a concrete randomizer commitment (e.g. a Merkle root or digest).
pub const DOMAIN_RANDOMIZER_COMMITMENT: &str = "SHROUD_V1_RANDOMIZER_COMMITMENT";

/// Domain label for the quotient degree contract.
pub const DOMAIN_DEGREE_CONTRACT: &str = "SHROUD_V1_DEGREE_CONTRACT";

/// Domain label for the proof security level (`Statistical` or `Perfect`).
pub const DOMAIN_SECURITY_LEVEL: &str = "SHROUD_V1_SECURITY_LEVEL";

/// Domain label for public opening values observed before final verification.
pub const DOMAIN_PUBLIC_OPENINGS: &str = "SHROUD_V1_PUBLIC_OPENINGS";

/// A single transcript absorption event: a domain-separated label and its canonical bytes.
///
/// `domain_label` provides protocol-version domain separation, preventing a binding
/// from one context (e.g. the basis descriptor) from being confused with a binding
/// from another (e.g. the security level), even when their byte representations coincide.
///
/// `canonical_bytes` is a little-endian encoding of every field that influences
/// the challenge. The encoding convention must be stable across prover and verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptBinding {
    domain_label: &'static str,
    canonical_bytes: Vec<u8>,
}

impl TranscriptBinding {
    /// Creates a transcript binding from an explicit domain label and canonical bytes.
    #[must_use]
    pub fn new(domain_label: &'static str, canonical_bytes: Vec<u8>) -> Self {
        Self {
            domain_label,
            canonical_bytes,
        }
    }

    /// The domain label separating this binding from others in the same transcript.
    #[must_use]
    pub fn domain_label(&self) -> &'static str {
        self.domain_label
    }

    /// Canonical byte representation of the bound value.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// A SHROUD protocol object that can produce a canonical transcript binding.
///
/// Implementors encode every field that influences verifier challenges into a
/// [`TranscriptBinding`] with a stable domain label and little-endian byte
/// encoding. The verifier absorbs these bytes into its hash state before
/// sampling any challenge that depends on those fields.
pub trait TranscriptBindable {
    /// Returns a canonical transcript binding for this object.
    fn to_transcript_binding(&self) -> TranscriptBinding;
}

/// Error raised when a required transcript binding is absent from the record.
///
/// Produced by verification methods when a binding with the required domain
/// label was never absorbed before a challenge was sampled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranscriptBindingError {
    /// A required domain label was never absorbed into the transcript.
    MissingBinding {
        /// The domain label that was expected but absent.
        domain_label: String,
    },
    /// A binding with the required domain label was absorbed, but its canonical
    /// bytes do not match the expected value.
    ///
    /// This indicates that the prover supplied a binding for the correct domain
    /// but encoded a different (possibly adversarially chosen) value.
    BindingMismatch {
        /// The domain label whose bytes did not match.
        domain_label: String,
    },
}

impl fmt::Display for TranscriptBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBinding { domain_label } => write!(
                f,
                "required transcript binding is missing: domain label {domain_label:?} \
                 was never absorbed before the challenge was sampled; \
                 omitting this binding allows an attacker to replay or substitute \
                 the corresponding protocol parameter"
            ),
            Self::BindingMismatch { domain_label } => write!(
                f,
                "transcript binding mismatch: a binding for domain label {domain_label:?} \
                 was absorbed, but its canonical bytes do not match the expected value; \
                 this may indicate adversarial substitution of a protocol parameter"
            ),
        }
    }
}

impl std::error::Error for TranscriptBindingError {}

// ── Core-type implementations ────────────────────────────────────────────────

impl TranscriptBindable for SecurityLevel {
    /// Encodes the security level as a single byte: `0` = Statistical, `1` = Perfect.
    fn to_transcript_binding(&self) -> TranscriptBinding {
        let byte = match self {
            Self::Statistical => 0u8,
            Self::Perfect => 1u8,
        };
        TranscriptBinding::new(DOMAIN_SECURITY_LEVEL, vec![byte])
    }
}

impl TranscriptBindable for BasisDescriptor {
    /// Encodes the extension degree (u64 LE, 8 bytes), coordinate-order discriminant,
    /// and reconstruction-rule discriminant (each 1 byte). Total: 10 bytes.
    fn to_transcript_binding(&self) -> TranscriptBinding {
        let mut bytes = Vec::with_capacity(10);
        bytes.extend_from_slice(&(self.extension_degree as u64).to_le_bytes());
        bytes.push(match self.coordinate_order {
            CoordinateOrder::LittleEndianMonomial => 0u8,
        });
        bytes.push(match self.reconstruction_rule {
            ReconstructionRule::BinomialExtension => 0u8,
        });
        TranscriptBinding::new(DOMAIN_BASIS, bytes)
    }
}

/// A per-sampling-stage manifest of expected transcript bindings.
///
/// Associates each sampling stage with the exact [`TranscriptBinding`] values
/// that must have been absorbed before that stage may be entered. Used by
/// `ReferenceTranscript::advance` to enforce exact-byte binding validation
/// instead of label-only presence checks.
///
/// Build using the `with_before_*` builder methods:
///
/// ```rust
/// # use shroud_core::{TranscriptBindingManifest, TranscriptBindable, SecurityLevel};
/// let manifest = TranscriptBindingManifest::new()
///     .with_before_batching_challenge(SecurityLevel::Statistical.to_transcript_binding());
/// ```
#[derive(Clone, Debug, Default)]
pub struct TranscriptBindingManifest {
    before_batching_challenge: Vec<TranscriptBinding>,
    before_ood_point: Vec<TranscriptBinding>,
    before_prove_masked: Vec<TranscriptBinding>,
}

impl TranscriptBindingManifest {
    /// Creates an empty manifest — no exact-byte requirements on any sampling stage.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an expected binding that must be present before `SampleBatchingChallenge`.
    #[must_use]
    pub fn with_before_batching_challenge(mut self, binding: TranscriptBinding) -> Self {
        self.before_batching_challenge.push(binding);
        self
    }

    /// Adds an expected binding that must be present before `SampleOodPoint`.
    #[must_use]
    pub fn with_before_ood_point(mut self, binding: TranscriptBinding) -> Self {
        self.before_ood_point.push(binding);
        self
    }

    /// Adds an expected binding that must be present before `ProveMaskedRelation`.
    #[must_use]
    pub fn with_before_prove_masked(mut self, binding: TranscriptBinding) -> Self {
        self.before_prove_masked.push(binding);
        self
    }

    /// Returns the expected bindings for the given stage.
    ///
    /// Returns an empty slice for non-sampling stages.
    #[must_use]
    pub fn required_before(&self, stage: crate::TranscriptStage) -> &[TranscriptBinding] {
        match stage {
            crate::TranscriptStage::SampleBatchingChallenge => &self.before_batching_challenge,
            crate::TranscriptStage::SampleOodPoint => &self.before_ood_point,
            crate::TranscriptStage::ProveMaskedRelation => &self.before_prove_masked,
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::BasisDescriptor;

    #[test]
    fn statistical_security_level_encodes_as_zero() {
        let binding = SecurityLevel::Statistical.to_transcript_binding();
        assert_eq!(binding.domain_label(), DOMAIN_SECURITY_LEVEL);
        assert_eq!(binding.canonical_bytes(), &[0u8]);
    }

    #[test]
    fn perfect_security_level_encodes_as_one() {
        let binding = SecurityLevel::Perfect.to_transcript_binding();
        assert_eq!(binding.domain_label(), DOMAIN_SECURITY_LEVEL);
        assert_eq!(binding.canonical_bytes(), &[1u8]);
    }

    #[test]
    fn security_level_bindings_are_distinct() {
        let s = SecurityLevel::Statistical.to_transcript_binding();
        let p = SecurityLevel::Perfect.to_transcript_binding();
        assert_ne!(s, p);
    }

    #[test]
    fn basis_descriptor_encodes_extension_degree_and_discriminants() {
        let basis = BasisDescriptor::plonky3_binomial(4);
        let binding = basis.to_transcript_binding();
        assert_eq!(binding.domain_label(), DOMAIN_BASIS);
        let mut expected = Vec::new();
        expected.extend_from_slice(&4u64.to_le_bytes());
        expected.push(0u8); // LittleEndianMonomial
        expected.push(0u8); // BinomialExtension
        assert_eq!(binding.canonical_bytes(), &expected);
    }

    #[test]
    fn basis_descriptors_with_different_degrees_produce_different_bindings() {
        let b2 = BasisDescriptor::plonky3_binomial(2).to_transcript_binding();
        let b4 = BasisDescriptor::plonky3_binomial(4).to_transcript_binding();
        assert_ne!(b2, b4);
    }

    #[test]
    fn domain_labels_are_distinct_across_all_constants() {
        let labels = [
            DOMAIN_PROFILE,
            DOMAIN_BASIS,
            DOMAIN_ORACLE_COMMITMENT,
            DOMAIN_RANDOMIZER_COMMITMENT,
            DOMAIN_DEGREE_CONTRACT,
            DOMAIN_SECURITY_LEVEL,
            DOMAIN_PUBLIC_OPENINGS,
        ];
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i], labels[j], "domain labels {i} and {j} collide");
            }
        }
    }

    #[test]
    fn transcript_binding_error_displays_missing_label() {
        let err = TranscriptBindingError::MissingBinding {
            domain_label: "SHROUD_V1_BASIS".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("SHROUD_V1_BASIS"));
        assert!(msg.contains("missing"));
    }

    #[test]
    fn empty_manifest_has_no_requirements_for_any_stage() {
        use crate::TranscriptStage;
        let manifest = TranscriptBindingManifest::new();
        assert!(
            manifest
                .required_before(TranscriptStage::SampleBatchingChallenge)
                .is_empty()
        );
        assert!(
            manifest
                .required_before(TranscriptStage::SampleOodPoint)
                .is_empty()
        );
        assert!(
            manifest
                .required_before(TranscriptStage::ProveMaskedRelation)
                .is_empty()
        );
        assert!(
            manifest
                .required_before(TranscriptStage::ObserveMainCommitments)
                .is_empty()
        );
    }

    #[test]
    fn manifest_routes_bindings_to_correct_stage() {
        use crate::{BasisDescriptor, TranscriptStage};
        let basis_binding = BasisDescriptor::plonky3_binomial(4).to_transcript_binding();
        let manifest =
            TranscriptBindingManifest::new().with_before_batching_challenge(basis_binding.clone());
        assert_eq!(
            manifest.required_before(TranscriptStage::SampleBatchingChallenge),
            &[basis_binding]
        );
        assert!(
            manifest
                .required_before(TranscriptStage::SampleOodPoint)
                .is_empty()
        );
    }
}
