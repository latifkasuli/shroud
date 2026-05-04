use core::fmt;

/// The source of randomness used by a hiding commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomnessModel {
    /// Fresh uniform randomness is sampled per proof from OS entropy.
    UniformPerProof,
    /// A CSPRNG seeded from OS entropy is used per proof.
    CsprngFromOsEntropy,
}

impl fmt::Display for RandomnessModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UniformPerProof => f.write_str("uniform per proof"),
            Self::CsprngFromOsEntropy => f.write_str("CSPRNG from OS entropy"),
        }
    }
}

/// Coordinate ordering convention for base-field coordinate encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinateOrder {
    /// Little-endian monomial: coordinate `i` is the coefficient of `ω^i`.
    ///
    /// This is the Plonky3 `BinomialExtensionField` convention used by
    /// `ExtensionMmcs` (via `FlatMatrixView`) and `reconstitute_from_base`.
    LittleEndianMonomial,
}

impl fmt::Display for CoordinateOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LittleEndianMonomial => f.write_str("little-endian monomial"),
        }
    }
}

/// Algebraic reconstruction rule for rebuilding an extension-field element from coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconstructionRule {
    /// Binomial extension `F[X] / (X^n − W)` for some non-residue `W`.
    ///
    /// Element is `c₀ + c₁·X + … + c_{n-1}·X^{n-1}` where `X^n = W`.
    /// This is the Plonky3 `BinomialExtensionField` convention.
    BinomialExtension,
}

impl fmt::Display for ReconstructionRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BinomialExtension => f.write_str("binomial extension"),
        }
    }
}

/// Self-describing basis for an encoded-coordinates oracle bundle.
///
/// Carries the minimal metadata needed to:
/// 1. Flatten an extension-field element to base-field coordinates (commit path).
/// 2. Reconstruct an extension-field element from those coordinates (verify path).
///
/// Use [`BasisDescriptor::plonky3_binomial`] for the `BinomialExtensionField`
/// convention used by `ExtensionMmcs` in Plonky3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BasisDescriptor {
    /// Degree of the extension field over the base field.
    pub extension_degree: usize,
    /// Ordering of the base-field coordinates.
    pub coordinate_order: CoordinateOrder,
    /// Algebraic rule used to reconstruct an extension-field element from coordinates.
    pub reconstruction_rule: ReconstructionRule,
}

impl BasisDescriptor {
    /// Standard Plonky3 `BinomialExtensionField` descriptor for `extension_degree`.
    ///
    /// Uses little-endian monomial order and binomial extension reconstruction —
    /// matching `ExtensionMmcs::reconstitute_from_base` and `FlatMatrixView`.
    ///
    /// # Panics
    ///
    /// Panics if `extension_degree` is zero — a degree-zero extension field cannot
    /// represent any element and no coordinate reconstruction is possible.
    #[must_use]
    pub const fn plonky3_binomial(extension_degree: usize) -> Self {
        assert!(
            extension_degree >= 1,
            "extension_degree must be at least 1; a degree-zero extension field is not valid"
        );
        Self {
            extension_degree,
            coordinate_order: CoordinateOrder::LittleEndianMonomial,
            reconstruction_rule: ReconstructionRule::BinomialExtension,
        }
    }
}

impl fmt::Display for BasisDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (degree {}, {})",
            self.reconstruction_rule, self.extension_degree, self.coordinate_order
        )
    }
}

/// The field model used by a perfect-variant randomizer commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldModel {
    /// The randomizer is encoded as base-field coordinates of an extension-field element.
    ///
    /// This is the SHROUD v1 `EncodedOracleBundle` path. The commitment stores
    /// `basis.extension_degree` base-field coordinate columns and reconstructs one
    /// extension-field element per opening point on verify. The `basis` descriptor
    /// makes the encoding self-describing: an auditor can verify that the backend's
    /// `reconstitute_from_base` implementation matches the declared convention without
    /// relying on implicit `BabyBear`/`BinomialExtension` assumptions.
    EncodedCoordinates {
        /// Self-describing basis for coordinate encoding and reconstruction.
        basis: BasisDescriptor,
    },
    /// The randomizer is committed natively as an extension-field element.
    ///
    /// This is the long-term path requiring native extension-field PCS support.
    NativeExtension {
        /// Degree of the extension field over the base field.
        extension_degree: usize,
    },
}

impl FieldModel {
    /// Returns the extension degree for either field model variant.
    #[must_use]
    pub const fn extension_degree(self) -> usize {
        match self {
            Self::EncodedCoordinates { basis } => basis.extension_degree,
            Self::NativeExtension { extension_degree } => extension_degree,
        }
    }
}

impl fmt::Display for FieldModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedCoordinates { basis } => {
                write!(f, "encoded coordinates ({basis})")
            }
            Self::NativeExtension { extension_degree } => {
                write!(f, "native extension field (degree {extension_degree})")
            }
        }
    }
}

/// The simulator's obligations for a perfect HVZK claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulatorObligations {
    /// Honest-verifier setting: the simulator has access to the verifier's challenges.
    ///
    /// This is the standard STARK ZK claim. The simulator can produce a valid
    /// transcript because it knows the challenges in advance, but the honest verifier
    /// still learns nothing about the witness.
    HonestVerifierChallengeAccess,
    /// Fully oblivious: the simulator produces a valid transcript without the witness
    /// or the challenges.
    ///
    /// This is a stronger claim and harder to instantiate in practice.
    FullyOblivious,
}

impl fmt::Display for SimulatorObligations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HonestVerifierChallengeAccess => {
                f.write_str("honest-verifier with challenge access")
            }
            Self::FullyOblivious => f.write_str("fully oblivious"),
        }
    }
}

/// A structured justification for a `SecurityLevel::Perfect` claim.
///
/// A SHROUD object or backend that sets `SecurityLevel::Perfect` must supply a
/// `PerfectClaim`. The claim is not a cryptographic proof — it is a declared
/// contract that auditors can check against the concrete backend. The `validate`
/// method checks internal consistency; correctness of the declared fields against
/// the actual backend is the auditor's responsibility.
///
/// The key invariant `PerfectClaim::validate` enforces: a perfect claim is
/// internally inconsistent if the query budget is zero or the MMCS is non-hiding.
/// A non-hiding MMCS leaks witness row values on query, which defeats polynomial
/// randomization regardless of how many randomizer columns are appended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfectClaim {
    /// The source of randomness used by the commitment.
    pub randomness_model: RandomnessModel,
    /// The field model used by the randomizer commitment.
    pub field_model: FieldModel,
    /// The number of verifier queries the hiding guarantee must survive.
    pub query_budget: usize,
    /// The simulator's obligations for this HVZK claim.
    pub simulator_obligations: SimulatorObligations,
    /// Whether the underlying MMCS is also hiding.
    ///
    /// Must be `true`. A non-hiding MMCS leaks witness values on row queries,
    /// making polynomial randomization insufficient for perfect ZK.
    pub hiding_mmcs: bool,
}

impl PerfectClaim {
    /// Validates internal consistency of the claim.
    ///
    /// This does not verify the claim against a concrete backend. It only
    /// checks that the declared fields are mutually non-contradictory.
    pub fn validate(&self) -> Result<(), PerfectClaimError> {
        if self.field_model.extension_degree() == 0 {
            return Err(PerfectClaimError::ZeroExtensionDegree);
        }
        if self.query_budget == 0 {
            return Err(PerfectClaimError::ZeroQueryBudget);
        }
        if !self.hiding_mmcs {
            return Err(PerfectClaimError::NonHidingMmcs);
        }
        Ok(())
    }
}

/// Error raised when a `PerfectClaim` is internally inconsistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerfectClaimError {
    /// The field model's extension degree must be at least one.
    ZeroExtensionDegree,
    /// The query budget must be at least one.
    ZeroQueryBudget,
    /// Perfect ZK requires a hiding MMCS.
    NonHidingMmcs,
}

impl fmt::Display for PerfectClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroExtensionDegree => write!(
                f,
                "perfect claim field model extension degree must be at least one; \
                 a degree-zero extension field cannot represent an extension-field randomizer"
            ),
            Self::ZeroQueryBudget => {
                write!(f, "perfect claim query budget must be at least one")
            }
            Self::NonHidingMmcs => write!(
                f,
                "perfect ZK requires a hiding MMCS; a non-hiding MMCS leaks \
                 witness values on row queries regardless of polynomial randomization"
            ),
        }
    }
}

impl std::error::Error for PerfectClaimError {}

#[cfg(test)]
mod tests {
    use super::{
        BasisDescriptor, FieldModel, PerfectClaim, PerfectClaimError, RandomnessModel,
        SimulatorObligations,
    };

    fn valid_claim() -> PerfectClaim {
        PerfectClaim {
            randomness_model: RandomnessModel::UniformPerProof,
            field_model: FieldModel::EncodedCoordinates {
                basis: BasisDescriptor::plonky3_binomial(4),
            },
            query_budget: 40,
            simulator_obligations: SimulatorObligations::HonestVerifierChallengeAccess,
            hiding_mmcs: true,
        }
    }

    #[test]
    fn valid_claim_validates() {
        assert!(valid_claim().validate().is_ok());
    }

    #[test]
    fn zero_query_budget_is_rejected() {
        let mut claim = valid_claim();
        claim.query_budget = 0;
        assert_eq!(claim.validate(), Err(PerfectClaimError::ZeroQueryBudget));
    }

    #[test]
    fn non_hiding_mmcs_is_rejected() {
        let mut claim = valid_claim();
        claim.hiding_mmcs = false;
        assert_eq!(claim.validate(), Err(PerfectClaimError::NonHidingMmcs));
    }

    #[test]
    fn field_model_extension_degree_accessor() {
        assert_eq!(
            FieldModel::EncodedCoordinates {
                basis: BasisDescriptor::plonky3_binomial(4),
            }
            .extension_degree(),
            4
        );
        assert_eq!(
            FieldModel::NativeExtension {
                extension_degree: 2
            }
            .extension_degree(),
            2
        );
    }

    #[test]
    fn basis_descriptor_plonky3_binomial_convention() {
        let basis = BasisDescriptor::plonky3_binomial(4);
        assert_eq!(basis.extension_degree, 4);
        assert_eq!(
            basis.coordinate_order,
            super::CoordinateOrder::LittleEndianMonomial
        );
        assert_eq!(
            basis.reconstruction_rule,
            super::ReconstructionRule::BinomialExtension
        );
    }

    #[test]
    fn native_extension_claim_validates() {
        let mut claim = valid_claim();
        claim.field_model = FieldModel::NativeExtension {
            extension_degree: 4,
        };
        assert!(claim.validate().is_ok());
    }

    #[test]
    fn zero_extension_degree_native_is_rejected() {
        let mut claim = valid_claim();
        claim.field_model = FieldModel::NativeExtension {
            extension_degree: 0,
        };
        assert_eq!(
            claim.validate(),
            Err(PerfectClaimError::ZeroExtensionDegree)
        );
    }

    #[test]
    #[should_panic(expected = "extension_degree must be at least 1")]
    fn basis_descriptor_rejects_zero_degree() {
        let _ = BasisDescriptor::plonky3_binomial(0);
    }
}
