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

/// The field model used by a perfect-variant randomizer commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldModel {
    /// The randomizer is encoded as base-field coordinates of an extension-field element.
    ///
    /// This is the SHROUD v1 `EncodedOracleBundle` path. The commitment stores
    /// `extension_degree` base-field coordinate columns and reconstructs one
    /// extension-field element per opening point on verify. Perfect ZK holds only
    /// when the backend proves the coordinate bundle is an exact extension-field
    /// randomizer, not a loose collection of base-field columns.
    EncodedCoordinates {
        /// Degree of the extension field over the base field.
        extension_degree: usize,
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
            Self::EncodedCoordinates { extension_degree }
            | Self::NativeExtension { extension_degree } => extension_degree,
        }
    }
}

impl fmt::Display for FieldModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedCoordinates { extension_degree } => {
                write!(
                    f,
                    "encoded coordinates (extension degree {extension_degree})"
                )
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
    /// The query budget must be at least one.
    ZeroQueryBudget,
    /// Perfect ZK requires a hiding MMCS.
    NonHidingMmcs,
}

impl fmt::Display for PerfectClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
        FieldModel, PerfectClaim, PerfectClaimError, RandomnessModel, SimulatorObligations,
    };

    fn valid_claim() -> PerfectClaim {
        PerfectClaim {
            randomness_model: RandomnessModel::UniformPerProof,
            field_model: FieldModel::EncodedCoordinates {
                extension_degree: 4,
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
                extension_degree: 4
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
    fn native_extension_claim_validates() {
        let mut claim = valid_claim();
        claim.field_model = FieldModel::NativeExtension {
            extension_degree: 4,
        };
        assert!(claim.validate().is_ok());
    }
}
