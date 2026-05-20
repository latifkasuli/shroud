#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SHROUD object for hidden oracle commitments and authenticated row openings.
//!
//! In this crate, `SecurityLevel` records the claimed hiding level of the
//! oracle-commitment object. It does not, by itself, force one particular
//! hiding-witness transport. Different backends may keep row salts in-band with
//! the opening proof or move them into a separate auxiliary proof path.

use core::fmt;

use shroud_core::{
    DOMAIN_ORACLE_COMMITMENT, PerfectClaim, PerfectClaimError, SecurityLevel, TranscriptBindable,
    TranscriptBinding,
};

/// How row-hiding witness material is transported through the outer proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleAuxiliaryTransport {
    /// Hidden row-hiding witness material stays in-band with the opening proof.
    InBandWithOpeningProof,
    /// Hidden row-hiding witness material moves in a separate proof envelope or field.
    SeparateAuxiliaryProof,
}

/// Shape of the hidden oracle-commitment opening surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleCommitmentShape {
    committed_oracles: usize,
    queried_rows: usize,
    row_width: usize,
    authentication_items_per_query: usize,
    hidden_hiding_witness_items_per_query: usize,
}

impl OracleCommitmentShape {
    /// Builds a validated oracle-commitment shape.
    pub fn new(
        committed_oracles: usize,
        queried_rows: usize,
        row_width: usize,
        authentication_items_per_query: usize,
        hidden_hiding_witness_items_per_query: usize,
    ) -> Result<Self, OracleCommitmentError> {
        if committed_oracles == 0 {
            return Err(OracleCommitmentError::ZeroCommittedOracles);
        }
        if queried_rows == 0 {
            return Err(OracleCommitmentError::ZeroQueriedRows);
        }
        if row_width == 0 {
            return Err(OracleCommitmentError::ZeroRowWidth);
        }
        if authentication_items_per_query == 0 {
            return Err(OracleCommitmentError::ZeroAuthenticationItemsPerQuery);
        }
        if hidden_hiding_witness_items_per_query == 0 {
            return Err(OracleCommitmentError::ZeroHiddenWitnessItemsPerQuery);
        }
        if queried_rows.checked_mul(row_width).is_none() {
            return Err(OracleCommitmentError::PublicRowValuesOverflow {
                queried_rows,
                row_width,
            });
        }
        if queried_rows
            .checked_mul(authentication_items_per_query)
            .is_none()
        {
            return Err(OracleCommitmentError::PublicAuthenticationItemsOverflow {
                queried_rows,
                authentication_items_per_query,
            });
        }
        if queried_rows
            .checked_mul(hidden_hiding_witness_items_per_query)
            .is_none()
        {
            return Err(OracleCommitmentError::HiddenWitnessItemsOverflow {
                queried_rows,
                hidden_hiding_witness_items_per_query,
            });
        }

        Ok(Self {
            committed_oracles,
            queried_rows,
            row_width,
            authentication_items_per_query,
            hidden_hiding_witness_items_per_query,
        })
    }

    /// Number of committed oracle objects.
    #[must_use]
    pub const fn committed_oracles(self) -> usize {
        self.committed_oracles
    }

    /// Number of queried rows opened by the backend.
    #[must_use]
    pub const fn queried_rows(self) -> usize {
        self.queried_rows
    }

    /// Number of public row values exposed per queried row.
    #[must_use]
    pub const fn row_width(self) -> usize {
        self.row_width
    }

    /// Number of public authentication items exposed per queried row.
    #[must_use]
    pub const fn authentication_items_per_query(self) -> usize {
        self.authentication_items_per_query
    }

    /// Number of hidden row-hiding witness items carried per queried row.
    ///
    /// This may model explicit salts or an equivalent backend witness.
    #[must_use]
    pub const fn hidden_hiding_witness_items_per_query(self) -> usize {
        self.hidden_hiding_witness_items_per_query
    }
}

/// Public-vs-hidden opening payload implied by a hidden oracle-commitment object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleCommitmentPayload {
    public_commitments: usize,
    public_row_values: usize,
    public_authentication_items: usize,
    hidden_hiding_witness_items: usize,
    auxiliary_transport: OracleAuxiliaryTransport,
}

impl OracleCommitmentPayload {
    /// Builds an oracle-commitment payload from a validated shape.
    ///
    /// Lean theorems: `OracleCommitmentPayload.fromShape_publicCommitments`,
    /// `OracleCommitmentPayload.fromShape_publicRowValues`,
    /// `OracleCommitmentPayload.fromShape_publicAuthenticationItems`, and
    /// `OracleCommitmentPayload.fromShape_hiddenHidingWitnessItems`.
    #[must_use]
    pub const fn new(
        shape: OracleCommitmentShape,
        auxiliary_transport: OracleAuxiliaryTransport,
    ) -> Self {
        Self {
            public_commitments: shape.committed_oracles(),
            public_row_values: shape.queried_rows() * shape.row_width(),
            public_authentication_items: shape.queried_rows()
                * shape.authentication_items_per_query(),
            hidden_hiding_witness_items: shape.queried_rows()
                * shape.hidden_hiding_witness_items_per_query(),
            auxiliary_transport,
        }
    }

    /// Number of public commitment objects carried by the outer proof.
    #[must_use]
    pub const fn public_commitments(self) -> usize {
        self.public_commitments
    }

    /// Number of public row values revealed by the opening surface.
    #[must_use]
    pub const fn public_row_values(self) -> usize {
        self.public_row_values
    }

    /// Number of public authentication items revealed by the opening surface.
    #[must_use]
    pub const fn public_authentication_items(self) -> usize {
        self.public_authentication_items
    }

    /// Number of hidden row-hiding witness items carried in the proof.
    #[must_use]
    pub const fn hidden_hiding_witness_items(self) -> usize {
        self.hidden_hiding_witness_items
    }

    /// Transport used for the hidden row-hiding witness material.
    #[must_use]
    pub const fn auxiliary_transport(self) -> OracleAuxiliaryTransport {
        self.auxiliary_transport
    }
}

/// SHROUD object for hidden oracle commitments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShroudOracleCommitmentSpec {
    security_level: SecurityLevel,
    perfect_claim: Option<PerfectClaim>,
    shape: OracleCommitmentShape,
    payload: OracleCommitmentPayload,
}

impl ShroudOracleCommitmentSpec {
    /// Builds a statistical hidden oracle-commitment object.
    pub fn statistical(
        shape: OracleCommitmentShape,
        auxiliary_transport: OracleAuxiliaryTransport,
    ) -> Result<Self, OracleCommitmentError> {
        Self::new_with_claim(SecurityLevel::Statistical, None, shape, auxiliary_transport)
    }

    /// Builds a perfect hidden oracle-commitment object.
    pub fn perfect(
        shape: OracleCommitmentShape,
        auxiliary_transport: OracleAuxiliaryTransport,
        perfect_claim: PerfectClaim,
    ) -> Result<Self, OracleCommitmentError> {
        Self::new_with_claim(
            SecurityLevel::Perfect,
            Some(perfect_claim),
            shape,
            auxiliary_transport,
        )
    }

    /// Builds a hidden oracle-commitment object with an explicit security level.
    pub fn new(
        security_level: SecurityLevel,
        shape: OracleCommitmentShape,
        auxiliary_transport: OracleAuxiliaryTransport,
    ) -> Result<Self, OracleCommitmentError> {
        Self::new_with_claim(security_level, None, shape, auxiliary_transport)
    }

    fn new_with_claim(
        security_level: SecurityLevel,
        perfect_claim: Option<PerfectClaim>,
        shape: OracleCommitmentShape,
        auxiliary_transport: OracleAuxiliaryTransport,
    ) -> Result<Self, OracleCommitmentError> {
        let payload = OracleCommitmentPayload::new(shape, auxiliary_transport);
        let spec = Self {
            security_level,
            perfect_claim,
            shape,
            payload,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Security level implemented by the hidden oracle-commitment object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Structured justification for a perfect HVZK claim, if this is a perfect variant.
    #[must_use]
    pub const fn perfect_claim(&self) -> Option<PerfectClaim> {
        self.perfect_claim
    }

    /// Shape of the hidden oracle-commitment opening surface.
    #[must_use]
    pub const fn shape(&self) -> OracleCommitmentShape {
        self.shape
    }

    /// Public-vs-hidden payload implied by the commitment object.
    #[must_use]
    pub const fn payload(&self) -> OracleCommitmentPayload {
        self.payload
    }

    /// Transport used by the hidden row-hiding witness material.
    #[must_use]
    pub const fn auxiliary_transport(&self) -> OracleAuxiliaryTransport {
        self.payload.auxiliary_transport()
    }

    /// Validates the shape-level invariants of the oracle-commitment object.
    pub fn validate(&self) -> Result<(), OracleCommitmentError> {
        match (self.security_level, self.perfect_claim) {
            (SecurityLevel::Perfect, None) => {
                return Err(OracleCommitmentError::PerfectRequiresClaim);
            }
            (SecurityLevel::Statistical, Some(_)) => {
                return Err(OracleCommitmentError::PerfectClaimOnStatisticalSpec);
            }
            (_, _) => {}
        }

        if let Some(claim) = self.perfect_claim {
            claim.validate()?;
            let required_query_budget = self.shape.queried_rows();
            if claim.query_budget < required_query_budget {
                return Err(OracleCommitmentError::PerfectClaimQueryBudgetTooSmall {
                    claim_query_budget: claim.query_budget,
                    required_query_budget,
                });
            }
        }

        if self.payload.public_commitments() != self.shape.committed_oracles()
            || self.payload.public_row_values()
                != self.shape.queried_rows() * self.shape.row_width()
            || self.payload.public_authentication_items()
                != self.shape.queried_rows() * self.shape.authentication_items_per_query()
            || self.payload.hidden_hiding_witness_items()
                != self.shape.queried_rows() * self.shape.hidden_hiding_witness_items_per_query()
        {
            return Err(OracleCommitmentError::PayloadShapeMismatch);
        }

        Ok(())
    }
}

impl TranscriptBindable for ShroudOracleCommitmentSpec {
    /// Encodes all five shape fields, derived payload counts, security level,
    /// and auxiliary transport.
    fn to_transcript_binding(&self) -> TranscriptBinding {
        let shape = self.shape();
        let mut bytes = Vec::with_capacity(97);
        match self.perfect_claim() {
            Some(claim) => {
                bytes.push(1);
                bytes.extend_from_slice(&claim.to_canonical_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&(shape.committed_oracles() as u64).to_le_bytes());
        bytes.extend_from_slice(&(shape.queried_rows() as u64).to_le_bytes());
        bytes.extend_from_slice(&(shape.row_width() as u64).to_le_bytes());
        bytes.extend_from_slice(&(shape.authentication_items_per_query() as u64).to_le_bytes());
        bytes.extend_from_slice(
            &(shape.hidden_hiding_witness_items_per_query() as u64).to_le_bytes(),
        );
        let payload = self.payload();
        bytes.extend_from_slice(&(payload.public_commitments() as u64).to_le_bytes());
        bytes.extend_from_slice(&(payload.public_row_values() as u64).to_le_bytes());
        bytes.extend_from_slice(&(payload.public_authentication_items() as u64).to_le_bytes());
        bytes.extend_from_slice(&(payload.hidden_hiding_witness_items() as u64).to_le_bytes());
        bytes.push(security_level_discriminant(self.security_level()));
        bytes.push(auxiliary_transport_discriminant(self.auxiliary_transport()));
        TranscriptBinding::new(DOMAIN_ORACLE_COMMITMENT, bytes)
    }
}

const fn security_level_discriminant(security_level: SecurityLevel) -> u8 {
    match security_level {
        SecurityLevel::Statistical => 0,
        SecurityLevel::Perfect => 1,
    }
}

const fn auxiliary_transport_discriminant(transport: OracleAuxiliaryTransport) -> u8 {
    match transport {
        OracleAuxiliaryTransport::InBandWithOpeningProof => 0,
        OracleAuxiliaryTransport::SeparateAuxiliaryProof => 1,
    }
}

/// Error raised when an oracle-commitment object violates a SHROUD invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleCommitmentError {
    /// A hidden oracle commitment must contain at least one commitment object.
    ZeroCommittedOracles,
    /// A hidden oracle commitment must open at least one queried row.
    ZeroQueriedRows,
    /// A queried row must expose at least one value.
    ZeroRowWidth,
    /// Each queried row must expose at least one authentication item.
    ZeroAuthenticationItemsPerQuery,
    /// Each queried row must carry at least one hidden row-hiding witness item.
    ZeroHiddenWitnessItemsPerQuery,
    /// Perfect variants must carry a structured `PerfectClaim`.
    PerfectRequiresClaim,
    /// Statistical variants must not carry perfect-claim evidence.
    PerfectClaimOnStatisticalSpec,
    /// The supplied `PerfectClaim` is internally inconsistent.
    PerfectClaim(PerfectClaimError),
    /// The perfect claim query budget does not cover all queried oracle rows.
    PerfectClaimQueryBudgetTooSmall {
        /// Query budget declared by the perfect claim.
        claim_query_budget: usize,
        /// Query budget required by the object surface.
        required_query_budget: usize,
    },
    /// The public row value count `queried_rows * row_width` overflowed `usize`.
    ///
    /// SHROUD's normative Lean model uses exact natural-number multiplication
    /// for payload accounting. Rust must reject shapes whose exact count cannot
    /// be represented by `usize`.
    PublicRowValuesOverflow {
        /// Number of queried rows.
        queried_rows: usize,
        /// Number of public row values per queried row.
        row_width: usize,
    },
    /// The public authentication item count overflowed `usize`.
    ///
    /// This is the exact product `queried_rows * authentication_items_per_query`.
    PublicAuthenticationItemsOverflow {
        /// Number of queried rows.
        queried_rows: usize,
        /// Number of authentication items per queried row.
        authentication_items_per_query: usize,
    },
    /// The hidden witness item count overflowed `usize`.
    ///
    /// This is the exact product `queried_rows * hidden_hiding_witness_items_per_query`.
    HiddenWitnessItemsOverflow {
        /// Number of queried rows.
        queried_rows: usize,
        /// Number of hidden witness items per queried row.
        hidden_hiding_witness_items_per_query: usize,
    },
    /// The derived payload no longer matches the validated shape.
    PayloadShapeMismatch,
}

impl fmt::Display for OracleCommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCommittedOracles => {
                write!(
                    f,
                    "oracle commitment must contain at least one commitment object"
                )
            }
            Self::ZeroQueriedRows => {
                write!(f, "oracle commitment must open at least one queried row")
            }
            Self::ZeroRowWidth => {
                write!(f, "oracle commitment rows must expose at least one value")
            }
            Self::ZeroAuthenticationItemsPerQuery => write!(
                f,
                "oracle commitment must expose at least one authentication item per queried row"
            ),
            Self::ZeroHiddenWitnessItemsPerQuery => write!(
                f,
                "oracle commitment must carry at least one hidden witness item per queried row"
            ),
            Self::PerfectRequiresClaim => write!(
                f,
                "perfect oracle-commitment specs must carry a validated PerfectClaim"
            ),
            Self::PerfectClaimOnStatisticalSpec => write!(
                f,
                "statistical oracle-commitment specs must not carry a PerfectClaim"
            ),
            Self::PerfectClaim(err) => err.fmt(f),
            Self::PerfectClaimQueryBudgetTooSmall {
                claim_query_budget,
                required_query_budget,
            } => write!(
                f,
                "perfect oracle-commitment claim query budget ({claim_query_budget}) does not \
                 cover the required queried-row count ({required_query_budget})"
            ),
            Self::PublicRowValuesOverflow {
                queried_rows,
                row_width,
            } => write!(
                f,
                "oracle commitment public row value count overflows usize: \
                 queried_rows ({queried_rows}) * row_width ({row_width})"
            ),
            Self::PublicAuthenticationItemsOverflow {
                queried_rows,
                authentication_items_per_query,
            } => write!(
                f,
                "oracle commitment public authentication count overflows usize: \
                 queried_rows ({queried_rows}) * authentication_items_per_query \
                 ({authentication_items_per_query})"
            ),
            Self::HiddenWitnessItemsOverflow {
                queried_rows,
                hidden_hiding_witness_items_per_query,
            } => write!(
                f,
                "oracle commitment hidden witness count overflows usize: \
                 queried_rows ({queried_rows}) * hidden_hiding_witness_items_per_query \
                 ({hidden_hiding_witness_items_per_query})"
            ),
            Self::PayloadShapeMismatch => {
                write!(f, "oracle commitment payload no longer matches its shape")
            }
        }
    }
}

impl std::error::Error for OracleCommitmentError {}

impl From<PerfectClaimError> for OracleCommitmentError {
    fn from(value: PerfectClaimError) -> Self {
        Self::PerfectClaim(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OracleAuxiliaryTransport, OracleCommitmentError, OracleCommitmentShape,
        ShroudOracleCommitmentSpec,
    };
    use shroud_core::{
        BasisDescriptor, FieldModel, PerfectClaim, RandomnessModel, SecurityLevel,
        SimulatorObligations, TranscriptBindable,
    };

    fn valid_perfect_claim(extension_degree: usize, query_budget: usize) -> PerfectClaim {
        PerfectClaim::new(
            RandomnessModel::UniformPerProof,
            FieldModel::EncodedCoordinates {
                basis: BasisDescriptor::plonky3_binomial(extension_degree),
            },
            query_budget,
            SimulatorObligations::HonestVerifierChallengeAccess,
            true,
        )
        .expect("valid perfect claim")
    }

    #[test]
    fn statistical_oracle_commitment_tracks_public_and_hidden_surface() {
        let shape = OracleCommitmentShape::new(2, 3, 4, 5, 1).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::statistical(
            shape,
            OracleAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Statistical);
        assert_eq!(spec.payload().public_commitments(), 2);
        assert_eq!(spec.payload().public_row_values(), 12);
        assert_eq!(spec.payload().public_authentication_items(), 15);
        assert_eq!(spec.payload().hidden_hiding_witness_items(), 3);
    }

    #[test]
    fn perfect_oracle_commitment_can_use_separate_auxiliary_transport() {
        let shape = OracleCommitmentShape::new(1, 2, 8, 4, 2).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::perfect(
            shape,
            OracleAuxiliaryTransport::SeparateAuxiliaryProof,
            valid_perfect_claim(8, 2),
        )
        .expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Perfect);
        assert_eq!(
            spec.auxiliary_transport(),
            OracleAuxiliaryTransport::SeparateAuxiliaryProof
        );
        assert_eq!(spec.payload().hidden_hiding_witness_items(), 4);
        assert!(spec.perfect_claim().is_some());
    }

    #[test]
    fn generic_constructor_rejects_perfect_without_claim() {
        let shape = OracleCommitmentShape::new(1, 2, 8, 4, 2).expect("valid shape");
        assert_eq!(
            ShroudOracleCommitmentSpec::new(
                SecurityLevel::Perfect,
                shape,
                OracleAuxiliaryTransport::SeparateAuxiliaryProof,
            ),
            Err(OracleCommitmentError::PerfectRequiresClaim)
        );
    }

    #[test]
    fn perfect_claim_query_budget_must_cover_queried_rows() {
        let shape = OracleCommitmentShape::new(1, 3, 8, 4, 2).expect("valid shape");
        assert_eq!(
            ShroudOracleCommitmentSpec::perfect(
                shape,
                OracleAuxiliaryTransport::SeparateAuxiliaryProof,
                valid_perfect_claim(8, 1),
            ),
            Err(OracleCommitmentError::PerfectClaimQueryBudgetTooSmall {
                claim_query_budget: 1,
                required_query_budget: 3,
            })
        );
    }

    #[test]
    fn rejects_zero_hidden_witness_surface() {
        assert_eq!(
            OracleCommitmentShape::new(1, 1, 4, 3, 0),
            Err(OracleCommitmentError::ZeroHiddenWitnessItemsPerQuery)
        );
    }

    #[test]
    fn rejects_public_row_values_overflow() {
        assert_eq!(
            OracleCommitmentShape::new(1, usize::MAX, 2, 1, 1),
            Err(OracleCommitmentError::PublicRowValuesOverflow {
                queried_rows: usize::MAX,
                row_width: 2,
            })
        );
    }

    #[test]
    fn rejects_public_authentication_items_overflow() {
        assert_eq!(
            OracleCommitmentShape::new(1, usize::MAX, 1, 2, 1),
            Err(OracleCommitmentError::PublicAuthenticationItemsOverflow {
                queried_rows: usize::MAX,
                authentication_items_per_query: 2,
            })
        );
    }

    #[test]
    fn rejects_hidden_witness_items_overflow() {
        assert_eq!(
            OracleCommitmentShape::new(1, usize::MAX, 1, 1, 2),
            Err(OracleCommitmentError::HiddenWitnessItemsOverflow {
                queried_rows: usize::MAX,
                hidden_hiding_witness_items_per_query: 2,
            })
        );
    }

    #[test]
    fn oracle_commitment_binding_encodes_shape_and_security_level() {
        let shape = OracleCommitmentShape::new(2, 3, 4, 5, 1).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::statistical(
            shape,
            OracleAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid spec");
        let binding = spec.to_transcript_binding();
        assert_eq!(
            binding.domain_label(),
            shroud_core::DOMAIN_ORACLE_COMMITMENT
        );
        assert_eq!(binding.canonical_bytes().len(), 75);
        // statistical = 0x00, in-band transport = 0x00 as final two bytes
        assert_eq!(
            &binding.canonical_bytes()[binding.canonical_bytes().len() - 2..],
            &[0u8, 0u8]
        );
    }

    #[test]
    fn oracle_commitment_bindings_differ_by_security_level() {
        let shape = OracleCommitmentShape::new(2, 3, 4, 5, 1).expect("valid shape");
        let stat = ShroudOracleCommitmentSpec::statistical(
            shape,
            OracleAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid");
        let perf = ShroudOracleCommitmentSpec::perfect(
            shape,
            OracleAuxiliaryTransport::InBandWithOpeningProof,
            valid_perfect_claim(4, 3),
        )
        .expect("valid");
        assert_ne!(stat.to_transcript_binding(), perf.to_transcript_binding());
    }
}
