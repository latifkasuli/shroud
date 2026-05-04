#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SHROUD object for hidden oracle commitments and authenticated row openings.
//!
//! In this crate, `SecurityLevel` records the claimed hiding level of the
//! oracle-commitment object. It does not, by itself, force one particular
//! hiding-witness transport. Different backends may keep row salts in-band with
//! the opening proof or move them into a separate auxiliary proof path.

use core::fmt;

use shroud_core::SecurityLevel;

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
    #[must_use]
    pub const fn new(
        shape: OracleCommitmentShape,
        auxiliary_transport: OracleAuxiliaryTransport,
    ) -> Self {
        Self {
            public_commitments: shape.committed_oracles(),
            public_row_values: shape.queried_rows().saturating_mul(shape.row_width()),
            public_authentication_items: shape
                .queried_rows()
                .saturating_mul(shape.authentication_items_per_query()),
            hidden_hiding_witness_items: shape
                .queried_rows()
                .saturating_mul(shape.hidden_hiding_witness_items_per_query()),
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
    shape: OracleCommitmentShape,
    payload: OracleCommitmentPayload,
}

impl ShroudOracleCommitmentSpec {
    /// Builds a statistical hidden oracle-commitment object.
    pub fn statistical(
        shape: OracleCommitmentShape,
        auxiliary_transport: OracleAuxiliaryTransport,
    ) -> Result<Self, OracleCommitmentError> {
        Self::new(SecurityLevel::Statistical, shape, auxiliary_transport)
    }

    /// Builds a perfect hidden oracle-commitment object.
    pub fn perfect(
        shape: OracleCommitmentShape,
        auxiliary_transport: OracleAuxiliaryTransport,
    ) -> Result<Self, OracleCommitmentError> {
        Self::new(SecurityLevel::Perfect, shape, auxiliary_transport)
    }

    /// Builds a hidden oracle-commitment object with an explicit security level.
    pub fn new(
        security_level: SecurityLevel,
        shape: OracleCommitmentShape,
        auxiliary_transport: OracleAuxiliaryTransport,
    ) -> Result<Self, OracleCommitmentError> {
        let payload = OracleCommitmentPayload::new(shape, auxiliary_transport);
        let spec = Self {
            security_level,
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
        if self.payload.public_commitments() != self.shape.committed_oracles()
            || self.payload.public_row_values()
                != self
                    .shape
                    .queried_rows()
                    .saturating_mul(self.shape.row_width())
            || self.payload.public_authentication_items()
                != self
                    .shape
                    .queried_rows()
                    .saturating_mul(self.shape.authentication_items_per_query())
            || self.payload.hidden_hiding_witness_items()
                != self
                    .shape
                    .queried_rows()
                    .saturating_mul(self.shape.hidden_hiding_witness_items_per_query())
        {
            return Err(OracleCommitmentError::PayloadShapeMismatch);
        }

        Ok(())
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
            Self::PayloadShapeMismatch => {
                write!(f, "oracle commitment payload no longer matches its shape")
            }
        }
    }
}

impl std::error::Error for OracleCommitmentError {}

#[cfg(test)]
mod tests {
    use super::{
        OracleAuxiliaryTransport, OracleCommitmentError, OracleCommitmentShape,
        ShroudOracleCommitmentSpec,
    };
    use shroud_core::SecurityLevel;

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
        )
        .expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Perfect);
        assert_eq!(
            spec.auxiliary_transport(),
            OracleAuxiliaryTransport::SeparateAuxiliaryProof
        );
        assert_eq!(spec.payload().hidden_hiding_witness_items(), 4);
    }

    #[test]
    fn rejects_zero_hidden_witness_surface() {
        assert_eq!(
            OracleCommitmentShape::new(1, 1, 4, 3, 0),
            Err(OracleCommitmentError::ZeroHiddenWitnessItemsPerQuery)
        );
    }
}
