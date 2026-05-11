#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SHROUD object for separating public opening views from hidden auxiliary openings.
//!
//! In this crate, `SecurityLevel` records the claimed outer guarantee for the
//! projection object. It does not, by itself, constrain the chosen auxiliary
//! transport. That policy is left explicit so different backends can map the
//! same projection object into different proof layouts honestly.

use core::fmt;

use shroud_core::{
    DOMAIN_OPENING_PROJECTION, SecurityLevel, TranscriptBindable, TranscriptBinding,
};

/// How hidden auxiliary opening material is carried through the outer proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuxiliaryOpeningTransport {
    /// Hidden auxiliaries stay in-band with the main opening proof.
    ///
    /// This is the opening-projection-level analogue of
    /// `shroud_batch_opening::HiddenOpeningTransport::InBandWithMainOpeningProof`.
    InBandWithMainProof,
    /// Hidden auxiliaries move in a separate proof envelope or field.
    ///
    /// This is the opening-projection-level analogue of
    /// `shroud_batch_opening::HiddenOpeningTransport::SeparateAuxiliaryProof`.
    SeparateAuxiliaryProof,
}

/// Shape of the public-vs-hidden opening split.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpeningProjectionShape {
    public_opening_values: usize,
    hidden_auxiliary_values: usize,
    verifier_reconstruction_items: usize,
}

impl OpeningProjectionShape {
    /// Builds a validated opening-projection shape.
    pub fn new(
        public_opening_values: usize,
        hidden_auxiliary_values: usize,
        verifier_reconstruction_items: usize,
    ) -> Result<Self, OpeningProjectionError> {
        if public_opening_values == 0 {
            return Err(OpeningProjectionError::ZeroPublicOpeningValues);
        }
        if hidden_auxiliary_values == 0 {
            return Err(OpeningProjectionError::ZeroHiddenAuxiliaryValues);
        }
        if verifier_reconstruction_items == 0 {
            return Err(OpeningProjectionError::ZeroVerifierReconstructionItems);
        }

        Ok(Self {
            public_opening_values,
            hidden_auxiliary_values,
            verifier_reconstruction_items,
        })
    }

    /// Number of verifier-visible opening values carried by the statement surface.
    #[must_use]
    pub const fn public_opening_values(self) -> usize {
        self.public_opening_values
    }

    /// Number of hidden auxiliary opening values carried in the proof.
    #[must_use]
    pub const fn hidden_auxiliary_values(self) -> usize {
        self.hidden_auxiliary_values
    }

    /// Number of internal reconstruction items the verifier needs.
    #[must_use]
    pub const fn verifier_reconstruction_items(self) -> usize {
        self.verifier_reconstruction_items
    }
}

/// Concrete public-vs-hidden opening surface implied by a SHROUD projection object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpeningProjectionPayload {
    public_opening_values: usize,
    hidden_auxiliary_values: usize,
    verifier_reconstruction_items: usize,
    auxiliary_transport: AuxiliaryOpeningTransport,
}

impl OpeningProjectionPayload {
    /// Builds a projection payload from a validated shape.
    #[must_use]
    pub const fn new(
        shape: OpeningProjectionShape,
        auxiliary_transport: AuxiliaryOpeningTransport,
    ) -> Self {
        Self {
            public_opening_values: shape.public_opening_values(),
            hidden_auxiliary_values: shape.hidden_auxiliary_values(),
            verifier_reconstruction_items: shape.verifier_reconstruction_items(),
            auxiliary_transport,
        }
    }

    /// Number of public opening values carried by the outer statement surface.
    #[must_use]
    pub const fn public_opening_values(self) -> usize {
        self.public_opening_values
    }

    /// Number of hidden auxiliary opening values carried in the proof.
    #[must_use]
    pub const fn hidden_auxiliary_values(self) -> usize {
        self.hidden_auxiliary_values
    }

    /// Number of verifier reconstruction items implied by the projection.
    #[must_use]
    pub const fn verifier_reconstruction_items(self) -> usize {
        self.verifier_reconstruction_items
    }

    /// Transport mechanism for the hidden auxiliary opening material.
    #[must_use]
    pub const fn auxiliary_transport(self) -> AuxiliaryOpeningTransport {
        self.auxiliary_transport
    }
}

/// SHROUD object that projects public openings away from hidden auxiliary openings.
///
/// The `security_level` here records the claim that the surrounding protocol
/// makes about this projection boundary. It does not currently impose a
/// transport policy by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShroudOpeningProjectionSpec {
    security_level: SecurityLevel,
    shape: OpeningProjectionShape,
    payload: OpeningProjectionPayload,
}

impl ShroudOpeningProjectionSpec {
    /// Builds a statistical opening-projection object.
    ///
    /// This constructor records a statistical claim but does not constrain the
    /// chosen auxiliary transport beyond the validated shape.
    pub fn statistical(
        shape: OpeningProjectionShape,
        auxiliary_transport: AuxiliaryOpeningTransport,
    ) -> Result<Self, OpeningProjectionError> {
        Self::new(SecurityLevel::Statistical, shape, auxiliary_transport)
    }

    /// Builds a perfect opening-projection object.
    ///
    /// This constructor records a perfect-variant claim but does not require a
    /// specific auxiliary transport by itself.
    pub fn perfect(
        shape: OpeningProjectionShape,
        auxiliary_transport: AuxiliaryOpeningTransport,
    ) -> Result<Self, OpeningProjectionError> {
        Self::new(SecurityLevel::Perfect, shape, auxiliary_transport)
    }

    /// Builds an opening-projection object with an explicit security level.
    pub fn new(
        security_level: SecurityLevel,
        shape: OpeningProjectionShape,
        auxiliary_transport: AuxiliaryOpeningTransport,
    ) -> Result<Self, OpeningProjectionError> {
        let payload = OpeningProjectionPayload::new(shape, auxiliary_transport);
        let spec = Self {
            security_level,
            shape,
            payload,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Security level implemented by the opening-projection object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Shape of the projection.
    #[must_use]
    pub const fn shape(&self) -> OpeningProjectionShape {
        self.shape
    }

    /// Public-vs-hidden opening payload implied by the projection object.
    #[must_use]
    pub const fn payload(&self) -> OpeningProjectionPayload {
        self.payload
    }

    /// Transport mechanism used by the hidden auxiliary opening material.
    #[must_use]
    pub const fn auxiliary_transport(&self) -> AuxiliaryOpeningTransport {
        self.payload.auxiliary_transport()
    }

    /// Validates the shape-level invariants of the projection object.
    pub fn validate(&self) -> Result<(), OpeningProjectionError> {
        if self.payload.public_opening_values() != self.shape.public_opening_values()
            || self.payload.hidden_auxiliary_values() != self.shape.hidden_auxiliary_values()
            || self.payload.verifier_reconstruction_items()
                != self.shape.verifier_reconstruction_items()
        {
            return Err(OpeningProjectionError::PayloadShapeMismatch);
        }

        Ok(())
    }
}

impl TranscriptBindable for ShroudOpeningProjectionSpec {
    /// Encodes the complete opening-projection spec: security level, shape,
    /// derived payload, and auxiliary transport.
    fn to_transcript_binding(&self) -> TranscriptBinding {
        let mut bytes = Vec::with_capacity(58);
        bytes.push(security_level_discriminant(self.security_level()));
        let shape = self.shape();
        bytes.extend_from_slice(&(shape.public_opening_values() as u64).to_le_bytes());
        bytes.extend_from_slice(&(shape.hidden_auxiliary_values() as u64).to_le_bytes());
        bytes.extend_from_slice(&(shape.verifier_reconstruction_items() as u64).to_le_bytes());
        let payload = self.payload();
        bytes.extend_from_slice(&(payload.public_opening_values() as u64).to_le_bytes());
        bytes.extend_from_slice(&(payload.hidden_auxiliary_values() as u64).to_le_bytes());
        bytes.extend_from_slice(&(payload.verifier_reconstruction_items() as u64).to_le_bytes());
        bytes.push(auxiliary_transport_discriminant(
            payload.auxiliary_transport(),
        ));
        TranscriptBinding::new(DOMAIN_OPENING_PROJECTION, bytes)
    }
}

const fn security_level_discriminant(security_level: SecurityLevel) -> u8 {
    match security_level {
        SecurityLevel::Statistical => 0,
        SecurityLevel::Perfect => 1,
    }
}

const fn auxiliary_transport_discriminant(transport: AuxiliaryOpeningTransport) -> u8 {
    match transport {
        AuxiliaryOpeningTransport::InBandWithMainProof => 0,
        AuxiliaryOpeningTransport::SeparateAuxiliaryProof => 1,
    }
}

/// Error raised when an opening-projection object violates a SHROUD invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpeningProjectionError {
    /// The public opening surface must expose at least one value.
    ZeroPublicOpeningValues,
    /// The proof must carry at least one hidden auxiliary value.
    ZeroHiddenAuxiliaryValues,
    /// The verifier must have at least one internal reconstruction item.
    ZeroVerifierReconstructionItems,
    /// The derived payload no longer matches the validated shape.
    PayloadShapeMismatch,
}

impl fmt::Display for OpeningProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPublicOpeningValues => {
                write!(
                    f,
                    "opening projection must expose at least one public opening value"
                )
            }
            Self::ZeroHiddenAuxiliaryValues => {
                write!(
                    f,
                    "opening projection must carry at least one hidden auxiliary value"
                )
            }
            Self::ZeroVerifierReconstructionItems => {
                write!(
                    f,
                    "opening projection must retain at least one verifier reconstruction item"
                )
            }
            Self::PayloadShapeMismatch => {
                write!(f, "opening projection payload no longer matches its shape")
            }
        }
    }
}

impl std::error::Error for OpeningProjectionError {}

#[cfg(test)]
mod tests {
    use super::{
        AuxiliaryOpeningTransport, OpeningProjectionError, OpeningProjectionShape,
        ShroudOpeningProjectionSpec,
    };
    use shroud_core::SecurityLevel;

    #[test]
    fn statistical_projection_tracks_in_band_auxiliaries() {
        let shape = OpeningProjectionShape::new(4, 8, 3).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::statistical(
            shape,
            AuxiliaryOpeningTransport::InBandWithMainProof,
        )
        .expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Statistical);
        assert_eq!(spec.payload().public_opening_values(), 4);
        assert_eq!(spec.payload().hidden_auxiliary_values(), 8);
        assert_eq!(
            spec.payload().auxiliary_transport(),
            AuxiliaryOpeningTransport::InBandWithMainProof
        );
    }

    #[test]
    fn perfect_projection_can_require_separate_auxiliary_transport() {
        let shape = OpeningProjectionShape::new(2, 6, 2).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::perfect(
            shape,
            AuxiliaryOpeningTransport::SeparateAuxiliaryProof,
        )
        .expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Perfect);
        assert_eq!(spec.payload().public_opening_values(), 2);
        assert_eq!(spec.payload().hidden_auxiliary_values(), 6);
        assert_eq!(spec.payload().verifier_reconstruction_items(), 2);
    }

    #[test]
    fn security_level_does_not_by_itself_constrain_auxiliary_transport() {
        let shape = OpeningProjectionShape::new(2, 6, 2).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::perfect(
            shape,
            AuxiliaryOpeningTransport::InBandWithMainProof,
        )
        .expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Perfect);
        assert_eq!(
            spec.auxiliary_transport(),
            AuxiliaryOpeningTransport::InBandWithMainProof
        );
    }

    #[test]
    fn rejects_empty_hidden_auxiliary_surface() {
        assert_eq!(
            OpeningProjectionShape::new(2, 0, 1),
            Err(OpeningProjectionError::ZeroHiddenAuxiliaryValues)
        );
    }
}
