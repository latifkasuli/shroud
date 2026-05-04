#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SHROUD object for hiding quotient commitments and quotient-opening structure.
//!
//! In this crate, `SecurityLevel` records the claimed hiding level of the
//! quotient-hiding object. It does not, by itself, force one particular
//! auxiliary transport. Different backends may keep quotient masking witnesses
//! in-band with the main opening proof or move them into a separate auxiliary
//! path. The object also exposes both the quotient decomposition family and the
//! claimed query budget, because SHROUD treats both as first-class contract
//! items rather than backend-internal assumptions.

use core::fmt;

use shroud_core::SecurityLevel;

/// Quotient decomposition family supported by the hiding transform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientDecompositionFamily {
    /// A single monolithic quotient object is committed and opened.
    Monolithic,
    /// The quotient is split into degree-bounded chunks or pieces.
    DegreeChunked,
    /// The quotient uses a segmented backend-specific decomposition family.
    Segmented,
}

/// How hidden quotient witness material is transported through the outer proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientAuxiliaryTransport {
    /// Hidden quotient auxiliaries stay in-band with the opening proof.
    InBandWithOpeningProof,
    /// Hidden quotient auxiliaries move in a separate proof envelope or field.
    SeparateAuxiliaryProof,
}

/// Shape of the hidden quotient-opening surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientHiderShape {
    decomposition_components: usize,
    opening_points: usize,
    openings_per_point: usize,
    hidden_mask_values_per_point: usize,
    hidden_normalization_items: usize,
}

impl QuotientHiderShape {
    /// Builds a validated quotient-hider shape.
    pub fn new(
        decomposition_components: usize,
        opening_points: usize,
        openings_per_point: usize,
        hidden_mask_values_per_point: usize,
        hidden_normalization_items: usize,
    ) -> Result<Self, QuotientHiderError> {
        if decomposition_components == 0 {
            return Err(QuotientHiderError::ZeroDecompositionComponents);
        }
        if opening_points == 0 {
            return Err(QuotientHiderError::ZeroOpeningPoints);
        }
        if openings_per_point == 0 {
            return Err(QuotientHiderError::ZeroOpeningsPerPoint);
        }
        if hidden_mask_values_per_point == 0 {
            return Err(QuotientHiderError::ZeroHiddenMaskValuesPerPoint);
        }
        if hidden_normalization_items == 0 {
            return Err(QuotientHiderError::ZeroHiddenNormalizationItems);
        }

        Ok(Self {
            decomposition_components,
            opening_points,
            openings_per_point,
            hidden_mask_values_per_point,
            hidden_normalization_items,
        })
    }

    /// Number of committed quotient components.
    #[must_use]
    pub const fn decomposition_components(self) -> usize {
        self.decomposition_components
    }

    /// Number of queried opening points used by the verifier.
    #[must_use]
    pub const fn opening_points(self) -> usize {
        self.opening_points
    }

    /// Number of public quotient evaluations revealed per opening point.
    #[must_use]
    pub const fn openings_per_point(self) -> usize {
        self.openings_per_point
    }

    /// Number of hidden quotient-mask values carried per opening point.
    #[must_use]
    pub const fn hidden_mask_values_per_point(self) -> usize {
        self.hidden_mask_values_per_point
    }

    /// Number of hidden normalization items carried by the proof.
    #[must_use]
    pub const fn hidden_normalization_items(self) -> usize {
        self.hidden_normalization_items
    }
}

/// Public-vs-hidden surface implied by a quotient-hider object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientHiderPayload {
    public_commitments: usize,
    public_opening_values: usize,
    hidden_mask_values: usize,
    hidden_normalization_items: usize,
    auxiliary_transport: QuotientAuxiliaryTransport,
}

impl QuotientHiderPayload {
    /// Builds a quotient-hider payload from a validated shape.
    #[must_use]
    pub const fn new(
        shape: QuotientHiderShape,
        auxiliary_transport: QuotientAuxiliaryTransport,
    ) -> Self {
        Self {
            public_commitments: shape.decomposition_components(),
            public_opening_values: shape
                .opening_points()
                .saturating_mul(shape.openings_per_point()),
            hidden_mask_values: shape
                .opening_points()
                .saturating_mul(shape.hidden_mask_values_per_point()),
            hidden_normalization_items: shape.hidden_normalization_items(),
            auxiliary_transport,
        }
    }

    /// Number of public quotient commitments carried by the outer proof.
    #[must_use]
    pub const fn public_commitments(self) -> usize {
        self.public_commitments
    }

    /// Number of public quotient opening values revealed by the outer proof.
    #[must_use]
    pub const fn public_opening_values(self) -> usize {
        self.public_opening_values
    }

    /// Number of hidden quotient-mask values carried in the proof.
    #[must_use]
    pub const fn hidden_mask_values(self) -> usize {
        self.hidden_mask_values
    }

    /// Number of hidden normalization items carried in the proof.
    #[must_use]
    pub const fn hidden_normalization_items(self) -> usize {
        self.hidden_normalization_items
    }

    /// Transport used for the hidden quotient auxiliary material.
    #[must_use]
    pub const fn auxiliary_transport(self) -> QuotientAuxiliaryTransport {
        self.auxiliary_transport
    }
}

/// SHROUD object for hidden quotient commitments and openings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShroudQuotientHiderSpec {
    security_level: SecurityLevel,
    decomposition_family: QuotientDecompositionFamily,
    query_budget: usize,
    shape: QuotientHiderShape,
    payload: QuotientHiderPayload,
}

impl ShroudQuotientHiderSpec {
    /// Builds a statistical quotient-hider object.
    pub fn statistical(
        decomposition_family: QuotientDecompositionFamily,
        query_budget: usize,
        shape: QuotientHiderShape,
        auxiliary_transport: QuotientAuxiliaryTransport,
    ) -> Result<Self, QuotientHiderError> {
        Self::new(
            SecurityLevel::Statistical,
            decomposition_family,
            query_budget,
            shape,
            auxiliary_transport,
        )
    }

    /// Builds a perfect quotient-hider object.
    pub fn perfect(
        decomposition_family: QuotientDecompositionFamily,
        query_budget: usize,
        shape: QuotientHiderShape,
        auxiliary_transport: QuotientAuxiliaryTransport,
    ) -> Result<Self, QuotientHiderError> {
        Self::new(
            SecurityLevel::Perfect,
            decomposition_family,
            query_budget,
            shape,
            auxiliary_transport,
        )
    }

    /// Builds a quotient-hider object with an explicit security level.
    pub fn new(
        security_level: SecurityLevel,
        decomposition_family: QuotientDecompositionFamily,
        query_budget: usize,
        shape: QuotientHiderShape,
        auxiliary_transport: QuotientAuxiliaryTransport,
    ) -> Result<Self, QuotientHiderError> {
        let payload = QuotientHiderPayload::new(shape, auxiliary_transport);
        let spec = Self {
            security_level,
            decomposition_family,
            query_budget,
            shape,
            payload,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Security level implemented by the quotient-hider object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Quotient decomposition family supported by the object.
    #[must_use]
    pub const fn decomposition_family(&self) -> QuotientDecompositionFamily {
        self.decomposition_family
    }

    /// Claimed query budget for the hiding guarantee.
    #[must_use]
    pub const fn query_budget(&self) -> usize {
        self.query_budget
    }

    /// Shape of the hidden quotient-opening surface.
    #[must_use]
    pub const fn shape(&self) -> QuotientHiderShape {
        self.shape
    }

    /// Public-vs-hidden payload implied by the quotient-hider object.
    #[must_use]
    pub const fn payload(&self) -> QuotientHiderPayload {
        self.payload
    }

    /// Transport used by the hidden quotient auxiliary material.
    #[must_use]
    pub const fn auxiliary_transport(&self) -> QuotientAuxiliaryTransport {
        self.payload.auxiliary_transport()
    }

    /// Validates the shape-level and decomposition-level invariants of the quotient-hider object.
    pub fn validate(&self) -> Result<(), QuotientHiderError> {
        if self.query_budget == 0 {
            return Err(QuotientHiderError::ZeroQueryBudget);
        }

        if self.shape.opening_points() > self.query_budget {
            return Err(QuotientHiderError::OpeningPointsExceedQueryBudget {
                query_budget: self.query_budget,
                opening_points: self.shape.opening_points(),
            });
        }

        if matches!(
            self.decomposition_family,
            QuotientDecompositionFamily::Monolithic
        ) && self.shape.decomposition_components() != 1
        {
            return Err(QuotientHiderError::MonolithicRequiresSingleComponent {
                observed: self.shape.decomposition_components(),
            });
        }

        if self.payload.public_commitments() != self.shape.decomposition_components()
            || self.payload.public_opening_values()
                != self
                    .shape
                    .opening_points()
                    .saturating_mul(self.shape.openings_per_point())
            || self.payload.hidden_mask_values()
                != self
                    .shape
                    .opening_points()
                    .saturating_mul(self.shape.hidden_mask_values_per_point())
            || self.payload.hidden_normalization_items() != self.shape.hidden_normalization_items()
        {
            return Err(QuotientHiderError::PayloadShapeMismatch);
        }

        Ok(())
    }
}

/// Error raised when a quotient-hider object violates a SHROUD invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotientHiderError {
    /// A quotient-hider object must contain at least one quotient component.
    ZeroDecompositionComponents,
    /// A quotient-hider object must open at least one point.
    ZeroOpeningPoints,
    /// Each opening point must reveal at least one public quotient evaluation.
    ZeroOpeningsPerPoint,
    /// Each opening point must carry at least one hidden mask value.
    ZeroHiddenMaskValuesPerPoint,
    /// A quotient-hider object must carry at least one hidden normalization item.
    ZeroHiddenNormalizationItems,
    /// The query budget must be at least one.
    ZeroQueryBudget,
    /// A monolithic decomposition must expose exactly one quotient component.
    MonolithicRequiresSingleComponent {
        /// Number of components actually supplied.
        observed: usize,
    },
    /// The opening surface exceeds the claimed query budget.
    OpeningPointsExceedQueryBudget {
        /// Query budget claimed by the object.
        query_budget: usize,
        /// Opening points requested by the shape.
        opening_points: usize,
    },
    /// The derived payload no longer matches the validated shape.
    PayloadShapeMismatch,
}

impl fmt::Display for QuotientHiderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDecompositionComponents => write!(
                f,
                "quotient hider must contain at least one decomposition component"
            ),
            Self::ZeroOpeningPoints => {
                write!(f, "quotient hider must open at least one point")
            }
            Self::ZeroOpeningsPerPoint => write!(
                f,
                "quotient hider must reveal at least one quotient evaluation per point"
            ),
            Self::ZeroHiddenMaskValuesPerPoint => write!(
                f,
                "quotient hider must carry at least one hidden mask value per point"
            ),
            Self::ZeroHiddenNormalizationItems => write!(
                f,
                "quotient hider must carry at least one hidden normalization item"
            ),
            Self::ZeroQueryBudget => write!(f, "quotient hider query budget must be at least one"),
            Self::MonolithicRequiresSingleComponent { observed } => write!(
                f,
                "monolithic quotient decomposition requires exactly one component, observed {observed}"
            ),
            Self::OpeningPointsExceedQueryBudget {
                query_budget,
                opening_points,
            } => write!(
                f,
                "quotient hider opening points {opening_points} exceed query budget {query_budget}"
            ),
            Self::PayloadShapeMismatch => {
                write!(f, "quotient hider payload no longer matches its shape")
            }
        }
    }
}

impl std::error::Error for QuotientHiderError {}

#[cfg(test)]
mod tests {
    use super::{
        QuotientAuxiliaryTransport, QuotientDecompositionFamily, QuotientHiderError,
        QuotientHiderShape, ShroudQuotientHiderSpec,
    };
    use shroud_core::SecurityLevel;

    #[test]
    fn statistical_quotient_hider_tracks_public_and_hidden_surface() {
        let shape = QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid shape");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Statistical);
        assert_eq!(
            spec.decomposition_family(),
            QuotientDecompositionFamily::DegreeChunked
        );
        assert_eq!(spec.query_budget(), 8);
        assert_eq!(spec.payload().public_commitments(), 3);
        assert_eq!(spec.payload().public_opening_values(), 8);
        assert_eq!(spec.payload().hidden_mask_values(), 2);
        assert_eq!(spec.payload().hidden_normalization_items(), 2);
    }

    #[test]
    fn perfect_quotient_hider_can_use_separate_auxiliary_transport() {
        let shape = QuotientHiderShape::new(2, 3, 2, 2, 4).expect("valid shape");
        let spec = ShroudQuotientHiderSpec::perfect(
            QuotientDecompositionFamily::Segmented,
            6,
            shape,
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof,
        )
        .expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Perfect);
        assert_eq!(
            spec.auxiliary_transport(),
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof
        );
        assert_eq!(spec.payload().hidden_mask_values(), 6);
    }

    #[test]
    fn monolithic_decomposition_rejects_multiple_components() {
        let shape = QuotientHiderShape::new(2, 1, 4, 1, 1).expect("valid shape");

        assert_eq!(
            ShroudQuotientHiderSpec::statistical(
                QuotientDecompositionFamily::Monolithic,
                4,
                shape,
                QuotientAuxiliaryTransport::InBandWithOpeningProof,
            ),
            Err(QuotientHiderError::MonolithicRequiresSingleComponent { observed: 2 })
        );
    }

    #[test]
    fn rejects_opening_surface_that_exceeds_query_budget() {
        let shape = QuotientHiderShape::new(1, 5, 2, 1, 1).expect("valid shape");

        assert_eq!(
            ShroudQuotientHiderSpec::statistical(
                QuotientDecompositionFamily::Monolithic,
                4,
                shape,
                QuotientAuxiliaryTransport::InBandWithOpeningProof,
            ),
            Err(QuotientHiderError::OpeningPointsExceedQueryBudget {
                query_budget: 4,
                opening_points: 5,
            })
        );
    }
}
