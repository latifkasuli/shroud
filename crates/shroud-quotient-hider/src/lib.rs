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

use shroud_core::{DOMAIN_DEGREE_CONTRACT, SecurityLevel, TranscriptBindable, TranscriptBinding};

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

/// Degree compatibility contract for a quotient decomposition.
///
/// Carries two distinct degree bounds:
///
/// - **`quotient_chunk_degree`** — the degree of `q_i(X)` before masking; this is the
///   algebraic degree imposed by the constraint system.
/// - **`randomized_chunk_degree_bound`** — the degree of the masked polynomial that is
///   actually committed; may exceed `quotient_chunk_degree` when a vanishing-factor mask
///   is used.
///
/// Supports both algebraic shapes that appear in hiding quotient constructions:
///
/// - **Plain additive** `q_i(X) + r_i(X)`: `mask_poly_degree ≤ quotient_chunk_degree` so
///   the committed degree equals the original chunk degree. Use [`QuotientDegreeContract::new`].
///
/// - **Vanishing-factor** `q_i(X) + v_{H_i}(X) · t_i(X)`: the product
///   `v_{H_i} · t_i` may exceed `deg(q_i)`, so the committed degree bound is
///   `max(quotient_chunk_degree, vanishing_poly_degree + mask_poly_degree)`, which must not
///   exceed the caller-supplied `randomized_chunk_degree_bound`. Use
///   [`QuotientDegreeContract::with_vanishing_poly`].
///
/// This is structurally different from the batch-opening [`DegreeBudget`], which
/// models `(R(X) - R(ζ)) / (X - ζ)` and allows one extra degree of slack.
///
/// Required when the decomposition family is [`QuotientDecompositionFamily::DegreeChunked`].
/// Optional but validated when present for other families.
///
/// [`DegreeBudget`]: shroud_core::DegreeBudget
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientDegreeContract {
    quotient_chunk_degree: usize,
    vanishing_poly_degree: usize,
    mask_poly_degree: usize,
    randomized_chunk_degree_bound: usize,
}

impl QuotientDegreeContract {
    /// Builds a plain-additive degree contract: `q_i(X) + r_i(X)`.
    ///
    /// Validates `mask_poly_degree ≤ quotient_chunk_degree`. The committed degree
    /// equals the original chunk degree (`randomized_chunk_degree_bound = quotient_chunk_degree`).
    /// For the vanishing-factor form `q_i(X) + v_{H_i}(X) · t_i(X)`,
    /// use [`Self::with_vanishing_poly`] instead.
    pub fn new(
        quotient_chunk_degree: usize,
        mask_poly_degree: usize,
    ) -> Result<Self, QuotientHiderError> {
        if mask_poly_degree > quotient_chunk_degree {
            return Err(QuotientHiderError::DegreeContractViolation {
                quotient_chunk_degree,
                vanishing_poly_degree: 0,
                mask_poly_degree,
                randomized_chunk_degree_bound: quotient_chunk_degree,
                required_degree: mask_poly_degree,
            });
        }
        Ok(Self {
            quotient_chunk_degree,
            vanishing_poly_degree: 0,
            mask_poly_degree,
            randomized_chunk_degree_bound: quotient_chunk_degree,
        })
    }

    /// Builds a vanishing-factor degree contract: `q_i(X) + v_{H_i}(X) · t_i(X)`.
    ///
    /// The required committed degree is `max(quotient_chunk_degree, vanishing_poly_degree +
    /// mask_poly_degree)`. This must not exceed `randomized_chunk_degree_bound`.
    /// When the product exceeds the original chunk degree, the committed degree class expands.
    /// For plain additive hiding, prefer [`Self::new`].
    pub fn with_vanishing_poly(
        quotient_chunk_degree: usize,
        vanishing_poly_degree: usize,
        mask_poly_degree: usize,
        randomized_chunk_degree_bound: usize,
    ) -> Result<Self, QuotientHiderError> {
        let combined = vanishing_poly_degree.saturating_add(mask_poly_degree);
        let required = quotient_chunk_degree.max(combined);
        if required > randomized_chunk_degree_bound {
            return Err(QuotientHiderError::DegreeContractViolation {
                quotient_chunk_degree,
                vanishing_poly_degree,
                mask_poly_degree,
                randomized_chunk_degree_bound,
                required_degree: required,
            });
        }
        Ok(Self {
            quotient_chunk_degree,
            vanishing_poly_degree,
            mask_poly_degree,
            randomized_chunk_degree_bound,
        })
    }

    /// Degree of `q_i(X)` before masking.
    #[must_use]
    pub const fn quotient_chunk_degree(self) -> usize {
        self.quotient_chunk_degree
    }

    /// Degree of the vanishing polynomial factor `v_{H_i}(X)`; zero for plain additive hiding.
    #[must_use]
    pub const fn vanishing_poly_degree(self) -> usize {
        self.vanishing_poly_degree
    }

    /// Degree of the mask polynomial (`r_i` for plain additive, `t_i` for vanishing-factor).
    #[must_use]
    pub const fn mask_poly_degree(self) -> usize {
        self.mask_poly_degree
    }

    /// Degree bound of the masked quotient chunk as committed.
    ///
    /// Equal to `quotient_chunk_degree` for plain-additive masking.
    /// May exceed `quotient_chunk_degree` for the vanishing-factor form.
    #[must_use]
    pub const fn randomized_chunk_degree_bound(self) -> usize {
        self.randomized_chunk_degree_bound
    }

    /// Alias for [`randomized_chunk_degree_bound`](Self::randomized_chunk_degree_bound).
    #[must_use]
    pub const fn masked_chunk_degree_bound(self) -> usize {
        self.randomized_chunk_degree_bound
    }

    /// Returns `true` when the committed degree equals the original chunk degree.
    ///
    /// Always `true` for plain-additive contracts. May be `false` for vanishing-factor
    /// contracts where `vanishing_poly_degree + mask_poly_degree > quotient_chunk_degree`.
    #[must_use]
    pub const fn preserves_chunk_degree_class(self) -> bool {
        self.randomized_chunk_degree_bound == self.quotient_chunk_degree
    }
}

impl TranscriptBindable for QuotientDegreeContract {
    /// Encodes all four degree fields as u64 LE (32 bytes total):
    /// quotient_chunk_degree, vanishing_poly_degree, mask_poly_degree,
    /// randomized_chunk_degree_bound.
    fn to_transcript_binding(&self) -> TranscriptBinding {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&(self.quotient_chunk_degree() as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.vanishing_poly_degree() as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.mask_poly_degree() as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.randomized_chunk_degree_bound() as u64).to_le_bytes());
        TranscriptBinding::new(DOMAIN_DEGREE_CONTRACT, bytes)
    }
}

impl fmt::Display for QuotientDegreeContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.vanishing_poly_degree == 0 {
            write!(
                f,
                "quotient chunk {} + mask {} → committed bound {}",
                self.quotient_chunk_degree,
                self.mask_poly_degree,
                self.randomized_chunk_degree_bound
            )
        } else {
            write!(
                f,
                "quotient chunk {}, vanishing({}) * mask({}) → committed bound {}",
                self.quotient_chunk_degree,
                self.vanishing_poly_degree,
                self.mask_poly_degree,
                self.randomized_chunk_degree_bound
            )
        }
    }
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
    degree_contract: Option<QuotientDegreeContract>,
}

impl ShroudQuotientHiderSpec {
    /// Builds a statistical quotient-hider object.
    pub fn statistical(
        decomposition_family: QuotientDecompositionFamily,
        query_budget: usize,
        shape: QuotientHiderShape,
        auxiliary_transport: QuotientAuxiliaryTransport,
        degree_contract: Option<QuotientDegreeContract>,
    ) -> Result<Self, QuotientHiderError> {
        Self::new(
            SecurityLevel::Statistical,
            decomposition_family,
            query_budget,
            shape,
            auxiliary_transport,
            degree_contract,
        )
    }

    /// Builds a perfect quotient-hider object.
    pub fn perfect(
        decomposition_family: QuotientDecompositionFamily,
        query_budget: usize,
        shape: QuotientHiderShape,
        auxiliary_transport: QuotientAuxiliaryTransport,
        degree_contract: Option<QuotientDegreeContract>,
    ) -> Result<Self, QuotientHiderError> {
        Self::new(
            SecurityLevel::Perfect,
            decomposition_family,
            query_budget,
            shape,
            auxiliary_transport,
            degree_contract,
        )
    }

    /// Builds a quotient-hider object with an explicit security level.
    pub fn new(
        security_level: SecurityLevel,
        decomposition_family: QuotientDecompositionFamily,
        query_budget: usize,
        shape: QuotientHiderShape,
        auxiliary_transport: QuotientAuxiliaryTransport,
        degree_contract: Option<QuotientDegreeContract>,
    ) -> Result<Self, QuotientHiderError> {
        let payload = QuotientHiderPayload::new(shape, auxiliary_transport);
        let spec = Self {
            security_level,
            decomposition_family,
            query_budget,
            shape,
            payload,
            degree_contract,
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

    /// Degree compatibility contract, if declared.
    ///
    /// Required when [`decomposition_family`][Self::decomposition_family] is
    /// [`QuotientDecompositionFamily::DegreeChunked`].
    #[must_use]
    pub const fn degree_contract(&self) -> Option<QuotientDegreeContract> {
        self.degree_contract
    }

    /// Validates the shape-level, decomposition-level, and degree-contract invariants.
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

        if matches!(
            self.decomposition_family,
            QuotientDecompositionFamily::DegreeChunked
        ) && self.degree_contract.is_none()
        {
            return Err(QuotientHiderError::DegreeChunkedRequiresDegreeContract);
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
    /// A degree-chunked decomposition requires a degree contract.
    ///
    /// Set `degree_contract` to `Some(QuotientDegreeContract::new(quotient_chunk_degree, mask_poly_degree)?)`.
    /// For the vanishing-factor form, use `QuotientDegreeContract::with_vanishing_poly`.
    DegreeChunkedRequiresDegreeContract,
    /// The masking degree exceeds the randomized chunk degree bound.
    ///
    /// For plain additive: `mask_poly_degree ≤ quotient_chunk_degree`.
    /// For vanishing-factor: `max(quotient_chunk_degree, vanishing_poly_degree + mask_poly_degree)
    ///   ≤ randomized_chunk_degree_bound`.
    DegreeContractViolation {
        /// Degree of `q_i(X)` before masking.
        quotient_chunk_degree: usize,
        /// Degree of the vanishing polynomial factor; 0 for plain additive.
        vanishing_poly_degree: usize,
        /// Degree of the mask polynomial.
        mask_poly_degree: usize,
        /// Caller-supplied committed degree bound.
        randomized_chunk_degree_bound: usize,
        /// Actual required committed degree: `max(quotient_chunk_degree, vanishing_poly_degree + mask_poly_degree)`.
        required_degree: usize,
    },
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
            Self::DegreeChunkedRequiresDegreeContract => write!(
                f,
                "degree-chunked quotient decomposition requires a degree contract; \
                 supply QuotientDegreeContract::new(chunk_degree, randomizer_degree)"
            ),
            Self::DegreeContractViolation {
                quotient_chunk_degree,
                vanishing_poly_degree,
                mask_poly_degree,
                randomized_chunk_degree_bound,
                required_degree,
            } => {
                write!(
                    f,
                    "masking requires committed degree {required_degree} \
                     (max of quotient {quotient_chunk_degree} and \
                     vanishing({vanishing_poly_degree}) * mask({mask_poly_degree})) \
                     but randomized_chunk_degree_bound is {randomized_chunk_degree_bound}; \
                     for plain q_i + r_i: mask_poly_degree must not exceed quotient_chunk_degree; \
                     for q_i + v_H_i*t_i: supply a randomized_chunk_degree_bound large enough \
                     to hold max(deg(q_i), deg(v_H_i) + deg(t_i))"
                )
            }
        }
    }
}

impl std::error::Error for QuotientHiderError {}

#[cfg(test)]
mod tests {
    use super::{
        QuotientAuxiliaryTransport, QuotientDecompositionFamily, QuotientDegreeContract,
        QuotientHiderError, QuotientHiderShape, ShroudQuotientHiderSpec,
    };
    use shroud_core::{SecurityLevel, TranscriptBindable};

    fn chunked_shape() -> QuotientHiderShape {
        QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid shape")
    }

    fn chunked_contract() -> QuotientDegreeContract {
        QuotientDegreeContract::new(31, 31).expect("valid contract")
    }

    #[test]
    fn statistical_quotient_hider_tracks_public_and_hidden_surface() {
        let shape = chunked_shape();
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(chunked_contract()),
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
            None,
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
                None,
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
                None,
            ),
            Err(QuotientHiderError::OpeningPointsExceedQueryBudget {
                query_budget: 4,
                opening_points: 5,
            })
        );
    }

    #[test]
    fn degree_chunked_requires_degree_contract() {
        let shape = chunked_shape();
        assert_eq!(
            ShroudQuotientHiderSpec::statistical(
                QuotientDecompositionFamily::DegreeChunked,
                8,
                shape,
                QuotientAuxiliaryTransport::InBandWithOpeningProof,
                None,
            ),
            Err(QuotientHiderError::DegreeChunkedRequiresDegreeContract)
        );
    }

    #[test]
    fn degree_contract_rejects_oversized_mask() {
        assert_eq!(
            QuotientDegreeContract::new(31, 32),
            Err(QuotientHiderError::DegreeContractViolation {
                quotient_chunk_degree: 31,
                vanishing_poly_degree: 0,
                mask_poly_degree: 32,
                randomized_chunk_degree_bound: 31,
                required_degree: 32,
            })
        );
    }

    #[test]
    fn degree_contract_with_vanishing_poly_validates_compatible_degrees() {
        // vanishing(7) + mask(8) = 15 == quotient_chunk_degree, so bound of 15 is sufficient.
        let contract =
            QuotientDegreeContract::with_vanishing_poly(15, 7, 8, 15).expect("valid contract");
        assert_eq!(contract.quotient_chunk_degree(), 15);
        assert_eq!(contract.vanishing_poly_degree(), 7);
        assert_eq!(contract.mask_poly_degree(), 8);
        assert_eq!(contract.randomized_chunk_degree_bound(), 15);
        assert!(contract.preserves_chunk_degree_class());
    }

    #[test]
    fn degree_contract_with_vanishing_poly_expands_committed_degree() {
        // vanishing(8) + mask(10) = 18 > quotient_chunk_degree(15); bound of 18 is required.
        let contract =
            QuotientDegreeContract::with_vanishing_poly(15, 8, 10, 18).expect("valid contract");
        assert_eq!(contract.quotient_chunk_degree(), 15);
        assert_eq!(contract.randomized_chunk_degree_bound(), 18);
        assert!(!contract.preserves_chunk_degree_class());
    }

    #[test]
    fn degree_contract_with_vanishing_poly_rejects_insufficient_bound() {
        // vanishing(10) + mask(6) = 16 > quotient(15), so bound of 15 is too small.
        assert_eq!(
            QuotientDegreeContract::with_vanishing_poly(15, 10, 6, 15),
            Err(QuotientHiderError::DegreeContractViolation {
                quotient_chunk_degree: 15,
                vanishing_poly_degree: 10,
                mask_poly_degree: 6,
                randomized_chunk_degree_bound: 15,
                required_degree: 16,
            })
        );
    }

    #[test]
    fn degree_contract_validates_compatible_degrees() {
        let contract = QuotientDegreeContract::new(31, 31).expect("valid contract");
        assert_eq!(contract.quotient_chunk_degree(), 31);
        assert_eq!(contract.mask_poly_degree(), 31);
        assert_eq!(contract.randomized_chunk_degree_bound(), 31);
        assert!(contract.preserves_chunk_degree_class());
    }

    #[test]
    fn degree_contract_equal_degrees_are_compatible() {
        let contract = QuotientDegreeContract::new(15, 15).expect("valid contract");
        assert_eq!(contract.masked_chunk_degree_bound(), 15);
        assert!(contract.preserves_chunk_degree_class());
    }

    #[test]
    fn degree_contract_zero_randomizer_is_valid() {
        let contract = QuotientDegreeContract::new(8, 0).expect("valid contract");
        assert_eq!(contract.masked_chunk_degree_bound(), 8);
    }

    #[test]
    fn monolithic_allows_optional_degree_contract() {
        let shape = QuotientHiderShape::new(1, 2, 2, 1, 1).expect("valid shape");
        let contract = QuotientDegreeContract::new(63, 63).expect("valid contract");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::Monolithic,
            4,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(contract),
        )
        .expect("valid spec");

        assert_eq!(spec.degree_contract().unwrap().quotient_chunk_degree(), 63);
    }

    #[test]
    fn degree_chunked_exposes_contract_via_accessor() {
        let shape = chunked_shape();
        let contract = chunked_contract();
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(contract),
        )
        .expect("valid spec");

        let stored = spec.degree_contract().expect("degree contract present");
        assert_eq!(stored.quotient_chunk_degree(), 31);
        assert_eq!(stored.mask_poly_degree(), 31);
        assert_eq!(stored.randomized_chunk_degree_bound(), 31);
    }

    #[test]
    fn segmented_decomposition_accepts_no_contract() {
        let shape = QuotientHiderShape::new(4, 3, 2, 2, 2).expect("valid shape");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::Segmented,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            None,
        )
        .expect("valid spec");

        assert!(spec.degree_contract().is_none());
    }

    #[test]
    fn degree_contract_binding_encodes_all_four_fields() {
        let contract =
            QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid contract");
        let binding = contract.to_transcript_binding();
        assert_eq!(binding.domain_label(), shroud_core::DOMAIN_DEGREE_CONTRACT);
        let mut expected = Vec::new();
        expected.extend_from_slice(&7u64.to_le_bytes()); // quotient_chunk_degree
        expected.extend_from_slice(&8u64.to_le_bytes()); // vanishing_poly_degree
        expected.extend_from_slice(&7u64.to_le_bytes()); // mask_poly_degree
        expected.extend_from_slice(&15u64.to_le_bytes()); // randomized_chunk_degree_bound
        assert_eq!(binding.canonical_bytes(), &expected);
    }

    #[test]
    fn different_degree_contracts_produce_different_bindings() {
        let c1 = QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid");
        let c2 = QuotientDegreeContract::with_vanishing_poly(15, 16, 15, 31).expect("valid");
        assert_ne!(c1.to_transcript_binding(), c2.to_transcript_binding());
    }
}
