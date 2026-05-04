#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The first concrete SHROUD protocol object: batch-opening hiding.
//!
//! In this crate, `SecurityLevel::Perfect` means the instantiation targets a
//! perfect hiding / honest-verifier zero-knowledge claim at the protocol level.
//! That does not imply a native extension-field PCS. The
//! `EncodedOracleBundle` realization remains valid as a perfect-variant target
//! as long as the backend proves that the encoding is exact and preserves the
//! intended hiding claim.

use core::fmt;

use shroud_core::{
    BasisDescriptor, DegreeBudget, DegreeBudgetError, SecurityLevel, TranscriptPlan,
    TranscriptPlanError,
};

/// Statement shape for a reduced batch-opening relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchOpeningShape {
    committed_polynomials: usize,
    opening_points: usize,
    extension_degree: usize,
}

impl BatchOpeningShape {
    /// Creates a validated batch-opening shape.
    pub fn new(
        committed_polynomials: usize,
        opening_points: usize,
        extension_degree: usize,
    ) -> Result<Self, BatchOpeningSpecError> {
        if committed_polynomials == 0 {
            return Err(BatchOpeningSpecError::ZeroCommittedPolynomials);
        }
        if opening_points == 0 {
            return Err(BatchOpeningSpecError::ZeroOpeningPoints);
        }
        if extension_degree == 0 {
            return Err(BatchOpeningSpecError::ZeroExtensionDegree);
        }

        Ok(Self {
            committed_polynomials,
            opening_points,
            extension_degree,
        })
    }

    /// Number of committed polynomials participating in the reduced relation.
    ///
    /// This records the relation-level batching width even though the current
    /// randomizer payload math depends only on the opening points and extension
    /// degree. Backends may use it later when wiring the reduced statement into
    /// concrete batching logic.
    #[must_use]
    pub const fn committed_polynomials(self) -> usize {
        self.committed_polynomials
    }

    /// Number of opened points in the batched claim.
    #[must_use]
    pub const fn opening_points(self) -> usize {
        self.opening_points
    }

    /// Extension degree of the opening field over the base field.
    #[must_use]
    pub const fn extension_degree(self) -> usize {
        self.extension_degree
    }

    /// Number of public randomizer evaluations exposed by the claim surface.
    ///
    /// Today this is one public evaluation per opening point.
    #[must_use]
    pub const fn public_randomizer_evaluations(self) -> usize {
        self.opening_points
    }
}

/// Architectural boundary used to realize the batch-opening randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitmentBoundary {
    /// The randomizer is carried through the main PCS hook path.
    SharedPcsHook,
    /// The randomizer is modeled as its own auxiliary commitment object.
    DedicatedAuxiliaryPath,
}

/// Statistical randomizer model for the current Plonky3-style surrogate path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatisticalRandomizerSpec {
    coordinate_polynomials: usize,
}

impl StatisticalRandomizerSpec {
    /// Builds the statistical randomizer model from the extension degree.
    #[must_use]
    pub const fn from_shape(shape: BatchOpeningShape) -> Self {
        Self {
            coordinate_polynomials: shape.extension_degree(),
        }
    }

    /// Number of base-field coordinate polynomials used in the surrogate randomizer.
    #[must_use]
    pub const fn coordinate_polynomials(self) -> usize {
        self.coordinate_polynomials
    }

    /// Returns the opening payload shape for the statistical randomizer.
    #[must_use]
    pub const fn opening_payload(
        self,
        shape: BatchOpeningShape,
    ) -> StatisticalRandomizerOpeningPayload {
        StatisticalRandomizerOpeningPayload {
            public_extension_evaluations: shape.opening_points(),
            hidden_base_field_coordinate_evaluations: shape
                .opening_points()
                .saturating_mul(self.coordinate_polynomials),
            proof_slot_layout: ProofSlotLayout::ReuseCurrentRandomSlot,
            hidden_opening_transport: HiddenOpeningTransport::InBandWithMainOpeningProof,
        }
    }
}

/// Realization strategy for the perfect randomizer commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerfectRandomizerRealization {
    /// A bundled coordinate encoding interpreted as one exact extension-field object.
    ///
    /// This is not “native extension support.” It is the SHROUD v1 path where a
    /// backend reuses its existing oracle path while still treating the encoded
    /// bundle as one exact randomizer object. The `basis` descriptor makes the
    /// encoding self-describing so an auditor can verify the backend's
    /// `reconstitute_from_base` convention without relying on implicit field assumptions.
    EncodedOracleBundle {
        /// Self-describing basis for flattening and reconstructing the randomizer.
        basis: BasisDescriptor,
    },
    /// A native extension-field PCS or equivalent extension-aware backend.
    NativeExtensionPcs,
}

/// How the batch-opening randomizer is represented in the proof surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofSlotLayout {
    /// Reuse the current optional `random: Option<...>` commitment/proof-slot shape.
    ReuseCurrentRandomSlot,
    /// Give the perfect randomizer its own dedicated proof slot.
    DedicatedPerfectRandomizerSlot,
}

/// How hidden randomizer openings are transported inside the proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiddenOpeningTransport {
    /// Hidden openings stay in-band with the main batch-opening proof object.
    ///
    /// This is the batch-opening-local analogue of
    /// `shroud_opening_projection::AuxiliaryOpeningTransport::InBandWithMainProof`.
    InBandWithMainOpeningProof,
    /// Hidden openings are carried by a separate auxiliary proof object.
    ///
    /// This is the batch-opening-local analogue of
    /// `shroud_opening_projection::AuxiliaryOpeningTransport::SeparateAuxiliaryProof`.
    SeparateAuxiliaryProof,
}

/// Opening payload for the statistical randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatisticalRandomizerOpeningPayload {
    public_extension_evaluations: usize,
    hidden_base_field_coordinate_evaluations: usize,
    proof_slot_layout: ProofSlotLayout,
    hidden_opening_transport: HiddenOpeningTransport,
}

impl StatisticalRandomizerOpeningPayload {
    /// Number of public extension-field evaluations exposed by the claim surface.
    #[must_use]
    pub const fn public_extension_evaluations(self) -> usize {
        self.public_extension_evaluations
    }

    /// Number of hidden base-field coordinate evaluations carried in the proof.
    #[must_use]
    pub const fn hidden_base_field_coordinate_evaluations(self) -> usize {
        self.hidden_base_field_coordinate_evaluations
    }

    /// How the statistical randomizer fits into the proof surface.
    #[must_use]
    pub const fn proof_slot_layout(self) -> ProofSlotLayout {
        self.proof_slot_layout
    }

    /// How the hidden coordinate openings are transported.
    #[must_use]
    pub const fn hidden_opening_transport(self) -> HiddenOpeningTransport {
        self.hidden_opening_transport
    }
}

/// Hidden opening payload for the perfect randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerfectHiddenOpeningPayload {
    /// The perfect randomizer is represented by an exact coordinate encoding.
    EncodedCoordinates {
        /// Number of hidden base-field coordinate evaluations carried in the proof.
        base_field_coordinate_evaluations: usize,
        /// How the hidden coordinate openings move through the proof.
        transport: HiddenOpeningTransport,
    },
    /// The backend carries the hidden witness internally without exposing extra randomizer coordinates.
    BackendProofOnly {
        /// How the hidden witness moves through the proof.
        transport: HiddenOpeningTransport,
    },
}

/// Opening payload for the perfect randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfectRandomizerOpeningPayload {
    public_extension_evaluations: usize,
    hidden_payload: PerfectHiddenOpeningPayload,
    proof_slot_layout: ProofSlotLayout,
}

impl PerfectRandomizerOpeningPayload {
    /// Number of public extension-field evaluations exposed by the claim surface.
    #[must_use]
    pub const fn public_extension_evaluations(self) -> usize {
        self.public_extension_evaluations
    }

    /// Hidden opening payload carried in the proof.
    #[must_use]
    pub const fn hidden_payload(self) -> PerfectHiddenOpeningPayload {
        self.hidden_payload
    }

    /// How the perfect randomizer fits into the proof surface.
    #[must_use]
    pub const fn proof_slot_layout(self) -> ProofSlotLayout {
        self.proof_slot_layout
    }
}

/// Opening payload for a batch-opening randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomizerOpeningPayload {
    /// Opening payload for the statistical surrogate path.
    Statistical(StatisticalRandomizerOpeningPayload),
    /// Opening payload for the perfect variant.
    Perfect(PerfectRandomizerOpeningPayload),
}

/// Prover-side result of committing to a perfect batch-opening randomizer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPerfectRandomizer<Commitment, ProverState> {
    commitment: Commitment,
    prover_state: ProverState,
}

impl<Commitment, ProverState> PreparedPerfectRandomizer<Commitment, ProverState> {
    /// Builds a prepared perfect randomizer object.
    #[must_use]
    pub const fn new(commitment: Commitment, prover_state: ProverState) -> Self {
        Self {
            commitment,
            prover_state,
        }
    }

    /// Returns the public commitment observed by the transcript.
    #[must_use]
    pub const fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    /// Returns the prover-side state required to open the perfect randomizer later.
    #[must_use]
    pub const fn prover_state(&self) -> &ProverState {
        &self.prover_state
    }
}

/// Opening object for a perfect batch-opening randomizer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfectRandomizerOpening<PublicEvaluation, HiddenOpening> {
    public_evaluations: Vec<PublicEvaluation>,
    hidden_openings: HiddenOpening,
}

impl<PublicEvaluation, HiddenOpening> PerfectRandomizerOpening<PublicEvaluation, HiddenOpening> {
    /// Builds a perfect-randomizer opening object.
    #[must_use]
    pub fn new(public_evaluations: Vec<PublicEvaluation>, hidden_openings: HiddenOpening) -> Self {
        Self {
            public_evaluations,
            hidden_openings,
        }
    }

    /// Public extension-field evaluations revealed by the claim surface.
    #[must_use]
    pub fn public_evaluations(&self) -> &[PublicEvaluation] {
        &self.public_evaluations
    }

    /// Hidden opening material carried by the proof.
    #[must_use]
    pub const fn hidden_openings(&self) -> &HiddenOpening {
        &self.hidden_openings
    }
}

/// Reconstructed perfect-randomizer view used by the verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfectRandomizerReconstruction {
    commitment: PerfectRandomizerCommitment,
    opening_payload: PerfectRandomizerOpeningPayload,
}

impl PerfectRandomizerReconstruction {
    /// Builds a reconstructed verifier view of the perfect randomizer.
    #[must_use]
    pub const fn new(
        commitment: PerfectRandomizerCommitment,
        opening_payload: PerfectRandomizerOpeningPayload,
    ) -> Self {
        Self {
            commitment,
            opening_payload,
        }
    }

    /// Returns the commitment model used by the perfect randomizer.
    #[must_use]
    pub const fn commitment(self) -> PerfectRandomizerCommitment {
        self.commitment
    }

    /// Returns the opening payload reconstructed by the verifier.
    #[must_use]
    pub const fn opening_payload(self) -> PerfectRandomizerOpeningPayload {
        self.opening_payload
    }
}

/// Transcript interface for observing a perfect-randomizer commitment.
pub trait PerfectRandomizerTranscript {
    /// Error returned when the transcript cannot observe the commitment.
    type Error;

    /// Observe the perfect-randomizer commitment at the current transcript stage.
    fn observe_perfect_randomizer_commitment<Commitment>(
        &mut self,
        commitment: &Commitment,
    ) -> Result<(), Self::Error>;
}

/// Backend interface for the perfect batch-opening randomizer.
pub trait PerfectRandomizerBackend {
    /// Public commitment type emitted by the backend.
    type Commitment;
    /// Prover-side state carried between commitment and opening.
    type ProverState;
    /// Public evaluation type revealed by the claim surface.
    type PublicEvaluation;
    /// Hidden opening witness carried in the proof.
    type HiddenOpening;
    /// Backend-specific error type.
    type Error;

    /// Commitment model realized by this backend.
    fn commitment_model(&self) -> PerfectRandomizerCommitment;

    /// Commit to the perfect randomizer and retain any prover-side opening state.
    fn commit(
        &self,
        spec: &ShroudBatchOpeningSpec,
    ) -> Result<PreparedPerfectRandomizer<Self::Commitment, Self::ProverState>, Self::Error>;

    /// Observe the perfect-randomizer commitment in the transcript.
    fn observe<T: PerfectRandomizerTranscript>(
        &self,
        transcript: &mut T,
        commitment: &Self::Commitment,
    ) -> Result<(), T::Error> {
        transcript.observe_perfect_randomizer_commitment(commitment)
    }

    /// Open the perfect randomizer according to the claim surface described by the spec.
    fn open(
        &self,
        spec: &ShroudBatchOpeningSpec,
        prover_state: &Self::ProverState,
    ) -> Result<PerfectRandomizerOpening<Self::PublicEvaluation, Self::HiddenOpening>, Self::Error>;

    /// Reconstruct the verifier-facing perfect-randomizer view from the commitment and opening.
    fn reconstruct(
        &self,
        spec: &ShroudBatchOpeningSpec,
        commitment: &Self::Commitment,
        opening: &PerfectRandomizerOpening<Self::PublicEvaluation, Self::HiddenOpening>,
    ) -> Result<PerfectRandomizerReconstruction, Self::Error>;
}

/// Outer proof-system view of a perfect-randomizer commitment and its opening payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerfectRandomizerAdapterSurface<CommitmentSlot> {
    commitment_slot: CommitmentSlot,
    proof_slot_layout: ProofSlotLayout,
    opening_payload: PerfectRandomizerOpeningPayload,
}

impl<CommitmentSlot> PerfectRandomizerAdapterSurface<CommitmentSlot> {
    /// Builds an adapter surface for a perfect-randomizer commitment.
    #[must_use]
    pub const fn new(
        commitment_slot: CommitmentSlot,
        proof_slot_layout: ProofSlotLayout,
        opening_payload: PerfectRandomizerOpeningPayload,
    ) -> Self {
        Self {
            commitment_slot,
            proof_slot_layout,
            opening_payload,
        }
    }

    /// Returns the outer proof slot that should carry the perfect-randomizer commitment.
    #[must_use]
    pub const fn commitment_slot(&self) -> &CommitmentSlot {
        &self.commitment_slot
    }

    /// Returns the proof-slot layout decision for the perfect randomizer.
    #[must_use]
    pub const fn proof_slot_layout(&self) -> ProofSlotLayout {
        self.proof_slot_layout
    }

    /// Returns the opening payload expected by the adapter surface.
    #[must_use]
    pub const fn opening_payload(&self) -> PerfectRandomizerOpeningPayload {
        self.opening_payload
    }
}

/// Adapter surface between SHROUD's perfect-randomizer object and an outer proof layout.
pub trait PerfectRandomizerAdapter {
    /// Identifier used by the outer proof system for the commitment slot.
    type CommitmentSlot;
    /// Adapter-specific error type.
    type Error;

    /// Returns the outer proof layout required by the perfect-randomizer object.
    fn surface(
        &self,
        spec: &ShroudBatchOpeningSpec,
    ) -> Result<PerfectRandomizerAdapterSurface<Self::CommitmentSlot>, Self::Error>;

    /// Reconstructs the verifier-facing perfect-randomizer view from the adapter surface.
    fn reconstruct(
        &self,
        spec: &ShroudBatchOpeningSpec,
        surface: &PerfectRandomizerAdapterSurface<Self::CommitmentSlot>,
    ) -> Result<PerfectRandomizerReconstruction, Self::Error>;
}

/// Protocol boundary for the perfect batch-opening randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfectRandomizerCommitment {
    realization: PerfectRandomizerRealization,
    proof_slot_layout: ProofSlotLayout,
}

impl PerfectRandomizerCommitment {
    /// Preferred SHROUD v1 realization: exact encoding into the existing oracle backend.
    ///
    /// The `basis` descriptor makes the encoding self-describing. Use
    /// `BasisDescriptor::plonky3_binomial(extension_degree)` for the standard
    /// Plonky3 `BinomialExtensionField` convention.
    ///
    /// This remains a perfect-variant commitment model only if the backend can
    /// justify that the encoded coordinates represent the same exact
    /// extension-field randomizer that the protocol reasons about.
    #[must_use]
    pub const fn encoded_oracle_bundle(basis: BasisDescriptor) -> Self {
        Self {
            realization: PerfectRandomizerRealization::EncodedOracleBundle { basis },
            proof_slot_layout: ProofSlotLayout::ReuseCurrentRandomSlot,
        }
    }

    /// Long-term realization: native extension-field commitment support.
    #[must_use]
    pub const fn native_extension_pcs() -> Self {
        Self {
            realization: PerfectRandomizerRealization::NativeExtensionPcs,
            proof_slot_layout: ProofSlotLayout::DedicatedPerfectRandomizerSlot,
        }
    }

    /// Returns the chosen perfect-randomizer realization.
    #[must_use]
    pub const fn realization(self) -> PerfectRandomizerRealization {
        self.realization
    }

    /// Returns the proof-slot decision for this perfect randomizer.
    #[must_use]
    pub const fn proof_slot_layout(self) -> ProofSlotLayout {
        self.proof_slot_layout
    }

    /// Returns the exact opening payload shape for this perfect randomizer.
    #[must_use]
    pub const fn opening_payload(
        self,
        shape: BatchOpeningShape,
    ) -> PerfectRandomizerOpeningPayload {
        match self.realization {
            PerfectRandomizerRealization::EncodedOracleBundle { basis } => {
                PerfectRandomizerOpeningPayload {
                    public_extension_evaluations: shape.opening_points(),
                    hidden_payload: PerfectHiddenOpeningPayload::EncodedCoordinates {
                        base_field_coordinate_evaluations: shape
                            .opening_points()
                            .saturating_mul(basis.extension_degree),
                        transport: HiddenOpeningTransport::InBandWithMainOpeningProof,
                    },
                    proof_slot_layout: self.proof_slot_layout,
                }
            }
            PerfectRandomizerRealization::NativeExtensionPcs => PerfectRandomizerOpeningPayload {
                public_extension_evaluations: shape.opening_points(),
                hidden_payload: PerfectHiddenOpeningPayload::BackendProofOnly {
                    transport: HiddenOpeningTransport::SeparateAuxiliaryProof,
                },
                proof_slot_layout: self.proof_slot_layout,
            },
        }
    }
}

/// Randomizer model used by a `ShroudBatchOpeningSpec`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomizerSpec {
    /// Statistical base-field coordinate randomizer.
    Statistical(StatisticalRandomizerSpec),
    /// Perfect randomizer with an explicit commitment boundary.
    Perfect(PerfectRandomizerCommitment),
}

/// Concrete spec for the first SHROUD protocol object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShroudBatchOpeningSpec {
    security_level: SecurityLevel,
    shape: BatchOpeningShape,
    degree_budget: DegreeBudget,
    transcript_plan: TranscriptPlan,
    commitment_boundary: CommitmentBoundary,
    randomizer: RandomizerSpec,
}

impl ShroudBatchOpeningSpec {
    /// Builds the current statistical batch-opening object.
    pub fn statistical(
        shape: BatchOpeningShape,
        relation_degree: usize,
    ) -> Result<Self, BatchOpeningSpecError> {
        Self::statistical_with_degree_budget(
            shape,
            DegreeBudget::new(relation_degree, relation_degree.saturating_add(1))?,
        )
    }

    /// Builds the current statistical batch-opening object with an explicit degree budget.
    pub fn statistical_with_degree_budget(
        shape: BatchOpeningShape,
        degree_budget: DegreeBudget,
    ) -> Result<Self, BatchOpeningSpecError> {
        Self::new(
            SecurityLevel::Statistical,
            shape,
            degree_budget,
            TranscriptPlan::standard_batch_opening(),
            CommitmentBoundary::SharedPcsHook,
            RandomizerSpec::Statistical(StatisticalRandomizerSpec::from_shape(shape)),
        )
    }

    /// Builds the perfect batch-opening object.
    pub fn perfect(
        shape: BatchOpeningShape,
        relation_degree: usize,
        commitment: PerfectRandomizerCommitment,
    ) -> Result<Self, BatchOpeningSpecError> {
        Self::perfect_with_degree_budget(
            shape,
            DegreeBudget::new(relation_degree, relation_degree.saturating_add(1))?,
            commitment,
        )
    }

    /// Builds the perfect batch-opening object with an explicit degree budget.
    pub fn perfect_with_degree_budget(
        shape: BatchOpeningShape,
        degree_budget: DegreeBudget,
        commitment: PerfectRandomizerCommitment,
    ) -> Result<Self, BatchOpeningSpecError> {
        Self::new(
            SecurityLevel::Perfect,
            shape,
            degree_budget,
            TranscriptPlan::standard_batch_opening(),
            CommitmentBoundary::DedicatedAuxiliaryPath,
            RandomizerSpec::Perfect(commitment),
        )
    }

    /// Returns the SHROUD security level for this object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Returns the statement shape.
    #[must_use]
    pub const fn shape(&self) -> BatchOpeningShape {
        self.shape
    }

    /// Returns the degree budget.
    #[must_use]
    pub const fn degree_budget(&self) -> DegreeBudget {
        self.degree_budget
    }

    /// Returns the transcript plan.
    #[must_use]
    pub fn transcript_plan(&self) -> &TranscriptPlan {
        &self.transcript_plan
    }

    /// Returns the commitment boundary used by the randomizer.
    #[must_use]
    pub const fn commitment_boundary(&self) -> CommitmentBoundary {
        self.commitment_boundary
    }

    /// Returns the randomizer model.
    #[must_use]
    pub const fn randomizer(&self) -> RandomizerSpec {
        self.randomizer
    }

    fn new(
        security_level: SecurityLevel,
        shape: BatchOpeningShape,
        degree_budget: DegreeBudget,
        transcript_plan: TranscriptPlan,
        commitment_boundary: CommitmentBoundary,
        randomizer: RandomizerSpec,
    ) -> Result<Self, BatchOpeningSpecError> {
        let spec = Self {
            security_level,
            shape,
            degree_budget,
            transcript_plan,
            commitment_boundary,
            randomizer,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Returns the perfect randomizer commitment model when this is a perfect variant.
    #[must_use]
    pub const fn perfect_randomizer_commitment(&self) -> Option<PerfectRandomizerCommitment> {
        match self.randomizer {
            RandomizerSpec::Perfect(model) => Some(model),
            RandomizerSpec::Statistical(_) => None,
        }
    }

    /// Number of public randomizer evaluations exposed by the claim surface.
    #[must_use]
    pub const fn public_randomizer_evaluations(&self) -> usize {
        self.shape.public_randomizer_evaluations()
    }

    /// Exact opening payload carried by the randomizer in this batch-opening object.
    #[must_use]
    pub const fn randomizer_opening_payload(&self) -> RandomizerOpeningPayload {
        match self.randomizer {
            RandomizerSpec::Statistical(model) => {
                RandomizerOpeningPayload::Statistical(model.opening_payload(self.shape))
            }
            RandomizerSpec::Perfect(model) => {
                RandomizerOpeningPayload::Perfect(model.opening_payload(self.shape))
            }
        }
    }

    /// Validates the invariants of the batch-opening object.
    pub fn validate(&self) -> Result<(), BatchOpeningSpecError> {
        self.transcript_plan.validate()?;

        if self.security_level == SecurityLevel::Perfect
            && self.commitment_boundary != CommitmentBoundary::DedicatedAuxiliaryPath
        {
            return Err(BatchOpeningSpecError::PerfectVariantNeedsDedicatedAuxiliaryBoundary);
        }

        if let RandomizerSpec::Perfect(commitment) = self.randomizer
            && let PerfectRandomizerRealization::EncodedOracleBundle { basis } =
                commitment.realization()
        {
            let shape_degree = self.shape.extension_degree();
            if basis.extension_degree != shape_degree {
                return Err(BatchOpeningSpecError::InconsistentEncodedBundleDegree {
                    shape_degree,
                    basis_degree: basis.extension_degree,
                });
            }
        }

        Ok(())
    }
}

/// Error raised when a batch-opening spec violates a SHROUD invariant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchOpeningSpecError {
    /// A batch-opening relation must include at least one committed polynomial.
    ZeroCommittedPolynomials,
    /// A batch-opening relation must open at least one point.
    ZeroOpeningPoints,
    /// The extension field degree must be positive.
    ZeroExtensionDegree,
    /// The randomizer degree breaks the masked-relation degree class.
    DegreeBudget(DegreeBudgetError),
    /// The transcript order breaks a SHROUD invariant.
    Transcript(TranscriptPlanError),
    /// The perfect variant must use a dedicated auxiliary commitment boundary.
    PerfectVariantNeedsDedicatedAuxiliaryBoundary,
    /// For `EncodedOracleBundle`, the basis extension degree must match the shape.
    InconsistentEncodedBundleDegree {
        /// Extension degree declared in `BatchOpeningShape`.
        shape_degree: usize,
        /// Extension degree declared in `BasisDescriptor`.
        basis_degree: usize,
    },
}

impl fmt::Display for BatchOpeningSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCommittedPolynomials => {
                write!(
                    f,
                    "batch-opening shape must contain at least one committed polynomial"
                )
            }
            Self::ZeroOpeningPoints => {
                write!(
                    f,
                    "batch-opening shape must contain at least one opening point"
                )
            }
            Self::ZeroExtensionDegree => {
                write!(
                    f,
                    "batch-opening shape must use a non-zero extension degree"
                )
            }
            Self::DegreeBudget(err) => err.fmt(f),
            Self::Transcript(err) => err.fmt(f),
            Self::PerfectVariantNeedsDedicatedAuxiliaryBoundary => write!(
                f,
                "perfect batch-opening variants must use a dedicated auxiliary commitment boundary"
            ),
            Self::InconsistentEncodedBundleDegree {
                shape_degree,
                basis_degree,
            } => write!(
                f,
                "encoded-bundle basis extension degree ({basis_degree}) does not match \
                 batch-opening shape extension degree ({shape_degree}); \
                 the basis must describe the same field as the opening domain"
            ),
        }
    }
}

impl std::error::Error for BatchOpeningSpecError {}

impl From<DegreeBudgetError> for BatchOpeningSpecError {
    fn from(value: DegreeBudgetError) -> Self {
        Self::DegreeBudget(value)
    }
}

impl From<TranscriptPlanError> for BatchOpeningSpecError {
    fn from(value: TranscriptPlanError) -> Self {
        Self::Transcript(value)
    }
}

#[cfg(test)]
mod proptests {
    use super::{
        BatchOpeningShape, PerfectHiddenOpeningPayload, PerfectRandomizerCommitment,
        RandomizerOpeningPayload, ShroudBatchOpeningSpec,
    };
    use proptest::prelude::*;
    use shroud_core::BasisDescriptor;

    proptest! {
        #[test]
        fn statistical_hidden_evals_equal_points_times_extension_degree(
            committed in 1usize..64,
            points in 1usize..16,
            ext in 1usize..8,
            relation in 1usize..128,
        ) {
            let shape = BatchOpeningShape::new(committed, points, ext).expect("valid shape");
            let spec = ShroudBatchOpeningSpec::statistical(shape, relation).expect("valid spec");
            match spec.randomizer_opening_payload() {
                RandomizerOpeningPayload::Statistical(payload) => {
                    prop_assert_eq!(
                        payload.hidden_base_field_coordinate_evaluations(),
                        points * ext
                    );
                    prop_assert_eq!(payload.public_extension_evaluations(), points);
                }
                RandomizerOpeningPayload::Perfect(_) => {
                    prop_assert!(false, "expected statistical payload")
                }
            }
        }

        #[test]
        fn encoded_bundle_coordinate_evals_equal_points_times_extension_degree(
            committed in 1usize..64,
            points in 1usize..16,
            ext in 1usize..8,
            relation in 1usize..128,
        ) {
            let shape = BatchOpeningShape::new(committed, points, ext).expect("valid shape");
            let commitment = PerfectRandomizerCommitment::encoded_oracle_bundle(
                BasisDescriptor::plonky3_binomial(ext),
            );
            let spec = ShroudBatchOpeningSpec::perfect(shape, relation, commitment)
                .expect("valid spec");
            match spec.randomizer_opening_payload() {
                RandomizerOpeningPayload::Perfect(payload) => {
                    prop_assert_eq!(payload.public_extension_evaluations(), points);
                    match payload.hidden_payload() {
                        PerfectHiddenOpeningPayload::EncodedCoordinates {
                            base_field_coordinate_evaluations,
                            ..
                        } => {
                            prop_assert_eq!(base_field_coordinate_evaluations, points * ext);
                        }
                        PerfectHiddenOpeningPayload::BackendProofOnly { .. } => {
                            prop_assert!(false, "expected encoded coordinates")
                        }
                    }
                }
                RandomizerOpeningPayload::Statistical(_) => {
                    prop_assert!(false, "expected perfect payload")
                }
            }
        }

        #[test]
        fn inconsistent_encoded_bundle_degree_always_rejected(
            committed in 1usize..64,
            points in 1usize..16,
            shape_ext in 1usize..8,
            basis_ext in 1usize..8,
            relation in 1usize..128,
        ) {
            prop_assume!(shape_ext != basis_ext);
            let shape = BatchOpeningShape::new(committed, points, shape_ext).expect("valid shape");
            let commitment = PerfectRandomizerCommitment::encoded_oracle_bundle(
                BasisDescriptor::plonky3_binomial(basis_ext),
            );
            prop_assert!(
                ShroudBatchOpeningSpec::perfect(shape, relation, commitment).is_err()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BatchOpeningShape, BatchOpeningSpecError, CommitmentBoundary, HiddenOpeningTransport,
        PerfectHiddenOpeningPayload, PerfectRandomizerCommitment, PerfectRandomizerRealization,
        ProofSlotLayout, RandomizerOpeningPayload, RandomizerSpec, ShroudBatchOpeningSpec,
    };
    use shroud_core::{BasisDescriptor, DegreeBudget, SecurityLevel};

    #[test]
    fn statistical_spec_tracks_coordinate_polynomials_from_extension_degree() {
        let shape = BatchOpeningShape::new(6, 2, 4).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 31).expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Statistical);
        assert_eq!(
            spec.commitment_boundary(),
            CommitmentBoundary::SharedPcsHook
        );
        assert_eq!(spec.public_randomizer_evaluations(), 2);

        match spec.randomizer() {
            RandomizerSpec::Statistical(model) => assert_eq!(model.coordinate_polynomials(), 4),
            RandomizerSpec::Perfect(_) => panic!("expected statistical randomizer"),
        }

        match spec.randomizer_opening_payload() {
            RandomizerOpeningPayload::Statistical(payload) => {
                assert_eq!(payload.public_extension_evaluations(), 2);
                assert_eq!(payload.hidden_base_field_coordinate_evaluations(), 8);
                assert_eq!(
                    payload.proof_slot_layout(),
                    ProofSlotLayout::ReuseCurrentRandomSlot
                );
                assert_eq!(
                    payload.hidden_opening_transport(),
                    HiddenOpeningTransport::InBandWithMainOpeningProof
                );
            }
            RandomizerOpeningPayload::Perfect(_) => panic!("expected statistical payload"),
        }
    }

    #[test]
    fn perfect_spec_uses_dedicated_auxiliary_boundary() {
        let shape = BatchOpeningShape::new(6, 1, 2).expect("valid shape");
        let commitment = PerfectRandomizerCommitment::encoded_oracle_bundle(
            BasisDescriptor::plonky3_binomial(2),
        );
        let spec = ShroudBatchOpeningSpec::perfect(shape, 15, commitment).expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Perfect);
        assert_eq!(
            spec.commitment_boundary(),
            CommitmentBoundary::DedicatedAuxiliaryPath
        );

        match spec.randomizer() {
            RandomizerSpec::Perfect(model) => {
                assert_eq!(
                    model.realization(),
                    PerfectRandomizerRealization::EncodedOracleBundle {
                        basis: BasisDescriptor::plonky3_binomial(2),
                    }
                );
                assert_eq!(
                    model.proof_slot_layout(),
                    ProofSlotLayout::ReuseCurrentRandomSlot
                );
            }
            RandomizerSpec::Statistical(_) => panic!("expected perfect randomizer"),
        }

        match spec.randomizer_opening_payload() {
            RandomizerOpeningPayload::Perfect(payload) => {
                assert_eq!(payload.public_extension_evaluations(), 1);
                assert_eq!(
                    payload.proof_slot_layout(),
                    ProofSlotLayout::ReuseCurrentRandomSlot
                );
                assert_eq!(
                    payload.hidden_payload(),
                    PerfectHiddenOpeningPayload::EncodedCoordinates {
                        base_field_coordinate_evaluations: 2,
                        transport: HiddenOpeningTransport::InBandWithMainOpeningProof,
                    }
                );
            }
            RandomizerOpeningPayload::Statistical(_) => panic!("expected perfect payload"),
        }
    }

    #[test]
    fn native_extension_perfect_randomizer_needs_dedicated_slot_shape() {
        let shape = BatchOpeningShape::new(3, 2, 4).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            31,
            PerfectRandomizerCommitment::native_extension_pcs(),
        )
        .expect("valid spec");

        match spec.randomizer_opening_payload() {
            RandomizerOpeningPayload::Perfect(payload) => {
                assert_eq!(payload.public_extension_evaluations(), 2);
                assert_eq!(
                    payload.proof_slot_layout(),
                    ProofSlotLayout::DedicatedPerfectRandomizerSlot
                );
                assert_eq!(
                    payload.hidden_payload(),
                    PerfectHiddenOpeningPayload::BackendProofOnly {
                        transport: HiddenOpeningTransport::SeparateAuxiliaryProof,
                    }
                );
            }
            RandomizerOpeningPayload::Statistical(_) => panic!("expected perfect payload"),
        }
    }

    #[test]
    fn statistical_spec_can_override_the_default_degree_budget() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let budget = DegreeBudget::new(15, 15).expect("valid budget");
        let spec = ShroudBatchOpeningSpec::statistical_with_degree_budget(shape, budget)
            .expect("valid spec");

        assert_eq!(spec.degree_budget(), budget);
    }

    #[test]
    fn perfect_spec_can_override_the_default_degree_budget() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let budget = DegreeBudget::new(15, 14).expect("valid budget");
        let spec = ShroudBatchOpeningSpec::perfect_with_degree_budget(
            shape,
            budget,
            PerfectRandomizerCommitment::encoded_oracle_bundle(BasisDescriptor::plonky3_binomial(
                2,
            )),
        )
        .expect("valid spec");

        assert_eq!(spec.degree_budget(), budget);
    }

    #[test]
    fn rejects_encoded_bundle_with_mismatched_extension_degree() {
        // shape says degree 4 but basis says degree 2 — must be rejected.
        let shape = BatchOpeningShape::new(4, 1, 4).expect("valid shape");
        assert_eq!(
            ShroudBatchOpeningSpec::perfect(
                shape,
                15,
                PerfectRandomizerCommitment::encoded_oracle_bundle(
                    BasisDescriptor::plonky3_binomial(2),
                ),
            ),
            Err(BatchOpeningSpecError::InconsistentEncodedBundleDegree {
                shape_degree: 4,
                basis_degree: 2,
            })
        );
    }
}
