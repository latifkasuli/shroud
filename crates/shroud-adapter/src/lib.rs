#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Backend-neutral adapter surface for landing SHROUD objects in concrete proof systems.

use shroud_batch_opening::{
    CommitmentBoundary, ProofSlotLayout, RandomizerOpeningPayload, ShroudBatchOpeningSpec,
};
use shroud_codeword_embedding::{CodewordEmbeddingPayload, ShroudCodewordEmbeddingSpec};
use shroud_core::SecurityLevel;
use shroud_opening_projection::{OpeningProjectionPayload, ShroudOpeningProjectionSpec};
use shroud_oracle_commitment::{OracleCommitmentPayload, ShroudOracleCommitmentSpec};
use shroud_quotient_hider::{
    QuotientDecompositionFamily, QuotientHiderPayload, ShroudQuotientHiderSpec,
};

/// Outer proof-system plan for carrying a SHROUD batch-opening object.
///
/// The `CommitmentSlot` is intentionally generic: it may describe a struct field,
/// a logical proof bundle, or an auxiliary proof object depending on the backend.
///
/// `required_log_blowup` is a first-class plan field because it is a protocol
/// precondition, not a free backend parameter. A hiding FRI PCS with an
/// insufficient blowup silently breaks the statistical hiding guarantee: the
/// randomizer columns do not have enough evaluation points to mask the trace.
/// Adapters that wire up `HidingFriPcs` should assert
/// `fri_params.log_blowup >= plan.required_log_blowup()`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchOpeningAdapterPlan<CommitmentSlot> {
    security_level: SecurityLevel,
    commitment_boundary: CommitmentBoundary,
    commitment_slot: CommitmentSlot,
    proof_slot_layout: ProofSlotLayout,
    opening_payload: RandomizerOpeningPayload,
    required_log_blowup: usize,
}

impl<CommitmentSlot> BatchOpeningAdapterPlan<CommitmentSlot> {
    /// Builds a backend-neutral batch-opening adapter plan from a SHROUD spec.
    ///
    /// # Panics
    ///
    /// Panics if `required_log_blowup < 2`. All SHROUD hiding variants (statistical
    /// and perfect) require at least a blowup of 2; a blowup of 1 (the non-hiding
    /// default) does not provide enough evaluation points for the randomizer columns
    /// to mask the trace.
    ///
    /// Prefer plans emitted by a concrete adapter. This constructor does not
    /// cross-check that the supplied commitment boundary and opening payload are
    /// mutually consistent; adapter `validate` methods are responsible for that.
    #[must_use]
    pub fn new(
        security_level: SecurityLevel,
        commitment_boundary: CommitmentBoundary,
        commitment_slot: CommitmentSlot,
        opening_payload: RandomizerOpeningPayload,
        required_log_blowup: usize,
    ) -> Self {
        assert!(
            required_log_blowup >= 2,
            "required_log_blowup ({required_log_blowup}) must be at least 2; \
             a blowup of 1 does not provide enough evaluation points for the \
             randomizer columns to statistically hide the trace under FRI"
        );
        Self {
            security_level,
            commitment_boundary,
            commitment_slot,
            proof_slot_layout: proof_slot_layout(opening_payload),
            opening_payload,
            required_log_blowup,
        }
    }

    /// Security level implemented by the adapted batch-opening object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Commitment boundary required by the adapted batch-opening object.
    #[must_use]
    pub const fn commitment_boundary(&self) -> CommitmentBoundary {
        self.commitment_boundary
    }

    /// Outer proof slot used by the backend to carry the randomizer commitment.
    #[must_use]
    pub const fn commitment_slot(&self) -> &CommitmentSlot {
        &self.commitment_slot
    }

    /// Proof-slot layout required by the SHROUD randomizer payload.
    #[must_use]
    pub const fn proof_slot_layout(&self) -> ProofSlotLayout {
        self.proof_slot_layout
    }

    /// Randomizer opening payload required by the batch-opening object.
    #[must_use]
    pub const fn opening_payload(&self) -> RandomizerOpeningPayload {
        self.opening_payload
    }

    /// Minimum FRI blowup factor required by this batch-opening object.
    ///
    /// The backend's `fri_params.log_blowup` must be at least this value.
    #[must_use]
    pub const fn required_log_blowup(&self) -> usize {
        self.required_log_blowup
    }
}

/// Backend-neutral adapter trait for the SHROUD batch-opening object.
pub trait BatchOpeningAdapter {
    /// Identifier used by the outer proof system for the commitment slot.
    type CommitmentSlot;
    /// Adapter-specific error type.
    type Error;

    /// Produces the outer proof-layout plan required by the supplied SHROUD spec.
    fn plan(
        &self,
        spec: &ShroudBatchOpeningSpec,
    ) -> Result<BatchOpeningAdapterPlan<Self::CommitmentSlot>, Self::Error>;

    /// Checks that an outer proof-layout plan is compatible with the supplied SHROUD spec.
    fn validate(
        &self,
        spec: &ShroudBatchOpeningSpec,
        plan: &BatchOpeningAdapterPlan<Self::CommitmentSlot>,
    ) -> Result<(), Self::Error>;
}

/// Outer proof-system plan for carrying a SHROUD opening-projection object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpeningProjectionAdapterPlan<PublicOpeningSlot, HiddenAuxiliarySlot> {
    security_level: SecurityLevel,
    public_opening_slot: PublicOpeningSlot,
    hidden_auxiliary_slot: HiddenAuxiliarySlot,
    payload: OpeningProjectionPayload,
}

impl<PublicOpeningSlot, HiddenAuxiliarySlot>
    OpeningProjectionAdapterPlan<PublicOpeningSlot, HiddenAuxiliarySlot>
{
    /// Builds a backend-neutral opening-projection adapter plan from a SHROUD spec.
    ///
    /// Prefer plans emitted by a concrete adapter. This constructor only stores
    /// the supplied slots and payload; adapter `validate` methods are
    /// responsible for any backend-specific cross-checks.
    #[must_use]
    pub const fn new(
        security_level: SecurityLevel,
        public_opening_slot: PublicOpeningSlot,
        hidden_auxiliary_slot: HiddenAuxiliarySlot,
        payload: OpeningProjectionPayload,
    ) -> Self {
        Self {
            security_level,
            public_opening_slot,
            hidden_auxiliary_slot,
            payload,
        }
    }

    /// Security level implemented by the adapted opening-projection object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Outer proof slot used for the public opening view.
    #[must_use]
    pub const fn public_opening_slot(&self) -> &PublicOpeningSlot {
        &self.public_opening_slot
    }

    /// Outer proof slot or envelope used for the hidden auxiliary opening data.
    #[must_use]
    pub const fn hidden_auxiliary_slot(&self) -> &HiddenAuxiliarySlot {
        &self.hidden_auxiliary_slot
    }

    /// Projection payload carried by the outer proof layout.
    #[must_use]
    pub const fn payload(&self) -> OpeningProjectionPayload {
        self.payload
    }
}

/// Backend-neutral adapter trait for the SHROUD opening-projection object.
pub trait OpeningProjectionAdapter {
    /// Identifier used by the outer proof system for the public opening slot.
    type PublicOpeningSlot;
    /// Identifier used by the outer proof system for the hidden auxiliary slot.
    type HiddenAuxiliarySlot;
    /// Adapter-specific error type.
    type Error;

    /// Produces the outer proof-layout plan required by the supplied SHROUD projection spec.
    fn plan(
        &self,
        spec: &ShroudOpeningProjectionSpec,
    ) -> Result<
        OpeningProjectionAdapterPlan<Self::PublicOpeningSlot, Self::HiddenAuxiliarySlot>,
        Self::Error,
    >;

    /// Checks that an outer proof-layout plan is compatible with the supplied SHROUD projection.
    fn validate(
        &self,
        spec: &ShroudOpeningProjectionSpec,
        plan: &OpeningProjectionAdapterPlan<Self::PublicOpeningSlot, Self::HiddenAuxiliarySlot>,
    ) -> Result<(), Self::Error>;
}

/// Outer proof-system plan for carrying a SHROUD oracle-commitment object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleCommitmentAdapterPlan<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot> {
    security_level: SecurityLevel,
    commitment_slot: CommitmentSlot,
    public_opening_slot: PublicOpeningSlot,
    hidden_auxiliary_slot: HiddenAuxiliarySlot,
    payload: OracleCommitmentPayload,
}

impl<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot>
    OracleCommitmentAdapterPlan<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot>
{
    /// Builds a backend-neutral oracle-commitment adapter plan from a SHROUD spec.
    ///
    /// Prefer plans emitted by a concrete adapter. This constructor only stores
    /// the supplied slots and payload; adapter `validate` methods are
    /// responsible for any backend-specific cross-checks.
    #[must_use]
    pub const fn new(
        security_level: SecurityLevel,
        commitment_slot: CommitmentSlot,
        public_opening_slot: PublicOpeningSlot,
        hidden_auxiliary_slot: HiddenAuxiliarySlot,
        payload: OracleCommitmentPayload,
    ) -> Self {
        Self {
            security_level,
            commitment_slot,
            public_opening_slot,
            hidden_auxiliary_slot,
            payload,
        }
    }

    /// Security level implemented by the adapted oracle-commitment object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Outer proof slot used for the public commitment object.
    #[must_use]
    pub const fn commitment_slot(&self) -> &CommitmentSlot {
        &self.commitment_slot
    }

    /// Outer proof slot or envelope used for the public queried rows and authentication data.
    #[must_use]
    pub const fn public_opening_slot(&self) -> &PublicOpeningSlot {
        &self.public_opening_slot
    }

    /// Outer proof slot or envelope used for the hidden row-hiding witness material.
    #[must_use]
    pub const fn hidden_auxiliary_slot(&self) -> &HiddenAuxiliarySlot {
        &self.hidden_auxiliary_slot
    }

    /// Oracle-commitment payload carried by the outer proof layout.
    #[must_use]
    pub const fn payload(&self) -> OracleCommitmentPayload {
        self.payload
    }
}

/// Result type returned by backend-neutral oracle-commitment adapters.
pub type OracleCommitmentAdapterResult<
    CommitmentSlot,
    PublicOpeningSlot,
    HiddenAuxiliarySlot,
    Error,
> = Result<
    OracleCommitmentAdapterPlan<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot>,
    Error,
>;

/// Backend-neutral adapter trait for the SHROUD oracle-commitment object.
pub trait OracleCommitmentAdapter {
    /// Identifier used by the outer proof system for the public commitment slot.
    type CommitmentSlot;
    /// Identifier used by the outer proof system for the public opening slot.
    type PublicOpeningSlot;
    /// Identifier used by the outer proof system for the hidden auxiliary slot.
    type HiddenAuxiliarySlot;
    /// Adapter-specific error type.
    type Error;

    /// Produces the outer proof-layout plan required by the supplied SHROUD oracle-commitment spec.
    fn plan(
        &self,
        spec: &ShroudOracleCommitmentSpec,
    ) -> OracleCommitmentAdapterResult<
        Self::CommitmentSlot,
        Self::PublicOpeningSlot,
        Self::HiddenAuxiliarySlot,
        Self::Error,
    >;

    /// Checks that an outer proof-layout plan is compatible with the supplied SHROUD oracle commitment.
    fn validate(
        &self,
        spec: &ShroudOracleCommitmentSpec,
        plan: &OracleCommitmentAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
    ) -> Result<(), Self::Error>;
}

/// Outer proof-system plan for carrying a SHROUD quotient-hider object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientHiderAdapterPlan<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot> {
    security_level: SecurityLevel,
    decomposition_family: QuotientDecompositionFamily,
    query_budget: usize,
    commitment_slot: CommitmentSlot,
    public_opening_slot: PublicOpeningSlot,
    hidden_auxiliary_slot: HiddenAuxiliarySlot,
    payload: QuotientHiderPayload,
}

impl<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot>
    QuotientHiderAdapterPlan<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot>
{
    /// Builds a backend-neutral quotient-hider adapter plan from a SHROUD spec.
    ///
    /// Prefer plans emitted by a concrete adapter. This constructor only stores
    /// the supplied fields and payload; adapter `validate` methods are
    /// responsible for any backend-specific cross-checks.
    #[must_use]
    pub const fn new(
        security_level: SecurityLevel,
        decomposition_family: QuotientDecompositionFamily,
        query_budget: usize,
        commitment_slot: CommitmentSlot,
        public_opening_slot: PublicOpeningSlot,
        hidden_auxiliary_slot: HiddenAuxiliarySlot,
        payload: QuotientHiderPayload,
    ) -> Self {
        Self {
            security_level,
            decomposition_family,
            query_budget,
            commitment_slot,
            public_opening_slot,
            hidden_auxiliary_slot,
            payload,
        }
    }

    /// Security level implemented by the adapted quotient-hider object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Quotient decomposition family implemented by the adapted object.
    #[must_use]
    pub const fn decomposition_family(&self) -> QuotientDecompositionFamily {
        self.decomposition_family
    }

    /// Query budget claimed by the adapted quotient-hider object.
    #[must_use]
    pub const fn query_budget(&self) -> usize {
        self.query_budget
    }

    /// Outer proof slot used for the public quotient commitment object.
    #[must_use]
    pub const fn commitment_slot(&self) -> &CommitmentSlot {
        &self.commitment_slot
    }

    /// Outer proof slot or envelope used for the public quotient opening values.
    #[must_use]
    pub const fn public_opening_slot(&self) -> &PublicOpeningSlot {
        &self.public_opening_slot
    }

    /// Outer proof slot or envelope used for the hidden quotient auxiliary material.
    #[must_use]
    pub const fn hidden_auxiliary_slot(&self) -> &HiddenAuxiliarySlot {
        &self.hidden_auxiliary_slot
    }

    /// Quotient-hider payload carried by the outer proof layout.
    #[must_use]
    pub const fn payload(&self) -> QuotientHiderPayload {
        self.payload
    }
}

/// Result type returned by backend-neutral quotient-hider adapters.
pub type QuotientHiderAdapterResult<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot, Error> =
    Result<QuotientHiderAdapterPlan<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot>, Error>;

/// Backend-neutral adapter trait for the SHROUD quotient-hider object.
pub trait QuotientHiderAdapter {
    /// Identifier used by the outer proof system for the public commitment slot.
    type CommitmentSlot;
    /// Identifier used by the outer proof system for the public opening slot.
    type PublicOpeningSlot;
    /// Identifier used by the outer proof system for the hidden auxiliary slot.
    type HiddenAuxiliarySlot;
    /// Adapter-specific error type.
    type Error;

    /// Produces the outer proof-layout plan required by the supplied SHROUD quotient-hider spec.
    fn plan(
        &self,
        spec: &ShroudQuotientHiderSpec,
    ) -> QuotientHiderAdapterResult<
        Self::CommitmentSlot,
        Self::PublicOpeningSlot,
        Self::HiddenAuxiliarySlot,
        Self::Error,
    >;

    /// Checks that an outer proof-layout plan is compatible with the supplied SHROUD quotient hider.
    fn validate(
        &self,
        spec: &ShroudQuotientHiderSpec,
        plan: &QuotientHiderAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
    ) -> Result<(), Self::Error>;
}

/// Outer proof-system plan for carrying a SHROUD codeword-embedding object.
///
/// `CommitmentSlot` identifies the outer proof field holding the committed
/// matrix (trace + randomizer columns). `PublicOpeningSlot` covers the opened
/// trace column evaluations visible to the verifier. `HiddenAuxiliarySlot`
/// covers the randomizer column opening material, transported per
/// `payload.auxiliary_transport()`.
///
/// The blowup constraint lives in `payload.required_log_blowup()`. An adapter
/// wiring up `HidingFriPcs` must assert
/// `fri_params.log_blowup >= plan.payload().required_log_blowup()`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodewordEmbeddingAdapterPlan<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot> {
    security_level: SecurityLevel,
    commitment_slot: CommitmentSlot,
    public_opening_slot: PublicOpeningSlot,
    hidden_auxiliary_slot: HiddenAuxiliarySlot,
    payload: CodewordEmbeddingPayload,
}

impl<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot>
    CodewordEmbeddingAdapterPlan<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot>
{
    /// Builds a backend-neutral codeword-embedding adapter plan.
    ///
    /// Prefer plans emitted by a concrete adapter. This constructor only stores
    /// the supplied slots and payload; adapter `validate` methods are
    /// responsible for any backend-specific cross-checks.
    #[must_use]
    pub const fn new(
        security_level: SecurityLevel,
        commitment_slot: CommitmentSlot,
        public_opening_slot: PublicOpeningSlot,
        hidden_auxiliary_slot: HiddenAuxiliarySlot,
        payload: CodewordEmbeddingPayload,
    ) -> Self {
        Self {
            security_level,
            commitment_slot,
            public_opening_slot,
            hidden_auxiliary_slot,
            payload,
        }
    }

    /// Security level implemented by the adapted codeword-embedding object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Outer proof slot used for the committed matrix (trace + randomizer columns).
    #[must_use]
    pub const fn commitment_slot(&self) -> &CommitmentSlot {
        &self.commitment_slot
    }

    /// Outer proof slot used for the opened trace column evaluations.
    #[must_use]
    pub const fn public_opening_slot(&self) -> &PublicOpeningSlot {
        &self.public_opening_slot
    }

    /// Outer proof slot or envelope used for the hidden randomizer column opening material.
    #[must_use]
    pub const fn hidden_auxiliary_slot(&self) -> &HiddenAuxiliarySlot {
        &self.hidden_auxiliary_slot
    }

    /// Codeword-embedding payload carried by the outer proof layout.
    #[must_use]
    pub const fn payload(&self) -> CodewordEmbeddingPayload {
        self.payload
    }
}

/// Result type returned by backend-neutral codeword-embedding adapters.
pub type CodewordEmbeddingAdapterResult<
    CommitmentSlot,
    PublicOpeningSlot,
    HiddenAuxiliarySlot,
    Error,
> = Result<
    CodewordEmbeddingAdapterPlan<CommitmentSlot, PublicOpeningSlot, HiddenAuxiliarySlot>,
    Error,
>;

/// Backend-neutral adapter trait for the SHROUD codeword-embedding object.
pub trait CodewordEmbeddingAdapter {
    /// Identifier used by the outer proof system for the committed matrix slot.
    type CommitmentSlot;
    /// Identifier used by the outer proof system for the public trace opening slot.
    type PublicOpeningSlot;
    /// Identifier used by the outer proof system for the hidden randomizer auxiliary slot.
    type HiddenAuxiliarySlot;
    /// Adapter-specific error type.
    type Error;

    /// Produces the outer proof-layout plan required by the supplied SHROUD codeword-embedding spec.
    fn plan(
        &self,
        spec: &ShroudCodewordEmbeddingSpec,
    ) -> CodewordEmbeddingAdapterResult<
        Self::CommitmentSlot,
        Self::PublicOpeningSlot,
        Self::HiddenAuxiliarySlot,
        Self::Error,
    >;

    /// Checks that an outer proof-layout plan is compatible with the supplied SHROUD codeword embedding.
    fn validate(
        &self,
        spec: &ShroudCodewordEmbeddingSpec,
        plan: &CodewordEmbeddingAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
    ) -> Result<(), Self::Error>;
}

/// Returns the proof-slot layout implied by a randomizer opening payload.
#[must_use]
pub const fn proof_slot_layout(payload: RandomizerOpeningPayload) -> ProofSlotLayout {
    match payload {
        RandomizerOpeningPayload::Statistical(payload) => payload.proof_slot_layout(),
        RandomizerOpeningPayload::Perfect(payload) => payload.proof_slot_layout(),
    }
}

#[cfg(test)]
mod proptests {
    use super::BatchOpeningAdapterPlan;
    use proptest::prelude::*;
    use shroud_batch_opening::{BatchOpeningShape, CommitmentBoundary, ShroudBatchOpeningSpec};
    use shroud_core::SecurityLevel;

    proptest! {
        #[test]
        fn plan_accepts_all_blowup_values_at_least_two(blowup in 2usize..100) {
            let shape = BatchOpeningShape::new(4, 2, 3).expect("valid shape");
            let spec = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");
            let plan = BatchOpeningAdapterPlan::new(
                SecurityLevel::Statistical,
                CommitmentBoundary::SharedPcsHook,
                "slot",
                spec.randomizer_opening_payload(),
                blowup,
            );
            prop_assert_eq!(plan.required_log_blowup(), blowup);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BatchOpeningAdapterPlan, CodewordEmbeddingAdapterPlan, OpeningProjectionAdapterPlan,
        OracleCommitmentAdapterPlan, QuotientHiderAdapterPlan, proof_slot_layout,
    };
    use shroud_batch_opening::{
        BatchOpeningShape, CommitmentBoundary, PerfectRandomizerCommitment, ProofSlotLayout,
        RandomizerOpeningPayload, ShroudBatchOpeningSpec,
    };
    use shroud_codeword_embedding::{CodewordEmbeddingShape, ShroudCodewordEmbeddingSpec};
    use shroud_core::{
        FieldModel, PerfectClaim, RandomnessModel, SecurityLevel, SimulatorObligations,
    };
    use shroud_opening_projection::{
        AuxiliaryOpeningTransport, OpeningProjectionShape, ShroudOpeningProjectionSpec,
    };
    use shroud_oracle_commitment::{
        OracleAuxiliaryTransport, OracleCommitmentShape, ShroudOracleCommitmentSpec,
    };
    use shroud_quotient_hider::{
        QuotientAuxiliaryTransport, QuotientDecompositionFamily, QuotientDegreeContract,
        QuotientHiderShape, ShroudQuotientHiderSpec,
    };

    fn valid_native_perfect_claim(extension_degree: usize) -> PerfectClaim {
        PerfectClaim::new(
            RandomnessModel::UniformPerProof,
            FieldModel::NativeExtension { extension_degree },
            64,
            SimulatorObligations::HonestVerifierChallengeAccess,
            true,
        )
        .expect("valid native perfect claim")
    }

    #[test]
    fn codeword_embedding_plan_tracks_committed_columns_and_blowup() {
        let shape = CodewordEmbeddingShape::new(64, 4, 18, 4).expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");
        let payload = spec.payload();
        let plan = CodewordEmbeddingAdapterPlan::new(
            SecurityLevel::Statistical,
            "pcs_commitment",
            "trace_openings",
            "randomizer_openings",
            payload,
        );

        assert_eq!(plan.security_level(), SecurityLevel::Statistical);
        assert_eq!(plan.payload().committed_columns(), 68);
        assert_eq!(plan.payload().public_trace_columns(), 64);
        assert_eq!(plan.payload().hidden_randomizer_columns(), 4);
        assert_eq!(plan.payload().required_log_blowup(), 2);
        assert_eq!(plan.commitment_slot(), &"pcs_commitment");
        assert_eq!(plan.public_opening_slot(), &"trace_openings");
        assert_eq!(plan.hidden_auxiliary_slot(), &"randomizer_openings");
    }

    #[test]
    #[should_panic(expected = "required_log_blowup (1) must be at least 2")]
    fn batch_opening_plan_panics_on_blowup_below_two() {
        let shape = BatchOpeningShape::new(4, 2, 3).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");
        // required_log_blowup = 1 is the non-hiding default — must be rejected.
        let _ = BatchOpeningAdapterPlan::new(
            SecurityLevel::Statistical,
            CommitmentBoundary::SharedPcsHook,
            "slot",
            spec.randomizer_opening_payload(),
            1,
        );
    }

    #[test]
    fn plan_tracks_statistical_slot_layout_from_payload() {
        let shape = BatchOpeningShape::new(4, 2, 3).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");
        let payload = spec.randomizer_opening_payload();
        let plan = BatchOpeningAdapterPlan::new(
            SecurityLevel::Statistical,
            CommitmentBoundary::SharedPcsHook,
            "random",
            payload,
            2,
        );

        assert_eq!(
            plan.proof_slot_layout(),
            ProofSlotLayout::ReuseCurrentRandomSlot
        );
        assert_eq!(plan.opening_payload(), payload);
        assert_eq!(plan.required_log_blowup(), 2);
    }

    #[test]
    fn helper_extracts_perfect_slot_layout_from_payload() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::native_extension_pcs(),
            valid_native_perfect_claim(2),
        )
        .expect("valid spec");

        assert_eq!(
            proof_slot_layout(spec.randomizer_opening_payload()),
            ProofSlotLayout::DedicatedPerfectRandomizerSlot
        );
        assert!(matches!(
            spec.randomizer_opening_payload(),
            RandomizerOpeningPayload::Perfect(_)
        ));
    }

    #[test]
    fn projection_plan_tracks_public_and_hidden_slots() {
        let shape = OpeningProjectionShape::new(3, 5, 2).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::statistical(
            shape,
            AuxiliaryOpeningTransport::InBandWithMainProof,
        )
        .expect("valid spec");
        let payload = spec.payload();
        let plan = OpeningProjectionAdapterPlan::new(
            SecurityLevel::Statistical,
            "opened_values",
            "fri_opening_proof",
            payload,
        );

        assert_eq!(plan.payload(), payload);
        assert_eq!(plan.public_opening_slot(), &"opened_values");
        assert_eq!(plan.hidden_auxiliary_slot(), &"fri_opening_proof");
    }

    #[test]
    fn oracle_commitment_plan_tracks_commitment_opening_and_hidden_slots() {
        let shape = OracleCommitmentShape::new(2, 3, 4, 5, 1).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::statistical(
            shape,
            OracleAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid spec");
        let payload = spec.payload();
        let plan = OracleCommitmentAdapterPlan::new(
            SecurityLevel::Statistical,
            "oracle_commitment",
            "mmcs_opening",
            "salt_witness",
            payload,
        );

        assert_eq!(plan.payload(), payload);
        assert_eq!(plan.commitment_slot(), &"oracle_commitment");
        assert_eq!(plan.public_opening_slot(), &"mmcs_opening");
        assert_eq!(plan.hidden_auxiliary_slot(), &"salt_witness");
    }

    #[test]
    fn quotient_hider_plan_tracks_family_budget_and_slots() {
        let shape = QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid shape");
        let contract = QuotientDegreeContract::new(31, 31).expect("valid contract");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(contract),
        )
        .expect("valid spec");
        let payload = spec.payload();
        let plan = QuotientHiderAdapterPlan::new(
            SecurityLevel::Statistical,
            QuotientDecompositionFamily::DegreeChunked,
            8,
            "quotient_commitment",
            "quotient_opening",
            "quotient_mask",
            payload,
        );

        assert_eq!(
            plan.decomposition_family(),
            QuotientDecompositionFamily::DegreeChunked
        );
        assert_eq!(plan.query_budget(), 8);
        assert_eq!(plan.payload(), payload);
        assert_eq!(plan.commitment_slot(), &"quotient_commitment");
        assert_eq!(plan.public_opening_slot(), &"quotient_opening");
        assert_eq!(plan.hidden_auxiliary_slot(), &"quotient_mask");
    }
}
