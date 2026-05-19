#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Shared protocol types for the SHROUD workspace.

mod binding;
mod claim;
mod degree;
mod hiding;
mod surface;
mod transcript;

pub use binding::{
    CanonicalBatchOpeningManifest, DOMAIN_BASIS, DOMAIN_BATCH_OPENING, DOMAIN_CODEWORD_EMBEDDING,
    DOMAIN_DEGREE_BUDGET, DOMAIN_DEGREE_CONTRACT, DOMAIN_HASH_ID, DOMAIN_HIDING_TECHNIQUE,
    DOMAIN_OPENING_PROJECTION, DOMAIN_ORACLE_COMMITMENT, DOMAIN_PERFECT_CLAIM, DOMAIN_PROFILE,
    DOMAIN_PUBLIC_OPENINGS, DOMAIN_QUOTIENT_HIDER, DOMAIN_RANDOMIZER_COMMITMENT,
    DOMAIN_SAMPLED_CHALLENGE, DOMAIN_SECURITY_LEVEL, HashIdentifier, PublicOpeningBinding,
    SampledChallenge, StandardBatchOpeningBindings, TranscriptBindable, TranscriptBinding,
    TranscriptBindingError, TranscriptBindingManifest, TranscriptBindingSource,
    TranscriptChallengeDeriver, transcript_stage_discriminant,
};
pub use claim::{
    BasisDescriptor, CoordinateOrder, FieldModel, PerfectClaim, PerfectClaimError, RandomnessModel,
    ReconstructionRule, SimulatorObligations,
};
pub use degree::{DegreeBudget, DegreeBudgetError};
pub use hiding::HidingTechniqueClaim;
pub use surface::{AuxiliaryTransport, HiddenAuxiliarySurface, PublicSurface, QueryBudget};
pub use transcript::{TranscriptPlan, TranscriptPlanError, TranscriptStage};

/// The zero-knowledge level claimed by a SHROUD object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityLevel {
    /// The construction is only statistical honest-verifier zero-knowledge.
    Statistical,
    /// The construction targets perfect honest-verifier zero-knowledge.
    Perfect,
}
