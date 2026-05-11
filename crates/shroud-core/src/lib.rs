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
    DOMAIN_BASIS, DOMAIN_DEGREE_CONTRACT, DOMAIN_ORACLE_COMMITMENT, DOMAIN_PROFILE,
    DOMAIN_PUBLIC_OPENINGS, DOMAIN_RANDOMIZER_COMMITMENT, DOMAIN_SECURITY_LEVEL,
    TranscriptBindable, TranscriptBinding, TranscriptBindingError, TranscriptBindingManifest,
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
