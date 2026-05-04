#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Shared protocol types for the SHROUD workspace.

mod claim;
mod degree;
mod surface;
mod transcript;

pub use claim::{
    BasisDescriptor, CoordinateOrder, FieldModel, PerfectClaim, PerfectClaimError, RandomnessModel,
    ReconstructionRule, SimulatorObligations,
};
pub use degree::{DegreeBudget, DegreeBudgetError};
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
