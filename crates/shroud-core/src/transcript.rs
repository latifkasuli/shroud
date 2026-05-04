//! Transcript schedule for the SHROUD ZK batch-opening object.
//!
//! This module intentionally models the batch-opening schedule with an observed
//! randomizer commitment. It is not yet a generic transcript planner for non-ZK
//! STARK or PCS pipelines.

use core::fmt;

/// Ordered stages for the SHROUD batch-opening transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptStage {
    /// Observe ordinary trace, preprocessing, or equivalent oracle commitments.
    ObserveMainCommitments,
    /// Sample the batching challenge used to form the reduced relation.
    SampleBatchingChallenge,
    /// Observe quotient commitments or equivalent post-constraint commitments.
    ObserveQuotientCommitments,
    /// Observe the auxiliary randomizer commitment.
    ObserveRandomizerCommitment,
    /// Sample the out-of-domain point used for the opening claim.
    SampleOodPoint,
    /// Observe the public opening values that define the statement-facing claim.
    ObservePublicOpenings,
    /// Produce or verify the low-degree proof for the masked relation.
    ProveMaskedRelation,
}

impl TranscriptStage {
    const fn ordinal(self) -> usize {
        match self {
            Self::ObserveMainCommitments => 0,
            Self::SampleBatchingChallenge => 1,
            Self::ObserveQuotientCommitments => 2,
            Self::ObserveRandomizerCommitment => 3,
            Self::SampleOodPoint => 4,
            Self::ObservePublicOpenings => 5,
            Self::ProveMaskedRelation => 6,
        }
    }
}

impl fmt::Display for TranscriptStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ObserveMainCommitments => "observe main commitments",
            Self::SampleBatchingChallenge => "sample batching challenge",
            Self::ObserveQuotientCommitments => "observe quotient commitments",
            Self::ObserveRandomizerCommitment => "observe randomizer commitment",
            Self::SampleOodPoint => "sample out-of-domain point",
            Self::ObservePublicOpenings => "observe public openings",
            Self::ProveMaskedRelation => "prove masked relation",
        };
        f.write_str(label)
    }
}

/// Canonical transcript schedule for a SHROUD batch-opening object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptPlan {
    stages: Vec<TranscriptStage>,
}

impl TranscriptPlan {
    /// Returns the canonical SHROUD ZK batch-opening transcript order.
    #[must_use]
    pub fn standard_batch_opening() -> Self {
        Self {
            stages: vec![
                TranscriptStage::ObserveMainCommitments,
                TranscriptStage::SampleBatchingChallenge,
                TranscriptStage::ObserveQuotientCommitments,
                TranscriptStage::ObserveRandomizerCommitment,
                TranscriptStage::SampleOodPoint,
                TranscriptStage::ObservePublicOpenings,
                TranscriptStage::ProveMaskedRelation,
            ],
        }
    }

    /// Returns the ordered transcript stages.
    #[must_use]
    pub fn stages(&self) -> &[TranscriptStage] {
        &self.stages
    }

    /// Validates that every required stage is present exactly once and in canonical order.
    pub fn validate(&self) -> Result<(), TranscriptPlanError> {
        let mut seen = [false; 7];
        let mut previous: Option<TranscriptStage> = None;

        for stage in &self.stages {
            let ordinal = stage.ordinal();
            if seen[ordinal] {
                return Err(TranscriptPlanError::DuplicateStage(*stage));
            }
            seen[ordinal] = true;

            if let Some(previous_stage) = previous
                && ordinal < previous_stage.ordinal()
            {
                return Err(TranscriptPlanError::OutOfOrder {
                    previous: previous_stage,
                    observed: *stage,
                });
            }

            previous = Some(*stage);
        }

        if let Some(missing_idx) = seen.iter().position(|present| !present) {
            return Err(TranscriptPlanError::MissingStage(match missing_idx {
                0 => TranscriptStage::ObserveMainCommitments,
                1 => TranscriptStage::SampleBatchingChallenge,
                2 => TranscriptStage::ObserveQuotientCommitments,
                3 => TranscriptStage::ObserveRandomizerCommitment,
                4 => TranscriptStage::SampleOodPoint,
                5 => TranscriptStage::ObservePublicOpenings,
                6 => TranscriptStage::ProveMaskedRelation,
                _ => unreachable!("stage table is fixed"),
            }));
        }

        Ok(())
    }
}

/// Error raised when a transcript plan violates a SHROUD ordering invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptPlanError {
    /// A required stage is absent.
    MissingStage(TranscriptStage),
    /// A stage appears more than once.
    DuplicateStage(TranscriptStage),
    /// A stage appears before another stage it must follow.
    OutOfOrder {
        /// The last valid stage seen so far.
        previous: TranscriptStage,
        /// The stage that appeared too early.
        observed: TranscriptStage,
    },
}

impl fmt::Display for TranscriptPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingStage(stage) => write!(f, "missing transcript stage: {stage}"),
            Self::DuplicateStage(stage) => write!(f, "duplicate transcript stage: {stage}"),
            Self::OutOfOrder { previous, observed } => write!(
                f,
                "transcript stage {observed} appears before it is allowed after {previous}"
            ),
        }
    }
}

impl std::error::Error for TranscriptPlanError {}

#[cfg(test)]
mod proptests {
    use super::{TranscriptPlan, TranscriptStage};
    use proptest::prelude::*;

    fn canonical_stages() -> Vec<TranscriptStage> {
        vec![
            TranscriptStage::ObserveMainCommitments,
            TranscriptStage::SampleBatchingChallenge,
            TranscriptStage::ObserveQuotientCommitments,
            TranscriptStage::ObserveRandomizerCommitment,
            TranscriptStage::SampleOodPoint,
            TranscriptStage::ObservePublicOpenings,
            TranscriptStage::ProveMaskedRelation,
        ]
    }

    proptest! {
        #[test]
        fn any_transposition_of_canonical_stages_is_invalid(i in 0usize..7, j in 0usize..7) {
            prop_assume!(i != j);
            let mut stages = canonical_stages();
            stages.swap(i, j);
            let plan = TranscriptPlan { stages };
            prop_assert!(plan.validate().is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TranscriptPlan, TranscriptPlanError, TranscriptStage};

    #[test]
    fn standard_plan_is_valid() {
        let plan = TranscriptPlan::standard_batch_opening();
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn rejects_out_of_order_randomizer_commitment() {
        let plan = TranscriptPlan {
            stages: vec![
                TranscriptStage::ObserveMainCommitments,
                TranscriptStage::SampleBatchingChallenge,
                TranscriptStage::SampleOodPoint,
                TranscriptStage::ObserveQuotientCommitments,
                TranscriptStage::ObserveRandomizerCommitment,
                TranscriptStage::ObservePublicOpenings,
                TranscriptStage::ProveMaskedRelation,
            ],
        };

        assert_eq!(
            plan.validate(),
            Err(TranscriptPlanError::OutOfOrder {
                previous: TranscriptStage::SampleOodPoint,
                observed: TranscriptStage::ObserveQuotientCommitments,
            })
        );
    }
}
