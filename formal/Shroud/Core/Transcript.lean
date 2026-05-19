/-!
Normative transcript-stage model for the SHROUD batch-opening protocol.

This module is the first Lean mirror of the Rust `TranscriptStage` and
`TranscriptPlan::standard_batch_opening()` definitions.  It intentionally
models only the protocol-level stage order; backend-specific byte streams stay
in Rust.
-/

namespace Shroud
namespace Core

/-- Ordered stages for the SHROUD batch-opening transcript. -/
inductive TranscriptStage where
  /-- Observe ordinary trace, preprocessing, or equivalent oracle commitments. -/
  | observeMainCommitments
  /-- Sample the batching challenge used to form the reduced relation. -/
  | sampleBatchingChallenge
  /-- Observe quotient commitments or equivalent post-constraint commitments. -/
  | observeQuotientCommitments
  /-- Observe the auxiliary randomizer commitment. -/
  | observeRandomizerCommitment
  /-- Sample the out-of-domain point used for the opening claim. -/
  | sampleOodPoint
  /-- Observe public opening values that define the statement-facing claim. -/
  | observePublicOpenings
  /-- Produce or verify the low-degree proof for the masked relation. -/
  | proveMaskedRelation
  deriving BEq, DecidableEq, Repr

namespace TranscriptStage

/-- Canonical numeric position of a transcript stage in SHROUD v1. -/
def ordinal : TranscriptStage -> Nat
  | observeMainCommitments => 0
  | sampleBatchingChallenge => 1
  | observeQuotientCommitments => 2
  | observeRandomizerCommitment => 3
  | sampleOodPoint => 4
  | observePublicOpenings => 5
  | proveMaskedRelation => 6

/-- Protocol-order relation induced by the canonical stage ordinals. -/
def before (left right : TranscriptStage) : Prop :=
  left.ordinal < right.ordinal

/-- The randomizer commitment has a lower canonical ordinal than the OOD sample. -/
theorem observeRandomizerCommitment_ordinal_before_sampleOodPoint :
    before observeRandomizerCommitment sampleOodPoint := by
  simp [before, ordinal]

/-- The batching challenge is sampled before quotient commitments are observed. -/
theorem batchingChallenge_before_quotientCommitments :
    before sampleBatchingChallenge observeQuotientCommitments := by
  simp [before, ordinal]

end TranscriptStage

/-- Canonical SHROUD v1 batch-opening transcript schedule. -/
def canonicalBatchOpeningSchedule : List TranscriptStage :=
  [ TranscriptStage.observeMainCommitments
  , TranscriptStage.sampleBatchingChallenge
  , TranscriptStage.observeQuotientCommitments
  , TranscriptStage.observeRandomizerCommitment
  , TranscriptStage.sampleOodPoint
  , TranscriptStage.observePublicOpenings
  , TranscriptStage.proveMaskedRelation
  ]

/-- The canonical schedule contains exactly seven protocol stages. -/
theorem canonicalBatchOpeningSchedule_length :
    canonicalBatchOpeningSchedule.length = 7 := by
  decide

/-- Index of a stage in the concrete canonical batch-opening schedule. -/
def canonicalBatchOpeningScheduleIndex (stage : TranscriptStage) : Nat :=
  canonicalBatchOpeningSchedule.idxOf stage

/--
The concrete canonical schedule observes the randomizer commitment before
sampling the OOD point.

This theorem is intentionally about the schedule list, not only the independent
stage ordinals.  If the schedule is reordered while the ordinals stay fixed,
this proof fails.
-/
theorem observeRandomizerCommitment_before_sampleOodPoint :
    canonicalBatchOpeningScheduleIndex TranscriptStage.observeRandomizerCommitment
      < canonicalBatchOpeningScheduleIndex TranscriptStage.sampleOodPoint := by
  decide

/-- Short alias for the canonical schedule-level randomizer-before-OOD theorem. -/
theorem randomizerCommitment_before_ood :
    canonicalBatchOpeningScheduleIndex TranscriptStage.observeRandomizerCommitment
      < canonicalBatchOpeningScheduleIndex TranscriptStage.sampleOodPoint :=
  observeRandomizerCommitment_before_sampleOodPoint

end Core
end Shroud
