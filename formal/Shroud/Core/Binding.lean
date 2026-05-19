import Shroud.Core.Transcript

/-!
Normative transcript-binding manifest model for SHROUD.

This module models the protocol-level binding schedule.  It deliberately tracks
domain-label identity and stage buckets, not backend byte encodings.  Concrete
bytes remain the responsibility of the Rust `TranscriptBindable` implementations
and backend conformance tests.
-/

namespace Shroud
namespace Core

/-- Domain labels used by SHROUD transcript bindings. -/
inductive DomainLabel where
  /-- SHROUD hiding profile. -/
  | profile
  /-- Extension-field basis descriptor. -/
  | basis
  /-- Oracle-commitment shape and security level. -/
  | oracleCommitment
  /-- Concrete randomizer commitment. -/
  | randomizerCommitment
  /-- Quotient degree contract. -/
  | degreeContract
  /-- Proof security level. -/
  | securityLevel
  /-- Backend-canonical public opening values. -/
  | publicOpenings
  /-- Complete batch-opening spec. -/
  | batchOpening
  /-- Complete codeword-embedding spec. -/
  | codewordEmbedding
  /-- Complete opening-projection spec. -/
  | openingProjection
  /-- Complete quotient-hider spec. -/
  | quotientHider
  /-- Batch-opening degree budget. -/
  | degreeBudget
  /-- Declared hiding-technique claim. -/
  | hidingTechnique
  /-- Fiat-Shamir hash-suite identifier. -/
  | hashIdentifier
  /-- Sampled Fiat-Shamir challenge record. -/
  | sampledChallenge
  deriving BEq, DecidableEq, Repr

namespace DomainLabel

/-- Stable label discriminant mirroring the Rust domain-label list. -/
def discriminant : DomainLabel -> Nat
  | profile => 0
  | basis => 1
  | oracleCommitment => 2
  | randomizerCommitment => 3
  | degreeContract => 4
  | securityLevel => 5
  | publicOpenings => 6
  | batchOpening => 7
  | codewordEmbedding => 8
  | openingProjection => 9
  | quotientHider => 10
  | degreeBudget => 11
  | hidingTechnique => 12
  | hashIdentifier => 13
  | sampledChallenge => 14

end DomainLabel

/-- Every domain label currently named by SHROUD. -/
def allDomainLabels : List DomainLabel :=
  [ DomainLabel.profile
  , DomainLabel.basis
  , DomainLabel.oracleCommitment
  , DomainLabel.randomizerCommitment
  , DomainLabel.degreeContract
  , DomainLabel.securityLevel
  , DomainLabel.publicOpenings
  , DomainLabel.batchOpening
  , DomainLabel.codewordEmbedding
  , DomainLabel.openingProjection
  , DomainLabel.quotientHider
  , DomainLabel.degreeBudget
  , DomainLabel.hidingTechnique
  , DomainLabel.hashIdentifier
  , DomainLabel.sampledChallenge
  ]

/-- The finite SHROUD domain-label set has no duplicate labels. -/
theorem domainLabels_pairwiseDistinct : allDomainLabels.Nodup := by
  decide

/-- Domain labels used by the canonical batch-opening manifest. -/
def canonicalBatchOpeningBindingLabels : List DomainLabel :=
  [ DomainLabel.hashIdentifier
  , DomainLabel.profile
  , DomainLabel.basis
  , DomainLabel.batchOpening
  , DomainLabel.codewordEmbedding
  , DomainLabel.oracleCommitment
  , DomainLabel.openingProjection
  , DomainLabel.quotientHider
  , DomainLabel.securityLevel
  , DomainLabel.degreeContract
  , DomainLabel.randomizerCommitment
  , DomainLabel.publicOpenings
  ]

/-- Stage-scoped manifest of expected transcript binding labels. -/
structure TranscriptBindingManifest where
  /-- Labels required before the batching challenge is sampled. -/
  beforeBatchingChallenge : List DomainLabel
  /-- Labels required before the OOD point is sampled. -/
  beforeOodPoint : List DomainLabel
  /-- Labels required before proving/verifying the masked relation. -/
  beforeProveMasked : List DomainLabel
  deriving Repr

namespace TranscriptBindingManifest

/-- Required labels before a transcript stage. Non-sampling stages require no labels. -/
def requiredBefore (manifest : TranscriptBindingManifest) :
    TranscriptStage -> List DomainLabel
  | TranscriptStage.sampleBatchingChallenge => manifest.beforeBatchingChallenge
  | TranscriptStage.sampleOodPoint => manifest.beforeOodPoint
  | TranscriptStage.proveMaskedRelation => manifest.beforeProveMasked
  | _ => []

/-- All labels appearing in a manifest, in canonical bucket order. -/
def labels (manifest : TranscriptBindingManifest) : List DomainLabel :=
  manifest.beforeBatchingChallenge ++ manifest.beforeOodPoint ++ manifest.beforeProveMasked

end TranscriptBindingManifest

/-- Canonical SHROUD v1 batch-opening binding manifest. -/
def canonicalBatchOpeningManifest : TranscriptBindingManifest where
  beforeBatchingChallenge :=
    [ DomainLabel.hashIdentifier
    , DomainLabel.profile
    , DomainLabel.basis
    , DomainLabel.batchOpening
    , DomainLabel.codewordEmbedding
    , DomainLabel.oracleCommitment
    , DomainLabel.openingProjection
    , DomainLabel.quotientHider
    , DomainLabel.securityLevel
    ]
  beforeOodPoint :=
    [ DomainLabel.degreeContract
    , DomainLabel.randomizerCommitment
    ]
  beforeProveMasked :=
    [ DomainLabel.publicOpenings
    ]

/-- The canonical manifest contains exactly the canonical batch-opening labels. -/
theorem canonicalManifest_complete :
    canonicalBatchOpeningManifest.labels = canonicalBatchOpeningBindingLabels := by
  decide

/-- No canonical batch-opening binding label appears twice in the manifest. -/
theorem canonicalManifest_noDuplicates :
    canonicalBatchOpeningManifest.labels.Nodup := by
  decide

/-- Hash-suite identity is bound before the batching challenge. -/
theorem requiredBeforeBatching_containsHashIdentifier :
    DomainLabel.hashIdentifier ∈
      canonicalBatchOpeningManifest.requiredBefore TranscriptStage.sampleBatchingChallenge := by
  simp [TranscriptBindingManifest.requiredBefore, canonicalBatchOpeningManifest]

/-- The randomizer commitment is required before the OOD challenge. -/
theorem requiredBeforeOod_containsRandomizerCommitment :
    DomainLabel.randomizerCommitment ∈
      canonicalBatchOpeningManifest.requiredBefore TranscriptStage.sampleOodPoint := by
  simp [TranscriptBindingManifest.requiredBefore, canonicalBatchOpeningManifest]

/-- Public openings are required before proving or verifying the masked relation. -/
theorem requiredBeforeProveMasked_containsPublicOpenings :
    DomainLabel.publicOpenings ∈
      canonicalBatchOpeningManifest.requiredBefore TranscriptStage.proveMaskedRelation := by
  simp [TranscriptBindingManifest.requiredBefore, canonicalBatchOpeningManifest]

end Core
end Shroud
