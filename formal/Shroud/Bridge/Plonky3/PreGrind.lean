import Shroud.Core.Transcript

/-!
Normative bridge grammar for the current Plonky3 pre-grind boundary.

This module models the event slots that `shroud-plonky3` can extract from a
live `HidingFriPcs` prove transcript before the Rayon grind clone-pollution
boundary. It intentionally stops at the zeta sample. Post-zeta opened values
and FRI envelope bytes are bridge placeholders in Rust until live extraction is
extended.
-/

namespace Shroud
namespace Bridge
namespace Plonky3

open Shroud.Core

/-- Plonky3 transcript event slots relevant to the current SHROUD bridge. -/
inductive TranscriptEvent where
  /-- Event 1: extension-degree log. -/
  | logExtDegree
  /-- Event 2: trace-domain log degree. -/
  | logDegree
  /-- Event 3: preprocessed trace width. -/
  | preprocessedWidth
  /-- Event 4: main trace commitment. -/
  | traceCommitment
  /-- Event 5: optional preprocessed commitment. -/
  | preprocessedCommitment
  /-- Event 6: AIR public values. -/
  | airPublicValues
  /-- Event 7: batching challenge alpha. -/
  | sampleBatchingChallenge
  /-- Event 8: quotient commitment. -/
  | quotientCommitment
  /-- Event 9: hiding randomizer commitment. -/
  | randomizerCommitment
  /-- Event 10: OOD challenge zeta. -/
  | sampleOodPoint
  /-- Event 12: opened values, currently post-zeta placeholder material. -/
  | openedValues
  /-- Event 14: FRI commit-phase commitments, currently placeholder material. -/
  | friCommitPhaseCommitments
  /-- Event 17: FRI final polynomial, currently placeholder material. -/
  | friFinalPoly
  /-- Event 18: FRI log arities, currently placeholder material. -/
  | friLogArities
  deriving BEq, DecidableEq, Repr

/-- Shape parameters that affect which pre-grind slots exist. -/
structure PreGrindShape where
  /-- Whether the AIR has a preprocessed-commitment event. -/
  hasPreprocessedCommitment : Bool
  /-- Whether the AIR contributes a non-empty AIR-public-values event. -/
  hasAirPublicValues : Bool
  deriving Repr

namespace PreGrindShape

/-- Standard reference bridge shape: no preprocessed commitment or AIR public values. -/
def standard : PreGrindShape where
  hasPreprocessedCommitment := false
  hasAirPublicValues := false

end PreGrindShape

/-- Events that are always present in the pre-grind grammar. -/
def mandatoryPreGrindEvents : List TranscriptEvent :=
  [ TranscriptEvent.logExtDegree
  , TranscriptEvent.logDegree
  , TranscriptEvent.preprocessedWidth
  , TranscriptEvent.traceCommitment
  , TranscriptEvent.sampleBatchingChallenge
  , TranscriptEvent.quotientCommitment
  , TranscriptEvent.randomizerCommitment
  , TranscriptEvent.sampleOodPoint
  ]

/-- Mandatory byte-block events read with Rust's `read_observed_block`. -/
def mandatoryObservedPreGrindEvents : List TranscriptEvent :=
  [ TranscriptEvent.logExtDegree
  , TranscriptEvent.logDegree
  , TranscriptEvent.preprocessedWidth
  , TranscriptEvent.traceCommitment
  , TranscriptEvent.quotientCommitment
  , TranscriptEvent.randomizerCommitment
  ]

/-- Challenge-sample events read with Rust's `read_sampled_block`. -/
def sampledPreGrindEvents : List TranscriptEvent :=
  [ TranscriptEvent.sampleBatchingChallenge
  , TranscriptEvent.sampleOodPoint
  ]

/-- Post-zeta slots that Rust currently records as placeholders, not live pre-grind events. -/
def postZetaPlaceholderEvents : List TranscriptEvent :=
  [ TranscriptEvent.openedValues
  , TranscriptEvent.friCommitPhaseCommitments
  , TranscriptEvent.friFinalPoly
  , TranscriptEvent.friLogArities
  ]

/-- Current live-extractable Plonky3 pre-grind grammar for a given AIR shape. -/
def preGrindGrammar (shape : PreGrindShape) : List TranscriptEvent :=
  [ TranscriptEvent.logExtDegree
  , TranscriptEvent.logDegree
  , TranscriptEvent.preprocessedWidth
  , TranscriptEvent.traceCommitment
  ]
  ++ (if shape.hasPreprocessedCommitment then
      [TranscriptEvent.preprocessedCommitment]
    else
      [])
  ++ (if shape.hasAirPublicValues then
      [TranscriptEvent.airPublicValues]
    else
      [])
  ++ [ TranscriptEvent.sampleBatchingChallenge
     , TranscriptEvent.quotientCommitment
     , TranscriptEvent.randomizerCommitment
     , TranscriptEvent.sampleOodPoint
     ]

/-- Shape-specific byte-block events read with Rust's `read_observed_block`. -/
def observedPreGrindEvents (shape : PreGrindShape) : List TranscriptEvent :=
  [ TranscriptEvent.logExtDegree
  , TranscriptEvent.logDegree
  , TranscriptEvent.preprocessedWidth
  , TranscriptEvent.traceCommitment
  ]
  ++ (if shape.hasPreprocessedCommitment then
      [TranscriptEvent.preprocessedCommitment]
    else
      [])
  ++ (if shape.hasAirPublicValues then
      [TranscriptEvent.airPublicValues]
    else
      [])
  ++ [ TranscriptEvent.quotientCommitment
     , TranscriptEvent.randomizerCommitment
     ]

/-- Index of a Plonky3 event in the shape-specific pre-grind grammar. -/
def preGrindGrammarIndex (shape : PreGrindShape) (event : TranscriptEvent) : Nat :=
  (preGrindGrammar shape).idxOf event

/-- Whether a slot is a live observed byte block in the current extractor. -/
def isObservedBlock : TranscriptEvent -> Bool
  | TranscriptEvent.logExtDegree => true
  | TranscriptEvent.logDegree => true
  | TranscriptEvent.preprocessedWidth => true
  | TranscriptEvent.traceCommitment => true
  | TranscriptEvent.preprocessedCommitment => true
  | TranscriptEvent.airPublicValues => true
  | TranscriptEvent.quotientCommitment => true
  | TranscriptEvent.randomizerCommitment => true
  | _ => false

/-- Whether a slot is a sampled challenge in the current extractor. -/
def isSampledChallenge : TranscriptEvent -> Bool
  | TranscriptEvent.sampleBatchingChallenge => true
  | TranscriptEvent.sampleOodPoint => true
  | _ => false

/-- Whether a slot is live pre-grind material rather than placeholder material. -/
def isLivePreGrindEvent (event : TranscriptEvent) : Bool :=
  isObservedBlock event || isSampledChallenge event

/-- Predicate for post-zeta placeholder slots excluded from live pre-grind extraction. -/
def isPostZetaPlaceholder : TranscriptEvent -> Bool
  | TranscriptEvent.openedValues => true
  | TranscriptEvent.friCommitPhaseCommitments => true
  | TranscriptEvent.friFinalPoly => true
  | TranscriptEvent.friLogArities => true
  | _ => false

/-- Every mandatory pre-grind event appears in every shape-specific grammar. -/
theorem mandatoryPreGrindEvents_mem
    (shape : PreGrindShape) :
    ∀ event, event ∈ mandatoryPreGrindEvents -> event ∈ preGrindGrammar shape := by
  intro event hEvent
  rcases shape with ⟨hasPreprocessedCommitment, hasAirPublicValues⟩
  cases hasPreprocessedCommitment <;>
    cases hasAirPublicValues <;>
    cases event <;>
    simp [mandatoryPreGrindEvents, preGrindGrammar] at hEvent ⊢

/-- Every mandatory observed byte-block event has observed-block kind. -/
theorem mandatoryObservedPreGrindEvents_are_observed :
    ∀ event, event ∈ mandatoryObservedPreGrindEvents -> isObservedBlock event = true := by
  intro event hEvent
  cases event <;>
    simp [mandatoryObservedPreGrindEvents, isObservedBlock] at hEvent ⊢

/-- Every sampled pre-grind event has sampled-challenge kind. -/
theorem sampledPreGrindEvents_are_sampled :
    ∀ event, event ∈ sampledPreGrindEvents -> isSampledChallenge event = true := by
  intro event hEvent
  cases event <;>
    simp [sampledPreGrindEvents, isSampledChallenge] at hEvent ⊢

/-- Every shape-specific observed event has observed-block kind. -/
theorem observedPreGrindEvents_are_observed
    (shape : PreGrindShape) :
    ∀ event, event ∈ observedPreGrindEvents shape -> isObservedBlock event = true := by
  intro event hEvent
  rcases shape with ⟨hasPreprocessedCommitment, hasAirPublicValues⟩
  cases hasPreprocessedCommitment <;>
    cases hasAirPublicValues <;>
    cases event <;>
    simp [observedPreGrindEvents, isObservedBlock] at hEvent ⊢

/-- The pre-grind grammar contains only observed byte blocks or sampled challenges. -/
theorem preGrindGrammar_contains_only_liveEventKinds
    (shape : PreGrindShape) :
    ∀ event, event ∈ preGrindGrammar shape -> isLivePreGrindEvent event = true := by
  intro event hEvent
  rcases shape with ⟨hasPreprocessedCommitment, hasAirPublicValues⟩
  cases hasPreprocessedCommitment <;>
    cases hasAirPublicValues <;>
    cases event <;>
    simp [preGrindGrammar, isLivePreGrindEvent, isObservedBlock, isSampledChallenge] at hEvent ⊢

/-- Post-zeta placeholder slots are not live observed blocks or sampled challenges. -/
theorem postZetaPlaceholderEvents_not_livePreGrind :
    ∀ event, event ∈ postZetaPlaceholderEvents -> isLivePreGrindEvent event = false := by
  intro event hEvent
  cases event <;>
    simp [postZetaPlaceholderEvents, isLivePreGrindEvent, isObservedBlock, isSampledChallenge]
      at hEvent ⊢

/-- The optional preprocessed commitment appears exactly when the shape declares it. -/
theorem preprocessedCommitment_mem_iff
    (shape : PreGrindShape) :
    TranscriptEvent.preprocessedCommitment ∈ preGrindGrammar shape
      ↔ shape.hasPreprocessedCommitment = true := by
  rcases shape with ⟨hasPreprocessedCommitment, hasAirPublicValues⟩
  cases hasPreprocessedCommitment <;>
    cases hasAirPublicValues <;>
    simp [preGrindGrammar]

/-- AIR public values appear exactly when the shape declares a non-empty payload. -/
theorem airPublicValues_mem_iff
    (shape : PreGrindShape) :
    TranscriptEvent.airPublicValues ∈ preGrindGrammar shape
      ↔ shape.hasAirPublicValues = true := by
  rcases shape with ⟨hasPreprocessedCommitment, hasAirPublicValues⟩
  cases hasPreprocessedCommitment <;>
    cases hasAirPublicValues <;>
    simp [preGrindGrammar]

/-- In every supported shape, the Plonky3 randomizer commitment precedes zeta. -/
theorem randomizerCommitment_before_sampleOodPoint
    (shape : PreGrindShape) :
    preGrindGrammarIndex shape TranscriptEvent.randomizerCommitment
      < preGrindGrammarIndex shape TranscriptEvent.sampleOodPoint := by
  rcases shape with ⟨hasPreprocessedCommitment, hasAirPublicValues⟩
  cases hasPreprocessedCommitment <;>
    cases hasAirPublicValues <;>
    decide

/--
The pre-grind grammar contains no post-zeta placeholder slots.

This theorem is the Lean counterpart of Rust's current
`build_pre_grind_harness_input` boundary: opened values and FRI slots may exist
in the manifest/record, but they are not live pre-grind extraction events.
-/
theorem preGrindGrammar_contains_no_postZetaPlaceholders
    (shape : PreGrindShape) :
    ∀ event, event ∈ preGrindGrammar shape -> isPostZetaPlaceholder event = false := by
  intro event hEvent
  rcases shape with ⟨hasPreprocessedCommitment, hasAirPublicValues⟩
  cases hasPreprocessedCommitment <;>
    cases hasAirPublicValues <;>
    cases event <;>
    simp [preGrindGrammar, isPostZetaPlaceholder] at hEvent ⊢

/-- The standard Plonky3 pre-grind shape still observes randomizer before zeta. -/
theorem standard_randomizerCommitment_before_sampleOodPoint :
    preGrindGrammarIndex PreGrindShape.standard TranscriptEvent.randomizerCommitment
      < preGrindGrammarIndex PreGrindShape.standard TranscriptEvent.sampleOodPoint :=
  randomizerCommitment_before_sampleOodPoint PreGrindShape.standard

end Plonky3
end Bridge
end Shroud
