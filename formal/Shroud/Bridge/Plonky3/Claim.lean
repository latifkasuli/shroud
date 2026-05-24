import Shroud.Core.Conformance
import Shroud.Core.Security
import Shroud.Bridge.Plonky3.PreGrind

/-!
Plonky3-specific scoped claim wiring.

This module connects the abstract `Shroud.Core.Conformance` vocabulary to the
concrete Plonky3 pre-grind grammar in `Shroud.Bridge.Plonky3.PreGrind`.

The current `shroud-plonky3` bridge accepts the `plonky3UniStarkPreGrind`
claim scope. This module:

- names that scope as `plonky3CurrentScope`,
- proves the scope identity (`plonky3CurrentScope_eq`,
  `plonky3CurrentScope_discriminant_eq`),
- defines `Plonky3PreGrindScopeCovered` — the predicate that discharges the
  `ShroudChecks.scopeCovered` slot for this scope,
- proves it holds for every supported AIR shape
  (`plonky3PreGrindScopeCovered_holds`),
- exhibits a worked-example `BackendClaim` for the current deployment
  (`examplePlonky3UniStarkPreGrindClaim`),
- and proves the current scope cannot masquerade as a full-live scope
  (`plonky3CurrentScope_ne_fullFriReplay`,
  `plonky3CurrentScope_ne_whirHvzk`).

Phase C has landed: the Rust `shroud_core::ClaimScope` enum mirrors
`plonky3CurrentScope` constructively (matching discriminants), and
`Plonky3VerifiedLiveInput` implements `BackendClaimSurface` to expose the
typed scope from Rust. Phase D will move the post-zeta placeholders to live
bindings, at which point the accepted scope must change to
`plonky3FullFriReplay`.
-/

namespace Shroud
namespace Bridge
namespace Plonky3

open Shroud.Core

/-! ## Current Plonky3 scope identity -/

/-- The claim scope the current `shroud-plonky3` bridge accepts.

Frozen by `docs/plonky3-bridge-status.md`: pre-grind uni-stark rows 1-10
live-bound, post-zeta opened-values / FRI envelope slots intentionally
placeholder. -/
def plonky3CurrentScope : ClaimScope := ClaimScope.plonky3UniStarkPreGrind

/-- The current scope IS `plonky3UniStarkPreGrind`. (Allows downstream code
to refer to the alias without unfolding it.) -/
theorem plonky3CurrentScope_eq :
    plonky3CurrentScope = ClaimScope.plonky3UniStarkPreGrind := rfl

/-- The current scope is NOT a full-live scope. Direct consequence of
`Shroud.Core.plonky3UniStarkPreGrind_not_fullLive`. -/
theorem plonky3CurrentScope_not_fullLive :
    plonky3CurrentScope.requiresFullLive = false := rfl

/-- Stable cross-language identifier for the current scope. Mirrored by the
`PLONKY3_CURRENT_SCOPE_DISCRIMINANT` constant in `crates/shroud-conformance`. -/
theorem plonky3CurrentScope_discriminant_eq :
    plonky3CurrentScope.discriminant = 1 := rfl

/-- The current scope is distinct from the deferred Plonky3 full FRI replay
scope. This is the formal counterpart of "pre-grind cannot masquerade as full
FRI replay" promised by `docs/Maths First, Post-Zeta Second.md`. -/
theorem plonky3CurrentScope_ne_fullFriReplay :
    plonky3CurrentScope ≠ ClaimScope.plonky3FullFriReplay := by
  decide

/-- The current scope is distinct from the WHIR HVZK scope. -/
theorem plonky3CurrentScope_ne_whirHvzk :
    plonky3CurrentScope ≠ ClaimScope.whirHvzk := by
  decide

/-! ## Scope coverage for the pre-grind bridge -/

/-- Scope-coverage predicate for `plonky3CurrentScope`. Captures the two
grammar-level guarantees that justify accepting the pre-grind scope without
admitting post-zeta placeholders into the live region:

1. every event in the live grammar is a live event kind, and
2. no post-zeta placeholder event appears in the live grammar.

This is the concrete predicate that discharges the abstract
`ShroudChecks.scopeCovered : Prop` slot when the scope is
`plonky3CurrentScope`. -/
structure Plonky3PreGrindScopeCovered (shape : PreGrindShape) : Prop where
  /-- Every event in the live grammar is observed-block or sampled-challenge. -/
  allEventsLive : ∀ event,
    event ∈ preGrindGrammar shape → isLivePreGrindEvent event = true
  /-- No post-zeta placeholder event appears in the live grammar. -/
  noPostZetaPlaceholders : ∀ event,
    event ∈ preGrindGrammar shape → isPostZetaPlaceholder event = false

/-- Scope coverage holds for every supported AIR shape. Composes
`preGrindGrammar_contains_only_liveEventKinds` and
`preGrindGrammar_contains_no_postZetaPlaceholders`. -/
theorem plonky3PreGrindScopeCovered_holds (shape : PreGrindShape) :
    Plonky3PreGrindScopeCovered shape where
  allEventsLive := preGrindGrammar_contains_only_liveEventKinds shape
  noPostZetaPlaceholders := preGrindGrammar_contains_no_postZetaPlaceholders shape

/-- The standard reference shape satisfies the scope-coverage predicate. -/
theorem plonky3PreGrindScopeCovered_standard :
    Plonky3PreGrindScopeCovered PreGrindShape.standard :=
  plonky3PreGrindScopeCovered_holds PreGrindShape.standard

/-! ## Worked-example BackendClaim -/

/-- Upstream theorems the standard Plonky3 statistical deployment depends on.
See `docs/SHROUD Maths Bibliography.md` for full references. -/
def plonky3StandardCitations : List UpstreamCitation :=
  [ UpstreamCitation.bcsIop                       -- BCS HVZK→ZK lift in ROM
  , UpstreamCitation.deepFri                      -- DEEP-FRI Johnson-bound soundness
  , UpstreamCitation.proximityGaps                -- RS proximity-gap soundness
  , UpstreamCitation.habockKindi                  -- Vanishing-factor quotient masking
  , UpstreamCitation.aurora                       -- Bounded-independence masking
  , UpstreamCitation.ligero                       -- Interleaved-RS masking
  , UpstreamCitation.redshift                     -- Random codeword in interleaved batch
  , UpstreamCitation.spongeIndifferentiability    -- Keccak256 sponge indifferentiability
  , UpstreamCitation.chiesaOrruSpongeFs           -- Duplex-sponge FS transcript
  ]

/-- Worked example: a `BackendClaim` for the standard Plonky3 statistical
deployment. Demonstrates the Conformance layer in use; cited by Phase B
proofs and by `crates/shroud-conformance` fixtures. -/
def examplePlonky3UniStarkPreGrindClaim : BackendClaim where
  securityLevel := SecurityLevel.statistical
  scope := plonky3CurrentScope
  citations := plonky3StandardCitations

/-- The example claim's scope is the current Plonky3 scope. -/
theorem examplePlonky3Claim_scope :
    examplePlonky3UniStarkPreGrindClaim.scope = plonky3CurrentScope := rfl

/-- The example claim's scope is NOT a full-live scope. Composition with
`Shroud.Core.placeholderSource_acceptable_for_plonky3UniStarkPreGrind` gives
the headline thesis: placeholder bindings are admissible in this claim. -/
theorem examplePlonky3Claim_not_fullLive :
    examplePlonky3UniStarkPreGrindClaim.scope.requiresFullLive = false := rfl

/-- The example claim's security level is statistical. -/
theorem examplePlonky3Claim_statistical :
    examplePlonky3UniStarkPreGrindClaim.securityLevel = SecurityLevel.statistical := rfl

/-- The example claim's scope is NOT the full FRI replay scope. -/
theorem examplePlonky3Claim_ne_fullFriReplay :
    examplePlonky3UniStarkPreGrindClaim.scope ≠ ClaimScope.plonky3FullFriReplay :=
  plonky3CurrentScope_ne_fullFriReplay

/-- The example claim's scope is NOT the WHIR HVZK scope. -/
theorem examplePlonky3Claim_ne_whirHvzk :
    examplePlonky3UniStarkPreGrindClaim.scope ≠ ClaimScope.whirHvzk :=
  plonky3CurrentScope_ne_whirHvzk

/-! ## Acceptance preserves the example claim -/

/-- For any conformance witness, SHROUD acceptance preserves the example
claim's scope. Direct specialization of
`Shroud.Core.accept_preserves_scope`. -/
theorem accept_examplePlonky3Claim_preserves_scope
    (witness : BackendConforms examplePlonky3UniStarkPreGrindClaim) :
    (shroudAccept examplePlonky3UniStarkPreGrindClaim witness).scope =
      plonky3CurrentScope :=
  accept_preserves_scope examplePlonky3UniStarkPreGrindClaim witness

/-- For any conformance witness, SHROUD acceptance preserves the example
claim's security level. -/
theorem accept_examplePlonky3Claim_preserves_securityLevel
    (witness : BackendConforms examplePlonky3UniStarkPreGrindClaim) :
    (shroudAccept examplePlonky3UniStarkPreGrindClaim witness).securityLevel =
      SecurityLevel.statistical :=
  accept_preserves_securityLevel examplePlonky3UniStarkPreGrindClaim witness

/-- For any conformance witness, SHROUD acceptance preserves the example
claim's citation list. -/
theorem accept_examplePlonky3Claim_preserves_citations
    (witness : BackendConforms examplePlonky3UniStarkPreGrindClaim) :
    (shroudAccept examplePlonky3UniStarkPreGrindClaim witness).citations =
      plonky3StandardCitations :=
  accept_preserves_citations examplePlonky3UniStarkPreGrindClaim witness

end Plonky3
end Bridge
end Shroud
