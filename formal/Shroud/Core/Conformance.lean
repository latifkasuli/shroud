import Shroud.Core.Security

/-!
Normative claim-preservation layer for SHROUD.

This module formalizes the audit-layer thesis stated in
`docs/Maths First, Post-Zeta Second.md`:

> If a backend states a scoped hiding/ZK claim, and SHROUD's local checks pass
> for that same scope, then accepting through SHROUD preserves exactly that
> backend claim. It does not strengthen the claim. It does not extend the claim
> to unverified transcript regions. It does not prove the upstream cryptography.

The module is intentionally backend-neutral. Backend-specific instantiations
(Plonky3 pre-grind, Plonky3 full FRI replay, WHIR HVZK) live under
`Shroud.Bridge.*` and connect their grammar predicates to the abstract
`ShroudChecks` fields here.

Design posture (see `Maths First, Post-Zeta Second.md` brainstorm):

- `BackendClaim` carries only declared facts (scope + security level + an
  inspectable list of upstream citations). It does not embed deployment
  parameters; those are referenced from the backend bridge.
- `ShroudChecks (scope)` is phantom-parameterized by scope so two different
  scope's check bundles have distinct types — a typed firewall against passing
  a `plonky3UniStarkPreGrind` check bundle where a `plonky3FullFriReplay` one
  is expected.
- `AcceptedClaim` is a wrapper, not the identity function. Projections back to
  the underlying `BackendClaim` give structural — not tautological — facts
  that scope and security level are preserved.
- `BindingSource` mirrors Rust's `TranscriptBindingSource`. The
  placeholder-vs-live discipline is anchored by
  `BindingSource.isLiveAcceptable`.
- `ClaimScope.requiresFullLive` marks the scopes for which placeholder
  bindings must NOT appear. The Plonky3 current scope is **not** full-live;
  WHIR HVZK and Plonky3 full FRI replay are.

Upstream cryptographic theorems (FRI / DEEP-FRI / STIR / WHIR / HVZK-WHIR /
Haböck-Kindi / BCS / Fiat-Shamir / sponge indifferentiability) are NOT
re-proved here. They are cited by `UpstreamCitation` tags so a reader can
inspect what a given `BackendClaim` depends on.
-/

namespace Shroud
namespace Core

/-! ## Claim scope -/

/-- A SHROUD claim scope names exactly which backend events / oracle slots are
covered. Scope expansion is a PR — `ClaimScope` is intentionally a closed
inductive so adding a scope forces team review of the corresponding bridge
grammar, conformance fixtures, and live negative tests. -/
inductive ClaimScope where
  /-- SHROUD core protocol-object level only; no backend bridge attached. -/
  | coreBatchOpening
  /-- Plonky3 uni-stark transcript bound up to (and including) the ζ sample;
      post-zeta events are placeholders. Current production scope of
      `shroud-plonky3`. -/
  | plonky3UniStarkPreGrind
  /-- Plonky3 uni-stark transcript including PCS-internal post-grind events
      (opened values, FRI commit phase, final poly, log arities). Deferred until
      the grind clone-pollution blocker is resolved. -/
  | plonky3FullFriReplay
  /-- HVZK-WHIR PCS coverage; pivot target per
      `docs/HVZK-WHIR Impact on SHROUD.md`. Not yet implemented. -/
  | whirHvzk
  deriving BEq, DecidableEq, Repr

namespace ClaimScope

/-- Does this scope require every backend event to be sourced live (or
declared as static configuration), with no placeholder bindings? The current
Plonky3 pre-grind scope is intentionally NOT full-live — post-zeta slots are
placeholders. WHIR HVZK and Plonky3 full FRI replay ARE full-live. -/
def requiresFullLive : ClaimScope → Bool
  | coreBatchOpening => false
  | plonky3UniStarkPreGrind => false
  | plonky3FullFriReplay => true
  | whirHvzk => true

/-- Stable discriminant mirrored by the Rust `ClaimScope` enum once it lands. -/
def discriminant : ClaimScope → Nat
  | coreBatchOpening => 0
  | plonky3UniStarkPreGrind => 1
  | plonky3FullFriReplay => 2
  | whirHvzk => 3

/-- All four claim scopes have distinct discriminants. -/
theorem discriminants_distinct :
    [ (coreBatchOpening.discriminant)
    , (plonky3UniStarkPreGrind.discriminant)
    , (plonky3FullFriReplay.discriminant)
    , (whirHvzk.discriminant)
    ].Nodup := by
  decide

end ClaimScope

/-! ## Binding source provenance -/

/-- Provenance of a transcript binding, mirroring Rust's
`TranscriptBindingSource` enum. -/
inductive BindingSource where
  /-- Declared statically by SHROUD deployment configuration (e.g. profile,
      hash-suite identifier). Not from a live recorder, but not a stand-in for
      one either. -/
  | declared
  /-- Captured from a live backend transcript recorder. -/
  | live
  /-- Caller-supplied placeholder bytes — manifest-bound, not from a live
      recorder. Used today for post-zeta Plonky3 slots until phase 3. -/
  | placeholder
  deriving BEq, DecidableEq, Repr

namespace BindingSource

/-- Is this source acceptable for a full-live claim scope? `placeholder` is
explicitly rejected; `live` and `declared` are accepted. -/
def isLiveAcceptable : BindingSource → Bool
  | live => true
  | declared => true
  | placeholder => false

/-- A live source is always live-acceptable. -/
theorem live_isLiveAcceptable : isLiveAcceptable live = true := rfl

/-- A declared source is always live-acceptable (static SHROUD configuration
is not a placeholder for live backend bytes). -/
theorem declared_isLiveAcceptable : isLiveAcceptable declared = true := rfl

/-- A placeholder source is never live-acceptable. This is the formal
counterpart of Rust's `Plonky3ReplayHarness::verify_full_live` rejecting
`TranscriptBindingSource::Placeholder`. -/
theorem placeholder_not_liveAcceptable : isLiveAcceptable placeholder = false := rfl

end BindingSource

/-! ## Upstream citation surface -/

/-- Named upstream theorems SHROUD may rely on but does not re-prove. A
`BackendClaim`'s `citations` list makes these dependencies inspectable rather
than implicit. See `docs/SHROUD Maths Bibliography.md` for full references. -/
inductive UpstreamCitation where
  /-- BCS-IOP HVZK→ZK lift (Ben-Sasson-Chiesa-Spooner, ePrint 2016/116). -/
  | bcsIop
  /-- DEEP-FRI Johnson-bound soundness + OOD challenge mechanism (ePrint 2019/336). -/
  | deepFri
  /-- Reed-Solomon proximity-gap soundness (ePrint 2020/654). -/
  | proximityGaps
  /-- HVZK-WHIR ZK for constrained interleaved codes (ePrint 2026/391). -/
  | hvzkWhir
  /-- Haböck-Kindi vanishing-factor quotient masking (ePrint 2024/1037). -/
  | habockKindi
  /-- Aurora bounded-independence masking (ePrint 2018/828). -/
  | aurora
  /-- Ligero interleaved-RS masking (CCS 2017). -/
  | ligero
  /-- RedShift random codeword in interleaved batch (ePrint 2019/1400). -/
  | redshift
  /-- Bertoni sponge indifferentiability (EUROCRYPT 2008). -/
  | spongeIndifferentiability
  /-- Fiat-Shamir in the ROM, baseline (CRYPTO 1986). -/
  | fiatShamirRom
  /-- Chiesa-Orrù duplex-sponge Fiat-Shamir (ePrint 2025/536). -/
  | chiesaOrruSpongeFs
  deriving BEq, DecidableEq, Repr

namespace UpstreamCitation

/-- Stable cross-language discriminant for upstream citations. Mirrored by the
Rust `UpstreamCitation` enum's `#[repr(u32)]` discriminants in
`shroud-core`. -/
def discriminant : UpstreamCitation → Nat
  | bcsIop => 0
  | deepFri => 1
  | proximityGaps => 2
  | hvzkWhir => 3
  | habockKindi => 4
  | aurora => 5
  | ligero => 6
  | redshift => 7
  | spongeIndifferentiability => 8
  | fiatShamirRom => 9
  | chiesaOrruSpongeFs => 10

end UpstreamCitation

/-- All eleven upstream citations have distinct discriminants. -/
theorem upstreamCitation_discriminants_distinct :
    [ (UpstreamCitation.bcsIop.discriminant)
    , (UpstreamCitation.deepFri.discriminant)
    , (UpstreamCitation.proximityGaps.discriminant)
    , (UpstreamCitation.hvzkWhir.discriminant)
    , (UpstreamCitation.habockKindi.discriminant)
    , (UpstreamCitation.aurora.discriminant)
    , (UpstreamCitation.ligero.discriminant)
    , (UpstreamCitation.redshift.discriminant)
    , (UpstreamCitation.spongeIndifferentiability.discriminant)
    , (UpstreamCitation.fiatShamirRom.discriminant)
    , (UpstreamCitation.chiesaOrruSpongeFs.discriminant)
    ].Nodup := by
  decide

/-! ## Backend claim and SHROUD-side checks -/

/-- A backend's declared scoped claim. SHROUD's job is to accept this claim
under explicit local checks; it does not derive or strengthen it. -/
structure BackendClaim where
  /-- Declared hiding level. -/
  securityLevel : SecurityLevel
  /-- Declared scope (which transcript region the claim covers). -/
  scope : ClaimScope
  /-- Inspectable list of upstream theorems the claim depends on. -/
  citations : List UpstreamCitation
  deriving Repr

/-- Local SHROUD checks indexed by claim scope. The scope is a phantom
parameter — fields are uniform — but the type `ShroudChecks s₁` is distinct
from `ShroudChecks s₂` for distinct scopes, preventing cross-scope check
substitution. -/
structure ShroudChecks (_scope : ClaimScope) where
  /-- The transcript binding manifest exact-presence check holds. Discharged
      to `Shroud.Core.Binding.canonicalManifest_*` for `coreBatchOpening`. -/
  transcriptBound : Prop
  /-- The degree-accounting checks hold. Discharged to
      `Shroud.Core.Degree.DegreeBudget.Valid` and
      `QuotientDegreeContract.Valid`. -/
  degreeValid : Prop
  /-- Object-payload accounting holds. Discharged to `Shroud.Objects.*`. -/
  payloadAccounted : Prop
  /-- Provenance / advisory gates pass for the deployed backend. Discharged
      to the bridge's provenance gate (e.g.
      `shroud_plonky3::verify_provenance`). -/
  provenanceValid : Prop
  /-- Every backend event required by the scope is sourced live or declared,
      never placeholder. Discharged to a bridge-specific predicate (e.g.
      `Shroud.Bridge.Plonky3.PreGrind.Plonky3PreGrindScopeCovered`). -/
  scopeCovered : Prop

/-- Conformance witness for a `BackendClaim`: the checks bundle plus a proof
that each individual check holds. -/
structure BackendConforms (claim : BackendClaim) where
  /-- Scope-indexed check bundle. -/
  checks : ShroudChecks claim.scope
  /-- Proof that the transcript-binding check holds. -/
  transcriptBoundHolds : checks.transcriptBound
  /-- Proof that the degree-accounting check holds. -/
  degreeValidHolds : checks.degreeValid
  /-- Proof that the payload-accounting check holds. -/
  payloadAccountedHolds : checks.payloadAccounted
  /-- Proof that the provenance / advisory check holds. -/
  provenanceValidHolds : checks.provenanceValid
  /-- Proof that every scope-required event is sourced live or declared. -/
  scopeCoveredHolds : checks.scopeCovered

/-! ## SHROUD acceptance -/

/-- A SHROUD-accepted backend claim. Wraps the underlying `BackendClaim`
together with a conformance witness. This is intentionally a distinct type
from `BackendClaim` so the preservation theorems below are structural
projections (`rfl`-provable but type-disciplined) rather than identity
tautologies. -/
structure AcceptedClaim where
  /-- The original backend claim that SHROUD accepted. -/
  underlyingClaim : BackendClaim
  /-- The conformance witness that justified acceptance. -/
  conformanceWitness : BackendConforms underlyingClaim

namespace AcceptedClaim

/-- Scope of an accepted claim, projected from the underlying backend claim. -/
def scope (accepted : AcceptedClaim) : ClaimScope :=
  accepted.underlyingClaim.scope

/-- Security level of an accepted claim, projected from the underlying claim. -/
def securityLevel (accepted : AcceptedClaim) : SecurityLevel :=
  accepted.underlyingClaim.securityLevel

/-- Citations of an accepted claim, projected from the underlying claim. -/
def citations (accepted : AcceptedClaim) : List UpstreamCitation :=
  accepted.underlyingClaim.citations

end AcceptedClaim

/-- SHROUD acceptance: given a backend claim and a conformance witness,
produce an `AcceptedClaim`. The conformance witness is the only way to
construct an `AcceptedClaim`, so every accepted claim has all five checks
discharged. -/
def shroudAccept (claim : BackendClaim) (witness : BackendConforms claim) :
    AcceptedClaim where
  underlyingClaim := claim
  conformanceWitness := witness

/-! ## Preservation theorems -/

/-- SHROUD acceptance preserves the backend's declared scope. -/
theorem accept_preserves_scope
    (claim : BackendClaim) (witness : BackendConforms claim) :
    (shroudAccept claim witness).scope = claim.scope := rfl

/-- SHROUD acceptance preserves the backend's declared security level. -/
theorem accept_preserves_securityLevel
    (claim : BackendClaim) (witness : BackendConforms claim) :
    (shroudAccept claim witness).securityLevel = claim.securityLevel := rfl

/-- SHROUD acceptance preserves the backend's declared citations. -/
theorem accept_preserves_citations
    (claim : BackendClaim) (witness : BackendConforms claim) :
    (shroudAccept claim witness).citations = claim.citations := rfl

/-- SHROUD acceptance does not strengthen the backend claim: scope and
security level are exactly the backend's declared scope and security level.
This is the headline theorem promised by
`docs/Maths First, Post-Zeta Second.md`. -/
theorem accept_does_not_strengthen
    (claim : BackendClaim) (witness : BackendConforms claim) :
    (shroudAccept claim witness).scope = claim.scope ∧
    (shroudAccept claim witness).securityLevel = claim.securityLevel := by
  refine ⟨?_, ?_⟩
  · exact accept_preserves_scope claim witness
  · exact accept_preserves_securityLevel claim witness

/-! ## Placeholder / full-live discipline -/

/-- Whether a binding source is acceptable for the given claim scope.

- For **full-live** scopes (`requiresFullLive = true`), only `BindingSource`s
  that are individually live-acceptable are admitted; `placeholder` is
  rejected.
- For **non-full-live** scopes, every source is acceptable: placeholder
  bindings are part of the deliberate boundary (e.g. post-zeta slots in the
  current Plonky3 pre-grind scope).

This is the scope-indexed predicate that gives
`placeholderSource_incompatible_with_fullLive_scope` real content rather than
just restating `BindingSource.placeholder_not_liveAcceptable`. -/
def sourceAcceptableForScope (scope : ClaimScope) (source : BindingSource) : Bool :=
  if scope.requiresFullLive then source.isLiveAcceptable else true

/-- For any full-live claim scope, a placeholder binding source is rejected.

This is the scope-aware audit-layer thesis: a claim whose scope spans the
full live transcript cannot be justified by a record containing placeholder
bindings. Downstream code (bridge claim wrappers, Rust conformance fixtures)
cites this name. -/
theorem placeholderSource_incompatible_with_fullLive_scope
    (scope : ClaimScope) (h : scope.requiresFullLive = true) :
    sourceAcceptableForScope scope BindingSource.placeholder = false := by
  simp [sourceAcceptableForScope, h, BindingSource.placeholder_not_liveAcceptable]

/-- For any non-full-live claim scope, placeholder sources are acceptable.
Positive complement of `placeholderSource_incompatible_with_fullLive_scope`. -/
theorem placeholderSource_acceptable_for_nonFullLive_scope
    (scope : ClaimScope) (h : scope.requiresFullLive = false) :
    sourceAcceptableForScope scope BindingSource.placeholder = true := by
  simp [sourceAcceptableForScope, h]

/-- The current Plonky3 pre-grind scope is NOT a full-live scope. This is the
formal anchor for `docs/plonky3-bridge-status.md`'s claim that post-zeta
placeholders are intentional. -/
theorem plonky3UniStarkPreGrind_not_fullLive :
    ClaimScope.plonky3UniStarkPreGrind.requiresFullLive = false := rfl

/-- Corollary: placeholder bindings are acceptable for the current Plonky3
pre-grind scope. This is the precise formal counterpart of
`docs/plonky3-bridge-status.md`'s intentional-placeholder policy. -/
theorem placeholderSource_acceptable_for_plonky3UniStarkPreGrind :
    sourceAcceptableForScope ClaimScope.plonky3UniStarkPreGrind
        BindingSource.placeholder = true :=
  placeholderSource_acceptable_for_nonFullLive_scope _ plonky3UniStarkPreGrind_not_fullLive

/-- The Plonky3 full FRI replay scope is a full-live scope. When it lands,
post-zeta slots must move from `placeholder` to `live`. -/
theorem plonky3FullFriReplay_fullLive :
    ClaimScope.plonky3FullFriReplay.requiresFullLive = true := rfl

/-- Corollary: placeholder bindings are NOT acceptable for the Plonky3 full
FRI replay scope. -/
theorem placeholderSource_incompatible_with_plonky3FullFriReplay :
    sourceAcceptableForScope ClaimScope.plonky3FullFriReplay
        BindingSource.placeholder = false :=
  placeholderSource_incompatible_with_fullLive_scope _ plonky3FullFriReplay_fullLive

/-- The HVZK-WHIR scope is a full-live scope. -/
theorem whirHvzk_fullLive :
    ClaimScope.whirHvzk.requiresFullLive = true := rfl

/-- Corollary: placeholder bindings are NOT acceptable for the HVZK-WHIR
scope. -/
theorem placeholderSource_incompatible_with_whirHvzk :
    sourceAcceptableForScope ClaimScope.whirHvzk BindingSource.placeholder = false :=
  placeholderSource_incompatible_with_fullLive_scope _ whirHvzk_fullLive

/-- Core (no-backend) scope is not full-live — there is no backend transcript
to be live against. -/
theorem coreBatchOpening_not_fullLive :
    ClaimScope.coreBatchOpening.requiresFullLive = false := rfl

end Core
end Shroud
