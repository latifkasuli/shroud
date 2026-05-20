# Maths First, Post-Zeta Second

## Purpose

This note explains why SHROUD should prioritize the remaining local protocol
maths before investing heavily in Plonky3 post-zeta recorder work.

The recommendation is not "do more abstract maths instead of shipping code."
It is more precise:

1. First, formalize the top-level claim boundary: SHROUD preserves a backend's
   stated hiding/ZK claim under explicit checks; it does not create a stronger
   cryptographic claim.
2. Then, return to post-zeta engineering as a scoped expansion of an already
   formalized claim boundary.

This keeps SHROUD honest while the Plonky3 bridge is intentionally frozen at the
current uni-stark pre-grind boundary.

## Current Codebase State

SHROUD now has a useful formal base.

Lean currently covers:

- `formal/Shroud/Core/Security.lean`: security-level vocabulary.
- `formal/Shroud/Core/Transcript.lean`: canonical transcript schedule and
  randomizer-before-OOD facts.
- `formal/Shroud/Core/Binding.lean`: domain labels, canonical manifest buckets,
  completeness, no-duplication, and required-before facts.
- `formal/Shroud/Core/Degree.lean`: batch-opening degree budget and quotient
  degree-contract laws.
- `formal/Shroud/Objects/*.lean`: first-pass payload/accounting models for
  batch opening, codeword embedding, oracle commitment, quotient hider, and
  opening projection.
- `formal/Shroud/Bridge/Plonky3/PreGrind.lean`: current Plonky3 uni-stark
  pre-grind event grammar, optional slot semantics, observed-vs-sampled event
  kinds, randomizer-before-zeta, and exclusion of post-zeta placeholder slots.

Rust currently provides executable evidence for:

- Canonical transcript bindings and domain-separated canonical bytes in
  `shroud-core`.
- Perfect-claim enforcement and object-surface validation across the protocol
  object crates.
- Live/deferred provenance via `TranscriptBindingSource`.
- The Plonky3 pre-grind bridge facade in `shroud-plonky3`.
- Fixed Lean/Rust drift fixtures in `shroud-conformance`, including canonical
  manifest buckets, payload/accounting examples, perfect-claim realization
  matching, quotient degree contracts, Plonky3 pre-grind source provenance, and
  optional extractor shapes.

Docs currently state:

- `docs/security-model.md`: the threat classes SHROUD closes and the ones it
  does not close.
- `docs/plonky3-bridge-status.md`: the frozen current Plonky3 boundary:
  uni-stark rows 1-10 are live/pre-grind; post-zeta opened values and FRI
  envelope slots are placeholders.
- `docs/Lean Normative Spec Restructure.md`: phase roadmap and theorem names.

This is a good foundation, but it is still mostly a collection of local laws.
The missing piece is the top-level composition statement.

## The Missing Maths

SHROUD still needs a small theorem layer for claim preservation.

The central statement should be:

```text
If a backend states a scoped hiding/ZK claim,
and SHROUD's local checks pass for that same scope,
then accepting through SHROUD preserves exactly that backend claim.

It does not strengthen the claim.
It does not extend the claim to unverified transcript regions.
It does not prove the upstream cryptography.
```

This is the theorem layer that makes SHROUD a formally specified audit layer
instead of only a set of checked protocol objects.

## Proposed Lean Module

Add:

```text
formal/Shroud/Core/Conformance.lean
```

The module should stay backend-neutral. It should define the vocabulary needed
to express scoped backend claims and SHROUD acceptance.

Recommended definitions:

```lean
namespace Shroud.Core

inductive ClaimScope where
  | coreBatchOpening
  | plonky3UniStarkPreGrind
  | plonky3FullFriReplay
  | whirHvzk

structure BackendClaim where
  securityLevel : SecurityLevel
  scope : ClaimScope
  assumesBackendHiding : Prop
  assumesBackendSoundness : Prop

structure ShroudChecks (scope : ClaimScope) where
  transcriptBound : Prop
  degreeValid : Prop
  payloadAccounted : Prop
  provenanceValid : Prop
  /-- The checked transcript/manifest/provenance surface covers exactly `scope`. -/
  scopeCovered : Prop

structure BackendConforms (claim : BackendClaim) where
  checks : ShroudChecks claim.scope
  checksPass :
    checks.transcriptBound
      /\ checks.degreeValid
      /\ checks.payloadAccounted
      /\ checks.provenanceValid
      /\ checks.scopeCovered

def ShroudAcceptedClaim (claim : BackendClaim) : BackendClaim := claim

theorem shroud_preserves_backend_claim
    (claim : BackendClaim)
    (h : BackendConforms claim) :
    ShroudAcceptedClaim claim = claim := by
  rfl

end Shroud.Core
```

The first theorem can be intentionally simple. Its value is the type shape:
SHROUD's accepted claim is the backend's scoped claim, and the checks are
indexed by that same scope rather than by an unrelated free proposition.

Later refinements can replace coarse `Prop` fields with concrete predicates
from `Core.Binding`, `Core.Degree`, `Objects.*`, and `Bridge.Plonky3.PreGrind`.

## Concrete Theorem Targets

The next local maths should prove claim-boundary theorems like these.

### 1. SHROUD Does Not Strengthen Backend Claims

Statement:

```text
For any accepted backend claim, the accepted claim has the same security level
and the same scope as the backend claim.
```

Why it matters:

This prevents accidental wording such as "Plonky3 privacy is supported" when
the actual claim is only "Plonky3 uni-stark pre-grind transcript binding is
live-checked."

### 2. Scope Coverage Is Required

Statement:

```text
BackendConforms claim carries `ShroudChecks claim.scope`, and those checks
include `scopeCovered`.
```

For current Plonky3:

```text
scope = plonky3UniStarkPreGrind
```

not:

```text
scope = plonky3FullFriReplay
```

Why it matters:

This makes post-zeta placeholder status part of the claim boundary, not just a
documentation convention.

### 3. Placeholder Sources Cannot Support Full-Live Claims

Statement:

```text
A claim whose scope requires full live replay cannot be justified by a record
containing placeholder bindings for required backend event slots.
```

Lean does not need Rust bytes here. It can model provenance abstractly:

```lean
inductive BindingSource where
  | declared
  | live
  | placeholder
```

and prove that a "full live" predicate excludes `placeholder`.

Why it matters:

The current Rust `Plonky3ReplayHarness::verify_full_live` already enforces this.
Lean should own the local theorem shape.

### 4. Plonky3 Current Claim Is Pre-Grind Only

Statement:

```text
The current Plonky3 pre-grind grammar covers rows 1-10 and excludes opened
values and FRI envelope events.
```

This mostly exists now through:

- `randomizerCommitment_before_sampleOodPoint`;
- `preGrindGrammar_contains_no_postZetaPlaceholders`;
- `preGrindGrammar_contains_only_liveEventKinds`;
- `postZetaPlaceholderEvents_not_livePreGrind`.

The conformance module should connect those facts to a `ClaimScope`.

### 5. Upstream Assumptions Are Explicit

Statement:

```text
SHROUD acceptance assumes, but does not prove, backend hiding and backend
soundness.
```

Why it matters:

This is the line between SHROUD's local protocol maths and upstream proofs such
as FRI/DEEP-FRI/STIR/WHIR soundness, HVZK-WHIR privacy, Habock-Kindi masking,
BCS/Fiat-Shamir theory, and sponge/ROM assumptions.

## Why Maths First

Post-zeta engineering is important, but it is blocked by concrete Plonky3
recorder mechanics.

The known blocker:

- `SerializingChallenger32::grind` clones the challenger inside Rayon search.
- Recording clones currently share the recorder tape.
- Losing proof-of-work candidates pollute the byte log.
- The recorder cannot cleanly distinguish the canonical winning path from
  speculative worker paths.

That is a real engineering task, but it does not change the immediate protocol
claim. Today, SHROUD must still say:

```text
Plonky3 support is live for uni-stark pre-grind rows 1-10.
Post-zeta opened values and FRI envelope slots are placeholders.
```

The maths-first work prevents this partial implementation from becoming an
accidental overclaim.

## Why Post-Zeta Second

Once the claim-preservation layer exists, post-zeta work becomes a controlled
scope expansion.

Instead of asking:

```text
Can we record more bytes?
```

we ask:

```text
Which ClaimScope are we expanding?
Which events move from placeholder to live?
Which Lean grammar changes?
Which Rust conformance fixtures prove the new boundary?
Which live negative tests cover the new threat class?
```

This is safer because every implementation change must update the formal claim
surface.

## Recommended Work Order

### Phase A: Claim-Preservation Maths

Add `formal/Shroud/Core/Conformance.lean`.

Define:

- `ClaimScope`;
- `BackendClaim`;
- `ShroudChecks (scope : ClaimScope)`;
- `BackendConforms`;
- `ShroudAcceptedClaim`;
- theorem `shroud_preserves_backend_claim`;
- theorem `accepted_claim_scope_eq_backend_scope`;
- theorem `accepted_claim_security_eq_backend_security`.

Keep the first pass deliberately abstract. The goal is to formalize the shape of
the claim boundary before threading every existing object theorem through it.

### Phase B: Plonky3 Scoped Claim

Add either:

```text
formal/Shroud/Bridge/Plonky3/Claim.lean
```

or extend:

```text
formal/Shroud/Bridge/Plonky3/PreGrind.lean
```

Define:

- `plonky3CurrentScope = ClaimScope.plonky3UniStarkPreGrind`;
- predicate `Plonky3PreGrindScopeCovered`;
- theorem that `preGrindGrammar_contains_no_postZetaPlaceholders` prevents the
  current scope from being treated as full FRI replay.

### Phase C: Rust API Alignment

Only after the Lean claim shape exists, decide whether to add a Rust surface
such as:

```rust
pub enum ClaimScope {
    CoreBatchOpening,
    Plonky3UniStarkPreGrind,
    Plonky3FullFriReplay,
    WhirHvzk,
}

pub trait BackendClaimSurface {
    fn claim_scope(&self) -> ClaimScope;
    fn verify_independent_checks(&self) -> Result<(), Self::Error>;
}
```

This is not urgent. The current docs and tests document the intended boundary
and reduce overclaiming risk. A Rust type can eventually make the boundary
harder to misuse.

### Phase D: Post-Zeta Engineering

Return to the recorder blocker.

Acceptable paths:

- recording-safe grind API upstream;
- SHROUD-side `prove_with_recording_challenger` fork;
- transactional recorder forks where losing worker tapes are discarded and the
  winning tape is committed.

Each path must come with:

- new `TranscriptEvent` constructors or grammar extension;
- new manifest slots moving from placeholder to live;
- conformance fixtures for event order and source provenance;
- live negative tests for mutation/dropping/reordering;
- bridge-status doc update moving rows from "Deferred" or "Placeholder" to
  "Supported, live-tested."

## Non-Goals

Do not reprove:

- FRI, DEEP-FRI, STIR, or WHIR soundness;
- HVZK-WHIR privacy;
- Habock-Kindi masking;
- BCS / Fiat-Shamir theory;
- sponge or ROM indifferentiability.

SHROUD should cite these as upstream assumptions. Its theorem layer should
prove only local correctness, binding, accounting, provenance, and scoped
backend conformance.

## Publication Framing

Recommended framing:

```text
SHROUD is a formally specified audit layer for structured hiding over
Reed-Solomon/FRI/WHIR-style oracle protocols. Its theorems prove local
correctness, accounting, transcript binding, provenance discipline, and
backend-conformance conditions. Cryptographic hiding and proximity soundness
are inherited from cited upstream systems under explicit scoped claims.
```

This is accurate to the current architecture and avoids pretending SHROUD is a
new PCS, a new ZK proof, or a proof of Plonky3 itself.

## Exit Criteria For Maths-First Work

The maths-first phase is done when:

- `formal/Shroud/Core/Conformance.lean` exists.
- SHROUD can state that accepted claims preserve backend scope and security
  level.
- Plonky3 current support is represented as `plonky3UniStarkPreGrind`, not full
  FRI replay.
- Placeholder provenance is incompatible with full-live claim scopes.
- Docs cite theorem names for the claim-boundary layer.
- `shroud-conformance` has at least one fixture proving Rust's current Plonky3
  accepted scope is pre-grind-only.

After that, post-zeta engineering becomes the next high-value implementation
track.
