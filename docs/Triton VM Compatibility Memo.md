# SHROUD And Triton VM Compatibility Memo

This note deepens the downstream Triton VM mapping into a compatibility memo.

The goal is to make one question concrete:

- does Triton VM look like a real SHROUD v1 backend with missing layers
- or does it diverge enough that SHROUD would need a separate branch there too?

The current answer is more encouraging than the Stwo case:

- Triton VM appears compatible with the SHROUD v1 family at the architectural level
- but only part of the hiding story is visible today

So Triton VM should be read as a partial-mapping backend, not as a scope-exception backend.

## Executive Position

Triton VM should currently be read as:

- one of the best non-Plonky3 tests of SHROUD v1
- a backend with real hiding machinery already present
- a backend where SHROUD’s main value is formalization and completion rather than invention from zero

That makes Triton VM strategically important for a different reason than Stwo.

- Stwo tests the boundary of the protocol family
- Triton VM tests whether the family is genuinely broader than Plonky3 within that family

## What Seems To Exist Already

Based on the current survey, Triton VM appears to have:

- explicit trace-level randomization
- a randomized-trace domain story
- masking integrated into its trace/arithmetic flow

That is enough to say something meaningful:

- `ShroudCodewordEmbedding` appears to exist in ad hoc form already

The unresolved question is what happens after that layer.

## SHROUD v1 Assumptions Versus Triton VM

The current SHROUD packet assumes:

1. univariate Reed-Solomon style codeword commitments
2. Merkle/MMCS-backed row openings
3. quotient or out-of-domain reductions stated in that setting
4. FRI low-degree testing layered over those commitments

Unlike the Stwo case, nothing in the current Triton VM reading obviously breaks those assumptions at the family level.

The uncertainty is not:

- “does SHROUD v1 even apply?”

It is:

- “how many SHROUD layers are already present implicitly, and how many are still missing?”

That is a much better place for SHROUD to be.

## Object-By-Object Compatibility

### 1. `ShroudOracleCommitment`

Current status:

- unclear as a separately named hiding layer

What likely transfers:

- the idea of commitment/authentication hiding
- the need to keep auxiliary opening data out of the statement-level public surface

What remains unclear:

- whether Triton VM already achieves some of this implicitly through its current commitment/opening flow

Verdict:

- concept likely transfers cleanly
- current backend realization needs explicit audit

### 2. `ShroudCodewordEmbedding`

This is the strongest compatibility point.

Current status:

- present in ad hoc form through trace randomization

What transfers:

- the object itself
- the idea that witness-facing data must be masked before bounded queries are answered

What SHROUD adds:

- a named protocol layer
- an explicit contract for what the hiding budget is and what leakage it is meant to prevent

Verdict:

- high compatibility
- immediate candidate for first Triton-specific SHROUD mapping

### 3. `ShroudQuotientHider`

Current status:

- missing or unclear as a separate object

Why this matters:

- SHROUD treats quotient openings as an independent leakage surface
- current Triton VM discussion, at least in the survey, does not yet expose a quotient-hiding layer with that level of clarity

Verdict:

- the layer should transfer
- current realization is unknown or absent

### 4. `ShroudBatchOpening`

Current status:

- missing or unclear as a first-class object

Why this is the decisive compatibility question:

- if Triton VM already has a transcript location and reduction shape where a randomizer object could sit, then SHROUD maps naturally
- if not, that gap has to be made explicit before stronger claims are possible

The important difference from Stwo is:

- the question here appears to be one of missing structure, not incompatible structure

Verdict:

- medium to high compatibility at the architectural level
- implementation path depends on locating the real batch-opening surface precisely

### 5. `ShroudOpeningProjection`

Current status:

- unclear, not surfaced as an explicit contract

Why this matters:

- SHROUD wants to separate public opened values from hidden auxiliary material even when a backend already has some masking

Verdict:

- concept transfers cleanly
- likely missing as an explicit proof-shape discipline

## Compatibility Summary

| SHROUD object | Compatibility with Triton VM | Why |
| --- | --- | --- |
| `ShroudOracleCommitment` | Medium | Likely compatible, but current hiding contract is not surfaced explicitly |
| `ShroudCodewordEmbedding` | High | Existing trace randomization already points strongly at this layer |
| `ShroudQuotientHider` | Medium | Layer likely belongs here, but current realization is unclear |
| `ShroudBatchOpening` | Medium to high | Architectural fit looks plausible; concrete transcript/reduction seam must be identified |
| `ShroudOpeningProjection` | High at the concept level | Public/hidden split should transfer even if current proof shape does not expose it |

So the right reading is:

- Triton VM appears to be inside the SHROUD v1 family
- but only one layer is clearly visible today
- the rest need to be surfaced, not reinvented blindly

## What SHROUD Would Add

For Triton VM, SHROUD’s main contribution is:

- a vocabulary for separating the hiding story into layers
- an audit frame for deciding which layers already exist
- a way to state the missing quotient and batch-opening pieces precisely

That is why Triton VM is such a good next backend after Plonky3.

It is close enough to the SHROUD v1 family to matter, but different enough to prove the abstraction is not just Plonky3 terminology.

## Recommended Next Artifact

The right next Triton-specific document after this memo is:

- a layer audit that rewrites current Triton VM machinery in “present / partial / missing” form with direct code references

That audit should answer:

1. where the trace randomization belongs in SHROUD terms
2. whether quotient openings already carry implicit masking
3. what the true batch-opening surface is
4. whether the proof already has a hidden/public opening split or needs one

Only after that should SHROUD start proposing a Triton-specific strengthening.

## Final Position

Triton VM is the right next backend to deepen after Plonky3.

The current evidence suggests:

- Triton VM is not a SHROUD v1 scope exception
- Triton VM is a real partial-mapping backend
- the next missing step is a careful layer audit, not a brand-new protocol branch

That makes it a better immediate target than formalizing `SHROUD-Circle` right now.

That audit now exists as [Triton VM Layer Audit](Triton%20VM%20Layer%20Audit.md).

The narrower quotient-to-verifier seam note now exists as [Triton VM Batch Opening Seam](Triton%20VM%20Batch%20Opening%20Seam.md).
