# SHROUD And Stwo Compatibility Memo

This note deepens the downstream Stwo mapping into a compatibility memo.

The purpose is not to pretend that SHROUD v1 already drops into Stwo. The purpose is to make the boundary explicit:

- which SHROUD ideas are generic enough to carry over
- which SHROUD v1 assumptions fail in the Stwo setting
- what a future Stwo-oriented branch of SHROUD would actually need

## Executive Position

Stwo should currently be read as:

- strategically important for SHROUD
- not a direct SHROUD v1 backend
- the strongest test of whether SHROUD is really a protocol family rather than a renamed Plonky3 design

The reason is simple:

- SHROUD v1 is written for univariate Reed-Solomon + FRI stacks
- Stwo is a circle-STARK backend

So the right conclusion is not “unsupported forever.” It is:

> Stwo is the clearest candidate for a future SHROUD-Circle branch, but not a clean first-code target for SHROUD v1.

## SHROUD v1 Assumptions

The current SHROUD packet assumes:

1. univariate Reed-Solomon style codeword commitments
2. Merkle/MMCS-backed row openings over that codeword model
3. quotient or out-of-domain reductions stated in that same univariate setting
4. FRI low-degree testing whose hiding story can be layered on top of those assumptions

These assumptions are strong enough to define:

- `ShroudOracleCommitment`
- `ShroudCodewordEmbedding`
- `ShroudQuotientHider`
- `ShroudBatchOpening`
- `ShroudOpeningProjection`

They are also exactly the assumptions that become unstable in the Stwo setting.

## Where Stwo Diverges

Based on the current survey, the main divergence is not only “no hiding layer yet.”

It is also structural:

- the polynomial/domain model is not the standard SHROUD v1 univariate Reed-Solomon stack
- the degree/accounting story is therefore not just a plug-in replacement
- any quotient and batch-opening design would need to be restated against the circle-specific low-degree framework

That means Stwo is different from Winterfell.

For Winterfell, SHROUD mostly means “add the missing layers.”
For Stwo, SHROUD means “first decide which layers survive unchanged in the circle setting.”

## Object-By-Object Compatibility

### 1. `ShroudOracleCommitment`

This object is the most portable at the abstraction level.

What should transfer:

- the idea of hiding authenticated openings
- the separation between public queried values and hidden auxiliary opening material

What does not transfer automatically:

- any implicit assumption that the committed object is a standard Reed-Solomon row bundle over the SHROUD v1 domain model

Verdict:

- concept transfers
- exact backend contract must be restated

### 2. `ShroudCodewordEmbedding`

This is where compatibility becomes genuinely uncertain.

SHROUD v1 currently assumes:

- witness-facing evaluations can be embedded into hidden committed codewords in a way that matches the standard univariate FRI query model

For Stwo, the key question is:

- what is the correct analogue of “trace/codeword hiding before query exposure” in the circle setting?

Verdict:

- idea transfers
- concrete construction likely needs redesign

### 3. `ShroudQuotientHider`

This object depends on the exact quotient/reduction semantics of the backend.

In SHROUD v1, the quotient layer is already decomposition-sensitive even before circle-STARK concerns appear.

For Stwo, that means:

- the quotient-hider cannot simply be imported
- it would need a fresh statement against Stwo’s own reduction/arithmetic story

Verdict:

- high-level layer transfers
- concrete object does not transfer unchanged

### 4. `ShroudBatchOpening`

This is the sharpest compatibility point.

The SHROUD batch-opening object is built around:

- a final reduced opening relation
- an out-of-domain challenge point
- additive masking of that reduced relation
- a degree budget that remains compatible with the backend’s low-degree test

The general pattern may still survive in Stwo, but every important detail is backend-sensitive:

- what the reduced relation looks like
- which points are sampled
- how the masking term should be defined
- what degree budget is actually admissible

Verdict:

- the object almost certainly survives at the architectural level
- the protocol note would need a Stwo-specific restatement

### 5. `ShroudOpeningProjection`

This object is also highly portable.

The public-vs-hidden split is not specific to Reed-Solomon FRI. It is a protocol hygiene requirement:

- outer proofs should expose statement-level openings
- hiding witnesses and auxiliary openings should remain proof-internal when possible

Verdict:

- concept transfers cleanly
- proof-shape realization is backend-specific

## Compatibility Summary

| SHROUD object | Compatibility with Stwo | Why |
| --- | --- | --- |
| `ShroudOracleCommitment` | Medium | Concept transfers, contract must be restated |
| `ShroudCodewordEmbedding` | Low to medium | Hiding idea transfers, embedding construction is unclear |
| `ShroudQuotientHider` | Low | Quotient semantics are backend-sensitive |
| `ShroudBatchOpening` | Medium at the architectural level, low at the construction level | Layer survives, protocol needs circle-specific restatement |
| `ShroudOpeningProjection` | High | Public/hidden opening split is generic |

So the right reading is:

- SHROUD is relevant to Stwo
- SHROUD v1 is not sufficient as-is
- the main missing artifact is a circle-compatible reformulation, not just code work

## What A SHROUD-Circle Branch Would Need

If SHROUD eventually grows toward Stwo, the next branch would need to answer four concrete questions.

1. What is the right replacement for the SHROUD v1 codeword model?

This is the foundational question. Without it, the rest of the objects have no stable meaning.

2. What is the correct hiding analogue of trace/codeword embedding in the circle setting?

This determines whether the existing `ShroudCodewordEmbedding` object can be generalized or whether Stwo needs a sibling object with a different contract.

3. What does the reduced batch-opening relation look like in the circle setting?

This is the decisive question for whether `ShroudBatchOpening` becomes:

- a generalized object with multiple backend families
- or a separate `ShroudCircleBatchOpening` object

4. Can the same public-vs-hidden opening projection model be preserved?

If yes, SHROUD retains a strong cross-backend invariant even when the low-degree machinery changes.

## Recommended Next Artifact

The right next Stwo-specific document after this memo is:

- a circle-compatibility note that rewrites SHROUD assumptions in “portable / needs restatement / not yet defined” form

That note should not start with perfect zero-knowledge. It should start with:

- domain model
- opening model
- reduction model
- projection model

Only after those are stable does it make sense to revisit hiding variants.

## Final Position

Stwo is not evidence against SHROUD. It is evidence that SHROUD should be thought of as a family of hiding transforms with a clearly scoped v1.

For now, the most honest position is:

- SHROUD v1: not a direct Stwo integration target
- SHROUD beyond v1: Stwo is one of the most important backends to explain

That is a stronger position than either pretending Stwo already fits or excluding it from the project entirely.
