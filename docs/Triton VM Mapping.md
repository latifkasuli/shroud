# SHROUD To Triton VM Mapping

This note is a backend-specific downstream mapping for Triton VM.

It is not part of the SHROUD protocol definition. It records how SHROUD would apply to a backend that appears to have real trace-level hiding machinery but not yet a complete structured hiding stack.

## Current Reading

In the current survey, Triton VM has:

- real trace randomization
- a randomized-trace domain story
- masking tied to its own trace/domain arithmetic
- no clearly separated quotient-hiding layer
- no clearly separated batch-opening hiding layer
- no clearly stated public-vs-hidden opening projection layer

That makes Triton VM a partial-mapping target.

## SHROUD Layer Status

| SHROUD object | Current status in Triton VM | Immediate implication |
| --- | --- | --- |
| `ShroudOracleCommitment` | Unclear as a separate layer | May already exist implicitly, but not surfaced as a hiding object |
| `ShroudCodewordEmbedding` | Present in ad hoc form | Existing trace randomization should be recast as a named layer |
| `ShroudQuotientHider` | Missing or unclear | Would need an explicit quotient masking story |
| `ShroudBatchOpening` | Missing or unclear | Would need a first-class randomizer object |
| `ShroudOpeningProjection` | Unclear | Would need a public-vs-hidden opening contract |

## What SHROUD Would Mean Here

For Triton VM, SHROUD is mainly a formalization-and-completion project.

The point is not to invent privacy from zero. The point is to:

- isolate the existing trace-randomization mechanism as `ShroudCodewordEmbedding`
- identify the missing quotient and batch-opening layers explicitly
- make the public/hidden opening boundary visible at the protocol level

## First Sensible Path

The first realistic Triton-oriented sequence would be:

1. extract the current trace randomization into a named SHROUD layer mapping
2. determine whether quotient openings are already masked implicitly or not masked at all
3. identify the transcript point where a batch-opening randomizer would have to sit
4. define which opened values are statement-level public and which should remain hidden auxiliary material

Only after that does it make sense to ask about the perfect variant.

## Strategic Value

Triton VM is useful for SHROUD because it tests whether the protocol can absorb an already-partial design without flattening it into Plonky3 terminology.

If SHROUD can map cleanly onto Triton VM, that is good evidence that the protocol objects are real abstractions rather than renamed Plonky3 internals.

For the deeper version of this argument, see [Triton VM Compatibility Memo](Triton%20VM%20Compatibility%20Memo.md).

For the first code-referenced classification of Triton VM’s current layers, see [Triton VM Layer Audit](Triton%20VM%20Layer%20Audit.md).
