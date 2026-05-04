# SHROUD To Winterfell Mapping

This note is a backend-specific downstream mapping for Winterfell.

It is not part of the SHROUD protocol definition. It records how SHROUD would land in a backend that currently appears to acknowledge the zero-knowledge gap explicitly but does not yet implement a structured hiding stack.

## Current Reading

In the current survey, Winterfell has:

- no structured oracle-hiding layer
- no structured trace/codeword hiding layer
- no structured quotient-hiding layer
- no structured batch-opening randomizer layer
- no structured public-vs-hidden opening projection layer

That makes Winterfell a greenfield SHROUD target.

## Why Winterfell Matters

Winterfell is a particularly clean downstream case because the current project framing already acknowledges that its proofs are not yet perfect zero-knowledge.

So SHROUD’s value here is direct:

- turn an explicit non-goal into a roadmap
- replace “not yet” with a concrete layer decomposition
- provide a reusable hiding architecture instead of one-off patches

## SHROUD Layer Status

| SHROUD object | Current status in Winterfell | Immediate implication |
| --- | --- | --- |
| `ShroudOracleCommitment` | Missing | Would need a hiding/authenticated commitment path |
| `ShroudCodewordEmbedding` | Missing | Would need trace masking before FRI queries |
| `ShroudQuotientHider` | Missing | Would need quotient masking as a separate layer |
| `ShroudBatchOpening` | Missing | Would need a randomizer commitment/opening contract |
| `ShroudOpeningProjection` | Missing | Would need explicit separation of public and hidden openings |

## What SHROUD Would Mean Here

For Winterfell, SHROUD is a full privacy blueprint.

The first integration sequence would be:

1. introduce a hiding commitment/authentication layer
2. introduce trace/codeword hiding before queries
3. introduce quotient hiding
4. introduce batch-opening hiding
5. define the public-vs-hidden opening boundary explicitly

That is a much larger effort than the Plonky3 mapping, but it is still the same protocol story.

## First Sensible Path

The first realistic Winterfell-oriented note after this one would be:

- a minimal adoption path that stops at statistical SHROUD first

That would answer:

- what the smallest meaningful hiding claim for Winterfell would be
- which APIs would have to grow hidden opening support
- whether the batch-opening layer can reuse existing proof layout or needs a new surface

## Strategic Value

If SHROUD eventually lands outside Plonky3, Winterfell is one of the clearest “why this matters” examples:

- there is already an explicit gap
- the backend is close enough to SHROUD v1 assumptions to make the comparison meaningful
- the contribution would be a first zero-knowledge architecture, not a small refinement
