# SHROUD To Stwo Mapping

This note is a backend-specific downstream mapping for Stwo.

It is not part of the SHROUD protocol definition. It is a gap-analysis and integration-stub note for a backend that currently appears to have no structured hiding layer.

## Current Reading

In the current survey, Stwo has:

- no explicit oracle-hiding layer
- no explicit trace/codeword hiding layer
- no explicit quotient-hiding layer
- no explicit batch-opening randomizer layer
- no explicit public-vs-hidden opening projection layer

That makes Stwo a greenfield privacy target rather than a refinement target.

## Scope Caveat

Stwo is also the main backend that stresses SHROUD v1 scope boundaries.

SHROUD v1 is written for univariate Reed-Solomon + FRI stacks and explicitly does not try to cover every circle-STARK variant. So this note should be read as:

- a downstream gap-analysis stub
- not a claim that SHROUD v1 drops into Stwo unchanged

If SHROUD later grows a circle-oriented branch, Stwo is the natural first target for that extension.

For the deeper version of this argument, see [Stwo Compatibility Memo](Stwo%20Compatibility%20Memo.md).

## SHROUD Layer Status

| SHROUD object | Current status in Stwo | Immediate implication |
| --- | --- | --- |
| `ShroudOracleCommitment` | Missing | Would need a hiding/authenticated commitment story |
| `ShroudCodewordEmbedding` | Missing | Would need witness/trace masking before query exposure |
| `ShroudQuotientHider` | Missing | Would need quotient masking as a first-class layer |
| `ShroudBatchOpening` | Missing | Would need a randomizer object and transcript placement |
| `ShroudOpeningProjection` | Missing | Would need a public-vs-hidden opening contract |

## What SHROUD Would Mean Here

For Stwo, SHROUD is not “upgrade statistical ZK to perfect ZK.”

It is:

- the first structured hiding architecture
- a layer decomposition for a backend that currently appears to provide computational integrity only
- a blueprint for turning privacy into a protocol concern rather than an afterthought

## First Sensible Path

The first sensible Stwo path is not to start with the perfect batch-opening variant.

It is:

1. decide whether a SHROUD-like layer decomposition even transfers cleanly to the circle setting
2. define an oracle-commitment and codeword-embedding story for Stwo first
3. only then ask how quotient hiding and batch-opening hiding should look in that backend

So the current role of this note is mostly to mark Stwo as:

- strategically important
- architecturally interesting
- but outside the direct “first code mapping” lane for SHROUD v1

## What Would Make This More Concrete

The next useful Stwo-specific artifact would be:

- a compatibility memo comparing SHROUD’s current univariate assumptions with Stwo’s circle-STARK structure

Until that exists, this note should stay a scoped downstream stub rather than pretending the integration path is already clear.
