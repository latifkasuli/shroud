# SHROUD To RISC Zero Mapping

This note is a backend-specific downstream mapping for RISC Zero.

It is not part of the SHROUD protocol definition. It records how SHROUD would apply to a backend whose zero-knowledge story appears to have been improved through targeted fixes rather than through one reusable hiding architecture.

## Current Reading

In the current survey, RISC Zero appears to have:

- patched known leakage issues
- no clearly exposed structured hiding layer
- no clearly exposed batch-opening randomizer object
- no clearly exposed public-vs-hidden opening projection contract

That makes RISC Zero a patch-driven partial-mapping target.

## SHROUD Layer Status

| SHROUD object | Current status in RISC Zero | Immediate implication |
| --- | --- | --- |
| `ShroudOracleCommitment` | Patch-level | Some concerns may already be addressed, but not as a reusable layer |
| `ShroudCodewordEmbedding` | Patch-level | Hiding logic is not yet surfaced as one protocol object |
| `ShroudQuotientHider` | Patch-level or unclear | Would need explicit decomposition-aware treatment |
| `ShroudBatchOpening` | Unclear | Missing as a named reusable object |
| `ShroudOpeningProjection` | Unclear | Missing as an explicit public/hidden contract |

## What SHROUD Would Mean Here

For RISC Zero, SHROUD is less about “adding privacy from nothing” and more about:

- turning issue-by-issue fixes into a stable architecture
- documenting which leakage surfaces are already covered
- making the missing batch-opening and projection layers explicit

## First Sensible Path

The first realistic RISC Zero-oriented sequence would be:

1. catalog which hiding/leakage surfaces are already addressed by existing fixes
2. restate those fixes in SHROUD layer terms
3. identify whether a batch-opening randomizer layer exists implicitly or is still absent
4. define a public-vs-hidden opening contract if the current proof surface does not already make one explicit

That would turn SHROUD into an organizing framework rather than a claim that the backend needs a wholesale rewrite.

## Strategic Value

RISC Zero matters because it represents a common ecosystem pattern:

- correctness and privacy issues get fixed
- but the fixes do not become a reusable design vocabulary

If SHROUD can organize that patch history into a protocol-level layer model, it becomes useful not only for new implementations but also for audit and maintenance.
