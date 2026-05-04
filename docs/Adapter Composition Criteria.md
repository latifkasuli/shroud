# SHROUD Adapter Composition Criteria

This note records when SHROUD adapters should remain object-by-object and when it becomes correct to lift them into a composed backend plan.

## Decision

SHROUD should keep the adapter crate **object-by-object** for now.

It should **not** introduce a composed backend plan yet.

## Why

### 1. The protocol object set is not concrete enough yet

The SHROUD interface currently names five protocol objects:

- `ShroudOracleCommitment`
- `ShroudCodewordEmbedding`
- `ShroudQuotientHider`
- `ShroudBatchOpening`
- `ShroudOpeningProjection`

In code, only two of those objects are concrete today:

- `ShroudBatchOpening`
- `ShroudOpeningProjection`

Lifting the adapter crate now would force SHROUD to invent composed slot and carrier vocabulary for objects that are still only protocol sketches. That would freeze integration structure before the underlying objects are stable.

### 2. The current impact comes from clarifying protocol responsibilities

SHROUD is meant to make hiding responsibilities explicit:

- what is committed
- what is opened publicly
- what remains hidden auxiliary proof material
- what security mode is actually claimed

Object-by-object adapters preserve that clarity. A composed backend plan too early would shift the center of gravity from protocol responsibilities to proof-layout engineering.

### 3. Partial backend adoption is a feature, not a temporary inconvenience

Different backends will adopt SHROUD at different depths.

Examples:

- Plonky3 can already map multiple layers.
- Triton VM may first map only some hiding layers.
- Winterfell or Stwo may start with a greenfield subset.

Object-by-object adapters let SHROUD describe those partial mappings honestly. A composed backend plan would push the design toward an all-or-nothing structure too soon.

### 4. Real proof layouts already compose, but that does not mean SHROUD should compose first

Backends like Plonky3 do use one outer proof object carrying commitments, openings, and the PCS proof. That is real.

But this is a downstream integration fact, not the right abstraction boundary for SHROUD at the current stage. The protocol should first stabilize the individual hiding objects and only then describe how a backend composes them into one proof layout.

## When To Revisit Composition

SHROUD should revisit a composed backend plan only when at least one of these conditions becomes true:

1. three or more SHROUD objects are concrete in code
2. two concrete backends show the same cross-object collision or duplication
3. object-by-object adapter plans can no longer express a real backend integration cleanly
4. one backend mapping needs shared control-plane fields that cannot be assigned to a single object without distortion

Until then, composition should remain a downstream concern.

## What Composition Would Mean Later

When SHROUD is ready, composition should not replace the object adapters.

Instead, SHROUD should add a new layer above them:

- object-local adapter plans remain canonical
- a composed backend plan becomes an integration artifact
- the composed plan is derived from the object-local plans rather than defining them

This keeps SHROUD protocol-first and avoids collapsing the design into one backend’s proof shape.

## Recommendation

For the next stage:

- keep `shroud-adapter` object-by-object
- continue implementing the remaining protocol objects one at a time
- treat composition as a later aggregation layer

The next object to prioritize should be `ShroudOracleCommitment` or `ShroudQuotientHider`, because those are the missing pieces most likely to create real cross-object composition pressure.
