# SHROUD To Plonky3 Mapping

This memo explains how the current SHROUD perfect-randomizer interfaces map onto the existing Plonky3 proof shape without changing Plonky3 code yet.

It is intentionally backend-specific. SHROUD itself should be read from the protocol notes and backend-requirements memos first; this document is only the Plonky3 mapping layer.

The key split is:

- `PerfectRandomizerBackend` models the cryptographic object itself
- `PerfectRandomizerAdapter` models how that object lands in an outer proof layout

That split matters because Plonky3 already has a usable proof slot for the randomizer commitment, but the backend story and the outer proof-shape story are not the same thing.

## Current Plonky3 Slot Shape

Plonky3 already carries an optional randomizer commitment at the outer proof level:

- uni-stark uses `Commitments { trace, quotient_chunks, random }` in [uni-stark/src/proof.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/src/proof.rs#L27)
- batch-stark uses `BatchCommitments { main, permutation, quotient_chunks, random }` in [batch-stark/src/proof.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/src/proof.rs#L28)

So for SHROUD purposes, there is already an obvious candidate for the adapter slot:

- `ReferencePlonky3CommitmentSlot::RandomOptionField`

This is why the encoded-oracle-bundle perfect variant can plausibly reuse the current slot shape.

## Transcript Position

Plonky3 also already observes the randomizer commitment in the right place:

- uni-stark observes `random` before sampling `zeta` in [uni-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/src/prover.rs#L281) and [uni-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/src/prover.rs#L287)
- batch-stark does the same in [batch-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/src/prover.rs#L454)

That matches the SHROUD transcript invariant exactly.

## Opening Round Layout

When ZK is enabled, the randomizer opening occupies round 0 of the PCS opening flow:

- uni-stark builds `round0` from `opt_r_data` in [uni-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/src/prover.rs#L310)
- batch-stark builds the analogous round in [batch-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/src/prover.rs#L467)

This aligns with the PCS indexing rule in [commit/src/pcs.rs](/Users/latifkasuli/web3/contributions/plonky3/commit/src/pcs.rs#L65), where `TRACE_IDX = Self::ZK as usize`.

Operationally this means:

- when `ZK = false`, the trace is at slot 0
- when `ZK = true`, the randomizer opening consumes slot 0 and the trace shifts to slot 1

That is already the proof-shape effect SHROUD wants to model with `ProofSlotLayout::ReuseCurrentRandomSlot`.

## Opened Values

Plonky3 does not hide the randomizer opening entirely inside an opaque PCS proof. It also threads the round-0 value into its outer opened-values structs:

- uni-stark copies `opened_values[0][0][0]` into `OpenedValues.random` in [uni-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/src/prover.rs#L348) and stores that field in [uni-stark/src/proof.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/src/proof.rs#L43)
- batch-stark copies `opened_values[0][i][0]` into per-instance `OpenedValues.random` in [batch-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/src/prover.rs#L586) and then stores those per-instance opened values in [batch-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/src/prover.rs#L647)

This matters for SHROUD because it means the current Plonky3 proof shape already has two useful properties:

1. a top-level optional commitment slot for the randomizer
2. an outer opened-values field for the public randomizer evaluation

So the encoded-oracle-bundle perfect variant does not need a new outer proof shape just to exist.

## What The Adapter Means

In SHROUD terms, the adapter surface is the answer to this question:

“Given a perfect-randomizer commitment model, where does it live in the outer proof and what public payload shape does the proof expose?”

For the current Plonky3-compatible path, the answer is:

- commitment slot: existing `random: Option<Com>` field
- proof-slot layout: reuse the current random slot
- public payload: one extension-field evaluation per opening point
- hidden payload: encoded coordinate openings carried in-band with the main opening proof

That is exactly what `ReferencePlonky3Adapter` models in the SHROUD reference repo.

## Encoded Bundle Mapping

The SHROUD encoded-oracle-bundle perfect variant maps to Plonky3 as follows:

- `PerfectRandomizerCommitment::encoded_oracle_bundle()`
- adapter slot: `ReferencePlonky3CommitmentSlot::RandomOptionField`
- `ProofSlotLayout::ReuseCurrentRandomSlot`
- hidden payload: `PerfectHiddenOpeningPayload::EncodedCoordinates`

This is the strongest “minimal change” path because it reuses:

- the existing commitment slot
- the existing transcript order
- the existing round-0 opening position
- the existing outer `random` opened-value field

The real work then moves into backend semantics:

- the grouped coordinate openings must be treated as one exact extension-field randomizer object
- not just as unrelated base-field random columns

## Native Extension Mapping

The native-extension perfect variant does not fit the current slot reuse story as cleanly.

In SHROUD it maps to:

- `PerfectRandomizerCommitment::native_extension_pcs()`
- adapter slot: `ReferencePlonky3CommitmentSlot::DedicatedPerfectRandomizerField`
- `ProofSlotLayout::DedicatedPerfectRandomizerSlot`
- hidden payload: `PerfectHiddenOpeningPayload::BackendProofOnly`

This is the clean protocol endpoint, but it implies one of:

- a new outer proof field for the perfect randomizer commitment
- a new PCS proof shape for its openings
- or a broader rewrite of how Plonky3 carries committed opening rounds

That is why SHROUD treats it as the long-term path rather than the first integration target.

## Immediate Integration Guidance

If the first real integration target is Plonky3, the recommended mapping is:

1. keep the outer proof fields unchanged
2. interpret the current `random` slot through `PerfectRandomizerAdapter`
3. realize the perfect backend initially through the encoded-oracle-bundle model
4. postpone native extension-field slot changes until the backend semantics are stable

That preserves reviewability and isolates the real semantic change: turning the randomizer from a loose surrogate into a first-class exact object.
