# Plonky3 Integration Checklist

This note scopes the first real SHROUD-oriented Plonky3 patch.

It is intentionally a backend-specific checklist, not the SHROUD protocol plan. SHROUD should stay protocol-agnostic; this note only describes the first concrete mapping into one backend.

It is intentionally narrow. The goal is not to implement a new PCS or a full native extension-field randomizer. The goal is to map the SHROUD perfect-randomizer model onto Plonky3's existing `random` slot with the smallest reviewable diff.

## Target Of The First PR

The first PR should integrate only the **encoded-oracle-bundle** path.

That means:

- reuse the existing `random: Option<Com>` commitment slot
- reuse the existing `OpenedValues.random` public payload shape
- reuse round 0 of the current PCS opening flow
- keep the outer proof structs stable
- keep the PCS trait stable

What changes is the interpretation:

- the randomizer should be treated as one exact grouped object
- not as a loose collection of unrelated base-field random columns

## Files To Change In The First PR

### Core Integration

- [plonky3/fri/src/hiding_pcs.rs](/Users/latifkasuli/web3/contributions/plonky3/fri/src/hiding_pcs.rs)

This is the main integration file.

It currently:

- commits the randomizer through `get_opt_randomization_poly_commitment(...)`
- splits random codeword openings off in `open_with_preprocessing(...)`
- merges them back in `verify(...)`

For the first PR, this file should:

- introduce an internal grouped-randomizer helper or type
- make the encoded-bundle semantics explicit at the PCS wrapper boundary
- keep the current proof shape and round ordering unchanged

### Uni-STARK Integration

- [plonky3/uni-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/src/prover.rs)
- [plonky3/uni-stark/src/verifier.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/src/verifier.rs)

These files already:

- request the randomizer commitment
- observe it before sampling `zeta`
- open it in round 0
- thread the public randomizer value into `OpenedValues.random`
- verify the commitment/opening pair against that same outer field

For the first PR, these files should:

- keep the outer flow identical
- switch comments and helper naming from “extra random columns” toward “grouped randomizer object”
- keep the verifier logic aligned with the existing `random` field shape

### Batch-STARK Integration

- [plonky3/batch-stark/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/src/prover.rs)
- [plonky3/batch-stark/src/verifier/mod.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/src/verifier/mod.rs)

These files play the same role for batch-STARK as the uni-STARK files above.

For the first PR, they should:

- keep the per-instance `random` opened value shape unchanged
- keep the top-level `commitments.random` field unchanged
- keep transcript order unchanged
- only adopt the grouped-randomizer semantics and any helper extraction needed to support it

### Optional Comment-Level Clarification

- [plonky3/commit/src/pcs.rs](/Users/latifkasuli/web3/contributions/plonky3/commit/src/pcs.rs)

This file should only be touched if the PR wants to clarify the contract of `get_opt_randomization_poly_commitment(...)`.

For the first PR:

- do **not** redesign the trait
- do **not** add a new commitment type parameter
- do **not** change `TRACE_IDX`, `QUOTIENT_IDX`, or `PREPROCESSED_TRACE_IDX`

At most, tighten the documentation of the existing hook.

## Files That Should Stay Untouched In The First PR

### Outer Proof Structs

- [plonky3/uni-stark/src/proof.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/src/proof.rs)
- [plonky3/batch-stark/src/proof.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/src/proof.rs)

The first PR should not change:

- `random: Option<Com>`
- `OpenedValues.random`
- any top-level proof field ordering

If these files need to change, the PR is no longer “minimal”.

### Transcript Surfaces

- [plonky3/batch-stark/src/transcript.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/src/transcript.rs)

The current transcript order is already correct for SHROUD. The first PR should reuse it.

### FRI Core And Base PCS Machinery

- [plonky3/fri/src/prover.rs](/Users/latifkasuli/web3/contributions/plonky3/fri/src/prover.rs)
- [plonky3/fri/src/verifier.rs](/Users/latifkasuli/web3/contributions/plonky3/fri/src/verifier.rs)
- [plonky3/fri/src/two_adic_pcs.rs](/Users/latifkasuli/web3/contributions/plonky3/fri/src/two_adic_pcs.rs)
- [plonky3/merkle-tree/src/hiding_mmcs.rs](/Users/latifkasuli/web3/contributions/plonky3/merkle-tree/src/hiding_mmcs.rs)

The first PR should not turn into:

- a new FRI verifier design
- a new MMCS design
- a native extension-field PCS implementation

### Constraint/AIR Logic

- AIR implementations and constraint folders across `uni-stark` and `batch-stark`

The first PR should not modify:

- AIR semantics
- quotient decomposition logic outside the current randomizer path
- lookup/permutation argument logic

## Tests To Add Or Update

### PCS-Level Regression

- [plonky3/fri/tests/pcs.rs](/Users/latifkasuli/web3/contributions/plonky3/fri/tests/pcs.rs)

Add or extend tests that confirm:

- the grouped randomizer object still reuses the existing round-0 slot
- opened values seen by callers are unchanged
- hidden auxiliary openings remain proof-internal at the PCS layer

### Uni-STARK Regression

- [plonky3/uni-stark/tests/mul_air.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/tests/mul_air.rs)
- [plonky3/uni-stark/tests/fib_air.rs](/Users/latifkasuli/web3/contributions/plonky3/uni-stark/tests/fib_air.rs)

Add or extend tests that confirm:

- proof shape stays the same
- `commitments.random` is still present iff ZK is enabled
- `opened_values.random` is still present iff ZK is enabled
- verifier acceptance is unchanged on honest proofs

### Batch-STARK Regression

- [plonky3/batch-stark/tests/simple.rs](/Users/latifkasuli/web3/contributions/plonky3/batch-stark/tests/simple.rs)

Add or extend tests that confirm:

- the per-instance random opening shape is unchanged
- batch proofs still verify under the existing outer proof structure
- negative tests around missing or malformed random data still fail for the same reasons

## Minimal First PR Checklist

1. Add an internal grouped-randomizer helper in `fri/src/hiding_pcs.rs`.
2. Route `get_opt_randomization_poly_commitment(...)` through that helper without changing its public signature.
3. Keep the round-0 opening order exactly as it is today.
4. Keep `random: Option<Com>` and `OpenedValues.random` exactly as they are today.
5. Update uni-stark and batch-stark prover/verifier code only enough to reflect the grouped-randomizer semantics.
6. Add regression tests proving that proof layout and verification behavior are unchanged.

If any step requires a new public proof field or a new PCS trait shape, stop and split that into a later PR.

## Explicit Non-Goals For The First PR

The first PR should **not**:

- add a dedicated perfect-randomizer commitment field
- implement native extension-field PCS support
- redesign `Pcs::Proof`
- redesign `get_opt_randomization_poly_commitment(...)`
- change commitment indexing constants
- modify FRI query logic
- solve the full long-term native-extension path

Those belong to a later phase.

## What The First PR Buys Us

If scoped correctly, the first PR gives three things:

1. a real Plonky3 integration seam for the SHROUD model
2. no outer proof-shape churn
3. a clear path to later evaluate whether the current grouped encoding is strong enough, or whether Plonky3 eventually needs a dedicated perfect-randomizer slot

That is the right first step because it hardens semantics without forcing a whole-stack redesign.
