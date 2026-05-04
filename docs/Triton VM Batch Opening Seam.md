# SHROUD Triton VM Batch Opening Seam

This note traces Triton VM’s quotient flow through verification and isolates the exact place where a `ShroudBatchOpening` object would have to attach.

It is downstream of:

- [Triton VM Mapping](Triton%20VM%20Mapping.md)
- [Triton VM Compatibility Memo](Triton%20VM%20Compatibility%20Memo.md)
- [Triton VM Layer Audit](Triton%20VM%20Layer%20Audit.md)

## Primary Sources

This note is based on the current upstream Triton VM source:

- [`triton-vm/src/stark.rs`](https://github.com/TritonVM/triton-vm/blob/master/triton-vm/src/stark.rs)
- [`triton-vm/src/table/master_table.rs`](https://github.com/TritonVM/triton-vm/blob/master/triton-vm/src/table/master_table.rs)
- [`triton-vm/src/proof_item.rs`](https://github.com/TritonVM/triton-vm/blob/master/triton-vm/src/proof_item.rs)

## Executive Result

Triton VM already has a real final reduction surface that plays the role SHROUD cares about:

- quotient segments are built
- out-of-domain values are sampled and exposed
- DEEP updates are applied
- a final combined codeword is low-degree tested

So the missing piece is not “where would `ShroudBatchOpening` go?”

The answer is:

> `ShroudBatchOpening` would sit between quotient commitment and DEEP/LDT reduction, with one transcript-binding phase before the out-of-domain point is sampled and one masking/reconstruction phase just before the final deep codeword is assembled and checked.

## Step 1: Quotient Construction In The Prover

The prover first derives quotient segments in [`Prover::compute_quotient_segments`](https://github.com/TritonVM/triton-vm/blob/master/triton-vm/src/stark.rs).

That function has two execution paths:

- cached path:
  - use `main_table.quotient_domain_table()` and `aux_table.quotient_domain_table()`
  - call `all_quotients_combined(...)`
  - interpolate quotient segments
  - evaluate the segment polynomials on the LDT domain
- JIT path:
  - `compute_quotient_segments_with_jit_lde(...)`
  - recompute just enough low-degree extension work to build the same segment codewords with lower peak memory

In both cases, the output is the same protocol object:

- `ldt_domain_quotient_segment_codewords`
- `quotient_segment_polynomials`

This is the first important observation for SHROUD:

- Triton VM already has a stable quotient artifact before any final DEEP reduction happens.

## Step 2: Quotient Commitment In The Transcript

After quotient segments are constructed, the prover:

- hashes quotient-segment rows
- builds a quotient Merkle tree
- enqueues its root into the proof stream

So there is already a transcript commitment point for the quotient side before out-of-domain sampling.

This is the right place to think about transcript binding for a future `ShroudBatchOpening` object.

## Step 3: Out-Of-Domain Exposure

Still in [`triton-vm/src/stark.rs`](https://github.com/TritonVM/triton-vm/blob/master/triton-vm/src/stark.rs), the prover then:

- samples `out_of_domain_point_curr_row`
- derives `out_of_domain_point_next_row`
- derives `out_of_domain_point_curr_row_pow_num_segments`
- enqueues:
  - `OutOfDomainMainRow`
  - `OutOfDomainAuxRow`
  - `OutOfDomainMainRow` for the next row
  - `OutOfDomainAuxRow` for the next row
  - `OutOfDomainQuotientSegments`

At this stage, Triton VM has already exposed the full OOD data needed to reconstruct:

- the current-row main+aux constraint state
- the next-row main+aux constraint state
- the current-row quotient-segment state

This is the second important SHROUD observation:

- Triton VM already has the public part of a batch-opening reconstruction surface
- but it is exposed as raw proof items, not as a named batch-opening object

## Step 4: Reduction To The Final Deep Codeword

After OOD rows are exposed, the prover samples `LinearCombinationWeights` and builds:

- one linear combination for main+aux
- one linear combination for quotient segments

Then it DEEP-updates three components:

1. current-row main+aux
2. next-row main+aux
3. current-row quotient segments

These are turned into:

- `main_and_aux_curr_row_deep_codeword`
- `main_and_aux_next_row_deep_codeword`
- `quotient_segments_curr_row_deep_codeword`

and finally combined into the `deep_codeword`, which is the object handed to the low-degree test.

This is the exact place where Triton VM’s current design most closely matches a `ShroudBatchOpening` target:

- there is a reduced relation
- it is built from batched main/aux and quotient data
- it is DEEP-transformed before the low-degree test

## Step 5: What The Verifier Reconstructs

In [`Verifier::verify`](https://github.com/TritonVM/triton-vm/blob/master/triton-vm/src/stark.rs), the verifier mirrors the same flow:

1. absorb the main, auxiliary, and quotient roots
2. sample extension and quotient-combination weights
3. sample the out-of-domain point
4. dequeue:
   - current OOD main row
   - current OOD aux row
   - next OOD main row
   - next OOD aux row
   - OOD quotient segments
5. evaluate AIR constraints at OOD rows
6. divide by the relevant zerofiers
7. recombine them into one OOD quotient value
8. verify that the OOD quotient-segment values reconstruct that same quotient value
9. sample `LinearCombinationWeights`
10. compute:
    - OOD current main+aux combined value
    - OOD next main+aux combined value
    - OOD current quotient-segment combined value
11. run the low-degree test verifier
12. dequeue revealed main rows, aux rows, quotient segment rows, and authentication structures
13. verify Merkle inclusion for all three families
14. for each queried row:
    - compute the local combined main+aux value
    - compute the local combined quotient-segment value
    - apply the same three DEEP updates
    - combine them with `weights.deep`
    - check equality against the revealed first-codeword value from the low-degree test

This is the strongest evidence that Triton VM already has a real batch-opening seam:

- the verifier reconstructs a final reduced relation from public OOD values, revealed row values, and authenticated openings
- then checks that the low-degree-test opening matches that reconstruction

That is precisely the kind of verifier contract SHROUD wants to isolate.

## Where `ShroudBatchOpening` Would Attach

There are really two attachment points.

### 1. Transcript-Binding Seam

If Triton VM were to add a dedicated batch-opening randomizer commitment, it would need to be observed:

- after quotient commitment is fixed
- before `out_of_domain_point_curr_row` is sampled

This is the transcript position that matches SHROUD’s invariant.

### 2. Masking/Reconstruction Seam

The masking object would then have to modify the relation at the point where Triton VM currently forms:

- the OOD combined main+aux values
- the OOD combined quotient-segment value
- the three DEEP-updated queried values
- the final `weights.deep` combination

So the clean SHROUD-style seam is:

- after quotient commitment exists
- after OOD points are known
- before DEEP-updated components are combined into the final low-degree-tested value

That is the real `ShroudBatchOpening` slot in Triton VM.

## Why This Is Not Yet A SHROUD Object

Even though the seam exists, Triton VM still lacks three things SHROUD would want.

### 1. No Dedicated Batch Randomizer Object

There is no separate batch-opening randomizer commitment or proof item analogous to Plonky3’s `random` slot.

### 2. No Explicit Public/Hidden Projection

The relevant proof items are all exposed directly:

- `OutOfDomainMainRow`
- `OutOfDomainAuxRow`
- `OutOfDomainQuotientSegments`
- `MasterMainTableRows`
- `MasterAuxTableRows`
- `QuotientSegmentsElements`
- `AuthenticationStructure`
- low-degree-test responses

The verifier uses them correctly, but they are not separated into:

- statement-level public openings
- proof-internal auxiliary openings

### 3. No Separate Batch-Hiding Layer

Trace randomization is explicit.
The final DEEP/LDT reduction is explicit.
But there is no separately named object that hides the final reduced relation itself.

## SHROUD Interpretation

Under SHROUD terms, Triton VM currently looks like this:

- trace hiding is explicit
- quotient construction is explicit
- final reduced-relation verification is explicit
- final batch-opening hiding is not yet explicit

That makes Triton VM unusually promising:

- the protocol seam already exists
- the main missing work is object extraction, not invention from scratch

## Best Next Step

The best Triton-specific next note after this one is:

- a `Triton VM ShroudBatchOpening Sketch`

That note should define:

1. what Triton VM’s current reduced relation is in SHROUD terms
2. what the minimal public opening surface should be
3. what could remain hidden auxiliary material
4. where a randomizer commitment would have to be observed in the transcript

That would be the first real attempt to phrase Triton VM’s final reduction as a SHROUD object rather than only auditing it from outside.
