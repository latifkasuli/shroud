# SHROUD Triton VM Layer Audit

This note is the first code-referenced SHROUD layer audit for Triton VM.

It is downstream of:

- [Triton VM Mapping](Triton%20VM%20Mapping.md)
- [Triton VM Compatibility Memo](Triton%20VM%20Compatibility%20Memo.md)

The goal here is narrower than a protocol note. This document answers:

- which SHROUD layers are visibly present in Triton VM source today
- which layers are only implied by lower-level machinery
- which layers are still not surfaced as independent protocol objects

## Primary Sources

This audit is based on the current upstream Triton VM repository:

- [`triton-vm/src/stark.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/stark.rs)
- [`triton-vm/src/table/master_table.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/table/master_table.rs)
- [`triton-vm/src/proof_item.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/proof_item.rs)

## Executive Result

The clearest current reading is:

- `ShroudCodewordEmbedding`: present
- `ShroudOracleCommitment`: partially present as commitment/authentication machinery, but not as an explicit hiding layer
- `ShroudQuotientHider`: not surfaced as a separate layer
- `ShroudBatchOpening`: not surfaced as a separate layer
- `ShroudOpeningProjection`: partially present as proof-stream discipline, but not as an explicit public-vs-hidden opening contract

That means Triton VM still looks like a real SHROUD v1-family backend, but only one layer is currently obvious in the code.

## Layer 1: `ShroudOracleCommitment`

### Evidence

In [`triton-vm/src/proof_item.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/proof_item.rs), the proof stream clearly distinguishes:

- `MerkleRoot`
- `AuthenticationStructure`
- `MasterMainTableRows`
- `MasterAuxTableRows`
- `QuotientSegmentsElements`
- `FriResponse`

The comments on `include_in_fiat_shamir_heuristic` make the intended commitment discipline explicit:

- Merkle roots are Fiat-Shamir bound
- authentication structures and opened rows are not re-absorbed because they are already committed through those roots

In [`triton-vm/src/table/master_table.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/table/master_table.rs), the master tables compute Merkle trees over low-degree-extended rows through:

- `merkle_tree()`
- `hash_all_ldt_domain_rows()`
- `reveal_rows()`

### Assessment

This is enough to say that Triton VM already has a serious commitment/authentication layer.

What is still missing from a SHROUD perspective is an explicit hiding interpretation of that layer:

- there is no separately named oracle-hiding object
- there is no explicit statement of how opened rows are separated from auxiliary hiding material

### Status

`ShroudOracleCommitment`: `partial`

The commitment machinery is real, but the SHROUD hiding contract is not yet surfaced explicitly.

## Layer 2: `ShroudCodewordEmbedding`

### Evidence

This is the strongest current SHROUD match in Triton VM.

In [`triton-vm/src/stark.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/stark.rs):

- `NUM_RANDOMIZER_POLYNOMIALS` is defined as a dedicated zk parameter
- `ProverDomains` includes a distinct `randomized_trace` domain
- `ProverDomains::derive(...)` derives that domain from the trace height and number of trace randomizers
- `Prover::prove(...)` computes `num_trace_randomizers` from the chosen low-degree test and constructs the master tables with that budget

In [`triton-vm/src/table/master_table.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/table/master_table.rs), the lifecycle comment states directly:

1. the main table is filled
2. it is padded
3. the remaining entries are filled with random elements, i.e. trace randomization
4. the auxiliary table is later derived
5. the auxiliary table is trace-randomized too

The same file also makes the mechanism explicit:

- `trace_randomizer_for_column(...)`
- `randomized_column_interpolant(...)`
- `out_of_domain_row(...)`
- `weighted_sum_of_columns(...)`

The core construction is exactly the pattern SHROUD cares about:

- interpolate the trace column
- add `zerofier * randomizer`
- work over the randomized trace domain

The file also says explicitly that the rightmost auxiliary columns are randomizer codewords and that they are necessary for zero-knowledge.

### Assessment

This is already a real `ShroudCodewordEmbedding` layer in everything but name.

Triton VM is not merely compatible with the idea. It already implements the essential mechanism:

- witness-facing rows are randomized before the low-degree/opening machinery sees them

### Status

`ShroudCodewordEmbedding`: `present`

This is the first Triton VM layer that can be mapped into SHROUD almost directly.

## Layer 3: `ShroudQuotientHider`

### Evidence

In [`triton-vm/src/stark.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/stark.rs), the quotient side is clearly structured:

- quotient segments are computed
- quotient segment codewords are hashed into a Merkle tree
- a quotient Merkle root is absorbed into the proof stream
- `OutOfDomainQuotientSegments` is emitted
- a quotient-segment combination polynomial is DEEP-transformed into the final combined codeword

So quotient data is definitely part of the proof pipeline.

What is not visible in the same source is a separate quotient-hiding randomizer or an independently named hiding treatment for quotient openings analogous to the trace-randomization layer.

The quotient logic is present as:

- segmentation
- commitment
- OOD evaluation
- DEEP reduction

But not yet as:

- a distinct hiding layer with its own randomness source and contract

### Assessment

From a SHROUD perspective, Triton VM clearly has quotient machinery, but it is still unclear whether quotient hiding exists as an independent design layer or whether privacy relies entirely on earlier trace randomization plus the later DEEP/LDT flow.

### Status

`ShroudQuotientHider`: `missing or unclear`

The quotient pipeline exists, but a separate hiding layer is not exposed.

## Layer 4: `ShroudBatchOpening`

### Evidence

The relevant prover flow in [`triton-vm/src/stark.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/stark.rs) is:

- sample out-of-domain points
- emit `OutOfDomainMainRow`
- emit `OutOfDomainAuxRow`
- emit `OutOfDomainQuotientSegments`
- sample linear-combination weights
- form combined main/aux and quotient-segment polynomials
- DEEP-transform those components
- combine them into the final deep codeword
- run the low-degree test on that codeword

This is a real final opening/reduction surface.

What is not visible is a separate batch-opening randomizer object of the SHROUD kind:

- there is no separate randomizer commitment at this stage
- there is no explicit additive masking layer attached to the final reduced opening relation
- there is no proof-surface object analogous to Plonky3’s `random` slot

### Assessment

Architecturally, Triton VM has a place where `ShroudBatchOpening` could exist.

But today the source reads as:

- trace randomization first
- quotient construction next
- OOD and DEEP combination after that

without an explicit, separately named final batch-opening hiding layer.

### Status

`ShroudBatchOpening`: `missing or unclear`

The reduction surface exists, but the SHROUD layer is not yet explicit in the code.

## Layer 5: `ShroudOpeningProjection`

### Evidence

In [`triton-vm/src/proof_item.rs`](https://github.com/TritonVM/triton-vm/blob/main/triton-vm/src/proof_item.rs), the proof stream already distinguishes between:

- items included in Fiat-Shamir
- items excluded from Fiat-Shamir because they are already committed elsewhere

That is real proof hygiene. It shows that Triton VM already thinks in terms of:

- commitment first
- reveal later

But the revealed items are still exposed directly as proof items:

- `OutOfDomainMainRow`
- `OutOfDomainAuxRow`
- `OutOfDomainQuotientSegments`
- `MasterMainTableRows`
- `MasterAuxTableRows`
- `QuotientSegmentsElements`
- `AuthenticationStructure`
- `FriResponse`

What is not visible is a SHROUD-style projection object that says:

- these are the statement-level public opened values
- these are proof-internal auxiliary openings needed only for verifier reconstruction

### Assessment

Triton VM has commitment discipline, but not yet an explicit opening-projection layer.

That means the raw material for `ShroudOpeningProjection` is there, but the abstraction itself is not.

### Status

`ShroudOpeningProjection`: `partial`

The proof stream already separates committed-vs-revealed flow, but not public-vs-hidden opening roles in the SHROUD sense.

## Audit Table

| SHROUD object | Triton VM status | Evidence |
| --- | --- | --- |
| `ShroudOracleCommitment` | Partial | Merkle roots, authentication structures, opened rows, `reveal_rows()` |
| `ShroudCodewordEmbedding` | Present | `randomized_trace`, `trace_randomizer_for_column()`, `randomized_column_interpolant()` |
| `ShroudQuotientHider` | Missing or unclear | Quotient segments and commitments exist, but no separate hiding layer is exposed |
| `ShroudBatchOpening` | Missing or unclear | OOD + DEEP reduction exists, but no distinct batch randomizer object appears |
| `ShroudOpeningProjection` | Partial | Proof items distinguish commitments from later reveals, but not statement-level public vs hidden auxiliary openings |

## Main Conclusion

The audit strengthens the earlier compatibility memo.

Triton VM is not a scope exception like Stwo. It already fits the SHROUD v1 family well enough that one layer can be mapped directly:

- `ShroudCodewordEmbedding`

The gap is now sharper:

- Triton VM does not obviously need a new protocol family
- it needs a clearer layer decomposition over code that already exists

## Best Next Step

The next Triton-specific step should be a narrower follow-up note:

- trace/codeword mapping done explicitly
- quotient flow traced from construction to verification
- final DEEP/LDT opening surface isolated as the candidate `ShroudBatchOpening` seam

That follow-up now exists as [Triton VM Batch Opening Seam](Triton%20VM%20Batch%20Opening%20Seam.md).
