# SHROUD

Structured Hiding for Reed-Solomon Oracles Under FRI.

This workspace is a small reference/spec implementation for the SHROUD protocol notes. It is not a proving system. The goal is to make the protocol objects concrete before adapting them into systems like Plonky3.

[![CI](https://github.com/latifkasuli/shroud/actions/workflows/ci.yml/badge.svg)](https://github.com/latifkasuli/shroud/actions/workflows/ci.yml)

## Crates

- `shroud-core`: shared protocol types for transcript ordering and degree-budget invariants. Primary types: `TranscriptPlan`, `DegreeBudget`, `SecurityLevel`.
- `shroud-adapter`: backend-neutral adapter plans for landing SHROUD objects in concrete proof layouts. Primary types: `BatchOpeningAdapterPlan`, `OpeningProjectionAdapterPlan`, `OracleCommitmentAdapterPlan`, `QuotientHiderAdapterPlan`.
- `shroud-batch-opening`: the first concrete SHROUD object, `ShroudBatchOpening`. Primary types: `ShroudBatchOpeningSpec`, `PerfectRandomizerCommitment`.
- `shroud-opening-projection`: the second SHROUD object, separating public openings from hidden auxiliary openings. Primary types: `ShroudOpeningProjectionSpec`, `OpeningProjectionPayload`.
- `shroud-oracle-commitment`: the third SHROUD object, modeling hidden oracle commitments and authenticated row openings. Primary types: `ShroudOracleCommitmentSpec`, `OracleCommitmentPayload`.
- `shroud-quotient-hider`: the fourth SHROUD object, modeling decomposition-aware quotient hiding. Primary types: `ShroudQuotientHiderSpec`, `QuotientHiderPayload`.
- `shroud-codeword-embedding`: the fifth SHROUD object, modeling the public trace plus hidden randomizer columns committed through a hiding FRI-style codeword embedding. Primary types: `ShroudCodewordEmbeddingSpec`, `CodewordEmbeddingShape`, `CodewordEmbeddingPayload`.
- `shroud-reference`: a toy transcript/model layer used to exercise the protocol boundary. Primary types: `ReferenceTranscript`, `ReferencePlonky3Adapter`, `ReferenceLayeredAdapter`.

## Research Packet

Start with:

- `../research/shroud/README.md`

That file gives the canonical reading order for the SHROUD packet, then points to the backend-specific downstream notes.

## Current Scope

The current code does the following:

1. Makes the batch-opening transcript order explicit.
2. Makes the degree-budget rule explicit.
3. Gives the perfect variant a dedicated commitment boundary without forcing a full extension-field PCS rewrite.
4. Makes the backend-adapter seam explicit so Plonky3 is only one mapping, not the definition of SHROUD.
5. Exercises that seam with two different reference adapter families: a Plonky3-like field-oriented adapter and a layered auxiliary-envelope adapter.
6. Makes the codeword-embedding payload explicit, including the statistical invariant `randomizer_columns == extension_degree` and the FRI blowup requirement `required_log_blowup >= 2`.
7. Exercises the adapter crate across multiple SHROUD objects instead of only `ShroudBatchOpening`.
8. Records an explicit rule that adapter composition stays downstream until more SHROUD objects are concrete.

## Development

This repository pins Rust `1.85.0`, the first stable Rust 2024 toolchain. The CI contract is:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Roadmap

Near-term work:

1. Add a `BasisDescriptor` to the perfect encoded-oracle bundle path so extension-degree, coordinate order, and reconstruction rules are self-describing.
2. Add property tests for transcript stage permutations, degree-budget violations, payload accounting, and malformed plans.
3. Build a thin Plonky3 prototype in `shroud-reference` around `HidingFriPcs`.

The codeword embedding's hidden row expansion should be captured as a design note when the Plonky3 reference adapter lands, because that detail is observable at the backend commitment layer rather than through the verifier-facing payload alone.
