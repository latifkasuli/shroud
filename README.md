# SHROUD

Structured Hiding for Reed-Solomon Oracles Under Decomposition.

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
- `shroud-plonky3`: backend-specific bridge to the pinned `p3-zk-proofs` integration vehicle. Owns the verifier-trust enforcement primitive (`verify_profile_matches_backend`), the `p3-symmetric` advisory (GHSA-3g92-f9ch-qjcm, `LAST_AFFECTED = 0.5.2`) derived from `Cargo.lock` at build time so callers cannot lie about provenance, and the canonical Plonky3 hash-suite identifier (embeds full provenance — source kind + version + checksum/rev — closing suite confusion at the transcript level). Primary types: `Plonky3HashIdentifier`, `P3SymmetricProvenance`, `BackendDriftError`. The workspace `[patch.crates-io]` redirects `p3-symmetric` to a reviewed git fork (`latifkasuli/p3-symmetric-patched` @ `1bb34116`) carrying the upstream `Pad10Sponge` patch; the `KNOWN_PATCHED_P3_SYMMETRIC_SOURCES` allowlist authorizes that exact `(url, rev)` pair. The bridge passes its advisory gate and is unblocked for item 4 (`RecordingChallenger`).

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

Completed foundations:

1. `BasisDescriptor` makes encoded-oracle bundle field reconstruction self-describing.
2. Transcript order, degree-budget, payload-accounting, and malformed-plan cases have focused tests across the workspace.
3. Fiat-Shamir binding now has a backend-neutral manifest layer, canonical `TranscriptBindable` surfaces, hash-suite binding, public-opening bindings, and reference challenge replay.
4. `shroud-plonky3` contains the Plonky3-facing bridge: pinned-backend profile alignment (`verify_profile_matches_backend`), the `p3-symmetric` advisory gate (provenance-typed, lying-fork-defended, suite-confusion-closed via provenance-in-identifier), and the canonical hash-suite identifier. Workspace `[patch.crates-io]` redirects `p3-symmetric` to a reviewed git fork carrying the upstream `Pad10Sponge` patch. `shroud-reference` stays backend-neutral.

Next bridge work:

1. Wire the canonical batch-opening manifest into the concrete Plonky3 transcript.
2. Replace reference challenge derivation with the production Plonky3 Fiat-Shamir sponge.
3. Add bridge-level tests that compare prover absorption, verifier replay, and sampled challenges byte-for-byte.

The codeword embedding's hidden row expansion should be captured as a design note when the Plonky3 bridge lands, because that detail is observable at the backend commitment layer rather than through the verifier-facing payload alone.
