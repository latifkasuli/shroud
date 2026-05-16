# Plonky3 Bridge — Supported Boundary

**Crate:** `shroud-plonky3`  
**Status as of:** current pre-grind bridge facade boundary  
**Audience:** integrators wiring SHROUD's hiding bridge to a live `HidingFriPcs` Plonky3 prover; auditors verifying which threat classes the current bridge actually defends.

This document is the **frozen contract** for what the bridge does and does not cover today. It is the source of truth for downstream callers, paper claims, and audit reports. When the bridge expands (e.g. phase 3 PCS-internal replay), this document is the first thing that must change.

---

## TL;DR

| | Status |
|---|---|
| Pre-grind SHROUD-stage transcript binding | **Supported, live-tested** |
| Profile drift gate (backend-pinned constants) | **Supported, live-tested** |
| Provenance gate (p3-symmetric GHSA-3g92-f9ch-qjcm) | **Supported** |
| Hash-suite identifier binding | **Supported, live-tested** |
| AIR preprocessed-commit binding (when AIR has preprocessed cols) | **Supported** |
| AIR public values binding | **Supported** |
| Randomizer-commit binding (`HidingFriPcs` event 9) | **Supported, live-tested** |
| Post-zeta `opened_values` binding | **Placeholder** (manifest-bound, not live) |
| FRI commit-phase commitments / final poly / log arities | **Placeholder** (manifest-bound, not live) |
| PCS-internal grind, query openings | **Deferred** (phase 3) |
| Non-ZK (`Pcs::ZK = false`) deployments | **Out of scope by design** |

---

## What is supported now

The bridge validates the **pre-grind portion** of a live `HidingFriPcs` transcript against SHROUD-canonical and Plonky3-extended bindings, using the production API in `crates/shroud-plonky3/src`:

- `live_extractor::extract_pre_grind_slices` — structurally walks the recorder event log; typed `LiveExtractionError` (`TruncatedLog`, `SampledInObserveBlock`, `ObservedBlockOvershoot`, `MissingChallengeSample`) on drift; no panics.
- `live_harness::build_pre_grind_harness_input` — composes the extraction into `(profile, record, manifest, prefix_events)`.
- `replay_harness::Plonky3ReplayHarness::verify` — runs provenance → manifest → byte-equivalence replay in fail-fast order.

**Events covered (matching `docs/Plonky3 Mapping.md` rows 1-10):**

1. `log_ext_degree` (uni-stark/src/prover.rs:163)
2. `log_degree` (line 164)
3. `preprocessed_width` (line 165)
4. `trace_commit` (line 169)
5. `preprocessed_commit` — conditional on `preprocessed_width > 0` (line 171)
6. `air_public_values` — conditional on non-empty (line 175)
7. α (`SampleBatchingChallenge`) (line 197)
8. `quotient_commit` (line 258)
9. `randomizer_commit` — always present, bridge is ZK-only (line 286)
10. ζ (`SampleOodPoint`) (line 300)

---

## What is intentionally placeholder

These slots **exist in the manifest and record** (so `ReferenceBindingRecord::finalize` succeeds end-to-end), but their bytes are **caller-supplied placeholders**, not live recorder output. They are bound in the SHROUD/Plonky3 manifest schema for future phase-3 work; they do **not** participate in live byte-equivalence verification.

Field on `Plonky3LiveHarnessConfig` | Manifest slot | Why placeholder
---|---|---
`opened_values` | `DOMAIN_PLONKY3_OPENED_VALUES` | Live bytes land after ζ but before grind; grind clone-pollution corrupts recorder downstream
`fri_commit_phase_commitments` | `DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS` | Post-grind — same blocker
`fri_final_poly` | `DOMAIN_PLONKY3_FRI_FINAL_POLY` | Post-grind
`fri_log_arities` | `DOMAIN_PLONKY3_FRI_LOG_ARITIES` | Post-grind

**Implication for callers:** the bridge does **not** detect attacks that mutate `opened_values` or any FRI commit-phase commitment in a real proof. The pre-grind SHROUD-stage binding layer is what the bridge claims to enforce — and that claim is currently live-tested. Downstream code MUST NOT rely on the post-zeta placeholder slots as live transcript bindings.

`PublicOpeningBinding` (the SHROUD-canonical `DOMAIN_PUBLIC_OPENINGS` slot, distinct from the Plonky3-event `DOMAIN_PLONKY3_OPENED_VALUES`) is also a caller-supplied placeholder in the live bridge: SHROUD's semantic is "concatenated opened-values at ζ in PCS round order", which is post-grind data the recorder cannot capture cleanly today.

---

## What is deferred

**Phase 3** (`prove_with_recording_challenger` or upstream grind patch):

`SerializingChallenger32::grind` clones the challenger inside a Rayon `find_any` parallel search. Clones share the `Arc<Mutex<…>>`-backed recorder tape, so throwaway PoW-candidate bytes pollute the recorder log and break byte-equivalence replay past the grind point. Two unblocking paths:

1. **`prove_with_recording_challenger`** — inline the uni-stark prove loop with `&mut challenger` instead of `Clone`, so only the primary challenger writes to the tape. Requires a fork of `p3-uni-stark::prove` or an upstream PR adding a recording-friendly entry point.
2. **Upstream grind patch** — change `SerializingChallenger32::grind` to spawn fresh challenger copies (`Arc::clone` of the inner challenger only, not the tape) for sub-search workers. Cleanest fix, but requires an upstream merge.

Either path closes the gap to full PCS-internal replay: live `opened_values`, live FRI commit-phase commitments, final poly, and log arities. Until then, the binding-layer claim stops at ζ.

---

## What is out of scope by design

- **Non-ZK (`Pcs::ZK = false`) deployments.** The bridge is the SHROUD **hiding** layer; every supported configuration runs against `HidingFriPcs` where ZK is on. `LiveExtractorShape` has no `zk_enabled` toggle. The randomizer-commit event (event 9) is unconditional. If a future SHROUD variant covers non-ZK STARKs, it will live in a different bridge.
- **Batch-stark transcripts** (multiple parallel STARK instances). The Plonky3 Mapping doc has the batch-stark event tables; the current bridge's manifest is uni-stark only. Batch-stark is on the roadmap.
- **AIRs with non-trivial preprocessed columns.** Supported in principle — `LiveExtractorShape.preprocessed_commit_bytes = Some(N)` works and `build_pre_grind_harness_input` wires the binding — but only the no-preprocessed-cols `SquareAir` shape is covered by the live integration test. Custom-AIR coverage is a follow-up test.

---

## Threat classes currently covered by live tests

Each row is enforced by `tests/live_hiding_negative_battery.rs` against real `HidingFriPcs` prove output:

| Test | security-model.md § | Threat class | Expected error |
|---|---|---|---|
| `live_harness_verifies_well_formed_inputs` | — (positive baseline) | Well-formed proof verifies cleanly | `Ok(())` |
| `live_negative_wrong_hash_identifier_rejected` | §5 (hash-suite substitution) | Verifier on attacker-controlled hash suite | `Manifest(BindingMismatch { DOMAIN_HASH_ID })` |
| `live_negative_mutated_trace_commitment_rejected` | §2 (missing inputs / commitment substitution) | Substituted trace commitment | `Manifest(BindingMismatch { DOMAIN_PLONKY3_TRACE_COMMITMENT })` |
| `live_negative_mutated_randomizer_commitment_rejected` | §2 (hiding-stack-specific) | Substituted randomizer commitment — the threat the bridge exists to close | `Manifest(BindingMismatch { DOMAIN_RANDOMIZER_COMMITMENT })` |
| `live_negative_dropped_quotient_commitment_rejected` | §1 (transcript must bind all public context) | Missing quotient commitment | `Manifest(MissingBinding { DOMAIN_PLONKY3_QUOTIENT_COMMITMENT })` |
| `live_negative_mutated_observation_in_prefix_rejected` | §5 (replay-stream tampering) | Byte mutation in the live transcript prefix | `Replay(_)` |
| `live_negative_reordered_events_in_prefix_rejected` | §7 (stage-scoped binding completeness) | Reordering attack — swap adjacent observe events | `Replay(_)` |
| `live_negative_profile_drift_rejected` | §4 (verifier independent validation) | Backend constant mutated in the profile | `Provenance(_)` |

**Coverage gap:** §6 (nonce/randomness reuse) is not currently exercised by a live test — the hiding-RNG seed is deployment-config, not transcript-controlled. §8 (failed observe must not pollute the record) is exercised by `shroud-reference` transcript unit tests, not by the live bridge.

---

## Public facade

For downstream callers wanting one entry point instead of stitching three modules together:

```rust
use shroud_plonky3::{
    verify_pre_grind_bridge,
    LiveExtractorShape, Plonky3LiveHarnessConfig,
    ByteTranscriptEvent,
};

let events: Vec<ByteTranscriptEvent> = recorder.events();
verify_pre_grind_bridge(&events, &LiveExtractorShape::standard(), &config)?;
```

Internally: `longest_byte_equivalent_prefix` → `extract_pre_grind_slices` → `build_pre_grind_harness_input` → `Plonky3ReplayHarness::verify`. Returns `Result<(), PreGrindBridgeError>` where `PreGrindBridgeError` flattens extractor + harness failures.

The facade is the **stable entry point**. Module-level APIs (`extract_pre_grind_slices`, `build_pre_grind_harness_input`, `Plonky3ReplayHarness`) remain public for callers that need finer control (e.g. inspecting `LivePreGrindExtraction` directly), but they are not the recommended downstream entry point.

---

## Frozen-boundary checklist (when expanding scope)

Before adding a new transcript event to the bridge, the following must all happen in the same change:

1. **Plonky3 Mapping doc** updated with the event row + file:line citation.
2. **Extractor** updated: new branch in `extract_pre_grind_slices`, new field on `LivePreGrindExtraction`, new `LiveExtractorShape` knob if shape-conditional.
3. **Harness builder** updated: live bytes wired into `Plonky3UniStarkBindings` (use accessor or `with_*` method).
4. **Manifest** updated: new `DOMAIN_PLONKY3_*` constant + `into_manifest` slot.
5. **Live integration test** covering at least one negative mutation per new event.
6. **This document** updated: move the row from "deferred"/"placeholder" to "supported", add the threat-coverage row.
7. **`security-model.md`** updated if the new event introduces a new threat class.

If any of those steps are skipped, the change is rejected.
