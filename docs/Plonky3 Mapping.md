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

---

# Full Transcript Event Map

This section enumerates every `challenger.observe(...)`, `challenger.observe_slice(...)`, `challenger.observe_algebra_*(...)`, `challenger.sample_*`, and `challenger.grind(...)` call in Plonky3's prove/verify paths, in execution order. Each event is a Fiat-Shamir absorption or sample point that SHROUD's transcript binding manifest must mirror byte-for-byte for replay to succeed.

File:line citations target the local Plonky3 checkout at `/Users/latifkasuli/web3/contributions/plonky3/`. The events are taken from the current `main` snapshot; revision-bump sweeps must re-run this enumeration.

## Reading the SHROUD-coverage column

- **canonical** — a `StandardBatchOpeningBindings` slot already covers this event (the v1 SHROUD batch-opening manifest binds the same parameter)
- **gap** — no canonical binding; the event needs a slot in `Plonky3ExtendedBindings` (a backend-specific wrapper composed on top of `StandardBatchOpeningBindings`)
- **PCS-internal** — the event happens inside `pcs.open_with_preprocessing` and is determined by polynomial values; SHROUD records it via `SampledChallenge` replay rather than a separate domain label

## uni-stark — prove transcript stream

In execution order from `uni-stark/src/prover.rs::prove(...)`:

| # | File:Line | Call | Purpose | SHROUD coverage |
|---|---|---|---|---|
| 1 | uni-stark/src/prover.rs:163 | `observe(Val::from_u8(log_ext_degree))` | instance shape | gap (`Plonky3ExtendedBindings::log_ext_degree`) |
| 2 | uni-stark/src/prover.rs:164 | `observe(Val::from_u8(log_degree))` | instance shape | gap (`Plonky3ExtendedBindings::log_degree`) |
| 3 | uni-stark/src/prover.rs:165 | `observe(Val::from_usize(preprocessed_width))` | preprocessed AIR width | gap (`Plonky3ExtendedBindings::preprocessed_width`) |
| 4 | uni-stark/src/prover.rs:169 | `observe(trace_commit)` | main trace commitment (MMCS root) | gap (`Plonky3ExtendedBindings::trace_commitment`) |
| 5 | uni-stark/src/prover.rs:171 | `observe(preprocessed_commit)` *(conditional: `preprocessed_width > 0`)* | preprocessed commitment | gap (`Plonky3ExtendedBindings::preprocessed_commitment`) |
| 6 | uni-stark/src/prover.rs:175 | `observe_slice(public_values)` | AIR public inputs | canonical-but-renamed — current `DOMAIN_PUBLIC_OPENINGS` binds opened values, not AIR public inputs; the bridge needs a distinct slot for AIR public inputs (`Plonky3ExtendedBindings::air_public_values`) |
| 7 | uni-stark/src/prover.rs:197 | `sample_algebra_element() → α` | AIR constraint batching | canonical — record under `SampledChallenge::SampleBatchingChallenge` |
| 8 | uni-stark/src/prover.rs:258 | `observe(quotient_commit)` | quotient chunks MMCS root | gap (`Plonky3ExtendedBindings::quotient_commitment`) |
| 9 | uni-stark/src/prover.rs:286 | `observe(r_commit)` *(conditional: ZK enabled)* | randomizer commitment | canonical (`DOMAIN_RANDOMIZER_COMMITMENT`) |
| 10 | uni-stark/src/prover.rs:300 | `sample_algebra_element() → ζ` | out-of-domain opening point | canonical — record under `SampledChallenge::SampleOodPoint` |
| 11 | uni-stark/src/prover.rs:332 → fri/two_adic_pcs.rs::open_with_preprocessing | *PCS open begins* | — | — |

### PCS open inserts (continuing from event 10)

`pcs.open_with_preprocessing` is called at `uni-stark/src/prover.rs:332` and runs the following events in order before returning. Round order is fixed by `rounds = round0(randomizer) ++ [round1(trace), round2(quotient)] ++ round3(preprocessed)`.

| # | File:Line | Call | Purpose | SHROUD coverage |
|---|---|---|---|---|
| 12 | fri/src/two_adic_pcs.rs:537 (per matrix, per point) | `observe_algebra_slice(&ys)` | opened values at ζ (and ζ_next for trace if `main_next`) | canonical-extended — the PCS observes the opened values in the order: randomizer-at-ζ, trace-at-ζ[/ζ_next], quotient-chunks-at-ζ, preprocessed-at-ζ[/ζ_next]. SHROUD's `DOMAIN_PUBLIC_OPENINGS` should bind the concatenation of these in the same order. |
| 13 | fri/src/two_adic_pcs.rs:555 | `sample_algebra_element() → α_pcs` | PCS opening combination challenge (distinct from AIR alpha) | gap — record as a Plonky3-specific `SampledChallenge` variant; no canonical binding |

### FRI commit phase (continuing from event 13)

`commit_phase` is called at `fri/src/prover.rs:85` with reduced openings as input. It runs once per fold round until `folded.len() ≤ blowup * final_poly_len`.

| # | File:Line | Call | Purpose | SHROUD coverage |
|---|---|---|---|---|
| 14 | fri/src/prover.rs:210 *(per fold round, in order)* | `observe(commit_phase_commit)` | fold-round MMCS commitment | gap (`Plonky3ExtendedBindings::fri_commit_phase_commitments`, ordered Vec) |
| 15 | fri/src/prover.rs:215 *(per fold round)* | `grind(commit_proof_of_work_bits)` | per-fold PoW witness | PCS-internal — verifier re-checks via `check_witness`; SHROUD records the witnesses Vec as part of the bridge proof envelope, not the manifest |
| 16 | fri/src/prover.rs:219 *(per fold round)* | `sample_algebra_element() → β` | folding challenge | PCS-internal — record under per-round `SampledChallenge` for replay |
| 17 | fri/src/prover.rs:248 | `observe_algebra_slice(final_poly)` | FRI final polynomial coefficients | gap (`Plonky3ExtendedBindings::fri_final_poly`) |

### FRI query phase (continuing from event 17)

| # | File:Line | Call | Purpose | SHROUD coverage |
|---|---|---|---|---|
| 18 | fri/src/prover.rs:89 *(per arity in `log_arities`)* | `observe(Val::from_usize(log_arity))` | variable-arity schedule | gap (`Plonky3ExtendedBindings::fri_log_arities`, ordered Vec) |
| 19 | fri/src/prover.rs:94 | `grind(query_proof_of_work_bits)` | query-phase PoW witness | PCS-internal — recorded as part of bridge proof envelope |
| 20 | fri/src/prover.rs:107 *(per query, `num_queries` times)* | `sample_bits(log_max_height + extra_query_index_bits)` | query index | PCS-internal — recorded as per-query `SampledChallenge` for replay |

## uni-stark — verify transcript stream (mirror)

From `uni-stark/src/verifier.rs::verify(...)`. The verifier mirrors every prover event in the same order. Cross-reference for the bridge replay harness:

| Prover event | Verifier file:line | Notes |
|---|---|---|
| 1 (log_ext_degree) | verifier.rs:310 | Verifier observes `proof.degree_bits` |
| 2 (log_degree) | verifier.rs:311 | Verifier observes `proof.degree_bits - is_zk` |
| 3 (preprocessed_width) | verifier.rs:312 | |
| 4 (trace_commit) | verifier.rs:318 | |
| 5 (preprocessed_commit) | verifier.rs:320 | conditional |
| 6 (public_values) | verifier.rs:322 | |
| 7 (α) | verifier.rs:328 | |
| 8 (quotient_commit) | verifier.rs:329 | |
| 9 (r_commit) | verifier.rs:334 | conditional |
| 10 (ζ) | verifier.rs:340 | |
| 12 (opened values) | fri/two_adic_pcs.rs:681 | iterates `commitments_with_opening_points` in the same order as prover rounds |
| 13 (α_pcs) | fri/src/verifier.rs:84 | sampled before FRI proof-shape checks, matching the prover's PCS open alpha |
| 14 (commit_phase_commits) | fri/src/verifier.rs:134 | per fold |
| 15 (check_witness) | fri/src/verifier.rs:135 | verifier `check_witness` instead of `grind` |
| 16 (β) | fri/src/verifier.rs:138 | per fold |
| 17 (final_poly) | fri/src/verifier.rs:148 | |
| 18 (log_arities) | fri/src/verifier.rs:157 | |
| 19 (query_pow_witness) | fri/src/verifier.rs:161 | |
| 20 (query indices) | fri/src/verifier.rs:175 | per query |

**Sanity check.** Prover and verifier consume identical events in identical order. Any divergence is a soundness break; the bridge replay harness fails the verifier-side test if it sees one.

## batch-stark — prove transcript stream

From `batch-stark/src/prover.rs::prove(...)`. Adds instance-level events on top of the uni-stark stream.

| # | File:Line | Call | Purpose | SHROUD coverage |
|---|---|---|---|---|
| B1 | batch-stark/src/prover.rs:164 | `observe_base_as_algebra_element(n_instances)` | batch instance count | gap (`Plonky3ExtendedBindings::n_instances`) |
| B2 | batch-stark/src/prover.rs:168 *(via `observe_instance_binding` → config.rs:35-38, per instance)* | `observe_base_as_algebra_element(log_ext_degree)`, `log_degree`, `width`, `n_quotient_chunks` | per-instance shape and quotient layout | gap (`Plonky3ExtendedBindings::instance_bindings`, ordered Vec) |
| B3 | batch-stark/src/prover.rs:186 | `observe(main_commit)` | single batched main trace commitment covering all instances | gap (`Plonky3ExtendedBindings::main_commitment`) |
| B4 | batch-stark/src/prover.rs:188 *(per instance)* | `observe_slice(pv)` | per-instance public values | gap (`Plonky3ExtendedBindings::public_values_per_instance`) |
| B5 | batch-stark/src/prover.rs:195 *(per instance)* | `observe_base_as_algebra_element(pre_w)` | per-instance preprocessed width | gap (`Plonky3ExtendedBindings::preprocessed_width_per_instance`) |
| B6 | batch-stark/src/prover.rs:198 *(conditional)* | `observe(global.commitment)` | single global preprocessed commitment | gap (`Plonky3ExtendedBindings::global_preprocessed_commitment`) |
| B6a | batch-stark/src/prover.rs:203 *(via `get_perm_challenges` → common.rs:297 and common.rs:305)* | `sample_algebra_element()` × lookup challenges | LogUp permutation challenges for local lookups and first-seen global lookup names | PCS-internal — record as a Vec of `SampledChallenge` entries between B6 and B7. Replay must traverse instances, lookup contexts, and global-name reuse in the same order. |
| B7 | batch-stark/src/prover.rs:275 *(conditional: lookups present)* | `observe(commitment.0)` | combined permutation/lookup MMCS commitment | gap (`Plonky3ExtendedBindings::permutation_commitment`) |
| B8 | batch-stark/src/prover.rs:277 *(per lookup, conditional)* | `observe_algebra_element(data.expected_cumulated)` | per-lookup cumulative value | gap (`Plonky3ExtendedBindings::lookup_cumulated_values`) |
| B9 | batch-stark/src/prover.rs:287 | `sample_algebra_element() → α` | constraint batching | canonical — same as uni-stark event 7 |
| B10 | batch-stark/src/prover.rs:398 | `observe(quotient_commit)` | quotient chunks commitment | gap (`Plonky3ExtendedBindings::quotient_commitment`) |
| B11 | batch-stark/src/prover.rs:418 *(conditional)* | `observe(r_commit)` | randomizer commitment | canonical (`DOMAIN_RANDOMIZER_COMMITMENT`) |
| B12 | batch-stark/src/prover.rs:422 | `sample_algebra_element() → ζ` | OOD point | canonical |

Then the shared PCS/FRI machinery runs. The PCS open mechanism is the same as uni-stark, but batch-stark's round list may include an additional lookup/permutation round after preprocessed openings (`batch-stark/src/prover.rs:499-501`), so opened-value binding must use the batch round order exactly.

### batch-stark verifier mirror

| Prover event | Verifier file:line |
|---|---|
| B1 (n_instances) | batch-stark/src/verifier.rs:86 |
| B2 (per-instance binding data) | batch-stark/src/verifier.rs:218 (via `observe_instance_binding` → config.rs:35-38) |
| B3 (main_commit) | batch-stark/src/verifier.rs:222 |
| B4 (pv) | batch-stark/src/verifier.rs:224 |
| B5 (pre_w) | batch-stark/src/verifier.rs:230 |
| B6 (global.commitment) | batch-stark/src/verifier.rs:233 |
| B6a (perm challenges) | batch-stark/src/verifier.rs:245 (via `get_perm_challenges` → common.rs:297 and common.rs:305) |
| B7 (permutation commitment) | batch-stark/src/verifier.rs:249 |
| B8 (expected_cumulated) | batch-stark/src/verifier.rs:256 |
| B9 (α) | batch-stark/src/verifier.rs:261 |
| B10 (quotient_commit) | batch-stark/src/verifier.rs:264 |
| B11 (r_commit) | batch-stark/src/verifier.rs:269 |
| B12 (ζ) | batch-stark/src/verifier.rs:273 |

## SHROUD coverage summary

Of the 20 uni-stark events (plus the batch-stark-specific additions above, of which B6a is a *sample* — permutation challenges — rather than an observe), **3 are canonical** in the current `StandardBatchOpeningBindings`:

- Event 9 / B11: randomizer commitment ↔ `DOMAIN_RANDOMIZER_COMMITMENT`
- Event 7 / B9: AIR α ↔ `SampledChallenge::SampleBatchingChallenge`
- Event 10 / B12: ζ ↔ `SampledChallenge::SampleOodPoint`

Event 6 (AIR public values) is *adjacent* to `DOMAIN_PUBLIC_OPENINGS` but the latter currently binds *opened values at ζ*, not AIR public inputs. Renaming or splitting is open design work; the safe path is to keep both as distinct slots.

Everything else is a gap that `Plonky3ExtendedBindings` must hold.

## `Plonky3ExtendedBindings` — required slots

The bridge wrapper composes `StandardBatchOpeningBindings` (canonical v1) with these Plonky3-specific bindings:

### Instance metadata (event 1, 2, 3, B1, B2, B5)
- `log_ext_degree: u8`
- `log_degree: u8`
- `preprocessed_width: usize`
- `n_instances: usize` *(batch-stark)*
- `instance_bindings: Vec<{ log_ext_degree, log_degree, width, n_quotient_chunks }>` *(batch-stark, one entry per instance)*
- `preprocessed_width_per_instance: Vec<usize>` *(batch-stark)*

### Commitments (event 4, 5, 8, B3, B6, B7, B10)
- `trace_commitment: Com` *(uni-stark)* / `main_commitment: Com` *(batch-stark, one batched commitment covering all instances)*
- `preprocessed_commitment: Option<Com>` *(uni)* / `global_preprocessed_commitment: Option<Com>` *(batch)*
- `quotient_commitment: Com`
- `permutation_commitment: Option<Com>` *(batch-stark, present iff any lookups)*

### Lookup state (events B6a, B8)
- `permutation_challenges: Vec<Challenge>` *(replay-only: derived from preceding bindings; preserve the exact `get_perm_challenges` traversal order, including local lookups and first-seen global-name reuse)*
- `lookup_cumulated_values: Vec<Challenge>`

### AIR public inputs (event 6, B4)
- `air_public_values: Vec<Val>` *(uni-stark, flat)* / `Vec<Vec<Val>>` *(batch-stark, per instance)*

### FRI proof envelope (events 14, 17, 18 → committed bytes; 15, 19, 20 → replay-only)
- `fri_commit_phase_commitments: Vec<Com>` *(in fold order)*
- `fri_final_poly: Vec<Challenge>`
- `fri_log_arities: Vec<usize>`
- PoW witnesses + query indices live in `SampledChallenge` records, not bindings

Where `Com` is the pinned `MerkleTreeHidingMmcs` commitment type (`MerkleCap<P::Value, [PW::Value; DIGEST_ELEMS]>` in `merkle-tree/src/hiding_mmcs.rs`). Canonical encoding must follow Plonky3's actual `CanObserve<Com>` serialization, not a hand-rolled digest guess. For field elements, serialize each BabyBear `Val` as canonical `u32` LE, and serialize `Challenge = BinomialExtensionField<Val, 4>` as 4 × `u32` LE in `BasisDescriptor` order.

## Replay test harness — minimum coverage

Once `Plonky3ExtendedBindings` is implemented, the bridge replay test must:

1. Generate a proof with the pinned `HidingBackend` config on a minimal AIR; capture the proof artifacts and the replayable transcript event stream.
2. Construct a `Plonky3ExtendedBindings` from the proof artifacts and pinned profile.
3. Build the `CanonicalBatchOpeningManifest` via `TranscriptBindingManifest::standard_for_batch_opening(...)`, explicitly call `into_inner()` at the Plonky3 extension boundary, then compose the Plonky3-specific slots.
4. Build a `Plonky3TranscriptChallengeDeriver` that wraps `SerializingChallenger32` and replays each `SampledChallenge` from the absorbed prefix.
5. Run `ReferenceTranscript::finish(deriver)` and assert `Ok(())`.

The negative battery mutates one binding at a time and asserts `finish` rejects with the expected variant:

| Mutation | Expected rejection |
|---|---|
| Flip a byte in `trace_commitment` | `BindingFinalization(BindingMismatch { DOMAIN_..._TRACE_COMMITMENT })` |
| Flip a byte in `fri_final_poly` | `BindingFinalization(BindingMismatch { ... })` |
| Drop one `fri_commit_phase_commitments` entry | `ChallengeReplayMismatch` (β derivation differs) |
| Swap two `log_arities` | `ChallengeReplayMismatch` (query index derivation differs) |
| Use a different hash-suite identifier | `ChallengeReplayMismatch` |
| Reorder opened values vs round order | `ChallengeReplayMismatch` (α_pcs derivation differs) |

Each is a determinism test, not a randomness test.

## Open question — `DOMAIN_PUBLIC_OPENINGS` semantics

The current `DOMAIN_PUBLIC_OPENINGS` slot is described as "public openings observed before final verification" but Plonky3 distinguishes:

- **AIR public values** (event 6): inputs to the AIR's transition constraints, observed *before* α.
- **Opened values at ζ** (event 12): polynomial evaluations at the OOD point, observed *inside the PCS* between ζ-sample and α_pcs-sample.

These are different transcript events at different stages. The current SHROUD spec implicitly conflates them. Bridge work needs to decide one of:

- **(a)** Rename `DOMAIN_PUBLIC_OPENINGS` to `DOMAIN_OPENED_VALUES` (event 12 semantics) and add `DOMAIN_AIR_PUBLIC_VALUES` (event 6) as a new canonical slot in `shroud-core`.
- **(b)** Keep `DOMAIN_PUBLIC_OPENINGS` for AIR public values (event 6, before α) and add `DOMAIN_OPENED_VALUES` for event 12.
- **(c)** Leave `DOMAIN_PUBLIC_OPENINGS` ambiguous in `shroud-core` and have `Plonky3ExtendedBindings` hold both events as Plonky3-specific slots.

Option (c) is the lowest-risk choice for the bridge work — defer the canonical-schedule split until a second backend forces the question.
