# SHROUD Security Model

This document is the canonical answer to *"what attack class does each piece of SHROUD defend against?"* It is structured as a threat-model mapping: each section names a Fiat-Shamir / interactive-protocol failure mode and points at the SHROUD code that closes it.

The structure mirrors the failure taxonomy commonly used to audit Schnorr-style interactive arguments after the Fiat-Shamir transform: most real-world breaks are not algebraic, they are implementation-level — missing transcript binding, prover-controlled verifier parameters, weak hash-suite domain separation, randomness reuse. SHROUD is FRI/Reed-Solomon based, not group-based, so the curve-specific panels (subgroup validation, bad generators, point-on-curve checks) do not apply. The rest do.

Read alongside:
- `crates/shroud-core/src/binding.rs` — binding types and canonical manifest
- `crates/shroud-reference/src/lib.rs` — `ReferenceTranscript`, challenge replay
- `docs/Plonky3 Integration Checklist.md` — bridge-side obligations

---

## 1. Transcript must bind all public context

**Failure class.** The Fiat-Shamir hash must absorb every public parameter that influences a challenge. Anything omitted is an attacker-controlled free variable: replay, context confusion, cross-protocol forgery.

**SHROUD answer.**

| Concern | Symbol |
|---|---|
| Typed binding for every protocol object | `TranscriptBindable` (`shroud-core/src/binding.rs:108`) |
| Compile-time-enforced complete manifest | `StandardBatchOpeningBindings::from_bindables` (`shroud-core/src/binding.rs:342`) |
| Canonical schedule mapping bindings to challenge points | `TranscriptBindingManifest::standard_for_batch_opening` (`shroud-core/src/binding.rs:417`) |
| Per-sampling-stage enforcement at runtime | `ReferenceTranscript::advance` (`shroud-reference/src/lib.rs`) calls `assert_exact_present(manifest.required_before(stage))` |

`from_bindables` takes ten typed `TranscriptBindable` generic params — a bridge using the canonical constructor *cannot* silently omit a binding; the compiler catches it.

---

## 2. Missing inputs → replay, context confusion, cross-protocol forgery

**Failure class.** If the hash does not bind the commitment, public key, protocol context, or domain separator, the proof no longer represents the intended statement. Replays succeed across contexts.

**SHROUD answer.**

Per-object domain labels prevent confusion at the byte-equality layer:

| Domain label | Object | File |
|---|---|---|
| `DOMAIN_HASH_ID` | hash-suite identifier | `binding.rs:60` |
| `DOMAIN_PROFILE` | hiding-FRI-PCS profile (log_blowup, randomizer count, basis, technique) | `binding.rs:21` |
| `DOMAIN_BASIS` | extension-field basis | `binding.rs:24` |
| `DOMAIN_BATCH_OPENING` | full batch-opening spec | `binding.rs:42` |
| `DOMAIN_CODEWORD_EMBEDDING` | codeword-embedding spec | `binding.rs:45` |
| `DOMAIN_ORACLE_COMMITMENT` | oracle-commitment spec | `binding.rs:27` |
| `DOMAIN_OPENING_PROJECTION` | opening-projection spec | `binding.rs:48` |
| `DOMAIN_QUOTIENT_HIDER` | quotient-hider spec | `binding.rs:51` |
| `DOMAIN_DEGREE_CONTRACT` | quotient degree contract | `binding.rs:33` |
| `DOMAIN_RANDOMIZER_COMMITMENT` | concrete randomizer commitment (Merkle root, etc.) | `binding.rs:30` |
| `DOMAIN_PUBLIC_OPENINGS` | backend-canonical public opening bytes | `binding.rs:39` |
| `DOMAIN_SECURITY_LEVEL` | Statistical vs Perfect | `binding.rs:36` |
| `DOMAIN_HIDING_TECHNIQUE` | declared hiding-technique tree | `binding.rs:57` |

Substituting one object's bytes under another's label triggers `TranscriptBindingError::BindingMismatch` (`binding.rs:242`) at finalize. Test: `cross_protocol_substitution_at_oracle_label_fails_finalize` in `shroud-reference/src/lib.rs`.

---

## 3. Weak vs strong transcript construction

**Failure class.** A hand-rolled manifest that forgets a binding compiles cleanly and runs successfully — until an attacker exploits the missing parameter.

**SHROUD answer.**

- **Strong path (recommended for all bridges):** `StandardBatchOpeningBindings::from_bindables(...)` → `TranscriptBindingManifest::standard_for_batch_opening(...)`. Compile-time check that every typed binding is supplied.
- **Weak path (test-only / experimental):** `TranscriptBindingManifest::new()` + `with_before_*` builders. Documented with a "Dangerous: hand-rolled" doctest on `TranscriptBindingManifest::new` (`shroud-core/src/binding.rs:408`) showing that a half-empty manifest is buildable and the only defense is calling-convention discipline.

Bridges should default to the strong path. The weak path exists so narrow schedule tests can construct minimal manifests; using it in production-facing code is a review red flag.

---

## 4. Verifier must independently validate, not trust prover-controlled inputs

**Failure class.** A verifier that accepts attacker-supplied generators, group orders, challenge values, or PCS parameters has surrendered part of its security boundary.

**SHROUD answer.**

The `shroud-plonky3` crate pins constants the verifier re-derives independently — not from the proof, from the bridge's own compile-time-pinned view of the backend:

| Pinned constant | Where verified |
|---|---|
| `LOG_BLOWUP_HIDING = 2` | `shroud_plonky3::BACKEND_LOG_BLOWUP` → `verify_profile_matches_backend` |
| `NUM_RANDOMIZER_COLS = 4` | `shroud_plonky3::BACKEND_NUM_RANDOMIZER_COLS` → `verify_profile_matches_backend` |
| Challenge field extension degree | `shroud_plonky3::BACKEND_EXTENSION_DEGREE` → `verify_profile_matches_backend` |
| FRI query count | `shroud_plonky3::BACKEND_NUM_QUERIES` |
| Query proof-of-work bits | `shroud_plonky3::BACKEND_QUERY_POW_BITS` |
| `p3-symmetric` advisory floor (GHSA-3g92-f9ch-qjcm) | `shroud_plonky3::PINNED_P3_SYMMETRIC_VERSION` (build-time-derived) → `check_advisory` |
| `input_mmcs_hiding == true` | `verify_profile_matches_backend` → `BackendDriftError::NonHidingInputMmcs` |
| `fri_mmcs_hiding == true` | `verify_profile_matches_backend` → `BackendDriftError::NonHidingFriMmcs` |
| Composite hiding technique present | `required_plonky3_hiding_techniques()` → `BackendDriftError::MissingHidingTechnique` |

`shroud_plonky3::verify_profile_matches_backend(profile)` is the canonical bridge-setup primitive. It takes **no caller-supplied advisory version** — the resolved `p3-symmetric` is derived from `Cargo.lock` at build time and exposed as `PINNED_P3_SYMMETRIC_VERSION`. Drift tests (`check_profile_drift_rejects_*`) prove every drift class is rejected; advisory tests (`check_advisory_currently_returns_unpatched`, `verify_profile_matches_backend_currently_blocks_on_advisory`) prove the gate fires against the real dependency graph.

**Residual risk.** This is currently a *pattern*, not a trait obligation. `BatchOpeningAdapter` does not force a bridge to call it. Promoting it to a trait method (e.g. `VerifierIndependentChecks::backend_constants() -> &'static [(&str, BackendConstant)]`) is open follow-up work — see `docs/Plonky3 Integration Checklist.md`.

### Hash-suite advisory enforcement (GHSA-3g92-f9ch-qjcm)

`p3-symmetric < 0.6` admits sponge-length collisions when an attacker can vary the number of hashed elements. SHROUD's `TranscriptBinding` payloads are length-prefixed throughout, which mitigates the attack surface, but `shroud-plonky3` treats the advisory floor as a **type-level precondition derived from reality**:

- `crates/shroud-plonky3/build.rs` parses the workspace `Cargo.lock` and emits `SHROUD_P3_SYM_{MAJOR,MINOR,PATCH}` as `cargo:rustc-env` variables.
- `PINNED_P3_SYMMETRIC_VERSION: P3SymmetricVersion` is a `pub const` built from those env vars via a `const fn parse_const_u64`. The version reflects the actually-resolved dependency, not a caller claim.
- `verify_profile_matches_backend(profile)` takes no version argument. The advisory check fires first — before any profile drift check — because without a patched hash, every other check is built on quicksand.
- An earlier API exposed a `p3_symmetric: P3SymmetricVersion` parameter, which let callers declare a patched version against an unpatched graph. That trust hole is closed by removing the parameter.

**Current state (intentionally surfaced):** the pinned `p3-zk-proofs` revision resolves `p3-symmetric = 0.5.2`. `verify_profile_matches_backend` therefore returns `BackendDriftError::UnpatchedSymmetric { declared: 0.5.2, min_patched: 0.6.0 }` for every profile, and `assert_profile_matches_backend()` panics with the advisory message. This is honest — the bridge is not production-safe until the pinned dep is upgraded. The test `pinned_state_is_currently_unpatched_per_advisory` asserts the current state and fails when the upgrade lands, triggering a sweep of related `#[should_panic]` tests.

---

## 5. Hash-suite substitution

**Failure class.** Two backends with identical absorbed protocol objects but different challenge derivation suites must not share a transcript. Without a bound suite identifier, a verifier using suite A can be convinced by a proof generated under suite B.

**SHROUD answer.**

- `HashIdentifier` (`shroud-core/src/binding.rs:119`) is a first-class `TranscriptBindable` absorbed under `DOMAIN_HASH_ID` before any challenge is sampled.
- `TranscriptChallengeDeriver::hash_identifier` (`binding.rs:214`) requires every challenge deriver to expose its identifier so verifier replay catches suite mismatch.
- `ReferenceTranscript::replay_challenges` (`shroud-reference/src/lib.rs:129`) re-derives every sampled challenge under the verifier's deriver and returns `ChallengeReplayMismatch` if any byte differs.

Test: `replay_with_wrong_hash_suite_fails` in `shroud-reference` uses `ReferenceChallengeDeriver::new(HashIdentifier::new("wrong-transcript-suite"))` and asserts the replay rejects.

---

## 6. Nonce / randomness reuse

**Failure class.** Schnorr's `z = r + xc` recovers `x` if `r` repeats. SHROUD doesn't use Schnorr's algebra, but the spirit applies: if the random codewords in `HidingFriPcs::new` come from a deterministic CSPRNG with a reused seed, the masking degenerates from statistical hiding to computational, and witness rows become recoverable from queries.

**SHROUD answer.**

- `RandomnessModel` (`shroud-core/src/claim.rs:10`) is the audit-obligation surface. Two declared models:
  - `UniformPerProof` — fresh OS-entropy randomness per proof.
  - `CsprngFromOsEntropy` — CSPRNG seeded from OS entropy per proof.
- Both forbid seed reuse across proofs. A backend that wires `HidingFriPcs::new` to a deterministic CSPRNG without fresh seeding violates the declared `RandomnessModel`.
- `PerfectClaim::validate` (`claim.rs`) rejects `hiding_mmcs = false` outright — a non-hiding MMCS leaks witness values on query, defeating any randomness model.

**Audit obligation.** Bridges must document where the randomness comes from and confirm it matches the declared `RandomnessModel`. SHROUD cannot enforce this at the type level — the entropy source lives in the backend.

---

## 7. Stage-scoped binding completeness

**Failure class.** "All bindings present at the end" is not enough. A challenge sampled before its required bindings were absorbed is unsound, even if every binding is eventually present.

**SHROUD answer.**

`TranscriptBindingManifest::required_before(stage)` (`binding.rs:458`) returns the exact bindings required before each sampling stage. `ReferenceTranscript::advance` calls `assert_exact_present` for that subset before moving the cursor. Failures surface as `ReferenceTranscriptError::MissingBindingBeforeStage` — distinct from end-of-transcript failures.

The canonical per-stage label sequence (in the order they are absorbed):

- Before `SampleBatchingChallenge`: `DOMAIN_HASH_ID`, `DOMAIN_PROFILE`, `DOMAIN_BASIS`, `DOMAIN_BATCH_OPENING`, `DOMAIN_CODEWORD_EMBEDDING`, `DOMAIN_ORACLE_COMMITMENT`, `DOMAIN_OPENING_PROJECTION`, `DOMAIN_QUOTIENT_HIDER`, `DOMAIN_SECURITY_LEVEL`.
- Before `SampleOodPoint`: `DOMAIN_DEGREE_CONTRACT`, `DOMAIN_RANDOMIZER_COMMITMENT`.
- Before `ProveMaskedRelation`: `DOMAIN_PUBLIC_OPENINGS`.

**Source of truth.** The above list is locked by `standard_manifest_per_stage_label_sequence_is_canonical` in `shroud-reference/src/lib.rs`. The test re-derives each per-stage sequence from `TranscriptBindingManifest::standard_for_batch_opening` and asserts byte-equality with the hard-coded expected order. Any future refactor that reorders bindings without updating this doc fails CI. Treat the test name as canonical — if it and this prose disagree, the test wins.

Additionally, `ReferenceTranscript::finish` (`shroud-reference/src/lib.rs:149`) enforces that every sampling stage actually recorded a challenge (`MissingSampledChallenge`) — catches the "advance past a sample stage without sampling" silent-skip bug.

---

## 8. Failed observe must not pollute the record

**Failure class.** If a transcript implementation absorbs bytes into its hash state before validating that the call was in-protocol, an attacker can call an observe method at the wrong stage, get an error back, and leave attacker-chosen bytes in the absorbed prefix. A later legitimate sampling stage may then be satisfied by the polluted bytes.

**SHROUD answer.**

`ReferenceTranscript::observe_perfect_randomizer_commitment` (`shroud-reference/src/lib.rs`) checks `expected_stage()` *before* mutating the record. On stage mismatch it returns `UnexpectedStage` without absorbing.

Test: `failed_observe_does_not_pollute_binding_record` drives `backend.observe(...)` against a transcript parked at `ObserveMainCommitments` and asserts (a) the error is `UnexpectedStage` and (b) `transcript.record().contains_binding(DOMAIN_RANDOMIZER_COMMITMENT)` is `false`.

---

## What does *not* apply (and why)

| Image panel | Does not apply because |
|---|---|
| Subgroup validation, "is this point on the curve" | SHROUD's commitments are FRI / Reed-Solomon, not group-element based. No curve, no subgroup. |
| Bad generators, group orders | Same — no group structure at the SHROUD layer. The backend's hash sponge may use group elements internally, but that's a hash-construction concern below SHROUD. |
| Schnorr-specific recovery `x = (z - z') / (c - c')` | Illustrative of nonce reuse, but the recovery algebra is Schnorr-specific. The *concept* maps to randomness reuse in `HidingFriPcs::new` (covered in §6); the math does not. |
| Vault-and-padlock metaphor | Pedagogy. |

---

## Adversarial test battery

For bridge code, the security model implies a five-test minimum:

| # | Test | Reference impl |
|---|---|---|
| 1 | Missing-binding | `missing_*_binding_fails_finalize` family (`shroud-reference/src/lib.rs`) |
| 2 | Context-substitution (wrong bytes, right label) | `wrong_bytes_for_typed_binding_fails_finalize_with_mismatch` |
| 3 | Cross-protocol substitution (right bytes, wrong label slot) | `cross_protocol_substitution_at_oracle_label_fails_finalize` |
| 4 | Hash-suite substitution | `replay_with_wrong_hash_suite_fails` |
| 5 | Verifier-trust drift (backend-constant mutation rejected) | `verify_profile_matches_backend_rejects_drifted_*` |

Bridges port these by replacing the reference deriver / record with the production Fiat-Shamir transcript and re-asserting every test against the real prove/verify path.

---

## Pre-merge checklist for new SHROUD objects

When a new SHROUD object lands:

1. **Domain label.** Add a `DOMAIN_*` constant in `shroud-core/src/binding.rs`. Distinct from all existing labels (the `domain_labels_are_distinct_across_all_constants` test enforces this).
2. **Canonical binding.** Implement `TranscriptBindable` with a stable little-endian encoding of every field that influences a challenge.
3. **Manifest routing.** Decide which sampling stage absorbs it. Add a binding slot in `StandardBatchOpeningBindings` and a `with_before_*` call in `standard_for_batch_opening`.
4. **Verifier independence.** Document which fields the verifier re-derives independently (vs trusts from the proof). If pinned to a backend, add a drift-detection function in the canonical `verify_profile_matches_backend` shape.
5. **Randomness audit.** If the object introduces a new randomness source, document the required `RandomnessModel` and the backend obligation.

The above is the lightweight ritual that prevents the binding layer from rotting as the workspace grows.
