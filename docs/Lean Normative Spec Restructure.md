# Lean Normative Spec Restructure

**Status:** architecture plan; phase 2 binding manifest started  
**Scope:** SHROUD core, protocol-object crates, reference model, backend bridges  
**Decision:** Lean becomes the normative protocol/specification layer; Rust remains the executable integration and backend-audit layer.

This document describes how to restructure SHROUD before publication so that its most important claims are stated and proved in Lean, while the Rust workspace continues to run the concrete Plonky3 bridge, transcript recorder, adversarial tests, and backend-specific integration code.

The goal is not to turn SHROUD into a Lean prover. The goal is to make SHROUD's protocol rules precise enough that Rust code, backend bridges, papers, and audits can all point to the same formal source of truth.

**Current implementation note:** the repository now contains `lean-toolchain`, `lakefile.lean`, `formal/Shroud/Core/Security.lean`, `formal/Shroud/Core/Transcript.lean`, and `formal/Shroud/Core/Binding.lean`. The initial quality gate is `lake build --wfail`.

## 1. Problem SHROUD Is Solving

SHROUD is meant to make privacy/hiding in transparent Reed-Solomon, FRI, and WHIR-style proof systems explicit and auditable.

The failure mode SHROUD is trying to prevent is not only "the prover forgot to add randomness." Real privacy failures usually appear at the implementation boundary:

- a commitment is not bound before a Fiat-Shamir challenge;
- a backend accepts prover-controlled PCS or hash parameters;
- a randomizer commitment exists but is observed in the wrong transcript position;
- hidden openings accidentally become public proof fields;
- a degree mask changes the polynomial class that the verifier expects;
- the declared query budget does not match the hiding construction;
- a "perfect" or "statistical" privacy label is attached without the supporting obligations;
- a backend hash suite or dependency version changes under the bridge;
- a live transcript test only covers a prefix while docs imply full proof coverage.

SHROUD's value is the structured contract around those hazards:

1. protocol objects name the hiding layers;
2. transcript bindings make public context explicit;
3. degree contracts make masking preconditions explicit;
4. adapter plans say where hidden/public data lands in backend proof layouts;
5. bridge code checks real backend bytes and dependency provenance.

Lean should formalize items 1-3 first, then parts of item 4 when there is enough backend evidence. Rust should continue to own item 5.

## 2. Architectural Decision

The target architecture is a two-layer system:

```text
Lean normative layer
  Defines protocol objects, schedules, binding manifests, degree rules,
  payload accounting, and theorem statements.

Rust executable layer
  Mirrors Lean definitions where practical, runs backend bridges, records
  real transcripts, checks Cargo provenance, and tests integrations.
```

Lean is the source of truth for protocol semantics. Rust is the source of truth for actual backend behavior.

That split is intentional. Lean is excellent for proving that a degree rule, transcript schedule, or payload accounting law follows from the SHROUD definitions. Rust is better for checking that Plonky3 actually absorbed these bytes, resolved this dependency, used this hash suite, and produced this event order.

### Normative Rule

After this restructure, any change that alters a SHROUD protocol rule must update Lean first or in the same PR.

Examples of protocol-rule changes:

- adding, removing, or reordering transcript stages;
- adding a required binding before a challenge;
- changing a degree budget formula;
- changing the conditions for `SecurityLevel::Perfect`;
- changing the payload shape of a SHROUD object;
- changing what a backend adapter must preserve.

Pure Rust integration changes do not need Lean updates unless they change the protocol contract.

Examples of Rust-only changes:

- changing Plonky3 recorder internals;
- updating Cargo provenance parsing;
- adding a live negative test;
- bumping a pinned backend revision;
- changing error display text;
- optimizing Rust constructors without semantic changes.

## 3. Proposed Repository Shape

Add a formal package beside the Rust crates:

```text
shroud/
  Cargo.toml
  lakefile.lean
  lean-toolchain
  formal/
    Shroud/
      Basic.lean
      Core/
        Nat.lean
        Labels.lean
        Security.lean
        Transcript.lean
        Binding.lean
        Degree.lean
        Claim.lean
        Hiding.lean
      Objects/
        BatchOpening.lean
        CodewordEmbedding.lean
        OracleCommitment.lean
        QuotientHider.lean
        OpeningProjection.lean
      Adapter/
        Plan.lean
        Composition.lean
      Bridge/
        Plonky3PreGrind.lean
        Provenance.lean
        Assumptions.lean
      Conformance/
        RustVectors.lean
      Theorems/
        TranscriptSafety.lean
        DegreeSafety.lean
        PayloadAccounting.lean
        ClaimConsistency.lean
  crates/
    shroud-core/
    shroud-batch-opening/
    shroud-codeword-embedding/
    shroud-oracle-commitment/
    shroud-quotient-hider/
    shroud-opening-projection/
    shroud-adapter/
    shroud-reference/
    shroud-plonky3/
  docs/
```

The exact Lean module layout can change, but the separation should remain:

- `Core`: reusable protocol vocabulary;
- `Objects`: the five SHROUD objects;
- `Adapter`: backend-neutral proof-layout obligations;
- `Bridge`: backend-specific assumptions and partial formal models;
- `Conformance`: Rust/Lean synchronization artifacts;
- `Theorems`: named properties that docs and papers cite.

## 4. Responsibility Boundary

### Lean Owns

Lean should own the normative definitions for:

- `SecurityLevel`;
- transcript stages and the canonical SHROUD schedule;
- domain labels as a finite label set;
- binding manifests and required-before-challenge relations;
- degree budgets for batch-opening masks;
- quotient degree contracts;
- nonzero shape constraints;
- payload accounting for public and hidden surfaces;
- claim consistency rules for perfect/statistical variants;
- adapter preservation laws once composition is introduced.

Lean should prove:

- valid transcript plans preserve challenge ordering;
- the canonical manifest contains all required SHROUD bindings;
- degree budgets imply masked relations stay inside declared degree classes;
- object payload fields are deterministic functions of validated shapes;
- codeword embedding statistical hiding preconditions are explicit;
- quotient hider query and degree bounds are internally consistent;
- perfect-claim constructors require the supporting claim object.

### Rust Owns

Rust should own:

- concrete constructors and errors;
- property tests and adversarial batteries;
- byte encodings used by real transcript bindings;
- Plonky3 live recorder behavior;
- `Cargo.lock` provenance and advisory gates;
- backend profile drift detection;
- CI against real Plonky3 proof generation and verification;
- ergonomic APIs used by downstream integrators.

Rust should not claim to prove protocol laws. It should claim to implement and test conformance to the Lean-defined protocol laws.

### Shared Boundary

The shared boundary is a conformance layer:

- Lean defines the expected constructor outcomes and theorem-backed invariants;
- Rust exposes test vectors or fixtures for canonical cases;
- CI checks that Rust constructors, encodings, and manifests match the Lean model.

For the first pass, this can be manual and test-vector based. Later, it can become generated.

## 5. Formalization Levels

Not every statement needs the same level of formal proof. SHROUD should classify each claim into one of four levels.

### Level 0: Executable Check Only

The claim is about a real backend, dependency graph, or byte stream.

Examples:

- `p3-symmetric` resolved to a reviewed git revision;
- Plonky3 observed a 32-byte commitment at event 4;
- the live pre-grind prefix replays byte-for-byte;
- a negative mutation test fails.

Tool: Rust tests.

### Level 1: Formal Data Model

The claim is represented in Lean, but has only simple decidable checks.

Examples:

- domain labels are distinct;
- transcript stages have an ordinal order;
- a shape field is nonzero;
- a security level is statistical or perfect.

Tool: Lean definitions plus decidable validation.

### Level 2: Proven Local Theorem

The claim is a local protocol invariant.

Examples:

- `randomizer_degree <= relation_degree + 1` implies the batch-opening mask preserves degree class;
- `randomizer_columns = extension_degree` is required for the current statistical codeword embedding;
- a monolithic quotient hider has exactly one component;
- a degree-chunked quotient hider carries a degree contract.

Tool: Lean theorem.

### Level 3: Conditional Bridge Theorem

The claim connects SHROUD's formal model to a backend under explicit assumptions.

Examples:

- if the event log satisfies the Plonky3 pre-grind grammar and byte replay succeeds, then the bridge transcript prefix is faithful to the modeled SHROUD schedule;
- if the backend profile matches pinned constants and advisory gate passes, then the bridge is not accepting prover-controlled hiding parameters;
- if every privacy-critical WHIR event is modeled and live-negative-tested, then the bridge enforces transcript binding for that event set.

Tool: Lean theorem with Rust-backed assumptions.

Level 3 statements must be written carefully. They should not pretend to prove Plonky3's cryptography or Keccak's security. They should say exactly what is assumed.

## 6. Lean Module Plan

### `Shroud.Core.Security`

Defines:

```lean
inductive SecurityLevel
  | statistical
  | perfect
```

Initial theorem targets:

- discriminants are injective;
- transcript encoding for security level is deterministic;
- perfect-specific constructors require a perfect claim once the Rust API is tightened.

### `Shroud.Core.Transcript`

Defines:

- `TranscriptStage`;
- canonical stage order;
- strict ordering relation;
- sampling stages;
- observe stages.

Important objects:

```lean
inductive TranscriptStage
  | observeMainCommitments
  | sampleBatchingChallenge
  | observeQuotientCommitments
  | observeRandomizerCommitment
  | sampleOodPoint
  | observePublicOpenings
  | proveMaskedRelation
```

Initial theorem targets:

- the canonical schedule is valid;
- every valid full schedule equals the canonical stage list, unless the model later permits extensions;
- `observeRandomizerCommitment` precedes `sampleOodPoint`;
- no sampling stage can be reached before its required prior observe stages.

### `Shroud.Core.Binding`

Defines:

- finite domain-label set;
- binding payload abstraction;
- exact binding equality;
- manifest stage buckets;
- canonical batch-opening manifest.

Lean does not need to model every byte initially. It can model payloads as an abstract type with equality. Byte-level encodings remain Rust-owned until conformance tests are introduced.

Initial theorem targets:

- domain labels are pairwise distinct;
- every canonical SHROUD binding appears exactly once in the canonical manifest;
- no canonical binding appears in two different stage buckets;
- required-before-batching, required-before-OOD, and required-before-prove buckets match the security model;
- manifest finalization implies exact expected binding presence, but not temporal hash ordering.

That last point is important: Lean should preserve the distinction already present in Rust. Manifest finalization is not the same as proving transcript chronology.

### `Shroud.Core.Degree`

Defines:

- natural-number degree bounds;
- `DegreeBudget`;
- masked relation degree bound;
- batch-opening mask precondition.

Initial theorem targets:

- `DegreeBudget.valid relation randomizer` iff `randomizer <= relation + 1`;
- if valid, `maskedBound = max relation (randomizer - 1)`;
- if valid, `maskedBound <= relation`;
- invalid budgets are exactly those where the randomizer would grow the relation class.

The last two may require careful handling of the convention around degree zero and `Nat` subtraction. The Lean model should avoid Rust's `saturating_sub` as the normative concept and instead state the mathematical rule directly.

### `Shroud.Core.Claim`

Defines:

- `RandomnessModel`;
- `BasisDescriptor`;
- `FieldModel`;
- `SimulatorObligations`;
- `PerfectClaim`;
- claim validation.

Initial theorem targets:

- `PerfectClaim.valid` implies extension degree is positive;
- `PerfectClaim.valid` implies query budget is positive;
- `PerfectClaim.valid` implies the MMCS hiding flag is true;
- encoded-coordinate field models expose the basis extension degree;
- native-extension field models expose the declared extension degree.

Lean should also name what it does not prove: randomness freshness and simulator correctness are assumptions until a concrete backend model exists.

### `Shroud.Core.Hiding`

Defines:

- hiding technique claims;
- composite hiding technique trees;
- containment relation.

Initial theorem targets:

- `contains` is reflexive for named variants;
- `contains` descends into composite branches;
- backend-specific containment is exact string equality;
- required Plonky3 hiding techniques are contained in the standard profile claim tree.

### `Shroud.Objects.BatchOpening`

Defines:

- `BatchOpeningShape`;
- statistical randomizer spec;
- perfect randomizer realization;
- proof slot layout;
- hidden opening transport;
- randomizer opening payload;
- `ShroudBatchOpeningSpec`.

Initial theorem targets:

- statistical randomizer coordinate count equals extension degree;
- statistical payload hidden coordinate openings equal `opening_points * extension_degree`;
- encoded-oracle-bundle perfect payload hidden coordinates equal `opening_points * basis.extension_degree`;
- native-extension perfect payload is backend-proof-only;
- the perfect constructor requires a `PerfectClaim` in the new normative model;
- the transcript plan of a valid batch-opening spec is canonical or explicitly extension-safe.

### `Shroud.Objects.CodewordEmbedding`

Defines:

- `CodewordEmbeddingShape`;
- `CodewordEmbeddingPayload`;
- `ShroudCodewordEmbeddingSpec`.

Initial theorem targets:

- statistical validity implies `randomizer_columns = extension_degree`;
- statistical validity implies `required_log_blowup >= 2`;
- committed columns equal trace columns plus randomizer columns;
- public trace columns equal shape trace columns;
- hidden randomizer columns equal shape randomizer columns;
- perfect codeword embedding is rejected until a perfect constructor carries a `PerfectClaim`.

### `Shroud.Objects.QuotientHider`

Defines:

- quotient decomposition family;
- quotient auxiliary transport;
- quotient degree contract;
- quotient hider shape;
- quotient hider payload;
- `ShroudQuotientHiderSpec`.

Initial theorem targets:

- plain additive degree contract is valid iff `mask_degree <= quotient_chunk_degree`;
- vanishing-factor contract is valid iff `max quotient_chunk_degree (vanishing_degree + mask_degree) <= randomized_bound`;
- query budget is positive;
- opening points do not exceed query budget;
- monolithic decomposition has one component;
- degree-chunked decomposition requires a degree contract;
- payload public openings equal `opening_points * openings_per_point`;
- payload hidden masks equal `opening_points * hidden_mask_values_per_point`.

### `Shroud.Objects.OracleCommitment`

Defines:

- oracle commitment shape;
- oracle commitment payload;
- `ShroudOracleCommitmentSpec`.

Initial theorem targets:

- public commitments equal committed oracle count;
- public row values equal queried rows times row width;
- public authentication items equal queried rows times authentication items per query;
- hidden witness items equal queried rows times hidden witness items per query;
- all shape dimensions are nonzero.

### `Shroud.Objects.OpeningProjection`

Defines:

- opening projection shape;
- opening projection payload;
- `ShroudOpeningProjectionSpec`.

Initial theorem targets:

- public opening count is preserved from shape to payload;
- hidden auxiliary count is preserved;
- verifier reconstruction count is preserved;
- transport is explicit and does not change the public/hidden counts.

### `Shroud.Adapter.Plan`

Defines:

- backend-neutral adapter plans;
- object-to-plan preservation relation;
- required blowup relation.

Initial theorem targets:

- a batch-opening adapter plan preserves security level, commitment boundary, proof slot layout, opening payload, and required blowup;
- a codeword embedding adapter plan preserves required log blowup through payload;
- adapter plan validity does not imply backend profile validity unless paired with bridge checks.

### `Shroud.Bridge.Plonky3PreGrind`

Defines a formal grammar for the currently supported pre-grind Plonky3 event prefix.

It should model:

1. `log_ext_degree`;
2. `log_degree`;
3. `preprocessed_width`;
4. `trace_commit`;
5. optional `preprocessed_commit`;
6. optional/non-empty AIR public values;
7. alpha sample;
8. quotient commitment;
9. randomizer commitment;
10. zeta sample.

Initial theorem targets:

- a well-formed pre-grind extraction places randomizer commitment before zeta;
- a well-formed extraction includes every mandatory event;
- optional events are controlled by explicit shape flags;
- the grammar stops before placeholder post-zeta slots.

This module should explicitly state that it does not model post-zeta opened values, FRI commit phase commitments, final polynomial, log arities, query proof-of-work, or query indices until phase 3.

### `Shroud.Bridge.Provenance`

Defines a small model of advisory acceptance:

- registry source with semver;
- git source with URL and revision;
- allowlist membership.

Initial theorem targets:

- registry provenance is accepted iff version is strictly greater than `LAST_AFFECTED`;
- git provenance is accepted iff `(url, rev)` is in the allowlist;
- git semver alone never proves patch state;
- Plonky3 bridge acceptance requires both advisory and profile drift checks.

This is not meant to replace Rust `Cargo.lock` parsing. It is meant to formalize the acceptance policy.

## 7. Rust API Changes Recommended By The Restructure

The Lean restructure should not only add proofs. It should also tighten Rust APIs so Rust mirrors the normative spec more directly.

### 7.1 Carry `PerfectClaim` In Perfect Constructors

Current issue: several Rust constructors can set `SecurityLevel::Perfect` without carrying a `PerfectClaim`.

Recommended change:

- `ShroudBatchOpeningSpec::perfect(...)` should require a `PerfectClaim`;
- `ShroudOracleCommitmentSpec::perfect(...)` should require a `PerfectClaim` or object-specific perfect claim;
- `ShroudOpeningProjectionSpec::perfect(...)` should require a claim or be renamed to avoid implying cryptographic proof;
- `ShroudQuotientHiderSpec::perfect(...)` should require a claim;
- `ShroudCodewordEmbeddingSpec` should keep rejecting perfect until a dedicated perfect constructor exists.

Lean should define the new rule first:

```text
SecurityLevel.Perfect is valid only when a PerfectClaim is attached and valid.
```

Rust should then mirror it.

### 7.2 Seal The Dangerous Manifest Path For Production

Current issue: `TranscriptBindingManifest::new()` is intentionally dangerous and useful for tests.

Recommended change:

- keep a test/experimental constructor;
- add a production-facing sealed constructor path;
- mark bridge APIs so they accept only canonical or explicitly audited manifests.

Possible Rust shape:

```rust
pub struct CanonicalBatchOpeningManifest(TranscriptBindingManifest);
pub struct ExperimentalManifest(TranscriptBindingManifest);
```

Lean should model the canonical manifest as the normative object. Experimental manifests can exist, but the theorem-backed claims should only apply to canonical manifests or manifests satisfying an explicit completeness predicate.

### 7.3 Distinguish Live Bindings From Placeholder Bindings

Current issue: the Plonky3 bridge has placeholder post-zeta slots that pass manifest checks but are not live byte-replayed.

Recommended change:

```rust
pub enum BindingSource {
    LiveRecorder,
    CallerPlaceholder,
    StaticProtocolConfig,
}
```

or stronger:

```rust
pub struct LiveBinding(TranscriptBinding);
pub struct PlaceholderBinding(TranscriptBinding);
```

The bridge status document already states this boundary. The type system should make it harder to accidentally claim placeholder bindings are live.

Lean should model this as a source annotation:

```text
BindingSource.live
BindingSource.placeholder
BindingSource.staticConfig
```

Theorems about live transcript enforcement should require `source = live` for every relevant backend event.

### 7.4 Add Verifier-Independent Checks As A Trait Obligation

Current issue: `verify_profile_matches_backend` is canonical, but adapter traits do not force integrators to call it.

Recommended change:

```rust
pub trait VerifierIndependentChecks {
    type Error;

    fn verify_independent_checks(&self) -> Result<(), Self::Error>;
}
```

Backend bridge setup should require this before producing a verified adapter plan.

Lean should model this as a predicate:

```text
VerifierIndependent profile backend
```

Bridge theorems should assume that predicate.

### 7.5 Add Conformance Test Vectors

Add a small set of canonical examples shared between Lean and Rust:

- standard transcript stage list;
- standard batch-opening manifest label buckets;
- valid and invalid `DegreeBudget` cases;
- valid and invalid `QuotientDegreeContract` cases;
- standard codeword embedding shape;
- standard Plonky3 profile descriptor;
- example binding-domain order.

Initial implementation can be hand-maintained Markdown or JSON fixtures. Later it can be generated.

Do not overbuild generation early. The first value is catching drift.

## 8. CI Contract After Restructure

The CI contract should become:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
lake build
```

Once conformance fixtures exist:

```sh
cargo test --workspace
lake build
cargo test -p shroud-conformance
```

or an equivalent command that checks Rust/Lean fixture agreement.

### Required CI Gates

1. Rust must compile and test.
2. Lean must compile.
3. The theorem modules for the current public claims must build.
4. Rust conformance fixtures must match the Lean model.
5. Docs that make claims must cite either:
   - a Lean theorem name;
   - a Rust test name;
   - or an explicit assumption/gap.

### PR Rule

Any PR changing protocol semantics must include one of:

- a new or updated Lean theorem;
- a Lean definition change plus a written reason why the theorem set is unchanged;
- a downgrade of the affected claim in docs.

Any PR changing backend bridge behavior must include one of:

- a live positive test;
- a live negative test;
- an explicit note that the change is outside the live-supported boundary.

## 9. Migration Plan

### Phase 0: Freeze Current Meaning

Goal: record the current boundary before changing code.

Actions:

1. Add this document.
2. Add a root README paragraph pointing to the Lean restructure plan.
3. Keep `docs/plonky3-bridge-status.md` as the source of truth for live bridge coverage.
4. Mark post-zeta/FRI placeholder status in any new claims.

Exit criteria:

- the intended Lean/Rust split is documented;
- no code behavior has changed;
- there is no claim that Lean already exists.

### Phase 1: Bootstrap Lean Project

Goal: add Lean with minimal definitions and no dependency on Rust internals.

Actions:

1. Add `lakefile.lean`.
2. Add `lean-toolchain`.
3. Add `formal/Shroud/Basic.lean`.
4. Add `formal/Shroud/Core/Security.lean`.
5. Add `formal/Shroud/Core/Transcript.lean`.
6. Add CI `lake build`.

Exit criteria:

- `lake build` passes;
- canonical transcript stage order is represented;
- `observeRandomizerCommitment_before_sampleOodPoint` theorem exists and proves the concrete schedule-index ordering.

### Phase 2: Formalize Core Binding Manifest

Goal: represent the canonical SHROUD binding schedule.

Actions:

1. Add finite domain-label type.
2. Add manifest buckets.
3. Add canonical batch-opening manifest.
4. Prove domain-label distinctness.
5. Prove every canonical binding appears exactly once.
6. Prove required-before buckets match the documented security model.

Exit criteria:

- docs can cite theorem names for manifest completeness;
- Rust tests still lock byte encodings separately.

Current Lean theorem names:

- `domainLabels_pairwiseDistinct`;
- `canonicalManifest_complete`;
- `canonicalManifest_noDuplicates`;
- `requiredBeforeBatching_containsHashIdentifier`;
- `requiredBeforeOod_containsRandomizerCommitment`;
- `requiredBeforeProveMasked_containsPublicOpenings`.

### Phase 3: Formalize Degree Algebra

Goal: make the degree safety story theorem-backed.

Actions:

1. Add `DegreeBudget` model.
2. Prove batch-opening masked-degree theorem.
3. Add quotient degree contract model.
4. Prove plain-additive and vanishing-factor bound theorems.

Exit criteria:

- `shroud-core/src/degree.rs` and `shroud-quotient-hider` can cite Lean theorem names in comments/docs;
- Rust proptests remain as executable regression checks.

### Phase 4: Formalize Protocol Objects

Goal: model all five SHROUD objects and their payload accounting.

Actions:

1. Add batch-opening object model.
2. Add codeword embedding model.
3. Add oracle commitment model.
4. Add quotient hider model.
5. Add opening projection model.
6. Prove payload-accounting theorems.
7. Decide and formalize the `PerfectClaim` requirement.

Exit criteria:

- every Rust protocol object has a Lean counterpart;
- object docs cite Lean theorem names for shape/payload laws;
- Rust constructors mirror Lean validation predicates.

### Phase 5: Rust API Tightening

Goal: make Rust match the new normative spec.

Actions:

1. Add `PerfectClaim` to perfect constructors or rename constructors that do not prove perfectness.
2. Introduce live vs placeholder binding source types.
3. Add a canonical manifest wrapper.
4. Add verifier-independent-check trait or equivalent bridge setup gate.
5. Add conformance fixtures for selected examples.

Exit criteria:

- Rust API cannot silently make the strongest privacy claims without the supporting objects;
- placeholder bridge coverage is visible in types;
- conformance tests catch Lean/Rust drift.

### Phase 6: Formalize Plonky3 Pre-Grind Boundary

Goal: formally describe what the current bridge does and does not cover.

Actions:

1. Add Plonky3 pre-grind event grammar in Lean.
2. Model mandatory and optional event slots.
3. Prove randomizer commitment precedes zeta in the grammar.
4. Prove the grammar stops before post-zeta placeholder slots.
5. Map Rust extractor errors to grammar failures in docs.

Exit criteria:

- `docs/plonky3-bridge-status.md` can cite Lean grammar theorem names;
- no one can confuse pre-grind support with full FRI replay support.

### Phase 7: WHIR/HVZK Extension

Goal: add WHIR-specific descriptors only after upstream Plonky3 WHIR ZK surfaces stabilize.

Actions:

1. Add WHIR profile descriptor.
2. Add ZK encoding descriptor.
3. Add mask oracle descriptor.
4. Add code-switching descriptor.
5. Add base-case descriptor.
6. Add transcript event grammar for WHIR privacy-critical events.
7. Add live negative tests for every modeled event.

Exit criteria:

- SHROUD can make a precise Plonky3 WHIR privacy claim;
- every WHIR privacy-critical event is either live-bound or explicitly out of scope.

## 10. Documentation Rules After Restructure

Docs should distinguish four kinds of statements:

1. **Definition:** stated in Lean.
2. **Theorem:** proved in Lean.
3. **Executable evidence:** tested in Rust.
4. **Assumption/gap:** explicitly not proven or not live-tested.

Recommended wording:

- "The canonical manifest is defined in Lean as `Shroud.Core.Binding.canonicalBatchOpeningManifest`."
- "The randomizer-before-zeta ordering is proved by `Shroud.Theorems.TranscriptSafety.randomizerBeforeOod`."
- "The Plonky3 pre-grind replay claim is tested by `live_harness_verifies_well_formed_inputs`."
- "Post-zeta opened values are placeholder-bound and are not live byte-replayed yet."

Avoid wording like:

- "SHROUD proves Plonky3 is zero-knowledge."
- "Perfect mode is proven."
- "The bridge binds the full proof transcript."
- "The Rust type guarantees randomness freshness."

Those are too strong for the current architecture.

## 11. Claim Language After Restructure

### Safe Claim After Phases 1-4

SHROUD has a Lean-backed protocol specification for transcript schedules, binding manifests, degree budgets, and payload accounting. Rust implements those definitions as an executable reference and integration layer.

### Safe Claim After Phase 6

SHROUD has a Lean-described and Rust-live-tested pre-grind Plonky3 bridge boundary. The bridge enforces profile/provenance checks, exact manifest presence, and byte-equivalent replay for the supported pre-grind event prefix.

### Unsafe Claim Until Later

SHROUD should not claim production Plonky3 privacy, full post-zeta FRI replay, perfect HVZK, or WHIR privacy until the corresponding bridge events and backend assumptions are modeled and live-tested.

## 12. First Lean Theorem Backlog

This is the recommended first theorem backlog, in order.

1. `canonicalSchedule_valid`
   - The canonical transcript stage list is valid.

2. `randomizerCommitment_before_ood`
   - In the canonical schedule list, the index of `ObserveRandomizerCommitment` is lower than the index of `SampleOodPoint`.

3. `domainLabels_pairwiseDistinct`
   - Every SHROUD domain label is distinct.

4. `canonicalManifest_complete`
   - Every canonical SHROUD binding label appears in the canonical manifest.

5. `canonicalManifest_noDuplicates`
   - No canonical binding label appears twice.

6. `requiredBeforeOod_containsRandomizerCommitment`
   - The randomizer commitment is required before the OOD challenge.

7. `degreeBudget_valid_iff`
   - Batch-opening degree budget validity is equivalent to `randomizer <= relation + 1`.

8. `maskedRelation_preservesDegreeClass`
   - A valid batch-opening degree budget preserves the relation degree class.

9. `quotientPlain_valid_iff`
   - Plain quotient masking is valid iff the mask degree does not exceed the quotient chunk degree.

10. `quotientVanishing_valid_iff`
    - Vanishing-factor quotient masking is valid iff the required bound is within the randomized chunk bound.

11. `codewordEmbedding_statistical_randomizers`
    - Statistical codeword embedding validity implies `randomizer_columns = extension_degree`.

12. `codewordEmbedding_minBlowup`
    - Statistical codeword embedding validity implies `required_log_blowup >= 2`.

13. `batchOpening_statisticalPayload_hiddenCount`
    - Statistical batch-opening hidden coordinate count is `opening_points * extension_degree`.

14. `perfectClaim_valid_implies_hidingMmcs`
    - A valid perfect claim requires a hiding MMCS.

15. `preGrindGrammar_randomizerBeforeZeta`
    - Any well-formed Plonky3 pre-grind event grammar has the randomizer commitment before zeta.

This backlog gives SHROUD a credible formal foundation without touching backend complexity too early.

## 13. Rust Conformance Backlog

After the Lean modules exist, add Rust conformance checks in this order:

1. Canonical stage order fixture.
2. Canonical manifest label bucket fixture.
3. Degree budget valid/invalid fixture.
4. Quotient degree contract valid/invalid fixture.
5. Codeword embedding standard fixture.
6. Batch-opening statistical payload fixture.
7. Perfect-claim validation fixture.
8. Plonky3 pre-grind event grammar fixture.

Each fixture should state:

- the Lean definition or theorem it mirrors;
- the Rust constructor or test it exercises;
- whether the fixture is normative, executable evidence, or bridge-specific.

## 14. Risks

### Risk: Lean Spec Drifts From Rust

Mitigation:

- add conformance fixtures early;
- require PRs that change protocol semantics to update Lean and Rust together;
- avoid duplicating byte encodings in Lean until there is a conformance mechanism.

### Risk: Lean Becomes Too Abstract

Mitigation:

- model exactly the Rust protocol objects first;
- keep theorem names tied to SHROUD docs;
- do not start with general STARK or FRI formalization.

### Risk: Lean Blocks Backend Work

Mitigation:

- classify backend integration as Rust-owned;
- require Lean only for protocol-rule changes;
- let live bridge work continue under explicit assumptions.

### Risk: Claims Become Too Strong

Mitigation:

- require every doc claim to cite Lean theorem, Rust test, or assumption/gap;
- preserve `plonky3-bridge-status.md` as the operational boundary;
- keep placeholder/live binding distinction visible.

### Risk: Perfect Variant Looks Proven Before It Is

Mitigation:

- require `PerfectClaim` in perfect constructors;
- explicitly state simulator and randomness freshness assumptions;
- keep perfect HVZK theorem statements conditional until backend models exist.

## 15. Non-Goals

This restructure does not aim to:

- rewrite Plonky3 in Lean;
- verify Keccak or the Plonky3 sponge;
- prove FRI or WHIR soundness from first principles;
- replace Rust property tests;
- replace live transcript replay;
- generate Rust from Lean in the first phase;
- make SHROUD a prover;
- claim production ZK privacy before backend-specific live coverage exists.

Those would make the project much larger and less likely to land.

## 16. Recommended Immediate Next Steps

Completed:

1. Add this document and link it from `docs/README.md`.
2. Add `lakefile.lean` and `lean-toolchain`.
3. Add `formal/Shroud/Core/Security.lean`.
4. Add `formal/Shroud/Core/Transcript.lean`.
5. Prove `observeRandomizerCommitment_before_sampleOodPoint` as a concrete schedule-index theorem.
6. Run `lake build --wfail`.
7. Add `formal/Shroud/Core/Binding.lean`.
8. Prove initial canonical manifest completeness, no-duplication, and required-before bucket facts.

Next:

1. Add `formal/Shroud/Core/Degree.lean`.
2. Prove the batch-opening degree-budget theorem.
3. Add Rust comments linking `TranscriptPlan` and `DegreeBudget` to those theorem names.
4. Only then tighten `PerfectClaim` and manifest APIs.

This sequence gives SHROUD immediate formal value without disrupting the Plonky3 bridge work.

## 17. Final Recommendation

Make Lean the normative layer for SHROUD's protocol laws. Keep Rust as the executable layer for backend reality.

In practice, that means:

- Lean defines what SHROUD means.
- Lean proves the core invariants.
- Rust implements those definitions.
- Rust tests live integrations.
- Docs and future papers cite both: Lean for protocol truth, Rust for backend evidence.

That is the right structure for SHROUD because the project is not mainly about inventing another prover. It is about making hiding claims in existing proof systems precise, composable, and auditable.
