# HVZK-WHIR Impact on SHROUD

**Date:** 2026-05-16  
**Scope:** Plonky3 WHIR zero-knowledge roadmap, ePrint 2026/391, and what SHROUD should do next.  
**Status:** Architecture memo. Not a protocol proof, not an audit report.

This note answers one question:

> Should SHROUD pivot toward Plonky3's HVZK-WHIR work, and if so how?

Short answer: **yes for the Plonky3 production bridge, no for SHROUD core.**

HVZK-WHIR is a strong candidate for SHROUD's long-term Plonky3 privacy backend. It is much closer to SHROUD's intended domain than a Halo2/PLONK detour, and it is more principled than layering ad hoc hiding over non-ZK WHIR. But SHROUD should not make its core objects WHIR-only. The right architecture is:

- keep SHROUD core backend-neutral
- freeze the current `HidingFriPcs` bridge as a pre-WHIR compatibility and audit layer
- prepare a WHIR-first Plonky3 bridge once `HidingWhirPcs` lands and stabilizes
- do not advertise a production privacy claim until the WHIR ZK path is merged, reviewed, and transcript-audited

## Sources

Primary sources used for this memo:

- Local paper: [`/Users/latifkasuli/web3/contributions/hvzk-whir-2026-391.pdf`](/Users/latifkasuli/web3/contributions/hvzk-whir-2026-391.pdf)
- Plonky3 tracking issue: [#1590 - Tracking: HVZK-WHIR](https://github.com/Plonky3/Plonky3/issues/1590)
- Plonky3 issue: [#1584 - ZK encoding trait + Reed-Solomon instantiation](https://github.com/Plonky3/Plonky3/issues/1584)
- Plonky3 PR: [#1601 - extract ZK encoding traits to p3-zk-codes](https://github.com/Plonky3/Plonky3/pull/1601)
- Plonky3 issue: [#1585 - Private zero-evader for OOD samples](https://github.com/Plonky3/Plonky3/issues/1585)
- Plonky3 PR: [#1593 - Private zero-evader for OOD samples](https://github.com/Plonky3/Plonky3/pull/1593)
- Plonky3 issue: [#1586 - HVZK sumcheck with sublinear masks](https://github.com/Plonky3/Plonky3/issues/1586)
- Plonky3 PR: [#1605 - HVZK sumcheck with sublinear masks](https://github.com/Plonky3/Plonky3/pull/1605)
- Plonky3 issue: [#1587 - HVZK code-switching round](https://github.com/Plonky3/Plonky3/issues/1587)
- Plonky3 PR: [#1636 - HVZK code-switching round](https://github.com/Plonky3/Plonky3/pull/1636)
- Plonky3 issue: [#1588 - HVZK base-case IOPP](https://github.com/Plonky3/Plonky3/issues/1588)
- Plonky3 PR: [#1635 - HVZK base-case IOPP](https://github.com/Plonky3/Plonky3/pull/1635)
- Plonky3 issue: [#1589 - Compose HVZK-WHIR PCS + end-to-end tests](https://github.com/Plonky3/Plonky3/issues/1589)
- Plonky3 PR: [#1637 - HidingWhirPcs adapter + ZK composition](https://github.com/Plonky3/Plonky3/pull/1637)
- Plonky3 PR: [#1612 - whir: wire stacked layouts to pcs](https://github.com/Plonky3/Plonky3/pull/1612)

All Plonky3 status statements in this document are current as of **2026-05-16**. These PRs are moving quickly, so re-check before making dependency or launch decisions.

## What the HVZK-WHIR Paper Actually Gives

The paper, *Zero-Knowledge IOPPs for Constrained Interleaved Codes*, studies hash-based SNARGs built from IOPs. Its central problem is direct: modern code-agnostic IOPs are fast, but they generally do not provide privacy. Existing concretely efficient ZK IOPs often impose a large overhead or are tied to specific polynomial-code settings.

The paper's important claims for SHROUD are:

1. It targets **constrained interleaved codes**, which is close to the WHIR family of protocols.
2. It provides **honest-verifier zero-knowledge** IOPs and IOPPs.
3. It aims for **1 + o(1)** ZK overhead over the corresponding non-ZK protocol.
4. It has a composition framework for HVZK interactive oracle reductions.
5. It explains how to move from HVZK IOPs to malicious-verifier ZK hash-based SNARGs through Fiat-Shamir / BCS, assuming the transcript transform is implemented correctly.

The paper is not saying "just turn on one flag and every downstream implementation is safe." The composition story is precise. The implementation must get the mask oracles, zero-evaders, code-switching, base case, randomness, query limits, and transcript ordering right.

This matters for SHROUD because SHROUD has deliberately focused on the implementation layer where privacy claims often fail:

- hidden material must be explicit
- commitments must bind before challenges
- hash suites must be pinned
- backend parameters must not be prover-controlled
- transcript replay must detect mutation, omission, and reordering

HVZK-WHIR does not make those obligations disappear. It makes the underlying PCS privacy story much stronger if those obligations are met.

## Current Upstream State

The HVZK-WHIR work is tracked by Plonky3 [#1590](https://github.com/Plonky3/Plonky3/issues/1590). The issue decomposes the work into six pieces.

| Piece | Upstream item | Status on 2026-05-16 | SHROUD relevance |
|---|---|---:|---|
| 1/6 ZK encoding trait + RS instantiation | #1584 / #1601 | PR merged | Defines reusable ZK encoding surface. |
| 2/6 Private zero-evader for OOD samples | #1585 / #1593 | PR merged | Hides OOD linear leakage. |
| 3/6 HVZK sumcheck with sublinear masks | #1586 / #1605 | PR merged | Adds masked sumcheck relation. |
| 4/6 HVZK code-switching round | #1587 / #1636 | PR open | Critical for recursive WHIR rounds. |
| 5/6 HVZK base-case IOPP | #1588 / #1635 | PR open | Prevents final small instance from leaking. |
| 6/6 Compose HVZK-WHIR PCS + E2E tests | #1589 / #1637 | PR open | Introduces `HidingWhirPcs`-style adapter. |

The open PRs are the important part. The direction is real, but a production SHROUD claim should wait for the end-to-end composition PR to land and receive serious review.

### Important Review Signal From #1636

The code-switching PR is where the architectural risk is most visible. Review comments in [#1636](https://github.com/Plonky3/Plonky3/pull/1636) flagged issues that are directly relevant to SHROUD's threat model:

- the ZK branch was not exercised by earlier test parameters
- an OOD answer and sumcheck claim could diverge if the padding relation is wired incorrectly
- a mask oracle was committed but not yet opened or bound through the verifier path in the reviewed version
- sending the final folded polynomial in clear would leak unless the base-case HVZK IOPP is composed correctly
- deterministic RNG in a ZK path is dangerous if it survives beyond scaffolding

Some of those were addressed or descoped in later commits, but the lesson is stable: **HVZK-WHIR is not only a cryptographic object; it is an implementation transcript discipline.** That is exactly the class of risk SHROUD is meant to audit.

## Impact on SHROUD

The impact is large, but it is not "delete the FRI work and become WHIR-only."

The better interpretation:

- SHROUD core remains backend-neutral.
- `shroud-plonky3` becomes WHIR-first once Plonky3 exposes a stable `HidingWhirPcs`.
- The current `HidingFriPcs` bridge remains useful as a compatibility bridge and as a tested transcript-binding harness.
- Production privacy claims should move behind HVZK-WHIR, not `HidingFriPcs`.

### What HVZK-WHIR Improves

Before HVZK-WHIR, the Plonky3 privacy story had a hard tradeoff:

1. Use a different ecosystem with mature ZK, accepting a different proving stack.
2. Use Plonky3's fast STARK tooling but rely on narrower hiding layers.
3. Build a custom masking layer on top of Plonky3, taking on research and audit risk.

HVZK-WHIR potentially gives a better path:

- stay in the Plonky3 ecosystem
- use WHIR's interleaved-code architecture
- get a principled HVZK construction
- keep prover overhead close to the non-ZK WHIR path
- compose with Fiat-Shamir to target malicious-verifier ZK at the SNARG level

That is a strong match for SHROUD's original motivation: **Structured Hiding for Reed-Solomon Oracles Under FRI and related PCS backends.**

WHIR is not FRI, but it is still in the same broad family of transparent, code-based, oracle-proof systems where hiding is about committed codewords, query views, transcript binding, and backend profile discipline.

### What HVZK-WHIR Does Not Solve For SHROUD

HVZK-WHIR does not remove these obligations:

- exact Fiat-Shamir transcript binding
- challenge domain separation
- hash-suite provenance
- RNG freshness
- verifier-side parameter validation
- backend drift detection
- simulator-real conformance tests
- proof object serialization checks
- query/opening accounting

In fact, HVZK-WHIR makes several of those obligations more important because there are more privacy-critical protocol objects:

- ZK encoding parameters
- mask oracle commitments
- private zero-evader parameters
- code-switching mask commitments
- base-case masks
- RNG-backed hidden material
- per-round ZK flags

SHROUD should treat these as new audit-surface objects.

## Response to the Quote

The quote says:

> Assume HVZK-WHIR is the PCS. Don't design SHROUD as PCS-agnostic - design it WHIR-shaped.

My recommendation is narrower:

> Assume HVZK-WHIR is the likely production Plonky3 PCS. Keep SHROUD core PCS-neutral, but make the Plonky3 production bridge WHIR-shaped.

That avoids two failure modes.

First, making SHROUD core WHIR-only would prematurely discard the backend-neutral value we already built. The transcript-binding, profile, degree-contract, basis, payload-accounting, and masking-claim ideas are not WHIR-specific.

Second, staying too abstract at the Plonky3 bridge layer would miss the real shape of the backend. WHIR has interleaving, code-switching, mask oracles, ZK encodings, and base-case behavior. A serious bridge must model those explicitly.

So the split should be:

| Layer | Direction |
|---|---|
| `shroud-core` | Backend-neutral privacy and transcript-audit vocabulary. |
| `shroud-*` protocol crates | Continue modeling generic hiding surfaces. |
| `shroud-plonky3` current FRI bridge | Freeze as pre-WHIR compatibility and regression harness. |
| future Plonky3 WHIR bridge | WHIR-shaped, using HVZK-WHIR profile and transcript events. |

## What To Change In SHROUD

### 1. Add A WHIR Profile, Not A WHIR Rewrite

Create a profile type analogous to `ReferenceHidingFriPcsProfile`, but for WHIR:

```rust
pub struct ReferenceHvzkWhirProfile {
    pub interleaving_log: usize,
    pub zk_enabled: bool,
    pub zk_encoding: ZkEncodingDescriptor,
    pub code_switching: CodeSwitchingDescriptor,
    pub base_case: HvzkBaseCaseDescriptor,
    pub hash_identifier: HashIdentifier,
    pub randomness_model: RandomnessModel,
    pub hiding_technique: HidingTechniqueClaim,
}
```

This should live in the Plonky3 bridge crate, not in SHROUD core, until a second backend needs the same object.

### 2. Add A `ZkEncodingDescriptor`

The paper and Plonky3 #1601 make ZK encodings first-class. SHROUD should not treat them as invisible implementation details.

Suggested shape:

```rust
pub enum ZkEncodingFamily {
    ReedSolomon,
    BackendSpecific(String),
}

pub struct ZkEncodingDescriptor {
    pub family: ZkEncodingFamily,
    pub message_len: usize,
    pub randomness_len: usize,
    pub query_privacy_bound: usize,
    pub simulation_error_num: u64,
    pub simulation_error_den: u64,
}
```

Audit invariant:

- query count must be `<= query_privacy_bound`
- simulation error must be acceptable for the declared security level
- descriptor must be transcript-bound before any challenge that depends on encoded masks

### 3. Add An `InterleavedCodeShape`

WHIR is interleaving-native. SHROUD should represent that in the Plonky3 bridge.

```rust
pub struct InterleavedCodeShape {
    pub base_code_len: usize,
    pub interleaving_factor: usize,
    pub alphabet_extension_degree: usize,
    pub rate_num: usize,
    pub rate_den: usize,
}
```

This should not replace the existing Reed-Solomon/Fri-oriented objects in core. It should sit beside them as a WHIR bridge descriptor.

### 4. Extend `HidingTechniqueClaim`

Today SHROUD can describe broad masking techniques. HVZK-WHIR needs more precise named components:

- `HvzkWhirZkEncoding`
- `HvzkWhirSumcheckMasking`
- `HvzkWhirPrivateZeroEvader`
- `HvzkWhirCodeSwitchingMask`
- `HvzkWhirBaseCaseMasking`

These can start as `BackendSpecific(...)` claims if we want to avoid changing core too early. Once stable, promote them to named variants.

### 5. Create A WHIR Transcript Event Map

The current Plonky3 bridge has `docs/Plonky3 Mapping.md` and `docs/plonky3-bridge-status.md` for `HidingFriPcs`. WHIR needs its own equivalent.

New doc:

```text
docs/Plonky3 WHIR Mapping.md
```

Minimum event classes to map:

- WHIR parameter binding
- interleaving/layout binding
- commitment roots
- ZK encoding descriptors
- mask oracle commitments
- sumcheck mask commitments
- code-switching target commitments
- private zero-evader parameters
- OOD challenge points
- base-case mask commitment
- query indices
- opened values
- proof-of-work or grinding events, if present

Every event should have:

- Plonky3 file:line citation
- prover event
- verifier mirror
- SHROUD domain label
- sampled challenge dependency
- mutation test plan

### 6. Add WHIR Domain Labels

Do not reuse FRI labels for WHIR-specific objects.

Example prefix:

```rust
SHROUD_V1_PLONKY3_WHIR_*
```

Potential labels:

- `DOMAIN_PLONKY3_WHIR_PROFILE`
- `DOMAIN_PLONKY3_WHIR_INTERLEAVED_SHAPE`
- `DOMAIN_PLONKY3_WHIR_ZK_ENCODING`
- `DOMAIN_PLONKY3_WHIR_SUMCHECK_MASK_COMMITMENT`
- `DOMAIN_PLONKY3_WHIR_CODE_SWITCH_MASK_COMMITMENT`
- `DOMAIN_PLONKY3_WHIR_ZERO_EVADER`
- `DOMAIN_PLONKY3_WHIR_BASE_CASE_MASK`
- `DOMAIN_PLONKY3_WHIR_QUERY_SET`
- `DOMAIN_PLONKY3_WHIR_OPENINGS`

### 7. Add A WHIR Provenance Gate

The current `shroud-plonky3` gate pins:

- `p3-symmetric` provenance
- backend constants
- hash suite identifier
- `HidingFriPcs` profile drift

The WHIR bridge should also pin:

- `p3-whir` git source / crate version
- `p3-zk-codes` version/source
- `p3-multilinear-util` if exposed through WHIR PCS
- exact `HidingWhirPcs` API revision
- WHIR parameter constructors used for ZK, for example `new_testing_zk` / `new_benchmark_zk` if those land
- query count, security parameter, folding schedule, and interleaving/layout mode

For git sources, never trust semver alone. Use the same provenance pattern we already implemented for `p3-symmetric`: registry semver can be accepted by version, git sources need `(source_url, rev)` allowlisting.

### 8. Update Public Claims

Until HVZK-WHIR is stable:

- SHROUD may claim "pre-grind Plonky3 `HidingFriPcs` transcript binding is live-tested"
- SHROUD may claim "HVZK-WHIR is the intended production Plonky3 privacy target"
- SHROUD must not claim "production Plonky3 privacy is complete"
- SHROUD must not claim "WHIR post-zeta / query / base-case privacy is enforced by SHROUD"

After HVZK-WHIR lands and SHROUD has a live bridge:

- SHROUD can claim a Plonky3 WHIR privacy profile only if every WHIR privacy-critical event is transcript-bound and live-negative-tested
- the claim should name the exact Plonky3 revision and WHIR profile
- the claim should be tied to verifier replay, not just prover API construction

## Recommended Roadmap

### Phase A - Document And Freeze Current Boundary

Already mostly done:

- `docs/plonky3-bridge-status.md`
- `verify_pre_grind_bridge`
- live `HidingFriPcs` negative battery
- provenance gate

Additions after this memo:

- link this doc from `docs/README.md`
- optionally add a short "HVZK-WHIR direction" paragraph to `docs/plonky3-bridge-status.md`

### Phase B - Track Upstream WHIR, No Integration Yet

Do not build against open PRs unless there is a clear reason. Instead:

1. Watch #1635, #1636, #1637.
2. When #1637 lands, inspect the final `HidingWhirPcs` API.
3. Re-check whether the final code uses a flag, const generic, parameter mode, or separate type.
4. Re-check transcript order from final source, not PR text.
5. Re-check simulator-real tests and benchmark claims.

Important: do not hard-code names like `R4ParamMode::HVZK` until they exist in merged upstream code. The current public discussion points more toward `HidingWhirPcs`, `zk: true`, and `ZK`-style gates, but that can change.

### Phase C - Add SHROUD WHIR Spec Objects

Add these as bridge-local objects first:

- `ReferenceHvzkWhirProfile`
- `ZkEncodingDescriptor`
- `InterleavedCodeShape`
- `WhirCodeSwitchingDescriptor`
- `WhirBaseCaseDescriptor`
- `WhirTranscriptBindingManifest`

Do not promote any of these to `shroud-core` until one of these is true:

- a second backend needs the same abstraction
- the object is clearly backend-independent
- keeping it bridge-local creates duplication or inconsistent claims

### Phase D - Implement WHIR Event Recorder

Use the same philosophy as the FRI bridge:

- record what the production challenger actually absorbs
- avoid reverse-engineering serialization where possible
- expose typed extraction errors
- make mutation, omission, and reordering fail
- keep post-challenge exact-byte replay as the verification target

WHIR may not have the same `grind` clone-pollution issue as the FRI path. If it does, treat that as a bridge blocker, not a documentation footnote.

### Phase E - Live Negative Battery

Minimum live tests for the WHIR bridge:

| Test | Threat class |
|---|---|
| wrong hash-suite identifier rejected | cross-suite replay |
| mutated interleaving/layout descriptor rejected | backend-parameter substitution |
| mutated ZK encoding descriptor rejected | privacy-bound substitution |
| dropped sumcheck mask commitment rejected | missing FS input |
| reordered mask commitment and challenge rejected | challenge-before-commit bug |
| mutated private zero-evader params rejected | OOD privacy break |
| deterministic/reused RNG test where observable | randomness freshness |
| mutated base-case mask/opening rejected | terminal leakage |
| profile drift rejected | verifier-trust boundary |
| simulator-real conformance smoke test, if upstream exposes simulator | implementation matches HVZK theorem shape |

### Phase F - Update SHROUD Claim Language

Once the WHIR bridge is live:

- make WHIR the recommended Plonky3 privacy path
- keep FRI bridge as compatibility/audit support
- mark any non-WHIR Plonky3 privacy path as non-production unless separately audited

## How This Affects Existing SHROUD Crates

### `shroud-core`

Do not make it WHIR-specific.

Potential future additions:

- named `HidingTechniqueClaim` variants for HVZK-WHIR components
- generic `ZkEncodingDescriptor` only if it proves backend-neutral
- maybe a generic `InterleavedOracleShape`, but only after another backend needs it

### `shroud-plonky3`

This is where most work belongs.

Add a parallel WHIR bridge:

```text
crates/shroud-plonky3/src/whir/
```

Suggested module split:

```text
whir/profile.rs
whir/bindings.rs
whir/extractor.rs
whir/harness.rs
whir/provenance.rs
whir/tests.rs
```

Keep FRI modules intact. Do not mutate the current `HidingFriPcs` boundary until WHIR support is live.

### `shroud-reference`

Do not add Plonky3 WHIR types here unless they are truly reference-generic. `shroud-reference` should remain backend-neutral.

### `shroud-quotient-hider`

WHIR may reduce the importance of the current FRI quotient-hiding contract for the Plonky3 production path, but the crate is still valid for FRI-style backends. Do not delete it.

If WHIR introduces a different masking algebra, add a separate WHIR descriptor rather than bending `QuotientDegreeContract` to fit two different protocols.

## Design Principle: WHIR-Shaped Bridge, Backend-Neutral Core

The clean architecture is:

```text
SHROUD core
  transcript binding
  security claims
  payload accounting
  backend-neutral hiding vocabulary

SHROUD Plonky3 FRI bridge
  HidingFriPcs profile
  pre-grind transcript extraction
  compatibility / regression harness

SHROUD Plonky3 WHIR bridge
  HidingWhirPcs profile
  WHIR interleaving descriptors
  ZK encoding descriptors
  mask oracle bindings
  full WHIR transcript replay
```

This gives us the best of both:

- SHROUD does not become a renamed WHIR adapter.
- The Plonky3 integration does not pretend that a generic FRI-shaped API captures WHIR's details.

## Decision Record

Recommended decision:

1. **Keep SHROUD core backend-neutral.**
2. **Make HVZK-WHIR the intended production Plonky3 privacy target.**
3. **Do not ship a production privacy claim before upstream `HidingWhirPcs` is merged and reviewed.**
4. **Keep the current `HidingFriPcs` bridge as live-tested compatibility infrastructure.**
5. **Prepare WHIR-specific profile and transcript-binding objects, but bridge-local first.**
6. **Require live negative tests for every WHIR privacy-critical transcript event.**

## Immediate Next Steps

The next productive SHROUD-side task is not to code against open upstream PRs. It is to prepare the repo for the pivot:

1. Add this memo to the docs index.
2. Add a `docs/Plonky3 WHIR Mapping.md` skeleton with TODO rows tied to #1635/#1636/#1637.
3. Add a `docs/WHIR Bridge Checklist.md` gate mirroring `docs/plonky3-bridge-status.md`.
4. When #1637 lands, fill the mapping from merged source lines.
5. Only then implement the WHIR bridge.

## Bottom Line

HVZK-WHIR is likely the right long-term Plonky3 privacy path for SHROUD. It strengthens the underlying PCS story in exactly the area SHROUD cares about: structured hiding for code-based oracle protocols.

But the architecture should be disciplined:

- **Core SHROUD stays general.**
- **Plonky3 production bridge becomes WHIR-first.**
- **Current FRI work remains useful.**
- **Production privacy waits for merged, reviewed, replay-tested HVZK-WHIR.**

