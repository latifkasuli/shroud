//! Live `Plonky3ReplayHarness` negative battery — exercises the
//! adversarial threat classes from `docs/security-model.md §2-§5`
//! against real `HidingFriPcs` prove output, not synthetic fixtures.
//!
//! This is the bridge between phase 2b (live recorder works) and the
//! synthetic [`Plonky3ReplayHarness`] tests in `replay_harness.rs`. It
//! adds:
//!
//! 1. A LIVE EXTRACTOR that slices the recorder's pre-grind event log
//!    into the named SHROUD-stage byte ranges
//!    (`instance_metadata`, `trace_commit`, `quotient_commit`,
//!    `randomizer_commit`) by walking observed bytes at deterministic
//!    offsets derived from `uni-stark/src/prover.rs`.
//!
//! 2. A LIVE FIXTURE that composes those slices with the canonical
//!    `StandardBatchOpeningBindings` + `Plonky3UniStarkBindings` →
//!    `TranscriptBindingManifest` → `ReferenceBindingRecord` chain,
//!    producing a real-data tuple the harness can verify against.
//!
//! 3. A negative battery: one mutation per threat class, each
//!    asserting the harness rejects with the correct `HarnessError`
//!    variant and (where applicable) the correct domain label.
//!
//! # Scope
//!
//! Pre-grind SHROUD-stage events only. Post-zeta Plonky3 slots
//! (`opened_values`, `fri_*`) are filled with placeholder bytes — the
//! manifest expects them and the record absorbs them, so manifest
//! verification passes, but they don't correspond to live data. The
//! threat coverage is on the pre-grind / pre-zeta portion of the
//! transcript, which is exactly the SHROUD-binding-layer scope.
//!
//! Phase 3 (`prove_with_recording_challenger`) will extend this to
//! live post-grind data once the clone-pollution issue is closed.
//!
//! # Why this matters
//!
//! Phase 2b proved the recorder captures real bytes. The synthetic
//! harness tests proved the harness logic is correct. **This file is
//! the first place those two facts compose against each other** — a
//! real prove invocation feeds the harness, and the harness's
//! adversarial assertions fire on real prove data. Every threat class
//! the security-model doc claims SHROUD defends against now has a
//! live-stack assertion proving it.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::HashChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeField64;
use p3_field::extension::BinomialExtensionField;
use p3_fri::HidingFriPcs;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use shroud_batch_opening::{BatchOpeningShape, ShroudBatchOpeningSpec};
use shroud_codeword_embedding::{CodewordEmbeddingShape, ShroudCodewordEmbeddingSpec};
use shroud_core::{
    BasisDescriptor, DOMAIN_HASH_ID, DOMAIN_RANDOMIZER_COMMITMENT, HashIdentifier,
    PublicOpeningBinding, SecurityLevel, StandardBatchOpeningBindings, TranscriptBindable,
    TranscriptBinding, TranscriptBindingError, TranscriptBindingManifest,
};
use shroud_opening_projection::{
    AuxiliaryOpeningTransport, OpeningProjectionShape, ShroudOpeningProjectionSpec,
};
use shroud_oracle_commitment::{
    OracleAuxiliaryTransport, OracleCommitmentShape, ShroudOracleCommitmentSpec,
};
use shroud_plonky3::{
    BACKEND_LOG_BLOWUP, BACKEND_NUM_RANDOMIZER_COLS, ByteRecorder, ByteTranscriptEvent,
    DOMAIN_PLONKY3_QUOTIENT_COMMITMENT, DOMAIN_PLONKY3_TRACE_COMMITMENT, HarnessError,
    Plonky3HashIdentifier, Plonky3ReplayHarness, Plonky3UniStarkBindings, RecordingByteChallenger,
    new_pinned_recording_challenger, verify_byte_equivalence,
};
use shroud_quotient_hider::{
    QuotientAuxiliaryTransport, QuotientDecompositionFamily, QuotientDegreeContract,
    QuotientHiderShape, ShroudQuotientHiderSpec,
};
use shroud_reference::{ReferenceBindingRecord, ReferenceHidingFriPcsProfile};

// ── Minimal AIR ──────────────────────────────────────────────────────────────

struct SquareAir;

impl<F> BaseAir<F> for SquareAir {
    fn width(&self) -> usize {
        2
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: AirBuilder> Air<AB> for SquareAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let a = main.current(0).unwrap();
        let b = main.current(1).unwrap();
        builder.assert_eq(a * a, b);
    }
}

fn generate_square_trace<F: PrimeField64>(n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());
    let mut values = F::zero_vec(n * 2);
    for i in 0..n {
        let a = F::from_u64((i + 1) as u64);
        values[i * 2] = a;
        values[i * 2 + 1] = a * a;
    }
    RowMajorMatrix::new(values, 2)
}

// ── Type web (same hiding stack as phase 2b) ─────────────────────────────────

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

type ValMmcs = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, SmallRng, 2, 32, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SmallRng>;
type RecordingChallenger = p3_challenger::SerializingChallenger32<
    Val,
    RecordingByteChallenger<HashChallenger<u8, ByteHash, 32>>,
>;
type MyConfig = StarkConfig<Pcs, Challenge, RecordingChallenger>;

const HIDING_RNG_SEED: u64 = 0xC0FFEE_BADC0DE;

fn make_recording_hiding_config() -> (MyConfig, ByteRecorder) {
    let byte_hash = Keccak256Hash;
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = ValMmcs::new(
        field_hash,
        compress,
        0,
        SmallRng::seed_from_u64(HIDING_RNG_SEED),
    );
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = p3_fri::FriParameters {
        log_blowup: BACKEND_LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 2,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(
        dft,
        val_mmcs,
        fri_params,
        BACKEND_NUM_RANDOMIZER_COLS,
        SmallRng::seed_from_u64(HIDING_RNG_SEED ^ 0xDEAD),
    );
    let (challenger, recorder) = new_pinned_recording_challenger();
    (MyConfig::new(pcs, challenger), recorder)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn longest_byte_equivalent_prefix(events: &[ByteTranscriptEvent]) -> usize {
    let mut lo = 0;
    let mut hi = events.len();
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if verify_byte_equivalence(&events[..mid]).is_ok() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// SHROUD-stage byte slices extracted by *structurally* walking the
/// recorder event log — NOT by flattening observed bytes and slicing
/// at fixed offsets.
///
/// `SerializingChallenger32<Val, HashChallenger<u8, _, 32>>` observes
/// bytes through the byte-oriented `CanObserve<u8>` path, so each
/// logical "observe a u32" or "observe an MMCS commitment" lands as a
/// run of `Observed(1)` events (or batched `Observed(N)` for some N)
/// in the recorder. Whatever the batching factor, the structural
/// invariant we audit is:
///
/// 1. **Contiguous run of Observed events totalling 4 bytes** —
///    log_ext_degree (uni-stark/src/prover.rs line 163)
/// 2. **Contiguous run** totalling 4 bytes — log_degree (line 164)
/// 3. **Contiguous run** totalling 4 bytes — preprocessed_width (line 165)
/// 4. **Contiguous run** totalling 32 bytes — trace_commit (line 169;
///    SquareAir has no preprocessed cols, line 171, and we pass empty
///    public values, line 175, so this is the next observed block)
/// 5. **≥1 `Sampled(*)` events** — α extension-element sample (line 197)
/// 6. **Contiguous run** totalling 32 bytes — quotient_commit (line 258)
/// 7. **Contiguous run** totalling 32 bytes — randomizer_commit
///    (line 286, ZK-only)
/// 8. **≥1 `Sampled(*)` events** — ζ extension-element sample (line 300)
///
/// Crucially, `read_observed_block` REFUSES to cross a `Sampled`
/// boundary or to overshoot its byte budget. So an inserted observe,
/// a resized commit, a moved/dropped Sampled call, or a domain label
/// landing on bytes that span an event boundary fails the extractor
/// before any binding is wired up — closing the boundary-loss gap of
/// the old offset-based slicer.
struct LiveExtraction {
    log_ext_degree: Vec<u8>,
    log_degree: Vec<u8>,
    preprocessed_width: Vec<u8>,
    trace_commit: Vec<u8>,
    quotient_commit: Vec<u8>,
    randomizer_commit: Vec<u8>,
}

/// Read a contiguous run of `Observed` events from `iter` until
/// `expected_len` bytes are accumulated. Fails if:
/// - a `Sampled` event appears before the budget is filled
///   (interrupted observe-block — Fiat-Shamir order violation);
/// - the iterator is exhausted (truncated log);
/// - a single `Observed` event would push us past `expected_len`
///   (event boundary doesn't align with the logical block boundary —
///   the domain label would attach to bytes crossing the boundary).
fn read_observed_block(
    iter: &mut std::iter::Peekable<std::slice::Iter<'_, ByteTranscriptEvent>>,
    expected_len: usize,
    name: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(expected_len);
    while out.len() < expected_len {
        match iter.next() {
            Some(ByteTranscriptEvent::Observed(bytes)) => {
                assert!(
                    out.len() + bytes.len() <= expected_len,
                    "structural extractor: Observed event for {name} crosses block boundary \
                     (had {} bytes, event adds {}, budget {})",
                    out.len(),
                    bytes.len(),
                    expected_len
                );
                out.extend_from_slice(bytes);
            }
            Some(ByteTranscriptEvent::Sampled(bytes)) => {
                panic!(
                    "structural extractor: Sampled({}) interrupts observe-block for {name} \
                     after {} of {} bytes — Fiat-Shamir order violation",
                    bytes.len(),
                    out.len(),
                    expected_len
                );
            }
            None => panic!(
                "structural extractor: event log exhausted while reading {name} \
                 (had {} of {} bytes)",
                out.len(),
                expected_len
            ),
        }
    }
    out
}

/// Consume ≥1 `Sampled` events. Fails if the next event is not a
/// `Sampled` (production must sample a challenge here).
fn read_sampled_block(
    iter: &mut std::iter::Peekable<std::slice::Iter<'_, ByteTranscriptEvent>>,
    challenge_name: &str,
) {
    let mut saw = false;
    while let Some(ByteTranscriptEvent::Sampled(_)) = iter.peek() {
        iter.next();
        saw = true;
    }
    assert!(
        saw,
        "structural extractor: expected ≥1 Sampled events for {challenge_name}, found none"
    );
}

fn extract_pre_grind_slices(events: &[ByteTranscriptEvent]) -> LiveExtraction {
    let mut iter = events.iter().peekable();

    // 1-4: instance metadata + trace commit. No preprocessed_commit
    // because SquareAir has no preprocessed cols; air_public_values
    // is empty because we pass &[] to prove. No Sampled may occur in
    // this region.
    let log_ext_degree = read_observed_block(&mut iter, 4, "log_ext_degree");
    let log_degree = read_observed_block(&mut iter, 4, "log_degree");
    let preprocessed_width = read_observed_block(&mut iter, 4, "preprocessed_width");
    let trace_commit = read_observed_block(&mut iter, 32, "trace_commit");

    // 5: α sample MUST fire between trace_commit and quotient_commit.
    read_sampled_block(&mut iter, "α (batching challenge)");

    // 6: quotient_commit (32B MMCS root).
    let quotient_commit = read_observed_block(&mut iter, 32, "quotient_commit");

    // 7: randomizer_commit (ZK-only, 32B MMCS root). No Sampled may
    // occur between quotient_commit and randomizer_commit (this is the
    // SHROUD-specific hiding-stack ordering invariant).
    let randomizer_commit = read_observed_block(&mut iter, 32, "randomizer_commit");

    // 8: ζ sample MUST follow randomizer_commit in the live prefix.
    read_sampled_block(&mut iter, "ζ (OOD point)");

    LiveExtraction {
        log_ext_degree,
        log_degree,
        preprocessed_width,
        trace_commit,
        quotient_commit,
        randomizer_commit,
    }
}

// ── Live fixture builder ─────────────────────────────────────────────────────

/// Everything a [`Plonky3ReplayHarness`] needs, built from a REAL
/// `HidingFriPcs` prove invocation. Pre-zeta SHROUD-stage slots use
/// live recorder bytes; post-zeta Plonky3 slots use placeholders.
struct LiveHidingFixture {
    profile: ReferenceHidingFriPcsProfile,
    record: ReferenceBindingRecord,
    manifest: TranscriptBindingManifest,
    prefix_events: Vec<ByteTranscriptEvent>,
}

/// Test-only `TranscriptBindable` wrapper for raw bindings.
struct RawBindable(TranscriptBinding);
impl TranscriptBindable for RawBindable {
    fn to_transcript_binding(&self) -> TranscriptBinding {
        self.0.clone()
    }
}

fn build_live_hiding_fixture() -> LiveHidingFixture {
    // 1. Run a real HidingFriPcs prove, capture the recorder log.
    let (config, recorder) = make_recording_hiding_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&config, &SquareAir, trace, &[]);

    let all_events = recorder.events();
    let longest = longest_byte_equivalent_prefix(&all_events);
    let prefix_events = all_events[..longest].to_vec();

    // 2. Walk the recorder events STRUCTURALLY (no flatten-and-slice).
    // The extractor asserts the exact pre-grind event shape from
    // uni-stark/src/prover.rs; a drift in event count, size, or
    // ordering fails the extractor before any binding is wired up.
    let LiveExtraction {
        log_ext_degree,
        log_degree,
        preprocessed_width,
        trace_commit,
        quotient_commit,
        randomizer_commit,
    } = extract_pre_grind_slices(&prefix_events);

    // 3. Build Plonky3UniStarkBindings.
    //
    // Pre-zeta slots use live extracted bytes. Post-zeta slots
    // (opened_values, fri_*) use deterministic placeholders — the
    // manifest will expect these placeholder bytes, the record will
    // absorb them, both match. The replay assertion uses prefix_events
    // which doesn't extend into the post-zeta region, so the
    // placeholder bytes don't affect byte-equivalence.
    let bindings = Plonky3UniStarkBindings::new(
        log_ext_degree,
        log_degree,
        preprocessed_width,
        trace_commit,
        vec![], // air_public_values — empty for our AIR
        quotient_commit,
        vec![0x00; 8], // opened_values placeholder
        vec![0x01; 8], // fri_commit_phase_commitments placeholder
        vec![0x02; 8], // fri_final_poly placeholder
        vec![0x03; 8], // fri_log_arities placeholder
    );

    // 4. Build StandardBatchOpeningBindings — canonical SHROUD bindings.
    // The randomizer_commitment binding uses LIVE bytes; everything else
    // uses the canonical protocol-object derivations from
    // shroud-{batch,codeword,oracle,opening,quotient}-* crates.
    let basis = BasisDescriptor::plonky3_binomial(4);
    let profile = ReferenceHidingFriPcsProfile::standard();
    let batch_spec =
        ShroudBatchOpeningSpec::statistical(BatchOpeningShape::new(4, 1, 2).expect("valid"), 15)
            .expect("valid");
    let codeword_spec = ShroudCodewordEmbeddingSpec::statistical(
        CodewordEmbeddingShape::new(64, 4, 18, 4).expect("valid"),
    )
    .expect("valid");
    let oracle_spec = ShroudOracleCommitmentSpec::statistical(
        OracleCommitmentShape::new(2, 3, 4, 5, 1).expect("valid"),
        OracleAuxiliaryTransport::InBandWithOpeningProof,
    )
    .expect("valid");
    let projection_spec = ShroudOpeningProjectionSpec::statistical(
        OpeningProjectionShape::new(3, 5, 2).expect("valid"),
        AuxiliaryOpeningTransport::InBandWithMainProof,
    )
    .expect("valid");
    let degree_contract = QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid");
    let quotient_spec = ShroudQuotientHiderSpec::statistical(
        QuotientDecompositionFamily::DegreeChunked,
        8,
        QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid"),
        QuotientAuxiliaryTransport::InBandWithOpeningProof,
        Some(degree_contract),
    )
    .expect("valid");
    let hash_identifier = Plonky3HashIdentifier::standard().to_hash_identifier();
    // DOMAIN_RANDOMIZER_COMMITMENT carries the LIVE randomizer commit
    // bytes extracted by the structural walker — this is the canonical
    // SHROUD slot for the hiding-stack randomizer.
    let randomizer = RawBindable(TranscriptBinding::new(
        DOMAIN_RANDOMIZER_COMMITMENT,
        randomizer_commit,
    ));
    let public_openings = PublicOpeningBinding::new(vec![0xCD; 8]); // placeholder, post-zeta

    let standard = StandardBatchOpeningBindings::from_bindables(
        &hash_identifier,
        &profile,
        &basis,
        &batch_spec,
        &codeword_spec,
        &oracle_spec,
        &projection_spec,
        &quotient_spec,
        &SecurityLevel::Statistical,
        &degree_contract,
        &randomizer,
        &public_openings,
    );

    // 5. Compose manifest = standard ⊕ plonky3 bindings.
    let manifest = bindings.clone().into_manifest(standard);

    // 6. Build record in **Plonky3 transcript order** (not arbitrary
    //    insertion order). The reviewer's P2 was: `absorb_into` plus
    //    the canonical-SHROUD block placed `DOMAIN_RANDOMIZER_COMMITMENT`
    //    before `DOMAIN_PLONKY3_QUOTIENT_COMMITMENT`, the reverse of
    //    actual Plonky3 order (quotient → randomizer → ζ).
    //
    //    Two layers, made explicit:
    //
    //    (a) **Pre-protocol SHROUD config bindings** — these are
    //        invariants of the SHROUD/Plonky3 deployment that have no
    //        Plonky3 transcript counterpart (hash_id, profile, basis,
    //        protocol specs, security_level, degree_contract). They
    //        bind the verifier to a fixed configuration before any
    //        prover-controlled byte enters the transcript.
    //
    //    (b) **Plonky3 transcript events**, in the order
    //        `uni-stark/src/prover.rs` emits them with `Pcs::ZK = true`:
    //        log_ext_degree, log_degree, preprocessed_width,
    //        trace_commit, air_public_values, quotient_commit,
    //        **randomizer_commit** (canonical SHROUD, slotted between
    //        quotient and ζ-dependent events), opened_values, fri_*.
    //
    //    `ReferenceBindingRecord::finalize` still checks **unordered
    //    presence** (per-stage exact-byte equality) — record order is
    //    NOT the audit's transcript-order invariant; replay against
    //    `prefix_events` is. But ordering the record to match
    //    transcript order keeps the audit trail honest: nobody reading
    //    the record can mistake its sequence for an out-of-order
    //    Fiat-Shamir commit.
    let mut record = ReferenceBindingRecord::new();

    // (a) Pre-protocol SHROUD config bindings.
    record.absorb_bindable(&hash_identifier);
    record.absorb_bindable(&profile);
    record.absorb_bindable(&basis);
    record.absorb_bindable(&batch_spec);
    record.absorb_bindable(&codeword_spec);
    record.absorb_bindable(&oracle_spec);
    record.absorb_bindable(&projection_spec);
    record.absorb_bindable(&quotient_spec);
    record.absorb_bindable(&SecurityLevel::Statistical);
    record.absorb_bindable(&degree_contract);

    // (b) Plonky3 transcript-order absorption.
    record.absorb(bindings.log_ext_degree().clone());
    record.absorb(bindings.log_degree().clone());
    record.absorb(bindings.preprocessed_width().clone());
    record.absorb(bindings.trace_commitment().clone());
    if let Some(pre) = bindings.preprocessed_commitment() {
        record.absorb(pre.clone());
    }
    record.absorb(bindings.air_public_values().clone());
    // (sample α — no observed bytes between trace_commit and quotient_commit)
    record.absorb(bindings.quotient_commitment().clone());
    // DOMAIN_RANDOMIZER_COMMITMENT slots HERE — between QUOTIENT and ζ
    // — matching the Plonky3 randomizer-commit event (event 9, ZK-only).
    record.absorb_bindable(&randomizer);
    // (sample ζ — no observed bytes between randomizer_commit and opened_values)
    record.absorb(bindings.opened_values().clone());
    record.absorb(bindings.fri_commit_phase_commitments().clone());
    record.absorb(bindings.fri_final_poly().clone());
    record.absorb(bindings.fri_log_arities().clone());

    // public_openings is a SHROUD-canonical binding for the post-zeta
    // public outputs; in our extended map it logically follows
    // opened_values. Placed after the Plonky3 transcript-order block
    // so it doesn't break the transcript-order audit narrative.
    record.absorb_bindable(&public_openings);

    LiveHidingFixture {
        profile,
        record,
        manifest,
        prefix_events,
    }
}

/// Rebuilds a record from `original` replacing the binding at `domain_label`
/// with `replacement_bytes`. Other bindings are preserved in absorption order.
fn record_with_replaced_binding(
    original: &ReferenceBindingRecord,
    domain_label: &'static str,
    replacement_bytes: Vec<u8>,
) -> ReferenceBindingRecord {
    let mut out = ReferenceBindingRecord::new();
    for binding in original.absorbed() {
        if binding.domain_label() == domain_label {
            out.absorb(TranscriptBinding::new(
                domain_label,
                replacement_bytes.clone(),
            ));
        } else {
            out.absorb(binding.clone());
        }
    }
    out
}

/// Rebuilds a record from `original` with the binding at `domain_label` dropped.
fn record_with_dropped_binding(
    original: &ReferenceBindingRecord,
    domain_label: &str,
) -> ReferenceBindingRecord {
    let mut out = ReferenceBindingRecord::new();
    for binding in original.absorbed() {
        if binding.domain_label() != domain_label {
            out.absorb(binding.clone());
        }
    }
    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// **Positive end-to-end invariant.** A live `Plonky3ReplayHarness` tuple
/// built from real `HidingFriPcs` prove output must verify cleanly. If
/// this fails, the extractor logic, the binding composition, or the
/// recorder is broken — every downstream negative test is moot.
#[test]
fn live_harness_verifies_well_formed_inputs() {
    let fixture = build_live_hiding_fixture();
    let harness = Plonky3ReplayHarness::new(
        &fixture.profile,
        &fixture.record,
        &fixture.manifest,
        &fixture.prefix_events,
    );
    harness
        .verify()
        .expect("live harness must verify against real prove output");
}

// ── Negative battery ─────────────────────────────────────────────────────────
//
// One mutation per threat class from docs/security-model.md, each
// asserting the harness rejects with the correct HarnessError variant.

/// **Cross-protocol confusion (security-model §2).** Replace the
/// hash-suite identifier binding in the record with a different suite.
/// The manifest still expects the canonical Plonky3HashIdentifier bytes.
/// → `Manifest(BindingMismatch { DOMAIN_HASH_ID })`.
#[test]
fn live_negative_wrong_hash_identifier_rejected() {
    let fixture = build_live_hiding_fixture();
    let wrong_suite = HashIdentifier::new("attacker-controlled-suite");
    let record = record_with_replaced_binding(
        &fixture.record,
        DOMAIN_HASH_ID,
        wrong_suite
            .to_transcript_binding()
            .canonical_bytes()
            .to_vec(),
    );
    let harness = Plonky3ReplayHarness::new(
        &fixture.profile,
        &record,
        &fixture.manifest,
        &fixture.prefix_events,
    );
    match harness.verify().unwrap_err() {
        HarnessError::Manifest(TranscriptBindingError::BindingMismatch { domain_label }) => {
            assert_eq!(domain_label, DOMAIN_HASH_ID);
        }
        other => panic!("expected BindingMismatch(DOMAIN_HASH_ID), got {other:?}"),
    }
}

/// **Commitment substitution (security-model §2).** Mutate the trace
/// commitment binding in the record. The manifest expects the live
/// `trace_commit_bytes`. → `Manifest(BindingMismatch { DOMAIN_PLONKY3_TRACE_COMMITMENT })`.
#[test]
fn live_negative_mutated_trace_commitment_rejected() {
    let fixture = build_live_hiding_fixture();
    let record = record_with_replaced_binding(
        &fixture.record,
        DOMAIN_PLONKY3_TRACE_COMMITMENT,
        vec![0xFF; 32],
    );
    let harness = Plonky3ReplayHarness::new(
        &fixture.profile,
        &record,
        &fixture.manifest,
        &fixture.prefix_events,
    );
    match harness.verify().unwrap_err() {
        HarnessError::Manifest(TranscriptBindingError::BindingMismatch { domain_label }) => {
            assert_eq!(domain_label, DOMAIN_PLONKY3_TRACE_COMMITMENT);
        }
        other => panic!("expected BindingMismatch on trace commitment, got {other:?}"),
    }
}

/// **Randomizer substitution (security-model §2, hiding-path-specific).**
/// Mutate the randomizer commitment binding. → `Manifest(BindingMismatch { DOMAIN_RANDOMIZER_COMMITMENT })`.
/// This is the hiding-stack-specific threat the bridge exists to close.
#[test]
fn live_negative_mutated_randomizer_commitment_rejected() {
    let fixture = build_live_hiding_fixture();
    let record = record_with_replaced_binding(
        &fixture.record,
        DOMAIN_RANDOMIZER_COMMITMENT,
        vec![0xEE; 32],
    );
    let harness = Plonky3ReplayHarness::new(
        &fixture.profile,
        &record,
        &fixture.manifest,
        &fixture.prefix_events,
    );
    match harness.verify().unwrap_err() {
        HarnessError::Manifest(TranscriptBindingError::BindingMismatch { domain_label }) => {
            assert_eq!(domain_label, DOMAIN_RANDOMIZER_COMMITMENT);
        }
        other => panic!("expected BindingMismatch on randomizer commitment, got {other:?}"),
    }
}

/// **Missing-binding (security-model §1).** Drop the quotient commitment
/// from the record entirely. The manifest still requires it.
/// → `Manifest(MissingBinding { DOMAIN_PLONKY3_QUOTIENT_COMMITMENT })`.
#[test]
fn live_negative_dropped_quotient_commitment_rejected() {
    let fixture = build_live_hiding_fixture();
    let record = record_with_dropped_binding(&fixture.record, DOMAIN_PLONKY3_QUOTIENT_COMMITMENT);
    let harness = Plonky3ReplayHarness::new(
        &fixture.profile,
        &record,
        &fixture.manifest,
        &fixture.prefix_events,
    );
    match harness.verify().unwrap_err() {
        HarnessError::Manifest(TranscriptBindingError::MissingBinding { domain_label }) => {
            assert_eq!(domain_label, DOMAIN_PLONKY3_QUOTIENT_COMMITMENT);
        }
        other => panic!("expected MissingBinding on quotient commitment, got {other:?}"),
    }
}

/// **Transcript-stream mutation (security-model §5).** Flip a byte in
/// the first `Observed` event of the live pre-grind prefix. The
/// recorder's state diverges from production at the next sample.
/// → `Replay(_)`. Independent of manifest checks — events drive replay.
#[test]
fn live_negative_mutated_observation_in_prefix_rejected() {
    let mut fixture = build_live_hiding_fixture();
    let first_observed = fixture
        .prefix_events
        .iter_mut()
        .find(|e| matches!(e, ByteTranscriptEvent::Observed(_)))
        .expect("prefix must contain at least one Observed event");
    if let ByteTranscriptEvent::Observed(bytes) = first_observed {
        bytes[0] ^= 0xFF;
    }
    let harness = Plonky3ReplayHarness::new(
        &fixture.profile,
        &fixture.record,
        &fixture.manifest,
        &fixture.prefix_events,
    );
    let err = harness.verify().unwrap_err();
    assert!(
        matches!(err, HarnessError::Replay(_)),
        "expected Replay error, got {err:?}"
    );
}

/// **Reordering attack (security-model §5).** Swap two adjacent
/// `Observed` events in the live prefix. Absorbed sequence differs at
/// the next sample. → `Replay(_)`.
#[test]
fn live_negative_reordered_events_in_prefix_rejected() {
    let mut fixture = build_live_hiding_fixture();
    let (i, j) = fixture
        .prefix_events
        .windows(2)
        .enumerate()
        .find_map(|(i, w)| match (&w[0], &w[1]) {
            (ByteTranscriptEvent::Observed(a), ByteTranscriptEvent::Observed(b)) if a != b => {
                Some((i, i + 1))
            }
            _ => None,
        })
        .expect("prefix must contain two adjacent Observed events with different bytes");
    fixture.prefix_events.swap(i, j);
    let harness = Plonky3ReplayHarness::new(
        &fixture.profile,
        &fixture.record,
        &fixture.manifest,
        &fixture.prefix_events,
    );
    let err = harness.verify().unwrap_err();
    assert!(
        matches!(err, HarnessError::Replay(_)),
        "expected Replay error, got {err:?}"
    );
}

/// **Profile drift (security-model §4).** Mutate a backend-pinned
/// constant in the profile. The provenance gate fires before the
/// downstream checks. → `Provenance(_)`.
#[test]
fn live_negative_profile_drift_rejected() {
    let mut fixture = build_live_hiding_fixture();
    fixture.profile.input_mmcs_hiding = false;
    let harness = Plonky3ReplayHarness::new(
        &fixture.profile,
        &fixture.record,
        &fixture.manifest,
        &fixture.prefix_events,
    );
    let err = harness.verify().unwrap_err();
    assert!(
        matches!(err, HarnessError::Provenance(_)),
        "expected Provenance error, got {err:?}"
    );
}
