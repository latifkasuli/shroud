//! Live `Plonky3ReplayHarness` negative battery — exercises the
//! adversarial threat classes from `docs/security-model.md §2-§5`
//! against real `HidingFriPcs` prove output, not synthetic fixtures.
//!
//! This is the integration counterpart to the unit tests in
//! [`shroud_plonky3::live_extractor`] and
//! [`shroud_plonky3::live_harness`]: the extractor and harness builder
//! now live in production code, and this file is the live-stack
//! integration test that drives them with real recorder output.
//!
//! # What this file proves
//!
//! 1. The production [`extract_pre_grind_slices`] walks a real
//!    `HidingFriPcs` recorder log without panicking and produces the
//!    expected byte slices.
//! 2. The production [`build_pre_grind_harness_input`] composes those
//!    live slices into a [`Plonky3LiveHarnessInput`] that
//!    [`Plonky3ReplayHarness`] accepts.
//! 3. Mutations corresponding to each `docs/security-model.md §2-§5`
//!    threat class are rejected with the correct [`HarnessError`]
//!    variant — on **live** data, not synthetic fixtures.
//!
//! # Scope
//!
//! Pre-grind SHROUD-stage events only. Post-zeta Plonky3 slots use
//! placeholder bytes; the manifest expects them and the record absorbs
//! them, so manifest verification passes, but replay against the live
//! prefix doesn't extend into the post-zeta region. Phase 3
//! (`prove_with_recording_challenger`) will extend this once the
//! clone-pollution issue is closed.

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
    BackendClaimSurface, BasisDescriptor, ClaimScope, DOMAIN_HASH_ID, DOMAIN_RANDOMIZER_COMMITMENT,
    HashIdentifier, PublicOpeningBinding, SecurityLevel, TranscriptBindable, TranscriptBinding,
    TranscriptBindingError,
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
    LiveExtractorShape, Plonky3HashIdentifier, Plonky3LiveHarnessConfig, Plonky3LiveHarnessInput,
    Plonky3ReplayHarness, RecordingByteChallenger, build_pre_grind_harness_input,
    extract_pre_grind_slices, longest_byte_equivalent_prefix, new_pinned_recording_challenger,
    verify_pre_grind_bridge, verify_pre_grind_bridge_into_verified,
};
use shroud_quotient_hider::{
    QuotientAuxiliaryTransport, QuotientDecompositionFamily, QuotientDegreeContract,
    QuotientHiderShape, ShroudQuotientHiderSpec,
};
use shroud_reference::ReferenceBindingRecord;

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

// ── Live fixture (drives the production builder against live bytes) ──────────

/// Holds owned protocol-spec values for the lifetime of one test
/// invocation, plus the harness input built from live recorder bytes.
/// The spec fields are owned here because
/// [`Plonky3LiveHarnessConfig`] holds references — keeping them in a
/// fixture struct gives the test a stable place to borrow from.
struct LiveHidingFixture {
    input: Plonky3LiveHarnessInput,
}

fn build_live_hiding_fixture() -> LiveHidingFixture {
    // 1. Run a real HidingFriPcs prove, capture the recorder log.
    let (config, recorder) = make_recording_hiding_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&config, &SquareAir, trace, &[]);

    let all_events = recorder.events();
    let longest = longest_byte_equivalent_prefix(&all_events);
    let prefix_events = all_events[..longest].to_vec();

    // 2. Production extractor: structural event walk.
    let extraction = extract_pre_grind_slices(&prefix_events, &LiveExtractorShape::standard())
        .expect("live recorder events must extract cleanly");

    // 3. Build canonical SHROUD protocol-spec values. (Owned here; the
    //    config below borrows them.)
    let hash_identifier = Plonky3HashIdentifier::standard().to_hash_identifier();
    let profile = shroud_reference::ReferenceHidingFriPcsProfile::standard();
    let basis = BasisDescriptor::plonky3_binomial(4);
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
    let security_level = SecurityLevel::Statistical;
    let public_openings = PublicOpeningBinding::new(vec![0xCD; 8]);

    // 4. Production builder.
    let config = Plonky3LiveHarnessConfig {
        hash_identifier: &hash_identifier,
        profile: &profile,
        basis: &basis,
        batch_spec: &batch_spec,
        codeword_spec: &codeword_spec,
        oracle_spec: &oracle_spec,
        projection_spec: &projection_spec,
        quotient_spec: &quotient_spec,
        security_level: &security_level,
        degree_contract: &degree_contract,
        public_openings: &public_openings,
        opened_values: vec![0x00; 8],
        fri_commit_phase_commitments: vec![0x01; 8],
        fri_final_poly: vec![0x02; 8],
        fri_log_arities: vec![0x03; 8],
    };

    let input = build_pre_grind_harness_input(&extraction, prefix_events, &config);

    LiveHidingFixture { input }
}

// ── Record mutation helpers ──────────────────────────────────────────────────

/// Rebuilds a record from `original` replacing the binding at
/// `domain_label` with `replacement_bytes`. Other bindings are
/// preserved in absorption order.
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

/// Rebuilds a record from `original` with the binding at `domain_label`
/// dropped.
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

/// **Positive end-to-end invariant.** A live
/// [`Plonky3LiveHarnessInput`] built from real `HidingFriPcs` prove
/// output via the production extractor + builder must verify cleanly
/// through [`Plonky3ReplayHarness`]. If this fails, the production
/// pipeline is broken — every downstream negative test is moot.
#[test]
fn live_harness_verifies_well_formed_inputs() {
    let fixture = build_live_hiding_fixture();
    let harness = Plonky3ReplayHarness::new(
        &fixture.input.profile,
        &fixture.input.record,
        &fixture.input.manifest,
        &fixture.input.prefix_events,
    );
    harness
        .verify()
        .expect("live harness must verify against real prove output");
}

/// **Facade positive path.** [`verify_pre_grind_bridge`] is the
/// stable downstream entry point. Driving it with the raw recorder
/// event log from a real `HidingFriPcs` prove must succeed — the
/// facade internally trims, extracts, builds, and verifies in one
/// call. If this fails, the facade is broken or the underlying
/// pipeline diverged from what `build_live_hiding_fixture` covers.
#[test]
fn live_facade_verifies_well_formed_proof_end_to_end() {
    let (config, recorder) = make_recording_hiding_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&config, &SquareAir, trace, &[]);
    let events = recorder.events();

    // Build the same SHROUD protocol-spec values + post-zeta
    // placeholders the in-test fixture uses; the facade does the rest.
    let hash_identifier = Plonky3HashIdentifier::standard().to_hash_identifier();
    let profile = shroud_reference::ReferenceHidingFriPcsProfile::standard();
    let basis = BasisDescriptor::plonky3_binomial(4);
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
    let security_level = SecurityLevel::Statistical;
    let public_openings = PublicOpeningBinding::new(vec![0xCD; 8]);

    let config = Plonky3LiveHarnessConfig {
        hash_identifier: &hash_identifier,
        profile: &profile,
        basis: &basis,
        batch_spec: &batch_spec,
        codeword_spec: &codeword_spec,
        oracle_spec: &oracle_spec,
        projection_spec: &projection_spec,
        quotient_spec: &quotient_spec,
        security_level: &security_level,
        degree_contract: &degree_contract,
        public_openings: &public_openings,
        opened_values: vec![0x00; 8],
        fri_commit_phase_commitments: vec![0x01; 8],
        fri_final_poly: vec![0x02; 8],
        fri_log_arities: vec![0x03; 8],
    };

    verify_pre_grind_bridge(&events, &LiveExtractorShape::standard(), &config)
        .expect("facade must verify a well-formed live proof end-to-end");
}

/// **Verifying-builder positive path.** [`verify_pre_grind_bridge_into_verified`]
/// returns a [`Plonky3VerifiedLiveInput`] on success; the wrapper carries
/// extraction provenance and exposes [`BackendClaimSurface`]. This test
/// proves the full Phase C P2 fix: on a well-formed proof, the verifying
/// builder produces a wrapper whose `backend_claim()` matches the Lean
/// `examplePlonky3UniStarkPreGrindClaim` (scope, security level, citations),
/// and whose `verify_independent_checks` (which re-extracts from the stored
/// prefix events) passes.
#[test]
fn verified_wrapper_exposes_backend_claim_and_passes_independent_checks() {
    let (recording_config, recorder) = make_recording_hiding_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&recording_config, &SquareAir, trace, &[]);
    let events = recorder.events();

    let hash_identifier = Plonky3HashIdentifier::standard().to_hash_identifier();
    let profile = shroud_reference::ReferenceHidingFriPcsProfile::standard();
    let basis = BasisDescriptor::plonky3_binomial(4);
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
    let security_level = SecurityLevel::Statistical;
    let public_openings = PublicOpeningBinding::new(vec![0xCD; 8]);

    let config = Plonky3LiveHarnessConfig {
        hash_identifier: &hash_identifier,
        profile: &profile,
        basis: &basis,
        batch_spec: &batch_spec,
        codeword_spec: &codeword_spec,
        oracle_spec: &oracle_spec,
        projection_spec: &projection_spec,
        quotient_spec: &quotient_spec,
        security_level: &security_level,
        degree_contract: &degree_contract,
        public_openings: &public_openings,
        opened_values: vec![0x00; 8],
        fri_commit_phase_commitments: vec![0x01; 8],
        fri_final_poly: vec![0x02; 8],
        fri_log_arities: vec![0x03; 8],
    };

    let verified =
        verify_pre_grind_bridge_into_verified(&events, &LiveExtractorShape::standard(), &config)
            .expect("verifying builder must succeed for a well-formed live proof");

    // BackendClaim exposes the full typed claim — scope + security level +
    // citations. Mirrors `examplePlonky3UniStarkPreGrindClaim` in Lean.
    let claim = verified.backend_claim();
    assert_eq!(claim.scope, ClaimScope::Plonky3UniStarkPreGrind);
    assert_eq!(claim.security_level, SecurityLevel::Statistical);
    assert_eq!(claim.citations.len(), 9);
    assert!(!claim.requires_full_live());

    // `verify_independent_checks` re-extracts from stored prefix events and
    // compares to the stored extraction (the P2 fix), then runs the
    // harness. Both must pass on a well-formed input.
    verified
        .verify_independent_checks()
        .expect("independent checks must pass on a well-formed verified wrapper");

    // Default `claim_scope()` impl on the trait projects from
    // `backend_claim()`; assert it agrees.
    assert_eq!(verified.claim_scope(), ClaimScope::Plonky3UniStarkPreGrind);
}

// ── Negative battery ─────────────────────────────────────────────────────────
//
// One mutation per threat class from docs/security-model.md, each
// asserting the harness rejects with the correct HarnessError variant.

/// **Cross-protocol confusion (security-model §2).** Replace the
/// hash-suite identifier binding in the record with a different suite.
/// The manifest still expects the canonical Plonky3HashIdentifier
/// bytes.
/// → `Manifest(BindingMismatch { DOMAIN_HASH_ID })`.
#[test]
fn live_negative_wrong_hash_identifier_rejected() {
    let fixture = build_live_hiding_fixture();
    let wrong_suite = HashIdentifier::new("attacker-controlled-suite");
    let record = record_with_replaced_binding(
        &fixture.input.record,
        DOMAIN_HASH_ID,
        wrong_suite
            .to_transcript_binding()
            .canonical_bytes()
            .to_vec(),
    );
    let harness = Plonky3ReplayHarness::new(
        &fixture.input.profile,
        &record,
        &fixture.input.manifest,
        &fixture.input.prefix_events,
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
/// `trace_commit` bytes.
/// → `Manifest(BindingMismatch { DOMAIN_PLONKY3_TRACE_COMMITMENT })`.
#[test]
fn live_negative_mutated_trace_commitment_rejected() {
    let fixture = build_live_hiding_fixture();
    let record = record_with_replaced_binding(
        &fixture.input.record,
        DOMAIN_PLONKY3_TRACE_COMMITMENT,
        vec![0xFF; 32],
    );
    let harness = Plonky3ReplayHarness::new(
        &fixture.input.profile,
        &record,
        &fixture.input.manifest,
        &fixture.input.prefix_events,
    );
    match harness.verify().unwrap_err() {
        HarnessError::Manifest(TranscriptBindingError::BindingMismatch { domain_label }) => {
            assert_eq!(domain_label, DOMAIN_PLONKY3_TRACE_COMMITMENT);
        }
        other => panic!("expected BindingMismatch on trace commitment, got {other:?}"),
    }
}

/// **Randomizer substitution (security-model §2, hiding-path-specific).**
/// Mutate the randomizer commitment binding.
/// → `Manifest(BindingMismatch { DOMAIN_RANDOMIZER_COMMITMENT })`.
/// This is the hiding-stack-specific threat the bridge exists to close.
#[test]
fn live_negative_mutated_randomizer_commitment_rejected() {
    let fixture = build_live_hiding_fixture();
    let record = record_with_replaced_binding(
        &fixture.input.record,
        DOMAIN_RANDOMIZER_COMMITMENT,
        vec![0xEE; 32],
    );
    let harness = Plonky3ReplayHarness::new(
        &fixture.input.profile,
        &record,
        &fixture.input.manifest,
        &fixture.input.prefix_events,
    );
    match harness.verify().unwrap_err() {
        HarnessError::Manifest(TranscriptBindingError::BindingMismatch { domain_label }) => {
            assert_eq!(domain_label, DOMAIN_RANDOMIZER_COMMITMENT);
        }
        other => panic!("expected BindingMismatch on randomizer commitment, got {other:?}"),
    }
}

/// **Missing-binding (security-model §1).** Drop the quotient
/// commitment from the record entirely. The manifest still requires
/// it.
/// → `Manifest(MissingBinding { DOMAIN_PLONKY3_QUOTIENT_COMMITMENT })`.
#[test]
fn live_negative_dropped_quotient_commitment_rejected() {
    let fixture = build_live_hiding_fixture();
    let record =
        record_with_dropped_binding(&fixture.input.record, DOMAIN_PLONKY3_QUOTIENT_COMMITMENT);
    let harness = Plonky3ReplayHarness::new(
        &fixture.input.profile,
        &record,
        &fixture.input.manifest,
        &fixture.input.prefix_events,
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
        .input
        .prefix_events
        .iter_mut()
        .find(|e| matches!(e, ByteTranscriptEvent::Observed(_)))
        .expect("prefix must contain at least one Observed event");
    if let ByteTranscriptEvent::Observed(bytes) = first_observed {
        bytes[0] ^= 0xFF;
    }
    let harness = Plonky3ReplayHarness::new(
        &fixture.input.profile,
        &fixture.input.record,
        &fixture.input.manifest,
        &fixture.input.prefix_events,
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
        .input
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
    fixture.input.prefix_events.swap(i, j);
    let harness = Plonky3ReplayHarness::new(
        &fixture.input.profile,
        &fixture.input.record,
        &fixture.input.manifest,
        &fixture.input.prefix_events,
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
    fixture.input.profile.input_mmcs_hiding = false;
    let harness = Plonky3ReplayHarness::new(
        &fixture.input.profile,
        &fixture.input.record,
        &fixture.input.manifest,
        &fixture.input.prefix_events,
    );
    let err = harness.verify().unwrap_err();
    assert!(
        matches!(err, HarnessError::Provenance(_)),
        "expected Provenance error, got {err:?}"
    );
}
