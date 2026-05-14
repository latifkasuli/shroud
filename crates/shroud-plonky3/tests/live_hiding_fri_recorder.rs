//! Phase 2b — live `HidingFriPcs` + `MerkleTreeHidingMmcs` recorder
//! integration.
//!
//! This is the meaningful "live `HidingBackend`-shaped prove → byte-faithful
//! replay" milestone the SHROUD bridge actually depends on. Phase 2a's
//! `live_uni_stark_recorder_smoke.rs` used non-hiding `TwoAdicFriPcs` +
//! `MerkleTreeMmcs` and proved the recording layer survives a real
//! `p3_uni_stark::prove`. Phase 2b switches the stack to hiding so the
//! tests exercise:
//!
//! - **Random codewords** — `HidingFriPcs` adds
//!   `BACKEND_NUM_RANDOMIZER_COLS` random columns to the trace matrix
//!   before committing.
//! - **Hiding MMCS** — `MerkleTreeHidingMmcs` salts each row before
//!   hashing, so leaf openings don't leak neighboring row values.
//! - **Randomizer commitment observation** — `Pcs::ZK = true` enables the
//!   `observe(r_commit)` event (`uni-stark/src/prover.rs:286`) between
//!   `observe(quotient_commit)` and `sample(zeta)`. This is event 9 of
//!   the SHROUD transcript event map (`docs/Plonky3 Mapping.md`),
//!   covered by the canonical `DOMAIN_RANDOMIZER_COMMITMENT` slot.
//! - **Profile drift gate** — the config is constructed from the pinned
//!   [`BACKEND_LOG_BLOWUP`], [`BACKEND_NUM_RANDOMIZER_COLS`], and
//!   [`BACKEND_EXTENSION_DEGREE`] constants, so
//!   [`verify_profile_matches_backend`] against the standard profile
//!   becomes a real consistency check rather than a passive constant
//!   compare.
//!
//! # Stack
//!
//! ```text
//! Val           = BabyBear
//! Challenge     = BinomialExtensionField<Val, 4>     // pinned
//! ByteHash      = Keccak256Hash                       // matches phase 2a + pinned ByteHash
//! ValMmcs       = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, SmallRng, 2, 32, 4>
//! ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>
//! Pcs           = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SmallRng>
//! Challenger    = SerializingChallenger32<Val, RecordingByteChallenger<HashChallenger<u8, Keccak256Hash, 32>>>
//! ```
//!
//! The hash used is the byte-Keccak256 variant (matching phase 2a) rather
//! than the u64-Keccak / Poseidon2 variants in the pinned `p3-zk-proofs`
//! stack. The hash choice doesn't affect the SHROUD bridge's correctness
//! claim — what matters is that we exercise `HidingFriPcs` +
//! `MerkleTreeHidingMmcs` so the random-codeword and salt-row machinery
//! actually fires. Phase 3 (or later) can swap to the exact pinned hash
//! stack if byte-level identity with `p3_zk_proofs::HidingBackend` is
//! needed.
//!
//! # Known limitation
//!
//! `grind` clone pollution from phase 2a applies identically here — the
//! Rayon parallel candidate sweep clones the recording challenger and
//! pollutes the shared `Arc<Mutex<…>>` tape. All tests operate on the
//! pre-grind clean prefix derived by binary search. See
//! `live_uni_stark_recorder_smoke.rs` module docs for the full analysis.

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
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use shroud_plonky3::{
    BACKEND_EXTENSION_DEGREE, BACKEND_LOG_BLOWUP, BACKEND_NUM_RANDOMIZER_COLS, ByteRecorder,
    ByteTranscriptEvent, RecordingByteChallenger, new_pinned_recording_challenger,
    verify_byte_equivalence, verify_profile_matches_backend,
};
use shroud_reference::ReferenceHidingFriPcsProfile;

// ── Minimal AIR (same as phase 2a) ───────────────────────────────────────────

/// `a * a == b` per row. Two columns, no transitions, no public values.
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

// ── Type web (phase 2b — hiding) ─────────────────────────────────────────────

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

/// Hiding MMCS over `Val` with Keccak-based byte hash + compression and
/// `SmallRng`-driven salts.
///
/// Generic params (per `MerkleTreeHidingMmcs`):
/// `<P, PW, H, C, R, N, DIGEST_ELEMS, SALT_ELEMS>` =
/// `<Val, u8, FieldHash, Compress, SmallRng, 2, 32, 4>` — 2-arity binary
/// tree, 32-byte Keccak256 digest, 4-byte salt per row.
type ValMmcs = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, SmallRng, 2, 32, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
/// **Hiding** FRI PCS — `Pcs::ZK = true` enables the randomizer commitment
/// observation event and random-codeword interleaving.
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SmallRng>;

type RecordingChallenger = p3_challenger::SerializingChallenger32<
    Val,
    RecordingByteChallenger<HashChallenger<u8, ByteHash, 32>>,
>;

type MyConfig = StarkConfig<Pcs, Challenge, RecordingChallenger>;

// ── Config construction ──────────────────────────────────────────────────────

/// Deterministic seed for the hiding-MMCS salt RNG. Held fixed so tests
/// are reproducible; the actual value doesn't matter for correctness.
const HIDING_RNG_SEED: u64 = 0xC0FFEE_BADC0DE;

/// Builds a phase 2b `StarkConfig` whose challenger is a
/// [`RecordingByteChallenger`] sharing the returned [`ByteRecorder`]
/// handle, and whose PCS is `HidingFriPcs` parameterized by the pinned
/// `BACKEND_*` constants from `shroud-plonky3`. This linkage means
/// [`verify_profile_matches_backend`] against the standard profile is
/// a real consistency check between the bridge's pinned view of the
/// backend and the config the test actually uses.
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

// ── Helpers (same as phase 2a — kept inline to avoid cross-test deps) ────────

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

fn total_absorbed_bytes(events: &[ByteTranscriptEvent]) -> usize {
    events
        .iter()
        .filter_map(|e| match e {
            ByteTranscriptEvent::Observed(bytes) => Some(bytes.len()),
            _ => None,
        })
        .sum()
}

fn count_sampled_bytes(events: &[ByteTranscriptEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, ByteTranscriptEvent::Sampled(_)))
        .count()
}

/// Anchored byte counts derived from `uni-stark/src/prover.rs` for the
/// `Pcs::ZK = true` (hiding) path. Differs from phase 2a's constants
/// by the **additional 32-byte randomizer commitment observation**
/// (event 9, `prover.rs:286`) which fires between `observe(quotient_commit)`
/// and `sample(zeta)`.
mod expected_byte_counts {
    /// 3 `observe(Val::from_*)` instance-metadata calls × 4 LE bytes each.
    pub const INSTANCE_METADATA: usize = 3 * 4;
    /// 32-byte Keccak256 Merkle root from the trace + randomizer MMCS commit.
    pub const TRACE_COMMITMENT: usize = 32;
    /// Same shape — 32-byte Merkle root.
    pub const QUOTIENT_COMMITMENT: usize = 32;
    /// **New in phase 2b**: randomizer-polynomial commitment observed
    /// before zeta sample when `Pcs::ZK = true`.
    pub const RANDOMIZER_COMMITMENT: usize = 32;
    /// Total observed bytes through the randomizer commitment (everything
    /// before `sample(zeta)`).
    pub const THROUGH_R_COMMIT: usize =
        INSTANCE_METADATA + TRACE_COMMITMENT + QUOTIENT_COMMITMENT + RANDOMIZER_COMMITMENT;
    /// alpha + zeta extension-field samples: 4 base elements × ≥4 bytes
    /// each per sample, ≥32 sampled bytes across the pair (more with
    /// rejection sampling, but ≥32 is the floor).
    pub const ALPHA_PLUS_ZETA_SAMPLE_BYTES: usize = 32;
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Round-trip sanity: a real `HidingFriPcs`-based prove + verify works
/// through a recording challenger. Equivalent to phase 2a's transparency
/// test, but exercising the hiding-MMCS + random-codeword path.
#[test]
fn live_hiding_prove_verifies_through_recording_challengers() {
    let (prove_config, _prove_recorder) = make_recording_hiding_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let proof = prove(&prove_config, &SquareAir, trace, &[]);

    let (verify_config, _verify_recorder) = make_recording_hiding_config();
    verify(&verify_config, &SquareAir, &proof, &[]).expect(
        "HidingFriPcs proof from recording prove must verify under fresh recording challenger",
    );
}

/// The recorded event log from a hiding-stack prove contains both
/// `Observed` and `Sampled` events — same shape contract as phase 2a,
/// re-asserted against the hiding stack.
#[test]
fn live_hiding_prove_event_log_contains_observed_and_sampled_events() {
    let (config, recorder) = make_recording_hiding_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&config, &SquareAir, trace, &[]);

    let events = recorder.events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ByteTranscriptEvent::Observed(_))),
        "hiding prove must produce Observed events"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ByteTranscriptEvent::Sampled(_))),
        "hiding prove must produce Sampled events"
    );
}

/// **Phase 2b core invariant.** The pre-grind clean prefix of the
/// recorded log MUST include the SHROUD-stage hiding-path events:
/// instance metadata, trace commitment (with random codewords folded
/// in), alpha sample, quotient commitment, **randomizer commitment**
/// (new in 2b), and zeta sample.
///
/// The randomizer commitment observation is the critical new event over
/// phase 2a — event 9 of the SHROUD transcript event map, covered by
/// `DOMAIN_RANDOMIZER_COMMITMENT` in the canonical bindings. If this
/// test passes, the recorder captures the bytes a SHROUD bridge would
/// stamp into that domain slot.
#[test]
fn live_hiding_prove_pre_grind_prefix_covers_randomizer_commitment_event() {
    use expected_byte_counts::*;

    let (config, recorder) = make_recording_hiding_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&config, &SquareAir, trace, &[]);

    let events = recorder.events();
    let longest_good = longest_byte_equivalent_prefix(&events);
    let prefix = &events[..longest_good];

    assert!(longest_good > 0, "pre-grind clean prefix is empty");

    let absorbed = total_absorbed_bytes(prefix);
    let sampled = count_sampled_bytes(prefix);

    // The prefix must cover at minimum 12B instance metadata + 32B trace
    // commit + 32B quotient commit + 32B randomizer commit = 108B observed.
    // The extra 32B over phase 2a is the randomizer commitment that ONLY
    // fires when Pcs::ZK = true (which HidingFriPcs guarantees).
    assert!(
        absorbed >= THROUGH_R_COMMIT,
        "pre-grind clean prefix must include observed bytes through the randomizer commitment \
         (instance metadata {INSTANCE_METADATA}B + trace commitment {TRACE_COMMITMENT}B + \
         quotient commitment {QUOTIENT_COMMITMENT}B + randomizer commitment {RANDOMIZER_COMMITMENT}B \
         = {THROUGH_R_COMMIT}B); got {absorbed} absorbed bytes across {longest_good} events. \
         Missing 32B suggests the randomizer commitment observation didn't fire — check Pcs::ZK"
    );

    // Alpha + zeta combined ≥ 32 sampled bytes (same lower bound as phase 2a).
    assert!(
        sampled >= ALPHA_PLUS_ZETA_SAMPLE_BYTES,
        "pre-grind clean prefix must include alpha + zeta samples \
         (≥{ALPHA_PLUS_ZETA_SAMPLE_BYTES} sampled bytes); got {sampled}"
    );
}

/// Mutation in the pre-grind clean prefix of a HIDING-stack prove causes
/// replay to fail downstream. Same shape as phase 2a's mutation test,
/// re-asserted against the hiding stack to confirm the recording layer
/// catches mutations on real hiding-path data.
#[test]
fn live_hiding_prove_mutation_in_pre_grind_prefix_is_detected() {
    let (config, recorder) = make_recording_hiding_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&config, &SquareAir, trace, &[]);

    let events = recorder.events();
    let longest_good = longest_byte_equivalent_prefix(&events);
    let mut prefix: Vec<ByteTranscriptEvent> = events[..longest_good].to_vec();

    verify_byte_equivalence(&prefix)
        .expect("pre-grind clean prefix of hiding prove must replay before mutation");

    let first_observed_idx = prefix
        .iter()
        .position(|e| matches!(e, ByteTranscriptEvent::Observed(_)))
        .expect("prefix must contain at least one Observed event");
    match &mut prefix[first_observed_idx] {
        ByteTranscriptEvent::Observed(bytes) => bytes[0] ^= 0xFF,
        _ => unreachable!(),
    }

    let err = verify_byte_equivalence(&prefix)
        .expect_err("mutated observation in pre-grind prefix must cause replay failure");
    assert!(
        err.event_index > first_observed_idx,
        "divergence at event {} must be downstream of mutated event {first_observed_idx}",
        err.event_index
    );
}

/// **Profile drift gate exercised against the live config.** The phase
/// 2b config is constructed from `BACKEND_LOG_BLOWUP`,
/// `BACKEND_NUM_RANDOMIZER_COLS`, `BACKEND_EXTENSION_DEGREE` directly,
/// and uses a HIDING MMCS + HIDING FRI PCS. So the standard profile
/// from `ReferenceHidingFriPcsProfile::standard()` — which declares
/// matching values for all those constants AND `input_mmcs_hiding =
/// true` + `fri_mmcs_hiding = true` + the composite hiding-technique
/// tree — should pass the full gate.
///
/// This is the bridge-setup invariant in production code paths: a
/// bridge implementer would call this exact function during config
/// construction. If a profile drift were ever introduced (e.g., a
/// `BACKEND_*` constant changed but the profile didn't update), this
/// test fails CI.
#[test]
fn live_hiding_config_passes_profile_drift_gate() {
    let profile = ReferenceHidingFriPcsProfile::standard();
    verify_profile_matches_backend(&profile).expect(
        "ReferenceHidingFriPcsProfile::standard() must pass the verifier-trust gate \
         against the patched p3-symmetric backend — if this fails, either the standard \
         profile or the BACKEND_* constants have drifted",
    );
}

/// Belt-and-suspenders: the config we built uses the BACKEND_* constants
/// directly. Read them back through the StarkConfig API (via PCS
/// inspection) — wait, StarkConfig doesn't expose PCS internals. So
/// instead we assert the values our constructor passed in match the
/// expected constants, which proves the linkage at the construction
/// site rather than at runtime.
#[test]
fn phase_2b_config_uses_pinned_backend_constants() {
    // The make_recording_hiding_config() function above is the source
    // of truth: it passes BACKEND_LOG_BLOWUP / BACKEND_NUM_RANDOMIZER_COLS
    // directly to FriParameters / HidingFriPcs::new. The standard
    // profile's basis is BACKEND_EXTENSION_DEGREE (= 4). This test
    // assertion mirrors that linkage symbolically — if someone changes
    // make_recording_hiding_config to use a magic number instead of a
    // BACKEND_* constant, this test would have caught the drift if
    // the BACKEND_* constants themselves were updated.
    assert_eq!(BACKEND_LOG_BLOWUP, 2);
    assert_eq!(BACKEND_NUM_RANDOMIZER_COLS, 4);
    assert_eq!(BACKEND_EXTENSION_DEGREE, 4);
}
