//! Phase 2a — live uni-stark recorder smoke test (NOT yet `HidingBackend`
//! integration).
//!
//! This file drives a REAL `p3_uni_stark::prove` invocation through
//! [`RecordingByteChallenger`] and asserts the recording mechanism
//! (a) doesn't break the production prove/verify flow and (b) captures
//! byte-faithful transcripts for the SHROUD-stage protocol events.
//!
//! # Scope (phase 2a)
//!
//! - `TwoAdicFriPcs` (NOT `HidingFriPcs`).
//! - `MerkleTreeMmcs` (non-hiding Keccak Merkle tree, NOT
//!   `MerkleTreeHidingMmcs`).
//! - No random codewords, no hiding RNG.
//!
//! This phase proves the recording layer integrates with the basic
//! `p3-uni-stark` prove path — the byte-level challenger plumbing,
//! `Clone` semantics, and `Arc<Mutex<…>>` tape all survive a real prove.
//!
//! Phase 2b will switch the test to `HidingFriPcs` +
//! `MerkleTreeHidingMmcs` to exercise the SHROUD-relevant hiding path
//! (random codewords, hiding MMCS, profile drift checks against
//! `verify_profile_matches_backend`). Phase 2b is the meaningful
//! "live `HidingBackend` prove → byte-faithful replay" milestone the
//! bridge actually depends on.
//!
//! # What this file proves today
//!
//! - **Live prove integration**: `RecordingByteChallenger` plugs into a
//!   real `StarkConfig` and survives a real `p3_uni_stark::prove`
//!   invocation. The proof verifies under a fresh recording challenger.
//! - **Event log shape**: the recorded events contain both `Observed`
//!   and `Sampled` entries, with the interleaving the production code
//!   actually performs.
//! - **SHROUD-stage byte-faithfulness**: the pre-grind clean prefix of
//!   the recorded event log contains the bytes for instance metadata,
//!   trace commitment, alpha sample, quotient commitment, and zeta
//!   sample (the events a SHROUD bridge harness depends on), and
//!   replays byte-equivalently through a fresh challenger.
//! - **Negative mutation rejection**: mutating an observation INSIDE
//!   the pre-grind clean prefix causes replay to fail at an event
//!   downstream of the mutation — demonstrating that mutation detection
//!   works on real prove data, not just on synthetic fixtures.
//!
//! # Known limitation — `grind` clone pollution
//!
//! `SerializingChallenger32::grind` (used by `HidingFriPcs` /
//! `TwoAdicFriPcs` for FRI proof-of-work) calls
//! `self.clone().check_witness(bits, *witness)` inside a Rayon
//! `find_any` parallel iterator. Each parallel candidate produces a
//! `clone()` of the challenger, runs an observe + sample_bits sequence
//! on it, and the clone is dropped.
//!
//! The recording layer captures every byte that flows through the byte
//! challenger via an `Arc<Mutex<Vec<…>>>` tape. Since `Clone` on
//! `RecordingByteChallenger` clones the `Arc` (not the underlying
//! tape), parallel candidates' throwaway observes/samples all land in
//! the same tape as the production-challenger's legitimate events. The
//! production challenger, by contrast, only commits the WINNING
//! witness's observe + sample_bits to its state — none of the
//! candidates.
//!
//! Net result: the recorded event log has MORE events than the
//! production challenger applied. Replaying the full log through a
//! fresh challenger puts it in a wildly different state, and the first
//! post-grind sample diverges.
//!
//! ## Why a quick fix doesn't exist
//!
//! - `Clone::clone(&self)` is immutable — no way to differentiate "the
//!   clone `prove` makes from `config.initialise_challenger()`" (which
//!   SHOULD record) from "the clone the grind parallel iterator makes"
//!   (which SHOULD NOT record). They use the same `Clone` method.
//! - Disabling recording on every clone would also disable it for the
//!   prove's primary challenger (which is itself a clone made by
//!   `initialise_challenger`), so nothing would be recorded.
//! - Clean fix: either patch upstream Plonky3 grind to avoid Rayon
//!   clones, or write `shroud_plonky3::prove_with_recording_challenger`
//!   that inlines the uni-stark prove logic with `&mut challenger`
//!   directly. Both are deferred to phase 3.
//!
//! ## Workaround
//!
//! All tests in this file operate on the pre-grind clean prefix
//! determined by binary search against `verify_byte_equivalence`. The
//! pre-grind prefix covers the SHROUD-stage protocol events (the only
//! events a bridge harness actually consumes), so the limitation does
//! not affect SHROUD's correctness claim — it only blocks the full-log
//! byte-equivalence assertion, which is phase 3 territory anyway.
//!
//! # AIR
//!
//! Minimal: [`SquareAir`] with two columns `a`, `b` per row and the
//! per-row constraint `a*a == b`. No transition constraints, no
//! preprocessed columns, no public values. Cribbed from
//! `p3-uni-stark/tests/no_next_row.rs`.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::HashChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::PrimeField64;
use p3_field::extension::BinomialExtensionField;
use p3_fri::TwoAdicFriPcs;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use shroud_plonky3::{
    ByteRecorder, ByteTranscriptEvent, RecordingByteChallenger, new_pinned_recording_challenger,
    verify_byte_equivalence,
};

// ── Minimal AIR ──────────────────────────────────────────────────────────────

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

// ── Type web (phase 2a — non-hiding) ─────────────────────────────────────────

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

/// MMCS over `Val` using Keccak-based byte hash + compression. NON-HIDING.
/// Phase 2b will switch to `MerkleTreeHidingMmcs` to exercise the
/// SHROUD-relevant hiding path.
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, Compress, 2, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
/// NON-HIDING FRI PCS. Phase 2b will switch to `HidingFriPcs`.
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// `SerializingChallenger32` over the recording byte challenger.
type RecordingChallenger = p3_challenger::SerializingChallenger32<
    Val,
    RecordingByteChallenger<HashChallenger<u8, ByteHash, 32>>,
>;

type MyConfig = StarkConfig<Pcs, Challenge, RecordingChallenger>;

// ── Config construction ──────────────────────────────────────────────────────

fn make_recording_config() -> (MyConfig, ByteRecorder) {
    let byte_hash = Keccak256Hash;
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = p3_fri::FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 2,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let (challenger, recorder) = new_pinned_recording_challenger();
    (MyConfig::new(pcs, challenger), recorder)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Binary-search the longest event prefix that replays byte-equivalently.
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

/// Total bytes absorbed by `Observed` events in this prefix.
fn total_absorbed_bytes(events: &[ByteTranscriptEvent]) -> usize {
    events
        .iter()
        .filter_map(|e| match e {
            ByteTranscriptEvent::Observed(bytes) => Some(bytes.len()),
            _ => None,
        })
        .sum()
}

/// Number of `Sampled` events (each is one byte) in this prefix.
fn count_sampled_bytes(events: &[ByteTranscriptEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, ByteTranscriptEvent::Sampled(_)))
        .count()
}

/// Pre-protocol-byte counts the SHROUD-stage events MUST contribute,
/// derived from `uni-stark/src/prover.rs` and `SerializingChallenger32`'s
/// `CanObserve<Val>` impl (each `Val` → 4 LE bytes via `to_unique_u32`).
mod expected_byte_counts {
    /// 3 instance-metadata `observe(Val::from_u8|usize(_))` calls × 4 bytes each.
    pub const INSTANCE_METADATA: usize = 3 * 4;
    /// 32-byte Keccak256 Merkle root.
    pub const TRACE_COMMITMENT: usize = 32;
    /// Same shape as trace commitment.
    pub const QUOTIENT_COMMITMENT: usize = 32;
    /// Total observed bytes through quotient-commit observation.
    pub const THROUGH_QUOTIENT_COMMIT: usize =
        INSTANCE_METADATA + TRACE_COMMITMENT + QUOTIENT_COMMITMENT;
    /// `BinomialExtensionField<Val, 4>` sample reads ≥4 base elements ×
    /// ≥4 bytes each = ≥16 bytes per alpha/zeta sample (more with rejection
    /// sampling). Alpha + zeta ≥ 32 sampled bytes combined.
    pub const ALPHA_PLUS_ZETA_SAMPLE_BYTES: usize = 32;
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Sanity: the recording layer is functionally invisible — prove + verify
/// round-trip works through it. If this fails, the recording wrapper is
/// not transparent to production code.
#[test]
fn live_prove_verifies_through_recording_challengers() {
    let (prove_config, _prove_recorder) = make_recording_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let proof = prove(&prove_config, &SquareAir, trace, &[]);

    let (verify_config, _verify_recorder) = make_recording_config();
    verify(&verify_config, &SquareAir, &proof, &[])
        .expect("proof produced by recording prove must verify under a fresh recording challenger");
}

/// The captured event log contains BOTH `Observed` and `Sampled` events —
/// confirming we're recording both sides of the interaction, not just
/// absorption.
#[test]
fn live_prove_event_log_contains_observed_and_sampled_events() {
    let (config, recorder) = make_recording_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&config, &SquareAir, trace, &[]);

    let events = recorder.events();
    let observed_count = events
        .iter()
        .filter(|e| matches!(e, ByteTranscriptEvent::Observed(_)))
        .count();
    let sampled_count = events
        .iter()
        .filter(|e| matches!(e, ByteTranscriptEvent::Sampled(_)))
        .count();

    assert!(
        observed_count > 0,
        "real prove must produce Observed events (instance metadata, commitments, etc.)"
    );
    assert!(
        sampled_count > 0,
        "real prove must produce Sampled events (alpha, zeta, FRI betas, query indices)"
    );
}

/// **Anchored phase 2a invariant.** The pre-grind clean prefix of the
/// recorded log MUST cover the SHROUD-stage protocol events — instance
/// metadata, trace commitment, alpha sample, quotient commitment, zeta
/// sample. We assert this via concrete byte/sample counts derived from
/// the protocol's deterministic structure (NOT a magic `>= N events`
/// bound).
///
/// Replaces the count-based `longest_good >= 50` assertion. A future
/// upstream change to Plonky3's event shape would break this test only
/// if it changed the byte counts of the protocol events themselves,
/// which is a meaningful semantic shift worth catching.
#[test]
fn live_prove_pre_grind_prefix_covers_shroud_stage_events() {
    use expected_byte_counts::*;

    let (config, recorder) = make_recording_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&config, &SquareAir, trace, &[]);

    let events = recorder.events();
    let longest_good = longest_byte_equivalent_prefix(&events);
    let prefix = &events[..longest_good];

    // Sanity: the binary search produced something non-trivial.
    assert!(longest_good > 0, "pre-grind clean prefix is empty");

    let absorbed = total_absorbed_bytes(prefix);
    let sampled = count_sampled_bytes(prefix);

    // The prefix must cover at minimum: 12 bytes of instance metadata
    // (3 Val observes), 32 bytes of trace commitment, and 32 bytes of
    // quotient commitment = 76 bytes of observed protocol data.
    assert!(
        absorbed >= THROUGH_QUOTIENT_COMMIT,
        "pre-grind clean prefix must include observed bytes through the quotient commitment \
         (instance metadata {INSTANCE_METADATA}B + trace commitment {TRACE_COMMITMENT}B + \
         quotient commitment {QUOTIENT_COMMITMENT}B = {THROUGH_QUOTIENT_COMMIT}B); \
         got {absorbed} absorbed bytes across {longest_good} events"
    );

    // Alpha and zeta are BinomialExtensionField<Val, 4> samples — each
    // pulls ≥16 bytes via 4 calls of sample_array<4> (potentially more
    // with rejection). The clean prefix must include BOTH samples, so
    // ≥32 sampled bytes total.
    assert!(
        sampled >= ALPHA_PLUS_ZETA_SAMPLE_BYTES,
        "pre-grind clean prefix must include both alpha and zeta samples (≥{ALPHA_PLUS_ZETA_SAMPLE_BYTES} \
         sampled bytes total); got {sampled} sampled bytes — possibly only alpha was captured \
         before grind clone pollution kicked in"
    );
}

/// **Anchored mutation-detection invariant.** Mutating an observation
/// INSIDE the pre-grind clean prefix causes replay to fail at an event
/// downstream of the mutation.
///
/// Replaces the false-positive test that mutated the full event log
/// (which already failed replay due to grind pollution — so "mutated log
/// still fails" was vacuous). This version asserts the clean prefix
/// passes BEFORE mutation, then fails AFTER — proving the mutation
/// detection genuinely fires on real prove data.
#[test]
fn live_prove_mutation_in_pre_grind_prefix_is_detected() {
    let (config, recorder) = make_recording_config();
    let trace = generate_square_trace::<Val>(1 << 3);
    let _proof = prove(&config, &SquareAir, trace, &[]);

    let events = recorder.events();
    let longest_good = longest_byte_equivalent_prefix(&events);
    let mut prefix: Vec<ByteTranscriptEvent> = events[..longest_good].to_vec();

    // Sanity: the clean prefix replays before mutation.
    verify_byte_equivalence(&prefix)
        .expect("pre-grind clean prefix must replay byte-equivalently before mutation");

    // Locate the first Observed event in the clean prefix and flip a bit.
    let first_observed_idx = prefix
        .iter()
        .position(|e| matches!(e, ByteTranscriptEvent::Observed(_)))
        .expect("pre-grind clean prefix must contain at least one Observed event");
    match &mut prefix[first_observed_idx] {
        ByteTranscriptEvent::Observed(bytes) => bytes[0] ^= 0xFF,
        _ => unreachable!(),
    }

    // The mutated prefix MUST now fail replay.
    let err = verify_byte_equivalence(&prefix).expect_err(
        "mutating an observation in the pre-grind clean prefix must cause replay to fail",
    );

    // The divergence must be downstream of the mutation — that's the
    // proof that the challenger state diverged because of the mutation,
    // not because of pre-existing brokenness.
    assert!(
        err.event_index > first_observed_idx,
        "divergence at event {} must be downstream of mutated event {first_observed_idx}",
        err.event_index
    );
}
