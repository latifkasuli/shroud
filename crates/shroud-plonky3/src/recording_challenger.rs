//! Shadow-recording wrapper for Plonky3's byte-level challenger.
//!
//! [`RecordingByteChallenger`] is the foundation of the SHROUD ↔ Plonky3
//! bridge replay test harness (item 4 of the bridge roadmap). It wraps a
//! byte-level challenger ([`HashChallenger<u8, _, 32>`]) and captures every
//! byte that flows through — both bytes absorbed into the cryptographic
//! hash and bytes returned from `sample()`. The captured tape is then used
//! by SHROUD to build [`shroud_core::TranscriptBinding`] payloads that are
//! by-construction byte-equivalent to what the production challenger
//! observes, with no reverse-engineered serialization.
//!
//! # Architecture
//!
//! The pinned `p3-zk-proofs` backend uses
//! `SerializingChallenger32<BabyBear, HashChallenger<u8, Keccak256Hash, 32>>`.
//! The serializer converts typed inputs (field elements, MMCS roots, etc.)
//! into byte streams and forwards them to the inner byte challenger. By
//! splicing [`RecordingByteChallenger`] BETWEEN the serializer and the
//! hash challenger:
//!
//! ```text
//!   SerializingChallenger32<Val, RecordingByteChallenger<HashChallenger<...>>>
//!                              └──── tap here ────┘
//! ```
//!
//! we record exactly the bytes that flow into the cryptographic hash, with
//! the typed serialization handled upstream by the production code. This
//! is the "do not reverse-engineer the byte format" property from the
//! design discussion.
//!
//! # Tape semantics
//!
//! [`ByteRecorder`] is a cloneable handle that holds two byte streams:
//!
//! - **`absorbed`** — every byte fed into the inner challenger's
//!   `observe(...)`. SHROUD's [`shroud_core::TranscriptBinding`] payloads
//!   are slices of this stream.
//! - **`sampled`** — every byte returned from the inner challenger's
//!   `sample()`. Used by the replay test harness (pass 2 / item 4b) to
//!   verify byte-equivalence end-to-end.
//!
//! [`ByteRecorder::snapshot`] + [`ByteRecorder::absorbed_since`] lets the
//! caller delimit per-event sub-tapes (e.g., "the bytes absorbed during
//! event 4 — the trace commitment observation").

use std::sync::{Arc, Mutex};

use p3_baby_bear::BabyBear;
use p3_challenger::{
    CanFinalizeDigest, CanObserve, CanSample, HashChallenger, SerializingChallenger32,
};
use p3_keccak::Keccak256Hash;

/// Base field of the pinned `p3-zk-proofs` stack.
pub type Val = BabyBear;
/// Byte-level cryptographic hash used by the pinned stack.
pub type PinnedByteHash = Keccak256Hash;
/// Pinned `HashChallenger` configuration (32-byte Keccak256 output, byte-typed).
pub type PinnedByteChallenger = HashChallenger<u8, PinnedByteHash, 32>;

// ── ByteRecorder + RecorderSnapshot ──────────────────────────────────────────

/// A single observe/sample call recorded by [`RecordingByteChallenger`].
///
/// Used by [`verify_byte_equivalence`] to replay the production challenger's
/// transcript through a fresh challenger and assert that every sampled byte
/// matches what the production challenger produced. This is the
/// byte-faithfulness invariant pass 2 (item 4b) establishes.
///
/// Why a structured event log and not just the absorbed/sampled tapes:
/// `HashChallenger`'s `sample()` flushes its input buffer, hashes it, and
/// CHAINS the output back into the input buffer. So an intermediate sample
/// between two observation phases mutates the challenger state in a way
/// that prefix-only replay (just feeding the absorbed bytes into a fresh
/// challenger) cannot reproduce. Replay must therefore see the exact
/// observe/sample interleaving — which the event log preserves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ByteTranscriptEvent {
    /// One `observe(...)` call on the byte-level inner challenger.
    /// Carries every byte that the call placed into the input buffer.
    Observed(Vec<u8>),
    /// One `sample(...)` call on the byte-level inner challenger.
    /// Carries the byte the sampler returned.
    Sampled(Vec<u8>),
}

/// A cloneable, thread-safe handle on the byte tape captured by a
/// [`RecordingByteChallenger`].
///
/// Cloning shares the underlying tape (via `Arc<Mutex<…>>`) — multiple
/// clones reflect the same recorded state. `Arc<Mutex<>>` rather than
/// `Rc<RefCell<>>` because Plonky3's [`p3_challenger::FieldChallenger`]
/// trait requires `Sync`, which `Rc` does not satisfy. The mutex overhead
/// is negligible at byte-granularity recording (one lock per `observe()`).
///
/// Three parallel views of the same recording:
///
/// - `absorbed_bytes()` — flat byte tape of everything observed. Used by
///   SHROUD to build [`shroud_core::TranscriptBinding`] payloads.
/// - `sampled_bytes()` — flat byte tape of everything sampled. Used by the
///   replay harness to compare against re-derived sampled bytes.
/// - `events()` — ordered observe/sample event log. Used by
///   [`verify_byte_equivalence`] for the byte-faithfulness test, which
///   needs the exact interleaving (samples chain state into the hash, so
///   prefix-only replay is insufficient — see [`ByteTranscriptEvent`]).
#[derive(Clone, Default, Debug)]
pub struct ByteRecorder {
    absorbed: Arc<Mutex<Vec<u8>>>,
    sampled: Arc<Mutex<Vec<u8>>>,
    events: Arc<Mutex<Vec<ByteTranscriptEvent>>>,
}

impl ByteRecorder {
    /// Creates a fresh recorder with empty tapes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a copy of every byte absorbed into the inner challenger so far.
    ///
    /// Use this when building the FULL [`shroud_core::TranscriptBinding`]
    /// for end-of-proof finalization. For per-event sub-tapes, see
    /// [`Self::snapshot`] + [`Self::absorbed_since`].
    #[must_use]
    pub fn absorbed_bytes(&self) -> Vec<u8> {
        self.absorbed
            .lock()
            .expect("byte-tape mutex poisoned")
            .clone()
    }

    /// Returns a copy of every byte returned from the inner challenger's
    /// `sample()` so far.
    ///
    /// SHROUD's transcript bindings don't use this — it's recorded for the
    /// replay harness (item 4b) to verify byte-equivalence between the
    /// production challenger's sampling and the replay challenger's.
    #[must_use]
    pub fn sampled_bytes(&self) -> Vec<u8> {
        self.sampled
            .lock()
            .expect("byte-tape mutex poisoned")
            .clone()
    }

    /// Returns the current cursor positions in both tapes.
    ///
    /// Pair with [`Self::absorbed_since`] / [`Self::sampled_since`] to
    /// delimit the bytes that flowed during a specific transcript event:
    ///
    /// ```text
    /// let before = recorder.snapshot();
    /// // … do an observe/sample sequence corresponding to event N …
    /// let event_n_bytes = recorder.absorbed_since(&before);
    /// ```
    #[must_use]
    pub fn snapshot(&self) -> RecorderSnapshot {
        RecorderSnapshot {
            absorbed_len: self
                .absorbed
                .lock()
                .expect("byte-tape mutex poisoned")
                .len(),
            sampled_len: self.sampled.lock().expect("byte-tape mutex poisoned").len(),
        }
    }

    /// Returns the bytes absorbed since the given snapshot.
    #[must_use]
    pub fn absorbed_since(&self, snapshot: &RecorderSnapshot) -> Vec<u8> {
        let absorbed = self.absorbed.lock().expect("byte-tape mutex poisoned");
        absorbed[snapshot.absorbed_len..].to_vec()
    }

    /// Returns the bytes returned from `sample()` since the given snapshot.
    #[must_use]
    pub fn sampled_since(&self, snapshot: &RecorderSnapshot) -> Vec<u8> {
        let sampled = self.sampled.lock().expect("byte-tape mutex poisoned");
        sampled[snapshot.sampled_len..].to_vec()
    }

    /// Number of bytes currently in the absorbed tape.
    #[must_use]
    pub fn absorbed_len(&self) -> usize {
        self.absorbed
            .lock()
            .expect("byte-tape mutex poisoned")
            .len()
    }

    /// Number of bytes currently in the sampled tape.
    #[must_use]
    pub fn sampled_len(&self) -> usize {
        self.sampled.lock().expect("byte-tape mutex poisoned").len()
    }

    /// Returns the ordered observe/sample event log.
    ///
    /// Each entry corresponds to one call into the byte-level inner
    /// challenger ([`ByteTranscriptEvent::Observed`] for `observe(...)`,
    /// [`ByteTranscriptEvent::Sampled`] for `sample()`). The event log is
    /// the input to [`verify_byte_equivalence`].
    #[must_use]
    pub fn events(&self) -> Vec<ByteTranscriptEvent> {
        self.events
            .lock()
            .expect("byte-tape mutex poisoned")
            .clone()
    }

    /// Number of observe/sample events currently recorded.
    #[must_use]
    pub fn events_len(&self) -> usize {
        self.events.lock().expect("byte-tape mutex poisoned").len()
    }
}

/// Snapshot of [`ByteRecorder`] cursor positions, taken by
/// [`ByteRecorder::snapshot`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecorderSnapshot {
    /// Number of bytes in the absorbed tape at snapshot time.
    pub absorbed_len: usize,
    /// Number of bytes in the sampled tape at snapshot time.
    pub sampled_len: usize,
}

// ── RecordingByteChallenger ──────────────────────────────────────────────────

/// Wraps a byte-level challenger and records every absorbed / sampled byte
/// into a shared [`ByteRecorder`] handle.
///
/// Designed to plug INSIDE `SerializingChallenger32`:
///
/// ```text
/// SerializingChallenger32<Val, RecordingByteChallenger<HashChallenger<u8, Keccak256Hash, 32>>>
/// ```
///
/// The recorder forwards every call to the inner challenger, so the
/// resulting type is observationally indistinguishable from a non-recording
/// `SerializingChallenger32<Val, HashChallenger<…>>` — same sampled values,
/// same hash state evolution. The only added behaviour is the shared byte
/// tape that the caller can inspect via the [`ByteRecorder`] handle.
#[derive(Clone, Debug)]
pub struct RecordingByteChallenger<C> {
    inner: C,
    recorder: ByteRecorder,
}

impl<C> RecordingByteChallenger<C> {
    /// Creates a recording wrapper around `inner`, sharing the tape via `recorder`.
    pub fn new(inner: C, recorder: ByteRecorder) -> Self {
        Self { inner, recorder }
    }

    /// Returns the cloneable recorder handle. Cloning the result shares
    /// the same underlying tape.
    #[must_use]
    pub fn recorder(&self) -> ByteRecorder {
        self.recorder.clone()
    }
}

impl<C: CanObserve<u8>> CanObserve<u8> for RecordingByteChallenger<C> {
    fn observe(&mut self, value: u8) {
        self.recorder
            .absorbed
            .lock()
            .expect("byte-tape mutex poisoned")
            .push(value);
        self.recorder
            .events
            .lock()
            .expect("byte-tape mutex poisoned")
            .push(ByteTranscriptEvent::Observed(vec![value]));
        self.inner.observe(value);
    }
}

impl<C: CanObserve<[u8; N]>, const N: usize> CanObserve<[u8; N]> for RecordingByteChallenger<C> {
    fn observe(&mut self, values: [u8; N]) {
        self.recorder
            .absorbed
            .lock()
            .expect("byte-tape mutex poisoned")
            .extend_from_slice(&values);
        self.recorder
            .events
            .lock()
            .expect("byte-tape mutex poisoned")
            .push(ByteTranscriptEvent::Observed(values.to_vec()));
        self.inner.observe(values);
    }
}

impl<C: CanSample<u8>> CanSample<u8> for RecordingByteChallenger<C> {
    fn sample(&mut self) -> u8 {
        let v = self.inner.sample();
        self.recorder
            .sampled
            .lock()
            .expect("byte-tape mutex poisoned")
            .push(v);
        self.recorder
            .events
            .lock()
            .expect("byte-tape mutex poisoned")
            .push(ByteTranscriptEvent::Sampled(vec![v]));
        v
    }
}

impl<C: CanFinalizeDigest> CanFinalizeDigest for RecordingByteChallenger<C> {
    type Digest = C::Digest;

    fn finalize(self) -> Self::Digest {
        self.inner.finalize()
    }
}

// ── Pinned-stack type aliases + constructors ─────────────────────────────────

/// Concrete `RecordingByteChallenger` over the pinned Keccak256 byte hash.
pub type PinnedRecordingByteChallenger = RecordingByteChallenger<PinnedByteChallenger>;

/// Concrete `SerializingChallenger32` over [`PinnedRecordingByteChallenger`].
///
/// Drop-in replacement for the production challenger type in
/// `p3-zk-proofs::backend`, adding only the recorded byte tape on the side.
pub type PinnedRecordingChallenger = SerializingChallenger32<Val, PinnedRecordingByteChallenger>;

/// Constructs a fresh [`PinnedRecordingChallenger`] and returns it alongside
/// a cloneable [`ByteRecorder`] handle for reading the captured byte tape.
///
/// The returned challenger has the same surface as the production challenger
/// in `p3-zk-proofs::backend` (`SerializingChallenger32<BabyBear,
/// HashChallenger<u8, Keccak256Hash, 32>>`) and is byte-for-byte equivalent
/// in its hash-state evolution — the recording layer is purely additive.
#[must_use]
pub fn new_pinned_recording_challenger() -> (PinnedRecordingChallenger, ByteRecorder) {
    let recorder = ByteRecorder::new();
    let byte_challenger = HashChallenger::<u8, PinnedByteHash, 32>::new(Vec::new(), Keccak256Hash);
    let recording = RecordingByteChallenger::new(byte_challenger, recorder.clone());
    let challenger = SerializingChallenger32::new(recording);
    (challenger, recorder)
}

/// Constructs a fresh non-recording challenger with the same configuration
/// as [`new_pinned_recording_challenger`]. Useful for byte-equivalence tests
/// that compare a recording challenger against a bare control.
#[must_use]
pub fn new_pinned_control_challenger()
-> SerializingChallenger32<Val, HashChallenger<u8, PinnedByteHash, 32>> {
    let byte_challenger = HashChallenger::<u8, PinnedByteHash, 32>::new(Vec::new(), Keccak256Hash);
    SerializingChallenger32::new(byte_challenger)
}

/// Constructs a fresh byte-level recording challenger (without the outer
/// `SerializingChallenger32` typed wrapper). Used by tests that observe
/// raw bytes directly to validate the byte-tape mechanism — the production
/// bridge uses [`new_pinned_recording_challenger`] for the full typed stack.
#[must_use]
pub fn new_pinned_recording_byte_challenger() -> (PinnedRecordingByteChallenger, ByteRecorder) {
    let recorder = ByteRecorder::new();
    let byte_challenger = HashChallenger::<u8, PinnedByteHash, 32>::new(Vec::new(), Keccak256Hash);
    let recording = RecordingByteChallenger::new(byte_challenger, recorder.clone());
    (recording, recorder)
}

// ── Byte-equivalence replay ──────────────────────────────────────────────────

/// First detected mismatch when replaying a [`ByteTranscriptEvent`] log
/// through a fresh challenger.
///
/// Returned by [`verify_byte_equivalence`]. The fields identify the exact
/// event and byte position where the recorded transcript and the replay
/// diverged — useful for triaging "which observation changed the state"
/// when a replay test fails after a code change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayMismatch {
    /// Index of the [`ByteTranscriptEvent::Sampled`] event in the log
    /// where the divergence was detected.
    pub event_index: usize,
    /// Byte position WITHIN the sampled event where the divergence
    /// occurred (a `Sampled(...)` event may carry multiple bytes if the
    /// caller batches them).
    pub byte_index: usize,
    /// Sampled byte recorded by the original challenger.
    pub expected: u8,
    /// Sampled byte produced by the replay challenger.
    pub actual: u8,
}

impl core::fmt::Display for ReplayMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "byte-equivalence replay diverged at event {} byte {}: \
             original challenger sampled 0x{:02x}, replay sampled 0x{:02x}",
            self.event_index, self.byte_index, self.expected, self.actual,
        )
    }
}

impl std::error::Error for ReplayMismatch {}

/// Replays an observe/sample event log through a fresh
/// `HashChallenger<u8, Keccak256Hash, 32>` and asserts that every sampled
/// byte matches the recorded value.
///
/// This is the byte-faithfulness invariant for item 4b: given a transcript
/// the production challenger produced, a fresh challenger fed the same
/// observe calls in the same order MUST produce the same sampled bytes.
/// If it doesn't, either the recording is incomplete (missing an event),
/// the replay logic differs from the production challenger, or the
/// challenger itself is non-deterministic — all of which break the
/// SHROUD ↔ Plonky3 bridge replay assumption.
///
/// Returns `Ok(())` on byte-equivalent replay, or [`ReplayMismatch`] at
/// the first divergence. The fresh challenger is discarded after replay.
pub fn verify_byte_equivalence(events: &[ByteTranscriptEvent]) -> Result<(), ReplayMismatch> {
    let mut challenger = HashChallenger::<u8, PinnedByteHash, 32>::new(Vec::new(), Keccak256Hash);
    for (event_index, event) in events.iter().enumerate() {
        match event {
            ByteTranscriptEvent::Observed(bytes) => {
                for byte in bytes {
                    challenger.observe(*byte);
                }
            }
            ByteTranscriptEvent::Sampled(expected_bytes) => {
                for (byte_index, &expected) in expected_bytes.iter().enumerate() {
                    let actual: u8 = challenger.sample();
                    if actual != expected {
                        return Err(ReplayMismatch {
                            event_index,
                            byte_index,
                            expected,
                            actual,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use p3_challenger::{CanSampleBits, FieldChallenger};
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};

    // ── Byte-level tests (direct on RecordingByteChallenger) ─────────────────

    #[test]
    fn absorbed_tape_captures_raw_byte_observations() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        let bytes = [0x10u8, 0x20, 0x30, 0x40, 0x50];
        for b in bytes {
            byte_challenger.observe(b);
        }
        assert_eq!(recorder.absorbed_bytes(), bytes.to_vec());
    }

    #[test]
    fn absorbed_tape_captures_array_observations() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        byte_challenger.observe([0xAAu8, 0xBB, 0xCC, 0xDD]);
        assert_eq!(recorder.absorbed_bytes(), vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn sampled_tape_captures_byte_samples() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        // Seed and force a flush by sampling.
        for b in [0xAAu8, 0xBB, 0xCC] {
            byte_challenger.observe(b);
        }
        let _: u8 = byte_challenger.sample();
        let _: u8 = byte_challenger.sample();

        assert_eq!(
            recorder.sampled_len(),
            2,
            "two sample() calls must produce two sampled-tape entries"
        );
    }

    // ── Transparency tests (typed surface via SerializingChallenger32) ───────

    /// **Critical correctness test.** A recording challenger must produce
    /// identical sampled values to a non-recording challenger with the same
    /// configuration — the recording layer is purely additive. If this
    /// fails, the recording wrapper has changed the challenger's behaviour
    /// and any captured bytes are meaningless for replay.
    #[test]
    fn recording_is_transparent_to_typed_sampling() {
        let (mut recording, _recorder) = new_pinned_recording_challenger();
        let mut control = new_pinned_control_challenger();

        let vals = [
            Val::from_u32(0x12345678),
            Val::from_u32(0x0abcdef0),
            Val::from_u32(0x00000001),
        ];
        for v in vals {
            CanObserve::<Val>::observe(&mut recording, v);
            CanObserve::<Val>::observe(&mut control, v);
        }

        for _ in 0..4 {
            let r: BinomialExtensionField<Val, 4> = recording.sample_algebra_element();
            let c: BinomialExtensionField<Val, 4> = control.sample_algebra_element();
            assert_eq!(
                r, c,
                "recording challenger sampled an algebra element differently from control"
            );
        }
    }

    #[test]
    fn recording_is_transparent_to_sample_bits() {
        let (mut recording, _recorder) = new_pinned_recording_challenger();
        let mut control = new_pinned_control_challenger();

        for v in [
            Val::from_u32(0x01020304),
            Val::from_u32(0x05060708),
            Val::from_u32(0x090a0b0c),
        ] {
            CanObserve::<Val>::observe(&mut recording, v);
            CanObserve::<Val>::observe(&mut control, v);
        }

        for bits in [4, 8, 16, 20] {
            let r: usize = recording.sample_bits(bits);
            let c: usize = control.sample_bits(bits);
            assert_eq!(
                r, c,
                "sample_bits({bits}) diverged between recording and control"
            );
        }
    }

    /// **Critical correctness test.** When SerializingChallenger32 observes
    /// a typed Val, it converts it to bytes via `to_unique_u32().to_le_bytes()`
    /// and forwards to the inner byte challenger. The recording wrapper
    /// must capture exactly those 4 LE bytes — proving the captured byte
    /// format is the production format, not a reverse-engineered guess.
    #[test]
    fn absorbed_tape_captures_typed_observations_via_serializer() {
        let (mut recording, recorder) = new_pinned_recording_challenger();
        let v = Val::from_u32(0x01020304);
        CanObserve::<Val>::observe(&mut recording, v);

        let expected = v.to_unique_u32().to_le_bytes();
        assert_eq!(recorder.absorbed_bytes(), expected.to_vec());
        assert_eq!(recorder.absorbed_len(), 4);
    }

    // ── Snapshot / slice for per-event extraction ────────────────────────────

    #[test]
    fn snapshot_and_absorbed_since_isolate_per_event_bytes() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();

        // Event A: observe two bytes.
        byte_challenger.observe(0x11u8);
        byte_challenger.observe(0x22u8);

        // Snapshot AFTER event A — this is the cursor going into event B.
        let after_a = recorder.snapshot();

        // Event B: observe three more bytes.
        byte_challenger.observe(0x33u8);
        byte_challenger.observe(0x44u8);
        byte_challenger.observe(0x55u8);

        // absorbed_since(after_a) must return ONLY event B's bytes.
        assert_eq!(recorder.absorbed_since(&after_a), vec![0x33, 0x44, 0x55]);
        // absorbed_bytes() returns the full tape.
        assert_eq!(
            recorder.absorbed_bytes(),
            vec![0x11, 0x22, 0x33, 0x44, 0x55]
        );
    }

    #[test]
    fn snapshot_pre_event_captures_full_event_bytes() {
        // Idiomatic pattern: snapshot BEFORE an event, slice AFTER.
        let (mut recording, recorder) = new_pinned_recording_challenger();
        CanObserve::<Val>::observe(&mut recording, Val::from_u32(0x01010101)); // pre-event

        let before_event = recorder.snapshot();
        // The "event": absorb a single Val (4 LE bytes).
        CanObserve::<Val>::observe(&mut recording, Val::from_u32(0x10203040));

        let event_bytes = recorder.absorbed_since(&before_event);
        assert_eq!(event_bytes.len(), 4);
    }

    // ── Cloneable recorder ───────────────────────────────────────────────────

    #[test]
    fn cloning_the_recorder_shares_the_tape() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        let recorder_clone = recorder.clone();

        byte_challenger.observe(0xAAu8);
        byte_challenger.observe(0xBBu8);

        assert_eq!(recorder.absorbed_bytes(), vec![0xAA, 0xBB]);
        assert_eq!(recorder_clone.absorbed_bytes(), vec![0xAA, 0xBB]);
    }

    // ── Snapshot semantics ───────────────────────────────────────────────────

    #[test]
    fn snapshot_at_origin_yields_full_tape() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        let origin = recorder.snapshot();
        assert_eq!(origin.absorbed_len, 0);
        assert_eq!(origin.sampled_len, 0);

        for b in [0x01u8, 0x02, 0x03] {
            byte_challenger.observe(b);
        }

        assert_eq!(recorder.absorbed_since(&origin), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn snapshot_after_all_observations_yields_empty_slice() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        byte_challenger.observe(0x42u8);
        let after_all = recorder.snapshot();
        let slice = recorder.absorbed_since(&after_all);
        assert!(slice.is_empty());
    }

    #[test]
    fn snapshot_fields_expose_cursor_positions() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        byte_challenger.observe(0x01u8);
        byte_challenger.observe(0x02u8);
        let snap = recorder.snapshot();
        assert_eq!(snap.absorbed_len, 2);
        assert_eq!(snap.sampled_len, 0);
    }

    // ── Event log capture ───────────────────────────────────────────────────

    #[test]
    fn events_log_captures_observe_in_order() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        byte_challenger.observe(0x11u8);
        byte_challenger.observe([0x22u8, 0x33, 0x44]);
        byte_challenger.observe(0x55u8);

        assert_eq!(
            recorder.events(),
            vec![
                ByteTranscriptEvent::Observed(vec![0x11]),
                ByteTranscriptEvent::Observed(vec![0x22, 0x33, 0x44]),
                ByteTranscriptEvent::Observed(vec![0x55]),
            ]
        );
    }

    #[test]
    fn events_log_captures_interleaved_observe_sample() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        byte_challenger.observe(0xAAu8);
        let _: u8 = byte_challenger.sample();
        byte_challenger.observe(0xBBu8);
        let _: u8 = byte_challenger.sample();

        let events = recorder.events();
        assert_eq!(events.len(), 4);
        assert!(matches!(events[0], ByteTranscriptEvent::Observed(_)));
        assert!(matches!(events[1], ByteTranscriptEvent::Sampled(_)));
        assert!(matches!(events[2], ByteTranscriptEvent::Observed(_)));
        assert!(matches!(events[3], ByteTranscriptEvent::Sampled(_)));
    }

    #[test]
    fn events_len_tracks_call_count() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        assert_eq!(recorder.events_len(), 0);
        byte_challenger.observe(0x01u8);
        assert_eq!(recorder.events_len(), 1);
        let _: u8 = byte_challenger.sample();
        assert_eq!(recorder.events_len(), 2);
    }

    // ── Byte-equivalence replay (the security invariant) ────────────────────

    /// **Critical correctness test.** The byte-faithfulness invariant: a
    /// recorded event log replayed through a fresh challenger must produce
    /// the same sampled bytes the original challenger produced. If this
    /// fails, SHROUD's transcript-replay verification of Plonky3 proofs is
    /// fundamentally broken — the bridge cannot honestly verify
    /// challenge-bytes match.
    #[test]
    fn byte_equivalence_holds_for_real_observe_sample_pattern() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();

        // Pattern that mirrors a real prove flow: observe metadata, sample
        // an alpha-shaped batch of bytes, observe more, sample again.
        for b in [0x01u8, 0x02, 0x03, 0x04, 0x05] {
            byte_challenger.observe(b);
        }
        for _ in 0..4 {
            let _: u8 = byte_challenger.sample();
        }
        for b in [0x10u8, 0x20, 0x30] {
            byte_challenger.observe(b);
        }
        for _ in 0..2 {
            let _: u8 = byte_challenger.sample();
        }

        // The event log MUST replay byte-equivalently through a fresh
        // challenger.
        verify_byte_equivalence(&recorder.events())
            .expect("byte-equivalent replay must succeed for an honestly-recorded transcript");
    }

    #[test]
    fn byte_equivalence_holds_through_serializing_typed_observations() {
        // Same byte-faithfulness invariant, but observations go through
        // the SerializingChallenger32 typed surface (Val observations
        // serialize to 4 LE bytes each). The byte tape captures the
        // post-serialization bytes, so replay must work identically.
        let (mut recording, recorder) = new_pinned_recording_challenger();

        for v in [
            Val::from_u32(0x12345678),
            Val::from_u32(0xabcdef00),
            Val::from_u32(0x00000001),
        ] {
            CanObserve::<Val>::observe(&mut recording, v);
        }
        for _ in 0..4 {
            let _: BinomialExtensionField<Val, 4> = recording.sample_algebra_element();
        }
        CanObserve::<Val>::observe(&mut recording, Val::from_u32(0xdeadbeef));
        let _: usize = recording.sample_bits(16);

        verify_byte_equivalence(&recorder.events())
            .expect("byte-equivalent replay must succeed for typed prove flow");
    }

    /// Negative: if one observation byte is mutated in the event log, the
    /// replay must reject the next sample. This proves the replay isn't
    /// trivially passing — it actually compares.
    #[test]
    fn byte_equivalence_rejects_mutated_observation() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        for b in [0x01u8, 0x02, 0x03] {
            byte_challenger.observe(b);
        }
        for _ in 0..3 {
            let _: u8 = byte_challenger.sample();
        }

        // Mutate one byte in an Observed event in the log.
        let mut events = recorder.events();
        match &mut events[0] {
            ByteTranscriptEvent::Observed(bytes) => bytes[0] ^= 0xFF,
            other => panic!("first event must be Observed, got {other:?}"),
        }

        let err = verify_byte_equivalence(&events)
            .expect_err("mutated observation must cause replay divergence");
        assert!(
            err.event_index >= 3,
            "divergence must be at a Sampled event"
        );
    }

    /// Negative: if one recorded "expected" sampled byte is mutated in the
    /// event log, the replay must reject it. Proves the replay's compare
    /// step actually fires.
    #[test]
    fn byte_equivalence_rejects_mutated_sampled_byte() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        byte_challenger.observe(0xAAu8);
        let _: u8 = byte_challenger.sample();
        let _: u8 = byte_challenger.sample();

        let mut events = recorder.events();
        // Find and mutate the first Sampled event.
        let mutated_index = events
            .iter_mut()
            .enumerate()
            .find_map(|(i, e)| match e {
                ByteTranscriptEvent::Sampled(bytes) => {
                    bytes[0] ^= 0xFF;
                    Some(i)
                }
                _ => None,
            })
            .expect("must contain a Sampled event");

        let err = verify_byte_equivalence(&events)
            .expect_err("mutated sampled byte must cause replay divergence");
        assert_eq!(err.event_index, mutated_index);
        assert_eq!(err.byte_index, 0);
    }

    /// Negative: removing one Observed event from the log shifts the
    /// challenger state and must cause replay divergence at the next
    /// sample.
    #[test]
    fn byte_equivalence_rejects_dropped_observation() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        for b in [0x01u8, 0x02, 0x03] {
            byte_challenger.observe(b);
        }
        for _ in 0..3 {
            let _: u8 = byte_challenger.sample();
        }

        let mut events = recorder.events();
        events.remove(0); // drop the first Observed

        assert!(
            verify_byte_equivalence(&events).is_err(),
            "dropped observation must break byte equivalence"
        );
    }

    /// Negative: swapping the order of two Observed events that happen
    /// BEFORE a sample changes the absorbed sequence, which must change
    /// the sampled bytes (because HashChallenger absorbs in order).
    #[test]
    fn byte_equivalence_rejects_reordered_observations() {
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();
        byte_challenger.observe(0x01u8);
        byte_challenger.observe(0x02u8);
        byte_challenger.observe(0x03u8);
        for _ in 0..2 {
            let _: u8 = byte_challenger.sample();
        }

        let mut events = recorder.events();
        events.swap(0, 2); // swap first and third Observed events

        assert!(
            verify_byte_equivalence(&events).is_err(),
            "reordering observations must break byte equivalence"
        );
    }

    #[test]
    fn replay_mismatch_display_includes_position_and_bytes() {
        let mismatch = ReplayMismatch {
            event_index: 5,
            byte_index: 2,
            expected: 0xAB,
            actual: 0xCD,
        };
        let msg = mismatch.to_string();
        assert!(msg.contains("event 5"));
        assert!(msg.contains("byte 2"));
        assert!(msg.contains("ab")); // expected
        assert!(msg.contains("cd")); // actual
    }

    #[test]
    fn empty_event_log_replays_trivially() {
        assert!(verify_byte_equivalence(&[]).is_ok());
    }
}
