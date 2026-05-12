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

/// A cloneable, thread-safe handle on the byte tape captured by a
/// [`RecordingByteChallenger`].
///
/// Cloning shares the underlying tape (via `Arc<Mutex<…>>`) — multiple
/// clones reflect the same recorded state. `Arc<Mutex<>>` rather than
/// `Rc<RefCell<>>` because Plonky3's [`p3_challenger::FieldChallenger`]
/// trait requires `Sync`, which `Rc` does not satisfy. The mutex overhead
/// is negligible at byte-granularity recording (one lock per `observe()`).
#[derive(Clone, Default, Debug)]
pub struct ByteRecorder {
    absorbed: Arc<Mutex<Vec<u8>>>,
    sampled: Arc<Mutex<Vec<u8>>>,
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
}
