//! Production-grade live pre-grind extractor.
//!
//! Walks a [`ByteTranscriptEvent`] log from a live
//! [`RecordingByteChallenger`]-driven `HidingFriPcs` prove invocation
//! and slices it into named SHROUD-stage byte ranges
//! ([`LivePreGrindExtraction`]) by **structurally** consuming events —
//! not by flattening observed bytes and slicing at fixed offsets.
//!
//! The structural invariant audited, matching event ordering in
//! `docs/Plonky3 Mapping.md` rows 1-10:
//!
//! 1. Contiguous run of `Observed` events totalling 4 bytes —
//!    `log_ext_degree` (uni-stark/src/prover.rs line 163)
//! 2. Contiguous run totalling 4 bytes — `log_degree` (line 164)
//! 3. Contiguous run totalling 4 bytes — `preprocessed_width` (line 165)
//! 4. Contiguous run totalling 32 bytes — `trace_commit` (line 169)
//! 5. Optional contiguous run for `preprocessed_commit` (line 171,
//!    conditional on `preprocessed_width > 0`)
//! 6. Optional contiguous run for `air_public_values` (line 175)
//! 7. ≥1 `Sampled` events — α extension-element sample (line 197)
//! 8. Contiguous run totalling 32 bytes — `quotient_commit` (line 258)
//! 9. Contiguous run totalling 32 bytes — `randomizer_commit`
//!    (line 286). The bridge is a **ZK-only** API — every supported
//!    deployment runs against [`HidingFriPcs`] where `Pcs::ZK = true`,
//!    so this event is unconditional.
//! 10. ≥1 `Sampled` events — ζ extension-element sample (line 300)
//!
//! [`read_observed_block`](self::read_observed_block) (private)
//! refuses to cross a `Sampled` boundary or to overshoot its byte
//! budget; a misaligned event boundary, inserted observe, moved sample
//! call, or resized commitment fails the extractor before any binding
//! is wired up.
//!
//! # Why this is in production, not in tests
//!
//! The test file `tests/live_hiding_negative_battery.rs` originally
//! held this logic; that proved the design but kept it unavailable to
//! downstream code. Production callers building
//! [`Plonky3ReplayHarness`](crate::Plonky3ReplayHarness) inputs from
//! live prove output need the same structural guarantees — without
//! re-implementing them or copy-pasting from a test file.
//!
//! # Scope: pre-grind only
//!
//! The extractor stops after the ζ sample. Post-grind events
//! (`opened_values`, `fri_*`) are not captured live because
//! `SerializingChallenger32::grind` clones the challenger under Rayon
//! `find_any`, polluting the shared `Arc`-backed recorder with
//! throwaway candidate bytes. That is the phase-3 work item
//! (`prove_with_recording_challenger` or upstream grind patch);
//! pre-grind SHROUD-stage events are the binding-layer scope.
//!
//! [`HidingFriPcs`]: https://docs.rs/p3-fri/latest/p3_fri/struct.HidingFriPcs.html

use core::fmt;

use crate::recording_challenger::{ByteTranscriptEvent, verify_byte_equivalence};

// ── Output type ──────────────────────────────────────────────────────────────

/// Named byte slices extracted from a live pre-grind recorder log.
///
/// Each field holds the **exact** bytes Plonky3 absorbed into the
/// transcript at that protocol-event boundary. Built by
/// [`extract_pre_grind_slices`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePreGrindExtraction {
    /// 4-byte `log_ext_degree` payload (uni-stark prover line 163).
    pub log_ext_degree: Vec<u8>,
    /// 4-byte `log_degree` payload (uni-stark prover line 164).
    pub log_degree: Vec<u8>,
    /// 4-byte `preprocessed_width` payload (uni-stark prover line 165).
    pub preprocessed_width: Vec<u8>,
    /// 32-byte MMCS root for the trace commitment
    /// (uni-stark prover line 169).
    pub trace_commit: Vec<u8>,
    /// MMCS root for the preprocessed commitment when the AIR has
    /// preprocessed columns (uni-stark prover line 171, conditional
    /// on `preprocessed_width > 0`); `None` otherwise.
    pub preprocessed_commit: Option<Vec<u8>>,
    /// AIR public-values payload (uni-stark prover line 175); empty
    /// when the prover is invoked with no public values.
    pub air_public_values: Vec<u8>,
    /// 32-byte MMCS root for the quotient commitment
    /// (uni-stark prover line 258).
    pub quotient_commit: Vec<u8>,
    /// 32-byte MMCS root for the randomizer commitment
    /// (uni-stark prover line 286). Always present — the bridge is
    /// ZK-only by design (`HidingFriPcs` / `Pcs::ZK = true`).
    pub randomizer_commit: Vec<u8>,
}

// ── Shape configuration ──────────────────────────────────────────────────────

/// Shape parameters the extractor must know up front: byte sizes of
/// each pre-grind block, whether the AIR contributes a
/// preprocessed-commitment event, and how many bytes of AIR public
/// values to consume.
///
/// The defaults come from the SHROUD reference deployment (BabyBear /
/// `Keccak256Hash`-rooted MMCS / `SquareAir`-shaped AIR with no
/// preprocessed columns and empty public values). Custom AIRs with
/// preprocessed commitments or non-empty public values must supply a
/// custom shape so the structural walk matches reality.
///
/// The bridge is ZK-only by design — every supported deployment runs
/// against [`HidingFriPcs`], so a randomizer-commit block is always
/// expected and there is no `zk_enabled` toggle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveExtractorShape {
    /// Byte size of the `log_ext_degree` payload. Pinned at 4 by
    /// `SerializingChallenger32::observe(u32)`.
    pub log_ext_degree_bytes: usize,
    /// Byte size of the `log_degree` payload. Pinned at 4.
    pub log_degree_bytes: usize,
    /// Byte size of the `preprocessed_width` payload. Pinned at 4.
    pub preprocessed_width_bytes: usize,
    /// Byte size of the trace-commit MMCS root. Pinned at 32 by
    /// `Keccak256Hash::DIGEST_BYTES`.
    pub trace_commit_bytes: usize,
    /// `Some(N)` iff the AIR has preprocessed columns and Plonky3 will
    /// observe an N-byte preprocessed-commit MMCS root **after**
    /// `trace_commit` (uni-stark prover line 171); `None` otherwise.
    /// Must agree with the `preprocessed_width` payload — when the
    /// width is zero, this must be `None`.
    pub preprocessed_commit_bytes: Option<usize>,
    /// Byte size of the AIR public-values payload (uni-stark prover
    /// line 175). `0` for the `SquareAir`-shaped no-public-values
    /// case, otherwise the prover-passed `pis` byte length under the
    /// `SerializingChallenger32` serialization.
    pub air_public_values_bytes: usize,
    /// Byte size of the quotient-commit MMCS root. Pinned at 32.
    pub quotient_commit_bytes: usize,
    /// Byte size of the randomizer-commit MMCS root. Pinned at 32.
    pub randomizer_commit_bytes: usize,
}

impl LiveExtractorShape {
    /// Default shape for the SHROUD reference Plonky3 deployment:
    /// BabyBear values, Keccak256 MMCS, no preprocessed columns,
    /// empty AIR public values, ZK enabled (the only supported mode).
    pub const fn standard() -> Self {
        Self {
            log_ext_degree_bytes: 4,
            log_degree_bytes: 4,
            preprocessed_width_bytes: 4,
            trace_commit_bytes: 32,
            preprocessed_commit_bytes: None,
            air_public_values_bytes: 0,
            quotient_commit_bytes: 32,
            randomizer_commit_bytes: 32,
        }
    }
}

impl Default for LiveExtractorShape {
    fn default() -> Self {
        Self::standard()
    }
}

// ── Error type ───────────────────────────────────────────────────────────────

/// Typed error variants reported by [`extract_pre_grind_slices`]. No
/// panics: every drift returns a structured value that the caller can
/// surface to a verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveExtractionError {
    /// The event log was exhausted before the requested block could be
    /// filled. Indicates a truncated recorder log or a too-aggressive
    /// pre-grind cutoff.
    TruncatedLog {
        /// Name of the block being read when the log ran out.
        reading: &'static str,
        /// Bytes accumulated so far.
        had: usize,
        /// Bytes expected for this block.
        expected: usize,
    },
    /// A `Sampled` event interrupted a logical observe-block. The
    /// production prover must not sample a challenge mid-commitment;
    /// this is a Fiat-Shamir ordering violation.
    SampledInObserveBlock {
        /// Name of the block being read.
        reading: &'static str,
        /// Bytes accumulated before the Sampled event.
        had: usize,
        /// Bytes expected for this block.
        expected: usize,
        /// Length of the offending Sampled event.
        sampled_len: usize,
    },
    /// A single `Observed` event would push the cumulative byte count
    /// past the block budget. The event boundary doesn't align with
    /// the logical block boundary, so the domain label would attach
    /// to bytes crossing the boundary.
    ObservedBlockOvershoot {
        /// Name of the block being read.
        reading: &'static str,
        /// Bytes accumulated before this event.
        had: usize,
        /// Length of the offending event.
        event_len: usize,
        /// Bytes expected for this block.
        expected: usize,
    },
    /// Expected ≥1 `Sampled` events at a challenge-sampling point but
    /// the next event was an `Observed` (or the log ended).
    MissingChallengeSample {
        /// Human-readable name of the missing challenge.
        challenge: &'static str,
    },
}

impl fmt::Display for LiveExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedLog {
                reading,
                had,
                expected,
            } => write!(
                f,
                "[live_extractor] event log exhausted while reading {reading} \
                 (had {had} of {expected} bytes)"
            ),
            Self::SampledInObserveBlock {
                reading,
                had,
                expected,
                sampled_len,
            } => write!(
                f,
                "[live_extractor] Sampled({sampled_len}) interrupts observe-block \
                 for {reading} after {had} of {expected} bytes — \
                 Fiat-Shamir order violation"
            ),
            Self::ObservedBlockOvershoot {
                reading,
                had,
                event_len,
                expected,
            } => write!(
                f,
                "[live_extractor] Observed event for {reading} crosses block boundary \
                 (had {had} bytes, event adds {event_len}, budget {expected})"
            ),
            Self::MissingChallengeSample { challenge } => write!(
                f,
                "[live_extractor] expected >=1 Sampled events for {challenge}, found none"
            ),
        }
    }
}

impl std::error::Error for LiveExtractionError {}

// ── Extractor ────────────────────────────────────────────────────────────────

/// Read a contiguous run of `Observed` events from `iter`, accumulating
/// bytes until `expected` are consumed. Returns one of the
/// observed-block error variants on drift.
fn read_observed_block<'a, I>(
    iter: &mut core::iter::Peekable<I>,
    expected: usize,
    reading: &'static str,
) -> Result<Vec<u8>, LiveExtractionError>
where
    I: Iterator<Item = &'a ByteTranscriptEvent>,
{
    let mut out = Vec::with_capacity(expected);
    while out.len() < expected {
        match iter.next() {
            Some(ByteTranscriptEvent::Observed(bytes)) => {
                if out.len() + bytes.len() > expected {
                    return Err(LiveExtractionError::ObservedBlockOvershoot {
                        reading,
                        had: out.len(),
                        event_len: bytes.len(),
                        expected,
                    });
                }
                out.extend_from_slice(bytes);
            }
            Some(ByteTranscriptEvent::Sampled(bytes)) => {
                return Err(LiveExtractionError::SampledInObserveBlock {
                    reading,
                    had: out.len(),
                    expected,
                    sampled_len: bytes.len(),
                });
            }
            None => {
                return Err(LiveExtractionError::TruncatedLog {
                    reading,
                    had: out.len(),
                    expected,
                });
            }
        }
    }
    Ok(out)
}

/// Consume ≥1 `Sampled` events from `iter`. Returns
/// [`LiveExtractionError::MissingChallengeSample`] if the next event
/// is not a `Sampled` (or the log is empty).
fn read_sampled_block<'a, I>(
    iter: &mut core::iter::Peekable<I>,
    challenge: &'static str,
) -> Result<(), LiveExtractionError>
where
    I: Iterator<Item = &'a ByteTranscriptEvent>,
{
    let mut saw = false;
    while let Some(ByteTranscriptEvent::Sampled(_)) = iter.peek() {
        iter.next();
        saw = true;
    }
    if !saw {
        return Err(LiveExtractionError::MissingChallengeSample { challenge });
    }
    Ok(())
}

/// Walk `events` structurally and extract the named SHROUD-stage byte
/// slices. See the module docs for the asserted event-shape invariant.
///
/// `shape` selects the per-block byte sizes and whether to expect a
/// preprocessed-commitment block / a randomizer-commitment block. Use
/// [`LiveExtractorShape::standard()`] for the SHROUD reference
/// deployment.
///
/// Returns [`LiveExtractionError`] on any drift; does not panic.
pub fn extract_pre_grind_slices(
    events: &[ByteTranscriptEvent],
    shape: &LiveExtractorShape,
) -> Result<LivePreGrindExtraction, LiveExtractionError> {
    let mut iter = events.iter().peekable();

    // Events 1-4: instance metadata + trace commit. No Sampled may
    // occur in this region.
    let log_ext_degree =
        read_observed_block(&mut iter, shape.log_ext_degree_bytes, "log_ext_degree")?;
    let log_degree = read_observed_block(&mut iter, shape.log_degree_bytes, "log_degree")?;
    let preprocessed_width = read_observed_block(
        &mut iter,
        shape.preprocessed_width_bytes,
        "preprocessed_width",
    )?;
    let trace_commit = read_observed_block(&mut iter, shape.trace_commit_bytes, "trace_commit")?;

    // Event 5: preprocessed_commit, conditional on
    //          `preprocessed_width > 0` (Plonky3 Mapping doc row 5).
    //          Reads AFTER `trace_commit`, matching uni-stark/src/prover.rs
    //          line 171.
    let preprocessed_commit = match shape.preprocessed_commit_bytes {
        Some(n) => Some(read_observed_block(&mut iter, n, "preprocessed_commit")?),
        None => None,
    };

    // Event 6: air_public_values, conditional on non-empty
    //          `air_public_values_bytes` (Plonky3 Mapping doc row 6).
    let air_public_values = if shape.air_public_values_bytes > 0 {
        read_observed_block(
            &mut iter,
            shape.air_public_values_bytes,
            "air_public_values",
        )?
    } else {
        Vec::new()
    };

    // Event 7: α sample MUST fire between the trace / preprocessed /
    //          public values block and quotient_commit.
    read_sampled_block(&mut iter, "alpha (batching challenge)")?;

    // Event 8: quotient_commit.
    let quotient_commit =
        read_observed_block(&mut iter, shape.quotient_commit_bytes, "quotient_commit")?;

    // Event 9: randomizer_commit. The bridge is ZK-only — no shape
    //          toggle. No Sampled may occur between quotient_commit
    //          and randomizer_commit (SHROUD-specific hiding-stack
    //          ordering invariant).
    let randomizer_commit = read_observed_block(
        &mut iter,
        shape.randomizer_commit_bytes,
        "randomizer_commit",
    )?;

    // Event 10: ζ sample MUST follow the randomizer commit.
    read_sampled_block(&mut iter, "zeta (OOD point)")?;

    Ok(LivePreGrindExtraction {
        log_ext_degree,
        log_degree,
        preprocessed_width,
        trace_commit,
        preprocessed_commit,
        air_public_values,
        quotient_commit,
        randomizer_commit,
    })
}

// ── Prefix selection helper ──────────────────────────────────────────────────

/// Returns the length of the longest event prefix of `events` that
/// replays cleanly through [`verify_byte_equivalence`].
///
/// This is the canonical workaround for the grind clone-pollution
/// issue: `SerializingChallenger32::grind` clones the challenger
/// inside a Rayon `find_any`, and clones share the `Arc`-backed
/// recorder tape, so post-grind candidate bytes pollute the recorder.
/// Binary-searching for the longest byte-equivalent prefix yields the
/// pre-grind clean region the extractor operates on.
///
/// Phase 3 will replace this helper with a single-clean-pass
/// `prove_with_recording_challenger` or an upstream grind patch.
pub fn longest_byte_equivalent_prefix(events: &[ByteTranscriptEvent]) -> usize {
    let mut lo = 0;
    let mut hi = events.len();
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if verify_byte_equivalence(&events[..mid]).is_ok() {
            lo = mid;
        } else if mid == 0 {
            return 0;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(bytes: &[u8]) -> ByteTranscriptEvent {
        ByteTranscriptEvent::Observed(bytes.to_vec())
    }

    fn samp(bytes: &[u8]) -> ByteTranscriptEvent {
        ByteTranscriptEvent::Sampled(bytes.to_vec())
    }

    /// Synthetic minimal pre-grind event shape: `(4, 4, 4, 32)` Observed
    /// (byte-by-byte to mimic `SerializingChallenger32<u8>`), then a
    /// Sampled (α), then 32 Observed (quotient_commit), then 32
    /// Observed (randomizer_commit), then a Sampled (ζ).
    fn synthetic_pre_grind_events() -> Vec<ByteTranscriptEvent> {
        let mut v = Vec::new();
        // log_ext_degree (4B), byte-by-byte
        for b in [0x01, 0x02, 0x03, 0x04] {
            v.push(obs(&[b]));
        }
        // log_degree (4B)
        for b in [0x11, 0x12, 0x13, 0x14] {
            v.push(obs(&[b]));
        }
        // preprocessed_width (4B)
        for b in [0x21, 0x22, 0x23, 0x24] {
            v.push(obs(&[b]));
        }
        // trace_commit (32B), as a single batched Observed(32) — proves
        // the extractor accepts any internal batching.
        v.push(obs(&[0xAA; 32]));
        // α sample
        v.push(samp(&[0xC0; 16]));
        // quotient_commit (32B)
        v.push(obs(&[0xBB; 32]));
        // randomizer_commit (32B)
        v.push(obs(&[0xCC; 32]));
        // ζ sample
        v.push(samp(&[0xD0; 16]));
        v
    }

    #[test]
    fn extracts_well_formed_events() {
        let events = synthetic_pre_grind_events();
        let ext = extract_pre_grind_slices(&events, &LiveExtractorShape::standard())
            .expect("well-formed events must extract");
        assert_eq!(ext.log_ext_degree, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(ext.log_degree, vec![0x11, 0x12, 0x13, 0x14]);
        assert_eq!(ext.preprocessed_width, vec![0x21, 0x22, 0x23, 0x24]);
        assert_eq!(ext.trace_commit, vec![0xAA; 32]);
        assert_eq!(ext.preprocessed_commit, None);
        assert!(ext.air_public_values.is_empty());
        assert_eq!(ext.quotient_commit, vec![0xBB; 32]);
        assert_eq!(ext.randomizer_commit, vec![0xCC; 32]);
    }

    #[test]
    fn truncated_log_returns_typed_error() {
        // Drop the last few events so randomizer_commit can't be read.
        let mut events = synthetic_pre_grind_events();
        events.truncate(events.len() - 2); // drop randomizer_commit + ζ
        let err = extract_pre_grind_slices(&events, &LiveExtractorShape::standard()).unwrap_err();
        assert!(
            matches!(
                err,
                LiveExtractionError::TruncatedLog {
                    reading: "randomizer_commit",
                    ..
                }
            ),
            "expected TruncatedLog(randomizer_commit), got {err:?}"
        );
    }

    #[test]
    fn sampled_inside_observe_block_is_rejected() {
        // Insert a Sampled mid-way through log_ext_degree's 4-byte run.
        // The synthetic log has 4 × Observed(1) at indices 0..4 for
        // log_ext_degree; injecting a Sampled at index 1 breaks that
        // observe block.
        let mut events = synthetic_pre_grind_events();
        events.insert(1, samp(&[0x99; 4]));
        let err = extract_pre_grind_slices(&events, &LiveExtractorShape::standard()).unwrap_err();
        assert!(
            matches!(
                err,
                LiveExtractionError::SampledInObserveBlock {
                    reading: "log_ext_degree",
                    ..
                }
            ),
            "expected SampledInObserveBlock(log_ext_degree), got {err:?}"
        );
    }

    #[test]
    fn missing_alpha_sample_is_rejected() {
        // Drop the α Sampled event (index 12 + 1 = 13: after 3×4 metadata
        // and the batched trace_commit).
        let mut events = synthetic_pre_grind_events();
        // First 12 bytes-by-byte metadata, then 1 batched trace_commit,
        // then the α Sampled at index 13.
        events.remove(13);
        let err = extract_pre_grind_slices(&events, &LiveExtractorShape::standard()).unwrap_err();
        // After removing α, the next event is the quotient_commit
        // Observed(32). read_sampled_block sees Observed in peek and
        // returns MissingChallengeSample.
        assert!(
            matches!(
                err,
                LiveExtractionError::MissingChallengeSample { challenge }
                    if challenge == "alpha (batching challenge)"
            ),
            "expected MissingChallengeSample(alpha), got {err:?}"
        );
    }

    #[test]
    fn observed_block_overshoot_is_rejected() {
        // Replace the 32B batched trace_commit with a single 33B
        // Observed — overshoot by one byte.
        let mut events = synthetic_pre_grind_events();
        // trace_commit was the 13th element (index 12).
        events[12] = obs(&[0xAA; 33]);
        let err = extract_pre_grind_slices(&events, &LiveExtractorShape::standard()).unwrap_err();
        assert!(
            matches!(
                err,
                LiveExtractionError::ObservedBlockOvershoot {
                    reading: "trace_commit",
                    ..
                }
            ),
            "expected ObservedBlockOvershoot(trace_commit), got {err:?}"
        );
    }

    #[test]
    fn preprocessed_commit_shape_reads_after_trace_commit() {
        // Plonky3 order (docs/Plonky3 Mapping.md rows 4-5): trace_commit
        // FIRST, then preprocessed_commit (conditional). Build a log
        // matching that order and assert the extractor returns the
        // correct bytes in the correct fields.
        let mut v = Vec::new();
        for b in [0x01, 0x02, 0x03, 0x04] {
            v.push(obs(&[b]));
        }
        for b in [0x11, 0x12, 0x13, 0x14] {
            v.push(obs(&[b]));
        }
        for b in [0x21, 0x22, 0x23, 0x24] {
            v.push(obs(&[b]));
        }
        v.push(obs(&[0xAA; 32])); // trace_commit (event 4)
        v.push(obs(&[0x77; 32])); // preprocessed_commit (event 5)
        v.push(samp(&[0xC0; 16])); // α
        v.push(obs(&[0xBB; 32])); // quotient_commit
        v.push(obs(&[0xCC; 32])); // randomizer_commit
        v.push(samp(&[0xD0; 16])); // ζ

        let shape = LiveExtractorShape {
            preprocessed_commit_bytes: Some(32),
            ..LiveExtractorShape::standard()
        };
        let ext =
            extract_pre_grind_slices(&v, &shape).expect("preprocessed-commit shape must extract");
        assert_eq!(ext.trace_commit, vec![0xAA; 32]);
        assert_eq!(ext.preprocessed_commit, Some(vec![0x77; 32]));
        assert!(ext.air_public_values.is_empty());
        assert_eq!(ext.randomizer_commit, vec![0xCC; 32]);
    }

    #[test]
    fn preprocessed_commit_before_trace_commit_maps_to_plonky3_order() {
        // Wrong producer intent: preprocessed_commit-shaped bytes BEFORE
        // trace_commit-shaped bytes. These adjacent blocks have the same
        // size, so a byte-only extractor cannot infer semantic intent from
        // the payload. The security property we can enforce here is that
        // the first block is ALWAYS interpreted as trace_commit and the
        // second block is ALWAYS interpreted as preprocessed_commit,
        // matching Plonky3 order.
        let mut v = Vec::new();
        for b in [0x01, 0x02, 0x03, 0x04] {
            v.push(obs(&[b]));
        }
        for b in [0x11, 0x12, 0x13, 0x14] {
            v.push(obs(&[b]));
        }
        for b in [0x21, 0x22, 0x23, 0x24] {
            v.push(obs(&[b]));
        }
        v.push(obs(&[0x77; 32])); // (wrong slot) preprocessed_commit-shaped bytes
        v.push(obs(&[0xAA; 32])); // (wrong slot) trace_commit-shaped bytes
        v.push(samp(&[0xC0; 16])); // α
        v.push(obs(&[0xBB; 32])); // quotient_commit
        v.push(obs(&[0xCC; 32])); // randomizer_commit
        v.push(samp(&[0xD0; 16])); // ζ

        let shape = LiveExtractorShape {
            preprocessed_commit_bytes: Some(32),
            ..LiveExtractorShape::standard()
        };
        // The walker reads trace_commit FIRST (correct order), so it
        // takes the 0x77 bytes as trace_commit and the 0xAA bytes as
        // preprocessed_commit. This test intentionally succeeds: it
        // locks the schema mapping and avoids overclaiming that equal-size
        // adjacent observe blocks can be semantically distinguished.
        let ext = extract_pre_grind_slices(&v, &shape)
            .expect("byte-count shape is valid; schema order determines labels");
        // Interpreted by Plonky3 order, not by producer intent.
        assert_eq!(ext.trace_commit, vec![0x77; 32]);
        assert_eq!(ext.preprocessed_commit, Some(vec![0xAA; 32]));
    }

    #[test]
    fn air_public_values_shape_consumes_extra_block() {
        // Build a log with an 8-byte air_public_values block between
        // trace_commit and the α sample.
        let mut v = Vec::new();
        for b in [0x01, 0x02, 0x03, 0x04] {
            v.push(obs(&[b]));
        }
        for b in [0x11, 0x12, 0x13, 0x14] {
            v.push(obs(&[b]));
        }
        for b in [0x21, 0x22, 0x23, 0x24] {
            v.push(obs(&[b]));
        }
        v.push(obs(&[0xAA; 32])); // trace_commit
        v.push(obs(&[0x42; 8])); // air_public_values
        v.push(samp(&[0xC0; 16])); // α
        v.push(obs(&[0xBB; 32])); // quotient_commit
        v.push(obs(&[0xCC; 32])); // randomizer_commit
        v.push(samp(&[0xD0; 16])); // ζ

        let shape = LiveExtractorShape {
            air_public_values_bytes: 8,
            ..LiveExtractorShape::standard()
        };
        let ext =
            extract_pre_grind_slices(&v, &shape).expect("air-public-values shape must extract");
        assert_eq!(ext.air_public_values, vec![0x42; 8]);
    }

    #[test]
    fn missing_zeta_is_rejected() {
        // Drop the trailing ζ Sampled event.
        let mut events = synthetic_pre_grind_events();
        events.pop();
        let err = extract_pre_grind_slices(&events, &LiveExtractorShape::standard()).unwrap_err();
        assert!(
            matches!(
                err,
                LiveExtractionError::MissingChallengeSample { challenge }
                    if challenge == "zeta (OOD point)"
            ),
            "expected MissingChallengeSample(zeta), got {err:?}"
        );
    }

    #[test]
    fn longest_byte_equivalent_prefix_empty_is_zero() {
        assert_eq!(longest_byte_equivalent_prefix(&[]), 0);
    }
}
