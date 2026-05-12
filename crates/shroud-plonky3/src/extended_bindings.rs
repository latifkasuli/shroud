#![allow(clippy::too_many_arguments)]
// Backend-binding records encode 10+ Plonky3 events; one constructor argument per event is the readable shape.

//! Plonky3-specific transcript bindings.
//!
//! [`Plonky3UniStarkBindings`] holds one [`TranscriptBinding`] per gap event
//! identified in `docs/Plonky3 Mapping.md` § "Full Transcript Event Map" for
//! the **uni-stark** prove/verify path. Each binding stamps its domain label
//! at construction time so the recorder cannot accidentally cross-wire bytes
//! into the wrong slot.
//!
//! # Composition with `StandardBatchOpeningBindings`
//!
//! Per the design decision recorded in `docs/Plonky3 Mapping.md`, Plonky3
//! event slots **compose** with the canonical SHROUD v1 batch-opening
//! schedule, they do not mutate it. [`Plonky3UniStarkBindings::into_manifest`]
//! takes a [`StandardBatchOpeningBindings`] and returns a
//! [`TranscriptBindingManifest`] that adds the Plonky3-specific slots to the
//! right sampling-stage gates:
//!
//! - **Before `SampleBatchingChallenge` (α):** instance metadata + main
//!   commitments + AIR public values (events 1–6 of the event map).
//! - **Before `SampleOodPoint` (ζ):** quotient commitment (event 8).
//!   (The randomizer commitment, event 9, is already canonical under
//!   `DOMAIN_RANDOMIZER_COMMITMENT`.)
//! - **Before `ProveMaskedRelation`:** opened values at ζ, FRI commit-phase
//!   commitments, FRI final poly, FRI log-arities (events 12, 14, 17, 18).
//!
//! # Byte format is the recorder's responsibility
//!
//! This module is a typed container. The byte payloads come from the
//! `RecordingChallenger` (item 4) which forwards real Plonky3 challenger
//! `observe(...)` calls and captures the exact bytes the production
//! challenger absorbs. That keeps SHROUD's wire format consistent with
//! Plonky3's [`CanObserve<Com>`] behaviour by construction, rather than by
//! reverse-engineering. Item 3 only fixes the slot identity (domain label)
//! and the placement of each slot in the SHROUD manifest schedule.
//!
//! # Why uni-stark only
//!
//! `docs/Plonky3 Integration Checklist.md` scopes the first integration PR
//! to uni-stark + the encoded-oracle-bundle randomizer path. Batch-stark
//! adds 12 additional events (instance bindings, batched main commitment,
//! permutation challenges, lookup cumulated values, etc.) — captured as a
//! follow-on `Plonky3BatchStarkBindings` once the uni-stark bridge is
//! shipping byte-for-byte against the real challenger.

use shroud_core::{StandardBatchOpeningBindings, TranscriptBinding, TranscriptBindingManifest};
use shroud_reference::ReferenceBindingRecord;

// ── Domain labels ────────────────────────────────────────────────────────────

/// Domain label for Plonky3 event 1 — `observe(Val::from_u8(log_ext_degree))`.
pub const DOMAIN_PLONKY3_LOG_EXT_DEGREE: &str = "SHROUD_V1_PLONKY3_LOG_EXT_DEGREE";

/// Domain label for Plonky3 event 2 — `observe(Val::from_u8(log_degree))`.
pub const DOMAIN_PLONKY3_LOG_DEGREE: &str = "SHROUD_V1_PLONKY3_LOG_DEGREE";

/// Domain label for Plonky3 event 3 — `observe(Val::from_usize(preprocessed_width))`.
pub const DOMAIN_PLONKY3_PREPROCESSED_WIDTH: &str = "SHROUD_V1_PLONKY3_PREPROCESSED_WIDTH";

/// Domain label for Plonky3 event 4 — `observe(trace_commit)`.
pub const DOMAIN_PLONKY3_TRACE_COMMITMENT: &str = "SHROUD_V1_PLONKY3_TRACE_COMMITMENT";

/// Domain label for Plonky3 event 5 — `observe(preprocessed_commit)` (conditional).
pub const DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT: &str =
    "SHROUD_V1_PLONKY3_PREPROCESSED_COMMITMENT";

/// Domain label for Plonky3 event 6 — `observe_slice(public_values)`.
///
/// Note: distinct from `DOMAIN_PUBLIC_OPENINGS` (which holds opened values at ζ,
/// event 12). The AIR public inputs are an earlier transcript event with
/// different semantics, see `docs/Plonky3 Mapping.md` § "Open question".
pub const DOMAIN_PLONKY3_AIR_PUBLIC_VALUES: &str = "SHROUD_V1_PLONKY3_AIR_PUBLIC_VALUES";

/// Domain label for Plonky3 event 8 — `observe(quotient_commit)`.
pub const DOMAIN_PLONKY3_QUOTIENT_COMMITMENT: &str = "SHROUD_V1_PLONKY3_QUOTIENT_COMMITMENT";

/// Domain label for Plonky3 event 12 — `observe_algebra_slice(&ys)` inside
/// `pcs.open_with_preprocessing`, for opened values at ζ (and ζ_next) across
/// all rounds.
///
/// The byte payload is the recorder's per-round concatenation in the order:
/// randomizer-at-ζ, trace-at-ζ[/ζ_next], quotient-chunks-at-ζ,
/// preprocessed-at-ζ[/ζ_next]. The exact encoding mirrors the bytes the
/// production challenger absorbs.
pub const DOMAIN_PLONKY3_OPENED_VALUES: &str = "SHROUD_V1_PLONKY3_OPENED_VALUES";

/// Domain label for Plonky3 event 14 — `observe(commit_phase_commit)` per fold round.
///
/// The byte payload is the recorder's concatenation of all fold-round
/// commitments in fold order, length-prefixed by the recorder so the verifier
/// can round-trip the sequence.
pub const DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS: &str =
    "SHROUD_V1_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS";

/// Domain label for Plonky3 event 17 — `observe_algebra_slice(final_poly)`.
pub const DOMAIN_PLONKY3_FRI_FINAL_POLY: &str = "SHROUD_V1_PLONKY3_FRI_FINAL_POLY";

/// Domain label for Plonky3 event 18 — `observe(Val::from_usize(log_arity))` per
/// arity in the variable-arity schedule.
pub const DOMAIN_PLONKY3_FRI_LOG_ARITIES: &str = "SHROUD_V1_PLONKY3_FRI_LOG_ARITIES";

// ── Plonky3UniStarkBindings ──────────────────────────────────────────────────

/// Typed container holding one [`TranscriptBinding`] per gap event in the
/// uni-stark prove/verify transcript stream.
///
/// Construct via [`Self::new`] (passing raw bytes from the recording
/// challenger), optionally attach a preprocessed commitment via
/// [`Self::with_preprocessed_commitment`], then compose with the canonical
/// SHROUD bindings via [`Self::into_manifest`].
///
/// # Why fields are private
///
/// Each field has a fixed [`DOMAIN_PLONKY3_*`] label. Public fields would let
/// a caller construct a binding under one label and stash it in a slot
/// belonging to a different label, defeating the cross-protocol confusion
/// defense that the binding layer provides. The constructor enforces the
/// label/slot correspondence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plonky3UniStarkBindings {
    log_ext_degree: TranscriptBinding,
    log_degree: TranscriptBinding,
    preprocessed_width: TranscriptBinding,
    preprocessed_commitment: Option<TranscriptBinding>,
    trace_commitment: TranscriptBinding,
    air_public_values: TranscriptBinding,
    quotient_commitment: TranscriptBinding,
    opened_values: TranscriptBinding,
    fri_commit_phase_commitments: TranscriptBinding,
    fri_final_poly: TranscriptBinding,
    fri_log_arities: TranscriptBinding,
}

impl Plonky3UniStarkBindings {
    /// Constructs a binding record from raw recorded byte payloads.
    ///
    /// Each payload is the exact byte sequence the production challenger
    /// absorbed when the corresponding Plonky3 event fired. The recorder
    /// (item 4 of the bridge work) produces these payloads by tapping the
    /// real `SerializingChallenger32` rather than reconstructing them from
    /// typed values.
    ///
    /// The optional preprocessed commitment is set separately via
    /// [`Self::with_preprocessed_commitment`] — AIRs without preprocessed
    /// columns omit event 5 entirely from the Plonky3 transcript stream.
    #[must_use]
    pub fn new(
        log_ext_degree: Vec<u8>,
        log_degree: Vec<u8>,
        preprocessed_width: Vec<u8>,
        trace_commitment: Vec<u8>,
        air_public_values: Vec<u8>,
        quotient_commitment: Vec<u8>,
        opened_values: Vec<u8>,
        fri_commit_phase_commitments: Vec<u8>,
        fri_final_poly: Vec<u8>,
        fri_log_arities: Vec<u8>,
    ) -> Self {
        Self {
            log_ext_degree: TranscriptBinding::new(DOMAIN_PLONKY3_LOG_EXT_DEGREE, log_ext_degree),
            log_degree: TranscriptBinding::new(DOMAIN_PLONKY3_LOG_DEGREE, log_degree),
            preprocessed_width: TranscriptBinding::new(
                DOMAIN_PLONKY3_PREPROCESSED_WIDTH,
                preprocessed_width,
            ),
            preprocessed_commitment: None,
            trace_commitment: TranscriptBinding::new(
                DOMAIN_PLONKY3_TRACE_COMMITMENT,
                trace_commitment,
            ),
            air_public_values: TranscriptBinding::new(
                DOMAIN_PLONKY3_AIR_PUBLIC_VALUES,
                air_public_values,
            ),
            quotient_commitment: TranscriptBinding::new(
                DOMAIN_PLONKY3_QUOTIENT_COMMITMENT,
                quotient_commitment,
            ),
            opened_values: TranscriptBinding::new(DOMAIN_PLONKY3_OPENED_VALUES, opened_values),
            fri_commit_phase_commitments: TranscriptBinding::new(
                DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS,
                fri_commit_phase_commitments,
            ),
            fri_final_poly: TranscriptBinding::new(DOMAIN_PLONKY3_FRI_FINAL_POLY, fri_final_poly),
            fri_log_arities: TranscriptBinding::new(
                DOMAIN_PLONKY3_FRI_LOG_ARITIES,
                fri_log_arities,
            ),
        }
    }

    /// Attaches the optional preprocessed-commitment binding (event 5).
    ///
    /// Call this iff the AIR has preprocessed columns and the prover observed
    /// the preprocessed MMCS root.
    #[must_use]
    pub fn with_preprocessed_commitment(mut self, bytes: Vec<u8>) -> Self {
        self.preprocessed_commitment = Some(TranscriptBinding::new(
            DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT,
            bytes,
        ));
        self
    }

    // ── Accessors (read-only) ───────────────────────────────────────────────

    /// Event 1 binding.
    #[must_use]
    pub fn log_ext_degree(&self) -> &TranscriptBinding {
        &self.log_ext_degree
    }

    /// Event 2 binding.
    #[must_use]
    pub fn log_degree(&self) -> &TranscriptBinding {
        &self.log_degree
    }

    /// Event 3 binding.
    #[must_use]
    pub fn preprocessed_width(&self) -> &TranscriptBinding {
        &self.preprocessed_width
    }

    /// Event 4 binding.
    #[must_use]
    pub fn trace_commitment(&self) -> &TranscriptBinding {
        &self.trace_commitment
    }

    /// Event 5 binding (`None` for AIRs with no preprocessed columns).
    #[must_use]
    pub fn preprocessed_commitment(&self) -> Option<&TranscriptBinding> {
        self.preprocessed_commitment.as_ref()
    }

    /// Event 6 binding.
    #[must_use]
    pub fn air_public_values(&self) -> &TranscriptBinding {
        &self.air_public_values
    }

    /// Event 8 binding.
    #[must_use]
    pub fn quotient_commitment(&self) -> &TranscriptBinding {
        &self.quotient_commitment
    }

    /// Event 12 binding.
    #[must_use]
    pub fn opened_values(&self) -> &TranscriptBinding {
        &self.opened_values
    }

    /// Event 14 binding.
    #[must_use]
    pub fn fri_commit_phase_commitments(&self) -> &TranscriptBinding {
        &self.fri_commit_phase_commitments
    }

    /// Event 17 binding.
    #[must_use]
    pub fn fri_final_poly(&self) -> &TranscriptBinding {
        &self.fri_final_poly
    }

    /// Event 18 binding.
    #[must_use]
    pub fn fri_log_arities(&self) -> &TranscriptBinding {
        &self.fri_log_arities
    }

    // ── Composition ─────────────────────────────────────────────────────────

    /// Composes this bindings record with [`StandardBatchOpeningBindings`] to
    /// produce a [`TranscriptBindingManifest`] covering both the canonical
    /// SHROUD schedule and the Plonky3-specific events.
    ///
    /// Stage assignment follows `docs/Plonky3 Mapping.md`:
    ///
    /// | Stage | Plonky3 events added |
    /// |---|---|
    /// | `SampleBatchingChallenge` (α) | log_ext_degree, log_degree, preprocessed_width, trace_commitment, [preprocessed_commitment], air_public_values |
    /// | `SampleOodPoint` (ζ) | quotient_commitment |
    /// | `ProveMaskedRelation` | opened_values, fri_commit_phase_commitments, fri_final_poly, fri_log_arities |
    ///
    /// Within each stage, the Plonky3 events are appended after the canonical
    /// SHROUD bindings. Order within a stage does not affect
    /// [`shroud_reference::ReferenceBindingRecord::assert_exact_present`]
    /// (which checks each expected binding for exact match anywhere in the
    /// absorbed sequence), but it does fix the canonical order for the
    /// per-stage label sequence locked by
    /// `standard_manifest_per_stage_label_sequence_is_canonical` tests in
    /// `shroud-reference`.
    #[must_use]
    pub fn into_manifest(
        self,
        standard: StandardBatchOpeningBindings,
    ) -> TranscriptBindingManifest {
        let mut manifest = TranscriptBindingManifest::standard_for_batch_opening(standard);

        // Before SampleBatchingChallenge: events 1–6
        manifest = manifest
            .with_before_batching_challenge(self.log_ext_degree)
            .with_before_batching_challenge(self.log_degree)
            .with_before_batching_challenge(self.preprocessed_width)
            .with_before_batching_challenge(self.trace_commitment);
        if let Some(pre) = self.preprocessed_commitment {
            manifest = manifest.with_before_batching_challenge(pre);
        }
        manifest = manifest.with_before_batching_challenge(self.air_public_values);

        // Before SampleOodPoint: event 8 (event 9, randomizer commitment, is
        // already canonical under DOMAIN_RANDOMIZER_COMMITMENT and lives in
        // the StandardBatchOpeningBindings.before_ood_point slot)
        manifest = manifest.with_before_ood_point(self.quotient_commitment);

        // Before ProveMaskedRelation: events 12, 14, 17, 18
        manifest = manifest
            .with_before_prove_masked(self.opened_values)
            .with_before_prove_masked(self.fri_commit_phase_commitments)
            .with_before_prove_masked(self.fri_final_poly)
            .with_before_prove_masked(self.fri_log_arities);

        manifest
    }

    /// Absorbs every Plonky3 event binding into the record in event-map order.
    ///
    /// Order: 1, 2, 3, 4, 5 *(if present)*, 6, 8, 12, 14, 17, 18. This is the
    /// time-order in which the events fire on the Plonky3 prove path. Use
    /// this on the prover side to build a [`ReferenceBindingRecord`] whose
    /// absorption sequence mirrors the actual Plonky3 challenger transcript.
    pub fn absorb_into(&self, record: &mut ReferenceBindingRecord) {
        record.absorb(self.log_ext_degree.clone());
        record.absorb(self.log_degree.clone());
        record.absorb(self.preprocessed_width.clone());
        record.absorb(self.trace_commitment.clone());
        if let Some(pre) = &self.preprocessed_commitment {
            record.absorb(pre.clone());
        }
        record.absorb(self.air_public_values.clone());
        record.absorb(self.quotient_commitment.clone());
        record.absorb(self.opened_values.clone());
        record.absorb(self.fri_commit_phase_commitments.clone());
        record.absorb(self.fri_final_poly.clone());
        record.absorb(self.fri_log_arities.clone());
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::{
        DOMAIN_RANDOMIZER_COMMITMENT, HashIdentifier, SecurityLevel, TranscriptBindable,
        TranscriptStage,
    };

    /// Test-only wrapper that lifts a raw [`TranscriptBinding`] into something
    /// implementing [`TranscriptBindable`], so we can feed synthetic bytes
    /// into `StandardBatchOpeningBindings::from_bindables` (which expects
    /// `TranscriptBindable` for each slot).
    struct RawBindable(TranscriptBinding);

    impl TranscriptBindable for RawBindable {
        fn to_transcript_binding(&self) -> TranscriptBinding {
            self.0.clone()
        }
    }

    /// Test fixture: every Plonky3-event binding gets a distinct synthetic
    /// byte payload so collisions / mis-stamping show up loudly.
    fn synthetic_bindings() -> Plonky3UniStarkBindings {
        Plonky3UniStarkBindings::new(
            vec![0x01],                   // log_ext_degree
            vec![0x02, 0x02],             // log_degree
            vec![0x03, 0x03, 0x03],       // preprocessed_width
            vec![0x04; 32],               // trace_commitment (32-byte MMCS root)
            vec![0x06, 0x06, 0x06, 0x06], // air_public_values
            vec![0x08; 32],               // quotient_commitment
            vec![0x0C; 64],               // opened_values
            vec![0x0E; 96],               // fri_commit_phase_commitments (3 × 32-byte folds)
            vec![0x11; 16],               // fri_final_poly
            vec![0x12, 0x12],             // fri_log_arities
        )
    }

    // ── Domain label hygiene ─────────────────────────────────────────────────

    #[test]
    fn all_plonky3_domain_labels_are_distinct() {
        let labels = [
            DOMAIN_PLONKY3_LOG_EXT_DEGREE,
            DOMAIN_PLONKY3_LOG_DEGREE,
            DOMAIN_PLONKY3_PREPROCESSED_WIDTH,
            DOMAIN_PLONKY3_TRACE_COMMITMENT,
            DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT,
            DOMAIN_PLONKY3_AIR_PUBLIC_VALUES,
            DOMAIN_PLONKY3_QUOTIENT_COMMITMENT,
            DOMAIN_PLONKY3_OPENED_VALUES,
            DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS,
            DOMAIN_PLONKY3_FRI_FINAL_POLY,
            DOMAIN_PLONKY3_FRI_LOG_ARITIES,
        ];
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i], labels[j], "labels {i} and {j} collide");
            }
        }
    }

    #[test]
    fn plonky3_domain_labels_use_distinct_prefix_from_shroud_core() {
        // Every Plonky3-specific label must be prefixed `SHROUD_V1_PLONKY3_`
        // so it cannot collide with a future `shroud_core::DOMAIN_*` constant.
        let labels = [
            DOMAIN_PLONKY3_LOG_EXT_DEGREE,
            DOMAIN_PLONKY3_LOG_DEGREE,
            DOMAIN_PLONKY3_PREPROCESSED_WIDTH,
            DOMAIN_PLONKY3_TRACE_COMMITMENT,
            DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT,
            DOMAIN_PLONKY3_AIR_PUBLIC_VALUES,
            DOMAIN_PLONKY3_QUOTIENT_COMMITMENT,
            DOMAIN_PLONKY3_OPENED_VALUES,
            DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS,
            DOMAIN_PLONKY3_FRI_FINAL_POLY,
            DOMAIN_PLONKY3_FRI_LOG_ARITIES,
        ];
        for label in labels {
            assert!(
                label.starts_with("SHROUD_V1_PLONKY3_"),
                "label {label:?} missing required prefix"
            );
        }
    }

    #[test]
    fn plonky3_domain_labels_disjoint_from_shroud_core_labels() {
        use shroud_core::{
            DOMAIN_BASIS, DOMAIN_BATCH_OPENING, DOMAIN_CODEWORD_EMBEDDING, DOMAIN_DEGREE_BUDGET,
            DOMAIN_DEGREE_CONTRACT, DOMAIN_HASH_ID, DOMAIN_HIDING_TECHNIQUE,
            DOMAIN_OPENING_PROJECTION, DOMAIN_ORACLE_COMMITMENT, DOMAIN_PROFILE,
            DOMAIN_PUBLIC_OPENINGS, DOMAIN_QUOTIENT_HIDER, DOMAIN_RANDOMIZER_COMMITMENT,
            DOMAIN_SAMPLED_CHALLENGE, DOMAIN_SECURITY_LEVEL,
        };

        let plonky3_labels = [
            DOMAIN_PLONKY3_LOG_EXT_DEGREE,
            DOMAIN_PLONKY3_LOG_DEGREE,
            DOMAIN_PLONKY3_PREPROCESSED_WIDTH,
            DOMAIN_PLONKY3_TRACE_COMMITMENT,
            DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT,
            DOMAIN_PLONKY3_AIR_PUBLIC_VALUES,
            DOMAIN_PLONKY3_QUOTIENT_COMMITMENT,
            DOMAIN_PLONKY3_OPENED_VALUES,
            DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS,
            DOMAIN_PLONKY3_FRI_FINAL_POLY,
            DOMAIN_PLONKY3_FRI_LOG_ARITIES,
        ];
        let core_labels = [
            DOMAIN_PROFILE,
            DOMAIN_BASIS,
            DOMAIN_ORACLE_COMMITMENT,
            DOMAIN_RANDOMIZER_COMMITMENT,
            DOMAIN_DEGREE_CONTRACT,
            DOMAIN_SECURITY_LEVEL,
            DOMAIN_PUBLIC_OPENINGS,
            DOMAIN_BATCH_OPENING,
            DOMAIN_CODEWORD_EMBEDDING,
            DOMAIN_OPENING_PROJECTION,
            DOMAIN_QUOTIENT_HIDER,
            DOMAIN_DEGREE_BUDGET,
            DOMAIN_HIDING_TECHNIQUE,
            DOMAIN_HASH_ID,
            DOMAIN_SAMPLED_CHALLENGE,
        ];
        for p in plonky3_labels {
            for c in core_labels {
                assert_ne!(
                    p, c,
                    "Plonky3 label {p:?} collides with shroud-core label {c:?}"
                );
            }
        }
    }

    // ── Constructor / accessor wiring ────────────────────────────────────────

    #[test]
    fn constructor_stamps_correct_domain_labels() {
        let b = synthetic_bindings();
        assert_eq!(
            b.log_ext_degree().domain_label(),
            DOMAIN_PLONKY3_LOG_EXT_DEGREE
        );
        assert_eq!(b.log_degree().domain_label(), DOMAIN_PLONKY3_LOG_DEGREE);
        assert_eq!(
            b.preprocessed_width().domain_label(),
            DOMAIN_PLONKY3_PREPROCESSED_WIDTH
        );
        assert_eq!(
            b.trace_commitment().domain_label(),
            DOMAIN_PLONKY3_TRACE_COMMITMENT
        );
        assert!(b.preprocessed_commitment().is_none());
        assert_eq!(
            b.air_public_values().domain_label(),
            DOMAIN_PLONKY3_AIR_PUBLIC_VALUES
        );
        assert_eq!(
            b.quotient_commitment().domain_label(),
            DOMAIN_PLONKY3_QUOTIENT_COMMITMENT
        );
        assert_eq!(
            b.opened_values().domain_label(),
            DOMAIN_PLONKY3_OPENED_VALUES
        );
        assert_eq!(
            b.fri_commit_phase_commitments().domain_label(),
            DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS,
        );
        assert_eq!(
            b.fri_final_poly().domain_label(),
            DOMAIN_PLONKY3_FRI_FINAL_POLY
        );
        assert_eq!(
            b.fri_log_arities().domain_label(),
            DOMAIN_PLONKY3_FRI_LOG_ARITIES
        );
    }

    #[test]
    fn constructor_preserves_byte_payloads() {
        let b = synthetic_bindings();
        // Each field carries the exact bytes passed to new().
        assert_eq!(b.log_ext_degree().canonical_bytes(), &[0x01]);
        assert_eq!(b.log_degree().canonical_bytes(), &[0x02, 0x02]);
        assert_eq!(
            b.preprocessed_width().canonical_bytes(),
            &[0x03, 0x03, 0x03]
        );
        assert_eq!(b.trace_commitment().canonical_bytes(), &[0x04; 32]);
        assert_eq!(
            b.air_public_values().canonical_bytes(),
            &[0x06, 0x06, 0x06, 0x06]
        );
        assert_eq!(b.quotient_commitment().canonical_bytes(), &[0x08; 32]);
        assert_eq!(b.opened_values().canonical_bytes(), &[0x0C; 64]);
        assert_eq!(
            b.fri_commit_phase_commitments().canonical_bytes(),
            &[0x0E; 96]
        );
        assert_eq!(b.fri_final_poly().canonical_bytes(), &[0x11; 16]);
        assert_eq!(b.fri_log_arities().canonical_bytes(), &[0x12, 0x12]);
    }

    #[test]
    fn with_preprocessed_commitment_attaches_event_5() {
        let b = synthetic_bindings().with_preprocessed_commitment(vec![0x05; 32]);
        let pre = b
            .preprocessed_commitment()
            .expect("event 5 should be present");
        assert_eq!(pre.domain_label(), DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT);
        assert_eq!(pre.canonical_bytes(), &[0x05; 32]);
    }

    // ── Manifest composition ─────────────────────────────────────────────────

    /// Builds a `StandardBatchOpeningBindings` from minimal synthetic protocol
    /// objects so we can test composition without dragging in the full
    /// shroud-reference fixture.
    fn synthetic_standard_bindings() -> StandardBatchOpeningBindings {
        use shroud_batch_opening::{BatchOpeningShape, ShroudBatchOpeningSpec};
        use shroud_codeword_embedding::{CodewordEmbeddingShape, ShroudCodewordEmbeddingSpec};
        use shroud_opening_projection::{
            AuxiliaryOpeningTransport, OpeningProjectionShape, ShroudOpeningProjectionSpec,
        };
        use shroud_oracle_commitment::{
            OracleAuxiliaryTransport, OracleCommitmentShape, ShroudOracleCommitmentSpec,
        };
        use shroud_quotient_hider::{
            QuotientAuxiliaryTransport, QuotientDecompositionFamily, QuotientDegreeContract,
            QuotientHiderShape, ShroudQuotientHiderSpec,
        };

        let basis = shroud_core::BasisDescriptor::plonky3_binomial(4);
        let profile = shroud_reference::ReferenceHidingFriPcsProfile::standard();
        let batch_spec = ShroudBatchOpeningSpec::statistical(
            BatchOpeningShape::new(4, 1, 2).expect("valid batch shape"),
            15,
        )
        .expect("valid batch spec");
        let codeword_spec = ShroudCodewordEmbeddingSpec::statistical(
            CodewordEmbeddingShape::new(64, 4, 18, 4).expect("valid codeword shape"),
        )
        .expect("valid codeword spec");
        let oracle_spec = ShroudOracleCommitmentSpec::statistical(
            OracleCommitmentShape::new(2, 3, 4, 5, 1).expect("valid oracle shape"),
            OracleAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid oracle spec");
        let projection_spec = ShroudOpeningProjectionSpec::statistical(
            OpeningProjectionShape::new(3, 5, 2).expect("valid projection shape"),
            AuxiliaryOpeningTransport::InBandWithMainProof,
        )
        .expect("valid projection spec");
        let degree_contract =
            QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid contract");
        let quotient_spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid quotient shape"),
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(degree_contract),
        )
        .expect("valid quotient spec");
        let hash_identifier = HashIdentifier::new("shroud-plonky3-test-suite-v1");
        let randomizer = RawBindable(TranscriptBinding::new(
            DOMAIN_RANDOMIZER_COMMITMENT,
            vec![0xAB; 32],
        ));
        let public_openings = shroud_core::PublicOpeningBinding::new(vec![0xCD; 16]);

        StandardBatchOpeningBindings::from_bindables(
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
        )
    }

    #[test]
    fn into_manifest_adds_plonky3_events_to_batching_challenge_stage() {
        let bindings = synthetic_bindings();
        let manifest = bindings.into_manifest(synthetic_standard_bindings());

        let domains: Vec<_> = manifest
            .required_before(TranscriptStage::SampleBatchingChallenge)
            .iter()
            .map(TranscriptBinding::domain_label)
            .collect();

        // Plonky3 events 1, 2, 3, 4, 6 should be present (event 5 is None here).
        assert!(domains.contains(&DOMAIN_PLONKY3_LOG_EXT_DEGREE));
        assert!(domains.contains(&DOMAIN_PLONKY3_LOG_DEGREE));
        assert!(domains.contains(&DOMAIN_PLONKY3_PREPROCESSED_WIDTH));
        assert!(domains.contains(&DOMAIN_PLONKY3_TRACE_COMMITMENT));
        assert!(domains.contains(&DOMAIN_PLONKY3_AIR_PUBLIC_VALUES));
        assert!(!domains.contains(&DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT));
    }

    #[test]
    fn into_manifest_includes_preprocessed_when_present() {
        let bindings = synthetic_bindings().with_preprocessed_commitment(vec![0x05; 32]);
        let manifest = bindings.into_manifest(synthetic_standard_bindings());

        let domains: Vec<_> = manifest
            .required_before(TranscriptStage::SampleBatchingChallenge)
            .iter()
            .map(TranscriptBinding::domain_label)
            .collect();
        assert!(domains.contains(&DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT));
    }

    #[test]
    fn into_manifest_adds_quotient_commitment_to_ood_point_stage() {
        let bindings = synthetic_bindings();
        let manifest = bindings.into_manifest(synthetic_standard_bindings());

        let domains: Vec<_> = manifest
            .required_before(TranscriptStage::SampleOodPoint)
            .iter()
            .map(TranscriptBinding::domain_label)
            .collect();
        assert!(domains.contains(&DOMAIN_PLONKY3_QUOTIENT_COMMITMENT));
        // Canonical bindings stay where they are:
        assert!(domains.contains(&DOMAIN_RANDOMIZER_COMMITMENT));
    }

    #[test]
    fn into_manifest_adds_fri_envelope_to_prove_masked_stage() {
        let bindings = synthetic_bindings();
        let manifest = bindings.into_manifest(synthetic_standard_bindings());

        let domains: Vec<_> = manifest
            .required_before(TranscriptStage::ProveMaskedRelation)
            .iter()
            .map(TranscriptBinding::domain_label)
            .collect();
        assert!(domains.contains(&DOMAIN_PLONKY3_OPENED_VALUES));
        assert!(domains.contains(&DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS));
        assert!(domains.contains(&DOMAIN_PLONKY3_FRI_FINAL_POLY));
        assert!(domains.contains(&DOMAIN_PLONKY3_FRI_LOG_ARITIES));
    }

    #[test]
    fn into_manifest_preserves_standard_canonical_labels() {
        // Composition must not drop any canonical SHROUD label. This locks in
        // the "compose, don't extend" property — the canonical schedule is
        // additive-only from Plonky3's side.
        use shroud_core::{
            DOMAIN_BASIS, DOMAIN_BATCH_OPENING, DOMAIN_CODEWORD_EMBEDDING, DOMAIN_HASH_ID,
            DOMAIN_OPENING_PROJECTION, DOMAIN_ORACLE_COMMITMENT, DOMAIN_PROFILE,
            DOMAIN_QUOTIENT_HIDER, DOMAIN_SECURITY_LEVEL,
        };

        let bindings = synthetic_bindings();
        let manifest = bindings.into_manifest(synthetic_standard_bindings());
        let batching_domains: Vec<_> = manifest
            .required_before(TranscriptStage::SampleBatchingChallenge)
            .iter()
            .map(TranscriptBinding::domain_label)
            .collect();

        for required in &[
            DOMAIN_HASH_ID,
            DOMAIN_PROFILE,
            DOMAIN_BASIS,
            DOMAIN_BATCH_OPENING,
            DOMAIN_CODEWORD_EMBEDDING,
            DOMAIN_ORACLE_COMMITMENT,
            DOMAIN_OPENING_PROJECTION,
            DOMAIN_QUOTIENT_HIDER,
            DOMAIN_SECURITY_LEVEL,
        ] {
            assert!(
                batching_domains.contains(required),
                "canonical SHROUD label {required:?} missing from composed manifest"
            );
        }
    }

    #[test]
    fn into_manifest_per_stage_label_order_plonky3_appended() {
        // Within each stage, Plonky3 events must appear AFTER the canonical
        // SHROUD bindings. This documents the "append" composition policy.
        let bindings = synthetic_bindings();
        let manifest = bindings.into_manifest(synthetic_standard_bindings());
        let batching: Vec<_> = manifest
            .required_before(TranscriptStage::SampleBatchingChallenge)
            .iter()
            .map(TranscriptBinding::domain_label)
            .collect();

        // The first 9 entries must be the canonical SHROUD bindings (per
        // standard_for_batch_opening); the Plonky3-prefixed ones come after.
        let last_canonical_idx = batching
            .iter()
            .rposition(|l| !l.starts_with("SHROUD_V1_PLONKY3_"))
            .expect("at least one canonical binding must be present");
        let first_plonky3_idx = batching
            .iter()
            .position(|l| l.starts_with("SHROUD_V1_PLONKY3_"))
            .expect("at least one plonky3 binding must be present");
        assert!(
            last_canonical_idx < first_plonky3_idx,
            "canonical SHROUD bindings must precede Plonky3-specific ones in stage order; \
             got last_canonical={last_canonical_idx}, first_plonky3={first_plonky3_idx}, \
             sequence={batching:?}"
        );
    }

    // ── absorb_into ──────────────────────────────────────────────────────────

    #[test]
    fn absorb_into_writes_every_event_in_time_order() {
        let bindings = synthetic_bindings().with_preprocessed_commitment(vec![0x05; 32]);
        let mut record = ReferenceBindingRecord::new();
        bindings.absorb_into(&mut record);

        let labels: Vec<_> = record
            .absorbed()
            .iter()
            .map(TranscriptBinding::domain_label)
            .collect();

        // Time-order on the Plonky3 prove path: 1, 2, 3, 4, 5, 6, 8, 12, 14, 17, 18
        assert_eq!(
            labels,
            vec![
                DOMAIN_PLONKY3_LOG_EXT_DEGREE,
                DOMAIN_PLONKY3_LOG_DEGREE,
                DOMAIN_PLONKY3_PREPROCESSED_WIDTH,
                DOMAIN_PLONKY3_TRACE_COMMITMENT,
                DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT,
                DOMAIN_PLONKY3_AIR_PUBLIC_VALUES,
                DOMAIN_PLONKY3_QUOTIENT_COMMITMENT,
                DOMAIN_PLONKY3_OPENED_VALUES,
                DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS,
                DOMAIN_PLONKY3_FRI_FINAL_POLY,
                DOMAIN_PLONKY3_FRI_LOG_ARITIES,
            ]
        );
    }

    #[test]
    fn absorb_into_skips_preprocessed_when_none() {
        let bindings = synthetic_bindings();
        let mut record = ReferenceBindingRecord::new();
        bindings.absorb_into(&mut record);

        let has_preprocessed = record
            .absorbed()
            .iter()
            .any(|b| b.domain_label() == DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT);
        assert!(
            !has_preprocessed,
            "preprocessed commitment must be absent when not attached"
        );
    }
}
