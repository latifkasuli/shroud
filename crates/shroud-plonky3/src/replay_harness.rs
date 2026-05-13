//! End-to-end bridge replay harness composing all four byte-faithful
//! verification invariants into a single check.
//!
//! [`Plonky3ReplayHarness::verify`] is the production-shaped invariant
//! that a Plonky3 prove + verify cycle must satisfy for a SHROUD-bridged
//! proof to be trustworthy. It composes:
//!
//! 1. **Provenance gate** ([`verify_profile_matches_backend`]) — the
//!    `p3-symmetric` advisory passes AND every pinned-backend constant
//!    matches the profile.
//! 2. **Manifest exact-presence** ([`ReferenceBindingRecord::finalize`]) —
//!    the absorbed binding record contains every binding declared by the
//!    manifest, with exact canonical-byte equality.
//! 3. **Byte-faithful challenger replay** ([`verify_byte_equivalence`]) —
//!    the recorded transcript event log, replayed through a fresh Plonky3
//!    challenger, produces byte-identical sampled bytes.
//!
//! Any divergence fails the harness with the appropriate
//! [`HarnessError`] variant. The intent: a bridge implementer wires up
//! the prove path with [`RecordingByteChallenger`], collects the
//! resulting record, manifest, and event log, and runs
//! [`Plonky3ReplayHarness::verify`] as the single end-to-end gate.
//!
//! # Why the SHROUD trait `TranscriptChallengeDeriver` is not used here
//!
//! `TranscriptChallengeDeriver::derive_challenge(&self, prefix, stage)`
//! models a stateless `H(prefix) -> challenge` function — appropriate for
//! the in-process [`ReferenceChallengeDeriver`] and for non-stateful
//! backends. Plonky3's `HashChallenger` is stateful: `sample()` chains
//! hash output into future input, so prefix-only replay produces the
//! wrong challenge bytes once any intermediate sample has fired.
//!
//! Modern Fiat-Shamir practice (see IETF FS draft and Merlin) treats the
//! transcript hash as a stateful absorb/squeeze object, not a function of
//! a prefix. [`verify_byte_equivalence`] replays the full
//! observe/sample event log against a fresh challenger and is the
//! authoritative byte-equivalence primitive for the Plonky3 backend.
//! Other backends with stateless challengers can continue to use the
//! SHROUD trait directly.
//!
//! [`ReferenceChallengeDeriver`]: shroud_reference::ReferenceChallengeDeriver
//! [`ReferenceBindingRecord::finalize`]: shroud_reference::ReferenceBindingRecord::finalize

use core::fmt;

use shroud_core::{TranscriptBindingError, TranscriptBindingManifest};
use shroud_reference::{ReferenceBindingRecord, ReferenceHidingFriPcsProfile};

use crate::{
    BackendDriftError, ByteTranscriptEvent, ReplayMismatch, verify_byte_equivalence,
    verify_profile_matches_backend,
};

// ── HarnessError ─────────────────────────────────────────────────────────────

/// First detected failure from [`Plonky3ReplayHarness::verify`].
///
/// Variants correspond to the harness's three sequenced invariants.
/// Display surfaces the underlying error along with a brief identifier
/// of which invariant fired, so triage logs identify the failed gate
/// without inspecting the variant programmatically.
#[derive(Clone, Debug)]
pub enum HarnessError {
    /// Backend constants or `p3-symmetric` advisory check failed. Bridge
    /// cannot start under this condition.
    Provenance(BackendDriftError),
    /// Manifest exact-presence check failed — either a required binding
    /// is absent from the record, or its canonical bytes diverge from
    /// the expected value.
    Manifest(TranscriptBindingError),
    /// Byte-faithful challenger replay diverged. Carries the event index
    /// and byte position of the first mismatch.
    Replay(ReplayMismatch),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provenance(err) => write!(f, "[provenance] {err}"),
            Self::Manifest(err) => write!(f, "[manifest] {err}"),
            Self::Replay(err) => write!(f, "[replay] {err}"),
        }
    }
}

impl std::error::Error for HarnessError {}

impl From<BackendDriftError> for HarnessError {
    fn from(err: BackendDriftError) -> Self {
        Self::Provenance(err)
    }
}

impl From<TranscriptBindingError> for HarnessError {
    fn from(err: TranscriptBindingError) -> Self {
        Self::Manifest(err)
    }
}

impl From<ReplayMismatch> for HarnessError {
    fn from(err: ReplayMismatch) -> Self {
        Self::Replay(err)
    }
}

// ── Plonky3ReplayHarness ─────────────────────────────────────────────────────

/// Composes the three Plonky3-bridge byte-faithfulness invariants into a
/// single end-to-end check.
///
/// Usage pattern (Phase 2, post-real-prove integration):
///
/// ```text
/// // 1. Run a real HidingBackend::prove with a RecordingByteChallenger.
/// let (challenger, recorder) = new_pinned_recording_challenger();
/// // … prove flow populates `recorder` …
///
/// // 2. Build the manifest from the prove inputs.
/// let bindings = Plonky3UniStarkBindings::new(/* slot bytes from recorder */);
/// let manifest = bindings.into_manifest(standard);
///
/// // 3. Build the absorbed record from the same bindings.
/// let mut record = ReferenceBindingRecord::new();
/// // … absorb canonical bindings + bindings.absorb_into(&mut record) …
///
/// // 4. Run the harness.
/// let harness = Plonky3ReplayHarness::new(&profile, &record, &manifest, &recorder.events());
/// harness.verify()?;  // Ok iff every invariant holds.
/// ```
///
/// For Phase 1, tests construct fixtures synthetically via
/// `RecordingByteChallenger` driven from inside the test (no live prove).
/// The harness logic is identical either way.
pub struct Plonky3ReplayHarness<'a> {
    profile: &'a ReferenceHidingFriPcsProfile,
    record: &'a ReferenceBindingRecord,
    manifest: &'a TranscriptBindingManifest,
    events: &'a [ByteTranscriptEvent],
}

impl<'a> Plonky3ReplayHarness<'a> {
    /// Constructs a harness over the given prove artifacts.
    ///
    /// All four references must come from the SAME prove invocation:
    /// the record was populated alongside the manifest's bindings, and
    /// the events were captured by the recorder that fed the production
    /// challenger. Mismatched inputs produce false-negative failures
    /// (each invariant looks correct in isolation but the cross-checks
    /// fail).
    #[must_use]
    pub fn new(
        profile: &'a ReferenceHidingFriPcsProfile,
        record: &'a ReferenceBindingRecord,
        manifest: &'a TranscriptBindingManifest,
        events: &'a [ByteTranscriptEvent],
    ) -> Self {
        Self {
            profile,
            record,
            manifest,
            events,
        }
    }

    /// Runs all three invariants in order and returns the first failure
    /// or `Ok(())` if all pass.
    ///
    /// Ordering:
    /// 1. **Provenance** — fails fast under an unpatched stack so subsequent
    ///    checks don't waste cycles on a fundamentally broken backend.
    /// 2. **Manifest** — fails on missing or byte-mismatched bindings,
    ///    which catches recording-layer bugs before replay.
    /// 3. **Replay** — fails on challenger-state divergence, the deepest
    ///    correctness check.
    pub fn verify(&self) -> Result<(), HarnessError> {
        self.verify_provenance()?;
        self.verify_manifest()?;
        self.verify_byte_equivalence()?;
        Ok(())
    }

    /// Invariant 1 only — pinned-backend constants + `p3-symmetric`
    /// advisory gate.
    pub fn verify_provenance(&self) -> Result<(), HarnessError> {
        verify_profile_matches_backend(self.profile)?;
        Ok(())
    }

    /// Invariant 2 only — manifest exact-presence of every absorbed binding.
    pub fn verify_manifest(&self) -> Result<(), HarnessError> {
        self.record.finalize(self.manifest)?;
        Ok(())
    }

    /// Invariant 3 only — byte-faithful event-log replay through a fresh
    /// Plonky3 challenger.
    pub fn verify_byte_equivalence(&self) -> Result<(), HarnessError> {
        verify_byte_equivalence(self.events)?;
        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use p3_challenger::{CanObserve, CanSample};
    use shroud_batch_opening::{BatchOpeningShape, ShroudBatchOpeningSpec};
    use shroud_codeword_embedding::{CodewordEmbeddingShape, ShroudCodewordEmbeddingSpec};
    use shroud_core::{
        BasisDescriptor, DOMAIN_RANDOMIZER_COMMITMENT, HashIdentifier, PublicOpeningBinding,
        SecurityLevel, StandardBatchOpeningBindings, TranscriptBindable, TranscriptBinding,
    };
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

    use crate::{
        Plonky3HashIdentifier, Plonky3UniStarkBindings, new_pinned_recording_byte_challenger,
    };

    /// Test-only wrapper to lift a raw [`TranscriptBinding`] into something
    /// implementing [`TranscriptBindable`]. Used to feed synthetic randomizer
    /// commitment bytes into `StandardBatchOpeningBindings::from_bindables`.
    struct RawBindable(TranscriptBinding);

    impl TranscriptBindable for RawBindable {
        fn to_transcript_binding(&self) -> TranscriptBinding {
            self.0.clone()
        }
    }

    /// Fixture: everything a `Plonky3ReplayHarness::verify()` call needs,
    /// built from synthetic prove-shaped data. Phase 2 will replace this
    /// with a live `HidingBackend::prove` invocation.
    struct HarnessFixture {
        profile: ReferenceHidingFriPcsProfile,
        record: ReferenceBindingRecord,
        manifest: TranscriptBindingManifest,
        events: Vec<ByteTranscriptEvent>,
    }

    /// Builds a complete, self-consistent fixture by driving a
    /// [`RecordingByteChallenger`] through a sequence of observe/sample
    /// calls and using the captured tape both for the
    /// [`Plonky3UniStarkBindings`] slot bytes AND for the event log.
    fn build_fixture() -> HarnessFixture {
        // 1. Drive a recording challenger to produce a real (synthetic) event log.
        let (mut byte_challenger, recorder) = new_pinned_recording_byte_challenger();

        // Slot 1: log_ext_degree (1 byte, like Plonky3's Val::from_u8)
        let log_ext_degree_bytes = vec![0x02u8];
        byte_challenger.observe(log_ext_degree_bytes[0]);

        // Slot 2: log_degree (1 byte)
        let log_degree_bytes = vec![0x10u8];
        byte_challenger.observe(log_degree_bytes[0]);

        // Slot 3: preprocessed_width (4 bytes, like Val::from_usize)
        let preprocessed_width_bytes = vec![0x00u8, 0x00, 0x00, 0x00];
        for &b in &preprocessed_width_bytes {
            byte_challenger.observe(b);
        }

        // Slot 4: trace_commitment (32 bytes, like a Keccak Merkle root)
        let trace_commitment_bytes = (0..32u8).map(|i| i ^ 0xA0).collect::<Vec<_>>();
        for &b in &trace_commitment_bytes {
            byte_challenger.observe(b);
        }

        // Slot 6: air_public_values (8 bytes)
        let air_public_values_bytes = vec![0xCAu8, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
        for &b in &air_public_values_bytes {
            byte_challenger.observe(b);
        }

        // α sample (4 bytes, like the start of an algebra element sample)
        let _: u8 = byte_challenger.sample();
        let _: u8 = byte_challenger.sample();
        let _: u8 = byte_challenger.sample();
        let _: u8 = byte_challenger.sample();

        // Slot 8: quotient_commitment (32 bytes)
        let quotient_commitment_bytes = (0..32u8).map(|i| i ^ 0xB0).collect::<Vec<_>>();
        for &b in &quotient_commitment_bytes {
            byte_challenger.observe(b);
        }

        // ζ sample
        let _: u8 = byte_challenger.sample();
        let _: u8 = byte_challenger.sample();

        // Slot 12: opened_values (16 bytes)
        let opened_values_bytes = (0..16u8).map(|i| i ^ 0xC0).collect::<Vec<_>>();
        for &b in &opened_values_bytes {
            byte_challenger.observe(b);
        }

        // Slot 14: fri_commit_phase_commitments (length-prefixed: 1 fold × 32B)
        let mut fri_commit_phase_bytes = (1u32).to_le_bytes().to_vec();
        fri_commit_phase_bytes.extend((32u32).to_le_bytes());
        fri_commit_phase_bytes.extend((0..32u8).map(|i| i ^ 0xD0));
        for &b in &fri_commit_phase_bytes {
            byte_challenger.observe(b);
        }

        // Slot 17: fri_final_poly (16 bytes)
        let fri_final_poly_bytes = (0..16u8).map(|i| i ^ 0xE0).collect::<Vec<_>>();
        for &b in &fri_final_poly_bytes {
            byte_challenger.observe(b);
        }

        // Slot 18: fri_log_arities (4 bytes)
        let fri_log_arities_bytes = vec![0x01u8, 0x00, 0x00, 0x00];
        for &b in &fri_log_arities_bytes {
            byte_challenger.observe(b);
        }

        let events = recorder.events();

        // 2. Build Plonky3UniStarkBindings from the slot bytes.
        let bindings = Plonky3UniStarkBindings::new(
            log_ext_degree_bytes.clone(),
            log_degree_bytes.clone(),
            preprocessed_width_bytes.clone(),
            trace_commitment_bytes.clone(),
            air_public_values_bytes.clone(),
            quotient_commitment_bytes.clone(),
            opened_values_bytes.clone(),
            fri_commit_phase_bytes.clone(),
            fri_final_poly_bytes.clone(),
            fri_log_arities_bytes.clone(),
        );

        // 3. Build StandardBatchOpeningBindings from concrete SHROUD spec objects.
        let basis = BasisDescriptor::plonky3_binomial(4);
        let profile = ReferenceHidingFriPcsProfile::standard();
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
        let hash_identifier = Plonky3HashIdentifier::standard().to_hash_identifier();
        let randomizer = RawBindable(TranscriptBinding::new(
            DOMAIN_RANDOMIZER_COMMITMENT,
            vec![0xAB; 32],
        ));
        let public_openings = PublicOpeningBinding::new(vec![0xCD; 16]);

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

        // 4. Compose manifest = standard ⊕ plonky3 bindings.
        let manifest = bindings.into_manifest(standard);

        // 5. Build a record by absorbing every canonical binding from the
        // same sources. The Plonky3UniStarkBindings slots are absorbed via
        // their stamped TranscriptBinding values directly (we re-construct
        // them via Plonky3UniStarkBindings::new clone path).
        let bindings_for_record = Plonky3UniStarkBindings::new(
            log_ext_degree_bytes,
            log_degree_bytes,
            preprocessed_width_bytes,
            trace_commitment_bytes,
            air_public_values_bytes,
            quotient_commitment_bytes,
            opened_values_bytes,
            fri_commit_phase_bytes,
            fri_final_poly_bytes,
            fri_log_arities_bytes,
        );

        let mut record = ReferenceBindingRecord::new();
        // Canonical SHROUD bindings (the ones the manifest expects under
        // the SampleBatchingChallenge stage from standard_for_batch_opening).
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
        record.absorb_bindable(&randomizer);
        record.absorb_bindable(&public_openings);
        // Plonky3-specific bindings (the ones the manifest expects added on top).
        bindings_for_record.absorb_into(&mut record);

        HarnessFixture {
            profile,
            record,
            manifest,
            events,
        }
    }

    // ── Positive case ────────────────────────────────────────────────────────

    /// **End-to-end correctness invariant.** A well-formed harness — patched
    /// stack, complete manifest, byte-equivalent event log — must verify.
    /// If this fails, the harness composition itself is broken regardless
    /// of any specific failure mode.
    #[test]
    fn harness_verifies_well_formed_inputs() {
        let fixture = build_fixture();
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &fixture.record,
            &fixture.manifest,
            &fixture.events,
        );
        harness.verify().expect("well-formed harness must verify");
    }

    // ── Adversarial battery ──────────────────────────────────────────────────

    /// Provenance failure: a non-hiding MMCS flag in the profile.
    /// (Can't easily mutate PINNED_P3_SYMMETRIC_PROVENANCE from a test, so
    /// we exercise a different provenance-gate path: profile drift.)
    #[test]
    fn harness_rejects_non_hiding_input_mmcs() {
        let mut fixture = build_fixture();
        fixture.profile.input_mmcs_hiding = false;
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &fixture.record,
            &fixture.manifest,
            &fixture.events,
        );
        let err = harness.verify().unwrap_err();
        assert!(
            matches!(
                err,
                HarnessError::Provenance(BackendDriftError::NonHidingInputMmcs)
            ),
            "expected provenance error, got {err:?}"
        );
    }

    #[test]
    fn harness_rejects_drifted_log_blowup() {
        let mut fixture = build_fixture();
        fixture.profile.log_blowup += 1;
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &fixture.record,
            &fixture.manifest,
            &fixture.events,
        );
        let err = harness.verify().unwrap_err();
        assert!(
            matches!(
                err,
                HarnessError::Provenance(BackendDriftError::LogBlowup { .. })
            ),
            "expected log_blowup drift, got {err:?}"
        );
    }

    /// Manifest failure: drop a binding from the record. Manifest expects
    /// it; record doesn't have it → MissingBinding.
    #[test]
    fn harness_rejects_missing_binding_in_record() {
        let fixture = build_fixture();
        // Build a record missing one canonical binding.
        let mut crippled = ReferenceBindingRecord::new();
        for binding in fixture.record.absorbed() {
            if binding.domain_label() == shroud_core::DOMAIN_BASIS {
                continue; // drop the basis binding
            }
            crippled.absorb(binding.clone());
        }
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &crippled,
            &fixture.manifest,
            &fixture.events,
        );
        let err = harness.verify().unwrap_err();
        match err {
            HarnessError::Manifest(TranscriptBindingError::MissingBinding { domain_label }) => {
                assert_eq!(domain_label, shroud_core::DOMAIN_BASIS);
            }
            other => panic!("expected MissingBinding(DOMAIN_BASIS), got {other:?}"),
        }
    }

    /// Manifest failure: mutate the bytes of a binding in the record.
    /// Manifest expects exact bytes; record has different bytes → BindingMismatch.
    #[test]
    fn harness_rejects_mutated_binding_bytes() {
        let fixture = build_fixture();
        // Build a record where DOMAIN_PLONKY3_TRACE_COMMITMENT has wrong bytes.
        let mut crippled = ReferenceBindingRecord::new();
        for binding in fixture.record.absorbed() {
            if binding.domain_label() == crate::DOMAIN_PLONKY3_TRACE_COMMITMENT {
                crippled.absorb(TranscriptBinding::new(
                    crate::DOMAIN_PLONKY3_TRACE_COMMITMENT,
                    vec![0xFFu8; 32],
                ));
            } else {
                crippled.absorb(binding.clone());
            }
        }
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &crippled,
            &fixture.manifest,
            &fixture.events,
        );
        let err = harness.verify().unwrap_err();
        match err {
            HarnessError::Manifest(TranscriptBindingError::BindingMismatch { domain_label }) => {
                assert_eq!(domain_label, crate::DOMAIN_PLONKY3_TRACE_COMMITMENT);
            }
            other => panic!("expected BindingMismatch, got {other:?}"),
        }
    }

    /// Replay failure: mutate one observation byte in the event log. Replay
    /// challenger absorbs the mutated byte; at the next sample, the
    /// recorded "expected" sample byte no longer matches.
    #[test]
    fn harness_rejects_mutated_observation_in_events() {
        let mut fixture = build_fixture();
        // Mutate the first observation event.
        match &mut fixture.events[0] {
            ByteTranscriptEvent::Observed(bytes) => bytes[0] ^= 0xFF,
            other => panic!("first event must be Observed, got {other:?}"),
        }
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &fixture.record,
            &fixture.manifest,
            &fixture.events,
        );
        let err = harness.verify().unwrap_err();
        assert!(
            matches!(err, HarnessError::Replay(_)),
            "expected replay error, got {err:?}"
        );
    }

    /// Replay failure: drop an observation event. State at next sample
    /// differs → ReplayMismatch.
    #[test]
    fn harness_rejects_dropped_event() {
        let mut fixture = build_fixture();
        // Drop the first event.
        fixture.events.remove(0);
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &fixture.record,
            &fixture.manifest,
            &fixture.events,
        );
        let err = harness.verify().unwrap_err();
        assert!(
            matches!(err, HarnessError::Replay(_)),
            "expected replay error, got {err:?}"
        );
    }

    /// Replay failure: reorder two observations that precede a sample.
    /// Absorbed sequence differs → ReplayMismatch.
    #[test]
    fn harness_rejects_reordered_events() {
        let mut fixture = build_fixture();
        // Find two adjacent Observed events early in the log and swap them.
        let (i, j) = fixture
            .events
            .windows(2)
            .enumerate()
            .find_map(|(i, w)| match (&w[0], &w[1]) {
                (ByteTranscriptEvent::Observed(_), ByteTranscriptEvent::Observed(_)) => {
                    Some((i, i + 1))
                }
                _ => None,
            })
            .expect("must have two adjacent Observed events");
        fixture.events.swap(i, j);
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &fixture.record,
            &fixture.manifest,
            &fixture.events,
        );
        let err = harness.verify().unwrap_err();
        assert!(
            matches!(err, HarnessError::Replay(_)),
            "expected replay error, got {err:?}"
        );
    }

    /// Manifest failure: build a manifest with the wrong hash-suite
    /// identifier and assert the harness rejects on the
    /// `DOMAIN_HASH_ID` slot.
    #[test]
    fn harness_rejects_wrong_hash_suite_identifier() {
        let fixture = build_fixture();
        // Build a manifest with a deliberately-wrong hash identifier.
        let wrong_hash_id = HashIdentifier::new("wrong-suite-identifier");
        let mut wrong_record = ReferenceBindingRecord::new();
        for binding in fixture.record.absorbed() {
            if binding.domain_label() == shroud_core::DOMAIN_HASH_ID {
                wrong_record.absorb(wrong_hash_id.to_transcript_binding());
            } else {
                wrong_record.absorb(binding.clone());
            }
        }
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &wrong_record,
            &fixture.manifest,
            &fixture.events,
        );
        let err = harness.verify().unwrap_err();
        match err {
            HarnessError::Manifest(TranscriptBindingError::BindingMismatch { domain_label }) => {
                assert_eq!(domain_label, shroud_core::DOMAIN_HASH_ID);
            }
            other => panic!("expected BindingMismatch on DOMAIN_HASH_ID, got {other:?}"),
        }
    }

    // ── Invariant ordering ───────────────────────────────────────────────────

    /// If both provenance AND a downstream invariant would fail, the
    /// harness must return the provenance error — the gate ordering is
    /// fail-fast on the deepest precondition.
    #[test]
    fn harness_returns_provenance_error_first_when_multiple_fail() {
        let mut fixture = build_fixture();
        // Break the profile AND mutate an event.
        fixture.profile.log_blowup += 1;
        if let ByteTranscriptEvent::Observed(bytes) = &mut fixture.events[0] {
            bytes[0] ^= 0xFF;
        }
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &fixture.record,
            &fixture.manifest,
            &fixture.events,
        );
        let err = harness.verify().unwrap_err();
        assert!(
            matches!(err, HarnessError::Provenance(_)),
            "provenance must win when multiple fail, got {err:?}"
        );
    }

    // ── Individual invariant accessors ───────────────────────────────────────

    #[test]
    fn individual_verifiers_can_be_called_independently() {
        let fixture = build_fixture();
        let harness = Plonky3ReplayHarness::new(
            &fixture.profile,
            &fixture.record,
            &fixture.manifest,
            &fixture.events,
        );
        harness.verify_provenance().expect("provenance");
        harness.verify_manifest().expect("manifest");
        harness.verify_byte_equivalence().expect("replay");
    }

    // ── Error display ────────────────────────────────────────────────────────

    #[test]
    fn harness_error_display_identifies_invariant() {
        let prov = HarnessError::Provenance(BackendDriftError::NonHidingInputMmcs);
        assert!(prov.to_string().starts_with("[provenance]"));

        let manifest = HarnessError::Manifest(TranscriptBindingError::MissingBinding {
            domain_label: "TEST".to_string(),
        });
        assert!(manifest.to_string().starts_with("[manifest]"));

        let replay = HarnessError::Replay(ReplayMismatch {
            event_index: 0,
            byte_index: 0,
            expected: 0xAA,
            actual: 0xBB,
        });
        assert!(replay.to_string().starts_with("[replay]"));
    }
}
