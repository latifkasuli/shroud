#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Toy transcript/model layer for concrete SHROUD objects and adapter mappings.

use core::fmt;

use shroud_adapter::{
    BatchOpeningAdapter, BatchOpeningAdapterPlan, CodewordEmbeddingAdapter,
    CodewordEmbeddingAdapterPlan, OpeningProjectionAdapter, OpeningProjectionAdapterPlan,
    OracleCommitmentAdapter, OracleCommitmentAdapterPlan, QuotientHiderAdapter,
    QuotientHiderAdapterPlan, proof_slot_layout,
};
use shroud_batch_opening::{
    BatchOpeningShape, HiddenOpeningTransport, PerfectHiddenOpeningPayload,
    PerfectRandomizerAdapter, PerfectRandomizerAdapterSurface, PerfectRandomizerBackend,
    PerfectRandomizerCommitment, PerfectRandomizerOpening, PerfectRandomizerRealization,
    PerfectRandomizerReconstruction, PerfectRandomizerTranscript, PreparedPerfectRandomizer,
    ProofSlotLayout, RandomizerOpeningPayload, ShroudBatchOpeningSpec,
};
use shroud_codeword_embedding::ShroudCodewordEmbeddingSpec;
use shroud_core::{
    AuxiliaryTransport, BasisDescriptor, CanonicalBatchOpeningManifest, DOMAIN_PROFILE,
    DOMAIN_RANDOMIZER_COMMITMENT, HashIdentifier, HidingTechniqueClaim, SampledChallenge,
    TranscriptBindable, TranscriptBinding, TranscriptBindingError, TranscriptBindingManifest,
    TranscriptBindingSource, TranscriptChallengeDeriver, TranscriptStage,
    transcript_stage_discriminant,
};
use shroud_opening_projection::{AuxiliaryOpeningTransport, ShroudOpeningProjectionSpec};
use shroud_oracle_commitment::{OracleAuxiliaryTransport, ShroudOracleCommitmentSpec};
use shroud_quotient_hider::{QuotientAuxiliaryTransport, ShroudQuotientHiderSpec};

/// Reference transcript state machine for the SHROUD batch-opening schedule.
#[derive(Debug)]
pub struct ReferenceTranscript<'a> {
    spec: &'a ShroudBatchOpeningSpec,
    cursor: usize,
    record: ReferenceBindingRecord,
    manifest: TranscriptBindingManifest,
    challenges: Vec<ReferenceSampledChallenge>,
}

impl<'a> ReferenceTranscript<'a> {
    /// Creates a transcript at the first stage of the supplied spec.
    ///
    /// `manifest` declares the exact [`TranscriptBinding`] values that must be
    /// present in the record before each sampling stage may be entered. Pass
    /// [`TranscriptBindingManifest::new`] when no exact-byte enforcement is needed
    /// (e.g. pure stage-ordering tests). Pass a manifest built from concrete
    /// spec objects to enforce Fiat-Shamir binding correctness.
    #[must_use]
    pub fn new(spec: &'a ShroudBatchOpeningSpec, manifest: TranscriptBindingManifest) -> Self {
        Self {
            spec,
            cursor: 0,
            record: ReferenceBindingRecord::new(),
            manifest,
            challenges: Vec::new(),
        }
    }

    /// Returns the next stage expected by the transcript, if any.
    #[must_use]
    pub fn expected_stage(&self) -> Option<TranscriptStage> {
        self.spec
            .transcript_plan()
            .stages()
            .get(self.cursor)
            .copied()
    }

    /// Returns a reference to the binding record for inspection.
    #[must_use]
    pub fn record(&self) -> &ReferenceBindingRecord {
        &self.record
    }

    /// Returns a mutable reference to the binding record for absorbing bindings.
    pub fn record_mut(&mut self) -> &mut ReferenceBindingRecord {
        &mut self.record
    }

    /// Advances the transcript by one stage.
    pub fn advance(&mut self, stage: TranscriptStage) -> Result<(), ReferenceTranscriptError> {
        match self.expected_stage() {
            Some(expected) if expected == stage => {
                // Binding check fires only when the stage is correct
                if let Err(e) = self
                    .record
                    .assert_exact_present(self.manifest.required_before(stage))
                {
                    let domain_label = match e {
                        TranscriptBindingError::MissingBinding { domain_label }
                        | TranscriptBindingError::BindingMismatch { domain_label }
                        | TranscriptBindingError::PlaceholderBinding { domain_label }
                        | TranscriptBindingError::BindingSourceMismatch { domain_label, .. } => {
                            domain_label
                        }
                    };
                    return Err(ReferenceTranscriptError::MissingBindingBeforeStage {
                        stage,
                        domain_label,
                    });
                }
                self.cursor += 1;
                Ok(())
            }
            Some(expected) => Err(ReferenceTranscriptError::UnexpectedStage {
                expected,
                observed: stage,
            }),
            None => Err(ReferenceTranscriptError::AlreadyComplete),
        }
    }

    /// Samples and records a Fiat-Shamir challenge at the current sampling stage.
    pub fn sample_challenge<D: TranscriptChallengeDeriver>(
        &mut self,
        stage: TranscriptStage,
        deriver: &D,
    ) -> Result<SampledChallenge, ReferenceTranscriptError> {
        self.advance(stage)?;
        let absorbed_len = self.record.absorbed().len();
        let challenge = deriver.derive_challenge(self.record.absorbed(), stage);
        self.challenges.push(ReferenceSampledChallenge {
            challenge: challenge.clone(),
            absorbed_len,
        });
        Ok(challenge)
    }

    /// Replays every sampled challenge against the absorbed binding prefix used
    /// when it was sampled.
    pub fn replay_challenges<D: TranscriptChallengeDeriver>(
        &self,
        deriver: &D,
    ) -> Result<(), ReferenceTranscriptError> {
        for recorded in &self.challenges {
            let expected = deriver.derive_challenge(
                &self.record.absorbed()[..recorded.absorbed_len],
                recorded.challenge.stage(),
            );
            if expected != recorded.challenge {
                return Err(ReferenceTranscriptError::ChallengeReplayMismatch {
                    stage: recorded.challenge.stage(),
                });
            }
        }
        Ok(())
    }

    /// Consumes the transcript, verifies completion, validates the manifest, and
    /// replays all sampled challenges.
    pub fn finish<D: TranscriptChallengeDeriver>(
        self,
        deriver: &D,
    ) -> Result<ReferenceBindingRecord, ReferenceTranscriptError> {
        if self.cursor != self.spec.transcript_plan().stages().len() {
            return Err(ReferenceTranscriptError::IncompleteTranscript {
                next_stage: self.expected_stage(),
            });
        }
        self.record
            .finalize(&self.manifest)
            .map_err(ReferenceTranscriptError::BindingFinalization)?;
        self.replay_challenges(deriver)?;
        self.require_logged_sampling_challenges()?;
        Ok(self.record)
    }

    fn require_logged_sampling_challenges(&self) -> Result<(), ReferenceTranscriptError> {
        for stage in [
            TranscriptStage::SampleBatchingChallenge,
            TranscriptStage::SampleOodPoint,
        ] {
            if !self
                .challenges
                .iter()
                .any(|recorded| recorded.challenge.stage() == stage)
            {
                return Err(ReferenceTranscriptError::MissingSampledChallenge { stage });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceSampledChallenge {
    challenge: SampledChallenge,
    absorbed_len: usize,
}

/// Deterministic reference challenge deriver for replay tests.
///
/// This is not a cryptographic hash. A real backend bridge must implement
/// [`TranscriptChallengeDeriver`] using its production Fiat-Shamir transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceChallengeDeriver {
    hash_identifier: HashIdentifier,
}

impl ReferenceChallengeDeriver {
    /// Creates a reference challenge deriver from a hash-suite identifier.
    #[must_use]
    pub fn new(hash_identifier: HashIdentifier) -> Self {
        Self { hash_identifier }
    }
}

impl TranscriptChallengeDeriver for ReferenceChallengeDeriver {
    fn hash_identifier(&self) -> HashIdentifier {
        self.hash_identifier.clone()
    }

    fn derive_challenge(
        &self,
        absorbed_prefix: &[TranscriptBinding],
        stage: TranscriptStage,
    ) -> SampledChallenge {
        let mut bytes = self
            .hash_identifier
            .to_transcript_binding()
            .canonical_bytes()
            .to_vec();
        bytes.push(transcript_stage_discriminant(stage));
        bytes.extend_from_slice(&(absorbed_prefix.len() as u32).to_le_bytes());
        for binding in absorbed_prefix {
            bytes.extend_from_slice(&(binding.domain_label().len() as u32).to_le_bytes());
            bytes.extend_from_slice(binding.domain_label().as_bytes());
            bytes.extend_from_slice(&(binding.canonical_bytes().len() as u32).to_le_bytes());
            bytes.extend_from_slice(binding.canonical_bytes());
        }
        SampledChallenge::new(stage, bytes)
    }
}

/// Error raised when the reference transcript violates the planned stage order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceTranscriptError {
    /// The transcript observed a stage other than the one required next.
    UnexpectedStage {
        /// Stage required by the plan.
        expected: TranscriptStage,
        /// Stage supplied by the caller.
        observed: TranscriptStage,
    },
    /// The transcript was advanced after it had already consumed every stage.
    AlreadyComplete,
    /// A required binding was absent when a sampling stage was reached.
    MissingBindingBeforeStage {
        /// The sampling stage that required the binding.
        stage: TranscriptStage,
        /// The domain label that was absent.
        domain_label: String,
    },
    /// The transcript was finished before every planned stage was consumed.
    IncompleteTranscript {
        /// Next stage expected by the transcript.
        next_stage: Option<TranscriptStage>,
    },
    /// End-of-transcript binding validation failed.
    BindingFinalization(TranscriptBindingError),
    /// A sampled challenge did not replay to the same bytes.
    ChallengeReplayMismatch {
        /// Stage whose challenge failed replay.
        stage: TranscriptStage,
    },
    /// A sampling stage was advanced without recording the sampled challenge.
    MissingSampledChallenge {
        /// Sampling stage with no recorded challenge.
        stage: TranscriptStage,
    },
}

impl fmt::Display for ReferenceTranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedStage { expected, observed } => {
                write!(
                    f,
                    "expected transcript stage {expected}, observed {observed}"
                )
            }
            Self::AlreadyComplete => write!(f, "transcript is already complete"),
            Self::MissingBindingBeforeStage {
                stage,
                domain_label,
            } => write!(
                f,
                "binding {domain_label:?} was not absorbed before reaching stage {stage}; \
                 absorb it during the preceding observe stage to satisfy the Fiat-Shamir requirement"
            ),
            Self::IncompleteTranscript { next_stage } => write!(
                f,
                "cannot finish transcript before all stages are consumed; next stage is {next_stage:?}"
            ),
            Self::BindingFinalization(err) => err.fmt(f),
            Self::ChallengeReplayMismatch { stage } => {
                write!(
                    f,
                    "sampled challenge at stage {stage} failed verifier replay"
                )
            }
            Self::MissingSampledChallenge { stage } => {
                write!(
                    f,
                    "sampling stage {stage} advanced without recording a challenge"
                )
            }
        }
    }
}

impl std::error::Error for ReferenceTranscriptError {}

/// Records transcript binding events and enforces that all required bindings
/// were absorbed before a challenge is sampled.
///
/// This is the SHROUD reference answer to the Fiat-Shamir completeness check.
/// It does not replace the cryptographic hash — it tracks *which protocol
/// parameters* were absorbed and fails loudly if any required binding is absent,
/// catching the class of vulnerabilities described by incomplete transcript binding.
///
/// # Usage
///
/// ```rust
/// # use shroud_reference::ReferenceBindingRecord;
/// # use shroud_core::{SecurityLevel, TranscriptBindable};
/// let mut record = ReferenceBindingRecord::new();
/// record.absorb_bindable(&SecurityLevel::Statistical);
/// // … absorb remaining required bindings …
/// ```
#[derive(Debug, Default)]
pub struct ReferenceBindingRecord {
    absorbed: Vec<TranscriptBinding>,
    sources: Vec<TranscriptBindingSource>,
}

impl ReferenceBindingRecord {
    /// Creates an empty binding record.
    #[must_use]
    pub fn new() -> Self {
        Self {
            absorbed: Vec::new(),
            sources: Vec::new(),
        }
    }

    /// Absorbs a raw transcript binding into the record as declared data.
    pub fn absorb(&mut self, binding: TranscriptBinding) {
        self.absorb_with_source(binding, TranscriptBindingSource::Declared);
    }

    /// Absorbs a raw transcript binding with explicit provenance.
    pub fn absorb_with_source(
        &mut self,
        binding: TranscriptBinding,
        source: TranscriptBindingSource,
    ) {
        self.absorbed.push(binding);
        self.sources.push(source);
    }

    /// Absorbs a binding derived from a live backend transcript event.
    pub fn absorb_live(&mut self, binding: TranscriptBinding) {
        self.absorb_with_source(binding, TranscriptBindingSource::Live);
    }

    /// Absorbs a deliberate placeholder binding.
    pub fn absorb_placeholder(&mut self, binding: TranscriptBinding) {
        self.absorb_with_source(binding, TranscriptBindingSource::Placeholder);
    }

    /// Absorbs the canonical binding for a declared [`TranscriptBindable`] protocol object.
    pub fn absorb_bindable<T: TranscriptBindable>(&mut self, value: &T) {
        self.absorb(value.to_transcript_binding());
    }

    /// Absorbs the canonical binding for a [`TranscriptBindable`] with explicit provenance.
    pub fn absorb_bindable_with_source<T: TranscriptBindable>(
        &mut self,
        value: &T,
        source: TranscriptBindingSource,
    ) {
        self.absorb_with_source(value.to_transcript_binding(), source);
    }

    /// Returns `true` if a binding with the given domain label was absorbed.
    #[must_use]
    pub fn contains_binding(&self, domain_label: &str) -> bool {
        self.absorbed
            .iter()
            .any(|b| b.domain_label() == domain_label)
    }

    /// Returns `true` if a binding with the exact domain label AND canonical bytes was absorbed.
    #[must_use]
    pub fn contains_exact_binding(&self, expected: &TranscriptBinding) -> bool {
        self.absorbed.iter().any(|b| {
            b.domain_label() == expected.domain_label()
                && b.canonical_bytes() == expected.canonical_bytes()
        })
    }

    /// Returns `true` if an exact binding was absorbed with the given provenance.
    #[must_use]
    pub fn contains_exact_binding_from_source(
        &self,
        expected: &TranscriptBinding,
        source: TranscriptBindingSource,
    ) -> bool {
        self.absorbed.iter().enumerate().any(|(index, b)| {
            b.domain_label() == expected.domain_label()
                && b.canonical_bytes() == expected.canonical_bytes()
                && self.source_at(index) == source
        })
    }

    /// Returns all absorbed bindings in absorption order.
    #[must_use]
    pub fn absorbed(&self) -> &[TranscriptBinding] {
        &self.absorbed
    }

    /// Returns the provenance source for an absorbed binding by index.
    ///
    /// Records created before source tracking, or test-only direct mutations of
    /// the internal binding vector, are treated as declared data.
    #[must_use]
    pub fn source_at(&self, index: usize) -> TranscriptBindingSource {
        self.sources
            .get(index)
            .copied()
            .unwrap_or(TranscriptBindingSource::Declared)
    }

    /// Returns absorbed bindings paired with their provenance.
    #[must_use]
    pub fn absorbed_with_sources(&self) -> Vec<(&TranscriptBinding, TranscriptBindingSource)> {
        self.absorbed
            .iter()
            .enumerate()
            .map(|(index, binding)| (binding, self.source_at(index)))
            .collect()
    }

    /// Returns `true` if any absorbed binding is marked as a placeholder.
    #[must_use]
    pub fn contains_placeholder_binding(&self) -> bool {
        self.absorbed
            .iter()
            .enumerate()
            .any(|(index, _)| self.source_at(index).is_placeholder())
    }

    /// Rejects records containing placeholder bindings.
    pub fn assert_no_placeholder_bindings(&self) -> Result<(), TranscriptBindingError> {
        for (index, binding) in self.absorbed.iter().enumerate() {
            if self.source_at(index).is_placeholder() {
                return Err(TranscriptBindingError::PlaceholderBinding {
                    domain_label: binding.domain_label().to_string(),
                });
            }
        }
        Ok(())
    }

    /// Checks that every label in `required_labels` was absorbed.
    ///
    /// Returns the first missing label as [`TranscriptBindingError::MissingBinding`].
    pub fn assert_required_present(
        &self,
        required_labels: &[&str],
    ) -> Result<(), TranscriptBindingError> {
        for &label in required_labels {
            if !self.contains_binding(label) {
                return Err(TranscriptBindingError::MissingBinding {
                    domain_label: label.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Checks that every binding in `expected` was absorbed with exact canonical bytes.
    ///
    /// Returns [`TranscriptBindingError::MissingBinding`] if no binding for the domain label
    /// was absorbed at all, or [`TranscriptBindingError::BindingMismatch`] if a binding was
    /// absorbed but its bytes differ from the expected value.
    pub fn assert_exact_present(
        &self,
        expected: &[TranscriptBinding],
    ) -> Result<(), TranscriptBindingError> {
        for binding in expected {
            if self.contains_exact_binding(binding) {
                continue;
            }
            if self.contains_binding(binding.domain_label()) {
                return Err(TranscriptBindingError::BindingMismatch {
                    domain_label: binding.domain_label().to_string(),
                });
            }
            return Err(TranscriptBindingError::MissingBinding {
                domain_label: binding.domain_label().to_string(),
            });
        }
        Ok(())
    }

    /// Checks that every binding in `expected` was absorbed with exact bytes and provenance.
    pub fn assert_exact_present_from_source(
        &self,
        expected: &[TranscriptBinding],
        source: TranscriptBindingSource,
    ) -> Result<(), TranscriptBindingError> {
        for binding in expected {
            if self.contains_exact_binding_from_source(binding, source) {
                continue;
            }
            if let Some((index, _)) = self.absorbed.iter().enumerate().find(|(_, absorbed)| {
                absorbed.domain_label() == binding.domain_label()
                    && absorbed.canonical_bytes() == binding.canonical_bytes()
            }) {
                return Err(TranscriptBindingError::BindingSourceMismatch {
                    domain_label: binding.domain_label().to_string(),
                    expected_source: source,
                    actual_source: self.source_at(index),
                });
            }
            if self.contains_binding(binding.domain_label()) {
                return Err(TranscriptBindingError::BindingMismatch {
                    domain_label: binding.domain_label().to_string(),
                });
            }
            return Err(TranscriptBindingError::MissingBinding {
                domain_label: binding.domain_label().to_string(),
            });
        }
        Ok(())
    }

    /// Verifies that every expected binding declared by the manifest was absorbed
    /// with the exact canonical bytes.
    ///
    /// Iterates over each sampling stage in the manifest and calls
    /// [`Self::assert_exact_present`] for that stage's expected bindings. Returns
    /// [`TranscriptBindingError::MissingBinding`] when a required label is absent,
    /// or [`TranscriptBindingError::BindingMismatch`] when a binding for the right
    /// label was absorbed but its canonical bytes differ from the expected value.
    ///
    /// This is the security-critical end-of-transcript validator. Use a manifest
    /// derived from the concrete SHROUD spec plus backend profile/adapter plan.
    pub fn finalize(
        &self,
        manifest: &TranscriptBindingManifest,
    ) -> Result<(), TranscriptBindingError> {
        for stage in [
            TranscriptStage::SampleBatchingChallenge,
            TranscriptStage::SampleOodPoint,
            TranscriptStage::ProveMaskedRelation,
        ] {
            self.assert_exact_present(manifest.required_before(stage))?;
        }
        Ok(())
    }

    /// Verifies the record against the reviewed canonical batch-opening manifest.
    pub fn finalize_canonical(
        &self,
        manifest: &CanonicalBatchOpeningManifest,
    ) -> Result<(), TranscriptBindingError> {
        self.finalize(manifest.as_manifest())
    }
}

impl PerfectRandomizerTranscript for ReferenceTranscript<'_> {
    type Error = ReferenceTranscriptError;

    fn observe_perfect_randomizer_commitment<Commitment: TranscriptBindable>(
        &mut self,
        commitment: &Commitment,
    ) -> Result<(), Self::Error> {
        // Validate stage BEFORE mutating the record — a failed observe must not
        // leave DOMAIN_RANDOMIZER_COMMITMENT bytes in the record, where they
        // could later satisfy a downstream sampling gate.
        match self.expected_stage() {
            Some(TranscriptStage::ObserveRandomizerCommitment) => {
                self.record.absorb_bindable(commitment);
                self.advance(TranscriptStage::ObserveRandomizerCommitment)
            }
            Some(expected) => Err(ReferenceTranscriptError::UnexpectedStage {
                expected,
                observed: TranscriptStage::ObserveRandomizerCommitment,
            }),
            None => Err(ReferenceTranscriptError::AlreadyComplete),
        }
    }
}

/// Reference commitment object for a perfect randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferencePerfectRandomizerCommitment {
    model: PerfectRandomizerCommitment,
    shape: BatchOpeningShape,
}

impl ReferencePerfectRandomizerCommitment {
    /// Returns the commitment model used by this reference commitment.
    #[must_use]
    pub const fn model(self) -> PerfectRandomizerCommitment {
        self.model
    }

    /// Returns the batch-opening shape this commitment was prepared for.
    #[must_use]
    pub const fn shape(self) -> BatchOpeningShape {
        self.shape
    }
}

/// Reference prover-side state for a perfect randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferencePerfectRandomizerState {
    shape: BatchOpeningShape,
}

impl ReferencePerfectRandomizerState {
    /// Returns the batch-opening shape retained by the prover.
    #[must_use]
    pub const fn shape(self) -> BatchOpeningShape {
        self.shape
    }
}

impl TranscriptBindable for ReferencePerfectRandomizerCommitment {
    /// Encodes the commitment model (realization discriminant + basis bytes if applicable)
    /// followed by the batch-opening shape (3 × u64 LE). Domain: `DOMAIN_RANDOMIZER_COMMITMENT`.
    fn to_transcript_binding(&self) -> TranscriptBinding {
        let mut bytes = Vec::new();
        match self.model().realization() {
            PerfectRandomizerRealization::EncodedOracleBundle { basis } => {
                bytes.push(0u8);
                bytes.extend_from_slice(basis.to_transcript_binding().canonical_bytes());
            }
            PerfectRandomizerRealization::NativeExtensionPcs => {
                bytes.push(1u8);
            }
        }
        let shape = self.shape();
        bytes.extend_from_slice(&(shape.committed_polynomials() as u64).to_le_bytes());
        bytes.extend_from_slice(&(shape.opening_points() as u64).to_le_bytes());
        bytes.extend_from_slice(&(shape.extension_degree() as u64).to_le_bytes());
        TranscriptBinding::new(DOMAIN_RANDOMIZER_COMMITMENT, bytes)
    }
}

/// Public extension-field evaluation exposed by the reference backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferencePublicEvaluation {
    point_index: usize,
}

impl ReferencePublicEvaluation {
    /// Returns the opening-point index for this public evaluation.
    #[must_use]
    pub const fn point_index(self) -> usize {
        self.point_index
    }
}

/// Hidden opening object emitted by the reference backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceHiddenOpening {
    evaluation_count: usize,
    transport: HiddenOpeningTransport,
}

impl ReferenceHiddenOpening {
    /// Returns the number of hidden evaluations carried by the proof.
    #[must_use]
    pub const fn evaluation_count(self) -> usize {
        self.evaluation_count
    }

    /// Returns how the hidden opening is transported.
    #[must_use]
    pub const fn transport(self) -> HiddenOpeningTransport {
        self.transport
    }
}

/// Reference backend for the perfect batch-opening randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferencePerfectRandomizerBackend {
    model: PerfectRandomizerCommitment,
}

impl ReferencePerfectRandomizerBackend {
    /// Builds the SHROUD v1 preferred backend model using an encoded oracle bundle.
    ///
    /// Uses the supplied basis descriptor. For the standard Plonky3
    /// `BinomialExtensionField` convention, pass
    /// `BasisDescriptor::plonky3_binomial(extension_degree)`.
    #[must_use]
    pub const fn encoded_oracle_bundle(basis: BasisDescriptor) -> Self {
        Self {
            model: PerfectRandomizerCommitment::encoded_oracle_bundle(basis),
        }
    }

    /// Builds the native extension-field PCS backend model.
    #[must_use]
    pub const fn native_extension_pcs() -> Self {
        Self {
            model: PerfectRandomizerCommitment::native_extension_pcs(),
        }
    }
}

/// Error raised by the reference perfect-randomizer backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePerfectRandomizerError {
    /// The supplied batch-opening spec is not a perfect variant.
    ExpectedPerfectVariant,
    /// The backend model does not match the one requested by the spec.
    CommitmentModelMismatch {
        /// Model expected by the backend or spec.
        expected: PerfectRandomizerCommitment,
        /// Model actually supplied.
        observed: PerfectRandomizerCommitment,
    },
    /// The opening exposed the wrong number of public evaluations.
    PublicEvaluationCountMismatch {
        /// Number expected by the payload model.
        expected: usize,
        /// Number present in the opening.
        observed: usize,
    },
    /// The hidden opening payload does not match the spec.
    HiddenOpeningMismatch {
        /// Number of hidden evaluations expected.
        expected_evaluations: usize,
        /// Number actually provided.
        observed_evaluations: usize,
        /// Transport expected by the payload model.
        expected_transport: HiddenOpeningTransport,
        /// Transport actually supplied.
        observed_transport: HiddenOpeningTransport,
    },
}

impl fmt::Display for ReferencePerfectRandomizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedPerfectVariant => write!(
                f,
                "perfect randomizer backend requires a perfect batch-opening spec"
            ),
            Self::CommitmentModelMismatch { expected, observed } => write!(
                f,
                "perfect randomizer commitment model mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::PublicEvaluationCountMismatch { expected, observed } => write!(
                f,
                "public evaluation count mismatch: expected {expected}, observed {observed}"
            ),
            Self::HiddenOpeningMismatch {
                expected_evaluations,
                observed_evaluations,
                expected_transport,
                observed_transport,
            } => write!(
                f,
                "hidden opening mismatch: expected {expected_evaluations} evaluations over {expected_transport:?}, observed {observed_evaluations} evaluations over {observed_transport:?}"
            ),
        }
    }
}

impl std::error::Error for ReferencePerfectRandomizerError {}

/// Plonky3-like commitment slots for the perfect-randomizer adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3CommitmentSlot {
    /// Reuse the existing `random: Option<Com>` slot.
    RandomOptionField,
    /// Introduce a dedicated top-level commitment slot for the perfect randomizer.
    DedicatedPerfectRandomizerField,
}

/// Adapter that maps the perfect-randomizer object onto a Plonky3-like proof shape.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReferencePlonky3Adapter;

/// Plonky3-like slot carrying the public opening view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3PublicOpeningSlot {
    /// Reuse the outer `opened_values` field.
    OpenedValuesField,
}

/// Plonky3-like slot carrying hidden auxiliary opening material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3HiddenAuxiliarySlot {
    /// Keep hidden auxiliaries inside the internal FRI opening proof object.
    FriOpeningProofInternals,
    /// Carry hidden auxiliaries in a dedicated outer field.
    DedicatedProjectionField,
}

/// Plonky3-like slot carrying a hidden oracle commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3OracleCommitmentSlot {
    /// Reuse the outer field that stores committed oracle objects.
    OracleCommitmentField,
}

/// Plonky3-like slot carrying public MMCS opening material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3OracleOpeningSlot {
    /// Reuse the internal MMCS opening proof object.
    MmcsOpeningProof,
}

/// Plonky3-like slot carrying hidden oracle witness material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3OracleHiddenAuxiliarySlot {
    /// Keep hidden row-hiding witnesses inside the internal MMCS proof object.
    HidingMmcsInternals,
    /// Carry hidden row-hiding witnesses in a dedicated outer field.
    DedicatedOracleWitnessField,
}

/// Plonky3-like slot carrying a hidden quotient commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3QuotientCommitmentSlot {
    /// Reuse the outer field that stores quotient commitments.
    QuotientCommitmentField,
}

/// Plonky3-like slot carrying public quotient opening material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3QuotientOpeningSlot {
    /// Reuse the outer field that stores opened quotient values.
    OpenedQuotientValuesField,
}

/// Plonky3-like slot carrying hidden quotient witness material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3QuotientHiddenAuxiliarySlot {
    /// Keep hidden quotient auxiliaries inside the internal opening proof object.
    FriOpeningProofInternals,
    /// Carry hidden quotient auxiliaries in a dedicated outer field.
    DedicatedQuotientWitnessField,
}

/// Logical proof carriers for a backend that uses explicit proof envelopes instead of fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredCommitmentCarrier {
    /// The randomizer travels inside the main batch-opening proof object.
    SharedBatchOpeningEnvelope,
    /// The randomizer travels in an auxiliary proof envelope shared with existing hiding material.
    AuxiliaryRandomizerEnvelope,
    /// The perfect randomizer gets its own dedicated proof envelope.
    DedicatedPerfectRandomizerEnvelope,
}

/// Adapter that maps SHROUD onto a layered proof format with explicit auxiliary envelopes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReferenceLayeredAdapter;

/// Public carrier for the layered reference adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredPublicOpeningCarrier {
    /// Public openings travel in the statement-visible opening envelope.
    StatementOpeningEnvelope,
}

/// Hidden carrier for the layered reference adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredHiddenAuxiliaryCarrier {
    /// Hidden auxiliaries stay inside the main opening-proof envelope.
    MainOpeningProofEnvelope,
    /// Hidden auxiliaries travel in a separate projection envelope.
    ProjectionAuxiliaryEnvelope,
}

/// Logical commitment carriers for a layered oracle-commitment mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredOracleCommitmentCarrier {
    /// The hidden oracle commitment travels in the public oracle-commitment envelope.
    OracleCommitmentEnvelope,
}

/// Public carrier for layered oracle openings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredOracleOpeningCarrier {
    /// Public row values and authentication data travel in the oracle-opening envelope.
    OracleOpeningEnvelope,
}

/// Hidden carrier for layered oracle witness material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredOracleHiddenAuxiliaryCarrier {
    /// Hidden witnesses stay in-band with the main oracle-opening envelope.
    OracleOpeningEnvelope,
    /// Hidden witnesses move into a dedicated auxiliary oracle envelope.
    OracleAuxiliaryWitnessEnvelope,
}

/// Logical commitment carriers for a layered quotient-hider mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredQuotientCommitmentCarrier {
    /// The quotient commitment travels in the public quotient-commitment envelope.
    QuotientCommitmentEnvelope,
}

/// Public carrier for layered quotient openings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredQuotientOpeningCarrier {
    /// Public quotient openings travel in the quotient-opening envelope.
    QuotientOpeningEnvelope,
}

/// Hidden carrier for layered quotient auxiliary material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredQuotientHiddenAuxiliaryCarrier {
    /// Hidden quotient auxiliaries stay in-band with the quotient-opening envelope.
    QuotientOpeningEnvelope,
    /// Hidden quotient auxiliaries move into a dedicated auxiliary quotient envelope.
    QuotientAuxiliaryEnvelope,
}

/// Plonky3-like commitment slot for the codeword-embedding adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3CodewordCommitmentSlot {
    /// The outer PCS commitment object (carries the committed trace+randomizer matrix).
    TraceCommitment,
}

/// Plonky3-like slot carrying the public trace opening values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3CodewordPublicOpeningSlot {
    /// The outer opened-values field (public trace column evaluations at OOD points).
    OpenedTraceValues,
}

/// Plonky3-like slot carrying hidden randomizer opening material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePlonky3CodewordHiddenAuxiliarySlot {
    /// Hidden randomizer codeword openings embedded inside the FRI opening proof.
    FriProofRandomCodewordOpenings,
    /// Randomizer openings carried in a dedicated outer field (not supported by standard HidingFriPcs).
    DedicatedCodewordAuxiliaryField,
}

/// Declared configuration of a Plonky3 `HidingFriPcs` instance.
///
/// `HidingFriPcs` fields are private; callers must declare the parameters they
/// used when constructing it. The codeword-embedding adapter validates the SHROUD
/// spec against this declared profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceHidingFriPcsProfile {
    /// `log_blowup` passed to the FRI parameters.
    pub log_blowup: usize,
    /// `num_random_codewords` passed to `HidingFriPcs::new`.
    pub num_random_codewords: usize,
    /// Extension-field basis used by the challenge field.
    pub basis: BasisDescriptor,
    /// Whether the input MMCS is a hiding MMCS.
    pub input_mmcs_hiding: bool,
    /// Whether the FRI query-phase MMCS is a hiding MMCS.
    pub fri_mmcs_hiding: bool,
    /// Declared hiding techniques used by this backend configuration.
    pub hiding_technique: HidingTechniqueClaim,
}

impl ReferenceHidingFriPcsProfile {
    /// Returns the standard BabyBear/BinomialExtension(4) profile used by the reference adapter.
    ///
    /// Matches the `HidingBackend` constants in `p3-zk-proofs`:
    /// `log_blowup = 2`, `num_random_codewords = 4`, degree-4 binomial extension,
    /// both MMCS layers hiding.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            log_blowup: REFERENCE_LOG_BLOWUP,
            num_random_codewords: REFERENCE_NUM_RANDOM_CODEWORDS,
            basis: BasisDescriptor::plonky3_binomial(4),
            input_mmcs_hiding: true,
            fri_mmcs_hiding: true,
            hiding_technique: HidingTechniqueClaim::Composite(
                Box::new(HidingTechniqueClaim::Composite(
                    Box::new(HidingTechniqueClaim::RandomCodewordInterleaving),
                    Box::new(HidingTechniqueClaim::QuotientChunkRandomization),
                )),
                Box::new(HidingTechniqueClaim::RandomRowPadding),
            ),
        }
    }

    /// Validates a SHROUD codeword-embedding spec against this profile.
    ///
    /// Checks that both MMCS layers are hiding, the FRI blowup is sufficient,
    /// and the number of random codewords matches the spec's required randomizer columns.
    pub fn validate_for_spec(
        &self,
        spec: &ShroudCodewordEmbeddingSpec,
    ) -> Result<(), ReferenceCodewordEmbeddingAdapterError> {
        if !self
            .hiding_technique
            .contains(&HidingTechniqueClaim::RandomCodewordInterleaving)
        {
            return Err(
                ReferenceCodewordEmbeddingAdapterError::RandomCodewordInterleavingNotDeclared,
            );
        }

        if !self.input_mmcs_hiding || !self.fri_mmcs_hiding {
            return Err(ReferenceCodewordEmbeddingAdapterError::NonHidingMmcs);
        }

        let required_blowup = spec.payload().required_log_blowup();
        if self.log_blowup < required_blowup {
            return Err(
                ReferenceCodewordEmbeddingAdapterError::InsufficientFriBlowup {
                    required: required_blowup,
                    configured: self.log_blowup,
                },
            );
        }

        let required_randomizers = spec.payload().hidden_randomizer_columns();
        if self.num_random_codewords != required_randomizers {
            return Err(
                ReferenceCodewordEmbeddingAdapterError::RandomizerColumnMismatch {
                    required: required_randomizers,
                    configured: self.num_random_codewords,
                },
            );
        }

        let spec_extension_degree = spec.shape().extension_degree();
        if self.basis.extension_degree != spec_extension_degree {
            return Err(
                ReferenceCodewordEmbeddingAdapterError::ExtensionDegreeMismatch {
                    profile: self.basis.extension_degree,
                    spec: spec_extension_degree,
                },
            );
        }

        Ok(())
    }
}

impl TranscriptBindable for ReferenceHidingFriPcsProfile {
    /// Encodes `log_blowup`, `num_random_codewords`, and `basis.extension_degree`
    /// as u64 LE (24 bytes), followed by `input_mmcs_hiding` and `fri_mmcs_hiding`
    /// as single bytes (2 bytes), then a u32 LE length prefix followed by the
    /// canonical bytes of the hiding technique claim tree.
    fn to_transcript_binding(&self) -> TranscriptBinding {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&(self.log_blowup as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.num_random_codewords as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.basis.extension_degree as u64).to_le_bytes());
        bytes.push(self.input_mmcs_hiding as u8);
        bytes.push(self.fri_mmcs_hiding as u8);
        // Encode the hiding technique claim tree
        let technique_bytes = self.hiding_technique.to_canonical_bytes();
        bytes.extend_from_slice(&(technique_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&technique_bytes);
        TranscriptBinding::new(DOMAIN_PROFILE, bytes)
    }
}

/// Error raised by the codeword-embedding adapter for `ReferencePlonky3Adapter`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceCodewordEmbeddingAdapterError {
    /// The adapter plan fields do not match the SHROUD codeword-embedding spec.
    PlanMismatch,
    /// The commitment slot does not match the expected layout.
    CommitmentSlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3CodewordCommitmentSlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3CodewordCommitmentSlot,
    },
    /// The public opening slot does not match the expected layout.
    PublicOpeningSlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3CodewordPublicOpeningSlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3CodewordPublicOpeningSlot,
    },
    /// The hidden auxiliary slot does not match the expected layout.
    HiddenAuxiliarySlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3CodewordHiddenAuxiliarySlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3CodewordHiddenAuxiliarySlot,
    },
    /// The FRI blowup is insufficient for the required statistical hiding guarantee.
    InsufficientFriBlowup {
        /// Minimum blowup required by the SHROUD spec.
        required: usize,
        /// Blowup actually configured.
        configured: usize,
    },
    /// The number of random codewords does not match the hidden randomizer column count.
    RandomizerColumnMismatch {
        /// Number of hidden randomizer columns required by the SHROUD spec.
        required: usize,
        /// Number of random codewords actually configured.
        configured: usize,
    },
    /// The auxiliary transport is `SeparateEnvelope`, which is not supported by standard `HidingFriPcs`.
    UnsupportedAuxiliaryTransport,
    /// The profile declares a non-hiding input or FRI MMCS, which cannot provide ZK.
    NonHidingMmcs,
    /// The profile's `hiding_technique` does not declare `RandomCodewordInterleaving`.
    ///
    /// Codeword embedding requires random codewords to be interleaved with the witness
    /// matrix. A profile that does not declare this technique cannot validate a
    /// codeword-embedding spec.
    RandomCodewordInterleavingNotDeclared,
    /// The profile's basis extension degree does not match the spec's extension degree.
    ///
    /// `BasisDescriptor::extension_degree` is the audit surface for coordinate reconstruction.
    /// A mismatch means the declared profile and the SHROUD spec describe incompatible
    /// challenge field configurations.
    ExtensionDegreeMismatch {
        /// Extension degree declared in the profile.
        profile: usize,
        /// Extension degree required by the SHROUD spec.
        spec: usize,
    },
}

impl fmt::Display for ReferenceCodewordEmbeddingAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanMismatch => write!(
                f,
                "codeword-embedding adapter plan does not match the SHROUD spec"
            ),
            Self::CommitmentSlotMismatch { expected, observed } => write!(
                f,
                "codeword commitment slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::PublicOpeningSlotMismatch { expected, observed } => write!(
                f,
                "codeword public opening slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::HiddenAuxiliarySlotMismatch { expected, observed } => write!(
                f,
                "codeword hidden auxiliary slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::InsufficientFriBlowup {
                required,
                configured,
            } => write!(
                f,
                "FRI blowup {configured} is below the required minimum {required} for statistical hiding"
            ),
            Self::RandomizerColumnMismatch {
                required,
                configured,
            } => write!(
                f,
                "randomizer column mismatch: SHROUD spec requires {required}, HidingFriPcs configured with {configured}"
            ),
            Self::UnsupportedAuxiliaryTransport => write!(
                f,
                "SeparateEnvelope auxiliary transport is not supported by standard HidingFriPcs; \
                 use InBand transport for the reference Plonky3 adapter"
            ),
            Self::NonHidingMmcs => write!(
                f,
                "profile declares a non-hiding MMCS; both input_mmcs_hiding and fri_mmcs_hiding \
                 must be true to provide zero-knowledge"
            ),
            Self::RandomCodewordInterleavingNotDeclared => write!(
                f,
                "profile hiding_technique does not declare RandomCodewordInterleaving; \
                 codeword embedding requires random codewords interleaved with the witness matrix"
            ),
            Self::ExtensionDegreeMismatch { profile, spec } => write!(
                f,
                "extension degree mismatch: profile declares degree {profile}, \
                 spec requires degree {spec}; basis extension degree is the audit surface \
                 for challenge-field coordinate reconstruction"
            ),
        }
    }
}

impl std::error::Error for ReferenceCodewordEmbeddingAdapterError {}

/// Error raised by the reference adapter surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceAdapterError {
    /// The supplied batch-opening spec is not a perfect variant.
    ExpectedPerfectVariant,
    /// The supplied outer proof-layout plan does not match the SHROUD spec.
    PlanMismatch,
    /// The provided commitment slot does not match the layout implied by the spec.
    CommitmentSlotMismatch {
        /// Slot required by the adapter surface.
        expected: ReferencePlonky3CommitmentSlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3CommitmentSlot,
    },
}

impl fmt::Display for ReferenceAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedPerfectVariant => {
                write!(f, "adapter requires a perfect batch-opening spec")
            }
            Self::PlanMismatch => write!(f, "adapter plan does not match the SHROUD spec"),
            Self::CommitmentSlotMismatch { expected, observed } => write!(
                f,
                "adapter commitment slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
        }
    }
}

impl std::error::Error for ReferenceAdapterError {}

/// Error raised by the Plonky3-like opening-projection adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceProjectionAdapterError {
    /// The supplied outer proof-layout plan does not match the SHROUD projection spec.
    PlanMismatch,
    /// The public opening slot does not match the expected outer layout.
    PublicOpeningSlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3PublicOpeningSlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3PublicOpeningSlot,
    },
    /// The hidden auxiliary slot does not match the expected outer layout.
    HiddenAuxiliarySlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3HiddenAuxiliarySlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3HiddenAuxiliarySlot,
    },
}

impl fmt::Display for ReferenceProjectionAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanMismatch => {
                write!(
                    f,
                    "opening-projection adapter plan does not match the SHROUD spec"
                )
            }
            Self::PublicOpeningSlotMismatch { expected, observed } => write!(
                f,
                "public opening slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::HiddenAuxiliarySlotMismatch { expected, observed } => write!(
                f,
                "hidden auxiliary slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
        }
    }
}

impl std::error::Error for ReferenceProjectionAdapterError {}

/// Error raised by the Plonky3-like oracle-commitment adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceOracleCommitmentAdapterError {
    /// The supplied outer proof-layout plan does not match the SHROUD oracle-commitment spec.
    PlanMismatch,
    /// The public commitment slot does not match the expected outer layout.
    CommitmentSlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3OracleCommitmentSlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3OracleCommitmentSlot,
    },
    /// The public opening slot does not match the expected outer layout.
    PublicOpeningSlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3OracleOpeningSlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3OracleOpeningSlot,
    },
    /// The hidden auxiliary slot does not match the expected outer layout.
    HiddenAuxiliarySlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3OracleHiddenAuxiliarySlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3OracleHiddenAuxiliarySlot,
    },
}

impl fmt::Display for ReferenceOracleCommitmentAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanMismatch => write!(
                f,
                "oracle-commitment adapter plan does not match the SHROUD spec"
            ),
            Self::CommitmentSlotMismatch { expected, observed } => write!(
                f,
                "oracle commitment slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::PublicOpeningSlotMismatch { expected, observed } => write!(
                f,
                "oracle public opening slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::HiddenAuxiliarySlotMismatch { expected, observed } => write!(
                f,
                "oracle hidden auxiliary slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
        }
    }
}

impl std::error::Error for ReferenceOracleCommitmentAdapterError {}

/// Error raised by the Plonky3-like quotient-hider adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceQuotientHiderAdapterError {
    /// The supplied outer proof-layout plan does not match the SHROUD quotient-hider spec.
    PlanMismatch,
    /// The public commitment slot does not match the expected outer layout.
    CommitmentSlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3QuotientCommitmentSlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3QuotientCommitmentSlot,
    },
    /// The public opening slot does not match the expected outer layout.
    PublicOpeningSlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3QuotientOpeningSlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3QuotientOpeningSlot,
    },
    /// The hidden auxiliary slot does not match the expected outer layout.
    HiddenAuxiliarySlotMismatch {
        /// Slot required by the adapter.
        expected: ReferencePlonky3QuotientHiddenAuxiliarySlot,
        /// Slot actually supplied.
        observed: ReferencePlonky3QuotientHiddenAuxiliarySlot,
    },
    /// The degree contract does not satisfy the Haböck-Kindi quotient degree relation required
    /// by `HidingFriPcs`: for chunk degree `h - 1`, the coset vanishing polynomial has degree
    /// `h`, the mask polynomial has degree `h - 1`, and the committed bound is `2h - 1`.
    ///
    /// Required: `vanishing_poly_degree == quotient_chunk_degree + 1`,
    /// `mask_poly_degree == quotient_chunk_degree`, and
    /// `randomized_chunk_degree_bound == quotient_chunk_degree + vanishing_poly_degree`.
    HKDegreeRelationViolation {
        /// Declared original chunk degree (`h - 1`).
        quotient_chunk_degree: usize,
        /// Declared vanishing polynomial degree; expected `quotient_chunk_degree + 1`.
        vanishing_poly_degree: usize,
        /// Declared mask polynomial degree; expected `quotient_chunk_degree`.
        mask_poly_degree: usize,
        /// Declared committed degree bound; expected `quotient_chunk_degree + vanishing_poly_degree`.
        randomized_chunk_degree_bound: usize,
    },
}

impl fmt::Display for ReferenceQuotientHiderAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanMismatch => write!(
                f,
                "quotient-hider adapter plan does not match the SHROUD spec"
            ),
            Self::CommitmentSlotMismatch { expected, observed } => write!(
                f,
                "quotient commitment slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::PublicOpeningSlotMismatch { expected, observed } => write!(
                f,
                "quotient public opening slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::HiddenAuxiliarySlotMismatch { expected, observed } => write!(
                f,
                "quotient hidden auxiliary slot mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::HKDegreeRelationViolation {
                quotient_chunk_degree,
                vanishing_poly_degree,
                mask_poly_degree,
                randomized_chunk_degree_bound,
            } => {
                let expected_vanishing = quotient_chunk_degree + 1;
                let expected_mask = quotient_chunk_degree;
                let expected_bound = quotient_chunk_degree + expected_vanishing;
                write!(
                    f,
                    "HidingFriPcs requires Haböck-Kindi quotient degree relation: \
                     vanishing_poly_degree = quotient_chunk_degree + 1 = {expected_vanishing}, \
                     mask_poly_degree = quotient_chunk_degree = {expected_mask}, \
                     randomized_chunk_degree_bound = quotient_chunk_degree + vanishing_poly_degree \
                     = {expected_bound}; \
                     got vanishing_poly_degree = {vanishing_poly_degree}, \
                     mask_poly_degree = {mask_poly_degree}, \
                     randomized_chunk_degree_bound = {randomized_chunk_degree_bound}"
                )
            }
        }
    }
}

impl std::error::Error for ReferenceQuotientHiderAdapterError {}

/// Error raised by the layered reference adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredAdapterError {
    /// The supplied outer proof-layout plan does not match the SHROUD spec.
    PlanMismatch,
    /// The provided proof carrier does not match the layout implied by the spec.
    CommitmentCarrierMismatch {
        /// Carrier required by the adapter surface.
        expected: ReferenceLayeredCommitmentCarrier,
        /// Carrier actually supplied.
        observed: ReferenceLayeredCommitmentCarrier,
    },
}

impl fmt::Display for ReferenceLayeredAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanMismatch => write!(f, "layered adapter plan does not match the SHROUD spec"),
            Self::CommitmentCarrierMismatch { expected, observed } => write!(
                f,
                "layered adapter carrier mismatch: expected {expected:?}, observed {observed:?}"
            ),
        }
    }
}

impl std::error::Error for ReferenceLayeredAdapterError {}

fn layered_carrier_for_plan(
    commitment_boundary: shroud_batch_opening::CommitmentBoundary,
    proof_slot_layout: ProofSlotLayout,
) -> ReferenceLayeredCommitmentCarrier {
    match (commitment_boundary, proof_slot_layout) {
        (shroud_batch_opening::CommitmentBoundary::SharedPcsHook, _) => {
            ReferenceLayeredCommitmentCarrier::SharedBatchOpeningEnvelope
        }
        (
            shroud_batch_opening::CommitmentBoundary::DedicatedAuxiliaryPath,
            ProofSlotLayout::ReuseCurrentRandomSlot,
        ) => ReferenceLayeredCommitmentCarrier::AuxiliaryRandomizerEnvelope,
        (
            shroud_batch_opening::CommitmentBoundary::DedicatedAuxiliaryPath,
            ProofSlotLayout::DedicatedPerfectRandomizerSlot,
        ) => ReferenceLayeredCommitmentCarrier::DedicatedPerfectRandomizerEnvelope,
    }
}

impl BatchOpeningAdapter for ReferenceLayeredAdapter {
    type CommitmentSlot = ReferenceLayeredCommitmentCarrier;
    type Error = ReferenceLayeredAdapterError;

    fn plan(
        &self,
        spec: &ShroudBatchOpeningSpec,
    ) -> Result<BatchOpeningAdapterPlan<Self::CommitmentSlot>, Self::Error> {
        Ok(BatchOpeningAdapterPlan::new(
            spec.security_level(),
            spec.commitment_boundary(),
            layered_carrier_for_plan(
                spec.commitment_boundary(),
                proof_slot_layout(spec.randomizer_opening_payload()),
            ),
            spec.randomizer_opening_payload(),
            2,
        ))
    }

    fn validate(
        &self,
        spec: &ShroudBatchOpeningSpec,
        plan: &BatchOpeningAdapterPlan<Self::CommitmentSlot>,
    ) -> Result<(), Self::Error> {
        let expected_carrier =
            layered_carrier_for_plan(plan.commitment_boundary(), plan.proof_slot_layout());

        if *plan.commitment_slot() != expected_carrier {
            return Err(ReferenceLayeredAdapterError::CommitmentCarrierMismatch {
                expected: expected_carrier,
                observed: *plan.commitment_slot(),
            });
        }

        if plan.security_level() != spec.security_level()
            || plan.commitment_boundary() != spec.commitment_boundary()
            || plan.opening_payload() != spec.randomizer_opening_payload()
        {
            return Err(ReferenceLayeredAdapterError::PlanMismatch);
        }

        Ok(())
    }
}

impl OpeningProjectionAdapter for ReferencePlonky3Adapter {
    type PublicOpeningSlot = ReferencePlonky3PublicOpeningSlot;
    type HiddenAuxiliarySlot = ReferencePlonky3HiddenAuxiliarySlot;
    type Error = ReferenceProjectionAdapterError;

    fn plan(
        &self,
        spec: &ShroudOpeningProjectionSpec,
    ) -> Result<
        OpeningProjectionAdapterPlan<Self::PublicOpeningSlot, Self::HiddenAuxiliarySlot>,
        Self::Error,
    > {
        let hidden_auxiliary_slot = match spec.auxiliary_transport() {
            AuxiliaryOpeningTransport::InBandWithMainProof => {
                ReferencePlonky3HiddenAuxiliarySlot::FriOpeningProofInternals
            }
            AuxiliaryOpeningTransport::SeparateAuxiliaryProof => {
                ReferencePlonky3HiddenAuxiliarySlot::DedicatedProjectionField
            }
        };

        Ok(OpeningProjectionAdapterPlan::new(
            spec.security_level(),
            ReferencePlonky3PublicOpeningSlot::OpenedValuesField,
            hidden_auxiliary_slot,
            spec.payload(),
        ))
    }

    fn validate(
        &self,
        spec: &ShroudOpeningProjectionSpec,
        plan: &OpeningProjectionAdapterPlan<Self::PublicOpeningSlot, Self::HiddenAuxiliarySlot>,
    ) -> Result<(), Self::Error> {
        if *plan.public_opening_slot() != ReferencePlonky3PublicOpeningSlot::OpenedValuesField {
            return Err(ReferenceProjectionAdapterError::PublicOpeningSlotMismatch {
                expected: ReferencePlonky3PublicOpeningSlot::OpenedValuesField,
                observed: *plan.public_opening_slot(),
            });
        }

        let expected_hidden_slot = match plan.payload().auxiliary_transport() {
            AuxiliaryOpeningTransport::InBandWithMainProof => {
                ReferencePlonky3HiddenAuxiliarySlot::FriOpeningProofInternals
            }
            AuxiliaryOpeningTransport::SeparateAuxiliaryProof => {
                ReferencePlonky3HiddenAuxiliarySlot::DedicatedProjectionField
            }
        };

        if *plan.hidden_auxiliary_slot() != expected_hidden_slot {
            return Err(
                ReferenceProjectionAdapterError::HiddenAuxiliarySlotMismatch {
                    expected: expected_hidden_slot,
                    observed: *plan.hidden_auxiliary_slot(),
                },
            );
        }

        if plan.security_level() != spec.security_level() || plan.payload() != spec.payload() {
            return Err(ReferenceProjectionAdapterError::PlanMismatch);
        }

        Ok(())
    }
}

/// Error raised by the layered opening-projection adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredProjectionAdapterError {
    /// The supplied outer proof-layout plan does not match the SHROUD projection spec.
    PlanMismatch,
    /// The public opening carrier does not match the expected layered layout.
    PublicCarrierMismatch {
        /// Carrier required by the adapter.
        expected: ReferenceLayeredPublicOpeningCarrier,
        /// Carrier actually supplied.
        observed: ReferenceLayeredPublicOpeningCarrier,
    },
    /// The hidden auxiliary carrier does not match the expected layered layout.
    HiddenCarrierMismatch {
        /// Carrier required by the adapter.
        expected: ReferenceLayeredHiddenAuxiliaryCarrier,
        /// Carrier actually supplied.
        observed: ReferenceLayeredHiddenAuxiliaryCarrier,
    },
}

impl fmt::Display for ReferenceLayeredProjectionAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanMismatch => write!(
                f,
                "layered opening-projection adapter plan does not match the SHROUD spec"
            ),
            Self::PublicCarrierMismatch { expected, observed } => write!(
                f,
                "layered public opening carrier mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::HiddenCarrierMismatch { expected, observed } => write!(
                f,
                "layered hidden auxiliary carrier mismatch: expected {expected:?}, observed {observed:?}"
            ),
        }
    }
}

impl std::error::Error for ReferenceLayeredProjectionAdapterError {}

/// Error raised by the layered oracle-commitment adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredOracleCommitmentAdapterError {
    /// The supplied outer proof-layout plan does not match the SHROUD oracle-commitment spec.
    PlanMismatch,
    /// The commitment carrier does not match the expected layered layout.
    CommitmentCarrierMismatch {
        /// Carrier required by the adapter.
        expected: ReferenceLayeredOracleCommitmentCarrier,
        /// Carrier actually supplied.
        observed: ReferenceLayeredOracleCommitmentCarrier,
    },
    /// The public opening carrier does not match the expected layered layout.
    PublicCarrierMismatch {
        /// Carrier required by the adapter.
        expected: ReferenceLayeredOracleOpeningCarrier,
        /// Carrier actually supplied.
        observed: ReferenceLayeredOracleOpeningCarrier,
    },
    /// The hidden auxiliary carrier does not match the expected layered layout.
    HiddenCarrierMismatch {
        /// Carrier required by the adapter.
        expected: ReferenceLayeredOracleHiddenAuxiliaryCarrier,
        /// Carrier actually supplied.
        observed: ReferenceLayeredOracleHiddenAuxiliaryCarrier,
    },
}

impl fmt::Display for ReferenceLayeredOracleCommitmentAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanMismatch => write!(
                f,
                "layered oracle-commitment adapter plan does not match the SHROUD spec"
            ),
            Self::CommitmentCarrierMismatch { expected, observed } => write!(
                f,
                "layered oracle commitment carrier mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::PublicCarrierMismatch { expected, observed } => write!(
                f,
                "layered oracle public carrier mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::HiddenCarrierMismatch { expected, observed } => write!(
                f,
                "layered oracle hidden carrier mismatch: expected {expected:?}, observed {observed:?}"
            ),
        }
    }
}

impl std::error::Error for ReferenceLayeredOracleCommitmentAdapterError {}

/// Error raised by the layered quotient-hider adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceLayeredQuotientHiderAdapterError {
    /// The supplied outer proof-layout plan does not match the SHROUD quotient-hider spec.
    PlanMismatch,
    /// The commitment carrier does not match the expected layered layout.
    CommitmentCarrierMismatch {
        /// Carrier required by the adapter.
        expected: ReferenceLayeredQuotientCommitmentCarrier,
        /// Carrier actually supplied.
        observed: ReferenceLayeredQuotientCommitmentCarrier,
    },
    /// The public opening carrier does not match the expected layered layout.
    PublicCarrierMismatch {
        /// Carrier required by the adapter.
        expected: ReferenceLayeredQuotientOpeningCarrier,
        /// Carrier actually supplied.
        observed: ReferenceLayeredQuotientOpeningCarrier,
    },
    /// The hidden auxiliary carrier does not match the expected layered layout.
    HiddenCarrierMismatch {
        /// Carrier required by the adapter.
        expected: ReferenceLayeredQuotientHiddenAuxiliaryCarrier,
        /// Carrier actually supplied.
        observed: ReferenceLayeredQuotientHiddenAuxiliaryCarrier,
    },
}

impl fmt::Display for ReferenceLayeredQuotientHiderAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanMismatch => write!(
                f,
                "layered quotient-hider adapter plan does not match the SHROUD spec"
            ),
            Self::CommitmentCarrierMismatch { expected, observed } => write!(
                f,
                "layered quotient commitment carrier mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::PublicCarrierMismatch { expected, observed } => write!(
                f,
                "layered quotient public carrier mismatch: expected {expected:?}, observed {observed:?}"
            ),
            Self::HiddenCarrierMismatch { expected, observed } => write!(
                f,
                "layered quotient hidden carrier mismatch: expected {expected:?}, observed {observed:?}"
            ),
        }
    }
}

impl std::error::Error for ReferenceLayeredQuotientHiderAdapterError {}

impl OpeningProjectionAdapter for ReferenceLayeredAdapter {
    type PublicOpeningSlot = ReferenceLayeredPublicOpeningCarrier;
    type HiddenAuxiliarySlot = ReferenceLayeredHiddenAuxiliaryCarrier;
    type Error = ReferenceLayeredProjectionAdapterError;

    fn plan(
        &self,
        spec: &ShroudOpeningProjectionSpec,
    ) -> Result<
        OpeningProjectionAdapterPlan<Self::PublicOpeningSlot, Self::HiddenAuxiliarySlot>,
        Self::Error,
    > {
        let hidden_auxiliary_slot = match spec.auxiliary_transport() {
            AuxiliaryOpeningTransport::InBandWithMainProof => {
                ReferenceLayeredHiddenAuxiliaryCarrier::MainOpeningProofEnvelope
            }
            AuxiliaryOpeningTransport::SeparateAuxiliaryProof => {
                ReferenceLayeredHiddenAuxiliaryCarrier::ProjectionAuxiliaryEnvelope
            }
        };

        Ok(OpeningProjectionAdapterPlan::new(
            spec.security_level(),
            ReferenceLayeredPublicOpeningCarrier::StatementOpeningEnvelope,
            hidden_auxiliary_slot,
            spec.payload(),
        ))
    }

    fn validate(
        &self,
        spec: &ShroudOpeningProjectionSpec,
        plan: &OpeningProjectionAdapterPlan<Self::PublicOpeningSlot, Self::HiddenAuxiliarySlot>,
    ) -> Result<(), Self::Error> {
        if *plan.public_opening_slot()
            != ReferenceLayeredPublicOpeningCarrier::StatementOpeningEnvelope
        {
            return Err(
                ReferenceLayeredProjectionAdapterError::PublicCarrierMismatch {
                    expected: ReferenceLayeredPublicOpeningCarrier::StatementOpeningEnvelope,
                    observed: *plan.public_opening_slot(),
                },
            );
        }

        let expected_hidden_carrier = match plan.payload().auxiliary_transport() {
            AuxiliaryOpeningTransport::InBandWithMainProof => {
                ReferenceLayeredHiddenAuxiliaryCarrier::MainOpeningProofEnvelope
            }
            AuxiliaryOpeningTransport::SeparateAuxiliaryProof => {
                ReferenceLayeredHiddenAuxiliaryCarrier::ProjectionAuxiliaryEnvelope
            }
        };

        if *plan.hidden_auxiliary_slot() != expected_hidden_carrier {
            return Err(
                ReferenceLayeredProjectionAdapterError::HiddenCarrierMismatch {
                    expected: expected_hidden_carrier,
                    observed: *plan.hidden_auxiliary_slot(),
                },
            );
        }

        if plan.security_level() != spec.security_level() || plan.payload() != spec.payload() {
            return Err(ReferenceLayeredProjectionAdapterError::PlanMismatch);
        }

        Ok(())
    }
}

impl OracleCommitmentAdapter for ReferencePlonky3Adapter {
    type CommitmentSlot = ReferencePlonky3OracleCommitmentSlot;
    type PublicOpeningSlot = ReferencePlonky3OracleOpeningSlot;
    type HiddenAuxiliarySlot = ReferencePlonky3OracleHiddenAuxiliarySlot;
    type Error = ReferenceOracleCommitmentAdapterError;

    fn plan(
        &self,
        spec: &ShroudOracleCommitmentSpec,
    ) -> Result<
        OracleCommitmentAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
        Self::Error,
    > {
        let hidden_auxiliary_slot = match spec.auxiliary_transport() {
            OracleAuxiliaryTransport::InBandWithOpeningProof => {
                ReferencePlonky3OracleHiddenAuxiliarySlot::HidingMmcsInternals
            }
            OracleAuxiliaryTransport::SeparateAuxiliaryProof => {
                ReferencePlonky3OracleHiddenAuxiliarySlot::DedicatedOracleWitnessField
            }
        };

        Ok(OracleCommitmentAdapterPlan::new(
            spec.security_level(),
            ReferencePlonky3OracleCommitmentSlot::OracleCommitmentField,
            ReferencePlonky3OracleOpeningSlot::MmcsOpeningProof,
            hidden_auxiliary_slot,
            spec.payload(),
        ))
    }

    fn validate(
        &self,
        spec: &ShroudOracleCommitmentSpec,
        plan: &OracleCommitmentAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
    ) -> Result<(), Self::Error> {
        if *plan.commitment_slot() != ReferencePlonky3OracleCommitmentSlot::OracleCommitmentField {
            return Err(
                ReferenceOracleCommitmentAdapterError::CommitmentSlotMismatch {
                    expected: ReferencePlonky3OracleCommitmentSlot::OracleCommitmentField,
                    observed: *plan.commitment_slot(),
                },
            );
        }

        if *plan.public_opening_slot() != ReferencePlonky3OracleOpeningSlot::MmcsOpeningProof {
            return Err(
                ReferenceOracleCommitmentAdapterError::PublicOpeningSlotMismatch {
                    expected: ReferencePlonky3OracleOpeningSlot::MmcsOpeningProof,
                    observed: *plan.public_opening_slot(),
                },
            );
        }

        let expected_hidden_slot = match plan.payload().auxiliary_transport() {
            OracleAuxiliaryTransport::InBandWithOpeningProof => {
                ReferencePlonky3OracleHiddenAuxiliarySlot::HidingMmcsInternals
            }
            OracleAuxiliaryTransport::SeparateAuxiliaryProof => {
                ReferencePlonky3OracleHiddenAuxiliarySlot::DedicatedOracleWitnessField
            }
        };

        if *plan.hidden_auxiliary_slot() != expected_hidden_slot {
            return Err(
                ReferenceOracleCommitmentAdapterError::HiddenAuxiliarySlotMismatch {
                    expected: expected_hidden_slot,
                    observed: *plan.hidden_auxiliary_slot(),
                },
            );
        }

        if plan.security_level() != spec.security_level() || plan.payload() != spec.payload() {
            return Err(ReferenceOracleCommitmentAdapterError::PlanMismatch);
        }

        Ok(())
    }
}

impl OracleCommitmentAdapter for ReferenceLayeredAdapter {
    type CommitmentSlot = ReferenceLayeredOracleCommitmentCarrier;
    type PublicOpeningSlot = ReferenceLayeredOracleOpeningCarrier;
    type HiddenAuxiliarySlot = ReferenceLayeredOracleHiddenAuxiliaryCarrier;
    type Error = ReferenceLayeredOracleCommitmentAdapterError;

    fn plan(
        &self,
        spec: &ShroudOracleCommitmentSpec,
    ) -> Result<
        OracleCommitmentAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
        Self::Error,
    > {
        let hidden_auxiliary_slot = match spec.auxiliary_transport() {
            OracleAuxiliaryTransport::InBandWithOpeningProof => {
                ReferenceLayeredOracleHiddenAuxiliaryCarrier::OracleOpeningEnvelope
            }
            OracleAuxiliaryTransport::SeparateAuxiliaryProof => {
                ReferenceLayeredOracleHiddenAuxiliaryCarrier::OracleAuxiliaryWitnessEnvelope
            }
        };

        Ok(OracleCommitmentAdapterPlan::new(
            spec.security_level(),
            ReferenceLayeredOracleCommitmentCarrier::OracleCommitmentEnvelope,
            ReferenceLayeredOracleOpeningCarrier::OracleOpeningEnvelope,
            hidden_auxiliary_slot,
            spec.payload(),
        ))
    }

    fn validate(
        &self,
        spec: &ShroudOracleCommitmentSpec,
        plan: &OracleCommitmentAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
    ) -> Result<(), Self::Error> {
        if *plan.commitment_slot()
            != ReferenceLayeredOracleCommitmentCarrier::OracleCommitmentEnvelope
        {
            return Err(
                ReferenceLayeredOracleCommitmentAdapterError::CommitmentCarrierMismatch {
                    expected: ReferenceLayeredOracleCommitmentCarrier::OracleCommitmentEnvelope,
                    observed: *plan.commitment_slot(),
                },
            );
        }

        if *plan.public_opening_slot()
            != ReferenceLayeredOracleOpeningCarrier::OracleOpeningEnvelope
        {
            return Err(
                ReferenceLayeredOracleCommitmentAdapterError::PublicCarrierMismatch {
                    expected: ReferenceLayeredOracleOpeningCarrier::OracleOpeningEnvelope,
                    observed: *plan.public_opening_slot(),
                },
            );
        }

        let expected_hidden_carrier = match plan.payload().auxiliary_transport() {
            OracleAuxiliaryTransport::InBandWithOpeningProof => {
                ReferenceLayeredOracleHiddenAuxiliaryCarrier::OracleOpeningEnvelope
            }
            OracleAuxiliaryTransport::SeparateAuxiliaryProof => {
                ReferenceLayeredOracleHiddenAuxiliaryCarrier::OracleAuxiliaryWitnessEnvelope
            }
        };

        if *plan.hidden_auxiliary_slot() != expected_hidden_carrier {
            return Err(
                ReferenceLayeredOracleCommitmentAdapterError::HiddenCarrierMismatch {
                    expected: expected_hidden_carrier,
                    observed: *plan.hidden_auxiliary_slot(),
                },
            );
        }

        if plan.security_level() != spec.security_level() || plan.payload() != spec.payload() {
            return Err(ReferenceLayeredOracleCommitmentAdapterError::PlanMismatch);
        }

        Ok(())
    }
}

/// Checks that `contract` satisfies the Haböck-Kindi quotient degree relation used by
/// `HidingFriPcs`: vanishing_poly_degree = chunk + 1, mask_poly_degree = chunk,
/// committed bound = chunk + vanishing = 2*chunk + 1.
fn check_hk_quotient_degree_relation(
    contract: &shroud_quotient_hider::QuotientDegreeContract,
) -> Result<(), ReferenceQuotientHiderAdapterError> {
    let d = contract.quotient_chunk_degree();
    if contract.vanishing_poly_degree() == d + 1
        && contract.mask_poly_degree() == d
        && contract.randomized_chunk_degree_bound() == d + contract.vanishing_poly_degree()
    {
        Ok(())
    } else {
        Err(
            ReferenceQuotientHiderAdapterError::HKDegreeRelationViolation {
                quotient_chunk_degree: d,
                vanishing_poly_degree: contract.vanishing_poly_degree(),
                mask_poly_degree: contract.mask_poly_degree(),
                randomized_chunk_degree_bound: contract.randomized_chunk_degree_bound(),
            },
        )
    }
}

impl QuotientHiderAdapter for ReferencePlonky3Adapter {
    type CommitmentSlot = ReferencePlonky3QuotientCommitmentSlot;
    type PublicOpeningSlot = ReferencePlonky3QuotientOpeningSlot;
    type HiddenAuxiliarySlot = ReferencePlonky3QuotientHiddenAuxiliarySlot;
    type Error = ReferenceQuotientHiderAdapterError;

    fn plan(
        &self,
        spec: &ShroudQuotientHiderSpec,
    ) -> Result<
        QuotientHiderAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
        Self::Error,
    > {
        if matches!(
            spec.decomposition_family(),
            shroud_quotient_hider::QuotientDecompositionFamily::DegreeChunked
        ) && let Some(contract) = spec.degree_contract()
        {
            check_hk_quotient_degree_relation(&contract)?;
        }

        let hidden_auxiliary_slot = match spec.auxiliary_transport() {
            QuotientAuxiliaryTransport::InBandWithOpeningProof => {
                ReferencePlonky3QuotientHiddenAuxiliarySlot::FriOpeningProofInternals
            }
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof => {
                ReferencePlonky3QuotientHiddenAuxiliarySlot::DedicatedQuotientWitnessField
            }
        };

        Ok(QuotientHiderAdapterPlan::new(
            spec.security_level(),
            spec.decomposition_family(),
            spec.query_budget(),
            ReferencePlonky3QuotientCommitmentSlot::QuotientCommitmentField,
            ReferencePlonky3QuotientOpeningSlot::OpenedQuotientValuesField,
            hidden_auxiliary_slot,
            spec.payload(),
        ))
    }

    fn validate(
        &self,
        spec: &ShroudQuotientHiderSpec,
        plan: &QuotientHiderAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
    ) -> Result<(), Self::Error> {
        // Enforce the full Haböck-Kindi quotient degree relation (same check as plan()).
        if matches!(
            spec.decomposition_family(),
            shroud_quotient_hider::QuotientDecompositionFamily::DegreeChunked
        ) && let Some(contract) = spec.degree_contract()
        {
            check_hk_quotient_degree_relation(&contract)?;
        }

        if *plan.commitment_slot()
            != ReferencePlonky3QuotientCommitmentSlot::QuotientCommitmentField
        {
            return Err(ReferenceQuotientHiderAdapterError::CommitmentSlotMismatch {
                expected: ReferencePlonky3QuotientCommitmentSlot::QuotientCommitmentField,
                observed: *plan.commitment_slot(),
            });
        }

        if *plan.public_opening_slot()
            != ReferencePlonky3QuotientOpeningSlot::OpenedQuotientValuesField
        {
            return Err(
                ReferenceQuotientHiderAdapterError::PublicOpeningSlotMismatch {
                    expected: ReferencePlonky3QuotientOpeningSlot::OpenedQuotientValuesField,
                    observed: *plan.public_opening_slot(),
                },
            );
        }

        let expected_hidden_slot = match plan.payload().auxiliary_transport() {
            QuotientAuxiliaryTransport::InBandWithOpeningProof => {
                ReferencePlonky3QuotientHiddenAuxiliarySlot::FriOpeningProofInternals
            }
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof => {
                ReferencePlonky3QuotientHiddenAuxiliarySlot::DedicatedQuotientWitnessField
            }
        };

        if *plan.hidden_auxiliary_slot() != expected_hidden_slot {
            return Err(
                ReferenceQuotientHiderAdapterError::HiddenAuxiliarySlotMismatch {
                    expected: expected_hidden_slot,
                    observed: *plan.hidden_auxiliary_slot(),
                },
            );
        }

        if plan.security_level() != spec.security_level()
            || plan.decomposition_family() != spec.decomposition_family()
            || plan.query_budget() != spec.query_budget()
            || plan.payload() != spec.payload()
        {
            return Err(ReferenceQuotientHiderAdapterError::PlanMismatch);
        }

        Ok(())
    }
}

impl QuotientHiderAdapter for ReferenceLayeredAdapter {
    type CommitmentSlot = ReferenceLayeredQuotientCommitmentCarrier;
    type PublicOpeningSlot = ReferenceLayeredQuotientOpeningCarrier;
    type HiddenAuxiliarySlot = ReferenceLayeredQuotientHiddenAuxiliaryCarrier;
    type Error = ReferenceLayeredQuotientHiderAdapterError;

    fn plan(
        &self,
        spec: &ShroudQuotientHiderSpec,
    ) -> Result<
        QuotientHiderAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
        Self::Error,
    > {
        let hidden_auxiliary_slot = match spec.auxiliary_transport() {
            QuotientAuxiliaryTransport::InBandWithOpeningProof => {
                ReferenceLayeredQuotientHiddenAuxiliaryCarrier::QuotientOpeningEnvelope
            }
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof => {
                ReferenceLayeredQuotientHiddenAuxiliaryCarrier::QuotientAuxiliaryEnvelope
            }
        };

        Ok(QuotientHiderAdapterPlan::new(
            spec.security_level(),
            spec.decomposition_family(),
            spec.query_budget(),
            ReferenceLayeredQuotientCommitmentCarrier::QuotientCommitmentEnvelope,
            ReferenceLayeredQuotientOpeningCarrier::QuotientOpeningEnvelope,
            hidden_auxiliary_slot,
            spec.payload(),
        ))
    }

    fn validate(
        &self,
        spec: &ShroudQuotientHiderSpec,
        plan: &QuotientHiderAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
    ) -> Result<(), Self::Error> {
        if *plan.commitment_slot()
            != ReferenceLayeredQuotientCommitmentCarrier::QuotientCommitmentEnvelope
        {
            return Err(
                ReferenceLayeredQuotientHiderAdapterError::CommitmentCarrierMismatch {
                    expected: ReferenceLayeredQuotientCommitmentCarrier::QuotientCommitmentEnvelope,
                    observed: *plan.commitment_slot(),
                },
            );
        }

        if *plan.public_opening_slot()
            != ReferenceLayeredQuotientOpeningCarrier::QuotientOpeningEnvelope
        {
            return Err(
                ReferenceLayeredQuotientHiderAdapterError::PublicCarrierMismatch {
                    expected: ReferenceLayeredQuotientOpeningCarrier::QuotientOpeningEnvelope,
                    observed: *plan.public_opening_slot(),
                },
            );
        }

        let expected_hidden_carrier = match plan.payload().auxiliary_transport() {
            QuotientAuxiliaryTransport::InBandWithOpeningProof => {
                ReferenceLayeredQuotientHiddenAuxiliaryCarrier::QuotientOpeningEnvelope
            }
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof => {
                ReferenceLayeredQuotientHiddenAuxiliaryCarrier::QuotientAuxiliaryEnvelope
            }
        };

        if *plan.hidden_auxiliary_slot() != expected_hidden_carrier {
            return Err(
                ReferenceLayeredQuotientHiderAdapterError::HiddenCarrierMismatch {
                    expected: expected_hidden_carrier,
                    observed: *plan.hidden_auxiliary_slot(),
                },
            );
        }

        if plan.security_level() != spec.security_level()
            || plan.decomposition_family() != spec.decomposition_family()
            || plan.query_budget() != spec.query_budget()
            || plan.payload() != spec.payload()
        {
            return Err(ReferenceLayeredQuotientHiderAdapterError::PlanMismatch);
        }

        Ok(())
    }
}

impl BatchOpeningAdapter for ReferencePlonky3Adapter {
    type CommitmentSlot = ReferencePlonky3CommitmentSlot;
    type Error = ReferenceAdapterError;

    fn plan(
        &self,
        spec: &ShroudBatchOpeningSpec,
    ) -> Result<BatchOpeningAdapterPlan<Self::CommitmentSlot>, Self::Error> {
        let commitment_slot = match spec.randomizer_opening_payload() {
            RandomizerOpeningPayload::Statistical(_) => {
                ReferencePlonky3CommitmentSlot::RandomOptionField
            }
            RandomizerOpeningPayload::Perfect(payload) => match payload.proof_slot_layout() {
                ProofSlotLayout::ReuseCurrentRandomSlot => {
                    ReferencePlonky3CommitmentSlot::RandomOptionField
                }
                ProofSlotLayout::DedicatedPerfectRandomizerSlot => {
                    ReferencePlonky3CommitmentSlot::DedicatedPerfectRandomizerField
                }
            },
        };

        Ok(BatchOpeningAdapterPlan::new(
            spec.security_level(),
            spec.commitment_boundary(),
            commitment_slot,
            spec.randomizer_opening_payload(),
            2,
        ))
    }

    fn validate(
        &self,
        spec: &ShroudBatchOpeningSpec,
        plan: &BatchOpeningAdapterPlan<Self::CommitmentSlot>,
    ) -> Result<(), Self::Error> {
        let expected_slot = match plan.proof_slot_layout() {
            ProofSlotLayout::ReuseCurrentRandomSlot => {
                ReferencePlonky3CommitmentSlot::RandomOptionField
            }
            ProofSlotLayout::DedicatedPerfectRandomizerSlot => {
                ReferencePlonky3CommitmentSlot::DedicatedPerfectRandomizerField
            }
        };

        if *plan.commitment_slot() != expected_slot {
            return Err(ReferenceAdapterError::CommitmentSlotMismatch {
                expected: expected_slot,
                observed: *plan.commitment_slot(),
            });
        }

        if plan.security_level() != spec.security_level()
            || plan.commitment_boundary() != spec.commitment_boundary()
            || plan.opening_payload() != spec.randomizer_opening_payload()
        {
            return Err(ReferenceAdapterError::PlanMismatch);
        }

        Ok(())
    }
}

impl PerfectRandomizerAdapter for ReferencePlonky3Adapter {
    type CommitmentSlot = ReferencePlonky3CommitmentSlot;
    type Error = ReferenceAdapterError;

    fn surface(
        &self,
        spec: &ShroudBatchOpeningSpec,
    ) -> Result<PerfectRandomizerAdapterSurface<Self::CommitmentSlot>, Self::Error> {
        let payload = match spec.randomizer_opening_payload() {
            RandomizerOpeningPayload::Perfect(payload) => payload,
            RandomizerOpeningPayload::Statistical(_) => {
                return Err(ReferenceAdapterError::ExpectedPerfectVariant);
            }
        };

        let commitment_slot = match payload.proof_slot_layout() {
            ProofSlotLayout::ReuseCurrentRandomSlot => {
                ReferencePlonky3CommitmentSlot::RandomOptionField
            }
            ProofSlotLayout::DedicatedPerfectRandomizerSlot => {
                ReferencePlonky3CommitmentSlot::DedicatedPerfectRandomizerField
            }
        };

        Ok(PerfectRandomizerAdapterSurface::new(
            commitment_slot,
            payload.proof_slot_layout(),
            payload,
        ))
    }

    fn reconstruct(
        &self,
        spec: &ShroudBatchOpeningSpec,
        surface: &PerfectRandomizerAdapterSurface<Self::CommitmentSlot>,
    ) -> Result<PerfectRandomizerReconstruction, Self::Error> {
        let model = spec
            .perfect_randomizer_commitment()
            .ok_or(ReferenceAdapterError::ExpectedPerfectVariant)?;

        let expected_slot = match surface.proof_slot_layout() {
            ProofSlotLayout::ReuseCurrentRandomSlot => {
                ReferencePlonky3CommitmentSlot::RandomOptionField
            }
            ProofSlotLayout::DedicatedPerfectRandomizerSlot => {
                ReferencePlonky3CommitmentSlot::DedicatedPerfectRandomizerField
            }
        };

        if *surface.commitment_slot() != expected_slot {
            return Err(ReferenceAdapterError::CommitmentSlotMismatch {
                expected: expected_slot,
                observed: *surface.commitment_slot(),
            });
        }

        Ok(PerfectRandomizerReconstruction::new(
            model,
            surface.opening_payload(),
        ))
    }
}

impl PerfectRandomizerBackend for ReferencePerfectRandomizerBackend {
    type Commitment = ReferencePerfectRandomizerCommitment;
    type ProverState = ReferencePerfectRandomizerState;
    type PublicEvaluation = ReferencePublicEvaluation;
    type HiddenOpening = ReferenceHiddenOpening;
    type Error = ReferencePerfectRandomizerError;

    fn commitment_model(&self) -> PerfectRandomizerCommitment {
        self.model
    }

    fn commit(
        &self,
        spec: &ShroudBatchOpeningSpec,
    ) -> Result<PreparedPerfectRandomizer<Self::Commitment, Self::ProverState>, Self::Error> {
        let observed = spec
            .perfect_randomizer_commitment()
            .ok_or(ReferencePerfectRandomizerError::ExpectedPerfectVariant)?;

        if observed != self.model {
            return Err(ReferencePerfectRandomizerError::CommitmentModelMismatch {
                expected: self.model,
                observed,
            });
        }

        Ok(PreparedPerfectRandomizer::new(
            ReferencePerfectRandomizerCommitment {
                model: self.model,
                shape: spec.shape(),
            },
            ReferencePerfectRandomizerState {
                shape: spec.shape(),
            },
        ))
    }

    fn open(
        &self,
        spec: &ShroudBatchOpeningSpec,
        prover_state: &Self::ProverState,
    ) -> Result<PerfectRandomizerOpening<Self::PublicEvaluation, Self::HiddenOpening>, Self::Error>
    {
        let observed = spec
            .perfect_randomizer_commitment()
            .ok_or(ReferencePerfectRandomizerError::ExpectedPerfectVariant)?;

        if observed != self.model {
            return Err(ReferencePerfectRandomizerError::CommitmentModelMismatch {
                expected: self.model,
                observed,
            });
        }

        let payload = match spec.randomizer_opening_payload() {
            RandomizerOpeningPayload::Perfect(payload) => payload,
            RandomizerOpeningPayload::Statistical(_) => {
                return Err(ReferencePerfectRandomizerError::ExpectedPerfectVariant);
            }
        };

        let public_evaluations = (0..payload.public_extension_evaluations())
            .map(|point_index| ReferencePublicEvaluation { point_index })
            .collect();

        let hidden_openings = match payload.hidden_payload() {
            PerfectHiddenOpeningPayload::EncodedCoordinates {
                base_field_coordinate_evaluations,
                transport,
            } => ReferenceHiddenOpening {
                evaluation_count: base_field_coordinate_evaluations,
                transport,
            },
            PerfectHiddenOpeningPayload::BackendProofOnly { transport } => ReferenceHiddenOpening {
                evaluation_count: 0,
                transport,
            },
        };

        let _ = prover_state.shape();

        Ok(PerfectRandomizerOpening::new(
            public_evaluations,
            hidden_openings,
        ))
    }

    fn reconstruct(
        &self,
        spec: &ShroudBatchOpeningSpec,
        commitment: &Self::Commitment,
        opening: &PerfectRandomizerOpening<Self::PublicEvaluation, Self::HiddenOpening>,
    ) -> Result<PerfectRandomizerReconstruction, Self::Error> {
        let observed = spec
            .perfect_randomizer_commitment()
            .ok_or(ReferencePerfectRandomizerError::ExpectedPerfectVariant)?;

        if observed != self.model || commitment.model() != self.model {
            return Err(ReferencePerfectRandomizerError::CommitmentModelMismatch {
                expected: self.model,
                observed: commitment.model(),
            });
        }

        let payload = match spec.randomizer_opening_payload() {
            RandomizerOpeningPayload::Perfect(payload) => payload,
            RandomizerOpeningPayload::Statistical(_) => {
                return Err(ReferencePerfectRandomizerError::ExpectedPerfectVariant);
            }
        };

        let observed_public = opening.public_evaluations().len();
        if observed_public != payload.public_extension_evaluations() {
            return Err(
                ReferencePerfectRandomizerError::PublicEvaluationCountMismatch {
                    expected: payload.public_extension_evaluations(),
                    observed: observed_public,
                },
            );
        }

        let hidden_openings = opening.hidden_openings();
        let (expected_evaluations, expected_transport) = match payload.hidden_payload() {
            PerfectHiddenOpeningPayload::EncodedCoordinates {
                base_field_coordinate_evaluations,
                transport,
            } => (base_field_coordinate_evaluations, transport),
            PerfectHiddenOpeningPayload::BackendProofOnly { transport } => (0, transport),
        };

        if hidden_openings.evaluation_count() != expected_evaluations
            || hidden_openings.transport() != expected_transport
        {
            return Err(ReferencePerfectRandomizerError::HiddenOpeningMismatch {
                expected_evaluations,
                observed_evaluations: hidden_openings.evaluation_count(),
                expected_transport,
                observed_transport: hidden_openings.transport(),
            });
        }

        Ok(PerfectRandomizerReconstruction::new(self.model, payload))
    }
}

/// Standard Plonky3 BabyBear/BinomialExtension(4) FRI blowup used by the reference adapter.
const REFERENCE_LOG_BLOWUP: usize = 2;

/// Standard Plonky3 number of random codewords used by the reference adapter.
const REFERENCE_NUM_RANDOM_CODEWORDS: usize = 4;

impl CodewordEmbeddingAdapter for ReferencePlonky3Adapter {
    type CommitmentSlot = ReferencePlonky3CodewordCommitmentSlot;
    type PublicOpeningSlot = ReferencePlonky3CodewordPublicOpeningSlot;
    type HiddenAuxiliarySlot = ReferencePlonky3CodewordHiddenAuxiliarySlot;
    type Error = ReferenceCodewordEmbeddingAdapterError;

    fn plan(
        &self,
        spec: &ShroudCodewordEmbeddingSpec,
    ) -> Result<
        CodewordEmbeddingAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
        Self::Error,
    > {
        if spec.auxiliary_transport() == AuxiliaryTransport::SeparateEnvelope {
            return Err(ReferenceCodewordEmbeddingAdapterError::UnsupportedAuxiliaryTransport);
        }

        Ok(CodewordEmbeddingAdapterPlan::new(
            spec.security_level(),
            ReferencePlonky3CodewordCommitmentSlot::TraceCommitment,
            ReferencePlonky3CodewordPublicOpeningSlot::OpenedTraceValues,
            ReferencePlonky3CodewordHiddenAuxiliarySlot::FriProofRandomCodewordOpenings,
            spec.payload(),
        ))
    }

    fn validate(
        &self,
        spec: &ShroudCodewordEmbeddingSpec,
        plan: &CodewordEmbeddingAdapterPlan<
            Self::CommitmentSlot,
            Self::PublicOpeningSlot,
            Self::HiddenAuxiliarySlot,
        >,
    ) -> Result<(), Self::Error> {
        if spec.auxiliary_transport() == AuxiliaryTransport::SeparateEnvelope {
            return Err(ReferenceCodewordEmbeddingAdapterError::UnsupportedAuxiliaryTransport);
        }

        if *plan.commitment_slot() != ReferencePlonky3CodewordCommitmentSlot::TraceCommitment {
            return Err(
                ReferenceCodewordEmbeddingAdapterError::CommitmentSlotMismatch {
                    expected: ReferencePlonky3CodewordCommitmentSlot::TraceCommitment,
                    observed: *plan.commitment_slot(),
                },
            );
        }

        if *plan.public_opening_slot()
            != ReferencePlonky3CodewordPublicOpeningSlot::OpenedTraceValues
        {
            return Err(
                ReferenceCodewordEmbeddingAdapterError::PublicOpeningSlotMismatch {
                    expected: ReferencePlonky3CodewordPublicOpeningSlot::OpenedTraceValues,
                    observed: *plan.public_opening_slot(),
                },
            );
        }

        if *plan.hidden_auxiliary_slot()
            != ReferencePlonky3CodewordHiddenAuxiliarySlot::FriProofRandomCodewordOpenings
        {
            return Err(
                ReferenceCodewordEmbeddingAdapterError::HiddenAuxiliarySlotMismatch {
                    expected:
                        ReferencePlonky3CodewordHiddenAuxiliarySlot::FriProofRandomCodewordOpenings,
                    observed: *plan.hidden_auxiliary_slot(),
                },
            );
        }

        ReferenceHidingFriPcsProfile::standard().validate_for_spec(spec)?;

        if plan.security_level() != spec.security_level() || plan.payload() != spec.payload() {
            return Err(ReferenceCodewordEmbeddingAdapterError::PlanMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        REFERENCE_LOG_BLOWUP, REFERENCE_NUM_RANDOM_CODEWORDS, ReferenceAdapterError,
        ReferenceBindingRecord, ReferenceChallengeDeriver, ReferenceCodewordEmbeddingAdapterError,
        ReferenceHidingFriPcsProfile, ReferenceLayeredAdapter, ReferenceLayeredAdapterError,
        ReferenceLayeredCommitmentCarrier, ReferenceLayeredHiddenAuxiliaryCarrier,
        ReferenceLayeredOracleCommitmentAdapterError, ReferenceLayeredOracleCommitmentCarrier,
        ReferenceLayeredOracleHiddenAuxiliaryCarrier, ReferenceLayeredOracleOpeningCarrier,
        ReferenceLayeredProjectionAdapterError, ReferenceLayeredPublicOpeningCarrier,
        ReferenceLayeredQuotientCommitmentCarrier, ReferenceLayeredQuotientHiddenAuxiliaryCarrier,
        ReferenceLayeredQuotientHiderAdapterError, ReferenceLayeredQuotientOpeningCarrier,
        ReferenceOracleCommitmentAdapterError, ReferencePerfectRandomizerBackend,
        ReferencePerfectRandomizerCommitment, ReferencePerfectRandomizerError,
        ReferencePlonky3Adapter, ReferencePlonky3CodewordCommitmentSlot,
        ReferencePlonky3CodewordHiddenAuxiliarySlot, ReferencePlonky3CodewordPublicOpeningSlot,
        ReferencePlonky3CommitmentSlot, ReferencePlonky3HiddenAuxiliarySlot,
        ReferencePlonky3OracleCommitmentSlot, ReferencePlonky3OracleHiddenAuxiliarySlot,
        ReferencePlonky3OracleOpeningSlot, ReferencePlonky3PublicOpeningSlot,
        ReferencePlonky3QuotientCommitmentSlot, ReferencePlonky3QuotientHiddenAuxiliarySlot,
        ReferencePlonky3QuotientOpeningSlot, ReferenceProjectionAdapterError,
        ReferenceQuotientHiderAdapterError, ReferenceTranscript, ReferenceTranscriptError,
    };
    use shroud_adapter::{
        BatchOpeningAdapter, BatchOpeningAdapterPlan, CodewordEmbeddingAdapter,
        CodewordEmbeddingAdapterPlan, OpeningProjectionAdapter, OpeningProjectionAdapterPlan,
        OracleCommitmentAdapter, OracleCommitmentAdapterPlan, QuotientHiderAdapter,
        QuotientHiderAdapterPlan,
    };
    use shroud_batch_opening::{
        BatchOpeningShape, HiddenOpeningTransport, PerfectHiddenOpeningPayload,
        PerfectRandomizerAdapter, PerfectRandomizerBackend, PerfectRandomizerCommitment,
        PerfectRandomizerReconstruction, ProofSlotLayout, ShroudBatchOpeningSpec,
    };
    use shroud_codeword_embedding::{CodewordEmbeddingShape, ShroudCodewordEmbeddingSpec};
    use shroud_core::{
        AuxiliaryTransport, BasisDescriptor, CanonicalBatchOpeningManifest, DOMAIN_BASIS,
        DOMAIN_DEGREE_CONTRACT, DOMAIN_ORACLE_COMMITMENT, DOMAIN_PROFILE, DOMAIN_PUBLIC_OPENINGS,
        DOMAIN_RANDOMIZER_COMMITMENT, DOMAIN_SECURITY_LEVEL, FieldModel, HashIdentifier,
        PerfectClaim, PublicOpeningBinding, RandomnessModel, SecurityLevel, SimulatorObligations,
        StandardBatchOpeningBindings, TranscriptBindable, TranscriptBinding,
        TranscriptBindingError, TranscriptBindingManifest, TranscriptStage,
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

    fn valid_perfect_claim() -> PerfectClaim {
        valid_perfect_claim_for_degree(4)
    }

    fn valid_perfect_claim_for_degree(extension_degree: usize) -> PerfectClaim {
        PerfectClaim::new(
            RandomnessModel::UniformPerProof,
            FieldModel::EncodedCoordinates {
                basis: BasisDescriptor::plonky3_binomial(extension_degree),
            },
            64,
            SimulatorObligations::HonestVerifierChallengeAccess,
            true,
        )
        .expect("valid perfect claim")
    }

    fn valid_native_perfect_claim_for_degree(extension_degree: usize) -> PerfectClaim {
        PerfectClaim::new(
            RandomnessModel::UniformPerProof,
            FieldModel::NativeExtension { extension_degree },
            64,
            SimulatorObligations::HonestVerifierChallengeAccess,
            true,
        )
        .expect("valid native perfect claim")
    }

    #[test]
    fn accepts_the_standard_statistical_flow() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");
        let mut transcript = ReferenceTranscript::new(&spec, TranscriptBindingManifest::new());

        for stage in spec.transcript_plan().stages() {
            transcript
                .advance(*stage)
                .expect("stage should be accepted");
        }

        assert_eq!(transcript.expected_stage(), None);
    }

    #[test]
    fn rejects_sampling_ood_point_before_randomizer_commitment() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::encoded_oracle_bundle(BasisDescriptor::plonky3_binomial(
                2,
            )),
            valid_perfect_claim_for_degree(2),
        )
        .expect("valid spec");
        let mut transcript = ReferenceTranscript::new(&spec, TranscriptBindingManifest::new());

        transcript
            .advance(TranscriptStage::ObserveMainCommitments)
            .expect("first stage should be accepted");
        transcript
            .advance(TranscriptStage::SampleBatchingChallenge)
            .expect("second stage should be accepted");
        transcript
            .advance(TranscriptStage::ObserveQuotientCommitments)
            .expect("third stage should be accepted");

        assert_eq!(
            transcript.advance(TranscriptStage::SampleOodPoint),
            Err(ReferenceTranscriptError::UnexpectedStage {
                expected: TranscriptStage::ObserveRandomizerCommitment,
                observed: TranscriptStage::SampleOodPoint,
            })
        );
    }

    #[test]
    fn failed_observe_does_not_pollute_binding_record() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::encoded_oracle_bundle(BasisDescriptor::plonky3_binomial(
                2,
            )),
            valid_perfect_claim_for_degree(2),
        )
        .expect("valid spec");
        let mut transcript = ReferenceTranscript::new(&spec, TranscriptBindingManifest::new());

        let backend = ReferencePerfectRandomizerBackend::encoded_oracle_bundle(
            BasisDescriptor::plonky3_binomial(2),
        );
        let prepared = backend.commit(&spec).expect("commit should succeed");

        // Cursor is at ObserveMainCommitments. Observing the randomizer here is out of order.
        let err = backend
            .observe(&mut transcript, prepared.commitment())
            .unwrap_err();
        assert!(matches!(
            err,
            ReferenceTranscriptError::UnexpectedStage { .. }
        ));

        // CRITICAL: the failed observe must not have absorbed the commitment binding,
        // otherwise a later sampling gate could be satisfied by stale bytes.
        assert!(
            !transcript
                .record()
                .contains_binding(DOMAIN_RANDOMIZER_COMMITMENT),
            "failed observe leaked DOMAIN_RANDOMIZER_COMMITMENT into the record"
        );
    }

    #[test]
    fn encoded_backend_round_trips_through_commit_observe_open_and_reconstruct() {
        let shape = BatchOpeningShape::new(5, 2, 3).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            31,
            PerfectRandomizerCommitment::encoded_oracle_bundle(BasisDescriptor::plonky3_binomial(
                3,
            )),
            valid_perfect_claim_for_degree(3),
        )
        .expect("valid spec");
        let backend = ReferencePerfectRandomizerBackend::encoded_oracle_bundle(
            BasisDescriptor::plonky3_binomial(3),
        );
        let prepared = backend.commit(&spec).expect("commit should succeed");

        let mut transcript = ReferenceTranscript::new(&spec, TranscriptBindingManifest::new());
        transcript
            .advance(TranscriptStage::ObserveMainCommitments)
            .expect("first stage should be accepted");
        transcript
            .advance(TranscriptStage::SampleBatchingChallenge)
            .expect("second stage should be accepted");
        transcript
            .advance(TranscriptStage::ObserveQuotientCommitments)
            .expect("third stage should be accepted");

        backend
            .observe(&mut transcript, prepared.commitment())
            .expect("observation should succeed");
        // After observe, DOMAIN_RANDOMIZER_COMMITMENT is now in the record
        assert_eq!(
            transcript.expected_stage(),
            Some(TranscriptStage::SampleOodPoint)
        );

        let opening = backend
            .open(&spec, prepared.prover_state())
            .expect("opening should succeed");
        let reconstruction = backend
            .reconstruct(&spec, prepared.commitment(), &opening)
            .expect("reconstruction should succeed");

        assert_eq!(
            reconstruction.commitment(),
            PerfectRandomizerCommitment::encoded_oracle_bundle(BasisDescriptor::plonky3_binomial(
                3
            ))
        );
        assert_eq!(
            reconstruction.opening_payload().proof_slot_layout(),
            ProofSlotLayout::ReuseCurrentRandomSlot
        );
        assert_eq!(
            reconstruction.opening_payload().hidden_payload(),
            PerfectHiddenOpeningPayload::EncodedCoordinates {
                base_field_coordinate_evaluations: 6,
                transport: HiddenOpeningTransport::InBandWithMainOpeningProof,
            }
        );
    }

    #[test]
    fn native_backend_reconstructs_backend_only_hidden_payload() {
        let shape = BatchOpeningShape::new(3, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::native_extension_pcs(),
            valid_native_perfect_claim_for_degree(2),
        )
        .expect("valid spec");
        let backend = ReferencePerfectRandomizerBackend::native_extension_pcs();
        let prepared = backend.commit(&spec).expect("commit should succeed");
        let opening = backend
            .open(&spec, prepared.prover_state())
            .expect("opening should succeed");
        let reconstruction = backend
            .reconstruct(&spec, prepared.commitment(), &opening)
            .expect("reconstruction should succeed");

        assert_eq!(
            reconstruction.opening_payload().proof_slot_layout(),
            ProofSlotLayout::DedicatedPerfectRandomizerSlot
        );
        assert_eq!(
            reconstruction.opening_payload().hidden_payload(),
            PerfectHiddenOpeningPayload::BackendProofOnly {
                transport: HiddenOpeningTransport::SeparateAuxiliaryProof,
            }
        );
    }

    #[test]
    fn backend_rejects_mismatched_perfect_commitment_model() {
        let shape = BatchOpeningShape::new(3, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::native_extension_pcs(),
            valid_native_perfect_claim_for_degree(2),
        )
        .expect("valid spec");
        let backend = ReferencePerfectRandomizerBackend::encoded_oracle_bundle(
            BasisDescriptor::plonky3_binomial(2),
        );

        assert_eq!(
            backend.commit(&spec),
            Err(ReferencePerfectRandomizerError::CommitmentModelMismatch {
                expected: PerfectRandomizerCommitment::encoded_oracle_bundle(
                    BasisDescriptor::plonky3_binomial(2),
                ),
                observed: PerfectRandomizerCommitment::native_extension_pcs(),
            })
        );
    }

    #[test]
    fn adapter_maps_encoded_bundle_to_existing_random_slot() {
        let shape = BatchOpeningShape::new(5, 2, 3).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            31,
            PerfectRandomizerCommitment::encoded_oracle_bundle(BasisDescriptor::plonky3_binomial(
                3,
            )),
            valid_perfect_claim_for_degree(3),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let surface = adapter.surface(&spec).expect("surface should be built");
        assert_eq!(
            *surface.commitment_slot(),
            ReferencePlonky3CommitmentSlot::RandomOptionField
        );
        assert_eq!(
            surface.proof_slot_layout(),
            ProofSlotLayout::ReuseCurrentRandomSlot
        );

        let reconstruction = adapter
            .reconstruct(&spec, &surface)
            .expect("reconstruction should succeed");
        assert_eq!(
            reconstruction,
            PerfectRandomizerReconstruction::new(
                PerfectRandomizerCommitment::encoded_oracle_bundle(
                    BasisDescriptor::plonky3_binomial(3),
                ),
                surface.opening_payload(),
            )
        );
    }

    #[test]
    fn adapter_maps_native_extension_to_dedicated_slot() {
        let shape = BatchOpeningShape::new(3, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::native_extension_pcs(),
            valid_native_perfect_claim_for_degree(2),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let surface = adapter.surface(&spec).expect("surface should be built");
        assert_eq!(
            *surface.commitment_slot(),
            ReferencePlonky3CommitmentSlot::DedicatedPerfectRandomizerField
        );
        assert_eq!(
            surface.proof_slot_layout(),
            ProofSlotLayout::DedicatedPerfectRandomizerSlot
        );
    }

    #[test]
    fn adapter_rejects_statistical_specs() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        assert_eq!(
            adapter.surface(&spec),
            Err(ReferenceAdapterError::ExpectedPerfectVariant)
        );
    }

    #[test]
    fn backend_neutral_plan_covers_statistical_specs_too() {
        let shape = BatchOpeningShape::new(5, 2, 4).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 31).expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let plan = BatchOpeningAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(plan.security_level(), SecurityLevel::Statistical);
        assert_eq!(
            plan.commitment_slot(),
            &ReferencePlonky3CommitmentSlot::RandomOptionField
        );
        assert_eq!(
            plan.proof_slot_layout(),
            ProofSlotLayout::ReuseCurrentRandomSlot
        );
        BatchOpeningAdapter::validate(&adapter, &spec, &plan)
            .expect("statistical plan should validate");
    }

    #[test]
    fn backend_neutral_plan_can_detect_slot_mismatches() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::native_extension_pcs(),
            valid_native_perfect_claim_for_degree(2),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let bad_plan = BatchOpeningAdapterPlan::new(
            SecurityLevel::Perfect,
            spec.commitment_boundary(),
            ReferencePlonky3CommitmentSlot::RandomOptionField,
            spec.randomizer_opening_payload(),
            2,
        );

        assert_eq!(
            BatchOpeningAdapter::validate(&adapter, &spec, &bad_plan),
            Err(ReferenceAdapterError::CommitmentSlotMismatch {
                expected: ReferencePlonky3CommitmentSlot::DedicatedPerfectRandomizerField,
                observed: ReferencePlonky3CommitmentSlot::RandomOptionField,
            })
        );
    }

    #[test]
    fn layered_adapter_maps_statistical_specs_to_shared_envelope() {
        let shape = BatchOpeningShape::new(5, 2, 4).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 31).expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let plan = BatchOpeningAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(plan.security_level(), SecurityLevel::Statistical);
        assert_eq!(
            plan.commitment_slot(),
            &ReferenceLayeredCommitmentCarrier::SharedBatchOpeningEnvelope
        );
        BatchOpeningAdapter::validate(&adapter, &spec, &plan)
            .expect("statistical plan should validate");
    }

    #[test]
    fn layered_adapter_maps_encoded_perfect_specs_to_auxiliary_envelope() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::encoded_oracle_bundle(BasisDescriptor::plonky3_binomial(
                2,
            )),
            valid_perfect_claim_for_degree(2),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let plan = BatchOpeningAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(plan.security_level(), SecurityLevel::Perfect);
        assert_eq!(
            plan.commitment_slot(),
            &ReferenceLayeredCommitmentCarrier::AuxiliaryRandomizerEnvelope
        );
        assert_eq!(
            plan.proof_slot_layout(),
            ProofSlotLayout::ReuseCurrentRandomSlot
        );
        BatchOpeningAdapter::validate(&adapter, &spec, &plan)
            .expect("encoded perfect plan should validate");
    }

    #[test]
    fn layered_adapter_maps_native_perfect_specs_to_dedicated_envelope() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::native_extension_pcs(),
            valid_native_perfect_claim_for_degree(2),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let plan = BatchOpeningAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.commitment_slot(),
            &ReferenceLayeredCommitmentCarrier::DedicatedPerfectRandomizerEnvelope
        );
        assert_eq!(
            plan.proof_slot_layout(),
            ProofSlotLayout::DedicatedPerfectRandomizerSlot
        );
    }

    #[test]
    fn layered_adapter_detects_carrier_mismatches() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::encoded_oracle_bundle(BasisDescriptor::plonky3_binomial(
                2,
            )),
            valid_perfect_claim_for_degree(2),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let bad_plan = BatchOpeningAdapterPlan::new(
            SecurityLevel::Perfect,
            spec.commitment_boundary(),
            ReferenceLayeredCommitmentCarrier::SharedBatchOpeningEnvelope,
            spec.randomizer_opening_payload(),
            2,
        );

        assert_eq!(
            BatchOpeningAdapter::validate(&adapter, &spec, &bad_plan),
            Err(ReferenceLayeredAdapterError::CommitmentCarrierMismatch {
                expected: ReferenceLayeredCommitmentCarrier::AuxiliaryRandomizerEnvelope,
                observed: ReferenceLayeredCommitmentCarrier::SharedBatchOpeningEnvelope,
            })
        );
    }

    #[test]
    fn plonky3_projection_adapter_maps_statistical_projection_in_band() {
        let shape = OpeningProjectionShape::new(3, 5, 2).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::statistical(
            shape,
            AuxiliaryOpeningTransport::InBandWithMainProof,
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let plan = OpeningProjectionAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.public_opening_slot(),
            &ReferencePlonky3PublicOpeningSlot::OpenedValuesField
        );
        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferencePlonky3HiddenAuxiliarySlot::FriOpeningProofInternals
        );
        OpeningProjectionAdapter::validate(&adapter, &spec, &plan)
            .expect("statistical projection plan should validate");
    }

    #[test]
    fn plonky3_projection_adapter_maps_perfect_projection_to_dedicated_field() {
        let shape = OpeningProjectionShape::new(2, 6, 3).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::perfect(
            shape,
            AuxiliaryOpeningTransport::SeparateAuxiliaryProof,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let plan = OpeningProjectionAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferencePlonky3HiddenAuxiliarySlot::DedicatedProjectionField
        );
        OpeningProjectionAdapter::validate(&adapter, &spec, &plan)
            .expect("perfect projection plan should validate");
    }

    #[test]
    fn plonky3_projection_adapter_detects_hidden_slot_mismatches() {
        let shape = OpeningProjectionShape::new(2, 6, 3).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::perfect(
            shape,
            AuxiliaryOpeningTransport::SeparateAuxiliaryProof,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let bad_plan = OpeningProjectionAdapterPlan::new(
            SecurityLevel::Perfect,
            ReferencePlonky3PublicOpeningSlot::OpenedValuesField,
            ReferencePlonky3HiddenAuxiliarySlot::FriOpeningProofInternals,
            spec.payload(),
        );

        assert_eq!(
            OpeningProjectionAdapter::validate(&adapter, &spec, &bad_plan),
            Err(
                ReferenceProjectionAdapterError::HiddenAuxiliarySlotMismatch {
                    expected: ReferencePlonky3HiddenAuxiliarySlot::DedicatedProjectionField,
                    observed: ReferencePlonky3HiddenAuxiliarySlot::FriOpeningProofInternals,
                }
            )
        );
    }

    #[test]
    fn layered_projection_adapter_maps_statistical_projection_to_main_envelope() {
        let shape = OpeningProjectionShape::new(3, 5, 2).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::statistical(
            shape,
            AuxiliaryOpeningTransport::InBandWithMainProof,
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let plan = OpeningProjectionAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.public_opening_slot(),
            &ReferenceLayeredPublicOpeningCarrier::StatementOpeningEnvelope
        );
        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferenceLayeredHiddenAuxiliaryCarrier::MainOpeningProofEnvelope
        );
        OpeningProjectionAdapter::validate(&adapter, &spec, &plan)
            .expect("layered statistical projection plan should validate");
    }

    #[test]
    fn layered_projection_adapter_maps_perfect_projection_to_auxiliary_envelope() {
        let shape = OpeningProjectionShape::new(2, 6, 3).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::perfect(
            shape,
            AuxiliaryOpeningTransport::SeparateAuxiliaryProof,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let plan = OpeningProjectionAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferenceLayeredHiddenAuxiliaryCarrier::ProjectionAuxiliaryEnvelope
        );
        OpeningProjectionAdapter::validate(&adapter, &spec, &plan)
            .expect("layered perfect projection plan should validate");
    }

    #[test]
    fn layered_projection_adapter_detects_hidden_carrier_mismatches() {
        let shape = OpeningProjectionShape::new(2, 6, 3).expect("valid shape");
        let spec = ShroudOpeningProjectionSpec::perfect(
            shape,
            AuxiliaryOpeningTransport::SeparateAuxiliaryProof,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let bad_plan = OpeningProjectionAdapterPlan::new(
            SecurityLevel::Perfect,
            ReferenceLayeredPublicOpeningCarrier::StatementOpeningEnvelope,
            ReferenceLayeredHiddenAuxiliaryCarrier::MainOpeningProofEnvelope,
            spec.payload(),
        );

        assert_eq!(
            OpeningProjectionAdapter::validate(&adapter, &spec, &bad_plan),
            Err(
                ReferenceLayeredProjectionAdapterError::HiddenCarrierMismatch {
                    expected: ReferenceLayeredHiddenAuxiliaryCarrier::ProjectionAuxiliaryEnvelope,
                    observed: ReferenceLayeredHiddenAuxiliaryCarrier::MainOpeningProofEnvelope,
                }
            )
        );
    }

    #[test]
    fn plonky3_oracle_adapter_maps_statistical_oracle_in_band() {
        let shape = OracleCommitmentShape::new(2, 3, 4, 5, 1).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::statistical(
            shape,
            OracleAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let plan = OracleCommitmentAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.commitment_slot(),
            &ReferencePlonky3OracleCommitmentSlot::OracleCommitmentField
        );
        assert_eq!(
            plan.public_opening_slot(),
            &ReferencePlonky3OracleOpeningSlot::MmcsOpeningProof
        );
        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferencePlonky3OracleHiddenAuxiliarySlot::HidingMmcsInternals
        );
        OracleCommitmentAdapter::validate(&adapter, &spec, &plan)
            .expect("statistical oracle plan should validate");
    }

    #[test]
    fn plonky3_oracle_adapter_maps_perfect_oracle_to_dedicated_field() {
        let shape = OracleCommitmentShape::new(1, 2, 8, 4, 2).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::perfect(
            shape,
            OracleAuxiliaryTransport::SeparateAuxiliaryProof,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let plan = OracleCommitmentAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferencePlonky3OracleHiddenAuxiliarySlot::DedicatedOracleWitnessField
        );
        OracleCommitmentAdapter::validate(&adapter, &spec, &plan)
            .expect("perfect oracle plan should validate");
    }

    #[test]
    fn plonky3_oracle_adapter_detects_hidden_slot_mismatches() {
        let shape = OracleCommitmentShape::new(1, 2, 8, 4, 2).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::perfect(
            shape,
            OracleAuxiliaryTransport::SeparateAuxiliaryProof,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let bad_plan = OracleCommitmentAdapterPlan::new(
            SecurityLevel::Perfect,
            ReferencePlonky3OracleCommitmentSlot::OracleCommitmentField,
            ReferencePlonky3OracleOpeningSlot::MmcsOpeningProof,
            ReferencePlonky3OracleHiddenAuxiliarySlot::HidingMmcsInternals,
            spec.payload(),
        );

        assert_eq!(
            OracleCommitmentAdapter::validate(&adapter, &spec, &bad_plan),
            Err(
                ReferenceOracleCommitmentAdapterError::HiddenAuxiliarySlotMismatch {
                    expected:
                        ReferencePlonky3OracleHiddenAuxiliarySlot::DedicatedOracleWitnessField,
                    observed: ReferencePlonky3OracleHiddenAuxiliarySlot::HidingMmcsInternals,
                }
            )
        );
    }

    #[test]
    fn layered_oracle_adapter_maps_statistical_oracle_to_opening_envelope() {
        let shape = OracleCommitmentShape::new(2, 3, 4, 5, 1).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::statistical(
            shape,
            OracleAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let plan = OracleCommitmentAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.commitment_slot(),
            &ReferenceLayeredOracleCommitmentCarrier::OracleCommitmentEnvelope
        );
        assert_eq!(
            plan.public_opening_slot(),
            &ReferenceLayeredOracleOpeningCarrier::OracleOpeningEnvelope
        );
        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferenceLayeredOracleHiddenAuxiliaryCarrier::OracleOpeningEnvelope
        );
        OracleCommitmentAdapter::validate(&adapter, &spec, &plan)
            .expect("layered statistical oracle plan should validate");
    }

    #[test]
    fn layered_oracle_adapter_maps_perfect_oracle_to_auxiliary_envelope() {
        let shape = OracleCommitmentShape::new(1, 2, 8, 4, 2).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::perfect(
            shape,
            OracleAuxiliaryTransport::SeparateAuxiliaryProof,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let plan = OracleCommitmentAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferenceLayeredOracleHiddenAuxiliaryCarrier::OracleAuxiliaryWitnessEnvelope
        );
        OracleCommitmentAdapter::validate(&adapter, &spec, &plan)
            .expect("layered perfect oracle plan should validate");
    }

    #[test]
    fn layered_oracle_adapter_detects_hidden_carrier_mismatches() {
        let shape = OracleCommitmentShape::new(1, 2, 8, 4, 2).expect("valid shape");
        let spec = ShroudOracleCommitmentSpec::perfect(
            shape,
            OracleAuxiliaryTransport::SeparateAuxiliaryProof,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let bad_plan = OracleCommitmentAdapterPlan::new(
            SecurityLevel::Perfect,
            ReferenceLayeredOracleCommitmentCarrier::OracleCommitmentEnvelope,
            ReferenceLayeredOracleOpeningCarrier::OracleOpeningEnvelope,
            ReferenceLayeredOracleHiddenAuxiliaryCarrier::OracleOpeningEnvelope,
            spec.payload(),
        );

        assert_eq!(
            OracleCommitmentAdapter::validate(&adapter, &spec, &bad_plan),
            Err(
                ReferenceLayeredOracleCommitmentAdapterError::HiddenCarrierMismatch {
                    expected:
                        ReferenceLayeredOracleHiddenAuxiliaryCarrier::OracleAuxiliaryWitnessEnvelope,
                    observed: ReferenceLayeredOracleHiddenAuxiliaryCarrier::OracleOpeningEnvelope,
                }
            )
        );
    }

    #[test]
    fn plonky3_quotient_adapter_maps_statistical_quotient_in_band() {
        let shape = QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid shape");
        // HidingFriPcs uses q'_i = q_i + v_H_i * t_i. For chunk degree h-1=31:
        //   vanishing_poly_degree = h = 32, mask_poly_degree = h-1 = 31, committed bound = 2h-1 = 63.
        let contract =
            QuotientDegreeContract::with_vanishing_poly(31, 32, 31, 63).expect("valid contract");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(contract),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let plan = QuotientHiderAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.commitment_slot(),
            &ReferencePlonky3QuotientCommitmentSlot::QuotientCommitmentField
        );
        assert_eq!(
            plan.public_opening_slot(),
            &ReferencePlonky3QuotientOpeningSlot::OpenedQuotientValuesField
        );
        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferencePlonky3QuotientHiddenAuxiliarySlot::FriOpeningProofInternals
        );
        assert_eq!(
            plan.decomposition_family(),
            QuotientDecompositionFamily::DegreeChunked
        );
        assert_eq!(plan.query_budget(), 8);
        QuotientHiderAdapter::validate(&adapter, &spec, &plan)
            .expect("statistical quotient plan should validate");
    }

    #[test]
    fn plonky3_quotient_adapter_maps_perfect_quotient_to_dedicated_field() {
        let shape = QuotientHiderShape::new(2, 3, 2, 2, 4).expect("valid shape");
        let spec = ShroudQuotientHiderSpec::perfect(
            QuotientDecompositionFamily::Segmented,
            6,
            shape,
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof,
            None,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let plan = QuotientHiderAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferencePlonky3QuotientHiddenAuxiliarySlot::DedicatedQuotientWitnessField
        );
        QuotientHiderAdapter::validate(&adapter, &spec, &plan)
            .expect("perfect quotient plan should validate");
    }

    #[test]
    fn plonky3_quotient_adapter_detects_hidden_slot_mismatches() {
        let shape = QuotientHiderShape::new(2, 3, 2, 2, 4).expect("valid shape");
        let spec = ShroudQuotientHiderSpec::perfect(
            QuotientDecompositionFamily::Segmented,
            6,
            shape,
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof,
            None,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let bad_plan = QuotientHiderAdapterPlan::new(
            SecurityLevel::Perfect,
            QuotientDecompositionFamily::Segmented,
            6,
            ReferencePlonky3QuotientCommitmentSlot::QuotientCommitmentField,
            ReferencePlonky3QuotientOpeningSlot::OpenedQuotientValuesField,
            ReferencePlonky3QuotientHiddenAuxiliarySlot::FriOpeningProofInternals,
            spec.payload(),
        );

        assert_eq!(
            QuotientHiderAdapter::validate(&adapter, &spec, &bad_plan),
            Err(
                ReferenceQuotientHiderAdapterError::HiddenAuxiliarySlotMismatch {
                    expected:
                        ReferencePlonky3QuotientHiddenAuxiliarySlot::DedicatedQuotientWitnessField,
                    observed: ReferencePlonky3QuotientHiddenAuxiliarySlot::FriOpeningProofInternals,
                }
            )
        );
    }

    #[test]
    fn layered_quotient_adapter_maps_statistical_quotient_to_opening_envelope() {
        let shape = QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid shape");
        let contract = QuotientDegreeContract::new(31, 31).expect("valid contract");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(contract),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let plan = QuotientHiderAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.commitment_slot(),
            &ReferenceLayeredQuotientCommitmentCarrier::QuotientCommitmentEnvelope
        );
        assert_eq!(
            plan.public_opening_slot(),
            &ReferenceLayeredQuotientOpeningCarrier::QuotientOpeningEnvelope
        );
        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferenceLayeredQuotientHiddenAuxiliaryCarrier::QuotientOpeningEnvelope
        );
        QuotientHiderAdapter::validate(&adapter, &spec, &plan)
            .expect("layered statistical quotient plan should validate");
    }

    #[test]
    fn layered_quotient_adapter_maps_perfect_quotient_to_auxiliary_envelope() {
        let shape = QuotientHiderShape::new(2, 3, 2, 2, 4).expect("valid shape");
        let spec = ShroudQuotientHiderSpec::perfect(
            QuotientDecompositionFamily::Segmented,
            6,
            shape,
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof,
            None,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let plan = QuotientHiderAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferenceLayeredQuotientHiddenAuxiliaryCarrier::QuotientAuxiliaryEnvelope
        );
        QuotientHiderAdapter::validate(&adapter, &spec, &plan)
            .expect("layered perfect quotient plan should validate");
    }

    #[test]
    fn layered_quotient_adapter_detects_hidden_carrier_mismatches() {
        let shape = QuotientHiderShape::new(2, 3, 2, 2, 4).expect("valid shape");
        let spec = ShroudQuotientHiderSpec::perfect(
            QuotientDecompositionFamily::Segmented,
            6,
            shape,
            QuotientAuxiliaryTransport::SeparateAuxiliaryProof,
            None,
            valid_perfect_claim(),
        )
        .expect("valid spec");
        let adapter = ReferenceLayeredAdapter;

        let bad_plan = QuotientHiderAdapterPlan::new(
            SecurityLevel::Perfect,
            QuotientDecompositionFamily::Segmented,
            6,
            ReferenceLayeredQuotientCommitmentCarrier::QuotientCommitmentEnvelope,
            ReferenceLayeredQuotientOpeningCarrier::QuotientOpeningEnvelope,
            ReferenceLayeredQuotientHiddenAuxiliaryCarrier::QuotientOpeningEnvelope,
            spec.payload(),
        );

        assert_eq!(
            QuotientHiderAdapter::validate(&adapter, &spec, &bad_plan),
            Err(
                ReferenceLayeredQuotientHiderAdapterError::HiddenCarrierMismatch {
                    expected:
                        ReferenceLayeredQuotientHiddenAuxiliaryCarrier::QuotientAuxiliaryEnvelope,
                    observed:
                        ReferenceLayeredQuotientHiddenAuxiliaryCarrier::QuotientOpeningEnvelope,
                }
            )
        );
    }

    #[test]
    fn codeword_embedding_adapter_maps_statistical_spec_to_standard_slots() {
        let profile = ReferenceHidingFriPcsProfile::standard();
        let shape = CodewordEmbeddingShape::new(
            64,
            profile.num_random_codewords,
            18,
            profile.basis.extension_degree,
        )
        .expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let plan = CodewordEmbeddingAdapter::plan(&adapter, &spec).expect("plan should succeed");

        assert_eq!(plan.security_level(), SecurityLevel::Statistical);
        assert_eq!(
            plan.commitment_slot(),
            &ReferencePlonky3CodewordCommitmentSlot::TraceCommitment
        );
        assert_eq!(
            plan.public_opening_slot(),
            &ReferencePlonky3CodewordPublicOpeningSlot::OpenedTraceValues
        );
        assert_eq!(
            plan.hidden_auxiliary_slot(),
            &ReferencePlonky3CodewordHiddenAuxiliarySlot::FriProofRandomCodewordOpenings
        );
        assert_eq!(plan.payload().required_log_blowup(), profile.log_blowup);
        assert_eq!(
            plan.payload().hidden_randomizer_columns(),
            profile.num_random_codewords
        );
        assert_eq!(plan.payload().public_trace_columns(), 64);
        CodewordEmbeddingAdapter::validate(&adapter, &spec, &plan)
            .expect("standard statistical plan should validate");
    }

    #[test]
    fn codeword_embedding_adapter_rejects_separate_envelope_transport() {
        let profile = ReferenceHidingFriPcsProfile::standard();
        let shape = CodewordEmbeddingShape::new(
            64,
            profile.num_random_codewords,
            18,
            profile.basis.extension_degree,
        )
        .expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical_with_transport(
            shape,
            AuxiliaryTransport::SeparateEnvelope,
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        assert_eq!(
            CodewordEmbeddingAdapter::plan(&adapter, &spec),
            Err(ReferenceCodewordEmbeddingAdapterError::UnsupportedAuxiliaryTransport)
        );
    }

    #[test]
    fn codeword_embedding_adapter_rejects_wrong_randomizer_count() {
        let wrong_randomizers = REFERENCE_NUM_RANDOM_CODEWORDS + 1;
        let shape = CodewordEmbeddingShape::new(64, wrong_randomizers, 18, wrong_randomizers)
            .expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let plan = CodewordEmbeddingAdapter::plan(&adapter, &spec).expect("plan should succeed");
        assert_eq!(
            CodewordEmbeddingAdapter::validate(&adapter, &spec, &plan),
            Err(
                ReferenceCodewordEmbeddingAdapterError::RandomizerColumnMismatch {
                    required: wrong_randomizers,
                    configured: REFERENCE_NUM_RANDOM_CODEWORDS,
                }
            )
        );
    }

    #[test]
    fn codeword_embedding_adapter_rejects_wrong_hidden_slot() {
        let profile = ReferenceHidingFriPcsProfile::standard();
        let shape = CodewordEmbeddingShape::new(
            64,
            profile.num_random_codewords,
            18,
            profile.basis.extension_degree,
        )
        .expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        let bad_plan = CodewordEmbeddingAdapterPlan::new(
            SecurityLevel::Statistical,
            ReferencePlonky3CodewordCommitmentSlot::TraceCommitment,
            ReferencePlonky3CodewordPublicOpeningSlot::OpenedTraceValues,
            ReferencePlonky3CodewordHiddenAuxiliarySlot::DedicatedCodewordAuxiliaryField,
            spec.payload(),
        );

        assert_eq!(
            CodewordEmbeddingAdapter::validate(&adapter, &spec, &bad_plan),
            Err(
                ReferenceCodewordEmbeddingAdapterError::HiddenAuxiliarySlotMismatch {
                    expected:
                        ReferencePlonky3CodewordHiddenAuxiliarySlot::FriProofRandomCodewordOpenings,
                    observed:
                        ReferencePlonky3CodewordHiddenAuxiliarySlot::DedicatedCodewordAuxiliaryField,
                }
            )
        );
    }

    #[test]
    fn hiding_fri_pcs_profile_standard_matches_adapter_constants() {
        let profile = ReferenceHidingFriPcsProfile::standard();

        assert_eq!(profile.log_blowup, REFERENCE_LOG_BLOWUP);
        assert_eq!(profile.num_random_codewords, REFERENCE_NUM_RANDOM_CODEWORDS);
        assert_eq!(profile.basis, BasisDescriptor::plonky3_binomial(4));
        assert!(profile.input_mmcs_hiding);
        assert!(profile.fri_mmcs_hiding);

        let shape = CodewordEmbeddingShape::new(
            8,
            profile.num_random_codewords,
            profile.log_blowup + 1,
            profile.basis.extension_degree,
        )
        .expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");

        profile
            .validate_for_spec(&spec)
            .expect("standard profile should accept matching spec");
    }

    #[test]
    fn profile_validate_for_spec_rejects_non_hiding_mmcs() {
        let profile = ReferenceHidingFriPcsProfile {
            input_mmcs_hiding: false,
            ..ReferenceHidingFriPcsProfile::standard()
        };
        let shape = CodewordEmbeddingShape::new(
            8,
            profile.num_random_codewords,
            profile.log_blowup + 1,
            profile.basis.extension_degree,
        )
        .expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");

        assert_eq!(
            profile.validate_for_spec(&spec),
            Err(ReferenceCodewordEmbeddingAdapterError::NonHidingMmcs)
        );
    }

    #[test]
    fn profile_validate_for_spec_rejects_missing_random_codeword_technique() {
        use shroud_core::HidingTechniqueClaim;
        let profile = ReferenceHidingFriPcsProfile {
            hiding_technique: HidingTechniqueClaim::RandomRowPadding,
            ..ReferenceHidingFriPcsProfile::standard()
        };
        let shape = CodewordEmbeddingShape::new(
            8,
            profile.num_random_codewords,
            profile.log_blowup + 1,
            profile.basis.extension_degree,
        )
        .expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");

        assert_eq!(
            profile.validate_for_spec(&spec),
            Err(ReferenceCodewordEmbeddingAdapterError::RandomCodewordInterleavingNotDeclared)
        );
    }

    #[test]
    fn profile_validate_for_spec_rejects_extension_degree_mismatch() {
        use shroud_core::BasisDescriptor;
        let profile = ReferenceHidingFriPcsProfile {
            basis: BasisDescriptor::plonky3_binomial(2),
            num_random_codewords: 4,
            ..ReferenceHidingFriPcsProfile::standard()
        };
        // Spec declares extension_degree = 4; profile declares degree = 2.
        let shape =
            CodewordEmbeddingShape::new(8, 4, profile.log_blowup + 1, 4).expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");

        assert_eq!(
            profile.validate_for_spec(&spec),
            Err(
                ReferenceCodewordEmbeddingAdapterError::ExtensionDegreeMismatch {
                    profile: 2,
                    spec: 4,
                }
            )
        );
    }

    #[test]
    fn plonky3_quotient_adapter_plan_rejects_wrong_hk_degree_relation() {
        let shape = QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid shape");
        // Plain-additive: vanishing_poly_degree = 0, expected = quotient_chunk_degree + 1 = 32.
        let contract = QuotientDegreeContract::new(31, 31).expect("valid contract");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(contract),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        // plan() itself must reject — not just validate().
        assert_eq!(
            QuotientHiderAdapter::plan(&adapter, &spec),
            Err(
                ReferenceQuotientHiderAdapterError::HKDegreeRelationViolation {
                    quotient_chunk_degree: 31,
                    vanishing_poly_degree: 0,
                    mask_poly_degree: 31,
                    randomized_chunk_degree_bound: 31,
                }
            )
        );
    }

    #[test]
    fn plonky3_quotient_adapter_rejects_malformed_vanishing_factor_contract() {
        let shape = QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid shape");
        // vanishing_poly_degree = 1 (nonzero) but not quotient_chunk_degree + 1 = 16.
        let contract =
            QuotientDegreeContract::with_vanishing_poly(15, 1, 1, 15).expect("valid contract");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(contract),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;

        assert_eq!(
            QuotientHiderAdapter::plan(&adapter, &spec),
            Err(
                ReferenceQuotientHiderAdapterError::HKDegreeRelationViolation {
                    quotient_chunk_degree: 15,
                    vanishing_poly_degree: 1,
                    mask_poly_degree: 1,
                    randomized_chunk_degree_bound: 15,
                }
            )
        );
    }

    #[test]
    fn plonky3_quotient_adapter_accepts_exact_hk_degree_relation() {
        let shape = QuotientHiderShape::new(3, 2, 4, 1, 2).expect("valid shape");
        // Exact HK relation: chunk=15, vanishing=16=chunk+1, mask=15=chunk, bound=31=chunk+vanishing.
        let contract =
            QuotientDegreeContract::with_vanishing_poly(15, 16, 15, 31).expect("valid contract");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(contract),
        )
        .expect("valid spec");
        let adapter = ReferencePlonky3Adapter;
        let plan =
            QuotientHiderAdapter::plan(&adapter, &spec).expect("exact HK relation should plan");

        QuotientHiderAdapter::validate(&adapter, &spec, &plan)
            .expect("exact HK relation should validate");
    }

    // Plonky3-prototype profile/config tests live in the `shroud-plonky3` crate.

    // ── Transcript binding tests ─────────────────────────────────────────────────

    struct StandardManifestFixture {
        batch_spec: ShroudBatchOpeningSpec,
        codeword_spec: ShroudCodewordEmbeddingSpec,
        oracle_spec: ShroudOracleCommitmentSpec,
        projection_spec: ShroudOpeningProjectionSpec,
        quotient_spec: ShroudQuotientHiderSpec,
        degree_contract: QuotientDegreeContract,
        randomizer_commitment: ReferencePerfectRandomizerCommitment,
        public_openings: PublicOpeningBinding,
        profile: ReferenceHidingFriPcsProfile,
        basis: BasisDescriptor,
        hash_identifier: HashIdentifier,
        deriver: ReferenceChallengeDeriver,
    }

    fn standard_manifest_fixture() -> StandardManifestFixture {
        let basis = BasisDescriptor::plonky3_binomial(4);
        let batch_shape = BatchOpeningShape::new(4, 2, 4).expect("valid batch shape");
        let batch_spec = ShroudBatchOpeningSpec::perfect(
            batch_shape,
            15,
            PerfectRandomizerCommitment::encoded_oracle_bundle(basis),
            valid_perfect_claim(),
        )
        .expect("valid batch spec");
        let codeword_shape =
            CodewordEmbeddingShape::new(8, 4, 16, 4).expect("valid codeword shape");
        let codeword_spec =
            ShroudCodewordEmbeddingSpec::statistical(codeword_shape).expect("valid codeword spec");
        let oracle_spec = ShroudOracleCommitmentSpec::statistical(
            OracleCommitmentShape::new(2, 3, 4, 5, 1).expect("valid oracle shape"),
            OracleAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid oracle spec");
        let projection_spec = ShroudOpeningProjectionSpec::statistical(
            OpeningProjectionShape::new(4, 8, 3).expect("valid projection shape"),
            AuxiliaryOpeningTransport::InBandWithMainProof,
        )
        .expect("valid projection spec");
        let degree_contract =
            QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid contract");
        let quotient_spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            2,
            QuotientHiderShape::new(2, 2, 1, 1, 1).expect("valid quotient shape"),
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(degree_contract),
        )
        .expect("valid quotient spec");
        let randomizer_commitment = ReferencePerfectRandomizerCommitment {
            model: PerfectRandomizerCommitment::encoded_oracle_bundle(basis),
            shape: batch_shape,
        };
        let public_openings = PublicOpeningBinding::new(vec![0xCD; 8]);
        let profile = ReferenceHidingFriPcsProfile::standard();
        let hash_identifier = HashIdentifier::new("shroud-reference-transcript-v1");
        let deriver = ReferenceChallengeDeriver::new(hash_identifier.clone());

        StandardManifestFixture {
            batch_spec,
            codeword_spec,
            oracle_spec,
            projection_spec,
            quotient_spec,
            degree_contract,
            randomizer_commitment,
            public_openings,
            profile,
            basis,
            hash_identifier,
            deriver,
        }
    }

    fn standard_manifest_from_fixture(
        fixture: &StandardManifestFixture,
    ) -> CanonicalBatchOpeningManifest {
        TranscriptBindingManifest::standard_for_batch_opening(
            StandardBatchOpeningBindings::from_bindables(
                &fixture.hash_identifier,
                &fixture.profile,
                &fixture.basis,
                &fixture.batch_spec,
                &fixture.codeword_spec,
                &fixture.oracle_spec,
                &fixture.projection_spec,
                &fixture.quotient_spec,
                &fixture.batch_spec.security_level(),
                &fixture.degree_contract,
                &fixture.randomizer_commitment,
                &fixture.public_openings,
            ),
        )
    }

    fn build_complete_finalize_state() -> (TranscriptBindingManifest, ReferenceBindingRecord) {
        let fixture = standard_manifest_fixture();
        let manifest = standard_manifest_from_fixture(&fixture).into_inner();

        let mut record = ReferenceBindingRecord::new();
        record.absorb_bindable(&fixture.hash_identifier);
        record.absorb_bindable(&fixture.profile);
        record.absorb_bindable(&fixture.basis);
        record.absorb_bindable(&fixture.batch_spec);
        record.absorb_bindable(&fixture.codeword_spec);
        record.absorb_bindable(&fixture.oracle_spec);
        record.absorb_bindable(&fixture.projection_spec);
        record.absorb_bindable(&fixture.quotient_spec);
        record.absorb_bindable(&fixture.batch_spec.security_level());
        record.absorb_bindable(&fixture.degree_contract);
        record.absorb_bindable(&fixture.randomizer_commitment);
        record.absorb_bindable(&fixture.public_openings);

        (manifest, record)
    }

    #[test]
    fn standard_manifest_routes_all_canonical_batch_opening_bindings() {
        let fixture = standard_manifest_fixture();
        let manifest = standard_manifest_from_fixture(&fixture);
        let batching_domains: Vec<_> = manifest
            .required_before(TranscriptStage::SampleBatchingChallenge)
            .iter()
            .map(TranscriptBinding::domain_label)
            .collect();
        assert!(batching_domains.contains(&shroud_core::DOMAIN_HASH_ID));
        assert!(batching_domains.contains(&shroud_core::DOMAIN_BATCH_OPENING));
        assert!(batching_domains.contains(&shroud_core::DOMAIN_CODEWORD_EMBEDDING));
        assert!(batching_domains.contains(&shroud_core::DOMAIN_OPENING_PROJECTION));
        assert!(batching_domains.contains(&shroud_core::DOMAIN_QUOTIENT_HIDER));
        assert_eq!(
            manifest
                .required_before(TranscriptStage::SampleOodPoint)
                .len(),
            2
        );
        assert_eq!(
            manifest
                .required_before(TranscriptStage::ProveMaskedRelation)
                .first()
                .map(TranscriptBinding::domain_label),
            Some(DOMAIN_PUBLIC_OPENINGS)
        );
    }

    /// Locks the per-stage binding sequence emitted by
    /// `TranscriptBindingManifest::standard_for_batch_opening`. This is the
    /// canonical source of truth cited by `docs/security-model.md §7`. If a
    /// future refactor reorders `standard_for_batch_opening`, this test fails
    /// loudly instead of silently drifting from the prose in the doc.
    #[test]
    fn standard_manifest_per_stage_label_sequence_is_canonical() {
        use shroud_core::{
            DOMAIN_BASIS, DOMAIN_BATCH_OPENING, DOMAIN_CODEWORD_EMBEDDING, DOMAIN_DEGREE_CONTRACT,
            DOMAIN_HASH_ID, DOMAIN_OPENING_PROJECTION, DOMAIN_ORACLE_COMMITMENT, DOMAIN_PROFILE,
            DOMAIN_PUBLIC_OPENINGS, DOMAIN_QUOTIENT_HIDER, DOMAIN_RANDOMIZER_COMMITMENT,
            DOMAIN_SECURITY_LEVEL,
        };

        let fixture = standard_manifest_fixture();
        let manifest = standard_manifest_from_fixture(&fixture);

        let labels_for = |stage| {
            manifest
                .required_before(stage)
                .iter()
                .map(TranscriptBinding::domain_label)
                .collect::<Vec<_>>()
        };

        // Before SampleBatchingChallenge: hash-id, profile, basis, then the
        // five protocol-object specs in declaration order, then security level.
        assert_eq!(
            labels_for(TranscriptStage::SampleBatchingChallenge),
            vec![
                DOMAIN_HASH_ID,
                DOMAIN_PROFILE,
                DOMAIN_BASIS,
                DOMAIN_BATCH_OPENING,
                DOMAIN_CODEWORD_EMBEDDING,
                DOMAIN_ORACLE_COMMITMENT,
                DOMAIN_OPENING_PROJECTION,
                DOMAIN_QUOTIENT_HIDER,
                DOMAIN_SECURITY_LEVEL,
            ]
        );

        // Before SampleOodPoint: degree contract first, then concrete randomizer commitment.
        assert_eq!(
            labels_for(TranscriptStage::SampleOodPoint),
            vec![DOMAIN_DEGREE_CONTRACT, DOMAIN_RANDOMIZER_COMMITMENT]
        );

        // Before ProveMaskedRelation: public openings.
        assert_eq!(
            labels_for(TranscriptStage::ProveMaskedRelation),
            vec![DOMAIN_PUBLIC_OPENINGS]
        );
    }

    #[test]
    fn complete_binding_record_finalizes_successfully() {
        let (manifest, record) = build_complete_finalize_state();
        assert!(record.finalize(&manifest).is_ok());
    }

    #[test]
    fn missing_profile_binding_fails_finalize() {
        let (manifest, mut record) = build_complete_finalize_state();
        record
            .absorbed
            .retain(|b| b.domain_label() != DOMAIN_PROFILE);
        assert_eq!(
            record.finalize(&manifest),
            Err(TranscriptBindingError::MissingBinding {
                domain_label: DOMAIN_PROFILE.to_string(),
            })
        );
    }

    #[test]
    fn missing_basis_binding_fails_finalize() {
        let (manifest, mut record) = build_complete_finalize_state();
        record.absorbed.retain(|b| b.domain_label() != DOMAIN_BASIS);
        assert_eq!(
            record.finalize(&manifest),
            Err(TranscriptBindingError::MissingBinding {
                domain_label: DOMAIN_BASIS.to_string(),
            })
        );
    }

    #[test]
    fn missing_oracle_commitment_binding_fails_finalize() {
        let (manifest, mut record) = build_complete_finalize_state();
        record
            .absorbed
            .retain(|b| b.domain_label() != DOMAIN_ORACLE_COMMITMENT);
        assert_eq!(
            record.finalize(&manifest),
            Err(TranscriptBindingError::MissingBinding {
                domain_label: DOMAIN_ORACLE_COMMITMENT.to_string(),
            })
        );
    }

    #[test]
    fn missing_randomizer_commitment_binding_fails_finalize() {
        let (manifest, mut record) = build_complete_finalize_state();
        record
            .absorbed
            .retain(|b| b.domain_label() != DOMAIN_RANDOMIZER_COMMITMENT);
        assert_eq!(
            record.finalize(&manifest),
            Err(TranscriptBindingError::MissingBinding {
                domain_label: DOMAIN_RANDOMIZER_COMMITMENT.to_string(),
            })
        );
    }

    #[test]
    fn missing_degree_contract_binding_fails_finalize() {
        let (manifest, mut record) = build_complete_finalize_state();
        record
            .absorbed
            .retain(|b| b.domain_label() != DOMAIN_DEGREE_CONTRACT);
        assert_eq!(
            record.finalize(&manifest),
            Err(TranscriptBindingError::MissingBinding {
                domain_label: DOMAIN_DEGREE_CONTRACT.to_string(),
            })
        );
    }

    #[test]
    fn missing_security_level_binding_fails_finalize() {
        let (manifest, mut record) = build_complete_finalize_state();
        record
            .absorbed
            .retain(|b| b.domain_label() != DOMAIN_SECURITY_LEVEL);
        assert_eq!(
            record.finalize(&manifest),
            Err(TranscriptBindingError::MissingBinding {
                domain_label: DOMAIN_SECURITY_LEVEL.to_string(),
            })
        );
    }

    #[test]
    fn missing_public_openings_binding_fails_finalize() {
        let (manifest, mut record) = build_complete_finalize_state();
        record
            .absorbed
            .retain(|b| b.domain_label() != DOMAIN_PUBLIC_OPENINGS);
        assert_eq!(
            record.finalize(&manifest),
            Err(TranscriptBindingError::MissingBinding {
                domain_label: DOMAIN_PUBLIC_OPENINGS.to_string(),
            })
        );
    }

    #[test]
    fn wrong_bytes_for_typed_binding_fails_finalize_with_mismatch() {
        let (manifest, mut record) = build_complete_finalize_state();
        // Remove the correct basis binding and absorb a different (degree-2) one
        record.absorbed.retain(|b| b.domain_label() != DOMAIN_BASIS);
        record.absorb_bindable(&BasisDescriptor::plonky3_binomial(2));
        assert_eq!(
            record.finalize(&manifest),
            Err(TranscriptBindingError::BindingMismatch {
                domain_label: DOMAIN_BASIS.to_string(),
            })
        );
    }

    #[test]
    fn wrong_domain_label_does_not_satisfy_requirement() {
        let mut record = ReferenceBindingRecord::new();
        // Absorb a binding with the wrong label for DOMAIN_BASIS
        record.absorb(TranscriptBinding::new("SHROUD_V1_WRONG_LABEL", vec![0x01]));
        assert!(!record.contains_binding(DOMAIN_BASIS));
        assert!(record.assert_required_present(&[DOMAIN_BASIS]).is_err());
    }

    #[test]
    fn cross_protocol_substitution_at_oracle_label_fails_finalize() {
        // Threat model §2: an attacker provides "looks-valid" bytes (a real
        // codeword-embedding spec binding) but wraps them under the oracle-
        // commitment domain label. The manifest must catch this as a
        // BindingMismatch — domain-label-vs-bytes substitution is the cross-
        // protocol confusion attack class.
        let fixture = standard_manifest_fixture();
        let manifest = standard_manifest_from_fixture(&fixture);

        // Build the cross-protocol attack binding: codeword spec's canonical
        // bytes wearing the oracle-commitment domain label.
        let codeword_bytes = fixture
            .codeword_spec
            .to_transcript_binding()
            .canonical_bytes()
            .to_vec();
        let cross_protocol_binding =
            TranscriptBinding::new(DOMAIN_ORACLE_COMMITMENT, codeword_bytes);

        // Build a record with every legitimate binding EXCEPT the oracle slot,
        // which gets the cross-protocol binding.
        let mut record = ReferenceBindingRecord::new();
        record.absorb_bindable(&fixture.hash_identifier);
        record.absorb_bindable(&fixture.profile);
        record.absorb_bindable(&fixture.basis);
        record.absorb_bindable(&fixture.batch_spec);
        record.absorb_bindable(&fixture.codeword_spec);
        record.absorb(cross_protocol_binding); // attacker move
        record.absorb_bindable(&fixture.projection_spec);
        record.absorb_bindable(&fixture.quotient_spec);
        record.absorb_bindable(&fixture.batch_spec.security_level());
        record.absorb_bindable(&fixture.degree_contract);
        record.absorb_bindable(&fixture.randomizer_commitment);
        record.absorb_bindable(&fixture.public_openings);

        assert_eq!(
            record.finalize_canonical(&manifest),
            Err(TranscriptBindingError::BindingMismatch {
                domain_label: DOMAIN_ORACLE_COMMITMENT.to_string(),
            })
        );
    }

    #[test]
    fn profile_binding_encodes_log_blowup_and_randomizers() {
        let profile = ReferenceHidingFriPcsProfile::standard();
        let binding = profile.to_transcript_binding();
        assert_eq!(binding.domain_label(), DOMAIN_PROFILE);
        // Binding is now longer than 26 bytes (includes technique bytes)
        assert!(binding.canonical_bytes().len() > 26);
        // First 8 bytes = log_blowup=2 as u64 LE
        assert_eq!(&binding.canonical_bytes()[..8], &2u64.to_le_bytes());
        // Next 8 bytes = num_random_codewords=4 as u64 LE
        assert_eq!(&binding.canonical_bytes()[8..16], &4u64.to_le_bytes());
        // Next 8 bytes = basis.extension_degree=4 as u64 LE
        assert_eq!(&binding.canonical_bytes()[16..24], &4u64.to_le_bytes());
        // bytes 24..26 = input_mmcs_hiding=1, fri_mmcs_hiding=1
        assert_eq!(&binding.canonical_bytes()[24..26], &[1u8, 1u8]);
        // After byte 26: 4-byte length prefix for technique bytes, then technique bytes
        let technique_bytes = profile.hiding_technique.to_canonical_bytes();
        let len_bytes = (technique_bytes.len() as u32).to_le_bytes();
        assert_eq!(&binding.canonical_bytes()[26..30], &len_bytes);
        assert_eq!(&binding.canonical_bytes()[30..], &technique_bytes[..]);
    }

    #[test]
    fn different_profiles_produce_different_bindings() {
        let standard = ReferenceHidingFriPcsProfile::standard();
        let mut modified = ReferenceHidingFriPcsProfile::standard();
        modified.log_blowup = 3;
        assert_ne!(
            standard.to_transcript_binding(),
            modified.to_transcript_binding()
        );
    }

    #[test]
    fn absorb_bindable_uses_correct_domain_for_security_level() {
        let mut record = ReferenceBindingRecord::new();
        record.absorb_bindable(&SecurityLevel::Statistical);
        assert!(record.contains_binding(DOMAIN_SECURITY_LEVEL));
    }

    // ── Stage-scoped binding enforcement tests ───────────────────────────────────

    #[test]
    fn advance_to_sampling_stage_fails_without_required_bindings() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");

        // Build a manifest that requires the standard profile before SampleBatchingChallenge
        let profile = ReferenceHidingFriPcsProfile::standard();
        let manifest = TranscriptBindingManifest::new()
            .with_before_batching_challenge(profile.to_transcript_binding());

        let mut transcript = ReferenceTranscript::new(&spec, manifest);
        transcript
            .advance(TranscriptStage::ObserveMainCommitments)
            .expect("observe main ok");
        // Do NOT absorb the profile — exact-byte check must fail
        let err = transcript
            .advance(TranscriptStage::SampleBatchingChallenge)
            .unwrap_err();
        assert!(
            matches!(
                err,
                ReferenceTranscriptError::MissingBindingBeforeStage { .. }
            ),
            "expected MissingBindingBeforeStage, got {err:?}"
        );
    }

    #[test]
    fn advance_to_ood_point_fails_without_randomizer_commitment_binding() {
        use shroud_quotient_hider::QuotientDegreeContract;
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");

        // Require a specific degree contract before SampleOodPoint
        let contract = QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid");
        let manifest = TranscriptBindingManifest::new()
            .with_before_ood_point(contract.to_transcript_binding());

        let mut transcript = ReferenceTranscript::new(&spec, manifest);
        transcript
            .advance(TranscriptStage::ObserveMainCommitments)
            .expect("ok");
        transcript
            .advance(TranscriptStage::SampleBatchingChallenge)
            .expect("ok");
        transcript
            .advance(TranscriptStage::ObserveQuotientCommitments)
            .expect("ok");
        transcript
            .advance(TranscriptStage::ObserveRandomizerCommitment)
            .expect("ok");
        // Do NOT absorb degree contract — exact-byte check must fail
        let err = transcript
            .advance(TranscriptStage::SampleOodPoint)
            .unwrap_err();
        assert!(
            matches!(
                err,
                ReferenceTranscriptError::MissingBindingBeforeStage { .. }
            ),
            "expected MissingBindingBeforeStage, got {err:?}"
        );
    }

    #[test]
    fn advance_fails_on_binding_byte_mismatch() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");

        let profile = ReferenceHidingFriPcsProfile::standard();
        let manifest = TranscriptBindingManifest::new()
            .with_before_batching_challenge(profile.to_transcript_binding());

        let mut transcript = ReferenceTranscript::new(&spec, manifest);
        transcript
            .advance(TranscriptStage::ObserveMainCommitments)
            .expect("ok");

        // Absorb a profile binding with WRONG bytes (different log_blowup)
        let mut wrong_profile = ReferenceHidingFriPcsProfile::standard();
        wrong_profile.log_blowup = 3;
        transcript.record_mut().absorb_bindable(&wrong_profile);

        let err = transcript
            .advance(TranscriptStage::SampleBatchingChallenge)
            .unwrap_err();
        assert!(
            matches!(
                err,
                ReferenceTranscriptError::MissingBindingBeforeStage { .. }
            ),
            "expected MissingBindingBeforeStage on byte mismatch, got {err:?}"
        );
    }

    #[test]
    fn advance_passes_when_exact_binding_is_absorbed() {
        let shape = BatchOpeningShape::new(4, 1, 2).expect("valid shape");
        let spec = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");

        let profile = ReferenceHidingFriPcsProfile::standard();
        let manifest = TranscriptBindingManifest::new()
            .with_before_batching_challenge(profile.to_transcript_binding());

        let mut transcript = ReferenceTranscript::new(&spec, manifest);
        transcript
            .advance(TranscriptStage::ObserveMainCommitments)
            .expect("ok");

        // Absorb the correct binding
        transcript.record_mut().absorb_bindable(&profile);

        transcript
            .advance(TranscriptStage::SampleBatchingChallenge)
            .expect("exact binding should satisfy the gate");
    }

    #[test]
    fn finish_requires_recorded_sampling_challenges() {
        let fixture = standard_manifest_fixture();
        let manifest = standard_manifest_from_fixture(&fixture);
        let mut transcript = ReferenceTranscript::new(&fixture.batch_spec, manifest.into_inner());
        transcript
            .record_mut()
            .absorb_bindable(&fixture.hash_identifier);
        transcript.record_mut().absorb_bindable(&fixture.profile);
        transcript.record_mut().absorb_bindable(&fixture.basis);
        transcript.record_mut().absorb_bindable(&fixture.batch_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.codeword_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.oracle_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.projection_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.quotient_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.batch_spec.security_level());
        transcript
            .record_mut()
            .absorb_bindable(&fixture.degree_contract);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.randomizer_commitment);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.public_openings);

        for stage in fixture.batch_spec.transcript_plan().stages() {
            transcript.advance(*stage).expect("stage should advance");
        }

        assert!(matches!(
            transcript.finish(&fixture.deriver),
            Err(ReferenceTranscriptError::MissingSampledChallenge {
                stage: TranscriptStage::SampleBatchingChallenge
            })
        ));
    }

    #[test]
    fn finish_replays_recorded_challenges() {
        let fixture = standard_manifest_fixture();
        let manifest = standard_manifest_from_fixture(&fixture);
        let mut transcript = ReferenceTranscript::new(&fixture.batch_spec, manifest.into_inner());
        transcript
            .record_mut()
            .absorb_bindable(&fixture.hash_identifier);
        transcript.record_mut().absorb_bindable(&fixture.profile);
        transcript.record_mut().absorb_bindable(&fixture.basis);
        transcript.record_mut().absorb_bindable(&fixture.batch_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.codeword_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.oracle_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.projection_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.quotient_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.batch_spec.security_level());

        transcript
            .advance(TranscriptStage::ObserveMainCommitments)
            .expect("observe main");
        transcript
            .sample_challenge(TranscriptStage::SampleBatchingChallenge, &fixture.deriver)
            .expect("batching challenge");
        transcript
            .advance(TranscriptStage::ObserveQuotientCommitments)
            .expect("observe quotient");
        transcript
            .advance(TranscriptStage::ObserveRandomizerCommitment)
            .expect("observe randomizer");
        transcript
            .record_mut()
            .absorb_bindable(&fixture.degree_contract);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.randomizer_commitment);
        transcript
            .sample_challenge(TranscriptStage::SampleOodPoint, &fixture.deriver)
            .expect("ood challenge");
        transcript
            .advance(TranscriptStage::ObservePublicOpenings)
            .expect("observe openings");
        transcript
            .record_mut()
            .absorb_bindable(&fixture.public_openings);
        transcript
            .advance(TranscriptStage::ProveMaskedRelation)
            .expect("prove masked");

        assert!(transcript.finish(&fixture.deriver).is_ok());
    }

    #[test]
    fn replay_rejects_wrong_hash_identifier() {
        let fixture = standard_manifest_fixture();
        let manifest = standard_manifest_from_fixture(&fixture);
        let mut transcript = ReferenceTranscript::new(&fixture.batch_spec, manifest.into_inner());
        transcript
            .record_mut()
            .absorb_bindable(&fixture.hash_identifier);
        transcript.record_mut().absorb_bindable(&fixture.profile);
        transcript.record_mut().absorb_bindable(&fixture.basis);
        transcript.record_mut().absorb_bindable(&fixture.batch_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.codeword_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.oracle_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.projection_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.quotient_spec);
        transcript
            .record_mut()
            .absorb_bindable(&fixture.batch_spec.security_level());
        transcript
            .advance(TranscriptStage::ObserveMainCommitments)
            .expect("observe main");
        transcript
            .sample_challenge(TranscriptStage::SampleBatchingChallenge, &fixture.deriver)
            .expect("batching challenge");

        let wrong_deriver =
            ReferenceChallengeDeriver::new(HashIdentifier::new("wrong-transcript-suite"));
        assert_eq!(
            transcript.replay_challenges(&wrong_deriver),
            Err(ReferenceTranscriptError::ChallengeReplayMismatch {
                stage: TranscriptStage::SampleBatchingChallenge,
            })
        );
    }

    // ── Exact-bytes validation tests ─────────────────────────────────────────────

    #[test]
    fn assert_exact_present_rejects_wrong_bytes_for_same_label() {
        let mut record = ReferenceBindingRecord::new();
        // Absorb a basis binding with wrong bytes (degree 2 instead of 4)
        record.absorb_bindable(&BasisDescriptor::plonky3_binomial(2));
        // Expect degree-4 binding
        let expected = BasisDescriptor::plonky3_binomial(4).to_transcript_binding();
        assert_eq!(
            record.assert_exact_present(&[expected]),
            Err(TranscriptBindingError::BindingMismatch {
                domain_label: DOMAIN_BASIS.to_string(),
            })
        );
    }

    #[test]
    fn assert_exact_present_accepts_matching_bytes() {
        let mut record = ReferenceBindingRecord::new();
        record.absorb_bindable(&BasisDescriptor::plonky3_binomial(4));
        let expected = BasisDescriptor::plonky3_binomial(4).to_transcript_binding();
        assert!(record.assert_exact_present(&[expected]).is_ok());
    }

    #[test]
    fn assert_exact_present_returns_missing_when_no_binding_for_label() {
        let record = ReferenceBindingRecord::new();
        let expected = BasisDescriptor::plonky3_binomial(4).to_transcript_binding();
        assert_eq!(
            record.assert_exact_present(&[expected]),
            Err(TranscriptBindingError::MissingBinding {
                domain_label: DOMAIN_BASIS.to_string(),
            })
        );
    }

    // ── Profile technique encoding tests ─────────────────────────────────────────

    #[test]
    fn profiles_with_different_techniques_produce_different_bindings() {
        use shroud_core::HidingTechniqueClaim;
        let a = ReferenceHidingFriPcsProfile::standard();
        let mut b = ReferenceHidingFriPcsProfile::standard();
        b.hiding_technique = HidingTechniqueClaim::RandomCodewordInterleaving;
        assert_ne!(a.to_transcript_binding(), b.to_transcript_binding());
    }
}
