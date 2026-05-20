//! Production builder for the live-prove
//! [`Plonky3ReplayHarness`](crate::Plonky3ReplayHarness) input bundle.
//!
//! Composes the structurally-validated byte slices from
//! [`live_extractor`](crate::live_extractor) with the canonical SHROUD
//! protocol-spec bindings and the Plonky3 transcript-order absorption
//! sequence into a [`Plonky3LiveHarnessInput`] — the full
//! `(profile, record, manifest, prefix_events)` tuple a verifier needs
//! to run [`Plonky3ReplayHarness::verify`](crate::Plonky3ReplayHarness::verify).
//!
//! # Two layers of record absorption
//!
//! `ReferenceBindingRecord::finalize` checks **unordered** per-stage
//! exact-byte presence — record absorption order is not the audit's
//! transcript-order invariant; replay against `prefix_events` is. But
//! we still order the record to match Plonky3's actual transcript
//! event order so the audit trail reads correctly:
//!
//! - **(a) Pre-protocol SHROUD config bindings** — hash_identifier,
//!   profile, basis, four protocol specs, security_level,
//!   degree_contract. These bind the deployment configuration before
//!   any prover-controlled byte enters the transcript.
//! - **(b) Plonky3 transcript-order events** —
//!   `log_ext_degree, log_degree, preprocessed_width,
//!   trace_commit, [preprocessed_commit], air_public_values,
//!   quotient_commit, randomizer_commit (between QUOTIENT and ζ),
//!   opened_values, fri_*`.
//! - `public_openings` absorbed at the tail as a SHROUD-canonical
//!   post-zeta binding.
//!
//! # Scope
//!
//! Pre-grind SHROUD-stage events only. Post-zeta Plonky3 slots
//! (`opened_values`, `fri_*`) are filled with caller-supplied
//! placeholder bytes; the manifest expects them and the record
//! absorbs them, so manifest verification passes, but the replay
//! assertion uses `prefix_events` which doesn't extend into the
//! post-zeta region. Phase 3 will extend this to live post-grind data
//! once the clone-pollution issue is closed.

use shroud_batch_opening::ShroudBatchOpeningSpec;
use shroud_codeword_embedding::ShroudCodewordEmbeddingSpec;
use shroud_core::{
    BasisDescriptor, DOMAIN_RANDOMIZER_COMMITMENT, HashIdentifier, PublicOpeningBinding,
    SecurityLevel, StandardBatchOpeningBindings, TranscriptBindable, TranscriptBinding,
    TranscriptBindingManifest,
};
use shroud_opening_projection::ShroudOpeningProjectionSpec;
use shroud_oracle_commitment::ShroudOracleCommitmentSpec;
use shroud_quotient_hider::{QuotientDegreeContract, ShroudQuotientHiderSpec};
use shroud_reference::{ReferenceBindingRecord, ReferenceHidingFriPcsProfile};

use core::fmt;

use crate::extended_bindings::Plonky3UniStarkBindings;
use crate::live_extractor::{
    LiveExtractionError, LiveExtractorShape, LivePreGrindExtraction, extract_pre_grind_slices,
    longest_byte_equivalent_prefix,
};
use crate::recording_challenger::ByteTranscriptEvent;
use crate::replay_harness::{HarnessError, Plonky3ReplayHarness};

// ── Output ───────────────────────────────────────────────────────────────────

/// Everything a [`Plonky3ReplayHarness`](crate::Plonky3ReplayHarness)
/// needs, derived from a live `HidingFriPcs` prove invocation plus
/// configuration. Construct via [`build_pre_grind_harness_input`].
///
/// Owns each field so the caller can borrow them all together when
/// constructing the harness:
///
/// ```ignore
/// let input: Plonky3LiveHarnessInput = build_pre_grind_harness_input(...);
/// let harness = Plonky3ReplayHarness::new(
///     &input.profile,
///     &input.record,
///     &input.manifest,
///     &input.prefix_events,
/// );
/// harness.verify()?;
/// ```
#[derive(Debug)]
pub struct Plonky3LiveHarnessInput {
    /// The pinned-backend hiding profile, owned for harness lifetime.
    pub profile: ReferenceHidingFriPcsProfile,
    /// Record absorbed in pre-protocol-config + Plonky3-transcript order.
    pub record: ReferenceBindingRecord,
    /// Composed manifest = canonical SHROUD ⊕ Plonky3-extended slots.
    pub manifest: TranscriptBindingManifest,
    /// Live pre-grind recorder events (caller-trimmed to the clean
    /// pre-grind prefix via
    /// [`longest_byte_equivalent_prefix`](crate::live_extractor::longest_byte_equivalent_prefix)).
    pub prefix_events: Vec<ByteTranscriptEvent>,
}

// ── Config ───────────────────────────────────────────────────────────────────

/// Inputs to the builder that do NOT come from live recorder bytes:
/// SHROUD protocol specs, the hash-suite identifier, the post-zeta
/// Plonky3 slot placeholders.
///
/// Held as references so the builder doesn't take ownership of large
/// protocol-spec structs — callers typically build these once at
/// startup and reuse them.
pub struct Plonky3LiveHarnessConfig<'a> {
    /// Canonical Plonky3 hash-suite identifier (build via
    /// [`Plonky3HashIdentifier::standard`](crate::Plonky3HashIdentifier::standard)).
    pub hash_identifier: &'a HashIdentifier,
    /// Backend-pinned hiding profile.
    pub profile: &'a ReferenceHidingFriPcsProfile,
    /// Basis descriptor binding the field embedding.
    pub basis: &'a BasisDescriptor,
    /// Batch-opening spec.
    pub batch_spec: &'a ShroudBatchOpeningSpec,
    /// Codeword-embedding spec.
    pub codeword_spec: &'a ShroudCodewordEmbeddingSpec,
    /// Oracle-commitment spec.
    pub oracle_spec: &'a ShroudOracleCommitmentSpec,
    /// Opening-projection spec.
    pub projection_spec: &'a ShroudOpeningProjectionSpec,
    /// Quotient-hider spec.
    pub quotient_spec: &'a ShroudQuotientHiderSpec,
    /// Statistical / perfect security level for the canonical bindings.
    pub security_level: &'a SecurityLevel,
    /// Quotient degree contract (HK relation).
    pub degree_contract: &'a QuotientDegreeContract,
    /// Public-openings binding (post-zeta, canonical SHROUD).
    pub public_openings: &'a PublicOpeningBinding,
    /// Placeholder bytes for the post-zeta `opened_values` slot.
    pub opened_values: Vec<u8>,
    /// Placeholder bytes for the `fri_commit_phase_commitments` slot.
    pub fri_commit_phase_commitments: Vec<u8>,
    /// Placeholder bytes for the `fri_final_poly` slot.
    pub fri_final_poly: Vec<u8>,
    /// Placeholder bytes for the `fri_log_arities` slot.
    pub fri_log_arities: Vec<u8>,
}

// ── Private bindable wrapper ─────────────────────────────────────────────────

/// Wraps raw bytes (with a fixed domain label) into a
/// [`TranscriptBindable`] so they can be slotted into
/// [`StandardBatchOpeningBindings::from_bindables`].
///
/// Private to this module; the builder is the only caller. Equivalent
/// in spirit to the test helper that lived in the negative-battery
/// file, but encapsulated here so downstream callers don't reach into
/// internals.
struct RawBindable(TranscriptBinding);

impl TranscriptBindable for RawBindable {
    fn to_transcript_binding(&self) -> TranscriptBinding {
        self.0.clone()
    }
}

// ── Builder ──────────────────────────────────────────────────────────────────

/// Build a [`Plonky3LiveHarnessInput`] from a live pre-grind
/// extraction, the SHROUD/Plonky3 config bundle, and the live recorder
/// events.
///
/// `prefix_events` should already be trimmed to the longest
/// byte-equivalent prefix via
/// [`longest_byte_equivalent_prefix`](crate::live_extractor::longest_byte_equivalent_prefix)
/// (grind clone-pollution workaround). The builder doesn't re-validate
/// the events; trust the extractor for shape, the prefix helper for
/// replay-cleanness.
///
/// The returned `record` absorbs bindings in the order documented in
/// the module-level docs (pre-protocol config + Plonky3 transcript
/// order + post-zeta tail). The returned `manifest` is the composed
/// canonical-SHROUD ⊕ Plonky3-extended manifest.
pub fn build_pre_grind_harness_input(
    extraction: &LivePreGrindExtraction,
    prefix_events: Vec<ByteTranscriptEvent>,
    config: &Plonky3LiveHarnessConfig<'_>,
) -> Plonky3LiveHarnessInput {
    // 1. Build Plonky3UniStarkBindings. Pre-zeta slots carry live
    //    bytes (including the optional `preprocessed_commit` and the
    //    live `air_public_values`); post-zeta slots carry
    //    caller-supplied placeholders.
    let bindings = {
        let base = Plonky3UniStarkBindings::new(
            extraction.log_ext_degree.clone(),
            extraction.log_degree.clone(),
            extraction.preprocessed_width.clone(),
            extraction.trace_commit.clone(),
            extraction.air_public_values.clone(),
            extraction.quotient_commit.clone(),
            config.opened_values.clone(),
            config.fri_commit_phase_commitments.clone(),
            config.fri_final_poly.clone(),
            config.fri_log_arities.clone(),
        );
        // Attach the preprocessed-commit binding when the AIR has
        // preprocessed columns (extractor returned `Some(_)`); skip
        // otherwise so the manifest/record stay AIR-shape-faithful.
        match &extraction.preprocessed_commit {
            Some(bytes) => base.with_preprocessed_commitment(bytes.clone()),
            None => base,
        }
    };

    // 2. The canonical SHROUD `DOMAIN_RANDOMIZER_COMMITMENT` binding
    //    carries LIVE randomizer-commit bytes from the extractor.
    let randomizer = RawBindable(TranscriptBinding::new(
        DOMAIN_RANDOMIZER_COMMITMENT,
        extraction.randomizer_commit.clone(),
    ));

    // 3. Compose StandardBatchOpeningBindings from the SHROUD-canonical
    //    spec inputs, then fold in the Plonky3-extended manifest.
    let standard = StandardBatchOpeningBindings::from_bindables(
        config.hash_identifier,
        config.profile,
        config.basis,
        config.batch_spec,
        config.codeword_spec,
        config.oracle_spec,
        config.projection_spec,
        config.quotient_spec,
        config.security_level,
        config.degree_contract,
        &randomizer,
        config.public_openings,
    );
    let manifest = bindings.clone().into_manifest(standard);

    // 4. Build record in transcript order (see module docs for the
    //    two-layer ordering rationale).
    let mut record = ReferenceBindingRecord::new();

    // (a) Pre-protocol SHROUD config bindings.
    record.absorb_bindable(config.hash_identifier);
    record.absorb_bindable(config.profile);
    record.absorb_bindable(config.basis);
    record.absorb_bindable(config.batch_spec);
    record.absorb_bindable(config.codeword_spec);
    record.absorb_bindable(config.oracle_spec);
    record.absorb_bindable(config.projection_spec);
    record.absorb_bindable(config.quotient_spec);
    record.absorb_bindable(config.security_level);
    record.absorb_bindable(config.degree_contract);

    // (b) Plonky3 transcript-order absorption.
    record.absorb_live(bindings.log_ext_degree().clone());
    record.absorb_live(bindings.log_degree().clone());
    record.absorb_live(bindings.preprocessed_width().clone());
    record.absorb_live(bindings.trace_commitment().clone());
    if let Some(pre) = bindings.preprocessed_commitment() {
        record.absorb_live(pre.clone());
    }
    record.absorb_live(bindings.air_public_values().clone());
    // (sample α — no observed bytes between trace_commit and
    //  quotient_commit)
    record.absorb_live(bindings.quotient_commitment().clone());
    // DOMAIN_RANDOMIZER_COMMITMENT slots HERE — between QUOTIENT and ζ
    // — matching Plonky3 event 9 (ZK-only).
    record.absorb_bindable_with_source(&randomizer, shroud_core::TranscriptBindingSource::Live);
    // (sample ζ — no observed bytes between randomizer_commit and
    //  opened_values)
    record.absorb_placeholder(bindings.opened_values().clone());
    record.absorb_placeholder(bindings.fri_commit_phase_commitments().clone());
    record.absorb_placeholder(bindings.fri_final_poly().clone());
    record.absorb_placeholder(bindings.fri_log_arities().clone());

    // public_openings: SHROUD-canonical post-zeta binding. This is
    // placeholder-sourced until post-zeta extraction can derive it from live
    // opened-values bytes.
    record.absorb_bindable_with_source(
        config.public_openings,
        shroud_core::TranscriptBindingSource::Placeholder,
    );

    Plonky3LiveHarnessInput {
        profile: config.profile.clone(),
        record,
        manifest,
        prefix_events,
    }
}

// ── Facade ───────────────────────────────────────────────────────────────────

/// Combined error reported by [`verify_pre_grind_bridge`]. Flattens
/// the two failure surfaces a downstream caller would otherwise have
/// to handle separately:
///
/// - [`Self::Extraction`] — the structural walker rejected the live
///   recorder events (truncated log, sampled-inside-observe-block,
///   overshoot, missing challenge sample). The recorder did not
///   produce a SHROUD-stage-shaped prefix; the bridge cannot proceed.
/// - [`Self::Harness`] — the harness invariants failed against the
///   composed bindings (provenance gate, manifest exact-presence,
///   byte-equivalence replay). Carries the [`HarnessError`] for
///   programmatic dispatch.
#[derive(Debug)]
pub enum PreGrindBridgeError {
    /// The live extractor rejected the recorder events.
    Extraction(LiveExtractionError),
    /// The replay harness rejected the composed bindings.
    Harness(HarnessError),
}

impl fmt::Display for PreGrindBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Extraction(e) => write!(f, "[pre_grind_bridge] {e}"),
            Self::Harness(e) => write!(f, "[pre_grind_bridge] {e}"),
        }
    }
}

impl std::error::Error for PreGrindBridgeError {}

impl From<LiveExtractionError> for PreGrindBridgeError {
    fn from(e: LiveExtractionError) -> Self {
        Self::Extraction(e)
    }
}

impl From<HarnessError> for PreGrindBridgeError {
    fn from(e: HarnessError) -> Self {
        Self::Harness(e)
    }
}

/// End-to-end pre-grind bridge verifier — the stable public entry
/// point for downstream callers.
///
/// Given the raw recorder event log from a live `HidingFriPcs`
/// prove invocation, the deployment's [`LiveExtractorShape`], and a
/// [`Plonky3LiveHarnessConfig`] carrying the SHROUD protocol-spec
/// bindings + post-zeta placeholders, this function:
///
/// 1. trims the events to the longest replay-clean prefix via
///    [`longest_byte_equivalent_prefix`] (grind clone-pollution
///    workaround);
/// 2. extracts the named SHROUD-stage byte slices via
///    [`extract_pre_grind_slices`];
/// 3. composes the harness input via
///    [`build_pre_grind_harness_input`];
/// 4. verifies the three [`Plonky3ReplayHarness`] invariants
///    (provenance → manifest → byte-equivalence replay).
///
/// All four steps run fail-fast; the first failing layer determines
/// the returned [`PreGrindBridgeError`] variant.
///
/// # Scope
///
/// See `docs/plonky3-bridge-status.md` for the frozen list of what is
/// supported / placeholder / deferred. The facade does NOT cover
/// post-grind PCS-internal events (opened values, FRI commit phase,
/// final poly, log arities).
///
/// # Example
///
/// ```ignore
/// use shroud_plonky3::{
///     verify_pre_grind_bridge, LiveExtractorShape, Plonky3LiveHarnessConfig,
/// };
///
/// let events = recorder.events();
/// verify_pre_grind_bridge(&events, &LiveExtractorShape::standard(), &config)?;
/// ```
pub fn verify_pre_grind_bridge(
    events: &[ByteTranscriptEvent],
    shape: &LiveExtractorShape,
    config: &Plonky3LiveHarnessConfig<'_>,
) -> Result<(), PreGrindBridgeError> {
    let longest = longest_byte_equivalent_prefix(events);
    let prefix_events: Vec<ByteTranscriptEvent> = events[..longest].to_vec();

    let extraction = extract_pre_grind_slices(&prefix_events, shape)?;
    let input = build_pre_grind_harness_input(&extraction, prefix_events, config);

    Plonky3ReplayHarness::new(
        &input.profile,
        &input.record,
        &input.manifest,
        &input.prefix_events,
    )
    .verify()?;

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Plonky3HashIdentifier;
    use shroud_batch_opening::BatchOpeningShape;
    use shroud_codeword_embedding::CodewordEmbeddingShape;
    use shroud_core::{TranscriptBindingError, TranscriptBindingSource};
    use shroud_opening_projection::{AuxiliaryOpeningTransport, OpeningProjectionShape};
    use shroud_oracle_commitment::{OracleAuxiliaryTransport, OracleCommitmentShape};
    use shroud_quotient_hider::{
        QuotientAuxiliaryTransport, QuotientDecompositionFamily, QuotientHiderShape,
    };

    /// Smoke test: build_pre_grind_harness_input with synthetic
    /// extraction bytes produces a record containing every expected
    /// domain label, and the manifest's standard-canonical labels are
    /// present.
    #[test]
    fn builder_produces_record_with_all_expected_labels() {
        let extraction = LivePreGrindExtraction {
            log_ext_degree: vec![0x01; 4],
            log_degree: vec![0x02; 4],
            preprocessed_width: vec![0x03; 4],
            trace_commit: vec![0x04; 32],
            preprocessed_commit: None,
            air_public_values: Vec::new(),
            quotient_commit: vec![0x05; 32],
            randomizer_commit: vec![0x06; 32],
        };

        let hash_identifier = Plonky3HashIdentifier::standard().to_hash_identifier();
        let profile = ReferenceHidingFriPcsProfile::standard();
        let basis = BasisDescriptor::plonky3_binomial(4);
        let batch_spec = ShroudBatchOpeningSpec::statistical(
            BatchOpeningShape::new(4, 1, 2).expect("valid"),
            15,
        )
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
        let degree_contract =
            QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid");
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

        let input = build_pre_grind_harness_input(&extraction, Vec::new(), &config);

        // Manifest exact-presence covers every expected label.
        input
            .record
            .finalize(&input.manifest)
            .expect("manifest finalize must succeed for well-formed builder output");

        // Record absorbs DOMAIN_PLONKY3_QUOTIENT_COMMITMENT before
        // DOMAIN_RANDOMIZER_COMMITMENT (Plonky3 transcript order).
        let labels: Vec<&str> = input
            .record
            .absorbed()
            .iter()
            .map(|b| b.domain_label())
            .collect();
        let q_pos = labels
            .iter()
            .position(|l| *l == crate::DOMAIN_PLONKY3_QUOTIENT_COMMITMENT)
            .expect("quotient commit absorbed");
        let r_pos = labels
            .iter()
            .position(|l| *l == DOMAIN_RANDOMIZER_COMMITMENT)
            .expect("randomizer commit absorbed");
        let opened_values_pos = labels
            .iter()
            .position(|l| *l == crate::DOMAIN_PLONKY3_OPENED_VALUES)
            .expect("opened-values placeholder absorbed");
        assert!(
            q_pos < r_pos,
            "Plonky3 transcript order: QUOTIENT_COMMITMENT must precede \
             RANDOMIZER_COMMITMENT in the absorbed record (got q={q_pos}, r={r_pos})"
        );
        assert_eq!(input.record.source_at(q_pos), TranscriptBindingSource::Live);
        assert_eq!(input.record.source_at(r_pos), TranscriptBindingSource::Live);
        assert_eq!(
            input.record.source_at(opened_values_pos),
            TranscriptBindingSource::Placeholder
        );
        assert!(input.record.contains_placeholder_binding());
        assert_eq!(
            input.record.assert_no_placeholder_bindings(),
            Err(TranscriptBindingError::PlaceholderBinding {
                domain_label: crate::DOMAIN_PLONKY3_OPENED_VALUES.to_string(),
            })
        );

        // No preprocessed_commit field on the extraction → the
        // manifest and record must NOT carry that label.
        assert!(
            !labels.contains(&crate::DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT),
            "extraction.preprocessed_commit = None must produce a record \
             without DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT"
        );
    }

    /// When the extraction carries `preprocessed_commit: Some(_)`, the
    /// builder must wire it into `Plonky3UniStarkBindings` via
    /// `with_preprocessed_commitment`, so both manifest and record
    /// carry `DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT` with the live
    /// bytes — closing the P2 finding from the second review pass.
    #[test]
    fn builder_wires_preprocessed_commit_when_present() {
        let extraction = LivePreGrindExtraction {
            log_ext_degree: vec![0x01; 4],
            log_degree: vec![0x02; 4],
            preprocessed_width: vec![0x03; 4],
            trace_commit: vec![0x04; 32],
            preprocessed_commit: Some(vec![0x77; 32]),
            air_public_values: Vec::new(),
            quotient_commit: vec![0x05; 32],
            randomizer_commit: vec![0x06; 32],
        };

        let hash_identifier = Plonky3HashIdentifier::standard().to_hash_identifier();
        let profile = ReferenceHidingFriPcsProfile::standard();
        let basis = BasisDescriptor::plonky3_binomial(4);
        let batch_spec = ShroudBatchOpeningSpec::statistical(
            BatchOpeningShape::new(4, 1, 2).expect("valid"),
            15,
        )
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
        let degree_contract =
            QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid");
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

        let input = build_pre_grind_harness_input(&extraction, Vec::new(), &config);

        // Manifest finalize covers the preprocessed-commit binding
        // when present — if the builder forgot to wire it, the
        // manifest would either omit it (and this assertion vacuously
        // passes) or expect it but the record wouldn't carry it
        // (failing finalize). The next assertion locks the record
        // side directly.
        input
            .record
            .finalize(&input.manifest)
            .expect("preprocessed-commit-bearing record must finalize");

        // The record carries DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT
        // with the live bytes (0x77 × 32) — locking the wiring.
        let absorbed = input.record.absorbed();
        let pp_binding = absorbed
            .iter()
            .find(|b| b.domain_label() == crate::DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT)
            .expect(
                "extraction.preprocessed_commit = Some must produce a record entry \
                 for DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT",
            );
        assert_eq!(pp_binding.canonical_bytes(), &[0x77u8; 32][..]);
    }

    // ── Facade error-flattening ──────────────────────────────────────────────

    /// The facade must surface a `LiveExtractionError` as the
    /// `Extraction` variant of `PreGrindBridgeError`. We use an
    /// obviously-malformed (empty) event log: the extractor's first
    /// call fails with `TruncatedLog { reading: "log_ext_degree" }`,
    /// and the facade must wrap-and-return that without ever
    /// reaching the harness layer.
    #[test]
    fn facade_surfaces_extraction_error_for_empty_events() {
        let hash_identifier = Plonky3HashIdentifier::standard().to_hash_identifier();
        let profile = ReferenceHidingFriPcsProfile::standard();
        let basis = BasisDescriptor::plonky3_binomial(4);
        let batch_spec = ShroudBatchOpeningSpec::statistical(
            BatchOpeningShape::new(4, 1, 2).expect("valid"),
            15,
        )
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
        let degree_contract =
            QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid");
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

        let err =
            verify_pre_grind_bridge(&[], &LiveExtractorShape::standard(), &config).unwrap_err();
        assert!(
            matches!(
                err,
                PreGrindBridgeError::Extraction(LiveExtractionError::TruncatedLog {
                    reading: "log_ext_degree",
                    ..
                })
            ),
            "expected Extraction(TruncatedLog(log_ext_degree)), got {err:?}"
        );
    }
}
