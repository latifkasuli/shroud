#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Rust conformance fixtures for the Lean-normative SHROUD protocol model.
//!
//! This crate intentionally contains fixed, representative examples rather than
//! property tests. Each fixture mirrors a theorem-backed Lean law or a reviewed
//! bridge boundary, so small Rust/Lean drift is caught by stable examples with
//! clear failure messages.

#[cfg(test)]
mod tests {
    use shroud_batch_opening::{
        BatchOpeningShape, BatchOpeningSpecError, HiddenOpeningTransport,
        PerfectHiddenOpeningPayload, PerfectRandomizerCommitment, ProofSlotLayout,
        RandomizerOpeningPayload, RandomizerSpec, ShroudBatchOpeningSpec,
    };
    use shroud_codeword_embedding::{CodewordEmbeddingShape, ShroudCodewordEmbeddingSpec};
    use shroud_core::{
        BackendClaim, BasisDescriptor, ClaimScope, DOMAIN_BASIS, DOMAIN_BATCH_OPENING,
        DOMAIN_CODEWORD_EMBEDDING, DOMAIN_DEGREE_CONTRACT, DOMAIN_HASH_ID,
        DOMAIN_OPENING_PROJECTION, DOMAIN_ORACLE_COMMITMENT, DOMAIN_PROFILE,
        DOMAIN_PUBLIC_OPENINGS, DOMAIN_QUOTIENT_HIDER, DOMAIN_RANDOMIZER_COMMITMENT,
        DOMAIN_SECURITY_LEVEL, FieldModel, HashIdentifier, PerfectClaim, PublicOpeningBinding,
        RandomnessModel, SecurityLevel, SimulatorObligations, StandardBatchOpeningBindings,
        TranscriptBindable, TranscriptBinding, TranscriptBindingManifest, TranscriptBindingSource,
        TranscriptStage, UpstreamCitation,
    };
    use shroud_opening_projection::{
        AuxiliaryOpeningTransport, OpeningProjectionShape, ShroudOpeningProjectionSpec,
    };
    use shroud_oracle_commitment::{
        OracleAuxiliaryTransport, OracleCommitmentShape, ShroudOracleCommitmentSpec,
    };
    use shroud_plonky3::{
        ByteTranscriptEvent, DOMAIN_PLONKY3_AIR_PUBLIC_VALUES,
        DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS, DOMAIN_PLONKY3_FRI_FINAL_POLY,
        DOMAIN_PLONKY3_FRI_LOG_ARITIES, DOMAIN_PLONKY3_LOG_DEGREE, DOMAIN_PLONKY3_LOG_EXT_DEGREE,
        DOMAIN_PLONKY3_OPENED_VALUES, DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT,
        DOMAIN_PLONKY3_PREPROCESSED_WIDTH, DOMAIN_PLONKY3_QUOTIENT_COMMITMENT,
        DOMAIN_PLONKY3_TRACE_COMMITMENT, LiveExtractorShape, LivePreGrindExtraction,
        Plonky3LiveHarnessConfig, PreGrindBridgeError, build_pre_grind_harness_input,
        extract_pre_grind_slices, verify_pre_grind_bridge, verify_pre_grind_bridge_into_verified,
    };
    use shroud_quotient_hider::{
        QuotientAuxiliaryTransport, QuotientDecompositionFamily, QuotientDegreeContract,
        QuotientHiderError, QuotientHiderShape, ShroudQuotientHiderSpec,
    };
    use shroud_reference::{ReferenceBindingRecord, ReferenceHidingFriPcsProfile};

    struct RawBindable(TranscriptBinding);

    impl TranscriptBindable for RawBindable {
        fn to_transcript_binding(&self) -> TranscriptBinding {
            self.0.clone()
        }
    }

    struct StandardFixture {
        hash_identifier: HashIdentifier,
        profile: ReferenceHidingFriPcsProfile,
        basis: BasisDescriptor,
        batch_spec: ShroudBatchOpeningSpec,
        codeword_spec: ShroudCodewordEmbeddingSpec,
        oracle_spec: ShroudOracleCommitmentSpec,
        projection_spec: ShroudOpeningProjectionSpec,
        quotient_spec: ShroudQuotientHiderSpec,
        degree_contract: QuotientDegreeContract,
        randomizer_commitment: RawBindable,
        public_openings: PublicOpeningBinding,
    }

    fn encoded_claim(extension_degree: usize, query_budget: usize) -> PerfectClaim {
        PerfectClaim::new(
            RandomnessModel::UniformPerProof,
            FieldModel::EncodedCoordinates {
                basis: BasisDescriptor::plonky3_binomial(extension_degree),
            },
            query_budget,
            SimulatorObligations::HonestVerifierChallengeAccess,
            true,
        )
        .expect("valid encoded perfect claim")
    }

    fn native_claim(extension_degree: usize, query_budget: usize) -> PerfectClaim {
        PerfectClaim::new(
            RandomnessModel::UniformPerProof,
            FieldModel::NativeExtension { extension_degree },
            query_budget,
            SimulatorObligations::HonestVerifierChallengeAccess,
            true,
        )
        .expect("valid native perfect claim")
    }

    fn standard_fixture() -> StandardFixture {
        let basis = BasisDescriptor::plonky3_binomial(4);
        let batch_shape = BatchOpeningShape::new(6, 2, 4).expect("valid batch shape");
        let degree_contract =
            QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid contract");

        StandardFixture {
            hash_identifier: HashIdentifier::new("shroud-conformance-suite"),
            profile: ReferenceHidingFriPcsProfile::standard(),
            basis,
            batch_spec: ShroudBatchOpeningSpec::statistical(batch_shape, 15)
                .expect("valid batch spec"),
            codeword_spec: ShroudCodewordEmbeddingSpec::statistical(
                CodewordEmbeddingShape::new(64, 4, 18, 4).expect("valid codeword shape"),
            )
            .expect("valid codeword spec"),
            oracle_spec: ShroudOracleCommitmentSpec::statistical(
                OracleCommitmentShape::new(2, 3, 4, 5, 6).expect("valid oracle shape"),
                OracleAuxiliaryTransport::InBandWithOpeningProof,
            )
            .expect("valid oracle spec"),
            projection_spec: ShroudOpeningProjectionSpec::statistical(
                OpeningProjectionShape::new(3, 5, 2).expect("valid projection shape"),
                AuxiliaryOpeningTransport::InBandWithMainProof,
            )
            .expect("valid projection spec"),
            quotient_spec: ShroudQuotientHiderSpec::statistical(
                QuotientDecompositionFamily::DegreeChunked,
                8,
                QuotientHiderShape::new(3, 2, 4, 3, 2).expect("valid quotient shape"),
                QuotientAuxiliaryTransport::InBandWithOpeningProof,
                Some(degree_contract),
            )
            .expect("valid quotient spec"),
            degree_contract,
            randomizer_commitment: RawBindable(TranscriptBinding::new(
                DOMAIN_RANDOMIZER_COMMITMENT,
                vec![0xA5; 32],
            )),
            public_openings: PublicOpeningBinding::new(vec![0xC0; 16]),
        }
    }

    fn observed(byte: u8, len: usize) -> ByteTranscriptEvent {
        ByteTranscriptEvent::Observed(vec![byte; len])
    }

    fn sampled(byte: u8, len: usize) -> ByteTranscriptEvent {
        ByteTranscriptEvent::Sampled(vec![byte; len])
    }

    fn pre_grind_events(
        has_preprocessed_commitment: bool,
        air_public_values_bytes: usize,
        split_samples: bool,
    ) -> Vec<ByteTranscriptEvent> {
        let mut events = vec![
            observed(0x01, 4),
            observed(0x02, 4),
            observed(0x03, 4),
            observed(0x04, 32),
        ];
        if has_preprocessed_commitment {
            events.push(observed(0x05, 32));
        }
        if air_public_values_bytes > 0 {
            events.push(observed(0x06, air_public_values_bytes));
        }
        if split_samples {
            events.push(sampled(0xA0, 16));
            events.push(sampled(0xA1, 16));
        } else {
            events.push(sampled(0xA0, 32));
        }
        events.push(observed(0x08, 32));
        events.push(observed(0x09, 32));
        if split_samples {
            events.push(sampled(0xB0, 8));
            events.push(sampled(0xB1, 8));
        } else {
            events.push(sampled(0xB0, 16));
        }
        events
    }

    fn assert_pre_grind_extraction_shape(
        has_preprocessed_commitment: bool,
        air_public_values_bytes: usize,
        split_samples: bool,
    ) {
        let shape = LiveExtractorShape {
            preprocessed_commit_bytes: has_preprocessed_commitment.then_some(32),
            air_public_values_bytes,
            ..LiveExtractorShape::standard()
        };
        let extraction = extract_pre_grind_slices(
            &pre_grind_events(
                has_preprocessed_commitment,
                air_public_values_bytes,
                split_samples,
            ),
            &shape,
        )
        .expect("shape-specific pre-grind extraction must succeed");

        assert_eq!(extraction.log_ext_degree, vec![0x01; 4]);
        assert_eq!(extraction.log_degree, vec![0x02; 4]);
        assert_eq!(extraction.preprocessed_width, vec![0x03; 4]);
        assert_eq!(extraction.trace_commit, vec![0x04; 32]);
        assert_eq!(
            extraction.preprocessed_commit,
            has_preprocessed_commitment.then(|| vec![0x05; 32])
        );
        assert_eq!(
            extraction.air_public_values,
            vec![0x06; air_public_values_bytes]
        );
        assert_eq!(extraction.quotient_commit, vec![0x08; 32]);
        assert_eq!(extraction.randomizer_commit, vec![0x09; 32]);
    }

    fn canonical_manifest_fixture() -> (shroud_core::CanonicalBatchOpeningManifest, StandardFixture)
    {
        let fixture = standard_fixture();
        let manifest = TranscriptBindingManifest::standard_for_batch_opening(
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
        );
        (manifest, fixture)
    }

    #[test]
    fn canonical_stage_order_fixture_matches_lean_schedule_model() {
        // Mirrors `canonicalBatchOpeningSchedule` and its required-before bucket
        // facts in `formal/Shroud/Core/Binding.lean`.
        let (manifest, _) = canonical_manifest_fixture();

        let labels_for = |stage| {
            manifest
                .required_before(stage)
                .iter()
                .map(TranscriptBinding::domain_label)
                .collect::<Vec<_>>()
        };

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
        assert_eq!(
            labels_for(TranscriptStage::SampleOodPoint),
            vec![DOMAIN_DEGREE_CONTRACT, DOMAIN_RANDOMIZER_COMMITMENT]
        );
        assert_eq!(
            labels_for(TranscriptStage::ProveMaskedRelation),
            vec![DOMAIN_PUBLIC_OPENINGS]
        );
    }

    #[test]
    fn canonical_manifest_fixture_finalizes_with_complete_record() {
        // Exercises the Rust executable counterpart of Lean's canonical
        // manifest completeness theorem.
        let (manifest, fixture) = canonical_manifest_fixture();
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

        record
            .finalize_canonical(&manifest)
            .expect("canonical record must satisfy canonical manifest");
    }

    #[test]
    fn codeword_embedding_payload_fixture_matches_lean_accounting() {
        // Mirrors the `CodewordEmbeddingPayload.fromShape_*` theorems and
        // `ShroudCodewordEmbeddingSpec.Valid` equalities.
        let shape = CodewordEmbeddingShape::new(64, 4, 18, 4).expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");
        let payload = spec.payload();

        assert_eq!(spec.security_level(), SecurityLevel::Statistical);
        assert_eq!(shape.committed_columns(), 68);
        assert_eq!(payload.committed_columns(), 64 + 4);
        assert_eq!(payload.public_trace_columns(), 64);
        assert_eq!(payload.hidden_randomizer_columns(), 4);
        assert_eq!(payload.domain_log_size(), 18);
        assert_eq!(payload.required_log_blowup(), 2);

        assert!(
            ShroudCodewordEmbeddingSpec::statistical(
                CodewordEmbeddingShape::new(64, 3, 18, 4)
                    .expect("shape allows non-standard randomizer count"),
            )
            .is_err(),
            "Lean Valid requires randomizerColumns = extensionDegree"
        );
    }

    #[test]
    fn batch_opening_payload_fixture_matches_lean_accounting() {
        // Mirrors the statistical and perfect randomizer payload theorems in
        // `formal/Shroud/Objects/BatchOpening.lean`.
        let shape = BatchOpeningShape::new(6, 3, 4).expect("valid shape");
        let statistical = ShroudBatchOpeningSpec::statistical(shape, 15).expect("valid spec");

        match statistical.randomizer() {
            RandomizerSpec::Statistical(model) => {
                assert_eq!(model.coordinate_polynomials(), shape.extension_degree());
            }
            RandomizerSpec::Perfect(_) => panic!("expected statistical randomizer"),
        }

        match statistical.randomizer_opening_payload() {
            RandomizerOpeningPayload::Statistical(payload) => {
                assert_eq!(payload.public_extension_evaluations(), 3);
                assert_eq!(payload.hidden_base_field_coordinate_evaluations(), 3 * 4);
                assert_eq!(
                    payload.proof_slot_layout(),
                    ProofSlotLayout::ReuseCurrentRandomSlot
                );
                assert_eq!(
                    payload.hidden_opening_transport(),
                    HiddenOpeningTransport::InBandWithMainOpeningProof
                );
            }
            RandomizerOpeningPayload::Perfect(_) => panic!("expected statistical payload"),
        }

        let encoded_commitment = PerfectRandomizerCommitment::encoded_oracle_bundle(
            BasisDescriptor::plonky3_binomial(4),
        );
        let encoded =
            ShroudBatchOpeningSpec::perfect(shape, 15, encoded_commitment, encoded_claim(4, 3))
                .expect("valid encoded perfect spec");
        match encoded.randomizer_opening_payload() {
            RandomizerOpeningPayload::Perfect(payload) => {
                assert_eq!(payload.public_extension_evaluations(), 3);
                assert_eq!(
                    payload.hidden_payload(),
                    PerfectHiddenOpeningPayload::EncodedCoordinates {
                        base_field_coordinate_evaluations: 3 * 4,
                        transport: HiddenOpeningTransport::InBandWithMainOpeningProof,
                    }
                );
                assert_eq!(
                    payload.proof_slot_layout(),
                    ProofSlotLayout::ReuseCurrentRandomSlot
                );
            }
            RandomizerOpeningPayload::Statistical(_) => panic!("expected perfect payload"),
        }

        let native = ShroudBatchOpeningSpec::perfect(
            shape,
            15,
            PerfectRandomizerCommitment::native_extension_pcs(),
            native_claim(4, 3),
        )
        .expect("valid native perfect spec");
        match native.randomizer_opening_payload() {
            RandomizerOpeningPayload::Perfect(payload) => {
                assert_eq!(
                    payload.hidden_payload(),
                    PerfectHiddenOpeningPayload::BackendProofOnly {
                        transport: HiddenOpeningTransport::SeparateAuxiliaryProof,
                    }
                );
                assert_eq!(
                    payload.proof_slot_layout(),
                    ProofSlotLayout::DedicatedPerfectRandomizerSlot
                );
            }
            RandomizerOpeningPayload::Statistical(_) => panic!("expected perfect payload"),
        }
    }

    #[test]
    fn perfect_claim_fixture_rejects_field_model_drift() {
        // Guards the Rust-only API invariant that connects `PerfectClaim` to the
        // concrete realization modeled by Lean's perfect randomizer variants.
        let shape = BatchOpeningShape::new(6, 1, 4).expect("valid shape");
        let encoded_commitment = PerfectRandomizerCommitment::encoded_oracle_bundle(
            BasisDescriptor::plonky3_binomial(4),
        );
        let native = native_claim(4, 1);
        assert_eq!(
            ShroudBatchOpeningSpec::perfect(shape, 15, encoded_commitment, native),
            Err(BatchOpeningSpecError::PerfectClaimFieldModelMismatch {
                claim_field_model: native.field_model,
                realization: encoded_commitment.realization(),
            })
        );

        let native_commitment = PerfectRandomizerCommitment::native_extension_pcs();
        let encoded = encoded_claim(4, 1);
        assert_eq!(
            ShroudBatchOpeningSpec::perfect(shape, 15, native_commitment, encoded),
            Err(BatchOpeningSpecError::PerfectClaimFieldModelMismatch {
                claim_field_model: encoded.field_model,
                realization: native_commitment.realization(),
            })
        );
    }

    #[test]
    fn quotient_degree_and_payload_fixture_matches_lean_accounting() {
        // Mirrors `QuotientDegreeContract.vanishing_valid_iff_required_le_bound`
        // plus `QuotientHiderPayload.fromShape_*`.
        let contract =
            QuotientDegreeContract::with_vanishing_poly(7, 8, 7, 15).expect("valid contract");
        assert_eq!(contract.quotient_chunk_degree(), 7);
        assert_eq!(contract.vanishing_poly_degree(), 8);
        assert_eq!(contract.mask_poly_degree(), 7);
        assert_eq!(contract.randomized_chunk_degree_bound(), 15);
        assert!(!contract.preserves_chunk_degree_class());

        assert_eq!(
            QuotientDegreeContract::with_vanishing_poly(7, 8, 8, 15),
            Err(QuotientHiderError::DegreeContractViolation {
                quotient_chunk_degree: 7,
                vanishing_poly_degree: 8,
                mask_poly_degree: 8,
                randomized_chunk_degree_bound: 15,
                required_degree: 16,
            })
        );

        let shape = QuotientHiderShape::new(3, 2, 4, 3, 2).expect("valid shape");
        let spec = ShroudQuotientHiderSpec::statistical(
            QuotientDecompositionFamily::DegreeChunked,
            8,
            shape,
            QuotientAuxiliaryTransport::InBandWithOpeningProof,
            Some(contract),
        )
        .expect("valid quotient spec");
        let payload = spec.payload();
        assert_eq!(payload.public_commitments(), 3);
        assert_eq!(payload.public_opening_values(), 2 * 4);
        assert_eq!(payload.hidden_mask_values(), 2 * 3);
        assert_eq!(payload.hidden_normalization_items(), 2);

        assert_eq!(
            ShroudQuotientHiderSpec::statistical(
                QuotientDecompositionFamily::DegreeChunked,
                8,
                shape,
                QuotientAuxiliaryTransport::InBandWithOpeningProof,
                None,
            ),
            Err(QuotientHiderError::DegreeChunkedRequiresDegreeContract)
        );
    }

    #[test]
    fn oracle_and_projection_payload_fixtures_match_lean_accounting() {
        // Mirrors the oracle-commitment and opening-projection `fromShape_*`
        // payload laws.
        let oracle_shape = OracleCommitmentShape::new(2, 3, 4, 5, 6).expect("valid oracle shape");
        let oracle = ShroudOracleCommitmentSpec::statistical(
            oracle_shape,
            OracleAuxiliaryTransport::InBandWithOpeningProof,
        )
        .expect("valid oracle spec");
        let oracle_payload = oracle.payload();
        assert_eq!(oracle_payload.public_commitments(), 2);
        assert_eq!(oracle_payload.public_row_values(), 3 * 4);
        assert_eq!(oracle_payload.public_authentication_items(), 3 * 5);
        assert_eq!(oracle_payload.hidden_hiding_witness_items(), 3 * 6);

        let projection_shape = OpeningProjectionShape::new(3, 5, 2).expect("valid shape");
        let projection = ShroudOpeningProjectionSpec::statistical(
            projection_shape,
            AuxiliaryOpeningTransport::InBandWithMainProof,
        )
        .expect("valid projection spec");
        let projection_payload = projection.payload();
        assert_eq!(projection_payload.public_opening_values(), 3);
        assert_eq!(projection_payload.hidden_auxiliary_values(), 5);
        assert_eq!(projection_payload.verifier_reconstruction_items(), 2);
    }

    #[test]
    fn plonky3_pre_grind_source_fixture_marks_post_zeta_as_placeholder() {
        // Bridge-specific executable evidence: current pre-grind extraction
        // marks pre-zeta slots live and post-zeta slots as placeholders. This
        // goes through `build_pre_grind_harness_input` so it covers canonical
        // cross-layer slots as well as Plonky3-prefixed slots.
        let fixture = standard_fixture();
        let security_level = fixture.batch_spec.security_level();
        let extraction = LivePreGrindExtraction {
            log_ext_degree: vec![0x01; 4],
            log_degree: vec![0x02; 4],
            preprocessed_width: vec![0x03; 4],
            trace_commit: vec![0x04; 32],
            preprocessed_commit: Some(vec![0x05; 32]),
            air_public_values: vec![0x06; 8],
            quotient_commit: vec![0x08; 32],
            randomizer_commit: vec![0x09; 32],
        };
        let config = Plonky3LiveHarnessConfig {
            hash_identifier: &fixture.hash_identifier,
            profile: &fixture.profile,
            basis: &fixture.basis,
            batch_spec: &fixture.batch_spec,
            codeword_spec: &fixture.codeword_spec,
            oracle_spec: &fixture.oracle_spec,
            projection_spec: &fixture.projection_spec,
            quotient_spec: &fixture.quotient_spec,
            security_level: &security_level,
            degree_contract: &fixture.degree_contract,
            public_openings: &fixture.public_openings,
            opened_values: vec![0x0C; 16],
            fri_commit_phase_commitments: vec![0x0E; 32],
            fri_final_poly: vec![0x11; 16],
            fri_log_arities: vec![0x12; 4],
        };

        let input = build_pre_grind_harness_input(&extraction, Vec::new(), &config);
        input
            .record
            .finalize(&input.manifest)
            .expect("production builder output must satisfy its manifest");

        let labels: Vec<_> = input
            .record
            .absorbed()
            .iter()
            .map(TranscriptBinding::domain_label)
            .collect();

        let source_for = |label| {
            let index = labels
                .iter()
                .position(|observed| *observed == label)
                .expect("label must be present");
            input.record.source_at(index)
        };

        for label in [
            DOMAIN_PLONKY3_LOG_EXT_DEGREE,
            DOMAIN_PLONKY3_LOG_DEGREE,
            DOMAIN_PLONKY3_PREPROCESSED_WIDTH,
            DOMAIN_PLONKY3_TRACE_COMMITMENT,
            DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT,
            DOMAIN_PLONKY3_AIR_PUBLIC_VALUES,
            DOMAIN_PLONKY3_QUOTIENT_COMMITMENT,
            DOMAIN_RANDOMIZER_COMMITMENT,
        ] {
            assert_eq!(source_for(label), TranscriptBindingSource::Live);
        }

        for label in [
            DOMAIN_PLONKY3_OPENED_VALUES,
            DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS,
            DOMAIN_PLONKY3_FRI_FINAL_POLY,
            DOMAIN_PLONKY3_FRI_LOG_ARITIES,
            DOMAIN_PUBLIC_OPENINGS,
        ] {
            assert_eq!(source_for(label), TranscriptBindingSource::Placeholder);
        }
    }

    #[test]
    fn plonky3_pre_grind_extractor_shape_fixtures_match_lean_event_kinds() {
        // Mirrors `preprocessedCommitment_mem_iff`,
        // `airPublicValues_mem_iff`, `observedPreGrindEvents_are_observed`,
        // and `sampledPreGrindEvents_are_sampled`.
        //
        // Lean models alpha/zeta as logical sample slots; Rust may record one
        // logical sample slot as multiple contiguous byte-level Sampled events.
        assert_pre_grind_extraction_shape(false, 0, false);
        assert_pre_grind_extraction_shape(true, 0, false);
        assert_pre_grind_extraction_shape(false, 8, false);
        assert_pre_grind_extraction_shape(true, 8, true);
    }

    #[test]
    fn current_plonky3_input_is_not_full_live_capable() {
        // Phase A conformance (P2-2 corrected): the current `shroud-plonky3`
        // bridge produces inputs that CANNOT carry any full-live claim scope.
        // It does NOT also prove the accepted scope is specifically
        // `plonky3UniStarkPreGrind` — that requires a Rust `ClaimScope` enum
        // (deferred to Phase C) plus a scoped-claim builder. For now, the
        // narrower "not full-live capable" assertion is what this fixture
        // proves.
        //
        // Cites Lean theorems in `formal/Shroud/Core/Conformance.lean`:
        //
        // - `Shroud.Core.placeholderSource_incompatible_with_fullLive_scope
        //   (scope : ClaimScope) (h : scope.requiresFullLive = true) :
        //   sourceAcceptableForScope scope BindingSource.placeholder = false`
        //   — for every full-live scope, placeholder bindings are rejected.
        // - `Shroud.Core.plonky3FullFriReplay_fullLive`,
        //   `Shroud.Core.whirHvzk_fullLive` — the two currently-named full-live
        //   scopes.
        // - `Shroud.Core.placeholderSource_acceptable_for_plonky3UniStarkPreGrind`
        //   — placeholder bindings are admissible for the current Plonky3
        //   pre-grind scope (not full-live by design).
        //
        // The executable evidence: a standard `Plonky3LiveHarnessInput`
        // contains at least one `TranscriptBindingSource::Placeholder`
        // binding (specifically `DOMAIN_PLONKY3_OPENED_VALUES`, per the
        // post-zeta deferred list in `docs/plonky3-bridge-status.md`). By
        // composition with the Lean theorem above, any claim scope `s` with
        // `s.requiresFullLive = true` is excluded — including
        // `plonky3FullFriReplay` and `whirHvzk`. The fixture does NOT
        // claim which non-full-live scope the input actually carries.
        //
        // If this assertion fires, the bridge has moved to full-live
        // coverage and the claim-scope wiring must be revisited before the
        // next release.
        let fixture = standard_fixture();
        let security_level = fixture.batch_spec.security_level();
        let extraction = LivePreGrindExtraction {
            log_ext_degree: vec![0x01; 4],
            log_degree: vec![0x02; 4],
            preprocessed_width: vec![0x03; 4],
            trace_commit: vec![0x04; 32],
            preprocessed_commit: None,
            air_public_values: vec![],
            quotient_commit: vec![0x08; 32],
            randomizer_commit: vec![0x09; 32],
        };
        let config = Plonky3LiveHarnessConfig {
            hash_identifier: &fixture.hash_identifier,
            profile: &fixture.profile,
            basis: &fixture.basis,
            batch_spec: &fixture.batch_spec,
            codeword_spec: &fixture.codeword_spec,
            oracle_spec: &fixture.oracle_spec,
            projection_spec: &fixture.projection_spec,
            quotient_spec: &fixture.quotient_spec,
            security_level: &security_level,
            degree_contract: &fixture.degree_contract,
            public_openings: &fixture.public_openings,
            opened_values: vec![0x00; 8],
            fri_commit_phase_commitments: vec![0x01; 8],
            fri_final_poly: vec![0x02; 8],
            fri_log_arities: vec![0x03; 8],
        };

        let input = build_pre_grind_harness_input(&extraction, Vec::new(), &config);

        // At least one Placeholder-sourced binding must be present in a
        // standard pre-grind input. This is the witness that the scope is
        // `plonky3UniStarkPreGrind` and not `plonky3FullFriReplay`.
        let placeholder_count = input
            .record
            .absorbed()
            .iter()
            .enumerate()
            .filter(|(i, _)| input.record.source_at(*i) == TranscriptBindingSource::Placeholder)
            .count();
        assert!(
            placeholder_count > 0,
            "current Plonky3 bridge MUST carry placeholder bindings — \
             this is the structural witness that the input cannot satisfy \
             any full-live claim scope. By the Lean theorem \
             placeholderSource_incompatible_with_fullLive_scope in \
             formal/Shroud/Core/Conformance.lean, both plonky3FullFriReplay \
             and whirHvzk are excluded. If this fires, the bridge has \
             unexpectedly moved to full-live coverage."
        );

        // Sharper: DOMAIN_PLONKY3_OPENED_VALUES must remain a placeholder
        // until the grind clone-pollution blocker is closed (phase D).
        let opened_values_index = input
            .record
            .absorbed()
            .iter()
            .position(|b| b.domain_label() == DOMAIN_PLONKY3_OPENED_VALUES)
            .expect("DOMAIN_PLONKY3_OPENED_VALUES must appear in the record");
        assert_eq!(
            input.record.source_at(opened_values_index),
            TranscriptBindingSource::Placeholder,
            "DOMAIN_PLONKY3_OPENED_VALUES must be Placeholder-sourced until \
             post-zeta engineering (phase D) lands — see \
             docs/plonky3-bridge-status.md"
        );

        // (Phase C P2 follow-up note.) `Plonky3LiveHarnessInput` itself no
        // longer implements `BackendClaimSurface` — that impl was moved to
        // `Plonky3VerifiedLiveInput`, which carries extraction-provenance
        // and re-extracts during verification. See
        // `verified_wrapper_rejects_hand_built_input_with_empty_events`
        // below for the regression that motivates this split.
    }

    /// Rust mirror of `Shroud.Bridge.Plonky3.plonky3StandardCitations` as a
    /// typed `UpstreamCitation` list. Phase C replaces the previous string
    /// mirror with the actual `shroud-core` enum; the Lean → Rust
    /// correspondence is now constructive at the discriminant level
    /// (verified by `claim_scope_discriminants_match_lean` and
    /// `upstream_citation_discriminants_match_lean` in `shroud-core`).
    /// Drift between Lean and Rust is still caught by PR review per
    /// `docs/Lean Normative Spec Restructure.md` §8.
    const PLONKY3_STANDARD_CITATIONS: &[UpstreamCitation] = &[
        UpstreamCitation::BcsIop,
        UpstreamCitation::DeepFri,
        UpstreamCitation::ProximityGaps,
        UpstreamCitation::HabockKindi,
        UpstreamCitation::Aurora,
        UpstreamCitation::Ligero,
        UpstreamCitation::RedShift,
        UpstreamCitation::SpongeIndifferentiability,
        UpstreamCitation::ChiesaOrruSpongeFs,
    ];

    #[test]
    fn plonky3_current_scope_is_typed_to_pre_grind() {
        // Phase C conformance: with the Rust `ClaimScope` enum in place,
        // we can construct an actual `BackendClaim` whose scope is the
        // typed `Plonky3UniStarkPreGrind` variant. This closes the
        // Phase A P2-2 overclaim entirely — the scope identity now lives
        // in the type system, not in a docstring.
        //
        // Mirrors `Shroud.Bridge.Plonky3.plonky3CurrentScope = .plonky3UniStarkPreGrind`
        // (proven by `plonky3CurrentScope_eq` in
        // `formal/Shroud/Bridge/Plonky3/Claim.lean`).
        let claim = BackendClaim::new(
            SecurityLevel::Statistical,
            ClaimScope::Plonky3UniStarkPreGrind,
            PLONKY3_STANDARD_CITATIONS.to_vec(),
        );
        assert_eq!(claim.scope, ClaimScope::Plonky3UniStarkPreGrind);
        assert_eq!(claim.scope.discriminant(), 1);
        assert!(!claim.requires_full_live());
        assert_eq!(claim.security_level, SecurityLevel::Statistical);
        assert_eq!(claim.citations.len(), 9);
    }

    #[test]
    fn plonky3_current_scope_distinct_from_other_scopes() {
        // Phase C conformance: mirrors
        // `Shroud.Bridge.Plonky3.plonky3CurrentScope_ne_fullFriReplay` and
        // `_ne_whirHvzk`. With the typed enum, scope distinction becomes a
        // structural property.
        assert_ne!(
            ClaimScope::Plonky3UniStarkPreGrind,
            ClaimScope::Plonky3FullFriReplay
        );
        assert_ne!(ClaimScope::Plonky3UniStarkPreGrind, ClaimScope::WhirHvzk);
        assert_ne!(
            ClaimScope::Plonky3UniStarkPreGrind,
            ClaimScope::CoreBatchOpening
        );

        // All four scopes have distinct discriminants
        // (matches `Shroud.Core.ClaimScope.discriminants_distinct`).
        let mut discriminants = [
            ClaimScope::CoreBatchOpening.discriminant(),
            ClaimScope::Plonky3UniStarkPreGrind.discriminant(),
            ClaimScope::Plonky3FullFriReplay.discriminant(),
            ClaimScope::WhirHvzk.discriminant(),
        ];
        discriminants.sort_unstable();
        assert_eq!(discriminants, [0, 1, 2, 3]);
    }

    #[test]
    fn verifying_builder_rejects_empty_events_at_construction() {
        // P2 regression for the previous-cycle finding: the
        // `BackendClaimSurface` impl used to live on `Plonky3LiveHarnessInput`
        // directly, so a hand-built input with empty `prefix_events` could
        // pass `verify_independent_checks` — `Plonky3ReplayHarness::verify`
        // over an empty event log is trivially satisfiable. The fix:
        //
        // - The trait impl was moved to `Plonky3VerifiedLiveInput`.
        // - `Plonky3VerifiedLiveInput` has private fields and only one
        //   constructor (`verify_pre_grind_bridge_into_verified`), which
        //   runs `extract_pre_grind_slices` first and refuses empty events.
        //
        // This test locks the construction-time rejection: with `&[]` as
        // the event log, the verifying builder returns
        // `PreGrindBridgeError::Extraction(LiveExtractionError::TruncatedLog
        // { reading: "log_ext_degree", .. })`. The trait surface is
        // therefore unreachable for empty-event inputs.
        let fixture = standard_fixture();
        let security_level = fixture.batch_spec.security_level();
        let config = Plonky3LiveHarnessConfig {
            hash_identifier: &fixture.hash_identifier,
            profile: &fixture.profile,
            basis: &fixture.basis,
            batch_spec: &fixture.batch_spec,
            codeword_spec: &fixture.codeword_spec,
            oracle_spec: &fixture.oracle_spec,
            projection_spec: &fixture.projection_spec,
            quotient_spec: &fixture.quotient_spec,
            security_level: &security_level,
            degree_contract: &fixture.degree_contract,
            public_openings: &fixture.public_openings,
            opened_values: vec![0x00; 8],
            fri_commit_phase_commitments: vec![0x01; 8],
            fri_final_poly: vec![0x02; 8],
            fri_log_arities: vec![0x03; 8],
        };

        let err =
            verify_pre_grind_bridge_into_verified(&[], &LiveExtractorShape::standard(), &config)
                .expect_err("verifying builder must reject empty events");
        assert!(
            matches!(err, PreGrindBridgeError::Extraction(_)),
            "expected PreGrindBridgeError::Extraction for empty events, got {err:?}"
        );
    }

    #[test]
    fn verifying_builder_rejects_security_level_mismatch() {
        // P2 regression for the previous-cycle finding: the original Phase
        // C `backend_claim()` hardcoded `SecurityLevel::Statistical`, while
        // the verifying builder accepted any `config.security_level` and
        // bound that value into the manifest/record. A caller could build
        // a verified input whose transcript binding said `Perfect` while
        // `backend_claim()` reported `Statistical`. The harness would
        // accept (manifest/record were self-consistent), and the
        // claim/transcript disagreement would silently slip through.
        //
        // The fix has two parts:
        //
        // 1. `verify_pre_grind_bridge_into_verified` now validates that
        //    `config.security_level` agrees with every protocol spec's
        //    `security_level()` method before any byte work. Mismatches
        //    return `PreGrindBridgeError::SecurityLevelMismatch`.
        // 2. The validated level is stored on `Plonky3VerifiedLiveInput`
        //    and reported by `backend_claim()`, so `backend_claim()` and
        //    the bound transcript always agree.
        //
        // This regression locks the validation: a config that declares
        // `Perfect` against the standard statistical specs is rejected
        // before extraction is attempted. The Plonky3 backend has no
        // `Perfect` deployment today (all five specs above are constructed
        // via `*::statistical(...)`), so the inconsistency is purely a
        // declared-versus-bound mismatch — exactly the failure mode the
        // P2 finding identified.
        let fixture = standard_fixture();
        // Force a security-level mismatch by declaring `Perfect` while
        // the specs in `fixture` are all `Statistical`.
        let mismatched_level = SecurityLevel::Perfect;
        assert_eq!(
            fixture.batch_spec.security_level(),
            SecurityLevel::Statistical
        );

        let config = Plonky3LiveHarnessConfig {
            hash_identifier: &fixture.hash_identifier,
            profile: &fixture.profile,
            basis: &fixture.basis,
            batch_spec: &fixture.batch_spec,
            codeword_spec: &fixture.codeword_spec,
            oracle_spec: &fixture.oracle_spec,
            projection_spec: &fixture.projection_spec,
            quotient_spec: &fixture.quotient_spec,
            security_level: &mismatched_level,
            degree_contract: &fixture.degree_contract,
            public_openings: &fixture.public_openings,
            opened_values: vec![0x00; 8],
            fri_commit_phase_commitments: vec![0x01; 8],
            fri_final_poly: vec![0x02; 8],
            fri_log_arities: vec![0x03; 8],
        };

        // Pass an empty event log — the builder should reject on the
        // security-level check BEFORE reaching extraction. (If extraction
        // ran first, we'd get an `Extraction` error instead.)
        let err =
            verify_pre_grind_bridge_into_verified(&[], &LiveExtractorShape::standard(), &config)
                .expect_err("verifying builder must reject security-level mismatch");

        match err {
            PreGrindBridgeError::SecurityLevelMismatch {
                config,
                spec,
                spec_security_level,
            } => {
                assert_eq!(config, SecurityLevel::Perfect);
                assert_eq!(spec_security_level, SecurityLevel::Statistical);
                // First spec checked is batch_spec — the validation order
                // is fixed in `validate_security_level_agreement`.
                assert_eq!(spec, "batch_spec");
            }
            other => panic!("expected SecurityLevelMismatch, got {other:?}"),
        }
    }

    #[test]
    fn facade_rejects_security_level_mismatch() {
        // P2 regression for the previous-cycle finding: the older
        // `verify_pre_grind_bridge` facade bypassed
        // `validate_security_level_agreement` and could accept a config
        // with `config.security_level` disagreeing with the bound specs.
        // Phase C P2 second iteration: `verify_pre_grind_bridge` now
        // delegates to `verify_pre_grind_bridge_into_verified(...).map(|_|
        // ())`, so both facades inherit the same security-level check
        // and cannot drift apart.
        //
        // This regression mirrors
        // `verifying_builder_rejects_security_level_mismatch` (which
        // exercised the wrapper-returning facade) but on the
        // unit-returning facade. If `verify_pre_grind_bridge` stops
        // delegating to the verifying builder, this fixture fails.
        let fixture = standard_fixture();
        let mismatched_level = SecurityLevel::Perfect;
        assert_eq!(
            fixture.batch_spec.security_level(),
            SecurityLevel::Statistical
        );

        let config = Plonky3LiveHarnessConfig {
            hash_identifier: &fixture.hash_identifier,
            profile: &fixture.profile,
            basis: &fixture.basis,
            batch_spec: &fixture.batch_spec,
            codeword_spec: &fixture.codeword_spec,
            oracle_spec: &fixture.oracle_spec,
            projection_spec: &fixture.projection_spec,
            quotient_spec: &fixture.quotient_spec,
            security_level: &mismatched_level,
            degree_contract: &fixture.degree_contract,
            public_openings: &fixture.public_openings,
            opened_values: vec![0x00; 8],
            fri_commit_phase_commitments: vec![0x01; 8],
            fri_final_poly: vec![0x02; 8],
            fri_log_arities: vec![0x03; 8],
        };

        let err = verify_pre_grind_bridge(&[], &LiveExtractorShape::standard(), &config)
            .expect_err("verify_pre_grind_bridge must reject security-level mismatch");
        match err {
            PreGrindBridgeError::SecurityLevelMismatch {
                config,
                spec,
                spec_security_level,
            } => {
                assert_eq!(config, SecurityLevel::Perfect);
                assert_eq!(spec_security_level, SecurityLevel::Statistical);
                assert_eq!(spec, "batch_spec");
            }
            other => panic!("expected SecurityLevelMismatch from facade, got {other:?}"),
        }
    }

    #[test]
    fn plonky3_standard_citations_typed_set_mirror() {
        // Phase C conformance: typed-enum version of the previous
        // string-list mirror. Lean's `plonky3StandardCitations` is the
        // source of truth; this constant must match as a set (order is
        // not significant). Adding/removing/renaming a citation in either
        // Lean or Rust requires updating both sides in the same PR.
        let mut actual: Vec<u32> = PLONKY3_STANDARD_CITATIONS
            .iter()
            .map(|c| c.discriminant())
            .collect();
        actual.sort_unstable();
        let expected: Vec<u32> = vec![
            UpstreamCitation::BcsIop.discriminant(),
            UpstreamCitation::DeepFri.discriminant(),
            UpstreamCitation::ProximityGaps.discriminant(),
            UpstreamCitation::HabockKindi.discriminant(),
            UpstreamCitation::Aurora.discriminant(),
            UpstreamCitation::Ligero.discriminant(),
            UpstreamCitation::RedShift.discriminant(),
            UpstreamCitation::SpongeIndifferentiability.discriminant(),
            UpstreamCitation::ChiesaOrruSpongeFs.discriminant(),
        ];
        let mut expected_sorted = expected.clone();
        expected_sorted.sort_unstable();
        assert_eq!(actual, expected_sorted);
        assert_eq!(actual.len(), 9);
    }
}
