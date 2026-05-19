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
        BasisDescriptor, DOMAIN_BASIS, DOMAIN_BATCH_OPENING, DOMAIN_CODEWORD_EMBEDDING,
        DOMAIN_DEGREE_CONTRACT, DOMAIN_HASH_ID, DOMAIN_OPENING_PROJECTION,
        DOMAIN_ORACLE_COMMITMENT, DOMAIN_PROFILE, DOMAIN_PUBLIC_OPENINGS, DOMAIN_QUOTIENT_HIDER,
        DOMAIN_RANDOMIZER_COMMITMENT, DOMAIN_SECURITY_LEVEL, FieldModel, HashIdentifier,
        PerfectClaim, PublicOpeningBinding, RandomnessModel, SecurityLevel, SimulatorObligations,
        StandardBatchOpeningBindings, TranscriptBindable, TranscriptBinding,
        TranscriptBindingManifest, TranscriptBindingSource, TranscriptStage,
    };
    use shroud_opening_projection::{
        AuxiliaryOpeningTransport, OpeningProjectionShape, ShroudOpeningProjectionSpec,
    };
    use shroud_oracle_commitment::{
        OracleAuxiliaryTransport, OracleCommitmentShape, ShroudOracleCommitmentSpec,
    };
    use shroud_plonky3::{
        DOMAIN_PLONKY3_AIR_PUBLIC_VALUES, DOMAIN_PLONKY3_FRI_COMMIT_PHASE_COMMITMENTS,
        DOMAIN_PLONKY3_FRI_FINAL_POLY, DOMAIN_PLONKY3_FRI_LOG_ARITIES, DOMAIN_PLONKY3_LOG_DEGREE,
        DOMAIN_PLONKY3_LOG_EXT_DEGREE, DOMAIN_PLONKY3_OPENED_VALUES,
        DOMAIN_PLONKY3_PREPROCESSED_COMMITMENT, DOMAIN_PLONKY3_PREPROCESSED_WIDTH,
        DOMAIN_PLONKY3_QUOTIENT_COMMITMENT, DOMAIN_PLONKY3_TRACE_COMMITMENT,
        LivePreGrindExtraction, Plonky3LiveHarnessConfig, build_pre_grind_harness_input,
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
}
