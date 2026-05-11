use core::fmt;

/// Declared technique used to achieve hiding in a SHROUD object.
///
/// `SecurityLevel` (`Statistical` vs `Perfect`) records *how strong* the hiding is.
/// `HidingTechniqueClaim` records *how* hiding is achieved — the structural mechanism
/// that an auditor must verify against the concrete backend.
///
/// These are orthogonal: two objects can both be `SecurityLevel::Statistical` while
/// using entirely different hiding mechanisms (e.g., random codeword interleaving vs.
/// additive vanishing mask). The claim is declared by the SHROUD object author and
/// is not automatically checked by SHROUD — it is a contract for auditors.
///
/// # Combinability
///
/// Backends often compose multiple techniques. A hiding FRI PCS may apply both
/// [`RandomCodewordInterleaving`] for trace hiding and [`QuotientChunkRandomization`]
/// for quotient hiding simultaneously. Use [`HidingTechniqueClaim::Composite`]
/// to declare combinations, or attach separate `HidingTechniqueClaim` values to each
/// SHROUD object in the stack.
///
/// [`RandomCodewordInterleaving`]: HidingTechniqueClaim::RandomCodewordInterleaving
/// [`QuotientChunkRandomization`]: HidingTechniqueClaim::QuotientChunkRandomization
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HidingTechniqueClaim {
    /// Random codewords are interleaved with the witness matrix before commitment.
    ///
    /// Corresponds to Haböck-Kindi 2024 (ePrint 2024/1037) Layer 1: appending
    /// `num_random_codewords` uniformly random codewords so that every row of the
    /// committed matrix contains at least one fresh random field element.
    RandomCodewordInterleaving,

    /// An additive vanishing polynomial mask `R(X)` is applied before the FRI low-degree test.
    ///
    /// The prover adds a degree-bounded random polynomial `R(X)` that vanishes on
    /// the constraint domain, so the masked oracle `f(X) + R(X)` is
    /// indistinguishable from the original on the evaluation domain but hides
    /// `f(X)` from queries outside it. Corresponds to Haböck-Kindi Layer 2.
    AdditiveVanishingMask,

    /// Each quotient chunk is masked by a vanishing-factor random polynomial.
    ///
    /// The quotient `Q(X) = Q_0(X) + … + Q_{k-1}(X) · X^{dk}` is decomposed into
    /// degree-bounded chunks, and each chunk `Q_i(X)` is replaced by
    /// `Q_i(X) + v_{H_i}(X) · t_i(X)` where `v_{H_i}` is the vanishing polynomial
    /// of the `i`-th chunk domain and `t_i` is a random polynomial of matching degree.
    /// The masked chunks are committed separately. Corresponds to Haböck-Kindi Layer 3.
    QuotientChunkRandomization,

    /// Random padding rows are appended to oracle matrices before Merkle commitment.
    ///
    /// Corresponds to hiding MMCS (Haböck-Kindi Layer 4): each column vector is
    /// extended with random values before the tree is built, so that Merkle path
    /// openings do not reveal neighbouring witness rows.
    RandomRowPadding,

    /// A composition of two or more techniques applied together.
    ///
    /// Use this variant when a single SHROUD object requires multiple hiding
    /// mechanisms to achieve its declared security level.
    Composite(
        /// First technique in the composition.
        Box<HidingTechniqueClaim>,
        /// Second technique in the composition.
        Box<HidingTechniqueClaim>,
    ),

    /// A backend-specific hiding technique not covered by the named variants.
    ///
    /// The string describes the technique for audit purposes. Use this only when
    /// none of the named variants apply; prefer named variants when possible so
    /// that automated audit tools can recognize them.
    BackendSpecific(
        /// Human-readable description of the backend-specific technique.
        String,
    ),
}

impl HidingTechniqueClaim {
    /// Returns `true` if this claim contains the given technique at any depth.
    ///
    /// For `Composite`, recursively checks both branches. For `BackendSpecific`,
    /// compares the description string exactly — `BackendSpecific("foo")` does
    /// not contain `BackendSpecific("bar")`. For all other named variants, matches
    /// by discriminant.
    #[must_use]
    pub fn contains(&self, technique: &Self) -> bool {
        match (self, technique) {
            (Self::Composite(a, b), _) => a.contains(technique) || b.contains(technique),
            (Self::BackendSpecific(a), Self::BackendSpecific(b)) => a == b,
            (other, t) => core::mem::discriminant(other) == core::mem::discriminant(t),
        }
    }

    /// Returns a stable canonical byte encoding of this hiding technique claim tree.
    ///
    /// The encoding is:
    /// - `RandomCodewordInterleaving` → `[0]`
    /// - `AdditiveVanishingMask` → `[1]`
    /// - `QuotientChunkRandomization` → `[2]`
    /// - `RandomRowPadding` → `[3]`
    /// - `Composite(a, b)` → `[4] ‖ u32_le(len(a)) ‖ encode(a) ‖ u32_le(len(b)) ‖ encode(b)`
    /// - `BackendSpecific(s)` → `[5] ‖ u32_le(len(s)) ‖ s.as_bytes()`
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::RandomCodewordInterleaving => vec![0u8],
            Self::AdditiveVanishingMask => vec![1u8],
            Self::QuotientChunkRandomization => vec![2u8],
            Self::RandomRowPadding => vec![3u8],
            Self::Composite(a, b) => {
                let a_bytes = a.to_canonical_bytes();
                let b_bytes = b.to_canonical_bytes();
                let mut out = vec![4u8];
                out.extend_from_slice(&(a_bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(&a_bytes);
                out.extend_from_slice(&(b_bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(&b_bytes);
                out
            }
            Self::BackendSpecific(s) => {
                let s_bytes = s.as_bytes();
                let mut out = vec![5u8];
                out.extend_from_slice(&(s_bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(s_bytes);
                out
            }
        }
    }
}

impl fmt::Display for HidingTechniqueClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomCodewordInterleaving => f.write_str("random codeword interleaving"),
            Self::AdditiveVanishingMask => f.write_str("additive vanishing mask"),
            Self::QuotientChunkRandomization => f.write_str("quotient chunk randomization"),
            Self::RandomRowPadding => f.write_str("random row padding"),
            Self::Composite(a, b) => write!(f, "{a} + {b}"),
            Self::BackendSpecific(desc) => write!(f, "backend-specific ({desc})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HidingTechniqueClaim;

    #[test]
    fn display_named_variants() {
        assert_eq!(
            HidingTechniqueClaim::RandomCodewordInterleaving.to_string(),
            "random codeword interleaving"
        );
        assert_eq!(
            HidingTechniqueClaim::AdditiveVanishingMask.to_string(),
            "additive vanishing mask"
        );
        assert_eq!(
            HidingTechniqueClaim::QuotientChunkRandomization.to_string(),
            "quotient chunk randomization"
        );
        assert_eq!(
            HidingTechniqueClaim::RandomRowPadding.to_string(),
            "random row padding"
        );
    }

    #[test]
    fn display_backend_specific() {
        let claim = HidingTechniqueClaim::BackendSpecific("bivariate sumcheck masking".to_string());
        assert_eq!(
            claim.to_string(),
            "backend-specific (bivariate sumcheck masking)"
        );
    }

    #[test]
    fn display_composite_renders_both_branches() {
        let claim = HidingTechniqueClaim::Composite(
            Box::new(HidingTechniqueClaim::RandomCodewordInterleaving),
            Box::new(HidingTechniqueClaim::QuotientChunkRandomization),
        );
        assert_eq!(
            claim.to_string(),
            "random codeword interleaving + quotient chunk randomization"
        );
    }

    #[test]
    fn contains_returns_true_for_direct_match() {
        assert!(
            HidingTechniqueClaim::RandomCodewordInterleaving
                .contains(&HidingTechniqueClaim::RandomCodewordInterleaving)
        );
        assert!(
            !HidingTechniqueClaim::RandomCodewordInterleaving
                .contains(&HidingTechniqueClaim::AdditiveVanishingMask)
        );
    }

    #[test]
    fn backend_specific_contains_matches_string_exactly() {
        let foo = HidingTechniqueClaim::BackendSpecific("foo".to_string());
        let bar = HidingTechniqueClaim::BackendSpecific("bar".to_string());
        let foo2 = HidingTechniqueClaim::BackendSpecific("foo".to_string());
        assert!(foo.contains(&foo2));
        assert!(!foo.contains(&bar));
        assert!(!bar.contains(&foo));
    }

    #[test]
    fn contains_finds_technique_inside_composite() {
        let composite = HidingTechniqueClaim::Composite(
            Box::new(HidingTechniqueClaim::RandomCodewordInterleaving),
            Box::new(HidingTechniqueClaim::RandomRowPadding),
        );
        assert!(composite.contains(&HidingTechniqueClaim::RandomCodewordInterleaving));
        assert!(composite.contains(&HidingTechniqueClaim::RandomRowPadding));
        assert!(!composite.contains(&HidingTechniqueClaim::QuotientChunkRandomization));
    }

    #[test]
    fn contains_finds_technique_in_nested_composite() {
        let inner = HidingTechniqueClaim::Composite(
            Box::new(HidingTechniqueClaim::RandomCodewordInterleaving),
            Box::new(HidingTechniqueClaim::QuotientChunkRandomization),
        );
        let outer = HidingTechniqueClaim::Composite(
            Box::new(inner),
            Box::new(HidingTechniqueClaim::RandomRowPadding),
        );
        assert!(outer.contains(&HidingTechniqueClaim::QuotientChunkRandomization));
        assert!(outer.contains(&HidingTechniqueClaim::RandomRowPadding));
        assert!(!outer.contains(&HidingTechniqueClaim::AdditiveVanishingMask));
    }

    #[test]
    fn hiding_fri_pcs_composite_claim_layers_1_3_4() {
        // A hiding FRI PCS using Haböck-Kindi Layers 1, 3, and 4.
        let claim = HidingTechniqueClaim::Composite(
            Box::new(HidingTechniqueClaim::Composite(
                Box::new(HidingTechniqueClaim::RandomCodewordInterleaving),
                Box::new(HidingTechniqueClaim::QuotientChunkRandomization),
            )),
            Box::new(HidingTechniqueClaim::RandomRowPadding),
        );
        assert!(claim.contains(&HidingTechniqueClaim::RandomCodewordInterleaving));
        assert!(claim.contains(&HidingTechniqueClaim::QuotientChunkRandomization));
        assert!(claim.contains(&HidingTechniqueClaim::RandomRowPadding));
        assert!(!claim.contains(&HidingTechniqueClaim::AdditiveVanishingMask));
    }

    #[test]
    fn named_variants_produce_single_byte_encodings() {
        assert_eq!(
            HidingTechniqueClaim::RandomCodewordInterleaving.to_canonical_bytes(),
            vec![0u8]
        );
        assert_eq!(
            HidingTechniqueClaim::AdditiveVanishingMask.to_canonical_bytes(),
            vec![1u8]
        );
        assert_eq!(
            HidingTechniqueClaim::QuotientChunkRandomization.to_canonical_bytes(),
            vec![2u8]
        );
        assert_eq!(
            HidingTechniqueClaim::RandomRowPadding.to_canonical_bytes(),
            vec![3u8]
        );
    }

    #[test]
    fn composite_encoding_starts_with_discriminant_4() {
        let claim = HidingTechniqueClaim::Composite(
            Box::new(HidingTechniqueClaim::RandomCodewordInterleaving),
            Box::new(HidingTechniqueClaim::RandomRowPadding),
        );
        let bytes = claim.to_canonical_bytes();
        assert_eq!(bytes[0], 4u8);
    }

    #[test]
    fn backend_specific_encoding_starts_with_discriminant_5() {
        let claim = HidingTechniqueClaim::BackendSpecific("custom".to_string());
        let bytes = claim.to_canonical_bytes();
        assert_eq!(bytes[0], 5u8);
    }

    #[test]
    fn different_techniques_produce_different_encodings() {
        let a = HidingTechniqueClaim::RandomCodewordInterleaving.to_canonical_bytes();
        let b = HidingTechniqueClaim::AdditiveVanishingMask.to_canonical_bytes();
        assert_ne!(a, b);
    }
}
