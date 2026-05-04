#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SHROUD object for trace codeword embedding with randomizer columns.
//!
//! A codeword embedding is the step where a trace matrix of width `w` and
//! height `h` is augmented with `r` randomizer columns and committed via an
//! MMCS. The committed matrix has width `w + r` and height `2h` (the standard
//! Plonky3-style reshape: interleave the original rows with random rows, then
//! truncate the view to `w + r` columns so the verifier sees only the original
//! trace width on opening). The FRI codeword is the LDE of each column over a
//! domain that is `2^required_log_blowup` times the trace domain.
//!
//! This object models only the statistical hiding case (the current default in
//! `HidingFriPcs`). The statistical invariant requires that the number of
//! randomizer columns equals the extension degree of the challenge field,
//! ensuring each extension-field challenge evaluation is masked by an
//! independent base-field random column.
//!
//! The required blowup is a first-class field because it is a protocol
//! precondition: a hiding FRI PCS with `log_blowup = 1` (the standard
//! non-hiding default) does not provide enough evaluation points to mask the
//! trace. The minimum for statistical hiding is `log_blowup = 2`.

use core::fmt;

use shroud_core::{AuxiliaryTransport, SecurityLevel};

/// Shape of the codeword embedding: trace, randomizer, domain, and field parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodewordEmbeddingShape {
    trace_columns: usize,
    randomizer_columns: usize,
    domain_log_size: usize,
    extension_degree: usize,
}

impl CodewordEmbeddingShape {
    /// Builds a validated codeword embedding shape.
    ///
    /// All parameters must be non-zero. The statistical invariant
    /// (`randomizer_columns == extension_degree`) is enforced at the
    /// `ShroudCodewordEmbeddingSpec` level, not here, so that the shape can
    /// represent any count of randomizer columns for experimental or
    /// non-standard configurations.
    pub fn new(
        trace_columns: usize,
        randomizer_columns: usize,
        domain_log_size: usize,
        extension_degree: usize,
    ) -> Result<Self, CodewordEmbeddingError> {
        if trace_columns == 0 {
            return Err(CodewordEmbeddingError::ZeroTraceColumns);
        }
        if randomizer_columns == 0 {
            return Err(CodewordEmbeddingError::ZeroRandomizerColumns);
        }
        if domain_log_size == 0 {
            return Err(CodewordEmbeddingError::ZeroDomainLogSize);
        }
        if extension_degree == 0 {
            return Err(CodewordEmbeddingError::ZeroExtensionDegree);
        }

        Ok(Self {
            trace_columns,
            randomizer_columns,
            domain_log_size,
            extension_degree,
        })
    }

    /// Number of public trace columns in the committed matrix.
    #[must_use]
    pub const fn trace_columns(self) -> usize {
        self.trace_columns
    }

    /// Number of hidden randomizer columns appended to the trace.
    #[must_use]
    pub const fn randomizer_columns(self) -> usize {
        self.randomizer_columns
    }

    /// Total committed columns: trace columns plus randomizer columns.
    #[must_use]
    pub const fn committed_columns(self) -> usize {
        self.trace_columns.saturating_add(self.randomizer_columns)
    }

    /// Log base 2 of the trace evaluation domain size.
    #[must_use]
    pub const fn domain_log_size(self) -> usize {
        self.domain_log_size
    }

    /// Extension degree of the challenge field over the base field.
    #[must_use]
    pub const fn extension_degree(self) -> usize {
        self.extension_degree
    }
}

/// Public-vs-hidden surface implied by a codeword embedding object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodewordEmbeddingPayload {
    committed_columns: usize,
    public_trace_columns: usize,
    hidden_randomizer_columns: usize,
    domain_log_size: usize,
    required_log_blowup: usize,
    auxiliary_transport: AuxiliaryTransport,
}

impl CodewordEmbeddingPayload {
    /// Builds a codeword embedding payload from a validated shape.
    #[must_use]
    pub const fn new(
        shape: CodewordEmbeddingShape,
        required_log_blowup: usize,
        auxiliary_transport: AuxiliaryTransport,
    ) -> Self {
        Self {
            committed_columns: shape.committed_columns(),
            public_trace_columns: shape.trace_columns(),
            hidden_randomizer_columns: shape.randomizer_columns(),
            domain_log_size: shape.domain_log_size(),
            required_log_blowup,
            auxiliary_transport,
        }
    }

    /// Total number of committed columns (trace + randomizer).
    #[must_use]
    pub const fn committed_columns(self) -> usize {
        self.committed_columns
    }

    /// Number of public trace columns visible to the verifier.
    #[must_use]
    pub const fn public_trace_columns(self) -> usize {
        self.public_trace_columns
    }

    /// Number of hidden randomizer columns carried in the proof.
    #[must_use]
    pub const fn hidden_randomizer_columns(self) -> usize {
        self.hidden_randomizer_columns
    }

    /// Log base 2 of the trace evaluation domain size.
    #[must_use]
    pub const fn domain_log_size(self) -> usize {
        self.domain_log_size
    }

    /// Minimum log blowup the FRI PCS must use for this embedding to hide.
    #[must_use]
    pub const fn required_log_blowup(self) -> usize {
        self.required_log_blowup
    }

    /// Transport mechanism for the hidden randomizer opening material.
    #[must_use]
    pub const fn auxiliary_transport(self) -> AuxiliaryTransport {
        self.auxiliary_transport
    }
}

/// SHROUD object for trace codeword embedding with statistical randomizer columns.
///
/// The statistical invariant this object enforces:
/// `randomizer_columns == extension_degree`. This ensures that each
/// extension-field challenge evaluation is independently masked by one
/// base-field randomizer column, matching the `HidingFriPcs` contract where
/// `num_random_codewords = extension_degree`.
///
/// The blowup invariant this object enforces:
/// `required_log_blowup >= 2`. A blowup of 1 (the non-hiding default) does
/// not provide enough evaluation points for the randomizer columns to hide the
/// trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShroudCodewordEmbeddingSpec {
    security_level: SecurityLevel,
    shape: CodewordEmbeddingShape,
    payload: CodewordEmbeddingPayload,
}

impl ShroudCodewordEmbeddingSpec {
    /// Builds the standard statistical codeword embedding object.
    ///
    /// Uses `required_log_blowup = 2` and `AuxiliaryTransport::InBand`,
    /// matching the `HidingFriPcs` default.
    pub fn statistical(shape: CodewordEmbeddingShape) -> Result<Self, CodewordEmbeddingError> {
        Self::statistical_with_transport(shape, AuxiliaryTransport::InBand)
    }

    /// Builds a statistical codeword embedding object with an explicit transport.
    pub fn statistical_with_transport(
        shape: CodewordEmbeddingShape,
        auxiliary_transport: AuxiliaryTransport,
    ) -> Result<Self, CodewordEmbeddingError> {
        Self::new(SecurityLevel::Statistical, shape, 2, auxiliary_transport)
    }

    /// Builds a codeword embedding object with an explicit security level, blowup, and transport.
    pub fn new(
        security_level: SecurityLevel,
        shape: CodewordEmbeddingShape,
        required_log_blowup: usize,
        auxiliary_transport: AuxiliaryTransport,
    ) -> Result<Self, CodewordEmbeddingError> {
        let payload =
            CodewordEmbeddingPayload::new(shape, required_log_blowup, auxiliary_transport);
        let spec = Self {
            security_level,
            shape,
            payload,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Security level implemented by this codeword embedding object.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Shape of the codeword embedding.
    #[must_use]
    pub const fn shape(&self) -> CodewordEmbeddingShape {
        self.shape
    }

    /// Public-vs-hidden payload implied by this codeword embedding object.
    #[must_use]
    pub const fn payload(&self) -> CodewordEmbeddingPayload {
        self.payload
    }

    /// Transport mechanism for the hidden randomizer opening material.
    #[must_use]
    pub const fn auxiliary_transport(&self) -> AuxiliaryTransport {
        self.payload.auxiliary_transport()
    }

    /// Validates the invariants of this codeword embedding object.
    ///
    /// Checks:
    /// 1. Security level: `SecurityLevel::Perfect` is rejected; use a dedicated
    ///    perfect constructor (not yet implemented) that carries a `PerfectClaim`.
    /// 2. Statistical invariant: `randomizer_columns == extension_degree`.
    /// 3. Blowup invariant: `required_log_blowup >= 2`.
    /// 4. Payload consistency: derived payload fields match the shape.
    pub fn validate(&self) -> Result<(), CodewordEmbeddingError> {
        if matches!(self.security_level, SecurityLevel::Perfect) {
            return Err(CodewordEmbeddingError::PerfectRequiresClaim);
        }

        if self.shape.randomizer_columns() != self.shape.extension_degree() {
            return Err(CodewordEmbeddingError::StatisticalInvariantViolated {
                randomizer_columns: self.shape.randomizer_columns(),
                extension_degree: self.shape.extension_degree(),
            });
        }

        if self.payload.required_log_blowup() < 2 {
            return Err(CodewordEmbeddingError::InsufficientBlowup {
                required_log_blowup: self.payload.required_log_blowup(),
            });
        }

        if self.payload.committed_columns()
            != self
                .shape
                .trace_columns()
                .saturating_add(self.shape.randomizer_columns())
            || self.payload.public_trace_columns() != self.shape.trace_columns()
            || self.payload.hidden_randomizer_columns() != self.shape.randomizer_columns()
            || self.payload.domain_log_size() != self.shape.domain_log_size()
        {
            return Err(CodewordEmbeddingError::PayloadShapeMismatch);
        }

        Ok(())
    }
}

/// Error raised when a codeword embedding object violates a SHROUD invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodewordEmbeddingError {
    /// A codeword embedding must have at least one trace column.
    ZeroTraceColumns,
    /// A codeword embedding must have at least one randomizer column.
    ZeroRandomizerColumns,
    /// The trace evaluation domain must have a positive log size.
    ZeroDomainLogSize,
    /// The extension degree must be positive.
    ZeroExtensionDegree,
    /// The statistical invariant requires `randomizer_columns == extension_degree`.
    StatisticalInvariantViolated {
        /// Number of randomizer columns in the shape.
        randomizer_columns: usize,
        /// Extension degree of the challenge field.
        extension_degree: usize,
    },
    /// The FRI blowup must be at least 2 for the randomizer columns to hide the trace.
    InsufficientBlowup {
        /// The supplied `required_log_blowup` value.
        required_log_blowup: usize,
    },
    /// The derived payload no longer matches the validated shape.
    PayloadShapeMismatch,
    /// `SecurityLevel::Perfect` requires a `PerfectClaim`; use a dedicated
    /// perfect constructor that carries and validates the claim.
    PerfectRequiresClaim,
}

impl fmt::Display for CodewordEmbeddingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTraceColumns => {
                write!(f, "codeword embedding must have at least one trace column")
            }
            Self::ZeroRandomizerColumns => write!(
                f,
                "codeword embedding must have at least one randomizer column"
            ),
            Self::ZeroDomainLogSize => write!(
                f,
                "codeword embedding trace domain must have a positive log size"
            ),
            Self::ZeroExtensionDegree => {
                write!(f, "codeword embedding extension degree must be positive")
            }
            Self::StatisticalInvariantViolated {
                randomizer_columns,
                extension_degree,
            } => write!(
                f,
                "statistical invariant violated: randomizer_columns ({randomizer_columns}) \
                 must equal extension_degree ({extension_degree})"
            ),
            Self::InsufficientBlowup {
                required_log_blowup,
            } => write!(
                f,
                "required_log_blowup ({required_log_blowup}) must be at least 2 for \
                 randomizer columns to hide the trace under FRI"
            ),
            Self::PayloadShapeMismatch => {
                write!(f, "codeword embedding payload no longer matches its shape")
            }
            Self::PerfectRequiresClaim => write!(
                f,
                "SecurityLevel::Perfect requires a PerfectClaim; \
                 use a dedicated perfect constructor that carries and validates the claim"
            ),
        }
    }
}

impl std::error::Error for CodewordEmbeddingError {}

#[cfg(test)]
mod tests {
    use super::{
        AuxiliaryTransport, CodewordEmbeddingError, CodewordEmbeddingShape,
        ShroudCodewordEmbeddingSpec,
    };
    use shroud_core::SecurityLevel;

    fn standard_shape() -> CodewordEmbeddingShape {
        // 64 trace columns, 4 randomizer columns, domain log size 18, extension degree 4.
        // Matches the HidingFriPcs default for BabyBear / BinomialExtensionField<BabyBear, 4>.
        CodewordEmbeddingShape::new(64, 4, 18, 4).expect("valid shape")
    }

    #[test]
    fn statistical_default_satisfies_invariants() {
        let spec = ShroudCodewordEmbeddingSpec::statistical(standard_shape()).expect("valid spec");

        assert_eq!(spec.security_level(), SecurityLevel::Statistical);
        assert_eq!(spec.payload().committed_columns(), 68);
        assert_eq!(spec.payload().public_trace_columns(), 64);
        assert_eq!(spec.payload().hidden_randomizer_columns(), 4);
        assert_eq!(spec.payload().domain_log_size(), 18);
        assert_eq!(spec.payload().required_log_blowup(), 2);
        assert_eq!(
            spec.payload().auxiliary_transport(),
            AuxiliaryTransport::InBand
        );
    }

    #[test]
    fn payload_committed_columns_is_trace_plus_randomizer() {
        let shape = CodewordEmbeddingShape::new(10, 4, 8, 4).expect("valid shape");
        let spec = ShroudCodewordEmbeddingSpec::statistical(shape).expect("valid spec");
        assert_eq!(
            spec.payload().committed_columns(),
            spec.shape().trace_columns() + spec.shape().randomizer_columns()
        );
    }

    #[test]
    fn rejects_randomizer_columns_not_equal_to_extension_degree() {
        // 3 randomizer columns but extension degree 4 — violates statistical invariant.
        let shape = CodewordEmbeddingShape::new(16, 3, 8, 4).expect("valid shape");
        assert_eq!(
            ShroudCodewordEmbeddingSpec::statistical(shape),
            Err(CodewordEmbeddingError::StatisticalInvariantViolated {
                randomizer_columns: 3,
                extension_degree: 4,
            })
        );
    }

    #[test]
    fn rejects_blowup_less_than_two() {
        let shape = standard_shape();
        assert_eq!(
            ShroudCodewordEmbeddingSpec::new(
                SecurityLevel::Statistical,
                shape,
                1,
                AuxiliaryTransport::InBand,
            ),
            Err(CodewordEmbeddingError::InsufficientBlowup {
                required_log_blowup: 1
            })
        );
    }

    #[test]
    fn rejects_zero_trace_columns() {
        assert_eq!(
            CodewordEmbeddingShape::new(0, 4, 8, 4),
            Err(CodewordEmbeddingError::ZeroTraceColumns)
        );
    }

    #[test]
    fn rejects_zero_randomizer_columns() {
        assert_eq!(
            CodewordEmbeddingShape::new(16, 0, 8, 4),
            Err(CodewordEmbeddingError::ZeroRandomizerColumns)
        );
    }

    #[test]
    fn rejects_zero_domain_log_size() {
        assert_eq!(
            CodewordEmbeddingShape::new(16, 4, 0, 4),
            Err(CodewordEmbeddingError::ZeroDomainLogSize)
        );
    }

    #[test]
    fn rejects_zero_extension_degree() {
        assert_eq!(
            CodewordEmbeddingShape::new(16, 4, 8, 0),
            Err(CodewordEmbeddingError::ZeroExtensionDegree)
        );
    }

    #[test]
    fn explicit_separate_envelope_transport_is_recorded() {
        let shape = standard_shape();
        let spec = ShroudCodewordEmbeddingSpec::statistical_with_transport(
            shape,
            AuxiliaryTransport::SeparateEnvelope,
        )
        .expect("valid spec");
        assert_eq!(
            spec.auxiliary_transport(),
            AuxiliaryTransport::SeparateEnvelope
        );
    }

    #[test]
    fn rejects_perfect_security_level_without_claim() {
        // SecurityLevel::Perfect must carry a PerfectClaim. Passing it through
        // the generic constructor without one must be rejected so callers cannot
        // construct a "perfect" spec that skips the PerfectClaim obligations.
        assert_eq!(
            ShroudCodewordEmbeddingSpec::new(
                SecurityLevel::Perfect,
                standard_shape(),
                2,
                AuxiliaryTransport::InBand,
            ),
            Err(CodewordEmbeddingError::PerfectRequiresClaim)
        );
    }

    #[test]
    fn shape_committed_columns_accessor() {
        let shape = CodewordEmbeddingShape::new(10, 4, 8, 4).expect("valid shape");
        assert_eq!(shape.committed_columns(), 14);
    }
}
