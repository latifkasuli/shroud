use core::fmt;

/// Degree budget for a masked batch-opening relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DegreeBudget {
    relation_degree: usize,
    randomizer_degree: usize,
}

impl DegreeBudget {
    /// Builds a degree budget and validates that the masked relation stays in the same class.
    pub fn new(
        relation_degree: usize,
        randomizer_degree: usize,
    ) -> Result<Self, DegreeBudgetError> {
        let budget = Self {
            relation_degree,
            randomizer_degree,
        };
        budget.validate()?;
        Ok(budget)
    }

    /// Degree bound of the unmasked reduced batch-opening relation.
    pub const fn relation_degree(self) -> usize {
        self.relation_degree
    }

    /// Degree bound of the randomizer polynomial before quotienting by `(X - zeta)`.
    pub const fn randomizer_degree(self) -> usize {
        self.randomizer_degree
    }

    /// Degree bound of the masked relation after adding `(R(X) - R(zeta)) / (X - zeta)`.
    pub const fn masked_relation_degree_bound(self) -> usize {
        let randomizer_term_degree = self.randomizer_degree.saturating_sub(1);
        if randomizer_term_degree > self.relation_degree {
            randomizer_term_degree
        } else {
            self.relation_degree
        }
    }

    /// Returns `true` when the masking term preserves the original relation degree class.
    pub const fn preserves_relation_degree(self) -> bool {
        self.randomizer_degree <= self.relation_degree.saturating_add(1)
    }

    fn validate(self) -> Result<(), DegreeBudgetError> {
        let max_allowed = self.relation_degree.saturating_add(1);
        if self.randomizer_degree > max_allowed {
            return Err(DegreeBudgetError::RandomizerTooLarge {
                randomizer_degree: self.randomizer_degree,
                max_allowed,
            });
        }
        Ok(())
    }
}

/// Error raised when the randomizer degree would force the masked relation outside its class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegreeBudgetError {
    /// The randomizer degree exceeds the largest degree that preserves the target class.
    RandomizerTooLarge {
        /// Requested randomizer degree.
        randomizer_degree: usize,
        /// Largest allowed randomizer degree.
        max_allowed: usize,
    },
}

impl fmt::Display for DegreeBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomizerTooLarge {
                randomizer_degree,
                max_allowed,
            } => write!(
                f,
                "randomizer degree {randomizer_degree} exceeds the maximum allowed degree {max_allowed}"
            ),
        }
    }
}

impl std::error::Error for DegreeBudgetError {}

#[cfg(test)]
mod tests {
    use super::{DegreeBudget, DegreeBudgetError};

    #[test]
    fn preserves_relation_degree_when_randomizer_is_one_degree_higher() {
        let budget = DegreeBudget::new(15, 16).expect("valid budget");
        assert!(budget.preserves_relation_degree());
        assert_eq!(budget.masked_relation_degree_bound(), 15);
    }

    #[test]
    fn rejects_randomizer_that_grows_masked_relation_class() {
        let err = DegreeBudget::new(15, 17).expect_err("budget should be rejected");
        assert_eq!(
            err,
            DegreeBudgetError::RandomizerTooLarge {
                randomizer_degree: 17,
                max_allowed: 16,
            }
        );
    }
}
