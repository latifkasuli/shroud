use core::fmt;

/// Transport mechanism for hidden auxiliary material in a SHROUD proof.
///
/// Each SHROUD object has a domain-specific transport type with context-appropriate
/// variant names. This shared type captures the underlying semantic distinction used
/// by all of them: hidden material either travels in-band with the primary proof
/// object, or in a separate proof envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuxiliaryTransport {
    /// Hidden material travels in-band with the primary proof object.
    InBand,
    /// Hidden material moves in a separate proof envelope or auxiliary field.
    SeparateEnvelope,
}

impl fmt::Display for AuxiliaryTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InBand => f.write_str("in-band"),
            Self::SeparateEnvelope => f.write_str("separate envelope"),
        }
    }
}

/// A non-zero count of items on the public proof surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PublicSurface(usize);

impl PublicSurface {
    /// Builds a public surface count. Returns `None` if `count` is zero.
    #[must_use]
    pub const fn new(count: usize) -> Option<Self> {
        if count == 0 { None } else { Some(Self(count)) }
    }

    /// Returns the item count on the public surface.
    #[must_use]
    pub const fn count(self) -> usize {
        self.0
    }
}

impl fmt::Display for PublicSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} public item(s)", self.0)
    }
}

/// A non-zero count of hidden items carried by the proof, with their transport mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HiddenAuxiliarySurface {
    count: usize,
    transport: AuxiliaryTransport,
}

impl HiddenAuxiliarySurface {
    /// Builds a hidden auxiliary surface. Returns `None` if `count` is zero.
    #[must_use]
    pub const fn new(count: usize, transport: AuxiliaryTransport) -> Option<Self> {
        if count == 0 {
            None
        } else {
            Some(Self { count, transport })
        }
    }

    /// Returns the count of hidden items.
    #[must_use]
    pub const fn count(self) -> usize {
        self.count
    }

    /// Returns the transport mechanism for the hidden items.
    #[must_use]
    pub const fn transport(self) -> AuxiliaryTransport {
        self.transport
    }
}

impl fmt::Display for HiddenAuxiliarySurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} hidden item(s) via {}", self.count, self.transport)
    }
}

/// A non-zero query budget claimed by a SHROUD object.
///
/// The query budget is the number of verifier queries the hiding guarantee must
/// survive. It is a first-class protocol item: SHROUD treats it as a contract
/// between prover and verifier, not an internal backend assumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct QueryBudget(usize);

impl QueryBudget {
    /// Builds a query budget. Returns `None` if `budget` is zero.
    #[must_use]
    pub const fn new(budget: usize) -> Option<Self> {
        if budget == 0 {
            None
        } else {
            Some(Self(budget))
        }
    }

    /// Returns the query budget value.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl fmt::Display for QueryBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} queries", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuxiliaryTransport, HiddenAuxiliarySurface, PublicSurface, QueryBudget};

    #[test]
    fn public_surface_rejects_zero() {
        assert!(PublicSurface::new(0).is_none());
    }

    #[test]
    fn public_surface_accepts_nonzero() {
        let s = PublicSurface::new(3).expect("valid");
        assert_eq!(s.count(), 3);
    }

    #[test]
    fn hidden_surface_rejects_zero() {
        assert!(HiddenAuxiliarySurface::new(0, AuxiliaryTransport::InBand).is_none());
    }

    #[test]
    fn hidden_surface_tracks_transport() {
        let s =
            HiddenAuxiliarySurface::new(5, AuxiliaryTransport::SeparateEnvelope).expect("valid");
        assert_eq!(s.count(), 5);
        assert_eq!(s.transport(), AuxiliaryTransport::SeparateEnvelope);
    }

    #[test]
    fn query_budget_rejects_zero() {
        assert!(QueryBudget::new(0).is_none());
    }

    #[test]
    fn query_budget_accepts_nonzero() {
        let q = QueryBudget::new(40).expect("valid");
        assert_eq!(q.get(), 40);
        assert!(q > QueryBudget::new(1).unwrap());
    }
}
