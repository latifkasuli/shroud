//! Rust mirror of `formal/Shroud/Core/Conformance.lean`.
//!
//! Types defined here mirror the Lean Conformance layer constructively:
//! discriminants on the `#[repr(u32)]` enums match the values in
//! `Shroud.Core.ClaimScope.discriminant` and
//! `Shroud.Core.UpstreamCitation.discriminant`. The trait
//! [`BackendClaimSurface`] is the Rust counterpart of Lean's
//! `BackendConforms` witness pattern.
//!
//! This module is the Phase C "Rust API alignment" deliverable from
//! `docs/Maths First, Post-Zeta Second.md` — backend bridges implement
//! [`BackendClaimSurface`] to declare which [`ClaimScope`] their accepted
//! claim covers and to run their independent-check pipeline.

/// A SHROUD claim scope names exactly which backend events / oracle slots
/// are covered by the accepted claim. Scope expansion is a code review —
/// `ClaimScope` is intentionally a closed enum so adding a scope forces
/// review of the corresponding bridge grammar, conformance fixtures, and
/// live negative tests.
///
/// Rust mirror of `Shroud.Core.ClaimScope`. Discriminants match
/// `Shroud.Core.ClaimScope.discriminant` (proven distinct by
/// `Shroud.Core.ClaimScope.discriminants_distinct`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum ClaimScope {
    /// SHROUD core protocol-object level only; no backend bridge attached.
    CoreBatchOpening = 0,
    /// Plonky3 uni-stark transcript bound up to (and including) the ζ
    /// sample; post-zeta events are placeholders. Current production scope
    /// of `shroud-plonky3`.
    Plonky3UniStarkPreGrind = 1,
    /// Plonky3 uni-stark transcript including PCS-internal post-grind
    /// events (opened values, FRI commit phase, final poly, log arities).
    /// Deferred until the grind clone-pollution blocker is resolved
    /// (Phase D).
    Plonky3FullFriReplay = 2,
    /// HVZK-WHIR PCS coverage; pivot target per
    /// `docs/HVZK-WHIR Impact on SHROUD.md`. Not yet implemented.
    WhirHvzk = 3,
}

impl ClaimScope {
    /// Stable cross-language discriminant, matching
    /// `Shroud.Core.ClaimScope.discriminant`.
    #[must_use]
    pub const fn discriminant(self) -> u32 {
        self as u32
    }

    /// Does this scope require every backend event to be sourced live (or
    /// declared as static configuration), with no placeholder bindings?
    ///
    /// Matches `Shroud.Core.ClaimScope.requiresFullLive`. The current
    /// Plonky3 pre-grind scope is intentionally NOT full-live — post-zeta
    /// slots are placeholders. WHIR HVZK and Plonky3 full FRI replay ARE
    /// full-live.
    #[must_use]
    pub const fn requires_full_live(self) -> bool {
        matches!(self, Self::Plonky3FullFriReplay | Self::WhirHvzk)
    }
}

/// Named upstream theorems SHROUD may rely on but does not re-prove. A
/// [`BackendClaim`]'s `citations` list makes these dependencies inspectable
/// rather than implicit. See `docs/SHROUD Maths Bibliography.md` for full
/// references.
///
/// Rust mirror of `Shroud.Core.UpstreamCitation`. Discriminants match
/// `Shroud.Core.UpstreamCitation.discriminant` (proven distinct by
/// `Shroud.Core.upstreamCitation_discriminants_distinct`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum UpstreamCitation {
    /// BCS-IOP HVZK→ZK lift (Ben-Sasson-Chiesa-Spooner, ePrint 2016/116).
    BcsIop = 0,
    /// DEEP-FRI Johnson-bound soundness + OOD challenge mechanism
    /// (ePrint 2019/336).
    DeepFri = 1,
    /// Reed-Solomon proximity-gap soundness (ePrint 2020/654).
    ProximityGaps = 2,
    /// HVZK-WHIR ZK for constrained interleaved codes (ePrint 2026/391).
    HvzkWhir = 3,
    /// Haböck-Kindi vanishing-factor quotient masking (ePrint 2024/1037).
    HabockKindi = 4,
    /// Aurora bounded-independence masking (ePrint 2018/828).
    Aurora = 5,
    /// Ligero interleaved-RS masking (CCS 2017).
    Ligero = 6,
    /// RedShift random codeword in interleaved batch (ePrint 2019/1400).
    RedShift = 7,
    /// Bertoni sponge indifferentiability (EUROCRYPT 2008).
    SpongeIndifferentiability = 8,
    /// Fiat-Shamir in the ROM, baseline (CRYPTO 1986).
    FiatShamirRom = 9,
    /// Chiesa-Orrù duplex-sponge Fiat-Shamir (ePrint 2025/536).
    ChiesaOrruSpongeFs = 10,
}

impl UpstreamCitation {
    /// Stable cross-language discriminant, matching
    /// `Shroud.Core.UpstreamCitation.discriminant`.
    #[must_use]
    pub const fn discriminant(self) -> u32 {
        self as u32
    }
}

/// A backend's declared scoped claim. SHROUD's job is to accept this claim
/// under explicit local checks; it does not derive or strengthen it.
///
/// Rust mirror of `Shroud.Core.BackendClaim`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendClaim {
    /// Declared hiding level.
    pub security_level: crate::SecurityLevel,
    /// Declared scope (which transcript region the claim covers).
    pub scope: ClaimScope,
    /// Inspectable list of upstream theorems the claim depends on.
    pub citations: Vec<UpstreamCitation>,
}

impl BackendClaim {
    /// Convenience constructor.
    #[must_use]
    pub fn new(
        security_level: crate::SecurityLevel,
        scope: ClaimScope,
        citations: Vec<UpstreamCitation>,
    ) -> Self {
        Self {
            security_level,
            scope,
            citations,
        }
    }

    /// Whether this claim's scope requires full-live binding sources.
    #[must_use]
    pub const fn requires_full_live(&self) -> bool {
        self.scope.requires_full_live()
    }
}

/// Backend-bridge contract: any type implementing this trait exposes its
/// declared [`BackendClaim`] (scope + security level + upstream citations)
/// and runs the local independent-check pipeline (provenance, manifest
/// exact-presence, byte-equivalence replay, extraction provenance, etc.)
/// that justifies acceptance.
///
/// Rust counterpart of Lean's `BackendConforms` witness pattern — but
/// without the phantom `ShroudChecks (scope : ClaimScope)` indexing, which
/// is harder to express cleanly in Rust without GATs and intentionally
/// deferred per the Phase C scope in
/// `docs/Maths First, Post-Zeta Second.md`. The trait method signature is
/// the minimum surface a backend bridge needs to expose for SHROUD
/// acceptance to be cited consistently across crates.
///
/// **Implementer contract.** `backend_claim()` should return a fixed claim
/// for the deployment (the bridge's accepted claim, not derived from
/// runtime state). `verify_independent_checks()` must run every local
/// check the bridge has — not just byte-equivalence — including any
/// extraction-provenance or recorder-shape checks that prove the input
/// came from a live backend, not a hand-rolled fixture.
pub trait BackendClaimSurface {
    /// Error type returned by `verify_independent_checks`.
    type Error;

    /// The full [`BackendClaim`] this implementation accepts: scope,
    /// security level, and inspectable list of upstream citations.
    /// Callers can inspect every field — scope alone is not enough for
    /// audit-grade introspection of what theorems the claim depends on.
    fn backend_claim(&self) -> BackendClaim;

    /// Convenience: the scope of the accepted claim. Default impl projects
    /// from [`backend_claim`](Self::backend_claim). Implementations should
    /// not override this unless they have a more efficient path that
    /// avoids cloning the citation list.
    fn claim_scope(&self) -> ClaimScope {
        self.backend_claim().scope
    }

    /// Run the local independent-check pipeline (provenance gate, manifest
    /// exact-presence, byte-equivalence replay, extraction provenance).
    /// Returns `Ok(())` on success, or the bridge's error on any failed
    /// check. This must be sufficient to reject hand-rolled inputs that
    /// did not come from a live recorder — see the bridge implementation
    /// for the specific provenance check it performs.
    fn verify_independent_checks(&self) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityLevel;

    #[test]
    fn claim_scope_discriminants_match_lean() {
        // Mirrors `Shroud.Core.ClaimScope.discriminant` definitions in
        // `formal/Shroud/Core/Conformance.lean`. Bumping the Lean side
        // without updating these constants — or vice versa — is caught by
        // PR review per the protocol-semantics rule in
        // `docs/Lean Normative Spec Restructure.md` §8.
        assert_eq!(ClaimScope::CoreBatchOpening.discriminant(), 0);
        assert_eq!(ClaimScope::Plonky3UniStarkPreGrind.discriminant(), 1);
        assert_eq!(ClaimScope::Plonky3FullFriReplay.discriminant(), 2);
        assert_eq!(ClaimScope::WhirHvzk.discriminant(), 3);
    }

    #[test]
    fn upstream_citation_discriminants_match_lean() {
        // Mirrors `Shroud.Core.UpstreamCitation.discriminant`.
        assert_eq!(UpstreamCitation::BcsIop.discriminant(), 0);
        assert_eq!(UpstreamCitation::DeepFri.discriminant(), 1);
        assert_eq!(UpstreamCitation::ProximityGaps.discriminant(), 2);
        assert_eq!(UpstreamCitation::HvzkWhir.discriminant(), 3);
        assert_eq!(UpstreamCitation::HabockKindi.discriminant(), 4);
        assert_eq!(UpstreamCitation::Aurora.discriminant(), 5);
        assert_eq!(UpstreamCitation::Ligero.discriminant(), 6);
        assert_eq!(UpstreamCitation::RedShift.discriminant(), 7);
        assert_eq!(
            UpstreamCitation::SpongeIndifferentiability.discriminant(),
            8
        );
        assert_eq!(UpstreamCitation::FiatShamirRom.discriminant(), 9);
        assert_eq!(UpstreamCitation::ChiesaOrruSpongeFs.discriminant(), 10);
    }

    #[test]
    fn requires_full_live_matches_lean() {
        // Mirrors `Shroud.Core.ClaimScope.requiresFullLive`.
        assert!(!ClaimScope::CoreBatchOpening.requires_full_live());
        assert!(!ClaimScope::Plonky3UniStarkPreGrind.requires_full_live());
        assert!(ClaimScope::Plonky3FullFriReplay.requires_full_live());
        assert!(ClaimScope::WhirHvzk.requires_full_live());
    }

    #[test]
    fn backend_claim_construction_preserves_fields() {
        let claim = BackendClaim::new(
            SecurityLevel::Statistical,
            ClaimScope::Plonky3UniStarkPreGrind,
            vec![UpstreamCitation::BcsIop, UpstreamCitation::DeepFri],
        );
        assert_eq!(claim.security_level, SecurityLevel::Statistical);
        assert_eq!(claim.scope, ClaimScope::Plonky3UniStarkPreGrind);
        assert!(!claim.requires_full_live());
        assert_eq!(
            claim.citations,
            vec![UpstreamCitation::BcsIop, UpstreamCitation::DeepFri]
        );
    }
}
