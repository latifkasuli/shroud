import Shroud.Core.Degree
import Shroud.Core.Security

/-!
Normative payload-accounting model for SHROUD quotient hiders.

This module covers the quotient-hider object surface: decomposition family,
query budget, exact public/hidden payload counts, and the requirement that
degree-chunked decompositions carry a degree contract.
-/

namespace Shroud
namespace Objects

open Shroud.Core

/-- Quotient decomposition family supported by the hiding transform. -/
inductive QuotientDecompositionFamily where
  /-- A single monolithic quotient object is committed and opened. -/
  | monolithic
  /-- The quotient is split into degree-bounded chunks. -/
  | degreeChunked
  /-- The quotient uses a segmented backend-specific decomposition family. -/
  | segmented
  deriving DecidableEq, Repr

/-- How hidden quotient witness material is transported through the outer proof. -/
inductive QuotientAuxiliaryTransport where
  /-- Hidden quotient auxiliaries stay in-band with the opening proof. -/
  | inBandWithOpeningProof
  /-- Hidden quotient auxiliaries move in a separate proof envelope. -/
  | separateAuxiliaryProof
  deriving DecidableEq, Repr

/-- Shape of the hidden quotient-opening surface. -/
structure QuotientHiderShape where
  /-- Number of committed quotient components. -/
  decompositionComponents : Nat
  /-- Number of queried opening points used by the verifier. -/
  openingPoints : Nat
  /-- Number of public quotient evaluations revealed per opening point. -/
  openingsPerPoint : Nat
  /-- Number of hidden quotient-mask values carried per opening point. -/
  hiddenMaskValuesPerPoint : Nat
  /-- Number of hidden normalization items carried by the proof. -/
  hiddenNormalizationItems : Nat
  deriving Repr

namespace QuotientHiderShape

/-- Shape-level validity: every quotient-hider dimension is nonzero. -/
def Valid (shape : QuotientHiderShape) : Prop :=
  shape.decompositionComponents > 0
    /\ shape.openingPoints > 0
    /\ shape.openingsPerPoint > 0
    /\ shape.hiddenMaskValuesPerPoint > 0
    /\ shape.hiddenNormalizationItems > 0

end QuotientHiderShape

/-- Public-vs-hidden surface implied by a quotient-hider object. -/
structure QuotientHiderPayload where
  /-- Number of public quotient commitments carried by the outer proof. -/
  publicCommitments : Nat
  /-- Number of public quotient opening values revealed by the outer proof. -/
  publicOpeningValues : Nat
  /-- Number of hidden quotient-mask values carried in the proof. -/
  hiddenMaskValues : Nat
  /-- Number of hidden normalization items carried in the proof. -/
  hiddenNormalizationItems : Nat
  /-- Transport used for hidden quotient auxiliary material. -/
  auxiliaryTransport : QuotientAuxiliaryTransport
  deriving Repr

namespace QuotientHiderPayload

/-- Payload deterministically derived from a quotient-hider shape. -/
def fromShape
    (shape : QuotientHiderShape)
    (auxiliaryTransport : QuotientAuxiliaryTransport) :
    QuotientHiderPayload where
  publicCommitments := shape.decompositionComponents
  publicOpeningValues := shape.openingPoints * shape.openingsPerPoint
  hiddenMaskValues := shape.openingPoints * shape.hiddenMaskValuesPerPoint
  hiddenNormalizationItems := shape.hiddenNormalizationItems
  auxiliaryTransport := auxiliaryTransport

/-- Public commitments equal the number of decomposition components. -/
theorem fromShape_publicCommitments
    (shape : QuotientHiderShape) (transport : QuotientAuxiliaryTransport) :
    (fromShape shape transport).publicCommitments =
      shape.decompositionComponents := by
  rfl

/-- Public opening values are opening points times openings per point. -/
theorem fromShape_publicOpeningValues
    (shape : QuotientHiderShape) (transport : QuotientAuxiliaryTransport) :
    (fromShape shape transport).publicOpeningValues =
      shape.openingPoints * shape.openingsPerPoint := by
  rfl

/-- Hidden mask values are opening points times hidden mask values per point. -/
theorem fromShape_hiddenMaskValues
    (shape : QuotientHiderShape) (transport : QuotientAuxiliaryTransport) :
    (fromShape shape transport).hiddenMaskValues =
      shape.openingPoints * shape.hiddenMaskValuesPerPoint := by
  rfl

/-- Hidden normalization items are copied from the shape. -/
theorem fromShape_hiddenNormalizationItems
    (shape : QuotientHiderShape) (transport : QuotientAuxiliaryTransport) :
    (fromShape shape transport).hiddenNormalizationItems =
      shape.hiddenNormalizationItems := by
  rfl

end QuotientHiderPayload

/-- Whether a decomposition family requires an explicit quotient degree contract. -/
def RequiresDegreeContract : QuotientDecompositionFamily -> Prop
  | QuotientDecompositionFamily.monolithic => False
  | QuotientDecompositionFamily.degreeChunked => True
  | QuotientDecompositionFamily.segmented => False

/-- SHROUD object for hidden quotient commitments and openings. -/
structure ShroudQuotientHiderSpec where
  /-- Declared security level. -/
  securityLevel : SecurityLevel
  /-- Quotient decomposition family supported by the object. -/
  decompositionFamily : QuotientDecompositionFamily
  /-- Claimed query budget for the hiding guarantee. -/
  queryBudget : Nat
  /-- Hidden quotient-opening shape. -/
  shape : QuotientHiderShape
  /-- Derived public-vs-hidden quotient-hider payload. -/
  payload : QuotientHiderPayload
  /-- Optional degree compatibility contract. -/
  degreeContract : Option QuotientDegreeContract
  deriving Repr

namespace ShroudQuotientHiderSpec

/-- The optional degree-contract field satisfies the decomposition requirement. -/
def DegreeContractRequirementSatisfied (spec : ShroudQuotientHiderSpec) : Prop :=
  RequiresDegreeContract spec.decompositionFamily -> spec.degreeContract.isSome

/-- Any present degree contract satisfies the quotient degree-contract predicate. -/
def DegreeContractValidWhenPresent (spec : ShroudQuotientHiderSpec) : Prop :=
  match spec.degreeContract with
  | none => True
  | some contract => contract.Valid

/-- Monolithic decomposition exposes exactly one quotient component. -/
def MonolithicShapeSatisfied (spec : ShroudQuotientHiderSpec) : Prop :=
  spec.decompositionFamily = QuotientDecompositionFamily.monolithic ->
    spec.shape.decompositionComponents = 1

/-- Validity predicate for quotient-hider shape, decomposition, and payload consistency. -/
def Valid (spec : ShroudQuotientHiderSpec) : Prop :=
  spec.queryBudget > 0
    /\ spec.shape.Valid
    /\ spec.shape.openingPoints <= spec.queryBudget
    /\ spec.MonolithicShapeSatisfied
    /\ spec.DegreeContractRequirementSatisfied
    /\ spec.DegreeContractValidWhenPresent
    /\ spec.payload.publicCommitments = spec.shape.decompositionComponents
    /\ spec.payload.publicOpeningValues =
      spec.shape.openingPoints * spec.shape.openingsPerPoint
    /\ spec.payload.hiddenMaskValues =
      spec.shape.openingPoints * spec.shape.hiddenMaskValuesPerPoint
    /\ spec.payload.hiddenNormalizationItems =
      spec.shape.hiddenNormalizationItems

/-- Valid quotient hiders keep opening points within the query budget. -/
theorem valid_implies_openingPoints_le_queryBudget
    (spec : ShroudQuotientHiderSpec) (h : spec.Valid) :
    spec.shape.openingPoints <= spec.queryBudget :=
  by
    rcases h with ⟨_, _, hOpeningPoints, _⟩
    exact hOpeningPoints

/-- Valid degree-chunked quotient hiders carry a degree contract. -/
theorem valid_degreeChunked_implies_degreeContract_isSome
    (spec : ShroudQuotientHiderSpec)
    (h : spec.Valid)
    (hFamily : spec.decompositionFamily = QuotientDecompositionFamily.degreeChunked) :
    spec.degreeContract.isSome := by
  rcases h with ⟨_, _, _, _, hDegreeContractRequired, _⟩
  apply hDegreeContractRequired
  rw [hFamily]
  trivial

/-- Valid quotient hiders validate any degree contract they contain. -/
theorem valid_implies_degreeContractValidWhenPresent
    (spec : ShroudQuotientHiderSpec) (h : spec.Valid) :
    spec.DegreeContractValidWhenPresent := by
  rcases h with ⟨_, _, _, _, _, hDegreeContractValid, _⟩
  exact hDegreeContractValid

/-- If a valid quotient hider contains a specific degree contract, that contract is valid. -/
theorem valid_some_degreeContract_implies_contract_valid
    (spec : ShroudQuotientHiderSpec)
    (contract : QuotientDegreeContract)
    (h : spec.Valid)
    (hSome : spec.degreeContract = some contract) :
    contract.Valid := by
  have hValidWhenPresent := valid_implies_degreeContractValidWhenPresent spec h
  rw [DegreeContractValidWhenPresent, hSome] at hValidWhenPresent
  exact hValidWhenPresent

/-- Valid degree-chunked quotient hiders contain a valid degree contract. -/
theorem valid_degreeChunked_implies_exists_valid_degreeContract
    (spec : ShroudQuotientHiderSpec)
    (h : spec.Valid)
    (hFamily : spec.decompositionFamily = QuotientDecompositionFamily.degreeChunked) :
    ∃ contract, spec.degreeContract = some contract /\ contract.Valid := by
  have hSome := valid_degreeChunked_implies_degreeContract_isSome spec h hFamily
  cases hContract : spec.degreeContract with
  | none =>
      rw [hContract] at hSome
      contradiction
  | some contract =>
      exact ⟨contract, rfl,
        valid_some_degreeContract_implies_contract_valid spec contract h hContract⟩

/-- Valid monolithic quotient hiders have exactly one decomposition component. -/
theorem valid_monolithic_implies_singleComponent
    (spec : ShroudQuotientHiderSpec)
    (h : spec.Valid)
    (hFamily : spec.decompositionFamily = QuotientDecompositionFamily.monolithic) :
    spec.shape.decompositionComponents = 1 := by
  rcases h with ⟨_, _, _, hMonolithicShape, _⟩
  exact hMonolithicShape hFamily

/-- Valid quotient-hider payloads expose opening points times openings per point. -/
theorem valid_implies_publicOpeningValues_eq
    (spec : ShroudQuotientHiderSpec) (h : spec.Valid) :
    spec.payload.publicOpeningValues =
      spec.shape.openingPoints * spec.shape.openingsPerPoint :=
  by
    rcases h with ⟨_, _, _, _, _, _, _, hPublicOpeningValues, _⟩
    exact hPublicOpeningValues

/-- Valid quotient-hider payloads carry opening points times hidden masks per point. -/
theorem valid_implies_hiddenMaskValues_eq
    (spec : ShroudQuotientHiderSpec) (h : spec.Valid) :
    spec.payload.hiddenMaskValues =
      spec.shape.openingPoints * spec.shape.hiddenMaskValuesPerPoint :=
  by
    rcases h with ⟨_, _, _, _, _, _, _, _, hHiddenMaskValues, _⟩
    exact hHiddenMaskValues

/-- Valid quotient-hider payloads preserve the hidden normalization item count. -/
theorem valid_implies_hiddenNormalizationItems_eq
    (spec : ShroudQuotientHiderSpec) (h : spec.Valid) :
    spec.payload.hiddenNormalizationItems =
      spec.shape.hiddenNormalizationItems :=
  by
    rcases h with ⟨_, _, _, _, _, _, _, _, _, hHiddenNormalizationItems⟩
    exact hHiddenNormalizationItems

end ShroudQuotientHiderSpec

end Objects
end Shroud
