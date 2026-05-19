import Shroud.Core.Security

/-!
Normative payload-accounting model for SHROUD opening projections.

Opening projection is a direct public/hidden split: payload fields copy the
validated shape and record how hidden auxiliary opening material is transported.
-/

namespace Shroud
namespace Objects

open Shroud.Core

/-- How hidden auxiliary opening material is carried through the outer proof. -/
inductive AuxiliaryOpeningTransport where
  /-- Hidden auxiliaries stay in-band with the main opening proof. -/
  | inBandWithMainProof
  /-- Hidden auxiliaries move in a separate proof envelope. -/
  | separateAuxiliaryProof
  deriving DecidableEq, Repr

/-- Shape of the public-vs-hidden opening split. -/
structure OpeningProjectionShape where
  /-- Number of verifier-visible opening values. -/
  publicOpeningValues : Nat
  /-- Number of hidden auxiliary opening values carried in the proof. -/
  hiddenAuxiliaryValues : Nat
  /-- Number of internal reconstruction items the verifier needs. -/
  verifierReconstructionItems : Nat
  deriving Repr

namespace OpeningProjectionShape

/-- Shape-level validity: every opening-projection dimension is nonzero. -/
def Valid (shape : OpeningProjectionShape) : Prop :=
  shape.publicOpeningValues > 0
    /\ shape.hiddenAuxiliaryValues > 0
    /\ shape.verifierReconstructionItems > 0

end OpeningProjectionShape

/-- Concrete public-vs-hidden opening surface implied by a projection object. -/
structure OpeningProjectionPayload where
  /-- Public opening values carried by the outer statement surface. -/
  publicOpeningValues : Nat
  /-- Hidden auxiliary opening values carried in the proof. -/
  hiddenAuxiliaryValues : Nat
  /-- Verifier reconstruction items implied by the projection. -/
  verifierReconstructionItems : Nat
  /-- Transport mechanism for hidden auxiliary opening material. -/
  auxiliaryTransport : AuxiliaryOpeningTransport
  deriving Repr

namespace OpeningProjectionPayload

/-- Payload deterministically derived from an opening-projection shape. -/
def fromShape
    (shape : OpeningProjectionShape)
    (auxiliaryTransport : AuxiliaryOpeningTransport) :
    OpeningProjectionPayload where
  publicOpeningValues := shape.publicOpeningValues
  hiddenAuxiliaryValues := shape.hiddenAuxiliaryValues
  verifierReconstructionItems := shape.verifierReconstructionItems
  auxiliaryTransport := auxiliaryTransport

/-- Public opening values are copied from the shape. -/
theorem fromShape_publicOpeningValues
    (shape : OpeningProjectionShape) (transport : AuxiliaryOpeningTransport) :
    (fromShape shape transport).publicOpeningValues =
      shape.publicOpeningValues := by
  rfl

/-- Hidden auxiliary values are copied from the shape. -/
theorem fromShape_hiddenAuxiliaryValues
    (shape : OpeningProjectionShape) (transport : AuxiliaryOpeningTransport) :
    (fromShape shape transport).hiddenAuxiliaryValues =
      shape.hiddenAuxiliaryValues := by
  rfl

/-- Verifier reconstruction items are copied from the shape. -/
theorem fromShape_verifierReconstructionItems
    (shape : OpeningProjectionShape) (transport : AuxiliaryOpeningTransport) :
    (fromShape shape transport).verifierReconstructionItems =
      shape.verifierReconstructionItems := by
  rfl

end OpeningProjectionPayload

/-- SHROUD object that projects public openings away from hidden auxiliaries. -/
structure ShroudOpeningProjectionSpec where
  /-- Declared security level. -/
  securityLevel : SecurityLevel
  /-- Projection shape. -/
  shape : OpeningProjectionShape
  /-- Derived opening payload. -/
  payload : OpeningProjectionPayload
  deriving Repr

namespace ShroudOpeningProjectionSpec

/-- Validity predicate for opening-projection shape and payload consistency. -/
def Valid (spec : ShroudOpeningProjectionSpec) : Prop :=
  spec.shape.Valid
    /\ spec.payload.publicOpeningValues = spec.shape.publicOpeningValues
    /\ spec.payload.hiddenAuxiliaryValues = spec.shape.hiddenAuxiliaryValues
    /\ spec.payload.verifierReconstructionItems =
      spec.shape.verifierReconstructionItems

/-- Valid projection payloads preserve the public opening count. -/
theorem valid_implies_publicOpeningValues_eq
    (spec : ShroudOpeningProjectionSpec) (h : spec.Valid) :
    spec.payload.publicOpeningValues = spec.shape.publicOpeningValues :=
  h.2.1

/-- Valid projection payloads preserve the hidden auxiliary count. -/
theorem valid_implies_hiddenAuxiliaryValues_eq
    (spec : ShroudOpeningProjectionSpec) (h : spec.Valid) :
    spec.payload.hiddenAuxiliaryValues = spec.shape.hiddenAuxiliaryValues :=
  h.2.2.1

/-- Valid projection payloads preserve the verifier reconstruction count. -/
theorem valid_implies_verifierReconstructionItems_eq
    (spec : ShroudOpeningProjectionSpec) (h : spec.Valid) :
    spec.payload.verifierReconstructionItems =
      spec.shape.verifierReconstructionItems :=
  h.2.2.2

end ShroudOpeningProjectionSpec

end Objects
end Shroud
