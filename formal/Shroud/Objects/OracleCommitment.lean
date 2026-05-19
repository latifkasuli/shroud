import Shroud.Core.Security

/-!
Normative payload-accounting model for SHROUD oracle commitments.

This module states oracle opening payloads over exact natural-number products.
Rust implementations must compute these counts exactly or reject finite-machine
overflow before constructing a validated shape.
-/

namespace Shroud
namespace Objects

open Shroud.Core

/-- How row-hiding witness material is transported through the outer proof. -/
inductive OracleAuxiliaryTransport where
  /-- Hidden row-hiding witness material stays in-band with the opening proof. -/
  | inBandWithOpeningProof
  /-- Hidden row-hiding witness material moves in a separate auxiliary proof path. -/
  | separateAuxiliaryProof
  deriving DecidableEq, Repr

/-- Shape of the hidden oracle-commitment opening surface. -/
structure OracleCommitmentShape where
  /-- Number of committed oracle objects. -/
  committedOracles : Nat
  /-- Number of queried rows opened by the backend. -/
  queriedRows : Nat
  /-- Number of public row values exposed per queried row. -/
  rowWidth : Nat
  /-- Number of public authentication items exposed per queried row. -/
  authenticationItemsPerQuery : Nat
  /-- Number of hidden row-hiding witness items carried per queried row. -/
  hiddenHidingWitnessItemsPerQuery : Nat
  deriving Repr

namespace OracleCommitmentShape

/-- Shape-level validity: every oracle-opening dimension is nonzero. -/
def Valid (shape : OracleCommitmentShape) : Prop :=
  shape.committedOracles > 0
    /\ shape.queriedRows > 0
    /\ shape.rowWidth > 0
    /\ shape.authenticationItemsPerQuery > 0
    /\ shape.hiddenHidingWitnessItemsPerQuery > 0

end OracleCommitmentShape

/-- Public-vs-hidden opening payload implied by a hidden oracle-commitment object. -/
structure OracleCommitmentPayload where
  /-- Number of public commitment objects carried by the outer proof. -/
  publicCommitments : Nat
  /-- Number of public row values revealed by the opening surface. -/
  publicRowValues : Nat
  /-- Number of public authentication items revealed by the opening surface. -/
  publicAuthenticationItems : Nat
  /-- Number of hidden row-hiding witness items carried in the proof. -/
  hiddenHidingWitnessItems : Nat
  /-- Transport used for hidden row-hiding witness material. -/
  auxiliaryTransport : OracleAuxiliaryTransport
  deriving Repr

namespace OracleCommitmentPayload

/-- Payload deterministically derived from an oracle-commitment shape. -/
def fromShape
    (shape : OracleCommitmentShape)
    (auxiliaryTransport : OracleAuxiliaryTransport) :
    OracleCommitmentPayload where
  publicCommitments := shape.committedOracles
  publicRowValues := shape.queriedRows * shape.rowWidth
  publicAuthenticationItems :=
    shape.queriedRows * shape.authenticationItemsPerQuery
  hiddenHidingWitnessItems :=
    shape.queriedRows * shape.hiddenHidingWitnessItemsPerQuery
  auxiliaryTransport := auxiliaryTransport

/-- Public commitments equal the number of committed oracle objects. -/
theorem fromShape_publicCommitments
    (shape : OracleCommitmentShape) (transport : OracleAuxiliaryTransport) :
    (fromShape shape transport).publicCommitments = shape.committedOracles := by
  rfl

/-- Public row values are queried rows times row width. -/
theorem fromShape_publicRowValues
    (shape : OracleCommitmentShape) (transport : OracleAuxiliaryTransport) :
    (fromShape shape transport).publicRowValues =
      shape.queriedRows * shape.rowWidth := by
  rfl

/-- Public authentication items are queried rows times authentication items per query. -/
theorem fromShape_publicAuthenticationItems
    (shape : OracleCommitmentShape) (transport : OracleAuxiliaryTransport) :
    (fromShape shape transport).publicAuthenticationItems =
      shape.queriedRows * shape.authenticationItemsPerQuery := by
  rfl

/-- Hidden witness items are queried rows times hidden witness items per query. -/
theorem fromShape_hiddenHidingWitnessItems
    (shape : OracleCommitmentShape) (transport : OracleAuxiliaryTransport) :
    (fromShape shape transport).hiddenHidingWitnessItems =
      shape.queriedRows * shape.hiddenHidingWitnessItemsPerQuery := by
  rfl

end OracleCommitmentPayload

/-- SHROUD object for hidden oracle commitments. -/
structure ShroudOracleCommitmentSpec where
  /-- Declared security level. -/
  securityLevel : SecurityLevel
  /-- Hidden oracle-commitment opening shape. -/
  shape : OracleCommitmentShape
  /-- Derived public-vs-hidden opening payload. -/
  payload : OracleCommitmentPayload
  deriving Repr

namespace ShroudOracleCommitmentSpec

/-- Validity predicate for oracle-commitment shape and payload consistency. -/
def Valid (spec : ShroudOracleCommitmentSpec) : Prop :=
  spec.shape.Valid
    /\ spec.payload.publicCommitments = spec.shape.committedOracles
    /\ spec.payload.publicRowValues = spec.shape.queriedRows * spec.shape.rowWidth
    /\ spec.payload.publicAuthenticationItems =
      spec.shape.queriedRows * spec.shape.authenticationItemsPerQuery
    /\ spec.payload.hiddenHidingWitnessItems =
      spec.shape.queriedRows * spec.shape.hiddenHidingWitnessItemsPerQuery

/-- Valid oracle commitments expose queried rows times row width public values. -/
theorem valid_implies_publicRowValues_eq
    (spec : ShroudOracleCommitmentSpec) (h : spec.Valid) :
    spec.payload.publicRowValues = spec.shape.queriedRows * spec.shape.rowWidth :=
  h.2.2.1

/-- Valid oracle commitments expose queried rows times authentication items. -/
theorem valid_implies_publicAuthenticationItems_eq
    (spec : ShroudOracleCommitmentSpec) (h : spec.Valid) :
    spec.payload.publicAuthenticationItems =
      spec.shape.queriedRows * spec.shape.authenticationItemsPerQuery :=
  h.2.2.2.1

/-- Valid oracle commitments carry queried rows times hidden witness items. -/
theorem valid_implies_hiddenHidingWitnessItems_eq
    (spec : ShroudOracleCommitmentSpec) (h : spec.Valid) :
    spec.payload.hiddenHidingWitnessItems =
      spec.shape.queriedRows * spec.shape.hiddenHidingWitnessItemsPerQuery :=
  h.2.2.2.2

end ShroudOracleCommitmentSpec

end Objects
end Shroud
