/-!
Normative payload-accounting model for SHROUD batch-opening randomizers.

The module captures the public/hidden randomizer opening surface for the
statistical and perfect-variant batch-opening objects.
-/

namespace Shroud
namespace Objects

/-- Statement shape for a reduced batch-opening relation. -/
structure BatchOpeningShape where
  /-- Number of committed polynomials participating in the reduced relation. -/
  committedPolynomials : Nat
  /-- Number of opened points in the batched claim. -/
  openingPoints : Nat
  /-- Extension degree of the opening field over the base field. -/
  extensionDegree : Nat
  deriving Repr

namespace BatchOpeningShape

/-- Shape-level validity: every dimension is nonzero. -/
def Valid (shape : BatchOpeningShape) : Prop :=
  shape.committedPolynomials > 0
    /\ shape.openingPoints > 0
    /\ shape.extensionDegree > 0

/-- Public randomizer evaluations exposed by the claim surface. -/
def publicRandomizerEvaluations (shape : BatchOpeningShape) : Nat :=
  shape.openingPoints

end BatchOpeningShape

/-- How the batch-opening randomizer is represented in the proof surface. -/
inductive ProofSlotLayout where
  /-- Reuse the current optional random commitment/proof-slot shape. -/
  | reuseCurrentRandomSlot
  /-- Give the perfect randomizer a dedicated proof slot. -/
  | dedicatedPerfectRandomizerSlot
  deriving DecidableEq, Repr

/-- How hidden randomizer openings are transported inside the proof. -/
inductive HiddenOpeningTransport where
  /-- Hidden openings stay in-band with the main batch-opening proof object. -/
  | inBandWithMainOpeningProof
  /-- Hidden openings are carried by a separate auxiliary proof object. -/
  | separateAuxiliaryProof
  deriving DecidableEq, Repr

/-- Statistical randomizer model for the current Plonky3-style surrogate path. -/
structure StatisticalRandomizerSpec where
  /-- Number of base-field coordinate polynomials used in the surrogate randomizer. -/
  coordinatePolynomials : Nat
  deriving Repr

namespace StatisticalRandomizerSpec

/-- Build the statistical randomizer model from the extension degree. -/
def fromShape (shape : BatchOpeningShape) : StatisticalRandomizerSpec where
  coordinatePolynomials := shape.extensionDegree

/-- Opening payload for the statistical randomizer. -/
structure OpeningPayload where
  /-- Public extension-field evaluations exposed by the claim surface. -/
  publicExtensionEvaluations : Nat
  /-- Hidden base-field coordinate evaluations carried in the proof. -/
  hiddenBaseFieldCoordinateEvaluations : Nat
  /-- How the randomizer fits into the proof surface. -/
  proofSlotLayout : ProofSlotLayout
  /-- How hidden coordinate openings move through the proof. -/
  hiddenOpeningTransport : HiddenOpeningTransport
  deriving Repr

/-- Opening payload implied by a statistical randomizer and statement shape. -/
def openingPayload
    (spec : StatisticalRandomizerSpec)
    (shape : BatchOpeningShape) :
    OpeningPayload where
  publicExtensionEvaluations := shape.openingPoints
  hiddenBaseFieldCoordinateEvaluations :=
    shape.openingPoints * spec.coordinatePolynomials
  proofSlotLayout := ProofSlotLayout.reuseCurrentRandomSlot
  hiddenOpeningTransport := HiddenOpeningTransport.inBandWithMainOpeningProof

/-- Statistical public randomizer evaluations equal the number of opening points. -/
theorem openingPayload_publicExtensionEvaluations
    (spec : StatisticalRandomizerSpec) (shape : BatchOpeningShape) :
    (openingPayload spec shape).publicExtensionEvaluations = shape.openingPoints := by
  rfl

/-- Statistical hidden coordinate evaluations are points times coordinate polynomials. -/
theorem openingPayload_hiddenBaseFieldCoordinateEvaluations
    (spec : StatisticalRandomizerSpec) (shape : BatchOpeningShape) :
    (openingPayload spec shape).hiddenBaseFieldCoordinateEvaluations =
      shape.openingPoints * spec.coordinatePolynomials := by
  rfl

/-- The standard statistical randomizer uses one coordinate polynomial per extension degree. -/
theorem fromShape_coordinatePolynomials (shape : BatchOpeningShape) :
    (fromShape shape).coordinatePolynomials = shape.extensionDegree := by
  rfl

/-- Standard statistical hidden evaluations are points times extension degree. -/
theorem fromShape_openingPayload_hiddenBaseFieldCoordinateEvaluations
    (shape : BatchOpeningShape) :
    (openingPayload (fromShape shape) shape).hiddenBaseFieldCoordinateEvaluations =
      shape.openingPoints * shape.extensionDegree := by
  rfl

end StatisticalRandomizerSpec

/-- Realization strategy for a perfect randomizer commitment. -/
inductive PerfectRandomizerRealization where
  /-- Coordinate encoding interpreted as one exact extension-field object. -/
  | encodedOracleBundle (basisExtensionDegree : Nat)
  /-- Native extension-field PCS or equivalent extension-aware backend. -/
  | nativeExtensionPcs
  deriving DecidableEq, Repr

/-- Commitment model for a perfect batch-opening randomizer. -/
structure PerfectRandomizerCommitment where
  /-- Realization strategy. -/
  realization : PerfectRandomizerRealization
  /-- Proof-slot layout. -/
  proofSlotLayout : ProofSlotLayout
  deriving Repr

namespace PerfectRandomizerCommitment

/-- Preferred SHROUD v1 realization: exact coordinate encoding into an oracle backend. -/
def encodedOracleBundle (basisExtensionDegree : Nat) :
    PerfectRandomizerCommitment where
  realization := PerfectRandomizerRealization.encodedOracleBundle basisExtensionDegree
  proofSlotLayout := ProofSlotLayout.reuseCurrentRandomSlot

/-- Long-term realization: native extension-field commitment support. -/
def nativeExtensionPcs : PerfectRandomizerCommitment where
  realization := PerfectRandomizerRealization.nativeExtensionPcs
  proofSlotLayout := ProofSlotLayout.dedicatedPerfectRandomizerSlot

end PerfectRandomizerCommitment

/-- Hidden opening payload for the perfect randomizer. -/
inductive PerfectHiddenOpeningPayload where
  /-- Exact coordinate encoding carried as hidden base-field openings. -/
  | encodedCoordinates
      (baseFieldCoordinateEvaluations : Nat)
      (transport : HiddenOpeningTransport)
  /-- Backend carries the hidden witness internally. -/
  | backendProofOnly
      (transport : HiddenOpeningTransport)
  deriving DecidableEq, Repr

/-- Opening payload for the perfect randomizer. -/
structure PerfectRandomizerOpeningPayload where
  /-- Public extension-field evaluations exposed by the claim surface. -/
  publicExtensionEvaluations : Nat
  /-- Hidden opening payload carried in the proof. -/
  hiddenPayload : PerfectHiddenOpeningPayload
  /-- How the perfect randomizer fits into the proof surface. -/
  proofSlotLayout : ProofSlotLayout
  deriving Repr

namespace PerfectRandomizerCommitment

/-- Opening payload implied by a perfect-randomizer commitment and statement shape. -/
def openingPayload
    (commitment : PerfectRandomizerCommitment)
    (shape : BatchOpeningShape) :
    PerfectRandomizerOpeningPayload :=
  match commitment.realization with
  | PerfectRandomizerRealization.encodedOracleBundle basisExtensionDegree =>
      { publicExtensionEvaluations := shape.openingPoints
        hiddenPayload := PerfectHiddenOpeningPayload.encodedCoordinates
          (shape.openingPoints * basisExtensionDegree)
          HiddenOpeningTransport.inBandWithMainOpeningProof
        proofSlotLayout := commitment.proofSlotLayout }
  | PerfectRandomizerRealization.nativeExtensionPcs =>
      { publicExtensionEvaluations := shape.openingPoints
        hiddenPayload := PerfectHiddenOpeningPayload.backendProofOnly
          HiddenOpeningTransport.separateAuxiliaryProof
        proofSlotLayout := commitment.proofSlotLayout }

/-- Encoded-bundle public evaluations equal the number of opening points. -/
theorem encodedOpeningPayload_publicExtensionEvaluations
    (shape : BatchOpeningShape) (basisExtensionDegree : Nat) :
    (openingPayload (encodedOracleBundle basisExtensionDegree) shape).publicExtensionEvaluations =
      shape.openingPoints := by
  rfl

/-- Encoded-bundle hidden coordinates are points times basis extension degree. -/
theorem encodedOpeningPayload_hiddenCoordinates
    (shape : BatchOpeningShape) (basisExtensionDegree : Nat) :
    (openingPayload (encodedOracleBundle basisExtensionDegree) shape).hiddenPayload =
      PerfectHiddenOpeningPayload.encodedCoordinates
        (shape.openingPoints * basisExtensionDegree)
        HiddenOpeningTransport.inBandWithMainOpeningProof := by
  rfl

/-- Native-extension payload carries hidden material inside the backend proof. -/
theorem nativeOpeningPayload_backendProofOnly
    (shape : BatchOpeningShape) :
    (openingPayload nativeExtensionPcs shape).hiddenPayload =
      PerfectHiddenOpeningPayload.backendProofOnly
        HiddenOpeningTransport.separateAuxiliaryProof := by
  rfl

end PerfectRandomizerCommitment

end Objects
end Shroud
