/-!
Normative degree-budget model for SHROUD masking rules.

This module gives the first Lean-backed algebraic contract for SHROUD.  It
mirrors the Rust `DegreeBudget` object and the quotient-hider degree contract,
but states the rules as mathematical predicates over natural-number degree
bounds.
-/

namespace Shroud
namespace Core

/-- Degree budget for the masked batch-opening relation. -/
structure DegreeBudget where
  /-- Degree bound of the unmasked reduced batch-opening relation. -/
  relationDegree : Nat
  /-- Degree bound of the randomizer polynomial before quotienting by `(X - zeta)`. -/
  randomizerDegree : Nat
  deriving Repr

namespace DegreeBudget

/--
Validity condition for the batch-opening degree budget.

The randomizer may be one degree higher than the relation because
`(R(X) - R(zeta)) / (X - zeta)` lowers its degree by one.
-/
def Valid (budget : DegreeBudget) : Prop :=
  budget.randomizerDegree <= budget.relationDegree + 1

/-- Degree bound of `(R(X) - R(zeta)) / (X - zeta)`. -/
def randomizerTermDegree (budget : DegreeBudget) : Nat :=
  budget.randomizerDegree - 1

/-- Degree bound of the masked relation after adding the randomizer term. -/
def maskedRelationDegreeBound (budget : DegreeBudget) : Nat :=
  max budget.relationDegree budget.randomizerTermDegree

/-- A budget preserves the original relation degree class. -/
def PreservesRelationDegree (budget : DegreeBudget) : Prop :=
  budget.maskedRelationDegreeBound <= budget.relationDegree

/-- Validity is exactly the Rust constructor's degree inequality. -/
theorem valid_iff_randomizer_le_relation_succ (budget : DegreeBudget) :
    budget.Valid <-> budget.randomizerDegree <= budget.relationDegree + 1 := by
  rfl

/-- The masked degree bound is the maximum of the relation and randomizer-term bounds. -/
theorem maskedRelationDegreeBound_eq (budget : DegreeBudget) :
    budget.maskedRelationDegreeBound =
      max budget.relationDegree (budget.randomizerDegree - 1) := by
  rfl

/-- A valid randomizer contributes a term no larger than the relation degree. -/
theorem valid_implies_randomizerTerm_le_relation
    (budget : DegreeBudget) (h : budget.Valid) :
    budget.randomizerTermDegree <= budget.relationDegree := by
  unfold Valid randomizerTermDegree at *
  omega

/-- A valid degree budget keeps the masked relation inside the original degree class. -/
theorem valid_preservesRelationDegree
    (budget : DegreeBudget) (h : budget.Valid) :
    budget.PreservesRelationDegree := by
  unfold PreservesRelationDegree maskedRelationDegreeBound randomizerTermDegree
  apply Nat.max_le.mpr
  constructor
  · exact Nat.le_refl budget.relationDegree
  · exact valid_implies_randomizerTerm_le_relation budget h

/-- If a masked relation preserves the degree class, its randomizer budget is valid. -/
theorem preservesRelationDegree_implies_valid
    (budget : DegreeBudget) (h : budget.PreservesRelationDegree) :
    budget.Valid := by
  unfold PreservesRelationDegree maskedRelationDegreeBound randomizerTermDegree Valid at *
  have hterm := (Nat.max_le.mp h).2
  omega

/--
Batch-opening budget validity is equivalent to preserving the relation degree
class after masking.
-/
theorem valid_iff_preservesRelationDegree (budget : DegreeBudget) :
    budget.Valid <-> budget.PreservesRelationDegree := by
  constructor
  · exact valid_preservesRelationDegree budget
  · exact preservesRelationDegree_implies_valid budget

end DegreeBudget

/-- Degree compatibility contract for a quotient decomposition. -/
structure QuotientDegreeContract where
  /-- Degree of `q_i(X)` before masking. -/
  quotientChunkDegree : Nat
  /-- Degree of the vanishing polynomial factor; zero for plain additive hiding. -/
  vanishingPolyDegree : Nat
  /-- Degree of the mask polynomial. -/
  maskPolyDegree : Nat
  /-- Degree bound of the masked quotient chunk as committed. -/
  randomizedChunkDegreeBound : Nat
  deriving Repr

namespace QuotientDegreeContract

/-- Required committed degree for the declared quotient mask form. -/
def requiredDegree (contract : QuotientDegreeContract) : Nat :=
  max contract.quotientChunkDegree
    (contract.vanishingPolyDegree + contract.maskPolyDegree)

/-- Validity condition for a quotient degree contract. -/
def Valid (contract : QuotientDegreeContract) : Prop :=
  contract.requiredDegree <= contract.randomizedChunkDegreeBound

/-- Plain additive quotient masking has no vanishing factor. -/
def PlainAdditive (contract : QuotientDegreeContract) : Prop :=
  contract.vanishingPolyDegree = 0
    /\ contract.randomizedChunkDegreeBound = contract.quotientChunkDegree

/-- Plain additive masking is valid exactly when the mask degree fits the chunk. -/
theorem plain_valid_iff_mask_le_chunk
    (contract : QuotientDegreeContract)
    (hPlain : contract.PlainAdditive) :
    contract.Valid <-> contract.maskPolyDegree <= contract.quotientChunkDegree := by
  unfold Valid requiredDegree PlainAdditive at *
  omega

/--
Vanishing-factor quotient masking is valid exactly when the required degree is
within the randomized chunk bound.
-/
theorem vanishing_valid_iff_required_le_bound
    (contract : QuotientDegreeContract) :
    contract.Valid <-> max contract.quotientChunkDegree
      (contract.vanishingPolyDegree + contract.maskPolyDegree)
        <= contract.randomizedChunkDegreeBound := by
  rfl

/-- A valid quotient degree contract bounds the committed masked chunk degree. -/
theorem valid_implies_requiredDegree_le_bound
    (contract : QuotientDegreeContract) (h : contract.Valid) :
    contract.requiredDegree <= contract.randomizedChunkDegreeBound := h

end QuotientDegreeContract

end Core
end Shroud
