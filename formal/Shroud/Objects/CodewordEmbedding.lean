import Shroud.Core.Security

/-!
Normative payload-accounting model for SHROUD codeword embeddings.

This module mirrors the protocol-level fields of `shroud-codeword-embedding`.
It states exact arithmetic over natural numbers; Rust implementations must
either compute the same values or reject finite-machine overflow.
-/

namespace Shroud
namespace Objects

open Shroud.Core

/-- Transport mechanism for hidden codeword-embedding auxiliary material. -/
inductive AuxiliaryTransport where
  /-- Hidden material travels in-band with the primary proof object. -/
  | inBand
  /-- Hidden material moves in a separate proof envelope. -/
  | separateEnvelope
  deriving DecidableEq, Repr

/-- Shape of a codeword embedding: trace, randomizer, domain, and field parameters. -/
structure CodewordEmbeddingShape where
  /-- Number of public trace columns. -/
  traceColumns : Nat
  /-- Number of hidden randomizer columns. -/
  randomizerColumns : Nat
  /-- Log base 2 of the trace evaluation domain size. -/
  domainLogSize : Nat
  /-- Extension degree of the challenge field over the base field. -/
  extensionDegree : Nat
  deriving Repr

namespace CodewordEmbeddingShape

/-- Shape-level validity: every dimension is nonzero. -/
def Valid (shape : CodewordEmbeddingShape) : Prop :=
  shape.traceColumns > 0
    /\ shape.randomizerColumns > 0
    /\ shape.domainLogSize > 0
    /\ shape.extensionDegree > 0

/-- Total committed columns: trace columns plus randomizer columns. -/
def committedColumns (shape : CodewordEmbeddingShape) : Nat :=
  shape.traceColumns + shape.randomizerColumns

end CodewordEmbeddingShape

/-- Public-vs-hidden surface implied by a codeword embedding object. -/
structure CodewordEmbeddingPayload where
  /-- Total committed columns. -/
  committedColumns : Nat
  /-- Number of public trace columns. -/
  publicTraceColumns : Nat
  /-- Number of hidden randomizer columns. -/
  hiddenRandomizerColumns : Nat
  /-- Log base 2 of the trace evaluation domain size. -/
  domainLogSize : Nat
  /-- Minimum FRI log blowup required by the embedding. -/
  requiredLogBlowup : Nat
  /-- Transport for hidden randomizer opening material. -/
  auxiliaryTransport : AuxiliaryTransport
  deriving Repr

namespace CodewordEmbeddingPayload

/-- Payload deterministically derived from a shape, required blowup, and transport. -/
def fromShape
    (shape : CodewordEmbeddingShape)
    (requiredLogBlowup : Nat)
    (auxiliaryTransport : AuxiliaryTransport) :
    CodewordEmbeddingPayload where
  committedColumns := shape.committedColumns
  publicTraceColumns := shape.traceColumns
  hiddenRandomizerColumns := shape.randomizerColumns
  domainLogSize := shape.domainLogSize
  requiredLogBlowup := requiredLogBlowup
  auxiliaryTransport := auxiliaryTransport

/-- The payload's committed-column count is trace plus randomizer columns. -/
theorem fromShape_committedColumns
    (shape : CodewordEmbeddingShape)
    (requiredLogBlowup : Nat)
    (transport : AuxiliaryTransport) :
    (fromShape shape requiredLogBlowup transport).committedColumns =
      shape.traceColumns + shape.randomizerColumns := by
  rfl

/-- The payload's public trace-column count is the shape trace-column count. -/
theorem fromShape_publicTraceColumns
    (shape : CodewordEmbeddingShape)
    (requiredLogBlowup : Nat)
    (transport : AuxiliaryTransport) :
    (fromShape shape requiredLogBlowup transport).publicTraceColumns =
      shape.traceColumns := by
  rfl

/-- The payload's hidden randomizer-column count is the shape randomizer-column count. -/
theorem fromShape_hiddenRandomizerColumns
    (shape : CodewordEmbeddingShape)
    (requiredLogBlowup : Nat)
    (transport : AuxiliaryTransport) :
    (fromShape shape requiredLogBlowup transport).hiddenRandomizerColumns =
      shape.randomizerColumns := by
  rfl

end CodewordEmbeddingPayload

/-- Codeword-embedding spec with its derived payload. -/
structure ShroudCodewordEmbeddingSpec where
  /-- Declared security level. -/
  securityLevel : SecurityLevel
  /-- Embedding shape. -/
  shape : CodewordEmbeddingShape
  /-- Derived public-vs-hidden payload. -/
  payload : CodewordEmbeddingPayload
  deriving Repr

namespace ShroudCodewordEmbeddingSpec

/--
Validity for the current statistical codeword-embedding object.

Perfect codeword embedding is intentionally not valid here until a dedicated
perfect constructor carries the required perfect claim.
-/
def Valid (spec : ShroudCodewordEmbeddingSpec) : Prop :=
  spec.securityLevel = SecurityLevel.statistical
    /\ spec.shape.Valid
    /\ spec.shape.randomizerColumns = spec.shape.extensionDegree
    /\ spec.payload.requiredLogBlowup >= 2
    /\ spec.payload.committedColumns = spec.shape.committedColumns
    /\ spec.payload.publicTraceColumns = spec.shape.traceColumns
    /\ spec.payload.hiddenRandomizerColumns = spec.shape.randomizerColumns
    /\ spec.payload.domainLogSize = spec.shape.domainLogSize

/-- Statistical validity requires one randomizer column per extension coordinate. -/
theorem valid_implies_randomizerColumns_eq_extensionDegree
    (spec : ShroudCodewordEmbeddingSpec) (h : spec.Valid) :
    spec.shape.randomizerColumns = spec.shape.extensionDegree :=
  h.2.2.1

/-- Statistical validity requires at least log-blowup 2. -/
theorem valid_implies_requiredLogBlowup_atLeastTwo
    (spec : ShroudCodewordEmbeddingSpec) (h : spec.Valid) :
    spec.payload.requiredLogBlowup >= 2 :=
  h.2.2.2.1

/-- Valid payload accounting preserves the trace-plus-randomizer committed-column count. -/
theorem valid_implies_committedColumns_eq_trace_plus_randomizer
    (spec : ShroudCodewordEmbeddingSpec) (h : spec.Valid) :
    spec.payload.committedColumns =
      spec.shape.traceColumns + spec.shape.randomizerColumns := by
  rw [h.2.2.2.2.1]
  rfl

end ShroudCodewordEmbeddingSpec

end Objects
end Shroud
