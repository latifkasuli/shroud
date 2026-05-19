/-!
Normative security-level vocabulary for SHROUD.

This mirrors the Rust `SecurityLevel` enum.  It only records the declared
privacy level; object-specific claim obligations are introduced in later
modules.
-/

namespace Shroud
namespace Core

/-- Declared hiding level of a SHROUD protocol object. -/
inductive SecurityLevel where
  /-- Statistical hiding under an explicit query/security budget. -/
  | statistical
  /-- Perfect-variant hiding, valid only with the required claim obligations. -/
  | perfect
  deriving DecidableEq, Repr

namespace SecurityLevel

/-- Stable discriminant used by the Rust transcript-binding mirror. -/
def discriminant : SecurityLevel -> Nat
  | statistical => 0
  | perfect => 1

/-- Statistical and perfect security levels have distinct discriminants. -/
theorem statistical_discriminant_ne_perfect :
    discriminant statistical != discriminant perfect := by
  decide

end SecurityLevel

end Core
end Shroud
