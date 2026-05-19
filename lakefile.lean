import Lake
open Lake DSL

package «shroud» where
  version := v!"0.1.0"
  keywords := #["zero-knowledge", "formal-verification", "protocol-specification"]

@[default_target]
lean_lib «Shroud» where
  srcDir := "formal"
