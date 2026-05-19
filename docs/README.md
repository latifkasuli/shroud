# SHROUD Notes

These notes are downstream of the core SHROUD packet in [../../research/shroud/README.md](/Users/latifkasuli/web3/contributions/research/shroud/README.md).

Read them after the protocol notes. Architecture notes explain how SHROUD should be organized; backend notes show how the same SHROUD objects land in specific systems.

## Architecture Notes

- [Lean Normative Spec Restructure](Lean%20Normative%20Spec%20Restructure.md)
- [SHROUD Maths Bibliography](SHROUD%20Maths%20Bibliography.md)
- [Adapter Composition Criteria](Adapter%20Composition%20Criteria.md)

## Current Backend Notes

- [Plonky3 Mapping](Plonky3%20Mapping.md)
- [Plonky3 Bridge Status](plonky3-bridge-status.md)
- [HVZK-WHIR Impact on SHROUD](HVZK-WHIR%20Impact%20on%20SHROUD.md)
- [Stwo Mapping](Stwo%20Mapping.md)
- [Stwo Compatibility Memo](Stwo%20Compatibility%20Memo.md)
- [Winterfell Mapping](Winterfell%20Mapping.md)
- [Triton VM Mapping](Triton%20VM%20Mapping.md)
- [Triton VM Compatibility Memo](Triton%20VM%20Compatibility%20Memo.md)
- [Triton VM Layer Audit](Triton%20VM%20Layer%20Audit.md)
- [Triton VM Batch Opening Seam](Triton%20VM%20Batch%20Opening%20Seam.md)
- [RISC Zero Mapping](RISC%20Zero%20Mapping.md)
- [Plonky3 Integration Checklist](Plonky3%20Integration%20Checklist.md)

## Intended Use

Use these notes to answer:

- how much of SHROUD already exists in a given backend
- which SHROUD layers are missing
- whether the backend is a strengthening case, a partial-mapping case, or a greenfield case
- what the first integration step should be
- when backend composition should remain downstream instead of becoming part of SHROUD's core adapter layer

The backend notes should never replace the protocol notes. They are meant to show how the same SHROUD objects land in different systems.
