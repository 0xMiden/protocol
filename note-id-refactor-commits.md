## Summary

This PR separates **note details** from the full public **note identifier**: it introduces **`NoteDetailsCommitment`** (recipient + assets only), defines **`NoteId`** as the merged hash of the details commitment and metadata commitment (matching block/batch note-tree leaves), and renames kernel memory, assembly, and call sites so terminology matches that model end-to-end.

## Changes

**Rust (`miden-protocol`)**

- Adds **`NoteDetailsCommitment`** and wires **`NoteHeader`** / **`Note`** so the serialized header stores details commitment + metadata, while **`NoteId`** is derived via **`NoteId::new(details_commitment, metadata)`**.
- Updates **`NoteDetails`** to expose **`commitment()`** for the details hash (replacing the old overloaded **`id()`** semantics).
- Adjusts block/batch note trees, Merkle verification, transaction inputs/outputs, batch trackers, advice inputs, and tests to use details commitment vs **`NoteId`** consistently; removes the previous **`compute_note_commitment`**-style helpers where superseded.

**Transaction kernel (MASM + `memory.rs`)**

- Renames offsets (**`INPUT_NOTE_DETAILS_COMMITMENT_OFFSET`**, **`OUTPUT_NOTE_DETAILS_COMMITMENT_OFFSET`**) and procedures (**`compute_input_note_details_commitment`**, **`compute_output_note_details_commitment`**, **`set_input_note_details_commitment`**) so offset **0** of each note segment holds the **details commitment**; authentication uses **`NOTE_ID`** (merged leaf) and docs use **`EMPTY_WORD_OR_NOTE_ID`** for the input-notes commitment hash second limb where applicable.
- Aligns kernel memory diagrams and constant names with the layout above.

**Tests & docs**

- Updates kernel tests (epilogue/prologue) for new offsets and naming.
- Aligns Rust **`OutputNoteCollection::compute_commitment`** docs with masm (**note_details_commitment** / **metadata_commitment** **tuples**).
