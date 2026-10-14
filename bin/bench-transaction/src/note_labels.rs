//! Stable labels for the input notes of a benchmark scenario.
//!
//! A note's identity commits to its recipient - script root, inputs and serial number - which
//! makes it unusable as a key in a checked-in artifact: any edit to an inlined note script renames
//! every per-note key. A label instead names the note's kind, resolved from its script root, and
//! changes only when that kind, its multiplicity within the transaction, or the note's position
//! among the same-kind notes changes.

use std::collections::BTreeMap;

use miden_agglayer::AgglayerNote;
use miden_protocol::note::{NoteId, NoteScriptRoot};
use miden_protocol::transaction::TransactionInputs;
use miden_standards::note::StandardNote;

/// Label of an input note whose script root belongs to neither the standard nor the agglayer set.
///
/// Reachable in the ordinary course: the fee-sponsorship scenarios consume a sponsored feature
/// note whose script is assembled inline by the test fixtures. Distinct inline-script notes all
/// collapse onto this one kind, so several of them in a single transaction are told apart only by
/// their occurrence index - that is, by consumption order.
const UNKNOWN_NOTE_LABEL: &str = "UNKNOWN";

/// Labels of a transaction's input notes, in consumption order.
#[derive(Debug)]
pub struct NoteLabels(Vec<(NoteId, String)>);

impl NoteLabels {
    /// Resolves a label for each input note of the transaction.
    ///
    /// A note that is the only one of its kind in the transaction gets the bare kind name
    /// (`P2ID`). When a transaction consumes several notes of one kind, each is suffixed with its
    /// index among that kind's occurrences, in input-note order (`P2ID#0`, `P2ID#1`).
    pub fn from_inputs(inputs: &TransactionInputs) -> Self {
        Self::from_script_roots(
            inputs
                .input_notes()
                .iter()
                .map(|input_note| (input_note.id(), input_note.note().script().root())),
        )
    }

    /// Returns the label of the given note, or `None` if it is not one of the labelled input
    /// notes.
    ///
    /// A miss is distinct from `UNKNOWN_NOTE_LABEL`, which is itself a legitimate label: callers
    /// join the kernel-reported note ID against these labels, and an ID that fails to resolve is
    /// a defect in that join rather than an unrecognised note kind.
    pub fn label(&self, note: NoteId) -> Option<&str> {
        self.0
            .iter()
            .find(|(labelled, _)| *labelled == note)
            .map(|(_, label)| label.as_str())
    }

    /// Labels the notes identified by the given `(note ID, script root)` pairs, in consumption
    /// order.
    ///
    /// Two passes: whether a kind needs an index suffix is only known once every note has been
    /// seen.
    fn from_script_roots(notes: impl Iterator<Item = (NoteId, NoteScriptRoot)>) -> Self {
        let kinds: Vec<(NoteId, &'static str)> =
            notes.map(|(note, root)| (note, note_kind(root))).collect();

        let mut occurrences: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (_, kind) in &kinds {
            *occurrences.entry(kind).or_default() += 1;
        }

        let mut next_index: BTreeMap<&'static str, usize> = BTreeMap::new();
        let labels = kinds
            .into_iter()
            .map(|(note, kind)| {
                let index = next_index.entry(kind).or_default();
                let label = if occurrences[kind] > 1 {
                    format!("{kind}#{index}")
                } else {
                    kind.to_string()
                };
                *index += 1;
                (note, label)
            })
            .collect();

        Self(labels)
    }
}

/// Returns the name of the note kind the script root identifies, or [`UNKNOWN_NOTE_LABEL`] if it
/// matches no known note.
fn note_kind(root: NoteScriptRoot) -> &'static str {
    StandardNote::from_script_root(root)
        .map(|note| note.name())
        .or_else(|| AgglayerNote::from_script_root(root).map(|note| note.name()))
        .unwrap_or(UNKNOWN_NOTE_LABEL)
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;

    use super::*;

    /// Lone kinds keep the bare name, repeated kinds are indexed in input order independently of
    /// each other, and unrecognised scripts share the indexed `UNKNOWN` placeholder.
    #[test]
    fn labels_index_repeated_kinds_in_input_order() {
        let note = |seed: u32| NoteId::from_raw(Word::from([seed; 4]));
        let unrecognised = NoteScriptRoot::from_raw(Word::from([9u32; 4]));
        let notes = [
            (note(1), StandardNote::P2ID.script_root()),
            (note(2), StandardNote::P2IDE.script_root()),
            (note(3), unrecognised),
            (note(4), StandardNote::P2ID.script_root()),
            (note(5), unrecognised),
        ];

        let labels = NoteLabels::from_script_roots(notes.into_iter());

        let resolved: Vec<_> = notes.iter().map(|(id, _)| labels.label(*id)).collect();
        assert_eq!(
            resolved,
            [
                Some("P2ID#0"),
                Some("P2IDE"),
                Some("UNKNOWN#0"),
                Some("P2ID#1"),
                Some("UNKNOWN#1")
            ],
        );
    }
}
