//! Stable labels for the input notes of a benchmark scenario.
//!
//! A note ID commits to the note's recipient - script root, inputs and serial number - which makes
//! it unusable as a key in a checked-in artifact: any edit to an inlined note script renames every
//! per-note key. A label instead names the note's kind, resolved from its script root, and changes
//! only when that kind, its multiplicity within the transaction, or the note's position among the
//! same-kind notes changes.

use std::collections::BTreeMap;

use miden_agglayer::AgglayerNote;
use miden_protocol::note::{NoteId, NoteScriptRoot};
use miden_protocol::transaction::TransactionInputs;
use miden_standards::note::StandardNote;

/// Label of an input note whose script root belongs to neither the standard nor the agglayer set.
///
/// Reachable in the ordinary course: the fee-sponsorship scenarios consume a sponsored feature
/// note whose script is assembled inline by the test fixtures.
const UNKNOWN_NOTE_LABEL: &str = "UNKNOWN";

/// Labels of a transaction's input notes, in consumption order.
///
/// Held as a flat slice rather than a map: a transaction consumes a handful of notes, so the
/// linear lookup is cheaper than the ordering machinery a map would require.
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
                .map(|input_note| (input_note.note().id(), input_note.note().script().root())),
        )
    }

    /// Returns the label of the given note, or `None` if it is not one of the labelled input
    /// notes.
    ///
    /// A miss is distinct from [`UNKNOWN_NOTE_LABEL`], which is itself a legitimate label: callers
    /// join measurements keyed by the kernel-reported note ID against these labels, and an ID that
    /// fails to resolve is a defect in that join rather than an unrecognised note kind.
    pub fn label(&self, id: NoteId) -> Option<&str> {
        self.0
            .iter()
            .find(|(labelled, _)| *labelled == id)
            .map(|(_, label)| label.as_str())
    }

    /// Labels the notes identified by the given `(ID, script root)` pairs, in consumption order.
    ///
    /// Two passes: whether a kind needs an index suffix is only known once every note has been
    /// seen.
    fn from_script_roots(notes: impl Iterator<Item = (NoteId, NoteScriptRoot)>) -> Self {
        let kinds: Vec<(NoteId, &'static str)> =
            notes.map(|(id, root)| (id, note_kind(root))).collect();

        let mut occurrences: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (_, kind) in &kinds {
            *occurrences.entry(kind).or_default() += 1;
        }

        let mut next_index: BTreeMap<&'static str, usize> = BTreeMap::new();
        let labels = kinds
            .into_iter()
            .map(|(id, kind)| {
                let index = next_index.entry(kind).or_default();
                let label = if occurrences[kind] > 1 {
                    format!("{kind}#{index}")
                } else {
                    kind.to_string()
                };
                *index += 1;
                (id, label)
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

    /// Builds a note ID that is distinct per `seed` and unrelated to any script root, so the tests
    /// exercise labelling independently of how real IDs are derived.
    fn note_id(seed: u32) -> NoteId {
        NoteId::from_raw(Word::from([seed, seed, seed, seed]))
    }

    fn labels(notes: &[(NoteId, NoteScriptRoot)]) -> NoteLabels {
        NoteLabels::from_script_roots(notes.iter().copied())
    }

    #[test]
    fn sole_note_of_a_kind_keeps_the_bare_name() {
        let (p2id, claim) = (note_id(1), note_id(2));
        let labels = labels(&[
            (p2id, StandardNote::P2ID.script_root()),
            (claim, AgglayerNote::CLAIM.script_root()),
        ]);

        assert_eq!(labels.label(p2id), Some("P2ID"));
        assert_eq!(labels.label(claim), Some("CLAIM"));
    }

    #[test]
    fn repeated_kind_is_indexed_in_input_order() {
        let (first, second, third) = (note_id(1), note_id(2), note_id(3));
        let labels = labels(&[
            (first, StandardNote::P2ID.script_root()),
            (second, StandardNote::P2ID.script_root()),
            (third, StandardNote::P2ID.script_root()),
        ]);

        assert_eq!(labels.label(first), Some("P2ID#0"));
        assert_eq!(labels.label(second), Some("P2ID#1"));
        assert_eq!(labels.label(third), Some("P2ID#2"));
    }

    #[test]
    fn kinds_are_indexed_independently_of_each_other() {
        let (p2id, p2ide, other_p2id) = (note_id(1), note_id(2), note_id(3));
        let labels = labels(&[
            (p2id, StandardNote::P2ID.script_root()),
            (p2ide, StandardNote::P2IDE.script_root()),
            (other_p2id, StandardNote::P2ID.script_root()),
        ]);

        assert_eq!(labels.label(p2id), Some("P2ID#0"));
        assert_eq!(labels.label(other_p2id), Some("P2ID#1"));
        assert_eq!(labels.label(p2ide), Some("P2IDE"), "a lone P2IDE must not be indexed");
    }

    /// The placeholder is a label like any other - it is indexed when repeated, and it stays
    /// distinguishable from a lookup miss, which returns `None`.
    #[test]
    fn unrecognised_script_roots_share_the_indexed_placeholder() {
        let (first, second, absent) = (note_id(1), note_id(2), note_id(3));
        let unrecognised = NoteScriptRoot::from_raw(Word::from([9u32; 4]));
        let labels = labels(&[(first, unrecognised), (second, unrecognised)]);

        assert_eq!(labels.label(first), Some("UNKNOWN#0"));
        assert_eq!(labels.label(second), Some("UNKNOWN#1"));
        assert_eq!(labels.label(absent), None, "an unlabelled note must not read as UNKNOWN");
    }
}
