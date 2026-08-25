//! Stable labels for the input notes of a benchmark scenario.
//!
//! A note's identity commits to its recipient - script root, inputs and serial number - which
//! makes it unusable as a key in a checked-in artifact: any edit to an inlined note script renames
//! every per-note key. A label instead names the note's kind, resolved from its script root, and
//! changes only when that kind, its multiplicity within the transaction, or the note's position
//! among the same-kind notes changes.
//!
//! Labels are keyed by the note's details commitment, which is what a measurement entry carries
//! today; see [`measured_note_key`].

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use miden_agglayer::AgglayerNote;
use miden_protocol::note::{NoteDetailsCommitment, NoteId, NoteScriptRoot};
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
pub struct NoteLabels(Vec<(NoteDetailsCommitment, String)>);

impl NoteLabels {
    /// Resolves a label for each input note of the transaction.
    ///
    /// A note that is the only one of its kind in the transaction gets the bare kind name
    /// (`P2ID`). When a transaction consumes several notes of one kind, each is suffixed with its
    /// index among that kind's occurrences, in input-note order (`P2ID#0`, `P2ID#1`).
    ///
    /// # Errors
    /// Returns an error if two input notes share a details commitment, which would make the join
    /// in [`NoteLabels::label`] ambiguous. See [`measured_note_key`].
    pub fn from_inputs(inputs: &TransactionInputs) -> Result<Self> {
        Self::from_script_roots(inputs.input_notes().iter().map(|input_note| {
            (input_note.note().details_commitment(), input_note.note().script().root())
        }))
    }

    /// Returns the label of the given note, or `None` if it is not one of the labelled input
    /// notes.
    ///
    /// A miss is distinct from [`UNKNOWN_NOTE_LABEL`], which is itself a legitimate label: callers
    /// join the kernel-reported measurement key against these labels, and a key that fails to
    /// resolve is a defect in that join rather than an unrecognised note kind.
    pub fn label(&self, note: NoteDetailsCommitment) -> Option<&str> {
        self.0
            .iter()
            .find(|(labelled, _)| *labelled == note)
            .map(|(_, label)| label.as_str())
    }

    /// Labels the notes identified by the given `(details commitment, script root)` pairs, in
    /// consumption order.
    ///
    /// Two passes: whether a kind needs an index suffix is only known once every note has been
    /// seen.
    pub(crate) fn from_script_roots(
        notes: impl Iterator<Item = (NoteDetailsCommitment, NoteScriptRoot)>,
    ) -> Result<Self> {
        let kinds: Vec<(NoteDetailsCommitment, &'static str)> =
            notes.map(|(note, root)| (note, note_kind(root))).collect();

        // The details commitment excludes the metadata and attachments that the nullifier binds,
        // so unlike a note ID it is not unique among a transaction's input notes. Two notes
        // sharing one would both resolve to the first one's label, publishing one note's cycle
        // count twice and dropping the other's. No benchmark scenario does this today; fail
        // loudly rather than silently misattribute if one ever does.
        let mut seen = BTreeSet::new();
        for (note, _) in &kinds {
            ensure!(
                seen.insert(*note),
                "input notes share the details commitment {}, so their labels would be ambiguous",
                note.to_hex(),
            );
        }

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

        Ok(Self(labels))
    }
}

/// Reinterprets the note key of a `TransactionMeasurements::note_execution` entry as the details
/// commitment it actually holds, so it can be looked up with [`NoteLabels::label`].
///
/// TODO(#3724): the entry is typed `(NoteId, usize)`, but the host reads the input note segment's
/// base word - the details commitment - rather than the ID cached at `INPUT_NOTE_ID_OFFSET`, so
/// the key is a details commitment wearing a `NoteId`. Once
/// <https://github.com/0xMiden/protocol/pull/3724> lands the key becomes a real note ID: key
/// [`NoteLabels`] by `NoteId`, resolve it from `input_note.note().id()`, and delete this.
///
/// That switch is not graceful - a real note ID never equals a details commitment, so *every*
/// lookup misses at once and the generator aborts on its first scenario. Whoever lands #3724 has
/// to make this change in the same PR.
pub(crate) fn measured_note_key(measured: NoteId) -> NoteDetailsCommitment {
    NoteDetailsCommitment::from_raw(measured.as_word())
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

    /// Builds a note key that is distinct per `seed` and unrelated to any script root, so the
    /// tests exercise labelling independently of how real notes are committed to.
    fn note(seed: u32) -> NoteDetailsCommitment {
        NoteDetailsCommitment::from_raw(Word::from([seed, seed, seed, seed]))
    }

    fn labels(notes: &[(NoteDetailsCommitment, NoteScriptRoot)]) -> NoteLabels {
        NoteLabels::from_script_roots(notes.iter().copied()).expect("note keys are distinct")
    }

    #[test]
    fn sole_note_of_a_kind_keeps_the_bare_name() {
        let (p2id, claim) = (note(1), note(2));
        let labels = labels(&[
            (p2id, StandardNote::P2ID.script_root()),
            (claim, AgglayerNote::CLAIM.script_root()),
        ]);

        assert_eq!(labels.label(p2id), Some("P2ID"));
        assert_eq!(labels.label(claim), Some("CLAIM"));
    }

    #[test]
    fn repeated_kind_is_indexed_in_input_order() {
        let (first, second, third) = (note(1), note(2), note(3));
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
        let (p2id, p2ide, other_p2id) = (note(1), note(2), note(3));
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
        let (first, second, absent) = (note(1), note(2), note(3));
        let unrecognised = NoteScriptRoot::from_raw(Word::from([9u32; 4]));
        let labels = labels(&[(first, unrecognised), (second, unrecognised)]);

        assert_eq!(labels.label(first), Some("UNKNOWN#0"));
        assert_eq!(labels.label(second), Some("UNKNOWN#1"));
        assert_eq!(labels.label(absent), None, "an unlabelled note must not read as UNKNOWN");
    }

    /// The measurement key round-trips into the details commitment the input notes are keyed by,
    /// so the join in `MeasurementsPrinter::from_parts` resolves.
    #[test]
    fn measured_note_key_preserves_the_underlying_word() {
        let commitment = note(7);

        assert_eq!(measured_note_key(NoteId::from_raw(commitment.as_word())), commitment);
    }

    /// Unlike a note ID, a details commitment is not unique among input notes: it excludes the
    /// metadata the nullifier binds. Labelling must refuse rather than misattribute.
    #[test]
    fn duplicate_details_commitments_are_rejected() {
        let shared = note(1);

        let err = NoteLabels::from_script_roots(
            [
                (shared, StandardNote::P2ID.script_root()),
                (shared, StandardNote::P2ID.script_root()),
            ]
            .into_iter(),
        )
        .expect_err("a shared details commitment must not be labelled");

        assert!(err.to_string().contains("share the details commitment"), "unexpected: {err}");
    }
}
