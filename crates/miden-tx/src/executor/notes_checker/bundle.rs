use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_protocol::note::{Note, NoteId};
use miden_standards::note::FeeSponsorshipNote;

use super::checker_utils::{FailedNote, NoteFailure};
use super::sponsorship::SponsorshipRejection;

// NOTE BUNDLE
// ================================================================================================

/// A group of input notes that has to be tested for consumability as a unit, such as a feature note
/// and the notes which sponsor it.
#[derive(Debug)]
pub(super) struct NoteBundle {
    notes: Vec<Note>,
}

impl NoteBundle {
    /// Groups `notes` into bundles that must be consumed together.
    ///
    /// A FEE_SPONSORSHIP note joins the bundle of the feature note it sponsors; an unpaired
    /// sponsorship note forms a bundle of its own, so that it fails alone rather than dropping the
    /// notes it would otherwise have been grouped with. Every other note type forms a bundle of its
    /// own.
    ///
    /// The feature note is always first in the resulting bundle (if any); bundle preserves the
    /// relative order of the sponsorship notes in it.
    ///
    /// A FEE_SPONSORSHIP note whose feature note is itself a FEE_SPONSORSHIP note can never be
    /// consumed, so it joins no bundle and is returned among the rejected notes instead.
    pub(super) fn group(notes: &[Note]) -> (Vec<Self>, Vec<FailedNote>) {
        let note_indices: BTreeMap<NoteId, usize> =
            notes.iter().enumerate().map(|(idx, note)| (note.id(), idx)).collect();
        let mut rejected = Vec::new();

        // Put the feature notes and orphan notes to the values with keys equal to this note index
        // in the `note_indices`. Sponsorship notes are appended to the values which contain the
        // corresponding feature note.
        // Keying by index rather than by note ID keeps the bundles in the caller's order.
        let mut bundles: BTreeMap<usize, Vec<Note>> = BTreeMap::new();
        for (idx, note) in notes.iter().enumerate() {
            // A sponsorship is only bundled when the note it sponsors is actually an input;
            // otherwise it can only be reclaimed, which is something it has to attempt on its own.
            let sponsored_note_idx = FeeSponsorshipNote::try_from(note)
                .ok()
                .and_then(|sponsorship| note_indices.get(&sponsorship.feature_note_id()).copied());
            match sponsored_note_idx {
                // Reject a sponsorship which names another sponsorship as its feature note.
                Some(head_idx) if is_fee_sponsorship_at(notes, head_idx) => {
                    let reason = SponsorshipRejection::FeatureNoteIsSponsorship {
                        feature_note_id: notes[head_idx].id(),
                    };
                    rejected.push(FailedNote::new(note.clone(), NoteFailure::from(reason)));
                },
                Some(head_idx) => bundles.entry(head_idx).or_default().push(note.clone()),
                // This note heads its own bundle, so it goes first whichever side of the notes
                // bound to it it arrives on.
                None => bundles.entry(idx).or_default().insert(0, note.clone()),
            }
        }

        let bundles = bundles.into_values().map(|notes| Self { notes }).collect();
        (bundles, rejected)
    }

    /// Returns the notes forming the bundle.
    pub(super) fn notes(&self) -> &[Note] {
        &self.notes
    }

    /// Returns the note heading the bundle: its feature note, or a FEE_SPONSORSHIP note whose
    /// feature note is absent.
    pub(super) fn head(&self) -> &Note {
        self.notes.first().expect("a bundle holds at least the note heading it")
    }

    /// Returns the notes bound to the note heading the bundle, which are the FEE_SPONSORSHIP notes
    /// sponsoring it.
    pub(super) fn bound_notes(&self) -> &[Note] {
        &self.notes[1..]
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns `true` if the note at index `head_idx` in the provided `notes` array is the 
/// [`FeeSponsorshipNote`]. Returns `false` otherwise.
fn is_fee_sponsorship_at(notes: &[Note], head_idx: usize) -> bool {
    FeeSponsorshipNote::try_from(&notes[head_idx]).is_ok()
}
