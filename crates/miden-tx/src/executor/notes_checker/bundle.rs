use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};
use miden_standards::note::FeeSponsorshipNote;

use super::checker_utils::{FailedNote, NoteFailure};
use super::error::SponsorshipRejectionError;

// NOTE BUNDLE
// ================================================================================================

/// A group of input notes that has to be tested for consumability as a unit, such as a feature note
/// and the notes which sponsor it.
///
/// The note heading the bundle comes first: a feature note, or a FEE_SPONSORSHIP note whose feature
/// note is absent.
#[derive(Debug, Clone)]
pub(super) struct NoteBundle {
    notes: Vec<Note>,
}

impl NoteBundle {
    /// Returns the notes forming the bundle.
    pub(super) fn notes(&self) -> &[Note] {
        &self.notes
    }

    /// Consumes the bundle reporting every note of it as failed: the note at `blamed_idx` with
    /// `failure`, and the rest as its collateral, since they cannot be consumed without it.
    ///
    /// # Panics
    ///
    /// Panics if the `blamed_idx` is out of bounds.
    pub(super) fn failed_notes(self, blamed_idx: usize, failure: NoteFailure) -> Vec<FailedNote> {
        let blamed_note = self.notes[blamed_idx].clone();
        let mut failed_notes: Vec<FailedNote> = self
            .notes
            .into_iter()
            .map(|note| {
                FailedNote::new(note, NoteFailure::Collateral { blamed_by: blamed_note.id() })
            })
            .collect();
        failed_notes[blamed_idx] = FailedNote::new(blamed_note, failure);

        failed_notes
    }
}

// NOTE BUNDLES
// ================================================================================================

/// The bundles a set of input notes is checked in.
#[derive(Debug, Default)]
pub(super) struct NoteBundles(Vec<NoteBundle>);

impl NoteBundles {
    /// Returns the bundles.
    pub(super) fn bundles(&self) -> &[NoteBundle] {
        &self.0
    }

    /// Returns `true` if there are no bundles.
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the notes of all bundles, bundle by bundle.
    pub(super) fn to_notes(&self) -> Vec<Note> {
        self.0.iter().flat_map(|bundle| bundle.notes().iter().cloned()).collect()
    }

    /// Consumes the bundles, returning their notes in the same order as [`Self::to_notes`].
    pub(super) fn into_notes(self) -> Vec<Note> {
        self.0.into_iter().flat_map(|bundle| bundle.notes).collect()
    }

    /// Removes and returns the bundle at `idx`.
    ///     
    /// # Panics
    ///
    /// Panics if the `idx` is out of bounds.
    pub(super) fn remove(&mut self, idx: usize) -> NoteBundle {
        self.0.remove(idx)
    }

    /// Removes and returns the bundle holding the note with `note_id`, or `None` if no bundle
    /// holds it.
    pub(super) fn remove_containing(&mut self, note_id: NoteId) -> Option<NoteBundle> {
        let idx = self
            .0
            .iter()
            .position(|bundle| bundle.notes().iter().any(|note| note.id() == note_id))?;
        Some(self.0.remove(idx))
    }
}

// NOTE BUNDLER
// ================================================================================================

/// Groups input notes into the [`NoteBundles`] they have to be checked in, rejecting the
/// FEE_SPONSORSHIP notes the native account cannot consume along the way.
pub(super) struct NoteBundler {
    /// The account consuming the notes.
    native_account_id: AccountId,
    /// The reference block the notes are consumed at.
    block_ref: BlockNumber,
}

impl NoteBundler {
    /// Returns a new [`NoteBundler`] for notes consumed by `native_account_id` at `block_ref`.
    pub(super) fn new(native_account_id: AccountId, block_ref: BlockNumber) -> Self {
        Self { native_account_id, block_ref }
    }

    /// Groups `notes` into bundles that must be consumed together, and rejects the FEE_SPONSORSHIP
    /// notes that cannot be consumed.
    ///
    /// A FEE_SPONSORSHIP note joins the bundle of the feature note it sponsors, and every other
    /// note heads a bundle of its own. A sponsorship whose feature note is absent can only be
    /// reclaimed, so it forms a bundle of its own as well, and fails alone rather than dropping the
    /// notes it would otherwise have been grouped with.
    ///
    /// A FEE_SPONSORSHIP note is rejected when:
    /// - its feature note is absent, and the native account cannot reclaim it.
    /// - its feature note is itself a FEE_SPONSORSHIP note.
    ///
    /// The bundles keep the order of the notes heading them, and the sponsorships in a bundle keep
    /// their relative order.
    pub(super) fn bundle(&self, notes: &[Note]) -> (NoteBundles, Vec<FailedNote>) {
        let note_indices: BTreeMap<NoteId, usize> =
            notes.iter().enumerate().map(|(idx, note)| (note.id(), idx)).collect();
        let mut rejected = Vec::new();

        // Each bundle is keyed by the index of the note heading it, which keeps the bundles in the
        // caller's order.
        let mut bundles: BTreeMap<usize, Vec<Note>> = BTreeMap::new();
        for (idx, note) in notes.iter().enumerate() {
            match FeeSponsorshipNote::try_from(note) {
                // A feature note heads its bundle, whichever side of its sponsorships it arrives
                // on.
                Err(_) => bundles.entry(idx).or_default().insert(0, note.clone()),
                Ok(sponsorship) => {
                    match self.get_feature_index_by_sponsor(&sponsorship, idx, notes, &note_indices)
                    {
                        Ok(feature_note_idx) => {
                            bundles.entry(feature_note_idx).or_default().push(note.clone())
                        },
                        Err(reason) => {
                            rejected.push(FailedNote::new(note.clone(), NoteFailure::from(reason)))
                        },
                    }
                },
            }
        }

        let bundles = bundles.into_values().map(|notes| NoteBundle { notes }).collect();
        (NoteBundles(bundles), rejected)
    }

    /// Returns the index of the feature note which FEE_SPONSORSHIP note at `idx` in `notes` joins,
    /// or the reason why it cannot be consumed.
    fn get_feature_index_by_sponsor(
        &self,
        sponsorship: &FeeSponsorshipNote,
        idx: usize,
        notes: &[Note],
        note_indices: &BTreeMap<NoteId, usize>,
    ) -> Result<usize, SponsorshipRejectionError> {
        match note_indices.get(&sponsorship.feature_note_id()).copied() {
            // The feature note is absent, so the sponsorship can only be reclaimed, on its own.
            None => sponsorship
                .check_reclaim(self.native_account_id, self.block_ref)
                .map(|()| idx)
                .map_err(SponsorshipRejectionError::NotReclaimable),

            // obtained index points to another sponsorship note
            Some(feature_note_idx)
                if FeeSponsorshipNote::try_from(&notes[feature_note_idx]).is_ok() =>
            {
                Err(SponsorshipRejectionError::FeatureNoteIsSponsorship {
                    feature_note_id: sponsorship.feature_note_id(),
                })
            },

            // The feature note is present, so the sponsorship joins its bundle.
            Some(feature_note_idx) => Ok(feature_note_idx),
        }
    }
}
