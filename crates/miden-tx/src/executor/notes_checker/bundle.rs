use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::iter;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId};
use miden_standards::note::FeeSponsorshipNote;

use super::checker_utils::{FailedNote, NoteFailure};
use super::error::SponsorshipRejectionError;

// SPONSORSHIP INPUT
// ================================================================================================

/// A FEE_SPONSORSHIP input note, together with the amount of the fee asset it carries.
#[derive(Debug, Clone)]
pub(super) struct SponsorshipInput {
    note: Note,
    amount: AssetAmount,
}

impl SponsorshipInput {
    /// Returns the input note.
    pub(super) fn note(&self) -> &Note {
        &self.note
    }

    /// Returns the amount of the fee asset the note carries.
    pub(super) fn amount(&self) -> AssetAmount {
        self.amount
    }
}

// NOTE BUNDLE
// ================================================================================================

/// A group of input notes that has to be tested for consumability as a unit.
#[derive(Debug, Clone)]
pub(super) enum NoteBundle {
    /// A note other than FEE_SPONSORSHIP, and the FEE_SPONSORSHIP notes that fund its fee.
    Feature {
        feature_note: Note,
        sponsorships: Vec<SponsorshipInput>,
    },
    /// A FEE_SPONSORSHIP note whose feature note is not an input, so it can only be reclaimed.
    Reclaim(SponsorshipInput),
}

impl NoteBundle {
    /// Returns the notes forming the bundle, the feature note first.
    pub(super) fn notes(&self) -> impl Iterator<Item = &Note> {
        let (first, sponsorships) = match self {
            Self::Feature { feature_note, sponsorships } => (feature_note, sponsorships.as_slice()),
            Self::Reclaim(sponsorship) => (sponsorship.note(), [].as_slice()),
        };
        iter::once(first).chain(sponsorships.iter().map(SponsorshipInput::note))
    }

    /// Consumes the bundle, returning its notes in the same order as [`Self::notes`].
    pub(super) fn into_notes(self) -> Vec<Note> {
        match self {
            Self::Feature { feature_note, sponsorships } => iter::once(feature_note)
                .chain(sponsorships.into_iter().map(|sponsorship| sponsorship.note))
                .collect(),
            Self::Reclaim(sponsorship) => vec![sponsorship.note],
        }
    }

    /// Consumes the bundle reporting every note of it as failed: the note at `blamed_idx` of
    /// [`Self::notes`] with `failure`, and the rest as its collateral, since they cannot be
    /// consumed without it.
    ///
    /// # Panics
    ///
    /// Panics if the `blamed_idx` is out of bounds.
    pub(super) fn failed_notes(self, blamed_idx: usize, failure: NoteFailure) -> Vec<FailedNote> {
        let notes = self.into_notes();
        let blamed_note = notes[blamed_idx].clone();
        let mut failed_notes: Vec<FailedNote> = notes
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
        self.0.iter().flat_map(|bundle| bundle.notes().cloned()).collect()
    }

    /// Consumes the bundles, returning their notes in the same order as [`Self::to_notes`].
    pub(super) fn into_notes(self) -> Vec<Note> {
        self.0.into_iter().flat_map(NoteBundle::into_notes).collect()
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
            .position(|bundle| bundle.notes().any(|note| note.id() == note_id))?;
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
        // Parse every note once, telling the sponsorships apart from the feature notes.
        let parsed: Vec<Option<FeeSponsorshipNote>> =
            notes.iter().map(|note| FeeSponsorshipNote::try_from(note).ok()).collect();

        // Each bundle is keyed by the index of the note heading it, which keeps the bundles in the
        // caller's order. Every feature note heads a bundle, so the sponsorships placed below find
        // the bundle of their feature note whichever side of it they arrive on.
        let mut bundles: BTreeMap<usize, NoteBundle> = notes
            .iter()
            .zip(&parsed)
            .enumerate()
            .filter(|(_, (_, sponsorship))| sponsorship.is_none())
            .map(|(idx, (note, _))| {
                let bundle = NoteBundle::Feature {
                    feature_note: note.clone(),
                    sponsorships: Vec::new(),
                };
                (idx, bundle)
            })
            .collect();

        let mut rejected = Vec::new();
        for (idx, (note, sponsorship)) in notes.iter().zip(parsed.iter()).enumerate() {
            // iterate over the sponsorship notes -- feature notes have already formed bundles above
            let Some(sponsorship) = sponsorship else { continue };

            let input = SponsorshipInput {
                note: note.clone(),
                amount: sponsorship.asset().amount(),
            };

            match note_indices.get(&sponsorship.feature_note_id()).copied() {
                // The feature note is absent, so the sponsorship can only be reclaimed, on its own.
                None => match sponsorship.check_reclaim(self.native_account_id, self.block_ref) {
                    Ok(()) => {
                        bundles.insert(idx, NoteBundle::Reclaim(input));
                    },
                    Err(err) => rejected.push(FailedNote::new(
                        input.note,
                        NoteFailure::from(SponsorshipRejectionError::NotReclaimable(err)),
                    )),
                },
                // The note named as the feature note is itself a sponsorship.
                Some(feature_note_idx) if parsed[feature_note_idx].is_some() => {
                    let reason = SponsorshipRejectionError::FeatureNoteIsSponsorship {
                        feature_note_id: sponsorship.feature_note_id(),
                    };
                    rejected.push(FailedNote::new(input.note, NoteFailure::from(reason)));
                },
                // The feature note is present, so the sponsorship joins its bundle.
                Some(feature_note_idx) => match bundles.get_mut(&feature_note_idx) {
                    Some(NoteBundle::Feature { sponsorships, .. }) => sponsorships.push(input),
                    _ => unreachable!("every feature note heads a feature bundle"),
                },
            }
        }

        (NoteBundles(bundles.into_values().collect()), rejected)
    }
}
