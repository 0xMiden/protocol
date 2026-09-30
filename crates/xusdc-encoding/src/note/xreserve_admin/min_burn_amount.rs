//! The min-burn admin note: the standard min-burn-amount config note, constrained so the burn
//! floor cannot be lowered to zero.
//!
//! The note itself is entirely standard — its script asserts the note's target binding, then calls
//! the standard burn policy's `set_min_burn_amount`, which authorizes the note sender through the
//! account-wide authority. Nothing about it is faucet-specific and nothing here reimplements it:
//! the standard [`MinBurnAmountConfigNote`] supplies the script, its root, and the builder
//! directly, and the allowlist and callable-surface checks use it as-is.
//!
//! What is faucet-specific is which notes can be created. The faucet seeds its burn floor at
//! least [`MIN_BURN_SIZE_FLOOR`] and the builder rejects anything lower, but the standard setter
//! validates nothing about its value — a zero floor would admit zero-amount burn notes. So
//! [`XReserveMinBurnAmountNote::builder`] refuses to build such a note in the first place — the
//! one guard the standard note cannot express.
//!
//! That refusal is a guard against operator error, not an authorization boundary.

use core::fmt;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_standards::note::config::MinBurnAmountConfigNote;

use crate::account::xreserve::MIN_BURN_SIZE_FLOOR;

/// Why a min-burn admin note could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum XReserveMinBurnAmountNoteError {
    /// The note would have lowered the burn floor below [`MIN_BURN_SIZE_FLOOR`].
    MinBurnAmountTooSmall { min_burn_amount: u64 },
    /// The standard note could not be assembled.
    Note(NoteError),
}

impl fmt::Display for XReserveMinBurnAmountNoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MinBurnAmountTooSmall { min_burn_amount } => write!(
                f,
                "refusing to build a note that sets the burn floor to {min_burn_amount}, below \
                 the floor {MIN_BURN_SIZE_FLOOR}; a zero floor would admit zero-amount burn notes"
            ),
            Self::Note(_) => write!(
                f,
                "the standard min-burn-amount config note could not be built"
            ),
        }
    }
}

impl core::error::Error for XReserveMinBurnAmountNoteError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Note(source) => Some(source),
            Self::MinBurnAmountTooSmall { .. } => None,
        }
    }
}

impl From<NoteError> for XReserveMinBurnAmountNoteError {
    fn from(source: NoteError) -> Self {
        Self::Note(source)
    }
}

/// The min-burn admin note factory: the standard [`MinBurnAmountConfigNote`] constrained by the
/// zero-floor refusal. There is no faucet-owned script behind this type.
pub struct XReserveMinBurnAmountNote;

#[bon::bon]
impl XReserveMinBurnAmountNote {
    /// The `miden-standards` min-burn-amount config note script.
    pub fn script() -> NoteScript {
        MinBurnAmountConfigNote::script()
    }

    /// The `miden-standards` min-burn-amount config note script root.
    pub fn script_root() -> NoteScriptRoot {
        MinBurnAmountConfigNote::script_root()
    }

    /// Builds a note that sets `target`'s burn floor to `min_burn_amount` over the standard
    /// [`MinBurnAmountConfigNote`].
    ///
    /// # Errors
    ///
    /// Returns [`XReserveMinBurnAmountNoteError::MinBurnAmountTooSmall`] if `min_burn_amount` is
    /// below [`MIN_BURN_SIZE_FLOOR`]: a zero floor would admit zero-amount burn notes. The
    /// refusal is a construction-time gate only — on chain the note runs the unmodified
    /// `miden-standards` script, which does not validate the value. Returns
    /// [`XReserveMinBurnAmountNoteError::Note`] if the standard note cannot be assembled.
    #[builder]
    pub fn new<R: FeltRng>(
        sender: AccountId,
        target: AccountId,
        min_burn_amount: AssetAmount,
        generate_serial_number: &mut R,
    ) -> Result<Note, XReserveMinBurnAmountNoteError> {
        if min_burn_amount.as_u64() < MIN_BURN_SIZE_FLOOR {
            return Err(XReserveMinBurnAmountNoteError::MinBurnAmountTooSmall {
                min_burn_amount: min_burn_amount.as_u64(),
            });
        }
        let note = MinBurnAmountConfigNote::builder()
            .sender(sender)
            .target(target)
            .min_burn_amount(min_burn_amount)
            .generate_serial_number(generate_serial_number)
            .build()
            .map_err(XReserveMinBurnAmountNoteError::Note)?;
        Ok(Note::from(note))
    }
}
