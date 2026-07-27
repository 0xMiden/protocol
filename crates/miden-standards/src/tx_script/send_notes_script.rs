use alloc::vec::Vec;
use core::num::NonZeroU16;

use miden_protocol::account::{AccountCodeInterface, AccountId};
use miden_protocol::note::PartialNote;
use miden_protocol::transaction::{TransactionScript, TransactionScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word, ZERO};
use thiserror::Error;

use crate::account::access::{Ownable2Step, RoleBasedAccessControl};
use crate::account::faucets::FungibleFaucet;
use crate::account::wallets::BasicWallet;
use crate::tx_script::transaction_script;

// CONSTANTS
// ================================================================================================

/// Path to the `send_notes` wallet transaction script procedure in the standards library.
const SEND_NOTES_WALLET_TX_SCRIPT_PATH: &str =
    "::miden::standards::tx_scripts::send_notes::wallet::main";

/// Path to the `send_notes` faucet transaction script procedure in the standards library.
const SEND_NOTES_FAUCET_TX_SCRIPT_PATH: &str =
    "::miden::standards::tx_scripts::send_notes::faucet::main";

// SEND NOTES TRANSACTION SCRIPT
// ================================================================================================

static SEND_NOTES_WALLET_TX_SCRIPT: LazyLock<TransactionScript> =
    LazyLock::new(|| transaction_script(SEND_NOTES_WALLET_TX_SCRIPT_PATH));

static SEND_NOTES_FAUCET_TX_SCRIPT: LazyLock<TransactionScript> =
    LazyLock::new(|| transaction_script(SEND_NOTES_FAUCET_TX_SCRIPT_PATH));

/// A [`TransactionScript`] that sends the specified notes from an account whose code interface
/// exposes either the [`BasicWallet`] or [`FungibleFaucet`] procedures.
///
/// Provided `expiration_delta` specifies how close to the transaction's reference block the
/// transaction must be included into the chain. For example, with a reference block of 100 and a
/// delta of 10, the transaction must be included by block 110. The delta is part of the payload,
/// so it does not affect the script root.
///
/// When the account exposes both [`BasicWallet`] and [`FungibleFaucet`] procedures, the faucet
/// script is preferred. Faucets that delegate minting to an authority (those exposing
/// [`Ownable2Step`] or [`RoleBasedAccessControl`]) are network faucets that mint exclusively via
/// MINT notes, so the standard `send_note` flow is rejected at script build time to avoid runtime
/// failures under their OwnerOnly mint policy.
///
/// The payload and the attachment contents the script reads from the advice provider are embedded
/// in the script's MAST forest, so they are loaded with the script. Callers only have to set the
/// script ([`Self::tx_script`]) and the payload commitment it reads its parameters from
/// ([`Self::tx_script_args`]).
///
/// # Example
///
/// ```ignore
/// let script = SendNotesTransactionScript::new(&interface, &notes)?;
///
/// let tx_args = TransactionArgs::new(AdviceMap::default())
///     .with_tx_script_and_args(script.tx_script().clone(), script.tx_script_args());
/// ```
#[derive(Debug, Clone)]
pub struct SendNotesTransactionScript {
    script: TransactionScript,
    tx_script_args: Word,
}

impl SendNotesTransactionScript {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of elements in the payload header word: `[num_notes, expiration_delta, 0, 0]`.
    ///
    /// See `encode_payload` for the full payload layout.
    pub const PAYLOAD_HEADER_NUM_ELEMENTS: usize = 4;

    /// Element offset of the asset count within a note record, after the RECIPIENT word and the
    /// `tag` and `note_type` elements.
    ///
    /// See `encode_payload` for the full payload layout.
    pub const NOTE_RECORD_NUM_ASSETS_OFFSET: usize = 6;

    /// Element offset of the first asset or attachment item within a note record, after the
    /// RECIPIENT word and the metadata word.
    ///
    /// See `encode_payload` for the full payload layout.
    pub const NOTE_RECORD_ITEMS_OFFSET: usize = 8;

    /// Number of elements a single asset or attachment item occupies (two words).
    ///
    /// See `encode_payload` for the full payload layout.
    pub const ITEM_NUM_ELEMENTS: usize = 8;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Builds a `send_notes` transaction script for the account described by `interface`,
    /// without an expiration delta.
    ///
    /// See [`Self::with_expiration_delta`] for the variant that pins the transaction to a
    /// reference-block delta. See the [type-level docs](Self) for the full list of error
    /// conditions.
    pub fn new(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, 0)
    }

    /// Builds a `send_notes` transaction script for the account described by `interface`,
    /// with the given non-zero expiration delta.
    ///
    /// See the [type-level docs](Self) for the full list of error conditions.
    pub fn with_expiration_delta(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: NonZeroU16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, expiration_delta.get())
    }

    /// The transaction script argument the script reads its payload commitment from.
    ///
    /// Pass this as the transaction's `TX_SCRIPT_ARGS`.
    pub fn tx_script_args(&self) -> Word {
        self.tx_script_args
    }

    /// The underlying [`TransactionScript`], to be set as the transaction's script.
    pub fn tx_script(&self) -> &TransactionScript {
        &self.script
    }

    /// The [`TransactionScriptRoot`] of the canonical wallet script.
    pub fn wallet_script_root() -> TransactionScriptRoot {
        SEND_NOTES_WALLET_TX_SCRIPT.root()
    }

    /// The [`TransactionScriptRoot`] of the canonical faucet script.
    pub fn faucet_script_root() -> TransactionScriptRoot {
        SEND_NOTES_FAUCET_TX_SCRIPT.root()
    }

    fn build(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: u16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        let sender = interface.id();

        let has_mint_and_send = interface.contains([FungibleFaucet::mint_and_send_root()]);

        // The wallet script calls both procedures, so both must be exposed.
        let can_send_own_assets = interface
            .contains([BasicWallet::move_asset_to_note_root(), BasicWallet::create_note_root()]);

        // A faucet that delegates minting to an authority is a network faucet: it mints
        // exclusively via MINT notes, so the standard send_notes flow would fail at runtime under
        // its OwnerOnly mint policy. Exposing either access-control component signals this.
        let is_authority_controlled = interface.contains(Ownable2Step::code().procedure_roots())
            || interface.contains(RoleBasedAccessControl::code().procedure_roots());

        let script = if has_mint_and_send {
            if is_authority_controlled {
                return Err(SendNotesTransactionScriptError::UnsupportedAccountInterface);
            }
            validate_faucet_notes(sender, output_notes)?;
            SEND_NOTES_FAUCET_TX_SCRIPT.clone()
        } else if can_send_own_assets {
            validate_wallet_notes(sender, output_notes)?;
            SEND_NOTES_WALLET_TX_SCRIPT.clone()
        } else {
            return Err(SendNotesTransactionScriptError::UnsupportedAccountInterface);
        };

        let payload = encode_payload(output_notes, expiration_delta);
        let tx_script_args = Hasher::hash_elements(&payload);

        // Embed the data the script reads from the advice provider into the script's MAST forest,
        // so it is loaded automatically and callers only have to set the script and its arguments.
        let mut advice_map = AdviceMap::default();
        advice_map.insert(tx_script_args, payload);
        for note in output_notes {
            for attachment in note.attachments().iter() {
                advice_map.insert(attachment.to_commitment(), attachment.to_elements());
            }
        }
        let script = script.with_advice_map(advice_map);

        Ok(Self { script, tx_script_args })
    }
}

// SEND NOTES SCRIPT ERROR
// ================================================================================================

/// Errors that can occur while building a [`SendNotesTransactionScript`].
#[derive(Debug, Error)]
pub enum SendNotesTransactionScriptError {
    #[error("note asset is not issued by faucet {0}")]
    IssuanceFaucetMismatch(AccountId),
    #[error("note created by the basic fungible faucet doesn't contain exactly one asset")]
    FaucetNoteUnexpectedNumAssets,
    #[error("invalid sender account: {0}")]
    InvalidSenderAccount(AccountId),
    #[error(
        "account does not contain the basic fungible faucet or basic wallet interfaces \
         which are needed to support the send_notes script generation"
    )]
    UnsupportedAccountInterface,
}

// HELPER FUNCTIONS
// ================================================================================================

/// Validates that every note is sent by `sender`.
fn validate_wallet_notes(
    sender: AccountId,
    notes: &[PartialNote],
) -> Result<(), SendNotesTransactionScriptError> {
    for note in notes {
        validate_note_sender(sender, note)?;
    }
    Ok(())
}

/// Validates that every note is sent by `sender` and contains exactly one asset issued by it.
fn validate_faucet_notes(
    sender: AccountId,
    notes: &[PartialNote],
) -> Result<(), SendNotesTransactionScriptError> {
    for note in notes {
        validate_note_sender(sender, note)?;

        if note.assets().num_assets() != 1 {
            return Err(SendNotesTransactionScriptError::FaucetNoteUnexpectedNumAssets);
        }
        let asset = note.assets().iter().next().expect("note should contain an asset");
        if asset.faucet_id() != sender {
            return Err(SendNotesTransactionScriptError::IssuanceFaucetMismatch(asset.faucet_id()));
        }
    }
    Ok(())
}

fn validate_note_sender(
    sender: AccountId,
    note: &PartialNote,
) -> Result<(), SendNotesTransactionScriptError> {
    if note.metadata().sender() != sender {
        return Err(SendNotesTransactionScriptError::InvalidSenderAccount(
            note.metadata().sender(),
        ));
    }
    Ok(())
}

/// Encodes the notes and expiration delta into the payload element expected by the `send_notes`
/// MASM scripts. The payload structure is as follows:
/// ```text
/// word 0 (header):             [num_notes, expiration_delta, 0, 0]
/// per note record:
///   word 0:                    RECIPIENT
///   word 1:                    [tag, note_type, num_assets, num_attachments]
///   num_assets * 2 words:      ASSET_ID, ASSET_VALUE
///   num_attachments * 2 words: [attachment_scheme, 0, 0, 0], ATTACHMENT_COMMITMENT
/// ```
fn encode_payload(notes: &[PartialNote], expiration_delta: u16) -> Vec<Felt> {
    // SAFETY: kernel caps output notes and assets per note below u32::MAX, so these conversions
    // cannot truncate for any executable transaction.
    let num_notes = u32::try_from(notes.len()).expect("note count should fit in a u32");

    let mut payload = alloc::vec![Felt::from(num_notes), Felt::from(expiration_delta), ZERO, ZERO];
    debug_assert_eq!(
        payload.len(),
        SendNotesTransactionScript::PAYLOAD_HEADER_NUM_ELEMENTS,
        "header size should match the advertised constant"
    );

    for note in notes {
        let num_assets =
            u32::try_from(note.assets().num_assets()).expect("asset count should fit in a u32");

        let record_start = payload.len();
        payload.extend(note.recipient_digest().iter());
        payload.push(Felt::from(note.metadata().tag()));
        payload.push(Felt::from(note.metadata().note_type()));
        debug_assert_eq!(
            payload.len() - record_start,
            SendNotesTransactionScript::NOTE_RECORD_NUM_ASSETS_OFFSET,
            "asset count should sit at the advertised record offset"
        );
        payload.push(Felt::from(num_assets));
        payload.push(Felt::from(note.attachments().num_attachments()));
        debug_assert_eq!(
            payload.len() - record_start,
            SendNotesTransactionScript::NOTE_RECORD_ITEMS_OFFSET,
            "items should start at the advertised record offset"
        );

        for asset in note.assets().iter() {
            let item_start = payload.len();
            payload.extend(asset.to_id_word().iter());
            payload.extend(asset.to_value_word().iter());
            debug_assert_eq!(
                payload.len() - item_start,
                SendNotesTransactionScript::ITEM_NUM_ELEMENTS,
                "an asset item should occupy the advertised number of elements"
            );
        }

        for attachment in note.attachments().iter() {
            payload.push(Felt::from(attachment.attachment_scheme().as_u16()));
            payload.extend([ZERO; 3]);
            payload.extend(attachment.to_commitment().iter());
        }
    }

    payload
}
