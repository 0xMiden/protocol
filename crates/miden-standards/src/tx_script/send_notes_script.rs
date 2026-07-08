use alloc::vec::Vec;
use core::num::NonZeroU16;

use miden_protocol::account::{AccountCodeInterface, AccountId};
use miden_protocol::assembly::Path;
use miden_protocol::note::PartialNote;
use miden_protocol::transaction::{TransactionScript, TransactionScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Hasher, Word, ZERO};
use thiserror::Error;

use crate::StandardsLib;
use crate::account::access::Ownable2Step;
use crate::account::faucets::FungibleFaucet;
use crate::account::wallets::BasicWallet;

// CONSTANTS
// ================================================================================================

/// Path to the `send_notes` wallet transaction script procedure in the standards library,
/// assembled at build time from `asm/standards/tx_scripts/send_notes_wallet.masm`.
const SEND_NOTES_WALLET_TX_SCRIPT_PATH: &str =
    "::miden::standards::tx_scripts::send_notes_wallet::main";

/// Path to the `send_notes` faucet transaction script procedure in the standards library,
/// assembled at build time from `asm/standards/tx_scripts/send_notes_faucet.masm`.
const SEND_NOTES_FAUCET_TX_SCRIPT_PATH: &str =
    "::miden::standards::tx_scripts::send_notes_faucet::main";

// SEND NOTES TRANSACTION SCRIPT
// ================================================================================================

static SEND_NOTES_WALLET_TX_SCRIPT: LazyLock<TransactionScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(SEND_NOTES_WALLET_TX_SCRIPT_PATH);
    TransactionScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("standards library should contain the send_notes wallet tx script procedure")
});

static SEND_NOTES_FAUCET_TX_SCRIPT: LazyLock<TransactionScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(SEND_NOTES_FAUCET_TX_SCRIPT_PATH);
    TransactionScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("standards library should contain the send_notes faucet tx script procedure")
});

/// A [`TransactionScript`] that sends the specified notes from an account whose code interface
/// exposes either the [`BasicWallet`] or [`FungibleFaucet`] procedures.
///
/// Callers must pass [`Self::tx_script_args`] as the transaction script argument and extend
/// the transaction's advice map with [`Self::advice_entries`].
///
/// Provided `expiration_delta` specifies how close to the transaction's reference block the
/// transaction must be included into the chain. For example, with a reference block of 100 and a
/// delta of 10, the transaction must be included by block 110. The delta is part of the payload,
/// so it does not affect the script root.
///
/// When the account exposes both [`BasicWallet`] and [`FungibleFaucet`] procedures, the faucet
/// script is preferred. Owner-controlled faucets (those exposing [`Ownable2Step`]) mint
/// exclusively via MINT notes, so the standard `send_note` flow is rejected at script-build time
/// to avoid runtime failures under the OwnerOnly mint policy.
///
/// # Example
///
/// ```ignore
/// let script = SendNotesTransactionScript::new(&interface, &notes)?;
/// let context = build_tx_context(/* .. */)
///     .tx_script(script.clone().into())
///     .tx_script_args(script.tx_script_args())
///     .extend_advice_map(script.advice_entries().to_vec());
/// ```
#[derive(Debug, Clone)]
pub struct SendNotesTransactionScript {
    script: TransactionScript,
    tx_script_args: Word,
    advice_entries: Vec<(Word, Vec<Felt>)>,
}

impl SendNotesTransactionScript {
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
    /// Pass this as the transaction's `TX_SCRIPT_ARGS`, together with the advice map entries
    /// from [`Self::advice_entries`].
    pub fn tx_script_args(&self) -> Word {
        self.tx_script_args
    }

    /// The advice map entries the script requires at execution: the payload keyed by its
    /// commitment, plus each attachment's content keyed by the attachment commitment.
    pub fn advice_entries(&self) -> &[(Word, Vec<Felt>)] {
        &self.advice_entries
    }

    /// The [`TransactionScriptRoot`] of the canonical wallet script, to be allowlisted on a
    /// network account exposing the [`BasicWallet`] interface.
    pub fn wallet_script_root() -> TransactionScriptRoot {
        SEND_NOTES_WALLET_TX_SCRIPT.root()
    }

    /// The [`TransactionScriptRoot`] of the canonical faucet script, to be allowlisted on a
    /// network account exposing the [`FungibleFaucet`] interface.
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
        let has_move_asset_to_note = interface.contains([BasicWallet::move_asset_to_note_root()]);
        let is_owner_controlled = interface.contains(Ownable2Step::code().procedure_roots());

        let script = if has_mint_and_send {
            if is_owner_controlled {
                return Err(SendNotesTransactionScriptError::UnsupportedAccountInterface);
            }
            validate_faucet_notes(sender, output_notes)?;
            SEND_NOTES_FAUCET_TX_SCRIPT.clone()
        } else if has_move_asset_to_note {
            validate_wallet_notes(sender, output_notes)?;
            SEND_NOTES_WALLET_TX_SCRIPT.clone()
        } else {
            return Err(SendNotesTransactionScriptError::UnsupportedAccountInterface);
        };

        let payload = encode_payload(output_notes, expiration_delta);
        let tx_script_args = Hasher::hash_elements(&payload);

        let mut advice_entries = Vec::with_capacity(1 + output_notes.len());
        advice_entries.push((tx_script_args, payload));
        for note in output_notes {
            for attachment in note.attachments().iter() {
                advice_entries.push((attachment.to_commitment(), attachment.to_elements()));
            }
        }

        Ok(Self { script, tx_script_args, advice_entries })
    }
}

impl From<SendNotesTransactionScript> for TransactionScript {
    fn from(value: SendNotesTransactionScript) -> Self {
        value.script
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
    FaucetNoteWithoutAsset,
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
            return Err(SendNotesTransactionScriptError::FaucetNoteWithoutAsset);
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

/// Encodes the notes and expiration delta into the payload element stream expected by the
/// `send_notes` MASM scripts:
///
/// ```text
/// word 0 (header):             [num_notes, expiration_delta, 0, 0]
/// per note record:
///   word 0:                    RECIPIENT
///   word 1:                    [tag, note_type, num_assets, num_attachments]
///   num_assets * 2 words:      ASSET_ID, ASSET_VALUE
///   num_attachments * 2 words: [attachment_scheme, 0, 0, 0], ATTACHMENT_COMMITMENT
/// ```
///
/// The scripts load this stream into memory verbatim and validate it against its sequential
/// hash, which [`SendNotesTransactionScript::tx_script_args`] carries as the transaction script
/// argument.
fn encode_payload(notes: &[PartialNote], expiration_delta: u16) -> Vec<Felt> {
    // The kernel caps output notes at 1024 and assets per note at 256, both far below u32::MAX,
    // so these conversions cannot truncate for any executable transaction.
    let num_notes = u32::try_from(notes.len()).expect("note count should fit in a u32");

    let mut payload = alloc::vec![Felt::from(num_notes), Felt::from(expiration_delta), ZERO, ZERO];

    for note in notes {
        let num_assets =
            u32::try_from(note.assets().num_assets()).expect("asset count should fit in a u32");

        payload.extend(note.recipient_digest().iter());
        payload.push(Felt::from(note.metadata().tag()));
        payload.push(Felt::from(note.metadata().note_type()));
        payload.push(Felt::from(num_assets));
        payload.push(Felt::from(note.attachments().num_attachments()));

        for asset in note.assets().iter() {
            payload.extend(asset.to_id_word().iter());
            payload.extend(asset.to_value_word().iter());
        }

        for attachment in note.attachments().iter() {
            payload.push(Felt::from(attachment.attachment_scheme().as_u16()));
            payload.extend([ZERO; 3]);
            payload.extend(attachment.to_commitment().iter());
        }
    }

    payload
}
