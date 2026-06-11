use alloc::string::String;
use core::num::NonZeroU16;

use miden_protocol::Felt;
use miden_protocol::account::{AccountCodeInterface, AccountId};
use miden_protocol::note::PartialNote;
use miden_protocol::transaction::TransactionScript;
use thiserror::Error;

use crate::account::access::Ownable2Step;
use crate::account::faucets::FungibleFaucet;
use crate::account::wallets::BasicWallet;
use crate::code_builder::CodeBuilder;
use crate::errors::CodeBuilderError;

// SEND NOTES TRANSACTION SCRIPT
// ================================================================================================

/// A [`TransactionScript`] that sends the specified notes from an account whose code interface
/// exposes either the [`BasicWallet`] or [`FungibleFaucet`] procedures.
///
/// Construction is fallible (see [`SendNotesTransactionScriptError`]); converting the wrapper into
/// the underlying [`TransactionScript`] via the [`From`] impl is infallible.
///
/// Provided `expiration_delta` specifies how close to the transaction's reference block the
/// transaction must be included into the chain. For example, with a reference block of 100 and a
/// delta of 10, the transaction must be included by block 110.
///
/// When the account exposes both [`BasicWallet`] and [`FungibleFaucet`] procedures, the faucet
/// branch is preferred. Owner-controlled faucets (those exposing [`Ownable2Step`]) mint
/// exclusively via MINT notes, so the standard `send_note` flow is rejected at script-build time
/// to avoid runtime failures under the OwnerOnly mint policy.
///
/// # Example
///
/// Example of the generated script with one output note and an expiration delta against a
/// [`FungibleFaucet`]:
///
/// ```masm
/// begin
///     push.{expiration_delta} exec.::miden::protocol::tx::update_expiration_block_delta
///
///     push.{note information}
///
///     push.{ASSET_VALUE} push.{ASSET_KEY}
///     call.::miden::standards::faucets::fungible::mint_and_send
///     swapdw dropw dropw swapdw dropw dropw
/// end
/// ```
#[derive(Debug, Clone)]
pub struct SendNotesTransactionScript(TransactionScript);

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
        Self::build(interface, output_notes, "")
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
        let prelude = format!(
            "push.{expiration_delta} exec.::miden::protocol::tx::update_expiration_block_delta\n"
        );
        Self::build(interface, output_notes, &prelude)
    }

    fn build(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_prelude: &str,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        let sender = interface.id();

        let has_mint_and_send = interface.contains([FungibleFaucet::mint_and_send_root()]);
        let has_move_asset_to_note = interface.contains([BasicWallet::move_asset_to_note_root()]);
        let is_owner_controlled = interface.contains(Ownable2Step::code().procedure_roots());

        let body = if has_mint_and_send {
            if is_owner_controlled {
                return Err(SendNotesTransactionScriptError::UnsupportedAccountInterface);
            }
            mint_and_send_note_body(sender, output_notes)?
        } else if has_move_asset_to_note {
            move_asset_to_note_body(sender, output_notes)?
        } else {
            return Err(SendNotesTransactionScriptError::UnsupportedAccountInterface);
        };

        let script = format!("begin\n{expiration_prelude}\n{body}\nend");

        let mut code_builder = CodeBuilder::new();
        for note in output_notes {
            for attachment in note.attachments().iter() {
                code_builder
                    .add_advice_map_entry(attachment.to_commitment(), attachment.to_elements());
            }
        }

        let tx_script = code_builder
            .compile_tx_script(script)
            .map_err(SendNotesTransactionScriptError::InvalidTransactionScript)?;

        Ok(Self(tx_script))
    }
}

impl From<SendNotesTransactionScript> for TransactionScript {
    fn from(value: SendNotesTransactionScript) -> Self {
        value.0
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
    #[error("invalid transaction script")]
    InvalidTransactionScript(#[source] CodeBuilderError),
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

fn move_asset_to_note_body(
    sender: AccountId,
    notes: &[PartialNote],
) -> Result<String, SendNotesTransactionScriptError> {
    let mut body = String::new();
    for note in notes {
        push_note_header(&mut body, sender, note)?;

        body.push_str(
            "
            exec.::miden::protocol::output_note::create
            # => [note_idx, pad(16)]\n
            ",
        );

        for asset in note.assets().iter() {
            body.push_str(&format!(
                "
                # duplicate note index
                padw push.0 push.0 push.0 dup.7
                # => [note_idx, pad(7), note_idx, pad(16)]

                push.{ASSET_VALUE}
                push.{ASSET_KEY}
                # => [ASSET_KEY, ASSET_VALUE, note_idx, pad(7), note_idx, pad(16)]

                call.::miden::standards::wallets::basic::move_asset_to_note
                # => [pad(16), note_idx, pad(16)]

                dropw dropw dropw dropw
                # => [note_idx, pad(16)]\n
                ",
                ASSET_KEY = asset.to_key_word(),
                ASSET_VALUE = asset.to_value_word(),
            ));
        }

        push_attachments(&mut body, note);
        finalize_note(&mut body);
    }
    Ok(body)
}

fn mint_and_send_note_body(
    sender: AccountId,
    notes: &[PartialNote],
) -> Result<String, SendNotesTransactionScriptError> {
    let mut body = String::new();
    for note in notes {
        push_note_header(&mut body, sender, note)?;

        if note.assets().num_assets() != 1 {
            return Err(SendNotesTransactionScriptError::FaucetNoteWithoutAsset);
        }
        let asset = note.assets().iter().next().expect("note should contain an asset");
        if asset.faucet_id() != sender {
            return Err(SendNotesTransactionScriptError::IssuanceFaucetMismatch(asset.faucet_id()));
        }

        body.push_str(&format!(
            "
            push.{ASSET_VALUE}
            push.{ASSET_KEY}
            # => [ASSET_KEY, ASSET_VALUE, tag, note_type, RECIPIENT, pad(16)]

            call.::miden::standards::faucets::fungible::mint_and_send
            # => [note_idx, pad(29)]

            swapdw dropw dropw swapdw dropw dropw
            # => [note_idx, pad(13)]\n
            ",
            ASSET_KEY = asset.to_key_word(),
            ASSET_VALUE = asset.to_value_word(),
        ));

        push_attachments(&mut body, note);
        finalize_note(&mut body);
    }
    Ok(body)
}

fn push_note_header(
    body: &mut String,
    sender: AccountId,
    note: &PartialNote,
) -> Result<(), SendNotesTransactionScriptError> {
    if note.metadata().sender() != sender {
        return Err(SendNotesTransactionScriptError::InvalidSenderAccount(
            note.metadata().sender(),
        ));
    }

    body.push_str(&format!(
        "
        push.{recipient}
        push.{note_type}
        push.{tag}
        # => [tag, note_type, RECIPIENT, pad(16)]
        ",
        recipient = note.recipient_digest(),
        note_type = Felt::from(note.metadata().note_type()),
        tag = Felt::from(note.metadata().tag()),
    ));

    Ok(())
}

fn push_attachments(body: &mut String, note: &PartialNote) {
    for attachment in note.attachments().iter() {
        let attachment_scheme = attachment.attachment_scheme().as_u16();
        let attachment_commitment = attachment.content().to_commitment();

        body.push_str(&format!(
            "
            dup
            push.{attachment_commitment}
            push.{attachment_scheme}
            # => [attachment_scheme, ATTACHMENT_COMMITMENT, note_idx, note_idx, pad(16)]
            exec.::miden::protocol::output_note::add_attachment
            # => [note_idx, pad(16)]
        ",
        ));
    }
}

fn finalize_note(body: &mut String) {
    body.push_str(
        "
        # drop the note idx
        drop
        # => [pad(16)]
    ",
    );
}
