use alloc::vec::Vec;
use core::num::NonZeroU16;

use miden_protocol::account::{AccountCodeInterface, AccountId, AccountProcedureRoot};
use miden_protocol::asset::AssetComposition;
use miden_protocol::note::PartialNote;
use miden_protocol::transaction::{TransactionScript, TransactionScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word, ZERO};
use thiserror::Error;

use crate::account::access::{Ownable2Step, RoleBasedAccessControl};
use crate::account::faucets::{FungibleFaucet, NonFungibleFaucet};
use crate::account::wallets::BasicWallet;
use crate::tx_script::transaction_script;

// CONSTANTS
// ================================================================================================

/// Path to the `send_notes` wallet transaction script procedure in the standards library.
const SEND_NOTES_WALLET_TX_SCRIPT_PATH: &str =
    "::miden::standards::tx_scripts::send_notes::wallet::main";

/// Path to the `send_notes` fungible faucet transaction script procedure in the standards library.
const SEND_NOTES_FUNGIBLE_FAUCET_TX_SCRIPT_PATH: &str =
    "::miden::standards::tx_scripts::send_notes::fungible_faucet::main";

/// Path to the `send_notes` non-fungible faucet transaction script procedure in the standards
/// library.
const SEND_NOTES_NON_FUNGIBLE_FAUCET_TX_SCRIPT_PATH: &str =
    "::miden::standards::tx_scripts::send_notes::non_fungible_faucet::main";

// SEND NOTES TRANSACTION SCRIPT
// ================================================================================================

static SEND_NOTES_WALLET_TX_SCRIPT: LazyLock<TransactionScript> =
    LazyLock::new(|| transaction_script(SEND_NOTES_WALLET_TX_SCRIPT_PATH));

static SEND_NOTES_FUNGIBLE_FAUCET_TX_SCRIPT: LazyLock<TransactionScript> =
    LazyLock::new(|| transaction_script(SEND_NOTES_FUNGIBLE_FAUCET_TX_SCRIPT_PATH));

static SEND_NOTES_NON_FUNGIBLE_FAUCET_TX_SCRIPT: LazyLock<TransactionScript> =
    LazyLock::new(|| transaction_script(SEND_NOTES_NON_FUNGIBLE_FAUCET_TX_SCRIPT_PATH));

/// A `send_notes` [`TransactionScript`] for an account, abstracting over the concrete script that
/// the account's code interface calls for.
///
/// Each variant wraps the dedicated type for one canonical script. Use [`Self::new`] to let the
/// account's interface decide, or construct a concrete type directly when the kind is known.
///
/// When the account exposes both [`BasicWallet`] and faucet ([`FungibleFaucet`] or
/// [`NonFungibleFaucet`]) procedures, the faucet script is preferred.
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
#[non_exhaustive]
pub enum SendNotesTransactionScript {
    /// Sends notes holding assets the account already owns.
    Wallet(SendWalletNotesTransactionScript),
    /// Sends notes holding assets the fungible faucet mints as part of note creation.
    Fungible(SendFungibleFaucetNotesTransactionScript),
    /// Sends notes holding assets the non-fungible faucet mints as part of note creation.
    NonFungible(SendNonFungibleFaucetNotesTransactionScript),
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

    /// Builds the `send_notes` script that the account described by `interface` calls for, without
    /// an expiration delta.
    ///
    /// See [`Self::with_expiration_delta`] for the variant that pins the transaction to a
    /// reference-block delta.
    ///
    /// # Errors
    ///
    /// Returns an error if the interface exposes none of the wallet, fungible faucet or
    /// non-fungible faucet procedures, or if the notes fail the selected script's validation.
    pub fn new(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, 0)
    }

    /// Builds the `send_notes` script that the account described by `interface` calls for, with the
    /// given non-zero expiration delta.
    ///
    /// The delta specifies how close to the transaction's reference block the transaction must be
    /// included into the chain. For example, with a reference block of 100 and a delta of 10, the
    /// transaction must be included by block 110.
    ///
    /// # Errors
    ///
    /// See [`Self::new`].
    pub fn with_expiration_delta(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: NonZeroU16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, expiration_delta.get())
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// The underlying [`TransactionScript`], to be set as the transaction's script.
    pub fn tx_script(&self) -> &TransactionScript {
        match self {
            Self::Wallet(script) => script.tx_script(),
            Self::Fungible(script) => script.tx_script(),
            Self::NonFungible(script) => script.tx_script(),
        }
    }

    /// The transaction script argument the script reads its payload commitment from.
    ///
    /// Pass this as the transaction's `TX_SCRIPT_ARGS`.
    pub fn tx_script_args(&self) -> Word {
        match self {
            Self::Wallet(script) => script.tx_script_args(),
            Self::Fungible(script) => script.tx_script_args(),
            Self::NonFungible(script) => script.tx_script_args(),
        }
    }

    /// The [`TransactionScriptRoot`]s of every canonical `send_notes` script.
    ///
    /// Allowlisting all of them covers any account this type can build a script for.
    pub fn script_roots() -> [TransactionScriptRoot; 3] {
        [
            SendWalletNotesTransactionScript::script_root(),
            SendFungibleFaucetNotesTransactionScript::script_root(),
            SendNonFungibleFaucetNotesTransactionScript::script_root(),
        ]
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    fn build(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: u16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        if interface.contains([FungibleFaucet::mint_and_send_root()]) {
            SendFungibleFaucetNotesTransactionScript::build(
                interface,
                output_notes,
                expiration_delta,
            )
            .map(Self::Fungible)
        } else if interface.contains([NonFungibleFaucet::mint_and_send_root()]) {
            SendNonFungibleFaucetNotesTransactionScript::build(
                interface,
                output_notes,
                expiration_delta,
            )
            .map(Self::NonFungible)
        } else {
            SendWalletNotesTransactionScript::build(interface, output_notes, expiration_delta)
                .map(Self::Wallet)
        }
    }
}

// SEND WALLET NOTES TRANSACTION SCRIPT
// ================================================================================================

/// The canonical `send_notes` [`TransactionScript`] for accounts exposing the [`BasicWallet`]
/// procedures, which sends notes holding assets the account already owns.
///
/// The payload and the attachment contents the script reads from the advice provider are embedded
/// in the script's MAST forest, so they are loaded with the script. Callers only have to set the
/// script ([`Self::tx_script`]) and the payload commitment it reads its parameters from
/// ([`Self::tx_script_args`]).
#[derive(Debug, Clone)]
pub struct SendWalletNotesTransactionScript(SendNotesScript);

impl SendWalletNotesTransactionScript {
    /// Builds the script for the account described by `interface`, without an expiration delta.
    ///
    /// # Errors
    ///
    /// See [`Self::with_expiration_delta`].
    pub fn new(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, 0)
    }

    /// Builds the script for the account described by `interface`, with the given non-zero
    /// expiration delta.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The interface does not expose the [`BasicWallet`] procedures the script calls.
    /// - Any note is not sent by the account.
    pub fn with_expiration_delta(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: NonZeroU16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, expiration_delta.get())
    }

    /// The underlying [`TransactionScript`], to be set as the transaction's script.
    pub fn tx_script(&self) -> &TransactionScript {
        self.0.tx_script()
    }

    /// The transaction script argument the script reads its payload commitment from.
    pub fn tx_script_args(&self) -> Word {
        self.0.tx_script_args()
    }

    /// The [`TransactionScriptRoot`] of the canonical wallet script.
    pub fn script_root() -> TransactionScriptRoot {
        SEND_NOTES_WALLET_TX_SCRIPT.root()
    }

    fn build(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: u16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        // The script calls both procedures, so both must be exposed.
        let can_send_own_assets = interface
            .contains([BasicWallet::move_asset_to_note_root(), BasicWallet::create_note_root()]);
        if !can_send_own_assets {
            return Err(SendNotesTransactionScriptError::UnsupportedAccountInterface);
        }

        for note in output_notes {
            validate_note_sender(interface.id(), note)?;
        }

        Ok(Self(SendNotesScript::new(
            SEND_NOTES_WALLET_TX_SCRIPT.clone(),
            output_notes,
            expiration_delta,
        )))
    }
}

// SEND FUNGIBLE FAUCET NOTES TRANSACTION SCRIPT
// ================================================================================================

/// The canonical `send_notes` [`TransactionScript`] for accounts exposing the [`FungibleFaucet`]
/// procedures, which sends notes holding assets the faucet mints as part of note creation.
///
/// Every note must carry exactly one fungible asset, issued by this faucet.
///
/// Faucets that delegate minting to an authority (those exposing [`Ownable2Step`] or
/// [`RoleBasedAccessControl`]) are network faucets that mint exclusively via MINT notes, so they
/// are rejected at script build time to avoid runtime failures under their OwnerOnly mint policy.
///
/// The payload and the attachment contents the script reads from the advice provider are embedded
/// in the script's MAST forest, so they are loaded with the script. Callers only have to set the
/// script ([`Self::tx_script`]) and the payload commitment it reads its parameters from
/// ([`Self::tx_script_args`]).
#[derive(Debug, Clone)]
pub struct SendFungibleFaucetNotesTransactionScript(SendNotesScript);

impl SendFungibleFaucetNotesTransactionScript {
    /// Builds the script for the faucet described by `interface`, without an expiration delta.
    ///
    /// # Errors
    ///
    /// See [`Self::with_expiration_delta`].
    pub fn new(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, 0)
    }

    /// Builds the script for the faucet described by `interface`, with the given non-zero
    /// expiration delta.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The interface does not expose the [`FungibleFaucet`] procedure the script calls.
    /// - The faucet delegates minting to an authority.
    /// - Any note is not sent by the faucet.
    /// - Any note does not carry exactly one fungible asset issued by the faucet.
    pub fn with_expiration_delta(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: NonZeroU16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, expiration_delta.get())
    }

    /// The underlying [`TransactionScript`], to be set as the transaction's script.
    pub fn tx_script(&self) -> &TransactionScript {
        self.0.tx_script()
    }

    /// The transaction script argument the script reads its payload commitment from.
    pub fn tx_script_args(&self) -> Word {
        self.0.tx_script_args()
    }

    /// The [`TransactionScriptRoot`] of the canonical fungible faucet script.
    pub fn script_root() -> TransactionScriptRoot {
        SEND_NOTES_FUNGIBLE_FAUCET_TX_SCRIPT.root()
    }

    fn build(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: u16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        validate_faucet(interface, FungibleFaucet::mint_and_send_root())?;
        validate_minted_notes(interface.id(), output_notes, AssetComposition::Fungible)?;

        Ok(Self(SendNotesScript::new(
            SEND_NOTES_FUNGIBLE_FAUCET_TX_SCRIPT.clone(),
            output_notes,
            expiration_delta,
        )))
    }
}

// SEND NON-FUNGIBLE FAUCET NOTES TRANSACTION SCRIPT
// ================================================================================================

/// The canonical `send_notes` [`TransactionScript`] for accounts exposing the [`NonFungibleFaucet`]
/// procedures, which sends notes holding assets the faucet mints as part of note creation.
///
/// Every note must carry exactly one non-fungible asset, issued by this faucet. Unlike the fungible
/// faucet, `non_fungible::mint_and_send` derives the asset from the faucet itself, so the script
/// passes it only the asset's commitment.
///
/// Faucets that delegate minting to an authority (those exposing [`Ownable2Step`] or
/// [`RoleBasedAccessControl`]) are network faucets that mint exclusively via MINT notes, so they
/// are rejected at script build time to avoid runtime failures under their OwnerOnly mint policy.
///
/// The payload and the attachment contents the script reads from the advice provider are embedded
/// in the script's MAST forest, so they are loaded with the script. Callers only have to set the
/// script ([`Self::tx_script`]) and the payload commitment it reads its parameters from
/// ([`Self::tx_script_args`]).
#[derive(Debug, Clone)]
pub struct SendNonFungibleFaucetNotesTransactionScript(SendNotesScript);

impl SendNonFungibleFaucetNotesTransactionScript {
    /// Builds the script for the faucet described by `interface`, without an expiration delta.
    ///
    /// # Errors
    ///
    /// See [`Self::with_expiration_delta`].
    pub fn new(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, 0)
    }

    /// Builds the script for the faucet described by `interface`, with the given non-zero
    /// expiration delta.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The interface does not expose the [`NonFungibleFaucet`] procedure the script calls.
    /// - The faucet delegates minting to an authority.
    /// - Any note is not sent by the faucet.
    /// - Any note does not carry exactly one non-fungible asset issued by the faucet.
    pub fn with_expiration_delta(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: NonZeroU16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        Self::build(interface, output_notes, expiration_delta.get())
    }

    /// The underlying [`TransactionScript`], to be set as the transaction's script.
    pub fn tx_script(&self) -> &TransactionScript {
        self.0.tx_script()
    }

    /// The transaction script argument the script reads its payload commitment from.
    pub fn tx_script_args(&self) -> Word {
        self.0.tx_script_args()
    }

    /// The [`TransactionScriptRoot`] of the canonical non-fungible faucet script.
    pub fn script_root() -> TransactionScriptRoot {
        SEND_NOTES_NON_FUNGIBLE_FAUCET_TX_SCRIPT.root()
    }

    fn build(
        interface: &AccountCodeInterface,
        output_notes: &[PartialNote],
        expiration_delta: u16,
    ) -> Result<Self, SendNotesTransactionScriptError> {
        validate_faucet(interface, NonFungibleFaucet::mint_and_send_root())?;
        validate_minted_notes(interface.id(), output_notes, AssetComposition::None)?;

        Ok(Self(SendNotesScript::new(
            SEND_NOTES_NON_FUNGIBLE_FAUCET_TX_SCRIPT.clone(),
            output_notes,
            expiration_delta,
        )))
    }
}

// SEND NOTES SCRIPT
// ================================================================================================

/// The state every `send_notes` script shares: the script itself, with the data it reads from the
/// advice provider embedded in its MAST forest, and the commitment to that data.
#[derive(Debug, Clone)]
struct SendNotesScript {
    script: TransactionScript,
    tx_script_args: Word,
}

impl SendNotesScript {
    /// Encodes `output_notes` into the payload the `send_notes` scripts expect and embeds it, along
    /// with every attachment's contents, into `script`'s MAST forest.
    fn new(script: TransactionScript, output_notes: &[PartialNote], expiration_delta: u16) -> Self {
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

        Self {
            script: script.with_advice_map(advice_map),
            tx_script_args,
        }
    }

    fn tx_script(&self) -> &TransactionScript {
        &self.script
    }

    fn tx_script_args(&self) -> Word {
        self.tx_script_args
    }
}

// SEND NOTES SCRIPT ERROR
// ================================================================================================

/// Errors that can occur while building a [`SendNotesTransactionScript`].
#[derive(Debug, Error)]
pub enum SendNotesTransactionScriptError {
    #[error("note asset is not issued by faucet {0}")]
    IssuanceFaucetMismatch(AccountId),
    #[error("note created by the faucet doesn't contain exactly one asset")]
    FaucetNoteUnexpectedNumAssets,
    #[error(
        "note asset has the {actual} composition but the faucet mints assets with the {expected} \
         composition"
    )]
    AssetCompositionMismatch {
        expected: AssetComposition,
        actual: AssetComposition,
    },
    #[error("invalid sender account: {0}")]
    InvalidSenderAccount(AccountId),
    #[error(
        "account does not contain the basic wallet, fungible faucet or non-fungible faucet \
         interfaces which are needed to support the send_notes script generation"
    )]
    UnsupportedAccountInterface,
}

// HELPER FUNCTIONS
// ================================================================================================

/// Validates that `interface` exposes `mint_and_send_root` and does not delegate minting to an
/// authority.
///
/// A faucet that delegates minting is a network faucet: it mints exclusively via MINT notes, so the
/// standard `send_notes` flow would fail at runtime under its OwnerOnly mint policy. Exposing
/// either access-control component signals this.
fn validate_faucet(
    interface: &AccountCodeInterface,
    mint_and_send_root: AccountProcedureRoot,
) -> Result<(), SendNotesTransactionScriptError> {
    if !interface.contains([mint_and_send_root]) {
        return Err(SendNotesTransactionScriptError::UnsupportedAccountInterface);
    }

    let is_authority_controlled = interface.contains(Ownable2Step::code().procedure_roots())
        || interface.contains(RoleBasedAccessControl::code().procedure_roots());
    if is_authority_controlled {
        return Err(SendNotesTransactionScriptError::UnsupportedAccountInterface);
    }

    Ok(())
}

/// Validates that every note is sent by `sender` and carries exactly one asset issued by it with
/// the `expected_composition`, as both faucet scripts mint exactly one asset of the composition
/// their faucet type defines per note.
fn validate_minted_notes(
    sender: AccountId,
    notes: &[PartialNote],
    expected_composition: AssetComposition,
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

        let composition = asset.id().composition();
        if composition != expected_composition {
            return Err(SendNotesTransactionScriptError::AssetCompositionMismatch {
                expected: expected_composition,
                actual: composition,
            });
        }
    }
    Ok(())
}

/// Validates that `note` is sent by `sender`.
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
