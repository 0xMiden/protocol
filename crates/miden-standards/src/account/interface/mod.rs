use alloc::string::String;
use alloc::vec::Vec;

use miden_protocol::account::{AccountId, AccountIdPrefix, AccountType};
use miden_protocol::note::{NoteAttachmentContent, PartialNote};
use miden_protocol::transaction::TransactionScript;
use thiserror::Error;

use crate::AuthScheme;
use crate::code_builder::CodeBuilder;
use crate::errors::CodeBuilderError;

#[cfg(test)]
mod test;

mod component;
pub use component::AccountComponentInterface;

mod extension;
pub use extension::{AccountComponentInterfaceExt, AccountInterfaceExt};

// ACCOUNT INTERFACE
// ================================================================================================

/// An [`AccountInterface`] describes the exported, callable procedures of an account.
///
/// A note script's compatibility with this interface can be inspected to check whether the note may
/// result in a successful execution against this account.
pub struct AccountInterface {
    account_id: AccountId,
    auth: Vec<AuthScheme>,
    components: Vec<AccountComponentInterface>,
}

// ------------------------------------------------------------------------------------------------
/// Constructors and public accessors
impl AccountInterface {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AccountInterface`] instance from the provided account ID, authentication
    /// schemes and account component interfaces.
    pub fn new(
        account_id: AccountId,
        auth: Vec<AuthScheme>,
        components: Vec<AccountComponentInterface>,
    ) -> Self {
        Self { account_id, auth, components }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the account ID.
    pub fn id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the type of the reference account.
    pub fn account_type(&self) -> AccountType {
        self.account_id.account_type()
    }

    /// Returns true if the reference account can issue assets.
    pub fn is_faucet(&self) -> bool {
        self.account_id.is_faucet()
    }

    /// Returns true if the reference account is a regular.
    pub fn is_regular_account(&self) -> bool {
        self.account_id.is_regular_account()
    }

    /// Returns `true` if the full state of the account is public on chain, i.e. if the modes are
    /// [`AccountStorageMode::Public`](miden_protocol::account::AccountStorageMode::Public) or
    /// [`AccountStorageMode::Network`](miden_protocol::account::AccountStorageMode::Network),
    /// `false` otherwise.
    pub fn has_public_state(&self) -> bool {
        self.account_id.has_public_state()
    }

    /// Returns `true` if the reference account is a private account, `false` otherwise.
    pub fn is_private(&self) -> bool {
        self.account_id.is_private()
    }

    /// Returns true if the reference account is a public account, `false` otherwise.
    pub fn is_public(&self) -> bool {
        self.account_id.is_public()
    }

    /// Returns true if the reference account is a network account, `false` otherwise.
    pub fn is_network(&self) -> bool {
        self.account_id.is_network()
    }

    /// Returns a reference to the vector of used authentication schemes.
    pub fn auth(&self) -> &Vec<AuthScheme> {
        &self.auth
    }

    /// Returns a reference to the set of used component interfaces.
    pub fn components(&self) -> &Vec<AccountComponentInterface> {
        &self.components
    }
}

// ------------------------------------------------------------------------------------------------
/// Code generation
impl AccountInterface {
    /// Returns a transaction script which sends the specified notes using the procedures available
    /// in the current interface.
    ///
    /// Provided `expiration_delta` parameter is used to specify how close to the transaction's
    /// reference block the transaction must be included into the chain. For example, if the
    /// transaction's reference block is 100 and transaction expiration delta is 10, the transaction
    /// can be included into the chain by block 110. If this does not happen, the transaction is
    /// considered expired and cannot be included into the chain.
    ///
    /// Currently only [`AccountComponentInterface::BasicWallet`] and
    /// [`AccountComponentInterface::BasicFungibleFaucet`] interfaces are supported for the
    /// `send_note` script creation. Attempt to generate the script using some other interface will
    /// lead to an error. In case both supported interfaces are available in the account, the script
    /// will be generated for the [`AccountComponentInterface::BasicFungibleFaucet`] interface.
    ///
    /// # Example
    ///
    /// Example of the `send_note` script with specified expiration delta and one output note:
    ///
    /// ```masm
    /// begin
    ///     push.{expiration_delta} exec.::miden::protocol::tx::update_expiration_block_delta
    ///
    ///     push.{note information}
    ///
    ///     push.{asset amount}
    ///     call.::miden::standards::faucets::basic_fungible::distribute dropw dropw drop
    /// end
    /// ```
    ///
    /// # Errors:
    /// Returns an error if:
    /// - the available interfaces does not support the generation of the standard `send_note`
    ///   procedure.
    /// - the sender of the note isn't the account for which the script is being built.
    /// - the note created by the faucet doesn't contain exactly one asset.
    /// - a faucet tries to distribute an asset with a different faucet ID.
    ///
    /// [wallet]: crate::account::interface::AccountComponentInterface::BasicWallet
    /// [faucet]: crate::account::interface::AccountComponentInterface::BasicFungibleFaucet
    pub fn build_send_notes_script(
        &self,
        output_notes: &[PartialNote],
        expiration_delta: Option<u16>,
    ) -> Result<TransactionScript, AccountInterfaceError> {
        let note_creation_source = self.build_create_notes_section(output_notes)?;

        let script = format!(
            "begin\n{}\n{}\nend",
            self.build_set_tx_expiration_section(expiration_delta),
            note_creation_source,
        );

        // Add attachment array entries to the code builder's advice map.
        // For NoteAttachmentContent::Array, the commitment (to_word) is used as key
        // and the array elements as value.
        let mut code_builder = CodeBuilder::new();
        for note in output_notes {
            if let NoteAttachmentContent::Array(array) = note.metadata().attachment().content() {
                code_builder.add_advice_map_entry(array.commitment(), array.as_slice().to_vec());
            }
        }

        let tx_script = code_builder
            .compile_tx_script(script)
            .map_err(AccountInterfaceError::InvalidTransactionScript)?;

        Ok(tx_script)
    }

    /// Generates a note creation code required for the `send_note` transaction script.
    ///
    /// For the example of the resulting code see [AccountComponentInterface::send_note_body]
    /// description.
    ///
    /// # Errors:
    /// Returns an error if:
    /// - the available interfaces does not support the generation of the standard `send_note`
    ///   procedure.
    /// - the sender of the note isn't the account for which the script is being built.
    /// - the note created by the faucet doesn't contain exactly one asset.
    /// - a faucet tries to distribute an asset with a different faucet ID.
    fn build_create_notes_section(
        &self,
        output_notes: &[PartialNote],
    ) -> Result<String, AccountInterfaceError> {
        if let Some(basic_fungible_faucet) = self.components().iter().find(|component_interface| {
            matches!(component_interface, AccountComponentInterface::BasicFungibleFaucet)
        }) {
            basic_fungible_faucet.send_note_body(*self.id(), output_notes)
        } else if let Some(_network_fungible_faucet) =
            self.components().iter().find(|component_interface| {
                matches!(component_interface, AccountComponentInterface::NetworkFungibleFaucet)
            })
        {
            // Network fungible faucet doesn't support send_note_body, because minting
            // is done via a MINT note.
            Err(AccountInterfaceError::UnsupportedAccountInterface)
        } else if self.components().contains(&AccountComponentInterface::BasicWallet) {
            AccountComponentInterface::BasicWallet.send_note_body(*self.id(), output_notes)
        } else {
            Err(AccountInterfaceError::UnsupportedAccountInterface)
        }
    }

    /// Returns a string with the expiration delta update procedure call for the script.
    fn build_set_tx_expiration_section(&self, expiration_delta: Option<u16>) -> String {
        if let Some(expiration_delta) = expiration_delta {
            format!(
                "push.{expiration_delta} exec.::miden::protocol::tx::update_expiration_block_delta\n"
            )
        } else {
            String::new()
        }
    }
}

// NOTE ACCOUNT COMPATIBILITY
// ================================================================================================

/// Describes whether a note is compatible with a specific account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteAccountCompatibility {
    /// A note is incompatible with an account.
    ///
    /// The account interface does not have procedures for being able to execute at least one of
    /// the program execution branches.
    No,
    /// The account has all necessary procedures of one execution branch of the note script. This
    /// means the note may be able to be consumed by the account if that branch is executed.
    Maybe,
    /// A note could be successfully executed and consumed by the account.
    Yes,
}

// ACCOUNT INTERFACE ERROR
// ============================================================================================

/// Account interface related errors.
#[derive(Debug, Error)]
pub enum AccountInterfaceError {
    #[error("note asset is not issued by this faucet: {0}")]
    IssuanceFaucetMismatch(AccountIdPrefix),
    #[error("note created by the basic fungible faucet doesn't contain exactly one asset")]
    FaucetNoteWithoutAsset,
    #[error("invalid transaction script")]
    InvalidTransactionScript(#[source] CodeBuilderError),
    #[error("invalid sender account: {0}")]
    InvalidSenderAccount(AccountId),
    #[error("{} interface does not support the generation of the standard send_note script", interface.name())]
    UnsupportedInterface { interface: AccountComponentInterface },
    #[error(
        "account does not contain the basic fungible faucet or basic wallet interfaces which are needed to support the send_note script generation"
    )]
    UnsupportedAccountInterface,
}
