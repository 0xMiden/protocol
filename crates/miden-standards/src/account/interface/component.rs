use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{AccountId, AccountProcedureRoot, AccountStorage, StorageSlotName};
use miden_protocol::note::PartialNote;
use miden_protocol::{Felt, Word};

use crate::AuthMethod;
use crate::account::auth::{AuthGuardedMultisig, AuthMultisig, AuthSingleSig, AuthSingleSigAcl};
use crate::account::interface::AccountInterfaceError;

// ACCOUNT COMPONENT INTERFACE
// ================================================================================================

/// The enum holding all possible account interfaces which could be loaded to some account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountComponentInterface {
    /// Exposes procedures from the [`BasicWallet`][crate::account::wallets::BasicWallet] module.
    BasicWallet,
    /// Exposes procedures from the
    /// [`FungibleTokenMetadata`][crate::account::metadata::FungibleTokenMetadata] module.
    FungibleTokenMetadata,
    /// Exposes procedures from the
    /// [`BasicFungibleFaucet`][crate::account::faucets::BasicFungibleFaucet] module.
    BasicFungibleFaucet,
    /// Exposes procedures from the
    /// [`NetworkFungibleFaucet`][crate::account::faucets::NetworkFungibleFaucet] module.
    NetworkFungibleFaucet,
    /// Exposes procedures from the
    /// [`AuthSingleSig`][crate::account::auth::AuthSingleSig] module.
    AuthSingleSig,
    /// Exposes procedures from the
    /// [`AuthSingleSigAcl`][crate::account::auth::AuthSingleSigAcl] module.
    AuthSingleSigAcl,
    /// Exposes procedures from the
    /// [`AuthMultisig`][crate::account::auth::AuthMultisig] module.
    AuthMultisig,
    /// Exposes procedures from the
    /// [`AuthGuardedMultisig`][crate::account::auth::AuthGuardedMultisig] module.
    AuthGuardedMultisig,
    /// Exposes procedures from the [`NoAuth`][crate::account::auth::NoAuth] module.
    ///
    /// This authentication scheme provides no cryptographic authentication and only increments
    /// the nonce if the account state has actually changed during transaction execution.
    AuthNoAuth,
    /// Exposes procedures from the
    /// [`AuthNetworkAccount`][crate::account::auth::AuthNetworkAccount] module.
    ///
    /// This authentication scheme is intended for network-owned accounts. It rejects transactions
    /// that executed a tx script or consumed input notes outside of a fixed allowlist of note
    /// script roots.
    AuthNetworkAccount,
    /// A non-standard, custom interface which exposes the contained procedures.
    ///
    /// Custom interface holds all procedures which are not part of some standard interface which is
    /// used by this account.
    Custom(Vec<AccountProcedureRoot>),
}

impl AccountComponentInterface {
    /// Returns a string line with the name of the [AccountComponentInterface] enum variant.
    ///
    /// In case of a [AccountComponentInterface::Custom] along with the name of the enum variant
    /// the vector of shortened hex representations of the used procedures is returned, e.g.
    /// `Custom([0x6d93447, 0x0bf23d8])`.
    pub fn name(&self) -> String {
        match self {
            AccountComponentInterface::BasicWallet => "Basic Wallet".to_string(),
            AccountComponentInterface::FungibleTokenMetadata => {
                "Fungible Token Metadata".to_string()
            },
            AccountComponentInterface::BasicFungibleFaucet => "Basic Fungible Faucet".to_string(),
            AccountComponentInterface::NetworkFungibleFaucet => {
                "Network Fungible Faucet".to_string()
            },
            AccountComponentInterface::AuthSingleSig => "SingleSig".to_string(),
            AccountComponentInterface::AuthSingleSigAcl => "SingleSig ACL".to_string(),
            AccountComponentInterface::AuthMultisig => "Multisig".to_string(),
            AccountComponentInterface::AuthGuardedMultisig => "Guarded Multisig".to_string(),
            AccountComponentInterface::AuthNoAuth => "No Auth".to_string(),
            AccountComponentInterface::AuthNetworkAccount => "Network Account Auth".to_string(),
            AccountComponentInterface::Custom(proc_root_vec) => {
                let result = proc_root_vec
                    .iter()
                    .map(|proc_root| proc_root.mast_root().to_hex()[..9].to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("Custom([{result}])")
            },
        }
    }

    /// Returns true if this component interface is an authentication component.
    ///
    /// TODO: currently this can identify only standard auth components
    pub fn is_auth_component(&self) -> bool {
        matches!(
            self,
            AccountComponentInterface::AuthSingleSig
                | AccountComponentInterface::AuthSingleSigAcl
                | AccountComponentInterface::AuthMultisig
                | AccountComponentInterface::AuthGuardedMultisig
                | AccountComponentInterface::AuthNoAuth
                | AccountComponentInterface::AuthNetworkAccount
        )
    }

    /// Returns the authentication schemes associated with this component interface.
    pub fn get_auth_methods(&self, storage: &AccountStorage) -> Vec<AuthMethod> {
        match self {
            AccountComponentInterface::AuthSingleSig => vec![extract_singlesig_auth_method(
                storage,
                AuthSingleSig::public_key_slot(),
                AuthSingleSig::scheme_id_slot(),
            )],
            AccountComponentInterface::AuthSingleSigAcl => vec![extract_singlesig_auth_method(
                storage,
                AuthSingleSigAcl::public_key_slot(),
                AuthSingleSigAcl::scheme_id_slot(),
            )],
            AccountComponentInterface::AuthMultisig => {
                vec![extract_multisig_auth_method(
                    storage,
                    AuthMultisig::threshold_config_slot(),
                    AuthMultisig::approver_public_keys_slot(),
                    AuthMultisig::approver_scheme_ids_slot(),
                )]
            },
            AccountComponentInterface::AuthGuardedMultisig => {
                vec![extract_multisig_auth_method(
                    storage,
                    AuthGuardedMultisig::threshold_config_slot(),
                    AuthGuardedMultisig::approver_public_keys_slot(),
                    AuthGuardedMultisig::approver_scheme_ids_slot(),
                )]
            },
            AccountComponentInterface::AuthNoAuth => vec![AuthMethod::NoAuth],
            AccountComponentInterface::AuthNetworkAccount => vec![AuthMethod::NoAuth],
            _ => vec![], // Non-auth components return empty vector
        }
    }

    /// Generates a body for the note creation of the `send_note` transaction script. The resulting
    /// code could use different procedures for note creation, which depends on the used interface.
    ///
    /// The body consists of two sections:
    /// - Pushing the note information on the stack.
    /// - Creating a note:
    ///   - For basic fungible faucet: pushing the amount of assets and distributing them.
    ///   - For basic wallet: creating a note, pushing the assets on the stack and moving them to
    ///     the created note.
    ///
    /// # Examples
    ///
    /// Example script for the [`AccountComponentInterface::BasicWallet`] with one note:
    ///
    /// ```masm
    ///     push.{note_information}
    ///     call.::miden::protocol::output_note::create
    ///
    ///     push.{note asset}
    ///     call.::miden::standards::wallets::basic::move_asset_to_note dropw
    ///     dropw dropw dropw drop
    /// ```
    ///
    /// Example script for the [`AccountComponentInterface::BasicFungibleFaucet`] with one note:
    ///
    /// ```masm
    ///     push.{note information}
    ///
    ///     push.{asset amount}
    ///     call.::miden::standards::faucets::basic_fungible::mint_and_send dropw dropw drop
    /// ```
    ///
    /// # Errors:
    /// Returns an error if:
    /// - the interface does not support the generation of the standard `send_note` procedure.
    /// - the sender of the note isn't the account for which the script is being built.
    /// - the note created by the faucet doesn't contain exactly one asset.
    /// - a faucet tries to mint an asset with a different faucet ID.
    pub(crate) fn send_note_body(
        &self,
        sender_account_id: AccountId,
        notes: &[PartialNote],
    ) -> Result<String, AccountInterfaceError> {
        let mut body = String::new();

        for partial_note in notes {
            if partial_note.metadata().sender() != sender_account_id {
                return Err(AccountInterfaceError::InvalidSenderAccount(
                    partial_note.metadata().sender(),
                ));
            }

            body.push_str(&format!(
                "
                push.{recipient}
                push.{note_type}
                push.{tag}
                # => [tag, note_type, RECIPIENT, pad(16)]
                ",
                recipient = partial_note.recipient_digest(),
                note_type = Felt::from(partial_note.metadata().note_type()),
                tag = Felt::from(partial_note.metadata().tag()),
            ));

            match self {
                AccountComponentInterface::BasicFungibleFaucet => {
                    if partial_note.assets().num_assets() != 1 {
                        return Err(AccountInterfaceError::FaucetNoteWithoutAsset);
                    }

                    // SAFETY: We checked that the note contains exactly one asset
                    let asset =
                        partial_note.assets().iter().next().expect("note should contain an asset");

                    if asset.faucet_id() != sender_account_id {
                        return Err(AccountInterfaceError::IssuanceFaucetMismatch(
                            asset.faucet_id(),
                        ));
                    }

                    body.push_str(&format!(
                        "
                        push.{amount}
                        call.::miden::standards::faucets::basic_fungible::mint_and_send
                        # => [note_idx, pad(25)]
                        swapdw dropw dropw swap drop
                        # => [note_idx, pad(16)]\n
                        ",
                        amount = asset.unwrap_fungible().amount()
                    ));
                },
                AccountComponentInterface::BasicWallet => {
                    body.push_str(
                        "
                    exec.::miden::protocol::output_note::create
                    # => [note_idx, pad(16)]\n
                    ",
                    );

                    for asset in partial_note.assets().iter() {
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
                },
                _ => {
                    return Err(AccountInterfaceError::UnsupportedInterface {
                        interface: self.clone(),
                    });
                },
            }

            body.push_str(&format!(
                "
                push.{ATTACHMENT}
                push.{attachment_kind}
                push.{attachment_scheme}
                movup.6
                # => [note_idx, attachment_scheme, attachment_kind, ATTACHMENT, pad(16)]
                exec.::miden::protocol::output_note::set_attachment
                # => [pad(16)]
            ",
                ATTACHMENT = partial_note.metadata().to_attachment_word(),
                attachment_scheme =
                    partial_note.metadata().attachment().attachment_scheme().as_u32(),
                attachment_kind = partial_note.metadata().attachment().attachment_kind().as_u8(),
            ));
        }

        Ok(body)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Extracts authentication method from a single-signature component.
fn extract_singlesig_auth_method(
    storage: &AccountStorage,
    public_key_slot: &StorageSlotName,
    scheme_id_slot: &StorageSlotName,
) -> AuthMethod {
    let pub_key = PublicKeyCommitment::from(
        storage
            .get_item(public_key_slot)
            .expect("invalid storage index of the public key"),
    );

    let scheme_id = storage
        .get_item(scheme_id_slot)
        .expect("invalid storage index of the scheme id")[0]
        .as_canonical_u64() as u8;

    let auth_scheme =
        AuthScheme::try_from(scheme_id).expect("invalid auth scheme id in the scheme id slot");

    AuthMethod::SingleSig { approver: (pub_key, auth_scheme) }
}

/// Extracts authentication method from a multisig component.
fn extract_multisig_auth_method(
    storage: &AccountStorage,
    config_slot: &StorageSlotName,
    approver_public_keys_slot: &StorageSlotName,
    approver_scheme_ids_slot: &StorageSlotName,
) -> AuthMethod {
    // Read the multisig configuration from the config slot
    // Format: [threshold, num_approvers, 0, 0]
    let config = storage
        .get_item(config_slot)
        .expect("invalid slot name of the multisig configuration");

    let threshold = config[0].as_canonical_u64() as u32;
    let num_approvers = config[1].as_canonical_u64() as u8;

    let mut approvers = Vec::new();

    // Read each public key from the map
    for key_index in 0..num_approvers {
        // The multisig component stores keys and scheme IDs using pattern [index, 0, 0, 0]
        let map_key = Word::from([key_index as u32, 0, 0, 0]);

        let pub_key_word =
            storage.get_map_item(approver_public_keys_slot, map_key).unwrap_or_else(|_| {
                panic!(
                    "Failed to read public key {} from multisig configuration at storage slot {}. \
                     Expected key pattern [index, 0, 0, 0].",
                    key_index, approver_public_keys_slot
                )
            });

        let pub_key = PublicKeyCommitment::from(pub_key_word);

        let scheme_word = storage
            .get_map_item(approver_scheme_ids_slot, map_key)
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to read scheme id for approver {} from multisig configuration at storage slot {}. \
                     Expected key pattern [index, 0, 0, 0].",
                    key_index, approver_scheme_ids_slot
                )
            });

        let scheme_id = scheme_word[0].as_canonical_u64() as u8;
        let auth_scheme =
            AuthScheme::try_from(scheme_id).expect("invalid auth scheme id in the scheme id slot");
        approvers.push((pub_key, auth_scheme));
    }

    AuthMethod::Multisig { threshold, approvers }
}
