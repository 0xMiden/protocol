use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::{AccountId, AccountProcedureRoot, AccountStorage, StorageSlotName};
use miden_protocol::note::PartialNote;
use miden_protocol::{Felt, FieldElement, Word};

use crate::AuthScheme;
use crate::account::auth::{
    AuthEcdsaK256Keccak,
    AuthEcdsaK256KeccakAcl,
    AuthEcdsaK256KeccakMultisig,
    AuthFalcon512Rpo,
    AuthFalcon512RpoAcl,
    AuthFalcon512RpoMultisig,
};
use crate::account::interface::AccountInterfaceError;

// ACCOUNT COMPONENT INTERFACE
// ================================================================================================

/// The enum holding all possible account interfaces which could be loaded to some account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountComponentInterface {
    /// Exposes procedures from the [`BasicWallet`][crate::account::wallets::BasicWallet] module.
    BasicWallet,
    /// Exposes procedures from the
    /// [`BasicFungibleFaucet`][crate::account::faucets::BasicFungibleFaucet] module.
    BasicFungibleFaucet,
    /// Exposes procedures from the
    /// [`NetworkFungibleFaucet`][crate::account::faucets::NetworkFungibleFaucet] module.
    NetworkFungibleFaucet,
    /// Exposes procedures from the
    /// [`AuthEcdsaK256Keccak`][crate::account::auth::AuthEcdsaK256Keccak] module.
    AuthEcdsaK256Keccak,
    /// Exposes procedures from the
    /// [`AuthEcdsaK256KeccakAcl`][crate::account::auth::AuthEcdsaK256KeccakAcl] module.
    AuthEcdsaK256KeccakAcl,
    /// Exposes procedures from the
    /// [`AuthEcdsaK256KeccakMultisig`][crate::account::auth::AuthEcdsaK256KeccakMultisig] module.
    AuthEcdsaK256KeccakMultisig,
    /// Exposes procedures from the
    /// [`AuthFalcon512Rpo`][crate::account::auth::AuthFalcon512Rpo] module.
    AuthFalcon512Rpo,
    /// Exposes procedures from the
    /// [`AuthFalcon512RpoAcl`][crate::account::auth::AuthFalcon512RpoAcl] module.
    AuthFalcon512RpoAcl,
    /// Exposes procedures from the
    /// [`AuthFalcon512RpoMultisig`][crate::account::auth::AuthFalcon512RpoMultisig] module.
    AuthFalcon512RpoMultisig,
    /// Exposes procedures from the [`NoAuth`][crate::account::auth::NoAuth] module.
    ///
    /// This authentication scheme provides no cryptographic authentication and only increments
    /// the nonce if the account state has actually changed during transaction execution.
    AuthNoAuth,
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
            AccountComponentInterface::BasicFungibleFaucet => "Basic Fungible Faucet".to_string(),
            AccountComponentInterface::NetworkFungibleFaucet => {
                "Network Fungible Faucet".to_string()
            },
            AccountComponentInterface::AuthEcdsaK256Keccak => "ECDSA K256 Keccak".to_string(),
            AccountComponentInterface::AuthEcdsaK256KeccakAcl => {
                "ECDSA K256 Keccak ACL".to_string()
            },
            AccountComponentInterface::AuthEcdsaK256KeccakMultisig => {
                "ECDSA K256 Keccak Multisig".to_string()
            },
            AccountComponentInterface::AuthFalcon512Rpo => "Falcon512 RPO".to_string(),
            AccountComponentInterface::AuthFalcon512RpoAcl => "Falcon512 RPO ACL".to_string(),
            AccountComponentInterface::AuthFalcon512RpoMultisig => {
                "Falcon512 RPO Multisig".to_string()
            },

            AccountComponentInterface::AuthNoAuth => "No Auth".to_string(),
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
            AccountComponentInterface::AuthEcdsaK256Keccak
                | AccountComponentInterface::AuthEcdsaK256KeccakAcl
                | AccountComponentInterface::AuthEcdsaK256KeccakMultisig
                | AccountComponentInterface::AuthFalcon512Rpo
                | AccountComponentInterface::AuthFalcon512RpoAcl
                | AccountComponentInterface::AuthFalcon512RpoMultisig
                | AccountComponentInterface::AuthNoAuth
        )
    }

    /// Returns the authentication schemes associated with this component interface.
    pub fn get_auth_schemes(&self, storage: &AccountStorage) -> Vec<AuthScheme> {
        match self {
            AccountComponentInterface::AuthEcdsaK256Keccak => {
                vec![AuthScheme::EcdsaK256Keccak {
                    pub_key: PublicKeyCommitment::from(
                        storage
                            .get_item(AuthEcdsaK256Keccak::public_key_slot())
                            .expect("invalid storage index of the public key"),
                    ),
                }]
            },
            AccountComponentInterface::AuthEcdsaK256KeccakAcl => {
                vec![AuthScheme::EcdsaK256Keccak {
                    pub_key: PublicKeyCommitment::from(
                        storage
                            .get_item(AuthEcdsaK256KeccakAcl::public_key_slot())
                            .expect("invalid storage index of the public key"),
                    ),
                }]
            },
            AccountComponentInterface::AuthEcdsaK256KeccakMultisig => {
                vec![extract_multisig_auth_scheme(
                    storage,
                    AuthEcdsaK256KeccakMultisig::threshold_config_slot(),
                    AuthEcdsaK256KeccakMultisig::approver_public_keys_slot(),
                )]
            },
            AccountComponentInterface::AuthFalcon512Rpo => {
                vec![AuthScheme::Falcon512Rpo {
                    pub_key: PublicKeyCommitment::from(
                        storage
                            .get_item(AuthFalcon512Rpo::public_key_slot())
                            .expect("invalid slot name of the AuthFalcon512Rpo public key"),
                    ),
                }]
            },
            AccountComponentInterface::AuthFalcon512RpoAcl => {
                vec![AuthScheme::Falcon512Rpo {
                    pub_key: PublicKeyCommitment::from(
                        storage
                            .get_item(AuthFalcon512RpoAcl::public_key_slot())
                            .expect("invalid slot name of the AuthFalcon512RpoAcl public key"),
                    ),
                }]
            },
            AccountComponentInterface::AuthFalcon512RpoMultisig => {
                vec![extract_multisig_auth_scheme(
                    storage,
                    AuthFalcon512RpoMultisig::threshold_config_slot(),
                    AuthFalcon512RpoMultisig::approver_public_keys_slot(),
                )]
            },
            AccountComponentInterface::AuthNoAuth => vec![AuthScheme::NoAuth],
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
    ///     call.::miden::standards::faucets::basic_fungible::distribute dropw dropw drop
    /// ```
    ///
    /// # Errors:
    /// Returns an error if:
    /// - the interface does not support the generation of the standard `send_note` procedure.
    /// - the sender of the note isn't the account for which the script is being built.
    /// - the note created by the faucet doesn't contain exactly one asset.
    /// - a faucet tries to distribute an asset with a different faucet ID.
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

                    if asset.faucet_id_prefix() != sender_account_id.prefix() {
                        return Err(AccountInterfaceError::IssuanceFaucetMismatch(
                            asset.faucet_id_prefix(),
                        ));
                    }

                    body.push_str(&format!(
                        "
                        push.{amount}
                        call.::miden::standards::faucets::basic_fungible::distribute
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
                            push.{asset}
                            # => [ASSET, note_idx, pad(16)]
                            call.::miden::standards::wallets::basic::move_asset_to_note
                            dropw
                            # => [note_idx, pad(16)]\n
                            ",
                            asset = Word::from(*asset)
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

/// Extracts authentication scheme from a multisig component.
fn extract_multisig_auth_scheme(
    storage: &AccountStorage,
    config_slot: &StorageSlotName,
    approver_public_keys_slot: &StorageSlotName,
) -> AuthScheme {
    // Read the multisig configuration from the config slot
    // Format: [threshold, num_approvers, 0, 0]
    let config = storage
        .get_item(config_slot)
        .expect("invalid slot name of the multisig configuration");

    let threshold = config[0].as_int() as u32;
    let num_approvers = config[1].as_int() as u8;

    let mut pub_keys = Vec::new();

    // Read each public key from the map
    for key_index in 0..num_approvers {
        // The multisig component stores keys using pattern [index, 0, 0, 0]
        let map_key = [Felt::new(key_index as u64), Felt::ZERO, Felt::ZERO, Felt::ZERO];

        match storage.get_map_item(approver_public_keys_slot, map_key.into()) {
            Ok(pub_key) => {
                pub_keys.push(PublicKeyCommitment::from(pub_key));
            },
            Err(_) => {
                // If we can't read a public key, panic with a clear error message
                panic!(
                    "Failed to read public key {} from multisig configuration at storage slot {}. \
                        Expected key pattern [index, 0, 0, 0]. \
                        This indicates corrupted multisig storage or incorrect storage layout.",
                    key_index, approver_public_keys_slot
                );
            },
        }
    }

    AuthScheme::Falcon512RpoMultisig { threshold, pub_keys }
}
