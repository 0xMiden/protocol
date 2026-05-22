use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_protocol::Felt;
use miden_protocol::account::{AccountId, AccountProcedureRoot};
use miden_protocol::note::PartialNote;

use crate::account::auth::AccountAuthScheme;
use crate::account::interface::AccountInterfaceError;

// ACCOUNT COMPONENT INTERFACE
// ================================================================================================

/// The enum holding all possible account interfaces which could be loaded to some account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountComponentInterface {
    /// Exposes procedures from the [`BasicWallet`][crate::account::wallets::BasicWallet] module.
    BasicWallet,
    /// Exposes procedures from the
    /// [`FungibleFaucet`][crate::account::faucets::FungibleFaucet] module.
    FungibleFaucet,
    /// Exposes procedures from the
    /// [`Authority`][crate::account::access::Authority] access component.
    Authority,
    /// Exposes procedures from the
    /// [`Ownable2Step`][crate::account::access::Ownable2Step] access component.
    Ownable2Step,
    /// Exposes procedures from the
    /// [`RoleBasedAccessControl`][crate::account::access::RoleBasedAccessControl] access
    /// component.
    RoleBasedAccessControl,
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
    /// [`AuthMultisigSmart`][crate::account::auth::AuthMultisigSmart] module.
    AuthMultisigSmart,
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
            AccountComponentInterface::FungibleFaucet => "Fungible Faucet".to_string(),
            AccountComponentInterface::Authority => "Authority".to_string(),
            AccountComponentInterface::Ownable2Step => "Ownable2Step".to_string(),
            AccountComponentInterface::RoleBasedAccessControl => {
                "Role Based Access Control".to_string()
            },
            AccountComponentInterface::AuthSingleSig => "SingleSig".to_string(),
            AccountComponentInterface::AuthSingleSigAcl => "SingleSig ACL".to_string(),
            AccountComponentInterface::AuthMultisig => "Multisig".to_string(),
            AccountComponentInterface::AuthMultisigSmart => "Multisig Smart".to_string(),
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
                | AccountComponentInterface::AuthMultisigSmart
                | AccountComponentInterface::AuthGuardedMultisig
                | AccountComponentInterface::AuthNoAuth
                | AccountComponentInterface::AuthNetworkAccount
        )
    }

    /// Returns the [`AccountAuthScheme`] tag for this component interface, if it is an auth
    /// component. Returns [`None`] for non-auth components.
    pub fn auth_scheme(&self) -> Option<AccountAuthScheme> {
        match self {
            AccountComponentInterface::AuthSingleSig => Some(AccountAuthScheme::SingleSig),
            AccountComponentInterface::AuthSingleSigAcl => Some(AccountAuthScheme::SingleSigAcl),
            AccountComponentInterface::AuthMultisig => Some(AccountAuthScheme::Multisig),
            AccountComponentInterface::AuthMultisigSmart => Some(AccountAuthScheme::MultisigSmart),
            AccountComponentInterface::AuthGuardedMultisig => {
                Some(AccountAuthScheme::GuardedMultisig)
            },
            AccountComponentInterface::AuthNoAuth => Some(AccountAuthScheme::NoAuth),
            AccountComponentInterface::AuthNetworkAccount => {
                Some(AccountAuthScheme::NetworkAccount)
            },
            _ => None,
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
    /// Example script for the [`AccountComponentInterface::FungibleFaucet`] with one note:
    ///
    /// ```masm
    ///     push.{note information}
    ///
    ///     push.{ASSET_VALUE} push.{ASSET_KEY}
    ///     call.::miden::standards::faucets::fungible::mint_and_send
    ///     swapdw dropw dropw swapdw dropw dropw
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
                AccountComponentInterface::FungibleFaucet => {
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

            for attachment in partial_note.attachments().iter() {
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

            body.push_str(
                "
                # drop the note idx
                drop
                # => [pad(16)]
            ",
            );
        }

        Ok(body)
    }
}
