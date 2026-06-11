use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::{AccountProcedureRoot, AccountStorage, StorageSlotName};

use crate::AuthMethod;
use crate::account::auth::{
    AuthGuardedMultisig,
    AuthMultisig,
    AuthMultisigSmart,
    AuthSingleSig,
    AuthSingleSigAcl,
    NetworkAccountNoteAllowlist,
    NetworkAccountTxScriptAllowlist,
};

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
            AccountComponentInterface::AuthMultisigSmart => {
                vec![extract_multisig_auth_method(
                    storage,
                    AuthMultisigSmart::threshold_config_slot(),
                    AuthMultisigSmart::approver_public_keys_slot(),
                    AuthMultisigSmart::approver_scheme_ids_slot(),
                )]
            },
            AccountComponentInterface::AuthNoAuth => vec![AuthMethod::NoAuth],
            AccountComponentInterface::AuthNetworkAccount => {
                vec![extract_network_account_auth_method(storage)]
            },
            _ => vec![], // Non-auth components return empty vector
        }
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

/// Extracts authentication method from a network-account component.
fn extract_network_account_auth_method(storage: &AccountStorage) -> AuthMethod {
    let allowlist = NetworkAccountNoteAllowlist::try_from(storage)
        .expect("network account note allowlist slot should be present and valid");
    let tx_script_allowlist = NetworkAccountTxScriptAllowlist::try_from(storage)
        .expect("network account tx script allowlist slot should be present and valid");

    AuthMethod::NetworkAccount {
        allowed_script_roots: allowlist.into_allowed_script_roots(),
        allowed_tx_script_roots: tx_script_allowlist.into_allowed_script_roots(),
    }
}
