use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::Account;

use crate::account::auth::{
    AuthGuardedMultisig,
    AuthMultisig,
    AuthMultisigSmart,
    AuthSingleSig,
    AuthSingleSigAcl,
};
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};

/// Helper function to extract public key commitments from every standard auth component
/// installed on `account`. Reads storage directly via the component's slot accessors.
pub fn get_public_keys_from_account(account: &Account) -> Vec<Word> {
    let interface = AccountInterface::from_account(account);
    let storage = account.storage();

    let mut keys = Vec::new();
    for component in interface.components() {
        match component {
            AccountComponentInterface::AuthSingleSig => {
                if let Ok(key) = storage.get_item(AuthSingleSig::public_key_slot()) {
                    keys.push(key);
                }
            },
            AccountComponentInterface::AuthSingleSigAcl => {
                if let Ok(key) = storage.get_item(AuthSingleSigAcl::public_key_slot()) {
                    keys.push(key);
                }
            },
            AccountComponentInterface::AuthMultisig => {
                keys.extend(read_multisig_public_keys(
                    storage,
                    AuthMultisig::threshold_config_slot(),
                    AuthMultisig::approver_public_keys_slot(),
                ));
            },
            AccountComponentInterface::AuthGuardedMultisig => {
                keys.extend(read_multisig_public_keys(
                    storage,
                    AuthGuardedMultisig::threshold_config_slot(),
                    AuthGuardedMultisig::approver_public_keys_slot(),
                ));
            },
            AccountComponentInterface::AuthMultisigSmart => {
                keys.extend(read_multisig_public_keys(
                    storage,
                    AuthMultisigSmart::threshold_config_slot(),
                    AuthMultisigSmart::approver_public_keys_slot(),
                ));
            },
            _ => {},
        }
    }
    keys
}

fn read_multisig_public_keys(
    storage: &miden_protocol::account::AccountStorage,
    config_slot: &miden_protocol::account::StorageSlotName,
    keys_slot: &miden_protocol::account::StorageSlotName,
) -> Vec<Word> {
    let config = match storage.get_item(config_slot) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let num_approvers = config[1].as_canonical_u64() as u32;
    (0..num_approvers)
        .filter_map(|i| storage.get_map_item(keys_slot, Word::from([i, 0u32, 0, 0])).ok())
        .collect()
}
