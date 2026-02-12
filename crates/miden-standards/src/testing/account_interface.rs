use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::Account;

use crate::account::interface::{AccountInterface, AccountInterfaceExt};

/// Helper function to extract public keys from an account
pub fn get_public_keys_from_account(account: &Account) -> Vec<Word> {
    let interface = AccountInterface::from_account(account);

    interface
        .auth()
        .iter()
        .flat_map(|auth| auth.get_public_key_commitments())
        .map(Word::from)
        .collect()
}
