use miden_protocol::account::{AccountDelta, AccountVaultDelta};

use crate::proto;

#[cfg(test)]
mod tests;

// ACCOUNT DELTAS
// ================================================================================================

impl From<&AccountVaultDelta> for proto::account::AccountVaultDelta {
    fn from(delta: &AccountVaultDelta) -> Self {
        Self {
            added: delta.added_assets().map(Into::into).collect(),
            removed: delta.removed_assets().map(Into::into).collect(),
        }
    }
}

impl From<&AccountDelta> for proto::account::AccountDelta {
    fn from(delta: &AccountDelta) -> Self {
        Self {
            version: proto::account::AccountDeltaVersion::V1 as i32,
            account_id: Some(delta.id().into()),
            storage: Some(delta.storage().into()),
            vault: Some(delta.vault().into()),
            code: Some(delta.code().into()),
            nonce_delta: Some(delta.nonce_delta().into()),
        }
    }
}

impl From<AccountDelta> for proto::account::AccountDelta {
    fn from(delta: AccountDelta) -> Self {
        Self::from(&delta)
    }
}
