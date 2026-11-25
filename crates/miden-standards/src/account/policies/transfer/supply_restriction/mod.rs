use alloc::collections::BTreeMap;

use miden_protocol::account::{AccountId, StorageMap, StorageMapKey, StorageSlot, StorageSlotName};
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::errors::AssetError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use thiserror::Error;

mod manager;

pub use manager::SupplyRestrictionManager;

// SUPPLY RESTRICTION ERROR
// ================================================================================================

/// Errors returned by [`SupplyRestrictionStorage::with_restricted_amounts`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SupplyRestrictionError {
    /// The frozen plus confiscated amount of an account exceeds [`AssetAmount::MAX`].
    #[error("frozen plus confiscated amount of account {account_id} is invalid")]
    InvalidRestrictedAmount {
        account_id: AccountId,
        source: AssetError,
    },

    /// The same account was supplied more than once.
    #[error("account {0} is restricted more than once")]
    DuplicateAccount(AccountId),
}

// SUPPLY RESTRICTION STORAGE
// ================================================================================================

static RESTRICTED_AMOUNTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::faucets::policies::transfer::supply_restriction::restricted_amounts",
    )
    .expect("storage slot name should be valid")
});

/// Storage backing the frozen and confiscated amounts of a fungible faucet's asset per holder
/// account.
///
/// The amounts of an account are disjoint:
/// - frozen: restricted but can still be unfrozen. Freezing does not change the token supply.
/// - confiscated: restricted for good. Confiscating decreases the token supply by the confiscated
///   amount, so the issuer can re-mint it to another account without counting it twice.
///
/// `frozen + confiscated` of an account never exceeds [`AssetAmount::MAX`].
///
/// This is **not** an installable account component on its own. The policy component that installs
/// the storage map (typically [`super::SupplyRestrictionPolicy`]) takes the slot from here, and
/// [`SupplyRestrictionManager`] updates it.
///
/// ## Storage
///
/// - [`Self::restricted_amounts_slot()`]: storage map laid out as:
///   - key: `[0, 0, account_id_suffix, account_id_prefix]`
///   - value: `[frozen, confiscated, 0, 0]`.
#[derive(Debug, Clone, Default)]
pub struct SupplyRestrictionStorage {
    restricted_amounts: BTreeMap<AccountId, (AssetAmount, AssetAmount)>,
}

impl SupplyRestrictionStorage {
    /// Creates a [`SupplyRestrictionStorage`] with no initially restricted accounts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`SupplyRestrictionStorage`] with the given frozen and confiscated amounts, in
    /// this order, per account.
    ///
    /// This does not decrease the token supply, so the initial token supply of the faucet must
    /// already exclude the confiscated amounts.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the frozen plus confiscated amount of an account exceeds [`AssetAmount::MAX`].
    /// - the same account is provided more than once.
    pub fn with_restricted_amounts(
        restricted_amounts: impl IntoIterator<Item = (AccountId, AssetAmount, AssetAmount)>,
    ) -> Result<Self, SupplyRestrictionError> {
        let mut storage = Self::default();
        for (account_id, frozen, confiscated) in restricted_amounts {
            (frozen + confiscated).map_err(|source| {
                SupplyRestrictionError::InvalidRestrictedAmount { account_id, source }
            })?;

            if storage.restricted_amounts.insert(account_id, (frozen, confiscated)).is_some() {
                return Err(SupplyRestrictionError::DuplicateAccount(account_id));
            }
        }
        Ok(storage)
    }

    /// Returns the initial frozen and confiscated amounts per account captured in this storage.
    pub fn restricted_amounts(&self) -> &BTreeMap<AccountId, (AssetAmount, AssetAmount)> {
        &self.restricted_amounts
    }

    /// Storage slot name for the map of frozen and confiscated amounts.
    pub fn restricted_amounts_slot() -> &'static StorageSlotName {
        &RESTRICTED_AMOUNTS_SLOT_NAME
    }

    /// Builds the initial `restricted_amounts` [`StorageMap`] from the captured amounts.
    pub fn build_storage_map(&self) -> StorageMap {
        StorageMap::with_entries(self.restricted_amounts.iter().map(
            |(account_id, (frozen, confiscated))| {
                let key = StorageMapKey::new(AccountIdKey::from(*account_id).as_word());
                let value = Word::from([
                    Felt::from(*frozen),
                    Felt::from(*confiscated),
                    Felt::ZERO,
                    Felt::ZERO,
                ]);
                (key, value)
            },
        ))
        .expect("initially restricted accounts should have unique IDs")
    }

    /// Consumes the storage and returns the [`StorageSlot`] it contributes to an account
    /// component.
    pub fn into_slot(self) -> StorageSlot {
        StorageSlot::with_map(RESTRICTED_AMOUNTS_SLOT_NAME.clone(), self.build_storage_map())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn restricted_amounts_are_stored() -> anyhow::Result<()> {
        let account_id = AccountId::mock_private(1);
        let storage = SupplyRestrictionStorage::with_restricted_amounts([(
            account_id,
            AssetAmount::from(3u32),
            AssetAmount::from(4u32),
        )])?;

        let key = StorageMapKey::new(AccountIdKey::from(account_id).as_word());
        assert_eq!(storage.build_storage_map().get(&key), Word::from([3u32, 4, 0, 0]));

        Ok(())
    }

    #[test]
    fn restricted_amounts_up_to_max_are_accepted() -> anyhow::Result<()> {
        let account_id = AccountId::mock_private(1);
        let one = AssetAmount::from(1u32);
        SupplyRestrictionStorage::with_restricted_amounts([(
            account_id,
            (AssetAmount::MAX - one)?,
            one,
        )])?;

        let result = SupplyRestrictionStorage::with_restricted_amounts([(
            account_id,
            AssetAmount::MAX,
            one,
        )]);
        assert_matches!(
            result,
            Err(SupplyRestrictionError::InvalidRestrictedAmount { account_id: id, .. })
                if id == account_id
        );

        Ok(())
    }

    #[test]
    fn duplicate_account_is_rejected() {
        let account_id = AccountId::mock_private(1);
        let entry = (account_id, AssetAmount::from(1u32), AssetAmount::ZERO);
        assert_matches!(
            SupplyRestrictionStorage::with_restricted_amounts([entry, entry]),
            Err(SupplyRestrictionError::DuplicateAccount(id)) if id == account_id
        );
    }
}
