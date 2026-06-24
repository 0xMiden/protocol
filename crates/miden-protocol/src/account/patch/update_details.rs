use crate::account::AccountPatch;
use crate::errors::AccountPatchError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// ACCOUNT UPDATE DETAILS
// ================================================================================================

/// Describes the update of an account at any aggregation level: as the result of a single
/// transaction, of all transactions in a batch, or of all batches in a block. The representation is
/// the same in all cases, which lets transaction-, batch-, and block-level updates merge into one
/// another.
///
/// For a public account, the update is represented as an [`AccountPatch`] describing the new
/// absolute state of the changed components of the account. For a private account, the actual state
/// change is not publicly visible and only the state commitments are; this is captured by the
/// [`AccountUpdateDetails::Private`] variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountUpdateDetails {
    /// The state update of a private account is not publicly accessible.
    Private,

    /// The state update of a public account, represented as an [`AccountPatch`] describing the new
    /// absolute state of the changed components of the account.
    Public(AccountPatch),
}

impl AccountUpdateDetails {
    const PRIVATE_TAG: u8 = 0;
    const PUBLIC_TAG: u8 = 1;

    /// Returns `true` if the account update details are for a private account, `false` otherwise.
    pub fn is_private(&self) -> bool {
        matches!(self, Self::Private)
    }

    /// Returns `true` if the account update details are for a public account, `false` otherwise.
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public(_))
    }

    /// Merges the `other` update into this one.
    ///
    /// This account update (`self`) must come before `other`, i.e. `self.nonce + 1` must be equal
    /// to `other.nonce`.
    pub fn merge(self, other: AccountUpdateDetails) -> Result<Self, AccountPatchError> {
        let merged_update = match (self, other) {
            (AccountUpdateDetails::Private, AccountUpdateDetails::Private) => {
                AccountUpdateDetails::Private
            },
            (AccountUpdateDetails::Public(mut patch), AccountUpdateDetails::Public(new_patch)) => {
                patch.merge(new_patch)?;
                AccountUpdateDetails::Public(patch)
            },
            (left, right) => {
                return Err(AccountPatchError::IncompatibleAccountUpdates {
                    left_update_type: left.as_tag_str(),
                    right_update_type: right.as_tag_str(),
                });
            },
        };

        Ok(merged_update)
    }

    /// Returns the tag of the [`AccountUpdateDetails`] as a string for inclusion in error messages.
    pub(crate) const fn as_tag_str(&self) -> &'static str {
        match self {
            AccountUpdateDetails::Private => "private",
            AccountUpdateDetails::Public(_) => "public",
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountUpdateDetails {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            AccountUpdateDetails::Private => {
                Self::PRIVATE_TAG.write_into(target);
            },
            AccountUpdateDetails::Public(public) => {
                Self::PUBLIC_TAG.write_into(target);
                public.write_into(target);
            },
        }
    }

    fn get_size_hint(&self) -> usize {
        // Size of the serialized enum tag.
        let u8_size = 0u8.get_size_hint();

        match self {
            AccountUpdateDetails::Private => u8_size,
            AccountUpdateDetails::Public(public) => u8_size + public.get_size_hint(),
        }
    }
}

impl Deserializable for AccountUpdateDetails {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match u8::read_from(source)? {
            Self::PRIVATE_TAG => Ok(Self::Private),
            Self::PUBLIC_TAG => Ok(Self::Public(AccountPatch::read_from(source)?)),
            variant => Err(DeserializationError::InvalidValue(format!(
                "Unknown variant {variant} for AccountUpdateDetails"
            ))),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::AccountUpdateDetails;
    use crate::account::{
        AccountCode,
        AccountId,
        AccountPatch,
        AccountStoragePatch,
        AccountVaultPatch,
        StorageMapKey,
        StorageMapPatch,
        StorageSlotName,
    };
    use crate::asset::{Asset, FungibleAsset, NonFungibleAsset};
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
    use crate::utils::serde::Serializable;
    use crate::{ONE, Word};

    #[test]
    fn account_update_details_size_hint() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        let storage_patch = AccountStoragePatch::from_iters(
            [StorageSlotName::mock(1)],
            [
                (StorageSlotName::mock(2), Word::from([1, 1, 1, 1u32])),
                (StorageSlotName::mock(3), Word::from([1, 1, 0, 1u32])),
            ],
            [(
                StorageSlotName::mock(4),
                StorageMapPatch::from_iters(
                    [
                        StorageMapKey::from_array([1, 1, 1, 0]),
                        StorageMapKey::from_array([0, 1, 1, 1]),
                    ],
                    [(StorageMapKey::from_array([1, 1, 1, 1]), Word::from([1, 1, 1, 1u32]))],
                ),
            )],
        );

        let non_fungible: Asset = NonFungibleAsset::mock(&[6]);
        let fungible: Asset = FungibleAsset::mock(42);
        let vault_patch = AccountVaultPatch::with_assets([non_fungible, fungible]);

        let account_patch = AccountPatch::new(
            account_id,
            storage_patch,
            vault_patch,
            Some(AccountCode::mock()),
            Some(ONE),
        )?;

        let update_details_private = AccountUpdateDetails::Private;
        assert_eq!(update_details_private.to_bytes().len(), update_details_private.get_size_hint());

        let update_details_patch = AccountUpdateDetails::Public(account_patch);
        assert_eq!(update_details_patch.to_bytes().len(), update_details_patch.get_size_hint());

        // Verify the `Public` flavor differs from `Private` in size, just to confirm both branches
        // are exercised.
        assert!(update_details_patch.get_size_hint() > update_details_private.get_size_hint());

        Ok(())
    }
}
