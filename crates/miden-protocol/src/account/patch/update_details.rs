use crate::account::{Account, AccountId, AccountPatch};
use crate::errors::{
    AccountPatchError,
    AccountUpdateDetailsValidationError,
    AccountUpdateSizeValidationError,
    NewPublicAccountValidationError,
};
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{ACCOUNT_UPDATE_MAX_SIZE, Word};

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

    /// Validates that the serialized size of these details does not exceed the maximum account
    /// update size.
    pub(crate) fn validate_size(
        &self,
        account_id: AccountId,
    ) -> Result<(), AccountUpdateSizeValidationError> {
        let update_size = self.get_size_hint();
        if update_size > ACCOUNT_UPDATE_MAX_SIZE as usize {
            return Err(AccountUpdateSizeValidationError { account_id, update_size });
        }

        Ok(())
    }

    /// Validates that these details are compatible with `account_id`.
    ///
    /// Returns the account patch for a valid public account update and `None` for a valid private
    /// account update.
    pub(crate) fn validate_for_account(
        &self,
        account_id: AccountId,
    ) -> Result<Option<&AccountPatch>, AccountUpdateDetailsValidationError> {
        match (self, account_id.is_private()) {
            (Self::Private, true) => Ok(None),
            (Self::Public(_), true) => {
                Err(AccountUpdateDetailsValidationError::PrivateAccountWithDetails(account_id))
            },
            (Self::Private, false) => Err(
                AccountUpdateDetailsValidationError::PublicStateAccountMissingDetails(account_id),
            ),
            (Self::Public(patch), false) if patch.id() != account_id => {
                Err(AccountUpdateDetailsValidationError::AccountIdMismatch {
                    account_id,
                    patch_account_id: patch.id(),
                })
            },
            (Self::Public(patch), false) => Ok(Some(patch)),
        }
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

/// Validates that `patch` contains the complete state of a new public account and reconstructs to
/// `final_state_commitment`.
pub(crate) fn validate_new_public_account(
    patch: &AccountPatch,
    final_state_commitment: Word,
) -> Result<(), NewPublicAccountValidationError> {
    let account = Account::try_from(patch).map_err(|source| {
        NewPublicAccountValidationError::RequiresFullStatePatch { id: patch.id(), source }
    })?;
    let account_commitment = account.to_commitment();
    if account_commitment != final_state_commitment {
        return Err(NewPublicAccountValidationError::FinalCommitmentMismatch {
            final_state_commitment,
            account_commitment,
        });
    }

    Ok(())
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
        StorageSlotName,
    };
    use crate::asset::{Asset, FungibleAsset, NonFungibleAsset};
    use crate::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
    use crate::utils::serde::Serializable;
    use crate::{ONE, Word};

    #[test]
    fn account_update_details_size_hint() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER)?;

        // A full state patch may only create slots, so build it with create ops.
        let storage_patch = AccountStoragePatch::builder()
            .create_value(StorageSlotName::mock(2), Word::from([1, 1, 1, 1u32]))
            .create_value(StorageSlotName::mock(3), Word::from([1, 1, 0, 1u32]))
            .create_map(
                StorageSlotName::mock(4),
                [(StorageMapKey::from_array([1, 1, 1, 1]), Word::from([1, 1, 1, 1u32]))],
            )
            .build();

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
