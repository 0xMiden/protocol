use alloc::string::ToString;
use alloc::vec::Vec;

use crate::asset::{Asset, AssetVault};
use crate::crypto::SequentialCommit;
use crate::errors::AccountError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};
use crate::{Felt, Hasher, Word, ZERO};

mod account_id;
pub use account_id::{
    AccountId,
    AccountIdPrefix,
    AccountIdPrefixV1,
    AccountIdV1,
    AccountIdVersion,
    AccountType,
};

pub(crate) mod name_validation;

pub mod auth;

mod access;
pub use access::RoleSymbol;

mod builder;
pub use builder::AccountBuilder;

pub mod code;
pub use code::AccountCode;
pub use code::procedure::AccountProcedureRoot;

pub mod component;
pub use component::{AccountComponent, AccountComponentCode, AccountComponentMetadata};

pub mod interface;
pub use interface::{AccountCodeInterface, AccountComponentName};

mod patch;
pub use patch::{
    AccountPatch,
    AccountStoragePatch,
    AccountUpdateDetails,
    AccountVaultPatch,
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageSlotPatch,
    StorageValuePatch,
};

pub mod delta;
pub use delta::{
    AccountDelta,
    AccountVaultDelta,
    FungibleAssetDelta,
    NonFungibleAssetDelta,
    NonFungibleDeltaAction,
};

pub mod storage;
pub use storage::{
    AccountStorage,
    AccountStorageHeader,
    PartialStorage,
    PartialStorageMap,
    StorageMap,
    StorageMapKey,
    StorageMapKeyHash,
    StorageMapWitness,
    StorageSlot,
    StorageSlotContent,
    StorageSlotHeader,
    StorageSlotId,
    StorageSlotName,
    StorageSlotType,
};

mod header;
pub use header::AccountHeader;

mod file;
pub use file::AccountFile;

mod partial;
pub use partial::PartialAccount;

// ACCOUNT
// ================================================================================================

/// An account which can store assets and define rules for manipulating them.
///
/// An account consists of the following components:
/// - Account ID, which uniquely identifies the account and also defines basic properties of the
///   account.
/// - Account vault, which stores assets owned by the account.
/// - Account storage, which is a key-value map (both keys and values are words) used to store
///   arbitrary user-defined data.
/// - Account code, which is a set of Miden VM programs defining the public interface of the
///   account.
/// - Account nonce, a value which is incremented whenever account state is updated.
///
/// Out of the above components account ID is always immutable (once defined it can never be
/// changed). Other components may be mutated throughout the lifetime of the account. However,
/// account state can be changed only by invoking one of account interface methods.
///
/// The recommended way to build an account is through an [`AccountBuilder`], which can be
/// instantiated through [`Account::builder`]. See the type's documentation for details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    id: AccountId,
    vault: AssetVault,
    storage: AccountStorage,
    code: AccountCode,
    nonce: Felt,
    seed: Option<Word>,
}

impl Account {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns an [`Account`] instantiated with the provided components.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - an account seed is provided but the account's nonce indicates the account already exists.
    /// - an account seed is not provided but the account's nonce indicates the account is new.
    /// - an account seed is provided but the account ID derived from it is invalid or does not
    ///   match the provided account's ID.
    pub fn new(
        id: AccountId,
        vault: AssetVault,
        storage: AccountStorage,
        code: AccountCode,
        nonce: Felt,
        seed: Option<Word>,
    ) -> Result<Self, AccountError> {
        validate_account_seed(id, code.commitment(), storage.to_commitment(), seed, nonce)?;

        Ok(Self::new_unchecked(id, vault, storage, code, nonce, seed))
    }

    /// Returns an [`Account`] instantiated with the provided components.
    ///
    /// # Warning
    ///
    /// This does not check that the provided seed is valid with respect to the provided components.
    /// Prefer using [`Account::new`] whenever possible.
    pub fn new_unchecked(
        id: AccountId,
        vault: AssetVault,
        storage: AccountStorage,
        code: AccountCode,
        nonce: Felt,
        seed: Option<Word>,
    ) -> Self {
        Self { id, vault, storage, code, nonce, seed }
    }

    /// Creates an account's [`AccountCode`] and [`AccountStorage`] from the provided components.
    ///
    /// This merges all libraries of the components into a single
    /// [`MastForest`](miden_processor::MastForest) to produce the [`AccountCode`].
    ///
    /// The storage slots of all components are merged into a single [`AccountStorage`], where the
    /// slots are sorted by their [`StorageSlotName`].
    ///
    /// The resulting commitments from code and storage can then be used to construct an
    /// [`AccountId`]. Finally, a new account can then be instantiated from those parts using
    /// [`Account::new`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of procedures in all merged libraries is 0 or exceeds
    ///   [`AccountCode::MAX_NUM_PROCEDURES`].
    /// - Two or more libraries export a procedure with the same MAST root.
    /// - The first component doesn't contain exactly one authentication procedure.
    /// - Other components contain authentication procedures.
    /// - The number of [`StorageSlot`]s of all components exceeds 255.
    /// - [`MastForest::merge`](miden_processor::MastForest::merge) fails on all libraries.
    pub(super) fn initialize_from_components(
        components: Vec<AccountComponent>,
    ) -> Result<(AccountCode, AccountStorage), AccountError> {
        let code = AccountCode::from_components_unchecked(&components)?;
        let storage = AccountStorage::from_components(components)?;

        Ok((code, storage))
    }

    /// Creates a new [`AccountBuilder`] for an account and sets the initial seed from which the
    /// grinding process for that account's [`AccountId`] will start.
    ///
    /// This initial seed should come from a cryptographic random number generator.
    pub fn builder(init_seed: [u8; 32]) -> AccountBuilder {
        AccountBuilder::new(init_seed)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment of this account.
    ///
    /// See [`AccountHeader::to_commitment`] for details on how it is computed.
    pub fn to_commitment(&self) -> Word {
        AccountHeader::from(self).to_commitment()
    }

    /// Returns the commitment of this account as used for the initial account state commitment in
    /// transaction proofs.
    ///
    /// For existing accounts, this is exactly the same as [Account::to_commitment], however, for
    /// new accounts this value is set to [crate::EMPTY_WORD]. This is because when a
    /// transaction is executed against a new account, public input for the initial account
    /// state is set to [crate::EMPTY_WORD] to distinguish new accounts from existing accounts.
    /// The actual commitment of the initial account state (and the initial state itself), are
    /// provided to the VM via the advice provider.
    pub fn initial_commitment(&self) -> Word {
        if self.is_new() {
            Word::empty()
        } else {
            self.to_commitment()
        }
    }

    /// Returns unique identifier of this account.
    pub fn id(&self) -> AccountId {
        self.id
    }

    /// Returns a reference to the vault of this account.
    pub fn vault(&self) -> &AssetVault {
        &self.vault
    }

    /// Returns a reference to the storage of this account.
    pub fn storage(&self) -> &AccountStorage {
        &self.storage
    }

    /// Returns a reference to the code of this account.
    pub fn code(&self) -> &AccountCode {
        &self.code
    }

    /// Returns the public interface of this account: its ID and the set of procedure roots it
    /// exposes.
    pub fn code_interface(&self) -> AccountCodeInterface {
        self.code.interface(self.id())
    }

    /// Returns nonce for this account.
    pub fn nonce(&self) -> Felt {
        self.nonce
    }

    /// Returns the seed of the account's ID if the account is new.
    ///
    /// That is, if [`Account::is_new`] returns `true`, the seed will be `Some`.
    pub fn seed(&self) -> Option<Word> {
        self.seed
    }

    /// Returns `true` if the account type is [`AccountType::Public`], `false` otherwise.
    pub fn is_public(&self) -> bool {
        self.id().is_public()
    }

    /// Returns `true` if the account type is [`AccountType::Private`], `false` otherwise.
    pub fn is_private(&self) -> bool {
        self.id().is_private()
    }

    /// Returns `true` if the account is new, `false` otherwise.
    ///
    /// An account is considered new if the account's nonce is zero and it hasn't been registered on
    /// chain yet.
    pub fn is_new(&self) -> bool {
        self.nonce == ZERO
    }

    /// Decomposes the account into the underlying account components.
    pub fn into_parts(
        self,
    ) -> (AccountId, AssetVault, AccountStorage, AccountCode, Felt, Option<Word>) {
        (self.id, self.vault, self.storage, self.code, self.nonce, self.seed)
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Applies the provided patch to this account. This sets account vault, storage, and nonce to
    /// the values specified by the patch.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The patch's account ID does not match this account's ID.
    /// - The patch carries account code, i.e. represents a newly created account. Such patches can
    ///   be converted to accounts directly and cannot be applied to an existing account.
    /// - Applying the vault sub-patch to the vault of this account fails.
    /// - Applying the storage sub-patch to the storage of this account fails.
    /// - The nonce specified in the provided patch is not strictly greater than the current account
    ///   nonce.
    pub fn apply_patch(&mut self, patch: &AccountPatch) -> Result<(), AccountError> {
        if patch.id() != self.id {
            return Err(AccountError::PatchAccountIdMismatch {
                account_id: self.id,
                patch_id: patch.id(),
            });
        }

        if patch.is_full_state() {
            return Err(AccountError::ApplyFullStatePatchToAccount);
        }

        self.vault
            .apply_patch(patch.vault())
            .map_err(AccountError::AssetVaultUpdateError)?;

        self.storage.apply_patch(patch.storage())?;

        if let Some(new_nonce) = patch.final_nonce() {
            self.set_nonce(new_nonce)?;
        }

        Ok(())
    }

    /// Increments the nonce of this account by the provided increment.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Incrementing the nonce overflows a [`Felt`].
    pub fn increment_nonce(&mut self, nonce_delta: Felt) -> Result<(), AccountError> {
        let new_nonce = self.nonce + nonce_delta;

        self.set_nonce(new_nonce)
    }

    /// Sets the nonce of this account to the provided value.
    ///
    /// # Errors
    ///
    /// Returns an error if `new_nonce` is not equal to or greater than the current account nonce.
    pub fn set_nonce(&mut self, new_nonce: Felt) -> Result<(), AccountError> {
        if new_nonce.as_canonical_u64() < self.nonce.as_canonical_u64() {
            return Err(AccountError::NonceMustIncrease { current: self.nonce, new: new_nonce });
        }

        self.nonce = new_nonce;

        // Maintain internal consistency of the account, i.e. the seed should not be present for
        // existing accounts, where existing accounts are defined as having a nonce > 0.
        // If we've incremented the nonce, then we should remove the seed (if it was present at
        // all).
        if !self.is_new() {
            self.seed = None;
        }

        Ok(())
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    #[cfg(any(feature = "testing", test))]
    /// Returns a mutable reference to the vault of this account.
    pub fn vault_mut(&mut self) -> &mut AssetVault {
        &mut self.vault
    }

    #[cfg(any(feature = "testing", test))]
    /// Returns a mutable reference to the storage of this account.
    pub fn storage_mut(&mut self) -> &mut AccountStorage {
        &mut self.storage
    }
}

impl TryFrom<Account> for AccountDelta {
    type Error = AccountError;

    /// Converts an [`Account`] into an [`AccountDelta`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the account has a seed. Accounts with seeds have a nonce of 0. Representing such accounts
    ///   as deltas is not possible because deltas with a non-empty state change need a nonce_delta
    ///   greater than 0.
    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let Account { id, vault, storage, code, nonce, seed } = account;

        if seed.is_some() {
            return Err(AccountError::DeltaFromAccountWithSeed);
        }

        let slot_deltas = storage
            .into_slots()
            .into_iter()
            .map(StorageSlot::into_parts)
            .map(|(slot_name, slot_content)| (slot_name, StorageSlotPatch::from(slot_content)))
            .collect();
        let storage_patch = AccountStoragePatch::from_raw(slot_deltas);

        let mut fungible_delta = FungibleAssetDelta::default();
        let mut non_fungible_delta = NonFungibleAssetDelta::default();
        for asset in vault.assets() {
            // SAFETY: All assets in the account vault should be representable in the delta.
            match asset {
                Asset::Fungible(fungible_asset) => {
                    fungible_delta
                        .add(fungible_asset)
                        .expect("delta should allow representing valid fungible assets");
                },
                Asset::NonFungible(non_fungible_asset) => {
                    non_fungible_delta
                        .add(non_fungible_asset)
                        .expect("delta should allow representing valid non-fungible assets");
                },
            }
        }
        let vault_delta = AccountVaultDelta::new(fungible_delta, non_fungible_delta);

        // The nonce of the account is the nonce delta since adding the nonce_delta to 0 would
        // result in the nonce.
        let nonce_delta = nonce;

        // SAFETY: As checked earlier, the nonce delta should be greater than 0 allowing for
        // non-empty state changes.
        let delta = AccountDelta::new(id, storage_patch, vault_delta, nonce_delta)
            .expect("nonce_delta should be greater than 0")
            .with_code(Some(code));

        Ok(delta)
    }
}

impl TryFrom<Account> for AccountPatch {
    type Error = AccountError;

    /// Converts an [`Account`] into an [`AccountPatch`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the account has a seed. Accounts with seeds have a nonce of 0. Representing such accounts
    ///   as patches is not possible because patches with a non-empty state change need a
    ///   `final_nonce` greater than 0.
    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let Account { id, vault, storage, code, nonce, seed } = account;

        if seed.is_some() {
            return Err(AccountError::PatchFromAccountWithSeed);
        }

        let slot_patches = storage
            .into_slots()
            .into_iter()
            .map(StorageSlot::into_parts)
            .map(|(slot_name, slot_content)| (slot_name, StorageSlotPatch::from(slot_content)))
            .collect();
        let storage_patch = AccountStoragePatch::from_raw(slot_patches);

        let mut vault_patch = AccountVaultPatch::default();
        for asset in vault.assets() {
            vault_patch.insert_asset(asset);
        }

        // The account's nonce is the final (absolute) nonce of the patch. Since the seed was
        // checked above, the nonce is guaranteed to be greater than zero, so the patch can
        // represent non-empty state changes and the `final_nonce == 1` invariant is satisfied
        // by passing the account code.
        let patch = AccountPatch::new(id, storage_patch, vault_patch, Some(code), Some(nonce))
            .expect("non-seeded account should yield a valid patch");

        Ok(patch)
    }
}

impl SequentialCommit for Account {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        AccountHeader::from(self).to_elements()
    }

    fn to_commitment(&self) -> Self::Commitment {
        AccountHeader::from(self).to_commitment()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Account {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Account { id, vault, storage, code, nonce, seed } = self;

        id.write_into(target);
        vault.write_into(target);
        storage.write_into(target);
        code.write_into(target);
        nonce.write_into(target);
        seed.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.id.get_size_hint()
            + self.vault.get_size_hint()
            + self.storage.get_size_hint()
            + self.code.get_size_hint()
            + self.nonce.get_size_hint()
            + self.seed.get_size_hint()
    }
}

impl Deserializable for Account {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let id = AccountId::read_from(source)?;
        let vault = AssetVault::read_from(source)?;
        let storage = AccountStorage::read_from(source)?;
        let code = AccountCode::read_from(source)?;
        let nonce = Felt::read_from(source)?;
        let seed = <Option<Word>>::read_from(source)?;

        Self::new(id, vault, storage, code, nonce, seed)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Validates that the provided seed is valid for the provided account components.
pub(super) fn validate_account_seed(
    id: AccountId,
    code_commitment: Word,
    storage_commitment: Word,
    seed: Option<Word>,
    nonce: Felt,
) -> Result<(), AccountError> {
    let account_is_new = nonce == ZERO;

    match (account_is_new, seed) {
        (true, Some(seed)) => {
            let account_id =
                AccountId::new(seed, id.version(), code_commitment, storage_commitment)
                    .map_err(AccountError::SeedConvertsToInvalidAccountId)?;

            if account_id != id {
                return Err(AccountError::AccountIdSeedMismatch {
                    expected: id,
                    actual: account_id,
                });
            }

            Ok(())
        },
        (true, None) => Err(AccountError::NewAccountMissingSeed),
        (false, Some(_)) => Err(AccountError::ExistingAccountWithSeed),
        (false, None) => Ok(()),
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use miden_crypto::utils::{Deserializable, Serializable};
    use miden_crypto::{Felt, Word};

    use super::{AccountCode, AccountDelta, AccountId, AccountStorage, AccountStoragePatch};
    use crate::account::{
        Account,
        AccountBuilder,
        AccountIdVersion,
        AccountPatch,
        AccountType,
        AccountVaultDelta,
        AccountVaultPatch,
        PartialAccount,
        StorageMap,
        StorageMapKey,
        StorageMapPatch,
        StorageSlot,
        StorageSlotContent,
        StorageSlotName,
    };
    use crate::asset::{Asset, AssetVault, FungibleAsset, NonFungibleAsset};
    use crate::errors::AccountError;
    use crate::testing::account_id::{
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
    };
    use crate::testing::add_component::AddComponent;
    use crate::testing::noop_auth_component::NoopAuthComponent;

    #[test]
    fn test_serde_account() {
        let init_nonce = Felt::from(1_u32);
        let asset_0 = FungibleAsset::mock(99);
        let word = Word::from([1, 2, 3, 4u32]);
        let storage_slot = StorageSlotContent::Value(word);
        let account = build_account(vec![asset_0], init_nonce, vec![storage_slot]);

        let serialized = account.to_bytes();
        let deserialized = Account::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, account);
    }

    #[test]
    fn test_serde_account_delta() {
        let nonce_delta = Felt::from(2_u32);
        let asset_0 = FungibleAsset::mock(15);
        let asset_1 = NonFungibleAsset::mock(&[5, 5, 5]);
        let storage_patch = AccountStoragePatch::new()
            .add_cleared_items([StorageSlotName::mock(0)])
            .add_updated_values([(StorageSlotName::mock(1), Word::from([1, 2, 3, 4u32]))]);
        let account_delta =
            build_account_delta(vec![asset_1], vec![asset_0], nonce_delta, storage_patch);

        let serialized = account_delta.to_bytes();
        let deserialized = AccountDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, account_delta);
    }

    #[test]
    fn account_patch_is_correctly_applied() -> anyhow::Result<()> {
        let init_nonce = Felt::from(1_u32);
        let asset_0 = FungibleAsset::mock(100);
        let asset_1 = NonFungibleAsset::mock(&[1, 2, 3]);

        // build storage slots
        let storage_slot_value_0 = StorageSlotContent::Value(Word::from([1, 2, 3, 4u32]));
        let storage_slot_value_1 = StorageSlotContent::Value(Word::from([5, 6, 7, 8u32]));
        let map_key_0 = StorageMapKey::from_array([101, 102, 103, 104]);
        let map_key_1 = StorageMapKey::from_array([105, 106, 107, 108]);

        let mut storage_map = StorageMap::with_entries([
            (map_key_0, Word::from([1, 2, 3, 4_u32])),
            (map_key_1, Word::from([5, 6, 7, 8_u32])),
        ])
        .unwrap();
        let storage_slot_map = StorageSlotContent::Map(storage_map.clone());

        // build account
        let initial_account = build_account(
            vec![asset_0],
            init_nonce,
            vec![storage_slot_value_0, storage_slot_value_1, storage_slot_map],
        );

        let value = Word::from([9, 10, 11, 12u32]);
        let updated_map = StorageMapPatch::from_iters([], [(map_key_0, value)]);
        storage_map.insert(map_key_0, value).unwrap();

        // build account patch
        let final_nonce = init_nonce + Felt::ONE;
        let storage_patch = AccountStoragePatch::new()
            .add_cleared_items([StorageSlotName::mock(0)])
            .add_updated_values([(StorageSlotName::mock(1), Word::from([1, 2, 3, 4u32]))])
            .add_updated_maps([(StorageSlotName::mock(2), updated_map)]);
        let account_patch =
            build_account_patch(final_nonce, vec![asset_1], vec![asset_0], storage_patch);

        // apply patch and create final_account
        let mut account_with_patched = initial_account;

        account_with_patched.apply_patch(&account_patch)?;

        let final_account = build_account(
            vec![asset_1],
            final_nonce,
            vec![
                StorageSlotContent::Value(Word::empty()),
                StorageSlotContent::Value(Word::from([1, 2, 3, 4u32])),
                StorageSlotContent::Map(storage_map),
            ],
        );

        assert_eq!(account_with_patched, final_account);

        Ok(())
    }

    #[test]
    fn apply_patch_rejects_new_account_patch() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?;
        let init_nonce = Felt::from(1_u32);
        let mut account = build_account(vec![], init_nonce, vec![]);

        let patch = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            Some(AccountCode::mock()),
            Some(Felt::from(2_u32)),
        )?;

        let err = account.apply_patch(&patch).unwrap_err();
        assert_matches!(err, AccountError::ApplyFullStatePatchToAccount);

        Ok(())
    }

    #[test]
    fn apply_patch_rejects_non_increasing_nonce() -> anyhow::Result<()> {
        let account_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?;
        let init_nonce = 5_u32;
        let mut account = build_account(vec![], Felt::from(init_nonce), vec![]);

        // Smaller nonce.
        let patch_smaller = AccountPatch::new(
            account_id,
            AccountStoragePatch::new(),
            AccountVaultPatch::default(),
            None,
            Some(Felt::from(init_nonce - 1)),
        )?;
        let err = account.apply_patch(&patch_smaller).unwrap_err();
        assert_matches!(err, AccountError::NonceMustIncrease { .. });

        Ok(())
    }

    #[test]
    fn apply_patch_rejects_id_mismatch() -> anyhow::Result<()> {
        let other_account_id =
            AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2)?;
        let init_nonce = Felt::from(1_u32);
        let mut account = build_account(vec![], init_nonce, vec![]);

        let patch = AccountPatch::new(
            other_account_id,
            AccountStoragePatch::default(),
            AccountVaultPatch::default(),
            None,
            Some(Felt::from(2_u32)),
        )?;

        let err = account.apply_patch(&patch).unwrap_err();
        assert_matches!(err, AccountError::PatchAccountIdMismatch { .. });

        Ok(())
    }

    #[test]
    fn apply_empty_account_patch() -> anyhow::Result<()> {
        let nonce = Felt::from(2u8);
        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let empty_patch = AccountPatch::new(
            id,
            AccountStoragePatch::default(),
            AccountVaultPatch::default(),
            None,
            None,
        )?;
        let init_account = build_account(vec![], nonce, vec![]);

        let mut account_with_patch = init_account.clone();
        account_with_patch.apply_patch(&empty_patch)?;

        assert_eq!(init_account, account_with_patch, "account should be unchanged");

        Ok(())
    }

    #[test]
    fn apply_empty_account_patch_with_incremented_nonce() -> anyhow::Result<()> {
        let initial_nonce = Felt::from(2u8);
        let final_nonce = initial_nonce + Felt::ONE;

        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let empty_patch = AccountPatch::new(
            id,
            AccountStoragePatch::default(),
            AccountVaultPatch::default(),
            None,
            Some(final_nonce),
        )?;

        let init_account = build_account(vec![], initial_nonce, vec![]);
        let final_account = build_account(vec![], final_nonce, vec![]);

        let mut account_with_patch = init_account.clone();
        account_with_patch.apply_patch(&empty_patch)?;

        assert_eq!(final_account, account_with_patch);

        Ok(())
    }

    pub fn build_account_delta(
        added_assets: Vec<Asset>,
        removed_assets: Vec<Asset>,
        nonce_delta: Felt,
        storage_patch: AccountStoragePatch,
    ) -> AccountDelta {
        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let vault_delta = AccountVaultDelta::from_iters(added_assets, removed_assets);
        AccountDelta::new(id, storage_patch, vault_delta, nonce_delta).unwrap()
    }

    pub fn build_account_patch(
        final_nonce: Felt,
        added_assets: Vec<Asset>,
        removed_assets: Vec<Asset>,
        storage_patch: AccountStoragePatch,
    ) -> AccountPatch {
        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let vault_patch = AccountVaultPatch::from_iters(added_assets, removed_assets);
        AccountPatch::new(id, storage_patch, vault_patch, None, Some(final_nonce)).unwrap()
    }

    pub fn build_account(
        assets: Vec<Asset>,
        nonce: Felt,
        slots: Vec<StorageSlotContent>,
    ) -> Account {
        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let code = AccountCode::mock();

        let vault = AssetVault::new(&assets).unwrap();

        let slots = slots
            .into_iter()
            .enumerate()
            .map(|(idx, slot)| StorageSlot::new(StorageSlotName::mock(idx), slot))
            .collect();

        let storage = AccountStorage::new(slots).unwrap();

        Account::new_existing(id, vault, storage, code, nonce)
    }

    /// Tests all cases of account ID seed validation.
    #[test]
    fn seed_validation() -> anyhow::Result<()> {
        let account = AccountBuilder::new([5; 32])
            .with_auth_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build()?;
        let (id, vault, storage, code, _nonce, seed) = account.into_parts();
        assert!(seed.is_some());

        let other_seed = AccountId::compute_account_seed(
            [9; 32],
            AccountType::Public,
            AccountIdVersion::Version1,
            code.commitment(),
            storage.to_commitment(),
        )?;

        // Set nonce to 1 so the account is considered existing and provide the seed.
        let err = Account::new(id, vault.clone(), storage.clone(), code.clone(), Felt::ONE, seed)
            .unwrap_err();
        assert_matches!(err, AccountError::ExistingAccountWithSeed);

        // Set nonce to 0 so the account is considered new but don't provide the seed.
        let err = Account::new(id, vault.clone(), storage.clone(), code.clone(), Felt::ZERO, None)
            .unwrap_err();
        assert_matches!(err, AccountError::NewAccountMissingSeed);

        // Set nonce to 0 so the account is considered new and provide a valid seed that results in
        // a different ID than the provided one.
        let err = Account::new(
            id,
            vault.clone(),
            storage.clone(),
            code.clone(),
            Felt::ZERO,
            Some(other_seed),
        )
        .unwrap_err();
        assert_matches!(err, AccountError::AccountIdSeedMismatch { .. });

        // Set nonce to 0 so the account is considered new and provide a seed that results in an
        // invalid ID.
        let err = Account::new(
            id,
            vault.clone(),
            storage.clone(),
            code.clone(),
            Felt::ZERO,
            Some(Word::from([1, 2, 3, 4u32])),
        )
        .unwrap_err();
        assert_matches!(err, AccountError::SeedConvertsToInvalidAccountId(_));

        // Set nonce to 1 so the account is considered existing and don't provide the seed, which
        // should be valid.
        Account::new(id, vault.clone(), storage.clone(), code.clone(), Felt::ONE, None)?;

        // Set nonce to 0 so the account is considered new and provide the original seed, which
        // should be valid.
        Account::new(id, vault.clone(), storage.clone(), code.clone(), Felt::ZERO, seed)?;

        Ok(())
    }

    #[test]
    fn incrementing_nonce_should_remove_seed() -> anyhow::Result<()> {
        let mut account = AccountBuilder::new([5; 32])
            .with_auth_component(NoopAuthComponent)
            .with_component(AddComponent)
            .build()?;
        account.increment_nonce(Felt::ONE)?;

        assert_matches!(account.seed(), None);

        // Sanity check: We should be able to convert the account into a partial account which will
        // re-check the internal seed - nonce consistency.
        let _partial_account = PartialAccount::from(&account);

        Ok(())
    }
}
