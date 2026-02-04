use alloc::string::ToString;
use alloc::vec::Vec;

use crate::asset::{Asset, AssetVault};
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
    AccountIdPrefixV0,
    AccountIdV0,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
};

pub mod auth;

mod builder;
pub use builder::AccountBuilder;

pub mod code;
pub use code::AccountCode;
pub use code::procedure::AccountProcedureRoot;

pub mod component;
pub use component::{AccountComponent, AccountComponentCode, AccountComponentMetadata};

pub mod delta;
pub use delta::{
    AccountDelta,
    AccountStorageDelta,
    AccountVaultDelta,
    FungibleAssetDelta,
    NonFungibleAssetDelta,
    NonFungibleDeltaAction,
    StorageMapDelta,
    StorageSlotDelta,
};

pub mod storage;
pub use storage::{
    AccountStorage,
    AccountStorageHeader,
    PartialStorage,
    PartialStorageMap,
    StorageMap,
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
    /// - Any of the components does not support `account_type`.
    /// - The number of procedures in all merged libraries is 0 or exceeds
    ///   [`AccountCode::MAX_NUM_PROCEDURES`].
    /// - Two or more libraries export a procedure with the same MAST root.
    /// - The first component doesn't contain exactly one authentication procedure.
    /// - Other components contain authentication procedures.
    /// - The number of [`StorageSlot`]s of all components exceeds 255.
    /// - [`MastForest::merge`](miden_processor::MastForest::merge) fails on all libraries.
    pub(super) fn initialize_from_components(
        account_type: AccountType,
        components: Vec<AccountComponent>,
    ) -> Result<(AccountCode, AccountStorage), AccountError> {
        validate_components_support_account_type(&components, account_type)?;

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
    /// The commitment of an account is computed as hash(id, nonce, vault_root, storage_commitment,
    /// code_commitment). Computing the account commitment requires 2 permutations of the hash
    /// function.
    pub fn commitment(&self) -> Word {
        hash_account(
            self.id,
            self.nonce,
            self.vault.root(),
            self.storage.to_commitment(),
            self.code.commitment(),
        )
    }

    /// Returns the commitment of this account as used for the initial account state commitment in
    /// transaction proofs.
    ///
    /// For existing accounts, this is exactly the same as [Account::commitment()], however, for new
    /// accounts this value is set to [crate::EMPTY_WORD]. This is because when a transaction is
    /// executed against a new account, public input for the initial account state is set to
    /// [crate::EMPTY_WORD] to distinguish new accounts from existing accounts. The actual
    /// commitment of the initial account state (and the initial state itself), are provided to
    /// the VM via the advice provider.
    pub fn initial_commitment(&self) -> Word {
        if self.is_new() {
            Word::empty()
        } else {
            self.commitment()
        }
    }

    /// Returns unique identifier of this account.
    pub fn id(&self) -> AccountId {
        self.id
    }

    /// Returns the account type
    pub fn account_type(&self) -> AccountType {
        self.id.account_type()
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

    /// Returns true if this account can issue assets.
    pub fn is_faucet(&self) -> bool {
        self.id.is_faucet()
    }

    /// Returns true if this is a regular account.
    pub fn is_regular_account(&self) -> bool {
        self.id.is_regular_account()
    }

    /// Returns `true` if the full state of the account is public on chain, i.e. if the modes are
    /// [`AccountStorageMode::Public`] or [`AccountStorageMode::Network`], `false` otherwise.
    pub fn has_public_state(&self) -> bool {
        self.id().has_public_state()
    }

    /// Returns `true` if the storage mode is [`AccountStorageMode::Public`], `false` otherwise.
    pub fn is_public(&self) -> bool {
        self.id().is_public()
    }

    /// Returns `true` if the storage mode is [`AccountStorageMode::Private`], `false` otherwise.
    pub fn is_private(&self) -> bool {
        self.id().is_private()
    }

    /// Returns `true` if the storage mode is [`AccountStorageMode::Network`], `false` otherwise.
    pub fn is_network(&self) -> bool {
        self.id().is_network()
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

    /// Applies the provided delta to this account. This updates account vault, storage, and nonce
    /// to the values specified by the delta.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`AccountDelta::is_full_state`] returns `true`, i.e. represents the state of an entire
    ///   account. Only partial state deltas can be applied to an account.
    /// - Applying vault sub-delta to the vault of this account fails.
    /// - Applying storage sub-delta to the storage of this account fails.
    /// - The nonce specified in the provided delta smaller than or equal to the current account
    ///   nonce.
    pub fn apply_delta(&mut self, delta: &AccountDelta) -> Result<(), AccountError> {
        if delta.is_full_state() {
            return Err(AccountError::ApplyFullStateDeltaToAccount);
        }

        // update vault; we don't check vault delta validity here because `AccountDelta` can contain
        // only valid vault deltas
        self.vault
            .apply_delta(delta.vault())
            .map_err(AccountError::AssetVaultUpdateError)?;

        // update storage
        self.storage.apply_delta(delta.storage())?;

        // update nonce
        self.increment_nonce(delta.nonce_delta())?;

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

        if new_nonce.as_int() < self.nonce.as_int() {
            return Err(AccountError::NonceOverflow {
                current: self.nonce,
                increment: nonce_delta,
                new: new_nonce,
            });
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
            .map(|(slot_name, slot_content)| (slot_name, StorageSlotDelta::from(slot_content)))
            .collect();
        let storage_delta = AccountStorageDelta::from_raw(slot_deltas);

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
        let delta = AccountDelta::new(id, storage_delta, vault_delta, nonce_delta)
            .expect("nonce_delta should be greater than 0")
            .with_code(Some(code));

        Ok(delta)
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

// HELPERS
// ================================================================================================

/// Returns hash of an account with the specified ID, nonce, vault root, storage commitment, and
/// code commitment.
///
/// Hash of an account is computed as hash(id, nonce, vault_root, storage_commitment,
/// code_commitment). Computing the account commitment requires 2 permutations of the hash function.
pub fn hash_account(
    id: AccountId,
    nonce: Felt,
    vault_root: Word,
    storage_commitment: Word,
    code_commitment: Word,
) -> Word {
    let mut elements = [ZERO; 16];
    elements[0] = id.suffix();
    elements[1] = id.prefix().as_felt();
    elements[3] = nonce;
    elements[4..8].copy_from_slice(&*vault_root);
    elements[8..12].copy_from_slice(&*storage_commitment);
    elements[12..].copy_from_slice(&*code_commitment);
    Hasher::hash_elements(&elements)
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

/// Validates that all `components` support the given `account_type`.
fn validate_components_support_account_type(
    components: &[AccountComponent],
    account_type: AccountType,
) -> Result<(), AccountError> {
    for (component_index, component) in components.iter().enumerate() {
        if !component.supports_type(account_type) {
            return Err(AccountError::UnsupportedComponentForAccountType {
                account_type,
                component_index,
            });
        }
    }

    Ok(())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use miden_assembly::Assembler;
    use miden_core::FieldElement;
    use miden_crypto::utils::{Deserializable, Serializable};
    use miden_crypto::{Felt, Word};

    use super::{
        AccountCode,
        AccountDelta,
        AccountId,
        AccountStorage,
        AccountStorageDelta,
        AccountVaultDelta,
    };
    use crate::account::AccountStorageMode::Network;
    use crate::account::{
        Account,
        AccountBuilder,
        AccountComponent,
        AccountIdVersion,
        AccountType,
        PartialAccount,
        StorageMap,
        StorageMapDelta,
        StorageSlot,
        StorageSlotContent,
        StorageSlotName,
    };
    use crate::asset::{Asset, AssetVault, FungibleAsset, NonFungibleAsset};
    use crate::errors::AccountError;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };
    use crate::testing::add_component::AddComponent;
    use crate::testing::noop_auth_component::NoopAuthComponent;

    #[test]
    fn test_serde_account() {
        let init_nonce = Felt::new(1);
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
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let nonce_delta = Felt::new(2);
        let asset_0 = FungibleAsset::mock(15);
        let asset_1 = NonFungibleAsset::mock(&[5, 5, 5]);
        let storage_delta = AccountStorageDelta::new()
            .add_cleared_items([StorageSlotName::mock(0)])
            .add_updated_values([(StorageSlotName::mock(1), Word::from([1, 2, 3, 4u32]))]);
        let account_delta = build_account_delta(
            account_id,
            vec![asset_1],
            vec![asset_0],
            nonce_delta,
            storage_delta,
        );

        let serialized = account_delta.to_bytes();
        let deserialized = AccountDelta::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, account_delta);
    }

    #[test]
    fn valid_account_delta_is_correctly_applied() {
        // build account
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let init_nonce = Felt::new(1);
        let asset_0 = FungibleAsset::mock(100);
        let asset_1 = NonFungibleAsset::mock(&[1, 2, 3]);

        // build storage slots
        let storage_slot_value_0 = StorageSlotContent::Value(Word::from([1, 2, 3, 4u32]));
        let storage_slot_value_1 = StorageSlotContent::Value(Word::from([5, 6, 7, 8u32]));
        let mut storage_map = StorageMap::with_entries([
            (
                Word::new([Felt::new(101), Felt::new(102), Felt::new(103), Felt::new(104)]),
                Word::from([
                    Felt::new(1_u64),
                    Felt::new(2_u64),
                    Felt::new(3_u64),
                    Felt::new(4_u64),
                ]),
            ),
            (
                Word::new([Felt::new(105), Felt::new(106), Felt::new(107), Felt::new(108)]),
                Word::new([Felt::new(5_u64), Felt::new(6_u64), Felt::new(7_u64), Felt::new(8_u64)]),
            ),
        ])
        .unwrap();
        let storage_slot_map = StorageSlotContent::Map(storage_map.clone());

        let mut account = build_account(
            vec![asset_0],
            init_nonce,
            vec![storage_slot_value_0, storage_slot_value_1, storage_slot_map],
        );

        // update storage map
        let new_map_entry = (
            Word::new([Felt::new(101), Felt::new(102), Felt::new(103), Felt::new(104)]),
            [Felt::new(9_u64), Felt::new(10_u64), Felt::new(11_u64), Felt::new(12_u64)],
        );

        let updated_map =
            StorageMapDelta::from_iters([], [(new_map_entry.0, new_map_entry.1.into())]);
        storage_map.insert(new_map_entry.0, new_map_entry.1.into()).unwrap();

        // build account delta
        let final_nonce = Felt::new(2);
        let storage_delta = AccountStorageDelta::new()
            .add_cleared_items([StorageSlotName::mock(0)])
            .add_updated_values([(StorageSlotName::mock(1), Word::from([1, 2, 3, 4u32]))])
            .add_updated_maps([(StorageSlotName::mock(2), updated_map)]);
        let account_delta = build_account_delta(
            account_id,
            vec![asset_1],
            vec![asset_0],
            final_nonce - init_nonce,
            storage_delta,
        );

        // apply delta and create final_account
        account.apply_delta(&account_delta).unwrap();

        let final_account = build_account(
            vec![asset_1],
            final_nonce,
            vec![
                StorageSlotContent::Value(Word::empty()),
                StorageSlotContent::Value(Word::from([1, 2, 3, 4u32])),
                StorageSlotContent::Map(storage_map),
            ],
        );

        // assert account is what it should be
        assert_eq!(account, final_account);
    }

    #[test]
    #[should_panic]
    fn valid_account_delta_with_unchanged_nonce() {
        // build account
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let init_nonce = Felt::new(1);
        let asset = FungibleAsset::mock(110);
        let mut account =
            build_account(vec![asset], init_nonce, vec![StorageSlotContent::Value(Word::empty())]);

        // build account delta
        let storage_delta = AccountStorageDelta::new()
            .add_cleared_items([StorageSlotName::mock(0)])
            .add_updated_values([(StorageSlotName::mock(1), Word::from([1, 2, 3, 4u32]))]);
        let account_delta =
            build_account_delta(account_id, vec![], vec![asset], init_nonce, storage_delta);

        // apply delta
        account.apply_delta(&account_delta).unwrap()
    }

    #[test]
    #[should_panic]
    fn valid_account_delta_with_decremented_nonce() {
        // build account
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let init_nonce = Felt::new(2);
        let asset = FungibleAsset::mock(100);
        let mut account =
            build_account(vec![asset], init_nonce, vec![StorageSlotContent::Value(Word::empty())]);

        // build account delta
        let final_nonce = Felt::new(1);
        let storage_delta = AccountStorageDelta::new()
            .add_cleared_items([StorageSlotName::mock(0)])
            .add_updated_values([(StorageSlotName::mock(1), Word::from([1, 2, 3, 4u32]))]);
        let account_delta =
            build_account_delta(account_id, vec![], vec![asset], final_nonce, storage_delta);

        // apply delta
        account.apply_delta(&account_delta).unwrap()
    }

    #[test]
    fn empty_account_delta_with_incremented_nonce() {
        // build account
        let account_id = AccountId::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let init_nonce = Felt::new(1);
        let word = Word::from([1, 2, 3, 4u32]);
        let storage_slot = StorageSlotContent::Value(word);
        let mut account = build_account(vec![], init_nonce, vec![storage_slot]);

        // build account delta
        let nonce_delta = Felt::new(1);
        let account_delta = AccountDelta::new(
            account_id,
            AccountStorageDelta::new(),
            AccountVaultDelta::default(),
            nonce_delta,
        )
        .unwrap();

        // apply delta
        account.apply_delta(&account_delta).unwrap()
    }

    pub fn build_account_delta(
        account_id: AccountId,
        added_assets: Vec<Asset>,
        removed_assets: Vec<Asset>,
        nonce_delta: Felt,
        storage_delta: AccountStorageDelta,
    ) -> AccountDelta {
        let vault_delta = AccountVaultDelta::from_iters(added_assets, removed_assets);
        AccountDelta::new(account_id, storage_delta, vault_delta, nonce_delta).unwrap()
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

    /// Tests that initializing code and storage from a component which does not support the given
    /// account type returns an error.
    #[test]
    fn test_account_unsupported_component_type() {
        let code1 = "pub proc foo add end";
        let library1 = Assembler::default().assemble_library([code1]).unwrap();

        // This component support all account types except the regular account with updatable code.
        let component1 = AccountComponent::new(library1, vec![])
            .unwrap()
            .with_supported_type(AccountType::FungibleFaucet)
            .with_supported_type(AccountType::NonFungibleFaucet)
            .with_supported_type(AccountType::RegularAccountImmutableCode);

        let err = Account::initialize_from_components(
            AccountType::RegularAccountUpdatableCode,
            vec![component1],
        )
        .unwrap_err();

        assert!(matches!(
            err,
            AccountError::UnsupportedComponentForAccountType {
                account_type: AccountType::RegularAccountUpdatableCode,
                component_index: 0
            }
        ))
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
            AccountType::FungibleFaucet,
            Network,
            AccountIdVersion::Version0,
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
