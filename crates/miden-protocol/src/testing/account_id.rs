use rand_xoshiro::rand_core::SeedableRng;

use crate::account::{AccountId, AccountIdV0, AccountIdVersion, AccountStorageMode, AccountType};

// CONSTANTS
// --------------------------------------------------------------------------------------------

// REGULAR ACCOUNTS - PRIVATE
pub const ACCOUNT_ID_SENDER: u128 = account_id(
    AccountType::RegularAccountImmutableCode,
    AccountStorageMode::Private,
    0xfabb_ccde,
);
pub const ACCOUNT_ID_PRIVATE_SENDER: u128 = account_id(
    AccountType::RegularAccountImmutableCode,
    AccountStorageMode::Private,
    0xbfcc_dcee,
);
pub const ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE: u128 = account_id(
    AccountType::RegularAccountUpdatableCode,
    AccountStorageMode::Private,
    0xccdd_eeff,
);
// REGULAR ACCOUNTS - PUBLIC
pub const ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE: u128 = account_id(
    AccountType::RegularAccountImmutableCode,
    AccountStorageMode::Public,
    0xaabb_ccdd,
);
pub const ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2: u128 = account_id(
    AccountType::RegularAccountImmutableCode,
    AccountStorageMode::Public,
    0xbbcc_ddee,
);
pub const ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE: u128 = account_id(
    AccountType::RegularAccountUpdatableCode,
    AccountStorageMode::Public,
    0xacdd_eefc,
);
pub const ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE_ON_CHAIN_2: u128 = account_id(
    AccountType::RegularAccountUpdatableCode,
    AccountStorageMode::Public,
    0xeeff_ccdd,
);
// REGULAR ACCOUNTS - NETWORK
pub const ACCOUNT_ID_REGULAR_NETWORK_ACCOUNT_IMMUTABLE_CODE: u128 = account_id(
    AccountType::RegularAccountImmutableCode,
    AccountStorageMode::Network,
    0xaacc_bbdd,
);

// These faucet IDs all have a unique prefix and suffix felts. This is to ensure that when they
// are used to issue an asset they don't cause us to run into the "multiple leaf" case when
// calling std::collections::smt::{set,get} which doesn't support the "multiple leaf" case at
// this time.

// FUNGIBLE TOKENS - PRIVATE
pub const ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET: u128 =
    account_id(AccountType::FungibleFaucet, AccountStorageMode::Private, 0xfabb_cddd);
// FUNGIBLE TOKENS - PUBLIC
/// A native asset faucet ID for use in testing scenarios.
pub const ACCOUNT_ID_NATIVE_ASSET_FAUCET: u128 =
    account_id(AccountType::FungibleFaucet, AccountStorageMode::Public, 0xabcd_acde);
pub const ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET: u128 =
    account_id(AccountType::FungibleFaucet, AccountStorageMode::Public, 0xaabc_bcde);
pub const ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1: u128 =
    account_id(AccountType::FungibleFaucet, AccountStorageMode::Public, 0xbaca_ddef);
pub const ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2: u128 =
    account_id(AccountType::FungibleFaucet, AccountStorageMode::Public, 0xccdb_eefa);
pub const ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3: u128 =
    account_id(AccountType::FungibleFaucet, AccountStorageMode::Public, 0xeeff_cc99);
// FUNGIBLE TOKENS - NETWORK
pub const ACCOUNT_ID_NETWORK_FUNGIBLE_FAUCET: u128 =
    account_id(AccountType::FungibleFaucet, AccountStorageMode::Network, 0xaabc_bcdf);

// NON-FUNGIBLE TOKENS - PRIVATE
pub const ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET: u128 =
    account_id(AccountType::NonFungibleFaucet, AccountStorageMode::Private, 0xaabc_ccde);
// NON-FUNGIBLE TOKENS - PUBLIC
pub const ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET: u128 =
    account_id(AccountType::NonFungibleFaucet, AccountStorageMode::Public, 0xbcca_ddef);
pub const ACCOUNT_ID_PUBLIC_NON_FUNGIBLE_FAUCET_1: u128 =
    account_id(AccountType::NonFungibleFaucet, AccountStorageMode::Public, 0xccdf_eefa);
// NON-FUNGIBLE TOKENS - NETWORK
pub const ACCOUNT_ID_NETWORK_NON_FUNGIBLE_FAUCET: u128 =
    account_id(AccountType::NonFungibleFaucet, AccountStorageMode::Network, 0xabbc_ffde);

// TEST ACCOUNT IDs WITH CERTAIN PROPERTIES
/// The Account Id with the maximum possible one bits.
pub const ACCOUNT_ID_MAX_ONES: u128 =
    account_id(AccountType::NonFungibleFaucet, AccountStorageMode::Public, 0)
        | 0x7fff_ffff_ffff_ff00_7fff_ffff_ffff_ff00;
/// The Account Id with the maximum possible zero bits.
pub const ACCOUNT_ID_MAX_ZEROES: u128 =
    account_id(AccountType::NonFungibleFaucet, AccountStorageMode::Private, 0x001f_0000);

// UTILITIES
// --------------------------------------------------------------------------------------------

/// Produces a valid account ID with the given account type and storage mode.
///
/// - Version is set to 0.
///
/// Finally, distributes the given `random` value over the ID to produce non-trivial values for
/// testing. This is easiest explained with an example. Suppose `random` is `0xaabb_ccdd`,
/// then the layout of the generated ID will be:
///
/// ```text
/// prefix: [0xaa | 5 zero bytes | 0xbb | metadata byte]
/// suffix: [2 zero bytes | 0xcc | 3 zero bytes | 0xdd | zero byte]
/// ```
pub const fn account_id(
    account_type: AccountType,
    storage_mode: AccountStorageMode,
    random: u32,
) -> u128 {
    let mut prefix: u64 = 0;

    prefix |= (account_type as u64) << AccountIdV0::TYPE_SHIFT;
    prefix |= (storage_mode as u64) << AccountIdV0::STORAGE_MODE_SHIFT;

    // Produce non-trivial IDs by distributing the random value.
    let random_1st_felt_upper = random & 0xff00_0000;
    let random_1st_felt_lower = random & 0x00ff_0000;
    let random_2nd_felt_upper = random & 0x0000_ff00;
    let random_2nd_felt_lower = random & 0x0000_00ff;

    // Shift the random part of the ID to start at the most significant end.
    prefix |= (random_1st_felt_upper as u64) << 32;
    prefix |= (random_1st_felt_lower as u64) >> 8;

    let mut id = (prefix as u128) << 64;

    id |= (random_2nd_felt_upper as u128) << 32;
    id |= (random_2nd_felt_lower as u128) << 8;

    id
}

/// A builder for creating [`AccountId`]s for testing purposes.
///
/// This is essentially a wrapper around [`AccountId::dummy`] generating random values as its input.
/// Refer to its documentation for details.
///
/// # Example
///
/// ```
/// # use miden_protocol::account::{AccountType, AccountStorageMode, AccountId};
/// # use miden_protocol::testing::account_id::{AccountIdBuilder};
///
/// let mut rng = rand::rng();
///
/// // A random AccountId with random AccountType and AccountStorageMode.
/// let random_id1: AccountId = AccountIdBuilder::new().build_with_rng(&mut rng);
///
/// // A random AccountId with the given AccountType and AccountStorageMode.
/// let random_id2: AccountId = AccountIdBuilder::new()
///     .account_type(AccountType::FungibleFaucet)
///     .storage_mode(AccountStorageMode::Private)
///     .build_with_rng(&mut rng);
/// assert_eq!(random_id2.account_type(), AccountType::FungibleFaucet);
/// assert_eq!(random_id2.storage_mode(), AccountStorageMode::Private);
/// ```
pub struct AccountIdBuilder {
    account_type: Option<AccountType>,
    storage_mode: Option<AccountStorageMode>,
}

impl AccountIdBuilder {
    /// Creates a new [`AccountIdBuilder`].
    pub fn new() -> Self {
        Self { account_type: None, storage_mode: None }
    }

    /// Sets the [`AccountType`] of the generated [`AccountId`] to the provided value.
    pub fn account_type(mut self, account_type: AccountType) -> Self {
        self.account_type = Some(account_type);
        self
    }

    /// Sets the [`AccountStorageMode`] of the generated [`AccountId`] to the provided value.
    pub fn storage_mode(mut self, storage_mode: AccountStorageMode) -> Self {
        self.storage_mode = Some(storage_mode);
        self
    }

    /// Builds an [`AccountId`] using the provided [`rand::Rng`].
    ///
    /// If no [`AccountType`] or [`AccountStorageMode`] were previously set, random ones are
    /// generated.
    pub fn build_with_rng<R: rand::Rng + ?Sized>(self, rng: &mut R) -> AccountId {
        let account_type = match self.account_type {
            Some(account_type) => account_type,
            None => rng.random(),
        };

        let storage_mode = match self.storage_mode {
            Some(storage_mode) => storage_mode,
            None => rng.random(),
        };

        AccountId::dummy(rng.random(), AccountIdVersion::Version0, account_type, storage_mode)
    }

    /// Builds an [`AccountId`] using the provided seed as input for an RNG implemented in
    /// [`rand_xoshiro`].
    ///
    /// If no [`AccountType`] or [`AccountStorageMode`] were previously set, random ones are
    /// generated.
    pub fn build_with_seed(self, rng_seed: [u8; 32]) -> AccountId {
        // Match the implementation of rand::rngs::SmallRng and use different RNGs depending on the
        // platform.
        #[cfg(not(target_pointer_width = "64"))]
        let mut rng = {
            let rng_seed: [u8; 16] = rng_seed.as_slice()[0..16]
                .try_into()
                .expect("we should have sliced off 16 elements");
            rand_xoshiro::Xoshiro128PlusPlus::from_seed(rng_seed)
        };

        #[cfg(target_pointer_width = "64")]
        let mut rng = rand_xoshiro::Xoshiro256PlusPlus::from_seed(rng_seed);

        self.build_with_rng(&mut rng)
    }
}

impl Default for AccountIdBuilder {
    fn default() -> Self {
        Self::new()
    }
}
