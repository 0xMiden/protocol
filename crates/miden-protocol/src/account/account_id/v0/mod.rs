mod prefix;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::hash::Hash;

use bech32::Bech32m;
use bech32::primitives::decode::{ByteIter, CheckedHrpstring};
use miden_crypto::utils::hex_to_bytes;
pub use prefix::AccountIdPrefixV0;

use crate::account::account_id::NetworkId;
use crate::account::account_id::account_type::{
    FUNGIBLE_FAUCET,
    NON_FUNGIBLE_FAUCET,
    REGULAR_ACCOUNT_IMMUTABLE_CODE,
    REGULAR_ACCOUNT_UPDATABLE_CODE,
};
use crate::account::account_id::storage_mode::{NETWORK, PRIVATE, PUBLIC};
use crate::account::{AccountIdVersion, AccountStorageMode, AccountType};
use crate::address::AddressType;
use crate::errors::{AccountError, AccountIdError, Bech32Error};
use crate::utils::{ByteReader, Deserializable, DeserializationError, Serializable};
use crate::{EMPTY_WORD, Felt, Hasher, Word};

// ACCOUNT ID VERSION 0
// ================================================================================================

/// Version 0 of the [`Account`](crate::account::Account) identifier.
///
/// See the [`AccountId`](super::AccountId) type's documentation for details.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AccountIdV0 {
    prefix: Felt,
    suffix: Felt,
}

impl Hash for AccountIdV0 {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.prefix.inner().hash(state);
        self.suffix.inner().hash(state);
    }
}

impl AccountIdV0 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The serialized size of an [`AccountIdV0`] in bytes.
    const SERIALIZED_SIZE: usize = 15;

    /// The lower two bits of the second least significant nibble encode the account type.
    pub(crate) const TYPE_MASK: u8 = 0b11 << Self::TYPE_SHIFT;
    pub(crate) const TYPE_SHIFT: u64 = 4;

    /// The least significant nibble determines the account version.
    const VERSION_MASK: u64 = 0b1111;

    /// The higher two bits of the second least significant nibble encode the account storage
    /// mode.
    pub(crate) const STORAGE_MODE_MASK: u8 = 0b11 << Self::STORAGE_MODE_SHIFT;
    pub(crate) const STORAGE_MODE_SHIFT: u64 = 6;

    /// The bit at index 5 of the prefix encodes whether the account is a faucet.
    pub(crate) const IS_FAUCET_MASK: u64 = 0b10 << Self::TYPE_SHIFT;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// See [`AccountId::new`](super::AccountId::new) for details.
    pub fn new(
        seed: Word,
        code_commitment: Word,
        storage_commitment: Word,
    ) -> Result<Self, AccountIdError> {
        let seed_digest = compute_digest(seed, code_commitment, storage_commitment);

        let mut felts: [Felt; 2] = seed_digest.as_elements()[0..2]
            .try_into()
            .expect("we should have sliced off 2 elements");

        felts[1] = shape_suffix(felts[1]);

        account_id_from_felts(felts)
    }

    /// See [`AccountId::new_unchecked`](super::AccountId::new_unchecked) for details.
    pub fn new_unchecked(elements: [Felt; 2]) -> Self {
        let prefix = elements[0];
        let suffix = elements[1];

        // Panic on invalid felts in debug mode.
        if cfg!(debug_assertions) {
            validate_prefix(prefix).expect("AccountId::new_unchecked called with invalid prefix");
            validate_suffix(suffix).expect("AccountId::new_unchecked called with invalid suffix");
        }

        Self { prefix, suffix }
    }

    /// See [`AccountId::dummy`](super::AccountId::dummy) for details.
    #[cfg(any(feature = "testing", test))]
    pub fn dummy(
        mut bytes: [u8; 15],
        account_type: AccountType,
        storage_mode: AccountStorageMode,
    ) -> AccountIdV0 {
        let version = AccountIdVersion::Version0 as u8;
        let low_nibble = ((storage_mode as u8) << Self::STORAGE_MODE_SHIFT)
            | ((account_type as u8) << Self::TYPE_SHIFT)
            | version;

        // Set least significant byte.
        bytes[7] = low_nibble;

        // Clear the 32nd most significant bit.
        bytes[3] &= 0b1111_1110;

        let prefix_bytes =
            bytes[0..8].try_into().expect("we should have sliced off exactly 8 bytes");
        let prefix = Felt::try_from(u64::from_be_bytes(prefix_bytes))
            .expect("should be a valid felt due to the most significant bit being zero");

        let mut suffix_bytes = [0; 8];
        // Overwrite first 7 bytes, leaving the 8th byte 0 (which will be cleared by
        // shape_suffix anyway).
        suffix_bytes[..7].copy_from_slice(&bytes[8..]);

        // If the value is too large modular reduction is performed, which is fine here.
        let mut suffix = Felt::new(u64::from_be_bytes(suffix_bytes));

        // Clear the most significant bit of the suffix.
        suffix = Felt::try_from(suffix.as_int() & 0x7fff_ffff_ffff_ffff)
            .expect("no bits were set so felt should still be valid");

        suffix = shape_suffix(suffix);

        let account_id = account_id_from_felts([prefix, suffix])
            .expect("we should have shaped the felts to produce a valid id");

        debug_assert_eq!(account_id.account_type(), account_type);
        debug_assert_eq!(account_id.storage_mode(), storage_mode);

        account_id
    }

    /// See [`AccountId::compute_account_seed`](super::AccountId::compute_account_seed) for details.
    pub fn compute_account_seed(
        init_seed: [u8; 32],
        account_type: AccountType,
        storage_mode: AccountStorageMode,
        version: AccountIdVersion,
        code_commitment: Word,
        storage_commitment: Word,
    ) -> Result<Word, AccountError> {
        crate::account::account_id::seed::compute_account_seed(
            init_seed,
            account_type,
            storage_mode,
            version,
            code_commitment,
            storage_commitment,
        )
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// See [`AccountId::account_type`](super::AccountId::account_type) for details.
    pub const fn account_type(&self) -> AccountType {
        extract_type(self.prefix.as_int())
    }

    /// See [`AccountId::is_faucet`](super::AccountId::is_faucet) for details.
    pub fn is_faucet(&self) -> bool {
        self.account_type().is_faucet()
    }

    /// See [`AccountId::is_regular_account`](super::AccountId::is_regular_account) for details.
    pub fn is_regular_account(&self) -> bool {
        self.account_type().is_regular_account()
    }

    /// See [`AccountId::storage_mode`](super::AccountId::storage_mode) for details.
    pub fn storage_mode(&self) -> AccountStorageMode {
        extract_storage_mode(self.prefix().as_u64())
            .expect("account ID should have been constructed with a valid storage mode")
    }

    /// See [`AccountId::is_public`](super::AccountId::is_public) for details.
    pub fn is_public(&self) -> bool {
        self.storage_mode() == AccountStorageMode::Public
    }

    /// See [`AccountId::version`](super::AccountId::version) for details.
    pub fn version(&self) -> AccountIdVersion {
        extract_version(self.prefix().as_u64())
            .expect("account ID should have been constructed with a valid version")
    }

    /// See [`AccountId::from_hex`](super::AccountId::from_hex) for details.
    pub fn from_hex(hex_str: &str) -> Result<AccountIdV0, AccountIdError> {
        hex_to_bytes(hex_str)
            .map_err(AccountIdError::AccountIdHexParseError)
            .and_then(AccountIdV0::try_from)
    }

    /// See [`AccountId::to_hex`](super::AccountId::to_hex) for details.
    pub fn to_hex(self) -> String {
        // We need to pad the suffix with 16 zeroes so it produces a correctly padded 8 byte
        // big-endian hex string. Only then can we cut off the last zero byte by truncating. We
        // cannot use `:014x` padding.
        let mut hex_string =
            format!("0x{:016x}{:016x}", self.prefix().as_u64(), self.suffix().as_int());
        hex_string.truncate(32);
        hex_string
    }

    /// See [`AccountId::to_bech32`](super::AccountId::to_bech32) for details.
    pub fn to_bech32(&self, network_id: NetworkId) -> String {
        let id_bytes: [u8; Self::SERIALIZED_SIZE] = (*self).into();

        let mut data = [0; Self::SERIALIZED_SIZE + 1];
        data[0] = AddressType::AccountId as u8;
        data[1..16].copy_from_slice(&id_bytes);

        // SAFETY: Encoding only panics if the total length of the hrp, data (in GF(32)), separator
        // and checksum exceeds Bech32m::CODE_LENGTH, which is 1023. Since the data is 26 bytes in
        // that field and the hrp is at most 83 in size we are way below the limit.
        //
        // The only allowed checksum algorithm is [`Bech32m`](bech32::Bech32m) due to being the
        // best available checksum algorithm with no known weaknesses (unlike
        // [`Bech32`](bech32::Bech32)). No checksum is also not allowed since the intended
        // use of bech32 is to have error detection capabilities.
        bech32::encode::<Bech32m>(network_id.into_hrp(), &data)
            .expect("code length of bech32 should not be exceeded")
    }

    /// See [`AccountId::from_bech32`](super::AccountId::from_bech32) for details.
    pub fn from_bech32(bech32_string: &str) -> Result<(NetworkId, Self), AccountIdError> {
        // We use CheckedHrpString instead of bech32::decode with an explicit checksum algorithm so
        // we don't allow the `Bech32` or `NoChecksum` algorithms.
        let checked_string = CheckedHrpstring::new::<Bech32m>(bech32_string).map_err(|source| {
            // The CheckedHrpStringError does not implement core::error::Error, only
            // std::error::Error, so for now we convert it to a String. Even if it will
            // implement the trait in the future, we should include it as an opaque
            // error since the crate does not have a stable release yet.
            AccountIdError::Bech32DecodeError(Bech32Error::DecodeError(source.to_string().into()))
        })?;

        let hrp = checked_string.hrp();
        let network_id = NetworkId::from_hrp(hrp);

        let mut byte_iter = checked_string.byte_iter();

        // The length must be the serialized size of the account ID plus the address byte.
        if byte_iter.len() != Self::SERIALIZED_SIZE + 1 {
            return Err(AccountIdError::Bech32DecodeError(Bech32Error::InvalidDataLength {
                expected: Self::SERIALIZED_SIZE + 1,
                actual: byte_iter.len(),
            }));
        }

        let address_byte = byte_iter.next().expect("there should be at least one byte");
        if address_byte != AddressType::AccountId as u8 {
            return Err(AccountIdError::Bech32DecodeError(Bech32Error::UnknownAddressType(
                address_byte,
            )));
        }

        Self::from_bech32_byte_iter(byte_iter).map(|account_id| (network_id, account_id))
    }

    /// Decodes the data from the bech32 byte iterator into an [`AccountId`].
    pub(crate) fn from_bech32_byte_iter(byte_iter: ByteIter<'_>) -> Result<Self, AccountIdError> {
        // The _remaining_ length of the iterator must be the serialized size of the account ID.
        if byte_iter.len() != Self::SERIALIZED_SIZE {
            return Err(AccountIdError::Bech32DecodeError(Bech32Error::InvalidDataLength {
                expected: Self::SERIALIZED_SIZE,
                actual: byte_iter.len(),
            }));
        }

        // Every byte is guaranteed to be overwritten since we've checked the length of the
        // iterator.
        let mut id_bytes = [0_u8; Self::SERIALIZED_SIZE];
        for (i, byte) in byte_iter.enumerate() {
            id_bytes[i] = byte;
        }

        let account_id = Self::try_from(id_bytes)?;

        Ok(account_id)
    }

    /// Returns the [`AccountIdPrefixV0`] of this account ID.
    ///
    /// See also [`AccountId::prefix`](super::AccountId::prefix) for details.
    pub fn prefix(&self) -> AccountIdPrefixV0 {
        // SAFETY: We only construct account IDs with valid prefixes, so we don't have to validate
        // it again.
        AccountIdPrefixV0::new_unchecked(self.prefix)
    }

    /// See [`AccountId::suffix`](super::AccountId::suffix) for details.
    pub const fn suffix(&self) -> Felt {
        self.suffix
    }
}

// CONVERSIONS FROM ACCOUNT ID
// ================================================================================================

impl From<AccountIdV0> for [Felt; 2] {
    fn from(id: AccountIdV0) -> Self {
        [id.prefix, id.suffix]
    }
}

impl From<AccountIdV0> for [u8; 15] {
    fn from(id: AccountIdV0) -> Self {
        let mut result = [0_u8; 15];
        result[..8].copy_from_slice(&id.prefix().as_u64().to_be_bytes());
        // The last byte of the suffix is always zero so we skip it here.
        result[8..].copy_from_slice(&id.suffix().as_int().to_be_bytes()[..7]);
        result
    }
}

impl From<AccountIdV0> for u128 {
    fn from(id: AccountIdV0) -> Self {
        let mut le_bytes = [0_u8; 16];
        le_bytes[..8].copy_from_slice(&id.suffix().as_int().to_le_bytes());
        le_bytes[8..].copy_from_slice(&id.prefix().as_u64().to_le_bytes());
        u128::from_le_bytes(le_bytes)
    }
}

// CONVERSIONS TO ACCOUNT ID
// ================================================================================================

impl TryFrom<[Felt; 2]> for AccountIdV0 {
    type Error = AccountIdError;

    /// See [`TryFrom<[Felt; 2]> for
    /// AccountId`](super::AccountId#impl-TryFrom<%5BFelt;+2%5D>-for-AccountId) for details.
    fn try_from(elements: [Felt; 2]) -> Result<Self, Self::Error> {
        account_id_from_felts(elements)
    }
}

impl TryFrom<[u8; 15]> for AccountIdV0 {
    type Error = AccountIdError;

    /// See [`TryFrom<[u8; 15]> for
    /// AccountId`](super::AccountId#impl-TryFrom<%5Bu8;+15%5D>-for-AccountId) for details.
    fn try_from(mut bytes: [u8; 15]) -> Result<Self, Self::Error> {
        // Felt::try_from expects little-endian order, so reverse the individual felt slices.
        // This prefix slice has 8 bytes.
        bytes[..8].reverse();
        // The suffix slice has 7 bytes, since the 8th byte will always be zero.
        bytes[8..15].reverse();

        let prefix_slice = &bytes[..8];
        let suffix_slice = &bytes[8..15];

        // The byte order is little-endian here, so we prepend a 0 to set the least significant
        // byte.
        let mut suffix_bytes = [0; 8];
        suffix_bytes[1..8].copy_from_slice(suffix_slice);

        let prefix = Felt::try_from(prefix_slice)
            .map_err(AccountIdError::AccountIdInvalidPrefixFieldElement)?;

        let suffix = Felt::try_from(suffix_bytes.as_slice())
            .map_err(AccountIdError::AccountIdInvalidSuffixFieldElement)?;

        Self::try_from([prefix, suffix])
    }
}

impl TryFrom<u128> for AccountIdV0 {
    type Error = AccountIdError;

    /// See [`TryFrom<u128> for AccountId`](super::AccountId#impl-TryFrom<u128>-for-AccountId) for
    /// details.
    fn try_from(int: u128) -> Result<Self, Self::Error> {
        let mut bytes: [u8; 15] = [0; 15];
        bytes.copy_from_slice(&int.to_be_bytes()[0..15]);

        Self::try_from(bytes)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountIdV0 {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        let bytes: [u8; 15] = (*self).into();
        bytes.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl Deserializable for AccountIdV0 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        <[u8; 15]>::read_from(source)?
            .try_into()
            .map_err(|err: AccountIdError| DeserializationError::InvalidValue(err.to_string()))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns an [AccountId] instantiated with the provided field elements.
///
/// # Errors
///
/// Returns an error if any of the ID constraints are not met. See the [constraints
/// documentation](AccountId#constraints) for details.
fn account_id_from_felts(elements: [Felt; 2]) -> Result<AccountIdV0, AccountIdError> {
    validate_prefix(elements[0])?;
    validate_suffix(elements[1])?;

    Ok(AccountIdV0 { prefix: elements[0], suffix: elements[1] })
}

/// Checks that the prefix:
/// - has known values for metadata (storage mode, type and version).
pub(crate) fn validate_prefix(
    prefix: Felt,
) -> Result<(AccountType, AccountStorageMode, AccountIdVersion), AccountIdError> {
    let prefix = prefix.as_int();

    // Validate storage bits.
    let storage_mode = extract_storage_mode(prefix)?;

    // Validate version bits.
    let version = extract_version(prefix)?;

    let account_type = extract_type(prefix);

    Ok((account_type, storage_mode, version))
}

/// Checks that the suffix:
/// - has its most significant bit set to zero.
/// - has its lower 8 bits set to zero.
const fn validate_suffix(suffix: Felt) -> Result<(), AccountIdError> {
    let suffix = suffix.as_int();

    // Validate most significant bit is zero.
    if suffix >> 63 != 0 {
        return Err(AccountIdError::AccountIdSuffixMostSignificantBitMustBeZero);
    }

    // Validate lower 8 bits of second felt are zero.
    if suffix & 0xff != 0 {
        return Err(AccountIdError::AccountIdSuffixLeastSignificantByteMustBeZero);
    }

    Ok(())
}

pub(crate) fn extract_storage_mode(prefix: u64) -> Result<AccountStorageMode, AccountIdError> {
    let bits = (prefix & AccountIdV0::STORAGE_MODE_MASK as u64) >> AccountIdV0::STORAGE_MODE_SHIFT;
    // SAFETY: `STORAGE_MODE_MASK` is u8 so casting bits is lossless
    match bits as u8 {
        PUBLIC => Ok(AccountStorageMode::Public),
        NETWORK => Ok(AccountStorageMode::Network),
        PRIVATE => Ok(AccountStorageMode::Private),
        _ => Err(AccountIdError::UnknownAccountStorageMode(format!("0b{bits:b}").into())),
    }
}

pub(crate) fn extract_version(prefix: u64) -> Result<AccountIdVersion, AccountIdError> {
    // SAFETY: The mask guarantees that we only mask out the least significant nibble, so casting to
    // u8 is safe.
    let version = (prefix & AccountIdV0::VERSION_MASK) as u8;
    AccountIdVersion::try_from(version)
}

pub(crate) const fn extract_type(prefix: u64) -> AccountType {
    let bits = (prefix & (AccountIdV0::TYPE_MASK as u64)) >> AccountIdV0::TYPE_SHIFT;
    // SAFETY: `TYPE_MASK` is u8 so casting bits is lossless
    match bits as u8 {
        REGULAR_ACCOUNT_UPDATABLE_CODE => AccountType::RegularAccountUpdatableCode,
        REGULAR_ACCOUNT_IMMUTABLE_CODE => AccountType::RegularAccountImmutableCode,
        FUNGIBLE_FAUCET => AccountType::FungibleFaucet,
        NON_FUNGIBLE_FAUCET => AccountType::NonFungibleFaucet,
        _ => {
            // SAFETY: type mask contains only 2 bits and we've covered all 4 possible options.
            panic!("type mask contains only 2 bits and we've covered all 4 possible options")
        },
    }
}

/// Shapes the suffix so it meets the requirements of the account ID, by setting the lower 8 bits to
/// zero.
fn shape_suffix(suffix: Felt) -> Felt {
    let mut suffix = suffix.as_int();

    // Clear the lower 8 bits.
    suffix &= 0xffff_ffff_ffff_ff00;

    // SAFETY: Felt was previously valid and we only cleared bits, so it must still be valid.
    Felt::try_from(suffix).expect("no bits were set so felt should still be valid")
}

// COMMON TRAIT IMPLS
// ================================================================================================

impl PartialOrd for AccountIdV0 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AccountIdV0 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        u128::from(*self).cmp(&u128::from(*other))
    }
}

impl fmt::Display for AccountIdV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Returns the digest of two hashing permutations over the seed, code commitment, storage
/// commitment and padding.
pub(crate) fn compute_digest(seed: Word, code_commitment: Word, storage_commitment: Word) -> Word {
    let mut elements = Vec::with_capacity(16);
    elements.extend(seed);
    elements.extend(*code_commitment);
    elements.extend(*storage_commitment);
    elements.extend(EMPTY_WORD);
    Hasher::hash_elements(&elements)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use super::*;
    use crate::account::AccountIdPrefix;
    use crate::testing::account_id::{
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_SENDER,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    };

    #[test]
    fn account_id_from_felts_with_max_pop_count() {
        let valid_suffix = Felt::try_from(0x7fff_ffff_ffff_ff00u64).unwrap();
        let valid_prefix = Felt::try_from(0x7fff_ffff_ffff_ff70u64).unwrap();

        let id1 = AccountIdV0::new_unchecked([valid_prefix, valid_suffix]);
        assert_eq!(id1.account_type(), AccountType::NonFungibleFaucet);
        assert_eq!(id1.storage_mode(), AccountStorageMode::Network);
        assert_eq!(id1.version(), AccountIdVersion::Version0);
    }

    #[test]
    fn account_id_dummy_construction() {
        // Use the highest possible input to check if the constructed id is a valid Felt in that
        // scenario.
        // Use the lowest possible input to check whether the constructor produces valid IDs with
        // all-zeroes input.
        for input in [[0xff; 15], [0; 15]] {
            for account_type in [
                AccountType::FungibleFaucet,
                AccountType::NonFungibleFaucet,
                AccountType::RegularAccountImmutableCode,
                AccountType::RegularAccountUpdatableCode,
            ] {
                for storage_mode in [AccountStorageMode::Private, AccountStorageMode::Public] {
                    let id = AccountIdV0::dummy(input, account_type, storage_mode);
                    assert_eq!(id.account_type(), account_type);
                    assert_eq!(id.storage_mode(), storage_mode);
                    assert_eq!(id.version(), AccountIdVersion::Version0);

                    // Do a serialization roundtrip to ensure validity.
                    let serialized_id = id.to_bytes();
                    AccountIdV0::read_from_bytes(&serialized_id).unwrap();
                    assert_eq!(serialized_id.len(), AccountIdV0::SERIALIZED_SIZE);
                }
            }
        }
    }

    #[test]
    fn account_id_prefix_serialization_compatibility() {
        // Ensure that an AccountIdPrefix can be read from the serialized bytes of an AccountId.
        let account_id = AccountIdV0::try_from(ACCOUNT_ID_PRIVATE_SENDER).unwrap();
        let id_bytes = account_id.to_bytes();
        assert_eq!(account_id.prefix().to_bytes(), id_bytes[..8]);

        let deserialized_prefix = AccountIdPrefix::read_from_bytes(&id_bytes).unwrap();
        assert_eq!(AccountIdPrefix::V0(account_id.prefix()), deserialized_prefix);

        // Ensure AccountId and AccountIdPrefix's hex representation are compatible.
        assert!(account_id.to_hex().starts_with(&account_id.prefix().to_hex()));
    }

    // CONVERSION TESTS
    // ================================================================================================

    #[test]
    fn test_account_id_conversion_roundtrip() {
        for (idx, account_id) in [
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
            ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
            ACCOUNT_ID_PRIVATE_SENDER,
        ]
        .into_iter()
        .enumerate()
        {
            let id = AccountIdV0::try_from(account_id).expect("account ID should be valid");
            assert_eq!(id, AccountIdV0::from_hex(&id.to_hex()).unwrap(), "failed in {idx}");
            assert_eq!(id, AccountIdV0::try_from(<[u8; 15]>::from(id)).unwrap(), "failed in {idx}");
            assert_eq!(id, AccountIdV0::try_from(u128::from(id)).unwrap(), "failed in {idx}");
            // The u128 big-endian representation without the least significant byte and the
            // [u8; 15] representations should be equivalent.
            assert_eq!(u128::from(id).to_be_bytes()[0..15], <[u8; 15]>::from(id));
            assert_eq!(account_id, u128::from(id), "failed in {idx}");
        }
    }

    #[test]
    fn test_account_id_tag_identifiers() {
        let account_id = AccountIdV0::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)
            .expect("valid account ID");
        assert!(account_id.is_regular_account());
        assert_eq!(account_id.account_type(), AccountType::RegularAccountImmutableCode);
        assert!(account_id.is_public());

        let account_id = AccountIdV0::try_from(ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE)
            .expect("valid account ID");
        assert!(account_id.is_regular_account());
        assert_eq!(account_id.account_type(), AccountType::RegularAccountUpdatableCode);
        assert!(!account_id.is_public());

        let account_id =
            AccountIdV0::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).expect("valid account ID");
        assert!(account_id.is_faucet());
        assert_eq!(account_id.account_type(), AccountType::FungibleFaucet);
        assert!(account_id.is_public());

        let account_id = AccountIdV0::try_from(ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET)
            .expect("valid account ID");
        assert!(account_id.is_faucet());
        assert_eq!(account_id.account_type(), AccountType::NonFungibleFaucet);
        assert!(!account_id.is_public());
    }
}
