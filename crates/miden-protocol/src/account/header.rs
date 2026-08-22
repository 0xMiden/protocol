use alloc::vec::Vec;

use super::{Account, AccountId, Felt, PartialAccount};
use crate::Word;
use crate::crypto::SequentialCommit;
use crate::errors::AccountError;
use crate::utils::serde::{
    ByteReader,
    ByteWriter,
    Deserializable,
    DeserializationError,
    Serializable,
};

// ACCOUNT HEADER
// ================================================================================================

/// A header of an account which contains information that succinctly describes the state of the
/// components of the account.
///
/// The [AccountHeader] is composed of:
/// - id: the account ID ([`AccountId`]) of the account.
/// - nonce: the nonce of the account.
/// - vault_root: a commitment to the account's vault ([super::AssetVault]).
/// - storage_commitment: a commitment to the account's storage ([super::AccountStorage]).
/// - code_commitment: a commitment to the account's code ([super::AccountCode]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountHeader {
    version: u8,
    id: AccountId,
    nonce: Felt,
    vault_root: Word,
    storage_commitment: Word,
    code_commitment: Word,
}

impl AccountHeader {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Version 1 of the account header encoding.
    ///
    /// The version occupies the first element of the account metadata word, so a reader can get it
    /// before it interprets the rest of the header. Version 0 is unused, which means an all-zero
    /// word is never valid account metadata.
    pub(crate) const VERSION_1: u8 = 1;

    /// The number of elements in an account header.
    pub(crate) const NUM_ELEMENTS: u8 = 16;

    /// The index of the version in the account header elements.
    pub(crate) const VERSION_IDX: usize = 0;

    /// The index of the nonce in the account header elements.
    pub(crate) const NONCE_IDX: usize = 1;

    /// The index of the ID suffix in the account header elements.
    pub(crate) const ID_SUFFIX_IDX: usize = 2;

    /// The index of the ID prefix in the account header elements.
    pub(crate) const ID_PREFIX_IDX: usize = 3;

    /// The index at which the vault root word starts in the account header elements.
    const VAULT_ROOT_IDX: usize = 4;

    /// The index at which the storage commitment word starts in the account header elements.
    const STORAGE_COMMITMENT_IDX: usize = 8;

    /// The index at which the code commitment word starts in the account header elements.
    const CODE_COMMITMENT_IDX: usize = 12;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`AccountHeader`].
    pub fn new(
        id: AccountId,
        nonce: Felt,
        vault_root: Word,
        storage_commitment: Word,
        code_commitment: Word,
    ) -> Self {
        Self {
            version: Self::VERSION_1,
            id,
            nonce,
            vault_root,
            storage_commitment,
            code_commitment,
        }
    }

    /// Parses the account header data returned by the VM into individual account component
    /// commitments. Returns a tuple of account ID, vault root, storage commitment, code
    /// commitment, and nonce.
    pub(crate) fn try_from_elements(elements: &[Felt]) -> Result<AccountHeader, AccountError> {
        if elements.len() != Self::NUM_ELEMENTS as usize {
            return Err(AccountError::UnexpectedHeaderLength { actual: elements.len() });
        }

        let version = elements[Self::VERSION_IDX].as_canonical_u64();
        if version != u64::from(Self::VERSION_1) {
            return Err(AccountError::UnsupportedAccountVersion(version));
        }
        let nonce = elements[Self::NONCE_IDX];
        let id = AccountId::try_from_elements(
            elements[Self::ID_SUFFIX_IDX],
            elements[Self::ID_PREFIX_IDX],
        )
        .map_err(AccountError::FinalAccountHeaderIdParsingFailed)?;

        let vault_root = parse_word(elements, Self::VAULT_ROOT_IDX);
        let storage_commitment = parse_word(elements, Self::STORAGE_COMMITMENT_IDX);
        let code_commitment = parse_word(elements, Self::CODE_COMMITMENT_IDX);

        Ok(AccountHeader::new(id, nonce, vault_root, storage_commitment, code_commitment))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the commitment of this account.
    ///
    /// The commitment of an account is computed as a hash over the account header elements returned
    /// by [`Self::to_elements`]. Computing the account commitment requires 2 permutations of the
    /// hash function.
    pub fn to_commitment(&self) -> Word {
        <Self as SequentialCommit>::to_commitment(self)
    }

    /// Returns the id of this account.
    pub fn id(&self) -> AccountId {
        self.id
    }

    /// Returns the nonce of this account.
    pub fn nonce(&self) -> Felt {
        self.nonce
    }

    /// Returns the vault root of this account.
    pub fn vault_root(&self) -> Word {
        self.vault_root
    }

    /// Returns the storage commitment of this account.
    pub fn storage_commitment(&self) -> Word {
        self.storage_commitment
    }

    /// Returns the code commitment of this account.
    pub fn code_commitment(&self) -> Word {
        self.code_commitment
    }

    /// Returns the account header encoded to a vector of field elements.
    ///
    /// This is a vector of the following field elements:
    /// ```text
    /// [
    ///     [account_version, account_nonce, account_id_suffix, account_id_prefix],
    ///     VAULT_ROOT,
    ///     STORAGE_COMMITMENT,
    ///     CODE_COMMITMENT,
    /// ]
    /// ```
    ///
    /// `account_version` is an 8-bit version of this encoding. Version 0 is unused.
    pub fn to_elements(&self) -> Vec<Felt> {
        <Self as SequentialCommit>::to_elements(self)
    }
}

impl From<&PartialAccount> for AccountHeader {
    fn from(account: &PartialAccount) -> Self {
        Self {
            version: Self::VERSION_1,
            id: account.id(),
            nonce: account.nonce(),
            vault_root: account.vault().root(),
            storage_commitment: account.storage().commitment(),
            code_commitment: account.code().commitment(),
        }
    }
}

impl From<&Account> for AccountHeader {
    fn from(account: &Account) -> Self {
        Self {
            version: Self::VERSION_1,
            id: account.id(),
            nonce: account.nonce(),
            vault_root: account.vault().root(),
            storage_commitment: account.storage().to_commitment(),
            code_commitment: account.code().commitment(),
        }
    }
}

impl SequentialCommit for AccountHeader {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        let mut metadata_word = Word::empty();
        metadata_word[Self::VERSION_IDX] = Felt::from(Self::VERSION_1);
        metadata_word[Self::NONCE_IDX] = self.nonce;
        metadata_word[Self::ID_SUFFIX_IDX] = self.id.suffix();
        metadata_word[Self::ID_PREFIX_IDX] = self.id.prefix().as_felt();

        [
            metadata_word.as_elements(),
            self.vault_root.as_elements(),
            self.storage_commitment.as_elements(),
            self.code_commitment.as_elements(),
        ]
        .concat()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for AccountHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.version.write_into(target);
        self.id.write_into(target);
        self.nonce.write_into(target);
        self.vault_root.write_into(target);
        self.storage_commitment.write_into(target);
        self.code_commitment.write_into(target);
    }
}

impl Deserializable for AccountHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = u8::read_from(source)?;

        if version != Self::VERSION_1 {
            return Err(DeserializationError::InvalidValue(format!(
                "account version is {} but only {} is not supported",
                version,
                Self::VERSION_1,
            )));
        }

        let id = AccountId::read_from(source)?;
        let nonce = Felt::read_from(source)?;
        let vault_root = Word::read_from(source)?;
        let storage_commitment = Word::read_from(source)?;
        let code_commitment = Word::read_from(source)?;

        Ok(AccountHeader {
            version,
            id,
            nonce,
            vault_root,
            storage_commitment,
            code_commitment,
        })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates a new `Word` instance from the slice of `Felt`s using provided offset.
fn parse_word(data: &[Felt], offset: usize) -> Word {
    Word::try_from(&data[offset..offset + Word::NUM_ELEMENTS])
        .expect("we should have sliced off exactly 4 bytes")
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use assert_matches::assert_matches;
    use miden_core::Felt;

    use super::AccountHeader;
    use crate::Word;
    use crate::account::tests::build_account;
    use crate::account::{AccountId, StorageSlotContent};
    use crate::asset::FungibleAsset;
    use crate::errors::AccountError;
    use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
    use crate::utils::serde::{Deserializable, Serializable};

    /// Builds an account header whose fields are all distinguishable from one another so that a
    /// swapped element in the encoding is visible.
    fn mock_header() -> anyhow::Result<AccountHeader> {
        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)
            .context("failed to build account ID")?;

        Ok(AccountHeader::new(
            id,
            Felt::from(42u32),
            Word::from([1, 2, 3, 4u32]),
            Word::from([5, 6, 7, 8u32]),
            Word::from([9, 10, 11, 12u32]),
        ))
    }

    #[rstest::rstest]
    #[case::version_zero(0)]
    #[case::version_two(2)]
    // The lower 8 bits encode the supported version, so this guards against the upper bits being
    // truncated instead of rejected.
    #[case::version_exceeding_u8((1 << 8) | u32::from(AccountHeader::VERSION_1))]
    fn account_header_rejects_unsupported_version(#[case] version: u32) -> anyhow::Result<()> {
        let mut elements = mock_header()?.to_elements();
        elements[AccountHeader::VERSION_IDX] = Felt::from(version);

        let error = AccountHeader::try_from_elements(&elements)
            .expect_err("header with an unsupported version should not parse");

        assert_matches!(error, AccountError::UnsupportedAccountVersion(actual) => {
            assert_eq!(actual, u64::from(version));
        });

        Ok(())
    }

    #[test]
    fn test_serde_account_storage() {
        let init_nonce = Felt::from(1_u32);
        let asset_0 = FungibleAsset::mock(99);
        let word = Word::from([1, 2, 3, 4u32]);
        let storage_slot = StorageSlotContent::Value(word);
        let account = build_account(vec![asset_0], init_nonce, vec![storage_slot]);

        let account_header = account.to_header();

        let header_bytes = account_header.to_bytes();
        let deserialized_header = AccountHeader::read_from_bytes(&header_bytes).unwrap();
        assert_eq!(deserialized_header, account_header);
    }
}
