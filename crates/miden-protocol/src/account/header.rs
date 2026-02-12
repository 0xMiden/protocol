use alloc::vec::Vec;

use super::{Account, AccountId, Felt, PartialAccount, ZERO, hash_account};
use crate::errors::AccountError;
use crate::transaction::memory::{
    ACCT_CODE_COMMITMENT_OFFSET,
    ACCT_DATA_MEM_SIZE,
    ACCT_ID_AND_NONCE_OFFSET,
    ACCT_ID_PREFIX_IDX,
    ACCT_ID_SUFFIX_IDX,
    ACCT_NONCE_IDX,
    ACCT_STORAGE_COMMITMENT_OFFSET,
    ACCT_VAULT_ROOT_OFFSET,
    MemoryOffset,
};
use crate::utils::serde::{Deserializable, Serializable};
use crate::{WORD_SIZE, Word, WordError};

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
    id: AccountId,
    nonce: Felt,
    vault_root: Word,
    storage_commitment: Word,
    code_commitment: Word,
}

impl AccountHeader {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Creates a new [AccountHeader].
    pub fn new(
        id: AccountId,
        nonce: Felt,
        vault_root: Word,
        storage_commitment: Word,
        code_commitment: Word,
    ) -> Self {
        Self {
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
        if elements.len() != ACCT_DATA_MEM_SIZE {
            return Err(AccountError::HeaderDataIncorrectLength {
                actual: elements.len(),
                expected: ACCT_DATA_MEM_SIZE,
            });
        }

        let id = AccountId::try_from([
            elements[ACCT_ID_AND_NONCE_OFFSET as usize + ACCT_ID_PREFIX_IDX],
            elements[ACCT_ID_AND_NONCE_OFFSET as usize + ACCT_ID_SUFFIX_IDX],
        ])
        .map_err(AccountError::FinalAccountHeaderIdParsingFailed)?;
        let nonce = elements[ACCT_ID_AND_NONCE_OFFSET as usize + ACCT_NONCE_IDX];
        let vault_root = parse_word(elements, ACCT_VAULT_ROOT_OFFSET)
            .expect("we should have sliced off exactly 4 bytes");
        let storage_commitment = parse_word(elements, ACCT_STORAGE_COMMITMENT_OFFSET)
            .expect("we should have sliced off exactly 4 bytes");
        let code_commitment = parse_word(elements, ACCT_CODE_COMMITMENT_OFFSET)
            .expect("we should have sliced off exactly 4 bytes");

        Ok(AccountHeader::new(id, nonce, vault_root, storage_commitment, code_commitment))
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
            self.vault_root,
            self.storage_commitment,
            self.code_commitment,
        )
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

    /// Converts the account header into a vector of field elements.
    ///
    /// This is done by first converting the account header data into an array of Words as follows:
    /// ```text
    /// [
    ///     [account_id_suffix, account_id_prefix, 0, account_nonce]
    ///     [VAULT_ROOT]
    ///     [STORAGE_COMMITMENT]
    ///     [CODE_COMMITMENT]
    /// ]
    /// ```
    /// And then concatenating the resulting elements into a single vector.
    pub fn as_elements(&self) -> Vec<Felt> {
        [
            &[self.id.suffix(), self.id.prefix().as_felt(), ZERO, self.nonce],
            self.vault_root.as_elements(),
            self.storage_commitment.as_elements(),
            self.code_commitment.as_elements(),
        ]
        .concat()
    }
}

impl From<PartialAccount> for AccountHeader {
    fn from(account: PartialAccount) -> Self {
        (&account).into()
    }
}

impl From<&PartialAccount> for AccountHeader {
    fn from(account: &PartialAccount) -> Self {
        Self {
            id: account.id(),
            nonce: account.nonce(),
            vault_root: account.vault().root(),
            storage_commitment: account.storage().commitment(),
            code_commitment: account.code().commitment(),
        }
    }
}

impl From<Account> for AccountHeader {
    fn from(account: Account) -> Self {
        (&account).into()
    }
}

impl From<&Account> for AccountHeader {
    fn from(account: &Account) -> Self {
        Self {
            id: account.id(),
            nonce: account.nonce(),
            vault_root: account.vault().root(),
            storage_commitment: account.storage().to_commitment(),
            code_commitment: account.code().commitment(),
        }
    }
}

impl Serializable for AccountHeader {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        self.id.write_into(target);
        self.nonce.write_into(target);
        self.vault_root.write_into(target);
        self.storage_commitment.write_into(target);
        self.code_commitment.write_into(target);
    }
}

impl Deserializable for AccountHeader {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_processor::DeserializationError> {
        let id = AccountId::read_from(source)?;
        let nonce = Felt::read_from(source)?;
        let vault_root = Word::read_from(source)?;
        let storage_commitment = Word::read_from(source)?;
        let code_commitment = Word::read_from(source)?;

        Ok(AccountHeader {
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
fn parse_word(data: &[Felt], offset: MemoryOffset) -> Result<Word, WordError> {
    Word::try_from(&data[offset as usize..offset as usize + WORD_SIZE])
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::Felt;
    use miden_core::utils::{Deserializable, Serializable};

    use super::AccountHeader;
    use crate::Word;
    use crate::account::StorageSlotContent;
    use crate::account::tests::build_account;
    use crate::asset::FungibleAsset;

    #[test]
    fn test_serde_account_storage() {
        let init_nonce = Felt::new(1);
        let asset_0 = FungibleAsset::mock(99);
        let word = Word::from([1, 2, 3, 4u32]);
        let storage_slot = StorageSlotContent::Value(word);
        let account = build_account(vec![asset_0], init_nonce, vec![storage_slot]);

        let account_header: AccountHeader = account.into();

        let header_bytes = account_header.to_bytes();
        let deserialized_header = AccountHeader::read_from_bytes(&header_bytes).unwrap();
        assert_eq!(deserialized_header, account_header);
    }
}
