use miden_core::ZERO;
use miden_crypto::merkle::smt::LeafIndex;

use super::AccountId;
use crate::Word;
use crate::block::account_tree::AccountIdPrefix;
use crate::crypto::merkle::smt::SMT_DEPTH;
const KEY_PREFIX_IDX: usize = 3;
const KEY_SUFFIX_IDX: usize = 2;

/// The account ID encoded as a key for use in AccountTree and
/// advice maps in `TransactionAdviceInputs`.
///
/// Canonical word layout:
///
/// [0, 0, suffix, prefix]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountIdKey(AccountId);

impl AccountIdKey {
    /// Create from AccountId
    pub fn new(id: AccountId) -> Self {
        Self(id)
    }

    /// Returns the underlying AccountId
    pub fn account_id(&self) -> AccountId {
        self.0
    }

    // SMT WORD REPRESENTATION
    // ================================================================================================

    /// Returns `[0, 0, suffix, prefix]`
    pub fn as_word(&self) -> Word {
        let mut key = Word::empty();

        key[KEY_SUFFIX_IDX] = self.0.suffix();
        key[KEY_PREFIX_IDX] = self.0.prefix().as_felt();

        key
    }

    /// Construct from SMT word representation.
    ///
    /// Validates structure before converting.
    pub fn from_word(word: Word) -> AccountId {
        AccountId::try_from_elements(word[KEY_SUFFIX_IDX], word[KEY_PREFIX_IDX])
            .expect("account tree should only contain valid IDs")
    }

    // LEAF INDEX
    // ================================================================================================

    /// Converts to SMT leaf index used by AccountTree
    pub fn to_leaf_index(&self) -> LeafIndex<SMT_DEPTH> {
        // identical logic previously used by account_id_to_smt_index
        LeafIndex::from(self.as_word())
    }

    // ADVICE MAP KEY
    // ================================================================================================

    /// Returns advice map key:
    ///
    /// `[suffix, prefix, 0, 0]`
    pub fn to_advice_map_word(&self) -> Word {
        Word::from([self.0.suffix(), self.0.prefix().as_felt(), ZERO, ZERO])
    }

    // Return the prefix of the account ID.
    pub fn prefix(&self) -> AccountIdPrefix {
        self.0.prefix()
    }
}

impl From<AccountId> for AccountIdKey {
    fn from(id: AccountId) -> Self {
        Self(id)
    }
}

#[cfg(test)]
mod tests {

    use super::{AccountId, *};
    use crate::account::{AccountIdVersion, AccountStorageMode, AccountType};
    #[test]
    fn test_as_word_layout() {
        let id = AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Private,
        );
        let key = AccountIdKey::from(id);
        let word = key.as_word();

        assert_eq!(word[0], ZERO);
        assert_eq!(word[1], ZERO);
        assert_eq!(word[2], id.suffix());
        assert_eq!(word[3], id.prefix().as_felt());
    }

    #[test]
    fn test_roundtrip_word_conversion() {
        let id = AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Private,
        );

        let key = AccountIdKey::from(id);
        let recovered = AccountIdKey::from_word(key.as_word());

        assert_eq!(id, recovered);
    }

    #[test]
    fn test_advice_map_layout() {
        let id = AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Private,
        );
        let key = AccountIdKey::from(id);
        let word = key.to_advice_map_word();

        assert_eq!(word[0], id.suffix());
        assert_eq!(word[1], id.prefix().as_felt());
        assert_eq!(word[2], ZERO);
        assert_eq!(word[3], ZERO);
    }

    #[test]
    fn test_leaf_index_consistency() {
        let id = AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Private,
        );
        let key = AccountIdKey::from(id);

        let idx1 = key.to_leaf_index();
        let idx2 = key.to_leaf_index();

        assert_eq!(idx1, idx2);
    }

    #[test]
    fn test_from_conversion() {
        let id = AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Private,
        );
        let key: AccountIdKey = id.into();

        assert_eq!(key.account_id(), id);
    }

    #[test]
    fn test_multiple_roundtrips() {
        for _ in 0..100 {
            let id = AccountId::dummy(
                [1u8; 15],
                AccountIdVersion::Version0,
                AccountType::RegularAccountImmutableCode,
                AccountStorageMode::Private,
            );
            let key = AccountIdKey::from(id);

            let recovered = AccountIdKey::from_word(key.as_word());

            assert_eq!(id, recovered);
        }
    }
}
