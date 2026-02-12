use crate::Word;
use crate::account::{AccountCode, AccountId, PartialAccount, PartialStorage};
use crate::asset::PartialVault;
use crate::block::account_tree::AccountWitness;
use crate::crypto::merkle::smt::{SmtProof, SmtProofError};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// ACCOUNT INPUTS
// ================================================================================================

/// Contains information about an account, with everything required to execute a transaction.
///
/// `AccountInputs` combines a partial account representation with the merkle proof that verifies
/// the account's inclusion in the account tree. The partial account should contain verifiable
/// access to the parts of the state of the account of which the transaction will make use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountInputs {
    /// Partial representation of the account's state.
    partial_account: PartialAccount,
    /// Proof of the account's inclusion in the account tree for this account's state commitment.
    witness: AccountWitness,
}

impl AccountInputs {
    /// Creates a new instance of `AccountInputs` with the specified partial account and witness.
    pub fn new(partial_account: PartialAccount, witness: AccountWitness) -> AccountInputs {
        AccountInputs { partial_account, witness }
    }

    /// Returns the account ID.
    pub fn id(&self) -> AccountId {
        self.partial_account.id()
    }

    /// Returns a reference to the partial account representation.
    pub fn account(&self) -> &PartialAccount {
        &self.partial_account
    }

    /// Returns a reference to the account code.
    pub fn code(&self) -> &AccountCode {
        self.partial_account.code()
    }

    /// Returns a reference to the partial representation of the account storage.
    pub fn storage(&self) -> &PartialStorage {
        self.partial_account.storage()
    }

    /// Returns a reference to the partial vault representation of the account.
    pub fn vault(&self) -> &PartialVault {
        self.partial_account.vault()
    }

    /// Returns a reference to the account's witness.
    pub fn witness(&self) -> &AccountWitness {
        &self.witness
    }

    /// Decomposes the `AccountInputs` into its constituent parts.
    pub fn into_parts(self) -> (PartialAccount, AccountWitness) {
        (self.partial_account, self.witness)
    }

    /// Computes the account root based on the account witness.
    /// This root should be equal to the account root in the reference block header.
    pub fn compute_account_root(&self) -> Result<Word, SmtProofError> {
        let smt_merkle_path = self.witness.path().clone();
        let smt_leaf = self.witness.leaf();
        let root = SmtProof::new(smt_merkle_path, smt_leaf)?.compute_root();

        Ok(root)
    }
}

impl Serializable for AccountInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.partial_account);
        target.write(&self.witness);
    }
}

impl Deserializable for AccountInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let partial_account = source.read()?;
        let witness = source.read()?;

        Ok(AccountInputs { partial_account, witness })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::Felt;
    use miden_core::utils::{Deserializable, Serializable};
    use miden_crypto::merkle::SparseMerklePath;
    use miden_processor::SMT_DEPTH;

    use crate::account::{Account, AccountCode, AccountId, AccountStorage, PartialAccount};
    use crate::asset::AssetVault;
    use crate::block::account_tree::AccountWitness;
    use crate::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
    use crate::transaction::AccountInputs;

    #[test]
    fn serde_roundtrip() {
        let id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
        let code = AccountCode::mock();
        let vault = AssetVault::new(&[]).unwrap();
        let storage = AccountStorage::new(vec![]).unwrap();
        let account = Account::new_existing(id, vault, storage, code, Felt::new(10));

        let commitment = account.commitment();

        let mut merkle_nodes = Vec::with_capacity(SMT_DEPTH as usize);
        for _ in 0..(SMT_DEPTH as usize) {
            merkle_nodes.push(commitment);
        }
        let merkle_path = SparseMerklePath::from_sized_iter(merkle_nodes)
            .expect("The nodes given are of SMT_DEPTH count");

        let fpi_inputs = AccountInputs::new(
            PartialAccount::from(&account),
            AccountWitness::new(id, commitment, merkle_path).unwrap(),
        );

        let serialized = fpi_inputs.to_bytes();
        let deserialized = AccountInputs::read_from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, fpi_inputs);
    }
}
