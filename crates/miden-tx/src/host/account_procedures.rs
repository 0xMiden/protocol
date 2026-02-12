use miden_protocol::account::AccountCode;

use super::{BTreeMap, Word};
use crate::errors::TransactionKernelError;

// ACCOUNT PROCEDURE INDEX MAP
// ================================================================================================

/// A map of maps { acct_code_commitment |-> { proc_root |-> proc_index } } for all known
/// procedures of account interfaces for all accounts expected to be invoked during transaction
/// execution.
#[derive(Debug, Clone, Default)]
pub struct AccountProcedureIndexMap(BTreeMap<Word, BTreeMap<Word, u8>>);

impl AccountProcedureIndexMap {
    /// Returns a new [`AccountProcedureIndexMap`] instantiated with account procedures from the
    /// provided iterator of [`AccountCode`].
    pub fn new<'code>(account_codes: impl IntoIterator<Item = &'code AccountCode>) -> Self {
        let mut index_map = Self::default();

        for account_code in account_codes {
            // Insert each account procedures only once.
            if !index_map.0.contains_key(&account_code.commitment()) {
                index_map.insert_code(account_code);
            }
        }

        index_map
    }

    /// Inserts the procedures from the provided [`AccountCode`] into the advice inputs, using
    /// [`AccountCode::commitment`] as the key.
    ///
    /// The resulting instance will map the account code commitment to a mapping of
    /// `proc_root |-> proc_index` for any account that is expected to be involved in the
    /// transaction, enabling fast procedure index lookups at runtime.
    pub fn insert_code(&mut self, code: &AccountCode) {
        let mut procedure_map = BTreeMap::new();
        for (proc_idx, proc_root) in code.procedures().iter().enumerate() {
            // SAFETY: AccountCode::MAX_NUM_PROCEDURES is 256 and so the highest possible index is
            // 255.
            let proc_idx =
                u8::try_from(proc_idx).expect("account code should contain at most 256 procedures");
            procedure_map.insert(*proc_root.mast_root(), proc_idx);
        }

        self.0.insert(code.commitment(), procedure_map);
    }

    /// Returns the index of the requested procedure root in the account code identified by the
    /// provided commitment.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the requested procedure is not present in this map.
    pub fn get_proc_index(
        &self,
        code_commitment: Word,
        procedure_root: Word,
    ) -> Result<u8, TransactionKernelError> {
        self.0
            .get(&code_commitment)
            .ok_or(TransactionKernelError::UnknownCodeCommitment(code_commitment))?
            .get(&procedure_root)
            .cloned()
            .ok_or(TransactionKernelError::UnknownAccountProcedure(procedure_root))
    }
}
