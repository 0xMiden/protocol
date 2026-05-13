use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use miden_processor::MastForestStore;
use miden_protocol::account::AccountCode;
use miden_protocol::assembly::mast::MastForest;
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::sync::RwLock;
use miden_protocol::{CoreLibrary, ProtocolLib, Word};
use miden_standards::StandardsLib;

// TRANSACTION MAST STORE
// ================================================================================================

/// A store for the code available during transaction execution.
///
/// Transaction MAST store contains a map between procedure MAST roots and [MastForest]s containing
/// MASTs for these procedures. The VM will request [MastForest]s from the store when it encounters
/// a procedure which it doesn't have the code for. Thus, to execute a program which makes
/// references to external procedures, the store must be loaded with [MastForest]s containing these
/// procedures.
pub struct TransactionMastStore {
    mast_forests: RwLock<BTreeMap<Word, Arc<MastForest>>>,
}

#[allow(clippy::new_without_default)]
impl TransactionMastStore {
    /// Returns a new [TransactionMastStore] instantiated with the default libraries.
    ///
    /// The default libraries include:
    /// - Miden core library [`CoreLibrary`].
    /// - Miden protocol library [`ProtocolLib`].
    /// - Miden standards library [`StandardsLib`].
    /// - Transaction kernel [`TransactionKernel::kernel`].
    pub fn new() -> Self {
        let mast_forests = RwLock::new(BTreeMap::new());
        let store = Self { mast_forests };

        // load transaction kernel MAST forest
        let kernels_forest = TransactionKernel::kernel().mast_forest().clone();
        store.insert(kernels_forest);

        // load miden-core-lib MAST forest
        let miden_core_lib_forest = CoreLibrary::default().mast_forest().clone();
        store.insert(miden_core_lib_forest);

        // load protocol lib MAST forest
        let protocol_lib_forest = ProtocolLib::default().mast_forest().clone();
        store.insert(protocol_lib_forest);

        // load standards lib MAST forest
        let standards_lib_forest = StandardsLib::default().mast_forest().clone();
        store.insert(standards_lib_forest);

        store
    }

    /// Registers all procedures of the provided [MastForest] with this store.
    pub fn insert(&self, mast_forest: Arc<MastForest>) {
        let mut mast_forests = self.mast_forests.write();

        // only register procedures that are local to this forest
        for proc_digest in mast_forest.local_procedure_digests() {
            mast_forests.insert(proc_digest, mast_forest.clone());
        }
    }

    /// Loads the provided account code into this store.
    pub fn load_account_code(&self, code: &AccountCode) {
        self.insert(code.mast().clone());
    }
}

// MAST FOREST STORE IMPLEMENTATION
// ================================================================================================

impl MastForestStore for TransactionMastStore {
    fn get(&self, procedure_root: &Word) -> Option<Arc<MastForest>> {
        self.mast_forests.read().get(procedure_root).cloned()
    }
}
