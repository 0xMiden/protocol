use alloc::collections::BTreeMap;

use miden_processor::{LoadedMastForest, MastForestStore};
use miden_protocol::Word;
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::TransactionScript;
use miden_protocol::vm::AdviceMap;

/// Stores the MAST forests for a set of scripts (both note scripts and transaction scripts).
///
/// A [ScriptMastForestStore] is meant to exclusively store MAST forests related to both
/// transaction and input note scripts.
#[derive(Debug, Clone, Default)]
pub struct ScriptMastForestStore {
    mast_forests: BTreeMap<Word, LoadedMastForest>,
    advice_map: AdviceMap,
}

impl ScriptMastForestStore {
    /// Creates a new [ScriptMastForestStore].
    pub fn new(
        tx_script: Option<&TransactionScript>,
        note_scripts: impl Iterator<Item = impl AsRef<NoteScript>>,
    ) -> Self {
        let mut mast_store = ScriptMastForestStore {
            mast_forests: BTreeMap::new(),
            advice_map: AdviceMap::default(),
        };

        for note_script in note_scripts {
            mast_store.insert(note_script.as_ref().loaded_mast_forest());
        }

        if let Some(tx_script) = tx_script {
            mast_store.insert(tx_script.loaded_mast_forest());
        }
        mast_store
    }

    /// Registers all procedures of the provided [MastForest] with this store.
    fn insert(&mut self, loaded_mast_forest: LoadedMastForest) {
        // only register procedures that are local to this forest
        for proc_digest in loaded_mast_forest.mast_forest().local_procedure_digests() {
            self.mast_forests.insert(proc_digest, loaded_mast_forest.clone());
        }

        // collect advice data from the forest
        for (key, values) in loaded_mast_forest.mast_forest().advice_map().clone() {
            self.advice_map.insert((*key).into(), values);
        }
    }

    /// Returns a reference to the advice data collected from all forests.
    pub fn advice_map(&self) -> &AdviceMap {
        &self.advice_map
    }
}

// MAST FOREST STORE IMPLEMENTATION
// ================================================================================================

impl MastForestStore for ScriptMastForestStore {
    fn get(&self, procedure_root: &Word) -> Option<LoadedMastForest> {
        self.mast_forests.get(procedure_root).cloned()
    }
}
