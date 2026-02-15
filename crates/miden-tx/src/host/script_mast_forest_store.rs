use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use miden_processor::MastForestStore;
use miden_processor::mast::MastNodeExt;
use miden_protocol::Word;
use miden_protocol::assembly::mast::MastForest;
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::TransactionScript;
use miden_protocol::vm::AdviceMap;

/// Stores the MAST forests for a set of scripts (both note scripts and transaction scripts).
///
/// A [ScriptMastForestStore] is meant to exclusively store MAST forests related to both
/// transaction and input note scripts.
#[derive(Debug, Clone, Default)]
pub struct ScriptMastForestStore {
    mast_forests: BTreeMap<Word, Arc<MastForest>>,
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
            #[cfg(feature = "std")]
            if std::env::var("MIDEN_DEBUG_MAST_STORE").is_ok() {
                let root = note_script.as_ref().root();
                let mut root_in_forest = false;
                let mut root_is_external = None;
                for node in note_script.as_ref().mast().nodes() {
                    if node.digest() == root {
                        root_in_forest = true;
                        root_is_external = Some(node.is_external());
                        break;
                    }
                }
                std::eprintln!(
                    "debug mast store: note_script_root={:?} root_in_forest={} root_is_external={:?}",
                    root,
                    root_in_forest,
                    root_is_external
                );
            }
            mast_store.insert(note_script.as_ref().mast());
        }

        if let Some(tx_script) = tx_script {
            #[cfg(feature = "std")]
            if std::env::var("MIDEN_DEBUG_MAST_STORE").is_ok() {
                std::eprintln!(
                    "debug mast store: tx_script_root={:?}",
                    tx_script.root()
                );
            }
            mast_store.insert(tx_script.mast());
        }
        mast_store
    }

    /// Registers all local nodes of the provided [MastForest] with this store.
    fn insert(&mut self, mast_forest: Arc<MastForest>) {
        // register all non-external nodes so dynamic exec can resolve any local digest
        for node in mast_forest.nodes() {
            if !node.is_external() {
                self.mast_forests.insert(node.digest(), mast_forest.clone());
            }
        }

        // collect advice data from the forest
        for (key, values) in mast_forest.advice_map().clone() {
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
    fn get(&self, procedure_root: &Word) -> Option<Arc<MastForest>> {
        self.mast_forests.get(procedure_root).cloned()
    }
}
