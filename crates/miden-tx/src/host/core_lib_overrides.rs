use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};

use miden_core::crypto::merkle::{EmptySubtreeRoots, SMT_DEPTH, Smt};
use miden_core::events::EventName;
use miden_core::{Felt, WORD_SIZE, Word};
use miden_processor::ProcessorState;
use miden_processor::advice::AdviceMutation;
use miden_processor::event::{EventError, EventHandlerRegistry};

use crate::host::get_stack_word_le;

/// Overrides core library handlers that still assume BE stack word order.
pub(crate) fn override_core_lib_handlers(registry: &mut EventHandlerRegistry) {
    let smt_peek_name = EventName::new("miden::core::collections::smt::smt_peek");
    let smt_peek_id = smt_peek_name.to_event_id();

    // Remove the BE handler and install an LE-aware version.
    registry.unregister(smt_peek_id);
    registry
        .register(smt_peek_name, Arc::new(handle_smt_peek_le))
        .expect("smt_peek handler should be registered exactly once");
}

/// SMT_PEEK handler variant that assumes LE stack word order.
fn handle_smt_peek_le(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
    let empty_leaf = EmptySubtreeRoots::entry(SMT_DEPTH, SMT_DEPTH);
    // Stack at emit: [event_id, KEY, ROOT, ...] where KEY and ROOT are structural words.
    let key = get_stack_word_le(process, 1);
    let root = get_stack_word_le(process, 5);
    // K[3] is used as the leaf index (most significant in BE ordering).
    let node = process
        .advice_provider()
        .get_tree_node(root, Felt::new(SMT_DEPTH as u64), key[3])
        .map_err(|err| SmtPeekError::AdviceProviderError {
            message: format!("Failed to get tree node: {} (root={:?}, key={:?})", err, root, key),
        })?;

    if node == *empty_leaf {
        let mutation = AdviceMutation::extend_stack(Smt::EMPTY_VALUE);
        Ok(vec![mutation])
    } else {
        let leaf_preimage = get_smt_leaf_preimage(process, node)?;

        for (key_in_leaf, value_in_leaf) in leaf_preimage {
            if key == key_in_leaf {
                let mutation = AdviceMutation::extend_stack(value_in_leaf);
                return Ok(vec![mutation]);
            }
        }

        let mutation = AdviceMutation::extend_stack(Smt::EMPTY_VALUE);
        Ok(vec![mutation])
    }
}

fn get_smt_leaf_preimage(
    process: &ProcessorState,
    node: Word,
) -> Result<Vec<(Word, Word)>, SmtPeekError> {
    let kv_pairs = process
        .advice_provider()
        .get_mapped_values(&node)
        .ok_or(SmtPeekError::SmtNodeNotFound { node })?;

    if kv_pairs.len() % (WORD_SIZE * 2) != 0 {
        return Err(SmtPeekError::InvalidSmtNodePreimage { node, preimage_len: kv_pairs.len() });
    }

    Ok(kv_pairs
        .chunks_exact(WORD_SIZE * 2)
        .map(|kv_chunk| {
            let key = [kv_chunk[0], kv_chunk[1], kv_chunk[2], kv_chunk[3]];
            let value = [kv_chunk[4], kv_chunk[5], kv_chunk[6], kv_chunk[7]];

            (key.into(), value.into())
        })
        .collect())
}

#[derive(Debug, thiserror::Error)]
enum SmtPeekError {
    #[error("advice provider error: {message}")]
    AdviceProviderError { message: String },

    #[error("SMT node not found: {node:?}")]
    SmtNodeNotFound { node: Word },

    #[error("invalid SMT node preimage length for node {node:?}: got {preimage_len}, expected multiple of {}", WORD_SIZE * 2)]
    InvalidSmtNodePreimage { node: Word, preimage_len: usize },
}
