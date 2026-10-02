use miden_protocol::transaction::TransactionEffects;

use crate::proto;

#[cfg(test)]
mod tests;

// TRANSACTION EFFECTS
// ================================================================================================

impl From<&TransactionEffects> for proto::transaction::TransactionEffectsV1 {
    fn from(effects: &TransactionEffects) -> Self {
        Self {
            initial_state_commitment: Some(effects.initial_state_commitment().into()),
            final_state_commitment: Some(effects.final_state_commitment().into()),
            account_patch: Some(effects.account_patch().into()),
            input_notes: Some(effects.input_notes().into()),
            output_notes: Some(effects.output_notes().into()),
            ref_block_number: Some(effects.ref_block_number().into()),
            ref_block_commitment: Some(effects.ref_block_commitment().into()),
            expiration_block_num: Some(effects.expiration_block_num().into()),
        }
    }
}

impl From<&TransactionEffects> for proto::transaction::TransactionEffects {
    fn from(effects: &TransactionEffects) -> Self {
        use proto::transaction::transaction_effects::Version;

        Self {
            version: Some(Version::V1(effects.into())),
        }
    }
}

impl From<TransactionEffects> for proto::transaction::TransactionEffects {
    fn from(effects: TransactionEffects) -> Self {
        Self::from(&effects)
    }
}
