use miden_protocol::transaction::TransactionWitness;

use crate::proto;

// TRANSACTION WITNESS
// ================================================================================================

impl From<&TransactionWitness> for proto::transaction::TransactionWitnessV1 {
    fn from(witness: &TransactionWitness) -> Self {
        Self {
            tx_inputs: Some(witness.tx_inputs().into()),
            final_account: Some(witness.final_account().into()),
            expiration_block_num: Some(witness.expiration_block_num().into()),
        }
    }
}

impl From<&TransactionWitness> for proto::transaction::TransactionWitness {
    fn from(witness: &TransactionWitness) -> Self {
        use proto::transaction::transaction_witness::Version;

        Self {
            version: Some(Version::V1(witness.into())),
        }
    }
}

impl From<TransactionWitness> for proto::transaction::TransactionWitness {
    fn from(witness: TransactionWitness) -> Self {
        Self::from(&witness)
    }
}
