use miden_protocol::block::{
    BlockAccountUpdate,
    BlockBody,
    BlockHeader,
    BlockNumber,
    FeeParameters,
    OutputNoteBatch,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::protocol_config::NextProtocolConfig;
use miden_protocol::transaction::{OutputNote, PartialBlockchain};

use crate::proto;

#[cfg(test)]
mod tests;

// BLOCK NUMBER
// ================================================================================================

impl From<BlockNumber> for proto::blockchain::BlockNumber {
    fn from(value: BlockNumber) -> Self {
        Self { block_num: value.as_u32() }
    }
}

// PARTIAL BLOCKCHAIN
// ================================================================================================

impl From<&PartialBlockchain> for proto::blockchain::PartialBlockchain {
    fn from(value: &PartialBlockchain) -> Self {
        let mmr = value.mmr();
        let tracked_leaves = mmr
            .leaves()
            .map(|(position, leaf)| {
                let proof = mmr
                    .open(position)
                    .expect("tracked MMR position must be in bounds")
                    .expect("tracked MMR leaf must have an opening");
                proto::blockchain::TrackedMmrLeaf {
                    position: position as u64,
                    leaf: Some(leaf.into()),
                    path: proof.merkle_path().nodes().iter().map(Into::into).collect(),
                }
            })
            .collect();
        Self {
            forest: mmr.forest().num_leaves() as u64,
            peaks: mmr.peaks().peaks().iter().map(Into::into).collect(),
            tracked_leaves,
            block_headers: value.block_headers().map(Into::into).collect(),
        }
    }
}

// BLOCK HEADER
// ================================================================================================

impl From<&BlockHeader> for proto::blockchain::BlockHeader {
    fn from(header: &BlockHeader) -> Self {
        Self {
            version: proto::blockchain::BlockVersion::V1 as i32,
            timestamp: header.timestamp(),
            block_num: Some(header.block_num().into()),
            prev_block_commitment: Some(header.prev_block_commitment().into()),
            chain_commitment: Some(header.chain_commitment().into()),
            account_root: Some(header.account_root().into()),
            nullifier_root: Some(header.nullifier_root().into()),
            note_root: Some(header.note_root().into()),
            tx_commitment: Some(header.tx_commitment().into()),
            validator_config: Some(header.validator_config().into()),
            fee_parameters: Some(header.fee_parameters().into()),
            protocol_config_commitment: Some(header.protocol_config_commitment().into()),
            next_protocol_config: header.next_protocol_config().map(Into::into),
        }
    }
}

impl From<BlockHeader> for proto::blockchain::BlockHeader {
    fn from(header: BlockHeader) -> Self {
        (&header).into()
    }
}

// BLOCK BODY
// ================================================================================================

impl From<&BlockBody> for proto::blockchain::BlockBody {
    fn from(body: &BlockBody) -> Self {
        Self {
            updated_accounts: body.updated_accounts().iter().map(Into::into).collect(),
            output_note_batches: body.output_note_batches().iter().map(Into::into).collect(),
            created_nullifiers: body
                .created_nullifiers()
                .iter()
                .map(|nullifier| nullifier.as_word().into())
                .collect(),
            transactions: body.transactions().as_slice().iter().map(Into::into).collect(),
        }
    }
}

impl From<BlockBody> for proto::blockchain::BlockBody {
    fn from(body: BlockBody) -> Self {
        (&body).into()
    }
}

// BLOCK BODY COMPONENTS
// ================================================================================================

impl From<&BlockAccountUpdate> for proto::blockchain::BlockAccountUpdate {
    fn from(update: &BlockAccountUpdate) -> Self {
        Self {
            account_id: Some(update.account_id().into()),
            final_state_commitment: Some(update.final_state_commitment().into()),
            details: Some(update.details().into()),
        }
    }
}

impl From<&(usize, OutputNote)> for proto::blockchain::IndexedOutputNote {
    fn from((index, note): &(usize, OutputNote)) -> Self {
        Self {
            note_index_in_batch: u32::try_from(*index)
                .expect("valid output note indices fit into u32"),
            note: Some(note.into()),
        }
    }
}

impl From<&OutputNoteBatch> for proto::blockchain::OutputNoteBatch {
    fn from(batch: &OutputNoteBatch) -> Self {
        Self {
            notes: batch.iter().map(Into::into).collect(),
        }
    }
}

// SIGNED BLOCK
// ================================================================================================

impl From<&SignedBlock> for proto::blockchain::SignedBlock {
    fn from(block: &SignedBlock) -> Self {
        Self {
            header: Some(block.header().into()),
            body: Some(block.body().into()),
            signatures: block.signatures().as_signatures().iter().map(Into::into).collect(),
        }
    }
}

impl From<SignedBlock> for proto::blockchain::SignedBlock {
    fn from(block: SignedBlock) -> Self {
        (&block).into()
    }
}

// VALIDATOR AND PROTOCOL CONFIGURATION
// ================================================================================================

impl From<&ValidatorConfig> for proto::blockchain::ValidatorConfig {
    fn from(value: &ValidatorConfig) -> Self {
        Self {
            keys: value.keys().iter().map(Into::into).collect(),
            quorum: u32::from(value.quorum()),
        }
    }
}

impl From<ValidatorConfig> for proto::blockchain::ValidatorConfig {
    fn from(value: ValidatorConfig) -> Self {
        (&value).into()
    }
}

impl From<&NextProtocolConfig> for proto::blockchain::NextProtocolConfig {
    fn from(value: &NextProtocolConfig) -> Self {
        Self {
            effective_from: Some(value.effective_from().into()),
            protocol_config: Some(value.protocol_config().into()),
        }
    }
}

impl From<NextProtocolConfig> for proto::blockchain::NextProtocolConfig {
    fn from(value: NextProtocolConfig) -> Self {
        (&value).into()
    }
}

impl From<&FeeParameters> for proto::blockchain::FeeParameters {
    fn from(value: &FeeParameters) -> Self {
        Self {
            verification_base_fee: value.verification_base_fee(),
        }
    }
}

impl From<FeeParameters> for proto::blockchain::FeeParameters {
    fn from(value: FeeParameters) -> Self {
        (&value).into()
    }
}
