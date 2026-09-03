use alloc::format;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::block::{
    BlockAccountUpdate,
    BlockBody,
    BlockHeader,
    BlockNumber,
    BlockSignatures,
    FeeParameters,
    OutputNoteBatch,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::Signature;
use miden_protocol::crypto::merkle::MerklePath;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrPeaks, PartialMmr};
use miden_protocol::note::Nullifier;
use miden_protocol::protocol_config::NextProtocolConfig;
use miden_protocol::transaction::{
    OrderedTransactionHeaders,
    OutputNote,
    PartialBlockchain,
    TransactionHeader,
};

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

// BLOCK NUMBER
// ================================================================================================

impl From<BlockNumber> for proto::blockchain::BlockNumber {
    fn from(value: BlockNumber) -> Self {
        Self { block_num: value.as_u32() }
    }
}

impl From<proto::blockchain::BlockNumber> for BlockNumber {
    fn from(value: proto::blockchain::BlockNumber) -> Self {
        value.block_num.into()
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

impl TryFrom<proto::blockchain::PartialBlockchain> for PartialBlockchain {
    type Error = ConversionError;

    fn try_from(value: proto::blockchain::PartialBlockchain) -> Result<Self, Self::Error> {
        let forest_size = usize::try_from(value.forest).context("forest")?;
        let forest = Forest::new(forest_size).map_err(ConversionError::new).context("forest")?;
        let peaks = value
            .peaks
            .into_iter()
            .enumerate()
            .map(|(index, peak)| Word::try_from(peak).context(format!("peaks[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        let peaks = MmrPeaks::new(forest, peaks).map_err(ConversionError::new).context("peaks")?;
        let mut mmr = PartialMmr::from_peaks(peaks);

        let mut previous_position = None;
        for (index, tracked) in value.tracked_leaves.into_iter().enumerate() {
            let position = usize::try_from(tracked.position)
                .context(format!("tracked_leaves[{index}].position"))?;
            if position >= forest_size {
                return Err(ConversionError::message(format!(
                    "tracked leaf position {position} is outside forest of size {forest_size}"
                ))
                .context(format!("tracked_leaves[{index}].position")));
            }
            if previous_position.is_some_and(|previous| position <= previous) {
                return Err(ConversionError::message(
                    "tracked leaf positions must be unique and strictly increasing",
                )
                .context(format!("tracked_leaves[{index}].position")));
            }
            previous_position = Some(position);

            let decoder = tracked.decoder();
            let leaf = required!(decoder, tracked.leaf)?;
            let path = tracked
                .path
                .into_iter()
                .enumerate()
                .map(|(path_index, node)| {
                    Word::try_from(node)
                        .context(format!("tracked_leaves[{index}].path[{path_index}]"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            mmr.track(position, leaf, &MerklePath::new(path))
                .map_err(ConversionError::new)
                .context(format!("tracked_leaves[{index}]"))?;
        }

        let mut previous_block_num = None;
        let block_headers = value
            .block_headers
            .into_iter()
            .enumerate()
            .map(|(index, header)| {
                let header =
                    BlockHeader::try_from(header).context(format!("block_headers[{index}]"))?;
                if previous_block_num.is_some_and(|previous| header.block_num() <= previous) {
                    return Err(ConversionError::message(
                        "block headers must be unique and ordered by ascending block number",
                    )
                    .context(format!("block_headers[{index}].block_num")));
                }
                previous_block_num = Some(header.block_num());
                Ok(header)
            })
            .collect::<Result<Vec<_>, ConversionError>>()?;

        Self::new(mmr, block_headers).map_err(ConversionError::new)
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

impl TryFrom<&proto::blockchain::BlockHeader> for BlockHeader {
    type Error = ConversionError;

    fn try_from(value: &proto::blockchain::BlockHeader) -> Result<Self, Self::Error> {
        value.clone().try_into()
    }
}

impl TryFrom<proto::blockchain::BlockHeader> for BlockHeader {
    type Error = ConversionError;

    fn try_from(header: proto::blockchain::BlockHeader) -> Result<Self, Self::Error> {
        decode_block_version(header.version).context("version")?;

        let decoder = header.decoder();
        let block_num = required!(decoder, header.block_num).context("block_num")?;
        let prev_block_commitment = required!(decoder, header.prev_block_commitment)?;
        let chain_commitment = required!(decoder, header.chain_commitment)?;
        let account_root = required!(decoder, header.account_root)?;
        let nullifier_root = required!(decoder, header.nullifier_root)?;
        let note_root = required!(decoder, header.note_root)?;
        let tx_commitment = required!(decoder, header.tx_commitment)?;
        let validator_config = required!(decoder, header.validator_config)?;
        let fee_parameters = required!(decoder, header.fee_parameters)?;
        let protocol_config_commitment = required!(decoder, header.protocol_config_commitment)?;
        let next_protocol_config = header
            .next_protocol_config
            .map(TryInto::try_into)
            .transpose()
            .context("next_protocol_config")?;

        Ok(BlockHeader::new(
            prev_block_commitment,
            block_num,
            chain_commitment,
            account_root,
            nullifier_root,
            note_root,
            tx_commitment,
            validator_config,
            fee_parameters,
            protocol_config_commitment,
            next_protocol_config,
            header.timestamp,
        ))
    }
}

fn decode_block_version(version: i32) -> Result<(), ConversionError> {
    match proto::blockchain::BlockVersion::try_from(version) {
        Ok(proto::blockchain::BlockVersion::V1) => Ok(()),
        Ok(proto::blockchain::BlockVersion::Unspecified) => {
            Err(ConversionError::message("block header version is unspecified"))
        },
        Err(error) => Err(ConversionError::with_source(
            format!("unknown block header version {version}"),
            error,
        )),
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

impl TryFrom<proto::primitives::Word> for Nullifier {
    type Error = ConversionError;

    fn try_from(nullifier: proto::primitives::Word) -> Result<Self, Self::Error> {
        Word::try_from(nullifier).map(Self::from_raw)
    }
}

pub(crate) fn decode_block_body(
    updated_accounts: Vec<BlockAccountUpdate>,
    output_note_batches: Vec<OutputNoteBatch>,
    created_nullifiers: Vec<Nullifier>,
    transactions: Vec<TransactionHeader>,
) -> Result<BlockBody, ConversionError> {
    BlockBody::new(
        updated_accounts,
        output_note_batches,
        created_nullifiers,
        OrderedTransactionHeaders::new_unchecked(transactions),
    )
    .map_err(ConversionError::new)
}

impl TryFrom<&proto::blockchain::BlockBody> for BlockBody {
    type Error = ConversionError;

    fn try_from(value: &proto::blockchain::BlockBody) -> Result<Self, Self::Error> {
        value.clone().try_into()
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

impl TryFrom<proto::blockchain::IndexedOutputNote> for (usize, OutputNote) {
    type Error = ConversionError;

    fn try_from(note: proto::blockchain::IndexedOutputNote) -> Result<Self, Self::Error> {
        let decoder = note.decoder();
        let index = usize::try_from(note.note_index_in_batch).context("note_index_in_batch")?;
        let output_note = required!(decoder, note.note)?;
        Ok((index, output_note))
    }
}

impl From<&OutputNoteBatch> for proto::blockchain::OutputNoteBatch {
    fn from(batch: &OutputNoteBatch) -> Self {
        Self {
            notes: batch.iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::blockchain::OutputNoteBatch> for OutputNoteBatch {
    type Error = ConversionError;

    fn try_from(batch: proto::blockchain::OutputNoteBatch) -> Result<Self, Self::Error> {
        batch
            .notes
            .into_iter()
            .enumerate()
            .map(|(position, note)| {
                <(usize, OutputNote)>::try_from(note).context(format!("notes[{position}]"))
            })
            .collect()
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

impl TryFrom<proto::blockchain::SignedBlock> for SignedBlock {
    type Error = ConversionError;

    fn try_from(value: proto::blockchain::SignedBlock) -> Result<Self, Self::Error> {
        let decoder = value.decoder();
        let header = required!(decoder, value.header)?;
        let body = required!(decoder, value.body)?;
        let signatures = value
            .signatures
            .into_iter()
            .map(Signature::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("signatures")?;
        let signatures = BlockSignatures::new(signatures)
            .map_err(ConversionError::new)
            .context("signatures")?;

        SignedBlock::new(header, body, signatures)
            .map_err(ConversionError::new)
            .context("body")
    }
}

impl TryFrom<&proto::blockchain::SignedBlock> for SignedBlock {
    type Error = ConversionError;

    fn try_from(value: &proto::blockchain::SignedBlock) -> Result<Self, Self::Error> {
        value.clone().try_into()
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

impl From<proto::blockchain::FeeParameters> for FeeParameters {
    fn from(value: proto::blockchain::FeeParameters) -> Self {
        Self::new(value.verification_base_fee)
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
