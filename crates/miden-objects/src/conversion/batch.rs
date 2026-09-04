use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::batch::{BatchAccountUpdate, ProposedBatch, ProvenBatch};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, NoteInclusionProof};
use miden_protocol::transaction::{
    InputNoteCommitment,
    InputNotes,
    OrderedTransactionHeaders,
    OutputNote,
    ProvenTransaction,
    TransactionHeader,
};
use miden_protocol::vm::ExecutionProof;

use super::{MessageDecodeExt, required};
use crate::{ConversionError, ConversionResultExt, proto};

impl From<&BatchAccountUpdate> for proto::transaction::BatchAccountUpdate {
    fn from(value: &BatchAccountUpdate) -> Self {
        Self {
            account_id: Some(value.account_id().into()),
            initial_state_commitment: Some(value.initial_state_commitment().into()),
            final_state_commitment: Some(value.final_state_commitment().into()),
            details: Some(value.details().into()),
        }
    }
}

impl From<&ProposedBatch> for proto::transaction::ProposedBatch {
    fn from(value: &ProposedBatch) -> Self {
        let (transactions, reference_block_header, partial_blockchain, note_proofs, ..) =
            value.clone().into_parts();
        Self {
            transactions: transactions.iter().map(|tx| tx.as_ref().into()).collect(),
            reference_block_header: Some(reference_block_header.into()),
            partial_blockchain: Some((&partial_blockchain).into()),
            unauthenticated_note_proofs: note_proofs.iter().map(Into::into).collect(),
        }
    }
}

impl From<ProposedBatch> for proto::transaction::ProposedBatch {
    fn from(value: ProposedBatch) -> Self {
        Self::from(&value)
    }
}

/// Decodes and structurally validates a proposed batch, including transaction proof verification.
///
/// Callers handling untrusted requests should invoke this in a blocking task.
pub fn decode_proposed_batch(
    value: proto::transaction::ProposedBatch,
    proof_security_level: u32,
) -> Result<ProposedBatch, ConversionError> {
    let decoder = value.decoder();
    let transactions = value
        .transactions
        .into_iter()
        .enumerate()
        .map(|(index, tx)| {
            ProvenTransaction::try_from(tx)
                .map(Arc::new)
                .context(format!("transactions[{index}]"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let reference_block_header = required!(decoder, value.reference_block_header)?;
    let partial_blockchain = required!(decoder, value.partial_blockchain)?;

    let mut note_proofs = BTreeMap::new();
    let mut previous_note_id = None;
    for (index, proof) in value.unauthenticated_note_proofs.into_iter().enumerate() {
        let (note_id, proof) = <(NoteId, NoteInclusionProof)>::try_from(&proof)
            .context(format!("unauthenticated_note_proofs[{index}]"))?;
        if previous_note_id.is_some_and(|previous| note_id <= previous) {
            return Err(ConversionError::message(
                "unauthenticated note proofs must have unique, ascending note IDs",
            )
            .context(format!("unauthenticated_note_proofs[{index}].note_id")));
        }
        previous_note_id = Some(note_id);
        note_proofs.insert(note_id, proof);
    }

    ProposedBatch::new(
        transactions,
        reference_block_header,
        partial_blockchain,
        note_proofs,
        proof_security_level,
    )
    .map_err(ConversionError::new)
}

impl From<&ProvenBatch> for proto::transaction::ProvenBatch {
    fn from(value: &ProvenBatch) -> Self {
        Self {
            reference_block_commitment: Some(value.reference_block_commitment().into()),
            reference_block_num: Some(value.reference_block_num().into()),
            account_updates: value.account_updates().values().map(Into::into).collect(),
            input_notes: value.input_notes().iter().map(Into::into).collect(),
            output_notes: value.output_notes().iter().map(Into::into).collect(),
            expiration_block_num: Some(value.batch_expiration_block_num().into()),
            transactions: value.transactions().as_slice().iter().map(Into::into).collect(),
            proof: Some(value.proof().into()),
        }
    }
}

impl From<ProvenBatch> for proto::transaction::ProvenBatch {
    fn from(value: ProvenBatch) -> Self {
        Self::from(&value)
    }
}

struct DecodedProvenBatch {
    reference_block_commitment: Word,
    reference_block_num: BlockNumber,
    account_updates: BTreeMap<AccountId, BatchAccountUpdate>,
    input_notes: InputNotes<InputNoteCommitment>,
    output_notes: Vec<OutputNote>,
    expiration_block_num: BlockNumber,
    transactions: Vec<TransactionHeader>,
    proof: ExecutionProof,
}

impl DecodedProvenBatch {
    fn decode(value: proto::transaction::ProvenBatch) -> Result<Self, ConversionError> {
        let decoder = value.decoder();
        let reference_block_commitment = required!(decoder, value.reference_block_commitment)?;
        let reference_block_num =
            required!(decoder, value.reference_block_num).context("reference_block_num")?;
        let expiration_block_num =
            required!(decoder, value.expiration_block_num).context("expiration_block_num")?;

        let mut account_updates = BTreeMap::new();
        let mut previous_account_id = None;
        for (index, update) in value.account_updates.into_iter().enumerate() {
            let update = BatchAccountUpdate::try_from(update)
                .context(format!("account_updates[{index}]"))?;
            if previous_account_id.is_some_and(|previous| update.account_id() <= previous) {
                return Err(ConversionError::message(
                    "account updates must have unique, ascending account IDs",
                )
                .context(format!("account_updates[{index}].account_id")));
            }
            previous_account_id = Some(update.account_id());
            account_updates.insert(update.account_id(), update);
        }

        let input_notes = value
            .input_notes
            .into_iter()
            .enumerate()
            .map(|(index, note)| {
                InputNoteCommitment::try_from(note).context(format!("input_notes[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let input_notes = InputNotes::new_unchecked(input_notes);

        let output_notes = value
            .output_notes
            .into_iter()
            .enumerate()
            .map(|(index, note)| {
                OutputNote::try_from(note).context(format!("output_notes[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let transactions = value
            .transactions
            .into_iter()
            .enumerate()
            .map(|(index, tx)| {
                TransactionHeader::try_from(tx).context(format!("transactions[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proof = required!(decoder, value.proof)?;

        Ok(Self {
            reference_block_commitment,
            reference_block_num,
            account_updates,
            input_notes,
            output_notes,
            expiration_block_num,
            transactions,
            proof,
        })
    }

    fn into_domain(self) -> Result<ProvenBatch, ConversionError> {
        ProvenBatch::new(
            self.reference_block_commitment,
            self.reference_block_num,
            self.account_updates.into_values(),
            self.input_notes,
            self.output_notes,
            self.expiration_block_num,
            OrderedTransactionHeaders::new_unchecked(self.transactions),
            self.proof,
        )
        .map_err(ConversionError::new)
    }
}

/// Decodes a proven batch without a proposal and validates every invariant available from the
/// transmitted fields. Cryptographic proof verification remains a service-boundary concern.
pub fn decode_standalone_proven_batch(
    value: proto::transaction::ProvenBatch,
) -> Result<ProvenBatch, ConversionError> {
    DecodedProvenBatch::decode(value)?.into_domain()
}

/// Decodes a proven batch and checks every public field duplicated from its proposal.
pub fn decode_proven_batch(
    value: proto::transaction::ProvenBatch,
    proposed: &ProposedBatch,
) -> Result<ProvenBatch, ConversionError> {
    let decoded = DecodedProvenBatch::decode(value)?;
    let expected_header = proposed.reference_block_header();
    if decoded.reference_block_num != expected_header.block_num() {
        return Err(ConversionError::message("reference block number does not match proposal")
            .context("reference_block_num"));
    }
    if decoded.reference_block_commitment != expected_header.commitment() {
        return Err(ConversionError::message("reference block commitment does not match proposal")
            .context("reference_block_commitment"));
    }
    if decoded.account_updates != *proposed.account_updates() {
        return Err(ConversionError::message("account updates do not match proposal")
            .context("account_updates"));
    }
    if !decoded.input_notes.iter().eq(proposed.input_notes().iter()) {
        return Err(
            ConversionError::message("input notes do not match proposal").context("input_notes")
        );
    }
    if decoded.output_notes != proposed.output_notes() {
        return Err(
            ConversionError::message("output notes do not match proposal").context("output_notes")
        );
    }
    if decoded.expiration_block_num != proposed.batch_expiration_block_num() {
        return Err(ConversionError::message("expiration block does not match proposal")
            .context("expiration_block_num"));
    }
    if decoded.transactions.as_slice() != proposed.transaction_headers().as_slice() {
        return Err(ConversionError::message("transaction headers do not match proposal")
            .context("transactions"));
    }

    decoded.into_domain()
}
