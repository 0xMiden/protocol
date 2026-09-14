use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::{
    AccountId,
    AccountIdVersion,
    AccountType,
    AccountUpdateDetails,
    AssetCallbackFlag,
};
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::merkle::mmr::{Mmr, PartialMmr};
use miden_protocol::testing::dummy_execution_proof;
use miden_protocol::transaction::{
    InputNoteCommitment,
    OutputNote,
    PartialBlockchain,
    ProvenTransaction,
    TxAccountUpdate,
};
use prost::Message;

use crate::test_utils::error_source;
use crate::{BuildUnchecked, DecodeMessage, VerifyWith, proto};

fn proposal() -> ProposedBatch {
    let mut mmr = Mmr::default();
    for number in 0..3 {
        mmr.add(BlockHeader::mock(number, None, None, &[]).commitment()).unwrap();
    }
    let chain = PartialBlockchain::new(PartialMmr::from_peaks(mmr.peaks()), vec![]).unwrap();
    let header = BlockHeader::mock(3, Some(chain.peaks().hash_peaks()), None, &[]);
    let account = AccountId::dummy(
        [7; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    );
    let update = TxAccountUpdate::new(
        account,
        Word::from([1_u32; 4]),
        Word::from([2_u32; 4]),
        Word::empty(),
        AccountUpdateDetails::Private,
    )
    .unwrap();
    let transaction = ProvenTransaction::new(
        update,
        Vec::<InputNoteCommitment>::new(),
        Vec::<OutputNote>::new(),
        header.block_num(),
        header.commitment(),
        header.block_num() + 1,
        dummy_execution_proof(),
    )
    .unwrap();
    // A dummy proof is deliberate: structural decoding must not perform proof verification.
    ProposedBatch::new_unverified(vec![Arc::new(transaction)], header, chain, BTreeMap::new())
        .unwrap()
}

fn proven(proposal: &ProposedBatch) -> ProvenBatch {
    ProvenBatch::new(
        proposal.reference_block_header().commitment(),
        proposal.reference_block_header().block_num(),
        proposal.account_updates().values().cloned(),
        proposal.input_notes().clone(),
        proposal.output_notes().to_vec(),
        proposal.batch_expiration_block_num(),
        proposal.transaction_headers(),
        dummy_execution_proof(),
    )
    .unwrap()
}

#[test]
fn proposal_proofs_are_only_checked_by_explicit_verification() {
    let proposal = proposal();
    let wire: proto::transaction::ProposedBatch = (&proposal).into();
    let wire = proto::transaction::ProposedBatch::decode(wire.encode_to_vec().as_slice()).unwrap();
    let decoded = wire.decode_fields().unwrap();
    assert_eq!(decoded.transactions.len(), 1);
    let error = decoded.verify_with(96).unwrap_err();
    assert!(
        matches!(
            error_source::<miden_protocol::errors::ProposedBatchError>(&error),
            Some(
                miden_protocol::errors::ProposedBatchError::TransactionVerificationFailed { .. }
                    | miden_protocol::errors::ProposedBatchError::IncompleteTransactionProof { .. }
            )
        ),
        "{error}"
    );
}

#[test]
fn proven_batch_roundtrips_and_checks_proposal_agreement() {
    let proposal = proposal();
    let batch = proven(&proposal);
    let wire: proto::transaction::ProvenBatch = (&batch).into();
    let wire = proto::transaction::ProvenBatch::decode(wire.encode_to_vec().as_slice()).unwrap();
    assert_eq!(wire.clone().decode_fields().unwrap().build_unchecked().unwrap(), batch);
    assert_eq!(wire.decode_fields().unwrap().verify_with(&proposal).unwrap(), batch);
}

#[test]
fn proven_batch_rejects_changed_proposal_fields() {
    let proposal = proposal();
    let batch = proven(&proposal);
    for field in ["reference block number", "reference block commitment", "expiration block"] {
        let mut wire: proto::transaction::ProvenBatch = (&batch).into();
        match field {
            "reference block number" => wire.reference_block_num.as_mut().unwrap().block_num -= 1,
            "reference block commitment" => {
                wire.reference_block_commitment = Some(Word::empty().into())
            },
            "expiration block" => wire.expiration_block_num.as_mut().unwrap().block_num += 1,
            _ => unreachable!(),
        }
        let error = wire.decode_fields().unwrap().verify_with(&proposal).unwrap_err();
        assert!(
            matches!(
                error_source::<crate::decoded::transaction::ProvenBatchError>(&error),
                Some(crate::decoded::transaction::ProvenBatchError::ProposalMismatch(actual)) if *actual == field
            ),
            "{error}"
        );
    }
}
