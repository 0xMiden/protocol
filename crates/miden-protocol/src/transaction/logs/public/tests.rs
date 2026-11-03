use super::*;
use crate::Word;
use crate::batch::{OrderedBatches, ProvenBatch};
use crate::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
};
use crate::testing::dummy_execution_proof;
use crate::transaction::{InputNotes, TransactionHeader, TransactionLog};

fn header(seed: u32, public: bool, logs: &TransactionLogs) -> TransactionHeader {
    TransactionHeader::new(
        if public {
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE
        } else {
            ACCOUNT_ID_PRIVATE_SENDER
        }
        .try_into()
        .unwrap(),
        Word::from([seed; 4]),
        Word::from([seed + 1; 4]),
        InputNotes::default(),
        vec![],
        logs.commitment(),
    )
    .unwrap()
}

fn headers(values: Vec<TransactionHeader>) -> OrderedTransactionHeaders {
    OrderedTransactionHeaders::new_unchecked(values)
}

fn batch(headers: OrderedTransactionHeaders) -> ProvenBatch {
    let entries = headers
        .as_slice()
        .iter()
        .filter(|tx| tx.account_id().is_public())
        .map(|tx| {
            let logs = if tx.logs_commitment() == Word::empty() {
                TransactionLogs::default()
            } else {
                TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap()
            };
            (tx.id(), logs)
        })
        .collect();
    let logs = PublicTransactionLogs::new(entries, &headers).unwrap();
    ProvenBatch::new_unchecked(
        crate::batch::BatchId::from_ids(
            headers.as_slice().iter().map(|tx| (tx.id(), tx.account_id())),
        ),
        Word::empty(),
        0.into(),
        Default::default(),
        InputNotes::default(),
        vec![],
        1.into(),
        headers,
        logs,
        dummy_execution_proof(),
    )
    .unwrap()
}

#[test]
fn public_logs_match_native_public_headers() {
    let log = TransactionLog::mock(1);
    let logs = TransactionLogs::new(vec![log.clone(), log]).unwrap();
    let public = header(1, true, &logs);
    let private = header(2, false, &logs);
    let empty = header(3, true, &TransactionLogs::default());
    let entries = vec![(public.id(), logs), (empty.id(), TransactionLogs::default())];
    let all = headers(vec![public, private, empty]);
    let public_logs = PublicTransactionLogs::new(entries.clone(), &all).unwrap();
    assert_eq!(public_logs.entries(), entries);
    public_logs.validate_for_batch(&all).unwrap();
}

#[rstest::rstest]
#[case::missing(0)]
#[case::missing_empty(1)]
#[case::reordered(2)]
#[case::duplicate_entry(3)]
#[case::private_entry(4)]
#[case::duplicate_header(5)]
#[case::hash_mismatch(6)]
fn rejects_invalid_public_logs(#[case] mutation: u8) {
    let logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let public = header(1, true, &logs);
    let private = header(2, false, &logs);
    let empty = header(3, true, &TransactionLogs::default());
    let mut entries = vec![(public.id(), logs.clone()), (empty.id(), TransactionLogs::default())];
    let mut all = vec![public.clone(), private.clone(), empty];
    match mutation {
        0 => entries.clear(),
        1 => {
            entries.pop();
        },
        2 => entries.swap(0, 1),
        3 => entries[1] = entries[0].clone(),
        4 => entries.insert(1, (private.id(), logs)),
        5 => all.push(public),
        6 => entries[0].1 = TransactionLogs::default(),
        _ => unreachable!(),
    }
    let error = PublicTransactionLogs::new(entries, &headers(all)).unwrap_err();
    if mutation == 6 {
        assert!(matches!(error, TransactionLogError::PublicLogsCommitmentMismatch));
    } else {
        assert!(matches!(error, TransactionLogError::PublicLogsAssociationMismatch));
    }
}

#[test]
fn block_body_preserves_public_logs() {
    let logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let public = header(1, true, &logs);
    let empty = header(3, true, &TransactionLogs::default());
    let batches = OrderedBatches::new(vec![
        batch(headers(vec![public.clone()])),
        batch(headers(vec![header(2, false, &logs), empty.clone()])),
    ]);
    let expected = vec![(public.id(), logs), (empty.id(), TransactionLogs::default())];
    let (headers, logs) = batches.into_transactions_and_logs();
    let body = crate::block::BlockBody::new(vec![], vec![], vec![], headers, logs).unwrap();
    assert_eq!(body.public_logs().entries(), expected);
}

#[rstest::rstest]
#[case::batch(PublicLogLimits::BATCH)]
#[case::block(PublicLogLimits::BLOCK)]
fn aggregate_public_logs_limits(#[case] limits: PublicLogLimits) {
    limits
        .check(limits.transactions(), limits.logs(), limits.content_words())
        .unwrap();
    for (transactions, logs, words) in [
        (limits.transactions() + 1, 0, 0),
        (0, limits.logs() + 1, 0),
        (0, 0, limits.content_words() + 1),
    ] {
        assert!(matches!(
            limits.check(transactions, logs, words),
            Err(TransactionLogError::PublicLogsLimitExceeded)
        ));
    }
}

#[test]
fn embedded_logs_preserve_commitments() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::block::{BlockHeader, FeeParameters, ValidatorConfig};
    use crate::crypto::SequentialCommit;
    use crate::crypto::dsa::ecdsa_k256_keccak::SigningKey;

    let logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let first = headers(vec![header(1, true, &logs), header(2, false, &logs)]);
    let second = headers(vec![header(3, true, &TransactionLogs::default())]);
    let batches = OrderedBatches::new(vec![batch(first), batch(second)]);
    let transactions = batches.to_transactions();
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    let key = SigningKey::with_rng(&mut rng);
    let block = BlockHeader::new(
        Word::empty(),
        1.into(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        transactions.commitment(),
        ValidatorConfig::from_signers(&[key]),
        FeeParameters::new(500),
        Word::empty(),
        None,
        1234,
    );
    let actual: Vec<_> = transactions
        .as_slice()
        .iter()
        .map(|tx| tx.id().to_hex())
        .chain(batches.as_slice().iter().map(|batch| batch.id().to_hex()))
        .chain(
            [batches.to_commitment(), transactions.commitment(), block.commitment()]
                .map(|word| word.to_hex()),
        )
        .collect();
    assert_eq!(
        actual,
        [
            "0x1a0aa1dbc5d96d8d7605770a308bbd10eb054ca0157ecda72777ff225f2847df",
            "0x99b9277c38543218c245109fb0fd17b596ab2c10f94a75486961689dc9f789c5",
            "0x653c2a15819b4df9b0d045f5ee6057b8618c8fc147d623bcb8a9ebc0bdc63606",
            "0x1dcae8787c787c4094ffc7008849098ff22c913b2cffbbb2de26d72e96aa0260",
            "0x2cfa600b5f889f668b27c471586074d064ef1f5234e900d05ed5591162e2878d",
            "0xdb87e02da20bac5bfa24e2c16526f3b3d6f40cb1ad8b1857120e3bd9655a2ce8",
            "0x89b017ac78a42b2cbea32e2c4221a23f86a0f0ae7766a807b33b5f4ebfce41a1",
            "0xc144699926a73ccf34c836a1a2c673cf8dc4a76fa129e66671131dc03a8553cc"
        ]
    );
}

#[test]
fn block_rejects_combined_public_logs_over_budget() {
    use crate::block::{BlockHeader, BlockInputs, ProposedBlock};
    use crate::crypto::merkle::mmr::{Mmr, PartialMmr};
    use crate::errors::ProposedBlockError;
    use crate::transaction::PartialBlockchain;

    let logs =
        TransactionLogs::new(vec![TransactionLog::mock(TransactionLogs::MAX_NUM_WORDS)]).unwrap();
    let mut batches = Vec::new();
    // Each batch exactly fills its word budget, while the ninth exceeds the block word budget.
    for batch_index in 0..9 {
        let headers = headers(
            (0..PublicLogLimits::BATCH.transactions())
                .map(|index| {
                    header(
                        (batch_index * PublicLogLimits::BATCH.transactions() + index + 1) as u32,
                        true,
                        &logs,
                    )
                })
                .collect(),
        );
        let entries = headers.as_slice().iter().map(|header| (header.id(), logs.clone())).collect();
        let public_logs = PublicTransactionLogs::new(entries, &headers).unwrap();
        public_logs.validate_for_batch(&headers).unwrap();
        batches.push(
            ProvenBatch::new_unchecked(
                crate::batch::BatchId::from_ids(
                    headers.as_slice().iter().map(|tx| (tx.id(), tx.account_id())),
                ),
                Word::empty(),
                0.into(),
                Default::default(),
                InputNotes::default(),
                vec![],
                1.into(),
                headers,
                public_logs,
                dummy_execution_proof(),
            )
            .unwrap(),
        );
    }
    let inputs = BlockInputs::new(
        BlockHeader::mock(0, None, None, &[]),
        PartialBlockchain::new(PartialMmr::from_peaks(Mmr::default().peaks()), vec![]).unwrap(),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert!(matches!(
        ProposedBlock::new_at(inputs, batches, 1),
        Err(ProposedBlockError::TransactionLogs(
            TransactionLogError::PublicLogsLimitExceeded
        ))
    ));
}
