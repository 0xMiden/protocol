use super::*;
use crate::Word;
use crate::batch::{OrderedBatches, ProvenBatch};
use crate::block::code_tree::CodePatch;
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
        CodePatch::default().commitment(),
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
    assert_eq!(body.transactions().len(), 2);
    assert_eq!(body.transactions()[0].as_slice().len(), 1);
    assert_eq!(body.transactions()[1].as_slice().len(), 2);
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

    use crate::block::code_tree::CodeTree;
    use crate::block::{BlockHeader, FeeParameters, ValidatorConfig};
    use crate::crypto::SequentialCommit;
    use crate::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use crate::crypto::merkle::smt::Smt;

    let logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let first = headers(vec![header(1, true, &logs), header(2, false, &logs)]);
    let second = headers(vec![header(3, true, &TransactionLogs::default())]);
    let batches = OrderedBatches::new(vec![batch(first), batch(second)]);
    let (transactions, public_logs) = batches.clone().into_transactions_and_logs();
    let body =
        crate::block::BlockBody::new(vec![], vec![], vec![], transactions, public_logs).unwrap();
    assert_eq!(body.compute_batches_commitment().as_word(), batches.to_commitment());
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    let key = SigningKey::with_rng(&mut rng);
    let block = BlockHeader::new(
        Word::empty(),
        1.into(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        CodeTree::<Smt>::default().root(),
        Word::empty(),
        body.compute_transactions_commitment(),
        ValidatorConfig::from_signers(&[key]),
        FeeParameters::new(500),
        Word::empty(),
        None,
        1234,
    );
    let actual: Vec<_> = body
        .transactions()
        .iter()
        .flat_map(OrderedTransactionHeaders::as_slice)
        .map(|tx| tx.id().to_hex())
        .chain(batches.as_slice().iter().map(|batch| batch.id().to_hex()))
        .chain(
            [
                batches.to_commitment(),
                body.compute_transactions_commitment(),
                block.commitment(),
            ]
            .map(|word| word.to_hex()),
        )
        .collect();
    // Baseline includes the upstream code-patch commitment and empty code-tree root.
    assert_eq!(
        actual,
        [
            "0xc74558e2e9e86192d49a0579c545d6db3ddbb7a85a9b31c136ee7035b2e1ffe6",
            "0x80ff8be6343d57daf2743f41adff45bd766b17f1b0dc9208955fdfb395030410",
            "0x2da04a4c294fcf8e6a7f0c01583fd2f2b3499449a58b07e87fbab3e0ce0400ba",
            "0xeb96f7fb3518c0da190253191f70ded5e509c8a34703f1da757bcd1855d112d7",
            "0xc4ea288c66f2fb3fe13e0e6c922fba9044a03468190c3af1f32c94d41e3ff79f",
            "0x6d272412d571ab822400d41c608da9cb2d672230093f3afbe167dc9fd9d13bf5",
            "0x7ed1aedead6a64f22f8b74cef73f96fdb91bd85bd6ebe56d933fdcfd5109472e",
            "0xde56918d2eb7d0eac2dd9c69579c0fe746df6da87d8160af82b65d24aa8ee2d9"
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

#[rstest::rstest]
#[case::public(true)]
#[case::private(false)]
fn block_rejects_transaction_repeated_across_distinct_batches(#[case] public: bool) {
    use crate::account::{AccountPatch, AccountUpdateDetails};
    use crate::batch::BatchAccountUpdate;
    use crate::block::{BlockHeader, BlockInputs, ProposedBlock};
    use crate::crypto::merkle::mmr::{Mmr, PartialMmr};
    use crate::errors::ProposedBlockError;
    use crate::transaction::PartialBlockchain;

    let chain =
        PartialBlockchain::new(PartialMmr::from_peaks(Mmr::default().peaks()), vec![]).unwrap();
    let reference = BlockHeader::mock(0, Some(chain.peaks().hash_peaks()), None, &[]);
    let timestamp = reference.timestamp().checked_add(1).unwrap();
    let id = if public {
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE
    } else {
        ACCOUNT_ID_PRIVATE_SENDER
    }
    .try_into()
    .unwrap();
    let state = Word::from([1u32; 4]);
    let a_logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let b_logs = TransactionLogs::new(vec![TransactionLog::mock(2)]).unwrap();
    let tx = |logs: &TransactionLogs| {
        TransactionHeader::new(
            id,
            state,
            state,
            InputNotes::default(),
            vec![],
            logs.commitment(),
            CodePatch::default().commitment(),
        )
        .unwrap()
    };
    let a = tx(&a_logs);
    let b = tx(&b_logs);
    let make_batch = |transactions: Vec<TransactionHeader>, entries| {
        let headers = headers(transactions);
        let logs =
            PublicTransactionLogs::new(if public { entries } else { vec![] }, &headers).unwrap();
        ProvenBatch::new(
            reference.commitment(),
            reference.block_num(),
            [BatchAccountUpdate::new(
                id,
                state,
                state,
                if public {
                    AccountUpdateDetails::Public(AccountPatch::empty(id))
                } else {
                    AccountUpdateDetails::Private
                },
            )
            .unwrap()],
            InputNotes::default(),
            vec![],
            2.into(),
            headers,
            logs,
            dummy_execution_proof(),
        )
        .unwrap()
    };
    // Both batches pass their checked constructor and have different IDs, but share A.
    let first = make_batch(vec![a.clone()], vec![(a.id(), a_logs.clone())]);
    let second = make_batch(vec![a.clone(), b.clone()], vec![(a.id(), a_logs), (b.id(), b_logs)]);
    assert_ne!(first.id(), second.id());
    let inputs = BlockInputs::new(
        reference,
        chain,
        Default::default(),
        Default::default(),
        Default::default(),
    );
    let result = ProposedBlock::new_at(inputs, vec![first, second], timestamp);
    assert!(
        matches!(
            result,
            Err(ProposedBlockError::TransactionLogs(
                TransactionLogError::PublicLogsAssociationMismatch
            ))
        ),
        "{result:?}"
    );
}
