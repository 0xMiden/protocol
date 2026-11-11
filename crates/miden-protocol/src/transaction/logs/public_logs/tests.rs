use super::*;
use crate::Word;
use crate::batch::{BatchId, OrderedBatches, ProvenBatch};
use crate::block::code_tree::CodePatch;
use crate::block::{BlockBody, BlockHeader};
use crate::errors::ProvenBatchError;
use crate::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
};
use crate::testing::dummy_execution_proof;
use crate::transaction::{
    InputNotes,
    OrderedTransactionHeaders,
    TransactionHeader,
    TransactionLog,
};

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
    let logs = PublicTransactionLogs::new(entries, headers.as_slice().iter()).unwrap();
    ProvenBatch::new_unchecked(
        BatchId::from_ids(headers.as_slice().iter().map(|tx| (tx.id(), tx.account_id()))),
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
    let public_logs = PublicTransactionLogs::new(entries.clone(), all.as_slice().iter()).unwrap();
    assert_eq!(public_logs.entries(), entries);
    public_logs.validate(all.as_slice().iter()).unwrap();
}

#[rstest::rstest]
#[case::missing(0)]
#[case::missing_empty(1)]
#[case::reordered(2)]
#[case::duplicate_entry(3)]
#[case::private_entry(4)]
#[case::extra_header(5)]
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
    let error = PublicTransactionLogs::new(entries, headers(all).as_slice().iter()).unwrap_err();
    if mutation == 6 {
        assert!(matches!(error, TransactionLogError::PublicLogsCommitmentMismatch));
    } else {
        assert!(matches!(error, TransactionLogError::PublicLogsAssociationMismatch));
    }
}

#[test]
fn transaction_uniqueness_is_enforced_by_the_owner() {
    let logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let tx = header(1, true, &logs);
    let id = tx.id();
    let all = headers(vec![tx.clone(), tx]);
    let public_logs =
        PublicTransactionLogs::new(vec![(id, logs.clone()), (id, logs)], all.as_slice().iter())
            .unwrap();
    assert!(matches!(
        checked_batch(&BlockHeader::mock(0, None, None, &[]), all, public_logs),
        Err(ProvenBatchError::DuplicateTransaction(duplicate)) if duplicate == id
    ));
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
    let body = BlockBody::new(vec![], vec![], vec![], headers, logs).unwrap();
    assert_eq!(body.public_logs().entries(), expected);
    assert_eq!(body.transactions().len(), 2);
    assert_eq!(body.transactions()[0].as_slice().len(), 1);
    assert_eq!(body.transactions()[1].as_slice().len(), 2);
}

const PUBLIC_WORD_LIMIT: usize = PublicTransactionLogs::MAX_NUM_WORDS;

fn log_limit_fixture(
    start: u32,
    count: usize,
) -> (OrderedTransactionHeaders, Vec<(TransactionId, TransactionLogs)>) {
    let mut transactions = Vec::new();
    let mut entries = Vec::new();
    let mut remaining = count;
    while remaining != 0 {
        let records = remaining.min(TransactionLogs::MAX_NUM_WORDS);
        let logs = TransactionLogs::new(vec![TransactionLog::mock(records)]).unwrap();
        let tx = header(start + transactions.len() as u32, true, &logs);
        entries.push((tx.id(), logs));
        transactions.push(tx);
        remaining -= records;
    }
    (headers(transactions), entries)
}

fn checked_batch(
    reference: &BlockHeader,
    headers: OrderedTransactionHeaders,
    public_logs: PublicTransactionLogs,
) -> Result<ProvenBatch, ProvenBatchError> {
    use crate::account::{AccountPatch, AccountUpdateDetails};
    use crate::batch::BatchAccountUpdate;

    let first = &headers.as_slice()[0];
    let last = headers.as_slice().last().unwrap();
    let update = BatchAccountUpdate::new(
        first.account_id(),
        first.initial_state_commitment(),
        last.final_state_commitment(),
        AccountUpdateDetails::Public(AccountPatch::empty(first.account_id())),
    )
    .unwrap();
    ProvenBatch::new(
        reference.commitment(),
        reference.block_num(),
        [update],
        InputNotes::default(),
        vec![],
        reference.block_num() + 2,
        headers,
        public_logs,
        dummy_execution_proof(),
    )
}

#[rstest::rstest]
#[case::exact(PUBLIC_WORD_LIMIT)]
#[case::over(PUBLIC_WORD_LIMIT + 1)]
fn public_logs_enforce_word_limit(#[case] count: usize) {
    use crate::errors::BlockBodyError;

    let (headers, entries) = log_limit_fixture(1, count);
    let result = PublicTransactionLogs::new(entries.clone(), headers.as_slice().iter());
    // Bypass collection construction to exercise the checked owners' revalidation too.
    let logs = PublicTransactionLogs { entries };
    let batch_result =
        checked_batch(&BlockHeader::mock(0, None, None, &[]), headers.clone(), logs.clone());
    let body_result = BlockBody::new(vec![], vec![], vec![], vec![headers], logs);
    if count == PUBLIC_WORD_LIMIT {
        result.unwrap();
        batch_result.unwrap();
        body_result.unwrap();
    } else {
        assert!(matches!(result, Err(TransactionLogError::PublicLogsLimitExceeded)));
        assert!(matches!(
            batch_result,
            Err(ProvenBatchError::TransactionLogs(TransactionLogError::PublicLogsLimitExceeded))
        ));
        assert!(matches!(
            body_result,
            Err(BlockBodyError::TransactionLogs(TransactionLogError::PublicLogsLimitExceeded))
        ));
    }
}

#[test]
fn zero_content_records_consume_no_word_budget() {
    let logs =
        TransactionLogs::new(vec![TransactionLog::mock(0); TransactionLogs::MAX_COUNT]).unwrap();
    let all = headers((1..=65).map(|seed| header(seed, true, &logs)).collect());
    let entries = all.as_slice().iter().map(|tx| (tx.id(), logs.clone())).collect();
    PublicTransactionLogs::new(entries, all.as_slice().iter()).unwrap();
}

#[test]
fn zero_records_preserve_mixed_header_associations() {
    // More entries than the removed batch header budget, but no public records.
    let all = headers(
        (1..=1025)
            .map(|seed| header(seed, seed % 2 == 1, &TransactionLogs::default()))
            .collect(),
    );
    let entries: Vec<_> = all
        .as_slice()
        .iter()
        .filter(|tx| tx.account_id().is_public())
        .map(|tx| (tx.id(), TransactionLogs::default()))
        .collect();
    let logs = PublicTransactionLogs::new(entries.clone(), all.as_slice().iter()).unwrap();
    assert_eq!(logs.entries(), entries);
    logs.validate(all.as_slice().iter()).unwrap();

    let mut missing = entries.clone();
    missing.pop();
    assert!(matches!(
        PublicTransactionLogs::new(missing, all.as_slice().iter()),
        Err(TransactionLogError::PublicLogsAssociationMismatch)
    ));
    let mut private = entries;
    private.insert(1, (all.as_slice()[1].id(), TransactionLogs::default()));
    assert!(matches!(
        PublicTransactionLogs::new(private, all.as_slice().iter()),
        Err(TransactionLogError::PublicLogsAssociationMismatch)
    ));
}

#[test]
fn embedded_logs_preserve_commitments() {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::block::code_tree::CodeTree;
    use crate::block::{FeeParameters, ValidatorConfig};
    use crate::crypto::SequentialCommit;
    use crate::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use crate::crypto::merkle::smt::Smt;

    let logs = TransactionLogs::new(vec![TransactionLog::mock(1)]).unwrap();
    let first = headers(vec![header(1, true, &logs), header(2, false, &logs)]);
    let second = headers(vec![header(3, true, &TransactionLogs::default())]);
    let batches = OrderedBatches::new(vec![batch(first), batch(second)]);
    let (transactions, public_logs) = batches.clone().into_transactions_and_logs();
    let body = BlockBody::new(vec![], vec![], vec![], transactions, public_logs).unwrap();
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
    // Eidos baseline includes the code-patch commitment and empty code-tree root.
    assert_eq!(
        actual,
        [
            "0x5cb11cdf0528ab43fe5cfc63f253f25d74ecfd96ba57c91153ac69f7a8d05537",
            "0x577957de0466922e904be7c499f102753cc512f549fa32394bcc6099bffdde28",
            "0x10dd664b01772b32621cd6e9adca4e26141f2690fcc06b093686abd68f9ea120",
            "0x72f293a93540767ab12e7d14197b861573a2b3be6eebc67ddea25bf579e4ad22",
            "0x8779856e29b6624ce7ca1cd4570a8b7876c837a431d99761d8f5beb30923da78",
            "0x5a551ff4c9ab413e0f9be3ba505bfa4911f50b10e955b43e15a9384fcb11a056",
            "0xa6fb10de85ebaa199561ac156e2dbc38858227ad5eea9a1eafc4dd0854c43f5b",
            "0x9d24785ce627cb2240ea5656cb580666d6d3186fdf59fc5aeac81ced2d372255"
        ]
    );
}

#[rstest::rstest]
#[case::exact(PUBLIC_WORD_LIMIT)]
#[case::over(PUBLIC_WORD_LIMIT + 1)]
fn block_rejects_combined_public_logs_over_budget(#[case] count: usize) {
    use crate::block::account_tree::{AccountIdKey, AccountTree};
    use crate::block::{BlockInputs, ProposedBlock};
    use crate::crypto::merkle::mmr::{Mmr, PartialMmr};
    use crate::crypto::merkle::smt::Smt;
    use crate::errors::ProposedBlockError;
    use crate::transaction::PartialBlockchain;

    let chain =
        PartialBlockchain::new(PartialMmr::from_peaks(Mmr::default().peaks()), vec![]).unwrap();
    let (first_headers, first_entries) = log_limit_fixture(1, PUBLIC_WORD_LIMIT / 2);
    let initial = &first_headers.as_slice()[0];
    let id = initial.account_id();
    let tree = AccountTree::new(
        Smt::with_entries([(AccountIdKey::from(id).as_word(), initial.initial_state_commitment())])
            .unwrap(),
    )
    .unwrap();
    let template = BlockHeader::mock(0, Some(chain.peaks().hash_peaks()), None, &[]);
    let reference = BlockHeader::new(
        template.prev_block_commitment(),
        template.block_num(),
        template.chain_commitment(),
        tree.root(),
        template.nullifier_root(),
        template.code_tree_root(),
        template.note_root(),
        template.transactions_commitment(),
        template.validator_config().clone(),
        template.fee_parameters().clone(),
        template.protocol_config_commitment(),
        None,
        0,
    );
    let first_logs =
        PublicTransactionLogs::new(first_entries, first_headers.as_slice().iter()).unwrap();
    let next_seed = first_headers.as_slice().len() as u32 + 1;
    let first = checked_batch(&reference, first_headers, first_logs).unwrap();
    let (second_headers, second_entries) =
        log_limit_fixture(next_seed, count - PUBLIC_WORD_LIMIT / 2);
    let second_logs =
        PublicTransactionLogs::new(second_entries, second_headers.as_slice().iter()).unwrap();
    let second = checked_batch(&reference, second_headers, second_logs).unwrap();
    let inputs = BlockInputs::new(
        reference,
        chain,
        [(id, tree.open(id))].into(),
        Default::default(),
        Default::default(),
    );
    let result = ProposedBlock::new_at(inputs, vec![first, second], 1);
    if count == PUBLIC_WORD_LIMIT {
        let body = BlockBody::from(result.unwrap());
        assert_eq!(
            body.public_logs()
                .entries()
                .iter()
                .map(|(_, logs)| logs.num_content_words())
                .sum::<usize>(),
            PUBLIC_WORD_LIMIT
        );
        body.public_logs()
            .validate(body.transactions().iter().flat_map(OrderedTransactionHeaders::as_slice))
            .unwrap();
    } else {
        assert!(
            matches!(
                result,
                Err(ProposedBlockError::TransactionLogs(
                    TransactionLogError::PublicLogsLimitExceeded
                ))
            ),
            "{result:?}"
        );
    }
}

#[rstest::rstest]
#[case::public(true)]
#[case::private(false)]
fn block_rejects_transaction_repeated_across_distinct_batches(#[case] public: bool) {
    use crate::account::{AccountPatch, AccountUpdateDetails};
    use crate::batch::BatchAccountUpdate;
    use crate::block::{BlockInputs, ProposedBlock};
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
        let logs = PublicTransactionLogs::new(
            if public { entries } else { vec![] },
            headers.as_slice().iter(),
        )
        .unwrap();
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
            Err(ProposedBlockError::DuplicateTransaction(id)) if id == a.id()
        ),
        "{result:?}"
    );
}
