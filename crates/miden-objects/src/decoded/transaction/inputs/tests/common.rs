use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use miden_protocol::account::auth::{BoundSignature, SignatureKey};
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountComponent,
    AccountComponentMetadata,
    AccountId,
    AccountIdVersion,
    AccountStorage,
    AccountStorageHeader,
    AccountType,
    AssetCallbackFlag,
    PartialAccount,
    PartialStorage,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{AssetId, AssetVault, PartialVault};
use miden_protocol::block::account_tree::AccountTree;
use miden_protocol::block::{BlockHeader, BlockNoteIndex, BlockNoteTree};
use miden_protocol::crypto::merkle::InnerNodeInfo;
use miden_protocol::crypto::merkle::smt::Smt;
use miden_protocol::crypto::merkle::store::MerkleStore;
use miden_protocol::note::{Note, NoteInclusionProof, NoteScript};
use miden_protocol::protocol_config::{
    KernelConfig,
    ProofSecurityPolicy,
    ProofVerificationConfig,
    ProtocolConfig,
};
use miden_protocol::testing::assembler::assemble_test_package;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{
    AccountInputs,
    InputNote,
    InputNotes,
    PartialBlockchain,
    TransactionArgs,
    TransactionInputs,
};
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{Felt, Word};

use crate::decoded::account::test_utils::auth_secret_keys;
use crate::proto;

pub fn dummy_word(value: u32) -> Word {
    Word::from([value, value + 1, value + 2, value + 3])
}

fn dummy_account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

fn dummy_protocol_config() -> ProtocolConfig {
    ProtocolConfig::new(
        AssetId::new_fungible(dummy_account_id(8)),
        KernelConfig::new(dummy_word(10), vec![dummy_word(11)]).unwrap(),
        KernelConfig::new(dummy_word(12), vec![dummy_word(13)]).unwrap(),
        KernelConfig::new(dummy_word(14), vec![dummy_word(15)]).unwrap(),
        ProofVerificationConfig::new(
            dummy_word(16),
            dummy_word(17),
            ProofSecurityPolicy::new(dummy_word(18), 96).unwrap(),
        ),
    )
    .unwrap()
}

fn dummy_secondary_account_code() -> AccountCode {
    const CODE: &str = "
        @account_procedure
        pub proc baz
            push.3.4 add
        end
    ";
    let package =
        assemble_test_package("miden-testing-second-account", "miden::testing::second", CODE);
    let component = AccountComponent::new(
        package,
        vec![],
        AccountComponentMetadata::new("miden::testing::second"),
    )
    .unwrap();

    AccountCode::from_components(&[NoopAuthComponent.into(), component]).unwrap()
}

/// Returns account inputs for an account with one value slot, one map slot and the given code.
fn dummy_foreign_account(account_id: AccountId, code: AccountCode) -> AccountInputs {
    let storage = AccountStorage::new(vec![
        StorageSlot::with_value(
            StorageSlotName::new("foreign::first::value").unwrap(),
            dummy_word(80),
        ),
        StorageSlot::with_empty_map(StorageSlotName::new("foreign::second::map").unwrap()),
    ])
    .unwrap();
    let account =
        Account::new_existing(account_id, AssetVault::default(), storage, code, Felt::from(3_u32));

    let mut account_tree = AccountTree::<Smt>::default();
    account_tree.insert(account_id, account.to_commitment()).unwrap();

    AccountInputs::new(PartialAccount::from(&account), account_tree.open(account_id))
}

fn dummy_advice_inputs(stack_values: [u32; 2], map_key: u32, node_value: u32) -> AdviceInputs {
    let mut stack = AdviceInputs::default().stack();
    stack.append_elements(stack_values.map(Felt::from));
    let mut store = MerkleStore::new();
    store.extend([InnerNodeInfo {
        value: dummy_word(node_value),
        left: dummy_word(node_value + 1),
        right: dummy_word(node_value + 2),
    }]);

    AdviceInputs::default()
        .with_stack(stack)
        .with_map([(dummy_word(map_key), vec![Felt::from(map_key + 1)])])
        .with_merkle_store(store)
}

/// Returns one valid signature per authentication scheme.
pub fn dummy_signatures() -> Vec<BoundSignature> {
    auth_secret_keys()
        .into_iter()
        .map(|secret_key| {
            let message = dummy_word(70);
            let key = SignatureKey::new(secret_key.public_key().to_commitment(), message);
            BoundSignature::new(key, secret_key.sign(message))
                .expect("signature should be bound to the key of its signer")
        })
        .collect()
}

fn dummy_block_header(
    blockchain: &PartialBlockchain,
    note_root: Word,
    protocol_config: &ProtocolConfig,
) -> BlockHeader {
    let base = BlockHeader::mock(
        blockchain.chain_length(),
        Some(blockchain.peaks().hash_peaks()),
        Some(note_root),
        &[],
    );
    BlockHeader::new(
        base.prev_block_commitment(),
        base.block_num(),
        base.chain_commitment(),
        base.account_root(),
        base.nullifier_root(),
        base.code_tree_root(),
        base.note_root(),
        base.transactions_commitment(),
        base.validator_config().clone(),
        base.fee_parameters().clone(),
        protocol_config.to_commitment(),
        base.next_protocol_config().cloned(),
        base.timestamp(),
    )
}

pub fn dummy_transaction_inputs() -> TransactionInputs {
    let account_code = AccountCode::mock();
    let account = PartialAccount::new(
        dummy_account_id(7),
        Felt::from(9_u32),
        account_code.clone(),
        PartialStorage::new(AccountStorageHeader::new(vec![]).unwrap(), []).unwrap(),
        PartialVault::new(dummy_word(20)),
        None,
    )
    .unwrap();

    let authenticated_note = Note::mock_noop(dummy_word(30));
    let unauthenticated_note = Note::mock_noop(dummy_word(40));
    let note_index = BlockNoteIndex::new(0, 0).unwrap();
    let note_tree =
        BlockNoteTree::with_entries([(note_index, authenticated_note.header())]).unwrap();
    let proof = NoteInclusionProof::new(
        0_u32.into(),
        note_index.leaf_index_value(),
        note_tree.open(note_index),
    )
    .unwrap();
    let input_notes = InputNotes::new(vec![
        InputNote::authenticated(authenticated_note, proof),
        InputNote::unauthenticated(unauthenticated_note.clone()),
    ])
    .unwrap();

    let protocol_config = dummy_protocol_config();
    let mut blockchain = PartialBlockchain::default();
    let note_block_header = dummy_block_header(&blockchain, note_tree.root(), &protocol_config);
    blockchain.add_block(&note_block_header, true);
    let intermediate_block_header =
        dummy_block_header(&blockchain, BlockNoteTree::empty().root(), &protocol_config);
    blockchain.add_block(&intermediate_block_header, false);
    let block_header =
        dummy_block_header(&blockchain, BlockNoteTree::empty().root(), &protocol_config);
    let tx_args = TransactionArgs::from_parts(
        None,
        dummy_word(50),
        BTreeMap::from([(unauthenticated_note.id(), dummy_word(51))]),
        vec![Note::mock_noop(dummy_word(57)).recipient().clone()],
        dummy_signatures(),
        dummy_advice_inputs([52, 53], 54, 55),
        dummy_word(56),
        None,
    );
    let foreign_accounts = vec![
        dummy_foreign_account(dummy_account_id(20), account_code),
        dummy_foreign_account(dummy_account_id(21), dummy_secondary_account_code()),
    ];

    TransactionInputs::builder()
        .account(account)
        .block_header(block_header)
        .protocol_config(protocol_config)
        .blockchain(blockchain)
        .input_notes(input_notes)
        .tx_args(tx_args)
        .foreign_accounts(foreign_accounts)
        .note_scripts(vec![NoteScript::mock()])
        .signatures(dummy_signatures())
        .build()
        .unwrap()
}

#[allow(dead_code)]
pub fn dummy_transaction_inputs_message() -> proto::transaction::TransactionInputs {
    dummy_transaction_inputs().into()
}

pub fn transaction_inputs_v1_mut(
    message: &mut proto::transaction::TransactionInputs,
) -> &mut proto::transaction::TransactionInputsV1 {
    let Some(proto::transaction::transaction_inputs::Version::V1(v1)) = message.version.as_mut()
    else {
        panic!("transaction inputs should encode as v1");
    };
    v1
}

#[allow(dead_code)]
pub fn authenticated_input_note_mut(
    message: &mut proto::transaction::TransactionInputs,
) -> &mut proto::transaction::AuthenticatedInputNote {
    let input_notes = transaction_inputs_v1_mut(message).input_notes.as_mut().unwrap();
    let Some(proto::transaction::input_note::Note::Authenticated(note)) =
        input_notes.notes[0].note.as_mut()
    else {
        panic!("first input note should be authenticated");
    };
    note
}
