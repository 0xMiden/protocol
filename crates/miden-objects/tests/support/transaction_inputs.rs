use std::collections::BTreeMap;

use miden_objects::proto;
use miden_protocol::account::{
    AccountCode,
    AccountComponent,
    AccountComponentMetadata,
    AccountId,
    AccountIdVersion,
    AccountStorageHeader,
    AccountType,
    AssetCallbackFlag,
    PartialAccount,
    PartialStorage,
    StorageSlotName,
};
use miden_protocol::asset::{AssetId, PartialVault};
use miden_protocol::block::{BlockHeader, BlockNoteIndex, BlockNoteTree};
use miden_protocol::crypto::merkle::InnerNodeInfo;
use miden_protocol::crypto::merkle::store::MerkleStore;
use miden_protocol::note::{Note, NoteInclusionProof};
use miden_protocol::protocol_config::{
    KernelConfig,
    ProofSecurityPolicy,
    ProofVerificationConfig,
    ProtocolConfig,
};
use miden_protocol::testing::assembler::assemble_test_package;
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{
    InputNote,
    InputNotes,
    PartialBlockchain,
    TransactionArgs,
    TransactionInputs,
};
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{Felt, Word};

pub fn word(value: u32) -> Word {
    Word::from([value, value + 1, value + 2, value + 3])
}

fn account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

fn protocol_config() -> ProtocolConfig {
    ProtocolConfig::new(
        AssetId::new_fungible(account_id(8)),
        KernelConfig::new(word(10), vec![word(11)]).unwrap(),
        KernelConfig::new(word(12), vec![word(13)]).unwrap(),
        KernelConfig::new(word(14), vec![word(15)]).unwrap(),
        ProofVerificationConfig::new(
            word(16),
            word(17),
            ProofSecurityPolicy::new(word(18), 96).unwrap(),
        ),
    )
    .unwrap()
}

fn second_account_code() -> AccountCode {
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

fn advice_inputs(stack_values: [u32; 2], map_key: u32, node_value: u32) -> AdviceInputs {
    let mut stack = AdviceInputs::default().advice_stack();
    stack.append_elements(stack_values.map(Felt::from));
    let mut store = MerkleStore::new();
    store.extend([InnerNodeInfo {
        value: word(node_value),
        left: word(node_value + 1),
        right: word(node_value + 2),
    }]);

    AdviceInputs::default()
        .with_advice_stack(stack)
        .with_map([(word(map_key), vec![Felt::from(map_key + 1)])])
        .with_merkle_store(store)
}

fn block_header(
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
        base.note_root(),
        base.tx_commitment(),
        base.validator_config().clone(),
        base.fee_parameters().clone(),
        protocol_config.to_commitment(),
        base.next_protocol_config().cloned(),
        base.timestamp(),
    )
}

pub fn transaction_inputs() -> TransactionInputs {
    let account_code = AccountCode::mock();
    let account = PartialAccount::new(
        account_id(7),
        Felt::from(9_u32),
        account_code.clone(),
        PartialStorage::new(AccountStorageHeader::new(vec![]).unwrap(), []).unwrap(),
        PartialVault::new(word(20)),
        None,
    )
    .unwrap();

    let authenticated_note = Note::mock_noop(word(30));
    let unauthenticated_note = Note::mock_noop(word(40));
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

    let protocol_config = protocol_config();
    let mut blockchain = PartialBlockchain::default();
    let note_block_header = block_header(&blockchain, note_tree.root(), &protocol_config);
    blockchain.add_block(&note_block_header, true);
    let intermediate_block_header =
        block_header(&blockchain, BlockNoteTree::empty().root(), &protocol_config);
    blockchain.add_block(&intermediate_block_header, false);
    let block_header = block_header(&blockchain, BlockNoteTree::empty().root(), &protocol_config);
    let tx_args = TransactionArgs::from_parts(
        None,
        word(50),
        BTreeMap::from([(unauthenticated_note.id(), word(51))]),
        advice_inputs([52, 53], 54, 55),
        word(56),
    );
    let advice_inputs = advice_inputs([60, 61], 62, 63);
    let foreign_account_code = vec![account_code, second_account_code()];
    let first_slot = StorageSlotName::new("foreign::first::value").unwrap();
    let second_slot = StorageSlotName::new("foreign::second::map").unwrap();
    let foreign_account_slot_names =
        BTreeMap::from([(second_slot.id(), second_slot), (first_slot.id(), first_slot)]);

    TransactionInputs::try_from_parts(
        account,
        block_header,
        protocol_config,
        blockchain,
        input_notes,
        tx_args,
        advice_inputs,
        foreign_account_code,
        foreign_account_slot_names,
    )
    .unwrap()
}

#[allow(dead_code)]
pub fn transaction_inputs_message() -> proto::transaction::TransactionInputs {
    transaction_inputs().into()
}

pub fn transaction_inputs_v1(
    message: &mut proto::transaction::TransactionInputs,
) -> &mut proto::transaction::TransactionInputsV1 {
    let Some(proto::transaction::transaction_inputs::Version::V1(v1)) = message.version.as_mut()
    else {
        panic!("transaction inputs should encode as v1");
    };
    v1
}

#[allow(dead_code)]
pub fn authenticated_input_note(
    message: &mut proto::transaction::TransactionInputs,
) -> &mut proto::transaction::AuthenticatedInputNote {
    let input_notes = transaction_inputs_v1(message).input_notes.as_mut().unwrap();
    let Some(proto::transaction::input_note::Note::Authenticated(note)) =
        input_notes.notes[0].note.as_mut()
    else {
        panic!("first input note should be authenticated");
    };
    note
}
