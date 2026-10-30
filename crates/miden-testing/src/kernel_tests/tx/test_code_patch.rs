//! Tests the verification of code witnesses by the transaction kernel.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::ExecutionOutput;
use miden_protocol::account::{Account, AccountCode, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::code::ProcedureRoot;
use miden_protocol::errors::tx_kernel::{
    ERR_CODE_PATCH_HINT_INDEX_OUT_OF_BOUNDS,
    ERR_CODE_PATCH_HINT_ROOT_MISMATCH,
    ERR_CODE_PATCH_INVALID_HINT,
    ERR_NOTE_INVALID_RECIPIENT_PREIMAGE,
};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{ACCOUNT_ID_PRIVATE_SENDER, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::transaction::memory::{
    CODE_PATCH_LIST_ROOTS_OFFSET,
    CREATED_PROCS_LIST_PTR,
    DEPENDENCIES_LIST_PTR,
    MemoryAddress,
    PRESENT_TOP_LEVEL_LIST_PTR,
};
use miden_protocol::{Felt, ProtocolLib, WORD_SIZE, Word};
use miden_standards::StandardsLib;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::mock_account_code::MockAccountCodeExt;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::TransactionExecutor;
use miden_tx::auth::UnreachableAuth;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use super::ExecutionOutputExt;
use crate::mock_transaction::TestTransactionBuilder;
use crate::{AccountState, Auth, MockChain, assert_execution_error};

// TESTS
// ================================================================================================

/// Present note scripts go into the present top-level list and absent note scripts into the list
/// of created procedures, together with the procedures they reference. Repeated roots and private
/// notes do not change the lists.
#[tokio::test]
async fn note_scripts_are_put_into_code_patch_lists() -> anyhow::Result<()> {
    let p2id_note = create_p2id_note(1)?;
    let custom_note = create_custom_note(ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 2)?;
    let notes = [
        p2id_note.clone(),
        custom_note.clone(),
        create_p2id_note(3)?,
        create_custom_note(ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 4)?,
        create_custom_note(ACTIVE_NOTE_SCRIPT, NoteType::Private, 5)?,
    ];

    let exec_output = TestTransactionBuilder::with_existing_mock_account()
        .expected_output_notes(notes.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?
        .execute_code(&verify_note_scripts_code(&notes))
        .await?;

    assert_eq!(
        code_patch_list(&exec_output, PRESENT_TOP_LEVEL_LIST_PTR),
        [script_root(&p2id_note)]
    );
    assert_eq!(
        code_patch_list(&exec_output, CREATED_PROCS_LIST_PTR),
        [script_root(&custom_note)]
    );
    assert_eq!(
        code_patch_list(&exec_output, DEPENDENCIES_LIST_PTR),
        [protocol_procedure("miden::protocol::active_account::get_id")?]
    );

    Ok(())
}

/// The data store receives one request for the missing witnesses. It does not contain the script
/// of a private note that the transaction created before, so that the data store does not learn
/// it.
#[tokio::test]
async fn bulk_request_leaves_out_created_private_notes() -> anyhow::Result<()> {
    let private_note = create_custom_note(ACTIVE_NOTE_SCRIPT, NoteType::Private, 1)?;
    let public_note = create_custom_note(ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 2)?;
    let notes = [private_note, public_note.clone()];

    let create_notes = notes
        .iter()
        .map(|note| {
            format!(
                "
                push.{recipient}
                push.{note_type}
                push.{tag}
                call.::mock::account::create_note
                drop dropw drop
                ",
                recipient = note.recipient().digest(),
                note_type = Felt::from(note.metadata().note_type()),
                tag = Felt::from(note.metadata().tag()),
            )
        })
        .collect::<String>();
    let tx_script = CodeBuilder::with_mock_packages()
        .compile_tx_script(format!("@transaction_script\npub proc main\n{create_notes}\nend"))?;

    let mock_tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .expected_output_notes(notes.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?;

    // The transaction is executed through the executor, so that the host learns the types of the
    // created notes, and the mock transaction keeps the requests it received.
    TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx)
        .execute_transaction(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            mock_tx.input_notes().clone(),
            mock_tx.tx_args().clone(),
        )
        .await?;

    let requests = mock_tx.code_witness_requests();
    assert_eq!(requests.len(), 1);
    let requested_roots =
        requests[0].iter().map(|request| request.procedure_root()).collect::<Vec<_>>();
    assert_eq!(requested_roots, [script_root(&public_note)]);

    Ok(())
}

/// A present top-level root that an absent note script references goes into the dependencies.
#[tokio::test]
async fn referenced_present_top_level_root_is_a_dependency() -> anyhow::Result<()> {
    let p2id_note = create_p2id_note(1)?;
    let custom_note = create_custom_note(P2ID_REFERENCING_SCRIPT, NoteType::Public, 2)?;
    // The kernel verifies the notes from the last to the first, so the P2ID script is verified as
    // a top-level root before the custom note references it.
    let notes = [custom_note.clone(), p2id_note.clone()];

    let exec_output = TestTransactionBuilder::with_existing_mock_account()
        .expected_output_notes(notes.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?
        .execute_code(&verify_note_scripts_code(&notes))
        .await?;

    assert_eq!(
        code_patch_list(&exec_output, PRESENT_TOP_LEVEL_LIST_PTR),
        [script_root(&p2id_note)]
    );
    assert_eq!(
        code_patch_list(&exec_output, CREATED_PROCS_LIST_PTR),
        [script_root(&custom_note)]
    );
    assert_eq!(code_patch_list(&exec_output, DEPENDENCIES_LIST_PTR), [script_root(&p2id_note)]);

    Ok(())
}

/// An absent procedure that an absent note script references is a created procedure, and the
/// kernel also verifies the procedures that it references.
#[tokio::test]
async fn referenced_absent_procedure_is_a_created_procedure() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;

    // The mock account procedure is absent from the genesis code tree, and its code is available
    // through the account code.
    let mock_procedure = ProcedureRoot::from_raw(
        AccountCode::mock_account_package()
            .get_procedure_root_by_path("mock::account::get_nonce")
            .context("mock account package should export get_nonce")?,
    );
    let note = NoteBuilder::new(account.id(), SmallRng::seed_from_u64(1))
        .code(MOCK_PROCEDURE_REFERENCING_SCRIPT)
        .dynamically_linked_packages(CodeBuilder::mock_packages())
        .build()?;

    let exec_output = mock_chain
        .build_transaction(account.id())
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute_code(&verify_note_scripts_code(core::slice::from_ref(&note)))
        .await?;

    assert_eq!(
        code_patch_list(&exec_output, CREATED_PROCS_LIST_PTR),
        [script_root(&note), mock_procedure]
    );
    let dependencies = code_patch_list(&exec_output, DEPENDENCIES_LIST_PTR);
    assert!(
        dependencies.contains(&protocol_procedure("miden::protocol::active_account::get_nonce")?)
    );
    for dependency in dependencies {
        assert!(mock_chain.code_tree().contains(&dependency));
    }

    Ok(())
}

/// The procedures of a new public account are verified, while those of a new private account are
/// not.
#[rstest::rstest]
#[case::public(AccountType::Public)]
#[case::private(AccountType::Private)]
#[tokio::test]
async fn new_account_procedures_are_verified_if_public(
    #[case] account_type: AccountType,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_account_from_builder(
        Auth::IncrNonce,
        Account::builder([5; 32])
            .account_type(account_type)
            .with_component(MockAccountComponent::with_empty_slots()),
        AccountState::New,
    )?;
    let mock_chain = builder.build()?;

    let exec_output = mock_chain
        .build_transaction(account.clone())
        .build()?
        .execute_code(&verify_note_scripts_code(&[]))
        .await?;

    let mut verified_roots = code_patch_list(&exec_output, PRESENT_TOP_LEVEL_LIST_PTR);
    verified_roots.extend(code_patch_list(&exec_output, CREATED_PROCS_LIST_PTR));

    if account_type.is_public() {
        let procedure_roots = account
            .code()
            .procedure_roots()
            .map(ProcedureRoot::from_raw)
            .collect::<BTreeSet<_>>();
        assert_eq!(verified_roots.into_iter().collect::<BTreeSet<_>>(), procedure_roots);
        for procedure_root in code_patch_list(&exec_output, CREATED_PROCS_LIST_PTR) {
            assert!(!mock_chain.code_tree().contains(&procedure_root));
        }
    } else {
        assert!(verified_roots.is_empty());
        assert!(code_patch_list(&exec_output, DEPENDENCIES_LIST_PTR).is_empty());
    }

    Ok(())
}

/// The kernel rejects a hint that does not point to the hinted root in a code patch list.
#[rstest::rstest]
#[case::invalid_list(0, 4, ERR_CODE_PATCH_INVALID_HINT)]
#[case::index_out_of_bounds(1, 2, ERR_CODE_PATCH_HINT_INDEX_OUT_OF_BOUNDS)]
#[case::root_mismatch(0, 2, ERR_CODE_PATCH_HINT_ROOT_MISMATCH)]
#[tokio::test]
async fn invalid_hint_is_rejected(
    #[case] index: u32,
    #[case] hint_kind: u32,
    #[case] expected_error: miden_protocol::errors::MasmError,
) -> anyhow::Result<()> {
    // The kernel verifies the notes from the last to the first. The script of the last note is
    // verified as a present top-level root, so the present top-level list contains one root when
    // the kernel reads the hint for the first note.
    let custom_note = create_custom_note(ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 2)?;
    let notes = [custom_note.clone(), create_p2id_note(1)?];

    let result = TestTransactionBuilder::with_existing_mock_account()
        .expected_output_notes(notes.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?
        .execute_code_with_code_root_hint(
            &verify_note_scripts_code(&notes),
            script_root(&custom_note),
            [Felt::from(index), Felt::from(hint_kind)],
        )
        .await;

    assert_execution_error!(result, expected_error);

    Ok(())
}

/// The kernel rejects a recipient preimage that does not hash to the recipient of a public note,
/// so that a script root cannot be claimed for the note.
#[tokio::test]
async fn invalid_recipient_preimage_is_rejected() -> anyhow::Result<()> {
    let note = create_p2id_note(1)?;
    let invalid_preimage = [Word::from([1, 2, 3, 4u32]), Word::from([5, 6, 7, 8u32])]
        .into_iter()
        .flat_map(|word| word.into_iter())
        .collect();

    // The note is not an expected output note, so the advice map contains only the invalid
    // preimage of its recipient.
    let result = TestTransactionBuilder::with_existing_mock_account()
        .add_advice_map_entry(note.recipient().digest(), invalid_preimage)
        .build()?
        .execute_code(&verify_note_scripts_code(&[note]))
        .await;

    assert_execution_error!(result, ERR_NOTE_INVALID_RECIPIENT_PREIMAGE);

    Ok(())
}

// HELPERS
// ================================================================================================

/// A note script that references a procedure of the protocol library.
const ACTIVE_ACCOUNT_SCRIPT: &str = "
    use miden::protocol::active_account

    @note_script
    pub proc main
        exec.active_account::get_id drop drop
    end
";

/// Another note script that references a procedure of the protocol library.
const ACTIVE_NOTE_SCRIPT: &str = "
    use miden::protocol::active_account

    @note_script
    pub proc main
        exec.active_account::get_nonce drop
    end
";

/// A note script that references the script of the P2ID note. The script also contains its own
/// code, so that its root differs from the root of the P2ID script.
const P2ID_REFERENCING_SCRIPT: &str = "
    use miden::standards::notes::p2id

    @note_script
    pub proc main
        push.1 drop
        exec.p2id::main
    end
";

/// A note script that references a procedure of the mock account, which in turn references a
/// procedure of the protocol library.
const MOCK_PROCEDURE_REFERENCING_SCRIPT: &str = "
    @note_script
    pub proc main
        call.::mock::account::get_nonce dropw dropw dropw dropw
    end
";

/// Returns a public P2ID note, whose script is present in the genesis code tree.
fn create_p2id_note(seed: u32) -> anyhow::Result<Note> {
    Ok(Note::from(
        P2idNote::builder()
            .sender(ACCOUNT_ID_SENDER.try_into()?)
            .target(ACCOUNT_ID_PRIVATE_SENDER.try_into()?)
            .serial_number(Word::from([seed, 0, 0, 0]))
            .asset(FungibleAsset::mock(10))
            .note_type(NoteType::Public)
            .build()?,
    ))
}

/// Returns a note with the provided script, which is absent from the genesis code tree.
fn create_custom_note(code: &str, note_type: NoteType, seed: u64) -> anyhow::Result<Note> {
    Ok(NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, SmallRng::seed_from_u64(seed))
        .note_type(note_type)
        .code(code)
        .dynamically_linked_packages([StandardsLib::default().package().as_ref().clone()])
        .build()?)
}

/// Returns the code that creates the provided notes and verifies the top-level roots of the
/// transaction.
fn verify_note_scripts_code(notes: &[Note]) -> String {
    let create_notes = notes
        .iter()
        .map(|note| {
            format!(
                "
                push.{recipient}
                push.{note_type}
                push.{tag}
                call.::mock::account::create_note
                dropw drop drop
                ",
                recipient = note.recipient().digest(),
                note_type = Felt::from(note.metadata().note_type()),
                tag = Felt::from(note.metadata().tag()),
            )
        })
        .collect::<String>();

    format!(
        "
        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::code_patch
        use miden::core::sys

        begin
            exec.prologue::prepare_transaction
            {create_notes}
            exec.code_patch::verify_before_auth
            exec.sys::truncate_stack
        end
        "
    )
}

/// Returns the procedure roots in the code patch list at the provided memory address.
fn code_patch_list(exec_output: &ExecutionOutput, list_ptr: MemoryAddress) -> Vec<ProcedureRoot> {
    let num_roots = exec_output.get_kernel_mem_element(list_ptr).as_canonical_u64() as u32;
    (0..num_roots)
        .map(|root_idx| {
            let root_ptr =
                list_ptr + CODE_PATCH_LIST_ROOTS_OFFSET + root_idx * WORD_SIZE as MemoryAddress;
            ProcedureRoot::from_raw(exec_output.get_kernel_mem_word(root_ptr))
        })
        .collect()
}

/// Returns the script root of the note as a procedure root.
fn script_root(note: &Note) -> ProcedureRoot {
    ProcedureRoot::from_raw(note.script().root().into())
}

/// Returns the root of the procedure of the protocol library with the provided path.
fn protocol_procedure(path: &str) -> anyhow::Result<ProcedureRoot> {
    ProtocolLib::default()
        .package()
        .get_procedure_root_by_path(path)
        .map(ProcedureRoot::from_raw)
        .with_context(|| format!("protocol library should export {path}"))
}
