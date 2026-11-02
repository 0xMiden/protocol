//! Tests the creation of the code patch by the transaction kernel.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::{ExecutionError, ExecutionOutput};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountCode,
    AccountComponent,
    AccountType,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::code::ProcedureRoot;
use miden_protocol::errors::MasmError;
use miden_protocol::errors::tx_kernel::{
    ERR_CODE_PATCH_ALREADY_CREATED,
    ERR_CODE_PATCH_CREATED_OUTSIDE_AUTH,
    ERR_CODE_PATCH_MAX_ROOTS_EXCEEDED,
    ERR_CODE_PATCH_PROC_ROOT_PRESENCE_MISMATCH,
    ERR_CODE_PATCH_TOP_LEVEL_ROOT_MISSING,
    ERR_EPILOGUE_CODE_PATCH_NOT_CREATED,
    ERR_MEM_WORDS_NOT_STRICTLY_SORTED,
    ERR_NOTE_INVALID_RECIPIENT_PREIMAGE,
};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{ACCOUNT_ID_PRIVATE_SENDER, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::transaction::memory::{
    CODE_PATCH_LIST_ROOTS_OFFSET,
    CREATED_PROCS_LIST_PTR,
    DEPENDENCIES_LIST_PTR,
    EXISTING_PROCS_LIST_PTR,
    MemoryAddress,
};
use miden_protocol::{Felt, ProtocolLib, WORD_SIZE, Word};
use miden_standards::StandardsLib;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::mock_account_code::MockAccountCodeExt;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::auth::UnreachableAuth;
use miden_tx::{TransactionExecutor, TransactionKernelError};
use rand::SeedableRng;
use rand::rngs::SmallRng;

use super::ExecutionOutputExt;
use crate::mock_transaction::TestTransactionBuilder;
use crate::{
    AccountState,
    Auth,
    MockChain,
    assert_execution_error,
    assert_transaction_executor_error,
};

// TESTS
// ================================================================================================

/// Present note scripts go into the existing procedures and absent note scripts into the created
/// procedures, together with the procedures they reference. Repeated roots and private notes do not
/// change the lists.
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
        .execute_code(&create_code_patch_code(&notes, &[], &[]))
        .await?;

    assert_eq!(
        code_patch_list(&exec_output, EXISTING_PROCS_LIST_PTR),
        BTreeSet::from([script_root(&p2id_note)])
    );
    assert_eq!(
        code_patch_list(&exec_output, CREATED_PROCS_LIST_PTR),
        BTreeSet::from([script_root(&custom_note)])
    );
    assert_eq!(
        code_patch_list(&exec_output, DEPENDENCIES_LIST_PTR),
        BTreeSet::from([protocol_procedure("miden::protocol::active_account::get_id")?])
    );
    assert_eq!(code_patch_counts(&exec_output), [1, 1, 1]);

    Ok(())
}

/// `tx::create_code_patch` returns the sizes of the code patch lists in the documented order.
#[tokio::test]
async fn create_code_patch_returns_list_sizes() -> anyhow::Result<()> {
    // one present note script and two absent note scripts that reference three present procedures
    let notes = [
        create_p2id_note(1)?,
        create_custom_note(ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 2)?,
        create_custom_note(ACCOUNT_STATE_SCRIPT, NoteType::Public, 3)?,
    ];

    let exec_output = TestTransactionBuilder::with_existing_mock_account()
        .expected_output_notes(notes.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?
        .execute_code(&create_code_patch_code_with(
            &notes,
            &[],
            &[],
            "exec.protocol_tx::create_code_patch",
        ))
        .await?;

    assert_eq!(code_patch_counts(&exec_output), [1, 2, 3]);

    Ok(())
}

/// The data store receives one request for the missing witnesses. It does not contain the script
/// of a private note, so that the data store does not learn it.
#[tokio::test]
async fn bulk_request_leaves_out_private_notes() -> anyhow::Result<()> {
    let private_note = create_custom_note(ACTIVE_NOTE_SCRIPT, NoteType::Private, 1)?;
    let public_note = create_custom_note(ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 2)?;
    let notes = [private_note, public_note.clone()];

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(format!(
        "@transaction_script\npub proc main\n{}\nend",
        create_notes_code(&notes)
    ))?;

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

/// A present top-level root that an absent note script references is also a dependency.
#[tokio::test]
async fn referenced_present_top_level_root_is_a_dependency() -> anyhow::Result<()> {
    let p2id_note = create_p2id_note(1)?;
    let custom_note = create_custom_note(P2ID_REFERENCING_SCRIPT, NoteType::Public, 2)?;
    let notes = [custom_note.clone(), p2id_note.clone()];

    let exec_output = TestTransactionBuilder::with_existing_mock_account()
        .expected_output_notes(notes.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?
        .execute_code(&create_code_patch_code(&notes, &[], &[]))
        .await?;

    assert_eq!(
        code_patch_list(&exec_output, EXISTING_PROCS_LIST_PTR),
        BTreeSet::from([script_root(&p2id_note)])
    );
    assert_eq!(
        code_patch_list(&exec_output, CREATED_PROCS_LIST_PTR),
        BTreeSet::from([script_root(&custom_note)])
    );
    assert_eq!(
        code_patch_list(&exec_output, DEPENDENCIES_LIST_PTR),
        BTreeSet::from([script_root(&p2id_note)])
    );

    Ok(())
}

/// An absent procedure that an absent note script references is a created procedure, and the
/// procedures that it references are also part of the code patch.
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
        .execute_code(&create_code_patch_code(core::slice::from_ref(&note), &[], &[]))
        .await?;

    assert_eq!(
        code_patch_list(&exec_output, CREATED_PROCS_LIST_PTR),
        BTreeSet::from([script_root(&note), mock_procedure])
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

/// The procedures of a new public account are top-level roots, while those of a new private
/// account are not.
#[rstest::rstest]
#[case::public(AccountType::Public)]
#[case::private(AccountType::Private)]
#[tokio::test]
async fn new_account_procedures_are_top_level_roots_if_public(
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
        .execute_code(&create_code_patch_code(&[], &[], &[]))
        .await?;

    let mut top_level_roots = code_patch_list(&exec_output, EXISTING_PROCS_LIST_PTR);
    let created_procedures = code_patch_list(&exec_output, CREATED_PROCS_LIST_PTR);
    top_level_roots.extend(created_procedures.iter().copied());

    if account_type.is_public() {
        let procedure_roots = account
            .code()
            .procedure_roots()
            .map(ProcedureRoot::from_raw)
            .collect::<BTreeSet<_>>();
        assert_eq!(top_level_roots, procedure_roots);
        for procedure_root in created_procedures {
            assert!(!mock_chain.code_tree().contains(&procedure_root));
        }
    } else {
        assert!(top_level_roots.is_empty());
        assert!(code_patch_list(&exec_output, DEPENDENCIES_LIST_PTR).is_empty());
    }

    Ok(())
}

/// A note that is created after the code patch is covered only if its script root was announced.
#[rstest::rstest]
#[case::announced(true)]
#[case::not_announced(false)]
#[tokio::test]
async fn announced_root_covers_note_created_after_code_patch(
    #[case] is_announced: bool,
) -> anyhow::Result<()> {
    let note = create_p2id_note(1)?;
    let announced_roots = if is_announced {
        Vec::from([script_root(&note)])
    } else {
        Vec::new()
    };

    let result = TestTransactionBuilder::with_existing_mock_account()
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute_code(&create_code_patch_code(&[], &announced_roots, core::slice::from_ref(&note)))
        .await;

    if is_announced {
        let exec_output = result?;
        assert_eq!(
            code_patch_list(&exec_output, EXISTING_PROCS_LIST_PTR),
            BTreeSet::from([script_root(&note)])
        );
    } else {
        assert_execution_error!(result, ERR_CODE_PATCH_TOP_LEVEL_ROOT_MISSING);
    }

    Ok(())
}

/// An authentication procedure can create a note with an absent script after the code patch, if it
/// announces the script root. The executor gets the MAST of the script from the expected output
/// notes, so the data store does not need it.
#[tokio::test]
async fn auth_procedure_creates_announced_note_after_code_patch() -> anyhow::Result<()> {
    let note = create_custom_note(ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 1)?;
    let auth_source = format!(
        "
        use miden::protocol::code_patch
        use miden::protocol::native_account
        use miden::protocol::output_note
        use miden::protocol::tx

        @auth_script
        pub proc auth
            push.{script_root} exec.code_patch::announce_root
            exec.tx::create_code_patch drop drop drop

            push.{recipient} push.{note_type} push.{tag}
            exec.output_note::create drop

            exec.native_account::incr_nonce drop
            dropw dropw dropw dropw
        end
        ",
        script_root = script_root(&note).as_word(),
        recipient = note.recipient().digest(),
        note_type = Felt::from(note.metadata().note_type()),
        tag = Felt::from(note.metadata().tag()),
    );
    let auth_code =
        CodeBuilder::default().compile_component_code("mock::announcing_auth", &auth_source)?;
    let auth_component = AccountComponent::new(
        auth_code,
        vec![],
        AccountComponentMetadata::mock("mock::announcing_auth"),
    )?;
    let account = AccountBuilder::new([43; 32])
        .with_component(auth_component)
        .with_component(BasicWallet)
        .build_existing()?;

    let executed_tx = TestTransactionBuilder::new(account)
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await?;

    assert!(executed_tx.tx_inputs().code_tree().contains(&script_root(&note)).is_ok());

    Ok(())
}

/// The host rejects a root that is announced after the code patch was created, because the code
/// patch cannot cover it anymore.
#[tokio::test]
async fn root_announced_after_code_patch_is_rejected() -> anyhow::Result<()> {
    let code = "
        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::code_patch
        use miden::tx_kernel_core::memory
        use miden::protocol::code_patch as protocol_code_patch

        begin
            exec.prologue::prepare_transaction
            push.1 exec.memory::set_epilogue_auth_in_progress_flag
            exec.code_patch::create drop drop drop
            push.1.2.3.4 exec.protocol_code_patch::announce_root
        end
    ";

    let result = TestTransactionBuilder::with_existing_mock_account()
        .build()?
        .execute_code(code)
        .await;

    assert_execution_error!(
        result,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if matches!(
                event_err.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::CodePatchRootAnnouncedAfterCreation(_))
            )
    );

    Ok(())
}

/// The kernel rejects code patch lists that are not unique and sorted, have the wrong presence in
/// the code tree, are too long, or do not cover a top-level root.
///
/// The transaction creates a P2ID note, whose script is present, and a custom note, whose script
/// is absent and references a present protocol procedure.
#[rstest::rstest]
#[case::unsorted(InvalidLists::Unsorted, ERR_MEM_WORDS_NOT_STRICTLY_SORTED)]
#[case::duplicate(InvalidLists::Duplicate, ERR_MEM_WORDS_NOT_STRICTLY_SORTED)]
#[case::absent_existing_proc(
    InvalidLists::AbsentExistingProc,
    ERR_CODE_PATCH_PROC_ROOT_PRESENCE_MISMATCH
)]
#[case::present_created_proc(
    InvalidLists::PresentCreatedProc,
    ERR_CODE_PATCH_PROC_ROOT_PRESENCE_MISMATCH
)]
#[case::absent_dependency(
    InvalidLists::AbsentDependency,
    ERR_CODE_PATCH_PROC_ROOT_PRESENCE_MISMATCH
)]
#[case::too_many_roots(InvalidLists::TooManyRoots, ERR_CODE_PATCH_MAX_ROOTS_EXCEEDED)]
#[case::missing_top_level_root(
    InvalidLists::MissingTopLevelRoot,
    ERR_CODE_PATCH_TOP_LEVEL_ROOT_MISSING
)]
#[tokio::test]
async fn invalid_code_patch_lists_are_rejected(
    #[case] invalid_lists: InvalidLists,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let p2id_note = create_p2id_note(1)?;
    let custom_note = create_custom_note(ACTIVE_ACCOUNT_SCRIPT, NoteType::Public, 2)?;
    let notes = [p2id_note.clone(), custom_note.clone()];

    let present_root = script_root(&p2id_note);
    let absent_root = script_root(&custom_note);
    let dependency = protocol_procedure("miden::protocol::active_account::get_id")?;
    let [lower_present_root, higher_present_root] = sorted([present_root, dependency]);

    let response = match invalid_lists {
        InvalidLists::Unsorted => code_patch_lists_advice([
            &[higher_present_root, lower_present_root],
            &[absent_root],
            &[dependency],
        ]),
        InvalidLists::Duplicate => {
            code_patch_lists_advice([&[present_root, present_root], &[absent_root], &[dependency]])
        },
        InvalidLists::AbsentExistingProc => code_patch_lists_advice([
            &sorted([present_root, absent_root]),
            &[absent_root],
            &[dependency],
        ]),
        InvalidLists::PresentCreatedProc => code_patch_lists_advice([
            &[present_root],
            &sorted([absent_root, present_root]),
            &[dependency],
        ]),
        InvalidLists::AbsentDependency => code_patch_lists_advice([
            &[present_root],
            &[absent_root],
            &sorted([dependency, absent_root]),
        ]),
        InvalidLists::TooManyRoots => Vec::from([Felt::from(513u32)]),
        InvalidLists::MissingTopLevelRoot => {
            code_patch_lists_advice([&[], &[absent_root], &[dependency]])
        },
    };

    let result = TestTransactionBuilder::with_existing_mock_account()
        .expected_output_notes(notes.iter().cloned().map(RawOutputNote::Full).collect())
        .build()?
        .execute_code_with_code_patch_response(&create_code_patch_code(&notes, &[], &[]), response)
        .await;

    assert_execution_error!(result, expected_error);

    Ok(())
}

/// The kernel creates the code patch only once and only during the authentication procedure.
#[rstest::rstest]
#[case::outside_auth("exec.code_patch::create drop drop drop", ERR_CODE_PATCH_CREATED_OUTSIDE_AUTH)]
#[case::twice(
    "push.1 exec.memory::set_epilogue_auth_in_progress_flag
     exec.code_patch::create drop drop drop
     exec.code_patch::create drop drop drop",
    ERR_CODE_PATCH_ALREADY_CREATED
)]
#[tokio::test]
async fn code_patch_creation_is_restricted(
    #[case] create_code_patch: &str,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let code = format!(
        "
        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::code_patch
        use miden::tx_kernel_core::memory

        begin
            exec.prologue::prepare_transaction
            {create_code_patch}
        end
        "
    );

    let result = TestTransactionBuilder::with_existing_mock_account()
        .build()?
        .execute_code(&code)
        .await;

    assert_execution_error!(result, expected_error);

    Ok(())
}

/// The epilogue rejects a transaction whose authentication procedure does not create the code
/// patch.
#[tokio::test]
async fn auth_procedure_must_create_code_patch() -> anyhow::Result<()> {
    let auth_code = CodeBuilder::default().compile_component_code(
        "mock::no_code_patch_auth",
        "
        use miden::protocol::native_account

        @auth_script
        pub proc auth
            exec.native_account::incr_nonce drop
        end
        ",
    )?;
    let auth_component = AccountComponent::new(
        auth_code,
        vec![],
        AccountComponentMetadata::mock("mock::no_code_patch_auth"),
    )?;
    let account = AccountBuilder::new([42; 32])
        .with_component(auth_component)
        .with_component(BasicWallet)
        .build_existing()?;

    let result = TestTransactionBuilder::new(account).build()?.execute().await;

    assert_transaction_executor_error!(result, ERR_EPILOGUE_CODE_PATCH_NOT_CREATED);

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
    // preimage of its recipient. The root is announced, so that the host does not need the
    // recipient to create the code patch.
    let result = TestTransactionBuilder::with_existing_mock_account()
        .add_advice_map_entry(note.recipient().digest(), invalid_preimage)
        .build()?
        .execute_code(&create_code_patch_code(
            &[],
            &[script_root(&note)],
            core::slice::from_ref(&note),
        ))
        .await;

    assert_execution_error!(result, ERR_NOTE_INVALID_RECIPIENT_PREIMAGE);

    Ok(())
}

/// The invalid code patch lists of `invalid_code_patch_lists_are_rejected`.
#[derive(Debug, Clone, Copy)]
enum InvalidLists {
    Unsorted,
    Duplicate,
    AbsentExistingProc,
    PresentCreatedProc,
    AbsentDependency,
    TooManyRoots,
    MissingTopLevelRoot,
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

/// A note script that references two procedures of the protocol library.
const ACCOUNT_STATE_SCRIPT: &str = "
    use miden::protocol::active_account

    @note_script
    pub proc main
        exec.active_account::get_nonce drop
        exec.active_account::get_code_commitment dropw
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

/// Returns the code that creates the code patch as the authentication procedure would and asserts
/// that it covers the top-level roots of the transaction.
///
/// `notes_before` are created before the code patch and `notes_after` afterwards. The script roots
/// in `announced_roots` are announced before the code patch is created. The counts of the code
/// patch lists remain on the stack.
///
/// The mock host does not handle the note events, so the script roots of the public notes in
/// `notes_before` are also announced, as the host would learn them from these events.
fn create_code_patch_code(
    notes_before: &[Note],
    announced_roots: &[ProcedureRoot],
    notes_after: &[Note],
) -> String {
    create_code_patch_code_with(
        notes_before,
        announced_roots,
        notes_after,
        "exec.code_patch::create",
    )
}

/// Same as [`create_code_patch_code`], but creates the code patch with the provided call.
fn create_code_patch_code_with(
    notes_before: &[Note],
    announced_roots: &[ProcedureRoot],
    notes_after: &[Note],
    create_code_patch: &str,
) -> String {
    let public_note_roots =
        notes_before.iter().filter(|note| note.metadata().is_public()).map(script_root);
    let announce_roots = announced_roots
        .iter()
        .copied()
        .chain(public_note_roots)
        .map(|root| {
            format!("push.{root} exec.protocol_code_patch::announce_root\n", root = root.as_word())
        })
        .collect::<String>();

    format!(
        "
        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::code_patch
        use miden::tx_kernel_core::memory
        use miden::protocol::code_patch as protocol_code_patch
        use miden::protocol::tx as protocol_tx
        use miden::core::sys

        begin
            exec.prologue::prepare_transaction
            {create_notes_before}
            {announce_roots}

            # the code patch can only be created during the authentication procedure
            push.1 exec.memory::set_epilogue_auth_in_progress_flag
            {create_code_patch}
            # => [num_existing_procs, num_created_procs, num_dependencies]
            push.0 exec.memory::set_epilogue_auth_in_progress_flag

            {create_notes_after}
            exec.code_patch::assert_later_output_notes_in_code_patch
            exec.sys::truncate_stack
        end
        ",
        create_notes_before = create_notes_code(notes_before),
        create_notes_after = create_notes_code(notes_after),
    )
}

/// Returns the code that creates the provided notes through the mock account.
fn create_notes_code(notes: &[Note]) -> String {
    notes
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
        .collect()
}

/// Returns the advice stack of code patch lists in the layout that the kernel reads.
fn code_patch_lists_advice(lists: [&[ProcedureRoot]; 3]) -> Vec<Felt> {
    lists
        .into_iter()
        .flat_map(|list| {
            core::iter::once(Felt::from(list.len() as u32))
                .chain(list.iter().flat_map(|root| root.as_word()))
        })
        .collect()
}

/// Returns the counts of the code patch lists that `create_code_patch_code` leaves on the stack.
fn code_patch_counts(exec_output: &ExecutionOutput) -> [u64; 3] {
    [0, 1, 2].map(|idx| exec_output.get_stack_element(idx).as_canonical_u64())
}

/// Returns the procedure roots in the code patch list at the provided memory address.
fn code_patch_list(
    exec_output: &ExecutionOutput,
    list_ptr: MemoryAddress,
) -> BTreeSet<ProcedureRoot> {
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

/// Returns the procedure roots in ascending order.
fn sorted<const N: usize>(mut procedure_roots: [ProcedureRoot; N]) -> [ProcedureRoot; N] {
    procedure_roots.sort();
    procedure_roots
}
